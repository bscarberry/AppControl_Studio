/**
 * Policy Templates
 *
 * AppControl Manager parity for "Create AppControl Policy" and "Create Deny
 * Policy". Base templates are the Microsoft example policies that ship with
 * Windows (C:\Windows\schemas\CodeIntegrity\ExamplePolicies), bundled under
 * server/templates so the app works on any host. Derived templates:
 *
 *   signed-and-reputable   AllowMicrosoft + ISG (options 14, 15)
 *   strict-kernel-mode     DefaultWindows kernel scenario only, UMCI removed
 *   deny-policy            Two allow-all rules (user + kernel) + your deny
 *                          rules — AppControl Manager's deny-policy scaffold
 *   supplemental-blank     Empty supplemental (options 5 + 6)
 *   blank                  Empty base with UMCI + unsigned policy
 */

import { promises as fs } from "fs";
import path from "path";
import type {
  WdacPolicy,
  PolicyTemplateId,
  PolicyTemplateInfo,
  CreateFromTemplateRequest,
  CreateFromTemplateResponse,
  WdacSigningScenario,
} from "@appcontrol/shared";
import { newGuid, normalizeGuid, setOption, hasOption, NIL_GUID } from "@appcontrol/shared";
import { parseWdacXml } from "./xml-parser.js";
import { generateWdacXml } from "./xml-generator.js";

// __dirname is server/dist/services at runtime, server/src/services under ts-jest
const TEMPLATE_DIR = process.env.APPCONTROL_TEMPLATE_DIR
  ?? path.join(__dirname, "..", "..", "templates");

interface TemplateDef {
  info: Omit<PolicyTemplateInfo, "ruleCounts">;
  file?: string;
  build: (base: WdacPolicy | null) => WdacPolicy;
}

const BASE_SUPPORTS = { auditMode: true, requireEvSigners: true, scriptEnforcement: true, testMode: true, hvci: true, allowSupplemental: true };
const SUPP_SUPPORTS = { auditMode: false, requireEvSigners: false, scriptEnforcement: false, testMode: false, hvci: false, allowSupplemental: false };

function emptyScenarios(): WdacSigningScenario[] {
  return [
    { value: 131, id: "ID_SIGNINGSCENARIO_DRIVERS", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
    { value: 12, id: "ID_SIGNINGSCENARIO_WINDOWS", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
  ];
}

function blankBase(): WdacPolicy {
  const id = newGuid();
  return {
    policyId: id,
    basePolicyId: id,
    platformId: "2E07F7E4-194C-4D20-B7C9-6F44A6C5A234",
    versionEx: "1.0.0.0",
    policyType: "Base",
    options: [
      { value: 0, enabled: true },
      { value: 6, enabled: true },
      { value: 16, enabled: true },
      { value: 17, enabled: true },
      { value: 19, enabled: true },
      { value: 20, enabled: true },
    ],
    ekus: [],
    fileRules: [],
    signers: [],
    signingScenarios: emptyScenarios(),
    updatePolicySigners: [],
    ciSigners: [],
    hvciOptions: 0,
  };
}

const TEMPLATES: Record<PolicyTemplateId, TemplateDef> = {
  "allow-microsoft": {
    info: {
      id: "allow-microsoft", name: "Allow Microsoft", category: "base",
      description: "Allows everything signed by Microsoft (Windows, Office, Store, drivers). Third-party software is blocked unless added by a supplemental policy.",
      source: "Microsoft ExamplePolicies/AllowMicrosoft.xml",
      supports: BASE_SUPPORTS,
      notes: ["Recommended starting point for most organisations.", "Pair with supplemental policies for line-of-business apps."],
    },
    file: "AllowMicrosoft.xml",
    build: (b) => b!,
  },
  "default-windows": {
    info: {
      id: "default-windows", name: "Default Windows", category: "base",
      description: "Only files that ship with Windows (plus Microsoft-signed drivers). Office and other Microsoft apps are NOT allowed. Most restrictive Microsoft baseline.",
      source: "Microsoft ExamplePolicies/DefaultWindows_Enforced.xml",
      supports: BASE_SUPPORTS,
      notes: ["Add Microsoft 365 / Edge / Teams via supplemental policies.", "Enable audit mode for the first rollout."],
    },
    file: "DefaultWindows_Enforced.xml",
    build: (b) => b!,
  },
  "signed-and-reputable": {
    info: {
      id: "signed-and-reputable", name: "Signed and Reputable", category: "base",
      description: "Allow Microsoft plus the Intelligent Security Graph (ISG): files with good cloud reputation run automatically. Requires internet access to Microsoft's reputation service.",
      source: "AllowMicrosoft.xml + options 14 (ISG) and 15 (Invalidate EAs on Reboot)",
      supports: BASE_SUPPORTS,
      notes: ["ISG does not authorise kernel drivers.", "Devices must reach the ISG endpoint; offline devices fall back to explicit rules."],
    },
    file: "AllowMicrosoft.xml",
    build: (b) => setOption(setOption(b!, 14, true), 15, true),
  },
  "strict-kernel-mode": {
    info: {
      id: "strict-kernel-mode", name: "Strict Kernel-Mode", category: "base",
      description: "Kernel-mode enforcement only: drivers must be Microsoft/WHQL-signed; user-mode code is unrestricted (UMCI off).",
      source: "DefaultWindows_Enforced.xml kernel scenario, option 0 removed",
      supports: { ...BASE_SUPPORTS, scriptEnforcement: false },
      notes: ["Use with 'Create Supplemental Policy → Kernel-mode' for third-party drivers.", "Blocks unsigned and non-WHQL drivers when enforced."],
    },
    file: "DefaultWindows_Enforced.xml",
    build: (b) => {
      const p = setOption(b!, 0, false);
      const kernelSignerIds = new Set(p.signingScenarios.find((s) => s.value === 131)?.allowedSigners.map((a) => a.signerId) ?? []);
      return {
        ...p,
        signers: p.signers.filter((s) => kernelSignerIds.has(s.id)),
        signingScenarios: p.signingScenarios.map((s) =>
          s.value === 12 ? { ...s, allowedSigners: [], deniedSigners: [], fileRuleRefs: [] } : s
        ),
        ciSigners: [],
        fileRules: [],
      };
    },
  },
  "allow-all": {
    info: {
      id: "allow-all", name: "Allow All", category: "base",
      description: "Two FileName=\"*\" rules that allow everything. Used as the base for deny-only policies and for audit-only telemetry collection.",
      source: "Microsoft ExamplePolicies/AllowAll.xml",
      supports: { ...BASE_SUPPORTS, requireEvSigners: false },
      notes: ["Provides no protection on its own."],
    },
    file: "AllowAll.xml",
    build: (b) => b!,
  },
  "deny-all-audit": {
    info: {
      id: "deny-all-audit", name: "Deny All (Audit)", category: "base",
      description: "No allow rules, audit mode on. Logs every executable as a 3076 event — the fastest way to inventory what runs on a device.",
      source: "Microsoft ExamplePolicies/DenyAllAudit.xml",
      supports: { ...BASE_SUPPORTS, auditMode: false },
      notes: ["Never remove option 3 from this template — enforced it would block the OS."],
    },
    file: "DenyAllAudit.xml",
    build: (b) => b!,
  },
  "recommended-driver-block": {
    info: {
      id: "recommended-driver-block", name: "Microsoft Recommended Driver Block Rules", category: "block",
      description: "Microsoft's vulnerable-driver blocklist (kernel-mode). Deploy alongside your base policy; the user-mode scenario allows everything.",
      source: "Microsoft ExamplePolicies/RecommendedDriverBlock_Enforced.xml (single-policy format)",
      supports: { ...SUPP_SUPPORTS, auditMode: true },
      notes: ["Refresh from Microsoft periodically; the bundled copy reflects the Windows build this app was built on.", "Windows 11 22H2+ applies this list automatically via Smart App Control / HVCI."],
    },
    file: "RecommendedDriverBlock_Enforced.xml",
    build: (b) => ({ ...b!, policyFormat: "MultiplePolicy", policyId: newGuid(), basePolicyId: undefined, policyTypeId: undefined }),
  },
  "deny-policy": {
    info: {
      id: "deny-policy", name: "Deny Policy (scaffold)", category: "deny",
      description: "AppControl Manager style deny policy: two allow-all rules so anything you do not explicitly deny still runs. Add Deny rules from File Inspection or the editor.",
      source: "AllowAll.xml structure",
      supports: { ...BASE_SUPPORTS, requireEvSigners: false },
      notes: ["Deploy next to your real base policy; multiple base policies are ANDed — a file must be allowed by every base policy."],
    },
    file: "AllowAll.xml",
    build: (b) => ({ ...b!, options: b!.options.filter((o) => (o.value as number) !== 11) }),
  },
  "supplemental-blank": {
    info: {
      id: "supplemental-blank", name: "Blank Supplemental", category: "supplemental",
      description: "Empty supplemental policy (options 5 + 6). Set the base policy GUID, then add rules.",
      source: "Microsoft ExamplePolicies/DefaultWindows_Supplemental.xml structure",
      supports: SUPP_SUPPORTS,
      notes: ["The base policy must have option 17 (Allow Supplemental Policies)."],
    },
    build: () => ({
      ...blankBase(),
      policyType: "Supplemental",
      basePolicyId: NIL_GUID,
      options: [{ value: 5, enabled: true }, { value: 6, enabled: true }],
    }),
  },
  "blank": {
    info: {
      id: "blank", name: "Blank Base", category: "base",
      description: "Empty base policy with UMCI and sane defaults. Blocks everything until rules are added — start in audit mode.",
      source: "Generated",
      supports: BASE_SUPPORTS,
      notes: [],
    },
    build: () => blankBase(),
  },
};

const fileCache = new Map<string, WdacPolicy>();

async function loadTemplateFile(file: string): Promise<WdacPolicy> {
  const cached = fileCache.get(file);
  if (cached) return structuredClone(cached);
  const xml = await fs.readFile(path.join(TEMPLATE_DIR, file), "utf8");
  const { policy } = parseWdacXml(xml, file);
  fileCache.set(file, policy);
  return structuredClone(policy);
}

export async function listTemplates(): Promise<PolicyTemplateInfo[]> {
  const out: PolicyTemplateInfo[] = [];
  for (const def of Object.values(TEMPLATES)) {
    let p: WdacPolicy;
    try {
      p = def.build(def.file ? await loadTemplateFile(def.file) : null);
    } catch {
      continue;
    }
    out.push({
      ...def.info,
      ruleCounts: { signers: p.signers.length, fileRules: p.fileRules.length, ekus: p.ekus.length, options: p.options.length },
    });
  }
  return out;
}

export async function createFromTemplate(req: CreateFromTemplateRequest): Promise<CreateFromTemplateResponse> {
  const def = TEMPLATES[req.templateId];
  if (!def) throw new Error(`Unknown template '${req.templateId}'.`);
  const log: string[] = [`Template: ${def.info.name} (${def.info.source})`];

  let p = def.build(def.file ? await loadTemplateFile(def.file) : null);
  const isSupplemental = p.policyType === "Supplemental";

  // Fresh identity — never reuse Microsoft's example GUIDs
  if (p.policyFormat !== "SinglePolicy") {
    const id = newGuid();
    p = { ...p, policyId: id, basePolicyId: isSupplemental ? p.basePolicyId : id };
  }
  p = {
    ...p,
    friendlyName: req.policyName,
    settingsId: undefined,
    versionEx: req.versionEx && /^\d+\.\d+\.\d+\.\d+$/.test(req.versionEx) ? req.versionEx : "1.0.0.0",
    settings: (p.settings ?? []).filter((s) => s.provider !== "PolicyInfo"),
    sourceFileName: undefined,
  };
  log.push(`PolicyID ${p.policyId}`);

  if (isSupplemental) {
    const base = normalizeGuid(req.basePolicyId);
    if (base && base !== NIL_GUID) { p = { ...p, basePolicyId: base }; log.push(`BasePolicyID ${base}`); }
    else log.push("WARNING: no base policy GUID supplied — set it before deploying.");
  } else {
    const sup = def.info.supports;
    const audit = req.auditMode ?? def.info.id !== "allow-all";
    if (sup.auditMode) { p = setOption(p, 3, audit); log.push(`Audit mode: ${audit ? "on" : "off"}`); }
    if (sup.requireEvSigners && req.requireEvSigners !== undefined) { p = setOption(p, 8, req.requireEvSigners); log.push(`Require EV signers: ${req.requireEvSigners}`); }
    if (sup.scriptEnforcement && req.enableScriptEnforcement !== undefined) {
      p = setOption(p, 11, !req.enableScriptEnforcement);
      log.push(`Script enforcement: ${req.enableScriptEnforcement ? "enabled" : "disabled (option 11)"}`);
    }
    if (sup.testMode && req.testMode !== undefined) {
      p = setOption(setOption(p, 9, req.testMode), 10, req.testMode);
      log.push(`Test mode (options 9 + 10): ${req.testMode}`);
    } else if (sup.testMode && req.testMode === undefined && hasOption(p, 9)) {
      // Microsoft example policies ship with option 9; production defaults remove it.
      p = setOption(p, 9, false);
      log.push("Removed option 9 (Advanced Boot Options Menu) — enable Test mode to keep it.");
    }
    if (sup.allowSupplemental && req.allowSupplemental !== undefined) { p = setOption(p, 17, req.allowSupplemental); log.push(`Allow supplemental policies: ${req.allowSupplemental}`); }
    if (req.updateNoReboot !== undefined) { p = setOption(p, 16, req.updateNoReboot); }
    if (sup.hvci && req.hvci !== undefined) { p = { ...p, hvciOptions: req.hvci ? 1 : 0 }; log.push(`HVCI: ${req.hvci ? "enabled" : "off"}`); }
  }

  const xml = generateWdacXml(p);
  log.push(`Generated ${Buffer.byteLength(xml, "utf8")} bytes of XML.`);
  return {
    policy: p,
    xml,
    templateId: req.templateId,
    appliedOptions: p.options.filter((o) => o.enabled).map((o) => o.value as number).sort((a, b) => a - b),
    buildLog: log,
  };
}
