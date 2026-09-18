/**
 * AppControl Manager parity + conformance regression tests.
 *
 * Covers the behaviours added while bringing AppControl Manager capabilities
 * into AppControl Studio, each validated against cipolicy.xsd and the
 * Microsoft example policies shipped with Windows:
 *   - lossless <Settings> round-trip (AllHostIds, WindowsLockdownPolicySettings)
 *   - single-policy format (PolicyTypeID) round-trip
 *   - GUID sanitisation in the generator (no `{{…}}` / `{}` output)
 *   - simulator: FileName="*" wildcard, chain TBS matching, EKU, kernel paths
 *   - validator phases
 *   - templates
 *   - policy tools (regenerate IDs, dedupe, type conversion, apply bundles)
 *   - rule engine uses EVTX flat hashes
 */

import * as fs from "fs";
import * as path from "path";
import { parseWdacXml } from "../services/xml-parser.js";
import { generateWdacXml } from "../services/xml-generator.js";
import { simulateBinary } from "../services/policy-simulator.js";
import { validatePolicyStatic, validatePolicy } from "../services/policy-validator.js";
import { listTemplates, createFromTemplate } from "../services/policy-templates.js";
import { buildPolicyFromEvents } from "../services/policy-builder.js";
import { proposeRules } from "../services/rule-engine.js";
import { convertAppLockerToWdac } from "../services/applocker-converter.js";
import {
  regenerateIds, deduplicatePolicy, setPolicyType, clearAllRules, NIL_GUID, isSchemaValidFileRuleId,
} from "@appcontrol/shared";
import type { WdacPolicy, ParsedCiEvent } from "@appcontrol/shared";

const TEMPLATES = path.join(__dirname, "../../templates");
const read = (f: string) => fs.readFileSync(path.join(TEMPLATES, f), "utf8");
const GUID_A = "11111111-1111-1111-1111-111111111111";
const GUID_B = "22222222-2222-2222-2222-222222222222";

function minimalPolicy(overrides: Partial<WdacPolicy> = {}): WdacPolicy {
  return {
    policyId: GUID_A, versionEx: "10.0.0.0", policyType: "Base",
    options: [{ value: 0, enabled: true }, { value: 6, enabled: true }],
    ekus: [], fileRules: [], signers: [],
    signingScenarios: [
      { value: 131, id: "ID_SIGNINGSCENARIO_DRIVERS", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
      { value: 12, id: "ID_SIGNINGSCENARIO_WINDOWS", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
    ],
    updatePolicySigners: [], ciSigners: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Round-trip of Microsoft example policies
// ---------------------------------------------------------------------------

describe("Microsoft example policies round-trip", () => {
  test("AllowAll.xml: non-PolicyInfo settings and Boolean values are preserved", () => {
    const { policy, diagnostics } = parseWdacXml(read("AllowAll.xml"));
    expect(diagnostics.filter((d) => d.severity === "error")).toHaveLength(0);
    expect(policy.settings?.some((s) => s.provider === "AllHostIds" && s.valueType === "Boolean" && s.value === "true")).toBe(true);
    // PolicyInfo Id must not be coerced to a number ("022422" → 22422)
    expect(policy.settingsId).toBe("022422");
    const xml = generateWdacXml(policy);
    expect(xml).toContain('<Setting Provider="AllHostIds" Key="AllKeys" ValueName="EnterpriseDefinedClsId">');
    expect(xml).toContain("<Boolean>true</Boolean>");
    expect(xml).toContain("<String>022422</String>");
    const rt = parseWdacXml(xml).policy;
    expect(rt.settings).toEqual(policy.settings);
    expect(rt.fileRules).toHaveLength(2);
  });

  test("SmartAppControl.xml: every <Setting> survives and options include 23", () => {
    const { policy } = parseWdacXml(read("DefaultWindows_Enforced.xml"));
    expect(policy.signers).toHaveLength(31);
    const sacPath = "C:\\Windows\\schemas\\CodeIntegrity\\ExamplePolicies\\SmartAppControl.xml";
    const sacXml = fs.existsSync(sacPath) ? fs.readFileSync(sacPath, "utf8") : null;
    const sac = sacXml ? parseWdacXml(sacXml).policy : null;
    if (sac && sacXml) {
      expect(sac.settings!.length).toBe((sacXml.match(/<Setting /g) ?? []).length);
      const rt = parseWdacXml(generateWdacXml(sac)).policy;
      expect(rt.settings!.filter((s) => s.provider !== "PolicyInfo")).toEqual(sac.settings!.filter((s) => s.provider !== "PolicyInfo"));
      expect(rt.options.map((o) => o.value)).toContain(23);
    }
  });

  test("RecommendedDriverBlock (single-policy format) round-trips with PolicyTypeID and no PolicyID", () => {
    const { policy, diagnostics } = parseWdacXml(read("RecommendedDriverBlock_Enforced.xml"));
    expect(diagnostics.filter((d) => d.severity === "error")).toHaveLength(0);
    expect(diagnostics.some((d) => d.code === "SINGLE_POLICY_FORMAT")).toBe(true);
    expect(policy.policyFormat).toBe("SinglePolicy");
    expect(policy.policyId).toBe("D2BDA982-CCF6-4344-AC5B-0B44427B6816");
    expect(policy.fileRules.length).toBeGreaterThan(1500);
    const xml = generateWdacXml(policy);
    expect(xml).toContain("<PolicyTypeID>{D2BDA982-CCF6-4344-AC5B-0B44427B6816}</PolicyTypeID>");
    expect(xml).not.toContain("<PolicyID>");
    expect(xml).not.toContain("{}");
    const rt = parseWdacXml(xml).policy;
    expect(rt.fileRules.length).toBe(policy.fileRules.length);
    expect(rt.signers.length).toBe(policy.signers.length);
  });

  test("DefaultWindows_Supplemental round-trips its options and base reference", () => {
    const { policy } = parseWdacXml(read("DefaultWindows_Supplemental.xml"));
    expect(policy.policyType).toBe("Supplemental");
    const rt = parseWdacXml(generateWdacXml(policy)).policy;
    expect(rt.basePolicyId).toBe("E0ABDA1F-CCF0-468E-8855-3E0F08B02D6A");
    expect(rt.options.map((o) => o.value).sort()).toEqual([5, 6]);
  });

  test("SignTimeAfter on a signer survives round-trip", () => {
    const p = minimalPolicy({
      signers: [{ id: "ID_SIGNER_S_1", name: "X", certRoot: { type: "TBS", value: "AB" }, signTimeAfter: "2024-01-01T00:00:00Z" }],
    });
    const xml = generateWdacXml(p);
    expect(xml).toContain('SignTimeAfter="2024-01-01T00:00:00Z"');
    expect(parseWdacXml(xml).policy.signers[0].signTimeAfter).toBe("2024-01-01T00:00:00Z");
  });
});

// ---------------------------------------------------------------------------
// Generator GUID sanitisation
// ---------------------------------------------------------------------------

describe("generator GUID handling", () => {
  test("brace-wrapped basePolicyId is emitted with exactly one pair of braces", () => {
    const xml = generateWdacXml(minimalPolicy({ policyType: "Supplemental", basePolicyId: `{${GUID_B}}` }));
    expect(xml).toContain(`<BasePolicyID>{${GUID_B}}</BasePolicyID>`);
    expect(xml).not.toMatch(/\{\{/);
  });

  test("an empty PolicyID is an error, not `{}`", () => {
    expect(() => generateWdacXml(minimalPolicy({ policyId: "" }))).toThrow(/PolicyID/);
  });

  test("policy builder never propagates the nil GUID from events as a base policy", () => {
    const ev: ParsedCiEvent = {
      eventId: 3076, timestamp: "2026-01-01T00:00:00Z", filePath: "C:\\a.exe", fileName: "a.exe",
      severity: "audit", description: "", source: "evtx", sha256FlatHash: "A".repeat(64),
      policyGuid: "{00000000-0000-0000-0000-000000000000}",
    };
    const { policy, buildLog } = buildPolicyFromEvents({
      events: [ev], policyName: "S", policyType: "Supplemental",
      preferPublisherRules: false, includePathRules: false, auditMode: true,
    });
    expect(policy.basePolicyId).toBeUndefined();
    expect(buildLog.join("\n")).toMatch(/no base policy GUID/i);
    const withBase = buildPolicyFromEvents({
      events: [{ ...ev, policyGuid: `{${GUID_B}}` }], policyName: "S", policyType: "Supplemental",
      preferPublisherRules: false, includePathRules: false, auditMode: true,
    }).policy;
    expect(withBase.basePolicyId).toBe(GUID_B);
    expect(generateWdacXml(withBase)).toContain(`<BasePolicyID>{${GUID_B}}</BasePolicyID>`);
  });
});

// ---------------------------------------------------------------------------
// Simulator semantics
// ---------------------------------------------------------------------------

describe("simulator semantics", () => {
  test("AllowAll.xml allows an unsigned binary via FileName=\"*\"", () => {
    const { policy } = parseWdacXml(read("AllowAll.xml"));
    const r = simulateBinary({ sha256: "A".repeat(64), originalFileName: "anything.exe" }, policy);
    expect(r.verdict).toBe("allowed");
    expect(r.matchedBy).toBe("attribute");
    // Even with no originalFileName at all, "*" matches
    expect(simulateBinary({ sha256: "A".repeat(64) }, policy).verdict).toBe("allowed");
  });

  test("CertRoot TBS matches any certificate in the chain", () => {
    const policy = minimalPolicy({
      signers: [{ id: "ID_SIGNER_S_1", name: "PCA", certRoot: { type: "TBS", value: "CC".repeat(32) }, certPublisher: "Vendor" }],
      signingScenarios: [
        { value: 131, id: "ID_SIGNINGSCENARIO_DRIVERS", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
        { value: 12, id: "ID_SIGNINGSCENARIO_WINDOWS", allowedSigners: [{ signerId: "ID_SIGNER_S_1" }], deniedSigners: [], fileRuleRefs: [] },
      ],
    });
    const chain = ["AA".repeat(32), "BB".repeat(32), "CC".repeat(32)];
    expect(simulateBinary({ signerName: "Vendor", certChainTbs: chain }, policy).verdict).toBe("allowed");
    expect(simulateBinary({ signerName: "Vendor", certChainTbs: ["AA".repeat(32)] }, policy).verdict).toBe("blocked");
    expect(simulateBinary({ signerName: "Other", certChainTbs: chain }, policy).verdict).toBe("blocked");
  });

  test("CertEKU is enforced when the binary's leaf EKUs are known", () => {
    const { policy } = parseWdacXml(read("DefaultWindows_Enforced.xml"));
    const base = { signerName: "Microsoft Windows", wellknownRootId: "06" };
    const withWindowsEku = simulateBinary({ ...base, leafEkus: ["1.3.6.1.4.1.311.10.3.6", "1.3.6.1.5.5.7.3.3"] }, policy);
    expect(withWindowsEku.verdict).toBe("allowed");
    const codeSigningOnly = simulateBinary({ ...base, leafEkus: ["1.3.6.1.5.5.7.3.3"] }, policy);
    expect(codeSigningOnly.verdict).toBe("blocked");
  });

  test("Wellknown root ID is matched exactly when provided", () => {
    const { policy } = parseWdacXml(read("DefaultWindows_Enforced.xml"));
    const good = simulateBinary({ signerName: "X", wellknownRootId: "06", leafEkus: ["1.3.6.1.4.1.311.10.3.6"] }, policy);
    expect(good.verdict).toBe("allowed");
    const thirdParty = simulateBinary({ signerName: "X", wellknownRootId: "16", leafEkus: ["1.3.6.1.4.1.311.10.3.6"] }, policy);
    expect(thirdParty.verdict).toBe("blocked");
  });

  test("path rules have no effect in kernel mode", () => {
    const policy = minimalPolicy({
      fileRules: [{ kind: "path", id: "ID_ALLOW_P_1", effect: "Allow", filePath: "%WINDIR%\\*" }],
      signingScenarios: [
        { value: 131, id: "ID_SIGNINGSCENARIO_DRIVERS", allowedSigners: [], deniedSigners: [], fileRuleRefs: ["ID_ALLOW_P_1"] },
        { value: 12, id: "ID_SIGNINGSCENARIO_WINDOWS", allowedSigners: [], deniedSigners: [], fileRuleRefs: ["ID_ALLOW_P_1"] },
      ],
    });
    expect(simulateBinary({ filePath: "C:\\Windows\\x.dll" }, policy).verdict).toBe("allowed");
    const k = simulateBinary({ filePath: "C:\\Windows\\x.sys", isKernelMode: true }, policy);
    expect(k.verdict).toBe("blocked");
    expect(k.steps.find((s) => s.ruleId === "ID_ALLOW_P_1")?.outcome).toBe("skipped");
  });

  test("package rules match PackageFamilyName and are evaluated before path rules", () => {
    const policy = minimalPolicy({
      fileRules: [{ kind: "package", id: "ID_DENY_K_1", effect: "Deny", packageFamilyName: "Contoso.App_8wekyb3d8bbwe" }],
      signingScenarios: [
        { value: 131, id: "ID_SIGNINGSCENARIO_DRIVERS", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
        { value: 12, id: "ID_SIGNINGSCENARIO_WINDOWS", allowedSigners: [], deniedSigners: [], fileRuleRefs: ["ID_DENY_K_1"] },
      ],
    });
    const r = simulateBinary({ packageFamilyName: "contoso.app_8wekyb3d8bbwe" }, policy);
    expect(r.verdict).toBe("blocked");
    expect(r.matchedBy).toBe("package");
  });
});

// ---------------------------------------------------------------------------
// Validator
// ---------------------------------------------------------------------------

describe("policy validator", () => {
  test("Microsoft example policies produce no errors", () => {
    for (const f of ["AllowMicrosoft.xml", "DefaultWindows_Enforced.xml", "DefaultWindows_Supplemental.xml", "AllowAll.xml", "DenyAllAudit.xml"]) {
      const { policy } = parseWdacXml(read(f));
      const errors = validatePolicyStatic(policy).filter((x) => x.severity === "error");
      expect({ file: f, errors }).toEqual({ file: f, errors: [] });
    }
  });

  test("flags dangling references, bad IDs, and supplemental option violations", () => {
    const p = minimalPolicy({
      policyType: "Supplemental", basePolicyId: NIL_GUID,
      options: [{ value: 0, enabled: true }, { value: 5, enabled: true }],
      fileRules: [{ kind: "hash", id: "ID_HASH_1", effect: "Allow", hash: "ZZ", hashType: "SHA256" }],
      signers: [{ id: "ID_SIGNER_S_1", name: "S", certRoot: { type: "TBS", value: "AB" }, fileAttribRefs: ["ID_FILEATTRIB_F_MISSING"] }],
      signingScenarios: [
        { value: 12, id: "ID_SIGNINGSCENARIO_WINDOWS", allowedSigners: [{ signerId: "ID_SIGNER_S_NOPE" }], deniedSigners: [], fileRuleRefs: ["ID_HASH_1"] },
      ],
    });
    const codes = new Set(validatePolicyStatic(p).map((f) => f.code));
    for (const c of ["INVALID_RULE_ID", "INVALID_HASH", "UNRESOLVED_FILEATTRIB_REF", "UNRESOLVED_SIGNER_REF", "SUPPLEMENTAL_OPTION_NOT_ALLOWED", "SUPPLEMENTAL_NIL_BASE"]) {
      expect(codes).toContain(c);
    }
  });

  test("unsigned policy without option 6 and without UpdatePolicySigners is rejected (ConvertFrom-CIPolicy parity)", () => {
    const p = minimalPolicy({ options: [{ value: 0, enabled: true }] });
    expect(validatePolicyStatic(p).some((f) => f.code === "SIGNED_POLICY_WITHOUT_UPDATE_SIGNER")).toBe(true);
    const al = convertAppLockerToWdac(`<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled">
      <FilePathRule Id="r1" Name="PF" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\\*"/></Conditions></FilePathRule>
    </RuleCollection></AppLockerPolicy>`);
    expect(validatePolicyStatic(al.policy).filter((f) => f.severity === "error")).toHaveLength(0);
  });

  test("validatePolicy runs the toolchain on Windows when available", async () => {
    const { policy } = parseWdacXml(read("AllowMicrosoft.xml"));
    const r = await validatePolicy(policy, { useToolchain: true });
    expect(r.valid).toBe(true);
    if (r.toolchain.available) {
      expect(r.toolchain.xsdValidated).toBe(true);
      expect(r.toolchain.binaryConverted).toBe(true);
      expect(r.toolchain.binarySizeBytes).toBeGreaterThan(500);
    }
  }, 90_000);
});

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

describe("policy templates", () => {
  test("every template loads and validates without errors", async () => {
    const templates = await listTemplates();
    expect(templates.map((t) => t.id)).toEqual(expect.arrayContaining(["allow-microsoft", "default-windows", "signed-and-reputable", "strict-kernel-mode", "deny-policy", "supplemental-blank", "recommended-driver-block"]));
    for (const t of templates) {
      const r = await createFromTemplate({ templateId: t.id, policyName: `T ${t.id}`, basePolicyId: GUID_B });
      const errors = validatePolicyStatic(r.policy).filter((x) => x.severity === "error");
      expect({ id: t.id, errors }).toEqual({ id: t.id, errors: [] });
      expect(r.xml).toContain(`FriendlyName="T ${t.id}"`);
      expect(r.policy.policyId).not.toBe("959A0F15-8985-4551-A208-5FFE9EDB3A70"); // never Microsoft's GUID
    }
  });

  test("Signed and Reputable adds ISG options; Strict Kernel removes UMCI and user-mode signers", async () => {
    const sar = await createFromTemplate({ templateId: "signed-and-reputable", policyName: "S", auditMode: false });
    expect(sar.appliedOptions).toEqual(expect.arrayContaining([14, 15]));
    expect(sar.appliedOptions).not.toContain(3);
    const sk = await createFromTemplate({ templateId: "strict-kernel-mode", policyName: "K" });
    expect(sk.appliedOptions).not.toContain(0);
    expect(sk.policy.signingScenarios.find((s) => s.value === 12)!.allowedSigners).toHaveLength(0);
    expect(sk.policy.signingScenarios.find((s) => s.value === 131)!.allowedSigners.length).toBeGreaterThan(5);
  });

  test("switches map to the documented options", async () => {
    const r = await createFromTemplate({
      templateId: "allow-microsoft", policyName: "X",
      auditMode: true, requireEvSigners: true, enableScriptEnforcement: false, testMode: true, hvci: true, allowSupplemental: false,
    });
    expect(r.appliedOptions).toEqual(expect.arrayContaining([3, 8, 9, 10, 11]));
    expect(r.appliedOptions).not.toContain(17);
    expect(r.policy.hvciOptions).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Policy tools
// ---------------------------------------------------------------------------

describe("policy tools", () => {
  test("regenerateIds yields schema-valid IDs and keeps every reference resolvable", () => {
    const { policy } = parseWdacXml(read("DefaultWindows_Enforced.xml"));
    const r = regenerateIds(policy);
    expect(r.fileRules.every(isSchemaValidFileRuleId)).toBe(true);
    expect(validatePolicyStatic(r).filter((f) => f.severity === "error")).toHaveLength(0);
    expect(r.signers.map((s) => s.id)).not.toEqual(policy.signers.map((s) => s.id));
    expect(r.signingScenarios[0].allowedSigners.length).toBe(policy.signingScenarios[0].allowedSigners.length);
  });

  test("deduplicatePolicy collapses identical rules and drops dangling refs", () => {
    const p = minimalPolicy({
      fileRules: [
        { kind: "hash", id: "ID_ALLOW_A_1", effect: "Allow", hash: "AB".repeat(32), hashType: "SHA256" },
        { kind: "hash", id: "ID_ALLOW_A_2", effect: "Allow", hash: "ab".repeat(32), hashType: "SHA256" },
      ],
      signingScenarios: [
        { value: 12, id: "ID_SIGNINGSCENARIO_WINDOWS", allowedSigners: [{ signerId: "ID_SIGNER_S_GONE" }], deniedSigners: [], fileRuleRefs: ["ID_ALLOW_A_1", "ID_ALLOW_A_2", "ID_ALLOW_A_1"] },
      ],
    });
    const r = deduplicatePolicy(p);
    expect(r.removedFileRules).toBe(1);
    expect(r.droppedDanglingRefs).toBe(1);
    expect(r.policy.signingScenarios[0].fileRuleRefs).toEqual(["ID_ALLOW_A_1"]);
    expect(r.policy.signingScenarios[0].allowedSigners).toHaveLength(0);
  });

  test("setPolicyType filters options and clearAllRules keeps identity", () => {
    const { policy } = parseWdacXml(read("AllowMicrosoft.xml"));
    const supp = setPolicyType(policy, "Supplemental", GUID_B);
    expect(supp.policyType).toBe("Supplemental");
    expect(supp.basePolicyId).toBe(GUID_B);
    expect(supp.options.every((o) => [5, 6, 7, 13, 14, 18].includes(o.value as number))).toBe(true);
    expect(validatePolicyStatic(supp).filter((f) => f.severity === "error")).toHaveLength(0);
    const back = setPolicyType(supp, "Base");
    expect(back.basePolicyId).toBe(back.policyId);
    const cleared = clearAllRules(policy);
    expect(cleared.signers).toHaveLength(0);
    expect(cleared.policyId).toBe(policy.policyId);
    expect(cleared.options).toEqual(policy.options);
  });
});

// ---------------------------------------------------------------------------
// Rule engine — EVTX flat hashes
// ---------------------------------------------------------------------------

describe("rule engine hash source", () => {
  test("EVTX events carrying only sha256FlatHash produce hash rules, not path fallbacks", () => {
    const ev: ParsedCiEvent = {
      eventId: 3077, timestamp: "2026-01-01T00:00:00Z", filePath: "C:\\Tools\\x.exe", fileName: "x.exe",
      severity: "block", description: "", source: "evtx", sha256FlatHash: "AB".repeat(32),
    };
    const r = proposeRules({ events: [ev], preferSignerRules: true, scopeSignerRules: true, includePathRules: true, includeDenyRules: false });
    expect(r.summary.hashRules).toBe(1);
    expect(r.summary.pathRules).toBe(0);
    expect((r.rules[0].fileRule as { hash: string }).hash).toBe("AB".repeat(32));
  });
});
