/**
 * Policy Validator
 *
 * AppControl Manager "Validate Policies" parity, in four phases:
 *
 *   schema      — cipolicy.xsd constraints re-implemented (ID patterns, GUID
 *                 and hex formats, version formats, required elements, ranges)
 *   references  — every cross-reference resolves to an element of the right
 *                 kind; duplicate IDs; orphaned rules that have no effect
 *   content     — deployability and semantic checks (unsigned policy needs
 *                 option 6, supplemental option restrictions, base/supplemental
 *                 identity, kernel path rules, unsupported macros, …)
 *   toolchain   — on Windows hosts with the ConfigCI module: validate the
 *                 generated XML against C:\Windows\schemas\CodeIntegrity\
 *                 cipolicy.xsd and run ConvertFrom-CIPolicy to prove it compiles
 *
 * Every finding carries a machine-readable code so the UI can group them.
 */

import { execFile } from "child_process";
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import type {
  WdacPolicy,
  ValidationFinding,
  PolicyValidationResult,
  ToolchainValidation,
} from "@appcontrol/shared";
import {
  SUPPLEMENTAL_ALLOWED_OPTIONS,
  isSchemaValidFileRuleId,
  isSchemaValidSignerId,
  isSchemaValidEkuId,
  isSchemaValidScenarioId,
  isValidGuid,
  fileRuleFingerprint,
  signerFingerprint,
} from "@appcontrol/shared";
import { generateWdacXml } from "./xml-generator.js";

// ---------------------------------------------------------------------------
// Static validation
// ---------------------------------------------------------------------------

const VERSION_RE = /^\d+\.\d+\.\d+\.\d+$/;
const HEX_RE = /^[0-9A-Fa-f]*$/;
const WDAC_PATH_MACROS = ["%OSDRIVE%", "%WINDIR%", "%SYSTEM32%"];

export function validatePolicyStatic(policy: WdacPolicy): ValidationFinding[] {
  const f: ValidationFinding[] = [];
  const err = (code: string, message: string, context?: string, phase: ValidationFinding["phase"] = "schema") =>
    f.push({ severity: "error", phase, code, message, context });
  const warn = (code: string, message: string, context?: string, phase: ValidationFinding["phase"] = "content") =>
    f.push({ severity: "warning", phase, code, message, context });
  const info = (code: string, message: string, context?: string, phase: ValidationFinding["phase"] = "content") =>
    f.push({ severity: "info", phase, code, message, context });

  const enabled = new Set(policy.options.filter((o) => o.enabled).map((o) => o.value as number));
  const isSupplemental = policy.policyType === "Supplemental";
  const isSingle = policy.policyFormat === "SinglePolicy";

  // ---- schema: identity ----
  if (isSingle) {
    if (!isValidGuid(policy.policyTypeId ?? policy.policyId)) err("INVALID_POLICY_TYPE_ID", "Single-policy format requires a valid PolicyTypeID GUID.", "PolicyTypeID");
    if (isSupplemental) err("SINGLE_POLICY_SUPPLEMENTAL", "Supplemental policies require the multiple-policy format (PolicyID + BasePolicyID).", "PolicyType");
  } else {
    if (!isValidGuid(policy.policyId)) err("INVALID_POLICY_ID", `PolicyID '${policy.policyId}' is not a valid GUID.`, "PolicyID");
    if (policy.basePolicyId !== undefined && !isValidGuid(policy.basePolicyId)) err("INVALID_BASE_POLICY_ID", `BasePolicyID '${policy.basePolicyId}' is not a valid GUID.`, "BasePolicyID");
  }
  if (policy.platformId !== undefined && !isValidGuid(policy.platformId)) err("INVALID_PLATFORM_ID", `PlatformID '${policy.platformId}' is not a valid GUID.`, "PlatformID");
  if (!VERSION_RE.test(policy.versionEx)) err("INVALID_VERSION", `VersionEx '${policy.versionEx}' must be four dot-separated integers.`, "VersionEx");
  if (policy.hvciOptions !== undefined && (!Number.isInteger(policy.hvciOptions) || policy.hvciOptions < 0 || policy.hvciOptions > 0xffffffff)) {
    err("INVALID_HVCI", `HvciOptions '${policy.hvciOptions}' must be an unsigned 32-bit integer.`, "HvciOptions");
  }

  // ---- schema: IDs / formats ----
  const allIds = new Map<string, string>();
  const dup = (id: string, what: string) => {
    if (!id) return;
    const prev = allIds.get(id);
    if (prev) err("DUPLICATE_ID", `ID '${id}' is used by both ${prev} and ${what}.`, id, "references");
    else allIds.set(id, what);
  };

  for (const e of policy.ekus) {
    dup(e.id, "EKU");
    if (!isSchemaValidEkuId(e.id)) err("INVALID_EKU_ID", `EKU ID '${e.id}' must match ID_EKU_[A-Z][_A-Z0-9]*.`, e.id);
    if (!HEX_RE.test(e.value) || e.value.length % 2 !== 0 || e.value.length === 0) err("INVALID_EKU_VALUE", `EKU '${e.id}' Value must be even-length hex.`, e.id);
  }

  for (const r of policy.fileRules) {
    dup(r.id, `${r.kind} rule`);
    if (!isSchemaValidFileRuleId(r)) {
      const expected = r.kind === "fileAttrib" ? "ID_FILEATTRIB_" : r.effect === "Deny" ? "ID_DENY_" : "ID_ALLOW_";
      err("INVALID_RULE_ID", `Rule ID '${r.id}' must start with ${expected} (or ID_FILE_) and use only [A-Z0-9_].`, r.id);
    }
    if (r.kind === "hash") {
      if (!HEX_RE.test(r.hash) || r.hash.length % 2 !== 0) err("INVALID_HASH", `Hash rule '${r.id}' has a non-hex or odd-length Hash.`, r.id);
      else if (![40, 64].includes(r.hash.length)) warn("UNUSUAL_HASH_LENGTH", `Hash rule '${r.id}' has ${r.hash.length} hex chars (expected 40 for SHA-1 or 64 for SHA-256).`, r.id, "schema");
    }
    if (r.kind === "path") {
      const p = r.filePath;
      const macro = p.match(/%[A-Z0-9_()]+%/i)?.[0];
      if (macro && !WDAC_PATH_MACROS.includes(macro.toUpperCase())) {
        warn("UNSUPPORTED_PATH_MACRO", `Path rule '${r.id}' uses ${macro}; WDAC only expands %OSDRIVE%, %WINDIR% and %SYSTEM32% — other macros are matched literally.`, r.id);
      }
      const stars = p.split("*").length - 1;
      if (stars > 1 || (stars === 1 && !p.startsWith("*") && !p.endsWith("*"))) {
        warn("PATH_WILDCARD_POSITION", `Path rule '${r.id}': WDAC supports a single '*' wildcard only at the beginning or end of the path.`, r.id);
      }
      if (!/^(%[A-Z0-9_]+%|[A-Za-z]:|\\\\|\*)/i.test(p)) warn("PATH_NOT_ABSOLUTE", `Path rule '${r.id}' does not look like an absolute path or macro-anchored path.`, r.id);
    }
    if (r.kind === "attribute" || r.kind === "fileAttrib") {
      const hasAny = !!(r.fileName || r.internalName || r.fileDescription || r.productName || r.minimumFileVersion || r.maximumFileVersion);
      if (!hasAny) err("EMPTY_ATTRIBUTE_RULE", `${r.kind === "fileAttrib" ? "FileAttrib" : "Attribute rule"} '${r.id}' has no matching attributes.`, r.id);
    }
    for (const [k, v] of [["MinimumFileVersion", (r as { minimumFileVersion?: string }).minimumFileVersion], ["MaximumFileVersion", (r as { maximumFileVersion?: string }).maximumFileVersion], ["PackageVersion", (r as { packageVersion?: string }).packageVersion]] as const) {
      if (v !== undefined && !VERSION_RE.test(v)) err("INVALID_RULE_VERSION", `Rule '${r.id}' ${k} '${v}' must be four dot-separated integers.`, r.id);
    }
  }

  for (const s of policy.signers) {
    dup(s.id, "signer");
    if (!isSchemaValidSignerId(s.id)) err("INVALID_SIGNER_ID", `Signer ID '${s.id}' must match ID_SIGNER_[A-Z][_A-Z0-9]*.`, s.id);
    if (!s.name) err("MISSING_SIGNER_NAME", `Signer '${s.id}' has no Name attribute (required).`, s.id);
    if (!s.certRoot) err("MISSING_CERT_ROOT", `Signer '${s.id}' has no <CertRoot>; cipolicy.xsd requires exactly one.`, s.id);
    else {
      if (!HEX_RE.test(s.certRoot.value) || s.certRoot.value.length % 2 !== 0 || s.certRoot.value.length === 0) err("INVALID_CERT_ROOT", `Signer '${s.id}' CertRoot Value must be even-length hex.`, s.id);
      if (s.certRoot.type === "TBS" && ![40, 64, 96, 128].includes(s.certRoot.value.length)) warn("UNUSUAL_TBS_LENGTH", `Signer '${s.id}' TBS hash has ${s.certRoot.value.length} hex chars (expected 40/64/96/128 for SHA-1/256/384/512).`, s.id, "schema");
    }
  }

  for (const sc of policy.signingScenarios) {
    if (!isSchemaValidScenarioId(sc.id)) info("SCENARIO_ID_NORMALIZED", `SigningScenario ID '${sc.id}' is not schema-valid and will be normalised on export.`, sc.id, "schema");
    if (sc.value < 0 || sc.value > 255) err("INVALID_SCENARIO_VALUE", `SigningScenario Value '${sc.value}' must be 0-255.`, sc.id);
    if (sc.minHashVersion !== undefined) {
      const n = parseInt(sc.minHashVersion, 10);
      if (!Number.isInteger(n) || n < 0 || n > 65535) err("INVALID_MIN_HASH_ALG", `SigningScenario '${sc.id}' MinimumHashAlgorithm must be 0-65535.`, sc.id);
    }
  }
  const scenarioValues = policy.signingScenarios.map((s) => s.value);
  if (new Set(scenarioValues).size !== scenarioValues.length) err("DUPLICATE_SCENARIO", "Multiple SigningScenario elements share the same Value.", "SigningScenarios", "references");

  // ---- references ----
  const rulesById = new Map(policy.fileRules.map((r) => [r.id, r]));
  const signerIds = new Set(policy.signers.map((s) => s.id));
  const ekuIds = new Set(policy.ekus.map((e) => e.id));
  const referencedRules = new Set<string>();
  const referencedSigners = new Set<string>();
  const referencedEkus = new Set<string>();

  for (const s of policy.signers) {
    for (const e of s.certEKU ?? []) {
      referencedEkus.add(e.ekuId);
      if (!ekuIds.has(e.ekuId)) err("UNRESOLVED_EKU_REF", `Signer '${s.id}' references EKU '${e.ekuId}' which does not exist.`, s.id, "references");
    }
    for (const ref of s.fileAttribRefs ?? []) {
      referencedRules.add(ref);
      const r = rulesById.get(ref);
      if (!r) err("UNRESOLVED_FILEATTRIB_REF", `Signer '${s.id}' references FileAttrib '${ref}' which does not exist.`, s.id, "references");
      else if (r.kind !== "fileAttrib") err("FILEATTRIB_REF_WRONG_KIND", `Signer '${s.id}' FileAttribRef '${ref}' points at a ${r.kind} rule, not a <FileAttrib>.`, s.id, "references");
    }
  }
  for (const sc of policy.signingScenarios) {
    for (const a of sc.allowedSigners) {
      referencedSigners.add(a.signerId);
      if (!signerIds.has(a.signerId)) err("UNRESOLVED_SIGNER_REF", `Scenario ${sc.value} AllowedSigner '${a.signerId}' does not exist.`, sc.id, "references");
      for (const ex of a.exceptDenyRuleIds ?? []) {
        referencedRules.add(ex);
        const r = rulesById.get(ex);
        if (!r) err("UNRESOLVED_EXCEPT_REF", `ExceptDenyRule '${ex}' on signer '${a.signerId}' does not exist.`, sc.id, "references");
        else if (r.kind === "fileAttrib" || r.effect !== "Deny") err("EXCEPT_REF_WRONG_KIND", `ExceptDenyRule '${ex}' must reference a <Deny> rule.`, sc.id, "references");
      }
    }
    for (const d of sc.deniedSigners) {
      referencedSigners.add(d.signerId);
      if (!signerIds.has(d.signerId)) err("UNRESOLVED_SIGNER_REF", `Scenario ${sc.value} DeniedSigner '${d.signerId}' does not exist.`, sc.id, "references");
      for (const ex of d.exceptAllowRuleIds ?? []) {
        referencedRules.add(ex);
        const r = rulesById.get(ex);
        if (!r) err("UNRESOLVED_EXCEPT_REF", `ExceptAllowRule '${ex}' on signer '${d.signerId}' does not exist.`, sc.id, "references");
        else if (r.kind === "fileAttrib" || r.effect !== "Allow") err("EXCEPT_REF_WRONG_KIND", `ExceptAllowRule '${ex}' must reference an <Allow> rule.`, sc.id, "references");
      }
    }
    for (const ref of sc.fileRuleRefs) {
      referencedRules.add(ref);
      const r = rulesById.get(ref);
      if (!r) err("UNRESOLVED_FILE_RULE_REF", `Scenario ${sc.value} FileRuleRef '${ref}' does not exist.`, sc.id, "references");
      else if (r.kind === "fileAttrib") err("FILE_RULE_REF_TO_FILEATTRIB", `Scenario ${sc.value} FileRuleRef '${ref}' points at a <FileAttrib>; only Allow/Deny rules may be referenced.`, sc.id, "references");
      else if (r.kind === "path" && sc.value === 131) warn("KERNEL_PATH_RULE", `Path rule '${ref}' is referenced from the kernel-mode scenario; file path rules only apply to user mode.`, ref);
    }
  }
  for (const list of [["CiSigners", policy.ciSigners], ["UpdatePolicySigners", policy.updatePolicySigners], ["SupplementalPolicySigners", policy.supplementalPolicySigners ?? []]] as const) {
    for (const id of list[1]) {
      referencedSigners.add(id);
      if (!signerIds.has(id)) err("UNRESOLVED_SIGNER_REF", `${list[0]} entry '${id}' does not exist.`, list[0], "references");
    }
  }
  for (const r of policy.fileRules) {
    if (!referencedRules.has(r.id)) {
      if (r.kind === "fileAttrib") warn("ORPHAN_FILEATTRIB", `FileAttrib '${r.id}' is not referenced by any signer and has no effect.`, r.id, "references");
      else warn("ORPHAN_RULE", `${r.effect} rule '${r.id}' is not referenced from any SigningScenario and has no effect.`, r.id, "references");
    }
  }
  for (const s of policy.signers) {
    if (!referencedSigners.has(s.id)) warn("ORPHAN_SIGNER", `Signer '${s.id}' is not referenced from any scenario or signer list and has no effect.`, s.id, "references");
  }
  for (const e of policy.ekus) {
    if (!referencedEkus.has(e.id)) info("ORPHAN_EKU", `EKU '${e.id}' is not referenced by any signer.`, e.id, "references");
  }

  // Duplicate content
  const ruleFps = new Map<string, string>();
  for (const r of policy.fileRules) {
    const fp = fileRuleFingerprint(r);
    const prev = ruleFps.get(fp);
    if (prev) info("DUPLICATE_RULE", `Rule '${r.id}' duplicates '${prev}' (identical content). Deduplicate to shrink the policy.`, r.id, "references");
    else ruleFps.set(fp, r.id);
  }
  const signerFps = new Map<string, string>();
  for (const s of policy.signers) {
    const fp = signerFingerprint(s, rulesById);
    const prev = signerFps.get(fp);
    if (prev) info("DUPLICATE_SIGNER", `Signer '${s.id}' duplicates '${prev}' (identical certificate constraints and scope).`, s.id, "references");
    else signerFps.set(fp, s.id);
  }

  // ---- content: base / supplemental ----
  if (isSupplemental) {
    if (!policy.basePolicyId) err("SUPPLEMENTAL_NO_BASE", "Supplemental policy has no BasePolicyID.", "BasePolicyID", "content");
    else if (policy.basePolicyId === policy.policyId) err("SUPPLEMENTAL_SELF_BASE", "Supplemental policy's BasePolicyID equals its own PolicyID — that makes it a base policy.", "BasePolicyID", "content");
    else if (policy.basePolicyId === "00000000-0000-0000-0000-000000000000") err("SUPPLEMENTAL_NIL_BASE", "BasePolicyID is the all-zero placeholder GUID; set it to the real base policy's PolicyID.", "BasePolicyID", "content");
    for (const o of enabled) {
      if (!SUPPLEMENTAL_ALLOWED_OPTIONS.has(o)) err("SUPPLEMENTAL_OPTION_NOT_ALLOWED", `Option ${o} is not permitted in a supplemental policy (allowed: ${[...SUPPLEMENTAL_ALLOWED_OPTIONS].join(", ")}).`, `Option ${o}`, "content");
    }
    if (!enabled.has(5)) warn("SUPPLEMENTAL_MISSING_INHERIT", "Supplemental policies normally carry option 5 (Enabled:Inherit Default Policy).", "Rules");
    if (policy.supplementalPolicySigners?.length) err("SUPPLEMENTAL_HAS_SUPP_SIGNERS", "Supplemental policies cannot carry <SupplementalPolicySigners>.", "SupplementalPolicySigners", "content");
  } else if (!isSingle) {
    if (policy.basePolicyId && policy.basePolicyId !== policy.policyId) err("BASE_WITH_FOREIGN_BASE_ID", "Base policy's BasePolicyID differs from its PolicyID — Windows treats such a policy as supplemental.", "BasePolicyID", "content");
    if (!enabled.has(17) && (policy.supplementalPolicySigners?.length ?? 0) > 0) warn("SUPP_SIGNERS_WITHOUT_OPTION_17", "SupplementalPolicySigners are present but option 17 (Allow Supplemental Policies) is not enabled.", "Rules");
  }

  // ---- content: deployability ----
  if (!enabled.has(6) && policy.updatePolicySigners.length === 0) {
    err("SIGNED_POLICY_WITHOUT_UPDATE_SIGNER", "Signed policy is required (option 6 absent), but no UpdatePolicySigner is specified. Add option 6 for an unsigned policy or add an UpdatePolicySigner.", "Rules", "content");
  }
  if (!isSupplemental && !enabled.has(0)) warn("UMCI_DISABLED", "Option 0 (Enabled:UMCI) is not set — user-mode code is not enforced by this policy.", "Rules");
  if (enabled.has(3)) info("AUDIT_MODE", "Option 3 (Audit Mode) is enabled — violations are logged, not blocked.", "Rules");
  if (enabled.has(7)) warn("DEBUG_POLICY_AUGMENTED", "Option 7 (Allowed:Debug Policy Augmented) must not be enabled in production.", "Rules");
  if (enabled.has(9)) warn("ADVANCED_BOOT_MENU", "Option 9 allows the Advanced Boot Options menu, which can be used to bypass the policy.", "Rules");
  if (enabled.has(18)) warn("RUNTIME_FILEPATH_PROTECTION_DISABLED", "Option 18 disables runtime FilePath rule protection; path rules can be bypassed via user-writable directories.", "Rules");
  if (enabled.has(11)) info("SCRIPT_ENFORCEMENT_DISABLED", "Option 11 disables script enforcement (PowerShell, WSH, MSI are not restricted).", "Rules");
  if ((enabled.has(13) || enabled.has(14)) && !enabled.has(15)) info("EA_INVALIDATION_RECOMMENDED", "Managed Installer / ISG is enabled without option 15 (Invalidate EAs on Reboot).", "Rules");
  if (isSingle && policy.policyType === "Base" && enabled.has(17)) info("SINGLE_POLICY_SUPPLEMENTAL_OPTION", "Option 17 has no effect in the single-policy format.", "Rules");

  const userScenario = policy.signingScenarios.find((s) => s.value === 12);
  const kernelScenario = policy.signingScenarios.find((s) => s.value === 131);
  if (!isSupplemental && enabled.has(0) && !userScenario) warn("MISSING_USER_SCENARIO", "UMCI is enabled but there is no user-mode SigningScenario (Value=12).", "SigningScenarios");
  if (!isSupplemental && !kernelScenario) warn("MISSING_KERNEL_SCENARIO", "There is no kernel-mode SigningScenario (Value=131).", "SigningScenarios");
  const totalRefs = policy.signingScenarios.reduce((n, s) => n + s.allowedSigners.length + s.fileRuleRefs.length, 0);
  if (!isSupplemental && totalRefs === 0 && !enabled.has(3) && !enabled.has(14)) {
    warn("EMPTY_ENFORCED_POLICY", "Enforced base policy has no allow rules or signers — it will block everything, including Windows itself.", "SigningScenarios");
  }

  return f;
}

// ---------------------------------------------------------------------------
// Toolchain validation (Windows + ConfigCI only)
// ---------------------------------------------------------------------------

let toolchainProbe: Promise<boolean> | null = null;

function runPowerShell(script: string, timeoutMs = 60_000): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const exe = process.platform === "win32" ? "powershell.exe" : "pwsh";
    const child = execFile(
      exe,
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
      { timeout: timeoutMs, windowsHide: true, maxBuffer: 4 * 1024 * 1024 },
      (error, stdout, stderr) => {
        resolve({
          stdout: String(stdout ?? ""),
          stderr: String(stderr ?? ""),
          code: error ? 1 : 0,
        });
      }
    );
    child.on("error", () => resolve({ stdout: "", stderr: "spawn failed", code: 1 }));
  });
}

/** True when ConvertFrom-CIPolicy and cipolicy.xsd are available on this host. */
export function isToolchainAvailable(): Promise<boolean> {
  if (toolchainProbe) return toolchainProbe;
  toolchainProbe = (async () => {
    if (process.platform !== "win32") return false;
    if (process.env.APPCONTROL_DISABLE_TOOLCHAIN === "1") return false;
    const r = await runPowerShell(
      "if ((Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue) -and (Test-Path $env:SystemRoot\\schemas\\CodeIntegrity\\cipolicy.xsd)) { 'OK' } else { 'NO' }",
      20_000
    );
    return r.stdout.trim().endsWith("OK");
  })();
  return toolchainProbe;
}

const TOOLCHAIN_SCRIPT = `
param([string]$XmlPath, [string]$BinPath)
$xsd = Join-Path $env:SystemRoot 'schemas\\CodeIntegrity\\cipolicy.xsd'
$errs = New-Object System.Collections.Generic.List[string]
$settings = New-Object System.Xml.XmlReaderSettings
$settings.ValidationType = 'Schema'
$null = $settings.Schemas.Add('urn:schemas-microsoft-com:sipolicy', $xsd)
$settings.add_ValidationEventHandler({ param($s, $e) $errs.Add($e.Message) })
try {
  $reader = [System.Xml.XmlReader]::Create($XmlPath, $settings)
  while ($reader.Read()) {}
  $reader.Close()
} catch { $errs.Add('READ: ' + $_.Exception.Message) }
$result = @{ xsdErrors = @($errs); binaryConverted = $false; binarySize = 0; binaryError = '' }
try {
  $null = ConvertFrom-CIPolicy -XmlFilePath $XmlPath -BinaryFilePath $BinPath -ErrorAction Stop
  $result.binaryConverted = $true
  $result.binarySize = (Get-Item $BinPath).Length
} catch {
  $result.binaryError = ($_.Exception.Message -replace "\\r?\\n", ' ')
}
$result | ConvertTo-Json -Compress
`;

export async function validateWithToolchain(xml: string): Promise<ToolchainValidation> {
  if (!(await isToolchainAvailable())) {
    return {
      available: false,
      note: process.platform === "win32"
        ? "ConfigCI PowerShell module or cipolicy.xsd not found on this host."
        : "Binary conversion (ConvertFrom-CIPolicy) requires a Windows host; structural validation only.",
    };
  }
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "acs-validate-"));
  const xmlPath = path.join(dir, "policy.xml");
  const binPath = path.join(dir, "policy.cip");
  const scriptPath = path.join(dir, "validate.ps1");
  try {
    await fs.writeFile(xmlPath, xml, "utf8");
    await fs.writeFile(scriptPath, TOOLCHAIN_SCRIPT, "utf8");
    const r = await runPowerShell(`& '${scriptPath.replace(/'/g, "''")}' -XmlPath '${xmlPath.replace(/'/g, "''")}' -BinPath '${binPath.replace(/'/g, "''")}'`);
    const line = r.stdout.trim().split(/\r?\n/).reverse().find((l) => l.startsWith("{"));
    if (!line) {
      return { available: true, note: `Toolchain produced no result (${r.stderr.trim().slice(0, 300) || "no stderr"}).` };
    }
    const parsed = JSON.parse(line) as { xsdErrors: string[] | string; binaryConverted: boolean; binarySize: number; binaryError: string };
    const xsdErrors = Array.isArray(parsed.xsdErrors) ? parsed.xsdErrors : parsed.xsdErrors ? [parsed.xsdErrors] : [];
    return {
      available: true,
      xsdValidated: xsdErrors.length === 0,
      xsdErrors,
      binaryConverted: parsed.binaryConverted,
      binarySizeBytes: parsed.binaryConverted ? parsed.binarySize : undefined,
      binaryError: parsed.binaryError || undefined,
    };
  } catch (e) {
    return { available: true, note: `Toolchain validation failed to run: ${(e as Error).message}` };
  } finally {
    await fs.rm(dir, { recursive: true, force: true }).catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function validatePolicy(
  policy: WdacPolicy,
  opts: { useToolchain?: boolean } = {}
): Promise<PolicyValidationResult> {
  const findings = validatePolicyStatic(policy);

  let xml = "";
  let xmlSizeBytes = 0;
  try {
    xml = generateWdacXml(policy);
    xmlSizeBytes = Buffer.byteLength(xml, "utf8");
  } catch (e) {
    findings.push({ severity: "error", phase: "schema", code: "GENERATE_FAILED", message: `XML generation failed: ${(e as Error).message}` });
  }

  let toolchain: ToolchainValidation = { available: false, note: "Toolchain validation not requested." };
  if (xml && (opts.useToolchain ?? true)) {
    toolchain = await validateWithToolchain(xml);
    for (const e of toolchain.xsdErrors ?? []) {
      findings.push({ severity: "error", phase: "toolchain", code: "XSD_VIOLATION", message: e, context: "cipolicy.xsd" });
    }
    if (toolchain.available && toolchain.binaryConverted === false && toolchain.binaryError) {
      findings.push({ severity: "error", phase: "toolchain", code: "BINARY_CONVERSION_FAILED", message: toolchain.binaryError, context: "ConvertFrom-CIPolicy" });
    }
    if (toolchain.available && toolchain.binaryConverted) {
      findings.push({ severity: "info", phase: "toolchain", code: "BINARY_CONVERSION_OK", message: `ConvertFrom-CIPolicy produced a ${toolchain.binarySizeBytes} byte binary policy.`, context: "ConvertFrom-CIPolicy" });
    }
  }

  const summary = {
    errors: findings.filter((x) => x.severity === "error").length,
    warnings: findings.filter((x) => x.severity === "warning").length,
    infos: findings.filter((x) => x.severity === "info").length,
  };
  return { valid: summary.errors === 0, findings, summary, toolchain, xmlSizeBytes };
}
