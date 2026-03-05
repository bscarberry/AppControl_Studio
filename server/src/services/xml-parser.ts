/**
 * WDAC XML Parser
 *
 * Converts a WDAC SiPolicy XML document into a normalized WdacPolicy object
 * plus a RuleCollectionIndex for O(1) cross-reference lookups.
 *
 * The WDAC schema is defined in cipolicy.xsd (Windows SDK).
 * This parser follows the documented structure at:
 * https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune
 */

import { XMLParser } from "fast-xml-parser";
import type {
  WdacPolicy,
  WdacFileRule,
  WdacHashRule,
  WdacPathRule,
  WdacPackageRule,
  WdacAttributeRule,
  WdacFileAttrib,
  WdacSignerRule,
  WdacSigningScenario,
  WdacEku,
  PolicyRuleOption,
  PolicyRuleOptionNumber,
  AllowedSigner,
  DeniedSigner,
  SigningScenarioValue,
  FileRuleEffect,
  HashType,
  CertRootType,
  ParseDiagnostic,
  RuleCollectionIndex,
} from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function asArray<T>(value: T | T[] | undefined): T[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function attr(obj: Record<string, unknown>, name: string): string | undefined {
  const v = obj[`@_${name}`] ?? obj[name];
  return v != null ? String(v) : undefined;
}

function requireAttr(obj: Record<string, unknown>, name: string, ctx: string): string {
  const v = attr(obj, name);
  if (!v) throw new Error(`Missing required attribute '${name}' on <${ctx}>`);
  return v;
}

/** Strip surrounding curly braces from a GUID attribute value, e.g. "{GUID}" -> "GUID" */
function normalizeGuid(value: string | undefined): string | undefined {
  if (!value) return value;
  return value.replace(/^\{?([0-9A-Fa-f-]{36})\}?$/, "$1").toUpperCase();
}

// ---------------------------------------------------------------------------
// Diagnostic factories
// ---------------------------------------------------------------------------

function diagError(code: string, message: string, context?: string): ParseDiagnostic {
  return { severity: "error", code, message, context };
}

function diagWarn(code: string, message: string, context?: string): ParseDiagnostic {
  return { severity: "warning", code, message, context };
}

function diagInfo(code: string, message: string, context?: string): ParseDiagnostic {
  return { severity: "info", code, message, context };
}

// ---------------------------------------------------------------------------
// Main Parser
// ---------------------------------------------------------------------------

export interface ParseResult {
  policy: WdacPolicy;
  index: RuleCollectionIndex;
  diagnostics: ParseDiagnostic[];
}

export function parseWdacXml(xmlContent: string, fileName?: string): ParseResult {
  const diagnostics: ParseDiagnostic[] = [];

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_",
    isArray: (_name, _jpath, isLeafNode, _isAttribute) => {
      // Always treat these as arrays to handle single-child cases uniformly
      const alwaysArray = new Set([
        "Rule", "EKU", "Allow", "Deny", "FileAttrib",
        "Signer", "SigningScenario", "AllowedSigner", "DeniedSigner",
        "FileRuleRef", "CertEKU", "FileAttrib",
        "UpdatePolicySigner", "CiSigner",
        "ExceptDenyRule", "ExceptAllowRule",
        "Setting",
      ]);
      return alwaysArray.has(_name) && !isLeafNode;
    },
    parseAttributeValue: false,
    trimValues: true,
  });

  let root: Record<string, unknown>;
  try {
    const parsed = parser.parse(xmlContent) as Record<string, unknown>;
    const siPolicy = parsed["SiPolicy"] as Record<string, unknown>;
    if (!siPolicy) {
      throw new Error("Root element <SiPolicy> not found. Is this a valid WDAC policy XML?");
    }
    root = siPolicy;
  } catch (err) {
    throw new Error(`XML parse error: ${(err as Error).message}`);
  }

  // --- Top-level attributes ---
  // GUIDs in the XML are wrapped in curly braces: PolicyID="{GUID}" — strip them for normalization
  const policyId = normalizeGuid(attr(root, "PolicyID") ?? attr(root, "policyId")) ?? "";
  const basePolicyId = normalizeGuid(attr(root, "BasePolicyID") ?? attr(root, "basePolicyId"));
  const policyTypeId = normalizeGuid(attr(root, "PolicyTypeID") ?? attr(root, "policyTypeId"));
  const friendlyName =
    attr(root, "FriendlyName") ??
    attr(root, "friendlyName") ??
    parseSettingsField(root, "Name");
  const settingsId = parseSettingsField(root, "Id");
  const versionEx = attr(root, "VersionEx") ?? attr(root, "versionEx") ?? "10.0.0.0";
  const platformId = normalizeGuid(attr(root, "PlatformID") ?? attr(root, "platformId"));
  const hvciRaw = attr(root, "HvciOptions") ?? attr(root, "hvciOptions");
  const hvciOptions = hvciRaw !== undefined ? parseInt(hvciRaw, 10) : undefined;

  if (!policyId) {
    diagnostics.push(diagError("MISSING_POLICY_ID", "PolicyID attribute or element is missing or unparseable."));
  }
  if (friendlyName && parseSettingsField(root, "Name")) {
    diagnostics.push(diagInfo("SETTINGS_NAME_FALLBACK",
      "Policy name was read from <Settings> block, not FriendlyName attribute."));
  }

  // A policy is Supplemental only when it carries a BasePolicyID that differs
  // from its own PolicyID. Some base policies include a self-referential
  // BasePolicyID (BasePolicyID == PolicyID) as a legacy artifact — those are
  // still Base policies. Supplemental policies always reference a different base.
  const policyType = basePolicyId && basePolicyId !== policyId ? "Supplemental" : "Base";

  // --- Policy Rule Options ---
  const options = parsePolicyRuleOptions(root, diagnostics);

  // --- EKUs ---
  const ekus = parseEkus(root, diagnostics);

  // --- File Rules ---
  const fileRules = parseFileRules(root, diagnostics);

  // --- Signers ---
  const signers = parseSigners(root, diagnostics);

  // --- Signing Scenarios ---
  const signingScenarios = parseSigningScenarios(root, diagnostics);

  // --- Update Policy Signers ---
  const updatePolicySigners = parseUpdatePolicySigners(root);

  // --- CI Signers ---
  const ciSigners = parseCiSigners(root);

  const policy: WdacPolicy = {
    policyId,
    basePolicyId,
    policyTypeId,
    friendlyName,
    settingsId,
    versionEx,
    platformId,
    policyType,
    options,
    ekus,
    fileRules,
    signers,
    signingScenarios,
    updatePolicySigners,
    ciSigners,
    hvciOptions,
    sourceFileName: fileName,
  };

  const index = buildIndex(policy, diagnostics);

  return { policy, index, diagnostics };
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

function parsePolicyRuleOptions(
  root: Record<string, unknown>,
  diagnostics: ParseDiagnostic[]
): PolicyRuleOption[] {
  const options: PolicyRuleOption[] = [];
  const rulesSection = root["Rules"] as Record<string, unknown> | undefined;
  if (!rulesSection) return options;

  const rules = asArray(rulesSection["Rule"] as unknown);
  for (const rule of rules) {
    const ruleObj = rule as Record<string, unknown>;
    const option = ruleObj["Option"] as Record<string, unknown> | string | undefined;
    if (!option) {
      diagnostics.push(diagWarn("MISSING_RULE_OPTION", "Found <Rule> without <Option> child; skipping."));
      continue;
    }

    // Option can be a simple text node or have attributes
    let optionText: string;
    if (typeof option === "string") {
      optionText = option;
    } else {
      const optObj = option as Record<string, unknown>;
      optionText = (optObj["#text"] ?? String(option)) as string;
    }

    // Parse "Enabled:Boot Menu Protection" -> value 1 or "Disabled:Script Enforcement" -> value 11
    const match = optionText.trim().match(/^(Enabled|Disabled|Required|Allowed|Invalidated):(.+)$/);
    if (!match) {
      diagnostics.push(diagWarn("UNRECOGNIZED_OPTION_FORMAT",
        `Unrecognized Option format: '${optionText}'; skipping.`));
      continue;
    }

    const optionName = `${match[1]}:${match[2]}`;
    const optionNumber = findOptionNumber(optionName);
    if (optionNumber === undefined) {
      diagnostics.push(diagWarn("UNKNOWN_RULE_OPTION",
        `Unknown policy rule option '${optionText}'; skipping.`));
      continue;
    }

    options.push({
      value: optionNumber as PolicyRuleOptionNumber,
      enabled: true,
    });
  }

  return options;
}

function findOptionNumber(name: string): number | undefined {
  // Dynamic import not available; inline the lookup.
  // Canonical names as of current App Control for Business documentation.
  // Legacy aliases are included for parsing policies generated by older tooling.
  const map: Record<string, number> = {
    "Enabled:UMCI": 0,
    "Enabled:Boot Menu Protection": 1,
    "Required:WHQL": 2,
    "Enabled:Audit Mode": 3,
    "Disabled:Flight Signing": 4,
    "Enabled:Inherit Default Policy": 5,
    "Enabled:Unsigned System Integrity Policy": 6,
    "Allowed:Debug Policy Augmented": 7,
    "Required:EV Signers": 8,
    "Enabled:Advanced Boot Options Menu": 9,
    "Enabled:Boot Audit on Failure": 10,
    "Disabled:Script Enforcement": 11,
    "Required:Enforce Store Applications": 12,
    "Enabled:Managed Installer": 13,
    "Enabled:Intelligent Security Graph Authorization": 14,
    // Option 15 — canonical name since Windows 10 1903+
    "Enabled:Invalidate EAs on Reboot": 15,
    // Legacy alias: older policies and tooling used this name for option 15
    "Invalidated:EA Not Required": 15,
    "Enabled:Update Policy No Reboot": 16,
    "Enabled:Allow Supplemental Policies": 17,
    "Disabled:Runtime FilePath Rule Protection": 18,
    "Enabled:Dynamic Code Security": 19,
    "Enabled:Revoked Expired As Unsigned": 20,
    // Option 21 — canonical name per cipolicy.xsd OptionType enum
    "Enabled:Developer Mode Dynamic Code Trust": 21,
    // Legacy alias used by some older documentation and tooling
    "Enabled:Developer Unlockable MSA Apps": 21,
    // Option 22 — canonical name per cipolicy.xsd OptionType enum
    "Enabled:Secure Setting Policy": 22,
    // Legacy alias used by some older documentation and tooling
    "Enabled:Strict WHQL Attestation": 22,
  };
  return map[name];
}

function parseEkus(
  root: Record<string, unknown>,
  _diagnostics: ParseDiagnostic[]
): WdacEku[] {
  const ekus: WdacEku[] = [];
  const ekusSection = root["EKUs"] as Record<string, unknown> | undefined;
  if (!ekusSection) return ekus;

  const ekuList = asArray(ekusSection["EKU"] as unknown);
  for (const eku of ekuList) {
    const e = eku as Record<string, unknown>;
    ekus.push({
      id: attr(e, "ID") ?? attr(e, "Id") ?? "",
      friendlyName: attr(e, "FriendlyName"),
      value: attr(e, "Value") ?? "",
    });
  }
  return ekus;
}

// ---------------------------------------------------------------------------
// File rule parsing — discriminated union
// ---------------------------------------------------------------------------

function parseFileRules(
  root: Record<string, unknown>,
  diagnostics: ParseDiagnostic[]
): WdacFileRule[] {
  const rules: WdacFileRule[] = [];
  const fileRulesSection = root["FileRules"] as Record<string, unknown> | undefined;
  if (!fileRulesSection) return rules;

  asArray(fileRulesSection["Allow"]).forEach((r) =>
    rules.push(classifyEffectRule(r as Record<string, unknown>, "Allow", diagnostics))
  );
  asArray(fileRulesSection["Deny"]).forEach((r) =>
    rules.push(classifyEffectRule(r as Record<string, unknown>, "Deny", diagnostics))
  );
  asArray(fileRulesSection["FileAttrib"]).forEach((r) =>
    rules.push(buildFileAttrib(r as Record<string, unknown>, diagnostics))
  );

  return rules;
}

/**
 * Classifies an <Allow> or <Deny> element into the most specific rule kind
 * based on which discriminating fields are present.
 * Priority: hash > path > package > attribute (catch-all)
 */
function classifyEffectRule(
  r: Record<string, unknown>,
  effect: FileRuleEffect,
  diagnostics: ParseDiagnostic[]
): Exclude<WdacFileRule, WdacFileAttrib> {
  const id = attr(r, "ID") ?? attr(r, "Id") ?? "";
  const friendlyName = attr(r, "FriendlyName") ?? undefined;

  if (!id) {
    diagnostics.push(diagWarn("MISSING_FILE_RULE_ID",
      `${effect} rule is missing an ID attribute.`));
  }

  const hash = attr(r, "Hash");
  if (hash) {
    const hashType = (attr(r, "HashType") ?? "SHA256") as HashType;
    const rule: WdacHashRule = { kind: "hash", id, effect, hash, hashType };
    if (friendlyName) rule.friendlyName = friendlyName;
    const fileName = attr(r, "FileName");
    if (fileName) rule.fileName = fileName;
    return rule;
  }

  const filePath = attr(r, "FilePath");
  if (filePath) {
    const rule: WdacPathRule = { kind: "path", id, effect, filePath };
    if (friendlyName) rule.friendlyName = friendlyName;
    const minVer = attr(r, "MinimumFileVersion");
    const maxVer = attr(r, "MaximumFileVersion");
    if (minVer) rule.minimumFileVersion = minVer;
    if (maxVer) rule.maximumFileVersion = maxVer;
    return rule;
  }

  const packageFamilyName = attr(r, "PackageFamilyName");
  if (packageFamilyName) {
    const rule: WdacPackageRule = { kind: "package", id, effect, packageFamilyName };
    if (friendlyName) rule.friendlyName = friendlyName;
    const pkgVer = attr(r, "PackageVersion");
    if (pkgVer) rule.packageVersion = pkgVer;
    return rule;
  }

  // Catch-all: file attribute matching rule (no hash, path, or package)
  diagnostics.push(diagInfo("AMBIGUOUS_FILE_RULE",
    `Rule '${id}' has no Hash, FilePath, or PackageFamilyName — classified as 'attribute' kind.`,
    `${effect}[${id}]`));

  const rule: WdacAttributeRule = { kind: "attribute", id, effect };
  if (friendlyName) rule.friendlyName = friendlyName;
  const fn = attr(r, "FileName");      if (fn)  rule.fileName = fn;
  const inm = attr(r, "InternalName"); if (inm) rule.internalName = inm;
  const fd = attr(r, "FileDescription"); if (fd) rule.fileDescription = fd;
  const pn = attr(r, "ProductName");   if (pn)  rule.productName = pn;
  const minV = attr(r, "MinimumFileVersion"); if (minV) rule.minimumFileVersion = minV;
  const maxV = attr(r, "MaximumFileVersion"); if (maxV) rule.maximumFileVersion = maxV;
  return rule;
}

/** Builds a WdacFileAttrib from a <FileAttrib> element. */
function buildFileAttrib(
  r: Record<string, unknown>,
  diagnostics: ParseDiagnostic[]
): WdacFileAttrib {
  const id = attr(r, "ID") ?? attr(r, "Id") ?? "";
  if (!id) {
    diagnostics.push(diagWarn("MISSING_FILE_RULE_ID", "FileAttrib element is missing an ID attribute."));
  }
  const rule: WdacFileAttrib = { kind: "fileAttrib", id };
  const fn = attr(r, "FriendlyName"); if (fn)  rule.friendlyName = fn;
  const f  = attr(r, "FileName");     if (f)   rule.fileName = f;
  const inm = attr(r, "InternalName"); if (inm) rule.internalName = inm;
  const fd = attr(r, "FileDescription"); if (fd) rule.fileDescription = fd;
  const pn = attr(r, "ProductName");  if (pn)  rule.productName = pn;
  const minV = attr(r, "MinimumFileVersion"); if (minV) rule.minimumFileVersion = minV;
  const maxV = attr(r, "MaximumFileVersion"); if (maxV) rule.maximumFileVersion = maxV;
  return rule;
}

function parseSigners(
  root: Record<string, unknown>,
  diagnostics: ParseDiagnostic[]
): WdacSignerRule[] {
  const signers: WdacSignerRule[] = [];
  const signersSection = root["Signers"] as Record<string, unknown> | undefined;
  if (!signersSection) return signers;

  const signerList = asArray(signersSection["Signer"] as unknown);
  for (const s of signerList) {
    const signerObj = s as Record<string, unknown>;
    const id = attr(signerObj, "ID") ?? attr(signerObj, "Id") ?? "";
    const name = attr(signerObj, "Name") ?? "";

    // CertRoot
    let certRoot: WdacSignerRule["certRoot"];
    const certRootEl = signerObj["CertRoot"] as Record<string, unknown> | undefined;
    if (certRootEl) {
      certRoot = {
        type: (attr(certRootEl, "Type") ?? "TBS") as CertRootType,
        value: attr(certRootEl, "Value") ?? "",
      };
    }

    // CertEKU (array)
    const certEKUList = asArray(signerObj["CertEKU"]);
    const certEKU = certEKUList.map((e) => {
      const ekuEl = e as Record<string, unknown>;
      return { ekuId: attr(ekuEl, "ID") ?? attr(ekuEl, "Id") ?? "" };
    });

    // CertIssuer
    const certIssuerEl = signerObj["CertIssuer"] as Record<string, unknown> | undefined;
    const certIssuer = certIssuerEl ? attr(certIssuerEl, "Value") : undefined;

    // CertPublisher
    const certPublisherEl = signerObj["CertPublisher"] as Record<string, unknown> | undefined;
    const certPublisher = certPublisherEl ? attr(certPublisherEl, "Value") : undefined;

    // CertOemID
    const certOemIdEl = signerObj["CertOemID"] as Record<string, unknown> | undefined;
    const certOemID = certOemIdEl ? attr(certOemIdEl, "Value") : undefined;

    // FileAttribRef (array)
    const fileAttribRefList = asArray(signerObj["FileAttribRef"]);
    const fileAttribRefs = fileAttribRefList
      .map((r) => attr(r as Record<string, unknown>, "RuleID") ?? attr(r as Record<string, unknown>, "RuleId") ?? "")
      .filter(Boolean);

    if (!id) diagnostics.push(diagWarn("MISSING_SIGNER_ID", `Signer '${name}' is missing an ID attribute.`));

    signers.push({
      id,
      name,
      ...(certRoot && { certRoot }),
      ...(certEKU.length > 0 && { certEKU }),
      ...(certIssuer && { certIssuer }),
      ...(certPublisher && { certPublisher }),
      ...(certOemID && { certOemID }),
      ...(fileAttribRefs.length > 0 && { fileAttribRefs }),
    });
  }

  return signers;
}

function parseSigningScenarios(
  root: Record<string, unknown>,
  diagnostics: ParseDiagnostic[]
): WdacSigningScenario[] {
  const scenarios: WdacSigningScenario[] = [];
  const ssSection = root["SigningScenarios"] as Record<string, unknown> | undefined;
  if (!ssSection) return scenarios;

  const scenarioList = asArray(ssSection["SigningScenario"] as unknown);
  for (const ss of scenarioList) {
    const ssObj = ss as Record<string, unknown>;
    const valueStr = attr(ssObj, "Value") ?? "12";
    const value = parseInt(valueStr, 10) as SigningScenarioValue;
    const id = attr(ssObj, "ID") ?? attr(ssObj, "Id") ?? String(value);
    const minHashVersion = attr(ssObj, "MinimumHashAlgorithm");

    if (value !== 131 && value !== 12) {
      diagnostics.push(diagWarn("UNEXPECTED_SCENARIO_VALUE",
        `Unexpected SigningScenario Value '${value}'; expected 131 (kernel) or 12 (user mode).`));
    }

    // ProductSigners > AllowedSigners > AllowedSigner[]
    const allowedSigners: AllowedSigner[] = [];
    const deniedSigners: DeniedSigner[] = [];
    const fileRuleRefs: string[] = [];

    const productSigners = ssObj["ProductSigners"] as Record<string, unknown> | undefined;
    if (productSigners) {
      const allowedSection = productSigners["AllowedSigners"] as Record<string, unknown> | undefined;
      if (allowedSection) {
        const asList = asArray(allowedSection["AllowedSigner"]);
        for (const as_ of asList) {
          const asObj = as_ as Record<string, unknown>;
          const signerId = attr(asObj, "SignerId") ?? attr(asObj, "SignerID") ?? "";
          const exceptDenyList = asArray(asObj["ExceptDenyRule"]);
          const exceptDenyRuleIds = exceptDenyList
            .map((e) => attr(e as Record<string, unknown>, "DenyRuleID") ?? attr(e as Record<string, unknown>, "DenyRuleId") ?? "")
            .filter(Boolean);
          allowedSigners.push({
            signerId,
            ...(exceptDenyRuleIds.length > 0 && { exceptDenyRuleIds }),
          });
        }
      }

      const deniedSection = productSigners["DeniedSigners"] as Record<string, unknown> | undefined;
      if (deniedSection) {
        const dsList = asArray(deniedSection["DeniedSigner"]);
        for (const ds of dsList) {
          const dsObj = ds as Record<string, unknown>;
          const signerId = attr(dsObj, "SignerId") ?? attr(dsObj, "SignerID") ?? "";
          const exceptAllowList = asArray(dsObj["ExceptAllowRule"]);
          const exceptAllowRuleIds = exceptAllowList
            .map((e) => attr(e as Record<string, unknown>, "AllowRuleID") ?? attr(e as Record<string, unknown>, "AllowRuleId") ?? "")
            .filter(Boolean);
          deniedSigners.push({
            signerId,
            ...(exceptAllowRuleIds.length > 0 && { exceptAllowRuleIds }),
          });
        }
      }

      const fileRulesSection = productSigners["FileRulesRef"] as Record<string, unknown> | undefined;
      if (fileRulesSection) {
        const frList = asArray(fileRulesSection["FileRuleRef"]);
        for (const fr of frList) {
          const frObj = fr as Record<string, unknown>;
          const ruleId = attr(frObj, "RuleID") ?? attr(frObj, "RuleId") ?? "";
          if (ruleId) fileRuleRefs.push(ruleId);
        }
      }
    }

    scenarios.push({
      value,
      id,
      ...(minHashVersion && { minHashVersion }),
      allowedSigners,
      deniedSigners,
      fileRuleRefs,
    });
  }

  return scenarios;
}

function parseUpdatePolicySigners(root: Record<string, unknown>): string[] {
  const section = root["UpdatePolicySigners"] as Record<string, unknown> | undefined;
  if (!section) return [];
  return asArray(section["UpdatePolicySigner"])
    .map((u) => attr(u as Record<string, unknown>, "SignerId") ?? attr(u as Record<string, unknown>, "SignerID") ?? "")
    .filter(Boolean);
}

/**
 * Extracts a named field from the <Settings> block:
 *   <Setting Provider="PolicyInfo" Key="Information" ValueName="{valueName}">
 *     <Value><String>...</String></Value>
 *   </Setting>
 */
function parseSettingsField(root: Record<string, unknown>, valueName: string): string | undefined {
  const settingsSection = root["Settings"] as Record<string, unknown> | undefined;
  if (!settingsSection) return undefined;

  const settingList = asArray(settingsSection["Setting"] as unknown);
  for (const s of settingList) {
    const sObj = s as Record<string, unknown>;
    const provider = attr(sObj, "Provider");
    const key = attr(sObj, "Key");
    const vn = attr(sObj, "ValueName");
    if (provider === "PolicyInfo" && key === "Information" && vn === valueName) {
      const valueEl = sObj["Value"] as Record<string, unknown> | undefined;
      if (valueEl) {
        const str = valueEl["String"];
        if (str != null) return String(str);
      }
    }
  }
  return undefined;
}

function parseCiSigners(root: Record<string, unknown>): string[] {
  const section = root["CiSigners"] as Record<string, unknown> | undefined;
  if (!section) return [];
  return asArray(section["CiSigner"])
    .map((c) => attr(c as Record<string, unknown>, "SignerId") ?? attr(c as Record<string, unknown>, "SignerID") ?? "")
    .filter(Boolean);
}

// ---------------------------------------------------------------------------
// Rule Collection Index
// ---------------------------------------------------------------------------

function buildIndex(policy: WdacPolicy, diagnostics: ParseDiagnostic[]): RuleCollectionIndex {
  const fileRulesById = new Map(policy.fileRules.map((r) => [r.id, r]));
  const signersById   = new Map(policy.signers.map((s) => [s.id, s]));
  const ekusById      = new Map(policy.ekus.map((e) => [e.id, e]));

  const signerIdsByScenario   = new Map<SigningScenarioValue, Set<string>>();
  const fileRuleIdsByScenario = new Map<SigningScenarioValue, Set<string>>();
  const fileAttribsBySignerId = new Map<string, WdacFileAttrib[]>();
  const unresolvedSignerRefs:   RuleCollectionIndex["unresolvedSignerRefs"]   = [];
  const unresolvedFileRuleRefs: RuleCollectionIndex["unresolvedFileRuleRefs"] = [];

  for (const scenario of policy.signingScenarios) {
    const signerSet   = new Set<string>();
    const fileRuleSet = new Set<string>();
    signerIdsByScenario.set(scenario.value, signerSet);
    fileRuleIdsByScenario.set(scenario.value, fileRuleSet);

    for (const { signerId } of [...scenario.allowedSigners, ...scenario.deniedSigners]) {
      if (!signersById.has(signerId)) {
        unresolvedSignerRefs.push({ signerRef: signerId, inScenario: scenario.value });
        diagnostics.push(diagWarn("UNRESOLVED_SIGNER_REF",
          `Signer reference '${signerId}' in scenario ${scenario.value} has no matching <Signer>.`));
      } else {
        signerSet.add(signerId);
      }
    }

    for (const refId of scenario.fileRuleRefs) {
      if (!fileRulesById.has(refId)) {
        unresolvedFileRuleRefs.push({ ruleRef: refId, context: `scenario ${scenario.value}` });
        diagnostics.push(diagWarn("UNRESOLVED_FILE_RULE_REF",
          `FileRuleRef '${refId}' in scenario ${scenario.value} has no matching file rule.`));
      } else {
        fileRuleSet.add(refId);
      }
    }
  }

  for (const signer of policy.signers) {
    const attribs: WdacFileAttrib[] = [];
    for (const refId of signer.fileAttribRefs ?? []) {
      const rule = fileRulesById.get(refId);
      if (!rule || rule.kind !== "fileAttrib") {
        unresolvedFileRuleRefs.push({ ruleRef: refId, context: `signer ${signer.id}` });
        diagnostics.push(diagWarn("UNRESOLVED_FILE_ATTRIB_REF",
          `Signer '${signer.name}' references FileAttrib '${refId}' which does not exist.`));
      } else {
        attribs.push(rule);
      }
    }
    if (attribs.length > 0) fileAttribsBySignerId.set(signer.id, attribs);
  }

  return {
    fileRulesById,
    signersById,
    ekusById,
    signerIdsByScenario,
    fileRuleIdsByScenario,
    fileAttribsBySignerId,
    unresolvedSignerRefs,
    unresolvedFileRuleRefs,
  };
}
