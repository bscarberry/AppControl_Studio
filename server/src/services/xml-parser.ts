/**
 * WDAC XML Parser
 *
 * Converts a WDAC SiPolicy XML document into a normalized WdacPolicy object.
 *
 * The WDAC schema is defined in cipolicy.xsd (Windows SDK).
 * This parser follows the documented structure at:
 * https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune
 */

import { XMLParser } from "fast-xml-parser";
import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  WdacSigningScenario,
  WdacEku,
  PolicyRuleOption,
  PolicyRuleOptionNumber,
  AllowedSigner,
  DeniedSigner,
  SigningScenarioValue,
  FileRuleType,
  HashType,
  CertRootType,
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
// Main Parser
// ---------------------------------------------------------------------------

export interface ParseResult {
  policy: WdacPolicy;
  warnings: string[];
}

export function parseWdacXml(xmlContent: string, fileName?: string): ParseResult {
  const warnings: string[] = [];

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
  const friendlyName = attr(root, "FriendlyName") ?? attr(root, "friendlyName");
  const versionEx = attr(root, "VersionEx") ?? attr(root, "versionEx") ?? "10.0.0.0";
  const platformId = normalizeGuid(attr(root, "PlatformID") ?? attr(root, "platformId"));
  const hvciRaw = attr(root, "HvciOptions") ?? attr(root, "hvciOptions");
  const hvciOptions = hvciRaw !== undefined ? parseInt(hvciRaw, 10) : undefined;

  const policyType = basePolicyId ? "Supplemental" : "Base";

  // --- Policy Rule Options ---
  const options = parsePolicyRuleOptions(root, warnings);

  // --- EKUs ---
  const ekus = parseEkus(root, warnings);

  // --- File Rules ---
  const fileRules = parseFileRules(root, warnings);

  // --- Signers ---
  const signers = parseSigners(root, warnings);

  // --- Signing Scenarios ---
  const signingScenarios = parseSigningScenarios(root, warnings);

  // --- Update Policy Signers ---
  const updatePolicySigners = parseUpdatePolicySigners(root);

  // --- CI Signers ---
  const ciSigners = parseCiSigners(root);

  const policy: WdacPolicy = {
    policyId,
    basePolicyId,
    policyTypeId,
    friendlyName,
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

  return { policy, warnings };
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

function parsePolicyRuleOptions(
  root: Record<string, unknown>,
  warnings: string[]
): PolicyRuleOption[] {
  const options: PolicyRuleOption[] = [];
  const rulesSection = root["Rules"] as Record<string, unknown> | undefined;
  if (!rulesSection) return options;

  const rules = asArray(rulesSection["Rule"] as unknown);
  for (const rule of rules) {
    const ruleObj = rule as Record<string, unknown>;
    const option = ruleObj["Option"] as Record<string, unknown> | string | undefined;
    if (!option) {
      warnings.push("Found <Rule> without <Option> child; skipping.");
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
      warnings.push(`Unrecognized Option format: '${optionText}'; skipping.`);
      continue;
    }

    // Map option name to number by reverse-looking in POLICY_RULE_OPTIONS
    const optionName = `${match[1]}:${match[2]}`;
    const optionNumber = findOptionNumber(optionName);
    if (optionNumber === undefined) {
      warnings.push(`Unknown policy rule option '${optionText}'; recording as raw value.`);
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
  // Dynamic import not available; inline the lookup
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
    "Invalidated:EA Not Required": 15,
    "Enabled:Update Policy No Reboot": 16,
    "Enabled:Allow Supplemental Policies": 17,
    "Disabled:Runtime FilePath Rule Protection": 18,
    "Enabled:Dynamic Code Security": 19,
    "Enabled:Revoked Expired As Unsigned": 20,
    "Enabled:Developer Unlockable MSA Apps": 21,
    "Enabled:Strict WHQL Attestation": 22,
  };
  return map[name];
}

function parseEkus(
  root: Record<string, unknown>,
  _warnings: string[]
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

function parseFileRules(
  root: Record<string, unknown>,
  warnings: string[]
): WdacFileRule[] {
  const rules: WdacFileRule[] = [];
  const fileRulesSection = root["FileRules"] as Record<string, unknown> | undefined;
  if (!fileRulesSection) return rules;

  const parseRule = (ruleRaw: unknown, type: FileRuleType) => {
    const r = ruleRaw as Record<string, unknown>;
    const id = attr(r, "ID") ?? attr(r, "Id") ?? "";
    const rule: WdacFileRule = {
      id,
      type,
      friendlyName: attr(r, "FriendlyName"),
      fileName: attr(r, "FileName"),
      internalName: attr(r, "InternalName"),
      fileDescription: attr(r, "FileDescription"),
      productName: attr(r, "ProductName"),
      minimumFileVersion: attr(r, "MinimumFileVersion"),
      maximumFileVersion: attr(r, "MaximumFileVersion"),
      filePath: attr(r, "FilePath"),
      packageFamilyName: attr(r, "PackageFamilyName"),
      packageVersion: attr(r, "PackageVersion"),
      hash: attr(r, "Hash"),
      hashType: attr(r, "HashType") as HashType | undefined,
    };
    if (type === "FileAttrib") rule.isFileAttrib = true;
    // Remove undefined keys for cleaner objects
    Object.keys(rule).forEach((k) => {
      if (rule[k as keyof WdacFileRule] === undefined) {
        delete (rule as Record<string, unknown>)[k];
      }
    });
    if (!id) {
      warnings.push(`${type} rule missing ID attribute; rule will have empty ID.`);
    }
    rules.push(rule);
  };

  asArray(fileRulesSection["Allow"]).forEach((r) => parseRule(r, "Allow"));
  asArray(fileRulesSection["Deny"]).forEach((r) => parseRule(r, "Deny"));
  asArray(fileRulesSection["FileAttrib"]).forEach((r) => parseRule(r, "FileAttrib"));

  return rules;
}

function parseSigners(
  root: Record<string, unknown>,
  warnings: string[]
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

    if (!id) warnings.push(`Signer '${name}' missing ID attribute.`);

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
  warnings: string[]
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
      warnings.push(`Unexpected SigningScenario Value '${value}'; expected 131 (kernel) or 12 (user mode).`);
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

function parseCiSigners(root: Record<string, unknown>): string[] {
  const section = root["CiSigners"] as Record<string, unknown> | undefined;
  if (!section) return [];
  return asArray(section["CiSigner"])
    .map((c) => attr(c as Record<string, unknown>, "SignerId") ?? attr(c as Record<string, unknown>, "SignerID") ?? "")
    .filter(Boolean);
}
