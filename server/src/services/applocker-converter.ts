/**
 * AppLocker → WDAC Policy Converter
 *
 * Converts an AppLocker XML policy (exported via Get-AppLockerPolicy -Xml)
 * into a WDAC/App Control policy.
 *
 * Supported AppLocker rule types and their WDAC equivalents:
 *
 *   FileHashRule       → WdacHashRule    (SHA-256 preferred, SHA-1 fallback)
 *   FilePathRule       → WdacPathRule    (macros translated to the WDAC set)
 *   PackagedAppRule    → WdacPackageRule (Package Family Name)
 *   FilePublisherRule  → SKIPPED with guidance. WDAC signer rules require a
 *                        certificate TBS hash (<CertRoot> is mandatory in
 *                        cipolicy.xsd); AppLocker publisher conditions carry
 *                        only the subject DN, so no valid signer can be built.
 *
 * All four AppLocker rule collection types are handled:
 *   Exe, Dll, Script, Msi → all mapped to user-mode signing scenario (12)
 *
 * Important limitations documented in Microsoft's own guidance:
 *   - Generated policies SHOULD be merged with a base template (Default Windows,
 *     Allow Microsoft) before deployment — standalone converted policies typically
 *     lack Windows authorization rules and can cause boot issues.
 *   - Deny rules are skipped by default (they can cause lockouts if misconfigured).
 */

import crypto from "crypto";
import { XMLParser } from "fast-xml-parser";
import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  WdacSigningScenario,
  AllowedSigner,
} from "@appcontrol/shared";
import { generateWdacXml } from "./xml-generator.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function shortHex(): string {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}

/**
 * Translate an AppLocker path to WDAC path rule(s).
 *
 * WDAC's kernel path engine only expands %OSDRIVE%, %WINDIR%, and %SYSTEM32%
 * (see WDAC Policy Wizard Helper.cs). AppLocker's %PROGRAMFILES% has no WDAC
 * equivalent macro and covers BOTH Program Files directories, so it expands
 * to two %OSDRIVE%-anchored rules. %REMOVABLE% and %HOT% have no WDAC
 * equivalent at all and yield no rules.
 */
function translatePath(appLockerPath: string): { paths: string[]; note?: string } {
  const base = appLockerPath
    .replace(/\*\*/g, "*") // AppLocker uses ** for recursive; WDAC uses *
    .trim();

  if (/%REMOVABLE%|%HOT%/i.test(base)) {
    return {
      paths: [],
      note: "AppLocker %REMOVABLE%/%HOT% locations have no WDAC equivalent — rule skipped.",
    };
  }

  if (/%PROGRAMFILES%/i.test(base)) {
    return {
      paths: [
        base.replace(/%PROGRAMFILES%/gi, "%OSDRIVE%\\Program Files"),
        base.replace(/%PROGRAMFILES%/gi, "%OSDRIVE%\\Program Files (x86)"),
      ],
      note: "%PROGRAMFILES% expanded to both Program Files directories (WDAC has no such macro).",
    };
  }

  return {
    paths: [
      base
        .replace(/%WINDIR%/gi, "%WINDIR%")
        .replace(/%SYSTEM32%/gi, "%SYSTEM32%")
        .replace(/%OSDRIVE%/gi, "%OSDRIVE%"),
    ],
  };
}

/** Coerce to array if single item */
function asArray<T>(val: T | T[] | undefined): T[] {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

// ---------------------------------------------------------------------------
// AppLocker XML types (minimal, what we need to parse)
// ---------------------------------------------------------------------------

interface ALCondition {
  PublisherName?: string;
  ProductName?: string;
  BinaryName?: string;
  BinaryVersionRange?: { LowSection?: string; HighSection?: string };
}

interface ALFileHash {
  Type?: string;
  Data?: string;
  SourceFileName?: string;
}

interface ALPublisherRule {
  Id?: string;
  Name?: string;
  Action?: string;
  Conditions?: { FilePublisherCondition?: ALCondition | ALCondition[] };
}

interface ALHashRule {
  Id?: string;
  Name?: string;
  Action?: string;
  Conditions?: { FileHashCondition?: { FileHash?: ALFileHash | ALFileHash[] } };
}

interface ALPathRule {
  Id?: string;
  Name?: string;
  Action?: string;
  Conditions?: { FilePathCondition?: { Path?: string } };
}

interface ALPackagedRule {
  Id?: string;
  Name?: string;
  Action?: string;
  Conditions?: {
    FilePublisherCondition?: { PackageVersion?: string; PublisherCondition?: ALCondition };
  };
}

interface ALRuleCollection {
  Type?: string;
  EnforcementMode?: string;
  FilePublisherRule?: ALPublisherRule | ALPublisherRule[];
  FileHashRule?: ALHashRule | ALHashRule[];
  FilePathRule?: ALPathRule | ALPathRule[];
  PackagedAppRule?: ALPackagedRule | ALPackagedRule[];
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "",
  isArray: (name) => ["RuleCollection", "FilePublisherRule", "FileHashRule", "FilePathRule", "PackagedAppRule", "FileHash"].includes(name),
  parseTagValue: false,
  trimValues: true,
});

export interface ConvertResult {
  policy: WdacPolicy;
  xml: string;
  log: string[];
  stats: {
    publisherRules: number;
    hashRules: number;
    pathRules: number;
    packageRules: number;
    skippedRules: number;
  };
}

export function convertAppLockerToWdac(
  appLockerXml: string,
  includeDenyRules = false
): ConvertResult {
  const log: string[] = [];
  const stats = { publisherRules: 0, hashRules: 0, pathRules: 0, packageRules: 0, skippedRules: 0 };

  let parsed: { AppLockerPolicy?: { RuleCollection?: ALRuleCollection[] } };
  try {
    parsed = xmlParser.parse(appLockerXml);
  } catch (e) {
    throw new Error(`Failed to parse AppLocker XML: ${(e as Error).message}`);
  }

  const collections = asArray(parsed?.AppLockerPolicy?.RuleCollection);
  if (collections.length === 0) {
    throw new Error("No RuleCollection elements found. Is this a valid AppLocker policy XML?");
  }

  log.push(`Found ${collections.length} rule collection(s).`);

  const fileRules: WdacFileRule[] = [];
  const signers: WdacSignerRule[] = [];
  const allowedSignerIds: string[] = []; // for user-mode scenario

  // ---- Process each collection ----
  for (const col of collections) {
    const colType = col.Type ?? "Unknown";
    log.push(`Processing collection: ${colType} (EnforcementMode: ${col.EnforcementMode ?? "NotConfigured"})`);

    // -- FilePublisherRule → WdacSignerRule --
    for (const rule of asArray(col.FilePublisherRule)) {
      const action = (rule.Action ?? "Allow").toLowerCase();
      if (action === "deny" && !includeDenyRules) {
        log.push(`  SKIP deny rule (FilePublisher): "${rule.Name}"`);
        stats.skippedRules++;
        continue;
      }

      const cond = asArray(rule.Conditions?.FilePublisherCondition)[0];
      if (!cond) { stats.skippedRules++; continue; }

      const publisherName = cond.PublisherName ?? "";
      const binaryName = (cond.BinaryName ?? "").replace(/\*/g, "").trim();
      const lowVersion = cond.BinaryVersionRange?.LowSection ?? "";
      const hasFileScope = binaryName.length > 0 && binaryName !== "*";

      // WDAC signer rules must be anchored by a certificate TBS hash
      // (<CertRoot>) — cipolicy.xsd requires it, and CI cannot verify a trust
      // chain from a publisher name alone. AppLocker publisher conditions
      // carry only the subject DN, so a faithful, valid conversion is not
      // possible. Converting to a bare FileName/ProductName allow rule would
      // be worse: version-resource metadata is attacker-controlled on
      // unsigned files. Fail closed and tell the user how to recreate the
      // rule properly.
      log.push(
        `  SKIP publisher rule "${rule.Name ?? publisherName}": AppLocker publisher ` +
        `conditions have no certificate TBS hash, which WDAC signer rules require ` +
        `(CertRoot). Recreate this rule from a signed copy of the file ` +
        `(WDAC Wizard / New-CIPolicyRule -Level Publisher) or from CodeIntegrity ` +
        `events with 3089 signature data.` +
        (hasFileScope ? ` (was scoped to "${binaryName}" >= ${lowVersion || "any"})` : "")
      );
      stats.skippedRules++;
    }

    // -- FileHashRule → WdacHashRule --
    for (const rule of asArray(col.FileHashRule)) {
      const action = (rule.Action ?? "Allow").toLowerCase();
      if (action === "deny" && !includeDenyRules) {
        log.push(`  SKIP deny rule (FileHash): "${rule.Name}"`);
        stats.skippedRules++;
        continue;
      }

      const hashes = asArray(rule.Conditions?.FileHashCondition?.FileHash);
      for (const h of hashes) {
        const hashType = (h.Type ?? "SHA256").toUpperCase();
        const hashData = (h.Data ?? "").replace(/^0x/i, "");
        if (!hashData) { stats.skippedRules++; continue; }

        const ruleId = `${action === "deny" ? "ID_DENY" : "ID_ALLOW"}_A_${shortHex()}`;
        fileRules.push({
          kind: "hash",
          id: ruleId,
          effect: action === "deny" ? "Deny" : "Allow",
          friendlyName: rule.Name ?? h.SourceFileName ?? ruleId,
          hash: hashData,
          hashType: hashType === "SHA256" ? "SHA256" : "SHA1",
          fileName: h.SourceFileName,
        });
        stats.hashRules++;
        log.push(`  + Hash ${ruleId} (${hashType}): "${h.SourceFileName ?? ""}"`);
      }
    }

    // -- FilePathRule → WdacPathRule --
    for (const rule of asArray(col.FilePathRule)) {
      const action = (rule.Action ?? "Allow").toLowerCase();
      if (action === "deny" && !includeDenyRules) {
        log.push(`  SKIP deny rule (FilePath): "${rule.Name}"`);
        stats.skippedRules++;
        continue;
      }

      const rawPath = rule.Conditions?.FilePathCondition?.Path ?? "";
      if (!rawPath) { stats.skippedRules++; continue; }

      const { paths, note } = translatePath(rawPath);
      if (note) log.push(`  NOTE (${rule.Name ?? rawPath}): ${note}`);
      if (paths.length === 0) { stats.skippedRules++; continue; }

      const isFolder = rawPath.endsWith("\\*") || rawPath.endsWith("/*");
      for (const translatedPath of paths) {
        const ruleId = `${action === "deny" ? "ID_DENY" : "ID_ALLOW"}_P_${shortHex()}`;
        fileRules.push({
          kind: "path",
          id: ruleId,
          effect: action === "deny" ? "Deny" : "Allow",
          friendlyName: rule.Name ?? ruleId,
          filePath: translatedPath,
          isFolder,
        });
        stats.pathRules++;
        log.push(`  + Path ${ruleId} (${isFolder ? "folder" : "file"}): "${translatedPath}"`);
      }
    }

    // -- PackagedAppRule → WdacPackageRule --
    for (const rule of asArray(col.PackagedAppRule)) {
      const action = (rule.Action ?? "Allow").toLowerCase();
      if (action === "deny" && !includeDenyRules) {
        log.push(`  SKIP deny rule (PackagedApp): "${rule.Name}"`);
        stats.skippedRules++;
        continue;
      }

      // PackagedAppRule conditions are complex — try to extract PFN
      const pfn = (rule as unknown as Record<string, unknown>)["PackageFamilyName"] as string | undefined
        ?? (rule as unknown as Record<string, unknown>)["PackageId"] as string | undefined;
      if (!pfn) { stats.skippedRules++; continue; }

      const ruleId = `${action === "deny" ? "ID_DENY" : "ID_ALLOW"}_K_${shortHex()}`;
      fileRules.push({
        kind: "package",
        id: ruleId,
        effect: action === "deny" ? "Deny" : "Allow",
        friendlyName: rule.Name ?? pfn,
        packageFamilyName: pfn,
      });
      stats.packageRules++;
      log.push(`  + Package ${ruleId}: "${pfn}"`);
    }
  }

  // ---- Build signing scenario (user mode only — AppLocker is user-mode) ----
  const allowedSigners: AllowedSigner[] = allowedSignerIds.map((id) => ({ signerId: id }));

  // Hash/path/package rules → fileRuleRefs; fileAttrib descriptors are only
  // referenced from signers and never appear in FileRulesRef.
  const directRuleRefs = fileRules
    .filter((r) => r.kind !== "fileAttrib")
    .map((r) => r.id);

  const scenarios: WdacSigningScenario[] = [
    {
      value: 12,
      id: "ID_SIGNINGSCENARIO_WINDOWS",
      allowedSigners,
      deniedSigners: [],
      fileRuleRefs: directRuleRefs,
    },
  ];

  const merged: WdacPolicy = {
    // Bare GUID — the XML generator adds the surrounding braces.
    policyId: crypto.randomUUID().toUpperCase(),
    policyType: "Base",
    versionEx: "10.0.0.0",
    friendlyName: "Converted from AppLocker Policy",
    options: [
      { value: 0, enabled: true },  // UMCI
      { value: 3, enabled: true },  // Audit Mode (safe default)
      { value: 17, enabled: true }, // Allow Supplemental Policies
    ],
    ekus: [],
    fileRules,
    signers,
    signingScenarios: scenarios,
    updatePolicySigners: [],
    ciSigners: [],
  };

  const xml = generateWdacXml(merged);

  const totalConverted = stats.publisherRules + stats.hashRules + stats.pathRules + stats.packageRules;
  log.push(
    `Conversion complete. ${totalConverted} rules converted, ${stats.skippedRules} skipped.`
  );
  log.push(
    "⚠ IMPORTANT: Merge this policy with a base template (Default Windows / Allow Microsoft) " +
    "before deployment to avoid locking out Windows components."
  );

  return { policy: merged, xml, log, stats };
}
