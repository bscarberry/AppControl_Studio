/**
 * WDAC Policy Builder
 *
 * Creates a new WDAC policy from parsed CodeIntegrity events.
 * Generates the minimum required rules to allow the observed files.
 *
 * Rule-type precedence (best to broadest):
 *   Publisher (CertRoot TBS + CertPublisher)  — survives binary updates
 *   FileAttrib (OriginalFileName)             — survives version updates, requires publisher scoping
 *   Hash (SHA256FlatHash)                     — exact binary match
 *   Path (FilePath)                           — weakest; bypass risk
 */

import { v4 as uuidv4 } from "uuid";
import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  WdacSigningScenario,
  PolicyRuleOption,
  AllowedSigner,
} from "@appcontrol/shared";
import type { ParsedCiEvent, FileRuleType, FileRuleSelection } from "@appcontrol/shared";
import type { CreatePolicyFromEventsRequest } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Policy Templates
// ---------------------------------------------------------------------------

type TemplateName = NonNullable<CreatePolicyFromEventsRequest["template"]>;

/**
 * Options for a Supplemental policy (matches WDAC Wizard output).
 * Supplemental policies must NOT include Enabled:UMCI (option 0) — that is
 * inherited from the base policy. They require:
 *   6  Enabled:Unsigned System Integrity Policy
 *   5  Enabled:Inherit Default Policy
 */
function getSupplementalOptions(): PolicyRuleOption[] {
  return [
    { value: 6, enabled: true }, // Enabled:Unsigned System Integrity Policy
    { value: 5, enabled: true }, // Enabled:Inherit Default Policy
  ];
}

function getBaseTemplateOptions(template: TemplateName): PolicyRuleOption[] {
  const base: PolicyRuleOption[] = [
    { value: 0, enabled: true }, // UMCI
    { value: 6, enabled: true }, // Unsigned system integrity policy
  ];

  switch (template) {
    case "default-windows":
      return [
        ...base,
        { value: 2, enabled: true },  // WHQL required
      ];
    case "allow-microsoft":
      return [...base];
    case "deny-by-default":
      return [
        { value: 0, enabled: true },
        { value: 2, enabled: true },
        { value: 8, enabled: true }, // EV signers required
      ];
    case "blank":
    default:
      return [
        { value: 0, enabled: true },
        { value: 6, enabled: true },
      ];
  }
}

/**
 * Extract the GUID of the most common enforcing base policy from the events.
 * CI events carry the PolicyGuid of the policy that triggered the block/audit.
 * We pick the most-frequently-occurring non-empty GUID as the default base.
 */
function detectBasePolicyId(events: ParsedCiEvent[]): string | undefined {
  const counts = new Map<string, number>();
  for (const ev of events) {
    const guid = ev.policyGuid;
    if (guid && guid.length > 0) {
      counts.set(guid, (counts.get(guid) ?? 0) + 1);
    }
  }
  if (counts.size === 0) return undefined;
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
}

/**
 * Build the signer Name attribute to match WDAC Wizard format:
 *   "Allow CN = <publisher CN> issued by <issuer name>"
 * Falls back gracefully when issuer info is unavailable.
 */
function buildSignerName(publisherName?: string, issuerName?: string): string {
  if (!publisherName) return "Unknown Publisher";
  // Extract CN value from a full subject DN like "CN=Notepad++,O=...,L=..."
  const cn = publisherName.match(/^CN=([^,]+)/i)?.[1] ?? publisherName;
  if (issuerName) {
    // Extract CN from issuer DN too — matches WDAC Wizard format
    const issuerCn = issuerName.match(/^CN=([^,]+)/i)?.[1] ?? issuerName;
    return `Allow CN = ${cn} issued by ${issuerCn}`;
  }
  return `Allow CN = ${cn}`;
}

// ---------------------------------------------------------------------------
// Unique-file grouping
// ---------------------------------------------------------------------------

interface UniqueFile {
  /** Stable key for deduplication: sha256FlatHash if available, else filePath */
  key: string;
  events: ParsedCiEvent[];
  /** Best representative event (one with the most data) */
  best: ParsedCiEvent;
}

function groupUniqueFiles(events: ParsedCiEvent[]): UniqueFile[] {
  const map = new Map<string, UniqueFile>();

  for (const event of events) {
    const key = event.sha256FlatHash ?? event.sha256Hash ?? event.filePath.toLowerCase();
    const existing = map.get(key);
    if (existing) {
      existing.events.push(event);
      // Prefer the event with the most data (has publisher info, attributes, etc.)
      const score = (e: ParsedCiEvent) =>
        (e.signerInfo?.publisherTbsHash ? 4 : 0) +
        (e.signerInfo?.publisherName ? 2 : 0) +
        (e.originalFileName ? 1 : 0) +
        (e.sha256FlatHash ? 1 : 0);
      if (score(event) > score(existing.best)) existing.best = event;
    } else {
      map.set(key, { key, events: [event], best: event });
    }
  }

  return Array.from(map.values());
}

// ---------------------------------------------------------------------------
// Rule type resolution
// ---------------------------------------------------------------------------

function resolveRuleType(
  file: UniqueFile,
  ruleSelectionMap: Map<string, FileRuleType>,
  defaultRuleType: FileRuleType,
  preferPublisherRules: boolean,
  includePathRules: boolean
): FileRuleType {
  // Per-file override takes precedence
  const override = ruleSelectionMap.get(file.key);
  if (override) return override;

  // Legacy global toggles
  if (preferPublisherRules && file.best.signerInfo?.publisherTbsHash) {
    return "publisher";
  }

  if (defaultRuleType !== "hash") return defaultRuleType;

  if (file.best.sha256FlatHash ?? file.best.sha256Hash) return "hash";
  if (includePathRules) return "path";
  return "skip";
}

// ---------------------------------------------------------------------------
// Main builder
// ---------------------------------------------------------------------------

export function buildPolicyFromEvents(
  req: CreatePolicyFromEventsRequest
): { policy: WdacPolicy; buildLog: string[] } {
  const log: string[] = [];
  const policyId = uuidv4().toUpperCase();

  // Determine policy type — default to Supplemental when building from CI events
  // (mirrors WDAC Wizard behavior: event-log policies are supplemental by default)
  const isSupplemental = (req.policyType ?? "Supplemental") === "Supplemental";

  // Resolve base policy GUID: use explicit override, then auto-detect from events
  const basePolicyId = isSupplemental
    ? (req.basePolicyId?.replace(/^\{|\}$/g, "").toUpperCase() || detectBasePolicyId(req.events))
    : undefined;

  log.push(`Building policy '${req.policyName}' from ${req.events.length} events.`);
  log.push(`Type: ${isSupplemental ? "Supplemental" : "Base"}`);
  if (basePolicyId) log.push(`Base Policy ID: ${basePolicyId}`);
  log.push(`Template: ${req.template ?? "blank"}`);
  log.push(`Mode: ${req.auditMode ? "Audit" : "Enforcement"}`);

  // Policy options differ for supplemental vs base
  const options = isSupplemental
    ? getSupplementalOptions()
    : getBaseTemplateOptions(req.template ?? "blank");

  // Base policies can start in audit mode; supplemental inherits the base's mode
  if (!isSupplemental && req.auditMode) {
    const auditIdx = options.findIndex((o) => o.value === 3);
    if (auditIdx >= 0) options[auditIdx].enabled = true;
    else options.push({ value: 3, enabled: true });
    log.push("Added Option 3: Audit Mode");
  }

  // Build per-file rule selection map
  const ruleSelectionMap = new Map<string, FileRuleType>();
  for (const sel of req.ruleSelections ?? []) {
    ruleSelectionMap.set(sel.fileKey, sel.ruleType);
  }

  const defaultRuleType: FileRuleType = req.defaultRuleType ?? "hash";

  // Group events by unique file
  const uniqueFiles = groupUniqueFiles(req.events);
  log.push(`Unique files: ${uniqueFiles.length}`);

  const fileRules: WdacFileRule[] = [];
  const signers: WdacSignerRule[] = [];
  const signerFpMap = new Map<string, string>(); // fingerprint → signer ID
  const allowedSignerIds: string[] = [];
  const fileRuleIds: string[] = [];
  const seenHashes = new Set<string>();
  const seenPaths = new Set<string>();
  const seenFileNames = new Set<string>();

  for (const file of uniqueFiles) {
    const { best } = file;
    const ruleType = resolveRuleType(
      file,
      ruleSelectionMap,
      defaultRuleType,
      req.preferPublisherRules,
      req.includePathRules
    );

    if (ruleType === "skip") {
      log.push(`Skipped: ${best.filePath}`);
      continue;
    }

    if (ruleType === "publisher" && best.signerInfo?.issuerTbsHash) {
      // Publisher rule: CertRoot (TBS of issuer/root CA) + CertPublisher (leaf CN).
      // CertRoot pins the CA chain; CertPublisher scopes to the leaf cert's CN.
      // Signer IDs use WDAC Wizard format: ID_SIGNER_A_<0-based-counter>
      const fp = best.signerInfo.issuerTbsHash;
      if (!signerFpMap.has(fp)) {
        const signerId = `ID_SIGNER_A_${String(signers.length).padStart(4, "0")}`;
        signerFpMap.set(fp, signerId);

        // Name matches WDAC Wizard: "Allow CN = <leaf CN> issued by <issuer name>"
        const signerName = buildSignerName(
          best.signerInfo.publisherName,
          best.signerInfo.issuerName
        );

        // CertPublisher value: extract CN from full subject DN if present
        const certPublisher = best.signerInfo.publisherName
          ? (best.signerInfo.publisherName.match(/^CN=([^,]+)/i)?.[1] ?? best.signerInfo.publisherName)
          : undefined;

        const signer: WdacSignerRule = {
          id: signerId,
          name: signerName,
          certRoot: { type: "TBS", value: fp },
          ...(certPublisher && { certPublisher }),
        };

        signers.push(signer);
        allowedSignerIds.push(signerId);
        log.push(
          `Publisher rule: ${signerName} ` +
          `(TBS: ${fp.substring(0, 16)}…) — covers: ${best.filePath}`
        );
      } else {
        log.push(`Publisher rule reused for: ${best.filePath}`);
      }
    } else if (ruleType === "fileAttrib" && best.originalFileName) {
      // OriginalFileName-based allow rule (attribute rule)
      // More maintainable than hash rules; should be paired with publisher scoping in production
      const fn = best.originalFileName.toLowerCase();
      if (!seenFileNames.has(fn)) {
        seenFileNames.add(fn);
        const ruleId = `ID_ALLOW_ATTR_${String(fileRules.length + 1).padStart(4, "0")}`;
        fileRules.push({
          kind: "attribute",
          id: ruleId,
          effect: "Allow",
          friendlyName: `Allow ${best.originalFileName} (FileName)`,
          fileName: best.originalFileName,
          ...(best.fileVersion && { minimumFileVersion: "0.0.0.0" }),
        } as WdacFileRule);
        fileRuleIds.push(ruleId);
        log.push(
          `File attribute rule: OriginalFileName=${best.originalFileName}` +
          (best.productName ? ` (${best.productName})` : "")
        );
      }
    } else if (ruleType === "hash" || (ruleType === "publisher" && !best.signerInfo?.publisherTbsHash)) {
      // Hash rules — ConvertFrom-CIPolicy generates one Allow rule per hash type.
      // When both SHA1 and SHA256 flat hashes are available, emit both (matching
      // the real cipolicy output: ID_..._SHA1 and ID_..._SHA256).
      const sha256 = best.sha256FlatHash ?? best.sha256Hash;
      const sha1   = best.sha1FlatHash ?? best.sha1Hash;
      let addedAny = false;

      if (sha1 && !seenHashes.has(sha1)) {
        seenHashes.add(sha1);
        const seqTag = String(fileRules.length + 1).padStart(4, "0");
        const ruleId = `ID_ALLOW_${seqTag}_SHA1`;
        fileRules.push({
          kind: "hash",
          id: ruleId,
          effect: "Allow",
          friendlyName: best.fileName
            ? `${best.fileName} SHA1 hash allow rule`
            : `Allow Hash ${sha1.substring(0, 16)}… (SHA1)`,
          hash: sha1,
          hashType: "SHA1",
          ...(best.fileName && { fileName: best.fileName }),
        } as WdacFileRule);
        fileRuleIds.push(ruleId);
        addedAny = true;
        log.push(`Hash rule: ${best.filePath} (SHA1: ${sha1.substring(0, 16)}…)`);
      }

      if (sha256 && !seenHashes.has(sha256)) {
        seenHashes.add(sha256);
        const seqTag = String(fileRules.length + 1).padStart(4, "0");
        const ruleId = `ID_ALLOW_${seqTag}_SHA256`;
        fileRules.push({
          kind: "hash",
          id: ruleId,
          effect: "Allow",
          friendlyName: best.fileName
            ? `${best.fileName} SHA256 hash allow rule`
            : `Allow Hash ${sha256.substring(0, 16)}… (SHA256)`,
          hash: sha256,
          hashType: "SHA256",
          ...(best.fileName && { fileName: best.fileName }),
        } as WdacFileRule);
        fileRuleIds.push(ruleId);
        addedAny = true;
        log.push(`Hash rule: ${best.filePath} (SHA256: ${sha256.substring(0, 16)}…)`);
      }

      if (!addedAny) {
        // Fallback: no hash available, try path if enabled
        if (req.includePathRules && best.filePath && !seenPaths.has(best.filePath)) {
          const normalized = best.filePath.toLowerCase();
          if (!normalized.includes("temp") && !normalized.includes("downloads")) {
            seenPaths.add(best.filePath);
            const ruleId = `ID_ALLOW_PATH_${String(fileRules.length + 1).padStart(4, "0")}`;
            fileRules.push({
              kind: "path",
              id: ruleId,
              effect: "Allow",
              friendlyName: `Allow ${best.fileName ?? best.filePath} (Path)`,
              filePath: best.filePath,
            } as WdacFileRule);
            fileRuleIds.push(ruleId);
            log.push(`Path rule (no hash available): ${best.filePath}`);
          } else {
            log.push(`Skipped path rule for temp/downloads path: ${best.filePath}`);
          }
        } else {
          log.push(`No hash available and path rules disabled — skipping: ${best.filePath}`);
        }
      }
    } else if (ruleType === "path" && best.filePath) {
      // Explicit path rule request
      if (!seenPaths.has(best.filePath)) {
        const normalized = best.filePath.toLowerCase();
        if (!normalized.includes("temp") && !normalized.includes("downloads")) {
          seenPaths.add(best.filePath);
          const ruleId = `ID_ALLOW_PATH_${String(fileRules.length + 1).padStart(4, "0")}`;
          fileRules.push({
            kind: "path",
            id: ruleId,
            effect: "Allow",
            friendlyName: `Allow ${best.fileName ?? best.filePath} (Path)`,
            filePath: best.filePath,
          } as WdacFileRule);
          fileRuleIds.push(ruleId);
          log.push(`Path rule: ${best.filePath}`);
        } else {
          log.push(`Skipped path rule for temp/downloads path: ${best.filePath}`);
        }
      }
    }
  }

  log.push(`Total: ${fileRules.length} file rule(s), ${signers.length} signer rule(s)`);

  // Build signing scenarios.
  // Supplemental policies omit MinimumHashAlgorithm on KMCI (inherited from base).
  const userAllowedSigners: AllowedSigner[] = allowedSignerIds.map((id) => ({ signerId: id }));

  const signingScenarios: WdacSigningScenario[] = [
    {
      value: 131,
      id: "ID_SIGNINGSCENARIO_DRIVERS_1",
      ...(isSupplemental ? {} : { minHashVersion: "65536" }),
      allowedSigners: [],
      deniedSigners: [],
      fileRuleRefs: [],
    },
    {
      value: 12,
      id: "ID_SIGNINGSCENARIO_WINDOWS",
      allowedSigners: userAllowedSigners,
      deniedSigners: [],
      fileRuleRefs: fileRuleIds,
    },
  ];

  const policy: WdacPolicy = {
    policyId,
    ...(basePolicyId && { basePolicyId }),
    platformId: "2E07F7E4-194C-4D20-B7C9-6F44A6C5A234",
    versionEx: "10.0.0.0",
    friendlyName: req.policyName,
    policyType: isSupplemental ? "Supplemental" : "Base",
    options,
    ekus: [],
    fileRules,
    signers,
    signingScenarios,
    updatePolicySigners: [],
    ciSigners: allowedSignerIds,
    hvciOptions: 0,
  };

  return { policy, buildLog: log };
}
