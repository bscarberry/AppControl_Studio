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

function getTemplateOptions(template: TemplateName): PolicyRuleOption[] {
  const base: PolicyRuleOption[] = [
    { value: 0, enabled: true }, // UMCI
    { value: 6, enabled: true }, // Unsigned system integrity policy
  ];

  switch (template) {
    case "default-windows":
      return [
        ...base,
        { value: 2, enabled: true },  // WHQL required
        { value: 3, enabled: false },
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

  log.push(`Building policy '${req.policyName}' from ${req.events.length} events.`);
  log.push(`Template: ${req.template ?? "blank"}`);
  log.push(`Mode: ${req.auditMode ? "Audit" : "Enforcement"}`);

  // Template options
  const options = getTemplateOptions(req.template ?? "blank");
  if (req.auditMode) {
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

    if (ruleType === "publisher" && best.signerInfo?.publisherTbsHash) {
      // Publisher rule: CertRoot (TBS) + CertPublisher — survives binary updates
      const fp = best.signerInfo.publisherTbsHash;
      if (!signerFpMap.has(fp)) {
        const signerId = `ID_SIGNER_${String(signers.length + 1).padStart(4, "0")}`;
        signerFpMap.set(fp, signerId);

        const signer: WdacSignerRule = {
          id: signerId,
          name: best.signerInfo.publisherName ?? `Publisher ${signers.length + 1}`,
          certRoot: { type: "TBS", value: fp },
          ...(best.signerInfo.publisherName && {
            certPublisher: best.signerInfo.publisherName,
          }),
        };

        signers.push(signer);
        allowedSignerIds.push(signerId);
        log.push(
          `Publisher rule: ${best.signerInfo.publisherName ?? fp} ` +
          `(TBS: ${fp.substring(0, 16)}…) — covers: ${best.filePath}`
        );
      } else {
        log.push(
          `Publisher rule reused for: ${best.filePath}`
        );
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
      // Hash rule — exact SHA256 match
      const hash = best.sha256FlatHash ?? best.sha256Hash;
      if (hash && !seenHashes.has(hash)) {
        seenHashes.add(hash);
        const ruleId = `ID_ALLOW_${String(fileRules.length + 1).padStart(4, "0")}`;
        fileRules.push({
          kind: "hash",
          id: ruleId,
          effect: "Allow",
          friendlyName: best.fileName
            ? `Allow ${best.fileName} (SHA256)`
            : `Allow Hash ${hash.substring(0, 16)}…`,
          hash,
          hashType: "SHA256",
          ...(best.fileName && { fileName: best.fileName }),
        } as WdacFileRule);
        fileRuleIds.push(ruleId);
        log.push(`Hash rule: ${best.filePath} (SHA256: ${hash.substring(0, 16)}…)`);
      } else if (!hash) {
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

  // Build signing scenarios
  const userAllowedSigners: AllowedSigner[] = allowedSignerIds.map((id) => ({ signerId: id }));
  const kernelAllowedSigners: AllowedSigner[] = [];

  const signingScenarios: WdacSigningScenario[] = [
    {
      value: 131,
      id: "ID_SIGNINGSCENARIO_DRIVERS_1",
      minHashVersion: "65536",
      allowedSigners: kernelAllowedSigners,
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
    versionEx: "10.0.0.0",
    friendlyName: req.policyName,
    policyType: "Base",
    options,
    ekus: [],
    fileRules,
    signers,
    signingScenarios,
    updatePolicySigners: [],
    ciSigners: [],
  };

  return { policy, buildLog: log };
}
