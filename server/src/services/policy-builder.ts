/**
 * WDAC Policy Builder
 *
 * Creates a new WDAC policy from parsed CodeIntegrity events.
 * Generates the minimum required rules to allow the observed files.
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
import type { ParsedCiEvent } from "@appcontrol/shared";
import type { CreatePolicyFromEventsRequest } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Policy Templates
// ---------------------------------------------------------------------------

type TemplateName = NonNullable<CreatePolicyFromEventsRequest["template"]>;

function getTemplateOptions(template: TemplateName): PolicyRuleOption[] {
  const base: PolicyRuleOption[] = [
    { value: 0, enabled: true },  // UMCI
    { value: 6, enabled: true },  // Unsigned allowed (for dev)
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
        { value: 8, enabled: true },
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

  // Start with template options
  const options = getTemplateOptions(req.template ?? "blank");
  if (req.auditMode) {
    const auditIdx = options.findIndex((o) => o.value === 3);
    if (auditIdx >= 0) options[auditIdx].enabled = true;
    else options.push({ value: 3, enabled: true });
    log.push("Added Option 3: Audit Mode");
  }

  const fileRules: WdacFileRule[] = [];
  const signers: WdacSignerRule[] = [];
  const signerIdMap = new Map<string, string>(); // fingerprint -> signer ID
  const allowedSignerIds: string[] = [];
  const kernelAllowedSignerIds: string[] = [];
  const fileRuleIds: string[] = [];

  const seenHashes = new Set<string>();
  const seenPaths = new Set<string>();

  for (const event of req.events) {
    // Publisher rules (preferred when signer info available)
    if (req.preferPublisherRules && event.signerInfo?.publisherName) {
      const fp = JSON.stringify({
        publisher: event.signerInfo.publisherName,
        issuer: event.signerInfo.issuerName,
        root: event.signerInfo.rootCertTbs,
      });

      if (!signerIdMap.has(fp)) {
        const signerId = `ID_SIGNER_${String(signers.length + 1).padStart(4, "0")}`;
        signerIdMap.set(fp, signerId);

        const signer: WdacSignerRule = {
          id: signerId,
          name: event.signerInfo.publisherName,
          ...(event.signerInfo.rootCertTbs && {
            certRoot: { type: "TBS", value: event.signerInfo.rootCertTbs },
          }),
          ...(event.signerInfo.publisherName && {
            certPublisher: event.signerInfo.publisherName,
          }),
        };

        signers.push(signer);
        allowedSignerIds.push(signerId);
        log.push(`Added signer rule for publisher: ${event.signerInfo.publisherName}`);
      }
    }

    // Hash-based rules
    if (event.sha256Hash && !seenHashes.has(event.sha256Hash)) {
      seenHashes.add(event.sha256Hash);
      const ruleId = `ID_ALLOW_${String(fileRules.length + 1).padStart(4, "0")}`;
      fileRules.push({
        kind: "hash",
        id: ruleId,
        effect: "Allow",
        friendlyName: event.fileName
          ? `Allow ${event.fileName} (Hash)`
          : `Allow Hash ${event.sha256Hash.substring(0, 16)}...`,
        hash: event.sha256Hash,
        hashType: "SHA256",
        ...(event.fileName && { fileName: event.fileName }),
      });
      fileRuleIds.push(ruleId);
      log.push(`Added hash rule for: ${event.filePath}`);
    }

    // Path rules (optional)
    if (req.includePathRules && event.filePath && !seenPaths.has(event.filePath)) {
      const normalizedPath = event.filePath.toLowerCase();
      if (!normalizedPath.includes("temp") && !normalizedPath.includes("downloads")) {
        seenPaths.add(event.filePath);
        const ruleId = `ID_ALLOW_PATH_${String(fileRules.length + 1).padStart(4, "0")}`;
        fileRules.push({
          kind: "path",
          id: ruleId,
          effect: "Allow",
          friendlyName: `Allow ${event.fileName ?? event.filePath} (Path)`,
          filePath: event.filePath,
        });
        fileRuleIds.push(ruleId);
        log.push(`Added path rule for: ${event.filePath}`);
      } else {
        log.push(`Skipped path rule for temp/downloads path: ${event.filePath}`);
      }
    }
  }

  log.push(`Total: ${fileRules.length} file rule(s), ${signers.length} signer(s)`);

  // Build signing scenarios
  const userAllowedSigners: AllowedSigner[] = allowedSignerIds.map((id) => ({
    signerId: id,
  }));

  const kernelAllowedSigners: AllowedSigner[] = kernelAllowedSignerIds.map((id) => ({
    signerId: id,
  }));

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
