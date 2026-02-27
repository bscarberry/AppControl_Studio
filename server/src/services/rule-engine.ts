/**
 * WDAC Rule Generation Engine
 *
 * Converts CodeIntegrity operational log events into candidate WDAC policy
 * rules with confidence scoring, risk assessment, deduplication, rule
 * precedence, and safety warnings — all aligned with the official App Control
 * rule evaluation model.
 *
 * Official rule evaluation order (higher entries take precedence):
 *   1. Explicit Deny File Rules   (hash / path)
 *   2. Explicit Deny Signer Rules
 *   3. Explicit Allow Signer Rules  ← preferred (publisher-level, maintainable)
 *   4. Explicit Allow File Rules    ← fallback (hash = exact version, path = broad)
 *   5. ISG / Managed Installer      ← not generated here
 *
 * Reference: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create
 */

import { v4 as uuidv4 } from "uuid";
import type { ParsedCiEvent } from "@appcontrol/shared";
import type {
  WdacSignerRule,
  WdacFileAttrib,
  WdacHashRule,
  WdacPathRule,
} from "@appcontrol/shared";
import type {
  ProposedRule,
  ProposedPolicyChanges,
  ProposeRulesRequest,
  SafetyWarning,
  WdacEvaluationInfo,
  RuleConfidenceLevel,
  RuleRiskLevel,
  ProposedRuleKind,
} from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Internal grouping structures
// ---------------------------------------------------------------------------

/** Key used to group events that belong to the same publisher/certificate. */
interface SignerGroup {
  /** publisherName + "||" + rootCertTbs (or just publisherName) */
  key: string;
  publisherName: string;
  issuerName?: string;
  rootCertTbs?: string;
  leafCertTbs?: string;
  events: ParsedCiEvent[];
}

/** Key used to group events that share the same SHA-256 hash. */
interface HashGroup {
  hash: string;
  hashType: "SHA256";
  events: ParsedCiEvent[];
  /** Present when all events agree on a filename */
  consensusFileName?: string;
}

/** Key used to group unsigned/unhashed events for path rules. */
interface PathGroup {
  path: string;
  events: ParsedCiEvent[];
}

// ---------------------------------------------------------------------------
// Precedence constants (lower number = evaluated first by WDAC)
// ---------------------------------------------------------------------------

const PREC = {
  DENY_FILE: 10,
  DENY_SIGNER: 110,
  ALLOW_SIGNER_SCOPED: 200,
  ALLOW_SIGNER: 220,
  ALLOW_HASH: 310,
  ALLOW_PATH: 410,
} as const;

// ---------------------------------------------------------------------------
// Well-known broad publishers that warrant an UNSCOPED_PUBLISHER warning
// ---------------------------------------------------------------------------

const BROAD_PUBLISHERS = new Set([
  "microsoft windows",
  "microsoft corporation",
  "microsoft",
  "windows",
  "o=microsoft corporation",
]);

// ---------------------------------------------------------------------------
// Confidence scoring helpers
// ---------------------------------------------------------------------------

function scoreConfidence(
  eventCount: number,
  hasRootCertTbs: boolean,
  hasPublisher: boolean,
  hasIssuer: boolean,
  hasHash: boolean,
  hasProductName: boolean,
  hasOriginalFileName: boolean
): { score: number; level: RuleConfidenceLevel; factors: string[] } {
  let score = 0;
  const factors: string[] = [];

  // Event volume
  if (eventCount >= 5) {
    score += 0.30;
    factors.push(`${eventCount} supporting events (strong evidence)`);
  } else if (eventCount >= 2) {
    score += 0.20;
    factors.push(`${eventCount} supporting events`);
  } else {
    score += 0.08;
    factors.push("Single event (low evidence weight)");
  }

  // Cert chain completeness
  if (hasRootCertTbs) {
    score += 0.22;
    factors.push("Root certificate TBS hash available");
  } else {
    factors.push("Root certificate TBS hash absent — reduces verification strength");
  }

  if (hasPublisher) {
    score += 0.15;
    factors.push("Publisher name available");
  }

  if (hasIssuer) {
    score += 0.10;
    factors.push("Issuer name available");
  }

  // File identity
  if (hasHash) {
    score += 0.12;
    factors.push("SHA-256 hash available");
  }

  if (hasProductName) {
    score += 0.06;
    factors.push("Product name metadata available");
  }

  if (hasOriginalFileName) {
    score += 0.05;
    factors.push("Original file name metadata available");
  }

  score = Math.min(1.0, score);

  const level: RuleConfidenceLevel =
    score >= 0.72 ? "high" : score >= 0.45 ? "medium" : "low";

  return { score: Math.round(score * 100) / 100, level, factors };
}

// ---------------------------------------------------------------------------
// Risk scoring helpers
// ---------------------------------------------------------------------------

function riskForSignerRule(
  hasRootCertTbs: boolean,
  hasIssuer: boolean,
  isScoped: boolean,
  isBroadPublisher: boolean
): RuleRiskLevel {
  if (!hasRootCertTbs && !hasIssuer) return "high";   // Cannot verify cert chain
  if (!hasRootCertTbs) return "medium";               // Partial cert chain
  if (isBroadPublisher && !isScoped) return "medium"; // Broad unscoped publisher
  if (isScoped) return "safe";                        // Publisher + FileAttrib scope
  return "low";                                       // Full cert chain, unscoped
}

function riskForHashRule(
  isSigned: boolean,
  filePath: string
): RuleRiskLevel {
  const lp = filePath.toLowerCase();
  if (lp.includes("\\temp\\") || lp.includes("\\tmp\\") || lp.includes("\\downloads\\")) {
    return "critical"; // Binary from temp/user-writable path
  }
  if (!isSigned) return "high";  // Unsigned — cannot verify origin
  return "medium";               // Signed but hash-locked to one version
}

function riskForPathRule(filePath: string): RuleRiskLevel {
  const lp = filePath.toLowerCase();
  // Very short paths are wildcard-like
  if (lp.length < 8) return "critical";
  if (lp.includes("\\temp\\") || lp.includes("\\downloads\\")) return "critical";
  if (lp === "c:\\" || lp === "%osdrive%\\" || lp === "%windir%\\") return "critical";
  return "high";
}

// ---------------------------------------------------------------------------
// Safety warning builders
// ---------------------------------------------------------------------------

function warnUnsignedBinary(): SafetyWarning {
  return {
    code: "UNSIGNED_BINARY",
    severity: "warning",
    message: "File has no signing information",
    detail:
      "This binary was not authenticode-signed (or signing info was unavailable in the event). " +
      "Publisher identity cannot be verified — a hash rule provides exact-file trust without any " +
      "certificate verification. Investigate why this file is unsigned before allowing it.",
  };
}

function warnMissingRootCertTbs(): SafetyWarning {
  return {
    code: "MISSING_ROOT_CERT_TBS",
    severity: "warning",
    message: "Root certificate TBS hash not available",
    detail:
      "WDAC signer rules are anchored by the root certificate's TBS (To Be Signed) hash. " +
      "Without it, the rule can only match on publisher name and issuer — reducing the " +
      "cryptographic strength of the trust anchor. Collect events from a machine where " +
      "the full certificate chain is logged to improve rule quality.",
  };
}

function warnMissingPublisher(): SafetyWarning {
  return {
    code: "MISSING_PUBLISHER",
    severity: "warning",
    message: "Publisher name not available",
    detail:
      "The event did not include a publisher (leaf certificate subject). " +
      "Signer rules require at minimum a publisher name. Falling back to hash rule.",
  };
}

function warnCertChainIncomplete(): SafetyWarning {
  return {
    code: "CERT_CHAIN_INCOMPLETE",
    severity: "warning",
    message: "Certificate chain is incomplete",
    detail:
      "Only partial certificate chain information was available in the event data. " +
      "A complete chain (publisher + issuer + root TBS) allows WDAC to verify the " +
      "full trust path at evaluation time.",
  };
}

function warnUnscopedPublisher(publisherName: string): SafetyWarning {
  return {
    code: "UNSCOPED_PUBLISHER",
    severity: "warning",
    message: `Publisher rule for "${publisherName}" is not scoped to specific files`,
    detail:
      "An unscoped publisher rule will allow ANY binary signed by this publisher, " +
      "including future releases, updates, or any other tool from this vendor. " +
      "Consider scoping the rule with FileAttrib (product name or internal filename) " +
      "to limit the blast radius if the publisher's signing key is ever compromised.",
  };
}

function warnBroadPublisher(publisherName: string): SafetyWarning {
  return {
    code: "BROAD_PUBLISHER",
    severity: "warning",
    message: `"${publisherName}" is a very broad publisher`,
    detail:
      "This publisher signs an extremely large number of binaries across many products. " +
      "An unscoped rule for this publisher grants trust to thousands of executables. " +
      "Strongly consider scoping with FileAttrib or using the built-in Allow Microsoft or " +
      "Default Windows policy templates instead.",
  };
}

function warnPathBypassRisk(): SafetyWarning {
  return {
    code: "PATH_BYPASS_RISK",
    severity: "warning",
    message: "Path rules can be bypassed by placing files in allowed locations",
    detail:
      "If a user or malicious process can write to the allowed path, any binary placed " +
      "there will be trusted. Path rules are best used only for locations with strict " +
      "ACLs (e.g., %WINDIR%, %PROGRAMFILES%). Enable Option 18 (Runtime FilePath Rule " +
      "Protection) to require ACL enforcement at evaluation time.",
  };
}

function warnTempPath(): SafetyWarning {
  return {
    code: "TEMP_PATH",
    severity: "critical",
    message: "Path includes a user-writable temporary directory",
    detail:
      "Allowing binaries from %TEMP%, %TMP%, or %USERPROFILE%\\Downloads is extremely " +
      "dangerous — any process that can write to these directories can place a malicious " +
      "binary and have it trusted. Remove this path rule and investigate why legitimate " +
      "software is executing from temporary locations.",
  };
}

function warnKernelMode(): SafetyWarning {
  return {
    code: "KERNEL_MODE_DRIVER",
    severity: "critical",
    message: "Event originated from kernel-mode driver loading",
    detail:
      "This event involves kernel-mode code (signing scenario 131). Rules that allow " +
      "kernel drivers carry the highest possible risk — a malicious kernel driver can " +
      "completely compromise the OS. Ensure this driver is from a known-good vendor and " +
      "consider scoping the rule as tightly as possible.",
  };
}

function warnHashWillChange(): SafetyWarning {
  return {
    code: "HASH_WILL_CHANGE_ON_UPDATE",
    severity: "info",
    message: "Hash rule will break when the file is updated",
    detail:
      "Hash rules are tied to one exact binary version. Any update, patch, or re-build " +
      "will change the SHA-256 hash and the rule will no longer match. If this file is " +
      "updated regularly, a publisher/signer rule is more maintainable.",
  };
}

function warnMultipleVersions(count: number, fileName: string): SafetyWarning {
  return {
    code: "MULTIPLE_FILE_VERSIONS",
    severity: "info",
    message: `${count} different versions of "${fileName}" observed`,
    detail:
      `${count} distinct SHA-256 hashes were seen for files named "${fileName}". ` +
      "This may indicate multiple versions are deployed, or that different machines " +
      "have different patch levels. A publisher/signer rule would cover all versions " +
      "without needing per-version hash rules.",
  };
}

function warnSingleEventSource(): SafetyWarning {
  return {
    code: "SINGLE_EVENT_SOURCE",
    severity: "info",
    message: "Rule is based on a single event",
    detail:
      "Only one event supports this rule. Verify the event is legitimate before adding " +
      "this rule to a production policy. Cross-reference with additional machines or " +
      "consult your software inventory.",
  };
}

function warnHighEventVolume(count: number): SafetyWarning {
  return {
    code: "HIGH_EVENT_VOLUME",
    severity: "info",
    message: `High event volume: ${count} events for this rule`,
    detail:
      `${count} events observed — this binary is loaded frequently across your environment. ` +
      "A publisher/signer rule is strongly recommended over hash rules to avoid " +
      "operational overhead from maintaining per-version rules.",
  };
}

// ---------------------------------------------------------------------------
// Core grouping logic
// ---------------------------------------------------------------------------

/**
 * Build signer groups: events with matching publisher + rootCertTbs.
 * Only events with at least a publisher name are eligible.
 */
function buildSignerGroups(events: ParsedCiEvent[]): SignerGroup[] {
  const map = new Map<string, SignerGroup>();

  for (const ev of events) {
    const info = ev.signerInfo;
    if (!info?.publisherName) continue;

    // Key combines publisher + root cert TBS (or issuer as fallback)
    const key = [
      info.publisherName.toLowerCase().trim(),
      info.rootCertTbs ?? info.issuerName ?? "",
    ].join("||");

    if (!map.has(key)) {
      map.set(key, {
        key,
        publisherName: info.publisherName,
        issuerName: info.issuerName,
        rootCertTbs: info.rootCertTbs,
        leafCertTbs: info.leafCertTbs,
        events: [],
      });
    }

    map.get(key)!.events.push(ev);
  }

  return Array.from(map.values());
}

/**
 * Build hash groups from events not covered by a signer group.
 * Groups events by SHA-256 hash.
 */
function buildHashGroups(
  events: ParsedCiEvent[],
  coveredPaths: Set<string>
): HashGroup[] {
  const map = new Map<string, HashGroup>();

  for (const ev of events) {
    if (coveredPaths.has(ev.filePath)) continue;
    if (!ev.sha256Hash) continue;

    if (!map.has(ev.sha256Hash)) {
      map.set(ev.sha256Hash, {
        hash: ev.sha256Hash,
        hashType: "SHA256",
        events: [],
      });
    }

    map.get(ev.sha256Hash)!.events.push(ev);
  }

  // Compute consensus filename per group
  for (const group of map.values()) {
    const names = [...new Set(group.events.map((e) => e.fileName).filter(Boolean))];
    if (names.length === 1) group.consensusFileName = names[0];
  }

  return Array.from(map.values());
}

/**
 * Build path groups from events that have neither a signer nor a hash.
 */
function buildPathGroups(
  events: ParsedCiEvent[],
  coveredPaths: Set<string>
): PathGroup[] {
  const map = new Map<string, PathGroup>();

  for (const ev of events) {
    if (coveredPaths.has(ev.filePath)) continue;
    if (ev.sha256Hash) continue; // Already handled by hash group

    // Use directory as the grouping key, not the full path
    const path = ev.filePath;
    if (!map.has(path)) {
      map.set(path, { path, events: [] });
    }
    map.get(path)!.events.push(ev);
  }

  return Array.from(map.values());
}

// ---------------------------------------------------------------------------
// FileAttrib scoping decision
// ---------------------------------------------------------------------------

/**
 * Determine if and how to scope a signer rule with a FileAttrib.
 * Returns the scoping data, or null if no consistent scope can be found.
 */
function determineSignerScope(
  group: SignerGroup,
  scopeEnabled: boolean
): {
  productName?: string;
  internalName?: string;
  originalFileName?: string;
} | null {
  if (!scopeEnabled) return null;

  const events = group.events;

  // Check if all events agree on productName
  const productNames = new Set(
    events.map((e) => e.productName?.trim()).filter(Boolean)
  );
  if (productNames.size === 1) {
    return { productName: [...productNames][0] };
  }

  // Check if all events agree on originalFileName (internal name fallback)
  const origNames = new Set(
    events.map((e) => e.originalFileName?.trim()).filter(Boolean)
  );
  if (origNames.size === 1) {
    return { originalFileName: [...origNames][0] };
  }

  // Check internalName
  const internalNames = new Set(
    events.map((e) => e.internalName?.trim()).filter(Boolean)
  );
  if (internalNames.size === 1) {
    return { internalName: [...internalNames][0] };
  }

  return null; // Cannot determine consistent scope
}

// ---------------------------------------------------------------------------
// Kernel-mode detection
// ---------------------------------------------------------------------------

/**
 * Kernel-mode events are identified by event IDs 3001–3003 (driver-level).
 * CI_EVENT_IDS 3001: kernel driver signature failure
 * CI_EVENT_IDS 3002: kernel driver security requirement failure
 * CI_EVENT_IDS 3003: kernel driver requirement failure
 */
function isKernelEvent(eventId: number): boolean {
  return eventId === 3001 || eventId === 3002 || eventId === 3003;
}

function scenarioForEvents(events: ParsedCiEvent[]): "kernel" | "user" | "both" {
  const hasKernel = events.some((e) => isKernelEvent(e.eventId));
  const hasUser = events.some((e) => !isKernelEvent(e.eventId));
  if (hasKernel && hasUser) return "both";
  if (hasKernel) return "kernel";
  return "user";
}

// ---------------------------------------------------------------------------
// Signer rule builder
// ---------------------------------------------------------------------------

let _signerSeq = 0;
let _fileRuleSeq = 0;
let _attribSeq = 0;

function nextSignerId(): string {
  return `ID_SIGNER_${String(++_signerSeq).padStart(4, "0")}`;
}

function nextFileRuleId(prefix = "ID_ALLOW"): string {
  return `${prefix}_${String(++_fileRuleSeq).padStart(4, "0")}`;
}

function nextFileAttribId(): string {
  return `ID_FILEATTRIB_${String(++_attribSeq).padStart(4, "0")}`;
}

function buildSignerProposal(
  group: SignerGroup,
  scopeResult: ReturnType<typeof determineSignerScope>,
  effect: "Allow" | "Deny",
  includeDeny: boolean,
  log: string[]
): ProposedRule {
  const id = uuidv4();
  const isScoped = scopeResult !== null;
  const kind: ProposedRuleKind = isScoped ? "scoped-signer" : "signer";
  const events = group.events;

  const signerId = nextSignerId();
  const signerRule: WdacSignerRule = {
    id: signerId,
    name: group.publisherName,
    ...(group.rootCertTbs
      ? { certRoot: { type: "TBS" as const, value: group.rootCertTbs } }
      : {}),
    ...(group.publisherName ? { certPublisher: group.publisherName } : {}),
  };

  let fileAttrib: WdacFileAttrib | undefined;
  if (isScoped && scopeResult) {
    const attribId = nextFileAttribId();
    fileAttrib = {
      kind: "fileAttrib",
      id: attribId,
      ...(scopeResult.productName ? { productName: scopeResult.productName } : {}),
      ...(scopeResult.internalName ? { internalName: scopeResult.internalName } : {}),
      ...(scopeResult.originalFileName ? { fileName: scopeResult.originalFileName } : {}),
      friendlyName: `FileAttrib for ${group.publisherName}`,
    };
    signerRule.fileAttribRefs = [attribId];
  }

  const warnings: SafetyWarning[] = [];
  const hasRootCertTbs = Boolean(group.rootCertTbs);
  const hasIssuer = Boolean(group.issuerName);

  if (!hasRootCertTbs) warnings.push(warnMissingRootCertTbs());
  if (!hasIssuer || !hasRootCertTbs) warnings.push(warnCertChainIncomplete());
  if (!isScoped) warnings.push(warnUnscopedPublisher(group.publisherName));

  const pubLower = group.publisherName.toLowerCase();
  if (BROAD_PUBLISHERS.has(pubLower) || pubLower.includes("microsoft")) {
    warnings.push(warnBroadPublisher(group.publisherName));
  }

  const hasKernel = events.some((e) => isKernelEvent(e.eventId));
  if (hasKernel) warnings.push(warnKernelMode());

  if (events.length === 1) warnings.push(warnSingleEventSource());

  const { score, level, factors } = scoreConfidence(
    events.length,
    hasRootCertTbs,
    true,
    hasIssuer,
    events.some((e) => Boolean(e.sha256Hash)),
    Boolean(scopeResult?.productName),
    Boolean(scopeResult?.originalFileName)
  );

  const risk = riskForSignerRule(hasRootCertTbs, hasIssuer, isScoped, BROAD_PUBLISHERS.has(pubLower));

  const scenario = scenarioForEvents(events);
  const uniqueFiles = [...new Set(events.map((e) => e.filePath))];
  const machines = [...new Set(events.map((e) => e.machineName).filter(Boolean))] as string[];
  const eventIds = [...new Set(events.map((e) => e.eventId))];

  const scopeDesc = isScoped
    ? `scoped to ${scopeResult!.productName ?? scopeResult!.internalName ?? scopeResult!.originalFileName}`
    : "unscoped (all files from this publisher)";

  const reasoning =
    `Publisher/signer rule for "${group.publisherName}" (${scopeDesc}). ` +
    `Covers ${uniqueFiles.length} unique file path(s) across ${events.length} event(s). ` +
    (hasRootCertTbs
      ? `Trust is anchored to root cert TBS hash, providing strong cryptographic verification. `
      : `Root cert TBS not available — verification anchored on publisher name only. `) +
    (isScoped
      ? `FileAttrib scoping limits trust to matching ${Object.keys(scopeResult!).join("/")} attribute(s) — least-permissive signer trust.`
      : `Without FileAttrib scoping, ALL binaries from this publisher are trusted. ` +
        `Consider adding product/filename scoping to reduce the blast radius.`);

  const precedence = effect === "Deny"
    ? PREC.DENY_SIGNER
    : isScoped
      ? PREC.ALLOW_SIGNER_SCOPED
      : PREC.ALLOW_SIGNER;

  const wdacEvaluation: WdacEvaluationInfo = {
    evaluationPhase: effect === "Deny" ? "deny-signer" : "allow-signer",
    precedenceOrder: precedence,
    precedenceNote:
      effect === "Deny"
        ? "Deny signer rules are evaluated second — they override any allow signer or allow file rules."
        : isScoped
          ? "Scoped allow-signer rules are evaluated before unscoped signer rules (lower precedence order = earlier)."
          : "Allow signer rules are evaluated in phase 3, after all deny rules, before allow file rules.",
    impactsKernelMode: scenario === "kernel" || scenario === "both",
    impactsUserMode: scenario === "user" || scenario === "both",
    isBootCritical: hasKernel,
  };

  const action = effect === "Allow" ? "Allow" : "Deny";
  log.push(
    `[${action}:${kind}] "${group.publisherName}" — ${events.length} event(s), ` +
    `${uniqueFiles.length} file(s), risk=${risk}, confidence=${score}`
  );

  return {
    id,
    kind,
    effect,
    signingScenario: scenario,
    signerRule,
    ...(fileAttrib ? { fileAttrib } : {}),
    confidence: score,
    confidenceLevel: level,
    confidenceFactors: factors,
    riskLevel: risk,
    reasoning,
    sourceEventCount: events.length,
    sourceEventIds: eventIds,
    sourceMachines: machines,
    sourceFiles: uniqueFiles,
    warnings,
    wdacEvaluation,
  };
}

// ---------------------------------------------------------------------------
// Hash rule builder
// ---------------------------------------------------------------------------

function buildHashProposal(
  group: HashGroup,
  effect: "Allow" | "Deny",
  log: string[]
): ProposedRule {
  const id = uuidv4();
  const events = group.events;
  const ruleId = nextFileRuleId(effect === "Allow" ? "ID_ALLOW" : "ID_DENY");

  const isSigned = events.some((e) => Boolean(e.signerInfo?.publisherName));
  const representativeEvent = events[0];

  const fileRule: WdacHashRule = {
    kind: "hash",
    id: ruleId,
    effect,
    hash: group.hash,
    hashType: group.hashType,
    ...(group.consensusFileName ? { fileName: group.consensusFileName } : {}),
    friendlyName: group.consensusFileName
      ? `${effect} ${group.consensusFileName} (SHA-256)`
      : `${effect} Hash ${group.hash.substring(0, 16)}…`,
  };

  const warnings: SafetyWarning[] = [];
  if (!isSigned) warnings.push(warnUnsignedBinary());
  warnings.push(warnHashWillChange());
  if (events.length === 1) warnings.push(warnSingleEventSource());
  if (events.length >= 10) warnings.push(warnHighEventVolume(events.length));

  const hasKernel = events.some((e) => isKernelEvent(e.eventId));
  if (hasKernel) warnings.push(warnKernelMode());

  const risk = riskForHashRule(isSigned, representativeEvent.filePath);

  const { score, level, factors } = scoreConfidence(
    events.length,
    false,
    isSigned,
    events.some((e) => Boolean(e.signerInfo?.issuerName)),
    true,
    events.some((e) => Boolean(e.productName)),
    events.some((e) => Boolean(e.originalFileName))
  );

  const scenario = scenarioForEvents(events);
  const uniqueFiles = [...new Set(events.map((e) => e.filePath))];
  const machines = [...new Set(events.map((e) => e.machineName).filter(Boolean))] as string[];
  const eventIds = [...new Set(events.map((e) => e.eventId))];

  const reasoning =
    `Hash rule for SHA-256 ${group.hash.substring(0, 16)}… ` +
    (group.consensusFileName ? `("${group.consensusFileName}"). ` : ". ") +
    (isSigned
      ? `File is signed but a publisher rule was not generated (insufficient cert chain data). `
      : `File appears unsigned — publisher identity cannot be verified cryptographically. `) +
    `This rule will only match this exact binary version. Any update will require a new hash rule.`;

  const precedence = effect === "Deny" ? PREC.DENY_FILE : PREC.ALLOW_HASH;

  const wdacEvaluation: WdacEvaluationInfo = {
    evaluationPhase: effect === "Deny" ? "deny-file" : "allow-file",
    precedenceOrder: precedence,
    precedenceNote:
      effect === "Deny"
        ? "Deny file rules are evaluated FIRST — they take precedence over all signer and allow rules."
        : "Allow file (hash) rules are evaluated in phase 4, after all signer rules.",
    impactsKernelMode: scenario === "kernel" || scenario === "both",
    impactsUserMode: scenario === "user" || scenario === "both",
    isBootCritical: hasKernel,
  };

  log.push(
    `[${effect}:hash] ${group.hash.substring(0, 16)}… ` +
    `"${group.consensusFileName ?? "unknown"}" — ${events.length} event(s), ` +
    `risk=${risk}, confidence=${score}, signed=${isSigned}`
  );

  return {
    id,
    kind: "hash",
    effect,
    signingScenario: scenario,
    fileRule,
    confidence: score,
    confidenceLevel: level,
    confidenceFactors: factors,
    riskLevel: risk,
    reasoning,
    sourceEventCount: events.length,
    sourceEventIds: eventIds,
    sourceMachines: machines,
    sourceFiles: uniqueFiles,
    warnings,
    wdacEvaluation,
  };
}

// ---------------------------------------------------------------------------
// Path rule builder
// ---------------------------------------------------------------------------

function buildPathProposal(group: PathGroup, log: string[]): ProposedRule {
  const id = uuidv4();
  const events = group.events;
  const ruleId = nextFileRuleId("ID_ALLOW_PATH");

  const risk = riskForPathRule(group.path);

  const fileRule: WdacPathRule = {
    kind: "path",
    id: ruleId,
    effect: "Allow",
    filePath: group.path,
    friendlyName: `Allow path: ${group.path}`,
  };

  const warnings: SafetyWarning[] = [warnPathBypassRisk()];
  const lp = group.path.toLowerCase();
  if (lp.includes("\\temp\\") || lp.includes("\\tmp\\") || lp.includes("\\downloads\\")) {
    warnings.push(warnTempPath());
  }

  const hasKernel = events.some((e) => isKernelEvent(e.eventId));
  if (hasKernel) warnings.push(warnKernelMode());
  if (events.length === 1) warnings.push(warnSingleEventSource());

  const { score, level, factors } = scoreConfidence(
    events.length,
    false,
    false,
    false,
    false,
    false,
    false
  );

  const scenario = scenarioForEvents(events);
  const machines = [...new Set(events.map((e) => e.machineName).filter(Boolean))] as string[];
  const eventIds = [...new Set(events.map((e) => e.eventId))];

  const reasoning =
    `Path rule for "${group.path}". ` +
    `Generated as fallback — no hash or signer information was available for ${events.length} event(s). ` +
    `Path rules allow any binary placed in this location regardless of its contents or signature. ` +
    `This is the least restrictive and highest risk rule type. Investigate why these files ` +
    `lack signing information.`;

  const wdacEvaluation: WdacEvaluationInfo = {
    evaluationPhase: "allow-file",
    precedenceOrder: PREC.ALLOW_PATH,
    precedenceNote:
      "Path rules are allow-file rules evaluated in phase 4, after all signer rules. " +
      "They are the broadest allow rule type and can be bypassed by writing to the allowed path.",
    impactsKernelMode: scenario === "kernel" || scenario === "both",
    impactsUserMode: scenario === "user" || scenario === "both",
    isBootCritical: hasKernel,
  };

  log.push(
    `[Allow:path] "${group.path}" — ${events.length} event(s), risk=${risk}, confidence=${score}`
  );

  return {
    id,
    kind: "path",
    effect: "Allow",
    signingScenario: scenario,
    fileRule,
    confidence: score,
    confidenceLevel: level,
    confidenceFactors: factors,
    riskLevel: risk,
    reasoning,
    sourceEventCount: events.length,
    sourceEventIds: eventIds,
    sourceMachines: machines,
    sourceFiles: [group.path],
    warnings,
    wdacEvaluation,
  };
}

// ---------------------------------------------------------------------------
// Deduplication pass
// ---------------------------------------------------------------------------

/**
 * Mark hash rules as redundant when a signer rule covers the same file.
 *
 * WDAC evaluation: if an allow-signer rule matches, the binary is already
 * allowed — the allow-hash rule for the same file would never be reached.
 * This avoids polluting the policy with redundant rules.
 */
function deduplicateRules(rules: ProposedRule[], log: string[]): void {
  // Build a map of file paths covered by signer rules
  const signerCoveredPaths = new Set<string>();

  for (const rule of rules) {
    if ((rule.kind === "signer" || rule.kind === "scoped-signer") && rule.effect === "Allow") {
      for (const fp of rule.sourceFiles) {
        signerCoveredPaths.add(fp);
      }
    }
  }

  // Mark hash/path allow rules whose files are fully covered by signer rules
  for (const rule of rules) {
    if (rule.supersededBy) continue;
    if (rule.effect !== "Allow") continue;
    if (rule.kind !== "hash" && rule.kind !== "path") continue;

    const allCovered = rule.sourceFiles.every((fp) => signerCoveredPaths.has(fp));
    if (!allCovered) continue;

    // Find the signer rule(s) that cover all its files
    const supersedingRules = rules.filter(
      (r) =>
        (r.kind === "signer" || r.kind === "scoped-signer") &&
        r.effect === "Allow" &&
        rule.sourceFiles.every((fp) => r.sourceFiles.includes(fp))
    );

    if (supersedingRules.length > 0) {
      rule.supersededBy = supersedingRules[0].id;
      for (const sr of supersedingRules) {
        sr.supersedes = [...(sr.supersedes ?? []), rule.id];
      }
      log.push(
        `[Dedup] ${rule.kind} rule for ${rule.sourceFiles[0]} is redundant — ` +
        `covered by signer rule "${supersedingRules[0].signerRule?.name ?? supersedingRules[0].id}"`
      );
    }
  }

  // Deduplicate identical hash rules (same hash, multiple events already grouped)
  // This is handled upstream by the grouping logic so nothing to do here.
}

// ---------------------------------------------------------------------------
// Multiple-versions detection (global warning)
// ---------------------------------------------------------------------------

function detectMultipleVersions(
  hashGroups: HashGroup[],
  log: string[]
): SafetyWarning[] {
  // Group hash groups by consensus filename
  const byFileName = new Map<string, HashGroup[]>();
  for (const hg of hashGroups) {
    if (!hg.consensusFileName) continue;
    const key = hg.consensusFileName.toLowerCase();
    if (!byFileName.has(key)) byFileName.set(key, []);
    byFileName.get(key)!.push(hg);
  }

  const warnings: SafetyWarning[] = [];
  for (const [, groups] of byFileName) {
    if (groups.length > 1) {
      const name = groups[0].consensusFileName!;
      warnings.push(warnMultipleVersions(groups.length, name));
      log.push(
        `[MultiVersion] ${groups.length} hash rules for "${name}" — ` +
        "consider a publisher/signer rule to cover all versions"
      );
    }
  }
  return warnings;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function proposeRules(
  req: ProposeRulesRequest & { events: ParsedCiEvent[] }
): ProposedPolicyChanges {
  // Reset sequence counters per invocation
  _signerSeq = 0;
  _fileRuleSeq = 0;
  _attribSeq = 0;

  const log: string[] = [];
  const proposalId = uuidv4();
  const events = req.events;

  log.push(`Rule engine started. Processing ${events.length} event(s).`);
  log.push(
    `Options: preferSignerRules=${req.preferSignerRules}, ` +
    `scopeSignerRules=${req.scopeSignerRules}, ` +
    `includePathRules=${req.includePathRules}, ` +
    `includeDenyRules=${req.includeDenyRules}`
  );

  const rules: ProposedRule[] = [];
  const coveredPaths = new Set<string>();

  // -------- Phase 1: Signer rules --------

  if (req.preferSignerRules) {
    const signerGroups = buildSignerGroups(events);
    log.push(`Identified ${signerGroups.length} publisher group(s).`);

    for (const group of signerGroups) {
      const scopeResult = determineSignerScope(group, req.scopeSignerRules);

      // Allow rule
      const allowRule = buildSignerProposal(group, scopeResult, "Allow", req.includeDenyRules, log);
      rules.push(allowRule);

      // Mark all events in this group as covered
      for (const ev of group.events) {
        coveredPaths.add(ev.filePath);
      }

      // Deny rule (only for actual block events when includeDenyRules is set)
      if (req.includeDenyRules) {
        const blockEvents = group.events.filter((e) => e.severity === "block");
        if (blockEvents.length > 0) {
          const denyGroup: SignerGroup = { ...group, events: blockEvents };
          const denyRule = buildSignerProposal(denyGroup, scopeResult, "Deny", req.includeDenyRules, log);
          rules.push(denyRule);
        }
      }
    }
  }

  // -------- Phase 2: Hash rules --------

  const hashGroups = buildHashGroups(events, coveredPaths);
  log.push(`Identified ${hashGroups.length} hash group(s) not covered by signer rules.`);

  for (const group of hashGroups) {
    // Allow rule
    const allowRule = buildHashProposal(group, "Allow", log);
    rules.push(allowRule);

    for (const ev of group.events) {
      coveredPaths.add(ev.filePath);
    }

    // Deny rule (only for block events when requested)
    if (req.includeDenyRules) {
      const blockEvents = group.events.filter((e) => e.severity === "block");
      if (blockEvents.length > 0) {
        const denyGroup: HashGroup = { ...group, events: blockEvents };
        const denyRule = buildHashProposal(denyGroup, "Deny", log);
        rules.push(denyRule);
      }
    }
  }

  // -------- Phase 3: Path rules (opt-in) --------

  if (req.includePathRules) {
    const pathGroups = buildPathGroups(events, coveredPaths);
    log.push(`Identified ${pathGroups.length} path group(s) for fallback path rules.`);

    for (const group of pathGroups) {
      rules.push(buildPathProposal(group, log));
    }
  } else {
    // Count how many events still lack coverage — report to user
    const uncoveredEvents = events.filter(
      (ev) =>
        !coveredPaths.has(ev.filePath) &&
        !ev.sha256Hash &&
        !ev.signerInfo?.publisherName
    );
    if (uncoveredEvents.length > 0) {
      log.push(
        `Note: ${uncoveredEvents.length} event(s) have no hash or signer info and ` +
        "path rules are disabled. These files have no proposed rule."
      );
    }
  }

  // -------- Deduplication pass --------

  deduplicateRules(rules, log);

  // -------- Global warnings --------

  const globalWarnings: SafetyWarning[] = [];

  const versionWarnings = detectMultipleVersions(hashGroups, log);
  globalWarnings.push(...versionWarnings);

  const kernelRules = rules.filter(
    (r) => r.signingScenario === "kernel" || r.signingScenario === "both"
  );
  if (kernelRules.length > 0) {
    globalWarnings.push({
      code: "KERNEL_MODE_DRIVER",
      severity: "critical",
      message: `${kernelRules.length} rule(s) impact kernel-mode code`,
      detail:
        "One or more proposed rules affect kernel-mode code (signing scenario 131). " +
        "Kernel rules allow device drivers to load — review all kernel-mode rules carefully " +
        "before deploying to production systems.",
    });
  }

  // -------- Sort by precedence --------

  rules.sort((a, b) => a.wdacEvaluation.precedenceOrder - b.wdacEvaluation.precedenceOrder);

  // -------- Build summary --------

  const activeRules = rules.filter((r) => !r.supersededBy);
  const redundantRules = rules.filter((r) => Boolean(r.supersededBy));

  const summary = {
    totalRules: rules.length,
    activeRules: activeRules.length,
    signerRules: rules.filter((r) => r.kind === "signer").length,
    scopedSignerRules: rules.filter((r) => r.kind === "scoped-signer").length,
    hashRules: rules.filter((r) => r.kind === "hash").length,
    pathRules: rules.filter((r) => r.kind === "path").length,
    redundantRules: redundantRules.length,
    highRiskRules: activeRules.filter((r) => r.riskLevel === "high").length,
    criticalRiskRules: activeRules.filter((r) => r.riskLevel === "critical").length,
    totalWarnings:
      globalWarnings.length +
      activeRules.reduce((acc, r) => acc + r.warnings.length, 0),
  };

  log.push(
    `Engine complete. ${summary.activeRules} active rule(s) proposed ` +
    `(${summary.signerRules} signer, ${summary.scopedSignerRules} scoped-signer, ` +
    `${summary.hashRules} hash, ${summary.pathRules} path). ` +
    `${summary.redundantRules} redundant rule(s) suppressed. ` +
    `${summary.totalWarnings} total warning(s).`
  );

  return {
    proposalId,
    generatedAt: new Date().toISOString(),
    sourceEventCount: events.length,
    rules,
    summary,
    globalWarnings,
    buildLog: log,
  };
}
