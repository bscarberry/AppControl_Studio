/**
 * WDAC Rule Generation Engine — Shared Types
 *
 * Types for converting CodeIntegrity operational log events into candidate
 * WDAC policy rules, with confidence scoring, risk assessment, deduplication,
 * and mapping to the official App Control rule evaluation model.
 *
 * Reference: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create
 */

import type { WdacSignerRule, WdacFileAttrib, WdacFileRule } from "./policy";

// ---------------------------------------------------------------------------
// Rule engine primitives
// ---------------------------------------------------------------------------

/**
 * Confidence in a proposed rule — how well-evidenced the rule is.
 * Driven by: event count, signer info completeness, hash availability.
 */
export type RuleConfidenceLevel = "high" | "medium" | "low";

/**
 * Risk level of a proposed rule — how dangerous or broad the permission is.
 * Signer rules without FileAttrib scoping are broader (higher risk) than
 * hash rules; path rules are the broadest and highest risk.
 */
export type RuleRiskLevel = "safe" | "low" | "medium" | "high" | "critical";

/**
 * Which phase of WDAC's rule evaluation pipeline this rule participates in.
 *
 * WDAC evaluates rules in strict precedence order:
 *  1. deny-file     — explicit deny file/hash rules (checked first)
 *  2. deny-signer   — explicit deny signer rules
 *  3. allow-signer  — explicit allow signer rules (most maintainable trust)
 *  4. allow-file    — explicit allow hash/path rules (version-locked)
 *  5. isg           — Microsoft Intelligent Security Graph (cloud reputation)
 *  6. managed-installer — trusted package manager authorization
 *
 * A deny in any earlier phase overrides an allow in a later phase.
 */
export type RuleEvaluationPhase =
  | "deny-file"
  | "deny-signer"
  | "allow-signer"
  | "allow-file"
  | "isg"
  | "managed-installer";

/**
 * Kind of rule being proposed.
 * - signer        → CertPublisher-level trust; all files from publisher are allowed
 * - scoped-signer → Publisher trust scoped to specific product/filename via FileAttrib
 * - hash          → SHA-256 hash of one specific binary version
 * - path          → Filesystem path pattern (broadest, highest risk)
 */
export type ProposedRuleKind = "signer" | "scoped-signer" | "hash" | "path";

// ---------------------------------------------------------------------------
// Safety warnings
// ---------------------------------------------------------------------------

export type SafetyWarningSeverity = "critical" | "warning" | "info";

export interface SafetyWarning {
  /** Machine-readable code for programmatic handling */
  code: SafetyWarningCode;
  severity: SafetyWarningSeverity;
  /** Short human-readable message */
  message: string;
  /** Detailed explanation of the risk and recommended mitigation */
  detail: string;
}

export type SafetyWarningCode =
  // Signing
  | "UNSIGNED_BINARY"
  | "MISSING_ROOT_CERT_TBS"
  | "MISSING_PUBLISHER"
  | "CERT_CHAIN_INCOMPLETE"
  | "EXPIRED_CERT"
  // Rule breadth
  | "UNSCOPED_PUBLISHER"
  | "BROAD_PUBLISHER"
  | "PATH_BYPASS_RISK"
  | "TEMP_PATH"
  | "WILDCARD_PATH"
  // Operational
  | "KERNEL_MODE_DRIVER"
  | "HASH_WILL_CHANGE_ON_UPDATE"
  | "MULTIPLE_FILE_VERSIONS"
  | "HIGH_EVENT_VOLUME"
  | "SINGLE_EVENT_SOURCE"
  | "CROSS_MACHINE_VARIANCE";

// ---------------------------------------------------------------------------
// WDAC evaluation metadata
// ---------------------------------------------------------------------------

export interface WdacEvaluationInfo {
  /**
   * Which phase of WDAC evaluation this rule participates in.
   * Rules in earlier phases take precedence over later phases.
   */
  evaluationPhase: RuleEvaluationPhase;

  /**
   * Relative precedence within all proposed rules.
   * Lower = evaluated first = higher effective priority.
   *   Deny file rules:   1–99
   *   Deny signer rules: 100–199
   *   Allow signer:      200–299
   *   Allow file/hash:   300–399
   *   Path rules:        400–499
   */
  precedenceOrder: number;

  /** Human-readable explanation of evaluation order */
  precedenceNote: string;

  /** True if this rule would affect kernel-mode code (drivers, boot) */
  impactsKernelMode: boolean;

  /** True if this rule would affect user-mode code (applications) */
  impactsUserMode: boolean;

  /**
   * True if this could affect boot-critical drivers.
   * Kernel-mode deny rules with this flag warrant extra review.
   */
  isBootCritical: boolean;
}

// ---------------------------------------------------------------------------
// The proposed rule
// ---------------------------------------------------------------------------

export interface ProposedRule {
  /** Unique proposal ID (UUID) — not the eventual WDAC rule ID */
  id: string;

  /** Rule kind: signer, scoped-signer, hash, or path */
  kind: ProposedRuleKind;

  /** Whether this rule grants or denies trust */
  effect: "Allow" | "Deny";

  /** Which signing scenarios this rule targets */
  signingScenario: "kernel" | "user" | "both";

  // ---- Proposed WDAC rule objects (one or more will be set) ----

  /** Set for kind=signer or kind=scoped-signer */
  signerRule?: WdacSignerRule;

  /**
   * Set for kind=scoped-signer.
   * This FileAttrib restricts the signer rule to specific product/filename.
   */
  fileAttrib?: WdacFileAttrib;

  /** Set for kind=hash or kind=path */
  fileRule?: WdacFileRule;

  // ---- Confidence ----

  /** Numeric confidence score in [0, 1] */
  confidence: number;

  confidenceLevel: RuleConfidenceLevel;

  /** Factors that boosted or reduced confidence */
  confidenceFactors: string[];

  // ---- Risk ----

  riskLevel: RuleRiskLevel;

  // ---- Reasoning ----

  /**
   * Human-readable rationale: why this rule type was chosen,
   * what trust relationship it represents, and what files it covers.
   */
  reasoning: string;

  // ---- Source events ----

  /** Number of CI events that support this rule */
  sourceEventCount: number;

  /** Distinct event IDs observed (3076, 3033, etc.) */
  sourceEventIds: number[];

  /** Machine names this activity was observed on */
  sourceMachines: string[];

  /** File paths covered by this rule */
  sourceFiles: string[];

  // ---- Deduplication ----

  /**
   * If this rule is made redundant by a broader signer rule,
   * this is the proposal ID of the rule that supersedes it.
   * Redundant rules should be omitted from the final policy.
   */
  supersededBy?: string;

  /**
   * Proposal IDs of narrower rules this rule makes redundant
   * (e.g., a signer rule supersedes individual hash rules for same publisher).
   */
  supersedes?: string[];

  // ---- Safety warnings ----

  warnings: SafetyWarning[];

  // ---- WDAC evaluation model ----

  wdacEvaluation: WdacEvaluationInfo;
}

// ---------------------------------------------------------------------------
// The full output: ProposedPolicyChanges
// ---------------------------------------------------------------------------

export interface ProposedPolicyChanges {
  /** UUID identifying this proposal batch */
  proposalId: string;

  /** ISO timestamp when the engine ran */
  generatedAt: string;

  /** Number of source events processed */
  sourceEventCount: number;

  /** All proposed rules, sorted by precedenceOrder ascending */
  rules: ProposedRule[];

  summary: {
    totalRules: number;
    /** Rules not marked as redundant */
    activeRules: number;
    signerRules: number;
    scopedSignerRules: number;
    hashRules: number;
    pathRules: number;
    redundantRules: number;
    highRiskRules: number;
    criticalRiskRules: number;
    totalWarnings: number;
  };

  /**
   * Warnings that apply to the entire proposal set,
   * not to any individual rule.
   */
  globalWarnings: SafetyWarning[];

  /** Step-by-step log of engine decisions */
  buildLog: string[];
}

// ---------------------------------------------------------------------------
// Request / response
// ---------------------------------------------------------------------------

export interface ProposeRulesRequest {
  events: unknown[]; // ParsedCiEvent[] — typed as unknown for Zod passthrough

  /**
   * If true, the engine will prefer signer/publisher rules over hash rules
   * when sufficient signing information is available.
   * Default: true
   */
  preferSignerRules: boolean;

  /**
   * If true, signer rules will be scoped with FileAttrib when product/filename
   * metadata is consistent across the event group (least-permissive signer trust).
   * Default: true
   */
  scopeSignerRules: boolean;

  /**
   * If true, path rules will be proposed for files lacking hash/signer info.
   * Path rules are broad and can be bypassed — disabled by default.
   * Default: false
   */
  includePathRules: boolean;

  /**
   * If true, deny rules will also be proposed for events where the file was
   * actually blocked (block events vs audit events).
   * Default: false
   */
  includeDenyRules: boolean;
}

export interface ProposeRulesResponse {
  changes: ProposedPolicyChanges;
}
