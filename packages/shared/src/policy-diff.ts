/**
 * WDAC Policy Semantic Diff — Shared Types
 *
 * Represents the output of the semantic comparison engine.
 * Unlike a structural diff (which reports what fields changed),
 * a semantic diff answers: "what does this change mean for security?"
 *
 * Core concepts:
 *  - TrustDirection: did the change broaden or tighten trust?
 *  - RiskDelta: quantified risk change (positive = more permissive/risky)
 *  - SignerScopeChange: how FileAttrib scoping changed on a signer rule
 *  - RiskAssessment: aggregate risk verdict across all changes
 *  - HumanExplanation: plain-language summary for non-experts
 *
 * Reference: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create
 */

import type { WdacFileRule, WdacSignerRule, WdacFileAttrib } from "./policy";

// ---------------------------------------------------------------------------
// Foundational enumerations
// ---------------------------------------------------------------------------

/**
 * Security direction of a single policy change.
 * - broadened: change allows more software to run (higher risk)
 * - tightened: change restricts more software (lower risk)
 * - neutral:   change has no direct trust-surface effect
 */
export type TrustDirection = "broadened" | "tightened" | "neutral";

/**
 * Overall risk verdict comparing two policies.
 * Derived from the sum of all individual risk deltas.
 */
export type RiskVerdict =
  | "improved"               // totalRiskDelta <= -20
  | "unchanged"              // -20 < totalRiskDelta <= 10
  | "degraded"               // 10 < totalRiskDelta <= 40
  | "significantly-degraded"; // totalRiskDelta > 40

/**
 * Severity of an individual security finding.
 * Maps to the risk delta of the change that produced it.
 */
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

/**
 * How a rule was matched between the two policies.
 * - id:       Matched by WDAC rule ID (same ID in both policies)
 * - semantic: Matched by content fingerprint (same rule, different ID — e.g. after policy rebuild)
 * - unmatched: No equivalent rule found in the other policy
 */
export type MatchKind = "id" | "semantic" | "unmatched";

// ---------------------------------------------------------------------------
// Signer scope change — how FileAttrib scoping changed on a modified signer
// ---------------------------------------------------------------------------

/**
 * Describes how the FileAttrib scope of a signer rule changed.
 *
 * FileAttrib scoping restricts which files a signer rule applies to.
 * Removing scoping is a trust broadening; adding it is a trust tightening.
 */
export interface SignerScopeChange {
  /** Human-readable description of the scope before the change */
  scopeBefore: string;
  /** Human-readable description of the scope after the change */
  scopeAfter: string;

  /**
   * Direction of scope change:
   * - broadened:      FileAttrib removed or made less specific (higher risk)
   * - narrowed:       FileAttrib added or made more specific (lower risk)
   * - cert-changed:   Trust anchor (certRoot/certPublisher) changed
   * - scope-replaced: FileAttrib content changed; direction unclear
   * - unchanged:      No effective scope change
   */
  direction:
    | "broadened"
    | "narrowed"
    | "cert-changed"
    | "scope-replaced"
    | "unchanged";

  /** Detailed explanation of what the scope change means */
  detail: string;

  /**
   * Risk contribution from the scope change alone.
   * Positive = scope broadened (more permissive).
   * This is separate from the base rule risk delta.
   */
  riskDelta: number;
}

// ---------------------------------------------------------------------------
// Added / removed rules
// ---------------------------------------------------------------------------

/**
 * A rule that exists only in the left policy (removed) or only in the right
 * policy (added), annotated with its security impact.
 */
export interface DiffedRule {
  /** Rule ID */
  id: string;

  /** How this rule was identified (ID match or content fingerprint match) */
  matchKind: MatchKind;

  /** File rule or signer rule */
  ruleCategory: "file" | "signer";

  /** Allow or Deny effect */
  effect: "Allow" | "Deny";

  /** Which WDAC signing scenarios this rule participates in */
  signingScenarios: Array<"kernel" | "user">;

  /** The actual rule object */
  rule: WdacFileRule | WdacSignerRule;

  /**
   * For signer rules: the resolved FileAttrib objects that scope the rule.
   * Empty array means the signer is unscoped (trusts all publisher binaries).
   */
  fileAttribs?: WdacFileAttrib[];

  /** Security trust direction of this add/remove */
  trustDirection: TrustDirection;

  /**
   * Risk contribution of this add/remove.
   * Positive = more permissive (higher risk).
   * Negative = more restrictive (lower risk).
   */
  riskDelta: number;

  /** Severity of the security finding */
  severity: FindingSeverity;

  /** Whether this rule affects kernel-mode code (scenario 131) */
  affectsKernel: boolean;

  /** Plain-language explanation of the security impact */
  explanation: string;
}

// ---------------------------------------------------------------------------
// Modified rules
// ---------------------------------------------------------------------------

/**
 * A rule that exists in both policies but with different content,
 * annotated with the security meaning of the modifications.
 */
export interface ModifiedRule {
  /** Rule ID */
  id: string;

  /** How this rule was matched */
  matchKind: MatchKind;

  /** File rule or signer rule */
  ruleCategory: "file" | "signer";

  /** The rule as it appeared in the left (baseline) policy */
  leftRule: WdacFileRule | WdacSignerRule;

  /** The rule as it appears in the right (candidate) policy */
  rightRule: WdacFileRule | WdacSignerRule;

  /** Specific fields that changed */
  changedFields: string[];

  /** Security trust direction of the modification */
  trustDirection: TrustDirection;

  /** Aggregate risk delta from all field changes */
  riskDelta: number;

  /** Severity of the security finding */
  severity: FindingSeverity;

  /** Whether this rule affects kernel-mode code */
  affectsKernel: boolean;

  /** Plain-language explanation of what changed and why it matters */
  explanation: string;

  /**
   * Populated for signer rules where FileAttrib scoping changed.
   * Describes the scope change direction and risk contribution.
   */
  signerScopeChange?: SignerScopeChange;
}

// ---------------------------------------------------------------------------
// Option-level changes with security interpretation
// ---------------------------------------------------------------------------

/**
 * A policy rule option that changed between the two policies,
 * annotated with its security meaning.
 */
export interface OptionSemanticChange {
  optionValue: number;
  optionName: string;
  enabledBefore: boolean;
  enabledAfter: boolean;
  trustDirection: TrustDirection;
  riskDelta: number;
  severity: FindingSeverity;
  /** Plain-language description of what this option change means for security */
  explanation: string;
}

// ---------------------------------------------------------------------------
// Risk assessment — the aggregate security verdict
// ---------------------------------------------------------------------------

export interface RiskFactor {
  severity: FindingSeverity;
  category: string;
  description: string;
  /** IDs of rules contributing to this risk factor */
  affectedRuleIds: string[];
}

export interface RiskAssessment {
  /**
   * Aggregate risk delta: sum of all individual rule/option risk deltas.
   * Positive = right policy is more permissive than left.
   * Negative = right policy is more restrictive.
   */
  totalRiskDelta: number;

  /** Overall security verdict derived from totalRiskDelta */
  verdict: RiskVerdict;

  /** Number of trust-broadening changes */
  broadeningCount: number;

  /** Number of trust-tightening changes */
  tighteningCount: number;

  /** Number of neutral changes */
  neutralCount: number;

  /** Changes that affect kernel-mode code (highest impact) */
  kernelImpactCount: number;

  /** High-severity findings that warrant explicit attention */
  criticalFindings: string[];

  /** Risk delta broken down by category */
  riskByCategory: {
    fileRules: number;
    signerRules: number;
    options: number;
    scopeChanges: number;
  };

  /** Structured risk factors with severity and affected rules */
  riskFactors: RiskFactor[];
}

// ---------------------------------------------------------------------------
// Human-readable explanation
// ---------------------------------------------------------------------------

export interface HumanExplanation {
  /**
   * 2-3 sentence executive summary suitable for a security review.
   * States the direction of change, what types of rules changed,
   * and the overall risk assessment.
   */
  summary: string;

  /**
   * Plain-language descriptions of enforcement mode changes
   * (audit ↔ enforcement transitions).
   */
  modeChanges: string[];

  /**
   * Plain-language descriptions of the most significant rules added.
   * Each string is a complete sentence explaining one addition.
   */
  significantAdditions: string[];

  /**
   * Plain-language descriptions of the most significant rules removed.
   * Each string is a complete sentence explaining one removal.
   */
  significantRemovals: string[];

  /**
   * Plain-language descriptions of the most significant rule modifications.
   * Focuses on scope changes and trust-direction changes.
   */
  significantModifications: string[];

  /**
   * Changes specifically affecting kernel-mode code.
   * These carry the highest system-level risk.
   */
  kernelImpacts: string[];

  /**
   * Overall assessment sentence — a verdict on whether the candidate policy
   * represents an improvement, regression, or no change relative to baseline.
   */
  overallAssessment: string;
}

// ---------------------------------------------------------------------------
// Top-level output: PolicySemanticDiff
// ---------------------------------------------------------------------------

export interface PolicySemanticDiff {
  leftPolicy: {
    policyId: string;
    friendlyName?: string;
    versionEx: string;
  };

  rightPolicy: {
    policyId: string;
    friendlyName?: string;
    versionEx: string;
  };

  /**
   * If the effective mode (audit vs enforcement) changed between policies,
   * this describes the change and its risk impact.
   */
  effectiveModeChange?: {
    before: "enforcement" | "audit";
    after: "enforcement" | "audit";
    riskDelta: number;
    explanation: string;
  };

  /** Rules added in the right policy relative to the left */
  addedRules: DiffedRule[];

  /** Rules removed in the right policy relative to the left */
  removedRules: DiffedRule[];

  /** Rules present in both policies but with different content */
  modifiedRules: ModifiedRule[];

  /** Option-level changes with security interpretation */
  optionChanges: OptionSemanticChange[];

  /** Aggregate risk assessment across all changes */
  riskAssessment: RiskAssessment;

  /** Plain-language explanation for human reviewers */
  humanExplanation: HumanExplanation;
}
