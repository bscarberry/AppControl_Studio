/**
 * WDAC Policy Simulation Engine — Shared Types
 *
 * Types for simulating whether a binary would be allowed or blocked
 * by a WDAC policy, following the documented rule evaluation order.
 *
 * Evaluation order (per Microsoft App Control for Business documentation):
 *   1. Explicit deny file rules   (hash → path → attribute)
 *   2. Explicit deny signer rules
 *   3. Explicit allow signer rules (with optional FileAttrib scoping)
 *   4. Explicit allow file rules  (hash → attribute → path)
 *   5. Default deny
 *
 * Reference:
 *   https://learn.microsoft.com/en-us/windows/security/application-security/
 *   application-control/app-control-for-business/design/select-types-of-rules-to-create
 */

import type { WdacPolicy } from "./policy";

// ---------------------------------------------------------------------------
// Binary metadata — the "who is asking?"
// ---------------------------------------------------------------------------

/**
 * Metadata describing a binary to evaluate against a WDAC policy.
 * All fields are optional — only present fields are matched.
 * Providing more fields yields a more accurate simulation.
 */
export interface BinaryMetadata {
  // ---- Cryptographic identity (highest priority in WDAC matching) ----

  /** SHA-256 hash of the binary (hex string, 64 chars). Primary WDAC hash type. */
  sha256?: string;

  /** SHA-1 hash of the binary (hex, 40 chars). For legacy rule compatibility. */
  sha1?: string;

  // ---- Signing information ----

  /**
   * Common name (CN) of the leaf / end-entity certificate.
   * Matches the CertPublisher attribute on WDAC signer rules.
   */
  signerName?: string;

  /**
   * TBSCertificate hash (hex string) of the root certificate.
   * Matches certRoot TBS type on WDAC signer rules.
   */
  rootCertTbs?: string;

  /**
   * Common name of the issuing CA.
   * Matches certIssuer on WDAC signer rules.
   */
  issuerName?: string;

  // ---- PE version resource attributes (used by FileAttrib scoping) ----

  /** OriginalFilename from the PE version resource. */
  originalFileName?: string;

  /** InternalName from the PE version resource. */
  internalName?: string;

  /** ProductName from the PE version resource. */
  productName?: string;

  /**
   * Version string in "major.minor.patch.build" format.
   * Evaluated against minimumFileVersion / maximumFileVersion constraints.
   */
  fileVersion?: string;

  // ---- Path ----

  /**
   * Full Windows file path (e.g. "C:\Windows\System32\ntdll.dll").
   * WDAC macros (%WINDIR%, %OSDRIVE%, etc.) in rules are expanded during simulation.
   */
  filePath?: string;

  // ---- Signing scenario ----

  /**
   * True if this is a kernel-mode binary (driver .sys, etc.).
   * Determines which signing scenario is evaluated: 131 (kernel) or 12 (user).
   * Defaults to false (user-mode) when unset.
   */
  isKernelMode?: boolean;
}

// ---------------------------------------------------------------------------
// Evaluation phases — maps directly to WDAC's rule precedence order
// ---------------------------------------------------------------------------

/**
 * The phase of WDAC's rule evaluation pipeline a step belongs to.
 * Deny rules always precede allow rules; within each group, more-specific
 * rule types are checked before less-specific ones.
 */
export type EvalPhase =
  | "mode-check"             // UMCI / audit-mode pre-flight
  | "scenario-select"        // Signing scenario selection (kernel=131 / user=12)
  | "deny-hash"              // Explicit deny by SHA-256 or SHA-1
  | "deny-publisher"         // Explicit deny by signer/publisher rule
  | "deny-path"              // Explicit deny by file-path pattern
  | "allow-publisher"        // Unscoped publisher allow rule
  | "allow-publisher-scoped" // Publisher allow rule + FileAttrib scope check
  | "allow-hash"             // Allow by SHA-256 or SHA-1 hash
  | "allow-path"             // Allow by file-path pattern (broadest)
  | "default";               // No rule matched — implicit policy default

/** What happened at a single evaluation step. */
export type StepOutcome =
  | "matched"   // Rule matched the binary — evaluation stopped (final verdict from this rule)
  | "no-match"  // Rule did not match — evaluation continues
  | "skipped"   // Rule could not be evaluated (missing metadata)
  | "excepted"; // Rule matched but an exception override applied

// ---------------------------------------------------------------------------
// Rule type taxonomy
// ---------------------------------------------------------------------------

/** Identifies what kind of rule produced (or would have produced) the verdict. */
export type SimRuleType =
  | "deny-hash"
  | "deny-publisher"
  | "deny-publisher-scoped"
  | "deny-path"
  | "allow-hash"
  | "allow-publisher"
  | "allow-publisher-scoped"
  | "allow-path"
  | "allow-attribute"
  | "default-deny"
  | "default-allow"
  | "no-umci"       // UMCI disabled — user-mode not enforced
  | "no-scenario"   // Signing scenario absent from policy
  | "audit-passthrough";

// ---------------------------------------------------------------------------
// Step-level trace
// ---------------------------------------------------------------------------

/** A single entry in the rule evaluation trace. */
export interface EvalStep {
  /** Which evaluation phase this step belongs to. */
  phase: EvalPhase;

  /** ID of the rule being evaluated. Absent for pre-flight / default steps. */
  ruleId?: string;

  /** Display name of the rule (friendlyName ?? id). */
  ruleName?: string;

  /** Category of this rule. */
  ruleType: SimRuleType;

  /** Outcome of this step. */
  outcome: StepOutcome;

  /** Human-readable explanation of what was checked and why. */
  detail: string;
}

// ---------------------------------------------------------------------------
// Final verdict
// ---------------------------------------------------------------------------

/**
 * The simulation verdict.
 * - "allowed"    — binary would execute.
 * - "blocked"    — binary would be blocked.
 * - "audit-only" — policy is in audit mode; binary is logged but not blocked.
 *                  `enforcementVerdict` shows what would happen in enforcement mode.
 */
export type SimVerdict = "allowed" | "blocked" | "audit-only";

/**
 * How the final verdict was reached.
 */
export type MatchedBy =
  | "hash"
  | "publisher"
  | "publisher-scoped"
  | "path"
  | "attribute"
  | "default"
  | "umci-disabled"
  | "no-scenario";

// ---------------------------------------------------------------------------
// EvaluationResult — the top-level output
// ---------------------------------------------------------------------------

export interface EvaluationResult {
  /** Final verdict. */
  verdict: SimVerdict;

  /**
   * If audit mode is active, the verdict enforcement mode *would* have produced.
   * Only set when `verdict === "audit-only"`.
   */
  enforcementVerdict?: "allowed" | "blocked";

  /** ID of the rule that determined the verdict (absent for default deny). */
  matchingRuleId?: string;

  /** Display name of the matching rule. */
  matchingRuleName?: string;

  /** Category of the matching rule. */
  matchingRuleType?: SimRuleType;

  /** What class of match produced the verdict. */
  matchedBy?: MatchedBy;

  /** Signing scenario value that was evaluated (131 = kernel, 12 = user). */
  scenarioValue?: 131 | 12;

  /** Whether the policy is in enforcement or audit mode. */
  policyMode: "enforcement" | "audit";

  /** Plain-language explanation of the decision. */
  explanation: string;

  /** Ordered evaluation trace — one entry per rule checked. */
  steps: EvalStep[];

  /** Simulation accuracy warnings (e.g. missing hash → hash rules skipped). */
  warnings: string[];
}

// ---------------------------------------------------------------------------
// API shapes
// ---------------------------------------------------------------------------

export interface SimulateBinaryRequest {
  binary: BinaryMetadata;
  policy: WdacPolicy;
}

export interface SimulateBinaryResponse {
  result: EvaluationResult;
}
