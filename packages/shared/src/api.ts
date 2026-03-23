/**
 * API Request/Response Types
 *
 * Shared between client and server for type-safe API communication.
 */

import type { WdacPolicy, PolicyComparisonResult } from "./policy";
import type { EventImportResult, ParsedCiEvent } from "./events";

// ---------------------------------------------------------------------------
// Generic API response wrapper
// ---------------------------------------------------------------------------

export interface ApiSuccess<T> {
  ok: true;
  data: T;
}

export interface ApiError {
  ok: false;
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export type ApiResponse<T> = ApiSuccess<T> | ApiError;

// ---------------------------------------------------------------------------
// Policy endpoints
// ---------------------------------------------------------------------------

/** POST /api/policy/parse — upload XML, receive normalized policy model */
export interface ParsePolicyRequest {
  /** Raw XML string content */
  xml: string;
  /** Optional filename for display */
  fileName?: string;
}

export interface ParsePolicyResponse {
  policy: WdacPolicy;
  warnings: string[];
}

/** POST /api/policy/generate — policy model -> deployable XML */
export interface GeneratePolicyRequest {
  policy: WdacPolicy;
  /** If true, sign the policy (requires additional tooling — stub for now) */
  sign?: boolean;
}

export interface GeneratePolicyResponse {
  xml: string;
  /** Size in bytes */
  xmlSizeBytes: number;
}

/** POST /api/policy/compare — structural diff of two policies */
export interface ComparePoliciesRequest {
  leftXml: string;
  rightXml: string;
}

export interface ComparePoliciesResponse {
  comparison: PolicyComparisonResult;
}

/**
 * POST /api/policy/merge — merge 2–15 policies into one.
 *
 * The merged policy inherits its PolicyID, FriendlyName, and VersionEx from
 * the FIRST policy in the list (matching WDAC Wizard behavior). Rule IDs are
 * re-namespaced to avoid collisions.
 */
export interface MergePoliciesRequest {
  /** Array of raw XML strings, 2–15 policies. Order matters: first policy sets the base ID. */
  xmlFiles: string[];
  /** Override the merged policy's friendly name. Defaults to first policy's name. */
  friendlyName?: string;
}

export interface MergePoliciesResponse {
  policy: WdacPolicy;
  xml: string;
  mergeLog: string[];
  stats: {
    inputPolicies: number;
    totalFileRules: number;
    dedupedFileRules: number;
    totalSigners: number;
    dedupedSigners: number;
  };
}

/**
 * POST /api/policy/cert-info — extract publisher metadata from a certificate file.
 * Accepts DER (.cer/.crt) or PEM (.pem) X.509 certificates.
 */
export interface CertInfoRequest {
  /** Base64-encoded certificate file content */
  certBase64: string;
  fileName?: string;
}

export interface CertInfoResponse {
  subjectCN: string;
  subjectDN: string;
  issuerCN: string;
  issuerDN: string;
  /** TBSCertificate SHA-256 hash (hex) — use as certRoot value */
  tbsHash: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  isCodeSigning: boolean;
  isCa: boolean;
}

/**
 * POST /api/policy/convert-applocker — convert an AppLocker XML policy to WDAC rules.
 *
 * FilePublisherRule → WdacSignerRule (+ optional WdacFileAttrib for FilePublisher specificity)
 * FileHashRule      → WdacHashRule (SHA-256 preferred, SHA-1 fallback)
 * FilePathRule      → WdacPathRule
 * PackagedAppRule   → WdacPackageRule
 */
export interface ConvertAppLockerRequest {
  appLockerXml: string;
  /** Convert Deny rules too (default false — deny rules can cause lockouts) */
  includeDenyRules?: boolean;
}

export interface ConvertAppLockerResponse {
  policy: WdacPolicy;
  xml: string;
  convertLog: string[];
  stats: {
    publisherRules: number;
    hashRules: number;
    pathRules: number;
    packageRules: number;
    skippedRules: number;
  };
}

/**
 * Rule type to generate for a specific file in the policy build step.
 *
 * - hash       → SHA256 Allow rule (most precise; must update per binary build)
 * - publisher  → Signer rule using the publisher TBS hash (survives software updates)
 * - fileAttrib → OriginalFileName-based Allow rule (broader; requires publisher scoping for security)
 * - path       → FilePath Allow rule (broadest; weakest — bypass risk)
 * - skip       → Exclude this file from the generated policy
 */
export type FileRuleType = "hash" | "publisher" | "fileAttrib" | "path" | "skip";

/**
 * Per-file rule type selection made by the user in the Build Policy UI.
 * fileKey is the SHA256FlatHash if available, otherwise the normalized file path.
 */
export interface FileRuleSelection {
  fileKey: string;
  ruleType: FileRuleType;
}

/** POST /api/policy/from-events — generate a base policy from parsed events */
export interface CreatePolicyFromEventsRequest {
  events: ParsedCiEvent[];
  /** Policy template to start from */
  template?: "default-windows" | "allow-microsoft" | "deny-by-default" | "blank";
  policyName: string;
  /**
   * Whether to generate a Base or Supplemental policy.
   * Defaults to "Supplemental" when building from CI event logs (matching WDAC Wizard behavior).
   * A supplemental policy adds allow rules on top of an existing enforced base policy.
   */
  policyType?: "Base" | "Supplemental";
  /**
   * GUID of the base policy this supplemental policy extends.
   * Required when policyType is "Supplemental".
   * Populated from the PolicyGuid field in the CI events (the policy that triggered the blocks).
   */
  basePolicyId?: string;
  /**
   * Per-file rule type overrides from the Build Policy review table.
   * When provided these take precedence over the global fallback toggles below.
   */
  ruleSelections?: FileRuleSelection[];
  /**
   * Default rule type to use when no per-file selection is found.
   * Defaults to 'hash' if unset.
   */
  defaultRuleType?: FileRuleType;
  /** Legacy: if true and no ruleSelections are given, prefer publisher rules */
  preferPublisherRules: boolean;
  /** Legacy: if true and no ruleSelections are given, add path rules */
  includePathRules: boolean;
  auditMode: boolean;
}

export interface CreatePolicyFromEventsResponse {
  policy: WdacPolicy;
  xml: string;
  ruleCount: number;
  buildLog: string[];
}

// ---------------------------------------------------------------------------
// Event endpoints
// ---------------------------------------------------------------------------

/** POST /api/events/parse — parse CodeIntegrity event JSON/CSV */
export interface ParseEventsRequest {
  /** Raw file content */
  content: string;
  /** File format hint */
  format: "json" | "csv" | "evtx-json";
}

/** POST /api/hunting/parse — parse Advanced Hunting results */
export interface ParseHuntingRequest {
  content: string;
  format: "json" | "csv";
}

// ---------------------------------------------------------------------------
// Utility endpoints
// ---------------------------------------------------------------------------

/** GET /api/policy/options — returns all known policy rule options */
export interface PolicyOptionsResponse {
  options: Array<{
    value: number;
    name: string;
    description: string;
    critical: boolean;
  }>;
}

/** POST /api/policy/propose-rules — convert CI events into candidate WDAC rules */
export interface ProposeRulesApiRequest {
  events: ParsedCiEvent[];
  preferSignerRules: boolean;
  scopeSignerRules: boolean;
  includePathRules: boolean;
  includeDenyRules: boolean;
}

/** POST /api/policy/semantic-compare — security-aware diff of two normalized policy objects */
export interface SemanticComparePoliciesRequest {
  leftXml: string;
  rightXml: string;
}

export type { PolicySemanticDiff } from "./policy-diff";

export interface SemanticComparePoliciesResponse {
  diff: import("./policy-diff").PolicySemanticDiff;
}

/** POST /api/policy/ingest-advanced-hunting — parse AH export → rule candidates */
export interface HuntingIngestApiRequest {
  format: "json" | "csv" | "auto";
  content: string;
  preferPublisherRules?: boolean;
  scopePublisherRules?: boolean;
  includePathRules?: boolean;
  effect?: "Allow" | "Deny";
}

export type { HuntingImportResult } from "./hunting-ingest";

/** GET /api/security/status */
export type { SecurityStatus } from "./security-types";

/** GET /api/security/audit */
export interface SecurityAuditResponse {
  events: import("./security-types").AuditEvent[];
  totalInMemory: number;
}

export interface HuntingIngestApiResponse {
  binaries: import("./hunting-ingest").HuntingBinary[];
  ruleCandidates: import("./hunting-ingest").HuntingRuleCandidate[];
  stats: import("./hunting-ingest").HuntingImportStats;
  warnings: import("./hunting-ingest").HuntingImportWarning[];
}

/** POST /api/policy/simulate — evaluate whether a binary would be allowed or blocked */
export type { SimulateBinaryRequest, SimulateBinaryResponse } from "./simulation";

/** POST /api/policy/explain — returns human-readable explanation of a policy */
export interface ExplainPolicyRequest {
  policy: WdacPolicy;
}

export interface ExplainPolicyResponse {
  summary: string;
  effectiveMode: "enforcement" | "audit" | "mixed";
  riskFlags: Array<{
    severity: "critical" | "warning" | "info";
    message: string;
    detail: string;
  }>;
  ruleBreakdown: {
    kernelMode: {
      allowedSignerCount: number;
      deniedSignerCount: number;
      fileRuleCount: number;
    };
    userMode: {
      allowedSignerCount: number;
      deniedSignerCount: number;
      fileRuleCount: number;
    };
  };
  optionDescriptions: Array<{
    optionName: string;
    enabled: boolean;
    description: string;
  }>;
}
