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

/** POST /api/policy/merge — merge multiple policies into one */
export interface MergePoliciesRequest {
  baseXml: string;
  supplementXml: string;
  /** How to handle conflicts: 'union' (default) or 'base-wins' */
  conflictResolution?: "union" | "base-wins";
}

export interface MergePoliciesResponse {
  policy: WdacPolicy;
  mergeLog: string[];
}

/** POST /api/policy/from-events — generate a base policy from parsed events */
export interface CreatePolicyFromEventsRequest {
  events: ParsedCiEvent[];
  /** Policy template to start from */
  template?: "default-windows" | "allow-microsoft" | "deny-by-default" | "blank";
  policyName: string;
  /** If true, create publisher rules instead of hash rules where possible */
  preferPublisherRules: boolean;
  /** If true, add path rules for file paths */
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
