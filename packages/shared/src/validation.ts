/**
 * Policy Validation — Shared Types
 *
 * AppControl Manager parity for "Validate Policies":
 *   Phase 1 — schema-level structural validation (cipolicy.xsd constraints
 *             re-implemented in TypeScript so it works on any platform)
 *   Phase 2 — policy content analysis (reference integrity, duplicate IDs)
 *   Phase 3 — extended content tests (option conflicts, deployability)
 *   Phase 4 — binary conversion (ConvertFrom-CIPolicy) — only when the server
 *             runs on Windows with the ConfigCI module available
 */

export type ValidationSeverity = "error" | "warning" | "info";

export type ValidationPhase =
  | "schema"
  | "references"
  | "content"
  | "toolchain";

export interface ValidationFinding {
  severity: ValidationSeverity;
  phase: ValidationPhase;
  /** Machine-readable code, e.g. INVALID_SIGNER_ID */
  code: string;
  message: string;
  /** Element / ID the finding refers to */
  context?: string;
}

export interface ToolchainValidation {
  /** True when ConvertFrom-CIPolicy / cipolicy.xsd were reachable on this host */
  available: boolean;
  xsdValidated?: boolean;
  xsdErrors?: string[];
  binaryConverted?: boolean;
  binarySizeBytes?: number;
  binaryError?: string;
  note?: string;
}

export interface PolicyValidationResult {
  valid: boolean;
  findings: ValidationFinding[];
  summary: { errors: number; warnings: number; infos: number };
  toolchain: ToolchainValidation;
  /** Byte size of the XML that was validated */
  xmlSizeBytes: number;
}

export interface ValidatePolicyRequest {
  /** Either a policy model or raw XML must be supplied */
  policy?: unknown;
  xml?: string;
  /** Attempt ConvertFrom-CIPolicy when available (default true) */
  useToolchain?: boolean;
}
