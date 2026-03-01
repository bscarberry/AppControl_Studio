/**
 * Security Types — shared between client and server
 *
 * The server holds SecurityConfig (with token hashes) locally.
 * The client receives only SecurityStatus (safe for display).
 */

// ---------------------------------------------------------------------------
// Role-based access control
// ---------------------------------------------------------------------------

/**
 * Three-tier role hierarchy.
 *
 * viewer  — read-only (parse, compare, explain)
 * analyst — viewer + write-side operations (generate, propose rules, ingest)
 * admin   — analyst + security management (audit log access, RBAC config)
 */
export type RbacRole = "admin" | "analyst" | "viewer";

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export type AuditEventType =
  // Policy lifecycle
  | "POLICY_LOADED"
  | "POLICY_GENERATED"
  | "POLICY_COMPARED"
  | "POLICY_SEMANTIC_COMPARED"
  | "POLICY_EXPLAINED"
  | "POLICY_BUILT_FROM_EVENTS"
  // Rule / ingestion operations
  | "RULES_PROPOSED"
  | "HUNTING_INGESTED"
  // Security events
  | "AUTH_SUCCESS"
  | "AUTH_FAILED"
  | "AUTHZ_DENIED"
  | "VALIDATION_REJECTED"
  | "CONFIG_CHANGED"
  // Infrastructure
  | "SERVER_START"
  | "SERVER_STOP";

/**
 * One structured audit event.
 *
 * Policy content is NEVER stored — only metadata (hashes, counts, durations).
 * This file is append-only JSONL; never rewritten after creation.
 */
export interface AuditEvent {
  /** UUID v4 */
  id: string;
  /** ISO 8601 UTC */
  timestamp: string;
  eventType: AuditEventType;
  /** Role of the caller (undefined when RBAC is disabled) */
  role?: RbacRole;
  /** SHA-256 of raw input content (hex). NEVER the content itself. */
  inputHash?: string;
  /** Byte length of input */
  inputSizeBytes?: number;
  /** Human-readable output summary ("47 rules, 3 warnings") */
  outputSummary?: string;
  /** Request duration in milliseconds */
  durationMs?: number;
  /** Always 127.0.0.1 for local-only deployments */
  remoteAddr?: string;
  succeeded: boolean;
  /** Short machine-readable error code on failure */
  errorCode?: string;
  /** Sanitized error message — must never contain policy content */
  errorMessage?: string;
}

// ---------------------------------------------------------------------------
// Security status (safe for client display)
// ---------------------------------------------------------------------------

export interface SecurityStatus {
  /** Server is bound to 127.0.0.1 only */
  localOnlyBinding: true;
  /** No outbound HTTP calls are made during policy processing */
  noExternalTransmission: true;
  rbacEnabled: boolean;
  auditEnabled: boolean;
  /** Policy data is never written to temporary files */
  memoryOnlyMode: boolean;
  serverVersion: string;
  auditEventCount: number;
  recentEvents: AuditEvent[];
}
