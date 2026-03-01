/**
 * CodeIntegrity Event Log Models
 *
 * Models CodeIntegrity events from the Windows Event Log (Microsoft-Windows-CodeIntegrity/Operational)
 * and from Microsoft Defender Advanced Hunting query results.
 *
 * Reference: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations
 */

// ---------------------------------------------------------------------------
// CodeIntegrity Event IDs
// ---------------------------------------------------------------------------

export const CI_EVENT_IDS = {
  // -------------------------------------------------------------------------
  // Kernel-mode signing / driver integrity violations
  // -------------------------------------------------------------------------
  3001: "Code Integrity detected an unsigned driver. The driver was not loaded.",
  3002: "Code Integrity is unable to verify the image integrity of a file because the set of per-page image hashes could not be found on the system.",
  3003: "Code Integrity determined that a process attempted to load a kernel module that did not meet the security requirements for Shared Sections.",
  3004: "Code Integrity is unable to verify the image integrity of a file because the file hash could not be found on the system.",
  3010: "Code Integrity is unable to load the %2 catalog.",
  3023: "Code Integrity determined that a process attempted to load a binary that did not pass code signing requirements (revoked or lifetime-signing EKU expired).",

  // -------------------------------------------------------------------------
  // Kernel-mode App Control enforcement / audit
  // -------------------------------------------------------------------------
  3033: "Code Integrity determined that a process attempted to load a binary that did not meet the signing requirements. The binary was blocked.",
  3034: "Code Integrity determined that a process attempted to load a binary that did not meet the signing requirements. The binary would have been blocked if the policy were enforced (audit mode).",

  // -------------------------------------------------------------------------
  // User-mode App Control audit (policy in audit mode — file NOT blocked)
  // -------------------------------------------------------------------------
  3076: "App Control policy audit: the file would have been blocked if the policy were in enforcement mode.",

  // -------------------------------------------------------------------------
  // User-mode App Control enforcement (policy enforced — file IS blocked)
  // -------------------------------------------------------------------------
  3077: "App Control policy enforcement: the file did not pass the policy and was blocked from loading.",

  // -------------------------------------------------------------------------
  // Supplemental / correlated events
  // -------------------------------------------------------------------------
  3089: "Signature information for a file that triggered a 3076 or 3077 event (one 3089 per signature on the file).",
  3099: "An App Control policy was loaded or refreshed on the system.",

  // -------------------------------------------------------------------------
  // ISG / Managed Installer diagnostic events
  // -------------------------------------------------------------------------
  3090: "The file was allowed to run based on ISG or Managed Installer authorization.",
  3091: "The file was not authorized by ISG or Managed Installer. The policy is in audit mode — the file was not blocked.",
  3092: "The file was not authorized by ISG or Managed Installer. The policy is in enforcement mode — the file was blocked.",
} as const;

export type CiEventId = keyof typeof CI_EVENT_IDS;

// ---------------------------------------------------------------------------
// Parsed Event Record
// ---------------------------------------------------------------------------

export type EventSource = "evtx" | "json" | "csv" | "advanced-hunting";
export type EventSeverity = "block" | "audit" | "info";

export interface ParsedCiEvent {
  /** Source event ID */
  eventId: number;
  /** UTC timestamp */
  timestamp: string;
  /** Machine/device name */
  machineName?: string;
  /** Process that attempted to load the file */
  requestingProcess?: string;
  requestingProcessId?: number;

  /** File that was blocked/audited */
  filePath: string;
  fileName?: string;

  /** SHA256 authenticode hash */
  sha256Hash?: string;
  /** SHA1 authenticode hash */
  sha1Hash?: string;
  /** SHA256 of the file page hashes */
  sha256FlatHash?: string;

  /** Signer information from the event */
  signerInfo?: {
    publisherName?: string;
    issuerName?: string;
    notValidAfter?: string;
    notValidBefore?: string;
    thumbprint?: string;
    /** TBS hash of the leaf certificate */
    leafCertTbs?: string;
    /** TBS hash of the root certificate */
    rootCertTbs?: string;
  };

  /** Product name from the file's version info */
  productName?: string;
  /** Original file name from the file's version info */
  originalFileName?: string;
  /** Internal name from the file's version info */
  internalName?: string;
  /** File description from the file's version info */
  fileDescription?: string;
  /** File version */
  fileVersion?: string;

  /** PolicyGUID that generated this audit event */
  policyGuid?: string;
  policyName?: string;

  /** Whether this is a block or audit event */
  severity: EventSeverity;

  /** Human-readable description of the event */
  description: string;

  /** Source of this event record */
  source: EventSource;
}

// ---------------------------------------------------------------------------
// Advanced Hunting Query Results
// ---------------------------------------------------------------------------

/** Schema for Microsoft Defender Advanced Hunting DeviceEvents table rows
 *  matching AppControlCodeIntegrityPolicyAudited / AppControlCodeIntegrityPolicyBlocked
 */
export interface AdvancedHuntingRow {
  Timestamp?: string;
  DeviceName?: string;
  DeviceId?: string;
  ActionType?: string;
  FileName?: string;
  FolderPath?: string;
  SHA256?: string;
  SHA1?: string;
  ProcessCommandLine?: string;
  InitiatingProcessFileName?: string;
  InitiatingProcessFolderPath?: string;
  InitiatingProcessSHA256?: string;
  AdditionalFields?: string | Record<string, unknown>;
  ReportId?: string | number;

  // AppControl-specific fields from AdditionalFields
  PolicyName?: string;
  PolicyGuid?: string;
  RequestedSigningLevel?: string;
  ValidatedSigningLevel?: string;
  PolicyHash?: string;
  OriginalFileName?: string;
  InternalName?: string;
  FileDescription?: string;
  FileVersion?: string;
  ProductName?: string;

  // Parsed signer info
  PublisherName?: string;
  IssuerName?: string;

  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Event Import Session
// ---------------------------------------------------------------------------

export interface EventImportSummary {
  totalEvents: number;
  blockEvents: number;
  auditEvents: number;
  uniqueFiles: number;
  uniqueSigners: number;
  timeRange?: {
    earliest: string;
    latest: string;
  };
}

export interface EventImportResult {
  events: ParsedCiEvent[];
  summary: EventImportSummary;
  parseErrors: Array<{ line?: number; message: string }>;
}
