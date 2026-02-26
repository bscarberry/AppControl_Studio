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
  // Block events
  3001: "A code integrity check determined that a process attempted to load a kernel driver that did not meet the signing requirements.",
  3002: "Code Integrity determined that a process attempted to load a kernel driver that did not meet the security requirements.",
  3003: "Code Integrity determined that a process attempted to load a kernel driver that did not meet the requirements.",
  3004: "Code Integrity determined that this file does not meet the security requirements.",
  3010: "Code Integrity determined that a process attempted to load a module that did not meet the requirements.",
  3023: "Code Integrity determined that a process attempted to load a binary that did not meet the requirements.",
  3033: "Code Integrity determined that a process attempted to load a binary that did not meet the requirements (enforced).",
  3034: "Code Integrity determined that a process attempted to load a binary that did not meet the requirements (audit).",

  // Audit events
  3076: "AUDIT: Code integrity policy would have blocked the file from loading but is in audit mode.",
  3077: "AUDIT: Code integrity policy would have blocked the file from loading (script) but is in audit mode.",
  3089: "AUDIT: The file was blocked from loading due to a supplemental policy.",
  3099: "Code integrity policy was loaded.",

  // ISG/Managed Installer
  3097: "Code integrity determined that a file failed the ISG check.",
  3098: "AUDIT: Code integrity determined that a file failed the ISG check (audit mode).",
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
