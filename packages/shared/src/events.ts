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
  // Kernel-mode signing / driver integrity violations (block)
  // Source: MS Learn "Understanding App Control event IDs" appendix
  // -------------------------------------------------------------------------
  3001: "An unsigned driver was attempted to load on the system.",
  3002: "Code Integrity couldn't verify the boot image as the page hash couldn't be found.",
  // NOTE: 3003 does NOT appear in Microsoft's official event ID appendix and has been removed.
  3004: "Code Integrity couldn't verify the file as the page hash couldn't be found. May indicate a kernel driver with invalid signature or /INTEGRITYCHECK code that isn't signed correctly.",
  3010: "The catalog containing the signature for the file under validation is invalid.",
  3023: "The driver file under validation didn't meet the requirements to pass the App Control policy. Often caused by a revoked signature or an expired Lifetime Signing EKU.",

  // -------------------------------------------------------------------------
  // Revocation-related (block)
  // -------------------------------------------------------------------------
  3026: "Microsoft or the certificate issuing authority revoked the certificate that signed the catalog.",
  3032: "The file under validation is revoked or the file has a signature that is revoked.",
  3036: "Microsoft or the certificate issuing authority revoked the certificate that signed the file being validated.",

  // -------------------------------------------------------------------------
  // Kernel-mode App Control — enforcement and audit
  // -------------------------------------------------------------------------
  3033: "The file under validation didn't meet the requirements to pass the App Control policy. May occur alongside a 3077 event if caused by App Control; often a revoked or Lifetime Signing EKU-expired signature.",
  3034: "The file under validation wouldn't meet the requirements to pass the App Control policy if it was enforced. The file was allowed since the policy is in audit mode.",

  // -------------------------------------------------------------------------
  // User-mode DLL enforcement and audit
  // -------------------------------------------------------------------------
  3064: "If the App Control policy was enforced, a user mode DLL under validation wouldn't meet the requirements to pass the App Control policy. The DLL was allowed since the policy is in audit mode.",
  3065: "A user mode DLL under validation didn't meet the requirements to pass the App Control policy.",

  // -------------------------------------------------------------------------
  // User-mode App Control — audit (policy in audit mode, file NOT blocked)
  // -------------------------------------------------------------------------
  3076: "This event is the main App Control block event for audit mode policies. It indicates that the file would have been blocked if the policy was enforced.",

  // -------------------------------------------------------------------------
  // User-mode App Control — enforcement (policy enforced, file IS blocked)
  // -------------------------------------------------------------------------
  3077: "This event is the main App Control block event for enforced policies. It indicates that the file didn't pass your policy and was blocked.",

  // -------------------------------------------------------------------------
  // Additional file-control events — enforcement and audit
  // -------------------------------------------------------------------------
  3079: "The file under validation didn't meet the requirements to pass the App Control policy.",
  3080: "If the App Control policy was in enforced mode, the file under validation wouldn't have met the requirements to pass the App Control policy.",
  3081: "The file under validation didn't meet the requirements to pass the App Control policy.",
  3082: "If the App Control policy was enforced, the policy would have blocked this non-WHQL driver.",

  // -------------------------------------------------------------------------
  // HVCI / Dynamic Code Security (block)
  // -------------------------------------------------------------------------
  3111: "The file under validation didn't meet the hypervisor-protected code integrity (HVCI) policy.",
  3114: "Dynamic Code Security opted the .NET app or DLL into App Control policy validation. The file under validation didn't pass your policy and was blocked.",

  // -------------------------------------------------------------------------
  // Supplemental / correlated events (info)
  // -------------------------------------------------------------------------
  3089: "This event contains signature information for files that were blocked or audit-blocked by App Control. One 3089 event is created for each signature of a file. Correlated with 3004, 3033, 3034, 3076, and 3077 events.",
  3099: "Indicates that an App Control policy has been loaded. Includes information about the policy options.",

  // -------------------------------------------------------------------------
  // ISG / Managed Installer diagnostic events
  // -------------------------------------------------------------------------
  3090: "Optional: This event indicates that a file was allowed to run based purely on ISG or Managed Installer.",
  3091: "This event indicates that a file didn't have ISG or Managed Installer authorization and the App Control policy is in audit mode.",
  3092: "This event is the enforcement mode equivalent of 3091. The file was blocked.",
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
