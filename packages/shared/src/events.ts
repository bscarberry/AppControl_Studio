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
  // These events fire for kernel-mode code (signing scenario 131: drivers/boot images).
  // -------------------------------------------------------------------------
  3033: "A kernel-mode file under validation didn't meet the requirements to pass the App Control policy (enforcement mode). This kernel-mode block event often co-occurs with a revoked or Lifetime Signing EKU-expired signature.",
  3034: "A kernel-mode file under validation wouldn't meet the requirements to pass the App Control policy if it were enforced. The file was allowed since the policy is in audit mode (kernel-mode audit event).",

  // -------------------------------------------------------------------------
  // User-mode DLL enforcement and audit
  // -------------------------------------------------------------------------
  3064: "If the App Control policy was enforced, a user mode DLL under validation wouldn't meet the requirements to pass the App Control policy. The DLL was allowed since the policy is in audit mode.",
  3065: "A user mode DLL under validation didn't meet the requirements to pass the App Control policy.",

  // -------------------------------------------------------------------------
  // Kernel-mode App Control audit/block via signing level check
  // Source: WDAC Policy Wizard EventLog.cs (AUDIT_KERNEL_ID / BLOCK_KERNEL_ID)
  // -------------------------------------------------------------------------
  3067: "Kernel-mode audit event: A kernel-mode file would have been blocked by the signing level requirements if the App Control policy was enforced. The file was allowed since the policy is in audit mode.",
  3068: "Kernel-mode block event: A kernel-mode file didn't meet the signing level requirements of the App Control policy and was blocked.",

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
  // Require TestFlags registry key: 0x100 for 3091/3092, 0x300 for 3090 as well.
  // -------------------------------------------------------------------------
  3090: "Optional: This event indicates that a file was allowed to run based purely on ISG or Managed Installer.",
  3091: "This event indicates that a file didn't have ISG or Managed Installer authorization and the App Control policy is in audit mode.",
  3092: "This event is the enforcement mode equivalent of 3091. The file was blocked.",

  // -------------------------------------------------------------------------
  // AppLocker — MSI and Script log (Microsoft-Windows-AppLocker/MSI and Script)
  // These events cover script hosts (PowerShell, WSH, MSI) subject to App Control
  // when Option 11 (Disabled:Script Enforcement) is NOT set.
  // Source: WDAC Policy Wizard EventLog.cs (AUDIT_SCRIPT_ID / BLOCK_SCRIPT_ID / APP_SIG_INFO_ID)
  // -------------------------------------------------------------------------
  8028: "AppLocker audit event: A script or MSI file would have been blocked if the App Control policy was enforced. Logged to Microsoft-Windows-AppLocker/MSI and Script event log.",
  8029: "AppLocker block event: A script or MSI file was blocked from executing by the App Control policy. Logged to Microsoft-Windows-AppLocker/MSI and Script event log.",
  8038: "AppLocker signature information event: Contains signature details for a script or MSI file processed by App Control. Correlated with 8028/8029 events. Logged to Microsoft-Windows-AppLocker/MSI and Script event log.",
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
  /** UTC ISO-8601 timestamp */
  timestamp: string;
  /** Machine/device name */
  machineName?: string;
  /** Process that attempted to load the file */
  requestingProcess?: string;
  requestingProcessId?: number;

  /** Windows Event Log correlation activity ID — used to link 3089 signer events to 3076/3077 events */
  correlationId?: string;

  /** File that was blocked/audited */
  filePath: string;
  fileName?: string;

  // -------------------------------------------------------------------------
  // Cryptographic hashes
  //
  // For events 3076/3077 (and related), the EVTX property layout is:
  //   [5] Sha1FlatHash  (byte[20]) — SHA1 of the flat file
  //   [6] Sha256FlatHash (byte[32]) — SHA256 of the flat file  ← primary hash for policy rules
  //   [7] Sha1PageHash  (byte[20]) — SHA1 of page hashes
  //   [8] Sha256PageHash (byte[32]) — SHA256 of page hashes
  //
  // The "FlatHash" fields are what Microsoft uses in WDAC policy XML <Allow Hash="...">.
  // Legacy field sha256Hash is preserved for backwards compatibility with Advanced Hunting rows.
  // -------------------------------------------------------------------------

  /** SHA256 flat hash (primary policy hash — use this for Allow/Deny rules) */
  sha256FlatHash?: string;
  /** SHA1 flat hash */
  sha1FlatHash?: string;
  /** SHA256 page hash */
  sha256PageHash?: string;
  /** SHA1 page hash */
  sha1PageHash?: string;
  /**
   * Legacy: SHA256 hash from Advanced Hunting rows (DeviceFileCertificateInfo.SHA256).
   * For EVTX events, prefer sha256FlatHash.
   */
  sha256Hash?: string;
  /** Legacy SHA1 (Advanced Hunting). For EVTX events prefer sha1FlatHash. */
  sha1Hash?: string;

  /**
   * Signer information — populated by correlating 3089 "signature info" events
   * with their parent 3076/3077 events via the Windows Event Log Correlation ActivityID.
   */
  signerInfo?: {
    publisherName?: string;
    issuerName?: string;
    notValidAfter?: string;
    notValidBefore?: string;
    /** TBS hash of the publisher/leaf certificate — used as CertRoot in WDAC signer rules */
    publisherTbsHash?: string;
    /** TBS hash of the issuer certificate */
    issuerTbsHash?: string;
    /** Total number of signatures on the file (from 3089.TotalSignatureCount) */
    totalSignatureCount?: number;
    /** Index of this signature (0-based, from 3089.SignatureIndex) */
    signatureIndex?: number;
    /** Legacy fields kept for Advanced Hunting compatibility */
    thumbprint?: string;
    leafCertTbs?: string;
    rootCertTbs?: string;
  };

  // -------------------------------------------------------------------------
  // File version resource fields
  // Populated from EVTX properties for events 3076/3077 (props[13–18]):
  //   [13] OriginalFilename, [14] InternalName, [15] FileDescription,
  //   [16] ProductName, [17] FileVersion, [18] PackageFamilyName
  // -------------------------------------------------------------------------
  productName?: string;
  originalFileName?: string;
  internalName?: string;
  fileDescription?: string;
  fileVersion?: string;
  /** UWP / MSIX package family name (for packaged-app allow rules) */
  packageFamilyName?: string;

  /** PolicyGUID that generated this audit/block event */
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
