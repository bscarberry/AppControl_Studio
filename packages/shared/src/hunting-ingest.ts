/**
 * Advanced Hunting Ingest — Shared Types
 *
 * Types for the data ingestion pipeline that converts Microsoft Defender
 * Advanced Hunting query results into candidate WDAC policy rules.
 *
 * Supported source tables:
 *   - DeviceFileCertificateInfo  (SubjectName, IsSigned, SHA256)
 *   - DeviceFileEvents           (FileName, FolderPath, SHA256)
 *   - DeviceProcessEvents        (FileName, FolderPath, SHA256)
 *   - DeviceImageLoadEvents      (FileName, FolderPath, SHA256)
 *   - Generic / custom column sets (alias-based fallback)
 */

// ---------------------------------------------------------------------------
// Signing coverage classification
// ---------------------------------------------------------------------------

/** Describes how much signing metadata was found for this binary. */
export type HuntingSigningCoverage =
  /** SHA256 + signerName (publisher) + issuerName observed */
  | "full"
  /** SHA256 + signerName only — no issuer/root CA details */
  | "partial"
  /** SHA256 present, IsSigned=true, but no certificate details */
  | "hash-only"
  /** SHA256 present but binary is unsigned (IsSigned=false or no cert data) */
  | "unsigned"
  /** No SHA256 or SHA1 — only a file path is available */
  | "no-hash";

// ---------------------------------------------------------------------------
// Rule types and risk
// ---------------------------------------------------------------------------

export type HuntingRuleType =
  /** CertPublisher + FileAttrib scoped to FileName — most restrictive publisher rule */
  | "publisher-scoped"
  /** CertPublisher only — trusts all files from this publisher */
  | "publisher"
  /** SHA256 hash rule — precise but must be updated per binary build */
  | "hash"
  /** Explicit file path — use only when hash is unavailable */
  | "path"
  /** Wildcard path pattern — use with extreme caution */
  | "path-wildcard";

export type HuntingRuleRisk = "safe" | "low" | "medium" | "high" | "critical";

// ---------------------------------------------------------------------------
// Core data model
// ---------------------------------------------------------------------------

/** A deduplicated, merged record representing one unique binary across all observations. */
export interface HuntingBinary {
  /** Deduplication key: `sha256::<hex>` or `path::<lowercased-filepath>` */
  key: string;
  sha256: string | null;
  sha1: string | null;
  /** All distinct file names observed (usually 1; may vary for renamed binaries) */
  fileNames: string[];
  /** All distinct folder paths observed */
  folderPaths: string[];
  /** All assembled full file paths */
  filePaths: string[];
  /** All distinct publisher / SubjectName values observed */
  signerNames: string[];
  /** All distinct issuer / root CA names observed */
  issuerNames: string[];
  /** Raw IsSigned value if present in source data */
  isSigned: boolean | null;
  /** Signing coverage — set after deduplication pass */
  signingCoverage: HuntingSigningCoverage;
  /** All device names this binary was observed on */
  deviceNames: string[];
  /** Number of source rows merged into this record */
  observationCount: number;
  firstSeen: string | null;
  lastSeen: string | null;
}

/** A candidate WDAC policy rule generated from a HuntingBinary. */
export interface HuntingRuleCandidate {
  id: string;
  binary: HuntingBinary;
  ruleType: HuntingRuleType;
  effect: "Allow" | "Deny";
  risk: HuntingRuleRisk;
  /** 0–1 confidence score */
  confidence: number;
  /** Plain-language explanation of why this rule type was chosen */
  rationale: string;
  /**
   * Key WDAC XML attributes this rule would emit.
   * For UI display; not directly serialised to policy XML.
   */
  wdacAttributes: Record<string, string>;
  /** Rule-specific data quality warnings */
  warnings: string[];
  /** True when binary appears to be a kernel-mode driver (.sys / drivers path) */
  appliesToKernelMode: boolean;
}

// ---------------------------------------------------------------------------
// Import metadata
// ---------------------------------------------------------------------------

export interface HuntingImportWarning {
  code: string;
  message: string;
  affectedRows?: number;
}

export interface HuntingImportStats {
  totalRowsParsed: number;
  validRows: number;
  skippedRows: number;
  uniqueBinaries: number;
  /** full + partial coverage */
  signedBinaries: number;
  /** isSigned=false or no cert data */
  unsignedBinaries: number;
  /** partial + hash-only */
  partialSigningBinaries: number;
  /** no SHA256 at all */
  noHashBinaries: number;
  /** Schema adapter detected for this export */
  detectedSchema: string;
}

// ---------------------------------------------------------------------------
// Request / Response
// ---------------------------------------------------------------------------

export interface HuntingImportRequest {
  /** "auto" tries JSON first, then CSV */
  format: "json" | "csv" | "auto";
  /** Raw file content as a UTF-8 string */
  content: string;
  /** Prefer CertPublisher rules over hash rules where signing data is available. Default: true */
  preferPublisherRules?: boolean;
  /** Scope publisher rules to FileName via FileAttrib when FileName is consistent. Default: true */
  scopePublisherRules?: boolean;
  /** Generate path-rule candidates for no-hash binaries. Default: false */
  includePathRules?: boolean;
  /** Rule effect. Default: "Allow" */
  effect?: "Allow" | "Deny";
}

export interface HuntingImportResult {
  binaries: HuntingBinary[];
  ruleCandidates: HuntingRuleCandidate[];
  stats: HuntingImportStats;
  warnings: HuntingImportWarning[];
}
