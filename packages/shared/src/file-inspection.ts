/**
 * File Inspection — Shared Types
 *
 * Types for the file inspection pipeline (AppControl Manager parity for
 * "Get Code Integrity Hashes", "View File Certificates", and the file/folder
 * scan modes of "Create Supplemental Policy" / "Create Deny Policy").
 *
 * Hash semantics (match ConfigCI / New-CIPolicyRule -Level Hash):
 *   - Authenticode SHA1/SHA256: PE image hash excluding the CheckSum field,
 *     the Certificate Table data-directory entry and the certificate table
 *     itself. This is the value WDAC compares for PE files.
 *   - Page SHA1/SHA256: hash of the PE header page (SizeOfHeaders bytes)
 *     with the same two exclusions. Emitted by Microsoft tooling as the
 *     "Hash Page Sha1/Sha256" rules.
 *   - Flat SHA1/SHA256: plain file hash. WDAC uses flat hashes for non-PE
 *     files (scripts, MSI) — for PE files they are informational only.
 *
 * TBS hash semantics (match ConfigCI signer rules):
 *   The TBSCertificate bytes are hashed with the digest algorithm of the
 *   certificate's OWN signature algorithm (SHA1 / SHA256 / SHA384 / SHA512).
 */

import type { WdacFileRule, WdacSignerRule, WdacEku } from "./policy";
import type { BinaryMetadata } from "./simulation";

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

export interface CodeIntegrityHashes {
  /** Authenticode SHA-1 (PE only) */
  sha1Authenticode?: string;
  /** Authenticode SHA-256 (PE only) — the value used by WDAC hash rules */
  sha256Authenticode?: string;
  /** Header-page SHA-1 (PE only) */
  sha1Page?: string;
  /** Header-page SHA-256 (PE only) */
  sha256Page?: string;
  /** Flat SHA-1 of the whole file */
  sha1Flat: string;
  /** Flat SHA-256 of the whole file */
  sha256Flat: string;
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

export type TbsHashAlgorithm = "MD5" | "SHA1" | "SHA256" | "SHA384" | "SHA512";

export interface InspectedCertificate {
  subjectCN: string;
  subjectDN: string;
  issuerCN: string;
  issuerDN: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  /** Hex TBS hash computed with tbsHashAlgorithm (the cert's signature digest) */
  tbsHash: string;
  tbsHashAlgorithm: TbsHashAlgorithm;
  /** SHA-1 thumbprint of the full DER certificate */
  thumbprint: string;
  isCa: boolean;
  isSelfSigned: boolean;
  /** Extended key usage OIDs in dotted form (e.g. 1.3.6.1.5.5.7.3.3) */
  ekus: string[];
}

export interface InspectedSignature {
  /** 0 = primary signature; 1+ = nested (dual) signatures */
  index: number;
  /** Digest algorithm declared in SpcIndirectDataContent (e.g. SHA256) */
  digestAlgorithm?: string;
  /** Authenticode digest embedded in the signature */
  embeddedDigest?: string;
  /** True when the embedded digest equals the freshly computed Authenticode hash */
  digestMatches?: boolean;
  /** The signing (leaf) certificate */
  leaf: InspectedCertificate;
  /**
   * Certificate chain from leaf upward, as embedded in the PKCS#7 blob.
   * May stop before the root when the root is not embedded (typical for
   * Windows binaries).
   */
  chain: InspectedCertificate[];
  /**
   * The certificate used as CertRoot by Publisher / PcaCertificate rules:
   * the highest NON-self-signed certificate in the chain (ConfigCI ignores
   * self-signed roots).
   */
  pca?: InspectedCertificate;
  /** Wellknown root ID (hex, e.g. "06") when the chain terminates at a Microsoft well-known root */
  wellknownRootId?: string;
  hasTimestamp: boolean;
}

// ---------------------------------------------------------------------------
// PE metadata
// ---------------------------------------------------------------------------

export interface PeVersionInfo {
  originalFileName?: string;
  internalName?: string;
  fileDescription?: string;
  productName?: string;
  companyName?: string;
  /** Free-form FileVersion string from StringFileInfo */
  fileVersion?: string;
  productVersion?: string;
  /** Numeric file version from VS_FIXEDFILEINFO as "a.b.c.d" — used for MinimumFileVersion */
  fixedFileVersion?: string;
  fixedProductVersion?: string;
}

export type InspectedFileType = "pe" | "script" | "msi" | "catalog" | "other";
export type PeKind = "exe" | "dll" | "sys" | "other";

export interface InspectedFile {
  fileName: string;
  sizeBytes: number;
  fileType: InspectedFileType;
  isPe: boolean;
  peKind?: PeKind;
  /** PE machine type, e.g. "x64", "x86", "ARM64" */
  machine?: string;
  /** True for kernel-mode images (drivers) — determines signing scenario 131 */
  isKernelMode: boolean;
  hashes: CodeIntegrityHashes;
  versionInfo?: PeVersionInfo;
  /** Package family name when the file is an MSIX/AppX manifest-bearing package (rare in uploads) */
  packageFamilyName?: string;
  signature: {
    /** "embedded" = Authenticode PKCS#7 present; "none" = unsigned or catalog-signed */
    status: "embedded" | "none";
    signatures: InspectedSignature[];
  };
  /** Ready-to-use metadata for POST /api/policy/simulate */
  simulationMetadata: BinaryMetadata;
  warnings: string[];
}

// ---------------------------------------------------------------------------
// Rule levels — mirrors New-CIPolicyRule -Level / AppControl Manager scan levels
// ---------------------------------------------------------------------------

export type RuleLevel =
  | "Hash"
  | "FileName"
  | "FilePath"
  | "SignedVersion"
  | "Publisher"
  | "FilePublisher"
  | "LeafCertificate"
  | "PcaCertificate"
  | "RootCertificate"
  | "WHQL"
  | "WHQLPublisher"
  | "WHQLFilePublisher";

export const RULE_LEVELS: Array<{
  id: RuleLevel;
  label: string;
  description: string;
  requiresSignature: boolean;
  requiresVersionInfo: boolean;
}> = [
  { id: "Hash", label: "Hash", description: "Authenticode SHA1/SHA256 + page hashes. Exact binary only; breaks on every update.", requiresSignature: false, requiresVersionInfo: false },
  { id: "FilePublisher", label: "FilePublisher", description: "Publisher + FileAttrib (OriginalFileName + MinimumFileVersion). Recommended for signed apps.", requiresSignature: true, requiresVersionInfo: true },
  { id: "SignedVersion", label: "SignedVersion", description: "Publisher + version floor for any file name from this publisher.", requiresSignature: true, requiresVersionInfo: true },
  { id: "Publisher", label: "Publisher", description: "PCA CertRoot + leaf CN. Trusts every file this publisher signs under this CA.", requiresSignature: true, requiresVersionInfo: false },
  { id: "LeafCertificate", label: "LeafCertificate", description: "Pins the exact signing certificate. Breaks on certificate renewal.", requiresSignature: true, requiresVersionInfo: false },
  { id: "PcaCertificate", label: "PcaCertificate", description: "Trusts everything issued under the intermediate (PCA) certificate.", requiresSignature: true, requiresVersionInfo: false },
  { id: "RootCertificate", label: "RootCertificate", description: "Same anchor as PcaCertificate (ConfigCI ignores self-signed roots). Very broad.", requiresSignature: true, requiresVersionInfo: false },
  { id: "WHQLFilePublisher", label: "WHQLFilePublisher", description: "FilePublisher + WHQL EKU. Drivers only.", requiresSignature: true, requiresVersionInfo: true },
  { id: "WHQLPublisher", label: "WHQLPublisher", description: "Publisher + WHQL EKU. Drivers only.", requiresSignature: true, requiresVersionInfo: false },
  { id: "WHQL", label: "WHQL", description: "CertRoot + WHQL EKU (no publisher). Drivers only.", requiresSignature: true, requiresVersionInfo: false },
  { id: "FileName", label: "FileName", description: "OriginalFileName + MinimumFileVersion only. Mutable metadata — weak.", requiresSignature: false, requiresVersionInfo: true },
  { id: "FilePath", label: "FilePath", description: "Path pattern. Weakest; user-mode only.", requiresSignature: false, requiresVersionInfo: false },
];

// ---------------------------------------------------------------------------
// Rule bundles — output of level-based rule generation for one file
// ---------------------------------------------------------------------------

export interface FileRuleBundle {
  fileName: string;
  requestedLevel: RuleLevel;
  /** Level actually used (differs from requestedLevel when a fallback applied) */
  effectiveLevel: RuleLevel;
  effect: "Allow" | "Deny";
  /** 131 for kernel-mode images, 12 otherwise */
  scenario: 131 | 12;
  fileRules: WdacFileRule[];
  signers: WdacSignerRule[];
  ekus: WdacEku[];
  notes: string[];
  /** Set when no rule could be produced at the requested level or any fallback */
  skippedReason?: string;
}

// ---------------------------------------------------------------------------
// API shapes
// ---------------------------------------------------------------------------

export interface InspectFilesResponse {
  files: InspectedFile[];
  /** Whether the server could compute Authenticode hashes (always true; kept for forward-compat) */
  capabilities: { authenticode: boolean; pageHash: boolean; signatures: boolean };
}

export interface BuildFileRulesRequest {
  files: InspectedFile[];
  level: RuleLevel;
  effect?: "Allow" | "Deny";
  /** Fall back to Hash when the requested level is not possible (default true) */
  fallbackToHash?: boolean;
  /** Path to use for FilePath level (one per file, keyed by fileName) */
  filePaths?: Record<string, string>;
}

export interface BuildFileRulesResponse {
  bundles: FileRuleBundle[];
}
