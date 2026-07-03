/**
 * Advanced Hunting Ingestor
 *
 * Transformation pipeline:
 *   parse (JSON/CSV)
 *   → normalize rows via schema adapter
 *   → validate (require at least one identifier)
 *   → deduplicate by SHA256 or file path
 *   → classify signing coverage
 *   → generate WDAC rule candidates
 *   → collect stats and warnings
 *
 * Supported Microsoft Defender Advanced Hunting tables:
 *   DeviceFileCertificateInfo  — certificate-centric (SubjectName, IsSigned, SHA256)
 *   DeviceFileEvents           — file creation / modification events
 *   DeviceProcessEvents        — process launch events
 *   DeviceImageLoadEvents      — DLL / driver load events
 *   Generic                    — case-insensitive alias matching for custom exports
 *
 * Extensibility: add a new SchemaAdapter to ADAPTERS (before genericAdapter)
 * to handle additional Defender table schemas without changing the pipeline.
 */

import type {
  HuntingBinary,
  HuntingImportRequest,
  HuntingImportResult,
  HuntingImportStats,
  HuntingImportWarning,
  HuntingRuleCandidate,
  HuntingRuleRisk,
  HuntingRuleType,
  HuntingSigningCoverage,
} from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Internal normalized row (produced by schema adapters, before deduplication)
// ---------------------------------------------------------------------------

interface AhRow {
  sha256: string | null;
  sha1: string | null;
  fileName: string | null;
  folderPath: string | null;
  /** Pre-assembled full path from source, or assembled from folder+file */
  filePath: string | null;
  /** SubjectName / publisher name from the authenticode certificate */
  signerName: string | null;
  /** IssuerName / root CA from the authenticode certificate */
  issuerName: string | null;
  /** Explicit IsSigned flag from source row, if available */
  isSigned: boolean | null;
  deviceName: string | null;
  timestamp: string | null;
}

// ---------------------------------------------------------------------------
// CSV parser — RFC 4180, handles BOM, CRLF, escaped quotes
// ---------------------------------------------------------------------------

function parseCsvLine(line: string): string[] {
  const fields: string[] = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === ",") {
        fields.push(field);
        field = "";
      } else {
        field += ch;
      }
    }
  }
  fields.push(field);
  return fields;
}

function parseCsv(content: string): Record<string, string>[] {
  // Strip UTF-8 BOM if present (common in Excel/Defender CSV exports)
  const text = content.startsWith("\uFEFF") ? content.slice(1) : content;
  const lines = text.split(/\r?\n/);
  if (lines.length < 2) return [];

  const headers = parseCsvLine(lines[0]).map((h) => h.trim());
  const rows: Record<string, string>[] = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const values = parseCsvLine(line);
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => {
      row[h] = (values[idx] ?? "").trim();
    });
    rows.push(row);
  }

  return rows;
}

// ---------------------------------------------------------------------------
// JSON parser — handles three Defender export formats:
//   1. Array of objects:             [{...}, ...]
//   2. Results wrapper:              { "Results": [{...}, ...] }
//   3. Columnar (schema + rows):     { "schema": [...], "rows": [[...], ...] }
// ---------------------------------------------------------------------------

function flattenToStrings(obj: unknown): Record<string, string> {
  if (typeof obj !== "object" || obj === null) return {};
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    if (value === null || value === undefined) {
      result[key] = "";
    } else if (typeof value === "object") {
      result[key] = JSON.stringify(value);
    } else {
      result[key] = String(value);
    }
  }
  return result;
}

function parseJson(content: string): Record<string, string>[] {
  const parsed: unknown = JSON.parse(content);

  if (Array.isArray(parsed)) {
    return parsed.map(flattenToStrings);
  }

  if (parsed !== null && typeof parsed === "object") {
    const obj = parsed as Record<string, unknown>;

    // { Results: [...] }
    if (Array.isArray(obj["Results"])) {
      return (obj["Results"] as unknown[]).map(flattenToStrings);
    }

    // { schema: [...], rows: [...] }
    if (Array.isArray(obj["schema"]) && Array.isArray(obj["rows"])) {
      const schema = obj["schema"] as Array<Record<string, string>>;
      const headers = schema.map((col) => col["Name"] ?? col["name"] ?? "");
      return (obj["rows"] as unknown[][]).map((row) => {
        const r: Record<string, string> = {};
        headers.forEach((h, i) => {
          r[h] = String(row[i] ?? "");
        });
        return r;
      });
    }
  }

  return [];
}

function detectFormat(content: string): "json" | "csv" {
  const trimmed = content.trimStart().replace(/^\uFEFF/, "");
  return trimmed.startsWith("[") || trimmed.startsWith("{") ? "json" : "csv";
}

// ---------------------------------------------------------------------------
// Schema adapter interface
//
// Add new adapters here and insert them before genericAdapter in ADAPTERS.
// ---------------------------------------------------------------------------

interface SchemaAdapter {
  /** Display name shown in ImportStats.detectedSchema */
  name: string;
  /** Return true if this adapter should handle this export (based on header set) */
  canHandle(headers: Set<string>): boolean;
  /** Map a raw row Record to a normalized AhRow */
  mapRow(raw: Record<string, string>): AhRow;
}

// ---------------------------------------------------------------------------
// Adapter helpers
// ---------------------------------------------------------------------------

/** Case-insensitive first-match lookup across a set of field aliases */
function pick(raw: Record<string, string>, ...aliases: string[]): string | null {
  for (const alias of aliases) {
    const lower = alias.toLowerCase();
    for (const [key, value] of Object.entries(raw)) {
      if (key.toLowerCase() === lower && value.trim() !== "") {
        return value.trim();
      }
    }
  }
  return null;
}

function pickBool(raw: Record<string, string>, ...aliases: string[]): boolean | null {
  const val = pick(raw, ...aliases);
  if (val === null) return null;
  const lower = val.toLowerCase();
  if (lower === "true" || lower === "1" || lower === "yes") return true;
  if (lower === "false" || lower === "0" || lower === "no") return false;
  return null;
}

function hasHeader(headers: Set<string>, ...names: string[]): boolean {
  for (const name of names) {
    const lower = name.toLowerCase();
    for (const h of headers) {
      if (h.toLowerCase() === lower) return true;
    }
  }
  return false;
}

function assembleFilePath(folderPath: string | null, fileName: string | null): string | null {
  if (!folderPath || !fileName) return null;
  return `${folderPath.replace(/\\+$/, "")}\\${fileName}`;
}

// ---------------------------------------------------------------------------
// Built-in adapters
// ---------------------------------------------------------------------------

/**
 * DeviceFileCertificateInfo
 * Distinguishing features: SubjectName + IsSigned present; no FileName/FolderPath.
 */
const deviceFileCertInfoAdapter: SchemaAdapter = {
  name: "DeviceFileCertificateInfo",
  canHandle(headers) {
    return (
      hasHeader(headers, "SubjectName", "CertificateSubjectName") &&
      hasHeader(headers, "IsSigned") &&
      !hasHeader(headers, "FileName") &&
      !hasHeader(headers, "FolderPath")
    );
  },
  mapRow(raw) {
    return {
      sha256: pick(raw, "SHA256", "Sha256"),
      sha1: pick(raw, "SHA1", "Sha1"),
      fileName: null,
      folderPath: null,
      filePath: null,
      signerName: pick(raw, "SubjectName", "CertificateSubjectName", "SignerName"),
      issuerName: pick(raw, "IssuerName", "CertificateIssuerName", "Issuer"),
      isSigned: pickBool(raw, "IsSigned"),
      deviceName: pick(raw, "DeviceName", "ComputerName", "HostName"),
      timestamp: pick(raw, "Timestamp", "EventTime", "TimeGenerated"),
    };
  },
};

/**
 * DeviceEvents adapter — handles DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents.
 * Distinguishing features: FileName + FolderPath columns present.
 */
const deviceEventAdapter: SchemaAdapter = {
  name: "DeviceEvents",
  canHandle(headers) {
    return hasHeader(headers, "FileName") && hasHeader(headers, "FolderPath");
  },
  mapRow(raw) {
    const fileName = pick(raw, "FileName");
    const folderPath = pick(raw, "FolderPath");
    const signerName =
      pick(raw, "PublisherName") ??
      pick(raw, "SubjectName", "SignerName", "Publisher") ??
      null;
    const issuerName = pick(raw, "IssuerName", "Issuer") ?? null;
    return {
      sha256: pick(raw, "SHA256", "Sha256"),
      sha1: pick(raw, "SHA1", "Sha1"),
      fileName,
      folderPath,
      filePath: pick(raw, "FilePath") ?? assembleFilePath(folderPath, fileName),
      signerName,
      issuerName,
      // Infer isSigned=true when publisher data is present but no explicit field
      isSigned: pickBool(raw, "IsSigned") ?? (signerName ? true : null),
      deviceName: pick(raw, "DeviceName", "ComputerName"),
      timestamp: pick(raw, "Timestamp", "EventTime", "TimeGenerated"),
    };
  },
};

/**
 * Generic fallback — uses broad alias lists to handle custom column names
 * and mixed table exports. Always accepts any header set.
 */
const genericAdapter: SchemaAdapter = {
  name: "Generic",
  canHandle() {
    return true;
  },
  mapRow(raw) {
    const sha256 = pick(raw, "SHA256", "Sha256", "sha256", "FileHashSHA256", "Hash");
    const sha1 = pick(raw, "SHA1", "Sha1", "sha1", "FileHashSHA1");
    const fileName = pick(
      raw,
      "FileName",
      "filename",
      "file_name",
      "ProcessImageName",
      "ImageName",
      "Name"
    );
    const folderPath = pick(
      raw,
      "FolderPath",
      "folderPath",
      "folder_path",
      "DirectoryPath",
      "Directory"
    );
    const rawFilePath = pick(raw, "FilePath", "filePath", "file_path", "FullPath", "ImagePath");
    const signerName = pick(
      raw,
      "SubjectName",
      "SignerName",
      "Publisher",
      "PublisherName",
      "Signer",
      "CertSubject",
      "CertificateSubjectName"
    );
    const issuerName = pick(
      raw,
      "IssuerName",
      "Issuer",
      "CertIssuer",
      "CertificateIssuerName",
      "RootName"
    );
    return {
      sha256,
      sha1,
      fileName,
      folderPath,
      filePath: rawFilePath ?? assembleFilePath(folderPath, fileName),
      signerName,
      issuerName,
      isSigned:
        pickBool(raw, "IsSigned", "isSigned", "Signed") ?? (signerName ? true : null),
      deviceName: pick(
        raw,
        "DeviceName",
        "deviceName",
        "ComputerName",
        "HostName",
        "MachineName",
        "Device",
        "Machine"
      ),
      timestamp: pick(
        raw,
        "Timestamp",
        "timestamp",
        "EventTime",
        "TimeGenerated",
        "CreatedTime",
        "Datetime",
        "Date"
      ),
    };
  },
};

/** Adapter chain — evaluated in order; first match wins */
const ADAPTERS: SchemaAdapter[] = [
  deviceFileCertInfoAdapter,
  deviceEventAdapter,
  genericAdapter,
];

// ---------------------------------------------------------------------------
// Row validation
// ---------------------------------------------------------------------------

function isUsableRow(row: AhRow): boolean {
  return !!(row.sha256 || row.sha1 || row.filePath || (row.fileName && row.folderPath));
}

// ---------------------------------------------------------------------------
// Binary deduplication
// ---------------------------------------------------------------------------

function rowKey(row: AhRow): string {
  if (row.sha256) return `sha256::${row.sha256.toLowerCase()}`;
  if (row.filePath) return `path::${row.filePath.toLowerCase()}`;
  const fp = assembleFilePath(row.folderPath, row.fileName);
  if (fp) return `path::${fp.toLowerCase()}`;
  if (row.sha1) return `sha1::${row.sha1.toLowerCase()}`;
  // Should not reach here — validated rows always have one of the above
  return `unknown::${Math.random().toString(36).slice(2)}`;
}

function pushUniq(arr: string[], val: string | null): void {
  if (val && !arr.includes(val)) arr.push(val);
}

function createBinary(key: string, row: AhRow): HuntingBinary {
  const fp = row.filePath ?? assembleFilePath(row.folderPath, row.fileName);
  return {
    key,
    sha256: row.sha256,
    sha1: row.sha1,
    fileNames: row.fileName ? [row.fileName] : [],
    folderPaths: row.folderPath ? [row.folderPath] : [],
    filePaths: fp ? [fp] : [],
    signerNames: row.signerName ? [row.signerName] : [],
    issuerNames: row.issuerName ? [row.issuerName] : [],
    isSigned: row.isSigned,
    signingCoverage: "unsigned", // overwritten in classification pass
    deviceNames: row.deviceName ? [row.deviceName] : [],
    observationCount: 1,
    firstSeen: row.timestamp,
    lastSeen: row.timestamp,
  };
}

function mergeRow(binary: HuntingBinary, row: AhRow): void {
  if (!binary.sha256 && row.sha256) binary.sha256 = row.sha256;
  if (!binary.sha1 && row.sha1) binary.sha1 = row.sha1;
  pushUniq(binary.fileNames, row.fileName);
  pushUniq(binary.folderPaths, row.folderPath);
  pushUniq(binary.filePaths, row.filePath ?? assembleFilePath(row.folderPath, row.fileName));
  pushUniq(binary.signerNames, row.signerName);
  pushUniq(binary.issuerNames, row.issuerName);
  if (binary.isSigned === null && row.isSigned !== null) binary.isSigned = row.isSigned;
  pushUniq(binary.deviceNames, row.deviceName);
  binary.observationCount++;
  if (row.timestamp) {
    if (!binary.firstSeen || row.timestamp < binary.firstSeen) binary.firstSeen = row.timestamp;
    if (!binary.lastSeen || row.timestamp > binary.lastSeen) binary.lastSeen = row.timestamp;
  }
}

function deduplicateBinaries(rows: AhRow[]): HuntingBinary[] {
  const map = new Map<string, HuntingBinary>();
  for (const row of rows) {
    const key = rowKey(row);
    const existing = map.get(key);
    if (existing) {
      mergeRow(existing, row);
    } else {
      map.set(key, createBinary(key, row));
    }
  }
  return Array.from(map.values());
}

// ---------------------------------------------------------------------------
// Signing coverage classification
// ---------------------------------------------------------------------------

function classifySigningCoverage(binary: HuntingBinary): HuntingSigningCoverage {
  if (!binary.sha256) return "no-hash";
  if (binary.isSigned === false) return "unsigned";
  const hasSigner = binary.signerNames.length > 0;
  const hasIssuer = binary.issuerNames.length > 0;
  if (hasSigner && hasIssuer) return "full";
  if (hasSigner) return "partial";
  if (binary.isSigned === true) return "hash-only";
  return "unsigned";
}

// ---------------------------------------------------------------------------
// Path normalisation — map drive-letter paths to WDAC environment variables
// ---------------------------------------------------------------------------

// WDAC's kernel path engine only expands %OSDRIVE%, %WINDIR%, and %SYSTEM32%
// (WDAC Policy Wizard Helper.cs). Anything else must stay a concrete path
// anchored at %OSDRIVE% — macros like %PROGRAMFILES% would be treated as
// literal directory names by CI.
const PATH_SUBSTITUTIONS: Array<[RegExp, string]> = [
  [/^[A-Za-z]:\\Windows\\System32\\/i, "%SYSTEM32%\\"],
  [/^[A-Za-z]:\\Windows\\/i, "%WINDIR%\\"],
  [/^[A-Za-z]:\\/i, "%OSDRIVE%\\"],
];

function normalizeWdacPath(rawPath: string): string {
  const p = rawPath.replace(/\//g, "\\");
  for (const [pattern, replacement] of PATH_SUBSTITUTIONS) {
    if (pattern.test(p)) return p.replace(pattern, replacement);
  }
  return p;
}

// ---------------------------------------------------------------------------
// Kernel-mode detection heuristic
// ---------------------------------------------------------------------------

function isKernelMode(binary: HuntingBinary): boolean {
  return (
    binary.fileNames.some((fn) => fn.toLowerCase().endsWith(".sys")) ||
    binary.folderPaths.some((fp) => /\\drivers(\\|$)/i.test(fp))
  );
}

// ---------------------------------------------------------------------------
// Rule candidate generation
// ---------------------------------------------------------------------------

function generateRuleCandidates(
  binaries: HuntingBinary[],
  opts: {
    preferPublisherRules: boolean;
    scopePublisherRules: boolean;
    includePathRules: boolean;
    effect: "Allow" | "Deny";
  }
): { candidates: HuntingRuleCandidate[]; warnings: HuntingImportWarning[] } {
  const candidates: HuntingRuleCandidate[] = [];
  const warnings: HuntingImportWarning[] = [];
  let noHashSkipped = 0;
  let seq = 0;
  const nextId = (): string => `AH-${String(++seq).padStart(4, "0")}`;

  for (const binary of binaries) {
    const sc = binary.signingCoverage;

    // ── Publisher rule (full or partial signing coverage) ──────────────────
    if ((sc === "full" || sc === "partial") && opts.preferPublisherRules) {
      const signerName = binary.signerNames[0];
      const issuerName = binary.issuerNames[0] ?? null;
      const multiSigner = binary.signerNames.length > 1;
      const fileNameConsistent = binary.fileNames.length === 1;
      const isScoped = opts.scopePublisherRules && fileNameConsistent && !multiSigner;

      let ruleType: HuntingRuleType = isScoped ? "publisher-scoped" : "publisher";
      let risk: HuntingRuleRisk = isScoped ? "safe" : "low";
      let confidence = isScoped ? 0.85 : 0.70;
      const candidateWarnings: string[] = [];

      if (sc === "partial") {
        candidateWarnings.push(
          "Issuer / root CA not observed — publisher match only, no root certificate anchor. " +
            "Validate the signer identity against a DeviceFileCertificateInfo query."
        );
        confidence -= 0.10;
        if (risk === "safe") risk = "low";
        else if (risk === "low") risk = "medium";
      }

      if (multiSigner) {
        candidateWarnings.push(
          `Multiple distinct publisher names observed across devices (${binary.signerNames.join("; ")}). ` +
            `Using first entry. Confirm these represent the same signing identity.`
        );
        confidence -= 0.05;
        ruleType = "publisher";
        if (risk === "safe") risk = "low";
      }

      // Observation volume bonus (up to +0.10)
      confidence = Math.min(0.97, confidence + Math.min(0.10, (binary.observationCount - 1) * 0.01));

      const wdacAttributes: Record<string, string> = {
        CertPublisher: signerName,
        ...(issuerName ? { CertIssuer: issuerName } : {}),
        ...(isScoped && binary.fileNames[0] ? { FileAttrib_FileName: binary.fileNames[0] } : {}),
      };

      candidates.push({
        id: nextId(),
        binary,
        ruleType,
        effect: opts.effect,
        risk,
        confidence: Math.round(confidence * 100) / 100,
        rationale: isScoped
          ? `Publisher "${signerName}" scoped to FileName "${binary.fileNames[0]}" — ` +
            `least-permissive signer rule; only files with this exact name from this publisher are covered.`
          : `Publisher "${signerName}" — trusts all binaries signed by this publisher ` +
            `(${binary.observationCount} observation${binary.observationCount !== 1 ? "s" : ""} ` +
            `across ${binary.deviceNames.length} device${binary.deviceNames.length !== 1 ? "s" : ""}).`,
        wdacAttributes,
        warnings: candidateWarnings,
        appliesToKernelMode: isKernelMode(binary),
      });
      continue;
    }

    // ── Hash rule — signed without publisher details, hash-only, or unsigned ──
    if (sc !== "no-hash" && binary.sha256) {
      const isUnsigned = sc === "unsigned";
      const candidateWarnings: string[] = [];

      if (isUnsigned) {
        candidateWarnings.push(
          "Binary is unsigned — hash rules are the only viable option, but they become invalid " +
            "each time the binary is rebuilt or updated."
        );
      } else if (sc === "hash-only") {
        candidateWarnings.push(
          "Binary is signed but no certificate details were present in this export. " +
            "Join with DeviceFileCertificateInfo to obtain publisher data for a more durable rule."
        );
      } else if (!opts.preferPublisherRules) {
        candidateWarnings.push(
          "Publisher rules are disabled — using hash rule. " +
            "Enable publisher rules for a more maintainable long-term policy."
        );
      }

      candidates.push({
        id: nextId(),
        binary,
        ruleType: "hash",
        effect: opts.effect,
        risk: isUnsigned ? "medium" : "low",
        confidence: 0.90,
        rationale:
          `SHA256 hash rule — highly specific, covers exactly this binary build ` +
          `(${binary.sha256.substring(0, 16)}…).`,
        wdacAttributes: {
          HashType: "SHA256",
          Value: binary.sha256,
          ...(binary.sha1 ? { SHA1: binary.sha1 } : {}),
        },
        warnings: candidateWarnings,
        appliesToKernelMode: isKernelMode(binary),
      });
      continue;
    }

    // ── Path rule — no hash available ──────────────────────────────────────
    if (sc === "no-hash") {
      if (opts.includePathRules && binary.filePaths.length > 0) {
        const normalizedPath = normalizeWdacPath(binary.filePaths[0]);
        const isWildcard = normalizedPath.includes("*") || normalizedPath.includes("?");

        candidates.push({
          id: nextId(),
          binary,
          ruleType: isWildcard ? "path-wildcard" : "path",
          effect: opts.effect,
          risk: isWildcard ? "critical" : "high",
          confidence: isWildcard ? 0.20 : 0.35,
          rationale:
            `No hash available — path rule only: "${normalizedPath}". ` +
            `Path rules can be bypassed; obtain SHA256 for a more secure rule.`,
          wdacAttributes: { FilePath: normalizedPath },
          warnings: [
            "Path rules can be bypassed by placing a malicious binary at the same path.",
            "Obtain the SHA256 hash and rerun ingestion for a more secure rule.",
            ...(isWildcard
              ? ["Wildcard paths are especially permissive — review carefully before deploying."]
              : []),
          ],
          appliesToKernelMode: isKernelMode(binary),
        });
      } else {
        noHashSkipped++;
      }
    }
  }

  if (noHashSkipped > 0) {
    warnings.push({
      code: "BINARIES_SKIPPED_NO_HASH",
      message:
        `${noHashSkipped} binary record${noHashSkipped !== 1 ? "s were" : " was"} skipped — ` +
        `no SHA256 hash or file path available. Enable "Include path rules" to generate path candidates, ` +
        `or re-run the Advanced Hunting query with a JOIN to DeviceFileCertificateInfo to add hash data.`,
      affectedRows: noHashSkipped,
    });
  }

  return { candidates, warnings };
}

// ---------------------------------------------------------------------------
// Main pipeline entry point
// ---------------------------------------------------------------------------

export function ingestAdvancedHunting(req: HuntingImportRequest): HuntingImportResult {
  const warnings: HuntingImportWarning[] = [];

  // 1. Parse content
  const format = req.format === "auto" ? detectFormat(req.content) : req.format;
  let rawRows: Record<string, string>[];
  try {
    rawRows = format === "csv" ? parseCsv(req.content) : parseJson(req.content);
  } catch (err) {
    throw new Error(
      `Failed to parse ${format.toUpperCase()} content: ${(err as Error).message}`
    );
  }

  if (rawRows.length === 0) {
    throw new Error(
      "No rows found in the provided content. Verify the format and that the export is not empty."
    );
  }

  // 2. Detect schema adapter
  const headers = new Set(Object.keys(rawRows[0]));
  const adapter = ADAPTERS.find((a) => a.canHandle(headers)) ?? genericAdapter;

  // 3. Normalize and validate rows
  let validCount = 0;
  let skippedCount = 0;
  const normalizedRows: AhRow[] = [];

  for (const raw of rawRows) {
    const row = adapter.mapRow(raw);
    if (isUsableRow(row)) {
      normalizedRows.push(row);
      validCount++;
    } else {
      skippedCount++;
    }
  }

  if (skippedCount > 0) {
    warnings.push({
      code: "ROWS_SKIPPED_NO_IDENTIFIER",
      message:
        `${skippedCount} row${skippedCount !== 1 ? "s were" : " was"} skipped — ` +
        `no usable SHA256, SHA1, FileName, or FolderPath could be extracted. ` +
        `Verify the export contains at least one of these columns.`,
      affectedRows: skippedCount,
    });
  }

  if (normalizedRows.length === 0) {
    throw new Error(
      `No usable rows after normalization (detected schema: ${adapter.name}). ` +
        `Ensure the export contains SHA256, FileName+FolderPath, or FilePath columns.`
    );
  }

  // 4. Deduplicate by SHA256 (primary) or file path (fallback)
  const binaries = deduplicateBinaries(normalizedRows);

  // 5. Classify signing coverage
  for (const binary of binaries) {
    binary.signingCoverage = classifySigningCoverage(binary);
  }

  // 6. Data quality warnings
  const multiSignerBinaries = binaries.filter((b) => b.signerNames.length > 1);
  if (multiSignerBinaries.length > 0) {
    warnings.push({
      code: "MULTIPLE_SIGNERS_OBSERVED",
      message:
        `${multiSignerBinaries.length} binary record${multiSignerBinaries.length !== 1 ? "s have" : " has"} ` +
        `multiple distinct publisher names across observations. This may indicate binary identity variation, ` +
        `a signed updater, or a field mapping mismatch. Review these candidates carefully.`,
      affectedRows: multiSignerBinaries.length,
    });
  }

  // 7. Generate rule candidates
  const { candidates, warnings: ruleWarnings } = generateRuleCandidates(binaries, {
    preferPublisherRules: req.preferPublisherRules ?? true,
    scopePublisherRules: req.scopePublisherRules ?? true,
    includePathRules: req.includePathRules ?? false,
    effect: req.effect ?? "Allow",
  });
  warnings.push(...ruleWarnings);

  // 8. Compute stats
  const stats: HuntingImportStats = {
    totalRowsParsed: rawRows.length,
    validRows: validCount,
    skippedRows: skippedCount,
    uniqueBinaries: binaries.length,
    signedBinaries: binaries.filter(
      (b) => b.signingCoverage === "full" || b.signingCoverage === "partial"
    ).length,
    unsignedBinaries: binaries.filter((b) => b.signingCoverage === "unsigned").length,
    partialSigningBinaries: binaries.filter(
      (b) => b.signingCoverage === "partial" || b.signingCoverage === "hash-only"
    ).length,
    noHashBinaries: binaries.filter((b) => b.signingCoverage === "no-hash").length,
    detectedSchema: adapter.name,
  };

  return { binaries, ruleCandidates: candidates, stats, warnings };
}
