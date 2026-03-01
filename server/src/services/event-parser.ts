/**
 * CodeIntegrity Event Log Parser
 *
 * Parses CodeIntegrity events from:
 * 1. JSON export of EVTX (Get-WinEvent | ConvertTo-Json)
 * 2. Advanced Hunting query results (JSON or CSV)
 *
 * Reference:
 * https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations
 */

import type {
  ParsedCiEvent,
  EventImportResult,
  EventImportSummary,
  AdvancedHuntingRow,
  EventSeverity,
  EventSource,
} from "@appcontrol/shared";
import { CI_EVENT_IDS } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Block vs audit categorization
// ---------------------------------------------------------------------------

// Enforcement events: the file was actively blocked.
// Source: Microsoft Learn "Understanding App Control event IDs"
// https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations
const BLOCK_EVENT_IDS = new Set([
  3001, 3002, 3004, 3010, 3023, // kernel-mode signing violations (NOTE: 3003 is not in MS official list)
  3026, 3032, 3036,             // revocation events
  3033,                         // kernel-mode App Control enforcement block
  3065,                         // user-mode DLL enforcement block
  3077,                         // user-mode App Control enforcement block  ← NOT audit (3076 is audit)
  3079, 3081,                   // file didn't meet requirements (enforcement)
  3111,                         // HVCI policy violation
  3114,                         // Dynamic Code Security (.NET) block
  3092,                         // ISG/Managed Installer: file blocked (enforcement)
]);

// Audit events: the file would have been blocked in enforcement mode but was allowed to run.
const AUDIT_EVENT_IDS = new Set([
  3034,       // kernel-mode App Control audit (would have been blocked)
  3064,       // user-mode DLL audit (would have been blocked)
  3076,       // user-mode App Control audit (would have been blocked)  ← main audit event
  3080, 3082, // would have been blocked if enforced
  3091,       // ISG/Managed Installer: file not authorized (audit mode)
]);

// Everything else falls through to "info":
//   3026/3036 correlated revocation info, 3089 signer info, 3090 ISG allow, 3099 policy load

function categorizeSeverity(eventId: number): EventSeverity {
  if (BLOCK_EVENT_IDS.has(eventId)) return "block";
  if (AUDIT_EVENT_IDS.has(eventId)) return "audit";
  return "info";
}

// ---------------------------------------------------------------------------
// JSON EVTX format parser (output of Get-WinEvent | ConvertTo-Json)
// ---------------------------------------------------------------------------

interface EvtxJsonRecord {
  Id?: number;
  Id_?: number;
  EventId?: number;
  TimeCreated?: { SystemTime?: string } | string;
  MachineName?: string;
  Message?: string;
  Properties?: Array<{ Value?: unknown } | string | unknown>;
  // Flattened format
  EventRecordId?: number;
  Keywords?: string;
  TimeWritten?: string;
  [key: string]: unknown;
}

export function parseEvtxJson(content: string): EventImportResult {
  const errors: EventImportResult["parseErrors"] = [];
  let raw: unknown;

  try {
    raw = JSON.parse(content);
  } catch (e) {
    return {
      events: [],
      summary: buildSummary([]),
      parseErrors: [{ message: `JSON parse failed: ${(e as Error).message}` }],
    };
  }

  const records: EvtxJsonRecord[] = Array.isArray(raw) ? raw : [raw as EvtxJsonRecord];
  const events: ParsedCiEvent[] = [];

  for (let i = 0; i < records.length; i++) {
    try {
      const record = records[i];
      const eventId =
        (record.Id as number) ??
        (record.Id_ as number) ??
        (record.EventId as number) ??
        0;

      // Filter to CodeIntegrity event IDs
      const knownIds = Object.keys(CI_EVENT_IDS).map(Number);
      if (!knownIds.includes(eventId)) continue;

      const severity = categorizeSeverity(eventId);
      const description =
        CI_EVENT_IDS[eventId as keyof typeof CI_EVENT_IDS] ?? `Event ID ${eventId}`;

      // Timestamp extraction
      let timestamp = "";
      if (typeof record.TimeCreated === "object" && record.TimeCreated?.SystemTime) {
        timestamp = record.TimeCreated.SystemTime;
      } else if (typeof record.TimeCreated === "string") {
        timestamp = record.TimeCreated;
      } else if (record.TimeWritten) {
        timestamp = String(record.TimeWritten);
      }

      // Extract file path and hash from Properties array (position-based per event schema)
      let filePath = "";
      let sha256Hash: string | undefined;
      let sha1Hash: string | undefined;
      let requestingProcess: string | undefined;

      const props = record.Properties ?? [];
      const getProp = (idx: number): string => {
        const p = props[idx];
        if (typeof p === "object" && p !== null && "Value" in (p as object)) {
          return String((p as { Value: unknown }).Value ?? "");
        }
        return String(p ?? "");
      };

      // Event 3076/3077 and 3033/3034 have file info in properties[0] onwards
      // The exact position varies by event ID but commonly:
      // [0] = file path, [1] = process path, [2] = SHA256, [3] = SHA1 (or similar)
      if (props.length > 0) filePath = getProp(0);
      if (props.length > 1) requestingProcess = getProp(1);
      if (props.length > 2) {
        const val = getProp(2);
        if (val.length === 64) sha256Hash = val.toUpperCase();
      }
      if (props.length > 3) {
        const val = getProp(3);
        if (val.length === 40) sha1Hash = val.toUpperCase();
      }

      // Try to extract file name
      const fileName = filePath ? filePath.split(/[/\\]/).pop() : undefined;

      events.push({
        eventId,
        timestamp,
        machineName: record.MachineName ? String(record.MachineName) : undefined,
        requestingProcess,
        filePath: filePath || "(unknown)",
        fileName,
        sha256Hash,
        sha1Hash,
        severity,
        description,
        source: "evtx",
      });
    } catch (err) {
      errors.push({ line: i, message: `Failed to parse record ${i}: ${(err as Error).message}` });
    }
  }

  return { events, summary: buildSummary(events), parseErrors: errors };
}

// ---------------------------------------------------------------------------
// Advanced Hunting CSV parser
// ---------------------------------------------------------------------------

export function parseAdvancedHuntingCsv(content: string): EventImportResult {
  const errors: EventImportResult["parseErrors"] = [];
  const lines = content.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) {
    return {
      events: [],
      summary: buildSummary([]),
      parseErrors: [{ message: "CSV has no data rows." }],
    };
  }

  const headers = parseCsvLine(lines[0]).map((h) => h.trim());
  const events: ParsedCiEvent[] = [];

  for (let i = 1; i < lines.length; i++) {
    try {
      const values = parseCsvLine(lines[i]);
      const row: Record<string, string> = {};
      headers.forEach((h, idx) => {
        row[h] = values[idx] ?? "";
      });

      const huntingRow: AdvancedHuntingRow = row as unknown as AdvancedHuntingRow;
      const event = convertAdvancedHuntingRow(huntingRow, "csv");
      if (event) events.push(event);
    } catch (err) {
      errors.push({ line: i + 1, message: `Row ${i + 1}: ${(err as Error).message}` });
    }
  }

  return { events, summary: buildSummary(events), parseErrors: errors };
}

// ---------------------------------------------------------------------------
// Advanced Hunting JSON parser
// ---------------------------------------------------------------------------

export function parseAdvancedHuntingJson(content: string): EventImportResult {
  const errors: EventImportResult["parseErrors"] = [];
  let raw: unknown;

  try {
    raw = JSON.parse(content);
  } catch (e) {
    return {
      events: [],
      summary: buildSummary([]),
      parseErrors: [{ message: `JSON parse failed: ${(e as Error).message}` }],
    };
  }

  // Support both array of rows and {Results: [...]} wrapper
  let rows: AdvancedHuntingRow[];
  if (Array.isArray(raw)) {
    rows = raw as AdvancedHuntingRow[];
  } else if (
    raw &&
    typeof raw === "object" &&
    "Results" in (raw as object) &&
    Array.isArray((raw as { Results: unknown }).Results)
  ) {
    rows = (raw as { Results: AdvancedHuntingRow[] }).Results;
  } else {
    rows = [raw as AdvancedHuntingRow];
  }

  const events: ParsedCiEvent[] = [];
  for (let i = 0; i < rows.length; i++) {
    try {
      const event = convertAdvancedHuntingRow(rows[i], "advanced-hunting");
      if (event) events.push(event);
    } catch (err) {
      errors.push({ line: i, message: `Row ${i}: ${(err as Error).message}` });
    }
  }

  return { events, summary: buildSummary(events), parseErrors: errors };
}

// ---------------------------------------------------------------------------
// Convert Advanced Hunting row to ParsedCiEvent
// ---------------------------------------------------------------------------

function convertAdvancedHuntingRow(
  row: AdvancedHuntingRow,
  source: EventSource
): ParsedCiEvent | null {
  const actionType = String(row.ActionType ?? "");
  // Only process AppControl events
  if (
    actionType &&
    !actionType.includes("AppControl") &&
    !actionType.includes("CodeIntegrity")
  ) {
    return null;
  }

  const isBlock = actionType.toLowerCase().includes("blocked");
  const isAudit = actionType.toLowerCase().includes("audited") || actionType.toLowerCase().includes("audit");
  const severity: EventSeverity = isBlock ? "block" : isAudit ? "audit" : "info";

  // Parse AdditionalFields if it's a string
  let additionalFields: Record<string, unknown> = {};
  if (row.AdditionalFields) {
    if (typeof row.AdditionalFields === "string") {
      try {
        additionalFields = JSON.parse(row.AdditionalFields) as Record<string, unknown>;
      } catch {
        // ignore
      }
    } else {
      additionalFields = row.AdditionalFields as Record<string, unknown>;
    }
  }

  const filePath = [row.FolderPath, row.FileName].filter(Boolean).join("\\") || "(unknown)";
  const fileName = String(row.FileName ?? "");

  return {
    eventId: 3076, // Generic audit/block mapping
    timestamp: String(row.Timestamp ?? new Date().toISOString()),
    machineName: row.DeviceName ? String(row.DeviceName) : undefined,
    requestingProcess: row.InitiatingProcessFileName
      ? String(row.InitiatingProcessFileName)
      : undefined,
    filePath,
    fileName: fileName || undefined,
    sha256Hash: row.SHA256 ? String(row.SHA256).toUpperCase() : undefined,
    sha1Hash: row.SHA1 ? String(row.SHA1).toUpperCase() : undefined,
    productName: row.ProductName
      ? String(row.ProductName)
      : additionalFields.ProductName
      ? String(additionalFields.ProductName)
      : undefined,
    originalFileName: row.OriginalFileName
      ? String(row.OriginalFileName)
      : additionalFields.OriginalFileName
      ? String(additionalFields.OriginalFileName)
      : undefined,
    internalName: additionalFields.InternalName ? String(additionalFields.InternalName) : undefined,
    fileDescription: additionalFields.FileDescription
      ? String(additionalFields.FileDescription)
      : undefined,
    fileVersion: additionalFields.FileVersion ? String(additionalFields.FileVersion) : undefined,
    policyGuid: row.PolicyGuid
      ? String(row.PolicyGuid)
      : additionalFields.PolicyGuid
      ? String(additionalFields.PolicyGuid)
      : undefined,
    policyName: row.PolicyName
      ? String(row.PolicyName)
      : additionalFields.PolicyName
      ? String(additionalFields.PolicyName)
      : undefined,
    severity,
    description: actionType || "App Control event",
    source,
  };
}

// ---------------------------------------------------------------------------
// Summary builder
// ---------------------------------------------------------------------------

function buildSummary(events: ParsedCiEvent[]): EventImportSummary {
  const uniqueFiles = new Set(events.map((e) => e.filePath)).size;
  const uniqueSigners = new Set(
    events.flatMap((e) =>
      [e.signerInfo?.publisherName, e.signerInfo?.issuerName].filter(Boolean)
    )
  ).size;

  const timestamps = events.map((e) => e.timestamp).filter(Boolean).sort();

  return {
    totalEvents: events.length,
    blockEvents: events.filter((e) => e.severity === "block").length,
    auditEvents: events.filter((e) => e.severity === "audit").length,
    uniqueFiles,
    uniqueSigners,
    timeRange:
      timestamps.length > 0
        ? { earliest: timestamps[0], latest: timestamps[timestamps.length - 1] }
        : undefined,
  };
}

// ---------------------------------------------------------------------------
// CSV line parser (handles quoted fields with commas)
// ---------------------------------------------------------------------------

function parseCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === "," && !inQuotes) {
      result.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  result.push(current);
  return result;
}
