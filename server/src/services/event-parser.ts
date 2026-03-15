/**
 * CodeIntegrity Event Log Parser
 *
 * Parses CodeIntegrity / App Control events from:
 *  1. Named-field JSON  (preferred — use the PowerShell command in CollectionInstructions)
 *  2. Positional JSON   (legacy — Get-WinEvent | ConvertTo-Json)
 *  3. Advanced Hunting query results (JSON or CSV)
 *
 * Named-field format PowerShell command:
 *   Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -Oldest |
 *     Where-Object { $_.Id -in @(3033,3034,3036,3064,3065,3076,3077,3079,3080,3082,3089,3090,3091,3092,3111,3114) } |
 *     ForEach-Object {
 *       $xml = [xml]$_.ToXml()
 *       $fields = @{}
 *       foreach ($d in $xml.Event.EventData.Data) { if ($d.Name) { $fields[$d.Name] = $d.'#text' } }
 *       [PSCustomObject]@{
 *         EventId     = $_.Id
 *         TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
 *         MachineName = $_.MachineName
 *         ActivityId  = if ($_.ActivityId) { $_.ActivityId.ToString('B').ToUpper() } else { $null }
 *         Level       = $_.Level
 *         Fields      = $fields
 *       }
 *     } | ConvertTo-Json -Depth 5
 *
 * Reference:
 *   https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations
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

const BLOCK_EVENT_IDS = new Set([
  3001, 3002, 3004, 3010, 3023,
  3026, 3032, 3036,
  3033,
  3065,
  3077,
  3079, 3081,
  3111,
  3114,
  3092,
]);

const AUDIT_EVENT_IDS = new Set([
  3034,
  3064,
  3076,
  3080, 3082,
  3091,
]);

function categorizeSeverity(eventId: number): EventSeverity {
  if (BLOCK_EVENT_IDS.has(eventId)) return "block";
  if (AUDIT_EVENT_IDS.has(eventId)) return "audit";
  return "info";
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/**
 * Convert an unknown value to an uppercase hex string.
 *
 * Handles:
 *  - Array of integers  (Get-WinEvent | ConvertTo-Json serializes byte[] as int[])
 *  - Hex strings already (from ToXml() / named-field format)
 *  - Base64 strings (rare, but EVTX XML sometimes uses base64 for binary data)
 */
function byteArrayToHex(value: unknown): string | undefined {
  if (value == null) return undefined;

  if (typeof value === "string") {
    const clean = value.replace(/[^0-9a-fA-F]/g, "");
    if (clean.length >= 40) return clean.toUpperCase();
    // Try base64
    if (/^[A-Za-z0-9+/]+=*$/.test(value.trim()) && value.length > 20) {
      try {
        const buf = Buffer.from(value.trim(), "base64");
        if (buf.length >= 20) return buf.toString("hex").toUpperCase();
      } catch {
        // not valid base64
      }
    }
    return undefined;
  }

  // Array of integers (byte array from PowerShell JSON serialization)
  if (Array.isArray(value) && value.length >= 20 && typeof value[0] === "number") {
    return (value as number[])
      .map((b) => (b & 0xff).toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
  }

  return undefined;
}

/**
 * Normalize Windows Event Log timestamps to ISO-8601 UTC.
 *
 * Handles:
 *  - PowerShell /Date(milliseconds)/ JSON date format
 *  - {SystemTime: "..."} object from Get-WinEvent | ConvertTo-Json
 *  - Already-ISO strings (named-field format)
 *  - Windows FILETIME as string (100ns intervals since 1601-01-01)
 */
function normalizeTimestamp(raw: unknown): string {
  if (!raw) return "";

  if (typeof raw === "object" && raw !== null && "SystemTime" in raw) {
    return normalizeTimestamp((raw as { SystemTime: unknown }).SystemTime);
  }

  if (typeof raw !== "string") return "";

  // PowerShell /Date(ms)/ format
  const msMatch = raw.match(/\/Date\((-?\d+)\)\//);
  if (msMatch) {
    return new Date(parseInt(msMatch[1], 10)).toISOString();
  }

  // Already ISO or other parseable date string
  return raw;
}

// ---------------------------------------------------------------------------
// Positional property helpers (Get-WinEvent | ConvertTo-Json format)
// ---------------------------------------------------------------------------

function propRaw(props: unknown[], idx: number): unknown {
  const p = props[idx];
  if (p == null) return undefined;
  if (typeof p === "object" && p !== null && "Value" in (p as object)) {
    return (p as { Value: unknown }).Value;
  }
  return p;
}

function propStr(props: unknown[], idx: number): string | undefined {
  const v = propRaw(props, idx);
  if (v == null) return undefined;
  if (typeof v === "boolean") return undefined; // skip bool fields
  const s = String(v).trim();
  return s || undefined;
}

function propHex(props: unknown[], idx: number): string | undefined {
  return byteArrayToHex(propRaw(props, idx));
}

// ---------------------------------------------------------------------------
// Intermediate signer record (from event 3089)
// ---------------------------------------------------------------------------

interface Signer3089 {
  correlationId: string;
  filePath: string;
  policyGuid?: string;
  totalSignatureCount?: number;
  signatureIndex?: number;
  notValidBefore?: string;
  notValidAfter?: string;
  publisherName?: string;
  issuerName?: string;
  publisherTbsHash?: string;
  issuerTbsHash?: string;
  // File version resource fields (on newer Windows, 3089 carries these)
  originalFileName?: string;
  internalName?: string;
  fileDescription?: string;
  productName?: string;
  fileVersion?: string;
}

// ---------------------------------------------------------------------------
// Positional-format record (Get-WinEvent | ConvertTo-Json)
// ---------------------------------------------------------------------------

interface PositionalEvtxRecord {
  Id?: number;
  Id_?: number;
  EventId?: number;
  TimeCreated?: unknown;
  MachineName?: string;
  ActivityId?: string | null;
  Properties?: Array<{ Value?: unknown } | unknown>;
  [key: string]: unknown;
}

/**
 * Parse a single record from the positional (Get-WinEvent | ConvertTo-Json) format.
 *
 * Property layout per event ID is fixed by the Windows Code Integrity event manifest:
 *
 * Events 3076, 3077 (user-mode audit/block):
 *   [0]  FileNameBuffer      string — file that was audited/blocked
 *   [1]  ProcessNameBuffer   string — process that loaded it
 *   [2]  RequestedPolicy     uint32
 *   [3]  ValidatedPolicy     uint32
 *   [4]  Status              int32  (NT status code)
 *   [5]  Sha1FlatHash        byte[20] → 40-char hex
 *   [6]  Sha256FlatHash      byte[32] → 64-char hex  ← USE THIS FOR RULES
 *   [7]  Sha1PageHash        byte[20]
 *   [8]  Sha256PageHash      byte[32]
 *   [9]  Flags               uint32
 *   [10] PolicyName          string
 *   [11] PolicyGuid          string (GUID)
 *   [12] UserWriteable       bool   (may be absent on older Windows)
 *   [13] OriginalFilename    string
 *   [14] InternalName        string
 *   [15] FileDescription     string
 *   [16] ProductName         string
 *   [17] FileVersion         string
 *   [18] PackageFamilyName   string
 *
 * Event 3089 (signature info — correlated with 3076/3077 via ActivityId):
 *   [0]  FileNameBuffer      string
 *   [1]  PolicyGuid          string (GUID)
 *   [2]  TotalSignatureCount uint32
 *   [3]  SignatureIndex      uint32
 *   [4]  SignatureType       uint32
 *   [5]  ValidatedSigningLevel uint32
 *   [6]  VerificationError   uint32
 *   [7]  Flags               uint32
 *   [8]  PolicyBits          uint32
 *   [9]  NotValidBefore      FILETIME / datetime
 *   [10] NotValidAfter       FILETIME / datetime
 *   [11] PublisherName       string (leaf cert DN)
 *   [12] IssuerName          string (intermediate cert DN)
 *   [13] PublisherTBSHash    byte[] → hex
 *   [14] IssuerTBSHash       byte[] → hex
 *
 * Events 3033, 3034 (kernel-mode enforcement / audit):
 *   [0]  FileNameBuffer      string
 *   [1]  Status              uint32
 *   [2]  PolicyGuid          string (GUID)
 */
function parsePositionalRecord(
  record: PositionalEvtxRecord,
  events: Array<{ event: ParsedCiEvent; correlationId?: string }>,
  signers: Map<string, Signer3089[]>,
  errors: EventImportResult["parseErrors"],
  idx: number
): void {
  const eventId =
    (record.Id as number) ??
    (record.Id_ as number) ??
    (record.EventId as number) ??
    0;

  const knownIds = Object.keys(CI_EVENT_IDS).map(Number);
  if (!knownIds.includes(eventId)) return;

  const props: unknown[] = Array.isArray(record.Properties) ? record.Properties : [];
  const correlationId = record.ActivityId
    ? String(record.ActivityId).toUpperCase()
    : undefined;

  try {
    if (eventId === 3089) {
      // Signer correlation event — collect for later merging
      const cid = correlationId ?? `__pos__${idx}`;
      const signer: Signer3089 = {
        correlationId: cid,
        filePath: propStr(props, 0) ?? "(unknown)",
        policyGuid: propStr(props, 1),
        totalSignatureCount: typeof propRaw(props, 2) === "number"
          ? (propRaw(props, 2) as number)
          : undefined,
        signatureIndex: typeof propRaw(props, 3) === "number"
          ? (propRaw(props, 3) as number)
          : undefined,
        notValidBefore: normalizeTimestamp(propRaw(props, 9)),
        notValidAfter: normalizeTimestamp(propRaw(props, 10)),
        publisherName: propStr(props, 11),
        issuerName: propStr(props, 12),
        publisherTbsHash: propHex(props, 13),
        issuerTbsHash: propHex(props, 14),
        // Newer Windows: file attributes may appear starting at prop[15]
        originalFileName: propStr(props, 15),
        internalName: propStr(props, 16),
        fileDescription: propStr(props, 17),
        productName: propStr(props, 18),
        fileVersion: propStr(props, 19),
      };
      const arr = signers.get(cid) ?? [];
      arr.push(signer);
      signers.set(cid, arr);
      return;
    }

    const severity = categorizeSeverity(eventId);
    const description = CI_EVENT_IDS[eventId as keyof typeof CI_EVENT_IDS] ?? `Event ID ${eventId}`;

    let filePath: string;
    let requestingProcess: string | undefined;
    let sha1FlatHash: string | undefined;
    let sha256FlatHash: string | undefined;
    let sha1PageHash: string | undefined;
    let sha256PageHash: string | undefined;
    let policyName: string | undefined;
    let policyGuid: string | undefined;
    let originalFileName: string | undefined;
    let internalName: string | undefined;
    let fileDescription: string | undefined;
    let productName: string | undefined;
    let fileVersion: string | undefined;
    let packageFamilyName: string | undefined;

    if (eventId === 3076 || eventId === 3077 || eventId === 3064 || eventId === 3065 ||
        eventId === 3079 || eventId === 3080 || eventId === 3081 || eventId === 3082 ||
        eventId === 3111 || eventId === 3114) {
      filePath = propStr(props, 0) ?? "(unknown)";
      requestingProcess = propStr(props, 1);
      // [2] RequestedPolicy, [3] ValidatedPolicy, [4] Status — all ints, skip
      sha1FlatHash = propHex(props, 5);
      sha256FlatHash = propHex(props, 6);
      sha1PageHash = propHex(props, 7);
      sha256PageHash = propHex(props, 8);
      // [9] Flags — skip
      policyName = propStr(props, 10);
      policyGuid = propStr(props, 11);
      // [12] UserWriteable — bool, skip
      originalFileName = propStr(props, 13);
      internalName = propStr(props, 14);
      fileDescription = propStr(props, 15);
      productName = propStr(props, 16);
      fileVersion = propStr(props, 17);
      packageFamilyName = propStr(props, 18);
    } else if (eventId === 3033 || eventId === 3034 || eventId === 3036 ||
               eventId === 3032 || eventId === 3026 || eventId === 3023 ||
               eventId === 3001 || eventId === 3002 || eventId === 3004 || eventId === 3010) {
      filePath = propStr(props, 0) ?? "(unknown)";
      // [1] Status int — skip
      policyGuid = propStr(props, 2);
    } else if (eventId === 3090 || eventId === 3091 || eventId === 3092) {
      filePath = propStr(props, 0) ?? "(unknown)";
      policyName = propStr(props, 6);
    } else {
      filePath = propStr(props, 0) ?? "(unknown)";
    }

    const fileName = filePath ? filePath.split(/[/\\]/).pop() : undefined;

    events.push({
      correlationId,
      event: {
        eventId,
        timestamp: normalizeTimestamp(record.TimeCreated),
        machineName: record.MachineName ? String(record.MachineName) : undefined,
        correlationId,
        requestingProcess,
        filePath,
        fileName,
        sha256FlatHash,
        sha1FlatHash,
        sha256PageHash,
        sha1PageHash,
        originalFileName,
        internalName,
        fileDescription,
        productName,
        fileVersion,
        packageFamilyName,
        policyGuid,
        policyName,
        severity,
        description,
        source: "evtx",
      },
    });
  } catch (err) {
    errors.push({ line: idx, message: `Record ${idx}: ${(err as Error).message}` });
  }
}

// ---------------------------------------------------------------------------
// Named-field format record (our recommended PowerShell command using ToXml())
// ---------------------------------------------------------------------------

interface NamedEvtxRecord {
  EventId?: number;
  TimeCreated?: string;
  MachineName?: string;
  ActivityId?: string | null;
  Level?: number;
  Fields?: Record<string, string | null | undefined>;
}

/**
 * Parse a single record from the named-field format produced by the recommended
 * PowerShell command (using $event.ToXml() to get named Data elements).
 *
 * In the EVTX XML, binary data (hashes, TBS values) is stored as hex strings,
 * so no byte-array conversion is needed.
 */
function parseNamedRecord(
  record: NamedEvtxRecord,
  events: Array<{ event: ParsedCiEvent; correlationId?: string }>,
  signers: Map<string, Signer3089[]>,
  errors: EventImportResult["parseErrors"],
  idx: number
): void {
  const eventId = record.EventId ?? 0;
  const knownIds = Object.keys(CI_EVENT_IDS).map(Number);
  if (!knownIds.includes(eventId)) return;

  const f = record.Fields ?? {};
  const get = (name: string): string | undefined => {
    const v = f[name];
    return v ? v.trim() || undefined : undefined;
  };
  const getHex = (name: string): string | undefined => {
    return byteArrayToHex(get(name));
  };

  const correlationId = record.ActivityId
    ? String(record.ActivityId).toUpperCase()
    : undefined;

  try {
    if (eventId === 3089) {
      const cid = correlationId ?? `__named__${idx}`;
      const signer: Signer3089 = {
        correlationId: cid,
        filePath: get("FileNameBuffer") ?? "(unknown)",
        policyGuid: get("PolicyGuid"),
        totalSignatureCount: get("TotalSignatureCount")
          ? parseInt(get("TotalSignatureCount")!, 10)
          : undefined,
        signatureIndex: get("SignatureIndex")
          ? parseInt(get("SignatureIndex")!, 10)
          : undefined,
        notValidBefore: normalizeTimestamp(get("NotValidBefore")),
        notValidAfter: normalizeTimestamp(get("NotValidAfter")),
        publisherName: get("PublisherName"),
        issuerName: get("IssuerName"),
        publisherTbsHash: getHex("PublisherTBSHash") ?? getHex("PublisherTbsHash"),
        issuerTbsHash: getHex("IssuerTBSHash") ?? getHex("IssuerTbsHash"),
        originalFileName: get("OriginalFilename") ?? get("OriginalFileName"),
        internalName: get("InternalName"),
        fileDescription: get("FileDescription"),
        productName: get("ProductName"),
        fileVersion: get("FileVersion"),
      };
      const arr = signers.get(cid) ?? [];
      arr.push(signer);
      signers.set(cid, arr);
      return;
    }

    const severity = categorizeSeverity(eventId);
    const description = CI_EVENT_IDS[eventId as keyof typeof CI_EVENT_IDS] ?? `Event ID ${eventId}`;

    // Field names vary by event ID and Windows version.  Named-field EVTX
    // events (renderXml path) use space-separated names for 3077/3076, e.g.
    // "File Name", "SHA256 Flat Hash".  PowerShell ToXml() exports use camel/
    // Pascal-case names like "FileNameBuffer", "SHA256FlatHash".
    const filePath =
      get("FileNameBuffer") ??
      get("File Name") ??       // 3077 native EVTX field name
      get("FilePath") ??
      get("ImageName") ??
      "(unknown)";

    const event: ParsedCiEvent = {
      eventId,
      timestamp: normalizeTimestamp(record.TimeCreated),
      machineName: record.MachineName ?? undefined,
      correlationId,
      requestingProcess:
        get("ProcessNameBuffer") ??
        get("Process Name") ??  // 3077 native EVTX field name
        get("ProcessName"),
      filePath,
      fileName: filePath ? filePath.split(/[/\\]/).pop() : undefined,
      // Hashes — try camelCase (PowerShell/ToXml) then spaced (native EVTX renderXml)
      sha256FlatHash:
        getHex("Sha256FlatHash") ?? getHex("SHA256FlatHash") ??
        getHex("SHA256 Flat Hash") ?? getHex("SHA256 Hash"),
      sha1FlatHash:
        getHex("Sha1FlatHash") ?? getHex("SHA1FlatHash") ??
        getHex("SHA1 Flat Hash") ?? getHex("SHA1 Hash"),
      sha256PageHash:
        getHex("Sha256PageHash") ?? getHex("SHA256PageHash") ??
        getHex("SHA256 Page Hash"),
      sha1PageHash:
        getHex("Sha1PageHash") ?? getHex("SHA1PageHash") ??
        getHex("SHA1 Page Hash"),
      // File version resource fields (may come from 3076/3077 or 3089)
      originalFileName: get("OriginalFilename") ?? get("OriginalFileName"),
      internalName: get("InternalName"),
      fileDescription: get("FileDescription"),
      productName: get("ProductName"),
      fileVersion: get("FileVersion"),
      packageFamilyName: get("PackageFamilyName"),
      policyGuid: get("PolicyGuid") ?? get("PolicyGUID"),
      policyId: get("PolicyID"),
      policyName: get("PolicyName"),
      severity,
      description,
      source: "evtx",
    };

    events.push({ event, correlationId });
  } catch (err) {
    errors.push({ line: idx, message: `Named record ${idx}: ${(err as Error).message}` });
  }
}

// ---------------------------------------------------------------------------
// Main JSON parser — auto-detects positional vs named-field format
// ---------------------------------------------------------------------------

export function parseEvtxJson(content: string): EventImportResult {
  const parseErrors: EventImportResult["parseErrors"] = [];
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

  const records: unknown[] = Array.isArray(raw) ? raw : [raw];

  // Two-pass:
  // Pass 1 — parse all records; split 3089 signer events into a correlation map
  // Pass 2 — merge signer info from 3089 into their parent events

  const rawEvents: Array<{ event: ParsedCiEvent; correlationId?: string }> = [];
  const signer3089Map = new Map<string, Signer3089[]>();

  for (let i = 0; i < records.length; i++) {
    const record = records[i] as Record<string, unknown>;
    if (!record || typeof record !== "object") continue;

    // Auto-detect format: named-field has a "Fields" object, positional has "Properties" array
    if ("Fields" in record && typeof record.Fields === "object" && record.Fields !== null) {
      parseNamedRecord(
        record as NamedEvtxRecord,
        rawEvents,
        signer3089Map,
        parseErrors,
        i
      );
    } else {
      parsePositionalRecord(
        record as PositionalEvtxRecord,
        rawEvents,
        signer3089Map,
        parseErrors,
        i
      );
    }
  }

  // Pass 2 — attach signer info to parent events
  for (const { event, correlationId } of rawEvents) {
    if (!correlationId) continue;
    const signerList = signer3089Map.get(correlationId);
    if (!signerList || signerList.length === 0) continue;

    const primary = signerList[0];
    event.signerInfo = {
      publisherName: primary.publisherName,
      issuerName: primary.issuerName,
      publisherTbsHash: primary.publisherTbsHash,
      issuerTbsHash: primary.issuerTbsHash,
      notValidBefore: primary.notValidBefore || undefined,
      notValidAfter: primary.notValidAfter || undefined,
      totalSignatureCount: primary.totalSignatureCount,
      signatureIndex: primary.signatureIndex,
    };

    // Merge file attributes from 3089 when not already present in the parent event
    if (!event.originalFileName) event.originalFileName = primary.originalFileName;
    if (!event.internalName) event.internalName = primary.internalName;
    if (!event.fileDescription) event.fileDescription = primary.fileDescription;
    if (!event.productName) event.productName = primary.productName;
    if (!event.fileVersion) event.fileVersion = primary.fileVersion;
  }

  // Exclude 3089 events themselves from the output (they are informational-only,
  // their data has already been merged into the parent events above)
  const events = rawEvents
    .filter(({ event }) => event.eventId !== 3089)
    .map(({ event }) => event);

  return { events, summary: buildSummary(events), parseErrors };
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
      headers.forEach((h, idx) => { row[h] = values[idx] ?? ""; });
      const event = convertAdvancedHuntingRow(row as unknown as AdvancedHuntingRow, "csv");
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
  if (
    actionType &&
    !actionType.includes("AppControl") &&
    !actionType.includes("CodeIntegrity")
  ) {
    return null;
  }

  const isBlock = actionType.toLowerCase().includes("blocked");
  const isAudit =
    actionType.toLowerCase().includes("audited") ||
    actionType.toLowerCase().includes("audit");
  const severity: EventSeverity = isBlock ? "block" : isAudit ? "audit" : "info";

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

  const filePath =
    [row.FolderPath, row.FileName].filter(Boolean).join("\\") || "(unknown)";

  const sha256Raw = row.SHA256 ? String(row.SHA256) : undefined;

  return {
    eventId: isBlock ? 3077 : 3076,
    timestamp: String(row.Timestamp ?? new Date().toISOString()),
    machineName: row.DeviceName ? String(row.DeviceName) : undefined,
    requestingProcess: row.InitiatingProcessFileName
      ? String(row.InitiatingProcessFileName)
      : undefined,
    filePath,
    fileName: String(row.FileName ?? ""),
    // Advanced Hunting provides a single SHA256 field — store in sha256Hash (legacy)
    sha256Hash: sha256Raw ? sha256Raw.toUpperCase() : undefined,
    sha1Hash: row.SHA1 ? String(row.SHA1).toUpperCase() : undefined,
    // Also expose as sha256FlatHash so policy builder can use it
    sha256FlatHash: sha256Raw ? sha256Raw.toUpperCase() : undefined,
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
    internalName: additionalFields.InternalName
      ? String(additionalFields.InternalName)
      : undefined,
    fileDescription: additionalFields.FileDescription
      ? String(additionalFields.FileDescription)
      : undefined,
    fileVersion: additionalFields.FileVersion
      ? String(additionalFields.FileVersion)
      : undefined,
    // Signer info from Advanced Hunting
    ...(row.PublisherName || additionalFields.PublisherName
      ? {
          signerInfo: {
            publisherName: row.PublisherName
              ? String(row.PublisherName)
              : String(additionalFields.PublisherName ?? ""),
            issuerName: row.IssuerName
              ? String(row.IssuerName)
              : additionalFields.IssuerName
              ? String(additionalFields.IssuerName)
              : undefined,
          },
        }
      : {}),
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
  const uniqueFiles = new Set(
    events.map((e) => e.sha256FlatHash ?? e.sha256Hash ?? e.filePath)
  ).size;

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
// CSV line parser (handles quoted fields with embedded commas)
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
