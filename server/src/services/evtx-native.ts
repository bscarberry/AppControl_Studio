/**
 * Cross-platform EVTX binary parser.
 *
 * Uses @ts-evtx/core's low-level EvtxFile API to call record.renderXml()
 * on each record, then parses the resulting standard Windows XML with
 * fast-xml-parser to extract named EventData fields.
 *
 * Using renderXml() instead of the high-level evtx() query builder is
 * intentional: the builder's data.items extraction relies on internal BXML
 * template layout heuristics that miss named <Data> fields on CodeIntegrity
 * events. renderXml() produces the same XML structure as Windows Event
 * Viewer, guaranteeing the <Data Name="..."> elements are present.
 *
 * Named-field record shape (mirrors the PowerShell ToXml() output format):
 *   { EventId, TimeCreated, MachineName, ActivityId, Level, Fields }
 */

import path from "path";
import os from "os";
import { promises as fs } from "fs";
import { XMLParser } from "fast-xml-parser";

// CodeIntegrity event IDs we care about
const CI_IDS = new Set([
  3033, 3034, 3036,
  3064, 3065,
  3076, 3077, 3079, 3080, 3082,
  3089, 3091, 3092,
  3111, 3114,
]);

interface NamedRecord {
  EventId: number;
  TimeCreated: string | null;
  MachineName: string | null;
  ActivityId: string | null;
  Level: number;
  Fields: Record<string, string>;
}

// fast-xml-parser configured to match the EVTX XML schema:
//  - ignoreAttributes: false  — keep SystemTime, ActivityID, Name attrs
//  - attributeNamePrefix: ""  — e.g. Data.Name instead of Data.@_Name
//  - isArray for "Data"       — always treat EventData/Data as array
const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "",
  textNodeName: "#text",
  parseAttributeValue: false,
  isArray: (_name, jpath) =>
    jpath === "Event.EventData.Data" || _name === "Data",
});

function xmlToNamedRecord(xmlStr: string): NamedRecord | null {
  let doc: Record<string, unknown>;
  try {
    doc = xmlParser.parse(xmlStr) as Record<string, unknown>;
  } catch {
    return null;
  }

  const ev = (doc as { Event?: Record<string, unknown> }).Event;
  if (!ev) return null;

  const sys = (ev.System ?? {}) as Record<string, unknown>;

  // EventID can be a plain number or an object when Qualifiers attr is present
  const rawEventId = sys.EventID;
  const eventId =
    typeof rawEventId === "object" && rawEventId !== null
      ? Number((rawEventId as Record<string, unknown>)["#text"])
      : Number(rawEventId);

  if (!CI_IDS.has(eventId)) return null;

  // TimeCreated/@SystemTime
  const tc = sys.TimeCreated as Record<string, unknown> | undefined;
  const timeCreated = tc ? (String(tc["SystemTime"] ?? "")) || null : null;

  const machineName = sys.Computer ? String(sys.Computer) : null;

  // Correlation/@ActivityID
  const corr = sys.Correlation as Record<string, unknown> | undefined;
  const rawActivity = corr?.ActivityID ?? corr?.["ActivityID"] ?? null;
  const activityId = rawActivity ? String(rawActivity).toUpperCase() : null;

  const level = Number(sys.Level ?? 0);

  // EventData/Data[] — each item has Name attr and #text content
  const fields: Record<string, string> = {};
  const ed = ev.EventData as Record<string, unknown> | undefined;
  if (ed) {
    const dataItems = Array.isArray(ed.Data)
      ? (ed.Data as unknown[])
      : ed.Data != null
      ? [ed.Data]
      : [];
    for (const d of dataItems) {
      if (d && typeof d === "object") {
        const item = d as Record<string, unknown>;
        const name = item["Name"];
        if (name != null) {
          const val = item["#text"];
          fields[String(name)] = val != null ? String(val) : "";
        }
      }
    }
  }

  return {
    EventId: eventId,
    TimeCreated: timeCreated,
    MachineName: machineName,
    ActivityId: activityId,
    Level: level,
    Fields: fields,
  };
}

// Minimal types for EvtxFile / Record from @ts-evtx/core.
// Defined locally so we can load the module via new Function() — required
// because @ts-evtx/core is ESM-only and the server compiles to CommonJS.
// TypeScript compiles dynamic import() to require() in CJS mode; wrapping
// in new Function() keeps the raw import() expression intact in emitted JS.
interface EvtxRecord {
  renderXml(): string;
}
interface EvtxFileHandle {
  records(): Generator<EvtxRecord>;
}
interface EvtxFileClass {
  open(filePath: string): Promise<EvtxFileHandle>;
}
const loadEsm = new Function("m", "return import(m)") as
  (m: string) => Promise<{ EvtxFile: EvtxFileClass }>;

/**
 * Parse an EVTX binary buffer and return a JSON string in the named-field
 * format consumed by parseEvtxJson().
 */
export async function evtxBufferToNamedFieldJson(buffer: Buffer): Promise<string> {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const tmpEvtx = path.join(os.tmpdir(), `evtx-${stamp}.evtx`);

  try {
    await fs.writeFile(tmpEvtx, buffer);

    const { EvtxFile } = await loadEsm("@ts-evtx/core");
    const file = await EvtxFile.open(tmpEvtx);

    const records: NamedRecord[] = [];

    for (const record of file.records()) {
      try {
        const xml = record.renderXml();
        const named = xmlToNamedRecord(xml);
        if (named) records.push(named);
      } catch {
        // skip unreadable records
      }
    }

    return JSON.stringify(records);
  } finally {
    await fs.unlink(tmpEvtx).catch(() => {});
  }
}
