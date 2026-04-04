/**
 * Cross-platform EVTX binary parser.
 *
 * Uses evtx_dump (https://github.com/omerbenamram/evtx) as a subprocess.
 * evtx_dump correctly handles UTF-16LE strings, binary fields, and all EVTX
 * binary template types — none of the bugs present in @ts-evtx/core.
 *
 * The EVTX buffer is written to evtx_dump's stdin; records are streamed back
 * as JSON Lines (one JSON object per line) and filtered to CI event IDs.
 *
 * Install: cargo install evtx
 * Override binary path: EVTX_DUMP_PATH env var (default: evtx_dump)
 *
 * Named-field record shape (mirrors the PowerShell ToXml() output format):
 *   { EventId, TimeCreated, MachineName, ActivityId, Level, Fields }
 */

import { spawn } from "child_process";

// Path to evtx_dump binary.
// Default: bundled binary at server/bin/evtx_dump (relative to the compiled app.js in server/dist/).
// Override: set EVTX_DUMP_PATH env var.
import path from "path";
const EVTX_DUMP = process.env.EVTX_DUMP_PATH
  ?? path.join(__dirname, "..", "..", "bin", "evtx_dump");

// CodeIntegrity event IDs we care about
const CI_IDS = new Set([
  3033, 3034, 3036,
  3064, 3065,
  3076, 3077, 3079, 3080, 3082,
  3089, 3091, 3092,
  3111, 3114,
]);

/**
 * Known positional field layouts for CodeIntegrity events.
 * Used as a fallback when evtx_dump outputs Data items without a Name attribute.
 * Positions that are numeric/binary-only fields not needed for rule building are
 * omitted (they are not extracted by parseNamedRecord anyway).
 */
const CI_POSITIONAL_FIELDS: Record<number, string[]> = {
  // 3033, 3034, 3036 — kernel-mode enforcement/audit/scan
  3033: ["FileNameBuffer", "Status", "PolicyGuid"],
  3034: ["FileNameBuffer", "Status", "PolicyGuid"],
  3036: ["FileNameBuffer", "Status", "PolicyGuid"],
  // 3064, 3065 — boot-policy audit/block
  3064: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid", "UserWriteable",
         "OriginalFilename", "InternalName", "FileDescription", "ProductName",
         "FileVersion", "PackageFamilyName"],
  3065: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid", "UserWriteable",
         "OriginalFilename", "InternalName", "FileDescription", "ProductName",
         "FileVersion", "PackageFamilyName"],
  // 3076, 3077 — user-mode audit/block
  3076: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid", "UserWriteable",
         "OriginalFilename", "InternalName", "FileDescription", "ProductName",
         "FileVersion", "PackageFamilyName"],
  3077: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid", "UserWriteable",
         "OriginalFilename", "InternalName", "FileDescription", "ProductName",
         "FileVersion", "PackageFamilyName"],
  // 3079, 3080, 3082 — script/MSI audit/block
  3079: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid"],
  3080: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid"],
  3082: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid"],
  // 3089 — signature information (correlated with parent events)
  3089: ["FileNameBuffer", "PolicyGuid", "TotalSignatureCount", "SignatureIndex",
         "SignatureType", "ValidatedSigningLevel", "VerificationError", "Flags",
         "PolicyBits", "NotValidBefore", "NotValidAfter",
         "PublisherName", "IssuerName", "PublisherTBSHash", "IssuerTBSHash",
         "OriginalFilename", "InternalName", "FileDescription", "ProductName",
         "FileVersion"],
  // 3091, 3092
  3091: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "PolicyName"],
  3092: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "PolicyName"],
  // 3111, 3114
  3111: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid"],
  3114: ["FileNameBuffer", "ProcessNameBuffer", "RequestedPolicy", "ValidatedPolicy", "Status",
         "Sha1FlatHash", "Sha256FlatHash", "Sha1PageHash", "Sha256PageHash",
         "Flags", "PolicyName", "PolicyGuid"],
};

interface NamedRecord {
  EventId: number;
  TimeCreated: string | null;
  MachineName: string | null;
  ActivityId: string | null;
  Level: number;
  Fields: Record<string, string>;
}

/**
 * Parse one JSONL line from evtx_dump into a NamedRecord.
 *
 * evtx_dump JSON structure:
 *   Event.System.EventID               — number, or {#attributes:{Qualifiers}, #text: number}
 *   Event.System.TimeCreated.#attributes.SystemTime — ISO-8601 string
 *   Event.System.Correlation.#attributes.ActivityID — GUID string
 *   Event.System.Computer              — string
 *   Event.System.Level                 — number
 *   Event.EventData.Data               — array of {#attributes:{Name}, #text?}
 */
function parseJsonlLine(line: string): NamedRecord | null {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(line);
  } catch {
    return null;
  }

  const ev = doc.Event as Record<string, unknown> | undefined;
  if (!ev) return null;

  const sys = ev.System as Record<string, unknown> | undefined;
  if (!sys) return null;

  // EventID: plain number or {#attributes:{Qualifiers:"0"}, #text: number}
  const rawId = sys.EventID;
  const eventId =
    rawId !== null && typeof rawId === "object"
      ? Number((rawId as Record<string, unknown>)["#text"])
      : Number(rawId);

  if (!CI_IDS.has(eventId)) return null;

  // TimeCreated/@SystemTime
  const tc = sys.TimeCreated as Record<string, unknown> | undefined;
  const tcAttrs = tc?.["#attributes"] as Record<string, unknown> | undefined;
  const timeCreated = tcAttrs?.SystemTime ? String(tcAttrs.SystemTime) : null;

  const machineName = sys.Computer ? String(sys.Computer) : null;

  // Correlation/@ActivityID
  const corr = sys.Correlation as Record<string, unknown> | undefined;
  const corrAttrs = corr?.["#attributes"] as Record<string, unknown> | undefined;
  const rawActivity = corrAttrs?.ActivityID ?? null;
  const activityId = rawActivity ? String(rawActivity).toUpperCase() : null;

  const level = Number(sys.Level ?? 0);

  // EventData/Data[] — each item has #attributes.Name and optional #text.
  // Some EVTX files (or evtx_dump versions) emit Data items without a Name
  // attribute (positional format).  Fall back to the known field layout table.
  const fields: Record<string, string> = {};
  const ed = ev.EventData as Record<string, unknown> | undefined;
  if (ed) {
    const dataRaw = ed.Data;
    const dataItems: unknown[] = Array.isArray(dataRaw)
      ? dataRaw
      : dataRaw != null
      ? [dataRaw]
      : [];

    const positionalLayout = CI_POSITIONAL_FIELDS[eventId] ?? [];
    let hasNamedFields = false;

    for (let i = 0; i < dataItems.length; i++) {
      const d = dataItems[i];
      if (!d || typeof d !== "object") {
        // Plain string value — positional
        if (d != null && positionalLayout[i]) {
          fields[positionalLayout[i]] = String(d);
        }
        continue;
      }
      const item = d as Record<string, unknown>;
      const attrs = item["#attributes"] as Record<string, unknown> | undefined;
      const name = attrs?.Name;
      if (name == null) {
        // Object without Name — positional
        const raw = item["#text"];
        if (raw != null && positionalLayout[i]) {
          fields[positionalLayout[i]] = String(raw);
        }
        continue;
      }
      // Named field
      hasNamedFields = true;
      const raw = item["#text"];
      fields[String(name)] = raw != null ? String(raw) : "";
    }

    // If every item was named but none matched any expected CI field name,
    // the layout might use different casing.  No additional action needed —
    // parseNamedRecord already tries multiple name variants.
    void hasNamedFields; // suppress unused-var lint
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

/**
 * Return raw JSONL lines from evtx_dump for diagnostic purposes.
 * Only lines that parse as JSON objects are included (empty/separator lines
 * are dropped).  The first `limit` lines are returned.
 */
export async function evtxDumpRaw(buffer: Buffer, limit = 20): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const proc = spawn(EVTX_DUMP, ["-o", "jsonl", "-"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const lines: string[] = [];
    let lineBuf = "";

    proc.stdout.on("data", (chunk: Buffer) => {
      if (lines.length >= limit) return;
      lineBuf += chunk.toString("utf8");
      const parts = lineBuf.split("\n");
      lineBuf = parts.pop() ?? "";
      for (const line of parts) {
        const trimmed = line.trim();
        if (trimmed) lines.push(trimmed);
        if (lines.length >= limit) break;
      }
    });

    proc.on("close", (code) => {
      if (lineBuf.trim() && lines.length < limit) lines.push(lineBuf.trim());
      if (code !== 0 && lines.length === 0) {
        reject(new Error(`evtx_dump exited with code ${code}`));
        return;
      }
      resolve(lines);
    });

    proc.on("error", (err: NodeJS.ErrnoException) => {
      reject(new Error(`Failed to spawn evtx_dump: ${err.message}`));
    });

    proc.stdin.end(buffer);
  });
}

/**
 * Parse an EVTX binary buffer and return a JSON string in the named-field
 * format consumed by parseEvtxJson().
 *
 * Spawns evtx_dump, writes the buffer to its stdin, and collects the JSONL
 * output. Resolves even if some records are unreadable (they are skipped).
 */
export async function evtxBufferToNamedFieldJson(buffer: Buffer): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn(EVTX_DUMP, ["-o", "jsonl", "-"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const records: NamedRecord[] = [];
    let stderrBuf = "";
    let lineBuf = "";

    proc.stderr.on("data", (chunk: Buffer) => {
      stderrBuf += chunk.toString();
    });

    proc.stdout.on("data", (chunk: Buffer) => {
      lineBuf += chunk.toString("utf8");
      const lines = lineBuf.split("\n");
      lineBuf = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const record = parseJsonlLine(trimmed);
        if (record) records.push(record);
      }
    });

    proc.on("close", (code) => {
      // Flush any remaining partial line
      if (lineBuf.trim()) {
        const record = parseJsonlLine(lineBuf.trim());
        if (record) records.push(record);
      }
      // Treat non-zero exit as an error only if we got nothing at all
      if (code !== 0 && records.length === 0) {
        reject(
          new Error(
            `evtx_dump exited with code ${code}: ${stderrBuf.trim()}. ` +
            "Ensure evtx_dump is installed (cargo install evtx) and the file is a valid EVTX."
          )
        );
        return;
      }
      resolve(JSON.stringify(records));
    });

    proc.on("error", (err: NodeJS.ErrnoException) => {
      const hint =
        err.code === "ENOENT"
          ? " — install evtx_dump with: cargo install evtx"
          : "";
      reject(new Error(`Failed to spawn evtx_dump: ${err.message}${hint}`));
    });

    // Pipe the EVTX buffer into evtx_dump's stdin
    proc.stdin.end(buffer);
  });
}
