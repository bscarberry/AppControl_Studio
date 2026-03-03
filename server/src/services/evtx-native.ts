/**
 * Cross-platform EVTX binary parser.
 *
 * Uses @ts-evtx/core (pure TypeScript, no native bindings) to iterate over
 * EVTX records and extracts the fields into the named-field JSON format that
 * parseEvtxJson() already knows how to consume.
 *
 * Named-field record shape (mirrors the PowerShell ToXml() output format):
 *   { EventId, TimeCreated, MachineName, ActivityId, Level, Fields }
 */

import path from "path";
import os from "os";
import { promises as fs } from "fs";
import { evtx } from "@ts-evtx/core";

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

/**
 * Parse an EVTX binary buffer and return a JSON string in the named-field
 * format consumed by parseEvtxJson().
 *
 * @ts-evtx/core requires a file path, so the buffer is written to a temp
 * file and cleaned up in the finally block.
 */
export async function evtxBufferToNamedFieldJson(buffer: Buffer): Promise<string> {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const tmpEvtx = path.join(os.tmpdir(), `evtx-${stamp}.evtx`);

  try {
    await fs.writeFile(tmpEvtx, buffer);

    const records: NamedRecord[] = [];

    await evtx(tmpEvtx).forEach((e) => {
      const eventId = e.eventId;
      if (!CI_IDS.has(eventId)) return;

      // Build the Fields map from EventData named items
      const fields: Record<string, string> = {};
      for (const item of e.data.items) {
        if (item.name != null) {
          fields[item.name] = item.value != null ? String(item.value) : "";
        }
      }

      // ActivityID lives in System/Correlation — cast through unknown since the
      // ts-evtx correlation type is opaque; the actual runtime key is ActivityID.
      const corr = e.core?.correlation as Record<string, unknown> | undefined;
      const rawActivityId = corr?.ActivityID ?? corr?.activityId ?? null;
      const activityId = rawActivityId
        ? String(rawActivityId).toUpperCase()
        : null;

      records.push({
        EventId: eventId,
        TimeCreated: e.timestamp ?? null,
        MachineName: e.computer ?? null,
        ActivityId: activityId,
        Level: e.level ?? 0,
        Fields: fields,
      });
    });

    return JSON.stringify(records);
  } finally {
    await fs.unlink(tmpEvtx).catch(() => {});
  }
}
