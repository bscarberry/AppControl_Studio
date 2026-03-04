#!/usr/bin/env node
/**
 * Debug script — dumps the raw renderXml() output for every CI event
 * in an EVTX file so we can see exactly what the parser produces.
 *
 * Usage (from repo root):
 *   node debug-evtx.mjs <path-to-file.evtx>
 */

import { EvtxFile } from "./node_modules/@ts-evtx/core/dist/index.js";

const file = process.argv[2];
if (!file) { console.error("Usage: node debug-evtx.mjs <file.evtx>"); process.exit(1); }

const CI_IDS = new Set([3033,3034,3036,3064,3065,3076,3077,3079,3080,3082,3089,3091,3092,3111,3114]);

const evtx = await EvtxFile.open(file);
let count = 0;

for (const record of evtx.records()) {
  try {
    const xml = record.renderXml();

    // Quick event ID sniff — full parse is done below
    const idMatch = xml.match(/<EventID(?:[^>]*)>(\d+)<\/EventID>/);
    if (!idMatch) continue;
    const eventId = Number(idMatch[1]);
    if (!CI_IDS.has(eventId)) continue;

    console.log(`\n${"=".repeat(72)}`);
    console.log(`EVENT ID: ${eventId}`);
    console.log(`${"=".repeat(72)}`);
    console.log(xml);
    count++;
  } catch (e) {
    // skip unreadable records
  }
}

console.log(`\n--- ${count} CI events found ---`);
