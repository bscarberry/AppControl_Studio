#!/usr/bin/env node
/**
 * Debug script — dumps evtx_dump JSONL output for every CI event
 * in an EVTX file so we can inspect what the parser actually produces.
 *
 * Usage (from repo root):
 *   node debug-evtx.mjs <path-to-file.evtx>
 *
 * Requires evtx_dump: cargo install evtx
 */

import { spawnSync } from "child_process";

const file = process.argv[2];
if (!file) { console.error("Usage: node debug-evtx.mjs <file.evtx>"); process.exit(1); }

const EVTX_DUMP = process.env.EVTX_DUMP_PATH ?? "/root/.cargo/bin/evtx_dump";

const CI_IDS = new Set([3033,3034,3036,3064,3065,3076,3077,3079,3080,3082,3089,3091,3092,3111,3114]);

const result = spawnSync(EVTX_DUMP, ["-o", "jsonl", file], { encoding: "utf8", maxBuffer: 200 * 1024 * 1024 });

if (result.error) {
  console.error("Failed to run evtx_dump:", result.error.message);
  process.exit(1);
}

const lines = result.stdout.split("\n").filter(l => l.trim());
let count = 0;

for (const line of lines) {
  let doc;
  try { doc = JSON.parse(line); } catch { continue; }

  const sys = doc?.Event?.System;
  if (!sys) continue;

  const rawId = sys.EventID;
  const eventId = typeof rawId === "object" ? Number(rawId["#text"]) : Number(rawId);
  if (!CI_IDS.has(eventId)) continue;

  console.log(`\n${"=".repeat(72)}`);
  console.log(`EVENT ID: ${eventId}`);
  console.log(`${"=".repeat(72)}`);
  console.log(JSON.stringify(doc, null, 2));
  count++;
}

console.log(`\n--- ${count} CI events found ---`);
