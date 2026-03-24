import { Router, Request, Response } from "express";
import { z } from "zod";
import multer from "multer";
import {
  parseEvtxJson,
  parseAdvancedHuntingJson,
  parseAdvancedHuntingCsv,
} from "../services/event-parser.js";
import { evtxBufferToNamedFieldJson } from "../services/evtx-native.js";

export const eventsRouter = Router();

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// ---------------------------------------------------------------------------
// Parse CodeIntegrity event log JSON
// ---------------------------------------------------------------------------
eventsRouter.post("/parse", (req: Request, res: Response) => {
  const schema = z.object({
    content: z.string().min(1),
    format: z.enum(["json", "csv", "evtx-json"]),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  try {
    let result;
    switch (parsed.data.format) {
      case "json":
      case "evtx-json":
        result = parseEvtxJson(parsed.data.content);
        break;
      case "csv":
        result = parseAdvancedHuntingCsv(parsed.data.content);
        break;
    }
    res.json({ ok: true, data: result });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "PARSE_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Parse Advanced Hunting query results
// ---------------------------------------------------------------------------
eventsRouter.post("/hunting/parse", (req: Request, res: Response) => {
  const schema = z.object({
    content: z.string().min(1),
    format: z.enum(["json", "csv"]),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  try {
    const result =
      parsed.data.format === "json"
        ? parseAdvancedHuntingJson(parsed.data.content)
        : parseAdvancedHuntingCsv(parsed.data.content);
    res.json({ ok: true, data: result });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "PARSE_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Parse native EVTX binary — via evtx_dump (cargo install evtx)
// ---------------------------------------------------------------------------
eventsRouter.post("/parse-evtx", upload.single("file"), async (req: Request, res: Response) => {
  if (!req.file) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "No file provided." } });
    return;
  }

  try {
    const json = await evtxBufferToNamedFieldJson(req.file.buffer);
    const result = parseEvtxJson(json);
    res.json({ ok: true, data: result });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "PARSE_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Debug: return raw evtx_dump JSONL output (intermediate named records)
// ---------------------------------------------------------------------------
eventsRouter.post("/debug-evtx-raw", upload.single("file"), async (req: Request, res: Response) => {
  if (!req.file) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "No file provided." } });
    return;
  }
  try {
    const json = await evtxBufferToNamedFieldJson(req.file.buffer);
    res.json({ ok: true, raw: JSON.parse(json) });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "PARSE_ERROR", message: (err as Error).message },
    });
  }
});
