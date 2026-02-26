import { Router, Request, Response } from "express";
import { z } from "zod";
import {
  parseEvtxJson,
  parseAdvancedHuntingJson,
  parseAdvancedHuntingCsv,
} from "../services/event-parser.js";

export const eventsRouter = Router();

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
