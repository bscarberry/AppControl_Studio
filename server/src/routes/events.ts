import { Router, Request, Response } from "express";
import { z } from "zod";
import { spawn } from "child_process";
import path from "path";
import os from "os";
import { promises as fs } from "fs";
import multer from "multer";
import {
  parseEvtxJson,
  parseAdvancedHuntingJson,
  parseAdvancedHuntingCsv,
} from "../services/event-parser.js";

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
// Parse native EVTX binary via PowerShell (Windows only)
// ---------------------------------------------------------------------------
eventsRouter.post("/parse-evtx", upload.single("file"), async (req: Request, res: Response) => {
  if (!req.file) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "No file provided." } });
    return;
  }

  const tmpPath = path.join(
    os.tmpdir(),
    `evtx-${Date.now()}-${Math.random().toString(36).slice(2)}.evtx`
  );

  try {
    await fs.writeFile(tmpPath, req.file.buffer);

    const json = await new Promise<string>((resolve, reject) => {
      const ps = spawn("powershell.exe", [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `Get-WinEvent -Path '${tmpPath}' -Oldest -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 5`,
      ]);

      let stdout = "";
      let stderr = "";
      ps.stdout.on("data", (d: Buffer) => { stdout += d.toString(); });
      ps.stderr.on("data", (d: Buffer) => { stderr += d.toString(); });
      ps.on("close", (code: number) => {
        if (stdout.trim().length > 0) resolve(stdout);
        else reject(new Error(stderr.trim() || `PowerShell exited with code ${code}. Ensure this server is running on Windows.`));
      });
      ps.on("error", (err: Error) =>
        reject(new Error(`Failed to start PowerShell: ${err.message}. EVTX binary import requires Windows.`))
      );
    });

    const result = parseEvtxJson(json);
    res.json({ ok: true, data: result });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "PARSE_ERROR", message: (err as Error).message },
    });
  } finally {
    await fs.unlink(tmpPath).catch(() => {});
  }
});
