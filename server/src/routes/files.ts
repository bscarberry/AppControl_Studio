/**
 * File inspection routes
 *
 *   POST /api/files/inspect     multipart: file[] → hashes, signatures, version info
 *   POST /api/files/rules       JSON: { files, level, effect, fallbackToHash, filePaths }
 *   POST /api/files/cert-inspect multipart: file[] (.cer/.crt/.pem/.p7b) → certificates
 *
 * Files are processed in memory and never written to disk.
 */

import { Router, Request, Response } from "express";
import multer from "multer";
import { z } from "zod";
import type { InspectedFile, RuleLevel, FileRuleBundle } from "@appcontrol/shared";
import { RULE_LEVELS } from "@appcontrol/shared";
import { inspectFile, buildRulesForFile } from "../services/file-inspector.js";
import { parseCertificateFile } from "../services/pe/authenticode.js";
import { getAuditLogger } from "../services/audit-logger.js";

export const filesRouter = Router();

const MAX_FILE = 200 * 1024 * 1024; // per file; total request capped at 512 MB in app.ts
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE, files: 200 },
});

filesRouter.post("/inspect", upload.array("files", 200), (req: Request, res: Response) => {
  const files = (req.files as Express.Multer.File[] | undefined) ?? [];
  if (files.length === 0) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "No files provided (multipart field 'files')." } });
    return;
  }
  const start = Date.now();
  const out: InspectedFile[] = [];
  const errors: Array<{ fileName: string; message: string }> = [];
  for (const f of files) {
    try {
      out.push(inspectFile(f.originalname, f.buffer));
    } catch (e) {
      errors.push({ fileName: f.originalname, message: (e as Error).message });
    }
  }
  getAuditLogger().log("FILES_INSPECTED", {
    role: req.userRole,
    inputSizeBytes: files.reduce((n, f) => n + f.size, 0),
    outputSummary: `files=${out.length} signed=${out.filter((x) => x.signature.status === "embedded").length} errors=${errors.length}`,
    durationMs: Date.now() - start,
    succeeded: true,
  });
  res.json({
    ok: true,
    data: { files: out, errors, capabilities: { authenticode: true, pageHash: true, signatures: true } },
  });
});

const levelIds = RULE_LEVELS.map((l) => l.id) as [RuleLevel, ...RuleLevel[]];

filesRouter.post("/rules", (req: Request, res: Response) => {
  const schema = z.object({
    files: z.array(z.record(z.unknown())).min(1).max(5000),
    level: z.enum(levelIds),
    effect: z.enum(["Allow", "Deny"]).optional(),
    fallbackToHash: z.boolean().optional(),
    filePaths: z.record(z.string()).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }
  try {
    const bundles: FileRuleBundle[] = (parsed.data.files as unknown as InspectedFile[]).map((f) =>
      buildRulesForFile(f, parsed.data.level, {
        effect: parsed.data.effect,
        fallbackToHash: parsed.data.fallbackToHash,
        filePath: parsed.data.filePaths?.[f.fileName],
      })
    );
    res.json({ ok: true, data: { bundles } });
  } catch (e) {
    res.status(422).json({ ok: false, error: { code: "RULE_BUILD_ERROR", message: (e as Error).message } });
  }
});

filesRouter.post("/cert-inspect", upload.array("files", 50), (req: Request, res: Response) => {
  const files = (req.files as Express.Multer.File[] | undefined) ?? [];
  if (files.length === 0) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "No files provided." } });
    return;
  }
  const certificates = files.flatMap((f) =>
    parseCertificateFile(f.buffer).map((c) => {
      const { der: _d, issuerDer: _i, subjectDer: _s, ...rest } = c;
      return { ...rest, fileName: f.originalname };
    })
  );
  if (certificates.length === 0) {
    res.status(422).json({ ok: false, error: { code: "CERT_PARSE_ERROR", message: "No X.509 certificates could be parsed from the uploaded file(s)." } });
    return;
  }
  res.json({ ok: true, data: { certificates } });
});
