/**
 * Security API Routes
 *
 * GET  /api/security/status   — public (role: viewer) — current security posture
 * GET  /api/security/audit    — protected (role: admin) — recent audit events
 * POST /api/security/config   — protected (role: admin) — update RBAC tokens
 *
 * These endpoints never expose raw policy content.
 */

import { Router, Request, Response } from "express";
import { z } from "zod";
import { getAuditLogger } from "../services/audit-logger.js";
import { loadSecurityConfig, saveSecurityConfig } from "../config/security-config.js";
import type { SecurityStatus } from "@appcontrol/shared";

export const securityRouter = Router();

const SERVER_VERSION = "1.0.0";

// ---------------------------------------------------------------------------
// GET /api/security/status
// ---------------------------------------------------------------------------

securityRouter.get("/status", async (_req: Request, res: Response) => {
  const logger = getAuditLogger();
  const config = await loadSecurityConfig();

  const status: SecurityStatus = {
    localOnlyBinding: true,
    noExternalTransmission: true,
    rbacEnabled: config.rbac.enabled,
    auditEnabled: config.audit.enabled,
    memoryOnlyMode: config.memory.aggressiveClearingEnabled,
    serverVersion: SERVER_VERSION,
    auditEventCount: logger.eventCount,
    recentEvents: logger.recentEvents(20),
  };

  res.json({ ok: true, data: status });
});

// ---------------------------------------------------------------------------
// GET /api/security/audit
// ---------------------------------------------------------------------------

securityRouter.get("/audit", (req: Request, res: Response) => {
  // Role check: admin only
  if (req.userRole !== "admin") {
    res.status(403).json({
      ok: false,
      error: { code: "FORBIDDEN", message: "Audit log access requires admin role" },
    });
    return;
  }

  const limitParam = parseInt((req.query["limit"] as string) ?? "100", 10);
  const limit = Number.isNaN(limitParam) ? 100 : Math.min(Math.max(1, limitParam), 500);

  const logger = getAuditLogger();
  res.json({
    ok: true,
    data: {
      events: logger.recentEvents(limit),
      totalInMemory: logger.eventCount,
    },
  });
});

// ---------------------------------------------------------------------------
// POST /api/security/config  (admin only — add / revoke RBAC tokens)
// ---------------------------------------------------------------------------

const tokenEntrySchema = z.object({
  tokenHash: z.string().regex(/^[0-9a-f]{64}$/, "tokenHash must be a 64-char hex SHA-256 string"),
  role: z.enum(["admin", "analyst", "viewer"]),
  label: z.string().min(1).max(64),
});

const configUpdateSchema = z.object({
  rbac: z
    .object({
      enabled: z.boolean().optional(),
      tokens: z.array(tokenEntrySchema).optional(),
    })
    .optional(),
  audit: z
    .object({
      enabled: z.boolean().optional(),
    })
    .optional(),
  memory: z
    .object({
      aggressiveClearingEnabled: z.boolean().optional(),
    })
    .optional(),
});

securityRouter.post("/config", async (req: Request, res: Response) => {
  if (req.userRole !== "admin") {
    res.status(403).json({
      ok: false,
      error: { code: "FORBIDDEN", message: "Config changes require admin role" },
    });
    return;
  }

  const parsed = configUpdateSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      ok: false,
      error: { code: "VALIDATION", message: parsed.error.message },
    });
    return;
  }

  try {
    const current = await loadSecurityConfig();
    const update = parsed.data;

    if (update.rbac?.enabled !== undefined) current.rbac.enabled = update.rbac.enabled;
    if (update.rbac?.tokens !== undefined) current.rbac.tokens = update.rbac.tokens;
    if (update.audit?.enabled !== undefined) current.audit.enabled = update.audit.enabled;
    if (update.memory?.aggressiveClearingEnabled !== undefined) {
      current.memory.aggressiveClearingEnabled = update.memory.aggressiveClearingEnabled;
    }

    await saveSecurityConfig(current);

    const logger = getAuditLogger();
    logger.log("CONFIG_CHANGED", {
      role: req.userRole,
      outputSummary: `rbac.enabled=${current.rbac.enabled}, tokens=${current.rbac.tokens.length}`,
      succeeded: true,
    });

    res.json({ ok: true, data: { message: "Security configuration updated. Restart the server to apply RBAC changes." } });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: { code: "CONFIG_WRITE_ERROR", message: (err as Error).message },
    });
  }
});
