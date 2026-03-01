/**
 * AppControl Studio — Express Server
 *
 * Security architecture summary:
 *   • Bound exclusively to 127.0.0.1 — no inbound network exposure
 *   • No outbound HTTP calls during policy processing
 *   • Append-only structured audit log (metadata only — no policy content)
 *   • Optional RBAC with timing-safe SHA-256 token authentication
 *   • XML bomb / oversized document rejection before parsing
 *   • 50 MB body limit enforced at the content-length header level
 *   • Helmet security headers on all responses
 *
 * See SECURITY.md for the full threat model and data handling policy.
 */

import express from "express";
import cors from "cors";
import helmet from "helmet";
import { policyRouter } from "./routes/policy.js";
import { eventsRouter } from "./routes/events.js";
import { securityRouter } from "./routes/security.js";
import { errorHandler, requestSizeGuard } from "./middleware/error-handler.js";
import { createRbacMiddleware } from "./middleware/rbac.js";
import { loadSecurityConfig } from "./config/security-config.js";
import { initAuditLogger, getAuditLogger } from "./services/audit-logger.js";

const PORT = parseInt(process.env.PORT ?? "3001", 10);
const MAX_BODY = 50 * 1024 * 1024; // 50 MB

// Create app before async startup so it can be exported synchronously
const app = express();

// ---------------------------------------------------------------------------
// Async startup — load config before binding
// ---------------------------------------------------------------------------

(async () => {
  const secConfig = await loadSecurityConfig();

  // Initialise audit logger first so every subsequent event can be logged
  initAuditLogger(secConfig.audit);

  // ---------------------------------------------------------------------------
  // Security headers
  // ---------------------------------------------------------------------------

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:"],
          connectSrc: ["'self'"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
        },
      },
      // Disable caching of responses that contain policy data
      noSniff: true,
      frameguard: { action: "deny" },
    })
  );

  // No-cache for all API responses (policy data must not be cached by intermediaries)
  app.use("/api", (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    next();
  });

  // ---------------------------------------------------------------------------
  // CORS — restrict to local Vite dev server (or configured origin)
  // ---------------------------------------------------------------------------

  app.use(
    cors({
      origin: process.env.CLIENT_ORIGIN ?? "http://localhost:5173",
      methods: ["GET", "POST"],
      allowedHeaders: ["Content-Type", "Authorization"],
    })
  );

  // ---------------------------------------------------------------------------
  // Body parsing — size limits enforced before JSON parsing
  // ---------------------------------------------------------------------------

  app.use(requestSizeGuard(MAX_BODY));
  app.use(express.json({ limit: "50mb" }));
  app.use(express.text({ limit: "50mb" }));

  // ---------------------------------------------------------------------------
  // RBAC — applied to all /api/* routes
  // ---------------------------------------------------------------------------

  const rbacMiddleware = createRbacMiddleware(secConfig.rbac);
  app.use("/api", rbacMiddleware);

  // ---------------------------------------------------------------------------
  // Routes
  // ---------------------------------------------------------------------------

  app.use("/api/policy", policyRouter);
  app.use("/api/events", eventsRouter);
  app.use("/api/security", securityRouter);

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, data: { status: "healthy", version: "1.0.0" } });
  });

  // ---------------------------------------------------------------------------
  // Error handling
  // ---------------------------------------------------------------------------

  app.use(errorHandler);

  // ---------------------------------------------------------------------------
  // Start server — loopback only
  // ---------------------------------------------------------------------------

  app.listen(PORT, "127.0.0.1", () => {
    const logger = getAuditLogger();
    logger.log("SERVER_START", {
      outputSummary: `port=${PORT} rbac=${secConfig.rbac.enabled} audit=${secConfig.audit.enabled}`,
      succeeded: true,
    });
    console.log(`[AppControl Studio] Listening on http://127.0.0.1:${PORT}`);
    console.log(`[AppControl Studio] RBAC: ${secConfig.rbac.enabled ? "enabled" : "disabled (local mode)"}`);
    console.log(`[AppControl Studio] Audit log: ${secConfig.audit.enabled ? secConfig.audit.logDir : "in-memory only"}`);
    console.log(`[AppControl Studio] All processing is local — no external data transmission.`);
  });
})().catch((err: unknown) => {
  console.error("[AppControl Studio] Fatal startup error:", err);
  process.exit(1);
});

// Graceful shutdown
process.on("SIGTERM", () => {
  getAuditLogger().log("SERVER_STOP", { succeeded: true });
});
process.on("SIGINT", () => {
  getAuditLogger().log("SERVER_STOP", { succeeded: true });
  process.exit(0);
});

export default app;
