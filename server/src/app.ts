/**
 * AppControl Studio — Express Server
 *
 * All processing happens locally; no data is transmitted to external services.
 */

import express from "express";
import cors from "cors";
import helmet from "helmet";
import { policyRouter } from "./routes/policy.js";
import { eventsRouter } from "./routes/events.js";
import { errorHandler, requestSizeGuard } from "./middleware/error-handler.js";

const app = express();
const PORT = parseInt(process.env.PORT ?? "3001", 10);

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
      },
    },
  })
);

app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN ?? "http://localhost:5173",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);

// ---------------------------------------------------------------------------
// Body parsing — enforce max payload size to prevent DoS
// ---------------------------------------------------------------------------
const MAX_BODY = 50 * 1024 * 1024; // 50MB max (EVTX exports can be large)
app.use(requestSizeGuard(MAX_BODY));
app.use(express.json({ limit: "50mb" }));
app.use(express.text({ limit: "50mb" }));

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------
app.use("/api/policy", policyRouter);
app.use("/api/events", eventsRouter);

// Health check
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, data: { status: "healthy", version: "1.0.0" } });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------
app.use(errorHandler);

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.listen(PORT, "127.0.0.1", () => {
  console.log(`[AppControl Studio] Server listening on http://127.0.0.1:${PORT}`);
  console.log(`[AppControl Studio] All processing is local — no external data transmission.`);
});

export default app;
