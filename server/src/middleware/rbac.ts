/**
 * Role-Based Access Control Middleware
 *
 * Three-tier role hierarchy: viewer < analyst < admin
 *
 * Token authentication:
 *   Clients send `Authorization: Bearer <raw-token>` headers.
 *   The server compares SHA-256(raw-token) against stored token hashes
 *   using timing-safe comparison to prevent timing attacks.
 *
 * When RBAC is disabled (rbac.enabled = false), every request is treated
 * as role "admin" — appropriate for single-user local workstation use.
 *
 * Route permission matrix:
 *   viewer  — parse, compare, semantic-compare, explain, options, health, security/status
 *   analyst — all viewer routes + generate, from-events, propose-rules,
 *             ingest-advanced-hunting, events/*
 *   admin   — all analyst routes + security/audit, security/config
 *
 * To generate a token hash (run once, store result in security.json):
 *   node -e "const {createHash}=require('crypto'); \
 *            console.log(createHash('sha256').update('YOUR_TOKEN').digest('hex'))"
 */

import { createHash, timingSafeEqual } from "crypto";
import type { Request, Response, NextFunction } from "express";
import type { RbacRole } from "@appcontrol/shared";
import type { RbacConfig } from "../config/security-config.js";
import { getAuditLogger } from "../services/audit-logger.js";

// ---------------------------------------------------------------------------
// Extend Express Request with userRole
// ---------------------------------------------------------------------------

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      userRole?: RbacRole;
      /** Token label from rbac config (for audit log display) */
      userLabel?: string;
    }
  }
}

// ---------------------------------------------------------------------------
// Route permission matrix
// ---------------------------------------------------------------------------

const ROLE_RANK: Record<RbacRole, number> = {
  viewer: 1,
  analyst: 2,
  admin: 3,
};

/**
 * Minimum role required for each route.
 * Routes absent from this map are accessible without any role check.
 */
const ROUTE_PERMISSIONS: Record<string, Record<string, RbacRole>> = {
  POST: {
    // Read-only analysis
    "/api/policy/parse":             "viewer",
    "/api/policy/compare":           "viewer",
    "/api/policy/semantic-compare":  "viewer",
    "/api/policy/explain":           "viewer",
    "/api/events/parse":             "viewer",
    // Write / generation operations
    "/api/policy/generate":          "analyst",
    "/api/policy/from-events":       "analyst",
    "/api/policy/propose-rules":     "analyst",
    "/api/policy/ingest-advanced-hunting": "analyst",
    "/api/events/hunting/parse":     "analyst",
    // Admin
    "/api/security/config":          "admin",
  },
  GET: {
    "/api/policy/options":           "viewer",
    "/api/health":                   "viewer",
    "/api/security/status":          "viewer",
    "/api/security/audit":           "admin",
  },
};

export function requiredRoleFor(method: string, path: string): RbacRole | null {
  return ROUTE_PERMISSIONS[method.toUpperCase()]?.[path] ?? null;
}

// ---------------------------------------------------------------------------
// Token hashing
// ---------------------------------------------------------------------------

function hashToken(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

export function createRbacMiddleware(config: RbacConfig) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const logger = getAuditLogger();

    // Already authenticated by a prior middleware (e.g. MSAL JWT validation) —
    // skip token-hash check but still enforce route permission matrix below.
    if (req.userRole) {
      const required = requiredRoleFor(req.method, req.path);
      if (required !== null && ROLE_RANK[req.userRole] < ROLE_RANK[required]) {
        res.status(403).json({
          ok: false,
          error: {
            code: "FORBIDDEN",
            message: `Role '${req.userRole}' does not have access to this operation`,
          },
        });
        return;
      }
      return next();
    }

    // RBAC disabled — grant full access
    if (!config.enabled) {
      req.userRole = "admin";
      req.userLabel = "local";
      return next();
    }

    // Extract Bearer token
    const authHeader = req.headers.authorization ?? "";
    if (!authHeader.startsWith("Bearer ")) {
      logger.log("AUTH_FAILED", {
        succeeded: false,
        errorCode: "MISSING_BEARER",
        errorMessage: "Authorization header missing or not Bearer scheme",
        remoteAddr: req.ip,
      });
      res.status(401).json({
        ok: false,
        error: { code: "UNAUTHORIZED", message: "Bearer token required" },
      });
      return;
    }

    const rawToken = authHeader.slice(7);
    const tokenHash = hashToken(rawToken);

    // Timing-safe comparison against all stored token hashes
    let matchedRole: RbacRole | null = null;
    let matchedLabel = "";
    for (const entry of config.tokens) {
      const stored = Buffer.from(entry.tokenHash, "hex");
      if (stored.length === tokenHash.length && timingSafeEqual(stored, tokenHash)) {
        matchedRole = entry.role;
        matchedLabel = entry.label;
        break;
      }
    }

    if (!matchedRole) {
      logger.log("AUTH_FAILED", {
        succeeded: false,
        errorCode: "INVALID_TOKEN",
        errorMessage: "Token not recognised",
        remoteAddr: req.ip,
      });
      res.status(401).json({
        ok: false,
        error: { code: "UNAUTHORIZED", message: "Invalid token" },
      });
      return;
    }

    // Check route-level permission
    const required = requiredRoleFor(req.method, req.path);
    if (required !== null && ROLE_RANK[matchedRole] < ROLE_RANK[required]) {
      logger.log("AUTHZ_DENIED", {
        role: matchedRole,
        succeeded: false,
        errorCode: "INSUFFICIENT_ROLE",
        errorMessage: `Role '${matchedRole}' is below required '${required}' for ${req.method} ${req.path}`,
        remoteAddr: req.ip,
      });
      res.status(403).json({
        ok: false,
        error: {
          code: "FORBIDDEN",
          message: `Role '${matchedRole}' does not have access to this operation`,
        },
      });
      return;
    }

    logger.log("AUTH_SUCCESS", { role: matchedRole, remoteAddr: req.ip });
    req.userRole = matchedRole;
    req.userLabel = matchedLabel;
    next();
  };
}
