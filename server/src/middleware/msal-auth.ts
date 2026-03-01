/**
 * MSAL JWT Authentication Middleware
 *
 * Validates Azure AD access tokens (RS256 JWTs) issued by Microsoft's
 * identity platform using the tenant's public JWKS endpoint.
 *
 * When MSAL_TENANT_ID and MSAL_CLIENT_ID are set in the environment this
 * middleware is active.  Requests carrying a valid JWT are allowed through
 * with req.userRole = "admin"; all other requests receive HTTP 401.
 *
 * When those env vars are absent the middleware is a no-op — the existing
 * RBAC middleware (rbac.ts) handles authentication.
 *
 * JWT validation criteria (per Microsoft identity platform documentation):
 *   • Signature — verified against the tenant's rotating JWKS keys
 *   • iss        — must be https://login.microsoftonline.com/<tenantId>/v2.0
 *   • aud        — must be api://<clientId> or <clientId>
 *   • exp / nbf  — standard time-window validation (jsonwebtoken default)
 *   • alg        — RS256 only
 *
 * Reference:
 *   https://learn.microsoft.com/en-us/azure/active-directory/develop/access-tokens
 *   https://learn.microsoft.com/en-us/azure/active-directory/develop/id-tokens
 */

import jwksRsa from "jwks-rsa";
import jwt from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";
import { getAuditLogger } from "../services/audit-logger.js";

// ---------------------------------------------------------------------------
// Read MSAL configuration from environment
// ---------------------------------------------------------------------------

const MSAL_TENANT_ID = process.env.MSAL_TENANT_ID;
const MSAL_CLIENT_ID = process.env.MSAL_CLIENT_ID;

/** True when Azure AD JWT validation is active. */
export const isMsalAuthEnabled = !!(MSAL_TENANT_ID && MSAL_CLIENT_ID);

// ---------------------------------------------------------------------------
// JWKS client — caches signing keys, respects rotation
// ---------------------------------------------------------------------------

const jwksClient = isMsalAuthEnabled
  ? jwksRsa({
      jwksUri: `https://login.microsoftonline.com/${MSAL_TENANT_ID}/discovery/v2.0/keys`,
      cache: true,
      cacheMaxEntries: 10,
      cacheMaxAge: 10 * 60 * 1000, // 10 minutes
      rateLimit: true,
    })
  : null;

// ---------------------------------------------------------------------------
// Key retrieval callback for jsonwebtoken
// ---------------------------------------------------------------------------

function getSigningKey(
  header: jwt.JwtHeader,
  callback: (err: Error | null, key?: string) => void
): void {
  if (!jwksClient) {
    callback(new Error("JWKS client not initialised"));
    return;
  }
  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) {
      callback(err);
      return;
    }
    callback(null, key?.getPublicKey());
  });
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/**
 * Returns Express middleware that validates Azure AD JWTs when MSAL is
 * configured.  When MSAL is not configured this is a pass-through.
 *
 * Sets `req.userRole = "admin"` and `req.userLabel` on success so that the
 * downstream RBAC middleware skips its own token check.
 */
export function createMsalAuthMiddleware() {
  return (req: Request, res: Response, next: NextFunction): void => {
    // MSAL not configured — let existing RBAC middleware handle it
    if (!isMsalAuthEnabled) {
      return next();
    }

    const logger = getAuditLogger();
    const authHeader = req.headers.authorization ?? "";

    if (!authHeader.startsWith("Bearer ")) {
      logger.log("AUTH_FAILED", {
        succeeded: false,
        errorCode: "MISSING_BEARER",
        errorMessage: "MSAL: Authorization header missing or not Bearer scheme",
        remoteAddr: req.ip,
      });
      res.status(401).json({
        ok: false,
        error: { code: "UNAUTHORIZED", message: "Bearer token required" },
      });
      return;
    }

    const token = authHeader.slice(7);

    jwt.verify(
      token,
      getSigningKey,
      {
        // Accept both api://<clientId> and bare <clientId> as audience —
        // the exact value depends on how the app registration is configured.
        audience: [`api://${MSAL_CLIENT_ID}`, MSAL_CLIENT_ID!],
        issuer: `https://login.microsoftonline.com/${MSAL_TENANT_ID}/v2.0`,
        algorithms: ["RS256"],
      },
      (err, decoded) => {
        if (err) {
          logger.log("AUTH_FAILED", {
            succeeded: false,
            errorCode: "INVALID_JWT",
            errorMessage: `MSAL JWT validation failed: ${err.message}`,
            remoteAddr: req.ip,
          });
          res.status(401).json({
            ok: false,
            error: { code: "UNAUTHORIZED", message: "Invalid or expired token" },
          });
          return;
        }

        const payload = decoded as jwt.JwtPayload;
        // preferred_username is the UPN; fall back to oid (object ID)
        const label = (payload.preferred_username as string | undefined) ??
          (payload.oid as string | undefined) ??
          "msal-user";

        logger.log("AUTH_SUCCESS", {
          role: "admin",
          remoteAddr: req.ip,
          outputSummary: `msal user=${label}`,
        });

        // Grant full access — Azure AD is the authority; all authenticated
        // members of the tenant are trusted operators of this local tool.
        req.userRole = "admin";
        req.userLabel = label;
        next();
      }
    );
  };
}
