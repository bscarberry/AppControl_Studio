# AppControl Studio — Security Architecture

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Trust Boundaries](#trust-boundaries)
3. [Threat Model (STRIDE)](#threat-model-stride)
4. [Implemented Controls](#implemented-controls)
5. [Data Handling Policy](#data-handling-policy)
6. [Role-Based Access Control](#role-based-access-control)
7. [Audit Logging](#audit-logging)
8. [Secure Update Procedure](#secure-update-procedure)
9. [Known Limitations & Residual Risks](#known-limitations--residual-risks)

---

## Architecture Overview

AppControl Studio is a **local-first** WDAC policy management tool. All processing
occurs on the operator's machine. No policy data, events, or audit information is
transmitted to external services under any circumstances.

```
┌─────────────────────────────────────────────────────────┐
│                 Operator's Workstation                  │
│                                                         │
│  ┌──────────────┐  HTTP/JSON   ┌──────────────────────┐ │
│  │ React Client │◄────────────►│ Express Server       │ │
│  │ :5173 (dev)  │  127.0.0.1  │ 127.0.0.1:3001       │ │
│  └──────────────┘             └──────┬───────────────┘ │
│                                      │                  │
│                               ┌──────▼───────────────┐ │
│                               │  File System          │ │
│                               │  ~/.appcontrol-studio │ │
│                               │    security.json      │ │
│                               │    audit/             │ │
│                               └───────────────────────┘ │
│                                                         │
│  ← No outbound connections →  ← No inbound from net → │
└─────────────────────────────────────────────────────────┘
```

**Key invariants:**
- Server binds to `127.0.0.1` only — not `0.0.0.0`
- CORS is restricted to `http://localhost:5173` (configurable)
- Zero runtime dependencies make external HTTP calls
- Policy XML is processed in-memory and discarded after response

---

## Trust Boundaries

| Boundary | Left side | Right side | Controls |
|---|---|---|---|
| **B1** Browser ↔ Server | React UI (renderer process) | Express API | CORS, RBAC Bearer tokens, input validation |
| **B2** Server ↔ File system | Express process | ~/.appcontrol-studio/ | OS file permissions (mode 0o600 for security.json) |
| **B3** Server ↔ Memory | Route handlers | V8 heap | Zod schema validation, XML pre-checks, size limits |
| **B4** Admin ↔ Config | Human operator | security.json | File permissions, token hashing (no plaintext) |

---

## Threat Model (STRIDE)

### S — Spoofing

**Threat S1: Unauthorized local user claims a higher role**
- Attack: User on the same machine sends requests with a fabricated or stolen Bearer token.
- Likelihood: Medium (shared workstation / CI server scenario).
- Impact: Access to policy generation or audit log.
- **Mitigations:**
  - RBAC middleware checks SHA-256(token) against stored hashes using `crypto.timingSafeEqual` — prevents timing-based token enumeration.
  - Tokens are never stored in plaintext; only SHA-256 hashes in `security.json`.
  - Failed authentication events are logged immediately with `AUTH_FAILED`.
- Residual risk: Token compromise via shoulder surfing, clipboard, or shell history. Mitigated by token rotation process.

**Threat S2: Malicious process on localhost impersonates the server**
- Attack: Another local process binds to :3001 before AppControl Studio starts.
- Likelihood: Low.
- Impact: Client sends policy data to the wrong process.
- **Mitigations:** None at the application layer — this is an OS-level concern. Run AppControl Studio under a dedicated user account on multi-user systems.

---

### T — Tampering

**Threat T1: Malicious XML bomb in an uploaded policy file**
- Attack: Operator loads a crafted `<!DOCTYPE>` / `<!ENTITY>` XML file that expands exponentially during parsing, exhausting process memory.
- Likelihood: Medium (WDAC XML files are obtained from various sources).
- Impact: Server process crash (DoS), potential OOM.
- **Mitigations (`xml-validator.ts`):**
  - `<!DOCTYPE>` declarations → rejected with HTTP 422 before any parsing.
  - `<!ENTITY>` declarations → rejected with HTTP 422.
  - `<?xml-stylesheet?>` PIs → rejected (external resource load vector).
  - Element count heuristic (`<` character count > 100,000) → rejected.
  - Nesting depth heuristic (> 50 levels) → rejected.
  - 50 MB body limit enforced at `Content-Length` header level before body is read.

**Threat T2: Path traversal via XML attribute values**
- Attack: XML attribute contains `../../../etc/passwd` style values that are used as file paths.
- Likelihood: Low (server never uses XML attribute values as file system paths).
- Impact: None — all processing is in-memory; no file writes from XML content.
- **Mitigations:** Architecture — XML data never flows to `fs.readFile`/`fs.writeFile` calls.

**Threat T3: In-transit policy modification**
- Attack: Man-in-the-middle modifies request/response.
- Likelihood: Very low (loopback only; no network transit).
- Impact: Corrupted policy data.
- **Mitigations:** Loopback binding eliminates network transit. TLS is unnecessary and not implemented for loopback communication.

---

### R — Repudiation

**Threat R1: User denies having loaded or modified a policy**
- Attack: Insider claims a policy change was made by someone else.
- **Mitigations (audit-logger.ts):**
  - Every policy operation records: event type, timestamp (ISO 8601 UTC), role, SHA-256 of input, output summary, duration.
  - Audit log is append-only JSONL — existing entries cannot be modified without truncating the file (detectable by log size decrease).
  - `CONFIG_CHANGED` events log when RBAC tokens are added or revoked.
  - `SERVER_START` / `SERVER_STOP` events bracket the session.

**Threat R2: Operator repudiates an RBAC configuration change**
- **Mitigations:** `CONFIG_CHANGED` audit event records: role of the changer, new token count, timestamp.

---

### I — Information Disclosure

**Threat I1: Policy content leaked via audit log**
- Attack: Someone with read access to the audit log directory recovers sensitive policy XML.
- **Mitigations:**
  - Audit log records only SHA-256 hashes of inputs — never raw content.
  - Output summaries record counts and identifiers only (e.g., `"fileRules=47 signers=12"`).
  - `errorMessage` fields are sanitized — they contain only parser error strings, not policy content.
  - `security.json` is written with `mode: 0o600` (owner read/write only).

**Threat I2: Policy content exposed via server error messages**
- Attack: A malformed policy causes an unhandled exception that includes XML content in the stack trace.
- **Mitigations:**
  - `errorHandler` middleware returns generic messages in production (`NODE_ENV=production`).
  - Route handlers catch all exceptions; error messages passed to clients are the exception `.message` string only (not `.stack`).

**Threat I3: Policy content persisted in swap/pagefile**
- Attack: OS pages in-memory policy data to disk; attacker with physical access recovers it.
- Likelihood: Low for most deployments.
- **Mitigations:**
  - No mitigation at the application layer — this is an OS/hardware concern.
  - Enterprise deployments should use full-disk encryption (BitLocker/FileVault).
  - The `aggressiveClearingEnabled` memory config option is a placeholder for future `Buffer.fill(0)` post-processing.

---

### D — Denial of Service

**Threat D1: Large file upload exhausts server memory**
- Attack: Operator (or attacker via CSRF from another local tab) uploads a 500 MB XML file.
- **Mitigations:**
  - `requestSizeGuard` checks `Content-Length` header before the body is buffered.
  - `express.json({ limit: "50mb" })` as a second layer.
  - XML byte-size check in `validateXmlInput` as a third layer.

**Threat D2: Rapid successive requests exhaust CPU**
- Attack: Script hammers the `/parse` endpoint with 1,000 concurrent requests.
- Likelihood: Low (localhost only, same process sends requests).
- **Mitigations:** None at the application layer currently (no rate limiter implemented).
- **Recommendation:** Add per-IP rate limiting if deploying on a shared server (express-rate-limit).

**Threat D3: XML nesting exhausts call stack during recursive parsing**
- Attack: Deeply nested XML (10,000 levels) triggers a stack overflow in the XML parser.
- **Mitigations:** Nesting depth heuristic (> 50) rejects the document before parsing begins.

---

### E — Elevation of Privilege

**Threat E1: Viewer-role user accesses analyst/admin operations**
- Attack: Authenticated viewer calls `POST /api/policy/generate` directly.
- **Mitigations:**
  - `createRbacMiddleware` checks `ROLE_RANK[userRole] >= ROLE_RANK[required]` for every route.
  - Route permission matrix is defined centrally in `rbac.ts` — not scattered across routes.
  - `AUTHZ_DENIED` audit event is logged on every violation.

**Threat E2: URL path traversal bypasses route permissions**
- Attack: Caller sends `GET /api/security/../security/audit` to bypass middleware.
- **Mitigations:** Express normalises paths before routing; double-dot traversal in URL paths is handled by the Node.js HTTP parser.

**Threat E3: RBAC disabled in production**
- Attack: Operator forgets to enable RBAC when deploying on a shared host.
- **Mitigations:** Security page clearly flags RBAC as disabled with a yellow warning indicator. `SERVER_START` audit event logs the RBAC state.

---

## Implemented Controls

| Control | File | Threat mitigated |
|---|---|---|
| Loopback binding | `server/src/app.ts` | S2, T3 |
| CORS restriction | `server/src/app.ts` | S1 (cross-origin CSRF) |
| Helmet security headers | `server/src/app.ts` | I2, misc. browser attacks |
| No-cache headers on /api | `server/src/app.ts` | I1 (proxy caching) |
| Body size guard (50 MB) | `error-handler.ts` | D1 |
| XML bomb detection | `xml-validator.ts` | T1 |
| XML element count limit | `xml-validator.ts` | T1, D1 |
| XML nesting depth limit | `xml-validator.ts` | D3 |
| Zod schema validation | All route handlers | T2, D1 |
| RBAC token authentication | `rbac.ts` | S1, E1 |
| Timing-safe token comparison | `rbac.ts` | S1 |
| Token hash storage (SHA-256) | `security-config.ts` | I3 |
| security.json mode 0o600 | `security-config.ts` | I1 |
| Append-only audit log (JSONL) | `audit-logger.ts` | R1, R2 |
| Audit: input SHA-256 hash only | `audit-logger.ts` | I1 |
| Audit: sanitized error messages | Route handlers | I2 |
| Audit: SERVER_START/STOP | `app.ts` | R1 |
| Production error message filter | `error-handler.ts` | I2 |

---

## Data Handling Policy

### What is collected

| Data | Stored where | How long |
|---|---|---|
| SHA-256 hash of input XML | Audit log (JSONL) | Until log rotation (5 × 10 MB files) |
| Event type, timestamp, role | Audit log (JSONL) | Until log rotation |
| Output summary (rule counts) | Audit log (JSONL) | Until log rotation |
| Request duration (ms) | Audit log (JSONL) | Until log rotation |
| Sanitized error message | Audit log (JSONL) | Until log rotation |
| RBAC token hashes | security.json | Until manually deleted |

### What is never collected

- Raw policy XML content
- Rule definitions, hash values, file paths from within a policy
- Certificate data from within a policy
- Event log content
- IP addresses beyond 127.0.0.1 (always loopback)
- User identity beyond the configured role label

### Transmission

**Nothing is transmitted.** The server has no outbound HTTP client calls. Dependency
packages are fetched at install time via npm from the public registry; after
`npm install` succeeds, the application operates fully offline.

### Retention

Audit logs rotate when the active file reaches 10 MB. Up to 5 rotated files
(`audit.1.jsonl` … `audit.5.jsonl`) are retained. Oldest files are overwritten.
Default maximum on-disk audit storage: ~55 MB.

To disable disk logging entirely (in-memory only), set `audit.enabled: false`
in `~/.appcontrol-studio/security.json`.

---

## Role-Based Access Control

RBAC is **optional** and defaults to disabled. When disabled, all requests are
treated as `admin` — appropriate for single-user workstations. Enable RBAC
for shared servers or CI/CD pipeline integration.

### Role hierarchy

```
admin ⊃ analyst ⊃ viewer

viewer  — read-only analysis operations
analyst — viewer + policy generation / rule proposal
admin   — analyst + audit log access + RBAC config changes
```

### Enabling RBAC

1. Generate a token for each user/service:

   ```bash
   node -e "const {createHash,randomBytes}=require('crypto');
   const tok = randomBytes(32).toString('hex');
   const hash = createHash('sha256').update(tok).digest('hex');
   console.log('TOKEN:', tok);
   console.log('HASH: ', hash);"
   ```

2. Store the **token hash** (not the token) in `~/.appcontrol-studio/security.json`:

   ```json
   {
     "rbac": {
       "enabled": true,
       "tokens": [
         {
           "tokenHash": "<64-char hex SHA-256>",
           "role": "analyst",
           "label": "ci-pipeline"
         }
       ]
     }
   }
   ```

3. Distribute the **raw token** to the client via a secrets manager
   (e.g., Azure Key Vault, HashiCorp Vault, or environment variable).
   Never commit raw tokens to source control.

4. Restart the server to apply changes.

5. Clients include the token in every request:
   ```
   Authorization: Bearer <raw-token>
   ```

### Token rotation

1. Generate a new token/hash pair (see step 1 above).
2. Add the new entry to `security.json` **before** removing the old one.
3. Distribute the new token to clients.
4. After all clients are updated, remove the old token hash from `security.json`.
5. Restart the server.

---

## Audit Logging

### Log location

`~/.appcontrol-studio/audit/audit.jsonl` (active file)
`~/.appcontrol-studio/audit/audit.1.jsonl` … `audit.5.jsonl` (rotated)

### Log format (one JSON object per line)

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-01-15T14:23:01.234Z",
  "eventType": "POLICY_LOADED",
  "role": "analyst",
  "inputHash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "inputSizeBytes": 142857,
  "outputSummary": "fileRules=47 signers=12 warnings=0",
  "durationMs": 38,
  "remoteAddr": "127.0.0.1",
  "succeeded": true
}
```

### Event types and their meaning

| Event type | Trigger | Analyst-relevant fields |
|---|---|---|
| `SERVER_START` | Server process started | `outputSummary` = port, RBAC/audit state |
| `SERVER_STOP` | SIGTERM / SIGINT received | — |
| `POLICY_LOADED` | `POST /api/policy/parse` | `inputHash`, `inputSizeBytes`, `outputSummary` |
| `POLICY_GENERATED` | `POST /api/policy/generate` | `outputSummary` (xml byte count, policyId prefix) |
| `POLICY_COMPARED` | `POST /api/policy/compare` | `inputHash` (hash of both XMLs), `outputSummary` |
| `POLICY_SEMANTIC_COMPARED` | `POST /api/policy/semantic-compare` | `outputSummary` (verdict, delta, rule counts) |
| `POLICY_EXPLAINED` | `POST /api/policy/explain` | `outputSummary` (mode, risk flag count) |
| `POLICY_BUILT_FROM_EVENTS` | `POST /api/policy/from-events` | `inputSizeBytes` (event count), `outputSummary` |
| `RULES_PROPOSED` | `POST /api/policy/propose-rules` | `inputSizeBytes` (event count), `outputSummary` |
| `HUNTING_INGESTED` | `POST /api/policy/ingest-advanced-hunting` | `inputHash`, `outputSummary` (schema, counts) |
| `AUTH_SUCCESS` | Valid Bearer token presented | `role`, `remoteAddr` |
| `AUTH_FAILED` | Missing or invalid token | `errorCode`, `errorMessage` |
| `AUTHZ_DENIED` | Valid token, insufficient role | `role`, `errorMessage` (required role) |
| `VALIDATION_REJECTED` | XML pre-check failed | `errorCode`, `inputSizeBytes` |
| `CONFIG_CHANGED` | `POST /api/security/config` | `role`, `outputSummary` |

---

## Secure Update Procedure

AppControl Studio has **no auto-update mechanism**. Updates are manual and
operator-controlled. Follow this procedure to update safely:

### Before pulling

```bash
# Review incoming commits
git fetch origin
git log --oneline HEAD..origin/main

# Verify commit signatures (if the repository uses signed commits)
git verify-commit origin/main
```

### Review the changes

- Read the CHANGELOG or release notes.
- Inspect `server/src/` changes for new external dependencies or outbound calls.
- Inspect `packages/shared/src/` for API surface changes.
- Pay particular attention to changes in:
  - `server/src/app.ts` — middleware stack
  - `server/src/middleware/` — security controls
  - `server/src/config/security-config.ts` — config schema
  - Any new `import ... from "https://..."` or `require(...)` with a URL

### Apply and verify

```bash
git pull origin main
npm audit                  # Check for newly disclosed vulnerabilities
npm run build              # Must succeed — do not deploy a failing build
npm audit --audit-level=high  # Fail if high/critical advisories exist
```

### After updating

- If `rbac.ts` or `audit-logger.ts` changed: rotate RBAC tokens as a precaution.
- If `security-config.ts` changed: review the migration notes; default config
  may have new fields with different defaults.
- Restart the server and verify `SERVER_START` appears in the audit log with
  expected RBAC and audit settings.

### Dependency vetting

Before each update, run:

```bash
npm ls --depth=0           # Review direct dependencies
npm audit                  # Check for known CVEs
```

The production dependency graph should have zero dependencies that make
outbound network calls at runtime. If a new dependency is added, verify
it does not include analytics, telemetry, or update-check code.

---

## Known Limitations & Residual Risks

| Limitation | Risk | Recommendation |
|---|---|---|
| No rate limiting | A local script could saturate CPU with parse requests | Add `express-rate-limit` if deploying on a shared server |
| No TLS on loopback | Irrelevant for loopback — no network transit | Unnecessary; do not add complexity here |
| Token distribution out-of-band | Tokens must be delivered securely to clients | Use a secrets manager; never commit raw tokens |
| Audit log is not tamper-evident | A privileged local user can delete or truncate log files | Use OS-level file integrity monitoring (e.g., AIDE, auditd) for critical deployments |
| Memory not zeroed after processing | Policy data remains in V8 heap until GC | Enable full-disk encryption; `aggressiveClearingEnabled` is reserved for future implementation |
| No session expiry | Bearer tokens do not expire automatically | Implement a rotation schedule; revoke tokens when personnel change |
| No CSP nonce | `'unsafe-inline'` allowed for styles | Acceptable for local-only; tighten if serving over a network |
| Single process | No process isolation between parse operations | Run under a user account with minimal file system permissions |

---

*Last updated: 2026-03 | AppControl Studio v1.0.0*
