# AppControl Studio

A local-only web application for managing the full lifecycle of **Windows Defender Application Control (WDAC)** policies. Built for enterprise security engineers who manage App Control for Business in Windows environments.

All processing happens on your machine — no data is transmitted externally.

---

## Quick Start

```bash
# Install dependencies
npm install

# Start both frontend and backend in development mode
npm run dev
```

- **Frontend:** http://localhost:5173
- **Backend API:** http://localhost:3001

## Production Build

```bash
npm run build
```

---

## Authentication (MSAL / Azure AD)

Authentication is **opt-in**. By default the app runs in local workstation mode with no sign-in required. To enforce Azure AD authentication, configure the environment variables below.

### Prerequisites

Create an Azure AD App Registration with the following settings:

| Setting | Value |
|---------|-------|
| **Supported account types** | Accounts in this organizational directory only (single tenant) |
| **Platform** | Single-page application (SPA) |
| **Redirect URI** | `http://localhost:5173` (dev) or your production URL |
| **API Permissions** | None for sign-in alone. For the **Intune & XDR** section add the delegated Microsoft Graph permissions below and grant admin consent. |

#### Graph permissions for Intune & XDR (delegated, admin consent)

| Permission | Used for |
|-----------|----------|
| `DeviceManagementConfiguration.Read.All` | App Control for Business policies, settings, assignments, assignment filters |
| `DeviceManagementManagedDevices.Read.All` | Device search (name, user, serial) |
| `Directory.Read.All` | Group display names; transitive group membership of the device and its primary user |
| `ThreatHunting.Read.All` | Defender XDR Advanced Hunting (`security/runHuntingQuery`) |

Graph is called **directly from the browser** with the signed-in user's token (incremental consent via a popup on first use). The AppControl Studio server never receives or proxies Graph tokens. Hunting results only reach the local server when you click *Import into Studio*.

> "Expose an API" does **not** need to be configured. The app authenticates with standard OIDC scopes (`openid profile`) and passes the ID token to the backend for validation.
>
> You can find the **Application (client) ID** and **Directory (tenant) ID** on the Overview page of your app registration in the Azure portal.

### Client configuration

Copy `client/.env.example` to `client/.env` (or `client/.env.local`) and fill in:

```env
VITE_MSAL_CLIENT_ID=00000000-0000-0000-0000-000000000000   # Application (client) ID
VITE_MSAL_TENANT_ID=00000000-0000-0000-0000-000000000000   # Directory (tenant) ID
VITE_MSAL_REDIRECT_URI=http://localhost:5173                # Must match a registered Redirect URI
```

No API scope configuration is needed.

### Server configuration

Copy `server/.env.example` to `server/.env` and fill in:

```env
MSAL_CLIENT_ID=00000000-0000-0000-0000-000000000000   # Same Application (client) ID
MSAL_TENANT_ID=00000000-0000-0000-0000-000000000000   # Same Directory (tenant) ID
```

The server uses these to validate Azure AD JWTs — it fetches Microsoft's public signing keys from:
`https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`

No client secret is needed; the SPA uses the public PKCE flow.

### How it works

1. On first visit, unauthenticated users see a **Sign in with Microsoft** page
2. Clicking the button navigates the current tab to Microsoft's login page (redirect flow — no popups)
3. After successful login, Microsoft redirects back to `VITE_MSAL_REDIRECT_URI`; MSAL exchanges the auth code and stores the session in `sessionStorage`
4. Every API call automatically attaches `Authorization: Bearer <id-token>`
5. The server validates the JWT signature, issuer, audience, and expiry before processing any request
6. The signed-in username is displayed in the sidebar footer with a sign-out button

### Local workstation mode (no authentication)

Leave `VITE_MSAL_CLIENT_ID` and `MSAL_CLIENT_ID` unset (or empty) to disable authentication entirely. All API requests are treated as `admin` role — appropriate for a single-user local machine where network access is already restricted to `127.0.0.1`.

---

## Features

### Create Policy
Start a new policy from the Microsoft templates that ship with Windows (`C:\Windows\schemas\CodeIntegrity\ExamplePolicies`, bundled under `server/templates`) — the same baselines AppControl Manager and the WDAC Wizard use:

| Template | Category | Notes |
|----------|----------|-------|
| Allow Microsoft | base | Everything Microsoft-signed |
| Default Windows | base | Only files that ship with Windows |
| Signed and Reputable | base | Allow Microsoft + Intelligent Security Graph (options 14, 15) |
| Strict Kernel-Mode | base | Kernel enforcement only, UMCI off |
| Allow All / Deny All (Audit) | base | Telemetry and deny-policy scaffolds |
| Deny Policy (scaffold) | deny | Two allow-all rules plus your deny rules (AppControl Manager style) |
| Microsoft Recommended Driver Block Rules | block | Vulnerable-driver blocklist |
| Blank Supplemental / Blank Base | supplemental / base | Empty starting points |

Switches map to the documented options: Audit mode (3), Require EV signers (8), Script enforcement (11), Test mode (9 + 10), Allow supplemental (17), HVCI. Every template gets a fresh PolicyID.

### File Inspector
Drop executables, DLLs, drivers, scripts or MSI files (processed in memory, never written to disk) to get:

- **Code Integrity hashes** — Authenticode SHA-1/SHA-256, header page hashes, and flat hashes, computed with the same algorithm as `New-CIPolicyRule -Level Hash` (verified byte-for-byte against ConfigCI output)
- **Certificates** — the embedded Authenticode chain with per-certificate TBS hashes (hashed with the certificate's own signature digest, exactly as ConfigCI does), EKUs, well-known Microsoft root detection, timestamp and digest-match checks
- **Version resource** — OriginalFilename, InternalName, ProductName, fixed file version
- **Rule generation at any level** — Hash, FileName, FilePath, SignedVersion, Publisher, FilePublisher, LeafCertificate, PcaCertificate, RootCertificate, WHQL, WHQLPublisher, WHQLFilePublisher — with automatic fallback, Allow or Deny, added straight into the active policy
- **Simulate this file** — hands the extracted metadata (hashes, chain TBS, EKUs, well-known root) to the Simulator

### Validate
AppControl Manager "Validate Policies" parity in four phases: cipolicy.xsd structural rules (ID patterns, GUID/hex/version formats), reference integrity (dangling refs, duplicate IDs, orphans), content checks (unsigned policy without option 6, supplemental option restrictions, kernel path rules, unsupported macros), and — on Windows hosts with the ConfigCI module — real `cipolicy.xsd` validation plus `ConvertFrom-CIPolicy` binary conversion with the resulting binary size.

### Policy Editor
Load a WDAC policy XML file and inspect every component through tabbed views:

- **Overview** — policy identity, mode (audit/enforcement), rule counts, and an automated security risk assessment that flags dangerous option combinations
- **Details** — edit name, PolicyInfo Id, version, PolicyID / BasePolicyID, policy type (Base ⇄ Supplemental with option filtering), HVCI level, single ⇄ multiple policy format, and preserved `<Settings>`
- **Tools** — regenerate IDs (schema-conformant, references remapped), deduplicate rules and signers, clear all rules, convert type
- **Option presets** — pre-configured rule option sets for base, supplemental, ISG, managed installer, strict and test-mode policies
- **Options** — toggle any of the 25 recognized policy rule options (including newer schema options like Conditional Windows Lockdown Policy) with descriptions of each
- **File Rules** — searchable, filterable table of Allow/Deny/FileAttrib rules with type indicators (hash, path, publisher, package)
- **Signers** — expandable signer list showing certificate root, publisher, issuer, EKU, and FileAttrib references
- **XML Preview** — generate deployable XML and download it

### Policy Comparison
Drop two policy XML files and get a structural diff. Comparison is logical (by rule identity and content), not textual, so formatting or ordering differences don't produce false positives.

Sections:
- Option changes (added/removed/changed)
- File rule changes with field-level detail
- Signer changes
- Signing scenario membership changes (kernel and user mode)

### Intune & XDR
Review what is actually assigned in the tenant and what is being blocked in the field:

- **Policies** — every App Control for Business policy in Intune, from both the settings-catalog *Endpoint security → App Control for Business* template and legacy custom OMA-URI (`./Vendor/MSFT/ApplicationControl/…`) profiles. Shows assignments with resolved group and filter names, the flattened settings, built-in-controls mode, and decodes embedded SiPolicy XML (plain, base64 UTF-8 or UTF-16) so it can be opened in the editor, validated, simulated or diffed. Binary `.cip` payloads are flagged.
- **Devices** — search Intune (or Defender `DeviceInfo`) for a device, then see: *effective App Control assignments* (All devices / All users / include and exclude groups resolved through transitive membership of the device object and its primary user, with assignment filters called out because Intune evaluates them at check-in), the policies the device has actually *loaded* (Defender `AppControlCodeIntegrityPolicyLoaded` telemetry), and its recent App Control blocks and audits (1/7/30 days, blocked-only toggle). One click imports those events into Import & Build / Rule Engine to produce supplemental rules. The landing view ranks devices by block and audit counts over the last 7 days.
- **Hunting** — KQL presets (events, blocked only, per-device summary, policies loaded, top blocked files) or a custom query against `security/runHuntingQuery`; any result set with `ActionType` + `FileName` columns can be imported.

### Simulator
Evaluates a binary against a policy in the documented order (deny file → deny signer → allow signer → allow file → default deny) with semantics validated against the Microsoft example policies: `FileName="*"` wildcards, CertRoot TBS matching against any certificate in the chain, CertEKU enforcement, exact Wellknown-root matching, PackageFamilyName rules, and path rules ignored in kernel mode.

### Import Events
Parse CodeIntegrity event data from three sources:

| Source | Format |
|--------|--------|
| `Get-WinEvent` export | JSON (EVTX-JSON) |
| MDE Advanced Hunting | JSON |
| MDE Advanced Hunting | CSV |

The import page includes copy-ready PowerShell commands and KQL queries for collecting the data.

### Build Policy from Events
Generate a WDAC policy from imported CodeIntegrity events:

- Choose a base template (Blank, Allow Microsoft, Default Windows, Deny by Default)
- Prefer publisher rules over hash rules when signer info is available
- Optionally include path-based rules
- Start in audit mode (recommended) or enforcement mode

### Export
Generate the final XML with a step-by-step deployment guide covering:
1. Binary conversion (`ConvertFrom-CIPolicy`)
2. Audit mode testing
3. Intune/MDM deployment (`CiTool`)
4. Verification commands
5. Switching to enforcement mode

Includes a pre-deployment security checklist.

---

## Project Structure

```
AppControl_Studio/
├── packages/shared/           # Shared TypeScript types
│   └── src/
│       ├── policy.ts          # WdacPolicy, FileRule, Signer models
│       ├── events.ts          # ParsedCiEvent, AdvancedHuntingRow
│       └── api.ts             # API request/response types
│
├── server/                    # Node.js + Express backend
│   ├── .env.example           # MSAL + server environment variable template
│   └── src/
│       ├── app.ts             # Express server (port 3001)
│       ├── routes/            # API route handlers
│       ├── middleware/
│       │   ├── msal-auth.ts   # Azure AD JWT validation (RS256 + JWKS)
│       │   ├── rbac.ts        # Role-based access control
│       │   └── error-handler.ts
│       ├── services/
│       │   ├── xml-parser.ts      # SiPolicy XML → WdacPolicy
│       │   ├── xml-generator.ts   # WdacPolicy → SiPolicy XML
│       │   ├── policy-comparator.ts
│       │   ├── policy-explainer.ts
│       │   ├── policy-builder.ts
│       │   └── event-parser.ts
│       └── __tests__/         # Jest tests
│
├── client/                    # React + TypeScript frontend
│   ├── .env.example           # MSAL environment variable template
│   └── src/
│       ├── pages/             # Main pages (editor, simulator, etc.)
│       ├── components/
│       │   ├── auth/          # AuthGuard — gates app behind MSAL
│       │   └── ...            # Reusable UI components
│       ├── lib/
│       │   ├── api.ts         # Typed API client (attaches Bearer token)
│       │   └── msal-config.ts # MSAL PublicClientApplication setup
│       └── store/             # Zustand global state
│
└── fixtures/                  # Sample data for testing
    ├── sample-policy.xml
    ├── sample-events.json
    └── sample-hunting-results.csv
```

---

## API Reference

All endpoints accept and return JSON. Every response is wrapped in `{ ok: true, data: ... }` or `{ ok: false, error: { code, message } }`.

### Policy

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/policy/parse` | Parse XML string into a WdacPolicy model |
| `POST` | `/api/policy/generate` | Generate deployable XML from a WdacPolicy model |
| `POST` | `/api/policy/compare` | Structural diff of two policy XML strings |
| `POST` | `/api/policy/explain` | Human-readable analysis and risk assessment |
| `POST` | `/api/policy/from-events` | Build a policy from parsed CodeIntegrity events |
| `GET`  | `/api/policy/options` | List all recognized policy rule options with descriptions |
| `GET`  | `/api/policy/templates` | List policy templates and option presets |
| `POST` | `/api/policy/from-template` | Create a policy from a template with the standard switches |
| `POST` | `/api/policy/validate` | Four-phase validation (schema, references, content, ConvertFrom-CIPolicy) |
| `POST` | `/api/policy/tools/:tool` | `regenerate-ids`, `deduplicate`, `clear-rules`, `set-type`, `apply-preset`, `apply-rules` |

### Files

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/files/inspect` | Multipart upload → hashes, signature chains, version info, simulation metadata |
| `POST` | `/api/files/rules` | Generate rule bundles for inspected files at a given rule level |
| `POST` | `/api/files/cert-inspect` | Parse .cer/.crt/.pem/.p7b certificate files |

### Events

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/events/parse` | Parse EVTX JSON or CSV event exports |
| `POST` | `/api/events/hunting/parse` | Parse MDE Advanced Hunting results (JSON/CSV) |

---

## Data Model

The core abstraction is `WdacPolicy`, which normalizes the SiPolicy XML schema into structured TypeScript objects:

- **PolicyRuleOption** — the 23 numbered options (Enabled:UMCI, Enabled:Audit Mode, etc.)
- **WdacFileRule** — Allow, Deny, and FileAttrib rules with hash/path/publisher/package attributes
- **WdacSignerRule** — certificate-based trust rules (TBS root, publisher, issuer, EKU, OEM ID)
- **WdacSigningScenario** — kernel mode (131) and user mode (12) with allowed/denied signer lists and file rule references
- **WdacEku** — Enhanced Key Usage OID definitions

See `packages/shared/src/policy.ts` for full type definitions.

---

## Collecting Event Data

### CodeIntegrity Event Log (PowerShell)

```powershell
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" `
  | Where-Object { $_.Id -in @(3076,3077,3033,3034,3089,3097,3098) } `
  | ConvertTo-Json -Depth 5 `
  | Out-File -FilePath ".\ci-events.json" -Encoding utf8
```

### MDE Advanced Hunting (KQL)

```kusto
DeviceEvents
| where ActionType in (
    "AppControlCodeIntegrityPolicyAudited",
    "AppControlCodeIntegrityPolicyBlocked",
    "AppControlCIScriptAudited",
    "AppControlCIScriptBlocked")
| extend Fields = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    SHA256, SHA1, InitiatingProcessFileName,
    PolicyName = tostring(Fields.PolicyName),
    ProductName = tostring(Fields.ProductName),
    OriginalFileName = tostring(Fields.OriginalFileName)
| order by Timestamp desc
```

Export as JSON or CSV from the Microsoft Defender portal.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite |
| Styling | Tailwind CSS (dark theme) |
| State | Zustand |
| API calls | TanStack Query |
| Routing | React Router v6 |
| Authentication | MSAL (`@azure/msal-browser`, `@azure/msal-react`) |
| Backend | Node.js, Express, TypeScript |
| JWT validation | `jwks-rsa`, `jsonwebtoken` |
| XML parsing | fast-xml-parser |
| Validation | Zod |
| Icons | Lucide React |

---

## Security Design

- **Local only** — server binds to `127.0.0.1`, no external network calls during policy processing
- **MSAL authentication** — optional Azure AD sign-in; access tokens validated server-side via Microsoft's JWKS endpoint (RS256, audience + issuer checked)
- **CSP headers** via Helmet; Microsoft login endpoints added to `connectSrc`/`frameSrc` only when MSAL is active
- **CORS** restricted to the configured client origin
- **50 MB payload limit** to prevent DoS
- **Zod validation** on all API inputs
- **No eval** — XML parsed safely with fast-xml-parser
- **No filesystem writes** — files are read via the browser File API
- **Append-only audit log** — all authentication events (success/failure) are recorded

---

## Authoritative Sources

All WDAC behavior is modeled from official Microsoft documentation:

- [App Control for Business overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/)
- [Policy rule options reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/policy-rules)
- [Event ID explanations](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)
- [Select types of rules to create](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create)

When ambiguity exists, the most conservative security interpretation is chosen.

---

## License

Private — internal use only.
