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

## Features

### Policy Editor
Load a WDAC policy XML file and inspect every component through tabbed views:

- **Overview** — policy identity, mode (audit/enforcement), rule counts, and an automated security risk assessment that flags dangerous option combinations
- **Options** — toggle any of the 23 documented policy rule options (0–22) with descriptions of each
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
│   └── src/
│       ├── app.ts             # Express server (port 3001)
│       ├── routes/            # API route handlers
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
│   └── src/
│       ├── pages/             # 5 main pages
│       ├── components/        # Reusable UI components
│       ├── lib/api.ts         # Typed API client
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
| `GET`  | `/api/policy/options` | List all 23 policy rule options with descriptions |

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
| Backend | Node.js, Express, TypeScript |
| XML parsing | fast-xml-parser |
| Validation | Zod |
| Icons | Lucide React |

---

## Security Design

- **Local only** — server binds to `127.0.0.1`, no external network calls
- **CSP headers** via Helmet
- **CORS** restricted to the dev server origin
- **50 MB payload limit** to prevent DoS
- **Zod validation** on all API inputs
- **No eval** — XML parsed safely with fast-xml-parser
- **No filesystem writes** — files are read via the browser File API

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
