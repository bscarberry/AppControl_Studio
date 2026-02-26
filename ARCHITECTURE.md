# AppControl Studio — System Architecture

## Overview

AppControl Studio is a local-only web application for managing the full lifecycle of
Windows Defender Application Control (WDAC / App Control for Business) policies.
All processing happens on the local machine; no data is transmitted externally.

---

## System Architecture Diagram (Text)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          AppControl Studio                              │
│                                                                         │
│  ┌──────────────────────────────────┐  ┌──────────────────────────────┐│
│  │        React Frontend            │  │      Node.js Backend         ││
│  │        (Vite + TypeScript)       │  │      (Express + TypeScript)  ││
│  │                                  │  │                              ││
│  │  Pages:                          │  │  Routes:                     ││
│  │  ┌─────────────────────────┐     │  │  POST /api/policy/parse      ││
│  │  │  Policy Editor          │─────┼──│  POST /api/policy/generate   ││
│  │  │  Compare Policies       │     │  │  POST /api/policy/compare    ││
│  │  │  Import Events          │─────┼──│  POST /api/policy/explain    ││
│  │  │  Build Policy           │     │  │  POST /api/policy/from-events││
│  │  │  Export                 │─────┼──│  POST /api/events/parse      ││
│  │  └─────────────────────────┘     │  │  POST /api/events/hunting/…  ││
│  │                                  │  │  GET  /api/policy/options    ││
│  │  State: Zustand                  │  │                              ││
│  │  API:   TanStack Query           │  │  Services:                   ││
│  │  Styles: Tailwind CSS            │  │  ┌──────────────────────┐   ││
│  │                                  │  │  │ XML Parser           │   ││
│  └──────────────────────────────────┘  │  │ XML Generator        │   ││
│                │ HTTP (localhost)       │  │ Policy Comparator    │   ││
│                ▼                       │  │ Policy Explainer      │   ││
│        Vite dev proxy                  │  │ Event Parser         │   ││
│        :5173 → :3001                   │  │ Policy Builder       │   ││
│                                        │  └──────────────────────┘   ││
│                                        └──────────────────────────────┘│
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    @appcontrol/shared                            │  │
│  │  WdacPolicy model, FileRule, Signer, SigningScenario,            │  │
│  │  ParsedCiEvent, API request/response types                       │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘

Data Inputs:
  ┌───────────────┐  ┌────────────────────┐  ┌──────────────────────────┐
  │ WDAC Policy   │  │ CodeIntegrity EVTX │  │ MDE Advanced Hunting     │
  │ XML files     │  │ (exported as JSON) │  │ Results (JSON / CSV)     │
  └───────────────┘  └────────────────────┘  └──────────────────────────┘
         │                    │                         │
         └────────────────────┴─────────────────────────┘
                              │
                              ▼
                     [AppControl Studio]
                              │
                              ▼
                   ┌──────────────────────┐
                   │  Deployable Policy   │
                   │  XML (.xml / .p7b)   │
                   └──────────────────────┘
```

---

## Data Model Definitions

All types are defined in `packages/shared/src/` and shared between frontend and backend.

### WdacPolicy (top-level)

```typescript
interface WdacPolicy {
  policyId: string;           // Normalized GUID (no curly braces)
  basePolicyId?: string;      // For supplemental policies
  policyTypeId?: string;      // Policy type variant GUID
  friendlyName?: string;
  versionEx: string;          // e.g., "10.0.0.0"
  platformId?: string;
  policyType: "Base" | "Supplemental";
  options: PolicyRuleOption[];
  ekus: WdacEku[];
  fileRules: WdacFileRule[];
  signers: WdacSignerRule[];
  signingScenarios: WdacSigningScenario[];
  updatePolicySigners: string[];  // Signer IDs
  ciSigners: string[];            // Signer IDs
  hvciOptions?: number;
  sourceFileName?: string;
}
```

### WdacFileRule

```typescript
interface WdacFileRule {
  id: string;
  type: "Allow" | "Deny" | "FileAttrib";
  friendlyName?: string;
  hash?: string;               // SHA256/SHA1 authenticode hash
  hashType?: "SHA256" | "SHA1" | "SHA256Flat" | "SHA1Page";
  fileName?: string;           // Original file name from version info
  internalName?: string;
  fileDescription?: string;
  productName?: string;
  minimumFileVersion?: string;
  maximumFileVersion?: string;
  filePath?: string;           // Path-based rule
  packageFamilyName?: string;  // UWP app
  packageVersion?: string;
  isFileAttrib?: boolean;
}
```

### WdacSignerRule

```typescript
interface WdacSignerRule {
  id: string;
  name: string;
  certRoot?: { type: "TBS" | "Wellknown"; value: string };
  certEKU?: Array<{ ekuId: string }>;
  certIssuer?: string;
  certPublisher?: string;
  certOemID?: string;
  fileAttribRefs?: string[];  // IDs of FileAttrib rules
}
```

### WdacSigningScenario

```typescript
interface WdacSigningScenario {
  value: 131 | 12;             // 131=Kernel, 12=User Mode
  id: string;
  minHashVersion?: string;
  allowedSigners: Array<{
    signerId: string;
    exceptDenyRuleIds?: string[];
  }>;
  deniedSigners: Array<{
    signerId: string;
    exceptAllowRuleIds?: string[];
  }>;
  fileRuleRefs: string[];      // Direct file rule references
}
```

---

## API Structure

### Policy Endpoints (prefix: `/api/policy`)

| Method | Path           | Input                            | Output                        |
|--------|----------------|----------------------------------|-------------------------------|
| POST   | `/parse`       | `{ xml, fileName? }`             | `{ policy, warnings }`        |
| POST   | `/generate`    | `{ policy }`                     | `{ xml, xmlSizeBytes }`       |
| POST   | `/compare`     | `{ leftXml, rightXml }`          | `{ comparison }`              |
| POST   | `/explain`     | `{ policy }`                     | `{ summary, riskFlags, ... }` |
| POST   | `/from-events` | `{ events, policyName, ... }`    | `{ policy, xml, buildLog }`   |
| GET    | `/options`     | —                                | `{ options[] }`               |

### Event Endpoints (prefix: `/api/events`)

| Method | Path             | Input                      | Output                      |
|--------|------------------|----------------------------|-----------------------------|
| POST   | `/parse`         | `{ content, format }`      | `{ events, summary, ... }`  |
| POST   | `/hunting/parse` | `{ content, format }`      | `{ events, summary, ... }`  |

---

## Folder Structure

```
AppControl_Studio/
├── package.json               # npm workspaces root
├── ARCHITECTURE.md
│
├── packages/
│   └── shared/                # Shared TypeScript types
│       ├── src/
│       │   ├── policy.ts      # WdacPolicy model, rule types
│       │   ├── events.ts      # ParsedCiEvent, AdvancedHuntingRow
│       │   ├── api.ts         # API request/response types
│       │   └── index.ts
│       └── package.json
│
├── server/                    # Node.js + Express backend
│   ├── src/
│   │   ├── app.ts             # Express app entry point
│   │   ├── routes/
│   │   │   ├── policy.ts      # Policy CRUD and transformation routes
│   │   │   └── events.ts      # Event log and hunting result routes
│   │   ├── services/
│   │   │   ├── xml-parser.ts      # WDAC XML -> WdacPolicy model
│   │   │   ├── xml-generator.ts   # WdacPolicy model -> WDAC XML
│   │   │   ├── policy-comparator.ts # Structural diff of two policies
│   │   │   ├── policy-explainer.ts  # Human-readable policy analysis
│   │   │   ├── policy-builder.ts    # Create policy from events
│   │   │   └── event-parser.ts      # CI events + hunting results
│   │   ├── middleware/
│   │   │   └── error-handler.ts
│   │   └── __tests__/
│   │       ├── xml-parser.test.ts
│   │       ├── xml-roundtrip.test.ts
│   │       └── comparator.test.ts
│   ├── package.json
│   ├── tsconfig.json
│   └── jest.config.js
│
├── client/                    # React + TypeScript frontend
│   ├── public/
│   │   └── shield.svg
│   ├── src/
│   │   ├── main.tsx           # React entrypoint
│   │   ├── App.tsx            # Router setup
│   │   ├── index.css          # Tailwind base + component classes
│   │   ├── lib/
│   │   │   └── api.ts         # Typed fetch wrappers
│   │   ├── store/
│   │   │   └── index.ts       # Zustand global state
│   │   ├── pages/
│   │   │   ├── PolicyEditorPage.tsx
│   │   │   ├── ComparePage.tsx
│   │   │   ├── ImportEventsPage.tsx
│   │   │   ├── BuildPolicyPage.tsx
│   │   │   └── ExportPage.tsx
│   │   └── components/
│   │       ├── layout/
│   │       │   ├── Sidebar.tsx
│   │       │   └── Header.tsx
│   │       ├── policy/
│   │       │   ├── PolicyOverview.tsx
│   │       │   ├── FileRulesTable.tsx
│   │       │   ├── SignersTable.tsx
│   │       │   └── PolicyOptionsEditor.tsx
│   │       └── common/
│   │           ├── FileDropZone.tsx
│   │           ├── EmptyState.tsx
│   │           └── LoadingSpinner.tsx
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   └── tailwind.config.js
│
└── fixtures/                  # Test data
    ├── sample-policy.xml
    ├── sample-events.json
    └── sample-hunting-results.csv
```

---

## Implementation Roadmap

### Phase 1 — Core (Complete)
- [x] Monorepo setup (npm workspaces, shared types)
- [x] WDAC XML parser (SiPolicy XML → WdacPolicy model)
- [x] WDAC XML generator (WdacPolicy model → deployable XML)
- [x] Policy comparator (structural diff, not textual)
- [x] Policy explainer (human-readable analysis + risk flags)
- [x] Event log parser (EVTX JSON, Advanced Hunting JSON/CSV)
- [x] Policy builder (create policy from event observations)
- [x] React frontend with all 5 pages
- [x] Express API server with security middleware

### Phase 2 — Enhanced Editing
- [ ] Add Rule wizard (guided UI to create publisher/hash/path rules)
- [ ] Signer editor (modify cert attributes inline)
- [ ] Policy merge (combine supplemental into base)
- [ ] Diff export (generate a "delta" supplemental policy from diff results)
- [ ] Rule deduplication detection

### Phase 3 — Advanced Features
- [ ] Multiple policy session management (tabbed interface)
- [ ] Policy simulation / "would this file be blocked?" query
- [ ] Policy history (revision tracking with localStorage)
- [ ] WDAC policy catalog / template library
- [ ] Binary policy validation (detect if XML can convert to binary)
- [ ] ConvertFrom-CIPolicy integration (invoke PowerShell if on Windows)
- [ ] Bulk event import with deduplication across multiple files
- [ ] Report generation (PDF/HTML policy audit reports)

### Phase 4 — Enterprise
- [ ] Multi-device event aggregation (merge hunting results from fleet)
- [ ] Policy coverage analysis (what % of observed binaries are covered)
- [ ] Supplemental policy scoping wizard
- [ ] HVCI compatibility checking
- [ ] CiTool integration for direct deployment testing

---

## Security Design

- **No external network calls** — all processing is local (127.0.0.1)
- **Content-Security-Policy** via Helmet prevents XSS
- **CORS** restricted to localhost dev port
- **50MB payload limit** protects against DoS via large uploads
- **Input validation** via Zod schemas on all API endpoints
- **XML is never eval'd** — parsed with fast-xml-parser (no DOM injection)
- **No file system access** — files are read via browser File API, content sent as strings

## Authoritative Sources

All WDAC behavior is modeled from official Microsoft documentation:
- [App Control for Business Overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/)
- [Policy Rule Options](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/policy-rules)
- [Event ID Reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)
- [SiPolicy XML Schema](C:\Windows\schemas\CodeIntegrity\cipolicy.xsd)
