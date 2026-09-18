/**
 * API client — all requests stay local (proxied to 127.0.0.1:3001)
 */

import type {
  ApiResponse,
  ParsePolicyResponse,
  GeneratePolicyResponse,
  ComparePoliciesResponse,
  MergePoliciesResponse,
  SemanticComparePoliciesResponse,
  EventImportResult,
  ExplainPolicyResponse,
  CreatePolicyFromEventsRequest,
  CreatePolicyFromEventsResponse,
  ProposeRulesResponse,
  HuntingIngestApiResponse,
  CertInfoResponse,
  ConvertAppLockerResponse,
  SecurityStatus,
  SecurityAuditResponse,
  SimulateBinaryResponse,
  BinaryMetadata,
  WdacPolicy,
  ParsedCiEvent,
  InspectedFile,
  InspectedCertificate,
  RuleLevel,
  FileRuleBundle,
  PolicyValidationResult,
  ParseDiagnostic,
  PolicyTemplateInfo,
  OptionPreset,
  CreateFromTemplateRequest,
  CreateFromTemplateResponse,
  SigningScenarioValue,
} from "@appcontrol/shared";
import { getAccessToken } from "./msal-config.ts";

const BASE = "/api";

function authHeaders(): Record<string, string> {
  const token = getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify(body),
  });
  const json = (await res.json()) as ApiResponse<T>;
  if (!json.ok) {
    throw new Error(json.error.message ?? "Request failed");
  }
  return json.data;
}

async function postForm<T>(path: string, form: FormData): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { method: "POST", headers: authHeaders(), body: form });
  const json = (await res.json()) as ApiResponse<T>;
  if (!json.ok) throw new Error(json.error.message ?? "Request failed");
  return json.data;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() });
  const json = (await res.json()) as ApiResponse<T>;
  if (!json.ok) {
    throw new Error((json as { ok: false; error: { message: string } }).error.message);
  }
  return json.data;
}

// ---------------------------------------------------------------------------
// Policy API
// ---------------------------------------------------------------------------

export const policyApi = {
  parse: (xml: string, fileName?: string) =>
    post<ParsePolicyResponse>("/policy/parse", { xml, fileName }),

  generate: (policy: WdacPolicy) =>
    post<GeneratePolicyResponse>("/policy/generate", { policy }),

  compare: (leftXml: string, rightXml: string) =>
    post<ComparePoliciesResponse>("/policy/compare", { leftXml, rightXml }),

  semanticCompare: (leftXml: string, rightXml: string) =>
    post<SemanticComparePoliciesResponse>("/policy/semantic-compare", { leftXml, rightXml }),

  explain: (policy: WdacPolicy) =>
    post<ExplainPolicyResponse>("/policy/explain", { policy }),

  fromEvents: (params: CreatePolicyFromEventsRequest) =>
    post<CreatePolicyFromEventsResponse>("/policy/from-events", params),

  getOptions: () =>
    get<{ options: Array<{ value: number; name: string; description: string; critical: boolean }> }>(
      "/policy/options"
    ),

  proposeRules: (params: {
    events: ParsedCiEvent[];
    preferSignerRules: boolean;
    scopeSignerRules: boolean;
    includePathRules: boolean;
    includeDenyRules: boolean;
  }) => post<ProposeRulesResponse>("/policy/propose-rules", params),

  ingestAdvancedHunting: (params: {
    format: "json" | "csv" | "auto";
    content: string;
    preferPublisherRules?: boolean;
    scopePublisherRules?: boolean;
    includePathRules?: boolean;
    effect?: "Allow" | "Deny";
  }) => post<HuntingIngestApiResponse>("/policy/ingest-advanced-hunting", params),

  simulate: (binary: BinaryMetadata, policy: WdacPolicy) =>
    post<SimulateBinaryResponse>("/policy/simulate", { binary, policy }),

  /** Merge 2–15 policies into one (WDAC Wizard parity) */
  merge: (xmlFiles: string[], friendlyName?: string) =>
    post<MergePoliciesResponse>("/policy/merge", { xmlFiles, friendlyName }),

  /** Extract publisher metadata from a .cer/.crt/.pem certificate file */
  certInfo: (certBase64: string, fileName?: string) =>
    post<CertInfoResponse>("/policy/cert-info", { certBase64, fileName }),

  /** Convert an AppLocker XML policy to WDAC rules */
  convertAppLocker: (appLockerXml: string, includeDenyRules = false) =>
    post<ConvertAppLockerResponse>("/policy/convert-applocker", { appLockerXml, includeDenyRules }),

  /** Validate a policy model (or raw XML) — schema, references, content, optional ConvertFrom-CIPolicy */
  validate: (input: { policy?: WdacPolicy; xml?: string; useToolchain?: boolean }) =>
    post<PolicyValidationResult & { parseDiagnostics: ParseDiagnostic[] }>("/policy/validate", input),

  /** List base / supplemental / deny templates and option presets */
  templates: () =>
    get<{ templates: PolicyTemplateInfo[]; optionPresets: OptionPreset[] }>("/policy/templates"),

  /** Create a new policy from a template */
  fromTemplate: (req: CreateFromTemplateRequest) =>
    post<CreateFromTemplateResponse>("/policy/from-template", req),

  /** Pure policy tools (regenerate-ids, deduplicate, clear-rules, set-type, apply-preset, apply-rules) */
  tool: (
    tool: "regenerate-ids" | "deduplicate" | "clear-rules" | "set-type" | "apply-preset" | "apply-rules",
    body: {
      policy: WdacPolicy;
      policyType?: "Base" | "Supplemental";
      basePolicyId?: string;
      presetId?: string;
      bundles?: FileRuleBundle[];
      scenarioOverride?: SigningScenarioValue;
    }
  ) => post<{ policy: WdacPolicy; xml: string; summary: Record<string, number> }>(`/policy/tools/${tool}`, body),
};

// ---------------------------------------------------------------------------
// Files API — hashes, certificates, level-based rule generation
// ---------------------------------------------------------------------------

export const filesApi = {
  inspect: (files: File[]) => {
    const form = new FormData();
    for (const f of files) form.append("files", f, f.name);
    return postForm<{ files: InspectedFile[]; errors: Array<{ fileName: string; message: string }> }>("/files/inspect", form);
  },

  rules: (files: InspectedFile[], level: RuleLevel, opts: { effect?: "Allow" | "Deny"; fallbackToHash?: boolean; filePaths?: Record<string, string> } = {}) =>
    post<{ bundles: FileRuleBundle[] }>("/files/rules", { files, level, ...opts }),

  inspectCertificates: (files: File[]) => {
    const form = new FormData();
    for (const f of files) form.append("files", f, f.name);
    return postForm<{ certificates: Array<InspectedCertificate & { fileName: string }> }>("/files/cert-inspect", form);
  },
};

// ---------------------------------------------------------------------------
// Security API
// ---------------------------------------------------------------------------

export const securityApi = {
  status: () => get<SecurityStatus>("/security/status"),
  audit: (limit = 100) => get<SecurityAuditResponse>(`/security/audit?limit=${limit}`),
};

// ---------------------------------------------------------------------------
// Events API
// ---------------------------------------------------------------------------

export const eventsApi = {
  parse: (content: string, format: "json" | "csv" | "evtx-json") =>
    post<EventImportResult>("/events/parse", { content, format }),

  parseHunting: (content: string, format: "json" | "csv") =>
    post<EventImportResult>("/events/hunting/parse", { content, format }),

  parseEvtxBinary: async (file: File): Promise<EventImportResult> => {
    const formData = new FormData();
    formData.append("file", file);
    const token = getAccessToken();
    const res = await fetch(`${BASE}/events/parse-evtx`, {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: formData,
    });
    const json = (await res.json()) as ApiResponse<EventImportResult>;
    if (!json.ok) {
      throw new Error((json as { ok: false; error: { message: string } }).error.message);
    }
    return json.data;
  },
};
