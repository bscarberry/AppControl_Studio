/**
 * API client — all requests stay local (proxied to 127.0.0.1:3001)
 */

import type {
  ApiResponse,
  ParsePolicyResponse,
  GeneratePolicyResponse,
  ComparePoliciesResponse,
  SemanticComparePoliciesResponse,
  EventImportResult,
  ExplainPolicyResponse,
  CreatePolicyFromEventsResponse,
  ProposeRulesResponse,
  HuntingIngestApiResponse,
  SecurityStatus,
  SecurityAuditResponse,
  SimulateBinaryResponse,
  BinaryMetadata,
  WdacPolicy,
  ParsedCiEvent,
} from "@appcontrol/shared";
import { getAccessToken } from "./msal-config.ts";

const BASE = "/api";

async function authHeaders(): Promise<Record<string, string>> {
  const token = await getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await authHeaders()) },
    body: JSON.stringify(body),
  });
  const json = (await res.json()) as ApiResponse<T>;
  if (!json.ok) {
    throw new Error(json.error.message ?? "Request failed");
  }
  return json.data;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: await authHeaders() });
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

  fromEvents: (params: {
    events: ParsedCiEvent[];
    policyName: string;
    template?: "default-windows" | "allow-microsoft" | "deny-by-default" | "blank";
    preferPublisherRules: boolean;
    includePathRules: boolean;
    auditMode: boolean;
  }) => post<CreatePolicyFromEventsResponse>("/policy/from-events", params),

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
};
