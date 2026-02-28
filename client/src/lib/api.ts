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
  WdacPolicy,
  ParsedCiEvent,
} from "@appcontrol/shared";

const BASE = "/api";

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const json = (await res.json()) as ApiResponse<T>;
  if (!json.ok) {
    throw new Error(json.error.message ?? "Request failed");
  }
  return json.data;
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
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
