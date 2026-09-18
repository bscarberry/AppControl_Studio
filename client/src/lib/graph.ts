/**
 * Microsoft Graph client — Intune + Defender XDR Advanced Hunting.
 *
 * Runs entirely in the browser with the signed-in user's delegated token
 * (incremental consent on top of the existing MSAL sign-in). The AppControl
 * Studio server never receives a Graph token; hunting results are posted to
 * the local /api/events/hunting/parse endpoint only after the user chooses to
 * import them.
 *
 * Required delegated permissions on the app registration:
 *   DeviceManagementConfiguration.Read.All   — App Control policies + assignments
 *   DeviceManagementManagedDevices.Read.All  — device search
 *   Directory.Read.All                       — group names, device/user group membership
 *   ThreatHunting.Read.All                   — Advanced Hunting
 */

import { InteractionRequiredAuthError, BrowserAuthError } from "@azure/msal-browser";
import { msalInstance, isMsalEnabled } from "./msal-config.ts";
import type {
  IntuneAppControlPolicy,
  IntuneDevice,
  HuntingResultSet,
  HuntingTimespan,
  IntuneAssignment,
} from "@appcontrol/shared";
import {
  GRAPH_SCOPES,
  normalizeSettingsCatalogPolicy,
  normalizeOmaUriPolicy,
  isAppControlOmaProfile,
  normalizeManagedDevice,
} from "@appcontrol/shared";

const GRAPH = "https://graph.microsoft.com";

export class GraphError extends Error {
  constructor(message: string, public status: number, public code?: string) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

export const isGraphAvailable = isMsalEnabled;

async function token(scopes: readonly string[]): Promise<string> {
  if (!msalInstance) throw new GraphError("Sign-in is not configured (VITE_MSAL_CLIENT_ID / VITE_MSAL_TENANT_ID).", 0, "MSAL_DISABLED");
  const account = msalInstance.getAllAccounts()[0];
  if (!account) throw new GraphError("Not signed in.", 401, "NO_ACCOUNT");
  const request = { scopes: [...scopes], account };
  try {
    return (await msalInstance.acquireTokenSilent(request)).accessToken;
  } catch (e) {
    if (e instanceof InteractionRequiredAuthError || (e instanceof BrowserAuthError && e.errorCode === "monitor_window_timeout")) {
      // Incremental consent: a popup keeps the in-memory session; fall back to redirect if popups are blocked.
      try {
        return (await msalInstance.acquireTokenPopup(request)).accessToken;
      } catch (pe) {
        if (pe instanceof BrowserAuthError && (pe.errorCode === "popup_window_error" || pe.errorCode === "empty_window_error")) {
          await msalInstance.acquireTokenRedirect(request);
        }
        throw pe;
      }
    }
    throw e;
  }
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

async function call<T>(scopes: readonly string[], method: "GET" | "POST", url: string, body?: unknown): Promise<T> {
  const t = await token(scopes);
  const res = await fetch(url.startsWith("http") ? url : `${GRAPH}${url}`, {
    method,
    headers: {
      Authorization: `Bearer ${t}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
      ConsistencyLevel: "eventual",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  const json = (await res.json().catch(() => ({}))) as { error?: { code?: string; message?: string } } & T;
  if (!res.ok) {
    const code = json.error?.code;
    const msg = json.error?.message ?? res.statusText;
    if (res.status === 403) {
      throw new GraphError(`Graph denied the request (${code ?? 403}). Make sure the app registration grants the delegated permission and admin consent was given: ${msg}`, 403, code);
    }
    throw new GraphError(`${msg}`, res.status, code);
  }
  return json;
}

/** GET with @odata.nextLink paging. */
async function getAll<T>(scopes: readonly string[], url: string, max = 2000): Promise<T[]> {
  const out: T[] = [];
  let next: string | undefined = url;
  while (next && out.length < max) {
    const page: { value: T[]; "@odata.nextLink"?: string } = await call(scopes, "GET", next);
    out.push(...(page.value ?? []));
    next = page["@odata.nextLink"];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Intune — App Control policies
// ---------------------------------------------------------------------------

export interface PolicyListResult {
  policies: IntuneAppControlPolicy[];
  warnings: string[];
}

export async function listAppControlPolicies(): Promise<PolicyListResult> {
  const warnings: string[] = [];
  const policies: IntuneAppControlPolicy[] = [];

  // Settings Catalog / Endpoint security "App Control for Business" template family
  try {
    const raw = await getAll<Record<string, unknown>>(
      GRAPH_SCOPES.intune,
      `/beta/deviceManagement/configurationPolicies?$filter=templateReference/templateFamily eq 'endpointSecurityApplicationControl'&$expand=assignments,settings`
    );
    for (const p of raw) policies.push(normalizeSettingsCatalogPolicy(p));
  } catch (e) {
    warnings.push(`Settings catalog policies: ${(e as Error).message}`);
  }

  // Settings-catalog policies that carry ApplicationControl CSP settings without the template
  try {
    const raw = await getAll<Record<string, unknown>>(
      GRAPH_SCOPES.intune,
      `/beta/deviceManagement/configurationPolicies?$filter=technologies has 'mdm' and platforms has 'windows10'&$expand=assignments,settings&$top=100`,
      1000
    );
    const seen = new Set(policies.map((p) => p.id));
    for (const p of raw) {
      if (seen.has(String(p.id))) continue;
      const n = normalizeSettingsCatalogPolicy(p);
      if (n.settings.some((s) => /applicationcontrol/i.test(s.definitionId))) policies.push(n);
    }
  } catch (e) {
    warnings.push(`Settings catalog scan: ${(e as Error).message}`);
  }

  // Legacy custom OMA-URI profiles (./Vendor/MSFT/ApplicationControl/Policies/{GUID}/Policy)
  try {
    const raw = await getAll<Record<string, unknown>>(
      GRAPH_SCOPES.intune,
      `/beta/deviceManagement/deviceConfigurations?$expand=assignments&$top=100`,
      1000
    );
    for (const p of raw) if (isAppControlOmaProfile(p)) policies.push(normalizeOmaUriPolicy(p));
  } catch (e) {
    warnings.push(`Custom OMA-URI profiles: ${(e as Error).message}`);
  }

  await resolveAssignmentNames(policies.flatMap((p) => p.assignments), warnings);
  return { policies, warnings };
}

/** Fill in group and filter display names across all assignments. */
async function resolveAssignmentNames(assignments: IntuneAssignment[], warnings: string[]): Promise<void> {
  const groupIds = [...new Set(assignments.map((a) => a.groupId).filter((x): x is string => !!x))];
  const filterIds = [...new Set(assignments.map((a) => a.filterId).filter((x): x is string => !!x))];
  const groupNames = new Map<string, string>();
  for (let i = 0; i < groupIds.length; i += 1000) {
    try {
      const r = await call<{ value: Array<{ id: string; displayName?: string }> }>(
        GRAPH_SCOPES.intune, "POST", "/v1.0/directoryObjects/getByIds",
        { ids: groupIds.slice(i, i + 1000), types: ["group"] }
      );
      for (const g of r.value) groupNames.set(g.id, g.displayName ?? g.id);
    } catch (e) {
      warnings.push(`Group names: ${(e as Error).message}`);
    }
  }
  const filterNames = new Map<string, string>();
  if (filterIds.length) {
    try {
      const filters = await getAll<{ id: string; displayName?: string }>(GRAPH_SCOPES.intune, "/beta/deviceManagement/assignmentFilters?$select=id,displayName");
      for (const f of filters) filterNames.set(f.id, f.displayName ?? f.id);
    } catch (e) {
      warnings.push(`Assignment filters: ${(e as Error).message}`);
    }
  }
  for (const a of assignments) {
    if (a.groupId) a.groupName = groupNames.get(a.groupId) ?? a.groupName;
    if (a.filterId) a.filterName = filterNames.get(a.filterId) ?? a.filterName;
  }
}

// ---------------------------------------------------------------------------
// Intune — devices
// ---------------------------------------------------------------------------

export async function searchManagedDevices(query: string, top = 25): Promise<IntuneDevice[]> {
  const q = query.replace(/'/g, "''").trim();
  const select = "id,deviceName,azureADDeviceId,userPrincipalName,userId,operatingSystem,osVersion,complianceState,lastSyncDateTime,enrolledDateTime,managementAgent,model,manufacturer,serialNumber";
  const filter = `operatingSystem eq 'Windows' and (startswith(deviceName,'${q}') or startswith(userPrincipalName,'${q}') or startswith(serialNumber,'${q}'))`;
  const raw = await getAll<Record<string, unknown>>(
    GRAPH_SCOPES.intune,
    `/beta/deviceManagement/managedDevices?$filter=${encodeURIComponent(filter)}&$select=${select}&$top=${top}`,
    top
  );
  return raw.map(normalizeManagedDevice);
}

export interface DeviceGroupMembership {
  deviceObjectId?: string;
  deviceGroupIds: string[];
  userGroupIds: string[];
  hasPrimaryUser: boolean;
  warnings: string[];
}

/** Resolve transitive group membership for the device object and its primary user. */
export async function getDeviceMembership(device: IntuneDevice): Promise<DeviceGroupMembership> {
  const warnings: string[] = [];
  let deviceObjectId: string | undefined;
  let deviceGroupIds: string[] = [];
  let userGroupIds: string[] = [];

  if (device.azureADDeviceId) {
    try {
      const r = await call<{ value: Array<{ id: string }> }>(
        GRAPH_SCOPES.intune, "GET",
        `/v1.0/devices?$filter=deviceId eq '${device.azureADDeviceId}'&$select=id`
      );
      deviceObjectId = r.value[0]?.id;
      if (deviceObjectId) {
        const g = await call<{ value: string[] }>(GRAPH_SCOPES.intune, "POST", `/v1.0/devices/${deviceObjectId}/getMemberGroups`, { securityEnabledOnly: false });
        deviceGroupIds = g.value ?? [];
      } else {
        warnings.push("Entra device object not found for this Intune device (stale enrollment?).");
      }
    } catch (e) {
      warnings.push(`Device group membership: ${(e as Error).message}`);
    }
  } else {
    warnings.push("Intune device has no Entra device ID; group-based device assignments cannot be evaluated.");
  }

  if (device.userId) {
    try {
      const g = await call<{ value: string[] }>(GRAPH_SCOPES.intune, "POST", `/v1.0/users/${device.userId}/getMemberGroups`, { securityEnabledOnly: false });
      userGroupIds = g.value ?? [];
    } catch (e) {
      warnings.push(`User group membership: ${(e as Error).message}`);
    }
  }

  return { deviceObjectId, deviceGroupIds, userGroupIds, hasPrimaryUser: !!device.userId, warnings };
}

// ---------------------------------------------------------------------------
// Defender XDR — Advanced Hunting
// ---------------------------------------------------------------------------

export async function runHuntingQuery(query: string, timespan: HuntingTimespan = "P30D"): Promise<HuntingResultSet> {
  const r = await call<{ schema: Array<{ name: string; type: string }>; results: Array<Record<string, unknown>> }>(
    GRAPH_SCOPES.hunting, "POST", "/v1.0/security/runHuntingQuery",
    { Query: query, Timespan: timespan }
  );
  return { schema: r.schema ?? [], results: r.results ?? [] };
}
