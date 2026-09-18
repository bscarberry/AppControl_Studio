/**
 * Cloud integration — Intune (Microsoft Graph) and Defender XDR Advanced Hunting.
 *
 * Only pure, side-effect-free logic lives here so it can be unit-tested and
 * shared between the browser (which talks to Graph directly with the user's
 * delegated token) and the server (which never sees Graph tokens):
 *
 *   - normalising Intune App Control policies from two Graph shapes
 *       • Settings Catalog  (deviceManagement/configurationPolicies,
 *         templateFamily endpointSecurityApplicationControl)
 *       • Custom OMA-URI     (deviceManagement/deviceConfigurations of type
 *         windows10CustomConfiguration with ./Vendor/MSFT/ApplicationControl URIs)
 *   - extracting the embedded SiPolicy XML from either shape
 *   - evaluating which assignments apply to a given device (effective assignment)
 *   - building the Advanced Hunting KQL for App Control events
 */

// ---------------------------------------------------------------------------
// Graph delegated permissions the Cloud section needs
// ---------------------------------------------------------------------------

export const GRAPH_SCOPES = {
  intune: [
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "Directory.Read.All",
  ],
  hunting: ["ThreatHunting.Read.All"],
} as const;

export const GRAPH_ALL_SCOPES: string[] = [...GRAPH_SCOPES.intune, ...GRAPH_SCOPES.hunting];

// ---------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------

export type AssignmentTargetKind =
  | "allDevices"
  | "allUsers"
  | "group"
  | "exclusionGroup"
  | "unknown";

export interface IntuneAssignment {
  id?: string;
  kind: AssignmentTargetKind;
  groupId?: string;
  /** Resolved later via Graph; may be absent */
  groupName?: string;
  filterId?: string;
  filterType?: "include" | "exclude" | "none";
  filterName?: string;
  /** Raw @odata.type for display / debugging */
  odataType?: string;
}

/** Normalise a Graph assignment object (either policy family) */
export function normalizeAssignment(raw: Record<string, unknown>): IntuneAssignment {
  const target = (raw.target ?? {}) as Record<string, unknown>;
  const t = String(target["@odata.type"] ?? "");
  const kind: AssignmentTargetKind = t.endsWith("allDevicesAssignmentTarget")
    ? "allDevices"
    : t.endsWith("allLicensedUsersAssignmentTarget")
      ? "allUsers"
      : t.endsWith("exclusionGroupAssignmentTarget")
        ? "exclusionGroup"
        : t.endsWith("groupAssignmentTarget")
          ? "group"
          : "unknown";
  const filterType = String(target.deviceAndAppManagementAssignmentFilterType ?? "none");
  return {
    id: raw.id ? String(raw.id) : undefined,
    kind,
    groupId: target.groupId ? String(target.groupId) : undefined,
    filterId: target.deviceAndAppManagementAssignmentFilterId ? String(target.deviceAndAppManagementAssignmentFilterId) : undefined,
    filterType: filterType === "include" || filterType === "exclude" ? filterType : "none",
    odataType: t,
  };
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

export type IntunePolicySource = "settingsCatalog" | "customOmaUri";

export interface IntuneSettingPair {
  definitionId: string;
  value: string;
}

export interface IntuneAppControlPolicy {
  id: string;
  name: string;
  description?: string;
  source: IntunePolicySource;
  platform?: string;
  technologies?: string;
  createdDateTime?: string;
  lastModifiedDateTime?: string;
  /** Number of settings (settings catalog) or OMA-URI entries */
  settingCount: number;
  /** Flattened settings for display */
  settings: IntuneSettingPair[];
  /** Decoded SiPolicy XML documents found in the policy (may be several for OMA-URI profiles) */
  xmlPolicies: Array<{ label: string; xml: string }>;
  /** OMA-URI entries whose payload is a binary CIP (not decodable client-side) */
  binaryPolicies: Array<{ label: string; sizeBytes: number }>;
  /** Built-in-controls mode summary when no XML is present */
  builtInControls?: string[];
  assignments: IntuneAssignment[];
  /** Graph URL to open the policy in the Intune admin center */
  portalUrl: string;
}

const APP_CONTROL_OMA_URI = /\/vendor\/msft\/applicationcontrol\//i;

/** Walk a settings-catalog setting instance tree into flat definitionId/value pairs. */
export function flattenSettingInstance(instance: unknown, out: IntuneSettingPair[] = []): IntuneSettingPair[] {
  if (!instance || typeof instance !== "object") return out;
  const inst = instance as Record<string, unknown>;
  const defId = String(inst.settingDefinitionId ?? "");
  const simple = inst.simpleSettingValue as Record<string, unknown> | undefined;
  if (simple && simple.value !== undefined) out.push({ definitionId: defId, value: String(simple.value) });
  const simpleColl = inst.simpleSettingCollectionValue as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(simpleColl)) for (const v of simpleColl) if (v?.value !== undefined) out.push({ definitionId: defId, value: String(v.value) });
  const choice = inst.choiceSettingValue as Record<string, unknown> | undefined;
  if (choice) {
    if (choice.value !== undefined) out.push({ definitionId: defId, value: String(choice.value) });
    for (const c of (choice.children as unknown[]) ?? []) flattenSettingInstance(c, out);
  }
  const choiceColl = inst.choiceSettingCollectionValue as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(choiceColl)) {
    for (const cv of choiceColl) {
      if (cv?.value !== undefined) out.push({ definitionId: defId, value: String(cv.value) });
      for (const c of (cv?.children as unknown[]) ?? []) flattenSettingInstance(c, out);
    }
  }
  const groupColl = inst.groupSettingCollectionValue as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(groupColl)) for (const g of groupColl) for (const c of (g?.children as unknown[]) ?? []) flattenSettingInstance(c, out);
  const group = inst.groupSettingValue as Record<string, unknown> | undefined;
  if (group) for (const c of (group.children as unknown[]) ?? []) flattenSettingInstance(c, out);
  return out;
}

function base64ToUtf8(b64: string): string | null {
  const clean = b64.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]+$/.test(clean) || clean.length < 16) return null;
  try {
    if (typeof atob === "function") {
      const bin = atob(clean);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return decodeBytes(bytes);
    }
    const B = (globalThis as { Buffer?: { from(s: string, e: string): Uint8Array } }).Buffer;
    if (B) return decodeBytes(B.from(clean, "base64"));
  } catch {
    /* not base64 */
  }
  return null;
}

function decodeBytes(bytes: Uint8Array): string {
  // UTF-16LE BOM (ConvertFrom-CIPolicy XML saved by PowerShell) or UTF-8
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return new TextDecoder("utf-16le").decode(bytes.subarray(2));
  }
  const s = new TextDecoder("utf-8").decode(bytes);
  return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
}

/** Returns SiPolicy XML if the value is XML or base64-encoded XML; "binary" for a CIP blob; null otherwise. */
export function decodePolicyPayload(value: string): { kind: "xml"; xml: string } | { kind: "binary"; sizeBytes: number } | null {
  const trimmed = value.trim();
  if (/<SiPolicy[\s>]/.test(trimmed)) return { kind: "xml", xml: trimmed };
  const decoded = base64ToUtf8(trimmed);
  if (decoded && /<SiPolicy[\s>]/.test(decoded)) return { kind: "xml", xml: decoded.trim() };
  if (decoded !== null) {
    // Base64 that is not XML: a compiled .cip/.p7b policy (binary, starts with 0x07 0x00 0x00 0x00 for SiPolicy v7+)
    const approxBytes = Math.floor((trimmed.length * 3) / 4);
    if (approxBytes > 64) return { kind: "binary", sizeBytes: approxBytes };
  }
  return null;
}

const BUILT_IN_LABELS: Array<[RegExp, string]> = [
  [/applicationcontrol.*(enableauditmode|_audit)/i, "Audit mode"],
  [/applicationcontrol.*(trustappswithgoodreputation|isg|reputation)/i, "Trust apps with good reputation (ISG)"],
  [/applicationcontrol.*(managedinstaller|trustappsfrommanagedinstallers)/i, "Trust apps from managed installers"],
  [/applicationcontrol.*(windowscomponents|storeapps|enablewindowscomponents)/i, "Windows components and Store apps"],
];

/** Normalise a settings-catalog configurationPolicy (with $expand=settings,assignments). */
export function normalizeSettingsCatalogPolicy(raw: Record<string, unknown>): IntuneAppControlPolicy {
  const settingsRaw = (raw.settings as Array<Record<string, unknown>>) ?? [];
  const settings: IntuneSettingPair[] = [];
  for (const s of settingsRaw) flattenSettingInstance(s.settingInstance, settings);
  const xmlPolicies: IntuneAppControlPolicy["xmlPolicies"] = [];
  const binaryPolicies: IntuneAppControlPolicy["binaryPolicies"] = [];
  const builtIn = new Set<string>();
  for (const s of settings) {
    const p = decodePolicyPayload(s.value);
    if (p?.kind === "xml") xmlPolicies.push({ label: s.definitionId.split("_").pop() ?? s.definitionId, xml: p.xml });
    else if (p?.kind === "binary") binaryPolicies.push({ label: s.definitionId, sizeBytes: p.sizeBytes });
    for (const [re, label] of BUILT_IN_LABELS) {
      if (re.test(s.definitionId) && /_(1|true)$/i.test(s.value)) builtIn.add(label);
    }
  }
  const id = String(raw.id ?? "");
  return {
    id,
    name: String(raw.name ?? raw.displayName ?? "(unnamed)"),
    description: raw.description ? String(raw.description) : undefined,
    source: "settingsCatalog",
    platform: raw.platforms ? String(raw.platforms) : undefined,
    technologies: raw.technologies ? String(raw.technologies) : undefined,
    createdDateTime: raw.createdDateTime ? String(raw.createdDateTime) : undefined,
    lastModifiedDateTime: raw.lastModifiedDateTime ? String(raw.lastModifiedDateTime) : undefined,
    settingCount: settings.length,
    settings,
    xmlPolicies,
    binaryPolicies,
    builtInControls: builtIn.size ? [...builtIn] : undefined,
    assignments: ((raw.assignments as Array<Record<string, unknown>>) ?? []).map(normalizeAssignment),
    portalUrl: `https://intune.microsoft.com/#view/Microsoft_Intune_Workflows/PolicySummaryReportBlade/policyId/${encodeURIComponent(id)}/policyType~/1`,
  };
}

/** Returns true when a deviceConfiguration is a custom OMA-URI profile carrying App Control settings. */
export function isAppControlOmaProfile(raw: Record<string, unknown>): boolean {
  const type = String(raw["@odata.type"] ?? "");
  if (!type.endsWith("windows10CustomConfiguration")) return false;
  const oma = (raw.omaSettings as Array<Record<string, unknown>>) ?? [];
  return oma.some((s) => APP_CONTROL_OMA_URI.test(String(s.omaUri ?? "")));
}

/** Normalise a windows10CustomConfiguration profile (with $expand=assignments). */
export function normalizeOmaUriPolicy(raw: Record<string, unknown>): IntuneAppControlPolicy {
  const oma = ((raw.omaSettings as Array<Record<string, unknown>>) ?? []).filter((s) => APP_CONTROL_OMA_URI.test(String(s.omaUri ?? "")));
  const settings: IntuneSettingPair[] = [];
  const xmlPolicies: IntuneAppControlPolicy["xmlPolicies"] = [];
  const binaryPolicies: IntuneAppControlPolicy["binaryPolicies"] = [];
  for (const s of oma) {
    const uri = String(s.omaUri ?? "");
    const value = s.value === undefined || s.value === null ? "" : String(s.value);
    const guid = uri.match(/Policies\/\{?([0-9A-Fa-f-]{36})\}?/)?.[1];
    settings.push({ definitionId: uri, value: value.length > 200 ? `${value.slice(0, 200)}… (${value.length} chars)` : value });
    if (!value) continue;
    const p = decodePolicyPayload(value);
    if (p?.kind === "xml") xmlPolicies.push({ label: guid ?? String(s.displayName ?? uri), xml: p.xml });
    else if (p?.kind === "binary") binaryPolicies.push({ label: guid ?? String(s.displayName ?? uri), sizeBytes: p.sizeBytes });
  }
  const id = String(raw.id ?? "");
  return {
    id,
    name: String(raw.displayName ?? "(unnamed)"),
    description: raw.description ? String(raw.description) : undefined,
    source: "customOmaUri",
    platform: "windows10",
    createdDateTime: raw.createdDateTime ? String(raw.createdDateTime) : undefined,
    lastModifiedDateTime: raw.lastModifiedDateTime ? String(raw.lastModifiedDateTime) : undefined,
    settingCount: oma.length,
    settings,
    xmlPolicies,
    binaryPolicies,
    assignments: ((raw.assignments as Array<Record<string, unknown>>) ?? []).map(normalizeAssignment),
    portalUrl: `https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DeviceConfigurationMenuBlade/~/overview/id/${encodeURIComponent(id)}`,
  };
}

// ---------------------------------------------------------------------------
// Effective assignment evaluation
// ---------------------------------------------------------------------------

export interface DeviceMembership {
  /** Transitive group object IDs the device belongs to */
  deviceGroupIds: Set<string> | string[];
  /** Transitive group object IDs of the device's primary user (empty when unknown) */
  userGroupIds?: Set<string> | string[];
  /** Whether a primary user could be resolved */
  hasPrimaryUser: boolean;
}

export type EffectiveStatus = "assigned" | "excluded" | "notAssigned";

export interface EffectiveAssignment {
  policyId: string;
  status: EffectiveStatus;
  /** Human-readable reasons, e.g. "Included via group 'WDAC Pilot'" */
  reasons: string[];
  /** Assignments carrying filters — cannot be evaluated offline */
  filterNotes: string[];
}

function toSet(v: Set<string> | string[] | undefined): Set<string> {
  if (!v) return new Set();
  return v instanceof Set ? v : new Set(v);
}

export function evaluateEffectiveAssignment(
  policy: Pick<IntuneAppControlPolicy, "id" | "assignments">,
  membership: DeviceMembership
): EffectiveAssignment {
  const dev = toSet(membership.deviceGroupIds);
  const usr = toSet(membership.userGroupIds);
  const reasons: string[] = [];
  const filterNotes: string[] = [];
  let included = false;
  let excluded = false;

  for (const a of policy.assignments) {
    const gName = a.groupName ?? a.groupId ?? "(unknown group)";
    const filter = a.filterId && a.filterType !== "none"
      ? ` [${a.filterType} filter: ${a.filterName ?? a.filterId}]`
      : "";
    switch (a.kind) {
      case "allDevices":
        included = true;
        reasons.push(`Included: All devices${filter}`);
        break;
      case "allUsers":
        if (membership.hasPrimaryUser) {
          included = true;
          reasons.push(`Included: All users (via primary user)${filter}`);
        } else {
          reasons.push("All users assignment — device has no primary user, so it applies only when a licensed user signs in");
        }
        break;
      case "group":
        if (a.groupId && dev.has(a.groupId)) { included = true; reasons.push(`Included via device group '${gName}'${filter}`); }
        else if (a.groupId && usr.has(a.groupId)) { included = true; reasons.push(`Included via user group '${gName}'${filter}`); }
        break;
      case "exclusionGroup":
        if (a.groupId && (dev.has(a.groupId) || usr.has(a.groupId))) { excluded = true; reasons.push(`Excluded via group '${gName}'`); }
        break;
      default:
        reasons.push(`Unrecognised assignment target ${a.odataType ?? ""}`);
    }
    if (filter && (a.kind === "allDevices" || a.kind === "allUsers" || a.kind === "group")) {
      filterNotes.push(`${a.filterType} filter '${a.filterName ?? a.filterId}' is evaluated by Intune at check-in and cannot be resolved here.`);
    }
  }

  const status: EffectiveStatus = excluded ? "excluded" : included ? "assigned" : "notAssigned";
  if (status === "notAssigned" && reasons.length === 0) reasons.push("No assignment targets this device or its primary user.");
  return { policyId: policy.id, status, reasons, filterNotes };
}

// ---------------------------------------------------------------------------
// Advanced Hunting
// ---------------------------------------------------------------------------

/** DeviceEvents ActionTypes emitted by App Control (Code Integrity + AppLocker script hosts). */
export const APP_CONTROL_ACTION_TYPES = [
  "AppControlCodeIntegrityPolicyAudited",
  "AppControlCodeIntegrityPolicyBlocked",
  "AppControlCIScriptAudited",
  "AppControlCIScriptBlocked",
  "AppControlCodeIntegrityDriverRevoked",
  "AppControlCodeIntegrityImageRevoked",
  "AppControlCodeIntegrityPolicyLoaded",
  "AppControlCodeIntegritySigningInformation",
  "AppControlCodeIntegrityOriginAllowed",
  "AppControlCodeIntegrityOriginAudited",
  "AppControlCodeIntegrityOriginBlocked",
  "AppControlExecutableAudited",
  "AppControlExecutableBlocked",
  "AppControlPackagedAppAudited",
  "AppControlPackagedAppBlocked",
  "AppControlScriptAudited",
  "AppControlScriptBlocked",
] as const;

/** Subset that represents an actual enforcement/audit decision on a file. */
export const APP_CONTROL_DECISION_ACTION_TYPES = [
  "AppControlCodeIntegrityPolicyAudited",
  "AppControlCodeIntegrityPolicyBlocked",
  "AppControlCIScriptAudited",
  "AppControlCIScriptBlocked",
  "AppControlExecutableAudited",
  "AppControlExecutableBlocked",
  "AppControlPackagedAppAudited",
  "AppControlPackagedAppBlocked",
  "AppControlScriptAudited",
  "AppControlScriptBlocked",
] as const;

export type HuntingTimespan = "P1D" | "P7D" | "P30D";

function kqlString(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * KQL for recent App Control decisions. Columns are chosen to feed the existing
 * Advanced Hunting parser (FolderPath/FileName/SHA256/SHA1/PolicyGuid/…).
 */
export function buildAppControlEventsQuery(opts: {
  deviceName?: string;
  deviceId?: string;
  blockedOnly?: boolean;
  limit?: number;
}): string {
  const lines = [
    "DeviceEvents",
    `| where ActionType in (${APP_CONTROL_DECISION_ACTION_TYPES.map(kqlString).join(", ")})`,
  ];
  if (opts.deviceId) lines.push(`| where DeviceId == ${kqlString(opts.deviceId)}`);
  else if (opts.deviceName) lines.push(`| where DeviceName has ${kqlString(opts.deviceName)} or DeviceName startswith ${kqlString(opts.deviceName.toLowerCase())}`);
  if (opts.blockedOnly) lines.push('| where ActionType endswith "Blocked"');
  lines.push(
    "| extend F = parse_json(AdditionalFields)",
    "| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA256, SHA1,",
    "    InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessAccountName,",
    "    PolicyName = tostring(F.PolicyName), PolicyGuid = tostring(F.PolicyGuid), PolicyId = tostring(F.PolicyId),",
    "    OriginalFileName = tostring(F.OriginalFileName), InternalName = tostring(F.InternalName),",
    "    FileDescription = tostring(F.FileDescription), ProductName = tostring(F.ProductName), FileVersion = tostring(F.FileVersion),",
    "    PublisherName = tostring(F.PublisherName), IssuerName = tostring(F.IssuerName),",
    "    RequestedSigningLevel = tostring(F.RequestedSigningLevel), ValidatedSigningLevel = tostring(F.ValidatedSigningLevel),",
    "    UserWriteable = tostring(F.UserWriteable), ProcessId = tostring(F.ProcessId)",
    "| order by Timestamp desc",
    `| take ${Math.min(Math.max(opts.limit ?? 500, 1), 10000)}`
  );
  return lines.join("\n");
}

/** KQL: which devices are producing App Control blocks/audits, ranked. */
export function buildAppControlDeviceSummaryQuery(opts: { deviceName?: string } = {}): string {
  const lines = [
    "DeviceEvents",
    `| where ActionType in (${APP_CONTROL_DECISION_ACTION_TYPES.map(kqlString).join(", ")})`,
  ];
  if (opts.deviceName) lines.push(`| where DeviceName has ${kqlString(opts.deviceName)}`);
  lines.push(
    '| summarize Blocked = countif(ActionType endswith "Blocked"), Audited = countif(ActionType endswith "Audited"),',
    "    UniqueFiles = dcount(SHA256), LastEvent = max(Timestamp), Policies = make_set(tostring(parse_json(AdditionalFields).PolicyName), 5) by DeviceName, DeviceId",
    "| order by Blocked desc, Audited desc",
    "| take 200"
  );
  return lines.join("\n");
}

/** KQL: policies loaded on a device (3099 equivalent) — what WDAC actually enforces right now. */
export function buildPoliciesLoadedQuery(opts: { deviceName?: string; deviceId?: string }): string {
  const lines = [
    "DeviceEvents",
    '| where ActionType == "AppControlCodeIntegrityPolicyLoaded"',
  ];
  if (opts.deviceId) lines.push(`| where DeviceId == ${kqlString(opts.deviceId)}`);
  else if (opts.deviceName) lines.push(`| where DeviceName has ${kqlString(opts.deviceName)}`);
  lines.push(
    "| extend F = parse_json(AdditionalFields)",
    "| project Timestamp, DeviceName, DeviceId, PolicyName = tostring(F.PolicyName), PolicyGuid = tostring(F.PolicyGuid), PolicyId = tostring(F.PolicyId),",
    "    PolicyHash = tostring(F.PolicyHash), Options = tostring(F.PolicyOptions), Status = tostring(F.Status)",
    "| summarize arg_max(Timestamp, *) by DeviceId, PolicyGuid",
    "| order by Timestamp desc",
    "| take 100"
  );
  return lines.join("\n");
}

/** KQL: device lookup from Defender when Intune is unavailable. */
export function buildDeviceLookupQuery(deviceName: string): string {
  return [
    "DeviceInfo",
    `| where DeviceName has ${kqlString(deviceName)}`,
    "| summarize arg_max(Timestamp, *) by DeviceId",
    "| project DeviceName, DeviceId, OSPlatform, OSVersion, OSBuild, AadDeviceId, LoggedOnUsers, LastSeen = Timestamp, OnboardingStatus, MachineGroup",
    "| order by LastSeen desc",
    "| take 50",
  ].join("\n");
}

export interface HuntingResultSet {
  schema: Array<{ name: string; type: string }>;
  results: Array<Record<string, unknown>>;
}

/** Managed device summary from Intune (subset of microsoft.graph.managedDevice). */
export interface IntuneDevice {
  id: string;
  deviceName: string;
  azureADDeviceId?: string;
  userPrincipalName?: string;
  userId?: string;
  operatingSystem?: string;
  osVersion?: string;
  complianceState?: string;
  lastSyncDateTime?: string;
  enrolledDateTime?: string;
  managementAgent?: string;
  model?: string;
  manufacturer?: string;
  serialNumber?: string;
  /** Defender DeviceId when correlated via DeviceInfo */
  mdeDeviceId?: string;
}

export function normalizeManagedDevice(raw: Record<string, unknown>): IntuneDevice {
  const str = (k: string) => (raw[k] === undefined || raw[k] === null ? undefined : String(raw[k]));
  return {
    id: String(raw.id ?? ""),
    deviceName: str("deviceName") ?? "(unnamed)",
    azureADDeviceId: str("azureADDeviceId"),
    userPrincipalName: str("userPrincipalName"),
    userId: str("userId"),
    operatingSystem: str("operatingSystem"),
    osVersion: str("osVersion"),
    complianceState: str("complianceState"),
    lastSyncDateTime: str("lastSyncDateTime"),
    enrolledDateTime: str("enrolledDateTime"),
    managementAgent: str("managementAgent"),
    model: str("model"),
    manufacturer: str("manufacturer"),
    serialNumber: str("serialNumber"),
  };
}
