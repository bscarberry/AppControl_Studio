/**
 * Intune & XDR page
 *
 *   Policies — App Control for Business policies in the Intune tenant
 *              (settings catalog + legacy OMA-URI), assignments with resolved
 *              group / filter names, decoded SiPolicy XML → open in the editor.
 *   Devices  — search Intune managed devices, evaluate which App Control
 *              policies are effectively assigned to the device, pull recent
 *              Advanced Hunting blocks/audits, import them into the events
 *              pipeline (Build Policy / Rule Engine).
 *   Hunting  — run the App Control KQL presets or a custom query.
 *
 * All Graph calls happen in the browser with the user's delegated token.
 */

import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { v4 as uuidv4 } from "uuid";
import clsx from "clsx";
import {
  Cloud, Search, Monitor, ShieldOff, ShieldCheck, Users, Filter, ExternalLink, FileText, RefreshCw,
  ChevronDown, ChevronRight, AlertTriangle, Download, Play, Database, CheckCircle, XCircle, MinusCircle, Info, Copy,
} from "lucide-react";
import type { IntuneAppControlPolicy, IntuneDevice, HuntingResultSet, HuntingTimespan, EffectiveAssignment } from "@appcontrol/shared";
import {
  evaluateEffectiveAssignment, buildAppControlEventsQuery, buildAppControlDeviceSummaryQuery, buildPoliciesLoadedQuery,
  buildDeviceLookupQuery, GRAPH_SCOPES,
} from "@appcontrol/shared";
import { isGraphAvailable, listAppControlPolicies, searchManagedDevices, getDeviceMembership, runHuntingQuery, GraphError } from "../lib/graph.ts";
import { policyApi, eventsApi } from "../lib/api.ts";
import { useAppStore } from "../store/index.ts";
import { Header } from "../components/layout/Header.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import { EmptyState } from "../components/common/EmptyState.tsx";

type Tab = "policies" | "devices" | "hunting";

function fmtDate(s?: string) {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString();
}

function ErrorBox({ error }: { error: unknown }) {
  const e = error as Error;
  const g = error instanceof GraphError ? error : null;
  return (
    <div className="p-3 bg-accent-red/10 border border-accent-red/20 rounded text-xs text-accent-red space-y-1">
      <div className="flex gap-2"><AlertTriangle size={12} className="mt-0.5 flex-shrink-0" /><span>{e.message}</span></div>
      {g?.status === 403 && (
        <p className="text-text-muted">Required delegated permissions: {[...GRAPH_SCOPES.intune, ...GRAPH_SCOPES.hunting].join(", ")}. An admin must grant consent in Entra ID → App registrations → API permissions.</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Assignment chips
// ---------------------------------------------------------------------------

function AssignmentChips({ policy }: { policy: IntuneAppControlPolicy }) {
  if (policy.assignments.length === 0) return <span className="tag tag-gray text-[10px]">Not assigned</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {policy.assignments.map((a, i) => (
        <span key={a.id ?? i} className={clsx("tag text-[10px]", a.kind === "exclusionGroup" ? "tag-red" : a.kind === "allDevices" || a.kind === "allUsers" ? "tag-blue" : "tag-green")} title={a.groupId}>
          {a.kind === "allDevices" ? <><Monitor size={10} className="mr-1" />All devices</>
            : a.kind === "allUsers" ? <><Users size={10} className="mr-1" />All users</>
              : a.kind === "exclusionGroup" ? <><MinusCircle size={10} className="mr-1" />Exclude: {a.groupName ?? a.groupId}</>
                : <><Users size={10} className="mr-1" />{a.groupName ?? a.groupId}</>}
          {a.filterId && a.filterType !== "none" && <span className="ml-1 opacity-80" title={`${a.filterType} filter`}><Filter size={9} className="inline" /> {a.filterName ?? "filter"}</span>}
        </span>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Policies tab
// ---------------------------------------------------------------------------

function PoliciesTab({ policiesQuery }: { policiesQuery: ReturnType<typeof usePoliciesQuery> }) {
  const navigate = useNavigate();
  const { addSession } = useAppStore();
  const [openId, setOpenId] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const openInEditor = useMutation({
    mutationFn: async ({ xml, name }: { xml: string; name: string }) => {
      const r = await policyApi.parse(xml, `${name}.xml`);
      addSession({ id: uuidv4(), fileName: `${name}.xml`, policy: r.policy, xml, loadedAt: new Date().toISOString() });
      return r;
    },
    onSuccess: () => navigate("/"),
    onError: (e) => setStatus((e as Error).message),
  });

  if (policiesQuery.isLoading) return <LoadingSpinner label="Reading App Control policies from Intune…" />;
  if (policiesQuery.isError) return <ErrorBox error={policiesQuery.error} />;
  const { policies, warnings } = policiesQuery.data!;

  return (
    <div className="space-y-3 max-w-6xl">
      {warnings.map((w, i) => <div key={i} className="flex gap-2 text-[11px] text-accent-yellow"><AlertTriangle size={11} className="mt-0.5" />{w}</div>)}
      {status && <div className="text-xs text-accent-red">{status}</div>}
      <div className="flex items-center gap-3 text-xs text-text-muted">
        <span>{policies.length} App Control polic{policies.length === 1 ? "y" : "ies"}</span>
        <span>{policies.filter((p) => p.source === "settingsCatalog").length} settings catalog</span>
        <span>{policies.filter((p) => p.source === "customOmaUri").length} custom OMA-URI</span>
        <span>{policies.filter((p) => p.assignments.length === 0).length} unassigned</span>
      </div>
      {policies.length === 0 && <EmptyState icon={<ShieldCheck size={32} />} title="No App Control policies found" description="Neither settings-catalog App Control for Business policies nor custom OMA-URI ApplicationControl profiles exist in this tenant." />}
      {policies.map((p) => {
        const open = openId === p.id;
        return (
          <div key={p.id} className="border border-border rounded overflow-hidden">
            <button className="w-full flex items-center gap-3 px-3 py-2.5 bg-surface-2 hover:bg-surface-3 text-left" onClick={() => setOpenId(open ? null : p.id)}>
              {open ? <ChevronDown size={13} className="text-text-muted" /> : <ChevronRight size={13} className="text-text-muted" />}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-medium text-text-primary">{p.name}</span>
                  <span className="tag tag-gray text-[10px]">{p.source === "settingsCatalog" ? "Settings catalog" : "Custom OMA-URI"}</span>
                  {p.xmlPolicies.length > 0 && <span className="tag tag-blue text-[10px]"><FileText size={10} className="mr-1" />{p.xmlPolicies.length} XML</span>}
                  {p.binaryPolicies.length > 0 && <span className="tag tag-yellow text-[10px]">{p.binaryPolicies.length} binary CIP</span>}
                  {p.builtInControls?.map((b) => <span key={b} className="tag tag-green text-[10px]">{b}</span>)}
                </div>
                <div className="mt-1"><AssignmentChips policy={p} /></div>
              </div>
              <span className="text-[10px] text-text-muted whitespace-nowrap">modified {fmtDate(p.lastModifiedDateTime)}</span>
            </button>
            {open && (
              <div className="p-3 bg-surface-1 space-y-3 text-xs">
                {p.description && <p className="text-text-secondary">{p.description}</p>}
                <div className="flex gap-2 flex-wrap">
                  <a className="btn-secondary text-xs" href={p.portalUrl} target="_blank" rel="noreferrer"><ExternalLink size={12} />Open in Intune</a>
                  {p.xmlPolicies.map((x, i) => (
                    <button key={i} className="btn-primary text-xs" disabled={openInEditor.isPending} onClick={() => openInEditor.mutate({ xml: x.xml, name: p.xmlPolicies.length > 1 ? `${p.name} (${x.label})` : p.name })}>
                      <FileText size={12} />Open {p.xmlPolicies.length > 1 ? x.label : "XML"} in editor
                    </button>
                  ))}
                  {p.xmlPolicies.map((x, i) => (
                    <button key={`d${i}`} className="btn-ghost text-xs" onClick={() => {
                      const blob = new Blob([x.xml], { type: "text/xml" }); const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = `${p.name}-${x.label}.xml`; a.click(); URL.revokeObjectURL(url);
                    }}><Download size={12} />Download {x.label}</button>
                  ))}
                </div>
                {p.binaryPolicies.length > 0 && (
                  <p className="text-accent-yellow flex gap-1.5"><Info size={12} className="mt-0.5 flex-shrink-0" />Binary .cip payloads ({p.binaryPolicies.map((b) => `${b.label}, ~${Math.round(b.sizeBytes / 1024)} KB`).join("; ")}) cannot be decoded here. Keep the source XML alongside them in the editor.</p>
                )}
                <div>
                  <div className="section-header mb-1">Assignments ({p.assignments.length})</div>
                  {p.assignments.length === 0 ? <p className="text-text-muted">This policy is not assigned to anything.</p> : (
                    <table className="data-table"><thead><tr><th>Target</th><th>Group / scope</th><th>Filter</th></tr></thead>
                      <tbody>{p.assignments.map((a, i) => (
                        <tr key={a.id ?? i}>
                          <td>{a.kind}</td>
                          <td className="mono">{a.groupName ?? a.groupId ?? "—"}{a.groupName && a.groupId ? <span className="text-text-muted ml-2 text-[10px]">{a.groupId}</span> : null}</td>
                          <td>{a.filterId && a.filterType !== "none" ? `${a.filterType}: ${a.filterName ?? a.filterId}` : "—"}</td>
                        </tr>))}</tbody></table>
                  )}
                </div>
                <div>
                  <div className="section-header mb-1">Settings ({p.settings.length})</div>
                  <div className="max-h-48 overflow-auto rounded border border-border-muted">
                    {p.settings.map((s, i) => (
                      <div key={i} className="flex gap-2 px-2 py-1 border-b border-border-muted last:border-0">
                        <span className="mono text-text-muted truncate w-1/2" title={s.definitionId}>{s.definitionId}</span>
                        <span className="mono text-text-secondary truncate w-1/2" title={s.value}>{s.value.length > 120 ? `${s.value.slice(0, 120)}…` : s.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Devices tab
// ---------------------------------------------------------------------------

function StatusIcon({ s }: { s: EffectiveAssignment["status"] }) {
  if (s === "assigned") return <CheckCircle size={13} className="text-accent-green" />;
  if (s === "excluded") return <XCircle size={13} className="text-accent-red" />;
  return <MinusCircle size={13} className="text-text-muted" />;
}

function DeviceDetail({ device, policies }: { device: IntuneDevice; policies: IntuneAppControlPolicy[] | undefined }) {
  const navigate = useNavigate();
  const { setImportedEvents } = useAppStore();
  const [timespan, setTimespan] = useState<HuntingTimespan>("P7D");
  const [blockedOnly, setBlockedOnly] = useState(false);
  const [importMsg, setImportMsg] = useState<string | null>(null);

  const membership = useQuery({ queryKey: ["membership", device.id], queryFn: () => getDeviceMembership(device), staleTime: 5 * 60_000 });
  const loaded = useQuery({ queryKey: ["loaded", device.deviceName], queryFn: () => runHuntingQuery(buildPoliciesLoadedQuery({ deviceName: device.deviceName }), "P30D"), staleTime: 5 * 60_000 });
  const events = useQuery({
    queryKey: ["events", device.deviceName, timespan, blockedOnly],
    queryFn: () => runHuntingQuery(buildAppControlEventsQuery({ deviceName: device.deviceName, blockedOnly, limit: 1000 }), timespan),
    staleTime: 60_000,
  });

  const effective = useMemo(() => {
    if (!policies || !membership.data) return null;
    return policies.map((p) => ({ policy: p, result: evaluateEffectiveAssignment(p, { deviceGroupIds: membership.data!.deviceGroupIds, userGroupIds: membership.data!.userGroupIds, hasPrimaryUser: membership.data!.hasPrimaryUser }) }))
      .sort((a, b) => (a.result.status === "assigned" ? 0 : a.result.status === "excluded" ? 1 : 2) - (b.result.status === "assigned" ? 0 : b.result.status === "excluded" ? 1 : 2));
  }, [policies, membership.data]);

  const importEvents = useMutation({
    mutationFn: async () => {
      const rows = events.data?.results ?? [];
      if (rows.length === 0) throw new Error("No events to import.");
      const r = await eventsApi.parseHunting(JSON.stringify(rows), "json");
      setImportedEvents(r.events);
      return r;
    },
    onSuccess: (r) => setImportMsg(`Imported ${r.events.length} events (${r.summary.blockEvents} blocks, ${r.summary.auditEvents} audits, ${r.summary.uniqueFiles} unique files). Open Import & Build or Rule Engine to create rules.`),
    onError: (e) => setImportMsg((e as Error).message),
  });

  const rows = events.data?.results ?? [];
  const blocks = rows.filter((r) => String(r.ActionType).endsWith("Blocked")).length;

  return (
    <div className="space-y-4">
      <section className="card p-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2"><Monitor size={14} className="text-accent-blue" />{device.deviceName}</h2>
            <dl className="grid grid-cols-[8rem_1fr] gap-x-3 gap-y-0.5 text-xs mt-2">
              <dt className="text-text-muted">User</dt><dd className="text-text-secondary">{device.userPrincipalName ?? "— (no primary user)"}</dd>
              <dt className="text-text-muted">OS</dt><dd className="text-text-secondary">{device.operatingSystem} {device.osVersion}</dd>
              <dt className="text-text-muted">Compliance</dt><dd className="text-text-secondary">{device.complianceState}</dd>
              <dt className="text-text-muted">Last sync</dt><dd className="text-text-secondary">{fmtDate(device.lastSyncDateTime)}</dd>
              <dt className="text-text-muted">Model</dt><dd className="text-text-secondary">{device.manufacturer} {device.model} · {device.serialNumber}</dd>
              <dt className="text-text-muted">Entra device ID</dt><dd className="mono text-text-secondary">{device.azureADDeviceId ?? "—"}</dd>
            </dl>
          </div>
          <a className="btn-secondary text-xs" target="_blank" rel="noreferrer" href={`https://intune.microsoft.com/#view/Microsoft_Intune_Devices/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/${device.id}`}><ExternalLink size={12} />Open in Intune</a>
        </div>
      </section>

      <section className="card p-4">
        <h2 className="section-header">Effective App Control assignments</h2>
        {membership.isLoading || !policies ? <LoadingSpinner label="Resolving group membership…" /> : membership.isError ? <ErrorBox error={membership.error} /> : (
          <>
            {membership.data!.warnings.map((w, i) => <div key={i} className="flex gap-2 text-[11px] text-accent-yellow mb-1"><AlertTriangle size={11} className="mt-0.5" />{w}</div>)}
            <p className="text-[11px] text-text-muted mb-2">Device is in {membership.data!.deviceGroupIds.length} group(s); primary user in {membership.data!.userGroupIds.length}. Evaluated against {policies.length} polic{policies.length === 1 ? "y" : "ies"}.</p>
            {effective?.length === 0 && <p className="text-xs text-text-muted">No App Control policies exist in the tenant.</p>}
            <div className="space-y-1.5">
              {effective?.map(({ policy, result }) => (
                <div key={policy.id} className={clsx("p-2 rounded border text-xs", result.status === "assigned" ? "border-accent-green/30 bg-accent-green/5" : result.status === "excluded" ? "border-accent-red/30 bg-accent-red/5" : "border-border-muted bg-surface-2 opacity-70")}>
                  <div className="flex items-center gap-2"><StatusIcon s={result.status} /><span className="font-medium text-text-primary">{policy.name}</span><span className="tag tag-gray text-[10px]">{result.status}</span><span className="text-text-muted ml-auto">{policy.source === "settingsCatalog" ? "settings catalog" : "OMA-URI"}</span></div>
                  <ul className="mt-1 ml-5 text-text-secondary list-disc">{result.reasons.map((r, i) => <li key={i}>{r}</li>)}{result.filterNotes.map((r, i) => <li key={`f${i}`} className="text-accent-yellow">{r}</li>)}</ul>
                </div>
              ))}
            </div>
          </>
        )}
      </section>

      <section className="card p-4">
        <h2 className="section-header">Policies loaded on the device (Defender telemetry, 30 days)</h2>
        {loaded.isLoading ? <LoadingSpinner label="Querying Advanced Hunting…" /> : loaded.isError ? <ErrorBox error={loaded.error} /> : loaded.data!.results.length === 0 ? (
          <p className="text-xs text-text-muted">No AppControlCodeIntegrityPolicyLoaded events in the last 30 days. The device may not be onboarded to Defender, or has not rebooted / refreshed policy recently.</p>
        ) : (
          <table className="data-table"><thead><tr><th>Loaded</th><th>Policy</th><th>GUID</th><th>Options</th></tr></thead>
            <tbody>{loaded.data!.results.map((r, i) => (
              <tr key={i}><td className="whitespace-nowrap">{fmtDate(String(r.Timestamp))}</td><td>{String(r.PolicyName || "—")}</td><td className="mono text-[10px]">{String(r.PolicyGuid || r.PolicyId || "—")}</td><td className="text-[10px] max-w-md truncate" title={String(r.Options ?? "")}>{String(r.Options || "—")}</td></tr>
            ))}</tbody></table>
        )}
      </section>

      <section className="card p-4">
        <div className="flex items-center gap-3 mb-3 flex-wrap">
          <h2 className="section-header mb-0">Recent App Control events</h2>
          <select className="input text-xs py-1 w-auto" value={timespan} onChange={(e) => setTimespan(e.target.value as HuntingTimespan)}>
            <option value="P1D">Last 24 hours</option><option value="P7D">Last 7 days</option><option value="P30D">Last 30 days</option>
          </select>
          <label className="flex items-center gap-1.5 text-xs text-text-secondary"><input type="checkbox" checked={blockedOnly} onChange={(e) => setBlockedOnly(e.target.checked)} />Blocked only</label>
          <button className="btn-ghost text-xs" onClick={() => events.refetch()} disabled={events.isFetching}><RefreshCw size={12} className={events.isFetching ? "animate-spin" : ""} />Refresh</button>
          <button className="btn-primary text-xs ml-auto" disabled={rows.length === 0 || importEvents.isPending} onClick={() => importEvents.mutate()}><Database size={12} />Import {rows.length} events into Studio</button>
          {importMsg && <button className="btn-ghost text-xs" onClick={() => navigate("/import-events")}>Go to Import & Build →</button>}
        </div>
        {importMsg && <p className="text-xs text-accent-green mb-2">{importMsg}</p>}
        {events.isLoading ? <LoadingSpinner label="Querying Advanced Hunting…" /> : events.isError ? <ErrorBox error={events.error} /> : rows.length === 0 ? (
          <p className="text-xs text-text-muted">No App Control events for this device in the selected window.</p>
        ) : (
          <>
            <div className="flex gap-3 text-xs text-text-muted mb-2"><span className="text-accent-red">{blocks} blocked</span><span className="text-accent-yellow">{rows.length - blocks} audited</span><span>{new Set(rows.map((r) => r.SHA256)).size} unique hashes</span></div>
            <div className="overflow-auto max-h-[28rem] rounded border border-border">
              <table className="data-table text-[11px]"><thead><tr><th>Time</th><th>Action</th><th>File</th><th>Publisher</th><th>Policy</th><th>Process</th></tr></thead>
                <tbody>{rows.slice(0, 500).map((r, i) => (
                  <tr key={i}>
                    <td className="whitespace-nowrap">{fmtDate(String(r.Timestamp))}</td>
                    <td><span className={clsx("tag text-[10px]", String(r.ActionType).endsWith("Blocked") ? "tag-red" : "tag-yellow")}>{String(r.ActionType).replace(/^AppControl/, "").replace(/CodeIntegrity/, "CI ")}</span></td>
                    <td className="max-w-xs"><div className="truncate text-text-primary" title={`${r.FolderPath}\\${r.FileName}`}>{String(r.FileName)}</div><div className="truncate text-text-muted text-[10px]">{String(r.FolderPath ?? "")}</div></td>
                    <td className="max-w-[10rem] truncate" title={String(r.IssuerName ?? "")}>{String(r.PublisherName || "unsigned / unknown")}</td>
                    <td className="max-w-[10rem] truncate" title={String(r.PolicyGuid ?? "")}>{String(r.PolicyName || "—")}</td>
                    <td className="max-w-[8rem] truncate">{String(r.InitiatingProcessFileName || "—")}</td>
                  </tr>
                ))}</tbody></table>
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function DevicesTab({ policies }: { policies: IntuneAppControlPolicy[] | undefined }) {
  const [q, setQ] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [selected, setSelected] = useState<IntuneDevice | null>(null);
  const [source, setSource] = useState<"intune" | "defender">("intune");

  const intuneSearch = useQuery({ queryKey: ["devsearch", submitted], queryFn: () => searchManagedDevices(submitted), enabled: !!submitted && source === "intune" });
  const mdeSearch = useQuery({ queryKey: ["mdesearch", submitted], queryFn: () => runHuntingQuery(buildDeviceLookupQuery(submitted), "P30D"), enabled: !!submitted && source === "defender" });
  const summary = useQuery({ queryKey: ["blocksummary"], queryFn: () => runHuntingQuery(buildAppControlDeviceSummaryQuery(), "P7D"), enabled: !submitted && !selected, staleTime: 5 * 60_000 });

  const mdeDevices: IntuneDevice[] = (mdeSearch.data?.results ?? []).map((r) => ({
    id: String(r.DeviceId), deviceName: String(r.DeviceName), azureADDeviceId: r.AadDeviceId ? String(r.AadDeviceId) : undefined,
    operatingSystem: String(r.OSPlatform ?? ""), osVersion: String(r.OSVersion ?? ""), lastSyncDateTime: String(r.LastSeen ?? ""), mdeDeviceId: String(r.DeviceId),
    userPrincipalName: (() => { try { const u = JSON.parse(String(r.LoggedOnUsers ?? "[]")); return u[0]?.UserName ? `${u[0].DomainName ?? ""}\\${u[0].UserName}` : undefined; } catch { return undefined; } })(),
  }));

  return (
    <div className="space-y-4 max-w-6xl">
      <form className="card p-4 flex gap-2 items-end flex-wrap" onSubmit={(e) => { e.preventDefault(); setSelected(null); setSubmitted(q.trim()); }}>
        <div className="flex-1 min-w-[16rem]">
          <label className="text-xs font-medium text-text-secondary" htmlFor="devq">Device name, user, or serial number</label>
          <div className="relative mt-1"><Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" /><input id="devq" className="input pl-8 text-xs" placeholder="e.g. LAPTOP-042 or jane@contoso.com" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        </div>
        <div className="flex gap-1">
          {(["intune", "defender"] as const).map((s) => <button key={s} type="button" className={clsx("btn text-xs", source === s ? "btn-primary" : "btn-secondary")} onClick={() => setSource(s)}>{s === "intune" ? "Intune" : "Defender"}</button>)}
        </div>
        <button className="btn-primary" type="submit" disabled={!q.trim()}><Search size={13} />Search</button>
      </form>

      {selected ? (
        <>
          <button className="btn-ghost text-xs" onClick={() => setSelected(null)}>← Back to results</button>
          <DeviceDetail device={selected} policies={policies} />
        </>
      ) : submitted ? (
        (source === "intune" ? intuneSearch.isLoading : mdeSearch.isLoading) ? <LoadingSpinner label="Searching…" />
          : (source === "intune" ? intuneSearch.isError : mdeSearch.isError) ? <ErrorBox error={source === "intune" ? intuneSearch.error : mdeSearch.error} />
            : (
              <div className="card overflow-hidden">
                {(source === "intune" ? intuneSearch.data ?? [] : mdeDevices).length === 0 ? <p className="p-4 text-xs text-text-muted">No Windows devices match "{submitted}".</p> : (
                  <table className="data-table"><thead><tr><th>Device</th><th>User</th><th>OS</th><th>{source === "intune" ? "Compliance" : "Source"}</th><th>Last seen</th><th /></tr></thead>
                    <tbody>{(source === "intune" ? intuneSearch.data ?? [] : mdeDevices).map((d) => (
                      <tr key={d.id} className="cursor-pointer" onClick={() => setSelected(d)}>
                        <td className="font-medium text-text-primary">{d.deviceName}</td><td>{d.userPrincipalName ?? "—"}</td><td>{d.operatingSystem} {d.osVersion}</td>
                        <td>{source === "intune" ? d.complianceState : "Defender"}</td><td className="whitespace-nowrap">{fmtDate(d.lastSyncDateTime)}</td>
                        <td><button className="btn-secondary text-xs">Inspect →</button></td>
                      </tr>))}</tbody></table>
                )}
              </div>
            )
      ) : (
        <section className="card p-4">
          <h2 className="section-header">Devices with App Control activity (last 7 days)</h2>
          {summary.isLoading ? <LoadingSpinner label="Querying Advanced Hunting…" /> : summary.isError ? <ErrorBox error={summary.error} /> : summary.data!.results.length === 0 ? (
            <p className="text-xs text-text-muted">No App Control events in the tenant in the last 7 days.</p>
          ) : (
            <table className="data-table"><thead><tr><th>Device</th><th>Blocked</th><th>Audited</th><th>Unique files</th><th>Policies</th><th>Last event</th><th /></tr></thead>
              <tbody>{summary.data!.results.map((r, i) => (
                <tr key={i}>
                  <td className="font-medium text-text-primary">{String(r.DeviceName)}</td>
                  <td className="text-accent-red">{String(r.Blocked)}</td><td className="text-accent-yellow">{String(r.Audited)}</td><td>{String(r.UniqueFiles)}</td>
                  <td className="text-[10px] max-w-xs truncate">{(() => { try { return (JSON.parse(String(r.Policies)) as string[]).filter(Boolean).join(", "); } catch { return String(r.Policies ?? ""); } })()}</td>
                  <td className="whitespace-nowrap">{fmtDate(String(r.LastEvent))}</td>
                  <td><button className="btn-secondary text-xs" onClick={() => setSelected({ id: String(r.DeviceId), deviceName: String(r.DeviceName), mdeDeviceId: String(r.DeviceId) })}>Inspect →</button></td>
                </tr>))}</tbody></table>
          )}
        </section>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Hunting tab
// ---------------------------------------------------------------------------

const PRESETS: Array<{ id: string; label: string; query: () => string }> = [
  { id: "events", label: "App Control events (all devices)", query: () => buildAppControlEventsQuery({ limit: 1000 }) },
  { id: "blocked", label: "Blocked only", query: () => buildAppControlEventsQuery({ blockedOnly: true, limit: 1000 }) },
  { id: "summary", label: "Per-device summary", query: () => buildAppControlDeviceSummaryQuery() },
  { id: "loaded", label: "Policies loaded per device", query: () => buildPoliciesLoadedQuery({}) },
  { id: "topfiles", label: "Top blocked files", query: () => `DeviceEvents\n| where ActionType in ("AppControlCodeIntegrityPolicyBlocked", "AppControlCIScriptBlocked")\n| extend F = parse_json(AdditionalFields)\n| summarize Devices = dcount(DeviceId), Events = count(), LastSeen = max(Timestamp), Publisher = any(tostring(F.PublisherName)) by FileName, SHA256\n| order by Devices desc, Events desc\n| take 100` },
];

function HuntingTab() {
  const navigate = useNavigate();
  const { setImportedEvents } = useAppStore();
  const [query, setQuery] = useState(PRESETS[0].query());
  const [timespan, setTimespan] = useState<HuntingTimespan>("P7D");
  const [result, setResult] = useState<HuntingResultSet | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const run = useMutation({ mutationFn: () => runHuntingQuery(query, timespan), onSuccess: setResult });
  const importEvents = useMutation({
    mutationFn: async () => { const r = await eventsApi.parseHunting(JSON.stringify(result!.results), "json"); setImportedEvents(r.events); return r; },
    onSuccess: (r) => setMsg(`Imported ${r.events.length} events (${r.summary.uniqueFiles} unique files).`),
    onError: (e) => setMsg((e as Error).message),
  });
  const cols = result?.schema.map((c) => c.name) ?? [];
  const looksLikeEvents = cols.includes("ActionType") && cols.includes("FileName");

  return (
    <div className="space-y-4 max-w-6xl">
      <section className="card p-4 space-y-2">
        <div className="flex gap-2 flex-wrap items-center">
          {PRESETS.map((p) => <button key={p.id} className="btn-secondary text-xs" onClick={() => setQuery(p.query())}>{p.label}</button>)}
          <select className="input text-xs py-1 w-auto ml-auto" value={timespan} onChange={(e) => setTimespan(e.target.value as HuntingTimespan)}>
            <option value="P1D">24 hours</option><option value="P7D">7 days</option><option value="P30D">30 days</option>
          </select>
          <button className="btn-ghost text-xs" onClick={() => navigator.clipboard.writeText(query)}><Copy size={12} />Copy</button>
          <button className="btn-primary text-xs" disabled={run.isPending} onClick={() => run.mutate()}><Play size={12} />{run.isPending ? "Running…" : "Run"}</button>
        </div>
        <textarea className="input mono text-xs h-52" spellCheck={false} value={query} onChange={(e) => setQuery(e.target.value)} />
        {run.isError && <ErrorBox error={run.error} />}
      </section>
      {result && (
        <section className="card p-4">
          <div className="flex items-center gap-3 mb-2">
            <span className="text-xs text-text-muted">{result.results.length} rows · {cols.length} columns</span>
            {looksLikeEvents && <button className="btn-primary text-xs ml-auto" disabled={importEvents.isPending || result.results.length === 0} onClick={() => importEvents.mutate()}><Database size={12} />Import into Studio</button>}
            {msg && <button className="btn-ghost text-xs" onClick={() => navigate("/import-events")}>{msg} → Import & Build</button>}
          </div>
          <div className="overflow-auto max-h-[32rem] rounded border border-border">
            <table className="data-table text-[11px]"><thead><tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
              <tbody>{result.results.slice(0, 500).map((r, i) => <tr key={i}>{cols.map((c) => <td key={c} className="max-w-[14rem] truncate" title={String(r[c] ?? "")}>{r[c] === null || r[c] === undefined ? "" : typeof r[c] === "object" ? JSON.stringify(r[c]) : String(r[c])}</td>)}</tr>)}</tbody></table>
          </div>
        </section>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function usePoliciesQuery(enabled: boolean) {
  return useQuery({ queryKey: ["intune-policies"], queryFn: listAppControlPolicies, enabled, staleTime: 5 * 60_000 });
}

export function CloudPage() {
  const [tab, setTab] = useState<Tab>("devices");
  const policiesQuery = usePoliciesQuery(isGraphAvailable);

  if (!isGraphAvailable) {
    return (
      <div className="flex flex-col h-full">
        <Header title="Intune & XDR" subtitle="Review assigned App Control policies and recent blocks from Defender" />
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="max-w-lg">
            <EmptyState icon={<Cloud size={40} />} title="Microsoft sign-in is not configured" description="Set VITE_MSAL_CLIENT_ID and VITE_MSAL_TENANT_ID (client) and MSAL_CLIENT_ID / MSAL_TENANT_ID (server), then grant the app registration these delegated Graph permissions:" />
            <ul className="text-xs mono text-text-secondary space-y-1 mt-2 ml-8 list-disc">{[...GRAPH_SCOPES.intune, ...GRAPH_SCOPES.hunting].map((s) => <li key={s}>{s}</li>)}</ul>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <Header title="Intune & XDR" subtitle="App Control policy assignments from Intune and recent blocks from Defender Advanced Hunting"
        actions={<button className="btn-ghost" onClick={() => policiesQuery.refetch()} disabled={policiesQuery.isFetching}><RefreshCw size={13} className={policiesQuery.isFetching ? "animate-spin" : ""} />Refresh policies</button>} />
      <div className="flex border-b border-border px-6 gap-1 flex-shrink-0">
        {([["devices", "Devices", <Monitor size={14} key="d" />], ["policies", "Policies", <ShieldCheck size={14} key="p" />], ["hunting", "Hunting", <ShieldOff size={14} key="h" />]] as const).map(([id, label, icon]) => (
          <button key={id} onClick={() => setTab(id)} className={clsx("flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium border-b-2 -mb-px transition-colors", tab === id ? "border-accent-blue text-text-primary" : "border-transparent text-text-muted hover:text-text-secondary")}>
            {icon}{label}{id === "policies" && policiesQuery.data && <span className="ml-1 px-1 rounded bg-surface-3 text-text-muted text-xs">{policiesQuery.data.policies.length}</span>}
          </button>
        ))}
      </div>
      <div className="flex-1 overflow-auto p-6">
        {tab === "policies" && <PoliciesTab policiesQuery={policiesQuery} />}
        {tab === "devices" && <DevicesTab policies={policiesQuery.data?.policies} />}
        {tab === "hunting" && <HuntingTab />}
      </div>
    </div>
  );
}
