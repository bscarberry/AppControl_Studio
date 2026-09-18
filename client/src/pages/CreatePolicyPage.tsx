/**
 * Create Policy page
 *
 * AppControl Manager parity for "Create AppControl Policy", "Create
 * Supplemental Policy" (blank) and "Create Deny Policy": pick a template,
 * name it, toggle the standard switches (Audit, EV signers, script
 * enforcement, Test mode, HVCI, supplemental policies) and open the result in
 * the editor.
 */

import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { FilePlus, Shield, Layers, Ban, ShieldOff, Info, Download, ArrowRight } from "lucide-react";
import { v4 as uuidv4 } from "uuid";
import clsx from "clsx";
import type { PolicyTemplateInfo, PolicyTemplateId } from "@appcontrol/shared";
import { policyApi } from "../lib/api.ts";
import { useAppStore } from "../store/index.ts";
import { Header } from "../components/layout/Header.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";

const CATEGORY_META: Record<PolicyTemplateInfo["category"], { label: string; icon: React.ReactNode; hint: string }> = {
  base: { label: "Base policies", icon: <Shield size={14} />, hint: "A device needs at least one base policy. Multiple base policies are ANDed." },
  supplemental: { label: "Supplemental", icon: <Layers size={14} />, hint: "Extends one base policy with more allow rules. Needs the base's GUID." },
  block: { label: "Block lists", icon: <ShieldOff size={14} />, hint: "Microsoft-maintained deny lists. Deploy alongside your base policy." },
  deny: { label: "Deny", icon: <Ban size={14} />, hint: "Allow everything except what you explicitly deny." },
};

function Toggle({ label, hint, checked, onChange, disabled }: { label: string; hint: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <label className={clsx("flex items-start gap-3 p-3 rounded border cursor-pointer transition-colors", checked ? "bg-surface-2 border-border" : "bg-surface-1 border-border-muted", disabled && "opacity-40 cursor-not-allowed")}>
      <input type="checkbox" className="mt-0.5" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <div>
        <div className="text-xs font-medium text-text-primary">{label}</div>
        <p className="text-xs text-text-muted mt-0.5">{hint}</p>
      </div>
    </label>
  );
}

export function CreatePolicyPage() {
  const navigate = useNavigate();
  const { addSession } = useAppStore();
  const templatesQuery = useQuery({ queryKey: ["templates"], queryFn: policyApi.templates });
  const [templateId, setTemplateId] = useState<PolicyTemplateId>("allow-microsoft");
  const [name, setName] = useState("New App Control Policy");
  const [basePolicyId, setBasePolicyId] = useState("");
  const [opts, setOpts] = useState({
    auditMode: true,
    requireEvSigners: false,
    enableScriptEnforcement: true,
    testMode: false,
    hvci: false,
    allowSupplemental: true,
  });
  const [status, setStatus] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const template = templatesQuery.data?.templates.find((t) => t.id === templateId);
  useEffect(() => {
    if (template?.id === "deny-all-audit") setOpts((o) => ({ ...o, auditMode: true }));
  }, [template?.id]);

  const create = useMutation({
    mutationFn: () =>
      policyApi.fromTemplate({
        templateId,
        policyName: name.trim() || "New App Control Policy",
        ...(template?.category === "supplemental" ? { basePolicyId: basePolicyId.trim() || undefined } : opts),
      }),
    onSuccess: (data) => {
      addSession({ id: uuidv4(), fileName: `${name.trim() || "policy"}.xml`, policy: data.policy, xml: data.xml, loadedAt: new Date().toISOString() });
      setStatus({ type: "success", message: `Created "${data.policy.friendlyName}" — options ${data.appliedOptions.join(", ")}` });
    },
    onError: (e) => setStatus({ type: "error", message: (e as Error).message }),
  });

  const grouped = (templatesQuery.data?.templates ?? []).reduce<Record<string, PolicyTemplateInfo[]>>((m, t) => {
    (m[t.category] ??= []).push(t);
    return m;
  }, {});

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Create Policy"
        subtitle="Start from a Microsoft template — the same baselines AppControl Manager and the WDAC Wizard use"
        status={status}
        actions={
          create.data ? (
            <div className="flex gap-2">
              <button className="btn-secondary" onClick={() => {
                const blob = new Blob([create.data!.xml], { type: "text/xml" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a"); a.href = url; a.download = `${name.trim() || "policy"}.xml`; a.click();
                URL.revokeObjectURL(url);
              }}><Download size={13} />Download XML</button>
              <button className="btn-primary" onClick={() => navigate("/")}><ArrowRight size={13} />Open in Editor</button>
            </div>
          ) : null
        }
      />

      <div className="flex-1 overflow-auto p-6">
        {templatesQuery.isLoading ? (
          <LoadingSpinner label="Loading templates..." />
        ) : templatesQuery.isError ? (
          <div className="p-3 bg-accent-red/10 border border-accent-red/20 rounded text-xs text-accent-red">{(templatesQuery.error as Error).message}</div>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-6 max-w-6xl">
            {/* Template picker */}
            <div className="space-y-5">
              {(["base", "supplemental", "deny", "block"] as const).map((cat) =>
                grouped[cat]?.length ? (
                  <section key={cat} className="card p-4">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-accent-blue">{CATEGORY_META[cat].icon}</span>
                      <h2 className="section-header mb-0">{CATEGORY_META[cat].label}</h2>
                    </div>
                    <p className="text-xs text-text-muted mb-3">{CATEGORY_META[cat].hint}</p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {grouped[cat].map((t) => (
                        <button
                          key={t.id}
                          onClick={() => setTemplateId(t.id)}
                          className={clsx(
                            "text-left p-3 rounded border transition-colors",
                            templateId === t.id ? "border-accent-blue bg-accent-blue-dim/20" : "border-border hover:border-border-strong bg-surface-2"
                          )}
                        >
                          <div className="text-xs font-semibold text-text-primary">{t.name}</div>
                          <p className="text-xs text-text-muted mt-1 leading-relaxed">{t.description}</p>
                          <div className="flex gap-2 mt-2 text-[10px] text-text-muted mono">
                            <span>{t.ruleCounts.signers} signers</span>
                            <span>{t.ruleCounts.fileRules} rules</span>
                            <span>{t.ruleCounts.options} options</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  </section>
                ) : null
              )}
            </div>

            {/* Options */}
            <div className="space-y-4">
              <section className="card p-4 space-y-3">
                <h2 className="section-header">Policy details</h2>
                <div>
                  <label className="text-xs font-medium text-text-secondary" htmlFor="pname">Policy name</label>
                  <input id="pname" className="input text-xs mt-1" value={name} onChange={(e) => setName(e.target.value)} />
                </div>
                {template?.category === "supplemental" && (
                  <div>
                    <label className="text-xs font-medium text-text-secondary" htmlFor="bpid">Base policy GUID</label>
                    <input id="bpid" className="input text-xs mt-1 mono" placeholder="{00000000-0000-…}" value={basePolicyId} onChange={(e) => setBasePolicyId(e.target.value)} />
                    <p className="text-[11px] text-text-muted mt-1">Find it with <code className="mono">CiTool --list-policies</code> or in the base policy's Overview tab.</p>
                  </div>
                )}
                {template && (
                  <div className="text-[11px] text-text-muted flex items-start gap-1.5">
                    <Info size={11} className="mt-0.5 flex-shrink-0" />
                    <span>Source: {template.source}</span>
                  </div>
                )}
                {template?.notes.map((n, i) => (
                  <p key={i} className="text-[11px] text-accent-yellow flex items-start gap-1.5"><Info size={11} className="mt-0.5 flex-shrink-0" />{n}</p>
                ))}
              </section>

              {template && template.category !== "supplemental" && (
                <section className="card p-4 space-y-2">
                  <h2 className="section-header">Rule options</h2>
                  <Toggle label="Audit mode (option 3)" hint="Log violations without blocking. Recommended for the first deployment." checked={opts.auditMode} disabled={!template.supports.auditMode} onChange={(v) => setOpts({ ...opts, auditMode: v })} />
                  <Toggle label="Require EV signers (option 8)" hint="Kernel drivers must be signed with an Extended Validation certificate." checked={opts.requireEvSigners} disabled={!template.supports.requireEvSigners} onChange={(v) => setOpts({ ...opts, requireEvSigners: v })} />
                  <Toggle label="Enable script enforcement" hint="Unchecking adds option 11 — PowerShell, WSH and MSI run unrestricted." checked={opts.enableScriptEnforcement} disabled={!template.supports.scriptEnforcement} onChange={(v) => setOpts({ ...opts, enableScriptEnforcement: v })} />
                  <Toggle label="Test mode (options 9 + 10)" hint="Keep the Advanced Boot Options menu and boot into audit if the policy fails. Lab devices only." checked={opts.testMode} disabled={!template.supports.testMode} onChange={(v) => setOpts({ ...opts, testMode: v })} />
                  <Toggle label="Allow supplemental policies (option 17)" hint="Let supplemental policies extend this base." checked={opts.allowSupplemental} disabled={!template.supports.allowSupplemental} onChange={(v) => setOpts({ ...opts, allowSupplemental: v })} />
                  <Toggle label="Enable HVCI" hint="Sets HvciOptions=1 (hypervisor-protected code integrity)." checked={opts.hvci} disabled={!template.supports.hvci} onChange={(v) => setOpts({ ...opts, hvci: v })} />
                </section>
              )}

              <button className="btn-primary w-full justify-center" disabled={create.isPending || !template} onClick={() => create.mutate()}>
                <FilePlus size={13} />
                {create.isPending ? "Creating…" : "Create policy"}
              </button>

              {create.data && (
                <section className="card p-4">
                  <h2 className="section-header">Build log</h2>
                  <pre className="mono text-[11px] text-text-secondary whitespace-pre-wrap">{create.data.buildLog.join("\n")}</pre>
                </section>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
