/**
 * Policy identity editor — AppControl Manager "Policy Editor → Details":
 * Name, PolicyID, BasePolicyID, Version, HVCI, Type, PolicyInfo Id, format.
 */

import { useState } from "react";
import { RefreshCw, AlertTriangle } from "lucide-react";
import type { WdacPolicy } from "@appcontrol/shared";
import { newGuid, isValidGuid, normalizeGuid, setPolicyType } from "@appcontrol/shared";
import clsx from "clsx";

interface Props {
  policy: WdacPolicy;
  onChange: (p: WdacPolicy) => void;
}

const VERSION_RE = /^\d+\.\d+\.\d+\.\d+$/;

function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string | null; children: React.ReactNode }) {
  return (
    <div>
      <label className="text-xs font-medium text-text-secondary">{label}</label>
      <div className="mt-1">{children}</div>
      {error ? <p className="text-xs text-accent-red mt-0.5">{error}</p> : hint ? <p className="text-[11px] text-text-muted mt-0.5">{hint}</p> : null}
    </div>
  );
}

export function PolicyIdentityEditor({ policy, onChange }: Props) {
  const [policyId, setPolicyId] = useState(policy.policyId);
  const [basePolicyId, setBasePolicyId] = useState(policy.basePolicyId ?? "");
  const isSupp = policy.policyType === "Supplemental";
  const isSingle = policy.policyFormat === "SinglePolicy";

  const pidErr = !isValidGuid(policyId) ? "Must be a GUID (with or without braces)." : null;
  const bidErr = isSupp && !isValidGuid(basePolicyId) ? "Supplemental policies need the base policy's GUID." : (basePolicyId && !isValidGuid(basePolicyId) ? "Must be a GUID." : null);
  const verErr = !VERSION_RE.test(policy.versionEx) ? "Four dot-separated numbers, e.g. 1.0.0.0" : null;

  const commitPolicyId = () => {
    const g = normalizeGuid(policyId);
    if (!g) return;
    onChange({ ...policy, policyId: g, basePolicyId: isSupp ? policy.basePolicyId : g });
    setPolicyId(g);
    if (!isSupp) setBasePolicyId(g);
  };
  const commitBaseId = () => {
    const g = normalizeGuid(basePolicyId);
    if (!g) return;
    onChange({ ...policy, basePolicyId: g });
    setBasePolicyId(g);
  };

  return (
    <div className="max-w-2xl space-y-5">
      <section className="card p-4 space-y-4">
        <h2 className="section-header">Identity</h2>
        <Field label="Friendly name" hint="Written as the SiPolicy FriendlyName attribute and the PolicyInfo Name setting.">
          <input className="input text-xs" value={policy.friendlyName ?? ""} onChange={(e) => onChange({ ...policy, friendlyName: e.target.value || undefined })} />
        </Field>
        <Field label="PolicyInfo Id" hint="Optional short identifier stored in <Settings> (e.g. a build or ticket number).">
          <input className="input text-xs" value={policy.settingsId ?? ""} onChange={(e) => onChange({ ...policy, settingsId: e.target.value || undefined })} />
        </Field>
        <Field label="Version (VersionEx)" error={verErr}>
          <input className="input text-xs mono" value={policy.versionEx} onChange={(e) => onChange({ ...policy, versionEx: e.target.value })} />
        </Field>
      </section>

      <section className="card p-4 space-y-4">
        <h2 className="section-header">Type and GUIDs</h2>
        <Field label="Policy type">
          <div className="flex gap-2">
            {(["Base", "Supplemental"] as const).map((t) => (
              <button key={t} className={clsx("btn text-xs", policy.policyType === t ? "btn-primary" : "btn-secondary")} disabled={policy.policyType === t}
                onClick={() => { const p = setPolicyType(policy, t, basePolicyId); onChange(p); setBasePolicyId(p.basePolicyId ?? ""); }}>{t}</button>
            ))}
            <span className={clsx("tag ml-auto", isSingle ? "tag-yellow" : "tag-gray")}>{isSingle ? "Single-policy format (legacy)" : "Multiple-policy format"}</span>
          </div>
          {isSupp && <p className="text-[11px] text-accent-yellow mt-1 flex gap-1"><AlertTriangle size={11} className="mt-0.5" />Switching type filters rule options: supplemental policies keep only options 5, 6, 7, 13, 14 and 18.</p>}
        </Field>
        {isSingle && (
          <p className="text-[11px] text-text-muted">This policy uses PolicyTypeID instead of PolicyID/BasePolicyID. Switching to the multiple-policy format below assigns a PolicyID.</p>
        )}
        <Field label="PolicyID" error={pidErr} hint="Changing the PolicyID makes Windows treat this as a new policy on deployment.">
          <div className="flex gap-2">
            <input className="input text-xs mono" value={policyId} onChange={(e) => setPolicyId(e.target.value)} onBlur={commitPolicyId} />
            <button className="btn-secondary text-xs flex-shrink-0" title="New GUID" onClick={() => { const g = newGuid(); setPolicyId(g); onChange({ ...policy, policyId: g, basePolicyId: isSupp ? policy.basePolicyId : g, policyFormat: "MultiplePolicy" }); if (!isSupp) setBasePolicyId(g); }}>
              <RefreshCw size={12} />
            </button>
          </div>
        </Field>
        <Field label="BasePolicyID" error={bidErr} hint={isSupp ? "GUID of the base policy this supplement extends." : "Base policies reference themselves."}>
          <input className="input text-xs mono" value={basePolicyId} disabled={!isSupp} onChange={(e) => setBasePolicyId(e.target.value)} onBlur={commitBaseId} />
        </Field>
        {isSingle && (
          <button className="btn-secondary text-xs" onClick={() => { const g = newGuid(); onChange({ ...policy, policyFormat: "MultiplePolicy", policyId: g, basePolicyId: g, policyTypeId: undefined }); setPolicyId(g); setBasePolicyId(g); }}>
            Convert to multiple-policy format
          </button>
        )}
      </section>

      <section className="card p-4 space-y-4">
        <h2 className="section-header">Platform</h2>
        <Field label="HVCI options" hint="0 = off, 1 = enabled, 2 = strict, 4 = debug mode. Written to <HvciOptions>.">
          <select className="input text-xs" value={policy.hvciOptions ?? 0} onChange={(e) => onChange({ ...policy, hvciOptions: parseInt(e.target.value, 10) })}>
            <option value={0}>0 — Off</option>
            <option value={1}>1 — Enabled</option>
            <option value={2}>2 — Strict</option>
            <option value={3}>3 — Enabled + Strict</option>
            <option value={4}>4 — Debug mode</option>
          </select>
        </Field>
        <Field label="PlatformID" hint="Leave the default Windows platform GUID unless you know why.">
          <input className="input text-xs mono" value={policy.platformId ?? ""} placeholder="2E07F7E4-194C-4D20-B7C9-6F44A6C5A234" onChange={(e) => onChange({ ...policy, platformId: normalizeGuid(e.target.value) ?? (e.target.value || undefined) })} />
        </Field>
        {policy.settings && policy.settings.filter((s) => s.provider !== "PolicyInfo").length > 0 && (
          <div>
            <label className="text-xs font-medium text-text-secondary">Preserved settings</label>
            <div className="mt-1 space-y-1">
              {policy.settings.filter((s) => s.provider !== "PolicyInfo").map((s, i) => (
                <div key={i} className="flex items-center gap-2 text-[11px] bg-surface-2 rounded px-2 py-1">
                  <span className="mono text-text-muted truncate">{s.provider}/{s.key}/{s.valueName}</span>
                  <span className="mono text-text-secondary ml-auto">{s.valueType}={s.value}</span>
                  <button className="text-text-muted hover:text-accent-red" title="Remove" onClick={() => onChange({ ...policy, settings: policy.settings!.filter((x) => x !== s) })}>×</button>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
