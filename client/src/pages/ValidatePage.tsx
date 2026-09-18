/**
 * Validate page — AppControl Manager "Validate Policies" parity.
 *
 * Validates the active policy (or a dropped XML file) in four phases:
 * schema, references, content and — on Windows hosts — cipolicy.xsd +
 * ConvertFrom-CIPolicy binary conversion.
 */

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { BadgeCheck, AlertTriangle, XCircle, Info, Upload, Cpu, FileCheck } from "lucide-react";
import clsx from "clsx";
import type { PolicyValidationResult, ValidationFinding, ValidationPhase, ParseDiagnostic } from "@appcontrol/shared";
import { policyApi } from "../lib/api.ts";
import { useActiveSession } from "../store/index.ts";
import { Header } from "../components/layout/Header.tsx";
import { FileDropZone } from "../components/common/FileDropZone.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";

const PHASES: Array<{ id: ValidationPhase; label: string; hint: string }> = [
  { id: "schema", label: "1 · Schema", hint: "cipolicy.xsd constraints: ID patterns, GUIDs, hex, versions" },
  { id: "references", label: "2 · References", hint: "Every ref resolves, no duplicate IDs, no orphans" },
  { id: "content", label: "3 · Content", hint: "Deployability: unsigned policy, supplemental options, scenarios" },
  { id: "toolchain", label: "4 · Toolchain", hint: "cipolicy.xsd + ConvertFrom-CIPolicy (Windows host)" },
];

function SeverityIcon({ s }: { s: ValidationFinding["severity"] }) {
  if (s === "error") return <XCircle size={13} className="text-accent-red flex-shrink-0 mt-0.5" />;
  if (s === "warning") return <AlertTriangle size={13} className="text-accent-yellow flex-shrink-0 mt-0.5" />;
  return <Info size={13} className="text-accent-blue flex-shrink-0 mt-0.5" />;
}

type Result = PolicyValidationResult & { parseDiagnostics: ParseDiagnostic[] };

export function ValidatePage() {
  const active = useActiveSession();
  const [source, setSource] = useState<"active" | "file">(active ? "active" : "file");
  const [fileXml, setFileXml] = useState<{ xml: string; name: string } | null>(null);
  const [useToolchain, setUseToolchain] = useState(true);
  const [filter, setFilter] = useState<"all" | "error" | "warning">("all");

  const run = useMutation({
    mutationFn: (): Promise<Result> =>
      source === "active"
        ? policyApi.validate({ policy: active!.policy, useToolchain })
        : policyApi.validate({ xml: fileXml!.xml, useToolchain }),
  });

  const canRun = source === "active" ? !!active : !!fileXml;
  const r = run.data;
  const findings = (r?.findings ?? []).filter((f) => filter === "all" || f.severity === filter);
  const byPhase = PHASES.map((p) => ({ ...p, items: findings.filter((f) => f.phase === p.id) }));

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Validate Policy"
        subtitle="Prove the policy is schema-valid, internally consistent, and converts to a binary"
        actions={
          <button className="btn-primary" disabled={!canRun || run.isPending} onClick={() => run.mutate()}>
            <BadgeCheck size={13} />
            {run.isPending ? "Validating…" : "Validate"}
          </button>
        }
      />
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-5xl space-y-4">
          <section className="card p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <h2 className="section-header">Source</h2>
              <div className="flex gap-2">
                <button className={clsx("btn text-xs", source === "active" ? "btn-primary" : "btn-secondary")} disabled={!active} onClick={() => setSource("active")}>
                  <FileCheck size={12} /> Active policy{active ? `: ${active.policy.friendlyName ?? active.fileName}` : " (none loaded)"}
                </button>
                <button className={clsx("btn text-xs", source === "file" ? "btn-primary" : "btn-secondary")} onClick={() => setSource("file")}>
                  <Upload size={12} /> XML file
                </button>
              </div>
              {source === "file" && (
                <FileDropZone accept=".xml" label="Drop policy XML" description="Validated exactly as written — no re-serialisation of the model" onFile={(xml, name) => setFileXml({ xml, name })} />
              )}
            </div>
            <div className="space-y-2">
              <h2 className="section-header">Phases</h2>
              {PHASES.map((p) => (
                <div key={p.id} className="text-xs"><span className="font-medium text-text-primary">{p.label}</span> <span className="text-text-muted">— {p.hint}</span></div>
              ))}
              <label className="flex items-center gap-2 text-xs text-text-secondary mt-2">
                <input type="checkbox" checked={useToolchain} onChange={(e) => setUseToolchain(e.target.checked)} />
                <Cpu size={12} /> Run ConvertFrom-CIPolicy when the server is on Windows
              </label>
            </div>
          </section>

          {run.isPending && <LoadingSpinner label="Validating…" />}
          {run.isError && <div className="p-3 bg-accent-red/10 border border-accent-red/20 rounded text-xs text-accent-red">{(run.error as Error).message}</div>}

          {r && (
            <>
              <section className={clsx("rounded-lg p-5 flex items-start gap-4 border", r.valid ? "bg-accent-green/10 border-accent-green/30" : "bg-accent-red/10 border-accent-red/30")}>
                {r.valid ? <BadgeCheck size={28} className="text-accent-green" /> : <XCircle size={28} className="text-accent-red" />}
                <div className="flex-1">
                  <div className={clsx("text-xl font-bold", r.valid ? "text-accent-green" : "text-accent-red")}>{r.valid ? "VALID" : "INVALID"}</div>
                  <div className="flex gap-3 mt-1 text-xs">
                    <button onClick={() => setFilter("all")} className={clsx("tag", filter === "all" ? "tag-blue" : "tag-gray")}>{r.findings.length} findings</button>
                    <button onClick={() => setFilter("error")} className={clsx("tag", filter === "error" ? "tag-red" : "tag-gray")}>{r.summary.errors} errors</button>
                    <button onClick={() => setFilter("warning")} className={clsx("tag", filter === "warning" ? "tag-yellow" : "tag-gray")}>{r.summary.warnings} warnings</button>
                    <span className="tag tag-gray">{r.summary.infos} info</span>
                    <span className="tag tag-gray">{Math.round(r.xmlSizeBytes / 1024)} KB XML</span>
                  </div>
                  <p className="text-xs text-text-secondary mt-2">
                    {r.toolchain.available
                      ? r.toolchain.binaryConverted
                        ? `ConvertFrom-CIPolicy succeeded — binary policy is ${r.toolchain.binarySizeBytes} bytes. XSD ${r.toolchain.xsdValidated ? "passed" : "reported errors"}.`
                        : r.toolchain.binaryError
                          ? `ConvertFrom-CIPolicy failed: ${r.toolchain.binaryError}`
                          : r.toolchain.note ?? "Toolchain ran but returned no result."
                      : r.toolchain.note ?? "Toolchain validation skipped."}
                  </p>
                </div>
              </section>

              {r.parseDiagnostics.length > 0 && (
                <section className="card p-4">
                  <h2 className="section-header">Parser diagnostics</h2>
                  <div className="space-y-1">
                    {r.parseDiagnostics.map((d, i) => (
                      <div key={i} className="flex gap-2 text-xs"><SeverityIcon s={d.severity} /><span className="mono text-text-muted w-52 flex-shrink-0 truncate">{d.code}</span><span className="text-text-secondary">{d.message}</span></div>
                    ))}
                  </div>
                </section>
              )}

              {byPhase.map((p) => (
                <section key={p.id} className="card p-4">
                  <div className="flex items-center justify-between mb-2">
                    <h2 className="section-header mb-0">{p.label}</h2>
                    <span className="text-xs text-text-muted">{p.items.length === 0 ? "no findings" : `${p.items.length} finding${p.items.length === 1 ? "" : "s"}`}</span>
                  </div>
                  {p.items.length > 0 && (
                    <div className="space-y-1.5">
                      {p.items.map((f, i) => (
                        <div key={i} className={clsx("flex gap-2 text-xs p-2 rounded", f.severity === "error" ? "bg-accent-red/5" : f.severity === "warning" ? "bg-accent-yellow/5" : "bg-surface-2")}>
                          <SeverityIcon s={f.severity} />
                          <div className="min-w-0 flex-1">
                            <div className="flex gap-2 items-center flex-wrap">
                              <span className="mono text-text-muted">{f.code}</span>
                              {f.context && <span className="mono text-[10px] bg-surface-3 px-1 rounded text-text-secondary truncate max-w-xs">{f.context}</span>}
                            </div>
                            <p className="text-text-secondary mt-0.5">{f.message}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
