/**
 * File Inspector page
 *
 * AppControl Manager parity for "Get Code Integrity Hashes", "View File
 * Certificates", the Files/Folders scan of "Create Supplemental Policy" and
 * "Create Deny Policy", and file-based "Simulation".
 *
 * Drop binaries → see Authenticode/page/flat hashes, the embedded signature
 * chain with TBS hashes, PE version info → pick a rule level (Hash …
 * WHQLFilePublisher) → add Allow/Deny rules to the active policy, or send the
 * file's metadata straight to the Simulator.
 */

import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  FileSearch, Upload, Hash, Key, Tag, ShieldCheck, ShieldOff, Cpu, PlayCircle, Plus, Trash2,
  ChevronDown, ChevronRight, AlertTriangle, Copy, Check,
} from "lucide-react";
import clsx from "clsx";
import type { InspectedFile, RuleLevel, FileRuleBundle } from "@appcontrol/shared";
import { RULE_LEVELS } from "@appcontrol/shared";
import { filesApi, policyApi } from "../lib/api.ts";
import { useAppStore, useActiveSession } from "../store/index.ts";
import { Header } from "../components/layout/Header.tsx";
import { EmptyState } from "../components/common/EmptyState.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";

function short(h?: string, n = 16) {
  return h ? `${h.slice(0, n)}…` : "—";
}

function CopyHex({ value, label }: { value?: string; label: string }) {
  const [done, setDone] = useState(false);
  if (!value) return <div className="flex justify-between text-xs"><span className="text-text-muted">{label}</span><span className="text-text-muted">—</span></div>;
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-text-muted w-36 flex-shrink-0">{label}</span>
      <code className="mono text-text-secondary truncate flex-1" title={value}>{value}</code>
      <button className="text-text-muted hover:text-text-primary flex-shrink-0" title="Copy" onClick={() => { navigator.clipboard.writeText(value).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }); }}>
        {done ? <Check size={11} className="text-accent-green" /> : <Copy size={11} />}
      </button>
    </div>
  );
}

function FileCard({ file, onRemove, onSimulate }: { file: InspectedFile; onRemove: () => void; onSimulate: () => void }) {
  const [open, setOpen] = useState(false);
  const sig = file.signature.signatures[0];
  return (
    <div className="border border-border rounded overflow-hidden">
      <div className="flex items-center bg-surface-2">
        <button className="flex items-center gap-2 px-3 py-2 text-left hover:bg-surface-3 flex-1 min-w-0" onClick={() => setOpen(!open)}>
          {open ? <ChevronDown size={13} className="text-text-muted" /> : <ChevronRight size={13} className="text-text-muted" />}
          <span className="text-xs font-medium text-text-primary truncate">{file.fileName}</span>
          <span className="tag tag-gray text-[10px]">{file.isPe ? `${file.peKind?.toUpperCase()} · ${file.machine}` : file.fileType}</span>
          {file.isKernelMode && <span className="tag tag-orange text-[10px]"><Cpu size={10} className="mr-1" />kernel</span>}
          {file.signature.status === "embedded"
            ? <span className="tag tag-green text-[10px]"><ShieldCheck size={10} className="mr-1" />{sig?.leaf.subjectCN}</span>
            : <span className="tag tag-yellow text-[10px]"><ShieldOff size={10} className="mr-1" />no embedded signature</span>}
          <span className="text-[10px] text-text-muted mono ml-auto mr-2">{(file.sizeBytes / 1024).toFixed(0)} KB</span>
        </button>
        <button className="px-2 text-text-muted hover:text-accent-blue" title="Simulate this file against the active policy" onClick={onSimulate}><PlayCircle size={13} /></button>
        <button className="px-2 text-text-muted hover:text-accent-red" title="Remove" onClick={onRemove}><Trash2 size={13} /></button>
      </div>
      {open && (
        <div className="p-3 space-y-4 bg-surface-1">
          {file.warnings.length > 0 && (
            <div className="space-y-1">
              {file.warnings.map((w, i) => <div key={i} className="flex gap-2 text-[11px] text-accent-yellow"><AlertTriangle size={11} className="mt-0.5 flex-shrink-0" />{w}</div>)}
            </div>
          )}
          <div>
            <div className="flex items-center gap-1.5 text-xs font-medium text-text-primary mb-1.5"><Hash size={12} /> Code Integrity hashes</div>
            <div className="space-y-1">
              <CopyHex label="Authenticode SHA-256" value={file.hashes.sha256Authenticode} />
              <CopyHex label="Authenticode SHA-1" value={file.hashes.sha1Authenticode} />
              <CopyHex label="Page SHA-256" value={file.hashes.sha256Page} />
              <CopyHex label="Page SHA-1" value={file.hashes.sha1Page} />
              <CopyHex label="Flat SHA-256" value={file.hashes.sha256Flat} />
              <CopyHex label="Flat SHA-1" value={file.hashes.sha1Flat} />
            </div>
          </div>
          {file.versionInfo && (
            <div>
              <div className="flex items-center gap-1.5 text-xs font-medium text-text-primary mb-1.5"><Tag size={12} /> Version resource</div>
              <dl className="grid grid-cols-[9rem_1fr] gap-x-2 gap-y-0.5 text-xs">
                {([["OriginalFilename", file.versionInfo.originalFileName], ["InternalName", file.versionInfo.internalName], ["FileDescription", file.versionInfo.fileDescription], ["ProductName", file.versionInfo.productName], ["CompanyName", file.versionInfo.companyName], ["FileVersion (fixed)", file.versionInfo.fixedFileVersion], ["FileVersion (string)", file.versionInfo.fileVersion]] as const)
                  .filter(([, v]) => v).map(([k, v]) => <><dt key={k + "k"} className="text-text-muted">{k}</dt><dd key={k + "v"} className="text-text-secondary truncate">{v}</dd></>)}
              </dl>
            </div>
          )}
          {file.signature.signatures.map((s) => (
            <div key={s.index}>
              <div className="flex items-center gap-1.5 text-xs font-medium text-text-primary mb-1.5">
                <Key size={12} /> Signature #{s.index} {s.digestAlgorithm && <span className="tag tag-gray text-[10px]">{s.digestAlgorithm}</span>}
                {s.digestMatches === true && <span className="tag tag-green text-[10px]">digest matches</span>}
                {s.digestMatches === false && <span className="tag tag-red text-[10px]">digest mismatch</span>}
                {s.hasTimestamp && <span className="tag tag-gray text-[10px]">timestamped</span>}
                {s.wellknownRootId && <span className="tag tag-blue text-[10px]">Wellknown root {s.wellknownRootId}</span>}
              </div>
              <div className="space-y-1.5">
                {s.chain.map((c, i) => (
                  <div key={c.thumbprint} className={clsx("p-2 rounded border text-[11px]", c.thumbprint === s.pca?.thumbprint ? "border-accent-blue/40 bg-accent-blue/5" : "border-border-muted bg-surface-2")}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-text-muted">{i === 0 ? "Leaf" : c.isSelfSigned ? "Root" : "CA"}</span>
                      <span className="font-medium text-text-primary">{c.subjectCN}</span>
                      {c.thumbprint === s.pca?.thumbprint && <span className="tag tag-blue text-[10px]">CertRoot for Publisher / PcaCertificate</span>}
                      {i === 0 && <span className="tag tag-gray text-[10px]">CertPublisher = "{c.subjectCN}"</span>}
                      <span className="text-text-muted ml-auto">{c.notBefore.slice(0, 10)} → {c.notAfter.slice(0, 10)}</span>
                    </div>
                    <div className="mt-1"><CopyHex label={`TBS (${c.tbsHashAlgorithm})`} value={c.tbsHash} /></div>
                    {c.ekus.length > 0 && <div className="text-text-muted mt-0.5">EKU: {c.ekus.join(", ")}</div>}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function FileInspectorPage() {
  const navigate = useNavigate();
  const active = useActiveSession();
  const { inspectedFiles, setInspectedFiles, updateSessionPolicy } = useAppStore();
  const [level, setLevel] = useState<RuleLevel>("FilePublisher");
  const [effect, setEffect] = useState<"Allow" | "Deny">("Allow");
  const [fallback, setFallback] = useState(true);
  const [bundles, setBundles] = useState<FileRuleBundle[] | null>(null);
  const [status, setStatus] = useState<{ type: "success" | "error" | "warning"; message: string } | null>(null);
  const [dragging, setDragging] = useState(false);

  const inspect = useMutation({
    mutationFn: (files: File[]) => filesApi.inspect(files),
    onSuccess: (data) => {
      const names = new Set(data.files.map((f) => f.fileName));
      setInspectedFiles([...inspectedFiles.filter((f) => !names.has(f.fileName)), ...data.files]);
      setBundles(null);
      setStatus(data.errors.length
        ? { type: "warning", message: `${data.files.length} inspected, ${data.errors.length} failed: ${data.errors.map((e) => e.fileName).join(", ")}` }
        : { type: "success", message: `${data.files.length} file${data.files.length === 1 ? "" : "s"} inspected` });
    },
    onError: (e) => setStatus({ type: "error", message: (e as Error).message }),
  });

  const preview = useMutation({
    mutationFn: () => filesApi.rules(inspectedFiles, level, { effect, fallbackToHash: fallback }),
    onSuccess: (d) => setBundles(d.bundles),
    onError: (e) => setStatus({ type: "error", message: (e as Error).message }),
  });

  const apply = useMutation({
    mutationFn: () => policyApi.tool("apply-rules", { policy: active!.policy, bundles: bundles! }),
    onSuccess: (d) => {
      updateSessionPolicy(active!.id, d.policy);
      setStatus({ type: "success", message: `Added ${d.summary.addedSigners} signer(s), ${d.summary.addedFileRules} file rule(s), ${d.summary.addedEkus} EKU(s) to "${active!.policy.friendlyName ?? active!.fileName}"` });
    },
    onError: (e) => setStatus({ type: "error", message: (e as Error).message }),
  });

  const levelInfo = RULE_LEVELS.find((l) => l.id === level)!;
  const stats = useMemo(() => ({
    signed: inspectedFiles.filter((f) => f.signature.status === "embedded").length,
    kernel: inspectedFiles.filter((f) => f.isKernelMode).length,
  }), [inspectedFiles]);

  const onFiles = (list: FileList | null) => {
    if (!list || list.length === 0) return;
    inspect.mutate(Array.from(list));
  };

  return (
    <div className="flex flex-col h-full">
      <Header
        title="File Inspector"
        subtitle="Code Integrity hashes, certificate chains, and level-based rule generation from real files"
        status={status}
        actions={inspectedFiles.length > 0 ? (
          <button className="btn-ghost" onClick={() => { setInspectedFiles([]); setBundles(null); }}><Trash2 size={13} />Clear</button>
        ) : null}
      />
      <div className="flex-1 overflow-auto p-6">
        <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-6 max-w-7xl">
          <div className="space-y-4 min-w-0">
            <label
              className={clsx("block border-2 border-dashed rounded-lg p-5 text-center cursor-pointer transition-colors", dragging ? "border-accent-blue bg-accent-blue-dim/20" : "border-border hover:border-border-strong bg-surface-2")}
              onDragEnter={(e) => { e.preventDefault(); setDragging(true); }}
              onDragOver={(e) => e.preventDefault()}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); onFiles(e.dataTransfer.files); }}
            >
              <input type="file" multiple className="hidden" onChange={(e) => { onFiles(e.target.files); e.currentTarget.value = ""; }} />
              <Upload size={22} className="mx-auto text-text-muted mb-1.5" />
              <p className="text-sm font-medium text-text-primary">Drop executables, DLLs, drivers, scripts or MSI files</p>
              <p className="text-xs text-text-muted mt-0.5">Processed in memory on the server — nothing is written to disk. Up to 200 files, 200 MB each, 512 MB per upload.</p>
            </label>

            {inspect.isPending && <LoadingSpinner label="Hashing and parsing signatures…" />}

            {inspectedFiles.length === 0 && !inspect.isPending ? (
              <EmptyState icon={<FileSearch size={36} />} title="No files inspected yet" description="Drop files above to compute Authenticode hashes, read embedded certificates, and generate rules at any level." />
            ) : (
              <div className="space-y-1.5">
                <div className="flex gap-3 text-xs text-text-muted px-1">
                  <span>{inspectedFiles.length} files</span><span>{stats.signed} with embedded signature</span><span>{stats.kernel} kernel-mode</span>
                </div>
                {inspectedFiles.map((f) => (
                  <FileCard
                    key={f.fileName}
                    file={f}
                    onRemove={() => setInspectedFiles(inspectedFiles.filter((x) => x.fileName !== f.fileName))}
                    onSimulate={() => {
                      sessionStorage.setItem("acs.simulate.prefill", JSON.stringify(f.simulationMetadata));
                      navigate("/simulator");
                    }}
                  />
                ))}
              </div>
            )}
          </div>

          <div className="space-y-4">
            <section className="card p-4 space-y-3">
              <h2 className="section-header">Generate rules</h2>
              <div>
                <label className="text-xs font-medium text-text-secondary" htmlFor="lvl">Rule level</label>
                <select id="lvl" className="input text-xs mt-1" value={level} onChange={(e) => { setLevel(e.target.value as RuleLevel); setBundles(null); }}>
                  {RULE_LEVELS.map((l) => <option key={l.id} value={l.id}>{l.label}</option>)}
                </select>
                <p className="text-[11px] text-text-muted mt-1">{levelInfo.description}</p>
              </div>
              <div className="flex gap-2">
                {(["Allow", "Deny"] as const).map((e) => (
                  <button key={e} onClick={() => { setEffect(e); setBundles(null); }} className={clsx("btn text-xs flex-1 justify-center", effect === e ? (e === "Allow" ? "bg-accent-green-dim text-accent-green" : "bg-accent-red-dim text-accent-red") : "btn-secondary")}>{e}</button>
                ))}
              </div>
              <label className="flex items-center gap-2 text-xs text-text-secondary">
                <input type="checkbox" checked={fallback} onChange={(e) => { setFallback(e.target.checked); setBundles(null); }} />
                Fall back to Hash when the level is not possible
              </label>
              <button className="btn-secondary w-full justify-center" disabled={inspectedFiles.length === 0 || preview.isPending} onClick={() => preview.mutate()}>
                {preview.isPending ? "Building…" : "Preview rules"}
              </button>
            </section>

            {bundles && (
              <section className="card p-4 space-y-2">
                <h2 className="section-header">Preview</h2>
                <div className="space-y-1.5 max-h-80 overflow-auto">
                  {bundles.map((b) => (
                    <div key={b.fileName} className={clsx("p-2 rounded border text-[11px]", b.skippedReason ? "border-accent-red/30 bg-accent-red/5" : "border-border-muted bg-surface-2")}>
                      <div className="flex items-center gap-2">
                        <span className="font-medium text-text-primary truncate flex-1">{b.fileName}</span>
                        <span className={clsx("tag text-[10px]", b.effectiveLevel === b.requestedLevel ? "tag-blue" : "tag-yellow")}>{b.effectiveLevel}</span>
                        <span className="tag tag-gray text-[10px]">{b.scenario === 131 ? "kernel" : "user"}</span>
                      </div>
                      <div className="text-text-muted mt-0.5">{b.signers.length} signer · {b.fileRules.filter((r) => r.kind !== "fileAttrib").length} rule · {b.fileRules.filter((r) => r.kind === "fileAttrib").length} FileAttrib · {b.ekus.length} EKU</div>
                      {b.notes.map((n, i) => <div key={i} className="text-accent-yellow mt-0.5">{n}</div>)}
                      {b.skippedReason && <div className="text-accent-red mt-0.5">Skipped: {b.skippedReason}</div>}
                    </div>
                  ))}
                </div>
                <button className="btn-primary w-full justify-center" disabled={!active || apply.isPending} onClick={() => apply.mutate()} title={active ? undefined : "Load or create a policy first"}>
                  <Plus size={13} />{active ? `Add to "${active.policy.friendlyName ?? active.fileName}"` : "No active policy"}
                </button>
                {!active && <p className="text-[11px] text-text-muted">Create or load a policy, then come back — the inspected files stay here.</p>}
              </section>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
