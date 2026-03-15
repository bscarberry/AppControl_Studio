import { useState, useRef, useMemo } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Upload, AlertCircle, CheckCircle, Clock, Shield, ShieldAlert,
  ChevronDown, ChevronRight, AlertTriangle, Hash, FileWarning,
  Server, Eye, HelpCircle, Activity, Search, File as FileIcon,
  Key, Tag,
} from "lucide-react";
import clsx from "clsx";
import { v4 as uuidv4 } from "uuid";
import { eventsApi, policyApi } from "../lib/api.ts";
import { useAppStore } from "../store/index.ts";
import { Header } from "../components/layout/Header.tsx";
import { FileDropZone } from "../components/common/FileDropZone.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import type {
  ParsedCiEvent, EventImportResult,
  HuntingBinary, HuntingImportResult, HuntingImportWarning,
  HuntingRuleCandidate, HuntingRuleRisk, HuntingRuleType, HuntingSigningCoverage,
  CreatePolicyFromEventsResponse, FileRuleType, FileRuleSelection,
} from "@appcontrol/shared";

type PageTab = "ci-events" | "advanced-hunting" | "build-policy";

// ===========================================================================
// CI EVENTS TAB
// ===========================================================================

type ImportFormat = "evtx-json" | "json" | "evtx";

const FORMAT_OPTIONS = [
  { id: "evtx-json" as ImportFormat, label: "EVTX JSON Export",   description: "Get-WinEvent ... | ConvertTo-Json", accept: ".json" },
  { id: "evtx"     as ImportFormat, label: "EVTX Binary File",    description: "Raw .evtx event log — parsed natively on the server", accept: ".evtx" },
];

function CollectionInstructions({ format }: { format: ImportFormat }) {
  const commands: Record<ImportFormat, { title: string; code: string }> = {
    "evtx-json": {
      title: "Collect CodeIntegrity Events — Named-Field Format (Recommended)",
      code: `# Exports events with named fields — hashes, publisher TBS, and file attributes are\n# correctly extracted. Pipe to a file on the monitored machine, then import here.\n\n$ids = @(3033,3034,3036,3064,3065,3076,3077,3079,3080,3082,3089,3091,3092,3111,3114)\nGet-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -Oldest |\n  Where-Object { $_.Id -in $ids } |\n  ForEach-Object {\n    $xml = [xml]$_.ToXml()\n    $fields = @{}\n    foreach ($d in $xml.Event.EventData.Data) {\n      if ($d.Name) { $fields[$d.Name] = $d.'#text' }\n    }\n    [PSCustomObject]@{\n      EventId     = $_.Id\n      TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')\n      MachineName = $_.MachineName\n      ActivityId  = if ($_.ActivityId) { $_.ActivityId.ToString('B').ToUpper() } else { $null }\n      Level       = $_.Level\n      Fields      = $fields\n    }\n  } | ConvertTo-Json -Depth 5 | Out-File -FilePath '.\\ci-events.json' -Encoding utf8`,
    },
    json: {
      title: "Collect Events — Legacy Positional Format",
      code: `# Standard Get-WinEvent output — hashes are byte arrays that the parser\n# converts automatically. File attribute fields may be absent on older Windows.\n\nGet-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -Oldest |\n  Where-Object { $_.Id -in @(3076,3077,3033,3034,3089,3092) } |\n  ConvertTo-Json -Depth 5 |\n  Out-File -FilePath ".\\ci-events.json" -Encoding utf8`,
    },
    "evtx": {
      title: "Locate your EVTX file",
      code: `# The CodeIntegrity operational log is typically at:\nC:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-CodeIntegrity%4Operational.evtx\n\n# Or copy it first (the live log may be locked):\nwevtutil epl "Microsoft-Windows-CodeIntegrity/Operational" .\\ci-events.evtx`,
    },
  };
  const { title, code } = commands[format];
  return (
    <div className="card p-4 mb-5">
      <h2 className="section-header">Collection Instructions</h2>
      <p className="text-xs font-medium text-text-secondary mb-2">{title}</p>
      <pre className="mono text-xs bg-surface-2 p-3 rounded border border-border text-accent-blue overflow-auto">{code}</pre>
    </div>
  );
}

function SummaryCard({ label, value, color }: { label: string; value: number; color?: "red" | "yellow" | "blue" | "green" }) {
  const colorClass = color
    ? { red: "text-accent-red", yellow: "text-accent-yellow", blue: "text-accent-blue", green: "text-accent-green" }[color]
    : "text-text-primary";
  return (
    <div className="bg-surface-2 rounded p-3 text-center">
      <p className={clsx("text-xl font-bold mono", colorClass)}>{value}</p>
      <p className="text-xs text-text-muted">{label}</p>
    </div>
  );
}

function fmtTimestamp(ts: string): string {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString(undefined, { dateStyle: "short", timeStyle: "medium" });
  } catch {
    return ts;
  }
}

function fmtHash(h: string | undefined): string {
  if (!h) return "—";
  return `${h.substring(0, 16)}…`;
}

function EventRow({ event }: { event: ParsedCiEvent }) {
  // Use sha256FlatHash (EVTX) or fall back to sha256Hash (Advanced Hunting)
  const hash = event.sha256FlatHash ?? event.sha256Hash;
  const publisher = event.signerInfo?.publisherName;
  const publisherCn = publisher
    ? (publisher.match(/CN=([^,]+)/)?.[1] ?? publisher.substring(0, 30))
    : undefined;
  const policyLabel = event.policyName ?? event.policyId;

  return (
    <tr>
      <td>
        {event.severity === "block"
          ? <span className="tag tag-red flex items-center gap-1"><ShieldAlert size={10} />Block</span>
          : event.severity === "audit"
          ? <span className="tag tag-yellow flex items-center gap-1"><Shield size={10} />Audit</span>
          : <span className="tag tag-gray">Info</span>}
      </td>
      <td className="mono text-xs text-text-muted whitespace-nowrap">{fmtTimestamp(event.timestamp)}</td>
      <td className="text-xs text-text-secondary truncate max-w-[120px]" title={event.machineName}>{event.machineName ?? "—"}</td>
      <td className="text-xs max-w-xs">
        <p className="truncate" title={event.filePath}>{event.fileName ?? event.filePath}</p>
        {event.productName && <p className="text-text-muted truncate text-[10px]">{event.productName}</p>}
      </td>
      <td className="mono text-xs text-text-muted">{fmtHash(hash)}</td>
      <td className="text-xs">
        {publisherCn
          ? <span className="flex items-center gap-1 text-accent-blue"><Key size={10} className="flex-shrink-0" /><span className="truncate max-w-[120px]" title={publisher}>{publisherCn}</span></span>
          : event.originalFileName
          ? <span className="flex items-center gap-1 text-text-secondary"><Tag size={10} /><span className="truncate max-w-[120px]">{event.originalFileName}</span></span>
          : <span className="text-text-muted">Unsigned</span>}
      </td>
      <td className="text-xs max-w-[140px]">
        {policyLabel
          ? <span className="truncate block text-text-secondary" title={`${policyLabel}${event.policyGuid ? `\n${event.policyGuid}` : ""}`}>{policyLabel}</span>
          : event.policyGuid
          ? <span className="mono text-text-muted truncate block" title={event.policyGuid}>{event.policyGuid.substring(0, 8)}…</span>
          : <span className="text-text-muted">—</span>}
      </td>
      <td className="mono text-xs text-text-muted">{event.eventId}</td>
    </tr>
  );
}

function EventImportResults({ result }: { result: EventImportResult }) {
  const { summary, events, parseErrors } = result;

  const fmtTime = (ts: string) => {
    try { return new Date(ts).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" }); }
    catch { return ts; }
  };

  const withPublisher = events.filter((e) => e.signerInfo?.publisherName).length;

  return (
    <div className="space-y-4">
      <div className="card p-4">
        <h2 className="section-header">Import Summary</h2>
        <div className="grid grid-cols-5 gap-3">
          <SummaryCard label="Total Events" value={summary.totalEvents} />
          <SummaryCard label="Block Events" value={summary.blockEvents} color="red" />
          <SummaryCard label="Audit Events" value={summary.auditEvents} color="yellow" />
          <SummaryCard label="Unique Files" value={summary.uniqueFiles} color="blue" />
          <SummaryCard label="With Publisher" value={withPublisher} color="green" />
        </div>
        {summary.timeRange && (
          <p className="text-xs text-text-muted mt-3 flex items-center gap-1.5">
            <Clock size={11} />
            <span>{fmtTime(summary.timeRange.earliest)}</span>
            <span>—</span>
            <span>{fmtTime(summary.timeRange.latest)}</span>
          </p>
        )}
      </div>
      {parseErrors.length > 0 && (
        <div className="card p-4 border-accent-yellow/30">
          <h2 className="section-header text-accent-yellow">Parse Warnings ({parseErrors.length})</h2>
          <div className="space-y-1">
            {parseErrors.slice(0, 10).map((err, i) => (
              <p key={i} className="text-xs text-text-muted">
                {err.line !== undefined && <span className="mono mr-2">L{err.line}</span>}{err.message}
              </p>
            ))}
            {parseErrors.length > 10 && <p className="text-xs text-text-muted italic">…and {parseErrors.length - 10} more</p>}
          </div>
        </div>
      )}
      <div className="card p-4">
        <h2 className="section-header">Events ({events.length})</h2>
        <div className="overflow-auto max-h-[480px]">
          <table className="data-table">
            <thead className="sticky top-0 bg-surface-1">
              <tr>
                <th>Severity</th>
                <th>Time</th>
                <th>Machine</th>
                <th>File / Product</th>
                <th>SHA256 (flat)</th>
                <th>Publisher / Filename</th>
                <th>Policy</th>
                <th>Event ID</th>
              </tr>
            </thead>
            <tbody>{events.map((event, i) => <EventRow key={i} event={event} />)}</tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function EvtxBinaryDropZone({ onFile }: { onFile: (file: File) => void }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [loadedFile, setLoadedFile] = useState<string | null>(null);

  const handleFile = (file: File) => { setLoadedFile(file.name); onFile(file); };

  return (
    <div
      className={clsx(
        "relative border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors",
        isDragging ? "border-accent-blue bg-accent-blue-dim/20"
          : loadedFile ? "border-accent-green bg-accent-green-dim/10"
          : "border-border hover:border-border-strong bg-surface-2"
      )}
      onClick={() => inputRef.current?.click()}
      onDragEnter={(e) => { e.preventDefault(); setIsDragging(true); }}
      onDragLeave={() => setIsDragging(false)}
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => { e.preventDefault(); setIsDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
    >
      <input ref={inputRef} type="file" accept=".evtx" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); e.currentTarget.value = ""; }}
        onClick={(e) => (e.currentTarget.value = "")} />
      {loadedFile ? (
        <div className="flex flex-col items-center gap-2">
          <FileIcon size={24} className="text-accent-green" />
          <p className="text-sm font-medium text-text-primary mono">{loadedFile}</p>
          <p className="text-xs text-text-muted">Click to replace</p>
        </div>
      ) : (
        <div className="flex flex-col items-center gap-2">
          <Upload size={24} className="text-text-muted" />
          <p className="text-sm font-medium text-text-primary">Drop EVTX Binary File</p>
          <p className="text-xs text-text-muted">Windows Event Log (.evtx) — parsed natively on the server</p>
          <p className="text-xs text-text-muted mt-1">Drag & drop or click to browse</p>
        </div>
      )}
    </div>
  );
}

function CiEventsTab() {
  const { setImportedEvents, importedEvents, clearEvents } = useAppStore();
  const [format, setFormat] = useState<ImportFormat>("evtx-json");
  const [result, setResult] = useState<EventImportResult | null>(null);

  type ParseArgs = { kind: "text"; content: string; format: "evtx-json" | "json" } | { kind: "binary"; file: File };

  const parseMutation = useMutation({
    mutationFn: (args: ParseArgs) => {
      if (args.kind === "binary") return eventsApi.parseEvtxBinary(args.file);
      return eventsApi.parse(args.content, args.format);
    },
    onSuccess: (data) => { setResult(data); setImportedEvents(data.events); },
  });

  const selectedFormat = FORMAT_OPTIONS.find((f) => f.id === format)!;

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="max-w-3xl">
        {importedEvents.length > 0 && (
          <div className="flex items-center justify-between mb-4">
            <span className="text-xs text-text-muted">{importedEvents.length} events loaded</span>
            <button className="btn-ghost" onClick={() => { clearEvents(); setResult(null); }}>Clear</button>
          </div>
        )}
        <div className="card p-4 mb-5">
          <h2 className="section-header">Input Format</h2>
          <div className="grid grid-cols-2 gap-2">
            {FORMAT_OPTIONS.map((opt) => (
              <button key={opt.id} onClick={() => setFormat(opt.id)}
                className={clsx("text-left p-3 rounded border text-xs transition-colors",
                  format === opt.id ? "border-accent-blue bg-accent-blue-dim/20 text-text-primary" : "border-border text-text-muted hover:border-border-strong hover:text-text-secondary")}>
                <p className="font-medium text-sm mb-0.5">{opt.label}</p>
                <p className="text-text-muted">{opt.description}</p>
              </button>
            ))}
          </div>
        </div>
        <CollectionInstructions format={format} />
        <div className="mb-5">
          {format === "evtx" ? (
            <EvtxBinaryDropZone onFile={(file) => parseMutation.mutate({ kind: "binary", file })} />
          ) : (
            <FileDropZone accept={selectedFormat.accept} label={`Drop ${selectedFormat.label}`}
              description={selectedFormat.description}
              onFile={(content) => parseMutation.mutate({ kind: "text", content, format: format as "evtx-json" | "json" })} />
          )}
        </div>
        {parseMutation.isPending && <div className="flex justify-center py-8"><LoadingSpinner label="Parsing events..." /></div>}
        {parseMutation.isError && (
          <div className="p-4 bg-accent-red-dim/30 border border-accent-red/20 rounded text-sm text-accent-red mb-4">
            {(parseMutation.error as Error).message}
          </div>
        )}
        {result && <EventImportResults result={result} />}
      </div>
    </div>
  );
}

// ===========================================================================
// ADVANCED HUNTING TAB
// ===========================================================================

function riskClass(risk: HuntingRuleRisk): string {
  return { safe: "tag-green", low: "tag-blue", medium: "tag-yellow", high: "tag-orange", critical: "tag-red" }[risk];
}
function coverageClass(coverage: HuntingSigningCoverage): string {
  return { full: "tag-green", partial: "tag-yellow", "hash-only": "tag-blue", unsigned: "tag-orange", "no-hash": "tag-red" }[coverage];
}
function ruleTypeLabel(t: HuntingRuleType): string {
  return { "publisher-scoped": "Publisher (scoped)", publisher: "Publisher", hash: "Hash", path: "Path", "path-wildcard": "Path (wildcard)" }[t];
}
function ruleTypeIcon(t: HuntingRuleType) {
  if (t === "publisher-scoped" || t === "publisher") return <Shield size={13} />;
  if (t === "hash") return <Hash size={13} />;
  return <FileWarning size={13} />;
}

function HuntingFileDropZone({ onFile, label }: { onFile: (content: string, name: string) => void; label: string }) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  function handleFile(file: File) {
    const reader = new FileReader();
    reader.onload = (e) => onFile((e.target?.result as string) ?? "", file.name);
    reader.readAsText(file, "utf-8");
  }
  return (
    <div onClick={() => inputRef.current?.click()}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => { e.preventDefault(); setDragging(false); const f = e.dataTransfer.files[0]; if (f) handleFile(f); }}
      className={clsx("border-2 border-dashed rounded-lg p-8 cursor-pointer text-center transition-colors",
        dragging ? "border-accent-blue bg-accent-blue-dim" : "border-border hover:border-accent-blue hover:bg-surface-2")}>
      <Upload size={28} className="mx-auto mb-2 text-text-muted" />
      <p className="text-sm text-text-secondary">{label}</p>
      <p className="text-xs text-text-muted mt-1">JSON or CSV · drag & drop or click</p>
      <input ref={inputRef} type="file" accept=".json,.csv,.txt" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) handleFile(f); e.target.value = ""; }} />
    </div>
  );
}

function HuntingStatsBar({ result }: { result: HuntingImportResult }) {
  const { stats } = result;
  const items = [
    { label: "Rows parsed",      value: stats.totalRowsParsed },
    { label: "Valid rows",       value: stats.validRows },
    { label: "Unique binaries",  value: stats.uniqueBinaries },
    { label: "Signed",           value: stats.signedBinaries,          colorClass: "text-accent-green" },
    { label: "Partial signing",  value: stats.partialSigningBinaries,  colorClass: "text-accent-yellow" },
    { label: "Unsigned",         value: stats.unsignedBinaries,        colorClass: "text-accent-orange" },
    { label: "No hash",          value: stats.noHashBinaries,          colorClass: "text-accent-red" },
    { label: "Rule candidates",  value: result.ruleCandidates.length,  colorClass: "text-accent-blue" },
  ];
  return (
    <div className="panel">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-medium text-text-secondary uppercase tracking-wider">Import Summary</p>
        <span className="tag tag-blue text-xs">{stats.detectedSchema}</span>
      </div>
      <div className="grid grid-cols-4 gap-3">
        {items.map((item) => (
          <div key={item.label} className="bg-surface-2 rounded p-2.5">
            <p className={clsx("text-lg font-semibold tabular-nums", item.colorClass ?? "text-text-primary")}>{item.value.toLocaleString()}</p>
            <p className="text-xs text-text-muted mt-0.5">{item.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function HuntingWarningsPanel({ warnings }: { warnings: HuntingImportWarning[] }) {
  const [open, setOpen] = useState(true);
  if (warnings.length === 0) return null;
  return (
    <div className="panel border-l-2 border-accent-yellow">
      <button onClick={() => setOpen((v) => !v)} className="flex items-center gap-2 w-full text-left">
        <AlertTriangle size={14} className="text-accent-yellow flex-shrink-0" />
        <span className="text-sm font-medium text-text-primary flex-1">Import Warnings ({warnings.length})</span>
        {open ? <ChevronDown size={14} className="text-text-muted" /> : <ChevronRight size={14} className="text-text-muted" />}
      </button>
      {open && (
        <div className="mt-3 space-y-2">
          {warnings.map((w, i) => (
            <div key={i} className="bg-surface-2 rounded p-2.5 flex items-start gap-2">
              <span className="tag tag-yellow mt-0.5 flex-shrink-0">{w.code}</span>
              <p className="text-xs text-text-secondary">{w.message}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const colorClass = pct >= 80 ? "bg-accent-green" : pct >= 60 ? "bg-accent-yellow" : "bg-accent-red";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-surface-3 rounded-full overflow-hidden">
        <div className={clsx("h-full rounded-full", colorClass)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs tabular-nums text-text-muted w-8 text-right">{pct}%</span>
    </div>
  );
}

function HuntingRuleCandidateCard({ candidate }: { candidate: HuntingRuleCandidate }) {
  const [expanded, setExpanded] = useState(false);
  const { binary } = candidate;
  const primaryLabel =
    candidate.ruleType === "publisher-scoped" || candidate.ruleType === "publisher"
      ? binary.signerNames[0] ?? "Unknown publisher"
      : candidate.ruleType === "hash"
      ? (binary.sha256?.substring(0, 32) ?? binary.sha1?.substring(0, 32) ?? "—") + "…"
      : binary.filePaths[0] ?? binary.fileNames[0] ?? "—";

  return (
    <div className="panel">
      <div className="flex items-start gap-2">
        <div className="flex items-center gap-1.5 flex-shrink-0 mt-0.5">
          <span className={clsx("tag flex items-center gap-1", riskClass(candidate.risk))}>{ruleTypeIcon(candidate.ruleType)}{ruleTypeLabel(candidate.ruleType)}</span>
          <span className={clsx("tag", riskClass(candidate.risk))}>{candidate.risk}</span>
          <span className={clsx("tag", candidate.effect === "Allow" ? "tag-green" : "tag-red")}>{candidate.effect}</span>
          {candidate.appliesToKernelMode && <span className="tag tag-orange" title="Kernel-mode driver">KM</span>}
        </div>
        <div className="flex-1 min-w-0 ml-1">
          <p className="text-sm font-medium text-text-primary truncate">{primaryLabel}</p>
          {binary.fileNames.length > 0 && candidate.ruleType !== "path" && candidate.ruleType !== "path-wildcard" && (
            <p className="text-xs text-text-muted mt-0.5 truncate">
              {binary.fileNames.slice(0, 2).join(", ")}{binary.fileNames.length > 2 ? ` +${binary.fileNames.length - 2} more` : ""}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3 flex-shrink-0 ml-2">
          <div className="text-right">
            <div className="flex items-center gap-1 text-xs text-text-muted mb-1">
              <Server size={10} /><span>{binary.deviceNames.length} device{binary.deviceNames.length !== 1 ? "s" : ""}</span>
              <span className="ml-1">· {binary.observationCount} obs.</span>
            </div>
            <div className="w-28"><ConfidenceBar value={candidate.confidence} /></div>
          </div>
          <button onClick={() => setExpanded((v) => !v)} className="p-1 rounded hover:bg-surface-3 transition-colors" aria-label={expanded ? "Collapse" : "Expand"}>
            {expanded ? <ChevronDown size={14} className="text-text-muted" /> : <ChevronRight size={14} className="text-text-muted" />}
          </button>
        </div>
      </div>
      <p className="text-xs text-text-muted mt-2 leading-relaxed">{candidate.rationale}</p>
      {expanded && (
        <div className="mt-4 pt-4 border-t border-border space-y-4">
          <div>
            <p className="section-header mb-2">WDAC Rule Attributes</p>
            <div className="bg-surface-2 rounded p-3 space-y-1.5">
              {Object.entries(candidate.wdacAttributes).map(([k, v]) => (
                <div key={k} className="flex gap-2 text-xs">
                  <span className="text-text-muted w-36 flex-shrink-0">{k}</span>
                  <span className="text-text-primary font-mono break-all">{v}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <p className="section-header mb-2">Binary Details</p>
            <div className="bg-surface-2 rounded p-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
              {binary.sha256 && <><span className="text-text-muted">SHA256</span><span className="text-text-primary font-mono break-all">{binary.sha256}</span></>}
              {binary.sha1 && <><span className="text-text-muted">SHA1</span><span className="text-text-primary font-mono break-all">{binary.sha1}</span></>}
              {binary.fileNames.length > 0 && <><span className="text-text-muted">File Name(s)</span><span className="text-text-primary">{binary.fileNames.join(", ")}</span></>}
              {binary.folderPaths.length > 0 && <><span className="text-text-muted">Folder Path(s)</span><span className="text-text-primary break-all">{binary.folderPaths.slice(0, 3).join(", ")}{binary.folderPaths.length > 3 ? ` +${binary.folderPaths.length - 3} more` : ""}</span></>}
              {binary.issuerNames.length > 0 && <><span className="text-text-muted">Issuer</span><span className="text-text-primary">{binary.issuerNames[0]}</span></>}
              <span className="text-text-muted">Signing Coverage</span>
              <span className={clsx("tag w-fit", coverageClass(binary.signingCoverage))}>{binary.signingCoverage}</span>
              {binary.firstSeen && <><span className="text-text-muted">First / Last Seen</span><span className="text-text-primary">{binary.firstSeen.substring(0, 10)}{binary.lastSeen && binary.lastSeen !== binary.firstSeen ? ` → ${binary.lastSeen.substring(0, 10)}` : ""}</span></>}
            </div>
          </div>
          {binary.deviceNames.length > 0 && (
            <div>
              <p className="section-header mb-2">Devices Observed ({binary.deviceNames.length})</p>
              <div className="flex flex-wrap gap-1">
                {binary.deviceNames.slice(0, 20).map((d) => <span key={d} className="tag tag-gray text-xs">{d}</span>)}
                {binary.deviceNames.length > 20 && <span className="tag tag-gray text-xs">+{binary.deviceNames.length - 20} more</span>}
              </div>
            </div>
          )}
          {candidate.warnings.length > 0 && (
            <div>
              <p className="section-header mb-2">Data Quality Warnings</p>
              <div className="space-y-1.5">
                {candidate.warnings.map((w, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-accent-yellow">
                    <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" /><span className="text-text-secondary">{w}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const PAGE_SIZE = 50;

function BinaryInventory({ binaries }: { binaries: HuntingBinary[] }) {
  const [page, setPage] = useState(0);
  const pageCount = Math.ceil(binaries.length / PAGE_SIZE);
  const visible = binaries.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  return (
    <div className="space-y-2">
      <div className="overflow-x-auto rounded border border-border">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-border bg-surface-2">
              {["File Name(s)", "Coverage", "SHA256", "Publisher", "Devices", "Obs."].map((h) => (
                <th key={h} className="text-left px-3 py-2 text-text-muted font-medium whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((binary) => (
              <tr key={binary.key} className="border-b border-border hover:bg-surface-2 transition-colors">
                <td className="px-3 py-2 text-text-primary max-w-[200px]"><span className="truncate block" title={binary.fileNames.join(", ")}>{binary.fileNames.slice(0, 2).join(", ") || "—"}{binary.fileNames.length > 2 ? ` +${binary.fileNames.length - 2}` : ""}</span></td>
                <td className="px-3 py-2 whitespace-nowrap"><span className={clsx("tag", coverageClass(binary.signingCoverage))}>{binary.signingCoverage}</span></td>
                <td className="px-3 py-2 font-mono text-text-muted max-w-[160px]"><span className="truncate block" title={binary.sha256 ?? undefined}>{binary.sha256 ? binary.sha256.substring(0, 20) + "…" : "—"}</span></td>
                <td className="px-3 py-2 text-text-secondary max-w-[200px]"><span className="truncate block" title={binary.signerNames[0]}>{binary.signerNames[0] ?? "—"}</span></td>
                <td className="px-3 py-2 text-text-muted tabular-nums text-center">{binary.deviceNames.length}</td>
                <td className="px-3 py-2 text-text-muted tabular-nums text-center">{binary.observationCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pageCount > 1 && (
        <div className="flex items-center justify-between text-xs text-text-muted">
          <span>{page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, binaries.length)} of {binaries.length}</span>
          <div className="flex gap-1">
            <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="px-2 py-1 rounded border border-border hover:bg-surface-2 disabled:opacity-40">←</button>
            <button onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))} disabled={page === pageCount - 1} className="px-2 py-1 rounded border border-border hover:bg-surface-2 disabled:opacity-40">→</button>
          </div>
        </div>
      )}
    </div>
  );
}

function SchemaReferencePanel() {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel">
      <button onClick={() => setOpen((v) => !v)} className="flex items-center gap-2 w-full text-left">
        <HelpCircle size={14} className="text-text-muted" />
        <span className="text-sm font-medium text-text-primary flex-1">Supported Defender Tables & Field Mapping</span>
        {open ? <ChevronDown size={14} className="text-text-muted" /> : <ChevronRight size={14} className="text-text-muted" />}
      </button>
      {open && (
        <div className="mt-4 space-y-4 text-xs text-text-secondary">
          <div>
            <p className="font-medium text-text-primary mb-2">Recognised Defender Tables</p>
            <div className="space-y-2">
              {[
                { name: "DeviceFileCertificateInfo", key: "SubjectName, IsSigned, SHA256", note: "Certificate-centric. Best source for publisher data. No FileName/FolderPath." },
                { name: "DeviceFileEvents",          key: "FileName, FolderPath, SHA256",  note: "File creation/modification events. Good for path and hash context." },
                { name: "DeviceProcessEvents",       key: "FileName, FolderPath, SHA256",  note: "Process launch events. Covers executables loaded by users and services." },
                { name: "DeviceImageLoadEvents",     key: "FileName, FolderPath, SHA256",  note: "DLL and kernel driver load events. Relevant for driver policy." },
              ].map((t) => (
                <div key={t.name} className="bg-surface-2 rounded p-2.5">
                  <p className="font-mono font-medium text-text-primary">{t.name}</p>
                  <p className="text-text-muted mt-0.5">Key columns: {t.key}</p>
                  <p className="mt-0.5">{t.note}</p>
                </div>
              ))}
            </div>
          </div>
          <div>
            <p className="font-medium text-text-primary mb-2">Field Aliases (Generic Fallback)</p>
            <div className="bg-surface-2 rounded p-2.5 font-mono space-y-1">
              {[
                ["SHA256",     "SHA256 · Sha256 · FileHashSHA256 · Hash"],
                ["Signer",     "SubjectName · SignerName · Publisher · PublisherName · CertSubject"],
                ["Issuer",     "IssuerName · Issuer · CertIssuer · CertificateIssuerName"],
                ["FileName",   "FileName · ProcessImageName · ImageName"],
                ["FolderPath", "FolderPath · DirectoryPath · Directory"],
                ["DeviceName", "DeviceName · ComputerName · HostName · MachineName"],
                ["Timestamp",  "Timestamp · EventTime · TimeGenerated · CreatedTime"],
              ].map(([field, aliases]) => (
                <div key={field} className="grid grid-cols-[100px_1fr] gap-2">
                  <span className="text-text-muted">{field}</span>
                  <span className="text-text-secondary">{aliases}</span>
                </div>
              ))}
            </div>
          </div>
          <div>
            <p className="font-medium text-text-primary mb-2">JSON Export Formats</p>
            <p>Three formats are accepted automatically:</p>
            <ul className="mt-1 space-y-0.5 list-disc list-inside">
              <li>Direct array: <code className="font-mono">{"[{...}, ...]"}</code></li>
              <li>Results wrapper: <code className="font-mono">{'{ "Results": [...] }'}</code></li>
              <li>Columnar: <code className="font-mono">{'{ "schema": [...], "rows": [[...]] }'}</code></li>
            </ul>
          </div>
          <div>
            <p className="font-medium text-text-primary mb-2">Recommended KQL Pattern</p>
            <pre className="bg-surface-2 rounded p-3 text-xs font-mono overflow-x-auto leading-relaxed">{`DeviceFileEvents
| where Timestamp > ago(7d)
| project SHA256, FileName, FolderPath, DeviceName, Timestamp
| join kind=leftouter (
    DeviceFileCertificateInfo
    | project SHA256, SubjectName, IssuerName, IsSigned
) on SHA256
| summarize
    FileName=any(FileName), FolderPath=any(FolderPath),
    SubjectName=any(SubjectName), IssuerName=any(IssuerName),
    IsSigned=any(IsSigned), Devices=dcount(DeviceName), Timestamp=min(Timestamp)
  by SHA256
| export to csv`}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

interface CandidateFilters { ruleType: HuntingRuleType | "all"; risk: HuntingRuleRisk | "all"; effect: "Allow" | "Deny" | "all"; }

function filterCandidates(candidates: HuntingRuleCandidate[], filters: CandidateFilters): HuntingRuleCandidate[] {
  const riskOrder: Record<HuntingRuleRisk, number> = { critical: 5, high: 4, medium: 3, low: 2, safe: 1 };
  return candidates
    .filter((c) => filters.ruleType === "all" || c.ruleType === filters.ruleType)
    .filter((c) => filters.risk === "all" || c.risk === filters.risk)
    .filter((c) => filters.effect === "all" || c.effect === filters.effect)
    .sort((a, b) => { const dr = riskOrder[b.risk] - riskOrder[a.risk]; return dr !== 0 ? dr : b.confidence - a.confidence; });
}

const RISK_LEVELS: Array<HuntingRuleRisk | "all"> = ["all", "safe", "low", "medium", "high", "critical"];
const RULE_TYPES: Array<HuntingRuleType | "all"> = ["all", "publisher-scoped", "publisher", "hash", "path", "path-wildcard"];

function AdvancedHuntingTab() {
  const [fileName, setFileName] = useState<string | null>(null);
  const [format, setFormat] = useState<"auto" | "json" | "csv">("auto");
  const [preferPublisher, setPreferPublisher] = useState(true);
  const [scopePublisher, setScopePublisher] = useState(true);
  const [includePathRules, setIncludePathRules] = useState(false);
  const [effect, setEffect] = useState<"Allow" | "Deny">("Allow");
  const [activeResultTab, setActiveResultTab] = useState<"candidates" | "inventory">("candidates");
  const [filters, setFilters] = useState<CandidateFilters>({ ruleType: "all", risk: "all", effect: "all" });

  const mutation = useMutation({
    mutationFn: (content: string) =>
      policyApi.ingestAdvancedHunting({ format, content, preferPublisherRules: preferPublisher, scopePublisherRules: scopePublisher, includePathRules, effect }),
  });

  const result = mutation.data;
  const filteredCandidates = result ? filterCandidates(result.ruleCandidates, filters) : [];

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-4">
      <p className="text-xs text-text-muted">
        Convert Microsoft Defender Advanced Hunting query results into WDAC rule candidates.
        Supports DeviceFileCertificateInfo, DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents and generic column exports.
      </p>

      <div className="grid grid-cols-[1fr_320px] gap-4">
        <div className="panel space-y-4">
          <p className="text-xs font-medium text-text-secondary uppercase tracking-wider">Ingestion Options</p>
          <div>
            <p className="text-xs text-text-muted mb-1.5">Input Format</p>
            <div className="flex gap-1.5">
              {(["auto", "json", "csv"] as const).map((f) => (
                <button key={f} onClick={() => setFormat(f)}
                  className={clsx("px-3 py-1 rounded text-xs border transition-colors",
                    format === f ? "border-accent-blue bg-accent-blue-dim text-accent-blue" : "border-border text-text-secondary hover:border-accent-blue hover:text-text-primary")}>
                  {f.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs text-text-muted mb-1.5">Rule Effect</p>
            <div className="flex gap-1.5">
              {(["Allow", "Deny"] as const).map((e) => (
                <button key={e} onClick={() => setEffect(e)}
                  className={clsx("px-3 py-1 rounded text-xs border transition-colors",
                    effect === e
                      ? e === "Allow" ? "border-accent-green bg-accent-green-dim text-accent-green" : "border-accent-red bg-accent-red-dim text-accent-red"
                      : "border-border text-text-secondary hover:text-text-primary")}>
                  {e}
                </button>
              ))}
            </div>
          </div>
          <div className="space-y-2">
            {[
              { label: "Prefer publisher rules",           detail: "Use CertPublisher rules where signing data is available.", value: preferPublisher, set: setPreferPublisher },
              { label: "Scope publisher rules to FileName", detail: "Add FileAttrib scoping when FileName is consistent across all observations.", value: scopePublisher, set: setScopePublisher, disabled: !preferPublisher },
              { label: "Include path rules for no-hash binaries", detail: "Generate FilePath rules for binaries with no SHA256. Higher risk — use with caution.", value: includePathRules, set: setIncludePathRules },
            ].map(({ label, detail, value, set, disabled }) => (
              <label key={label} className={clsx("flex items-start gap-3 cursor-pointer", disabled && "opacity-50 cursor-not-allowed")}>
                <div className="flex-shrink-0 mt-0.5">
                  <div onClick={() => !disabled && set(!value)}
                    className={clsx("w-8 h-4 rounded-full transition-colors relative", value && !disabled ? "bg-accent-blue" : "bg-surface-3")}>
                    <div className={clsx("absolute top-0.5 w-3 h-3 rounded-full bg-white shadow transition-transform", value && !disabled ? "translate-x-4" : "translate-x-0.5")} />
                  </div>
                </div>
                <div>
                  <p className="text-xs font-medium text-text-primary">{label}</p>
                  <p className="text-xs text-text-muted mt-0.5">{detail}</p>
                </div>
              </label>
            ))}
          </div>
        </div>

        <div className="flex flex-col gap-3">
          <HuntingFileDropZone label="Drop Advanced Hunting export here" onFile={(content, name) => { setFileName(name); mutation.mutate(content); }} />
          {fileName && (
            <div className="flex items-center gap-2 px-3 py-2 bg-surface-2 rounded text-xs">
              <Eye size={12} className="text-text-muted" /><span className="text-text-secondary truncate" title={fileName}>{fileName}</span>
            </div>
          )}
          {mutation.isPending && (
            <div className="flex items-center gap-2 text-xs text-text-muted px-1">
              <div className="w-3 h-3 border border-accent-blue border-t-transparent rounded-full animate-spin" />Ingesting…
            </div>
          )}
          {mutation.isError && (
            <div className="flex items-start gap-2 text-xs text-accent-red px-1">
              <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" /><span>{(mutation.error as Error).message}</span>
            </div>
          )}
        </div>
      </div>

      {result && (
        <>
          <HuntingStatsBar result={result} />
          <HuntingWarningsPanel warnings={result.warnings} />
          <div>
            <div className="flex items-center border-b border-border mb-4">
              {([{ key: "candidates" as const, label: `Rule Candidates (${result.ruleCandidates.length})` }, { key: "inventory" as const, label: `Binary Inventory (${result.binaries.length})` }]).map(({ key, label }) => (
                <button key={key} onClick={() => setActiveResultTab(key)}
                  className={clsx("px-4 py-2 text-sm border-b-2 -mb-px transition-colors",
                    activeResultTab === key ? "border-accent-blue text-text-primary font-medium" : "border-transparent text-text-secondary hover:text-text-primary")}>
                  {label}
                </button>
              ))}
            </div>
            {activeResultTab === "candidates" && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-3 p-3 bg-surface-1 border border-border rounded">
                  {([["ruleType", RULE_TYPES, "All types", (t: string) => t === "all" ? "All types" : ruleTypeLabel(t as HuntingRuleType)] as const,
                     ["risk",     RISK_LEVELS, "All risks",  (r: string) => r === "all" ? "All risks" : r] as const,
                  ] as const).map(([key, opts, placeholder, labelFn]) => (
                    <div key={key} className="flex items-center gap-2 text-xs">
                      <span className="text-text-muted capitalize">{key === "ruleType" ? "Type" : key.charAt(0).toUpperCase() + key.slice(1)}:</span>
                      <select value={filters[key as keyof CandidateFilters]}
                        onChange={(e) => setFilters((f) => ({ ...f, [key]: e.target.value }))}
                        className="bg-surface-2 border border-border rounded px-2 py-1 text-text-primary focus:outline-none focus:border-accent-blue">
                        {opts.map((o) => <option key={o} value={o}>{labelFn(o)}</option>)}
                      </select>
                    </div>
                  ))}
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-text-muted">Effect:</span>
                    <select value={filters.effect} onChange={(e) => setFilters((f) => ({ ...f, effect: e.target.value as CandidateFilters["effect"] }))}
                      className="bg-surface-2 border border-border rounded px-2 py-1 text-text-primary focus:outline-none focus:border-accent-blue">
                      <option value="all">All</option><option value="Allow">Allow</option><option value="Deny">Deny</option>
                    </select>
                  </div>
                  {filteredCandidates.length !== result.ruleCandidates.length && (
                    <span className="text-xs text-text-muted ml-auto">{filteredCandidates.length} of {result.ruleCandidates.length} shown</span>
                  )}
                </div>
                {filteredCandidates.length === 0
                  ? <div className="text-center py-12 text-text-muted"><CheckCircle size={32} className="mx-auto mb-2 opacity-30" /><p className="text-sm">No candidates match the current filters.</p></div>
                  : <div className="space-y-2">{filteredCandidates.map((c) => <HuntingRuleCandidateCard key={c.id} candidate={c} />)}</div>}
              </div>
            )}
            {activeResultTab === "inventory" && <BinaryInventory binaries={result.binaries} />}
          </div>
        </>
      )}
      <SchemaReferencePanel />
    </div>
  );
}

// ===========================================================================
// BUILD POLICY TAB
// ===========================================================================

type Template = "default-windows" | "allow-microsoft" | "deny-by-default" | "blank";

const TEMPLATES: { id: Template; label: string; description: string }[] = [
  { id: "blank",           label: "Blank",           description: "Start with minimal options; only rules you define apply." },
  { id: "allow-microsoft", label: "Allow Microsoft", description: "Trust Microsoft-signed binaries. Add more rules for other software." },
  { id: "default-windows", label: "Default Windows", description: "Allow Windows components + WHQL drivers. Most restrictive template." },
  { id: "deny-by-default", label: "Deny by Default", description: "Explicit allow-list only. Requires EV signers." },
];

function Toggle({ label, description, checked, onChange, warning }: { label: string; description: string; checked: boolean; onChange: (v: boolean) => void; warning?: boolean }) {
  return (
    <div className="flex items-start gap-3">
      <button role="switch" aria-checked={checked} onClick={() => onChange(!checked)}
        className={clsx("relative inline-flex w-9 h-5 rounded-full flex-shrink-0 mt-0.5 transition-colors focus:outline-none focus:ring-2 focus:ring-accent-blue focus:ring-offset-2 focus:ring-offset-surface-1",
          checked ? "bg-accent-blue" : "bg-surface-5")}>
        <span className={clsx("inline-block w-3.5 h-3.5 rounded-full bg-white shadow transform transition-transform mt-0.5 ml-0.5", checked ? "translate-x-4" : "translate-x-0")} />
      </button>
      <div className="flex-1">
        <p className={clsx("text-xs font-medium", warning ? "text-accent-yellow" : "text-text-primary")}>{label}</p>
        <p className="text-xs text-text-muted mt-0.5">{description}</p>
      </div>
    </div>
  );
}

function BuildResult({ result }: { result: CreatePolicyFromEventsResponse }) {
  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 mb-3">
        <CheckCircle size={16} className="text-accent-green" />
        <h2 className="text-sm font-semibold text-text-primary">Policy Built Successfully</h2>
      </div>
      <div className="grid grid-cols-3 gap-3 mb-4 text-center">
        <div className="bg-surface-2 rounded p-2"><p className="text-lg font-bold mono text-text-primary">{result.ruleCount}</p><p className="text-xs text-text-muted">Total Rules</p></div>
        <div className="bg-surface-2 rounded p-2"><p className="text-lg font-bold mono text-accent-blue">{result.policy.fileRules.length}</p><p className="text-xs text-text-muted">File Rules</p></div>
        <div className="bg-surface-2 rounded p-2"><p className="text-lg font-bold mono text-accent-purple">{result.policy.signers.length}</p><p className="text-xs text-text-muted">Signer Rules</p></div>
      </div>
      <h3 className="section-header">Build Log</h3>
      <div className="bg-surface-2 rounded p-3 max-h-48 overflow-auto">
        {result.buildLog.map((line, i) => <p key={i} className="mono text-xs text-text-muted">{line}</p>)}
      </div>
      <div className="mt-4 flex gap-2">
        <button className="btn-primary" onClick={() => {
          const blob = new Blob([result.xml], { type: "text/xml" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = `${result.policy.friendlyName ?? "policy"}.xml`; a.click();
          URL.revokeObjectURL(url);
        }}>Download XML</button>
        <p className="text-xs text-text-muted self-center">Policy has been loaded into the editor</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Unique file grouping helper (mirrors server-side logic)
// ---------------------------------------------------------------------------

interface UniqueFileRow {
  key: string;
  filePath: string;
  fileName?: string;
  productName?: string;
  originalFileName?: string;
  sha256FlatHash?: string;
  sha256Hash?: string;
  publisherName?: string;
  publisherTbsHash?: string;
  hasHash: boolean;
  hasPublisher: boolean;
  hasAttributes: boolean;
  severity: "block" | "audit" | "info";
  eventCount: number;
  /** GUID of the base policy that triggered the block/audit for this file */
  triggeringPolicyGuid?: string;
  /** Human-readable name of the triggering base policy */
  triggeringPolicyName?: string;
}

function buildUniqueFiles(events: ParsedCiEvent[]): UniqueFileRow[] {
  const map = new Map<string, UniqueFileRow>();
  for (const ev of events) {
    const key = ev.sha256FlatHash ?? ev.sha256Hash ?? ev.filePath.toLowerCase();
    const existing = map.get(key);
    if (existing) {
      existing.eventCount++;
      if (!existing.publisherName && ev.signerInfo?.publisherName) {
        existing.publisherName = ev.signerInfo.publisherName;
        existing.publisherTbsHash = ev.signerInfo.publisherTbsHash;
        existing.hasPublisher = true;
      }
      if (!existing.originalFileName && ev.originalFileName) {
        existing.originalFileName = ev.originalFileName;
        existing.hasAttributes = true;
      }
    } else {
      const hasHash = !!(ev.sha256FlatHash ?? ev.sha256Hash);
      const hasPublisher = !!(ev.signerInfo?.publisherTbsHash ?? ev.signerInfo?.publisherName);
      const hasAttributes = !!(ev.originalFileName ?? ev.productName);
      map.set(key, {
        key,
        filePath: ev.filePath,
        fileName: ev.fileName,
        productName: ev.productName,
        originalFileName: ev.originalFileName,
        sha256FlatHash: ev.sha256FlatHash,
        sha256Hash: ev.sha256Hash,
        publisherName: ev.signerInfo?.publisherName,
        publisherTbsHash: ev.signerInfo?.publisherTbsHash,
        hasHash,
        hasPublisher,
        hasAttributes,
        severity: ev.severity,
        eventCount: 1,
        triggeringPolicyGuid: ev.policyGuid,
        triggeringPolicyName: ev.policyName,
      });
    }
  }
  return Array.from(map.values());
}

/** Returns distinct base policies detected in events, sorted by frequency. */
function detectBasePolicies(events: ParsedCiEvent[]): Array<{ guid: string; name?: string; count: number }> {
  const map = new Map<string, { name?: string; count: number }>();
  for (const ev of events) {
    if (!ev.policyGuid) continue;
    const existing = map.get(ev.policyGuid);
    if (existing) {
      existing.count++;
      if (!existing.name && ev.policyName) existing.name = ev.policyName;
    } else {
      map.set(ev.policyGuid, { name: ev.policyName, count: 1 });
    }
  }
  return [...map.entries()]
    .map(([guid, { name, count }]) => ({ guid, name, count }))
    .sort((a, b) => b.count - a.count);
}

// ---------------------------------------------------------------------------
// Rule type selector for a single file row
// ---------------------------------------------------------------------------

const RULE_TYPE_OPTIONS: { value: FileRuleType; label: string; desc: string }[] = [
  { value: "publisher", label: "Publisher",    desc: "Certificate TBS — survives updates" },
  { value: "fileAttrib", label: "FileName",    desc: "OriginalFileName match" },
  { value: "hash",       label: "Hash",        desc: "SHA256 exact match" },
  { value: "path",       label: "Path",        desc: "File path (weakest)" },
  { value: "skip",       label: "Skip",        desc: "Exclude from policy" },
];

function defaultRuleTypeForFile(row: UniqueFileRow, preferPublisher: boolean): FileRuleType {
  if (preferPublisher && row.hasPublisher) return "publisher";
  if (row.hasHash) return "hash";
  return "path";
}

function FileRuleRow({
  row,
  ruleType,
  onChange,
}: {
  row: UniqueFileRow;
  ruleType: FileRuleType;
  onChange: (key: string, type: FileRuleType) => void;
}) {
  const hash = row.sha256FlatHash ?? row.sha256Hash;
  const publisherCn = row.publisherName
    ? (row.publisherName.match(/CN=([^,]+)/)?.[1] ?? row.publisherName.substring(0, 28))
    : undefined;

  return (
    <tr>
      <td>
        {row.severity === "block"
          ? <span className="tag tag-red flex items-center gap-1 w-fit"><ShieldAlert size={9} />Block</span>
          : <span className="tag tag-yellow flex items-center gap-1 w-fit"><Shield size={9} />Audit</span>}
      </td>
      <td className="text-xs max-w-[180px]">
        <p className="truncate font-medium text-text-primary" title={row.filePath}>{row.fileName ?? row.filePath}</p>
        {row.productName && <p className="text-text-muted truncate text-[10px]">{row.productName}</p>}
      </td>
      <td className="text-xs">
        {publisherCn
          ? <span className="flex items-center gap-1 text-accent-blue"><Key size={10} /><span className="truncate max-w-[140px]" title={row.publisherName}>{publisherCn}</span></span>
          : row.originalFileName
          ? <span className="flex items-center gap-1 text-text-secondary"><Tag size={10} />{row.originalFileName}</span>
          : <span className="text-text-muted italic">Unsigned</span>}
      </td>
      <td className="mono text-xs text-text-muted">{hash ? `${hash.substring(0, 14)}…` : "—"}</td>
      <td className="text-xs max-w-[160px]">
        {row.triggeringPolicyName
          ? <span className="truncate block text-text-secondary" title={`${row.triggeringPolicyName}\n${row.triggeringPolicyGuid ?? ""}`}>{row.triggeringPolicyName}</span>
          : row.triggeringPolicyGuid
          ? <span className="mono text-text-muted truncate block" title={row.triggeringPolicyGuid}>{row.triggeringPolicyGuid.substring(0, 8)}…</span>
          : <span className="text-text-muted italic">—</span>}
      </td>
      <td>
        <div className="flex gap-1 flex-wrap">
          {row.hasPublisher && <span className="tag tag-blue text-[10px]">Pub</span>}
          {row.hasAttributes && <span className="tag tag-gray text-[10px]">Attr</span>}
          {row.hasHash && <span className="tag tag-gray text-[10px]">Hash</span>}
        </div>
      </td>
      <td>
        <select
          value={ruleType}
          onChange={(e) => onChange(row.key, e.target.value as FileRuleType)}
          className="bg-surface-2 border border-border rounded px-2 py-1 text-xs text-text-primary focus:outline-none focus:border-accent-blue"
        >
          {RULE_TYPE_OPTIONS.filter((opt) => {
            if (opt.value === "publisher" && !row.hasPublisher) return false;
            if (opt.value === "fileAttrib" && !row.hasAttributes) return false;
            if (opt.value === "hash" && !row.hasHash) return false;
            return true;
          }).map((opt) => (
            <option key={opt.value} value={opt.value} title={opt.desc}>{opt.label}</option>
          ))}
          <option value="skip">Skip</option>
        </select>
      </td>
    </tr>
  );
}

function BuildPolicyTab({ onSwitchToCiEvents }: { onSwitchToCiEvents: () => void }) {
  const { importedEvents, addSession } = useAppStore();
  const [options, setOptions] = useState({
    policyName: "Generated Policy",
    template: "blank" as Template,
    auditMode: true,
    preferPublisherRules: true,
    policyType: "Supplemental" as "Base" | "Supplemental",
    basePolicyId: "",
  });
  const [ruleOverrides, setRuleOverrides] = useState<Map<string, FileRuleType>>(new Map());
  const [result, setResult] = useState<CreatePolicyFromEventsResponse | null>(null);

  const uniqueFiles = useMemo(() => buildUniqueFiles(importedEvents), [importedEvents]);

  // Detect base policies from the imported events
  const detectedBasePolicies = useMemo(() => detectBasePolicies(importedEvents), [importedEvents]);

  // Auto-populate basePolicyId from the most common triggering policy when events are loaded
  const autoBasePolicyId = detectedBasePolicies[0]?.guid ?? "";

  // Resolved rule type per file (override → default)
  const resolvedType = (row: UniqueFileRow): FileRuleType =>
    ruleOverrides.get(row.key) ?? defaultRuleTypeForFile(row, options.preferPublisherRules);

  const setAllRules = (type: FileRuleType) => {
    const next = new Map<string, FileRuleType>();
    uniqueFiles.forEach((f) => next.set(f.key, type));
    setRuleOverrides(next);
  };

  const buildMutation = useMutation({
    mutationFn: () => {
      const ruleSelections: FileRuleSelection[] = uniqueFiles.map((f) => ({
        fileKey: f.key,
        ruleType: resolvedType(f),
      }));
      const basePolicyId = options.basePolicyId.trim() || autoBasePolicyId;
      return policyApi.fromEvents({
        events: importedEvents,
        policyName: options.policyName,
        template: options.template,
        policyType: options.policyType,
        ...(options.policyType === "Supplemental" && basePolicyId ? { basePolicyId } : {}),
        ruleSelections,
        preferPublisherRules: options.preferPublisherRules,
        includePathRules: false,
        auditMode: options.auditMode,
      });
    },
    onSuccess: (data) => {
      setResult(data);
      addSession({
        id: uuidv4(),
        fileName: `${options.policyName}.xml`,
        policy: data.policy,
        xml: data.xml,
        loadedAt: new Date().toISOString(),
      });
    },
  });

  if (importedEvents.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-center">
          <Activity size={40} className="mx-auto mb-3 text-text-muted opacity-40" />
          <p className="text-sm font-medium text-text-secondary mb-1">No events loaded</p>
          <p className="text-xs text-text-muted mb-4">Import CodeIntegrity events first, then return here to build a policy.</p>
          <button className="btn-primary" onClick={onSwitchToCiEvents}>Go to CI Events</button>
        </div>
      </div>
    );
  }

  const ruleTypeSummary = {
    publisher: uniqueFiles.filter((f) => resolvedType(f) === "publisher").length,
    fileAttrib: uniqueFiles.filter((f) => resolvedType(f) === "fileAttrib").length,
    hash: uniqueFiles.filter((f) => resolvedType(f) === "hash").length,
    path: uniqueFiles.filter((f) => resolvedType(f) === "path").length,
    skip: uniqueFiles.filter((f) => resolvedType(f) === "skip").length,
  };

  return (
    <div className="flex-1 overflow-auto p-6">
      <div className="max-w-4xl space-y-5">
        {/* Header row */}
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-text-muted">{importedEvents.length} events · {uniqueFiles.length} unique files</p>
          </div>
          <button
            className="btn-primary"
            onClick={() => buildMutation.mutate()}
            disabled={buildMutation.isPending || !options.policyName.trim() || ruleTypeSummary.skip === uniqueFiles.length}
          >
            <Activity size={13} />{buildMutation.isPending ? "Building…" : "Build Policy"}
          </button>
        </div>

        {/* Policy settings */}
        <div className="card p-4">
          <h2 className="section-header">Policy Settings</h2>

          {/* Policy Type — Supplemental is the default for event-log-based policies */}
          <div className="mb-4">
            <label className="text-xs font-medium text-text-secondary block mb-1.5">Policy Type</label>
            <div className="flex gap-2">
              {(["Supplemental", "Base"] as const).map((t) => (
                <button key={t} onClick={() => setOptions((o) => ({ ...o, policyType: t }))}
                  className={clsx("px-3 py-1.5 rounded border text-xs transition-colors",
                    options.policyType === t
                      ? "border-accent-blue bg-accent-blue-dim/20 text-text-primary font-medium"
                      : "border-border text-text-secondary hover:border-border-strong")}>
                  {t === "Supplemental" ? "Supplemental (recommended)" : "Base Policy"}
                </button>
              ))}
            </div>
            {options.policyType === "Supplemental" && (
              <p className="text-[10px] text-text-muted mt-1.5">
                Adds allow rules on top of an existing enforced base policy. Inherits options and
                signing scenarios from the base.
              </p>
            )}
          </div>

          {/* Base Policy ID — shown only for supplemental; auto-detected from events */}
          {options.policyType === "Supplemental" && (
            <div className="mb-4">
              <label className="text-xs font-medium text-text-secondary block mb-1.5">
                Base Policy ID
                <span className="ml-1 text-text-muted font-normal">(PolicyGUID of the enforcing base policy)</span>
              </label>
              {detectedBasePolicies.length > 0 ? (
                <div className="space-y-1.5">
                  {/* Show detected GUIDs as selectable chips */}
                  <div className="flex flex-wrap gap-1.5">
                    {detectedBasePolicies.map(({ guid, name, count }) => {
                      const isActive = (options.basePolicyId || autoBasePolicyId) === guid;
                      return (
                        <button key={guid}
                          onClick={() => setOptions((o) => ({ ...o, basePolicyId: guid }))}
                          className={clsx("text-[10px] px-2 py-1 rounded border transition-colors text-left",
                            isActive
                              ? "border-accent-blue bg-accent-blue-dim/20 text-text-primary"
                              : "border-border text-text-secondary hover:border-border-strong")}>
                          <span className="font-medium">{name ?? guid}</span>
                          {name && <span className="text-text-muted ml-1 mono">{guid.substring(0, 8)}…</span>}
                          <span className="text-text-muted ml-1">({count} events)</span>
                        </button>
                      );
                    })}
                  </div>
                  <input className="input mono text-xs"
                    value={options.basePolicyId || autoBasePolicyId}
                    onChange={(e) => setOptions((o) => ({ ...o, basePolicyId: e.target.value }))}
                    placeholder="XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" />
                </div>
              ) : (
                <input className="input mono text-xs"
                  value={options.basePolicyId}
                  onChange={(e) => setOptions((o) => ({ ...o, basePolicyId: e.target.value }))}
                  placeholder="Paste base policy GUID — e.g. 4E61C68C-97F6-430B-9CD7-9B1004706770" />
              )}
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-medium text-text-secondary block mb-1.5">Policy Name</label>
              <input className="input" value={options.policyName}
                onChange={(e) => setOptions((o) => ({ ...o, policyName: e.target.value }))}
                placeholder="My WDAC Policy" maxLength={256} />
            </div>
            <div className="flex items-end gap-3">
              <Toggle
                label="Start in Audit Mode"
                description="Option 3 — recommended for initial testing. (Base policies only)"
                checked={options.auditMode}
                onChange={(v) => setOptions((o) => ({ ...o, auditMode: v }))}
              />
            </div>
          </div>
          <div className="mt-3">
            <label className="text-xs font-medium text-text-secondary block mb-2">Base Template</label>
            <div className="grid grid-cols-4 gap-2">
              {TEMPLATES.map((t) => (
                <button key={t.id} onClick={() => setOptions((o) => ({ ...o, template: t.id }))}
                  className={clsx("text-left p-2.5 rounded border text-xs transition-colors",
                    options.template === t.id ? "border-accent-blue bg-accent-blue-dim/20" : "border-border hover:border-border-strong")}>
                  <p className="font-medium text-text-primary mb-0.5">{t.label}</p>
                  <p className="text-text-muted text-[10px] leading-tight">{t.description}</p>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* File rule type selection table */}
        <div className="card p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="section-header mb-0">File Rule Selection ({uniqueFiles.length} files)</h2>
            <div className="flex items-center gap-2">
              <span className="text-xs text-text-muted">Set all:</span>
              <select
                onChange={(e) => {
                  if (e.target.value) setAllRules(e.target.value as FileRuleType);
                  e.target.value = "";
                }}
                defaultValue=""
                className="bg-surface-2 border border-border rounded px-2 py-1 text-xs text-text-primary focus:outline-none focus:border-accent-blue"
              >
                <option value="" disabled>Select…</option>
                <option value="publisher">All → Publisher</option>
                <option value="hash">All → Hash</option>
                <option value="fileAttrib">All → FileName</option>
                <option value="path">All → Path</option>
                <option value="skip">All → Skip</option>
              </select>
            </div>
          </div>

          {/* Rule type summary chips */}
          <div className="flex gap-2 mb-3 flex-wrap">
            {ruleTypeSummary.publisher > 0 && <span className="tag tag-blue text-xs">{ruleTypeSummary.publisher} Publisher</span>}
            {ruleTypeSummary.fileAttrib > 0 && <span className="tag tag-gray text-xs">{ruleTypeSummary.fileAttrib} FileName</span>}
            {ruleTypeSummary.hash > 0 && <span className="tag tag-gray text-xs">{ruleTypeSummary.hash} Hash</span>}
            {ruleTypeSummary.path > 0 && <span className="tag tag-yellow text-xs">{ruleTypeSummary.path} Path</span>}
            {ruleTypeSummary.skip > 0 && <span className="tag tag-red text-xs">{ruleTypeSummary.skip} Skipped</span>}
          </div>

          <div className="overflow-auto max-h-[400px]">
            <table className="data-table">
              <thead className="sticky top-0 bg-surface-1">
                <tr>
                  <th>Severity</th>
                  <th>File / Product</th>
                  <th>Publisher / Filename</th>
                  <th>SHA256 (flat)</th>
                  <th>Triggering Policy</th>
                  <th>Available</th>
                  <th>Rule Type</th>
                </tr>
              </thead>
              <tbody>
                {uniqueFiles.map((row) => (
                  <FileRuleRow
                    key={row.key}
                    row={row}
                    ruleType={resolvedType(row)}
                    onChange={(key, type) =>
                      setRuleOverrides((prev) => new Map(prev).set(key, type))
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {buildMutation.isPending && <div className="flex justify-center py-8"><LoadingSpinner label="Building policy rules…" /></div>}
        {buildMutation.isError && (
          <div className="p-4 bg-accent-red-dim/30 border border-accent-red/20 rounded text-sm text-accent-red flex items-center gap-2">
            <AlertCircle size={14} />{(buildMutation.error as Error).message}
          </div>
        )}
        {result && !buildMutation.isPending && <BuildResult result={result} />}
      </div>
    </div>
  );
}

// ===========================================================================
// MAIN PAGE
// ===========================================================================

const TABS: { key: PageTab; label: string; icon: React.ReactNode }[] = [
  { key: "ci-events",        label: "CI Events",        icon: <Upload size={13} /> },
  { key: "advanced-hunting", label: "Advanced Hunting", icon: <Search size={13} /> },
  { key: "build-policy",     label: "Build Policy",     icon: <Activity size={13} /> },
];

export function ImportEventsPage() {
  const [activeTab, setActiveTab] = useState<PageTab>("ci-events");

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <Header title="Import & Build" subtitle="Import CodeIntegrity events and Advanced Hunting results, then build a WDAC policy" />

      <div className="border-b border-border px-6 flex-shrink-0">
        <div className="flex">
          {TABS.map(({ key, label, icon }) => (
            <button key={key} onClick={() => setActiveTab(key)}
              className={clsx("flex items-center gap-1.5 px-4 py-2.5 text-sm border-b-2 -mb-px transition-colors",
                activeTab === key ? "border-accent-blue text-text-primary font-medium" : "border-transparent text-text-secondary hover:text-text-primary")}>
              <span className={activeTab === key ? "text-accent-blue" : "text-text-muted"}>{icon}</span>
              {label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === "ci-events"        && <CiEventsTab />}
      {activeTab === "advanced-hunting" && <AdvancedHuntingTab />}
      {activeTab === "build-policy"     && <BuildPolicyTab onSwitchToCiEvents={() => setActiveTab("ci-events")} />}
    </div>
  );
}
