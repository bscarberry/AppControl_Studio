import { useState, useRef } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Search,
  Upload,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Shield,
  Hash,
  FileWarning,
  Server,
  Eye,
  HelpCircle,
} from "lucide-react";
import clsx from "clsx";
import { policyApi } from "../lib/api.ts";
import type {
  HuntingBinary,
  HuntingImportResult,
  HuntingImportWarning,
  HuntingRuleCandidate,
  HuntingRuleRisk,
  HuntingRuleType,
  HuntingSigningCoverage,
} from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

function riskClass(risk: HuntingRuleRisk): string {
  switch (risk) {
    case "safe":     return "tag-green";
    case "low":      return "tag-blue";
    case "medium":   return "tag-yellow";
    case "high":     return "tag-orange";
    case "critical": return "tag-red";
  }
}

function coverageClass(coverage: HuntingSigningCoverage): string {
  switch (coverage) {
    case "full":      return "tag-green";
    case "partial":   return "tag-yellow";
    case "hash-only": return "tag-blue";
    case "unsigned":  return "tag-orange";
    case "no-hash":   return "tag-red";
  }
}

function ruleTypeLabel(t: HuntingRuleType): string {
  switch (t) {
    case "publisher-scoped": return "Publisher (scoped)";
    case "publisher":        return "Publisher";
    case "hash":             return "Hash";
    case "path":             return "Path";
    case "path-wildcard":    return "Path (wildcard)";
  }
}

function ruleTypeIcon(t: HuntingRuleType) {
  switch (t) {
    case "publisher-scoped":
    case "publisher":
      return <Shield size={13} />;
    case "hash":
      return <Hash size={13} />;
    case "path":
    case "path-wildcard":
      return <FileWarning size={13} />;
  }
}

// ---------------------------------------------------------------------------
// File drop zone
// ---------------------------------------------------------------------------

interface FileZoneProps {
  onFile: (content: string, name: string) => void;
  label: string;
}

function FileDropZone({ onFile, label }: FileZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  function handleFile(file: File) {
    const reader = new FileReader();
    reader.onload = (e) => {
      onFile((e.target?.result as string) ?? "", file.name);
    };
    reader.readAsText(file, "utf-8");
  }

  return (
    <div
      onClick={() => inputRef.current?.click()}
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
      }}
      className={clsx(
        "border-2 border-dashed rounded-lg p-8 cursor-pointer text-center transition-colors",
        dragging
          ? "border-accent-blue bg-accent-blue-dim"
          : "border-border hover:border-accent-blue hover:bg-surface-2"
      )}
    >
      <Upload size={28} className="mx-auto mb-2 text-text-muted" />
      <p className="text-sm text-text-secondary">{label}</p>
      <p className="text-xs text-text-muted mt-1">JSON or CSV · drag & drop or click</p>
      <input
        ref={inputRef}
        type="file"
        accept=".json,.csv,.txt"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) handleFile(file);
          e.target.value = "";
        }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Stats bar
// ---------------------------------------------------------------------------

interface StatsBarProps {
  result: HuntingImportResult;
}

function StatsBar({ result }: StatsBarProps) {
  const { stats } = result;
  const items: Array<{ label: string; value: number; colorClass?: string }> = [
    { label: "Rows parsed", value: stats.totalRowsParsed },
    { label: "Valid rows", value: stats.validRows },
    { label: "Unique binaries", value: stats.uniqueBinaries },
    { label: "Signed", value: stats.signedBinaries, colorClass: "text-accent-green" },
    { label: "Partial signing", value: stats.partialSigningBinaries, colorClass: "text-accent-yellow" },
    { label: "Unsigned", value: stats.unsignedBinaries, colorClass: "text-accent-orange" },
    { label: "No hash", value: stats.noHashBinaries, colorClass: "text-accent-red" },
    { label: "Rule candidates", value: result.ruleCandidates.length, colorClass: "text-accent-blue" },
  ];

  return (
    <div className="panel">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-medium text-text-secondary uppercase tracking-wider">
          Import Summary
        </p>
        <span className="tag tag-blue text-xs">{stats.detectedSchema}</span>
      </div>
      <div className="grid grid-cols-4 gap-3">
        {items.map((item) => (
          <div key={item.label} className="bg-surface-2 rounded p-2.5">
            <p className={clsx("text-lg font-semibold tabular-nums", item.colorClass ?? "text-text-primary")}>
              {item.value.toLocaleString()}
            </p>
            <p className="text-xs text-text-muted mt-0.5">{item.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Warnings panel
// ---------------------------------------------------------------------------

function WarningsPanel({ warnings }: { warnings: HuntingImportWarning[] }) {
  const [open, setOpen] = useState(true);
  if (warnings.length === 0) return null;
  return (
    <div className="panel border-l-2 border-accent-yellow">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 w-full text-left"
      >
        <AlertTriangle size={14} className="text-accent-yellow flex-shrink-0" />
        <span className="text-sm font-medium text-text-primary flex-1">
          Import Warnings ({warnings.length})
        </span>
        {open ? <ChevronDown size={14} className="text-text-muted" /> : <ChevronRight size={14} className="text-text-muted" />}
      </button>
      {open && (
        <div className="mt-3 space-y-2">
          {warnings.map((w, i) => (
            <div key={i} className="bg-surface-2 rounded p-2.5">
              <div className="flex items-start gap-2">
                <span className="tag tag-yellow mt-0.5 flex-shrink-0">{w.code}</span>
                <p className="text-xs text-text-secondary">{w.message}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Rule candidate card
// ---------------------------------------------------------------------------

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const colorClass =
    pct >= 80 ? "bg-accent-green" : pct >= 60 ? "bg-accent-yellow" : "bg-accent-red";
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
      {/* Header row */}
      <div className="flex items-start gap-2">
        <div className="flex items-center gap-1.5 flex-shrink-0 mt-0.5">
          <span className={clsx("tag flex items-center gap-1", riskClass(candidate.risk))}>
            {ruleTypeIcon(candidate.ruleType)}
            {ruleTypeLabel(candidate.ruleType)}
          </span>
          <span className={clsx("tag", riskClass(candidate.risk))}>{candidate.risk}</span>
          <span className={clsx("tag", candidate.effect === "Allow" ? "tag-green" : "tag-red")}>
            {candidate.effect}
          </span>
          {candidate.appliesToKernelMode && (
            <span className="tag tag-orange" title="Kernel-mode driver">KM</span>
          )}
        </div>
        <div className="flex-1 min-w-0 ml-1">
          <p className="text-sm font-medium text-text-primary truncate">{primaryLabel}</p>
          {binary.fileNames.length > 0 && candidate.ruleType !== "path" && candidate.ruleType !== "path-wildcard" && (
            <p className="text-xs text-text-muted mt-0.5 truncate">
              {binary.fileNames.slice(0, 2).join(", ")}
              {binary.fileNames.length > 2 ? ` +${binary.fileNames.length - 2} more` : ""}
            </p>
          )}
        </div>
        <div className="flex items-center gap-3 flex-shrink-0 ml-2">
          <div className="text-right">
            <div className="flex items-center gap-1 text-xs text-text-muted mb-1">
              <Server size={10} />
              <span>{binary.deviceNames.length} device{binary.deviceNames.length !== 1 ? "s" : ""}</span>
              <span className="ml-1">· {binary.observationCount} obs.</span>
            </div>
            <div className="w-28">
              <ConfidenceBar value={candidate.confidence} />
            </div>
          </div>
          <button
            onClick={() => setExpanded((v) => !v)}
            className="p-1 rounded hover:bg-surface-3 transition-colors"
            aria-label={expanded ? "Collapse" : "Expand"}
          >
            {expanded
              ? <ChevronDown size={14} className="text-text-muted" />
              : <ChevronRight size={14} className="text-text-muted" />}
          </button>
        </div>
      </div>

      {/* Candidate ID + rationale always visible */}
      <p className="text-xs text-text-muted mt-2 leading-relaxed">{candidate.rationale}</p>

      {/* Expanded detail */}
      {expanded && (
        <div className="mt-4 pt-4 border-t border-border space-y-4">
          {/* WDAC attributes */}
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

          {/* Binary details */}
          <div>
            <p className="section-header mb-2">Binary Details</p>
            <div className="bg-surface-2 rounded p-3 grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
              {binary.sha256 && (
                <>
                  <span className="text-text-muted">SHA256</span>
                  <span className="text-text-primary font-mono break-all">{binary.sha256}</span>
                </>
              )}
              {binary.sha1 && (
                <>
                  <span className="text-text-muted">SHA1</span>
                  <span className="text-text-primary font-mono break-all">{binary.sha1}</span>
                </>
              )}
              {binary.fileNames.length > 0 && (
                <>
                  <span className="text-text-muted">File Name(s)</span>
                  <span className="text-text-primary">{binary.fileNames.join(", ")}</span>
                </>
              )}
              {binary.folderPaths.length > 0 && (
                <>
                  <span className="text-text-muted">Folder Path(s)</span>
                  <span className="text-text-primary break-all">
                    {binary.folderPaths.slice(0, 3).join(", ")}
                    {binary.folderPaths.length > 3 ? ` +${binary.folderPaths.length - 3} more` : ""}
                  </span>
                </>
              )}
              {binary.issuerNames.length > 0 && (
                <>
                  <span className="text-text-muted">Issuer</span>
                  <span className="text-text-primary">{binary.issuerNames[0]}</span>
                </>
              )}
              <span className="text-text-muted">Signing Coverage</span>
              <span className={clsx("tag w-fit", coverageClass(binary.signingCoverage))}>
                {binary.signingCoverage}
              </span>
              {binary.firstSeen && (
                <>
                  <span className="text-text-muted">First / Last Seen</span>
                  <span className="text-text-primary">
                    {binary.firstSeen.substring(0, 10)}
                    {binary.lastSeen && binary.lastSeen !== binary.firstSeen
                      ? ` → ${binary.lastSeen.substring(0, 10)}`
                      : ""}
                  </span>
                </>
              )}
            </div>
          </div>

          {/* Devices */}
          {binary.deviceNames.length > 0 && (
            <div>
              <p className="section-header mb-2">
                Devices Observed ({binary.deviceNames.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {binary.deviceNames.slice(0, 20).map((d) => (
                  <span key={d} className="tag tag-gray text-xs">{d}</span>
                ))}
                {binary.deviceNames.length > 20 && (
                  <span className="tag tag-gray text-xs">+{binary.deviceNames.length - 20} more</span>
                )}
              </div>
            </div>
          )}

          {/* Warnings */}
          {candidate.warnings.length > 0 && (
            <div>
              <p className="section-header mb-2">Data Quality Warnings</p>
              <div className="space-y-1.5">
                {candidate.warnings.map((w, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-accent-yellow">
                    <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" />
                    <span className="text-text-secondary">{w}</span>
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

// ---------------------------------------------------------------------------
// Binary inventory table
// ---------------------------------------------------------------------------

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
                <th key={h} className="text-left px-3 py-2 text-text-muted font-medium whitespace-nowrap">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {visible.map((binary) => (
              <tr key={binary.key} className="border-b border-border hover:bg-surface-2 transition-colors">
                <td className="px-3 py-2 text-text-primary max-w-[200px]">
                  <span className="truncate block" title={binary.fileNames.join(", ")}>
                    {binary.fileNames.slice(0, 2).join(", ") || "—"}
                    {binary.fileNames.length > 2 ? ` +${binary.fileNames.length - 2}` : ""}
                  </span>
                </td>
                <td className="px-3 py-2 whitespace-nowrap">
                  <span className={clsx("tag", coverageClass(binary.signingCoverage))}>
                    {binary.signingCoverage}
                  </span>
                </td>
                <td className="px-3 py-2 font-mono text-text-muted max-w-[160px]">
                  <span className="truncate block" title={binary.sha256 ?? undefined}>
                    {binary.sha256 ? binary.sha256.substring(0, 20) + "…" : "—"}
                  </span>
                </td>
                <td className="px-3 py-2 text-text-secondary max-w-[200px]">
                  <span className="truncate block" title={binary.signerNames[0]}>
                    {binary.signerNames[0] ?? "—"}
                  </span>
                </td>
                <td className="px-3 py-2 text-text-muted tabular-nums text-center">
                  {binary.deviceNames.length}
                </td>
                <td className="px-3 py-2 text-text-muted tabular-nums text-center">
                  {binary.observationCount}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {pageCount > 1 && (
        <div className="flex items-center justify-between text-xs text-text-muted">
          <span>
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, binaries.length)} of{" "}
            {binaries.length}
          </span>
          <div className="flex gap-1">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-2 py-1 rounded border border-border hover:bg-surface-2 disabled:opacity-40"
            >
              ←
            </button>
            <button
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              disabled={page === pageCount - 1}
              className="px-2 py-1 rounded border border-border hover:bg-surface-2 disabled:opacity-40"
            >
              →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Schema reference guide
// ---------------------------------------------------------------------------

function SchemaReferencePanel() {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 w-full text-left"
      >
        <HelpCircle size={14} className="text-text-muted" />
        <span className="text-sm font-medium text-text-primary flex-1">
          Supported Defender Tables & Field Mapping
        </span>
        {open ? <ChevronDown size={14} className="text-text-muted" /> : <ChevronRight size={14} className="text-text-muted" />}
      </button>
      {open && (
        <div className="mt-4 space-y-4 text-xs text-text-secondary">
          <div>
            <p className="font-medium text-text-primary mb-2">Recognised Defender Tables</p>
            <div className="space-y-2">
              {[
                {
                  name: "DeviceFileCertificateInfo",
                  key: "SubjectName, IsSigned, SHA256",
                  note: "Certificate-centric. Best source for publisher data. No FileName/FolderPath.",
                },
                {
                  name: "DeviceFileEvents",
                  key: "FileName, FolderPath, SHA256",
                  note: "File creation/modification events. Good for path and hash context.",
                },
                {
                  name: "DeviceProcessEvents",
                  key: "FileName, FolderPath, SHA256",
                  note: "Process launch events. Covers executables loaded by users and services.",
                },
                {
                  name: "DeviceImageLoadEvents",
                  key: "FileName, FolderPath, SHA256",
                  note: "DLL and kernel driver load events. Relevant for driver policy.",
                },
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
            <p className="mb-2">
              If no named table is detected, the importer uses case-insensitive matching against
              these aliases for each canonical field:
            </p>
            <div className="bg-surface-2 rounded p-2.5 font-mono space-y-1">
              {[
                ["SHA256", "SHA256 · Sha256 · FileHashSHA256 · Hash"],
                ["Signer", "SubjectName · SignerName · Publisher · PublisherName · CertSubject"],
                ["Issuer", "IssuerName · Issuer · CertIssuer · CertificateIssuerName"],
                ["FileName", "FileName · ProcessImageName · ImageName"],
                ["FolderPath", "FolderPath · DirectoryPath · Directory"],
                ["DeviceName", "DeviceName · ComputerName · HostName · MachineName"],
                ["Timestamp", "Timestamp · EventTime · TimeGenerated · CreatedTime"],
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
              <li>Results wrapper: <code className="font-mono">{"{ \"Results\": [...] }"}</code></li>
              <li>Columnar: <code className="font-mono">{"{ \"schema\": [...], \"rows\": [[...]] }"}</code></li>
            </ul>
          </div>
          <div>
            <p className="font-medium text-text-primary mb-2">Recommended KQL Pattern</p>
            <pre className="bg-surface-2 rounded p-3 text-xs font-mono overflow-x-auto leading-relaxed">
{`// Combine file events with cert info for best publisher coverage
DeviceFileEvents
| where Timestamp > ago(7d)
| project SHA256, FileName, FolderPath, DeviceName, Timestamp
| join kind=leftouter (
    DeviceFileCertificateInfo
    | project SHA256, SubjectName, IssuerName, IsSigned
) on SHA256
| summarize
    FileName=any(FileName),
    FolderPath=any(FolderPath),
    SubjectName=any(SubjectName),
    IssuerName=any(IssuerName),
    IsSigned=any(IsSigned),
    Devices=dcount(DeviceName),
    Timestamp=min(Timestamp)
  by SHA256
| export to csv`}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Filter bar for candidates tab
// ---------------------------------------------------------------------------

interface CandidateFilters {
  ruleType: HuntingRuleType | "all";
  risk: HuntingRuleRisk | "all";
  effect: "Allow" | "Deny" | "all";
}

function filterCandidates(
  candidates: HuntingRuleCandidate[],
  filters: CandidateFilters
): HuntingRuleCandidate[] {
  return candidates
    .filter((c) => filters.ruleType === "all" || c.ruleType === filters.ruleType)
    .filter((c) => filters.risk === "all" || c.risk === filters.risk)
    .filter((c) => filters.effect === "all" || c.effect === filters.effect)
    .sort((a, b) => {
      const riskOrder: Record<HuntingRuleRisk, number> = {
        critical: 5, high: 4, medium: 3, low: 2, safe: 1,
      };
      const dr = riskOrder[b.risk] - riskOrder[a.risk];
      if (dr !== 0) return dr;
      return b.confidence - a.confidence;
    });
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

const RISK_LEVELS: Array<HuntingRuleRisk | "all"> = ["all", "safe", "low", "medium", "high", "critical"];
const RULE_TYPES: Array<HuntingRuleType | "all"> = [
  "all", "publisher-scoped", "publisher", "hash", "path", "path-wildcard",
];

export function AdvancedHuntingPage() {
  const [fileName, setFileName] = useState<string | null>(null);
  const [format, setFormat] = useState<"auto" | "json" | "csv">("auto");
  const [preferPublisher, setPreferPublisher] = useState(true);
  const [scopePublisher, setScopePublisher] = useState(true);
  const [includePathRules, setIncludePathRules] = useState(false);
  const [effect, setEffect] = useState<"Allow" | "Deny">("Allow");
  const [activeTab, setActiveTab] = useState<"candidates" | "inventory">("candidates");
  const [filters, setFilters] = useState<CandidateFilters>({
    ruleType: "all",
    risk: "all",
    effect: "all",
  });

  const mutation = useMutation({
    mutationFn: (content: string) =>
      policyApi.ingestAdvancedHunting({
        format,
        content,
        preferPublisherRules: preferPublisher,
        scopePublisherRules: scopePublisher,
        includePathRules,
        effect,
      }),
  });

  function handleFile(content: string, name: string) {
    setFileName(name);
    mutation.mutate(content);
  }

  const result = mutation.data;
  const filteredCandidates = result
    ? filterCandidates(result.ruleCandidates, filters)
    : [];

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <Search size={18} className="text-accent-blue" />
          <h1 className="text-base font-semibold text-text-primary">Advanced Hunting Ingestor</h1>
        </div>
        <p className="text-xs text-text-muted mt-1">
          Convert Microsoft Defender Advanced Hunting query results into WDAC rule candidates.
          Supports DeviceFileCertificateInfo, DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
          and generic column exports.
        </p>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4">

        {/* Options + Drop Zone */}
        <div className="grid grid-cols-[1fr_320px] gap-4">
          {/* Options */}
          <div className="panel space-y-4">
            <p className="text-xs font-medium text-text-secondary uppercase tracking-wider">
              Ingestion Options
            </p>

            {/* Format selector */}
            <div>
              <p className="text-xs text-text-muted mb-1.5">Input Format</p>
              <div className="flex gap-1.5">
                {(["auto", "json", "csv"] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setFormat(f)}
                    className={clsx(
                      "px-3 py-1 rounded text-xs border transition-colors",
                      format === f
                        ? "border-accent-blue bg-accent-blue-dim text-accent-blue"
                        : "border-border text-text-secondary hover:border-accent-blue hover:text-text-primary"
                    )}
                  >
                    {f.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {/* Effect */}
            <div>
              <p className="text-xs text-text-muted mb-1.5">Rule Effect</p>
              <div className="flex gap-1.5">
                {(["Allow", "Deny"] as const).map((e) => (
                  <button
                    key={e}
                    onClick={() => setEffect(e)}
                    className={clsx(
                      "px-3 py-1 rounded text-xs border transition-colors",
                      effect === e
                        ? e === "Allow"
                          ? "border-accent-green bg-accent-green-dim text-accent-green"
                          : "border-accent-red bg-accent-red-dim text-accent-red"
                        : "border-border text-text-secondary hover:text-text-primary"
                    )}
                  >
                    {e}
                  </button>
                ))}
              </div>
            </div>

            {/* Toggle options */}
            <div className="space-y-2">
              {[
                {
                  label: "Prefer publisher rules",
                  detail: "Use CertPublisher rules where signing data is available.",
                  value: preferPublisher,
                  set: setPreferPublisher,
                },
                {
                  label: "Scope publisher rules to FileName",
                  detail: "Add FileAttrib scoping when FileName is consistent across all observations.",
                  value: scopePublisher,
                  set: setScopePublisher,
                  disabled: !preferPublisher,
                },
                {
                  label: "Include path rules for no-hash binaries",
                  detail: "Generate FilePath rules for binaries with no SHA256. Higher risk — use with caution.",
                  value: includePathRules,
                  set: setIncludePathRules,
                },
              ].map(({ label, detail, value, set, disabled }) => (
                <label
                  key={label}
                  className={clsx(
                    "flex items-start gap-3 cursor-pointer group",
                    disabled && "opacity-50 cursor-not-allowed"
                  )}
                >
                  <div className="flex-shrink-0 mt-0.5">
                    <div
                      onClick={() => !disabled && set(!value)}
                      className={clsx(
                        "w-8 h-4 rounded-full transition-colors relative",
                        value && !disabled ? "bg-accent-blue" : "bg-surface-3"
                      )}
                    >
                      <div
                        className={clsx(
                          "absolute top-0.5 w-3 h-3 rounded-full bg-white shadow transition-transform",
                          value && !disabled ? "translate-x-4" : "translate-x-0.5"
                        )}
                      />
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

          {/* Drop zone */}
          <div className="flex flex-col gap-3">
            <FileDropZone
              label="Drop Advanced Hunting export here"
              onFile={handleFile}
            />
            {fileName && (
              <div className="flex items-center gap-2 px-3 py-2 bg-surface-2 rounded text-xs">
                <Eye size={12} className="text-text-muted" />
                <span className="text-text-secondary truncate" title={fileName}>{fileName}</span>
              </div>
            )}
            {mutation.isPending && (
              <div className="flex items-center gap-2 text-xs text-text-muted px-1">
                <div className="w-3 h-3 border border-accent-blue border-t-transparent rounded-full animate-spin" />
                Ingesting…
              </div>
            )}
            {mutation.isError && (
              <div className="flex items-start gap-2 text-xs text-accent-red px-1">
                <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" />
                <span>{(mutation.error as Error).message}</span>
              </div>
            )}
          </div>
        </div>

        {/* Results section */}
        {result && (
          <>
            <StatsBar result={result} />
            <WarningsPanel warnings={result.warnings} />

            {/* Tabs */}
            <div>
              <div className="flex items-center border-b border-border mb-4">
                {[
                  { key: "candidates" as const, label: `Rule Candidates (${result.ruleCandidates.length})` },
                  { key: "inventory" as const, label: `Binary Inventory (${result.binaries.length})` },
                ].map(({ key, label }) => (
                  <button
                    key={key}
                    onClick={() => setActiveTab(key)}
                    className={clsx(
                      "px-4 py-2 text-sm border-b-2 -mb-px transition-colors",
                      activeTab === key
                        ? "border-accent-blue text-text-primary font-medium"
                        : "border-transparent text-text-secondary hover:text-text-primary"
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {activeTab === "candidates" && (
                <div className="space-y-4">
                  {/* Filter bar */}
                  <div className="flex flex-wrap items-center gap-3 p-3 bg-surface-1 border border-border rounded">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-text-muted">Type:</span>
                      <select
                        value={filters.ruleType}
                        onChange={(e) =>
                          setFilters((f) => ({ ...f, ruleType: e.target.value as CandidateFilters["ruleType"] }))
                        }
                        className="bg-surface-2 border border-border rounded px-2 py-1 text-text-primary focus:outline-none focus:border-accent-blue"
                      >
                        {RULE_TYPES.map((t) => (
                          <option key={t} value={t}>{t === "all" ? "All types" : ruleTypeLabel(t as HuntingRuleType)}</option>
                        ))}
                      </select>
                    </div>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-text-muted">Risk:</span>
                      <select
                        value={filters.risk}
                        onChange={(e) =>
                          setFilters((f) => ({ ...f, risk: e.target.value as CandidateFilters["risk"] }))
                        }
                        className="bg-surface-2 border border-border rounded px-2 py-1 text-text-primary focus:outline-none focus:border-accent-blue"
                      >
                        {RISK_LEVELS.map((r) => (
                          <option key={r} value={r}>{r === "all" ? "All risks" : r}</option>
                        ))}
                      </select>
                    </div>
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-text-muted">Effect:</span>
                      <select
                        value={filters.effect}
                        onChange={(e) =>
                          setFilters((f) => ({ ...f, effect: e.target.value as CandidateFilters["effect"] }))
                        }
                        className="bg-surface-2 border border-border rounded px-2 py-1 text-text-primary focus:outline-none focus:border-accent-blue"
                      >
                        <option value="all">All</option>
                        <option value="Allow">Allow</option>
                        <option value="Deny">Deny</option>
                      </select>
                    </div>
                    {filteredCandidates.length !== result.ruleCandidates.length && (
                      <span className="text-xs text-text-muted ml-auto">
                        {filteredCandidates.length} of {result.ruleCandidates.length} shown
                      </span>
                    )}
                  </div>

                  {filteredCandidates.length === 0 ? (
                    <div className="text-center py-12 text-text-muted">
                      <CheckCircle size={32} className="mx-auto mb-2 opacity-30" />
                      <p className="text-sm">No candidates match the current filters.</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {filteredCandidates.map((candidate) => (
                        <HuntingRuleCandidateCard key={candidate.id} candidate={candidate} />
                      ))}
                    </div>
                  )}
                </div>
              )}

              {activeTab === "inventory" && (
                <BinaryInventory binaries={result.binaries} />
              )}
            </div>
          </>
        )}

        {/* Schema reference (always visible at bottom) */}
        <SchemaReferencePanel />
      </div>
    </div>
  );
}
