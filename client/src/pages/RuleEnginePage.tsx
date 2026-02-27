import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  Cpu,
  ChevronDown,
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  Hash,
  FolderOpen,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Minus,
  ToggleLeft,
  ToggleRight,
  Lock,
  Unlock,
} from "lucide-react";
import clsx from "clsx";
import { policyApi } from "../lib/api.ts";
import { useAppStore } from "../store/index.ts";
import { Header } from "../components/layout/Header.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import { EmptyState } from "../components/common/EmptyState.tsx";
import type {
  ProposedRule,
  ProposedPolicyChanges,
  SafetyWarning,
  RuleRiskLevel,
  RuleConfidenceLevel,
  ProposedRuleKind,
} from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Options panel
// ---------------------------------------------------------------------------

interface EngineOptions {
  preferSignerRules: boolean;
  scopeSignerRules: boolean;
  includePathRules: boolean;
  includeDenyRules: boolean;
}

const DEFAULT_OPTIONS: EngineOptions = {
  preferSignerRules: true,
  scopeSignerRules: true,
  includePathRules: false,
  includeDenyRules: false,
};

// ---------------------------------------------------------------------------
// Color / badge helpers
// ---------------------------------------------------------------------------

function riskBadge(level: RuleRiskLevel) {
  const map: Record<RuleRiskLevel, string> = {
    safe: "tag-green",
    low: "tag-blue",
    medium: "tag-yellow",
    high: "tag-orange",
    critical: "tag-red",
  };
  return (
    <span className={clsx(map[level], "uppercase text-xs font-semibold px-1.5 py-0.5 rounded")}>
      {level}
    </span>
  );
}

function confidenceBadge(level: RuleConfidenceLevel, score: number) {
  const map: Record<RuleConfidenceLevel, string> = {
    high: "text-accent-green",
    medium: "text-accent-yellow",
    low: "text-accent-red",
  };
  return (
    <span className={clsx("mono text-xs font-semibold", map[level])}>
      {Math.round(score * 100)}%
    </span>
  );
}

function kindIcon(kind: ProposedRuleKind) {
  switch (kind) {
    case "signer":       return <Unlock size={13} className="text-accent-blue" />;
    case "scoped-signer": return <Lock size={13} className="text-accent-green" />;
    case "hash":         return <Hash size={13} className="text-accent-yellow" />;
    case "path":         return <FolderOpen size={13} className="text-accent-red" />;
  }
}

function kindLabel(kind: ProposedRuleKind) {
  switch (kind) {
    case "signer":       return "Publisher";
    case "scoped-signer": return "Scoped Publisher";
    case "hash":         return "Hash (SHA-256)";
    case "path":         return "Path";
  }
}

function warnIcon(severity: SafetyWarning["severity"]) {
  switch (severity) {
    case "critical": return <XCircle size={12} className="text-accent-red flex-shrink-0" />;
    case "warning":  return <AlertTriangle size={12} className="text-accent-yellow flex-shrink-0" />;
    case "info":     return <Info size={12} className="text-text-muted flex-shrink-0" />;
  }
}

function effectIcon(effect: "Allow" | "Deny") {
  return effect === "Allow"
    ? <CheckCircle2 size={12} className="text-accent-green flex-shrink-0" />
    : <XCircle size={12} className="text-accent-red flex-shrink-0" />;
}

// ---------------------------------------------------------------------------
// Toggle switch component
// ---------------------------------------------------------------------------

function Toggle({
  value,
  onChange,
  label,
  description,
}: {
  value: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description: string;
}) {
  return (
    <button
      onClick={() => onChange(!value)}
      className="flex items-start gap-3 text-left w-full p-3 rounded hover:bg-surface-2 transition-colors"
    >
      <span className="mt-0.5 text-accent-blue flex-shrink-0">
        {value ? <ToggleRight size={18} /> : <ToggleLeft size={18} className="text-text-muted" />}
      </span>
      <span>
        <p className={clsx("text-xs font-medium", value ? "text-text-primary" : "text-text-secondary")}>
          {label}
        </p>
        <p className="text-xs text-text-muted mt-0.5">{description}</p>
      </span>
    </button>
  );
}

// ---------------------------------------------------------------------------
// EngineOptionsPanel
// ---------------------------------------------------------------------------

function EngineOptionsPanel({
  options,
  onChange,
}: {
  options: EngineOptions;
  onChange: (opts: EngineOptions) => void;
}) {
  const set = (key: keyof EngineOptions) => (v: boolean) =>
    onChange({ ...options, [key]: v });

  return (
    <div className="card p-4">
      <h2 className="section-header mb-2">Engine Options</h2>
      <div className="divide-y divide-border">
        <Toggle
          value={options.preferSignerRules}
          onChange={set("preferSignerRules")}
          label="Prefer Publisher/Signer Rules"
          description="Use certificate-based trust when signing info is available — more maintainable than hash rules."
        />
        <Toggle
          value={options.scopeSignerRules}
          onChange={set("scopeSignerRules")}
          label="Scope Signer Rules with FileAttrib"
          description="Restrict publisher rules to specific product names or filenames (least-permissive signer trust)."
        />
        <Toggle
          value={options.includePathRules}
          onChange={set("includePathRules")}
          label="Include Path Rules (high risk)"
          description="Propose path-based rules as a last resort for files without hash or signing info."
        />
        <Toggle
          value={options.includeDenyRules}
          onChange={set("includeDenyRules")}
          label="Include Deny Rules for Block Events"
          description="Also propose explicit deny rules for files that were actively blocked (severity=block)."
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SafetyWarningList
// ---------------------------------------------------------------------------

function SafetyWarningList({ warnings }: { warnings: SafetyWarning[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="space-y-1.5">
      {warnings.map((w, i) => (
        <div key={i} className="flex items-start gap-2">
          {warnIcon(w.severity)}
          <div>
            <p className="text-xs font-medium text-text-secondary">{w.message}</p>
            <p className="text-xs text-text-muted mt-0.5">{w.detail}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ProposedRuleCard
// ---------------------------------------------------------------------------

function ProposedRuleCard({ rule }: { rule: ProposedRule }) {
  const [expanded, setExpanded] = useState(false);
  const isRedundant = Boolean(rule.supersededBy);

  const ruleValue =
    rule.kind === "hash"
      ? (rule.fileRule as { hash: string } | undefined)?.hash?.substring(0, 32) + "…"
      : rule.kind === "path"
        ? (rule.fileRule as { filePath: string } | undefined)?.filePath
        : rule.signerRule?.certPublisher ?? rule.signerRule?.name ?? "—";

  return (
    <div
      className={clsx(
        "card border transition-all",
        isRedundant && "opacity-50 border-dashed",
        !isRedundant && rule.riskLevel === "critical" && "border-accent-red/40",
        !isRedundant && rule.riskLevel === "high" && "border-accent-yellow/30",
      )}
    >
      {/* Header row */}
      <button
        className="w-full flex items-center gap-3 p-3 text-left"
        onClick={() => setExpanded((v) => !v)}
      >
        {/* Kind icon */}
        <span className="w-5 flex-shrink-0 flex items-center justify-center">
          {kindIcon(rule.kind)}
        </span>

        {/* Effect */}
        <span className="flex-shrink-0">{effectIcon(rule.effect)}</span>

        {/* Kind label */}
        <span className="text-xs font-medium text-text-secondary w-28 flex-shrink-0">
          {kindLabel(rule.kind)}
        </span>

        {/* Value */}
        <span className="flex-1 mono text-xs text-text-primary truncate" title={ruleValue ?? ""}>
          {ruleValue}
        </span>

        {/* Badges */}
        <div className="flex items-center gap-2 flex-shrink-0">
          {isRedundant && (
            <span className="text-xs text-text-muted italic">redundant</span>
          )}
          {confidenceBadge(rule.confidenceLevel, rule.confidence)}
          {riskBadge(rule.riskLevel)}
          {rule.warnings.length > 0 && (
            <span className="flex items-center gap-0.5 text-xs text-accent-yellow">
              <AlertTriangle size={11} />
              {rule.warnings.length}
            </span>
          )}
          <span className="text-text-muted">
            {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </span>
        </div>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-border p-4 space-y-4 text-xs">
          {/* Reasoning */}
          <div>
            <p className="section-header mb-1">Reasoning</p>
            <p className="text-text-secondary">{rule.reasoning}</p>
          </div>

          {/* WDAC evaluation */}
          <div>
            <p className="section-header mb-1">WDAC Evaluation</p>
            <div className="grid grid-cols-2 gap-2">
              <KV label="Phase" value={rule.wdacEvaluation.evaluationPhase} />
              <KV label="Precedence" value={String(rule.wdacEvaluation.precedenceOrder)} />
              <KV label="Kernel Mode" value={rule.wdacEvaluation.impactsKernelMode ? "Yes" : "No"} />
              <KV label="User Mode" value={rule.wdacEvaluation.impactsUserMode ? "Yes" : "No"} />
              <KV label="Boot Critical" value={rule.wdacEvaluation.isBootCritical ? "Yes" : "No"} />
              <KV label="Signing Scenario" value={rule.signingScenario} />
            </div>
            <p className="text-text-muted mt-2 italic">{rule.wdacEvaluation.precedenceNote}</p>
          </div>

          {/* Proposed rule IDs */}
          <div>
            <p className="section-header mb-1">Proposed Rule Object(s)</p>
            <div className="grid grid-cols-2 gap-2">
              {rule.signerRule && <KV label="Signer ID" value={rule.signerRule.id} mono />}
              {rule.fileAttrib && <KV label="FileAttrib ID" value={rule.fileAttrib.id} mono />}
              {rule.fileRule && <KV label="File Rule ID" value={rule.fileRule.id} mono />}
              {rule.fileAttrib?.productName && (
                <KV label="Scoped to Product" value={rule.fileAttrib.productName} />
              )}
              {rule.fileAttrib?.internalName && (
                <KV label="Scoped to InternalName" value={rule.fileAttrib.internalName} />
              )}
              {rule.fileAttrib?.fileName && (
                <KV label="Scoped to FileName" value={rule.fileAttrib.fileName} />
              )}
              {rule.signerRule?.certRoot && (
                <KV label="Cert Root TBS" value={rule.signerRule.certRoot.value.substring(0, 24) + "…"} mono />
              )}
            </div>
          </div>

          {/* Evidence */}
          <div>
            <p className="section-header mb-1">
              Evidence ({rule.sourceEventCount} event{rule.sourceEventCount !== 1 ? "s" : ""})
            </p>
            <div className="grid grid-cols-2 gap-2">
              <KV label="Event IDs" value={rule.sourceEventIds.join(", ")} />
              <KV label="Machines" value={rule.sourceMachines.join(", ") || "unknown"} />
            </div>
            <div className="mt-2 max-h-24 overflow-auto space-y-0.5">
              {rule.sourceFiles.map((f, i) => (
                <p key={i} className="mono text-text-muted truncate">{f}</p>
              ))}
            </div>
          </div>

          {/* Confidence factors */}
          <div>
            <p className="section-header mb-1">Confidence Factors</p>
            <ul className="space-y-0.5">
              {rule.confidenceFactors.map((f, i) => (
                <li key={i} className="text-text-muted flex items-start gap-1.5">
                  <Minus size={10} className="mt-0.5 flex-shrink-0" />
                  {f}
                </li>
              ))}
            </ul>
          </div>

          {/* Warnings */}
          {rule.warnings.length > 0 && (
            <div>
              <p className="section-header mb-1">Safety Warnings</p>
              <SafetyWarningList warnings={rule.warnings} />
            </div>
          )}

          {/* Deduplication info */}
          {rule.supersededBy && (
            <div className="p-2 bg-surface-2 rounded border border-border">
              <p className="text-text-muted">
                This rule is redundant — covered by proposal{" "}
                <span className="mono">{rule.supersededBy.substring(0, 8)}…</span>
              </p>
            </div>
          )}
          {rule.supersedes && rule.supersedes.length > 0 && (
            <div className="p-2 bg-surface-2 rounded border border-border">
              <p className="text-text-muted">
                This rule makes {rule.supersedes.length} hash/path rule(s) redundant.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function KV({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <p className="text-text-muted">{label}</p>
      <p className={clsx("text-text-secondary font-medium truncate", mono && "mono")}>{value}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Summary bar
// ---------------------------------------------------------------------------

function SummaryBar({ summary }: { summary: ProposedPolicyChanges["summary"] }) {
  const pills = [
    { label: "Active Rules", value: summary.activeRules, color: "text-accent-green" },
    { label: "Signer", value: summary.signerRules, color: "text-accent-blue" },
    { label: "Scoped", value: summary.scopedSignerRules, color: "text-accent-green" },
    { label: "Hash", value: summary.hashRules, color: "text-accent-yellow" },
    { label: "Path", value: summary.pathRules, color: "text-accent-red" },
    { label: "Redundant", value: summary.redundantRules, color: "text-text-muted" },
    { label: "High Risk", value: summary.highRiskRules, color: "text-accent-orange" },
    { label: "Critical", value: summary.criticalRiskRules, color: "text-accent-red" },
    { label: "Warnings", value: summary.totalWarnings, color: "text-accent-yellow" },
  ];

  return (
    <div className="card p-3 flex items-center gap-4 flex-wrap">
      {pills.map((p) => (
        <div key={p.label} className="text-center">
          <p className={clsx("text-lg font-bold mono leading-none", p.color)}>{p.value}</p>
          <p className="text-xs text-text-muted mt-0.5">{p.label}</p>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Filter bar
// ---------------------------------------------------------------------------

type FilterKind = "all" | "signer" | "scoped-signer" | "hash" | "path";
type FilterRisk = "all" | "safe" | "low" | "medium" | "high" | "critical";
type FilterEffect = "all" | "Allow" | "Deny";
type FilterRedundancy = "all" | "active" | "redundant";

interface Filters {
  kind: FilterKind;
  risk: FilterRisk;
  effect: FilterEffect;
  redundancy: FilterRedundancy;
}

function FilterBar({
  filters,
  onChange,
}: {
  filters: Filters;
  onChange: (f: Filters) => void;
}) {
  const set =
    <K extends keyof Filters>(key: K) =>
    (v: Filters[K]) =>
      onChange({ ...filters, [key]: v });

  function FilterSelect<T extends string>({
    label,
    value,
    options,
    onSelect,
  }: {
    label: string;
    value: T;
    options: T[];
    onSelect: (v: T) => void;
  }) {
    return (
      <div className="flex items-center gap-1.5">
        <span className="text-xs text-text-muted">{label}:</span>
        <select
          value={value}
          onChange={(e) => onSelect(e.target.value as T)}
          className="text-xs bg-surface-2 border border-border rounded px-1.5 py-0.5 text-text-secondary"
        >
          {options.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-4 flex-wrap">
      <FilterSelect
        label="Kind"
        value={filters.kind}
        options={["all", "signer", "scoped-signer", "hash", "path"] as FilterKind[]}
        onSelect={set("kind")}
      />
      <FilterSelect
        label="Risk"
        value={filters.risk}
        options={["all", "safe", "low", "medium", "high", "critical"] as FilterRisk[]}
        onSelect={set("risk")}
      />
      <FilterSelect
        label="Effect"
        value={filters.effect}
        options={["all", "Allow", "Deny"] as FilterEffect[]}
        onSelect={set("effect")}
      />
      <FilterSelect
        label="Show"
        value={filters.redundancy}
        options={["active", "all", "redundant"] as FilterRedundancy[]}
        onSelect={set("redundancy")}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Build log panel
// ---------------------------------------------------------------------------

function BuildLog({ log }: { log: string[] }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="card">
      <button
        className="w-full flex items-center justify-between p-3 text-left"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="text-xs font-medium text-text-secondary">
          Engine Build Log ({log.length} entries)
        </span>
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
      </button>
      {open && (
        <div className="border-t border-border p-3 max-h-64 overflow-auto">
          {log.map((line, i) => (
            <p key={i} className="mono text-xs text-text-muted leading-relaxed">
              {line}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Global warnings panel
// ---------------------------------------------------------------------------

function GlobalWarningsPanel({ warnings }: { warnings: SafetyWarning[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="card p-4 border-accent-yellow/30">
      <h2 className="section-header text-accent-yellow mb-2">
        Global Warnings ({warnings.length})
      </h2>
      <SafetyWarningList warnings={warnings} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function RuleEnginePage() {
  const { importedEvents, proposedChanges, setProposedChanges } = useAppStore();
  const [options, setOptions] = useState<EngineOptions>(DEFAULT_OPTIONS);
  const [filters, setFilters] = useState<Filters>({
    kind: "all",
    risk: "all",
    effect: "all",
    redundancy: "active",
  });

  const proposeMutation = useMutation({
    mutationFn: () =>
      policyApi.proposeRules({
        events: importedEvents,
        ...options,
      }),
    onSuccess: (data) => setProposedChanges(data.changes),
  });

  const changes = proposedChanges;

  // Apply filters
  const visibleRules = changes
    ? changes.rules.filter((r) => {
        if (filters.kind !== "all" && r.kind !== filters.kind) return false;
        if (filters.risk !== "all" && r.riskLevel !== filters.risk) return false;
        if (filters.effect !== "all" && r.effect !== filters.effect) return false;
        if (filters.redundancy === "active" && r.supersededBy) return false;
        if (filters.redundancy === "redundant" && !r.supersededBy) return false;
        return true;
      })
    : [];

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Rule Engine"
        subtitle="Convert CI event logs into candidate WDAC policy rules"
        actions={
          importedEvents.length > 0 ? (
            <button
              className="btn-primary"
              onClick={() => proposeMutation.mutate()}
              disabled={proposeMutation.isPending}
            >
              <Cpu size={13} />
              {proposeMutation.isPending ? "Analyzing…" : "Propose Rules"}
            </button>
          ) : null
        }
      />

      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-5xl space-y-5">
          {/* Event source indicator */}
          <div className="card p-3 flex items-center gap-3">
            {importedEvents.length > 0 ? (
              <>
                <CheckCircle2 size={14} className="text-accent-green" />
                <span className="text-xs text-text-secondary">
                  <span className="font-semibold text-text-primary">{importedEvents.length}</span>{" "}
                  CodeIntegrity events loaded — ready to analyze
                </span>
              </>
            ) : (
              <>
                <AlertTriangle size={14} className="text-accent-yellow" />
                <span className="text-xs text-text-muted">
                  No events loaded. Go to{" "}
                  <a href="/import-events" className="text-accent-blue hover:underline">
                    Import Events
                  </a>{" "}
                  to load CodeIntegrity event data first.
                </span>
              </>
            )}
          </div>

          {/* Options */}
          <EngineOptionsPanel options={options} onChange={setOptions} />

          {/* Loading */}
          {proposeMutation.isPending && (
            <div className="flex justify-center py-12">
              <LoadingSpinner label="Analyzing events and proposing rules…" />
            </div>
          )}

          {/* Error */}
          {proposeMutation.isError && (
            <div className="p-4 bg-accent-red-dim/30 border border-accent-red/20 rounded text-sm text-accent-red">
              {(proposeMutation.error as Error).message}
            </div>
          )}

          {/* Results */}
          {changes && !proposeMutation.isPending && (
            <>
              {/* Summary */}
              <SummaryBar summary={changes.summary} />

              {/* Global warnings */}
              <GlobalWarningsPanel warnings={changes.globalWarnings} />

              {/* WDAC evaluation model reference */}
              <WdacEvalModelRef />

              {/* Filter + rule list */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="section-header">
                    Proposed Rules ({visibleRules.length} of {changes.rules.length})
                  </h2>
                  <FilterBar filters={filters} onChange={setFilters} />
                </div>

                {visibleRules.length === 0 ? (
                  <EmptyState
                    icon={<ShieldCheck size={32} />}
                    title="No rules match the current filters"
                    description="Adjust the filter options above to see more rules."
                  />
                ) : (
                  <div className="space-y-2">
                    {visibleRules.map((rule) => (
                      <ProposedRuleCard key={rule.id} rule={rule} />
                    ))}
                  </div>
                )}
              </div>

              {/* Build log */}
              <BuildLog log={changes.buildLog} />
            </>
          )}

          {/* Empty state — no results yet */}
          {!changes && !proposeMutation.isPending && importedEvents.length > 0 && (
            <EmptyState
              icon={<Cpu size={40} />}
              title="Ready to propose rules"
              description="Configure the engine options above, then click Propose Rules to analyze your events."
            />
          )}

          {!changes && !proposeMutation.isPending && importedEvents.length === 0 && (
            <EmptyState
              icon={<ShieldAlert size={40} />}
              title="No event data"
              description="Import CodeIntegrity event logs from the Import Events page first."
            />
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// WDAC evaluation model reference card
// ---------------------------------------------------------------------------

function WdacEvalModelRef() {
  const [open, setOpen] = useState(false);

  const phases = [
    { order: 1, phase: "Deny File Rules", desc: "Explicit hash/path deny — evaluated first, highest priority." },
    { order: 2, phase: "Deny Signer Rules", desc: "Certificate-based deny — overrides any allow signer rules." },
    { order: 3, phase: "Allow Signer Rules", desc: "Publisher trust — most maintainable; covers all versions from a publisher." },
    { order: 4, phase: "Allow File Rules", desc: "Hash or path allow — version-locked (hash) or location-based (path)." },
    { order: 5, phase: "ISG", desc: "Microsoft cloud reputation (Intelligent Security Graph)." },
    { order: 6, phase: "Managed Installer", desc: "Trust from authorized package managers (e.g., MECM, Intune)." },
    { order: 7, phase: "Default Deny", desc: "If no rule matches in enforcement mode, the file is blocked." },
  ];

  return (
    <div className="card">
      <button
        className="w-full flex items-center justify-between p-3 text-left"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="flex items-center gap-2 text-xs font-medium text-text-secondary">
          <Info size={13} className="text-accent-blue" />
          WDAC Rule Evaluation Model Reference
        </span>
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
      </button>
      {open && (
        <div className="border-t border-border p-4">
          <p className="text-xs text-text-muted mb-3">
            App Control evaluates rules in the following order. A match at any phase short-circuits
            evaluation — later phases are not checked. Deny rules always take precedence over allow
            rules at the same or lower priority.
          </p>
          <div className="space-y-1.5">
            {phases.map((p) => (
              <div key={p.order} className="flex items-start gap-3">
                <span className="mono text-xs font-bold text-accent-blue w-4 flex-shrink-0 mt-0.5">
                  {p.order}.
                </span>
                <div>
                  <span className="text-xs font-semibold text-text-primary">{p.phase}</span>
                  <span className="text-xs text-text-muted ml-2">{p.desc}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
