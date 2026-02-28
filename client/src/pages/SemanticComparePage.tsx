import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  ShieldCheck,
  ShieldAlert,
  TrendingUp,
  TrendingDown,
  Minus,
  ChevronDown,
  ChevronRight,
  Plus,
  Trash2,
  Edit2,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Lock,
  Unlock,
  Hash,
  FolderOpen,
  Package,
  FileText,
} from "lucide-react";
import clsx from "clsx";
import { policyApi } from "../lib/api.ts";
import { Header } from "../components/layout/Header.tsx";
import { FileDropZone } from "../components/common/FileDropZone.tsx";
import { EmptyState } from "../components/common/EmptyState.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import type {
  PolicySemanticDiff,
  DiffedRule,
  ModifiedRule,
  OptionSemanticChange,
  RiskAssessment,
  HumanExplanation,
  TrustDirection,
  FindingSeverity,
  RiskVerdict,
} from "@appcontrol/shared";
import type { WdacHashRule, WdacPathRule, WdacPackageRule, WdacSignerRule } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Color / badge helpers
// ---------------------------------------------------------------------------

function verdictConfig(verdict: RiskVerdict) {
  switch (verdict) {
    case "improved":
      return { label: "Improved", color: "text-accent-green", bg: "bg-accent-green-dim/20 border-accent-green/30", icon: <TrendingDown size={14} /> };
    case "unchanged":
      return { label: "Unchanged", color: "text-text-secondary", bg: "bg-surface-2 border-border", icon: <Minus size={14} /> };
    case "degraded":
      return { label: "Degraded", color: "text-accent-yellow", bg: "bg-accent-yellow-dim/20 border-accent-yellow/30", icon: <TrendingUp size={14} /> };
    case "significantly-degraded":
      return { label: "Significantly Degraded", color: "text-accent-red", bg: "bg-accent-red-dim/20 border-accent-red/30", icon: <TrendingUp size={14} /> };
  }
}

function severityBadge(severity: FindingSeverity) {
  const map: Record<FindingSeverity, string> = {
    critical: "tag-red",
    high: "tag-orange",
    medium: "tag-yellow",
    low: "tag-blue",
    info: "tag-gray",
  };
  return <span className={clsx(map[severity], "capitalize")}>{severity}</span>;
}

function trustBadge(dir: TrustDirection) {
  if (dir === "broadened")
    return <span className="tag-red flex items-center gap-1"><TrendingUp size={10} />Broadened</span>;
  if (dir === "tightened")
    return <span className="tag-green flex items-center gap-1"><TrendingDown size={10} />Tightened</span>;
  return <span className="tag-gray">Neutral</span>;
}

function deltaChip(delta: number) {
  const sign = delta > 0 ? "+" : "";
  const color = delta > 0 ? "text-accent-red" : delta < 0 ? "text-accent-green" : "text-text-muted";
  return <span className={clsx("mono text-xs font-bold", color)}>{sign}{delta}</span>;
}

function ruleKindIcon(kind: string) {
  switch (kind) {
    case "hash":      return <Hash size={12} className="text-accent-yellow" />;
    case "path":      return <FolderOpen size={12} className="text-accent-red" />;
    case "package":   return <Package size={12} className="text-accent-blue" />;
    case "attribute": return <FileText size={12} className="text-text-muted" />;
    case "signer":
    case "scoped-signer":
      return <Lock size={12} className="text-accent-blue" />;
    default:          return <FileText size={12} />;
  }
}

function ruleValueSnippet(rule: DiffedRule | ModifiedRule): string {
  const r = "rule" in rule ? rule.rule : rule.rightRule;
  switch ((r as { kind: string }).kind) {
    case "hash":   return (r as WdacHashRule).hash?.substring(0, 24) + "…" ?? "";
    case "path":   return (r as WdacPathRule).filePath ?? "";
    case "package":return (r as WdacPackageRule).packageFamilyName ?? "";
    case "signer": return (r as WdacSignerRule).certPublisher ?? (r as WdacSignerRule).name ?? "";
    default: return "";
  }
}

// ---------------------------------------------------------------------------
// Risk Assessment banner
// ---------------------------------------------------------------------------

function RiskBanner({ assessment, modesChange }: {
  assessment: RiskAssessment;
  modesChange?: PolicySemanticDiff["effectiveModeChange"];
}) {
  const cfg = verdictConfig(assessment.verdict);

  return (
    <div className={clsx("card p-4 border", cfg.bg)}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <span className={cfg.color}>{cfg.icon}</span>
          <span className={clsx("text-sm font-semibold", cfg.color)}>
            Security Posture: {cfg.label}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-text-muted">Risk Delta:</span>
          {deltaChip(assessment.totalRiskDelta)}
        </div>
      </div>

      {modesChange && (
        <div className="mb-3 p-2.5 rounded bg-surface-2 border border-border text-xs">
          <span className="font-semibold text-text-primary mr-1.5">
            Mode: {modesChange.before} → {modesChange.after}
          </span>
          <span className="text-text-secondary">{modesChange.explanation}</span>
        </div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-6 gap-3">
        {[
          { label: "Added", value: assessment.broadeningCount, color: "text-accent-red" },
          { label: "Tightened", value: assessment.tighteningCount, color: "text-accent-green" },
          { label: "Neutral", value: assessment.neutralCount, color: "text-text-muted" },
          { label: "Kernel Impact", value: assessment.kernelImpactCount, color: "text-accent-yellow" },
          { label: "File Rules", value: assessment.riskByCategory.fileRules, color: assessment.riskByCategory.fileRules > 0 ? "text-accent-red" : "text-accent-green", prefix: true },
          { label: "Signer Rules", value: assessment.riskByCategory.signerRules, color: assessment.riskByCategory.signerRules > 0 ? "text-accent-red" : "text-accent-green", prefix: true },
        ].map((s) => (
          <div key={s.label} className="bg-surface-2/60 rounded p-2 text-center">
            <p className={clsx("text-base font-bold mono leading-none", s.color)}>
              {s.prefix && s.value > 0 ? "+" : ""}{s.value}
            </p>
            <p className="text-xs text-text-muted mt-0.5">{s.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Critical findings
// ---------------------------------------------------------------------------

function CriticalFindings({ findings }: { findings: string[] }) {
  if (findings.length === 0) return null;
  return (
    <div className="card p-4 border border-accent-red/30">
      <h2 className="section-header text-accent-red mb-2">
        Critical Findings ({findings.length})
      </h2>
      <div className="space-y-2">
        {findings.map((f, i) => (
          <div key={i} className="flex items-start gap-2">
            <XCircle size={12} className="text-accent-red flex-shrink-0 mt-0.5" />
            <p className="text-xs text-text-secondary">{f}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Human explanation panel
// ---------------------------------------------------------------------------

function HumanExplanationPanel({ explanation }: { explanation: HumanExplanation }) {
  const [open, setOpen] = useState(true);
  const sections = [
    { label: "Mode Changes", items: explanation.modeChanges, icon: <AlertTriangle size={12} className="text-accent-yellow" /> },
    { label: "Notable Additions", items: explanation.significantAdditions, icon: <Plus size={12} className="text-accent-red" /> },
    { label: "Notable Removals", items: explanation.significantRemovals, icon: <Trash2 size={12} className="text-accent-green" /> },
    { label: "Notable Modifications", items: explanation.significantModifications, icon: <Edit2 size={12} className="text-accent-yellow" /> },
    { label: "Kernel Impacts", items: explanation.kernelImpacts, icon: <ShieldAlert size={12} className="text-accent-red" /> },
  ].filter((s) => s.items.length > 0);

  return (
    <div className="card">
      <button
        className="w-full flex items-center justify-between p-4 text-left"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="flex items-center gap-2 text-sm font-medium text-text-primary">
          <Info size={14} className="text-accent-blue" />
          Security Analysis Summary
        </span>
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
      </button>

      {open && (
        <div className="border-t border-border p-4 space-y-4">
          {/* Executive summary */}
          <p className="text-xs text-text-secondary">{explanation.summary}</p>

          {/* Sections */}
          {sections.map((s) => (
            <div key={s.label}>
              <p className="flex items-center gap-1.5 text-xs font-semibold text-text-secondary mb-1.5">
                {s.icon}
                {s.label}
              </p>
              <ul className="space-y-1.5">
                {s.items.map((item, i) => (
                  <li key={i} className="text-xs text-text-muted pl-4 border-l border-border">
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}

          {/* Overall assessment */}
          <div className="p-3 bg-surface-2 rounded border border-border">
            <p className="text-xs font-semibold text-text-secondary mb-1">Overall Assessment</p>
            <p className="text-xs text-text-primary">{explanation.overallAssessment}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Single diffed rule card (added or removed)
// ---------------------------------------------------------------------------

function DiffedRuleCard({ rule, action }: { rule: DiffedRule; action: "added" | "removed" }) {
  const [expanded, setExpanded] = useState(false);
  const borderColor = action === "added" ? "border-accent-red/30" : "border-accent-green/30";
  const ruleKind = (rule.rule as { kind: string }).kind;
  const value = ruleValueSnippet(rule);

  return (
    <div className={clsx("card border", borderColor)}>
      <button
        className="w-full flex items-center gap-3 p-3 text-left"
        onClick={() => setExpanded((v) => !v)}
      >
        {/* Action icon */}
        <span className="flex-shrink-0">
          {action === "added"
            ? <Plus size={13} className="text-accent-red" />
            : <Trash2 size={13} className="text-accent-green" />
          }
        </span>

        {/* Rule kind */}
        <span className="flex-shrink-0">{ruleKindIcon(ruleKind)}</span>

        {/* Category */}
        <span className="text-xs font-medium text-text-secondary w-20 flex-shrink-0 capitalize">
          {ruleKind}
        </span>

        {/* Value */}
        <span className="flex-1 mono text-xs truncate text-text-primary" title={value}>
          {value || rule.id}
        </span>

        {/* Effect */}
        <span className="flex-shrink-0 text-xs text-text-muted">
          {rule.effect === "Allow"
            ? <CheckCircle2 size={12} className="text-accent-green" />
            : <XCircle size={12} className="text-accent-red" />
          }
        </span>

        {/* Badges */}
        <div className="flex items-center gap-2 flex-shrink-0">
          {trustBadge(rule.trustDirection)}
          {severityBadge(rule.severity)}
          {deltaChip(rule.riskDelta)}
          {rule.affectsKernel && (
            <span className="tag-red text-xs">Kernel</span>
          )}
          {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-border p-4 space-y-3 text-xs">
          <div>
            <p className="section-header mb-1">Security Explanation</p>
            <p className="text-text-secondary">{rule.explanation}</p>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <KV label="Rule ID" value={rule.id} mono />
            <KV label="Effect" value={rule.effect} />
            <KV label="Match Kind" value={rule.matchKind} />
            <KV label="Scenarios" value={rule.signingScenarios.join(", ")} />
            <KV label="Kernel Mode" value={rule.affectsKernel ? "Yes" : "No"} />
            <KV label="Risk Delta" value={(rule.riskDelta > 0 ? "+" : "") + rule.riskDelta} />
          </div>

          {rule.ruleCategory === "signer" && rule.fileAttribs !== undefined && (
            <div>
              <p className="section-header mb-1">FileAttrib Scope</p>
              <p className="text-text-secondary mono">
                {rule.fileAttribs.length > 0
                  ? rule.fileAttribs
                      .map((a) =>
                        [a.productName, a.internalName, a.fileName]
                          .filter(Boolean)
                          .join(", ")
                      )
                      .join("; ")
                  : "Unscoped — all files from this publisher"}
              </p>
            </div>
          )}

          {ruleKind === "hash" && (
            <div>
              <p className="section-header mb-1">Hash</p>
              <p className="mono text-text-muted break-all">
                {(rule.rule as WdacHashRule).hash}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Modified rule card
// ---------------------------------------------------------------------------

function ModifiedRuleCard({ rule }: { rule: ModifiedRule }) {
  const [expanded, setExpanded] = useState(false);
  const ruleKind = (rule.rightRule as { kind: string }).kind;
  const value = ruleValueSnippet(rule);
  const scopeDir = rule.signerScopeChange?.direction;

  return (
    <div className="card border border-accent-yellow/30">
      <button
        className="w-full flex items-center gap-3 p-3 text-left"
        onClick={() => setExpanded((v) => !v)}
      >
        <Edit2 size={13} className="text-accent-yellow flex-shrink-0" />
        <span className="flex-shrink-0">{ruleKindIcon(ruleKind)}</span>
        <span className="text-xs font-medium text-text-secondary w-20 flex-shrink-0 capitalize">{ruleKind}</span>
        <span className="flex-1 mono text-xs truncate text-text-primary" title={value}>{value || rule.id}</span>

        <div className="flex items-center gap-2 flex-shrink-0">
          {scopeDir === "broadened" && (
            <span className="tag-red text-xs flex items-center gap-1">
              <Unlock size={10} />Scope Broadened
            </span>
          )}
          {scopeDir === "narrowed" && (
            <span className="tag-green text-xs flex items-center gap-1">
              <Lock size={10} />Scope Narrowed
            </span>
          )}
          {rule.riskDelta !== 0 && trustBadge(rule.trustDirection)}
          {severityBadge(rule.severity)}
          {deltaChip(rule.riskDelta)}
          {rule.affectsKernel && <span className="tag-red text-xs">Kernel</span>}
          {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-border p-4 space-y-3 text-xs">
          <div>
            <p className="section-header mb-1">Explanation</p>
            <p className="text-text-secondary">{rule.explanation}</p>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <KV label="Changed Fields" value={rule.changedFields.join(", ")} />
            <KV label="Risk Delta" value={(rule.riskDelta > 0 ? "+" : "") + rule.riskDelta} />
          </div>

          {rule.signerScopeChange && rule.signerScopeChange.direction !== "unchanged" && (
            <div className="p-3 bg-surface-2 rounded border border-border space-y-2">
              <p className="font-semibold text-text-primary">Signer Scope Change</p>
              <p className="text-text-muted"><span className="text-text-secondary">Before: </span>{rule.signerScopeChange.scopeBefore}</p>
              <p className="text-text-muted"><span className="text-text-secondary">After: </span>{rule.signerScopeChange.scopeAfter}</p>
              <p className="text-text-secondary italic">{rule.signerScopeChange.detail}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Option changes panel
// ---------------------------------------------------------------------------

function OptionChangesPanel({ changes }: { changes: OptionSemanticChange[] }) {
  if (changes.length === 0) return null;
  return (
    <div className="card p-4">
      <h2 className="section-header mb-3">Option Changes ({changes.length})</h2>
      <div className="space-y-2">
        {changes.map((opt) => (
          <div
            key={opt.optionValue}
            className={clsx(
              "p-3 rounded border text-xs",
              opt.riskDelta > 20 ? "border-accent-red/30 bg-accent-red-dim/10" :
              opt.riskDelta > 0 ? "border-accent-yellow/30 bg-accent-yellow-dim/10" :
              opt.riskDelta < 0 ? "border-accent-green/30 bg-accent-green-dim/10" :
              "border-border"
            )}
          >
            <div className="flex items-center gap-3 mb-1.5">
              {trustBadge(opt.trustDirection)}
              {severityBadge(opt.severity)}
              {deltaChip(opt.riskDelta)}
              <span className="mono text-text-secondary font-medium">{opt.optionName}</span>
            </div>
            <p className="text-text-secondary">{opt.explanation}</p>
            <p className="text-text-muted mt-1">
              {opt.enabledBefore ? "✓ Enabled" : "✗ Disabled"} → {opt.enabledAfter ? "✓ Enabled" : "✗ Disabled"}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Diff section tabs
// ---------------------------------------------------------------------------

type DiffTab = "added" | "removed" | "modified" | "options";

function TabBar({
  tab,
  onTab,
  added,
  removed,
  modified,
  options,
}: {
  tab: DiffTab;
  onTab: (t: DiffTab) => void;
  added: number;
  removed: number;
  modified: number;
  options: number;
}) {
  const tabs: { id: DiffTab; label: string; count: number; countColor: string }[] = [
    { id: "added", label: "Added", count: added, countColor: "bg-accent-red text-white" },
    { id: "removed", label: "Removed", count: removed, countColor: "bg-accent-green text-black" },
    { id: "modified", label: "Modified", count: modified, countColor: "bg-accent-yellow text-black" },
    { id: "options", label: "Options", count: options, countColor: "bg-accent-blue text-white" },
  ];

  return (
    <div className="flex border-b border-border gap-1">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onTab(t.id)}
          className={clsx(
            "px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors",
            tab === t.id
              ? "border-accent-blue text-text-primary"
              : "border-transparent text-text-muted hover:text-text-secondary"
          )}
        >
          {t.label}
          {t.count > 0 && (
            <span className={clsx("ml-1.5 px-1.5 py-0.5 rounded-full text-xs font-bold", t.countColor)}>
              {t.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// KV helper
// ---------------------------------------------------------------------------

function KV({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-text-muted">{label}</p>
      <p className={clsx("text-text-secondary font-medium truncate", mono && "mono")}>{value}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Full diff view
// ---------------------------------------------------------------------------

function SemanticDiffView({ diff }: { diff: PolicySemanticDiff }) {
  const [tab, setTab] = useState<DiffTab>("added");

  return (
    <div className="space-y-5">
      {/* Risk banner */}
      <RiskBanner
        assessment={diff.riskAssessment}
        modesChange={diff.effectiveModeChange}
      />

      {/* Critical findings */}
      <CriticalFindings findings={diff.riskAssessment.criticalFindings} />

      {/* Human explanation */}
      <HumanExplanationPanel explanation={diff.humanExplanation} />

      {/* Policy identity */}
      <div className="card p-3 flex items-center gap-4 text-xs text-text-muted">
        <span>
          <span className="text-text-secondary font-medium">Baseline: </span>
          {diff.leftPolicy.friendlyName ?? diff.leftPolicy.policyId} v{diff.leftPolicy.versionEx}
        </span>
        <span className="text-text-muted">→</span>
        <span>
          <span className="text-text-secondary font-medium">Candidate: </span>
          {diff.rightPolicy.friendlyName ?? diff.rightPolicy.policyId} v{diff.rightPolicy.versionEx}
        </span>
      </div>

      {/* Tabs */}
      <div>
        <TabBar
          tab={tab}
          onTab={setTab}
          added={diff.addedRules.length}
          removed={diff.removedRules.length}
          modified={diff.modifiedRules.length}
          options={diff.optionChanges.length}
        />

        <div className="mt-4 space-y-2">
          {tab === "added" && (
            diff.addedRules.length === 0
              ? <p className="text-xs text-text-muted">No rules added.</p>
              : diff.addedRules
                  .sort((a, b) => b.riskDelta - a.riskDelta)
                  .map((r) => <DiffedRuleCard key={r.id} rule={r} action="added" />)
          )}
          {tab === "removed" && (
            diff.removedRules.length === 0
              ? <p className="text-xs text-text-muted">No rules removed.</p>
              : diff.removedRules
                  .sort((a, b) => Math.abs(b.riskDelta) - Math.abs(a.riskDelta))
                  .map((r) => <DiffedRuleCard key={r.id} rule={r} action="removed" />)
          )}
          {tab === "modified" && (
            diff.modifiedRules.length === 0
              ? <p className="text-xs text-text-muted">No rules modified.</p>
              : diff.modifiedRules
                  .sort((a, b) => Math.abs(b.riskDelta) - Math.abs(a.riskDelta))
                  .map((r) => <ModifiedRuleCard key={r.id} rule={r} />)
          )}
          {tab === "options" && (
            diff.optionChanges.length === 0
              ? <p className="text-xs text-text-muted">No option changes.</p>
              : <OptionChangesPanel changes={diff.optionChanges} />
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function SemanticComparePage() {
  const [leftXml, setLeftXml] = useState<string | null>(null);
  const [rightXml, setRightXml] = useState<string | null>(null);
  const [leftName, setLeftName] = useState("");
  const [rightName, setRightName] = useState("");

  const compareMutation = useMutation({
    mutationFn: ({ left, right }: { left: string; right: string }) =>
      policyApi.semanticCompare(left, right),
  });

  const diff = compareMutation.data?.diff ?? null;
  const canCompare = !!leftXml && !!rightXml;

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Semantic Comparison"
        subtitle="Security-aware policy diff — trust, risk, and plain-language impact"
        actions={
          canCompare ? (
            <button
              className="btn-primary"
              onClick={() => compareMutation.mutate({ left: leftXml!, right: rightXml! })}
              disabled={compareMutation.isPending}
            >
              <ShieldCheck size={13} />
              {compareMutation.isPending ? "Analyzing…" : "Analyze Security Impact"}
            </button>
          ) : null
        }
      />

      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-5xl space-y-5">
          {/* File pickers */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs font-medium text-text-secondary mb-2">
                Left Policy — Baseline
              </p>
              <FileDropZone
                accept=".xml"
                label="Drop Baseline Policy XML"
                onFile={(content, name) => { setLeftXml(content); setLeftName(name); }}
              />
              {leftName && (
                <p className="text-xs text-text-muted mt-1.5 flex items-center gap-1">
                  <CheckCircle2 size={11} className="text-accent-green" /> {leftName}
                </p>
              )}
            </div>
            <div>
              <p className="text-xs font-medium text-text-secondary mb-2">
                Right Policy — Candidate (newer / modified)
              </p>
              <FileDropZone
                accept=".xml"
                label="Drop Candidate Policy XML"
                onFile={(content, name) => { setRightXml(content); setRightName(name); }}
              />
              {rightName && (
                <p className="text-xs text-text-muted mt-1.5 flex items-center gap-1">
                  <CheckCircle2 size={11} className="text-accent-green" /> {rightName}
                </p>
              )}
            </div>
          </div>

          {/* Conceptual guide */}
          <ConceptualGuide />

          {compareMutation.isPending && (
            <div className="flex justify-center py-16">
              <LoadingSpinner label="Analyzing security impact of policy changes…" />
            </div>
          )}

          {compareMutation.isError && (
            <div className="p-4 bg-accent-red-dim/30 border border-accent-red/20 rounded text-sm text-accent-red">
              {(compareMutation.error as Error).message}
            </div>
          )}

          {diff && !compareMutation.isPending && <SemanticDiffView diff={diff} />}

          {!diff && !compareMutation.isPending && !compareMutation.isError && (
            <EmptyState
              icon={<ShieldCheck size={36} />}
              title="Load two policies to analyze"
              description="Drop baseline and candidate XML files above, then click Analyze Security Impact."
            />
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Conceptual guide card
// ---------------------------------------------------------------------------

function ConceptualGuide() {
  const [open, setOpen] = useState(false);

  const concepts = [
    {
      term: "Trust Broadened",
      color: "text-accent-red",
      desc: "A change allows more software to run (added Allow rule, removed Deny rule, widened signer scope).",
    },
    {
      term: "Trust Tightened",
      color: "text-accent-green",
      desc: "A change restricts more software (added Deny rule, removed Allow rule, narrowed signer scope with FileAttrib).",
    },
    {
      term: "Risk Delta",
      color: "text-text-secondary",
      desc: "Quantified risk change per change. Positive = more permissive. Aggregated across all changes for total verdict.",
    },
    {
      term: "Signer Scope (FileAttrib)",
      color: "text-accent-blue",
      desc: "A FileAttrib limits a publisher rule to specific product/filename. Removing scoping broadens trust to ALL publisher binaries.",
    },
    {
      term: "Rule Equivalence",
      color: "text-text-secondary",
      desc: "Rules matched by content fingerprint (not just ID), detecting semantically identical rules that were rebuilt with new IDs.",
    },
  ];

  return (
    <div className="card">
      <button
        className="w-full flex items-center justify-between p-3 text-left"
        onClick={() => setOpen((v) => !v)}
      >
        <span className="flex items-center gap-2 text-xs font-medium text-text-secondary">
          <Info size={12} className="text-accent-blue" />
          How Semantic Comparison Works
        </span>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>
      {open && (
        <div className="border-t border-border p-4">
          <div className="grid grid-cols-2 gap-3">
            {concepts.map((c) => (
              <div key={c.term} className="p-2 bg-surface-2 rounded">
                <p className={clsx("text-xs font-semibold mb-0.5", c.color)}>{c.term}</p>
                <p className="text-xs text-text-muted">{c.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
