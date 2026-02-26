import { useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { GitCompare, Plus, Minus, Edit2, Minus as MinusIcon } from "lucide-react";
import clsx from "clsx";
import { policyApi } from "../lib/api.ts";
import { Header } from "../components/layout/Header.tsx";
import { FileDropZone } from "../components/common/FileDropZone.tsx";
import { EmptyState } from "../components/common/EmptyState.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import type { PolicyComparisonResult, OptionDiff, FileRuleDiff, SignerDiff, ScenarioDiff } from "@appcontrol/shared";

type DiffSection = "options" | "file-rules" | "signers" | "scenarios";

export function ComparePage() {
  const [leftXml, setLeftXml] = useState<string | null>(null);
  const [rightXml, setRightXml] = useState<string | null>(null);
  const [leftName, setLeftName] = useState("");
  const [rightName, setRightName] = useState("");
  const [section, setSection] = useState<DiffSection>("options");

  const compareMutation = useMutation({
    mutationFn: ({ left, right }: { left: string; right: string }) =>
      policyApi.compare(left, right),
  });

  const result = compareMutation.data?.comparison ?? null;

  const canCompare = !!leftXml && !!rightXml;

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Policy Comparison"
        subtitle="Structural diff of two WDAC policies"
        actions={
          canCompare ? (
            <button
              className="btn-primary"
              onClick={() => compareMutation.mutate({ left: leftXml!, right: rightXml! })}
              disabled={compareMutation.isPending}
            >
              <GitCompare size={13} />
              {compareMutation.isPending ? "Comparing..." : "Compare Policies"}
            </button>
          ) : null
        }
      />

      <div className="flex-1 overflow-auto p-6">
        {/* File pickers */}
        <div className="grid grid-cols-2 gap-4 mb-6">
          <div>
            <p className="text-xs font-medium text-text-secondary mb-2">Left Policy (Baseline)</p>
            <FileDropZone
              accept=".xml"
              label="Drop Left Policy XML"
              onFile={(content, name) => { setLeftXml(content); setLeftName(name); }}
            />
          </div>
          <div>
            <p className="text-xs font-medium text-text-secondary mb-2">Right Policy (Candidate)</p>
            <FileDropZone
              accept=".xml"
              label="Drop Right Policy XML"
              onFile={(content, name) => { setRightXml(content); setRightName(name); }}
            />
          </div>
        </div>

        {compareMutation.isPending && (
          <div className="flex justify-center py-16">
            <LoadingSpinner label="Analyzing differences..." />
          </div>
        )}

        {compareMutation.isError && (
          <div className="p-4 bg-accent-red-dim/30 border border-accent-red/20 rounded text-sm text-accent-red">
            {(compareMutation.error as Error).message}
          </div>
        )}

        {result && !compareMutation.isPending && (
          <ComparisonView
            result={result}
            leftName={leftName}
            rightName={rightName}
            section={section}
            onSectionChange={setSection}
          />
        )}

        {!result && !compareMutation.isPending && !compareMutation.isError && (
          <EmptyState
            icon={<GitCompare size={36} />}
            title="Load two policies to compare"
            description="Drop XML files above, then click Compare Policies to see a structural diff."
          />
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Comparison view
// ---------------------------------------------------------------------------

interface ComparisonViewProps {
  result: PolicyComparisonResult;
  leftName: string;
  rightName: string;
  section: DiffSection;
  onSectionChange: (s: DiffSection) => void;
}

function ComparisonView({ result, leftName, rightName, section, onSectionChange }: ComparisonViewProps) {
  const { summary } = result;

  const tabs: { id: DiffSection; label: string; count: number }[] = [
    { id: "options", label: "Options", count: summary.optionChanges },
    { id: "file-rules", label: "File Rules", count: summary.fileRuleChanges },
    { id: "signers", label: "Signers", count: summary.signerChanges },
    { id: "scenarios", label: "Scenarios", count: summary.scenarioChanges },
  ];

  return (
    <div>
      {/* Summary banner */}
      <div className="card p-4 mb-4">
        <div className="flex items-center justify-between mb-3">
          <div>
            <p className="text-sm font-medium text-text-primary">
              {result.leftPolicy.friendlyName ?? result.leftPolicy.policyId}
              <span className="text-text-muted mx-2">→</span>
              {result.rightPolicy.friendlyName ?? result.rightPolicy.policyId}
            </p>
            <p className="text-xs text-text-muted mt-0.5">{leftName} vs {rightName}</p>
          </div>
          <div className="flex gap-4 text-center">
            <div>
              <p className="text-lg font-bold mono text-text-primary">{summary.totalDifferences}</p>
              <p className="text-xs text-text-muted">Total diffs</p>
            </div>
          </div>
        </div>
        <div className="grid grid-cols-4 gap-3">
          {tabs.map((t) => (
            <div key={t.id} className="bg-surface-2 rounded p-2 text-center">
              <p className={clsx("text-base font-bold mono", t.count > 0 ? "text-accent-yellow" : "text-text-muted")}>
                {t.count}
              </p>
              <p className="text-xs text-text-muted">{t.label}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Section tabs */}
      <div className="flex border-b border-border gap-1 mb-4">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => onSectionChange(tab.id)}
            className={clsx(
              "px-4 py-2 text-xs font-medium border-b-2 -mb-px transition-colors",
              section === tab.id
                ? "border-accent-blue text-text-primary"
                : "border-transparent text-text-muted hover:text-text-secondary"
            )}
          >
            {tab.label}
            {tab.count > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 rounded-full bg-accent-yellow text-black text-xs font-bold">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Diff content */}
      {section === "options" && <OptionsDiff diffs={result.optionDiffs} />}
      {section === "file-rules" && <FileRulesDiff diffs={result.fileRuleDiffs} />}
      {section === "signers" && <SignersDiff diffs={result.signerDiffs} />}
      {section === "scenarios" && <ScenariosDiff diffs={result.scenarioDiffs} />}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Diff sub-views
// ---------------------------------------------------------------------------

function DiffBadge({ status }: { status: string }) {
  if (status === "added") return <span className="tag-green flex items-center gap-1"><Plus size={10} />Added</span>;
  if (status === "removed") return <span className="tag-red flex items-center gap-1"><Minus size={10} />Removed</span>;
  if (status === "changed") return <span className="tag-yellow flex items-center gap-1"><Edit2 size={10} />Changed</span>;
  return <span className="tag-gray">Unchanged</span>;
}

function OptionsDiff({ diffs }: { diffs: OptionDiff[] }) {
  const changed = diffs.filter((d) => d.status !== "unchanged");
  if (changed.length === 0) return <p className="text-xs text-text-muted">No option differences.</p>;

  return (
    <div className="space-y-1.5">
      {changed.map((diff) => (
        <div
          key={diff.optionValue}
          className={clsx(
            "flex items-center gap-4 p-3 rounded border text-xs",
            diff.status === "added" ? "border-accent-green/20 bg-accent-green-dim/10" :
            diff.status === "removed" ? "border-accent-red/20 bg-accent-red-dim/10" :
            "border-accent-yellow/20 bg-accent-yellow-dim/10"
          )}
        >
          <DiffBadge status={diff.status} />
          <span className="mono font-medium text-text-primary flex-1">{diff.optionName}</span>
          <div className="flex gap-3 text-text-muted">
            <span>Left: {diff.leftEnabled ? "✓ On" : "✗ Off"}</span>
            <span>Right: {diff.rightEnabled ? "✓ On" : "✗ Off"}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function FileRulesDiff({ diffs }: { diffs: FileRuleDiff[] }) {
  const changed = diffs.filter((d) => d.status !== "unchanged");
  if (changed.length === 0) return <p className="text-xs text-text-muted">No file rule differences.</p>;

  return (
    <div className="space-y-1.5">
      {changed.map((diff) => (
        <div
          key={diff.id}
          className={clsx(
            "p-3 rounded border text-xs",
            diff.status === "added" ? "border-accent-green/20 bg-accent-green-dim/10" :
            diff.status === "removed" ? "border-accent-red/20 bg-accent-red-dim/10" :
            "border-accent-yellow/20 bg-accent-yellow-dim/10"
          )}
        >
          <div className="flex items-center gap-3 mb-1">
            <DiffBadge status={diff.status} />
            <span className="mono text-text-muted">{diff.id}</span>
            <span className="text-text-secondary">
              {(diff.left ?? diff.right)?.friendlyName ?? "(unnamed)"}
            </span>
          </div>
          {diff.changedFields && diff.changedFields.length > 0 && (
            <p className="text-text-muted mt-1">
              Changed fields: {diff.changedFields.join(", ")}
            </p>
          )}
          {diff.left && diff.right && (
            <div className="mt-2 grid grid-cols-2 gap-3">
              <div>
                <p className="text-text-muted mb-1">Left</p>
                <pre className="mono bg-surface-2 p-2 rounded text-xs text-text-secondary overflow-auto">
                  {JSON.stringify(diff.left, null, 2)}
                </pre>
              </div>
              <div>
                <p className="text-text-muted mb-1">Right</p>
                <pre className="mono bg-surface-2 p-2 rounded text-xs text-text-secondary overflow-auto">
                  {JSON.stringify(diff.right, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function SignersDiff({ diffs }: { diffs: SignerDiff[] }) {
  const changed = diffs.filter((d) => d.status !== "unchanged");
  if (changed.length === 0) return <p className="text-xs text-text-muted">No signer differences.</p>;

  return (
    <div className="space-y-1.5">
      {changed.map((diff) => (
        <div
          key={diff.id}
          className={clsx(
            "p-3 rounded border text-xs",
            diff.status === "added" ? "border-accent-green/20 bg-accent-green-dim/10" :
            diff.status === "removed" ? "border-accent-red/20 bg-accent-red-dim/10" :
            "border-accent-yellow/20 bg-accent-yellow-dim/10"
          )}
        >
          <div className="flex items-center gap-3">
            <DiffBadge status={diff.status} />
            <span className="mono text-text-muted">{diff.id}</span>
            <span className="text-text-secondary">{(diff.left ?? diff.right)?.name ?? "(unnamed)"}</span>
          </div>
          {diff.changedFields && diff.changedFields.length > 0 && (
            <p className="text-text-muted mt-1">Changed: {diff.changedFields.join(", ")}</p>
          )}
        </div>
      ))}
    </div>
  );
}

function ScenariosDiff({ diffs }: { diffs: ScenarioDiff[] }) {
  const hasChanges = diffs.some((d) =>
    d.addedAllowedSigners.length + d.removedAllowedSigners.length +
    d.addedDeniedSigners.length + d.removedDeniedSigners.length +
    d.addedFileRuleRefs.length + d.removedFileRuleRefs.length > 0
  );

  if (!hasChanges) return <p className="text-xs text-text-muted">No signing scenario differences.</p>;

  return (
    <div className="space-y-4">
      {diffs.map((diff) => (
        <div key={diff.scenarioValue} className="card p-4">
          <h3 className="text-xs font-semibold text-text-secondary mb-3">
            {diff.scenarioValue === 131 ? "Kernel Mode (131)" : "User Mode (12)"}
          </h3>
          <div className="space-y-2">
            <ScenarioDiffRows label="Allowed Signers" added={diff.addedAllowedSigners} removed={diff.removedAllowedSigners} />
            <ScenarioDiffRows label="Denied Signers" added={diff.addedDeniedSigners} removed={diff.removedDeniedSigners} />
            <ScenarioDiffRows label="File Rule Refs" added={diff.addedFileRuleRefs} removed={diff.removedFileRuleRefs} />
          </div>
        </div>
      ))}
    </div>
  );
}

function ScenarioDiffRows({ label, added, removed }: { label: string; added: string[]; removed: string[] }) {
  if (added.length === 0 && removed.length === 0) return null;
  return (
    <div>
      <p className="text-xs text-text-muted mb-1">{label}</p>
      <div className="space-y-0.5">
        {added.map((id) => (
          <div key={id} className="flex items-center gap-2 text-xs text-accent-green">
            <Plus size={10} />
            <span className="mono">{id}</span>
          </div>
        ))}
        {removed.map((id) => (
          <div key={id} className="flex items-center gap-2 text-xs text-accent-red">
            <MinusIcon size={10} />
            <span className="mono">{id}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
