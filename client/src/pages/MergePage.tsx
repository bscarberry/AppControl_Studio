/**
 * Policy Merge Page
 *
 * Merge 2–15 WDAC policies into one, matching the WDAC Policy Wizard's merge workflow.
 *
 * Behavior (consistent with WDAC Wizard):
 *   - The merged policy inherits PolicyID, FriendlyName, and VersionEx from the FIRST policy.
 *   - Ordering matters: drag-and-drop to set merge order.
 *   - Semantically duplicate rules (same hash / cert / path) are deduplicated.
 *   - Policy rule options are unioned (any policy enabling an option → enabled).
 *   - Warning: merge result should target audit mode before deploying to production.
 */

import { useState, useCallback, useRef } from "react";
import {
  Merge,
  Upload,
  X,
  GripVertical,
  Download,
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  Loader,
} from "lucide-react";
import clsx from "clsx";
import type { MergePoliciesResponse } from "@appcontrol/shared";
import { policyApi } from "../lib/api.ts";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface LoadedPolicy {
  id: string;
  fileName: string;
  xml: string;
  friendlyName?: string;
  policyId?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readFileText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
    reader.readAsText(file);
  });
}

function extractFriendlyName(xml: string): string | undefined {
  const m = xml.match(/FriendlyName\s*=\s*"([^"]+)"/i)
    ?? xml.match(/<FriendlyName>([^<]+)<\/FriendlyName>/i);
  return m?.[1]?.trim();
}

function extractPolicyId(xml: string): string | undefined {
  const m = xml.match(/<PolicyID>\s*(\{[^}]+\})\s*<\/PolicyID>/i);
  return m?.[1];
}

function downloadFile(content: string, filename: string) {
  const blob = new Blob([content], { type: "application/xml" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// PolicyCard component
// ---------------------------------------------------------------------------

function PolicyCard({
  policy,
  index,
  total,
  onRemove,
  onMoveUp,
  onMoveDown,
}: {
  policy: LoadedPolicy;
  index: number;
  total: number;
  onRemove: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
}) {
  return (
    <div
      className={clsx(
        "flex items-center gap-3 px-3 py-2.5 rounded border transition-colors",
        index === 0 ? "border-accent-blue bg-accent-blue/5" : "border-border"
      )}
    >
      {/* Order badge */}
      <div
        className={clsx(
          "flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold",
          index === 0 ? "bg-accent-blue text-white" : "bg-surface-3 text-text-muted"
        )}
      >
        {index + 1}
      </div>

      {/* Info */}
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-text-primary truncate">
          {policy.friendlyName ?? policy.fileName}
          {index === 0 && (
            <span className="ml-2 text-[10px] font-normal text-accent-blue">
              (base identity)
            </span>
          )}
        </p>
        <p className="text-[10px] text-text-muted font-mono truncate">
          {policy.policyId ?? policy.fileName}
        </p>
      </div>

      {/* Reorder */}
      <div className="flex flex-col gap-0.5">
        <button
          onClick={onMoveUp}
          disabled={index === 0}
          className="text-text-muted hover:text-text-secondary disabled:opacity-30 transition-colors p-0.5"
          title="Move up"
        >
          <ChevronUp size={12} />
        </button>
        <button
          onClick={onMoveDown}
          disabled={index === total - 1}
          className="text-text-muted hover:text-text-secondary disabled:opacity-30 transition-colors p-0.5"
          title="Move down"
        >
          <ChevronDown size={12} />
        </button>
      </div>

      <button
        onClick={onRemove}
        className="text-text-muted hover:text-accent-red transition-colors flex-shrink-0"
        title="Remove"
      >
        <X size={14} />
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function MergePage() {
  const [policies, setPolicies] = useState<LoadedPolicy[]>([]);
  const [friendlyName, setFriendlyName] = useState("");
  const [result, setResult] = useState<MergePoliciesResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showLog, setShowLog] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const addFiles = useCallback(async (files: File[]) => {
    const xmlFiles = files.filter(
      (f) => f.name.endsWith(".xml") || f.type === "text/xml" || f.type === "application/xml"
    );
    if (xmlFiles.length === 0) return;
    const remaining = 15 - policies.length;
    const toAdd = xmlFiles.slice(0, remaining);

    const loaded: LoadedPolicy[] = await Promise.all(
      toAdd.map(async (file) => {
        const xml = await readFileText(file);
        return {
          id: crypto.randomUUID(),
          fileName: file.name,
          xml,
          friendlyName: extractFriendlyName(xml),
          policyId: extractPolicyId(xml),
        };
      })
    );
    setPolicies((prev) => [...prev, ...loaded]);
  }, [policies.length]);

  function removePolicy(id: string) {
    setPolicies((prev) => prev.filter((p) => p.id !== id));
    setResult(null);
  }

  function movePolicy(id: string, direction: "up" | "down") {
    setPolicies((prev) => {
      const idx = prev.findIndex((p) => p.id === id);
      if (idx < 0) return prev;
      const newArr = [...prev];
      const swapIdx = direction === "up" ? idx - 1 : idx + 1;
      if (swapIdx < 0 || swapIdx >= newArr.length) return prev;
      [newArr[idx], newArr[swapIdx]] = [newArr[swapIdx], newArr[idx]];
      return newArr;
    });
    setResult(null);
  }

  async function handleMerge() {
    if (policies.length < 2) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await policyApi.merge(
        policies.map((p) => p.xml),
        friendlyName.trim() || undefined
      );
      setResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function handleDownload() {
    if (!result) return;
    const name = result.policy.friendlyName ?? "merged-policy";
    const safe = name.replace(/[^a-z0-9_-]/gi, "_").toLowerCase();
    downloadFile(result.xml, `${safe}.xml`);
  }

  const canMerge = policies.length >= 2 && !loading;

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Merge size={20} className="text-accent-blue" />
        <div>
          <h1 className="text-base font-semibold text-text-primary">Policy Merge</h1>
          <p className="text-xs text-text-muted mt-0.5">
            Combine 2–15 WDAC policies into one. The first policy in the list sets the merged policy's identity.
          </p>
        </div>
      </div>

      {/* WDAC Wizard parity note */}
      <div className="flex items-start gap-2 text-xs text-text-muted bg-surface-2 border border-border rounded p-3">
        <AlertTriangle size={13} className="flex-shrink-0 mt-0.5 text-accent-yellow" />
        <span>
          <strong className="text-text-secondary">WDAC Wizard parity:</strong> This merge follows the same
          rules as the Microsoft WDAC Policy Wizard — the first policy's PolicyID is used for the merged
          result, options are unioned, and semantically duplicate rules are deduplicated. Start with your
          base template (Default Windows / Allow Microsoft) as policy #1.
        </span>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Left: input */}
        <div className="space-y-4">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Input Policies ({policies.length}/15)
          </h2>

          {/* Drop zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              addFiles([...e.dataTransfer.files]);
            }}
            onClick={() => fileInputRef.current?.click()}
            className={clsx(
              "border-2 border-dashed rounded-lg px-4 py-8 text-center cursor-pointer transition-colors",
              dragOver ? "border-accent-blue bg-accent-blue/5" : "border-border hover:border-border-strong",
              policies.length >= 15 && "opacity-40 pointer-events-none"
            )}
          >
            <Upload size={20} className="mx-auto text-text-muted mb-2" />
            <p className="text-xs text-text-secondary">
              Drop XML policy files here or click to browse
            </p>
            <p className="text-[10px] text-text-muted mt-1">
              {policies.length >= 15 ? "Maximum 15 policies reached" : `Add up to ${15 - policies.length} more`}
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".xml"
              multiple
              className="hidden"
              onChange={(e) => {
                addFiles([...(e.target.files ?? [])]);
                e.target.value = "";
              }}
            />
          </div>

          {/* Policy list */}
          {policies.length > 0 && (
            <div className="space-y-2">
              {policies.map((p, i) => (
                <PolicyCard
                  key={p.id}
                  policy={p}
                  index={i}
                  total={policies.length}
                  onRemove={() => removePolicy(p.id)}
                  onMoveUp={() => movePolicy(p.id, "up")}
                  onMoveDown={() => movePolicy(p.id, "down")}
                />
              ))}
            </div>
          )}

          {/* Friendly name override */}
          {policies.length >= 2 && (
            <div className="flex flex-col gap-1">
              <label className="text-xs font-medium text-text-secondary">
                Merged Policy Name (optional)
              </label>
              <input
                type="text"
                className="input text-xs py-1.5"
                value={friendlyName}
                onChange={(e) => setFriendlyName(e.target.value)}
                placeholder={policies[0]?.friendlyName ?? "Merged Policy"}
              />
              <p className="text-[10px] text-text-muted">
                Defaults to the first policy's name.
              </p>
            </div>
          )}

          {/* Merge button */}
          <button
            onClick={handleMerge}
            disabled={!canMerge}
            className="btn-primary w-full text-xs py-2 disabled:opacity-40 flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader size={13} className="animate-spin" />
                Merging…
              </>
            ) : (
              <>
                <Merge size={13} />
                Merge {policies.length >= 2 ? `${policies.length} Policies` : "Policies"}
              </>
            )}
          </button>

          {error && (
            <div className="flex items-start gap-2 text-xs text-accent-red bg-accent-red/10 border border-accent-red/30 rounded p-2.5">
              <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Right: result */}
        <div className="space-y-4">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Merge Result
          </h2>

          {!result && !loading && (
            <div className="border border-border rounded-lg p-8 text-center text-text-muted">
              <Merge size={28} className="mx-auto mb-3 opacity-30" />
              <p className="text-xs">Add 2+ policies and click Merge</p>
            </div>
          )}

          {loading && (
            <div className="border border-border rounded-lg p-8 text-center">
              <Loader size={24} className="mx-auto mb-3 animate-spin text-accent-blue" />
              <p className="text-xs text-text-muted">Merging policies…</p>
            </div>
          )}

          {result && (
            <div className="space-y-4">
              {/* Success banner */}
              <div className="flex items-center gap-2 text-xs text-accent-green bg-accent-green/10 border border-accent-green/30 rounded p-2.5">
                <CheckCircle size={13} />
                <span className="font-medium">Merge successful</span>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-2 gap-3">
                {[
                  { label: "Input Policies", value: result.stats.inputPolicies },
                  {
                    label: "File Rules",
                    value: `${result.stats.dedupedFileRules}`,
                    sub: result.stats.totalFileRules !== result.stats.dedupedFileRules
                      ? `(${result.stats.totalFileRules - result.stats.dedupedFileRules} deduped)`
                      : undefined,
                  },
                  {
                    label: "Signers",
                    value: `${result.stats.dedupedSigners}`,
                    sub: result.stats.totalSigners !== result.stats.dedupedSigners
                      ? `(${result.stats.totalSigners - result.stats.dedupedSigners} deduped)`
                      : undefined,
                  },
                  { label: "Policy Type", value: result.policy.policyType },
                ].map(({ label, value, sub }) => (
                  <div key={label} className="bg-surface-2 rounded border border-border px-3 py-2.5">
                    <p className="text-[10px] text-text-muted">{label}</p>
                    <p className="text-sm font-semibold text-text-primary mt-0.5">{value}</p>
                    {sub && <p className="text-[10px] text-text-muted">{sub}</p>}
                  </div>
                ))}
              </div>

              {/* Policy summary */}
              <div className="bg-surface-2 rounded border border-border px-3 py-2.5 space-y-1">
                <p className="text-xs font-medium text-text-primary">
                  {result.policy.friendlyName ?? "Merged Policy"}
                </p>
                <p className="text-[10px] text-text-muted font-mono">{result.policy.policyId}</p>
                <p className="text-[10px] text-text-muted">
                  Type: {result.policy.policyType} · Version: {result.policy.versionEx}
                </p>
              </div>

              {/* Download */}
              <button
                onClick={handleDownload}
                className="btn-primary w-full text-xs py-2 flex items-center justify-center gap-2"
              >
                <Download size={13} />
                Download Merged XML
              </button>

              {/* Merge log */}
              <div>
                <button
                  onClick={() => setShowLog((v) => !v)}
                  className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text-secondary transition-colors"
                >
                  {showLog ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                  {showLog ? "Hide" : "Show"} merge log ({result.mergeLog.length} entries)
                </button>
                {showLog && (
                  <div className="mt-2 bg-surface-3 rounded border border-border p-3 max-h-60 overflow-y-auto">
                    {result.mergeLog.map((line, i) => (
                      <p key={i} className="text-[10px] font-mono text-text-muted leading-5">
                        {line}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
