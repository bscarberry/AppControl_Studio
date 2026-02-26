import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Activity, CheckCircle, AlertCircle } from "lucide-react";
import clsx from "clsx";
import { policyApi } from "../lib/api.ts";
import { useAppStore } from "../store/index.ts";
import { Header } from "../components/layout/Header.tsx";
import { EmptyState } from "../components/common/EmptyState.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import type { CreatePolicyFromEventsResponse } from "@appcontrol/shared";
import { useNavigate } from "react-router-dom";
import { v4 as uuidv4 } from "uuid";

type Template = "default-windows" | "allow-microsoft" | "deny-by-default" | "blank";

interface BuildOptions {
  policyName: string;
  template: Template;
  preferPublisherRules: boolean;
  includePathRules: boolean;
  auditMode: boolean;
}

const TEMPLATES: { id: Template; label: string; description: string }[] = [
  {
    id: "blank",
    label: "Blank",
    description: "Start with minimal options; only rules you define apply.",
  },
  {
    id: "allow-microsoft",
    label: "Allow Microsoft",
    description: "Trust Microsoft-signed binaries. Add more rules for other software.",
  },
  {
    id: "default-windows",
    label: "Default Windows",
    description: "Allow Windows components + WHQL drivers. Most restrictive template.",
  },
  {
    id: "deny-by-default",
    label: "Deny by Default",
    description: "Explicit allow-list only. Requires EV signers.",
  },
];

export function BuildPolicyPage() {
  const { importedEvents, addSession } = useAppStore();
  const navigate = useNavigate();

  const [options, setOptions] = useState<BuildOptions>({
    policyName: "Generated Policy",
    template: "blank",
    preferPublisherRules: true,
    includePathRules: false,
    auditMode: true,
  });

  const [result, setResult] = useState<CreatePolicyFromEventsResponse | null>(null);

  const buildMutation = useMutation({
    mutationFn: () =>
      policyApi.fromEvents({
        events: importedEvents,
        policyName: options.policyName,
        template: options.template,
        preferPublisherRules: options.preferPublisherRules,
        includePathRules: options.includePathRules,
        auditMode: options.auditMode,
      }),
    onSuccess: (data) => {
      setResult(data);
      // Also load the policy into the editor
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
      <div className="flex flex-col h-full">
        <Header title="Build Policy" subtitle="Generate a WDAC policy from CodeIntegrity events" />
        <div className="flex-1 flex items-center justify-center">
          <EmptyState
            icon={<Activity size={40} />}
            title="No events loaded"
            description="Import CodeIntegrity events first, then return here to build a policy."
            action={
              <button className="btn-primary" onClick={() => navigate("/import-events")}>
                Import Events
              </button>
            }
          />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Build Policy"
        subtitle={`Building from ${importedEvents.length} imported events`}
        actions={
          <button
            className="btn-primary"
            onClick={() => buildMutation.mutate()}
            disabled={buildMutation.isPending || !options.policyName.trim()}
          >
            <Activity size={13} />
            {buildMutation.isPending ? "Building..." : "Build Policy"}
          </button>
        }
      />

      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-2xl space-y-5">
          {/* Policy name */}
          <div className="card p-4">
            <h2 className="section-header">Policy Settings</h2>
            <div className="space-y-3">
              <div>
                <label className="text-xs font-medium text-text-secondary block mb-1.5">
                  Policy Name
                </label>
                <input
                  className="input"
                  value={options.policyName}
                  onChange={(e) => setOptions((o) => ({ ...o, policyName: e.target.value }))}
                  placeholder="My WDAC Policy"
                  maxLength={256}
                />
              </div>

              <div>
                <label className="text-xs font-medium text-text-secondary block mb-2">
                  Base Template
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {TEMPLATES.map((t) => (
                    <button
                      key={t.id}
                      onClick={() => setOptions((o) => ({ ...o, template: t.id }))}
                      className={clsx(
                        "text-left p-3 rounded border text-xs transition-colors",
                        options.template === t.id
                          ? "border-accent-blue bg-accent-blue-dim/20"
                          : "border-border hover:border-border-strong"
                      )}
                    >
                      <p className="font-medium text-text-primary mb-0.5">{t.label}</p>
                      <p className="text-text-muted">{t.description}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Rule generation options */}
          <div className="card p-4">
            <h2 className="section-header">Rule Generation</h2>
            <div className="space-y-3">
              <Toggle
                label="Prefer Publisher Rules"
                description="When signer info is available, create certificate publisher rules instead of hash rules. Publisher rules are more maintainable across software updates."
                checked={options.preferPublisherRules}
                onChange={(v) => setOptions((o) => ({ ...o, preferPublisherRules: v }))}
              />
              <Toggle
                label="Include Path Rules"
                description="Add file path-based allow rules. Use with caution — path rules are weaker than hash or publisher rules and can be bypassed by placing malicious files at the same path. Runtime path protection is recommended."
                checked={options.includePathRules}
                onChange={(v) => setOptions((o) => ({ ...o, includePathRules: v }))}
                warning
              />
              <Toggle
                label="Start in Audit Mode"
                description="Generate the policy with Enabled:Audit Mode (Option 3). Recommended for initial testing — deploy in audit mode, verify no legitimate software is blocked, then remove audit mode for enforcement."
                checked={options.auditMode}
                onChange={(v) => setOptions((o) => ({ ...o, auditMode: v }))}
              />
            </div>
          </div>

          {/* Event summary */}
          <div className="card p-4">
            <h2 className="section-header">Event Inputs</h2>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="bg-surface-2 rounded p-2">
                <p className="text-xl font-bold mono text-text-primary">{importedEvents.length}</p>
                <p className="text-xs text-text-muted">Total Events</p>
              </div>
              <div className="bg-surface-2 rounded p-2">
                <p className="text-xl font-bold mono text-accent-red">
                  {importedEvents.filter((e) => e.severity === "block").length}
                </p>
                <p className="text-xs text-text-muted">Block Events</p>
              </div>
              <div className="bg-surface-2 rounded p-2">
                <p className="text-xl font-bold mono text-accent-yellow">
                  {importedEvents.filter((e) => e.severity === "audit").length}
                </p>
                <p className="text-xs text-text-muted">Audit Events</p>
              </div>
            </div>
          </div>

          {/* Build result */}
          {buildMutation.isPending && (
            <div className="flex justify-center py-8">
              <LoadingSpinner label="Building policy rules..." />
            </div>
          )}

          {buildMutation.isError && (
            <div className="p-4 bg-accent-red-dim/30 border border-accent-red/20 rounded text-sm text-accent-red flex items-center gap-2">
              <AlertCircle size={14} />
              {(buildMutation.error as Error).message}
            </div>
          )}

          {result && !buildMutation.isPending && (
            <BuildResult result={result} />
          )}
        </div>
      </div>
    </div>
  );
}

function Toggle({
  label,
  description,
  checked,
  onChange,
  warning,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  warning?: boolean;
}) {
  return (
    <div className="flex items-start gap-3">
      <button
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={clsx(
          "relative inline-flex w-9 h-5 rounded-full flex-shrink-0 mt-0.5 transition-colors focus:outline-none focus:ring-2 focus:ring-accent-blue focus:ring-offset-2 focus:ring-offset-surface-1",
          checked ? "bg-accent-blue" : "bg-surface-5"
        )}
      >
        <span
          className={clsx(
            "inline-block w-3.5 h-3.5 rounded-full bg-white shadow transform transition-transform mt-0.5 ml-0.5",
            checked ? "translate-x-4" : "translate-x-0"
          )}
        />
      </button>
      <div className="flex-1">
        <p className={clsx("text-xs font-medium", warning ? "text-accent-yellow" : "text-text-primary")}>
          {label}
        </p>
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
        <div className="bg-surface-2 rounded p-2">
          <p className="text-lg font-bold mono text-text-primary">{result.ruleCount}</p>
          <p className="text-xs text-text-muted">Total Rules</p>
        </div>
        <div className="bg-surface-2 rounded p-2">
          <p className="text-lg font-bold mono text-accent-blue">{result.policy.fileRules.length}</p>
          <p className="text-xs text-text-muted">File Rules</p>
        </div>
        <div className="bg-surface-2 rounded p-2">
          <p className="text-lg font-bold mono text-accent-purple">{result.policy.signers.length}</p>
          <p className="text-xs text-text-muted">Signer Rules</p>
        </div>
      </div>

      {/* Build log */}
      <h3 className="section-header">Build Log</h3>
      <div className="bg-surface-2 rounded p-3 max-h-48 overflow-auto">
        {result.buildLog.map((line, i) => (
          <p key={i} className="mono text-xs text-text-muted">{line}</p>
        ))}
      </div>

      {/* Download */}
      <div className="mt-4 flex gap-2">
        <button
          className="btn-primary"
          onClick={() => {
            const blob = new Blob([result.xml], { type: "text/xml" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `${result.policy.friendlyName ?? "policy"}.xml`;
            a.click();
            URL.revokeObjectURL(url);
          }}
        >
          Download XML
        </button>
        <p className="text-xs text-text-muted self-center">Policy has been loaded into the editor</p>
      </div>
    </div>
  );
}
