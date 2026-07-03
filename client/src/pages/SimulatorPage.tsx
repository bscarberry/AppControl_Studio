/**
 * Policy Simulation Page
 *
 * Evaluates whether a binary would be allowed or blocked by a loaded WDAC
 * policy, following the documented rule evaluation order:
 *
 *   1. Deny file rules  (hash → path → attribute)
 *   2. Deny signer rules
 *   3. Allow signer rules (with optional FileAttrib scoping)
 *   4. Allow file rules  (hash → attribute → path)
 *   5. Default deny
 */

import { useState, useId } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  PlayCircle,
  ShieldOff,
  ShieldCheck,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Info,
  Hash,
  Key,
  FolderOpen,
  FileText,
  Cpu,
  CheckCircle,
  XCircle,
  SkipForward,
  GitMerge,
  Clock,
} from "lucide-react";
import clsx from "clsx";
import { policyApi } from "../lib/api.ts";
import { useAppStore } from "../store/index.ts";
import type {
  BinaryMetadata,
  EvaluationResult,
  EvalStep,
  SimRuleType,
  EvalPhase,
} from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ruleTypeBadge(rt: SimRuleType | undefined): string {
  if (!rt) return "tag-gray";
  if (rt.startsWith("deny-")) return "tag-red";
  if (rt.startsWith("allow-")) return "tag-green";
  if (rt === "no-umci" || rt === "no-scenario") return "tag-blue";
  if (rt === "default-deny") return "tag-orange";
  return "tag-gray";
}

function phaseLabel(phase: EvalPhase): string {
  const labels: Record<EvalPhase, string> = {
    "mode-check": "Mode Check",
    "scenario-select": "Scenario",
    "deny-hash": "Deny Hash",
    "deny-publisher": "Deny Publisher",
    "deny-path": "Deny Path",
    "deny-attribute": "Deny Attribute",
    "allow-publisher": "Allow Publisher",
    "allow-publisher-scoped": "Allow Publisher (Scoped)",
    "allow-hash": "Allow Hash",
    "allow-attribute": "Allow Attribute",
    "allow-path": "Allow Path",
    default: "Default",
  };
  return labels[phase] ?? phase;
}

function outcomeIcon(outcome: EvalStep["outcome"]) {
  if (outcome === "matched")
    return <CheckCircle size={12} className="text-accent-green flex-shrink-0" />;
  if (outcome === "no-match")
    return <XCircle size={12} className="text-text-muted flex-shrink-0" />;
  if (outcome === "skipped")
    return <SkipForward size={12} className="text-text-muted flex-shrink-0" />;
  if (outcome === "excepted")
    return <GitMerge size={12} className="text-accent-yellow flex-shrink-0" />;
  return null;
}

// ---------------------------------------------------------------------------
// Verdict banner
// ---------------------------------------------------------------------------

function VerdictBanner({ result }: { result: EvaluationResult }) {
  const isAllowed =
    result.verdict === "allowed" ||
    (result.verdict === "audit-only" && result.enforcementVerdict === "allowed");
  const isAudit = result.verdict === "audit-only";

  return (
    <div
      className={clsx(
        "rounded-lg p-5 flex items-start gap-4",
        isAllowed ? "bg-accent-green/10 border border-accent-green/30" : "bg-accent-red/10 border border-accent-red/30"
      )}
    >
      <div className="flex-shrink-0 mt-0.5">
        {isAllowed ? (
          <ShieldCheck size={28} className="text-accent-green" />
        ) : (
          <ShieldOff size={28} className="text-accent-red" />
        )}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-3 flex-wrap">
          <span
            className={clsx(
              "text-xl font-bold tracking-wide",
              isAllowed ? "text-accent-green" : "text-accent-red"
            )}
          >
            {isAllowed ? "ALLOWED" : "BLOCKED"}
          </span>
          {isAudit && (
            <span className="tag tag-blue text-xs">Audit Mode</span>
          )}
          <span className="tag tag-gray text-xs">
            {result.policyMode === "audit" ? "Audit Policy" : "Enforcement Policy"}
          </span>
          {result.scenarioValue && (
            <span className="tag tag-gray text-xs">
              Scenario {result.scenarioValue} ({result.scenarioValue === 131 ? "kernel" : "user"})
            </span>
          )}
        </div>
        {isAudit && (
          <p className="text-xs text-text-muted mt-1">
            Binary would be{" "}
            <strong className={result.enforcementVerdict === "allowed" ? "text-accent-green" : "text-accent-red"}>
              {result.enforcementVerdict?.toUpperCase()}
            </strong>{" "}
            in enforcement mode.
          </p>
        )}
        <p className="text-sm text-text-secondary mt-2 leading-relaxed">
          {result.explanation}
        </p>

        {/* Matching rule */}
        {result.matchingRuleId && (
          <div className="mt-3 flex items-center gap-2 flex-wrap text-xs">
            <span className="text-text-muted">Matched rule:</span>
            <code className="font-mono bg-surface-3 px-1.5 py-0.5 rounded text-text-primary">
              {result.matchingRuleId}
            </code>
            {result.matchingRuleName && result.matchingRuleName !== result.matchingRuleId && (
              <span className="text-text-secondary">
                "{result.matchingRuleName}"
              </span>
            )}
            {result.matchingRuleType && (
              <span className={clsx("tag text-xs", ruleTypeBadge(result.matchingRuleType))}>
                {result.matchingRuleType}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Evaluation trace
// ---------------------------------------------------------------------------

function EvalTrace({ steps }: { steps: EvalStep[] }) {
  const [open, setOpen] = useState(true);

  // Group consecutive steps by phase for visual clarity
  return (
    <div className="panel">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 w-full text-left"
      >
        <Clock size={14} className="text-text-muted" />
        <span className="text-sm font-medium text-text-primary flex-1">
          Evaluation Trace
          <span className="text-text-muted font-normal ml-2">
            ({steps.length} step{steps.length !== 1 ? "s" : ""})
          </span>
        </span>
        {open ? (
          <ChevronDown size={14} className="text-text-muted" />
        ) : (
          <ChevronRight size={14} className="text-text-muted" />
        )}
      </button>

      {open && (
        <div className="mt-4 overflow-x-auto rounded border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-surface-2">
                {["#", "Phase", "Rule", "Outcome", "Detail"].map((h) => (
                  <th
                    key={h}
                    className="text-left px-3 py-2 text-text-muted font-medium whitespace-nowrap"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {steps.map((step, i) => (
                <tr
                  key={i}
                  className={clsx(
                    "border-b border-border text-xs transition-colors",
                    step.outcome === "matched"
                      ? "bg-accent-green/5 hover:bg-accent-green/10"
                      : step.outcome === "excepted"
                      ? "bg-accent-yellow/5 hover:bg-accent-yellow/10"
                      : "hover:bg-surface-2"
                  )}
                >
                  <td className="px-3 py-2 text-text-muted tabular-nums">{i + 1}</td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    <span className="tag tag-gray text-xs">{phaseLabel(step.phase)}</span>
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap font-mono text-text-secondary">
                    {step.ruleId ? (
                      <span title={step.ruleName ?? step.ruleId}>
                        {step.ruleName
                          ? step.ruleName.length > 28
                            ? step.ruleName.slice(0, 28) + "…"
                            : step.ruleName
                          : step.ruleId.slice(0, 20) + "…"}
                      </span>
                    ) : (
                      <span className="text-text-muted">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      {outcomeIcon(step.outcome)}
                      <span
                        className={clsx(
                          step.outcome === "matched" ? "text-accent-green font-medium" :
                          step.outcome === "excepted" ? "text-accent-yellow font-medium" :
                          step.outcome === "skipped" ? "text-text-muted" :
                          "text-text-secondary"
                        )}
                      >
                        {step.outcome}
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-2 text-text-secondary max-w-sm" title={step.detail}>
                    <span className="line-clamp-2">{step.detail}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Warnings panel
// ---------------------------------------------------------------------------

function WarningsPanel({ warnings }: { warnings: string[] }) {
  if (warnings.length === 0) return null;
  return (
    <div className="flex flex-col gap-1.5">
      {warnings.map((w, i) => (
        <div
          key={i}
          className="flex items-start gap-2 text-xs text-accent-yellow p-2.5 bg-accent-yellow/8 rounded border border-accent-yellow/20"
        >
          <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" />
          <span>{w}</span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Input field
// ---------------------------------------------------------------------------

function Field({
  id,
  label,
  hint,
  value,
  onChange,
  placeholder,
  mono = false,
}: {
  id: string;
  label: string;
  hint?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium text-text-secondary">
        {label}
      </label>
      <input
        id={id}
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className={clsx(
          "input text-xs py-1.5",
          mono && "font-mono"
        )}
      />
      {hint && <p className="text-xs text-text-muted">{hint}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Toggle
// ---------------------------------------------------------------------------

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center gap-2 cursor-pointer select-none">
      <div
        className={clsx(
          "relative w-8 h-4 rounded-full transition-colors",
          checked ? "bg-accent-blue" : "bg-surface-3"
        )}
        onClick={() => onChange(!checked)}
      >
        <span
          className={clsx(
            "absolute top-0.5 w-3 h-3 rounded-full bg-white shadow transition-transform",
            checked ? "translate-x-4" : "translate-x-0.5"
          )}
        />
      </div>
      <span className="text-xs text-text-secondary">{label}</span>
    </label>
  );
}

// ---------------------------------------------------------------------------
// Section header
// ---------------------------------------------------------------------------

function SectionHeader({
  icon,
  title,
}: {
  icon: React.ReactNode;
  title: string;
}) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <span className="text-text-muted">{icon}</span>
      <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
        {title}
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export function SimulatorPage() {
  const uid = useId();
  const { sessions } = useAppStore();

  // Selected policy session index
  const [selectedSessionId, setSelectedSessionId] = useState<string>(
    sessions[0]?.id ?? ""
  );

  // Binary metadata form state
  const [sha256, setSha256] = useState("");
  const [sha1, setSha1] = useState("");
  const [signerName, setSignerName] = useState("");
  const [rootCertTbs, setRootCertTbs] = useState("");
  const [issuerName, setIssuerName] = useState("");
  const [originalFileName, setOriginalFileName] = useState("");
  const [internalName, setInternalName] = useState("");
  const [productName, setProductName] = useState("");
  const [fileVersion, setFileVersion] = useState("");
  const [filePath, setFilePath] = useState("");
  const [isKernelMode, setIsKernelMode] = useState(false);

  const selectedSession = sessions.find((s) => s.id === selectedSessionId);

  const mutation = useMutation({
    mutationFn: () => {
      if (!selectedSession) throw new Error("No policy selected.");

      const binary: BinaryMetadata = {
        sha256: sha256.trim() || undefined,
        sha1: sha1.trim() || undefined,
        signerName: signerName.trim() || undefined,
        rootCertTbs: rootCertTbs.trim() || undefined,
        issuerName: issuerName.trim() || undefined,
        originalFileName: originalFileName.trim() || undefined,
        internalName: internalName.trim() || undefined,
        productName: productName.trim() || undefined,
        fileVersion: fileVersion.trim() || undefined,
        filePath: filePath.trim() || undefined,
        isKernelMode,
      };

      return policyApi.simulate(binary, selectedSession.policy);
    },
  });

  const result: EvaluationResult | undefined = mutation.data?.result;

  const canRun =
    !!selectedSession &&
    (!!sha256.trim() ||
      !!sha1.trim() ||
      !!signerName.trim() ||
      !!rootCertTbs.trim() ||
      !!filePath.trim());

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <PlayCircle size={18} className="text-accent-blue" />
          <h1 className="text-base font-semibold text-text-primary">
            Policy Simulator
          </h1>
        </div>
        <p className="text-xs text-text-muted mt-1">
          Evaluate whether a binary would be allowed or blocked — follows the
          documented WDAC rule evaluation order.
        </p>
      </div>

      <div className="flex-1 overflow-hidden flex min-h-0">
        {/* Left panel — inputs */}
        <div className="w-80 flex-shrink-0 border-r border-border overflow-y-auto p-4 space-y-5">

          {/* Policy selector */}
          <div>
            <SectionHeader icon={<FileText size={13} />} title="Policy" />
            {sessions.length === 0 ? (
              <div className="text-xs text-text-muted p-3 bg-surface-2 rounded border border-border">
                No policies loaded. Open the Policy Editor to load a WDAC XML
                file first.
              </div>
            ) : (
              <select
                className="input text-xs py-1.5 w-full"
                value={selectedSessionId}
                onChange={(e) => setSelectedSessionId(e.target.value)}
              >
                {sessions.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.fileName ?? s.policy.friendlyName ?? s.policy.policyId.slice(0, 24)}
                  </option>
                ))}
              </select>
            )}
            {selectedSession && (
              <p className="text-xs text-text-muted mt-1.5">
                {selectedSession.policy.signingScenarios.length} signing scenario
                {selectedSession.policy.signingScenarios.length !== 1 ? "s" : ""} ·{" "}
                {selectedSession.policy.signers.length} signer
                {selectedSession.policy.signers.length !== 1 ? "s" : ""} ·{" "}
                {selectedSession.policy.fileRules.filter((r) => r.kind !== "fileAttrib").length} file rules
              </p>
            )}
          </div>

          {/* Scenario */}
          <div>
            <SectionHeader icon={<Cpu size={13} />} title="Signing Scenario" />
            <Toggle
              label="Kernel-mode binary (drivers / .sys)"
              checked={isKernelMode}
              onChange={setIsKernelMode}
            />
            <p className="text-xs text-text-muted mt-1.5">
              {isKernelMode
                ? "Signing scenario 131 (kernel mode) will be evaluated."
                : "Signing scenario 12 (user mode) will be evaluated."}
            </p>
          </div>

          {/* Hash */}
          <div>
            <SectionHeader icon={<Hash size={13} />} title="Hash" />
            <div className="space-y-3">
              <Field
                id={`${uid}-sha256`}
                label="SHA-256"
                value={sha256}
                onChange={setSha256}
                placeholder="64 hex chars"
                mono
                hint="Primary hash type for modern WDAC policies."
              />
              <Field
                id={`${uid}-sha1`}
                label="SHA-1"
                value={sha1}
                onChange={setSha1}
                placeholder="40 hex chars"
                mono
                hint="Legacy hash — supported for older rule compatibility."
              />
            </div>
          </div>

          {/* Signing */}
          <div>
            <SectionHeader icon={<Key size={13} />} title="Signing Information" />
            <div className="space-y-3">
              <Field
                id={`${uid}-signer`}
                label="Signer name (CertPublisher)"
                value={signerName}
                onChange={setSignerName}
                placeholder="e.g. Microsoft Windows"
                hint="Leaf certificate CN — matched against CertPublisher on signer rules."
              />
              <Field
                id={`${uid}-root`}
                label="Root cert TBS hash"
                value={rootCertTbs}
                onChange={setRootCertTbs}
                placeholder="hex"
                mono
                hint="TBSCertificate hash of the root CA — matched against certRoot TBS."
              />
              <Field
                id={`${uid}-issuer`}
                label="Issuer name"
                value={issuerName}
                onChange={setIssuerName}
                placeholder="e.g. Microsoft Code Signing PCA"
                hint="Issuing CA name — matched against certIssuer on signer rules."
              />
            </div>
          </div>

          {/* File attributes */}
          <div>
            <SectionHeader icon={<Info size={13} />} title="PE File Attributes" />
            <div className="space-y-3">
              <Field
                id={`${uid}-ofn`}
                label="OriginalFileName"
                value={originalFileName}
                onChange={setOriginalFileName}
                placeholder="e.g. ntdll.dll"
                hint="From the PE version resource — used by FileAttrib scoping."
              />
              <Field
                id={`${uid}-in`}
                label="InternalName"
                value={internalName}
                onChange={setInternalName}
                placeholder="e.g. ntdll.dll"
              />
              <Field
                id={`${uid}-pn`}
                label="ProductName"
                value={productName}
                onChange={setProductName}
                placeholder="e.g. Microsoft® Windows® Operating System"
              />
              <Field
                id={`${uid}-fv`}
                label="FileVersion"
                value={fileVersion}
                onChange={setFileVersion}
                placeholder="e.g. 10.0.22621.1"
                hint="Used for minimumFileVersion / maximumFileVersion checks."
              />
            </div>
          </div>

          {/* Path */}
          <div>
            <SectionHeader icon={<FolderOpen size={13} />} title="File Path" />
            <Field
              id={`${uid}-path`}
              label="Full file path"
              value={filePath}
              onChange={setFilePath}
              placeholder="C:\Windows\System32\ntdll.dll"
              hint="WDAC macros (%WINDIR%, %OSDRIVE%, etc.) in rules are expanded automatically."
            />
          </div>

          {/* Run button */}
          <button
            onClick={() => mutation.mutate()}
            disabled={!canRun || mutation.isPending}
            className={clsx(
              "btn-primary w-full flex items-center justify-center gap-2 text-sm",
              (!canRun || mutation.isPending) && "opacity-50 cursor-not-allowed"
            )}
          >
            <PlayCircle size={14} />
            {mutation.isPending ? "Simulating…" : "Run Simulation"}
          </button>

          {!canRun && sessions.length > 0 && (
            <p className="text-xs text-text-muted text-center -mt-2">
              Provide at least one field (hash, signer, or path) to run.
            </p>
          )}
        </div>

        {/* Right panel — results */}
        <div className="flex-1 overflow-y-auto p-6">
          {/* Idle state */}
          {!result && !mutation.isPending && !mutation.isError && (
            <div className="h-full flex flex-col items-center justify-center text-center gap-3">
              <PlayCircle size={40} className="text-text-muted opacity-40" />
              <p className="text-sm text-text-muted">
                Fill in binary metadata on the left and click{" "}
                <strong>Run Simulation</strong> to see the evaluation result.
              </p>
              <div className="text-xs text-text-muted max-w-sm space-y-1 mt-2">
                <p>The engine follows the documented WDAC rule evaluation order:</p>
                <ol className="text-left list-decimal list-inside space-y-0.5 mt-1">
                  {[
                    "Explicit deny file rules (hash → path → attribute)",
                    "Explicit deny signer rules",
                    "Explicit allow signer rules (with FileAttrib scoping)",
                    "Explicit allow file rules (hash → attribute → path)",
                    "Default deny",
                  ].map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
              </div>
            </div>
          )}

          {/* Loading */}
          {mutation.isPending && (
            <div className="h-full flex items-center justify-center">
              <div className="flex items-center gap-2 text-sm text-text-muted">
                <PlayCircle size={16} className="animate-spin" />
                Evaluating rules…
              </div>
            </div>
          )}

          {/* Error */}
          {mutation.isError && (
            <div className="flex items-start gap-2 text-sm text-accent-red p-4 bg-accent-red/10 rounded border border-accent-red/20">
              <AlertTriangle size={16} className="flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium">Simulation failed</p>
                <p className="text-xs mt-1">{(mutation.error as Error).message}</p>
              </div>
            </div>
          )}

          {/* Results */}
          {result && !mutation.isPending && (
            <div className="space-y-4">
              {/* Verdict */}
              <VerdictBanner result={result} />

              {/* Simulation warnings */}
              <WarningsPanel warnings={result.warnings} />

              {/* Stats row */}
              <div className="grid grid-cols-3 gap-3">
                <div className="panel">
                  <p className="text-xs text-text-muted mb-1">Rules checked</p>
                  <p className="text-lg font-semibold tabular-nums text-text-primary">
                    {result.steps.filter(
                      (s) => s.ruleId && s.outcome !== "skipped"
                    ).length}
                  </p>
                </div>
                <div className="panel">
                  <p className="text-xs text-text-muted mb-1">Rules skipped</p>
                  <p className="text-lg font-semibold tabular-nums text-text-primary">
                    {result.steps.filter((s) => s.outcome === "skipped").length}
                  </p>
                </div>
                <div className="panel">
                  <p className="text-xs text-text-muted mb-1">Matched by</p>
                  <p className="text-sm font-medium text-text-primary capitalize">
                    {result.matchedBy ?? "—"}
                  </p>
                </div>
              </div>

              {/* Evaluation trace */}
              <EvalTrace steps={result.steps} />

              {/* Evaluation order reference */}
              <EvalOrderReference />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Static reference panel — WDAC evaluation order
// ---------------------------------------------------------------------------

function EvalOrderReference() {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 w-full text-left"
      >
        <Info size={14} className="text-text-muted" />
        <span className="text-sm font-medium text-text-primary flex-1">
          WDAC Rule Evaluation Order Reference
        </span>
        {open ? (
          <ChevronDown size={14} className="text-text-muted" />
        ) : (
          <ChevronRight size={14} className="text-text-muted" />
        )}
      </button>
      {open && (
        <div className="mt-4 space-y-2 text-xs text-text-secondary">
          {[
            {
              phase: "1 — Deny file rules",
              color: "text-accent-red",
              detail:
                "Explicit deny hash, path, and attribute rules referenced in the signing scenario. A match here immediately blocks — no further rules are checked.",
            },
            {
              phase: "2 — Deny signer rules",
              color: "text-accent-red",
              detail:
                "Publisher deny rules from the scenario's DeniedSigners. Matched against certRoot TBS + certPublisher + optional FileAttrib. Can be overridden by an except-allow file rule.",
            },
            {
              phase: "3 — Allow signer rules",
              color: "text-accent-green",
              detail:
                "Publisher allow rules from AllowedSigners. Rules with fileAttribRefs are scoped: the signer trust applies only to files whose attributes match at least one referenced FileAttrib. Can be overridden by an except-deny file rule.",
            },
            {
              phase: "4 — Allow file rules",
              color: "text-accent-green",
              detail:
                "Hash rules checked first (most specific), then attribute rules, then path rules (broadest). Any match here allows the binary.",
            },
            {
              phase: "5 — Default deny",
              color: "text-accent-orange",
              detail:
                "No matching allow rule was found. App Control's implicit default action blocks the binary in enforcement mode. In audit mode the event is logged but the binary executes.",
            },
          ].map(({ phase, color, detail }) => (
            <div key={phase} className="bg-surface-2 rounded p-3">
              <p className={clsx("font-medium mb-0.5", color)}>{phase}</p>
              <p className="leading-relaxed">{detail}</p>
            </div>
          ))}
          <div className="bg-surface-2 rounded p-3">
            <p className="font-medium text-accent-blue mb-0.5">
              Policy options that affect evaluation
            </p>
            <ul className="space-y-0.5">
              <li>
                <strong>Option 0 — Enabled:UMCI</strong>: if absent, user-mode binaries bypass enforcement entirely.
              </li>
              <li>
                <strong>Option 3 — Enabled:Audit Mode</strong>: all verdicts become "audit-only" — binaries are logged but not blocked.
              </li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
