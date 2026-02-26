import type { WdacPolicy, ExplainPolicyResponse } from "@appcontrol/shared";
import { POLICY_RULE_OPTIONS } from "@appcontrol/shared";
import { AlertTriangle, CheckCircle, Info, Shield, ShieldAlert } from "lucide-react";
import clsx from "clsx";

interface PolicyOverviewProps {
  policy: WdacPolicy;
  explanation?: ExplainPolicyResponse | null;
}

export function PolicyOverview({ policy, explanation }: PolicyOverviewProps) {
  const isAuditMode = policy.options.some((o) => o.value === 3 && o.enabled);
  const isUmciEnabled = policy.options.some((o) => o.value === 0 && o.enabled);
  const kernelSS = policy.signingScenarios.find((s) => s.value === 131);
  const userSS = policy.signingScenarios.find((s) => s.value === 12);

  return (
    <div className="space-y-5">
      {/* Policy identity */}
      <section className="card p-4">
        <h2 className="section-header">Policy Identity</h2>
        <dl className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
          <MetaRow label="Name" value={policy.friendlyName ?? "(unnamed)"} />
          <MetaRow label="Version" value={policy.versionEx} mono />
          <MetaRow label="Type" value={policy.policyType} />
          <MetaRow
            label="Mode"
            value={
              <span
                className={clsx(
                  "tag",
                  isAuditMode ? "tag-yellow" : "tag-green"
                )}
              >
                {isAuditMode ? "Audit" : "Enforcement"}
              </span>
            }
          />
          <MetaRow label="Policy ID" value={policy.policyId} mono />
          {policy.basePolicyId && (
            <MetaRow label="Base Policy ID" value={policy.basePolicyId} mono />
          )}
        </dl>
      </section>

      {/* Risk flags */}
      {explanation && explanation.riskFlags.length > 0 && (
        <section className="card p-4">
          <h2 className="section-header">Security Assessment</h2>
          <div className="space-y-2">
            {explanation.riskFlags.map((flag, i) => (
              <div
                key={i}
                className={clsx(
                  "flex gap-3 p-3 rounded text-sm",
                  flag.severity === "critical"
                    ? "bg-accent-red-dim/30 border border-accent-red/20"
                    : flag.severity === "warning"
                    ? "bg-accent-yellow-dim/30 border border-accent-yellow/20"
                    : "bg-surface-2 border border-border"
                )}
              >
                {flag.severity === "critical" ? (
                  <ShieldAlert size={15} className="text-accent-red flex-shrink-0 mt-0.5" />
                ) : flag.severity === "warning" ? (
                  <AlertTriangle size={15} className="text-accent-yellow flex-shrink-0 mt-0.5" />
                ) : (
                  <Info size={15} className="text-accent-blue flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <p
                    className={clsx(
                      "font-medium",
                      flag.severity === "critical"
                        ? "text-accent-red"
                        : flag.severity === "warning"
                        ? "text-accent-yellow"
                        : "text-accent-blue"
                    )}
                  >
                    {flag.message}
                  </p>
                  <p className="text-text-muted text-xs mt-0.5">{flag.detail}</p>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Rule stats */}
      <section className="card p-4">
        <h2 className="section-header">Rule Summary</h2>
        <div className="grid grid-cols-2 gap-3">
          <StatCard
            title="Kernel Mode"
            allowed={kernelSS?.allowedSigners.length ?? 0}
            denied={kernelSS?.deniedSigners.length ?? 0}
            fileRefs={kernelSS?.fileRuleRefs.length ?? 0}
          />
          <StatCard
            title="User Mode"
            allowed={userSS?.allowedSigners.length ?? 0}
            denied={userSS?.deniedSigners.length ?? 0}
            fileRefs={userSS?.fileRuleRefs.length ?? 0}
            disabled={!isUmciEnabled}
          />
        </div>
        <div className="mt-3 grid grid-cols-3 gap-3 text-center">
          <MiniStat label="Allow Rules" value={policy.fileRules.filter((r) => r.type === "Allow").length} color="green" />
          <MiniStat label="Deny Rules" value={policy.fileRules.filter((r) => r.type === "Deny").length} color="red" />
          <MiniStat label="Signers" value={policy.signers.length} color="blue" />
        </div>
      </section>

      {/* Enabled options */}
      <section className="card p-4">
        <h2 className="section-header">Enabled Options</h2>
        {policy.options.filter((o) => o.enabled).length === 0 ? (
          <p className="text-xs text-text-muted">No options are enabled.</p>
        ) : (
          <div className="space-y-1.5">
            {policy.options
              .filter((o) => o.enabled)
              .sort((a, b) => (a.value as number) - (b.value as number))
              .map((opt) => {
                const def = POLICY_RULE_OPTIONS[opt.value as keyof typeof POLICY_RULE_OPTIONS];
                return (
                  <div key={opt.value} className="flex items-start gap-2">
                    <CheckCircle size={13} className="text-accent-green flex-shrink-0 mt-0.5" />
                    <div>
                      <span className="text-xs font-medium text-text-primary mono">{def?.name}</span>
                      <p className="text-xs text-text-muted">{def?.description}</p>
                    </div>
                  </div>
                );
              })}
          </div>
        )}
      </section>
    </div>
  );
}

function MetaRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <>
      <dt className="text-xs text-text-muted font-medium">{label}</dt>
      <dd className={clsx("text-xs text-text-primary", mono && "mono truncate")}>{value}</dd>
    </>
  );
}

function StatCard({
  title,
  allowed,
  denied,
  fileRefs,
  disabled,
}: {
  title: string;
  allowed: number;
  denied: number;
  fileRefs: number;
  disabled?: boolean;
}) {
  return (
    <div className={clsx("bg-surface-2 rounded p-3", disabled && "opacity-40")}>
      <p className="text-xs font-medium text-text-secondary mb-2">{title}</p>
      <div className="space-y-1 text-xs">
        <div className="flex justify-between">
          <span className="text-text-muted">Allowed signers</span>
          <span className="text-text-primary font-mono">{allowed}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-text-muted">Denied signers</span>
          <span className="text-text-primary font-mono">{denied}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-text-muted">File rule refs</span>
          <span className="text-text-primary font-mono">{fileRefs}</span>
        </div>
      </div>
      {disabled && (
        <p className="text-xs text-text-muted mt-1 italic">UMCI not enabled</p>
      )}
    </div>
  );
}

function MiniStat({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: "green" | "red" | "blue";
}) {
  const colorClass = { green: "text-accent-green", red: "text-accent-red", blue: "text-accent-blue" }[color];
  return (
    <div className="bg-surface-2 rounded p-2">
      <p className={clsx("text-lg font-bold font-mono", colorClass)}>{value}</p>
      <p className="text-xs text-text-muted">{label}</p>
    </div>
  );
}
