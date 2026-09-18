import type { PolicyRuleOption, WdacPolicy } from "@appcontrol/shared";
import { POLICY_RULE_OPTIONS, OPTION_PRESETS, SUPPLEMENTAL_ALLOWED_OPTIONS, applyOptionPreset } from "@appcontrol/shared";
import { AlertTriangle, Layers } from "lucide-react";
import clsx from "clsx";

interface PolicyOptionsEditorProps {
  policy: WdacPolicy;
  onChange: (updated: WdacPolicy) => void;
  readOnly?: boolean;
}

export function PolicyOptionsEditor({ policy, onChange, readOnly }: PolicyOptionsEditorProps) {
  const enabledSet = new Set(policy.options.filter((o) => o.enabled).map((o) => o.value as number));

  const toggle = (value: number) => {
    if (readOnly) return;
    const newEnabled = enabledSet.has(value);
    let newOptions: PolicyRuleOption[];
    if (newEnabled) {
      newOptions = policy.options.filter((o) => (o.value as number) !== value);
    } else {
      newOptions = [
        ...policy.options.filter((o) => (o.value as number) !== value),
        { value: value as PolicyRuleOption["value"], enabled: true },
      ];
    }
    onChange({ ...policy, options: newOptions });
  };

  const isSupplemental = policy.policyType === "Supplemental";
  const presets = OPTION_PRESETS.filter((p) => p.appliesTo === "both" || p.appliesTo === (isSupplemental ? "supplemental" : "base"));

  return (
    <div className="space-y-2">
      {!readOnly && (
        <div className="flex items-center gap-2 p-3 rounded border border-border bg-surface-2 mb-3">
          <Layers size={13} className="text-text-muted flex-shrink-0" />
          <span className="text-xs text-text-secondary">Preset:</span>
          <select
            className="input text-xs py-1 flex-1"
            value=""
            onChange={(e) => {
              const p = presets.find((x) => x.id === e.target.value);
              if (p) onChange(applyOptionPreset(policy, p));
            }}
          >
            <option value="">Apply a pre-configured option set…</option>
            {presets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>
      )}
      {isSupplemental && (
        <p className="text-xs text-accent-yellow flex items-center gap-1.5 px-1"><AlertTriangle size={12} />Supplemental policies may only carry options {[...SUPPLEMENTAL_ALLOWED_OPTIONS].join(", ")} — others are inherited from the base and will fail validation.</p>
      )}
      {Object.entries(POLICY_RULE_OPTIONS)
        .sort((a, b) => parseInt(a[0]) - parseInt(b[0]))
        .map(([num, def]) => {
          const value = parseInt(num);
          const enabled = enabledSet.has(value);
          const isCritical = "critical" in def && def.critical;
          const notAllowedHere = isSupplemental && !SUPPLEMENTAL_ALLOWED_OPTIONS.has(value);

          return (
            <div
              key={num}
              className={clsx(
                "flex items-start gap-3 p-3 rounded border transition-colors",
                enabled
                  ? "bg-surface-2 border-border"
                  : "bg-surface-1 border-border-muted opacity-60",
                !readOnly && "cursor-pointer hover:bg-surface-3"
              )}
              onClick={() => toggle(value)}
            >
              {/* Checkbox */}
              <div
                className={clsx(
                  "w-4 h-4 rounded border flex-shrink-0 mt-0.5 flex items-center justify-center transition-colors",
                  enabled
                    ? "bg-accent-blue border-accent-blue"
                    : "border-border"
                )}
              >
                {enabled && (
                  <svg
                    className="w-2.5 h-2.5 text-white"
                    viewBox="0 0 10 10"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                  >
                    <path d="M1.5 5.5l2.5 2.5 4.5-5" />
                  </svg>
                )}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-text-primary mono">{def.name}</span>
                  <span className="text-xs text-text-muted">({value})</span>
                  {notAllowedHere && <span className="tag tag-yellow text-[10px]">base only</span>}
                  {isCritical && (
                    <AlertTriangle size={12} className="text-accent-yellow flex-shrink-0" />
                  )}
                </div>
                <p className="text-xs text-text-muted mt-0.5">{def.description}</p>
              </div>
            </div>
          );
        })}
    </div>
  );
}
