import { useState } from "react";
import type { WdacFileRule } from "@appcontrol/shared";
import { Search, Hash, FolderOpen, Package, Tag } from "lucide-react";
import clsx from "clsx";

interface FileRulesTableProps {
  rules: WdacFileRule[];
  editable?: boolean;
  onDelete?: (id: string) => void;
}

type EffectFilter = "all" | "Allow" | "Deny" | "FileAttrib";

const EFFECT_COLORS: Record<string, string> = {
  Allow: "tag-green",
  Deny: "tag-red",
  FileAttrib: "tag-gray",
};

function getRuleIcon(rule: WdacFileRule): { icon: React.ReactNode; label: string } {
  switch (rule.kind) {
    case "hash":       return { icon: <Hash size={12} />, label: "Hash" };
    case "path":       return { icon: <FolderOpen size={12} />, label: "Path" };
    case "package":    return { icon: <Package size={12} />, label: "Package" };
    case "attribute":  return { icon: <Tag size={12} />, label: "Attributes" };
    case "fileAttrib": return { icon: <Tag size={12} />, label: "FileAttrib" };
  }
}

function getRuleEffectLabel(rule: WdacFileRule): string {
  return rule.kind === "fileAttrib" ? "FileAttrib" : rule.effect;
}

function getRuleValue(rule: WdacFileRule): string {
  switch (rule.kind) {
    case "hash":       return `${rule.hash.substring(0, 16)}…`;
    case "path":       return rule.filePath;
    case "package":    return rule.packageFamilyName;
    case "attribute":  return rule.fileName ?? rule.productName ?? rule.internalName ?? "—";
    case "fileAttrib": return rule.fileName ?? rule.productName ?? rule.internalName ?? "—";
  }
}

function matchesEffectFilter(rule: WdacFileRule, filter: EffectFilter): boolean {
  if (filter === "all") return true;
  if (filter === "FileAttrib") return rule.kind === "fileAttrib";
  return rule.kind !== "fileAttrib" && rule.effect === filter;
}

function countByFilter(rules: WdacFileRule[], filter: EffectFilter): number {
  return filter === "all" ? rules.length : rules.filter((r) => matchesEffectFilter(r, filter)).length;
}

export function FileRulesTable({ rules, editable, onDelete }: FileRulesTableProps) {
  const [filter, setFilter] = useState("");
  const [effectFilter, setEffectFilter] = useState<EffectFilter>("all");

  const filtered = rules.filter((r) => {
    if (!matchesEffectFilter(r, effectFilter)) return false;
    if (!filter) return true;
    const q = filter.toLowerCase();
    const value = getRuleValue(r);
    return (
      r.id.toLowerCase().includes(q) ||
      (r.friendlyName?.toLowerCase().includes(q) ?? false) ||
      value.toLowerCase().includes(q)
    );
  });

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-3 mb-3">
        <div className="relative flex-1">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            className="input pl-8 text-xs"
            placeholder="Search rules..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <div className="flex gap-1">
          {(["all", "Allow", "Deny", "FileAttrib"] as EffectFilter[]).map((t) => (
            <button
              key={t}
              onClick={() => setEffectFilter(t)}
              className={clsx(
                "px-2 py-1 text-xs rounded transition-colors",
                effectFilter === t
                  ? "bg-surface-4 text-text-primary"
                  : "text-text-muted hover:text-text-secondary"
              )}
            >
              {t === "all" ? "All" : t}
              <span className="ml-1 text-text-muted">
                ({countByFilter(rules, t)})
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <p className="text-xs text-text-muted text-center py-8">No rules match the filter.</p>
        ) : (
          <table className="data-table">
            <thead className="sticky top-0 bg-surface-1">
              <tr>
                <th>Effect</th>
                <th>Kind</th>
                <th>ID</th>
                <th>Friendly Name</th>
                <th>Value</th>
                {editable && <th></th>}
              </tr>
            </thead>
            <tbody>
              {filtered.map((rule) => {
                const { icon, label } = getRuleIcon(rule);
                const effectLabel = getRuleEffectLabel(rule);
                const value = getRuleValue(rule);

                return (
                  <tr key={rule.id}>
                    <td>
                      <span className={EFFECT_COLORS[effectLabel]}>{effectLabel}</span>
                    </td>
                    <td>
                      <span className="flex items-center gap-1 text-text-muted text-xs">
                        {icon}
                        {label}
                      </span>
                    </td>
                    <td className="mono text-xs text-text-muted">{rule.id}</td>
                    <td className="text-xs">{rule.friendlyName ?? "—"}</td>
                    <td className="mono text-xs max-w-xs truncate" title={value}>{value}</td>
                    {editable && (
                      <td>
                        <button
                          onClick={() => onDelete?.(rule.id)}
                          className="text-xs text-text-muted hover:text-accent-red transition-colors"
                        >
                          Remove
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
