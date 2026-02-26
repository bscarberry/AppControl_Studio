import { useState } from "react";
import type { WdacFileRule } from "@appcontrol/shared";
import { Search, Hash, FolderOpen, Package, Tag } from "lucide-react";
import clsx from "clsx";

interface FileRulesTableProps {
  rules: WdacFileRule[];
  editable?: boolean;
  onDelete?: (id: string) => void;
}

const RULE_TYPE_COLORS: Record<string, string> = {
  Allow: "tag-green",
  Deny: "tag-red",
  FileAttrib: "tag-gray",
};

function getRuleKind(rule: WdacFileRule): { icon: React.ReactNode; label: string } {
  if (rule.hash) return { icon: <Hash size={12} />, label: "Hash" };
  if (rule.filePath) return { icon: <FolderOpen size={12} />, label: "Path" };
  if (rule.packageFamilyName) return { icon: <Package size={12} />, label: "Package" };
  if (rule.fileName || rule.productName || rule.internalName)
    return { icon: <Tag size={12} />, label: "Attributes" };
  return { icon: null, label: "Unknown" };
}

export function FileRulesTable({ rules, editable, onDelete }: FileRulesTableProps) {
  const [filter, setFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState<"all" | "Allow" | "Deny" | "FileAttrib">("all");

  const filtered = rules.filter((r) => {
    if (typeFilter !== "all" && r.type !== typeFilter) return false;
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      r.id.toLowerCase().includes(q) ||
      r.friendlyName?.toLowerCase().includes(q) ||
      r.fileName?.toLowerCase().includes(q) ||
      r.hash?.toLowerCase().includes(q) ||
      r.filePath?.toLowerCase().includes(q) ||
      r.productName?.toLowerCase().includes(q)
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
          {(["all", "Allow", "Deny", "FileAttrib"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={clsx(
                "px-2 py-1 text-xs rounded transition-colors",
                typeFilter === t
                  ? "bg-surface-4 text-text-primary"
                  : "text-text-muted hover:text-text-secondary"
              )}
            >
              {t === "all" ? "All" : t}
              <span className="ml-1 text-text-muted">
                ({t === "all" ? rules.length : rules.filter((r) => r.type === t).length})
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
                <th>Type</th>
                <th>Kind</th>
                <th>ID</th>
                <th>Friendly Name</th>
                <th>Value</th>
                {editable && <th></th>}
              </tr>
            </thead>
            <tbody>
              {filtered.map((rule) => {
                const kind = getRuleKind(rule);
                const value =
                  rule.hash
                    ? `${rule.hash.substring(0, 16)}…`
                    : rule.filePath
                    ? rule.filePath
                    : rule.fileName
                    ? rule.fileName
                    : rule.packageFamilyName
                    ? rule.packageFamilyName
                    : rule.productName ?? "—";

                return (
                  <tr key={rule.id}>
                    <td>
                      <span className={RULE_TYPE_COLORS[rule.type]}>{rule.type}</span>
                    </td>
                    <td>
                      <span className="flex items-center gap-1 text-text-muted text-xs">
                        {kind.icon}
                        {kind.label}
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
