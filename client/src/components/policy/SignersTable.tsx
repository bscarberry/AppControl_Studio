import { useState } from "react";
import type { WdacSignerRule } from "@appcontrol/shared";
import { Search, ChevronDown, ChevronRight, Plus, Trash2 } from "lucide-react";
import clsx from "clsx";

interface SignersTableProps {
  signers: WdacSignerRule[];
  editable?: boolean;
  onDelete?: (id: string) => void;
  onAdd?: () => void;
}

export function SignersTable({ signers, editable, onDelete, onAdd }: SignersTableProps) {
  const [filter, setFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const filtered = signers.filter((s) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      s.id.toLowerCase().includes(q) ||
      s.name.toLowerCase().includes(q) ||
      (s.certPublisher?.toLowerCase().includes(q) ?? false) ||
      (s.certRoot?.value.toLowerCase().includes(q) ?? false)
    );
  });

  function handleDeleteClick(id: string) {
    if (confirmDeleteId === id) {
      onDelete?.(id);
      setConfirmDeleteId(null);
      if (expandedId === id) setExpandedId(null);
    } else {
      setConfirmDeleteId(id);
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-3 mb-3">
        <div className="relative flex-1">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            className="input pl-8 text-xs"
            placeholder="Search signers..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        {editable && onAdd && (
          <button
            onClick={onAdd}
            className="btn-secondary text-xs flex-shrink-0 flex items-center gap-1.5"
          >
            <Plus size={12} />
            Add Signer
          </button>
        )}
      </div>

      <div className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <p className="text-xs text-text-muted text-center py-8">No signers match the filter.</p>
        ) : (
          <div className="space-y-1">
            {filtered.map((signer) => {
              const isExpanded = expandedId === signer.id;
              const pendingDelete = confirmDeleteId === signer.id;

              return (
                <div
                  key={signer.id}
                  className={clsx(
                    "border rounded overflow-hidden transition-colors",
                    pendingDelete ? "border-accent-red/40" : "border-border"
                  )}
                >
                  <div className="flex items-center bg-surface-2">
                    <button
                      className="flex items-center gap-2 px-3 py-2 text-left hover:bg-surface-3 transition-colors flex-1 min-w-0"
                      onClick={() => setExpandedId(isExpanded ? null : signer.id)}
                    >
                      {isExpanded ? (
                        <ChevronDown size={13} className="text-text-muted flex-shrink-0" />
                      ) : (
                        <ChevronRight size={13} className="text-text-muted flex-shrink-0" />
                      )}
                      <span className="text-xs font-medium text-text-primary truncate flex-1">
                        {signer.name}
                      </span>
                      <span className="mono text-xs text-text-muted flex-shrink-0 mr-2">
                        {signer.id}
                      </span>
                    </button>

                    {editable && (
                      <div className="flex items-center gap-1 px-2 flex-shrink-0">
                        {pendingDelete ? (
                          <>
                            <button
                              onClick={() => handleDeleteClick(signer.id)}
                              className="text-xs text-accent-red font-medium transition-colors px-1"
                            >
                              Confirm
                            </button>
                            <span className="text-text-muted text-xs">·</span>
                            <button
                              onClick={() => setConfirmDeleteId(null)}
                              className="text-xs text-text-muted hover:text-text-secondary transition-colors px-1"
                            >
                              Cancel
                            </button>
                          </>
                        ) : (
                          <button
                            onClick={() => handleDeleteClick(signer.id)}
                            className="text-text-muted hover:text-accent-red transition-colors p-1 rounded"
                            title="Remove signer and all references"
                          >
                            <Trash2 size={12} />
                          </button>
                        )}
                      </div>
                    )}
                  </div>

                  {isExpanded && (
                    <div className="px-4 py-3 bg-surface-1 border-t border-border space-y-2">
                      {signer.certRoot && (
                        <DetailRow
                          label={`CertRoot (${signer.certRoot.type})`}
                          value={signer.certRoot.value}
                          mono
                        />
                      )}
                      {signer.certPublisher && (
                        <DetailRow label="Publisher" value={signer.certPublisher} />
                      )}
                      {signer.certIssuer && (
                        <DetailRow label="Issuer" value={signer.certIssuer} />
                      )}
                      {signer.certOemID && (
                        <DetailRow label="OEM ID" value={signer.certOemID} mono />
                      )}
                      {signer.certEKU && signer.certEKU.length > 0 && (
                        <DetailRow
                          label="EKUs"
                          value={signer.certEKU.map((e) => e.ekuId).join(", ")}
                          mono
                        />
                      )}
                      {signer.fileAttribRefs && signer.fileAttribRefs.length > 0 && (
                        <DetailRow
                          label="FileAttrib Refs"
                          value={signer.fileAttribRefs.join(", ")}
                          mono
                        />
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3 text-xs">
      <span className="text-text-muted w-32 flex-shrink-0">{label}</span>
      <span className={`text-text-primary break-all ${mono ? "mono" : ""}`}>{value}</span>
    </div>
  );
}
