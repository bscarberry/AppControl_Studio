import { useState } from "react";
import type { WdacSignerRule } from "@appcontrol/shared";
import { Search, ChevronDown, ChevronRight } from "lucide-react";

interface SignersTableProps {
  signers: WdacSignerRule[];
}

export function SignersTable({ signers }: SignersTableProps) {
  const [filter, setFilter] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filtered = signers.filter((s) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      s.id.toLowerCase().includes(q) ||
      s.name.toLowerCase().includes(q) ||
      s.certPublisher?.toLowerCase().includes(q) ||
      s.certRoot?.value.toLowerCase().includes(q)
    );
  });

  return (
    <div className="flex flex-col h-full">
      <div className="mb-3">
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-muted" />
          <input
            className="input pl-8 text-xs"
            placeholder="Search signers..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <p className="text-xs text-text-muted text-center py-8">No signers match the filter.</p>
        ) : (
          <div className="space-y-1">
            {filtered.map((signer) => {
              const isExpanded = expandedId === signer.id;
              return (
                <div key={signer.id} className="border border-border rounded overflow-hidden">
                  <button
                    className="w-full flex items-center gap-2 px-3 py-2 text-left bg-surface-2 hover:bg-surface-3 transition-colors"
                    onClick={() => setExpandedId(isExpanded ? null : signer.id)}
                  >
                    {isExpanded ? (
                      <ChevronDown size={13} className="text-text-muted flex-shrink-0" />
                    ) : (
                      <ChevronRight size={13} className="text-text-muted flex-shrink-0" />
                    )}
                    <span className="text-xs font-medium text-text-primary truncate flex-1">{signer.name}</span>
                    <span className="mono text-xs text-text-muted flex-shrink-0">{signer.id}</span>
                  </button>

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
