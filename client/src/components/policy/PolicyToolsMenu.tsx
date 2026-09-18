/**
 * Policy Tools menu — AppControl Manager Policy Editor parity:
 * regenerate IDs, deduplicate, clear all rules, convert Base ⇄ Supplemental.
 * All operations are pure functions from @appcontrol/shared and run locally.
 */

import { useEffect, useRef, useState } from "react";
import { Wrench, ChevronDown, Fingerprint, CopyMinus, Eraser, ArrowLeftRight } from "lucide-react";
import type { WdacPolicy } from "@appcontrol/shared";
import { regenerateIds, deduplicatePolicy, clearAllRules, setPolicyType, isValidGuid } from "@appcontrol/shared";

interface Props {
  policy: WdacPolicy;
  onChange: (policy: WdacPolicy, message: string) => void;
  onError: (message: string) => void;
}

export function PolicyToolsMenu({ policy, onChange, onError }: Props) {
  const [open, setOpen] = useState(false);
  const [confirm, setConfirm] = useState<"clear" | "convert" | null>(null);
  const [baseGuid, setBaseGuid] = useState(policy.basePolicyId ?? "");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) { setOpen(false); setConfirm(null); } };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);

  const isSupp = policy.policyType === "Supplemental";

  const item = (icon: React.ReactNode, label: string, hint: string, onClick: () => void) => (
    <button className="w-full text-left px-3 py-2 hover:bg-surface-3 flex gap-2.5 items-start" onClick={onClick}>
      <span className="text-text-muted mt-0.5">{icon}</span>
      <span>
        <span className="text-xs font-medium text-text-primary block">{label}</span>
        <span className="text-[11px] text-text-muted">{hint}</span>
      </span>
    </button>
  );

  return (
    <div className="relative" ref={ref}>
      <button className="btn-ghost" onClick={() => { setOpen(!open); setConfirm(null); }}>
        <Wrench size={13} /> Tools <ChevronDown size={11} />
      </button>
      {open && (
        <div className="absolute right-0 mt-1 w-80 bg-surface-1 border border-border rounded-lg shadow-2xl z-40 py-1">
          {item(<Fingerprint size={13} />, "Regenerate IDs", "Fresh schema-valid IDs for every rule, signer and EKU; references remapped.", () => {
            onChange(regenerateIds(policy), "All rule, signer and EKU IDs regenerated.");
            setOpen(false);
          })}
          {item(<CopyMinus size={13} />, "Deduplicate", "Remove rules and signers with identical content; drop dangling references.", () => {
            const r = deduplicatePolicy(policy);
            onChange(r.policy, `Removed ${r.removedFileRules} duplicate rule(s), ${r.removedSigners} signer(s), ${r.removedEkus} EKU(s); dropped ${r.droppedDanglingRefs} dangling ref(s).`);
            setOpen(false);
          })}
          {confirm === "clear" ? (
            <div className="px-3 py-2 space-y-2 bg-accent-red/5">
              <p className="text-xs text-accent-red">Remove every rule, signer and EKU? Identity and options are kept.</p>
              <div className="flex gap-2">
                <button className="btn-danger text-xs py-1" onClick={() => { onChange(clearAllRules(policy), "All rules cleared."); setOpen(false); setConfirm(null); }}>Clear all</button>
                <button className="btn-secondary text-xs py-1" onClick={() => setConfirm(null)}>Cancel</button>
              </div>
            </div>
          ) : item(<Eraser size={13} />, "Clear all rules", "Empty the policy while keeping PolicyID, options and settings.", () => setConfirm("clear"))}
          {confirm === "convert" ? (
            <div className="px-3 py-2 space-y-2 bg-surface-2">
              {!isSupp ? (
                <>
                  <p className="text-xs text-text-secondary">Convert to Supplemental. Options not allowed in supplemental policies are removed.</p>
                  <input className="input text-xs mono" placeholder="Base policy GUID" value={baseGuid} onChange={(e) => setBaseGuid(e.target.value)} />
                </>
              ) : (
                <p className="text-xs text-text-secondary">Convert to Base. BasePolicyID becomes self-referential.</p>
              )}
              <div className="flex gap-2">
                <button
                  className="btn-primary text-xs py-1"
                  onClick={() => {
                    if (!isSupp && baseGuid.trim() && !isValidGuid(baseGuid)) { onError("Base policy GUID is not a valid GUID."); return; }
                    onChange(setPolicyType(policy, isSupp ? "Base" : "Supplemental", baseGuid), `Converted to ${isSupp ? "Base" : "Supplemental"} policy.`);
                    setOpen(false); setConfirm(null);
                  }}
                >Convert</button>
                <button className="btn-secondary text-xs py-1" onClick={() => setConfirm(null)}>Cancel</button>
              </div>
            </div>
          ) : item(<ArrowLeftRight size={13} />, `Convert to ${isSupp ? "Base" : "Supplemental"}`, isSupp ? "Make this a standalone base policy." : "Attach this policy to a base policy as a supplement.", () => setConfirm("convert"))}
        </div>
      )}
    </div>
  );
}
