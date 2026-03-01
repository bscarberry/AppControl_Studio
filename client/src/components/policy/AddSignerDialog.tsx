/**
 * Add Signer Dialog
 *
 * Creates a new WDAC signer rule and registers it in one or more signing
 * scenarios as an AllowedSigner or DeniedSigner.
 *
 * A signer rule can express trust via:
 *   certRoot     — TBSCertificate hash of the root CA (type=TBS) or a
 *                  well-known root identifier (type=Wellknown)
 *   certPublisher — CN of the leaf / end-entity certificate
 *   certIssuer   — CN of the issuing CA
 *
 * At least one certificate constraint is required. FileAttrib scoping
 * (fileAttribRefs) can optionally restrict the signer to matching files.
 *
 * Reference:
 *   https://learn.microsoft.com/en-us/windows/security/application-security/
 *   application-control/app-control-for-business/design/use-wdac-policy-to-control-specific-plug-ins-add-ins-and-modules
 */

import { useState } from "react";
import { X, Info } from "lucide-react";
import clsx from "clsx";
import type {
  WdacPolicy,
  WdacSignerRule,
  CertRootType,
  SigningScenarioValue,
} from "@appcontrol/shared";
import { addSigner } from "../../lib/policy-mutations.ts";

interface Props {
  policy: WdacPolicy;
  onCommit: (updated: WdacPolicy) => void;
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function Label({ htmlFor, children }: { htmlFor: string; children: React.ReactNode }) {
  return (
    <label htmlFor={htmlFor} className="text-xs font-medium text-text-secondary">
      {children}
    </label>
  );
}

function FieldError({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return <p className="text-xs text-accent-red mt-0.5">{msg}</p>;
}

function TextInput({
  id,
  value,
  onChange,
  placeholder,
  mono,
  required,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  mono?: boolean;
  required?: boolean;
}) {
  return (
    <input
      id={id}
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      required={required}
      className={clsx("input text-xs py-1.5", mono && "font-mono")}
    />
  );
}

// ---------------------------------------------------------------------------
// Scenario effect row
// ---------------------------------------------------------------------------

function ScenarioRow({
  value,
  label,
  present,
  checked,
  effect,
  onToggle,
  onEffectChange,
}: {
  value: SigningScenarioValue;
  label: string;
  present: boolean;
  checked: boolean;
  effect: "Allow" | "Deny";
  onToggle: () => void;
  onEffectChange: (e: "Allow" | "Deny") => void;
}) {
  return (
    <div
      className={clsx(
        "flex items-center gap-3 px-3 py-2 rounded border transition-colors",
        checked
          ? "border-accent-blue bg-accent-blue/10"
          : "border-border"
      )}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={onToggle}
        className="accent-accent-blue flex-shrink-0"
      />
      <span className="text-xs text-text-primary flex-1">
        {label}
        {!present && (
          <span className="ml-1.5 text-text-muted">(will be created)</span>
        )}
      </span>
      {checked && (
        <select
          value={effect}
          onChange={(e) => onEffectChange(e.target.value as "Allow" | "Deny")}
          className="input text-xs py-1 w-24"
        >
          <option value="Allow">Allow</option>
          <option value="Deny">Deny</option>
        </select>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main dialog
// ---------------------------------------------------------------------------

export function AddSignerDialog({ policy, onCommit, onClose }: Props) {
  const [name, setName] = useState("");

  // Certificate constraints
  const [certRootEnabled, setCertRootEnabled] = useState(false);
  const [certRootType, setCertRootType] = useState<CertRootType>("TBS");
  const [certRootValue, setCertRootValue] = useState("");
  const [certPublisher, setCertPublisher] = useState("");
  const [certIssuer, setCertIssuer] = useState("");

  // FileAttrib scoping — multi-select from existing fileAttrib rules
  const fileAttribs = policy.fileRules.filter((r) => r.kind === "fileAttrib");
  const [selectedAttribRefs, setSelectedAttribRefs] = useState<Set<string>>(new Set());

  // Scenario assignments
  const scenariosPresent = policy.signingScenarios.map((sc) => sc.value);
  const allScenarioValues: SigningScenarioValue[] = [12, 131];

  const [scenarioChecked, setScenarioChecked] = useState<
    Record<SigningScenarioValue, boolean>
  >({ 12: scenariosPresent.includes(12), 131: scenariosPresent.includes(131) });
  const [scenarioEffect, setScenarioEffect] = useState<
    Record<SigningScenarioValue, "Allow" | "Deny">
  >({ 12: "Allow", 131: "Allow" });

  const [submitAttempted, setSubmitAttempted] = useState(false);

  function toggleAttribRef(id: string) {
    setSelectedAttribRefs((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  // ---- validation ----
  const nameErr = submitAttempted && !name.trim() ? "Signer name is required." : null;

  const hasAnyCert =
    (certRootEnabled && certRootValue.trim()) ||
    certPublisher.trim() ||
    certIssuer.trim();
  const certConstraintErr =
    submitAttempted && !hasAnyCert
      ? "At least one certificate constraint (CertRoot, Publisher, or Issuer) is required."
      : null;

  const certRootValErr =
    submitAttempted &&
    certRootEnabled &&
    !certRootValue.trim()
      ? "CertRoot value is required when CertRoot is enabled."
      : null;

  const tbsHexErr =
    submitAttempted &&
    certRootEnabled &&
    certRootType === "TBS" &&
    certRootValue.trim() &&
    !/^[0-9a-fA-F]+$/.test(certRootValue.trim())
      ? "TBS hash must be a hexadecimal string."
      : null;

  const noScenarioErr =
    submitAttempted &&
    !Object.entries(scenarioChecked).some(([, v]) => v)
      ? "Select at least one signing scenario."
      : null;

  function isValid(): boolean {
    if (!name.trim()) return false;
    if (!hasAnyCert) return false;
    if (certRootEnabled && !certRootValue.trim()) return false;
    if (
      certRootEnabled &&
      certRootType === "TBS" &&
      certRootValue.trim() &&
      !/^[0-9a-fA-F]+$/.test(certRootValue.trim())
    )
      return false;
    if (!Object.entries(scenarioChecked).some(([, v]) => v)) return false;
    return true;
  }

  function handleSubmit() {
    setSubmitAttempted(true);
    if (!isValid()) return;

    const signer: Omit<WdacSignerRule, "id"> = {
      name: name.trim(),
      certRoot: certRootEnabled
        ? { type: certRootType, value: certRootValue.trim() }
        : undefined,
      certPublisher: certPublisher.trim() || undefined,
      certIssuer: certIssuer.trim() || undefined,
      fileAttribRefs:
        selectedAttribRefs.size > 0 ? [...selectedAttribRefs] : undefined,
    };

    const scenarioEntries = allScenarioValues
      .filter((sv) => scenarioChecked[sv])
      .map((sv) => ({ scenarioValue: sv, effect: scenarioEffect[sv] }));

    const updated = addSigner(policy, { signer, scenarioEntries });
    onCommit(updated);
    onClose();
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-surface-1 border border-border rounded-lg w-full max-w-xl shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border flex-shrink-0">
          <h2 className="text-sm font-semibold text-text-primary">Add Signer Rule</h2>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto flex-1 px-5 py-4 space-y-5">

          {/* Name */}
          <div className="flex flex-col gap-1">
            <Label htmlFor="sname">Signer Name *</Label>
            <TextInput
              id="sname"
              value={name}
              onChange={setName}
              placeholder="e.g. Microsoft Windows Production PCA 2011"
              required
            />
            <FieldError msg={nameErr} />
          </div>

          {/* Cert constraints */}
          <div className="space-y-3">
            <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Certificate Constraints
            </p>
            <p className="text-xs text-text-muted">
              At least one constraint is required. WDAC matches all specified constraints — a
              binary must satisfy every constraint listed for the signer rule to apply.
            </p>

            {/* CertRoot */}
            <div
              className={clsx(
                "rounded border p-3 space-y-3 transition-colors",
                certRootEnabled ? "border-accent-blue/40 bg-accent-blue/5" : "border-border"
              )}
            >
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={certRootEnabled}
                  onChange={(e) => setCertRootEnabled(e.target.checked)}
                  className="accent-accent-blue"
                />
                <span className="text-xs font-medium text-text-primary">CertRoot</span>
                <span className="text-xs text-text-muted">— TBSCertificate hash of the root CA</span>
              </label>

              {certRootEnabled && (
                <div className="grid grid-cols-3 gap-3">
                  <div className="flex flex-col gap-1">
                    <Label htmlFor="crtype">Type</Label>
                    <select
                      id="crtype"
                      className="input text-xs py-1.5"
                      value={certRootType}
                      onChange={(e) => setCertRootType(e.target.value as CertRootType)}
                    >
                      <option value="TBS">TBS (hash)</option>
                      <option value="Wellknown">Wellknown (ID)</option>
                    </select>
                  </div>
                  <div className="flex flex-col gap-1 col-span-2">
                    <Label htmlFor="crval">
                      {certRootType === "TBS" ? "TBS Hash (hex)" : "Wellknown ID"}
                    </Label>
                    <TextInput
                      id="crval"
                      value={certRootValue}
                      onChange={setCertRootValue}
                      placeholder={certRootType === "TBS" ? "Hex-encoded TBS hash" : "e.g. 1"}
                      mono={certRootType === "TBS"}
                    />
                    <FieldError msg={certRootValErr ?? tbsHexErr} />
                  </div>
                </div>
              )}
            </div>

            {/* CertPublisher */}
            <div className="flex flex-col gap-1">
              <Label htmlFor="cpub">CertPublisher — leaf certificate CN</Label>
              <TextInput
                id="cpub"
                value={certPublisher}
                onChange={setCertPublisher}
                placeholder="e.g. Microsoft Windows"
              />
              <p className="text-xs text-text-muted">
                The Common Name (CN) of the end-entity (leaf) signing certificate.
              </p>
            </div>

            {/* CertIssuer */}
            <div className="flex flex-col gap-1">
              <Label htmlFor="ciss">CertIssuer — CA name</Label>
              <TextInput
                id="ciss"
                value={certIssuer}
                onChange={setCertIssuer}
                placeholder="e.g. Microsoft Code Signing PCA 2011"
              />
            </div>

            <FieldError msg={certConstraintErr} />
          </div>

          {/* FileAttrib scoping */}
          {fileAttribs.length > 0 && (
            <div className="space-y-2">
              <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                FileAttrib Scoping (optional)
              </p>
              <div className="flex items-start gap-2 text-xs text-text-muted bg-surface-2 p-2.5 rounded border border-border">
                <Info size={12} className="flex-shrink-0 mt-0.5" />
                <span>
                  When FileAttrib references are set, the signer rule applies only to files whose
                  PE version-resource attributes match at least one of the selected FileAttrib rules.
                </span>
              </div>
              <div className="space-y-1 max-h-36 overflow-y-auto">
                {fileAttribs.map((fa) => (
                  <label
                    key={fa.id}
                    className={clsx(
                      "flex items-center gap-2 px-3 py-1.5 rounded border cursor-pointer transition-colors text-xs",
                      selectedAttribRefs.has(fa.id)
                        ? "border-accent-blue/40 bg-accent-blue/10"
                        : "border-border hover:border-border-strong"
                    )}
                  >
                    <input
                      type="checkbox"
                      checked={selectedAttribRefs.has(fa.id)}
                      onChange={() => toggleAttribRef(fa.id)}
                      className="accent-accent-blue"
                    />
                    <span className="text-text-primary font-medium">
                      {fa.friendlyName ?? fa.id}
                    </span>
                    <span className="text-text-muted font-mono">{fa.id}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Scenario assignment */}
          <div className="space-y-2">
            <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Signing Scenario Assignment
            </p>
            <p className="text-xs text-text-muted">
              The signer ID will be added to the selected scenario's AllowedSigners or DeniedSigners.
            </p>
            <div className="space-y-2">
              {allScenarioValues.map((sv) => (
                <ScenarioRow
                  key={sv}
                  value={sv}
                  label={sv === 131 ? "Kernel Mode (131)" : "User Mode (12)"}
                  present={scenariosPresent.includes(sv)}
                  checked={scenarioChecked[sv]}
                  effect={scenarioEffect[sv]}
                  onToggle={() =>
                    setScenarioChecked((prev) => ({ ...prev, [sv]: !prev[sv] }))
                  }
                  onEffectChange={(e) =>
                    setScenarioEffect((prev) => ({ ...prev, [sv]: e }))
                  }
                />
              ))}
            </div>
            <FieldError msg={noScenarioErr} />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-border flex-shrink-0">
          <button onClick={onClose} className="btn-secondary text-xs">
            Cancel
          </button>
          <button onClick={handleSubmit} className="btn-primary text-xs">
            Add Signer
          </button>
        </div>
      </div>
    </div>
  );
}
