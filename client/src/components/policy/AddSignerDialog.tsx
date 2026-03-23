/**
 * Add Signer Dialog — with WDAC Wizard-style specificity slider
 *
 * Specificity levels (from broadest to narrowest), matching the WDAC Policy Wizard:
 *
 *   PCACertificate  — Trust anything signed by this root/PCA CA.
 *                     Required: CertRoot (TBS hash).
 *
 *   Publisher       — Trust all files from this specific publisher.
 *                     Required: CertRoot + CertPublisher (leaf CN).
 *
 *   FilePublisher   — Trust this specific file from this publisher.
 *                     Required: CertRoot + CertPublisher + FileAttrib (FileName + MinVersion).
 *
 * Certificate files (.cer/.crt/.pem) can be uploaded to auto-fill CertRoot
 * (TBS hash), CertPublisher (subject CN), and CertIssuer.
 */

import { useState, useRef } from "react";
import { X, Info, Upload, ChevronLeft, ChevronRight, Shield, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import type {
  WdacPolicy,
  WdacSignerRule,
  WdacFileAttrib,
  CertRootType,
  SigningScenarioValue,
  SignerSpecificity,
} from "@appcontrol/shared";
import { addSigner } from "../../lib/policy-mutations.ts";
import { policyApi } from "../../lib/api.ts";

interface Props {
  policy: WdacPolicy;
  onCommit: (updated: WdacPolicy) => void;
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Specificity slider configuration
// ---------------------------------------------------------------------------

const SPECIFICITY_LEVELS: {
  id: SignerSpecificity;
  label: string;
  summary: string;
  security: "broad" | "balanced" | "precise";
  requiredFields: string[];
}[] = [
  {
    id: "PCACertificate",
    label: "PCA Certificate",
    summary: "Trust all code signed by this root or intermediate CA. Broadest trust.",
    security: "broad",
    requiredFields: ["CertRoot (TBS hash)"],
  },
  {
    id: "Publisher",
    label: "Publisher",
    summary: "Trust all files from this specific publisher. Survives software updates.",
    security: "balanced",
    requiredFields: ["CertRoot (TBS hash)", "CertPublisher (leaf CN)"],
  },
  {
    id: "FilePublisher",
    label: "File Publisher",
    summary: "Trust only this specific file from this publisher. Narrowest — must update on version change.",
    security: "precise",
    requiredFields: ["CertRoot (TBS hash)", "CertPublisher (leaf CN)", "FileName", "Minimum Version"],
  },
];

const SPECIFICITY_INDEX: Record<SignerSpecificity, number> = {
  PCACertificate: 0,
  Publisher: 1,
  FilePublisher: 2,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function Label({ htmlFor, children }: { htmlFor: string; children: React.ReactNode }) {
  return <label htmlFor={htmlFor} className="text-xs font-medium text-text-secondary">{children}</label>;
}

function FieldError({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return <p className="text-xs text-accent-red mt-0.5">{msg}</p>;
}

function TextInput({
  id, value, onChange, placeholder, mono, disabled,
}: {
  id: string; value: string; onChange: (v: string) => void;
  placeholder?: string; mono?: boolean; disabled?: boolean;
}) {
  return (
    <input
      id={id} type="text" value={value} onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder} disabled={disabled}
      className={clsx("input text-xs py-1.5", mono && "font-mono", disabled && "opacity-50 cursor-not-allowed")}
    />
  );
}

function ScenarioRow({
  value, label, present, checked, effect, onToggle, onEffectChange,
}: {
  value: SigningScenarioValue; label: string; present: boolean;
  checked: boolean; effect: "Allow" | "Deny";
  onToggle: () => void; onEffectChange: (e: "Allow" | "Deny") => void;
}) {
  return (
    <div className={clsx(
      "flex items-center gap-3 px-3 py-2 rounded border transition-colors",
      checked ? "border-accent-blue bg-accent-blue/10" : "border-border"
    )}>
      <input type="checkbox" checked={checked} onChange={onToggle} className="accent-accent-blue flex-shrink-0" />
      <span className="text-xs text-text-primary flex-1">
        {label}
        {!present && <span className="ml-1.5 text-text-muted">(will be created)</span>}
      </span>
      {checked && (
        <select value={effect} onChange={(e) => onEffectChange(e.target.value as "Allow" | "Deny")} className="input text-xs py-1 w-24">
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
  // Mode: "guided" (specificity slider) or "advanced" (manual fields)
  const [mode, setMode] = useState<"guided" | "advanced">("guided");

  // Guided mode
  const [specificityIdx, setSpecificityIdx] = useState(1); // Publisher by default
  const specificity = SPECIFICITY_LEVELS[specificityIdx];

  // Common fields
  const [name, setName] = useState("");
  const [certRootValue, setCertRootValue] = useState("");
  const [certRootType, setCertRootType] = useState<CertRootType>("TBS");
  const [certPublisher, setCertPublisher] = useState("");
  const [certIssuer, setCertIssuer] = useState("");

  // FilePublisher-specific
  const [fileAttribFileName, setFileAttribFileName] = useState("");
  const [fileAttribMinVersion, setFileAttribMinVersion] = useState("");

  // Advanced mode: manual FileAttrib refs from existing policy rules
  const existingFileAttribs = policy.fileRules.filter((r) => r.kind === "fileAttrib") as WdacFileAttrib[];
  const [selectedAttribRefs, setSelectedAttribRefs] = useState<Set<string>>(new Set());

  // Cert file upload state
  const [certLoading, setCertLoading] = useState(false);
  const [certError, setCertError] = useState<string | null>(null);
  const [certLoaded, setCertLoaded] = useState(false);
  const certInputRef = useRef<HTMLInputElement>(null);

  // Scenario assignments
  const scenariosPresent = policy.signingScenarios.map((sc) => sc.value);
  const allScenarioValues: SigningScenarioValue[] = [12, 131];
  const [scenarioChecked, setScenarioChecked] = useState<Record<SigningScenarioValue, boolean>>(
    { 12: scenariosPresent.includes(12), 131: scenariosPresent.includes(131) }
  );
  const [scenarioEffect, setScenarioEffect] = useState<Record<SigningScenarioValue, "Allow" | "Deny">>(
    { 12: "Allow", 131: "Allow" }
  );

  const [submitAttempted, setSubmitAttempted] = useState(false);

  // ---- Certificate file upload ----
  async function handleCertUpload(file: File) {
    setCertLoading(true);
    setCertError(null);
    setCertLoaded(false);
    try {
      const buf = await file.arrayBuffer();
      const base64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
      const info = await policyApi.certInfo(base64, file.name);
      setCertRootValue(info.tbsHash);
      setCertRootType("TBS");
      setCertPublisher(info.subjectCN);
      setCertIssuer(info.issuerCN);
      if (!name) setName(info.subjectCN);
      setCertLoaded(true);
    } catch (e) {
      setCertError((e as Error).message);
    } finally {
      setCertLoading(false);
    }
  }

  // ---- Validation ----
  const requiresCertRoot = specificity.id !== undefined; // all levels need certRoot in guided mode
  const requiresPublisher = specificity.id === "Publisher" || specificity.id === "FilePublisher";
  const requiresFileAttrib = specificity.id === "FilePublisher";

  const nameErr = submitAttempted && !name.trim() ? "Signer name is required." : null;
  const certRootErr = submitAttempted && !certRootValue.trim() ? "CertRoot TBS hash is required." : null;
  const tbsHexErr = submitAttempted && certRootValue.trim() && !/^[0-9a-fA-F]+$/.test(certRootValue.trim())
    ? "TBS hash must be a hexadecimal string." : null;
  const publisherErr = submitAttempted && requiresPublisher && !certPublisher.trim()
    ? "CertPublisher (leaf certificate CN) is required for this specificity level." : null;
  const fileNameErr = submitAttempted && requiresFileAttrib && !fileAttribFileName.trim()
    ? "File name is required for FilePublisher specificity." : null;
  const noScenarioErr = submitAttempted && !Object.values(scenarioChecked).some(Boolean)
    ? "Select at least one signing scenario." : null;

  // Advanced mode validation
  const advancedHasAnyCert = certRootValue.trim() || certPublisher.trim() || certIssuer.trim();
  const advancedCertErr = submitAttempted && mode === "advanced" && !advancedHasAnyCert
    ? "At least one certificate constraint is required." : null;

  function isValid(): boolean {
    if (!name.trim()) return false;
    if (!Object.values(scenarioChecked).some(Boolean)) return false;
    if (mode === "guided") {
      if (!certRootValue.trim()) return false;
      if (certRootValue.trim() && !/^[0-9a-fA-F]+$/.test(certRootValue.trim())) return false;
      if (requiresPublisher && !certPublisher.trim()) return false;
      if (requiresFileAttrib && !fileAttribFileName.trim()) return false;
    } else {
      if (!advancedHasAnyCert) return false;
    }
    return true;
  }

  function handleSubmit() {
    setSubmitAttempted(true);
    if (!isValid()) return;

    const newRules: WdacFileAttrib[] = [];
    let newFileAttribRef: string | undefined;

    // In guided FilePublisher mode, create a new FileAttrib rule
    if (mode === "guided" && specificity.id === "FilePublisher" && fileAttribFileName.trim()) {
      const faId = `ID_FILEATTRIB_F_${Math.random().toString(16).slice(2, 8).toUpperCase()}`;
      const fa: WdacFileAttrib = {
        kind: "fileAttrib",
        id: faId,
        friendlyName: fileAttribFileName.trim(),
        fileName: fileAttribFileName.trim(),
        minimumFileVersion: fileAttribMinVersion.trim() || undefined,
      };
      newRules.push(fa);
      newFileAttribRef = faId;
    }

    const signer: Omit<WdacSignerRule, "id"> = {
      name: name.trim(),
      certRoot: certRootValue.trim()
        ? { type: certRootType, value: certRootValue.trim() }
        : undefined,
      certPublisher: certPublisher.trim() || undefined,
      certIssuer: certIssuer.trim() || undefined,
      fileAttribRefs: mode === "guided"
        ? (newFileAttribRef ? [newFileAttribRef] : undefined)
        : (selectedAttribRefs.size > 0 ? [...selectedAttribRefs] : undefined),
      specificity: mode === "guided" ? specificity.id : undefined,
    };

    const scenarioEntries = allScenarioValues
      .filter((sv) => scenarioChecked[sv])
      .map((sv) => ({ scenarioValue: sv, effect: scenarioEffect[sv] }));

    // Insert the FileAttrib rule(s) before adding the signer
    let updatedPolicy: WdacPolicy = policy;
    for (const fa of newRules) {
      updatedPolicy = { ...updatedPolicy, fileRules: [...updatedPolicy.fileRules, fa] };
    }
    updatedPolicy = addSigner(updatedPolicy, { signer, scenarioEntries });
    onCommit(updatedPolicy);
    onClose();
  }

  const securityColor = {
    broad: "text-accent-yellow",
    balanced: "text-accent-blue",
    precise: "text-accent-green",
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-surface-1 border border-border rounded-lg w-full max-w-xl shadow-2xl flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <Shield size={16} className="text-accent-blue" />
            <h2 className="text-sm font-semibold text-text-primary">Add Publisher Rule</h2>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMode(mode === "guided" ? "advanced" : "guided")}
              className="text-xs text-text-muted hover:text-text-secondary transition-colors"
            >
              {mode === "guided" ? "Advanced mode" : "Guided mode"}
            </button>
            <button onClick={onClose} className="text-text-muted hover:text-text-primary transition-colors">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="overflow-y-auto flex-1 px-5 py-4 space-y-5">

          {/* Signer name */}
          <div className="flex flex-col gap-1">
            <Label htmlFor="sname">Rule Name *</Label>
            <TextInput
              id="sname" value={name} onChange={setName}
              placeholder="e.g. Microsoft Windows Production PCA 2011"
            />
            <FieldError msg={nameErr} />
          </div>

          {/* === GUIDED MODE === */}
          {mode === "guided" && (
            <>
              {/* Specificity Slider */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                    Rule Specificity
                  </p>
                  <span className={clsx("text-xs font-semibold", securityColor[specificity.security])}>
                    {specificity.label}
                  </span>
                </div>

                {/* Track */}
                <div className="relative">
                  <div className="flex items-center justify-between gap-1">
                    {SPECIFICITY_LEVELS.map((level, i) => (
                      <button
                        key={level.id}
                        onClick={() => setSpecificityIdx(i)}
                        className={clsx(
                          "flex-1 px-2 py-2 text-xs rounded border transition-all text-center",
                          i === specificityIdx
                            ? "border-accent-blue bg-accent-blue/15 text-text-primary font-semibold"
                            : "border-border text-text-muted hover:border-border-strong hover:text-text-secondary"
                        )}
                      >
                        <div>{level.label}</div>
                        <div className="mt-0.5 text-[10px] opacity-70">
                          {i === 0 ? "← Broad" : i === 2 ? "Narrow →" : "Balanced"}
                        </div>
                      </button>
                    ))}
                  </div>
                </div>

                <div className="bg-surface-2 rounded border border-border px-3 py-2.5 space-y-1.5">
                  <p className="text-xs text-text-primary">{specificity.summary}</p>
                  <p className="text-xs text-text-muted">
                    Required fields: {specificity.requiredFields.join(", ")}
                  </p>
                </div>
              </div>

              {/* Cert Upload */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                    Certificate
                  </p>
                  <button
                    onClick={() => certInputRef.current?.click()}
                    disabled={certLoading}
                    className="flex items-center gap-1.5 text-xs text-accent-blue hover:text-accent-blue/80 transition-colors disabled:opacity-50"
                  >
                    <Upload size={12} />
                    {certLoading ? "Reading..." : "Upload .cer / .crt / .pem"}
                  </button>
                  <input
                    ref={certInputRef}
                    type="file"
                    accept=".cer,.crt,.pem,.der"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleCertUpload(file);
                      e.target.value = "";
                    }}
                  />
                </div>

                {certLoaded && (
                  <div className="flex items-center gap-1.5 text-xs text-accent-green">
                    <Shield size={11} />
                    Certificate fields populated from file.
                  </div>
                )}
                {certError && (
                  <div className="flex items-center gap-1.5 text-xs text-accent-red">
                    <AlertTriangle size={11} />
                    {certError}
                  </div>
                )}

                {/* CertRoot TBS */}
                <div className="flex flex-col gap-1">
                  <Label htmlFor="cr-guided">CertRoot TBS Hash (hex) *</Label>
                  <TextInput
                    id="cr-guided" value={certRootValue} onChange={setCertRootValue}
                    placeholder="SHA-256 TBSCertificate hash (hex)" mono
                  />
                  <FieldError msg={certRootErr ?? tbsHexErr} />
                </div>

                {/* CertPublisher — required for Publisher + FilePublisher */}
                <div className="flex flex-col gap-1">
                  <Label htmlFor="cpub-guided">
                    CertPublisher (leaf CN){requiresPublisher ? " *" : ""}
                  </Label>
                  <TextInput
                    id="cpub-guided" value={certPublisher} onChange={setCertPublisher}
                    placeholder="e.g. Microsoft Windows"
                    disabled={specificityIdx === 0}
                  />
                  {specificityIdx === 0 && (
                    <p className="text-xs text-text-muted">Not used at PCACertificate level.</p>
                  )}
                  <FieldError msg={publisherErr} />
                </div>

                {/* CertIssuer (optional on all levels) */}
                <div className="flex flex-col gap-1">
                  <Label htmlFor="ciss-guided">CertIssuer (CA name, optional)</Label>
                  <TextInput
                    id="ciss-guided" value={certIssuer} onChange={setCertIssuer}
                    placeholder="e.g. Microsoft Code Signing PCA 2011"
                  />
                </div>
              </div>

              {/* FileAttrib — only for FilePublisher */}
              {specificityIdx === 2 && (
                <div className="space-y-2">
                  <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                    File Scope (FilePublisher)
                  </p>
                  <div className="flex items-start gap-2 text-xs text-text-muted bg-surface-2 p-2.5 rounded border border-border">
                    <Info size={12} className="flex-shrink-0 mt-0.5" />
                    <span>
                      A new FileAttrib rule will be created and linked to this signer. The rule
                      applies only to files matching the specified name and version.
                    </span>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="flex flex-col gap-1">
                      <Label htmlFor="fa-filename">File Name *</Label>
                      <TextInput
                        id="fa-filename" value={fileAttribFileName} onChange={setFileAttribFileName}
                        placeholder="e.g. notepad.exe"
                      />
                      <FieldError msg={fileNameErr} />
                    </div>
                    <div className="flex flex-col gap-1">
                      <Label htmlFor="fa-version">Minimum Version</Label>
                      <TextInput
                        id="fa-version" value={fileAttribMinVersion} onChange={setFileAttribMinVersion}
                        placeholder="e.g. 10.0.0.0"
                      />
                    </div>
                  </div>
                </div>
              )}
            </>
          )}

          {/* === ADVANCED MODE === */}
          {mode === "advanced" && (
            <div className="space-y-4">
              <div className="flex items-start gap-2 text-xs text-text-muted bg-surface-2 p-2.5 rounded border border-border">
                <Info size={12} className="flex-shrink-0 mt-0.5" />
                <span>Advanced mode: manually configure all certificate constraints. At least one is required.</span>
              </div>

              {/* CertRoot */}
              <div className="rounded border p-3 space-y-3 border-border">
                <p className="text-xs font-semibold text-text-primary">CertRoot — TBSCertificate hash of the root CA</p>
                <div className="flex items-center gap-1.5 mb-1">
                  <button
                    onClick={() => certInputRef.current?.click()}
                    disabled={certLoading}
                    className="flex items-center gap-1.5 text-xs text-accent-blue hover:text-accent-blue/80 transition-colors disabled:opacity-50"
                  >
                    <Upload size={12} />
                    {certLoading ? "Reading..." : "Upload .cer/.crt/.pem to auto-fill"}
                  </button>
                  <input
                    ref={certInputRef}
                    type="file"
                    accept=".cer,.crt,.pem,.der"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleCertUpload(file);
                      e.target.value = "";
                    }}
                  />
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div className="flex flex-col gap-1">
                    <Label htmlFor="crtype-adv">Type</Label>
                    <select id="crtype-adv" className="input text-xs py-1.5" value={certRootType}
                      onChange={(e) => setCertRootType(e.target.value as CertRootType)}>
                      <option value="TBS">TBS (hash)</option>
                      <option value="Wellknown">Wellknown (ID)</option>
                    </select>
                  </div>
                  <div className="flex flex-col gap-1 col-span-2">
                    <Label htmlFor="crval-adv">{certRootType === "TBS" ? "TBS Hash (hex)" : "Wellknown ID"}</Label>
                    <TextInput id="crval-adv" value={certRootValue} onChange={setCertRootValue}
                      placeholder={certRootType === "TBS" ? "Hex-encoded TBS hash" : "e.g. 1"} mono={certRootType === "TBS"} />
                    <FieldError msg={certRootErr ?? tbsHexErr} />
                  </div>
                </div>
              </div>

              <div className="flex flex-col gap-1">
                <Label htmlFor="cpub-adv">CertPublisher — leaf certificate CN</Label>
                <TextInput id="cpub-adv" value={certPublisher} onChange={setCertPublisher}
                  placeholder="e.g. Microsoft Windows" />
              </div>

              <div className="flex flex-col gap-1">
                <Label htmlFor="ciss-adv">CertIssuer — CA name</Label>
                <TextInput id="ciss-adv" value={certIssuer} onChange={setCertIssuer}
                  placeholder="e.g. Microsoft Code Signing PCA 2011" />
              </div>

              <FieldError msg={advancedCertErr} />

              {/* FileAttrib scoping */}
              {existingFileAttribs.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                    FileAttrib Scoping (optional)
                  </p>
                  <div className="space-y-1 max-h-36 overflow-y-auto">
                    {existingFileAttribs.map((fa) => (
                      <label key={fa.id} className={clsx(
                        "flex items-center gap-2 px-3 py-1.5 rounded border cursor-pointer transition-colors text-xs",
                        selectedAttribRefs.has(fa.id)
                          ? "border-accent-blue/40 bg-accent-blue/10"
                          : "border-border hover:border-border-strong"
                      )}>
                        <input type="checkbox" checked={selectedAttribRefs.has(fa.id)}
                          onChange={() => setSelectedAttribRefs((prev) => {
                            const next = new Set(prev);
                            next.has(fa.id) ? next.delete(fa.id) : next.add(fa.id);
                            return next;
                          })} className="accent-accent-blue" />
                        <span className="text-text-primary font-medium">{fa.friendlyName ?? fa.id}</span>
                        <span className="text-text-muted font-mono">{fa.id}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Scenario assignment */}
          <div className="space-y-2">
            <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Signing Scenario Assignment
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
                  onToggle={() => setScenarioChecked((prev) => ({ ...prev, [sv]: !prev[sv] }))}
                  onEffectChange={(e) => setScenarioEffect((prev) => ({ ...prev, [sv]: e }))}
                />
              ))}
            </div>
            <FieldError msg={noScenarioErr} />
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-border flex-shrink-0">
          <button onClick={onClose} className="btn-secondary text-xs">Cancel</button>
          <button onClick={handleSubmit} className="btn-primary text-xs">Add Signer Rule</button>
        </div>
      </div>
    </div>
  );
}
