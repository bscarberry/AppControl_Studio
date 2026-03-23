/**
 * Add File Rule Dialog
 *
 * Allows the user to create a new WDAC file rule (Allow/Deny hash, path, or
 * attribute rule, or a FileAttrib signer-scoping descriptor) and assign it
 * to one or more signing scenarios.
 *
 * Supported rule kinds (per Microsoft cipolicy.xsd):
 *   hash      — matched by SHA-256 / SHA-1 / SHA256Flat / SHA1Page
 *   path      — matched by file-path pattern with optional version bounds
 *   attribute — Allow/Deny by PE version resource attributes only
 *   fileAttrib — signer-scoping descriptor (no independent Allow/Deny effect)
 *
 * Reference:
 *   https://learn.microsoft.com/en-us/windows/security/application-security/
 *   application-control/app-control-for-business/design/select-types-of-rules-to-create
 */

import { useState } from "react";
import { X, AlertTriangle } from "lucide-react";
import clsx from "clsx";
import type {
  WdacPolicy,
  FileRuleEffect,
  HashType,
  SigningScenarioValue,
} from "@appcontrol/shared";
import { addFileRule, type WdacFileRuleNoId } from "../../lib/policy-mutations.ts";

type RuleKind = "hash" | "path" | "attribute" | "fileAttrib";

interface Props {
  policy: WdacPolicy;
  onCommit: (updated: WdacPolicy) => void;
  onClose: () => void;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function validateHashValue(value: string, type: HashType): string | null {
  const hex = value.trim();
  if (!hex) return "Hash value is required.";
  if (!/^[0-9a-fA-F]+$/.test(hex)) return "Hash must be a hexadecimal string.";
  const isSha256 = type === "SHA256" || type === "SHA256Flat";
  const expected = isSha256 ? 64 : 40;
  if (hex.length !== expected)
    return `${type} hash must be exactly ${expected} hex characters (got ${hex.length}).`;
  return null;
}

function validateVersion(v: string): string | null {
  if (!v) return null; // optional
  if (!/^\d+(\.\d+){0,3}$/.test(v))
    return "Version must be in major.minor.patch.build format (e.g. 10.0.22621.1).";
  return null;
}

// ---------------------------------------------------------------------------
// Small form helpers
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

function Select<T extends string>({
  id,
  value,
  options,
  onChange,
}: {
  id: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <select
      id={id}
      className="input text-xs py-1.5"
      value={value}
      onChange={(e) => onChange(e.target.value as T)}
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

// ---------------------------------------------------------------------------
// Main dialog
// ---------------------------------------------------------------------------

export function AddFileRuleDialog({ policy, onCommit, onClose }: Props) {
  // ---- kind + effect ----
  const [kind, setKind] = useState<RuleKind>("hash");
  const [effect, setEffect] = useState<FileRuleEffect>("Allow");
  const [friendlyName, setFriendlyName] = useState("");

  // ---- hash fields ----
  const [hashType, setHashType] = useState<HashType>("SHA256");
  const [hashValue, setHashValue] = useState("");
  const [hashFileName, setHashFileName] = useState("");

  // ---- path fields ----
  const [filePath, setFilePath] = useState("");
  const [isFolder, setIsFolder] = useState(false);
  const [pathMinVer, setPathMinVer] = useState("");
  const [pathMaxVer, setPathMaxVer] = useState("");

  // ---- attribute / fileAttrib fields ----
  const [attrFileName, setAttrFileName] = useState("");
  const [attrInternalName, setAttrInternalName] = useState("");
  const [attrProductName, setAttrProductName] = useState("");
  const [attrMinVer, setAttrMinVer] = useState("");
  const [attrMaxVer, setAttrMaxVer] = useState("");

  // ---- scenario assignment ----
  const scenariosPresent = policy.signingScenarios.map((sc) => sc.value);
  // Default: select all present scenarios; always offer both
  const allScenarioValues: SigningScenarioValue[] = [12, 131];
  const [selectedScenarios, setSelectedScenarios] = useState<
    Set<SigningScenarioValue>
  >(new Set(scenariosPresent));

  // ---- validation errors ----
  const [submitAttempted, setSubmitAttempted] = useState(false);

  function toggleScenario(v: SigningScenarioValue) {
    setSelectedScenarios((prev) => {
      const next = new Set(prev);
      next.has(v) ? next.delete(v) : next.add(v);
      return next;
    });
  }

  // ---- per-field errors (computed, not stored) ----
  const hashErr = submitAttempted && kind === "hash" ? validateHashValue(hashValue, hashType) : null;
  const pathErr =
    submitAttempted && kind === "path" && !filePath.trim()
      ? "File path is required."
      : null;
  const pathMinVerErr = submitAttempted ? validateVersion(pathMinVer) : null;
  const pathMaxVerErr = submitAttempted ? validateVersion(pathMaxVer) : null;
  const attrMinVerErr = submitAttempted ? validateVersion(attrMinVer) : null;
  const attrMaxVerErr = submitAttempted ? validateVersion(attrMaxVer) : null;
  const attrEmptyErr =
    submitAttempted &&
    (kind === "attribute" || kind === "fileAttrib") &&
    !attrFileName.trim() &&
    !attrInternalName.trim() &&
    !attrProductName.trim()
      ? "At least one attribute (OriginalFileName, InternalName, or ProductName) is required."
      : null;
  const scenarioErr =
    submitAttempted && selectedScenarios.size === 0 && kind !== "fileAttrib"
      ? "Select at least one signing scenario."
      : null;

  function isValid(): boolean {
    if (kind === "hash") return validateHashValue(hashValue, hashType) === null;
    if (kind === "path")
      return (
        !!filePath.trim() &&
        validateVersion(pathMinVer) === null &&
        validateVersion(pathMaxVer) === null
      );
    if (kind === "attribute" || kind === "fileAttrib")
      return (
        (!!attrFileName.trim() ||
          !!attrInternalName.trim() ||
          !!attrProductName.trim()) &&
        validateVersion(attrMinVer) === null &&
        validateVersion(attrMaxVer) === null
      );
    return false;
  }

  function buildRule(): WdacFileRuleNoId {
    const base = { friendlyName: friendlyName.trim() || undefined };

    if (kind === "hash") {
      return {
        ...base,
        kind: "hash",
        effect,
        hash: hashValue.trim(),
        hashType,
        fileName: hashFileName.trim() || undefined,
      };
    }
    if (kind === "path") {
      // Auto-append \* for folder rules if the path doesn't already end with a wildcard
      let resolvedPath = filePath.trim();
      if (isFolder && !resolvedPath.endsWith("*")) {
        resolvedPath = resolvedPath.replace(/\\$/, "") + "\\*";
      }
      return {
        ...base,
        kind: "path",
        effect,
        filePath: resolvedPath,
        isFolder,
        minimumFileVersion: pathMinVer.trim() || undefined,
        maximumFileVersion: pathMaxVer.trim() || undefined,
      };
    }
    if (kind === "attribute") {
      return {
        ...base,
        kind: "attribute",
        effect,
        fileName: attrFileName.trim() || undefined,
        internalName: attrInternalName.trim() || undefined,
        productName: attrProductName.trim() || undefined,
        minimumFileVersion: attrMinVer.trim() || undefined,
        maximumFileVersion: attrMaxVer.trim() || undefined,
      };
    }
    // fileAttrib — no effect field
    return {
      ...base,
      kind: "fileAttrib",
      fileName: attrFileName.trim() || undefined,
      internalName: attrInternalName.trim() || undefined,
      productName: attrProductName.trim() || undefined,
      minimumFileVersion: attrMinVer.trim() || undefined,
      maximumFileVersion: attrMaxVer.trim() || undefined,
    };
  }

  function handleSubmit() {
    setSubmitAttempted(true);
    if (!isValid()) return;
    if (kind !== "fileAttrib" && selectedScenarios.size === 0) return;

    const rule = buildRule();
    const updated = addFileRule(policy, {
      rule,
      scenarioValues: kind === "fileAttrib" ? [] : [...selectedScenarios],
    });
    onCommit(updated);
    onClose();
  }

  const kindOptions: { value: RuleKind; label: string; desc: string }[] = [
    { value: "hash", label: "Hash", desc: "Match by SHA-256, SHA-1, or flat/page variant" },
    { value: "path", label: "Path", desc: "Match by file-path pattern (supports wildcards and WDAC macros)" },
    { value: "attribute", label: "Attribute", desc: "Match by PE version resource fields only" },
    {
      value: "fileAttrib",
      label: "FileAttrib",
      desc: "Signer-scoping descriptor — restricts a signer rule to matching files (no direct Allow/Deny effect)",
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
      <div className="bg-surface-1 border border-border rounded-lg w-full max-w-xl shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border flex-shrink-0">
          <h2 className="text-sm font-semibold text-text-primary">Add File Rule</h2>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto flex-1 px-5 py-4 space-y-5">

          {/* Kind selector */}
          <div className="space-y-1.5">
            <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">Rule Kind</p>
            <div className="grid grid-cols-2 gap-2">
              {kindOptions.map((o) => (
                <button
                  key={o.value}
                  type="button"
                  onClick={() => setKind(o.value)}
                  className={clsx(
                    "text-left p-3 rounded border transition-colors",
                    kind === o.value
                      ? "border-accent-blue bg-accent-blue/10"
                      : "border-border hover:border-border-strong hover:bg-surface-2"
                  )}
                >
                  <p className={clsx("text-xs font-medium", kind === o.value ? "text-accent-blue" : "text-text-primary")}>
                    {o.label}
                  </p>
                  <p className="text-xs text-text-muted mt-0.5 leading-snug">{o.desc}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Effect (hidden for fileAttrib) */}
          {kind !== "fileAttrib" && (
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col gap-1">
                <Label htmlFor="effect">Effect</Label>
                <Select<FileRuleEffect>
                  id="effect"
                  value={effect}
                  onChange={setEffect}
                  options={[
                    { value: "Allow", label: "Allow" },
                    { value: "Deny", label: "Deny" },
                  ]}
                />
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="fn">Friendly Name (optional)</Label>
                <TextInput
                  id="fn"
                  value={friendlyName}
                  onChange={setFriendlyName}
                  placeholder="Descriptive label"
                />
              </div>
            </div>
          )}

          {kind === "fileAttrib" && (
            <div className="flex flex-col gap-1">
              <Label htmlFor="fn-fa">Friendly Name (optional)</Label>
              <TextInput
                id="fn-fa"
                value={friendlyName}
                onChange={setFriendlyName}
                placeholder="Descriptive label"
              />
            </div>
          )}

          {/* ---- Kind-specific fields ---- */}

          {/* Hash */}
          {kind === "hash" && (
            <div className="space-y-3">
              <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Hash Details</p>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <Label htmlFor="hashtype">Hash Type</Label>
                  <Select<HashType>
                    id="hashtype"
                    value={hashType}
                    onChange={setHashType}
                    options={[
                      { value: "SHA256", label: "SHA-256" },
                      { value: "SHA1", label: "SHA-1" },
                      { value: "SHA256Flat", label: "SHA-256 Flat" },
                      { value: "SHA1Page", label: "SHA-1 Page" },
                    ]}
                  />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="hashfn">File Name (optional)</Label>
                  <TextInput
                    id="hashfn"
                    value={hashFileName}
                    onChange={setHashFileName}
                    placeholder="e.g. notepad.exe"
                  />
                </div>
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="hashval">
                  Hash Value{" "}
                  <span className="text-text-muted font-normal">
                    ({hashType === "SHA256" || hashType === "SHA256Flat" ? "64" : "40"} hex chars)
                  </span>
                </Label>
                <TextInput
                  id="hashval"
                  value={hashValue}
                  onChange={setHashValue}
                  placeholder={
                    hashType === "SHA256" || hashType === "SHA256Flat"
                      ? "64-character hex string"
                      : "40-character hex string"
                  }
                  mono
                  required
                />
                <FieldError msg={hashErr} />
              </div>
            </div>
          )}

          {/* Path */}
          {kind === "path" && (
            <div className="space-y-3">
              <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Path Details</p>

              {/* File vs Folder toggle */}
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setIsFolder(false)}
                  className={clsx(
                    "flex-1 px-3 py-2 text-xs rounded border transition-all text-center",
                    !isFolder ? "border-accent-blue bg-accent-blue/15 text-text-primary font-semibold" : "border-border text-text-muted hover:border-border-strong"
                  )}
                >
                  File Path
                  <div className="mt-0.5 text-[10px] opacity-70">Single file or pattern</div>
                </button>
                <button
                  type="button"
                  onClick={() => setIsFolder(true)}
                  className={clsx(
                    "flex-1 px-3 py-2 text-xs rounded border transition-all text-center",
                    isFolder ? "border-accent-blue bg-accent-blue/15 text-text-primary font-semibold" : "border-border text-text-muted hover:border-border-strong"
                  )}
                >
                  Folder Path
                  <div className="mt-0.5 text-[10px] opacity-70">Directory + subdirectories</div>
                </button>
              </div>

              <div className="flex flex-col gap-1">
                <Label htmlFor="fp">{isFolder ? "Folder Path" : "File Path"}</Label>
                <TextInput
                  id="fp"
                  value={filePath}
                  onChange={setFilePath}
                  placeholder={isFolder ? "%PROGRAMFILES%\\MyApp" : "%WINDIR%\\System32\\tool.exe"}
                  required
                />
                <p className="text-xs text-text-muted">
                  {isFolder
                    ? "Enter the directory path. A \\* wildcard will be appended automatically to cover all files in the folder and subfolders."
                    : "Supports WDAC macros (%WINDIR%, %OSDRIVE%, %PROGRAMFILES%, etc.) and wildcards (* = any sequence, ? = any single character)."}
                </p>
                <FieldError msg={pathErr} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <Label htmlFor="pminv">Min File Version (optional)</Label>
                  <TextInput
                    id="pminv"
                    value={pathMinVer}
                    onChange={setPathMinVer}
                    placeholder="10.0.0.0"
                  />
                  <FieldError msg={pathMinVerErr} />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="pmaxv">Max File Version (optional)</Label>
                  <TextInput
                    id="pmaxv"
                    value={pathMaxVer}
                    onChange={setPathMaxVer}
                    placeholder="10.0.99999.9999"
                  />
                  <FieldError msg={pathMaxVerErr} />
                </div>
              </div>
            </div>
          )}

          {/* Attribute / FileAttrib */}
          {(kind === "attribute" || kind === "fileAttrib") && (
            <div className="space-y-3">
              <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                {kind === "fileAttrib" ? "FileAttrib Attributes" : "PE Attribute Details"}
              </p>
              {kind === "fileAttrib" && (
                <div className="text-xs text-text-muted bg-surface-2 rounded p-2.5 border border-border leading-relaxed">
                  A FileAttrib rule scopes a signer rule to only match files whose version-resource attributes match.
                  It has no independent Allow/Deny effect — it only applies when referenced by a signer rule's fileAttribRefs.
                </div>
              )}
              <p className="text-xs text-text-muted">At least one attribute is required. Matching uses exact, case-insensitive comparison.</p>
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <Label htmlFor="afn">OriginalFileName</Label>
                  <TextInput id="afn" value={attrFileName} onChange={setAttrFileName} placeholder="e.g. ntdll.dll" />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="ain">InternalName</Label>
                  <TextInput id="ain" value={attrInternalName} onChange={setAttrInternalName} placeholder="e.g. ntdll.dll" />
                </div>
              </div>
              <div className="flex flex-col gap-1">
                <Label htmlFor="apn">ProductName</Label>
                <TextInput
                  id="apn"
                  value={attrProductName}
                  onChange={setAttrProductName}
                  placeholder="e.g. Microsoft® Windows® Operating System"
                />
              </div>
              <FieldError msg={attrEmptyErr} />
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <Label htmlFor="aminv">Min File Version (optional)</Label>
                  <TextInput id="aminv" value={attrMinVer} onChange={setAttrMinVer} placeholder="10.0.0.0" />
                  <FieldError msg={attrMinVerErr} />
                </div>
                <div className="flex flex-col gap-1">
                  <Label htmlFor="amaxv">Max File Version (optional)</Label>
                  <TextInput id="amaxv" value={attrMaxVer} onChange={setAttrMaxVer} placeholder="10.0.99999.9999" />
                  <FieldError msg={attrMaxVerErr} />
                </div>
              </div>
            </div>
          )}

          {/* Signing scenario assignment (not for fileAttrib) */}
          {kind !== "fileAttrib" && (
            <div className="space-y-2">
              <p className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                Add to Signing Scenarios
              </p>
              <p className="text-xs text-text-muted">
                The rule ID will be added to the selected scenario's FileRuleRefs.
              </p>
              <div className="flex gap-3">
                {allScenarioValues.map((sv) => {
                  const present = scenariosPresent.includes(sv);
                  return (
                    <label
                      key={sv}
                      className={clsx(
                        "flex items-center gap-2 cursor-pointer px-3 py-2 rounded border transition-colors flex-1",
                        selectedScenarios.has(sv)
                          ? "border-accent-blue bg-accent-blue/10"
                          : "border-border hover:border-border-strong"
                      )}
                    >
                      <input
                        type="checkbox"
                        checked={selectedScenarios.has(sv)}
                        onChange={() => toggleScenario(sv)}
                        className="accent-accent-blue"
                      />
                      <span className="text-xs text-text-primary">
                        {sv === 131 ? "Kernel Mode (131)" : "User Mode (12)"}
                      </span>
                      {!present && (
                        <span className="text-xs text-text-muted">(will be created)</span>
                      )}
                    </label>
                  );
                })}
              </div>
              <FieldError msg={scenarioErr} />
            </div>
          )}

          {kind === "fileAttrib" && (
            <div className="flex items-start gap-2 text-xs text-text-muted p-2.5 bg-surface-2 rounded border border-border">
              <AlertTriangle size={12} className="flex-shrink-0 mt-0.5 text-accent-yellow" />
              FileAttrib rules are added to the policy's FileRules pool but are not directly listed in scenario
              FileRuleRefs. They take effect only when referenced via a signer rule's fileAttribRefs.
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-5 py-4 border-t border-border flex-shrink-0">
          <button onClick={onClose} className="btn-secondary text-xs">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            className="btn-primary text-xs"
          >
            Add Rule
          </button>
        </div>
      </div>
    </div>
  );
}
