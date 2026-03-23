/**
 * AppLocker → WDAC Converter Page
 *
 * Converts an AppLocker XML policy (exported via Get-AppLockerPolicy -Xml)
 * into a WDAC/App Control policy file.
 *
 * Matches the WDAC Policy Wizard's AppLocker conversion tool capability.
 *
 * Important notes (displayed to user):
 *  - Converted policies should be merged with a base template before deployment
 *  - Deny rules are skipped by default to prevent lockouts
 *  - Publisher rules use certPublisher only (no TBS hash from AppLocker XML)
 */

import { useState, useRef } from "react";
import {
  ArrowRightLeft,
  Upload,
  Download,
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronUp,
  FileText,
  Loader,
  Info,
} from "lucide-react";
import clsx from "clsx";
import type { ConvertAppLockerResponse } from "@appcontrol/shared";
import { policyApi } from "../lib/api.ts";

function downloadFile(content: string, filename: string) {
  const blob = new Blob([content], { type: "application/xml" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const EXAMPLE_XML = `<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enforced">
    <FilePublisherRule Id="..." Name="Microsoft Office" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION"
          ProductName="*" BinaryName="WINWORD.EXE">
          <BinaryVersionRange LowSection="*" HighSection="*"/>
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
    <FileHashRule Id="..." Name="Custom Tool" Action="Allow">
      <Conditions>
        <FileHashCondition>
          <FileHash Type="SHA256"
            Data="0xABCDEF..." SourceFileName="tool.exe"/>
        </FileHashCondition>
      </Conditions>
    </FileHashRule>
  </RuleCollection>
</AppLockerPolicy>`;

export function AppLockerPage() {
  const [xmlInput, setXmlInput] = useState("");
  const [includeDeny, setIncludeDeny] = useState(false);
  const [result, setResult] = useState<ConvertAppLockerResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showLog, setShowLog] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    const text = await file.text();
    setXmlInput(text);
  }

  async function handleConvert() {
    if (!xmlInput.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await policyApi.convertAppLocker(xmlInput, includeDeny);
      setResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  function handleDownload() {
    if (!result) return;
    const name = (result.policy.friendlyName ?? "converted-applocker-policy")
      .replace(/[^a-z0-9_-]/gi, "_")
      .toLowerCase();
    downloadFile(result.xml, `${name}.xml`);
  }

  const totalConverted = result
    ? result.stats.publisherRules + result.stats.hashRules + result.stats.pathRules + result.stats.packageRules
    : 0;

  return (
    <div className="flex-1 overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <ArrowRightLeft size={20} className="text-accent-blue" />
        <div>
          <h1 className="text-base font-semibold text-text-primary">AppLocker → WDAC Converter</h1>
          <p className="text-xs text-text-muted mt-0.5">
            Convert an AppLocker XML policy to App Control (WDAC) format.
          </p>
        </div>
      </div>

      {/* Guidance */}
      <div className="grid grid-cols-2 gap-3">
        <div className="flex items-start gap-2 text-xs text-text-muted bg-surface-2 border border-border rounded p-3">
          <Info size={13} className="flex-shrink-0 mt-0.5 text-accent-blue" />
          <span>
            Export your AppLocker policy from PowerShell:
            <code className="block mt-1 font-mono text-[10px] bg-surface-3 rounded px-2 py-1">
              Get-AppLockerPolicy -Effective -Xml | Out-File applocker.xml
            </code>
          </span>
        </div>
        <div className="flex items-start gap-2 text-xs text-text-muted bg-amber-950/30 border border-amber-800/40 rounded p-3">
          <AlertTriangle size={13} className="flex-shrink-0 mt-0.5 text-accent-yellow" />
          <span>
            <strong className="text-text-secondary">Before deploying:</strong> Merge the converted policy
            with a base template (Default Windows or Allow Microsoft) to avoid blocking Windows components.
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Left: input */}
        <div className="space-y-4">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            AppLocker XML Input
          </h2>

          {/* Drop zone / file picker */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const file = e.dataTransfer.files[0];
              if (file) handleFile(file);
            }}
            onClick={() => fileInputRef.current?.click()}
            className={clsx(
              "border-2 border-dashed rounded-lg px-4 py-4 text-center cursor-pointer transition-colors",
              dragOver ? "border-accent-blue bg-accent-blue/5" : "border-border hover:border-border-strong"
            )}
          >
            <Upload size={16} className="mx-auto text-text-muted mb-1.5" />
            <p className="text-xs text-text-secondary">Drop applocker.xml or click to browse</p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".xml"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) handleFile(file);
                e.target.value = "";
              }}
            />
          </div>

          {/* Text editor */}
          <textarea
            className="w-full h-64 bg-surface-2 border border-border rounded text-[11px] font-mono text-text-secondary p-3 resize-none focus:outline-none focus:border-accent-blue/60"
            value={xmlInput}
            onChange={(e) => setXmlInput(e.target.value)}
            placeholder={EXAMPLE_XML}
            spellCheck={false}
          />

          {/* Options */}
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={includeDeny}
              onChange={(e) => setIncludeDeny(e.target.checked)}
              className="accent-accent-blue"
            />
            <span className="text-xs text-text-secondary">Include Deny rules</span>
            <span className="text-[10px] text-text-muted">(off by default — deny rules can cause lockouts)</span>
          </label>

          {/* Convert button */}
          <button
            onClick={handleConvert}
            disabled={!xmlInput.trim() || loading}
            className="btn-primary w-full text-xs py-2 disabled:opacity-40 flex items-center justify-center gap-2"
          >
            {loading ? (
              <>
                <Loader size={13} className="animate-spin" />
                Converting…
              </>
            ) : (
              <>
                <ArrowRightLeft size={13} />
                Convert to WDAC
              </>
            )}
          </button>

          {error && (
            <div className="flex items-start gap-2 text-xs text-accent-red bg-accent-red/10 border border-accent-red/30 rounded p-2.5">
              <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Right: result */}
        <div className="space-y-4">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Conversion Result
          </h2>

          {!result && !loading && (
            <div className="border border-border rounded-lg p-8 text-center text-text-muted">
              <FileText size={28} className="mx-auto mb-3 opacity-30" />
              <p className="text-xs">Paste or upload an AppLocker XML policy to convert</p>
            </div>
          )}

          {loading && (
            <div className="border border-border rounded-lg p-8 text-center">
              <Loader size={24} className="mx-auto mb-3 animate-spin text-accent-blue" />
              <p className="text-xs text-text-muted">Converting…</p>
            </div>
          )}

          {result && (
            <div className="space-y-4">
              {/* Success */}
              <div className="flex items-center gap-2 text-xs text-accent-green bg-accent-green/10 border border-accent-green/30 rounded p-2.5">
                <CheckCircle size={13} />
                <span className="font-medium">
                  Converted {totalConverted} rules ({result.stats.skippedRules} skipped)
                </span>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-3 gap-2">
                {[
                  { label: "Publisher", value: result.stats.publisherRules, color: "text-accent-blue" },
                  { label: "Hash", value: result.stats.hashRules, color: "text-accent-green" },
                  { label: "Path", value: result.stats.pathRules, color: "text-accent-yellow" },
                  { label: "Package", value: result.stats.packageRules, color: "text-text-secondary" },
                  { label: "Skipped", value: result.stats.skippedRules, color: "text-text-muted" },
                ].map(({ label, value, color }) => (
                  <div key={label} className="bg-surface-2 rounded border border-border px-2 py-2 text-center">
                    <p className={clsx("text-sm font-bold", color)}>{value}</p>
                    <p className="text-[10px] text-text-muted">{label}</p>
                  </div>
                ))}
              </div>

              {/* Deployment warning */}
              <div className="flex items-start gap-2 text-xs text-amber-400 bg-amber-950/30 border border-amber-800/40 rounded p-2.5">
                <AlertTriangle size={12} className="flex-shrink-0 mt-0.5" />
                <span>
                  This policy is in <strong>Audit Mode</strong>. Merge with a base template
                  (Default Windows / Allow Microsoft) then test before switching to enforcement.
                </span>
              </div>

              {/* Download */}
              <button
                onClick={handleDownload}
                className="btn-primary w-full text-xs py-2 flex items-center justify-center gap-2"
              >
                <Download size={13} />
                Download Converted XML
              </button>

              {/* Log */}
              <div>
                <button
                  onClick={() => setShowLog((v) => !v)}
                  className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text-secondary transition-colors"
                >
                  {showLog ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                  {showLog ? "Hide" : "Show"} conversion log ({result.convertLog.length} entries)
                </button>
                {showLog && (
                  <div className="mt-2 bg-surface-3 rounded border border-border p-3 max-h-60 overflow-y-auto">
                    {result.convertLog.map((line, i) => (
                      <p
                        key={i}
                        className={clsx(
                          "text-[10px] font-mono leading-5",
                          line.includes("⚠") ? "text-accent-yellow" : "text-text-muted"
                        )}
                      >
                        {line}
                      </p>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
