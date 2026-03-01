import { useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { Upload, FileText, Settings, List, Key, RefreshCw, RotateCcw, Code, X } from "lucide-react";
import { v4 as uuidv4 } from "uuid";
import clsx from "clsx";
import { policyApi } from "../lib/api.ts";
import { useAppStore, useActiveSession } from "../store/index.ts";
import { deleteFileRule, deleteSigner } from "../lib/policy-mutations.ts";
import { Header } from "../components/layout/Header.tsx";
import { FileDropZone } from "../components/common/FileDropZone.tsx";
import { EmptyState } from "../components/common/EmptyState.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import { PolicyOverview } from "../components/policy/PolicyOverview.tsx";
import { FileRulesTable } from "../components/policy/FileRulesTable.tsx";
import { SignersTable } from "../components/policy/SignersTable.tsx";
import { PolicyOptionsEditor } from "../components/policy/PolicyOptionsEditor.tsx";
import { AddFileRuleDialog } from "../components/policy/AddFileRuleDialog.tsx";
import { AddSignerDialog } from "../components/policy/AddSignerDialog.tsx";
import type { WdacPolicy, ExplainPolicyResponse } from "@appcontrol/shared";

type TabId = "overview" | "options" | "file-rules" | "signers" | "xml";

const TABS: { id: TabId; label: string; icon: React.ReactNode }[] = [
  { id: "overview", label: "Overview", icon: <FileText size={14} /> },
  { id: "options", label: "Options", icon: <Settings size={14} /> },
  { id: "file-rules", label: "File Rules", icon: <List size={14} /> },
  { id: "signers", label: "Signers", icon: <Key size={14} /> },
  { id: "xml", label: "XML Preview", icon: <Code size={14} /> },
];

export function PolicyEditorPage() {
  const { addSession, updateSessionPolicy } = useAppStore();
  const activeSession = useActiveSession();
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [explanation, setExplanation] = useState<ExplainPolicyResponse | null>(null);
  const [xmlPreview, setXmlPreview] = useState<string | null>(null);
  const [status, setStatus] = useState<{ type: "success" | "error"; message: string } | null>(null);

  // Dialog visibility
  const [showAddFileRule, setShowAddFileRule] = useState(false);
  const [showAddSigner, setShowAddSigner] = useState(false);
  const [showLoadModal, setShowLoadModal] = useState(false);

  // -------------------------------------------------------------------------
  // Parse — adds a new session (stores raw XML for reload capability)
  // -------------------------------------------------------------------------

  const parseMutation = useMutation({
    mutationFn: ({ xml, fileName }: { xml: string; fileName: string }) =>
      policyApi.parse(xml, fileName),
    onSuccess: (data, variables) => {
      const id = uuidv4();
      addSession({
        id,
        fileName: data.policy.sourceFileName,
        policy: data.policy,
        xml: variables.xml,       // store raw XML so Reload can re-parse it
        loadedAt: new Date().toISOString(),
      });
      setStatus({ type: "success", message: `Loaded: ${data.policy.friendlyName ?? data.policy.policyId}` });
      setShowLoadModal(false);
      explainMutation.mutate(data.policy);
    },
    onError: (err) => setStatus({ type: "error", message: (err as Error).message }),
  });

  // -------------------------------------------------------------------------
  // Reload — re-parses the stored XML for the active session, discarding edits
  // -------------------------------------------------------------------------

  const reloadMutation = useMutation({
    mutationFn: () => {
      if (!activeSession?.xml) throw new Error("No stored XML to reload from.");
      return policyApi.parse(activeSession.xml, activeSession.fileName ?? "policy.xml");
    },
    onSuccess: (data) => {
      if (!activeSession) return;
      updateSessionPolicy(activeSession.id, data.policy);
      setXmlPreview(null);
      setStatus({ type: "success", message: "Policy reloaded from original file — all edits discarded." });
      explainMutation.mutate(data.policy);
    },
    onError: (err) => setStatus({ type: "error", message: (err as Error).message }),
  });

  const explainMutation = useMutation({
    mutationFn: (policy: WdacPolicy) => policyApi.explain(policy),
    onSuccess: (data) => setExplanation(data),
  });

  const generateMutation = useMutation({
    mutationFn: (policy: WdacPolicy) => policyApi.generate(policy),
    onSuccess: (data) => {
      setXmlPreview(data.xml);
      setActiveTab("xml");
    },
    onError: (err) => setStatus({ type: "error", message: (err as Error).message }),
  });

  const handleFile = useCallback((content: string, fileName: string) => {
    parseMutation.mutate({ xml: content, fileName });
  }, []);

  const handlePolicyChange = (updated: WdacPolicy) => {
    if (activeSession) updateSessionPolicy(activeSession.id, updated);
  };

  // -------------------------------------------------------------------------
  // File rule handlers
  // -------------------------------------------------------------------------

  const handleDeleteFileRule = (id: string) => {
    if (!activeSession) return;
    // Removes the rule AND scrubs every cross-reference:
    //   signingScenarios[*].fileRuleRefs
    //   signers[*].fileAttribRefs  (when deleted rule is a fileAttrib)
    //   allowedSigners[*].exceptDenyRuleIds
    //   deniedSigners[*].exceptAllowRuleIds
    updateSessionPolicy(activeSession.id, deleteFileRule(activeSession.policy, id));
  };

  const handleAddFileRule = (updated: WdacPolicy) => {
    if (!activeSession) return;
    updateSessionPolicy(activeSession.id, updated);
    setStatus({ type: "success", message: "File rule added." });
  };

  // -------------------------------------------------------------------------
  // Signer handlers
  // -------------------------------------------------------------------------

  const handleDeleteSigner = (id: string) => {
    if (!activeSession) return;
    // Removes the signer AND scrubs every cross-reference:
    //   signingScenarios[*].allowedSigners
    //   signingScenarios[*].deniedSigners
    //   policy.updatePolicySigners
    //   policy.ciSigners
    updateSessionPolicy(activeSession.id, deleteSigner(activeSession.policy, id));
  };

  const handleAddSigner = (updated: WdacPolicy) => {
    if (!activeSession) return;
    updateSessionPolicy(activeSession.id, updated);
    setStatus({ type: "success", message: "Signer added." });
  };

  const isLoading = parseMutation.isPending;

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Policy Editor"
        subtitle="Load, inspect, and modify WDAC policies"
        status={status}
        actions={
          activeSession ? (
            <div className="flex gap-2">
              <button
                className="btn-ghost"
                onClick={() => setShowLoadModal(true)}
                title="Load a different or new policy XML file"
              >
                <Upload size={13} />
                Load Policy
              </button>
              {activeSession.xml && (
                <button
                  className="btn-ghost"
                  onClick={() => reloadMutation.mutate()}
                  disabled={reloadMutation.isPending}
                  title="Re-parse original file — discards all current edits"
                >
                  <RotateCcw size={13} className={reloadMutation.isPending ? "animate-spin" : ""} />
                  Reload File
                </button>
              )}
              <button
                className="btn-ghost"
                onClick={() => explainMutation.mutate(activeSession.policy)}
                disabled={explainMutation.isPending}
              >
                <RefreshCw size={13} className={explainMutation.isPending ? "animate-spin" : ""} />
                Analyze
              </button>
              <button
                className="btn-primary"
                onClick={() => generateMutation.mutate(activeSession.policy)}
                disabled={generateMutation.isPending}
              >
                <Code size={13} />
                Generate XML
              </button>
            </div>
          ) : null
        }
      />

      {!activeSession ? (
        <div className="flex-1 flex items-center justify-center p-8">
          {isLoading ? (
            <LoadingSpinner size="lg" label="Parsing policy XML..." />
          ) : (
            <div className="w-full max-w-lg">
              <EmptyState
                icon={<Upload size={40} />}
                title="No policy loaded"
                description="Drop a WDAC policy XML file to begin inspecting and editing it."
              />
              <FileDropZone
                accept=".xml"
                label="Drop WDAC Policy XML"
                description=".xml files exported from New-CIPolicy or PolicyStore"
                onFile={handleFile}
                className="mt-6"
              />
              {parseMutation.isError && (
                <div className="mt-4 p-3 bg-accent-red-dim/30 border border-accent-red/20 rounded text-xs text-accent-red">
                  {(parseMutation.error as Error).message}
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="flex-1 flex flex-col min-h-0">
          {/* Tab bar */}
          <div className="flex border-b border-border px-6 gap-1 flex-shrink-0">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  "flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium border-b-2 -mb-px transition-colors",
                  activeTab === tab.id
                    ? "border-accent-blue text-text-primary"
                    : "border-transparent text-text-muted hover:text-text-secondary"
                )}
              >
                {tab.icon}
                {tab.label}
                {tab.id === "file-rules" && (
                  <span className="ml-1 px-1 rounded bg-surface-3 text-text-muted text-xs">
                    {activeSession.policy.fileRules.filter((r) => r.kind !== "fileAttrib").length}
                  </span>
                )}
                {tab.id === "signers" && (
                  <span className="ml-1 px-1 rounded bg-surface-3 text-text-muted text-xs">
                    {activeSession.policy.signers.length}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="flex-1 overflow-auto p-6">
            {activeTab === "overview" && (
              <PolicyOverview policy={activeSession.policy} explanation={explanation} />
            )}

            {activeTab === "options" && (
              <PolicyOptionsEditor
                policy={activeSession.policy}
                onChange={handlePolicyChange}
              />
            )}

            {activeTab === "file-rules" && (
              <FileRulesTable
                rules={activeSession.policy.fileRules}
                editable
                onDelete={handleDeleteFileRule}
                onAdd={() => setShowAddFileRule(true)}
              />
            )}

            {activeTab === "signers" && (
              <SignersTable
                signers={activeSession.policy.signers}
                editable
                onDelete={handleDeleteSigner}
                onAdd={() => setShowAddSigner(true)}
              />
            )}

            {activeTab === "xml" && (
              <div className="h-full">
                {generateMutation.isPending ? (
                  <LoadingSpinner label="Generating XML..." />
                ) : xmlPreview ? (
                  <div>
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs text-text-muted">
                        {Math.round(xmlPreview.length / 1024)} KB
                      </span>
                      <button
                        className="btn-secondary"
                        onClick={() => {
                          const blob = new Blob([xmlPreview], { type: "text/xml" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `${activeSession.policy.friendlyName ?? "policy"}.xml`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                      >
                        Download XML
                      </button>
                    </div>
                    <pre className="mono text-xs bg-surface-2 p-4 rounded border border-border overflow-auto max-h-[calc(100vh-300px)] text-text-secondary leading-relaxed whitespace-pre">
                      {xmlPreview}
                    </pre>
                  </div>
                ) : (
                  <EmptyState
                    icon={<Code size={32} />}
                    title="No XML generated yet"
                    description="Click Generate XML to produce deployable policy XML"
                    action={
                      <button
                        className="btn-primary"
                        onClick={() => generateMutation.mutate(activeSession.policy)}
                      >
                        Generate XML
                      </button>
                    }
                  />
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Load Policy modal                                                   */}
      {/* ------------------------------------------------------------------ */}
      {showLoadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
          <div className="bg-surface-1 border border-border rounded-lg w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div>
                <h2 className="text-sm font-semibold text-text-primary">Load Policy</h2>
                <p className="text-xs text-text-muted mt-0.5">
                  Loads a new policy as an additional session — use the sidebar to switch between loaded policies.
                </p>
              </div>
              <button
                onClick={() => setShowLoadModal(false)}
                className="text-text-muted hover:text-text-primary transition-colors ml-4 flex-shrink-0"
              >
                <X size={16} />
              </button>
            </div>

            <div className="p-5">
              {parseMutation.isPending ? (
                <LoadingSpinner label="Parsing policy XML..." />
              ) : (
                <FileDropZone
                  accept=".xml"
                  label="Drop WDAC Policy XML"
                  description=".xml files from New-CIPolicy, PolicyStore, or this editor"
                  onFile={handleFile}
                />
              )}
              {parseMutation.isError && (
                <div className="mt-3 p-3 bg-accent-red/10 border border-accent-red/20 rounded text-xs text-accent-red">
                  {(parseMutation.error as Error).message}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Add File Rule dialog */}
      {showAddFileRule && activeSession && (
        <AddFileRuleDialog
          policy={activeSession.policy}
          onCommit={handleAddFileRule}
          onClose={() => setShowAddFileRule(false)}
        />
      )}

      {/* Add Signer dialog */}
      {showAddSigner && activeSession && (
        <AddSignerDialog
          policy={activeSession.policy}
          onCommit={handleAddSigner}
          onClose={() => setShowAddSigner(false)}
        />
      )}
    </div>
  );
}
