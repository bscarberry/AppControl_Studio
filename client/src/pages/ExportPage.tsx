import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Download, Code, Info } from "lucide-react";
import { policyApi } from "../lib/api.ts";
import { useActiveSession } from "../store/index.ts";
import clsx from "clsx";
import { Header } from "../components/layout/Header.tsx";
import { EmptyState } from "../components/common/EmptyState.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import { useNavigate } from "react-router-dom";

export function ExportPage() {
  const activeSession = useActiveSession();
  const navigate = useNavigate();
  const [xmlOutput, setXmlOutput] = useState<string | null>(null);

  const generateMutation = useMutation({
    mutationFn: () => policyApi.generate(activeSession!.policy),
    onSuccess: (data) => setXmlOutput(data.xml),
  });

  if (!activeSession) {
    return (
      <div className="flex flex-col h-full">
        <Header title="Export Policy" subtitle="Download deployable WDAC policy XML" />
        <div className="flex-1 flex items-center justify-center">
          <EmptyState
            icon={<Download size={40} />}
            title="No policy loaded"
            description="Load or build a policy first, then come here to export it."
            action={
              <button className="btn-primary" onClick={() => navigate("/")}>
                Go to Editor
              </button>
            }
          />
        </div>
      </div>
    );
  }

  const { policy } = activeSession;

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Export Policy"
        subtitle={`Exporting: ${policy.friendlyName ?? policy.policyId}`}
        actions={
          xmlOutput ? (
            <button
              className="btn-primary"
              onClick={() => {
                const blob = new Blob([xmlOutput], { type: "text/xml" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `${policy.friendlyName ?? "policy"}.xml`;
                a.click();
                URL.revokeObjectURL(url);
              }}
            >
              <Download size={13} />
              Download XML
            </button>
          ) : (
            <button
              className="btn-primary"
              onClick={() => generateMutation.mutate()}
              disabled={generateMutation.isPending}
            >
              <Code size={13} />
              Generate XML
            </button>
          )
        }
      />

      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-3xl space-y-4">
          {/* Deployment guide */}
          <div className="card p-4">
            <h2 className="section-header">Deployment Instructions</h2>
            <div className="space-y-3">
              <Step
                num={1}
                title="Convert to binary format"
                code={`ConvertFrom-CIPolicy -XmlFilePath "policy.xml" -BinaryFilePath "policy.p7b"`}
              />
              <Step
                num={2}
                title="Test in Audit Mode first"
                description="Ensure the policy contains Option 3 (Enabled:Audit Mode) for initial testing. Monitor CodeIntegrity operational log (EventID 3076/3077) for blocked items."
              />
              <Step
                num={3}
                title="Deploy via Intune or MDM"
                code={`# Deploy via CiTool (Windows 11 22H2+)\nCiTool --update-policy "policy.p7b"\n\n# Or deploy via Intune:\n# App Control for Business > Create Policy > Upload binary`}
              />
              <Step
                num={4}
                title="Verify deployment"
                code={`# Check active policies\nCiTool --list-policies\n\n# Monitor events\nGet-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" | Where-Object { $_.Id -in @(3076,3099) }`}
              />
              <Step
                num={5}
                title="Switch to Enforcement Mode"
                description="After confirming no legitimate software is blocked, remove Option 3 (Audit Mode), regenerate the binary, and redeploy."
              />
            </div>
          </div>

          {/* Security checklist */}
          <div className="card p-4">
            <h2 className="section-header">Pre-Deployment Security Checklist</h2>
            <div className="space-y-2">
              {[
                { check: "Policy has been tested in audit mode for at least 2 weeks", risk: false },
                { check: "Option 3 (Audit Mode) is REMOVED before production deployment", risk: true },
                { check: "Option 7 (Debug Policy Augmented) is NOT enabled", risk: true },
                { check: "Option 9 (Advanced Boot Options Menu) is NOT enabled in high-security environments", risk: true },
                { check: "Policy is signed (prevents unauthorized modification)", risk: false },
                { check: "HVCI (Hypervisor-Protected Code Integrity) is configured if supported", risk: false },
                { check: "Policy covers both Kernel (131) and User Mode (12) scenarios", risk: false },
                { check: "Option 0 (UMCI) is enabled for full user-mode protection", risk: true },
                { check: "Supplemental policies are scoped with Allow Supplemental Policies (Option 17)", risk: false },
              ].map((item, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <div className="w-4 h-4 border border-border rounded flex-shrink-0 mt-0.5" />
                  <span className={item.risk ? "text-accent-yellow" : "text-text-secondary"}>
                    {item.risk && <Info size={11} className="inline mr-1" />}
                    {item.check}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* XML output */}
          {generateMutation.isPending && (
            <div className="flex justify-center py-8">
              <LoadingSpinner label="Generating XML..." />
            </div>
          )}

          {generateMutation.isError && (
            <div className="p-4 bg-accent-red-dim/30 border border-accent-red/20 rounded text-sm text-accent-red">
              {(generateMutation.error as Error).message}
            </div>
          )}

          {xmlOutput && (
            <div className="card p-4">
              <div className="flex items-center justify-between mb-3">
                <h2 className="section-header mb-0">Generated XML</h2>
                <span className="text-xs text-text-muted">{Math.round(xmlOutput.length / 1024)} KB</span>
              </div>
              <pre className="mono text-xs bg-surface-2 p-4 rounded border border-border overflow-auto max-h-96 text-text-secondary leading-relaxed whitespace-pre">
                {xmlOutput}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Step({
  num,
  title,
  description,
  code,
}: {
  num: number;
  title: string;
  description?: string;
  code?: string;
}) {
  return (
    <div className="flex gap-3">
      <div className="w-5 h-5 rounded-full bg-accent-blue-dim flex items-center justify-center flex-shrink-0 mt-0.5">
        <span className="text-xs font-bold text-accent-blue">{num}</span>
      </div>
      <div className="flex-1">
        <p className="text-xs font-medium text-text-secondary mb-1">{title}</p>
        {description && <p className="text-xs text-text-muted mb-1.5">{description}</p>}
        {code && (
          <pre className="mono text-xs bg-surface-2 p-2.5 rounded border border-border text-accent-blue overflow-auto">
            {code}
          </pre>
        )}
      </div>
    </div>
  );
}

