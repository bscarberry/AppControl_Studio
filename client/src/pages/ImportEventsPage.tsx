import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Upload, AlertCircle, CheckCircle, Clock, Shield, ShieldAlert } from "lucide-react";
import clsx from "clsx";
import { eventsApi } from "../lib/api.ts";
import { useAppStore } from "../store/index.ts";
import { Header } from "../components/layout/Header.tsx";
import { FileDropZone } from "../components/common/FileDropZone.tsx";
import { LoadingSpinner } from "../components/common/LoadingSpinner.tsx";
import type { ParsedCiEvent, EventImportResult } from "@appcontrol/shared";

type ImportFormat = "evtx-json" | "json" | "csv" | "hunting-json" | "hunting-csv";

interface FormatOption {
  id: ImportFormat;
  label: string;
  description: string;
  accept: string;
}

const FORMAT_OPTIONS: FormatOption[] = [
  {
    id: "evtx-json",
    label: "EVTX JSON Export",
    description: "Get-WinEvent ... | ConvertTo-Json",
    accept: ".json",
  },
  {
    id: "hunting-json",
    label: "Advanced Hunting JSON",
    description: "MDE Advanced Hunting query export (JSON)",
    accept: ".json",
  },
  {
    id: "hunting-csv",
    label: "Advanced Hunting CSV",
    description: "MDE Advanced Hunting query export (CSV)",
    accept: ".csv",
  },
];

export function ImportEventsPage() {
  const { setImportedEvents, importedEvents, clearEvents } = useAppStore();
  const [format, setFormat] = useState<ImportFormat>("evtx-json");
  const [result, setResult] = useState<EventImportResult | null>(null);

  const parseMutation = useMutation({
    mutationFn: ({ content, format }: { content: string; format: ImportFormat }) => {
      if (format === "hunting-json") return eventsApi.parseHunting(content, "json");
      if (format === "hunting-csv") return eventsApi.parseHunting(content, "csv");
      return eventsApi.parse(content, format as "evtx-json" | "json" | "csv");
    },
    onSuccess: (data) => {
      setResult(data);
      setImportedEvents(data.events);
    },
  });

  const selectedFormat = FORMAT_OPTIONS.find((f) => f.id === format)!;

  return (
    <div className="flex flex-col h-full">
      <Header
        title="Import Events"
        subtitle="Parse CodeIntegrity event logs and Advanced Hunting results"
        actions={
          importedEvents.length > 0 ? (
            <div className="flex items-center gap-3">
              <span className="text-xs text-text-muted">{importedEvents.length} events loaded</span>
              <button className="btn-ghost" onClick={() => { clearEvents(); setResult(null); }}>
                Clear
              </button>
            </div>
          ) : null
        }
      />

      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-3xl">
          {/* Format selector */}
          <div className="card p-4 mb-5">
            <h2 className="section-header">Input Format</h2>
            <div className="grid grid-cols-3 gap-2">
              {FORMAT_OPTIONS.map((opt) => (
                <button
                  key={opt.id}
                  onClick={() => setFormat(opt.id)}
                  className={clsx(
                    "text-left p-3 rounded border text-xs transition-colors",
                    format === opt.id
                      ? "border-accent-blue bg-accent-blue-dim/20 text-text-primary"
                      : "border-border text-text-muted hover:border-border-strong hover:text-text-secondary"
                  )}
                >
                  <p className="font-medium text-sm mb-0.5">{opt.label}</p>
                  <p className="text-text-muted">{opt.description}</p>
                </button>
              ))}
            </div>
          </div>

          {/* Collection instructions */}
          <CollectionInstructions format={format} />

          {/* File upload */}
          <div className="mb-5">
            <FileDropZone
              accept={selectedFormat.accept}
              label={`Drop ${selectedFormat.label}`}
              description={selectedFormat.description}
              onFile={(content) => parseMutation.mutate({ content, format })}
            />
          </div>

          {parseMutation.isPending && (
            <div className="flex justify-center py-8">
              <LoadingSpinner label="Parsing events..." />
            </div>
          )}

          {parseMutation.isError && (
            <div className="p-4 bg-accent-red-dim/30 border border-accent-red/20 rounded text-sm text-accent-red mb-4">
              {(parseMutation.error as Error).message}
            </div>
          )}

          {result && (
            <EventImportResults result={result} />
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Collection instructions
// ---------------------------------------------------------------------------

function CollectionInstructions({ format }: { format: ImportFormat }) {
  const commands: Record<ImportFormat, { title: string; code: string }> = {
    "evtx-json": {
      title: "Collect CodeIntegrity Events (PowerShell)",
      code: `Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" \`
  | Where-Object { $_.Id -in @(3076,3077,3033,3034,3089,3097,3098) } \`
  | ConvertTo-Json -Depth 5 \`
  | Out-File -FilePath ".\\ci-events.json" -Encoding utf8`,
    },
    json: {
      title: "Collect Events (JSON format)",
      code: `Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" | ConvertTo-Json`,
    },
    csv: {
      title: "Advanced Hunting Query (Kusto)",
      code: `DeviceEvents
| where ActionType in ("AppControlCodeIntegrityPolicyAudited", "AppControlCodeIntegrityPolicyBlocked")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, AdditionalFields
| export to csv`,
    },
    "hunting-json": {
      title: "Advanced Hunting Query (MDE Portal)",
      code: `DeviceEvents
| where ActionType in ("AppControlCodeIntegrityPolicyAudited", "AppControlCodeIntegrityPolicyBlocked",
    "AppControlCIScriptAudited", "AppControlCIScriptBlocked")
| extend Fields = parse_json(AdditionalFields)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath,
    SHA256, SHA1, InitiatingProcessFileName,
    PolicyName = tostring(Fields.PolicyName),
    PolicyGuid = tostring(Fields.PolicyGuid),
    OriginalFileName = tostring(Fields.OriginalFileName),
    ProductName = tostring(Fields.ProductName)
| order by Timestamp desc`,
    },
    "hunting-csv": {
      title: "Export Hunting Results as CSV",
      code: `// Run the query above in Microsoft Defender portal > Hunting > Advanced Hunting
// Click Export > Download as CSV`,
    },
  };

  const { title, code } = commands[format];

  return (
    <div className="card p-4 mb-5">
      <h2 className="section-header">Collection Instructions</h2>
      <p className="text-xs font-medium text-text-secondary mb-2">{title}</p>
      <pre className="mono text-xs bg-surface-2 p-3 rounded border border-border text-accent-blue overflow-auto">
        {code}
      </pre>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Import results
// ---------------------------------------------------------------------------

function EventImportResults({ result }: { result: EventImportResult }) {
  const { summary, events, parseErrors } = result;

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="card p-4">
        <h2 className="section-header">Import Summary</h2>
        <div className="grid grid-cols-4 gap-3">
          <SummaryCard label="Total Events" value={summary.totalEvents} />
          <SummaryCard label="Block Events" value={summary.blockEvents} color="red" />
          <SummaryCard label="Audit Events" value={summary.auditEvents} color="yellow" />
          <SummaryCard label="Unique Files" value={summary.uniqueFiles} color="blue" />
        </div>
        {summary.timeRange && (
          <p className="text-xs text-text-muted mt-3 flex items-center gap-1">
            <Clock size={11} />
            {summary.timeRange.earliest} — {summary.timeRange.latest}
          </p>
        )}
      </div>

      {/* Parse errors */}
      {parseErrors.length > 0 && (
        <div className="card p-4 border-accent-yellow/30">
          <h2 className="section-header text-accent-yellow">Parse Warnings ({parseErrors.length})</h2>
          <div className="space-y-1">
            {parseErrors.slice(0, 10).map((err, i) => (
              <p key={i} className="text-xs text-text-muted">
                {err.line !== undefined && <span className="mono mr-2">L{err.line}</span>}
                {err.message}
              </p>
            ))}
            {parseErrors.length > 10 && (
              <p className="text-xs text-text-muted italic">...and {parseErrors.length - 10} more</p>
            )}
          </div>
        </div>
      )}

      {/* Event list */}
      <div className="card p-4">
        <h2 className="section-header">Events ({events.length})</h2>
        <div className="overflow-auto max-h-96">
          <table className="data-table">
            <thead className="sticky top-0 bg-surface-1">
              <tr>
                <th>Severity</th>
                <th>Time</th>
                <th>Machine</th>
                <th>File</th>
                <th>Hash (SHA256)</th>
                <th>Event ID</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, i) => (
                <EventRow key={i} event={event} />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function EventRow({ event }: { event: ParsedCiEvent }) {
  return (
    <tr>
      <td>
        {event.severity === "block" ? (
          <span className="tag-red flex items-center gap-1"><ShieldAlert size={10} />Block</span>
        ) : event.severity === "audit" ? (
          <span className="tag-yellow flex items-center gap-1"><Shield size={10} />Audit</span>
        ) : (
          <span className="tag-gray">Info</span>
        )}
      </td>
      <td className="mono text-xs text-text-muted whitespace-nowrap">
        {event.timestamp ? new Date(event.timestamp).toLocaleString() : "—"}
      </td>
      <td className="text-xs">{event.machineName ?? "—"}</td>
      <td className="text-xs max-w-xs truncate" title={event.filePath}>{event.filePath}</td>
      <td className="mono text-xs text-text-muted">
        {event.sha256Hash ? `${event.sha256Hash.substring(0, 16)}…` : "—"}
      </td>
      <td className="mono text-xs">{event.eventId}</td>
    </tr>
  );
}

function SummaryCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color?: "red" | "yellow" | "blue" | "green";
}) {
  const colorClass = color
    ? { red: "text-accent-red", yellow: "text-accent-yellow", blue: "text-accent-blue", green: "text-accent-green" }[color]
    : "text-text-primary";
  return (
    <div className="bg-surface-2 rounded p-3 text-center">
      <p className={clsx("text-xl font-bold mono", colorClass)}>{value}</p>
      <p className="text-xs text-text-muted">{label}</p>
    </div>
  );
}
