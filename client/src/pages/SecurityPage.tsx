import { useQuery } from "@tanstack/react-query";
import {
  Lock,
  ShieldAlert,
  CheckCircle,
  XCircle,
  Clock,
  User,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  FileText,
  RefreshCw,
} from "lucide-react";
import clsx from "clsx";
import { securityApi } from "../lib/api.ts";
import type { AuditEvent, AuditEventType, SecurityStatus } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Colour / label helpers
// ---------------------------------------------------------------------------

function eventTypeBadgeClass(t: AuditEventType): string {
  if (t.startsWith("AUTH_FAILED") || t === "AUTHZ_DENIED" || t === "VALIDATION_REJECTED") return "tag-red";
  if (t === "AUTH_SUCCESS") return "tag-green";
  if (t === "CONFIG_CHANGED") return "tag-orange";
  if (t.startsWith("SERVER_")) return "tag-blue";
  return "tag-gray";
}

function shortEventType(t: AuditEventType): string {
  return t.replace(/_/g, " ").toLowerCase().replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatTs(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  } catch {
    return iso;
  }
}

// ---------------------------------------------------------------------------
// Posture indicator card
// ---------------------------------------------------------------------------

interface PostureCardProps {
  label: string;
  active: boolean;
  description: string;
  inverseRisk?: boolean; // true = active is BAD (e.g. RBAC disabled is a posture gap)
}

function PostureCard({ label, active, description, inverseRisk = false }: PostureCardProps) {
  const good = inverseRisk ? !active : active;
  return (
    <div className={clsx(
      "panel flex flex-col gap-2",
      good ? "border-l-2 border-accent-green" : "border-l-2 border-accent-yellow"
    )}>
      <div className="flex items-center gap-2">
        {good
          ? <CheckCircle size={14} className="text-accent-green flex-shrink-0" />
          : <AlertTriangle size={14} className="text-accent-yellow flex-shrink-0" />}
        <span className="text-xs font-medium text-text-primary">{label}</span>
      </div>
      <p className="text-xs text-text-muted leading-relaxed">{description}</p>
      <span className={clsx("tag w-fit text-xs", good ? "tag-green" : "tag-yellow")}>
        {active ? "Active" : "Disabled"}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit event row
// ---------------------------------------------------------------------------

function AuditEventRow({ event }: { event: AuditEvent }) {
  return (
    <tr className="border-b border-border hover:bg-surface-2 transition-colors text-xs">
      <td className="px-3 py-2 text-text-muted whitespace-nowrap font-mono">
        {formatTs(event.timestamp)}
      </td>
      <td className="px-3 py-2 whitespace-nowrap">
        <span className={clsx("tag", eventTypeBadgeClass(event.eventType))}>
          {shortEventType(event.eventType)}
        </span>
      </td>
      <td className="px-3 py-2 whitespace-nowrap">
        {event.succeeded
          ? <CheckCircle size={12} className="text-accent-green" />
          : <XCircle size={12} className="text-accent-red" />}
      </td>
      <td className="px-3 py-2 text-text-muted">{event.role ?? "—"}</td>
      <td className="px-3 py-2 text-text-secondary max-w-xs truncate" title={event.outputSummary ?? event.errorMessage ?? ""}>
        {event.outputSummary ?? event.errorMessage ?? "—"}
      </td>
      <td className="px-3 py-2 text-text-muted tabular-nums text-right">
        {event.durationMs != null ? `${event.durationMs}ms` : "—"}
      </td>
    </tr>
  );
}

// ---------------------------------------------------------------------------
// Role permission matrix
// ---------------------------------------------------------------------------

function RoleMatrix() {
  const [open, setOpen] = useState(false);
  return (
    <div className="panel">
      <button onClick={() => setOpen(v => !v)} className="flex items-center gap-2 w-full text-left">
        <User size={14} className="text-text-muted" />
        <span className="text-sm font-medium text-text-primary flex-1">Role Permission Matrix</span>
        {open ? <ChevronDown size={14} className="text-text-muted" /> : <ChevronRight size={14} className="text-text-muted" />}
      </button>
      {open && (
        <div className="mt-4 space-y-3 text-xs">
          {[
            {
              role: "viewer",
              color: "tag-blue",
              ops: [
                "Parse / load policy XML",
                "Structural compare (two policies)",
                "Semantic compare (security-aware diff)",
                "Explain policy in plain language",
                "Read policy rule options",
                "View security posture status",
              ],
            },
            {
              role: "analyst",
              color: "tag-yellow",
              ops: [
                "All viewer operations",
                "Generate / export policy XML",
                "Build policy from CI events",
                "Propose WDAC rule candidates",
                "Advanced Hunting ingest",
                "Parse CodeIntegrity events",
              ],
            },
            {
              role: "admin",
              color: "tag-orange",
              ops: [
                "All analyst operations",
                "Read audit log",
                "Update RBAC configuration",
                "Add / revoke access tokens",
              ],
            },
          ].map(({ role, color, ops }) => (
            <div key={role} className="bg-surface-2 rounded p-3">
              <div className="flex items-center gap-2 mb-2">
                <span className={clsx("tag", color)}>{role}</span>
              </div>
              <ul className="space-y-0.5">
                {ops.map(op => (
                  <li key={op} className="flex items-center gap-2 text-text-secondary">
                    <CheckCircle size={10} className="text-accent-green flex-shrink-0" />
                    {op}
                  </li>
                ))}
              </ul>
            </div>
          ))}
          <div className="bg-surface-2 rounded p-3 text-text-muted">
            <p className="font-medium text-text-primary mb-1">Generating a token hash</p>
            <pre className="font-mono text-xs overflow-x-auto bg-surface-3 rounded p-2 mt-1">{
`# Run this once — store the hex output in security.json
node -e "const {createHash}=require('crypto');
console.log(createHash('sha256').update('YOUR_TOKEN').digest('hex'))"`
            }</pre>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Data handling policy (static — always visible)
// ---------------------------------------------------------------------------

function DataHandlingPolicy() {
  const [open, setOpen] = useState(true);
  return (
    <div className="panel">
      <button onClick={() => setOpen(v => !v)} className="flex items-center gap-2 w-full text-left">
        <FileText size={14} className="text-text-muted" />
        <span className="text-sm font-medium text-text-primary flex-1">Data Handling Policy</span>
        {open ? <ChevronDown size={14} className="text-text-muted" /> : <ChevronRight size={14} className="text-text-muted" />}
      </button>
      {open && (
        <div className="mt-4 grid grid-cols-2 gap-3 text-xs">
          {[
            {
              title: "No external transmission",
              items: [
                "The server binds exclusively to 127.0.0.1 — no inbound or outbound network connections are made during policy processing.",
                "No telemetry, error reporting, or analytics calls are made at any time.",
              ],
              icon: <CheckCircle size={12} className="text-accent-green" />,
            },
            {
              title: "Policy content never persisted",
              items: [
                "Uploaded policy XML is parsed in memory and discarded when the response is sent.",
                "No temporary files are written to disk for policy data.",
                "The audit log records only SHA-256 hashes and metadata — never policy content.",
              ],
              icon: <CheckCircle size={12} className="text-accent-green" />,
            },
            {
              title: "Audit log retention",
              items: [
                "Audit events are written to append-only JSONL files in ~/.appcontrol-studio/audit/.",
                "Files rotate at 10 MB; up to 5 rotated files are retained.",
                "Log files contain: event type, timestamp, role, input hash, output summary, duration.",
                "Log files never contain: policy XML, rule content, file paths from policies, or certificate data.",
              ],
              icon: <Lock size={12} className="text-accent-blue" />,
            },
            {
              title: "Access control",
              items: [
                "RBAC is optional. When disabled, the app operates as a single-user local tool.",
                "When enabled, tokens are stored as SHA-256 hashes — never in plaintext.",
                "Timing-safe comparison prevents token enumeration attacks.",
                "Role is logged with each audit event for accountability.",
              ],
              icon: <Lock size={12} className="text-accent-blue" />,
            },
          ].map(({ title, items, icon }) => (
            <div key={title} className="bg-surface-2 rounded p-3">
              <div className="flex items-center gap-2 mb-2">
                {icon}
                <span className="font-medium text-text-primary">{title}</span>
              </div>
              <ul className="space-y-1">
                {items.map((item, i) => (
                  <li key={i} className="text-text-secondary leading-relaxed">{item}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

import { useState } from "react";

export function SecurityPage() {
  const statusQuery = useQuery({
    queryKey: ["security-status"],
    queryFn: () => securityApi.status(),
    refetchInterval: 30_000,
  });

  const auditQuery = useQuery({
    queryKey: ["security-audit"],
    queryFn: () => securityApi.audit(200),
    refetchInterval: 10_000,
  });

  const status: SecurityStatus | undefined = statusQuery.data;

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-border flex-shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-accent-blue" />
            <h1 className="text-base font-semibold text-text-primary">Security</h1>
          </div>
          <button
            onClick={() => { void statusQuery.refetch(); void auditQuery.refetch(); }}
            className="flex items-center gap-1.5 text-xs text-text-muted hover:text-text-secondary transition-colors"
          >
            <RefreshCw size={12} className={clsx(statusQuery.isFetching && "animate-spin")} />
            Refresh
          </button>
        </div>
        <p className="text-xs text-text-muted mt-1">
          Local-only processing · No external data transmission · Append-only audit log
        </p>
      </div>

      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {/* Posture grid */}
        <div>
          <p className="text-xs font-medium text-text-secondary uppercase tracking-wider mb-3">
            Security Posture
          </p>
          <div className="grid grid-cols-4 gap-3">
            <PostureCard
              label="Local-only binding"
              active={true}
              description="Server listens on 127.0.0.1 only. No inbound connections from the network are possible."
            />
            <PostureCard
              label="No external transmission"
              active={true}
              description="Zero outbound HTTP calls during policy processing. No telemetry."
            />
            <PostureCard
              label="RBAC"
              active={status?.rbacEnabled ?? false}
              inverseRisk={true}
              description={status?.rbacEnabled
                ? "Token-based role authentication is active. Roles: viewer, analyst, admin."
                : "RBAC is disabled. Suitable for single-user local workstations. Enable for shared deployments."}
            />
            <PostureCard
              label="Audit logging"
              active={status?.auditEnabled ?? false}
              inverseRisk={true}
              description={status?.auditEnabled
                ? "Append-only JSONL audit log. Metadata only — no policy content."
                : "Disk audit logging is disabled. Events are kept in memory only."}
            />
          </div>
        </div>

        {/* Stats row */}
        {status && (
          <div className="grid grid-cols-3 gap-3">
            <div className="panel">
              <p className="text-xs text-text-muted mb-1">Server version</p>
              <p className="text-sm font-mono text-text-primary">{status.serverVersion}</p>
            </div>
            <div className="panel">
              <p className="text-xs text-text-muted mb-1">Audit events (session)</p>
              <p className="text-lg font-semibold tabular-nums text-text-primary">{status.auditEventCount}</p>
            </div>
            <div className="panel">
              <p className="text-xs text-text-muted mb-1">Memory-only mode</p>
              <p className="text-sm text-text-primary">{status.memoryOnlyMode ? "Enabled — buffers cleared aggressively" : "Standard"}</p>
            </div>
          </div>
        )}

        {/* Data handling */}
        <DataHandlingPolicy />

        {/* Role matrix */}
        <RoleMatrix />

        {/* Audit log */}
        <div className="panel">
          <div className="flex items-center gap-2 mb-4">
            <Clock size={14} className="text-text-muted" />
            <span className="text-sm font-medium text-text-primary flex-1">
              Audit Log
              {auditQuery.data && (
                <span className="text-text-muted font-normal ml-2">
                  ({auditQuery.data.events.length} of {auditQuery.data.totalInMemory} in-memory events)
                </span>
              )}
            </span>
            {auditQuery.isFetching && (
              <RefreshCw size={12} className="text-text-muted animate-spin" />
            )}
          </div>

          {auditQuery.isError && (
            <div className="flex items-center gap-2 text-xs text-accent-orange p-3 bg-surface-2 rounded">
              <AlertTriangle size={12} />
              <span>
                {(auditQuery.error as Error).message.includes("FORBIDDEN")
                  ? "Audit log access requires the admin role. Enable RBAC and authenticate with an admin token to view events."
                  : (auditQuery.error as Error).message}
              </span>
            </div>
          )}

          {auditQuery.data && auditQuery.data.events.length === 0 && (
            <p className="text-xs text-text-muted text-center py-6">No events recorded yet this session.</p>
          )}

          {auditQuery.data && auditQuery.data.events.length > 0 && (
            <div className="overflow-x-auto rounded border border-border">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border bg-surface-2">
                    {["Timestamp", "Event", "OK", "Role", "Summary", "Duration"].map(h => (
                      <th key={h} className="text-left px-3 py-2 text-text-muted font-medium whitespace-nowrap">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {[...auditQuery.data.events].reverse().map(event => (
                    <AuditEventRow key={event.id} event={event} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Secure update note */}
        <div className="panel border-l-2 border-border">
          <p className="text-xs font-medium text-text-primary mb-2">Secure Update Procedure</p>
          <ol className="text-xs text-text-secondary space-y-1 list-decimal list-inside">
            <li>Review the changelog and diff at the source repository before pulling.</li>
            <li>Run <code className="font-mono bg-surface-2 px-1 rounded">git log --oneline HEAD..origin/main</code> to inspect incoming commits.</li>
            <li>Verify the latest commit signature: <code className="font-mono bg-surface-2 px-1 rounded">git verify-commit HEAD</code>.</li>
            <li>Run <code className="font-mono bg-surface-2 px-1 rounded">npm audit</code> after pulling to check for newly disclosed dependency vulnerabilities.</li>
            <li>Rebuild: <code className="font-mono bg-surface-2 px-1 rounded">npm run build</code>. Do not deploy without a successful build.</li>
            <li>Rotate RBAC tokens after any update that modifies authentication code.</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
