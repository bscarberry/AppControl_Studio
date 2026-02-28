import { NavLink } from "react-router-dom";
import {
  Shield,
  FileText,
  GitCompare,
  Download,
  Upload,
  Activity,
  Cpu,
  ShieldCheck,
  Search,
  ChevronRight,
} from "lucide-react";
import clsx from "clsx";
import { useAppStore } from "../../store/index.ts";

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
  description: string;
}

const navItems: NavItem[] = [
  {
    to: "/",
    label: "Policy Editor",
    icon: <FileText size={16} />,
    description: "Load, inspect, and modify policies",
  },
  {
    to: "/compare",
    label: "Compare",
    icon: <GitCompare size={16} />,
    description: "Diff two policies structurally",
  },
  {
    to: "/semantic-compare",
    label: "Semantic Compare",
    icon: <ShieldCheck size={16} />,
    description: "Security-aware policy diff",
  },
  {
    to: "/advanced-hunting",
    label: "Advanced Hunting",
    icon: <Search size={16} />,
    description: "AH export → WDAC rule candidates",
  },
  {
    to: "/import-events",
    label: "Import Events",
    icon: <Upload size={16} />,
    description: "Parse CI events and hunting results",
  },
  {
    to: "/build",
    label: "Build Policy",
    icon: <Activity size={16} />,
    description: "Generate policy from events",
  },
  {
    to: "/rule-engine",
    label: "Rule Engine",
    icon: <Cpu size={16} />,
    description: "Events → candidate WDAC rules",
  },
  {
    to: "/export",
    label: "Export",
    icon: <Download size={16} />,
    description: "Download deployable XML",
  },
];

export function Sidebar() {
  const { sessions, activePolicyId, setActivePolicy } = useAppStore();

  return (
    <aside className="w-56 flex-shrink-0 bg-surface-1 border-r border-border flex flex-col">
      {/* Logo */}
      <div className="px-4 py-4 border-b border-border flex items-center gap-2.5">
        <Shield size={18} className="text-accent-blue flex-shrink-0" />
        <div>
          <div className="text-sm font-semibold text-text-primary leading-none">AppControl</div>
          <div className="text-xs text-text-muted mt-0.5">Studio</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-3 overflow-y-auto">
        <div className="px-3 mb-1">
          <p className="section-header">Navigation</p>
        </div>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              clsx(
                "flex items-center gap-2.5 px-3 py-2 mx-1 rounded text-sm transition-colors group",
                isActive
                  ? "bg-surface-3 text-text-primary"
                  : "text-text-secondary hover:text-text-primary hover:bg-surface-2"
              )
            }
          >
            {({ isActive }) => (
              <>
                <span className={clsx(isActive ? "text-accent-blue" : "text-text-muted group-hover:text-text-secondary")}>
                  {item.icon}
                </span>
                <span>{item.label}</span>
                {isActive && <ChevronRight size={12} className="ml-auto text-text-muted" />}
              </>
            )}
          </NavLink>
        ))}

        {/* Loaded Sessions */}
        {sessions.length > 0 && (
          <div className="mt-4 px-3">
            <p className="section-header">Loaded Policies</p>
            <div className="space-y-1">
              {sessions.map((session) => (
                <button
                  key={session.id}
                  onClick={() => setActivePolicy(session.id)}
                  className={clsx(
                    "w-full text-left px-2 py-1.5 rounded text-xs transition-colors truncate",
                    session.id === activePolicyId
                      ? "bg-accent-blue-dim text-accent-blue"
                      : "text-text-muted hover:text-text-secondary hover:bg-surface-2"
                  )}
                  title={session.fileName ?? session.policy.policyId}
                >
                  {session.fileName ?? session.policy.friendlyName ?? session.policy.policyId.substring(0, 16) + "..."}
                </button>
              ))}
            </div>
          </div>
        )}
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-border">
        <p className="text-xs text-text-muted">Local processing only.</p>
        <p className="text-xs text-text-muted">No data leaves your machine.</p>
      </div>
    </aside>
  );
}
