// Injected at build time by vite.config.ts define.__APP_VERSION__
declare const __APP_VERSION__: string;

import { NavLink } from "react-router-dom";
import {
  Shield,
  FileText,
  GitCompare,
  Download,
  Upload,
  Cpu,
  Lock,
  PlayCircle,
  ChevronRight,
  LogOut,
  User,
  Merge,
  ArrowRightLeft,
} from "lucide-react";
import clsx from "clsx";
import { useAppStore } from "../../store/index.ts";
import { isMsalEnabled } from "../../lib/msal-config.ts";
import { useMsal } from "@azure/msal-react";

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
    to: "/import-events",
    label: "Import & Build",
    icon: <Upload size={16} />,
    description: "Import CI events, hunt, and build policy",
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
  {
    to: "/simulator",
    label: "Simulator",
    icon: <PlayCircle size={16} />,
    description: "Test allow/block decisions",
  },
  {
    to: "/security",
    label: "Security",
    icon: <Lock size={16} />,
    description: "Posture, RBAC, audit log",
  },
  {
    to: "/merge",
    label: "Merge Policies",
    icon: <Merge size={16} />,
    description: "Combine up to 15 policies into one",
  },
  {
    to: "/applocker",
    label: "AppLocker Convert",
    icon: <ArrowRightLeft size={16} />,
    description: "Convert AppLocker XML to WDAC",
  },
];

/**
 * Shown in the sidebar footer when MSAL is enabled.
 * Kept as a separate component so useMsal() is only called when the component
 * is rendered inside MsalProvider (i.e. when isMsalEnabled is true).
 */
function MsalUserFooter() {
  const { instance, accounts } = useMsal();
  const account = accounts[0];
  if (!account) return null;

  return (
    <div className="flex items-center gap-2">
      <User size={12} className="text-text-muted flex-shrink-0" />
      <span className="text-xs text-text-muted truncate flex-1" title={account.username}>
        {account.username}
      </span>
      <button
        onClick={() => instance.logoutRedirect({ account })}
        className="text-text-muted hover:text-text-primary transition-colors flex-shrink-0"
        title="Sign out"
      >
        <LogOut size={12} />
      </button>
    </div>
  );
}

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
      <div className="px-4 py-3 border-t border-border space-y-2">
        {isMsalEnabled && <MsalUserFooter />}
        <p className="text-xs text-text-muted">Local processing only.</p>
        <p className="text-xs text-text-muted">No data leaves your machine.</p>
        <p className="text-[10px] text-text-muted opacity-50">v{__APP_VERSION__}</p>
      </div>
    </aside>
  );
}
