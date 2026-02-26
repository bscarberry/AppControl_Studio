import { AlertCircle, CheckCircle } from "lucide-react";

interface HeaderProps {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  status?: { type: "success" | "error" | "warning"; message: string } | null;
}

export function Header({ title, subtitle, actions, status }: HeaderProps) {
  return (
    <header className="px-6 py-4 border-b border-border flex items-center justify-between flex-shrink-0">
      <div>
        <h1 className="text-base font-semibold text-text-primary">{title}</h1>
        {subtitle && <p className="text-xs text-text-muted mt-0.5">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        {status && (
          <div
            className={`flex items-center gap-2 text-xs px-3 py-1 rounded ${
              status.type === "success"
                ? "bg-accent-green-dim text-accent-green"
                : status.type === "error"
                ? "bg-accent-red-dim text-accent-red"
                : "bg-accent-yellow-dim text-accent-yellow"
            }`}
          >
            {status.type === "success" ? (
              <CheckCircle size={12} />
            ) : (
              <AlertCircle size={12} />
            )}
            {status.message}
          </div>
        )}
        {actions}
      </div>
    </header>
  );
}
