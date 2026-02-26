import clsx from "clsx";

interface LoadingSpinnerProps {
  size?: "sm" | "md" | "lg";
  label?: string;
}

export function LoadingSpinner({ size = "md", label }: LoadingSpinnerProps) {
  const sizeClasses = { sm: "w-4 h-4", md: "w-6 h-6", lg: "w-8 h-8" };
  return (
    <div className="flex flex-col items-center gap-2">
      <div
        className={clsx(
          "border-2 border-border border-t-accent-blue rounded-full animate-spin",
          sizeClasses[size]
        )}
      />
      {label && <p className="text-xs text-text-muted">{label}</p>}
    </div>
  );
}
