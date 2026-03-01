/**
 * SignInPage — shown to unauthenticated users when MSAL is enabled.
 *
 * Uses loginPopup so the user stays on the same page/tab rather than
 * navigating away (better UX for a local desktop-style tool).
 */

import { useState } from "react";
import { useMsal } from "@azure/msal-react";
import { Shield, LogIn, AlertCircle } from "lucide-react";
import { API_SCOPE } from "../lib/msal-config.ts";

export function SignInPage() {
  const { instance } = useMsal();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSignIn = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await instance.loginPopup({
        scopes: [API_SCOPE],
        prompt: "select_account",
      });
    } catch (err) {
      // BrowserAuthError with code "user_cancelled" — user closed the popup
      const e = err as { errorCode?: string; message?: string };
      if (e.errorCode !== "user_cancelled" && e.errorCode !== "interaction_in_progress") {
        setError(e.message ?? "Sign-in failed. Please try again.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-surface-1">
      <div className="w-full max-w-sm">
        {/* Logo / branding */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl bg-accent-blue/10 border border-accent-blue/20 flex items-center justify-center mb-4">
            <Shield size={28} className="text-accent-blue" />
          </div>
          <h1 className="text-lg font-semibold text-text-primary">AppControl Studio</h1>
          <p className="text-xs text-text-muted mt-1">WDAC Policy Management</p>
        </div>

        {/* Sign-in card */}
        <div className="bg-surface-2 border border-border rounded-lg p-6 shadow-lg">
          <h2 className="text-sm font-medium text-text-primary mb-1">Sign in required</h2>
          <p className="text-xs text-text-muted mb-5">
            Authenticate with your Microsoft account to access this tool.
          </p>

          {error && (
            <div className="flex items-start gap-2 p-3 mb-4 bg-accent-red/10 border border-accent-red/20 rounded text-xs text-accent-red">
              <AlertCircle size={13} className="flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <button
            className="btn-primary w-full flex items-center justify-center gap-2"
            onClick={handleSignIn}
            disabled={isLoading}
          >
            {isLoading ? (
              <span className="text-xs">Signing in...</span>
            ) : (
              <>
                <LogIn size={14} />
                Sign in with Microsoft
              </>
            )}
          </button>
        </div>

        <p className="text-center text-xs text-text-muted mt-4">
          All policy data is processed locally and never transmitted externally.
        </p>
      </div>
    </div>
  );
}
