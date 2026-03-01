/**
 * SignInPage — shown to unauthenticated users when MSAL is enabled.
 *
 * Uses loginRedirect so authentication happens in the same browser window
 * instead of a popup. Microsoft's login page takes over the tab, and MSAL
 * processes the auth code when the browser returns to the redirect URI.
 */

import { useMsal } from "@azure/msal-react";
import { Shield, LogIn } from "lucide-react";

export function SignInPage() {
  const { instance } = useMsal();

  const handleSignIn = () => {
    instance.loginRedirect({
      scopes: ["openid", "profile"],
      prompt: "select_account",
    });
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

          <button
            className="btn-primary w-full flex items-center justify-center gap-2"
            onClick={handleSignIn}
          >
            <LogIn size={14} />
            Sign in with Microsoft
          </button>
        </div>

        <p className="text-center text-xs text-text-muted mt-4">
          All policy data is processed locally and never transmitted externally.
        </p>
      </div>
    </div>
  );
}
