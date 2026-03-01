/**
 * AuthGuard — gates the application behind MSAL authentication.
 *
 * When MSAL is enabled (VITE_MSAL_CLIENT_ID + VITE_MSAL_TENANT_ID are set):
 *   • Authenticated users see the application normally.
 *   • Unauthenticated users see the SignInPage.
 *   • During the MSAL interaction (redirect/popup in progress) a loading
 *     indicator is shown to avoid a flash of the sign-in screen.
 *
 * When MSAL is disabled (env vars absent), this component is never rendered
 * and the app runs without authentication.
 */

import { AuthenticatedTemplate, UnauthenticatedTemplate, useIsAuthenticated, useMsal } from "@azure/msal-react";
import { InteractionStatus } from "@azure/msal-browser";
import { SignInPage } from "../../pages/SignInPage.tsx";
import { LoadingSpinner } from "../common/LoadingSpinner.tsx";

interface AuthGuardProps {
  children: React.ReactNode;
}

export function AuthGuard({ children }: AuthGuardProps) {
  const { inProgress } = useMsal();
  const isAuthenticated = useIsAuthenticated();

  // While a login/logout interaction is in flight, show a neutral loading
  // screen instead of flashing the sign-in page.
  // msal-browser v5 removed InteractionStatus.Login; login interactions
  // now surface as AcquireToken.
  if (
    !isAuthenticated &&
    (inProgress === InteractionStatus.HandleRedirect ||
      inProgress === InteractionStatus.AcquireToken)
  ) {
    return (
      <div className="flex items-center justify-center h-screen bg-surface-1">
        <LoadingSpinner size="lg" label="Signing in..." />
      </div>
    );
  }

  return (
    <>
      <AuthenticatedTemplate>{children}</AuthenticatedTemplate>
      <UnauthenticatedTemplate>
        <SignInPage />
      </UnauthenticatedTemplate>
    </>
  );
}
