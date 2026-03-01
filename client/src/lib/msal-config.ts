/**
 * MSAL Configuration
 *
 * Reads Azure AD app registration settings from Vite environment variables.
 * When VITE_MSAL_CLIENT_ID and VITE_MSAL_TENANT_ID are not set, MSAL is
 * disabled and the app runs without authentication (local workstation mode).
 *
 * Required env vars (set in .env or environment):
 *   VITE_MSAL_CLIENT_ID   — Application (client) ID from Azure portal
 *   VITE_MSAL_TENANT_ID   — Directory (tenant) ID from Azure portal
 *
 * Optional:
 *   VITE_MSAL_REDIRECT_URI  — Defaults to window.location.origin
 *
 * No custom API scope or "Expose an API" configuration is required. The app
 * uses the OIDC ID token issued during login. The backend validates the ID
 * token against the tenant JWKS endpoint and accepts the client ID as the
 * audience claim — no additional app registration setup needed.
 */

import { PublicClientApplication, type Configuration } from "@azure/msal-browser";

export const MSAL_CLIENT_ID = import.meta.env.VITE_MSAL_CLIENT_ID as string | undefined;
export const MSAL_TENANT_ID = import.meta.env.VITE_MSAL_TENANT_ID as string | undefined;

/** True when MSAL env vars are present — authentication is enforced. */
export const isMsalEnabled = !!(MSAL_CLIENT_ID && MSAL_TENANT_ID);

// ---------------------------------------------------------------------------
// PublicClientApplication — only instantiated when MSAL is enabled
// ---------------------------------------------------------------------------

let _msalInstance: PublicClientApplication | null = null;

if (isMsalEnabled) {
  const config: Configuration = {
    auth: {
      clientId: MSAL_CLIENT_ID!,
      authority: `https://login.microsoftonline.com/${MSAL_TENANT_ID}`,
      redirectUri: (import.meta.env.VITE_MSAL_REDIRECT_URI as string | undefined) ?? window.location.origin,
      postLogoutRedirectUri: window.location.origin,
    },
    cache: {
      // sessionStorage is cleared when the browser tab closes — safer for
      // security-sensitive tooling than localStorage.
      cacheLocation: "sessionStorage",
    },
  };
  _msalInstance = new PublicClientApplication(config);
}

export const msalInstance = _msalInstance;

// ---------------------------------------------------------------------------
// Token helper — used by the API client
// ---------------------------------------------------------------------------

/**
 * Returns the cached ID token for the signed-in account, or null when MSAL
 * is disabled or no account is active.
 *
 * The ID token (aud = clientId) is used instead of a custom access token so
 * that "Expose an API" does not need to be configured in the app registration.
 * The backend's msal-auth middleware already accepts the bare client ID as a
 * valid audience when validating tokens.
 */
export function getAccessToken(): string | null {
  if (!isMsalEnabled || !msalInstance) return null;
  const accounts = msalInstance.getAllAccounts();
  if (accounts.length === 0) return null;
  return accounts[0].idToken ?? null;
}
