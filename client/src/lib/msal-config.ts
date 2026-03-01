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
 *   VITE_MSAL_API_SCOPE     — API scope URI; defaults to api://<clientId>/access_as_user
 */

import { PublicClientApplication, type Configuration } from "@azure/msal-browser";

export const MSAL_CLIENT_ID = import.meta.env.VITE_MSAL_CLIENT_ID as string | undefined;
export const MSAL_TENANT_ID = import.meta.env.VITE_MSAL_TENANT_ID as string | undefined;

/** True when MSAL env vars are present — authentication is enforced. */
export const isMsalEnabled = !!(MSAL_CLIENT_ID && MSAL_TENANT_ID);

/**
 * The scope to request when acquiring tokens for the backend API.
 * Must match a scope exposed under "Expose an API" in your app registration.
 */
export const API_SCOPE: string =
  (import.meta.env.VITE_MSAL_API_SCOPE as string | undefined) ??
  `api://${MSAL_CLIENT_ID}/access_as_user`;

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
// Token acquisition helper — used by the API client
// ---------------------------------------------------------------------------

/**
 * Returns the current access token for the signed-in account, or null if
 * MSAL is disabled or no account is signed in.
 *
 * Attempts a silent refresh first; falls back to returning null (letting the
 * AuthGuard redirect to sign-in).
 */
export async function getAccessToken(): Promise<string | null> {
  if (!isMsalEnabled || !msalInstance) return null;

  const accounts = msalInstance.getAllAccounts();
  if (accounts.length === 0) return null;

  try {
    const result = await msalInstance.acquireTokenSilent({
      scopes: [API_SCOPE],
      account: accounts[0],
    });
    return result.accessToken;
  } catch {
    // Silent acquisition failed (consent required, session expired, etc.)
    // The AuthGuard will force re-login on the next render cycle.
    return null;
  }
}
