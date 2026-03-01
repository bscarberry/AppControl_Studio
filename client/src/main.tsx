import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MsalProvider } from "@azure/msal-react";
import App from "./App.tsx";
import { AuthGuard } from "./components/auth/AuthGuard.tsx";
import { msalInstance, isMsalEnabled } from "./lib/msal-config.ts";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 1000 * 60 },
    mutations: { retry: 0 },
  },
});

// When MSAL env vars are present, initialize the MSAL instance before render.
// PublicClientApplication.initialize() is required in MSAL v3+ before the
// instance is passed to MsalProvider.
async function bootstrap() {
  if (isMsalEnabled && msalInstance) {
    await msalInstance.initialize();
    // Handle the redirect response if the page was loaded as a redirect callback
    await msalInstance.handleRedirectPromise();
  }

  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        {isMsalEnabled && msalInstance ? (
          <MsalProvider instance={msalInstance}>
            <AuthGuard>
              <App />
            </AuthGuard>
          </MsalProvider>
        ) : (
          <App />
        )}
      </QueryClientProvider>
    </React.StrictMode>
  );
}

bootstrap().catch((err: unknown) => {
  console.error("[AppControl Studio] Fatal startup error:", err);
});
