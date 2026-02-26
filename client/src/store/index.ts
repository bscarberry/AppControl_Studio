/**
 * Global application state — Zustand store
 */

import { create } from "zustand";
import type { WdacPolicy, ParsedCiEvent, PolicyComparisonResult } from "@appcontrol/shared";

export interface PolicySession {
  id: string;
  fileName?: string;
  policy: WdacPolicy;
  xml?: string;
  loadedAt: string;
}

interface AppState {
  // Loaded policies (up to 2 for comparison)
  sessions: PolicySession[];
  activePolicyId: string | null;

  // Comparison state
  comparison: PolicyComparisonResult | null;

  // Events import state
  importedEvents: ParsedCiEvent[];

  // Actions
  addSession: (session: PolicySession) => void;
  removeSession: (id: string) => void;
  setActivePolicy: (id: string) => void;
  updateSessionPolicy: (id: string, policy: WdacPolicy) => void;
  setComparison: (result: PolicyComparisonResult | null) => void;
  setImportedEvents: (events: ParsedCiEvent[]) => void;
  clearEvents: () => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  sessions: [],
  activePolicyId: null,
  comparison: null,
  importedEvents: [],

  addSession: (session) =>
    set((state) => {
      // Keep max 4 sessions; remove oldest if needed
      const sessions = [...state.sessions.slice(-3), session];
      return { sessions, activePolicyId: session.id };
    }),

  removeSession: (id) =>
    set((state) => {
      const sessions = state.sessions.filter((s) => s.id !== id);
      const activePolicyId =
        state.activePolicyId === id ? (sessions[0]?.id ?? null) : state.activePolicyId;
      return { sessions, activePolicyId };
    }),

  setActivePolicy: (id) => set({ activePolicyId: id }),

  updateSessionPolicy: (id, policy) =>
    set((state) => ({
      sessions: state.sessions.map((s) => (s.id === id ? { ...s, policy } : s)),
    })),

  setComparison: (comparison) => set({ comparison }),

  setImportedEvents: (events) => set({ importedEvents: events }),

  clearEvents: () => set({ importedEvents: [] }),
}));

// Selector helpers
export const useActiveSession = () => {
  const { sessions, activePolicyId } = useAppStore();
  return sessions.find((s) => s.id === activePolicyId) ?? null;
};
