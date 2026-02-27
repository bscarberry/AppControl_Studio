/**
 * Global application state — Zustand store
 */

import { create } from "zustand";
import type { WdacPolicy, ParsedCiEvent, PolicyComparisonResult, ProposedPolicyChanges } from "@appcontrol/shared";

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

  // Rule engine proposals
  proposedChanges: ProposedPolicyChanges | null;

  // Actions
  addSession: (session: PolicySession) => void;
  removeSession: (id: string) => void;
  setActivePolicy: (id: string) => void;
  updateSessionPolicy: (id: string, policy: WdacPolicy) => void;
  setComparison: (result: PolicyComparisonResult | null) => void;
  setImportedEvents: (events: ParsedCiEvent[]) => void;
  clearEvents: () => void;
  setProposedChanges: (changes: ProposedPolicyChanges | null) => void;
}

export const useAppStore = create<AppState>((set, get) => ({
  sessions: [],
  activePolicyId: null,
  comparison: null,
  importedEvents: [],
  proposedChanges: null,

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

  setProposedChanges: (changes) => set({ proposedChanges: changes }),
}));

// Selector helpers
export const useActiveSession = () => {
  const { sessions, activePolicyId } = useAppStore();
  return sessions.find((s) => s.id === activePolicyId) ?? null;
};
