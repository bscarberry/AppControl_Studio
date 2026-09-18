/**
 * Policy Templates — Shared Types
 *
 * AppControl Manager parity for "Create AppControl Policy" (base templates)
 * and "Create Deny Policy". Templates are backed by the Microsoft example
 * policies shipped in C:\Windows\schemas\CodeIntegrity\ExamplePolicies and by
 * derived variants (Signed and Reputable, Strict Kernel-Mode, Deny scaffold).
 */

import type { WdacPolicy } from "./policy";

export type PolicyTemplateId =
  | "allow-microsoft"
  | "default-windows"
  | "signed-and-reputable"
  | "strict-kernel-mode"
  | "allow-all"
  | "deny-all-audit"
  | "recommended-driver-block"
  | "deny-policy"
  | "supplemental-blank"
  | "blank";

export type PolicyTemplateCategory = "base" | "supplemental" | "block" | "deny";

export interface PolicyTemplateInfo {
  id: PolicyTemplateId;
  name: string;
  description: string;
  category: PolicyTemplateCategory;
  /** Where the template content comes from */
  source: string;
  /** Rule counts of the template before any user options are applied */
  ruleCounts: { signers: number; fileRules: number; ekus: number; options: number };
  /** Which optional switches apply to this template */
  supports: {
    auditMode: boolean;
    requireEvSigners: boolean;
    scriptEnforcement: boolean;
    testMode: boolean;
    hvci: boolean;
    allowSupplemental: boolean;
  };
  notes: string[];
}

export interface CreateFromTemplateRequest {
  templateId: PolicyTemplateId;
  policyName: string;
  /** Option 3 — log only, never block (default true for base templates) */
  auditMode?: boolean;
  /** Option 8 — Required:EV Signers */
  requireEvSigners?: boolean;
  /** When false, adds option 11 (Disabled:Script Enforcement). Default true (enforce scripts). */
  enableScriptEnforcement?: boolean;
  /** Options 9 + 10 — Advanced Boot Options Menu + Boot Audit On Failure */
  testMode?: boolean;
  /** HvciOptions = 1 (Enabled) when true; 0 otherwise */
  hvci?: boolean;
  /** Option 17 — Enabled:Allow Supplemental Policies (base policies only) */
  allowSupplemental?: boolean;
  /** Option 16 — Enabled:Update Policy No Reboot */
  updateNoReboot?: boolean;
  /** Base policy GUID for supplemental templates */
  basePolicyId?: string;
  /** Explicit version (default 1.0.0.0) */
  versionEx?: string;
}

export interface CreateFromTemplateResponse {
  policy: WdacPolicy;
  xml: string;
  templateId: PolicyTemplateId;
  /** Option numbers enabled in the resulting policy */
  appliedOptions: number[];
  buildLog: string[];
}

export interface PolicyTemplatesResponse {
  templates: PolicyTemplateInfo[];
}
