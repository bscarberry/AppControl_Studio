/**
 * Reference-safe WDAC policy mutations
 *
 * Every mutation here is a pure function: it takes a WdacPolicy and returns a
 * new WdacPolicy with all cross-references kept consistent.
 *
 * Reference graph (per cipolicy.xsd / Microsoft documentation):
 *
 *   WdacFileRule (id)
 *     ← WdacSigningScenario.fileRuleRefs
 *     ← WdacSignerRule.fileAttribRefs         (fileAttrib kind only)
 *     ← AllowedSigner.exceptDenyRuleIds
 *     ← DeniedSigner.exceptAllowRuleIds
 *
 *   WdacSignerRule (id)
 *     ← WdacSigningScenario.allowedSigners[*].signerId
 *     ← WdacSigningScenario.deniedSigners[*].signerId
 *     ← WdacPolicy.updatePolicySigners
 *     ← WdacPolicy.ciSigners
 *
 * References:
 *   https://learn.microsoft.com/en-us/windows/security/application-security/
 *   application-control/app-control-for-business/design/select-types-of-rules-to-create
 */

import type {
  WdacPolicy,
  WdacFileRule,
  WdacHashRule,
  WdacPathRule,
  WdacPackageRule,
  WdacAttributeRule,
  WdacFileAttrib,
  WdacSignerRule,
  WdacSigningScenario,
  SigningScenarioValue,
  AllowedSigner,
  DeniedSigner,
  FileRuleEffect,
} from "@appcontrol/shared";

// Distributed Omit that preserves the discriminated union
export type WdacFileRuleNoId =
  | Omit<WdacHashRule, "id">
  | Omit<WdacPathRule, "id">
  | Omit<WdacPackageRule, "id">
  | Omit<WdacAttributeRule, "id">
  | Omit<WdacFileAttrib, "id">;

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

function shortId(): string {
  return Math.random().toString(16).slice(2, 10).toUpperCase();
}

export function generateFileRuleId(effect: FileRuleEffect | "fileAttrib"): string {
  if (effect === "fileAttrib") return `ID_FILEATTRIB_F_${shortId()}`;
  return effect === "Allow"
    ? `ID_ALLOW_A_${shortId()}`
    : `ID_DENY_D_${shortId()}`;
}

export function generateSignerId(): string {
  return `ID_SIGNER_S_${shortId()}`;
}

// ---------------------------------------------------------------------------
// Delete file rule — removes the rule and cleans every reference to it
// ---------------------------------------------------------------------------

export function deleteFileRule(policy: WdacPolicy, ruleId: string): WdacPolicy {
  return {
    ...policy,
    // 1. Remove the rule itself
    fileRules: policy.fileRules.filter((r) => r.id !== ruleId),

    // 2. Remove from signer fileAttribRefs (if it was a fileAttrib)
    signers: policy.signers.map((s) => ({
      ...s,
      fileAttribRefs: s.fileAttribRefs?.filter((ref) => ref !== ruleId),
    })),

    // 3. Remove from scenario fileRuleRefs and exception lists
    signingScenarios: policy.signingScenarios.map((sc) => ({
      ...sc,
      fileRuleRefs: sc.fileRuleRefs.filter((ref) => ref !== ruleId),
      allowedSigners: sc.allowedSigners.map((as) => ({
        ...as,
        exceptDenyRuleIds: as.exceptDenyRuleIds?.filter((ref) => ref !== ruleId),
      })),
      deniedSigners: sc.deniedSigners.map((ds) => ({
        ...ds,
        exceptAllowRuleIds: ds.exceptAllowRuleIds?.filter((ref) => ref !== ruleId),
      })),
    })),
  };
}

// ---------------------------------------------------------------------------
// Delete signer — removes the signer and cleans every reference to it
// ---------------------------------------------------------------------------

export function deleteSigner(policy: WdacPolicy, signerId: string): WdacPolicy {
  return {
    ...policy,
    // 1. Remove the signer itself
    signers: policy.signers.filter((s) => s.id !== signerId),

    // 2. Remove from scenario allowed/denied signer lists
    signingScenarios: policy.signingScenarios.map((sc) => ({
      ...sc,
      allowedSigners: sc.allowedSigners.filter((as) => as.signerId !== signerId),
      deniedSigners: sc.deniedSigners.filter((ds) => ds.signerId !== signerId),
    })),

    // 3. Remove from policy-level signer lists
    updatePolicySigners: policy.updatePolicySigners.filter((id) => id !== signerId),
    ciSigners: policy.ciSigners.filter((id) => id !== signerId),
  };
}

// ---------------------------------------------------------------------------
// Add file rule — appends the rule and registers it in selected scenarios
// ---------------------------------------------------------------------------

export interface AddFileRuleOptions {
  rule: WdacFileRuleNoId;
  /** Which signing scenario values (131 / 12) to register the rule in. */
  scenarioValues: SigningScenarioValue[];
}

export function addFileRule(
  policy: WdacPolicy,
  options: AddFileRuleOptions
): WdacPolicy {
  const id = generateFileRuleId(
    options.rule.kind === "fileAttrib"
      ? "fileAttrib"
      : options.rule.effect
  );
  const newRule = { ...options.rule, id } as WdacFileRule;

  const scenarioSet = new Set(options.scenarioValues);

  // Ensure every requested scenario exists; create a minimal one if missing
  const existingValues = new Set(policy.signingScenarios.map((sc) => sc.value));
  const missingScenarios: WdacSigningScenario[] = [];
  for (const sv of options.scenarioValues) {
    if (!existingValues.has(sv)) {
      missingScenarios.push({
        value: sv,
        id: String(sv === 131 ? 0 : 1),
        allowedSigners: [],
        deniedSigners: [],
        fileRuleRefs: [],
      });
    }
  }

  const allScenarios = [...policy.signingScenarios, ...missingScenarios];

  return {
    ...policy,
    fileRules: [...policy.fileRules, newRule],
    signingScenarios: allScenarios.map((sc) =>
      scenarioSet.has(sc.value)
        ? { ...sc, fileRuleRefs: [...sc.fileRuleRefs, id] }
        : sc
    ),
  };
}

// ---------------------------------------------------------------------------
// Add signer rule — appends the signer and registers it in selected scenarios
// ---------------------------------------------------------------------------

export interface AddSignerScenarioEntry {
  scenarioValue: SigningScenarioValue;
  effect: "Allow" | "Deny";
}

export interface AddSignerOptions {
  signer: Omit<WdacSignerRule, "id">;
  /** Per-scenario effect assignments. */
  scenarioEntries: AddSignerScenarioEntry[];
}

export function addSigner(
  policy: WdacPolicy,
  options: AddSignerOptions
): WdacPolicy {
  const id = generateSignerId();
  const newSigner: WdacSignerRule = { ...options.signer, id };

  // Ensure requested scenarios exist
  const existingValues = new Set(policy.signingScenarios.map((sc) => sc.value));
  const missingScenarios: WdacSigningScenario[] = [];
  for (const { scenarioValue } of options.scenarioEntries) {
    if (!existingValues.has(scenarioValue)) {
      missingScenarios.push({
        value: scenarioValue,
        id: String(scenarioValue === 131 ? 0 : 1),
        allowedSigners: [],
        deniedSigners: [],
        fileRuleRefs: [],
      });
    }
  }

  const allScenarios = [...policy.signingScenarios, ...missingScenarios];

  // Build lookup: scenarioValue → effect
  const entryMap = new Map<SigningScenarioValue, "Allow" | "Deny">(
    options.scenarioEntries.map((e) => [e.scenarioValue, e.effect])
  );

  const allowedRef: AllowedSigner = { signerId: id };
  const deniedRef: DeniedSigner = { signerId: id };

  return {
    ...policy,
    signers: [...policy.signers, newSigner],
    signingScenarios: allScenarios.map((sc) => {
      const effect = entryMap.get(sc.value);
      if (!effect) return sc;
      return {
        ...sc,
        allowedSigners:
          effect === "Allow" ? [...sc.allowedSigners, allowedRef] : sc.allowedSigners,
        deniedSigners:
          effect === "Deny" ? [...sc.deniedSigners, deniedRef] : sc.deniedSigners,
      };
    }),
  };
}
