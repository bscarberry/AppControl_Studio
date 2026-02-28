/**
 * WDAC Policy Semantic Comparator
 *
 * Compares two normalized WdacPolicy objects at the security-meaning level,
 * not just the structural field level. Answers: "what does each change mean
 * for trust, enforcement, and attack surface?"
 *
 * Pipeline:
 *  1. Index both policies (by ID and by semantic fingerprint)
 *  2. Rule equivalence matching (ID → fingerprint fallback)
 *  3. Classify each diff as added / removed / modified
 *  4. Assign trust direction, risk delta, and severity per change
 *  5. Detect signer scope changes (FileAttrib added/removed/widened)
 *  6. Annotate options with security impact
 *  7. Aggregate risk across all changes
 *  8. Generate plain-language human explanation
 *
 * Risk delta sign convention:
 *   Positive = right policy is more permissive (higher risk) than left
 *   Negative = right policy is more restrictive (lower risk) than left
 *
 * Reference: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create
 */

import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  WdacFileAttrib,
  WdacHashRule,
  WdacPathRule,
  WdacPackageRule,
  WdacAttributeRule,
} from "@appcontrol/shared";
import { POLICY_RULE_OPTIONS } from "@appcontrol/shared";
import type {
  PolicySemanticDiff,
  DiffedRule,
  ModifiedRule,
  OptionSemanticChange,
  RiskAssessment,
  HumanExplanation,
  TrustDirection,
  FindingSeverity,
  SignerScopeChange,
  RiskFactor,
  RiskVerdict,
} from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Risk delta constants
// ---------------------------------------------------------------------------

const RISK = {
  // File rules — hash
  HASH_ALLOW_ADDED: 12,
  HASH_ALLOW_REMOVED: -8,
  HASH_DENY_ADDED: -8,
  HASH_DENY_REMOVED: 18,    // Explicit block removed — may cover malware

  // File rules — path
  PATH_ALLOW_ADDED: 25,
  PATH_ALLOW_ADDED_TEMP: 55, // Temp/downloads — critical
  PATH_ALLOW_REMOVED: -15,
  PATH_DENY_ADDED: -10,
  PATH_DENY_REMOVED: 22,

  // File rules — package (UWP)
  PACKAGE_ALLOW_ADDED: 14,
  PACKAGE_ALLOW_REMOVED: -10,
  PACKAGE_DENY_ADDED: -5,
  PACKAGE_DENY_REMOVED: 10,

  // File rules — attribute (no hash/path)
  ATTRIBUTE_ALLOW_ADDED: 20,
  ATTRIBUTE_ALLOW_REMOVED: -12,
  ATTRIBUTE_DENY_ADDED: -8,
  ATTRIBUTE_DENY_REMOVED: 15,

  // Signer rules — kernel mode (131)
  KERNEL_SIGNER_ALLOW_ADDED_UNSCOPED: 80,
  KERNEL_SIGNER_ALLOW_ADDED_SCOPED: 55,
  KERNEL_SIGNER_ALLOW_REMOVED_UNSCOPED: -45,
  KERNEL_SIGNER_ALLOW_REMOVED_SCOPED: -30,
  KERNEL_SIGNER_DENY_ADDED: -35,
  KERNEL_SIGNER_DENY_REMOVED: 60,

  // Signer rules — user mode (12)
  USER_SIGNER_ALLOW_ADDED_UNSCOPED: 35,
  USER_SIGNER_ALLOW_ADDED_SCOPED: 18,
  USER_SIGNER_ALLOW_REMOVED_UNSCOPED: -20,
  USER_SIGNER_ALLOW_REMOVED_SCOPED: -12,
  USER_SIGNER_DENY_ADDED: -15,
  USER_SIGNER_DENY_REMOVED: 25,

  // Signer scope changes (separate from base risk)
  SCOPE_REMOVED: 22,   // FileAttrib removed — all publisher binaries now trusted
  SCOPE_ADDED: -18,    // FileAttrib added — scope narrowed
  SCOPE_BROADENED: 12, // Existing scope made less specific
  SCOPE_NARROWED: -8,  // Existing scope made more specific
  CERT_ANCHOR_CHANGED: 30, // certRoot changed — different trust anchor

  // Options
  AUDIT_ENABLED: 30,
  ENFORCEMENT_ENABLED: -40,
  UMCI_DISABLED: 60,
  UMCI_ENABLED: -40,
  SCRIPT_ENFORCEMENT_DISABLED: 20,
  SCRIPT_ENFORCEMENT_ENABLED: -15,
  RUNTIME_FILEPATH_PROTECTION_DISABLED: 15,
  RUNTIME_FILEPATH_PROTECTION_ENABLED: -10,
  ADVANCED_BOOT_MENU_ENABLED: 10,
  DEBUG_POLICY_ENABLED: 40,
  ISG_ENABLED: -5,
  ISG_DISABLED: 5,
  MANAGED_INSTALLER_ENABLED: -3,
  UNSIGNED_POLICY_ENABLED: 8,
  UNSIGNED_POLICY_DISABLED: -5,
} as const;

// ---------------------------------------------------------------------------
// Policy indexing structures
// ---------------------------------------------------------------------------

interface PolicyIndex {
  fileRulesById: Map<string, WdacFileRule>;
  signersById: Map<string, WdacSignerRule>;
  fileAttribsById: Map<string, WdacFileAttrib>;
  /** signerIds that appear in scenario 131 (kernel) allowedSigners */
  kernelAllowedSignerIds: Set<string>;
  /** signerIds that appear in scenario 12 (user) allowedSigners */
  userAllowedSignerIds: Set<string>;
  /** signerIds in kernel denied */
  kernelDeniedSignerIds: Set<string>;
  /** signerIds in user denied */
  userDeniedSignerIds: Set<string>;
  /** fileRuleIds referenced in kernel scenario fileRuleRefs */
  kernelFileRuleIds: Set<string>;
  /** fileRuleIds referenced in user scenario fileRuleRefs */
  userFileRuleIds: Set<string>;
  /** Semantic fingerprint → rule ID */
  fileRuleByFingerprint: Map<string, string>;
  signerByFingerprint: Map<string, string>;
  /** Effective mode */
  isAuditMode: boolean;
}

function buildIndex(policy: WdacPolicy): PolicyIndex {
  const fileRulesById = new Map(policy.fileRules.map((r) => [r.id, r]));
  const signersById = new Map(policy.signers.map((s) => [s.id, s]));

  const fileAttribsById = new Map<string, WdacFileAttrib>();
  for (const rule of policy.fileRules) {
    if (rule.kind === "fileAttrib") {
      fileAttribsById.set(rule.id, rule);
    }
  }

  const kernelAllowedSignerIds = new Set<string>();
  const userAllowedSignerIds = new Set<string>();
  const kernelDeniedSignerIds = new Set<string>();
  const userDeniedSignerIds = new Set<string>();
  const kernelFileRuleIds = new Set<string>();
  const userFileRuleIds = new Set<string>();

  for (const scenario of policy.signingScenarios) {
    const isKernel = scenario.value === 131;
    for (const { signerId } of scenario.allowedSigners) {
      (isKernel ? kernelAllowedSignerIds : userAllowedSignerIds).add(signerId);
    }
    for (const { signerId } of scenario.deniedSigners) {
      (isKernel ? kernelDeniedSignerIds : userDeniedSignerIds).add(signerId);
    }
    for (const ref of scenario.fileRuleRefs) {
      (isKernel ? kernelFileRuleIds : userFileRuleIds).add(ref);
    }
  }

  const fileRuleByFingerprint = new Map<string, string>();
  for (const rule of policy.fileRules) {
    if (rule.kind !== "fileAttrib") {
      fileRuleByFingerprint.set(fileRuleSemanticKey(rule), rule.id);
    }
  }

  const signerByFingerprint = new Map<string, string>();
  for (const signer of policy.signers) {
    signerByFingerprint.set(signerSemanticKey(signer), signer.id);
  }

  const isAuditMode = policy.options.some(
    (o) => (o.value as number) === 3 && o.enabled
  );

  return {
    fileRulesById,
    signersById,
    fileAttribsById,
    kernelAllowedSignerIds,
    userAllowedSignerIds,
    kernelDeniedSignerIds,
    userDeniedSignerIds,
    kernelFileRuleIds,
    userFileRuleIds,
    fileRuleByFingerprint,
    signerByFingerprint,
    isAuditMode,
  };
}

// ---------------------------------------------------------------------------
// Semantic fingerprinting — rule equivalence without ID
// ---------------------------------------------------------------------------

function fileRuleSemanticKey(rule: WdacFileRule): string {
  switch (rule.kind) {
    case "hash":
      return `hash:${rule.effect}:${rule.hashType}:${rule.hash}`;
    case "path":
      return `path:${rule.effect}:${rule.filePath.toLowerCase()}`;
    case "package":
      return `pkg:${rule.effect}:${rule.packageFamilyName.toLowerCase()}`;
    case "attribute": {
      const r = rule as WdacAttributeRule;
      return [
        "attr",
        rule.effect,
        r.fileName ?? "",
        r.internalName ?? "",
        r.fileDescription ?? "",
        r.productName ?? "",
        r.minimumFileVersion ?? "",
        r.maximumFileVersion ?? "",
      ].join(":");
    }
    case "fileAttrib": {
      const r = rule as WdacFileAttrib;
      return [
        "fa",
        r.fileName ?? "",
        r.internalName ?? "",
        r.productName ?? "",
      ].join(":");
    }
  }
}

function signerSemanticKey(signer: WdacSignerRule): string {
  return [
    signer.certRoot?.value ?? "",
    signer.certPublisher ?? "",
    signer.certIssuer ?? "",
    signer.certOemID ?? "",
  ].join("::");
}

// ---------------------------------------------------------------------------
// Signing scenario helpers
// ---------------------------------------------------------------------------

function signerScenarios(
  signerId: string,
  idx: PolicyIndex
): Array<"kernel" | "user"> {
  const scenarios: Array<"kernel" | "user"> = [];
  if (idx.kernelAllowedSignerIds.has(signerId) || idx.kernelDeniedSignerIds.has(signerId))
    scenarios.push("kernel");
  if (idx.userAllowedSignerIds.has(signerId) || idx.userDeniedSignerIds.has(signerId))
    scenarios.push("user");
  return scenarios.length > 0 ? scenarios : ["user"]; // default user if not referenced
}

function fileRuleScenarios(
  ruleId: string,
  idx: PolicyIndex
): Array<"kernel" | "user"> {
  const scenarios: Array<"kernel" | "user"> = [];
  if (idx.kernelFileRuleIds.has(ruleId)) scenarios.push("kernel");
  if (idx.userFileRuleIds.has(ruleId)) scenarios.push("user");
  return scenarios.length > 0 ? scenarios : ["user"];
}

function signerEffect(
  signerId: string,
  idx: PolicyIndex
): "Allow" | "Deny" {
  if (idx.kernelDeniedSignerIds.has(signerId) || idx.userDeniedSignerIds.has(signerId))
    return "Deny";
  return "Allow";
}

// ---------------------------------------------------------------------------
// FileAttrib resolution and scope description
// ---------------------------------------------------------------------------

function resolveFileAttribs(
  signer: WdacSignerRule,
  idx: PolicyIndex
): WdacFileAttrib[] {
  if (!signer.fileAttribRefs || signer.fileAttribRefs.length === 0) return [];
  return signer.fileAttribRefs
    .map((ref) => idx.fileAttribsById.get(ref))
    .filter((fa): fa is WdacFileAttrib => fa !== undefined);
}

function describeAttribs(attribs: WdacFileAttrib[]): string {
  if (attribs.length === 0) return "All files from publisher (no scope restriction)";
  const parts: string[] = [];
  for (const a of attribs) {
    const constraints: string[] = [];
    if (a.productName) constraints.push(`product="${a.productName}"`);
    if (a.internalName) constraints.push(`internalName="${a.internalName}"`);
    if (a.fileName) constraints.push(`fileName="${a.fileName}"`);
    if (a.fileDescription) constraints.push(`description="${a.fileDescription}"`);
    if (a.minimumFileVersion) constraints.push(`version>=${a.minimumFileVersion}`);
    if (a.maximumFileVersion) constraints.push(`version<=${a.maximumFileVersion}`);
    parts.push(constraints.join(", ") || "(empty FileAttrib)");
  }
  return parts.join("; ");
}

// ---------------------------------------------------------------------------
// Signer scope comparison
// ---------------------------------------------------------------------------

function compareSignerScope(
  leftSigner: WdacSignerRule,
  rightSigner: WdacSignerRule,
  leftIdx: PolicyIndex,
  rightIdx: PolicyIndex
): SignerScopeChange {
  const leftAttribs = resolveFileAttribs(leftSigner, leftIdx);
  const rightAttribs = resolveFileAttribs(rightSigner, rightIdx);
  const leftHasScope = leftAttribs.length > 0;
  const rightHasScope = rightAttribs.length > 0;

  // Cert anchor changed — most significant change
  const leftCertRoot = leftSigner.certRoot?.value ?? "";
  const rightCertRoot = rightSigner.certRoot?.value ?? "";
  const leftPub = leftSigner.certPublisher ?? leftSigner.name ?? "";
  const rightPub = rightSigner.certPublisher ?? rightSigner.name ?? "";

  if (leftCertRoot !== rightCertRoot && leftCertRoot && rightCertRoot) {
    return {
      direction: "cert-changed",
      scopeBefore: `Publisher: "${leftPub}", Root TBS: ${leftCertRoot.substring(0, 16)}…`,
      scopeAfter: `Publisher: "${rightPub}", Root TBS: ${rightCertRoot.substring(0, 16)}…`,
      detail:
        `The certificate trust anchor (root TBS hash) changed from ${leftCertRoot.substring(0, 16)}… ` +
        `to ${rightCertRoot.substring(0, 16)}… — this is a fundamentally different trust relationship. ` +
        "The new rule trusts a different certificate root than the original.",
      riskDelta: RISK.CERT_ANCHOR_CHANGED,
    };
  }

  if (!leftHasScope && rightHasScope) {
    return {
      direction: "narrowed",
      scopeBefore: "All files from publisher (no FileAttrib scope restriction)",
      scopeAfter: describeAttribs(rightAttribs),
      detail:
        "FileAttrib scoping was ADDED in the candidate policy. The publisher trust has been " +
        "narrowed — only files matching the FileAttrib constraints are now trusted. " +
        "This is a positive security change (least-permissive signer trust).",
      riskDelta: RISK.SCOPE_ADDED,
    };
  }

  if (leftHasScope && !rightHasScope) {
    return {
      direction: "broadened",
      scopeBefore: describeAttribs(leftAttribs),
      scopeAfter: "All files from publisher (no FileAttrib scope restriction)",
      detail:
        "FileAttrib scoping was REMOVED in the candidate policy. The publisher trust has been " +
        "broadened — ALL binaries from this publisher are now trusted, not just those matching " +
        "the previous FileAttrib constraints. This is a trust-broadening change.",
      riskDelta: RISK.SCOPE_REMOVED,
    };
  }

  if (leftHasScope && rightHasScope) {
    const leftDesc = describeAttribs(leftAttribs);
    const rightDesc = describeAttribs(rightAttribs);

    if (leftDesc === rightDesc) {
      return {
        direction: "unchanged",
        scopeBefore: leftDesc,
        scopeAfter: rightDesc,
        detail: "FileAttrib scope is semantically unchanged.",
        riskDelta: 0,
      };
    }

    // Heuristic: if the right scope has fewer constraints, it's broader
    const leftConstraintCount = leftAttribs.reduce(
      (n, a) =>
        n +
        [a.productName, a.internalName, a.fileName, a.fileDescription,
          a.minimumFileVersion, a.maximumFileVersion].filter(Boolean).length,
      0
    );
    const rightConstraintCount = rightAttribs.reduce(
      (n, a) =>
        n +
        [a.productName, a.internalName, a.fileName, a.fileDescription,
          a.minimumFileVersion, a.maximumFileVersion].filter(Boolean).length,
      0
    );

    if (rightConstraintCount < leftConstraintCount) {
      return {
        direction: "broadened",
        scopeBefore: leftDesc,
        scopeAfter: rightDesc,
        detail:
          "FileAttrib scope was made LESS specific — fewer constraints are applied, " +
          "trusting a broader set of files from this publisher.",
        riskDelta: RISK.SCOPE_BROADENED,
      };
    }

    if (rightConstraintCount > leftConstraintCount) {
      return {
        direction: "narrowed",
        scopeBefore: leftDesc,
        scopeAfter: rightDesc,
        detail:
          "FileAttrib scope was made MORE specific — additional constraints are applied, " +
          "restricting trust to a narrower set of files from this publisher.",
        riskDelta: RISK.SCOPE_NARROWED,
      };
    }

    return {
      direction: "scope-replaced",
      scopeBefore: leftDesc,
      scopeAfter: rightDesc,
      detail:
        "FileAttrib scope content changed — the scope targets different file attributes. " +
        "Review to determine if the new scope is broader or narrower than the original.",
      riskDelta: 0,
    };
  }

  return {
    direction: "unchanged",
    scopeBefore: "No scope restriction",
    scopeAfter: "No scope restriction",
    detail: "No FileAttrib scope on either side.",
    riskDelta: 0,
  };
}

// ---------------------------------------------------------------------------
// Risk delta calculation for added/removed file rules
// ---------------------------------------------------------------------------

function fileRuleRiskDelta(
  rule: WdacFileRule,
  action: "added" | "removed",
  isKernel: boolean
): { delta: number; trustDirection: TrustDirection } {
  // For kernel-mode file rules, scale up risk
  const kernelScale = isKernel ? 1.5 : 1.0;

  if (rule.kind === "fileAttrib") {
    return { delta: 0, trustDirection: "neutral" };
  }

  const effect = (rule as WdacHashRule | WdacPathRule | WdacPackageRule | WdacAttributeRule).effect;
  const isAllow = effect === "Allow";
  const isAdded = action === "added";

  // Allow added → broadened, Allow removed → tightened
  // Deny added → tightened, Deny removed → broadened
  const trustDirection: TrustDirection =
    (isAllow && isAdded) || (!isAllow && !isAdded)
      ? "broadened"
      : "tightened";

  let baseDelta = 0;

  switch (rule.kind) {
    case "hash": {
      if (isAllow && isAdded) baseDelta = RISK.HASH_ALLOW_ADDED;
      else if (isAllow && !isAdded) baseDelta = RISK.HASH_ALLOW_REMOVED;
      else if (!isAllow && isAdded) baseDelta = RISK.HASH_DENY_ADDED;
      else baseDelta = RISK.HASH_DENY_REMOVED;
      break;
    }
    case "path": {
      const fp = ((rule as WdacPathRule).filePath ?? "").toLowerCase();
      const isTemp = fp.includes("\\temp\\") || fp.includes("\\tmp\\") || fp.includes("\\downloads\\");
      if (isAllow && isAdded) baseDelta = isTemp ? RISK.PATH_ALLOW_ADDED_TEMP : RISK.PATH_ALLOW_ADDED;
      else if (isAllow && !isAdded) baseDelta = RISK.PATH_ALLOW_REMOVED;
      else if (!isAllow && isAdded) baseDelta = RISK.PATH_DENY_ADDED;
      else baseDelta = RISK.PATH_DENY_REMOVED;
      break;
    }
    case "package": {
      if (isAllow && isAdded) baseDelta = RISK.PACKAGE_ALLOW_ADDED;
      else if (isAllow && !isAdded) baseDelta = RISK.PACKAGE_ALLOW_REMOVED;
      else if (!isAllow && isAdded) baseDelta = RISK.PACKAGE_DENY_ADDED;
      else baseDelta = RISK.PACKAGE_DENY_REMOVED;
      break;
    }
    case "attribute": {
      if (isAllow && isAdded) baseDelta = RISK.ATTRIBUTE_ALLOW_ADDED;
      else if (isAllow && !isAdded) baseDelta = RISK.ATTRIBUTE_ALLOW_REMOVED;
      else if (!isAllow && isAdded) baseDelta = RISK.ATTRIBUTE_DENY_ADDED;
      else baseDelta = RISK.ATTRIBUTE_DENY_REMOVED;
      break;
    }
  }

  return { delta: Math.round(baseDelta * kernelScale), trustDirection };
}

// ---------------------------------------------------------------------------
// Risk delta calculation for added/removed signer rules
// ---------------------------------------------------------------------------

function signerRiskDelta(
  hasScope: boolean,
  effect: "Allow" | "Deny",
  action: "added" | "removed",
  isKernel: boolean
): { delta: number; trustDirection: TrustDirection } {
  const isAllow = effect === "Allow";
  const isAdded = action === "added";

  const trustDirection: TrustDirection =
    (isAllow && isAdded) || (!isAllow && !isAdded)
      ? "broadened"
      : "tightened";

  let delta = 0;

  if (isKernel) {
    if (isAllow && isAdded) delta = hasScope ? RISK.KERNEL_SIGNER_ALLOW_ADDED_SCOPED : RISK.KERNEL_SIGNER_ALLOW_ADDED_UNSCOPED;
    else if (isAllow && !isAdded) delta = hasScope ? RISK.KERNEL_SIGNER_ALLOW_REMOVED_SCOPED : RISK.KERNEL_SIGNER_ALLOW_REMOVED_UNSCOPED;
    else if (!isAllow && isAdded) delta = RISK.KERNEL_SIGNER_DENY_ADDED;
    else delta = RISK.KERNEL_SIGNER_DENY_REMOVED;
  } else {
    if (isAllow && isAdded) delta = hasScope ? RISK.USER_SIGNER_ALLOW_ADDED_SCOPED : RISK.USER_SIGNER_ALLOW_ADDED_UNSCOPED;
    else if (isAllow && !isAdded) delta = hasScope ? RISK.USER_SIGNER_ALLOW_REMOVED_SCOPED : RISK.USER_SIGNER_ALLOW_REMOVED_UNSCOPED;
    else if (!isAllow && isAdded) delta = RISK.USER_SIGNER_DENY_ADDED;
    else delta = RISK.USER_SIGNER_DENY_REMOVED;
  }

  return { delta, trustDirection };
}

// ---------------------------------------------------------------------------
// Severity from risk delta magnitude
// ---------------------------------------------------------------------------

function severityFromDelta(delta: number): FindingSeverity {
  const abs = Math.abs(delta);
  if (abs >= 55) return "critical";
  if (abs >= 30) return "high";
  if (abs >= 15) return "medium";
  if (abs >= 5)  return "low";
  return "info";
}

// ---------------------------------------------------------------------------
// Explanation builders
// ---------------------------------------------------------------------------

function explainFileRuleAdded(rule: WdacFileRule, scenarios: Array<"kernel" | "user">): string {
  const mode = scenarios.includes("kernel") ? "kernel-mode" : "user-mode";
  const effect = (rule as { effect?: string }).effect ?? "Allow";

  switch (rule.kind) {
    case "hash": {
      const r = rule as WdacHashRule;
      const name = r.fileName ? `"${r.fileName}"` : `hash ${r.hash.substring(0, 16)}…`;
      return (
        `A new ${effect} hash rule was added for ${name} (${r.hashType}) in ${mode} context. ` +
        (effect === "Allow"
          ? "This specific binary version can now execute. The rule will break when the file is updated."
          : "This specific binary version is now explicitly blocked from executing.")
      );
    }
    case "path": {
      const r = rule as WdacPathRule;
      const lp = r.filePath.toLowerCase();
      const isTemp = lp.includes("\\temp\\") || lp.includes("\\tmp\\") || lp.includes("\\downloads\\");
      return (
        `A new ${effect} path rule was added for "${r.filePath}" in ${mode} context. ` +
        (effect === "Allow"
          ? `Any binary in this path can now execute. ` +
            (isTemp
              ? "WARNING: This path is a user-writable temporary directory — extremely high risk."
              : "Path rules can be bypassed if an attacker can write to this location.")
          : "Binaries at this path are now explicitly blocked from executing.")
      );
    }
    case "package": {
      const r = rule as WdacPackageRule;
      return (
        `A new ${effect} package rule was added for UWP family "${r.packageFamilyName}". ` +
        (effect === "Allow"
          ? "This app package (and its declared version) can now execute."
          : "This app package is now explicitly blocked.")
      );
    }
    case "attribute": {
      const r = rule as WdacAttributeRule;
      const attrs = [r.productName, r.fileName, r.internalName].filter(Boolean).join(", ");
      return (
        `A new ${effect} attribute rule was added for files matching: ${attrs || "(metadata attributes)"}. ` +
        (effect === "Allow"
          ? "Any file matching these metadata attributes can execute — no hash or certificate verification."
          : "Files matching these metadata attributes are now explicitly blocked.")
      );
    }
    case "fileAttrib":
      return "A FileAttrib descriptor was added (used for signer scoping, no direct Allow/Deny effect).";
  }
}

function explainFileRuleRemoved(rule: WdacFileRule, scenarios: Array<"kernel" | "user">): string {
  const mode = scenarios.includes("kernel") ? "kernel-mode" : "user-mode";
  const effect = (rule as { effect?: string }).effect ?? "Allow";

  switch (rule.kind) {
    case "hash": {
      const r = rule as WdacHashRule;
      const name = r.fileName ? `"${r.fileName}"` : `hash ${r.hash.substring(0, 16)}…`;
      return (
        `The ${effect} hash rule for ${name} was removed from ${mode} context. ` +
        (effect === "Allow"
          ? "This binary can no longer execute unless covered by another rule."
          : "The explicit block for this binary was removed — it may now execute if permitted by other rules.")
      );
    }
    case "path": {
      const r = rule as WdacPathRule;
      return (
        `The ${effect} path rule for "${r.filePath}" was removed from ${mode} context. ` +
        (effect === "Allow"
          ? "Binaries at this path can no longer execute unless covered by other rules."
          : "The explicit path block was removed.")
      );
    }
    case "package": {
      const r = rule as WdacPackageRule;
      return (
        `The ${effect} package rule for "${r.packageFamilyName}" was removed. ` +
        (effect === "Allow"
          ? "This UWP app package is no longer explicitly permitted."
          : "The explicit block for this package was removed.")
      );
    }
    case "attribute": {
      return (
        `An ${effect} attribute rule was removed. ` +
        (effect === "Allow"
          ? "Files that matched these metadata attributes are no longer explicitly permitted."
          : "The attribute-based block was removed.")
      );
    }
    case "fileAttrib":
      return "A FileAttrib descriptor was removed (scoping reference).";
  }
}

function explainSignerAdded(
  signer: WdacSignerRule,
  effect: "Allow" | "Deny",
  scenarios: Array<"kernel" | "user">,
  attribs: WdacFileAttrib[]
): string {
  const isKernel = scenarios.includes("kernel");
  const mode = isKernel ? "kernel-mode" : "user-mode";
  const publisher = signer.certPublisher ?? signer.name ?? "(unknown publisher)";
  const hasScope = attribs.length > 0;
  const scopeDesc = hasScope ? describeAttribs(attribs) : "all binaries from this publisher";

  if (effect === "Allow") {
    return (
      `A new ${mode} ${hasScope ? "scoped" : "unscoped"} allow-signer rule was added for "${publisher}". ` +
      `It trusts: ${scopeDesc}. ` +
      (isKernel
        ? "CRITICAL: Kernel-mode signer trust allows device drivers to load. A malicious or compromised driver can fully compromise the operating system."
        : hasScope
          ? "Scoped publisher trust limits exposure to specific product/filename attributes."
          : "Unscoped publisher trust allows ALL software from this publisher to execute — including future or unrelated releases.")
    );
  } else {
    return (
      `A new ${mode} deny-signer rule was added for "${publisher}" (${scopeDesc}). ` +
      "Binaries from this publisher matching these criteria will be explicitly blocked from executing. " +
      (isKernel ? "This prevents kernel-mode drivers from this publisher from loading." : "")
    );
  }
}

function explainSignerRemoved(
  signer: WdacSignerRule,
  effect: "Allow" | "Deny",
  scenarios: Array<"kernel" | "user">,
  attribs: WdacFileAttrib[]
): string {
  const isKernel = scenarios.includes("kernel");
  const mode = isKernel ? "kernel-mode" : "user-mode";
  const publisher = signer.certPublisher ?? signer.name ?? "(unknown publisher)";
  const hasScope = attribs.length > 0;
  const scopeDesc = hasScope ? describeAttribs(attribs) : "all binaries from this publisher";

  if (effect === "Allow") {
    return (
      `The ${mode} allow-signer rule for "${publisher}" (${scopeDesc}) was removed. ` +
      "Binaries from this publisher can no longer execute unless covered by other rules. " +
      (isKernel ? "Kernel-mode drivers from this publisher will no longer load." : "")
    );
  } else {
    return (
      `The ${mode} deny-signer rule for "${publisher}" (${scopeDesc}) was removed. ` +
      "Binaries from this publisher matching these criteria are no longer explicitly blocked. " +
      "If no other deny rule applies, they may now execute."
    );
  }
}

// ---------------------------------------------------------------------------
// Option impact map
// ---------------------------------------------------------------------------

interface OptionImpact {
  onEnable: { riskDelta: number; trustDirection: TrustDirection; severity: FindingSeverity; explanation: string } | null;
  onDisable: { riskDelta: number; trustDirection: TrustDirection; severity: FindingSeverity; explanation: string } | null;
}

const OPTION_IMPACTS: Record<number, OptionImpact> = {
  0: {
    onEnable: {
      riskDelta: RISK.UMCI_ENABLED,
      trustDirection: "tightened",
      severity: "high",
      explanation:
        "User-mode code integrity (UMCI) enforcement is now ENABLED. All user-mode applications must pass the App Control policy check before executing.",
    },
    onDisable: {
      riskDelta: RISK.UMCI_DISABLED,
      trustDirection: "broadened",
      severity: "critical",
      explanation:
        "CRITICAL: User-mode code integrity (UMCI) has been DISABLED. Only kernel-mode code is now subject to App Control enforcement. User-mode applications — including all desktop apps and scripts — can execute without any policy check.",
    },
  },
  3: {
    onEnable: {
      riskDelta: RISK.AUDIT_ENABLED,
      trustDirection: "neutral",
      severity: "high",
      explanation:
        "Audit Mode (Option 3) was ENABLED. The policy now runs in audit mode — violations are logged to the event log but nothing is blocked. This significantly reduces the enforcement effectiveness of the policy.",
    },
    onDisable: {
      riskDelta: RISK.ENFORCEMENT_ENABLED,
      trustDirection: "neutral",
      severity: "medium",
      explanation:
        "Audit Mode (Option 3) was DISABLED. The policy is now in enforcement mode — violations will block execution, not just log events. Enforcement effectiveness is increased.",
    },
  },
  6: {
    onEnable: {
      riskDelta: RISK.UNSIGNED_POLICY_ENABLED,
      trustDirection: "broadened",
      severity: "low",
      explanation:
        "Unsigned System Integrity Policy (Option 6) is now ENABLED. Unsigned App Control policy files can be loaded, which may allow policy tampering if an attacker gains administrative access.",
    },
    onDisable: {
      riskDelta: RISK.UNSIGNED_POLICY_DISABLED,
      trustDirection: "tightened",
      severity: "info",
      explanation:
        "Unsigned System Integrity Policy (Option 6) is now DISABLED. Policy files must be signed, preventing unauthorized policy modifications.",
    },
  },
  7: {
    onEnable: {
      riskDelta: RISK.DEBUG_POLICY_ENABLED,
      trustDirection: "broadened",
      severity: "high",
      explanation:
        "Debug Policy Augmented (Option 7) was ENABLED. The kernel debugger can augment the App Control policy. This should never be enabled in production — it allows bypassing the policy through the debugger.",
    },
    onDisable: null,
  },
  9: {
    onEnable: {
      riskDelta: RISK.ADVANCED_BOOT_MENU_ENABLED,
      trustDirection: "broadened",
      severity: "low",
      explanation:
        "Advanced Boot Options Menu (Option 9) was ENABLED. Users can access the advanced boot menu, which includes options that may allow bypassing App Control enforcement (e.g., disabling driver signing enforcement).",
    },
    onDisable: null,
  },
  11: {
    onEnable: {
      riskDelta: RISK.SCRIPT_ENFORCEMENT_DISABLED,
      trustDirection: "broadened",
      severity: "medium",
      explanation:
        "Script Enforcement (Option 11) was DISABLED. PowerShell, Windows Script Host, and similar interpreters are no longer subject to App Control policy checks. Scripts can execute regardless of policy rules.",
    },
    onDisable: {
      riskDelta: RISK.SCRIPT_ENFORCEMENT_ENABLED,
      trustDirection: "tightened",
      severity: "info",
      explanation:
        "Script Enforcement (Option 11) was ENABLED (Option 11 disabled). PowerShell, WSH, and script interpreters are now subject to App Control enforcement.",
    },
  },
  14: {
    onEnable: {
      riskDelta: RISK.ISG_ENABLED,
      trustDirection: "neutral",
      severity: "info",
      explanation:
        "Intelligent Security Graph (ISG) authorization (Option 14) was ENABLED. Microsoft's cloud reputation service is now a trust source — files with good reputation will be allowed even without explicit rules.",
    },
    onDisable: {
      riskDelta: RISK.ISG_DISABLED,
      trustDirection: "neutral",
      severity: "info",
      explanation:
        "ISG authorization (Option 14) was DISABLED. Binaries previously trusted by cloud reputation will now need explicit rules to execute.",
    },
  },
  13: {
    onEnable: {
      riskDelta: RISK.MANAGED_INSTALLER_ENABLED,
      trustDirection: "neutral",
      severity: "info",
      explanation:
        "Managed Installer trust (Option 13) was ENABLED. Software installed by authorized managed installers (e.g., Intune, MECM) will be trusted without explicit rules.",
    },
    onDisable: null,
  },
  18: {
    onEnable: {
      riskDelta: RISK.RUNTIME_FILEPATH_PROTECTION_DISABLED,
      trustDirection: "broadened",
      severity: "medium",
      explanation:
        "Runtime FilePath Rule Protection (Option 18) was DISABLED. Path rules no longer require the target path to have strict ACLs. This makes path rules easier to bypass by placing malicious binaries in allowed locations.",
    },
    onDisable: {
      riskDelta: RISK.RUNTIME_FILEPATH_PROTECTION_ENABLED,
      trustDirection: "tightened",
      severity: "info",
      explanation:
        "Runtime FilePath Rule Protection (Option 18) was ENABLED. Path rules now require the allowed path to have strict ACLs, reducing the risk of path-based bypass.",
    },
  },
};

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

export function semanticComparePolicies(
  left: WdacPolicy,
  right: WdacPolicy
): PolicySemanticDiff {
  const leftIdx = buildIndex(left);
  const rightIdx = buildIndex(right);

  // -------- Phase 1: File rule diffs --------

  const addedFileRules: DiffedRule[] = [];
  const removedFileRules: DiffedRule[] = [];
  const modifiedFileRules: ModifiedRule[] = [];

  const allFileRuleIds = new Set([
    ...left.fileRules.map((r) => r.id),
    ...right.fileRules.map((r) => r.id),
  ]);

  // Track which IDs we've already processed via semantic match
  const semanticallyMatchedLeft = new Set<string>();
  const semanticallyMatchedRight = new Set<string>();

  for (const id of allFileRuleIds) {
    const l = leftIdx.fileRulesById.get(id);
    const r = rightIdx.fileRulesById.get(id);

    if (l && r) {
      // ID match — check for modification
      const changedFields = findChangedFileRuleFields(l, r);
      if (changedFields.length > 0) {
        const scenarios = fileRuleScenarios(id, rightIdx);
        const isKernel = scenarios.includes("kernel");
        // Estimate modification risk based on changed fields
        const { delta, trustDirection } = estimateModificationRisk(l, r, changedFields, isKernel);
        modifiedFileRules.push({
          id,
          matchKind: "id",
          ruleCategory: "file",
          leftRule: l,
          rightRule: r,
          changedFields,
          trustDirection,
          riskDelta: delta,
          severity: severityFromDelta(delta),
          affectsKernel: isKernel,
          explanation: explainFileRuleModified(l, r, changedFields, scenarios),
        });
      }
      semanticallyMatchedLeft.add(id);
      semanticallyMatchedRight.add(id);
    } else if (l && !r) {
      // Check if it moved (semantic fingerprint match)
      const fp = fileRuleSemanticKey(l);
      const rightId = rightIdx.fileRuleByFingerprint.get(fp);
      if (rightId && !semanticallyMatchedRight.has(rightId)) {
        // Same rule, different ID — treat as unchanged (just ID drift)
        semanticallyMatchedLeft.add(id);
        semanticallyMatchedRight.add(rightId);
        continue;
      }

      // Genuinely removed
      if (!semanticallyMatchedLeft.has(id)) {
        const scenarios = fileRuleScenarios(id, leftIdx);
        const isKernel = scenarios.includes("kernel");
        if (l.kind === "fileAttrib") continue; // FileAttribs are handled via signer scope
        const { delta, trustDirection } = fileRuleRiskDelta(l, "removed", isKernel);
        removedFileRules.push({
          id,
          matchKind: "unmatched",
          ruleCategory: "file",
          effect: (l as { effect?: "Allow" | "Deny" }).effect ?? "Allow",
          signingScenarios: scenarios,
          rule: l,
          trustDirection,
          riskDelta: delta,
          severity: severityFromDelta(delta),
          affectsKernel: isKernel,
          explanation: explainFileRuleRemoved(l, scenarios),
        });
      }
    } else if (!l && r) {
      // Check if it moved
      const fp = fileRuleSemanticKey(r);
      const leftId = leftIdx.fileRuleByFingerprint.get(fp);
      if (leftId && !semanticallyMatchedLeft.has(leftId)) {
        semanticallyMatchedLeft.add(leftId);
        semanticallyMatchedRight.add(id);
        continue;
      }

      // Genuinely added
      if (!semanticallyMatchedRight.has(id)) {
        const scenarios = fileRuleScenarios(id, rightIdx);
        const isKernel = scenarios.includes("kernel");
        if (r.kind === "fileAttrib") continue; // Handled via signer scope
        const { delta, trustDirection } = fileRuleRiskDelta(r, "added", isKernel);
        addedFileRules.push({
          id,
          matchKind: "unmatched",
          ruleCategory: "file",
          effect: (r as { effect?: "Allow" | "Deny" }).effect ?? "Allow",
          signingScenarios: scenarios,
          rule: r,
          trustDirection,
          riskDelta: delta,
          severity: severityFromDelta(delta),
          affectsKernel: isKernel,
          explanation: explainFileRuleAdded(r, scenarios),
        });
      }
    }
  }

  // -------- Phase 2: Signer rule diffs --------

  const addedSignerRules: DiffedRule[] = [];
  const removedSignerRules: DiffedRule[] = [];
  const modifiedSignerRules: ModifiedRule[] = [];

  const allSignerIds = new Set([
    ...left.signers.map((s) => s.id),
    ...right.signers.map((s) => s.id),
  ]);

  const semanticallyMatchedLeftSigner = new Set<string>();
  const semanticallyMatchedRightSigner = new Set<string>();

  for (const id of allSignerIds) {
    const l = leftIdx.signersById.get(id);
    const r = rightIdx.signersById.get(id);

    if (l && r) {
      // ID match — check for modification
      const changedFields = findChangedSignerFields(l, r);
      if (changedFields.length > 0) {
        const scenarios = signerScenarios(id, rightIdx);
        const isKernel = scenarios.includes("kernel");
        const scopeChange = compareSignerScope(l, r, leftIdx, rightIdx);
        const effect = signerEffect(id, rightIdx);

        // Base modification risk from scope change + cert anchor
        const modRiskDelta = scopeChange.riskDelta + (changedFields.includes("certRoot") ? RISK.CERT_ANCHOR_CHANGED : 0);
        const trustDirection: TrustDirection =
          scopeChange.direction === "broadened" || scopeChange.direction === "cert-changed"
            ? "broadened"
            : scopeChange.direction === "narrowed"
              ? "tightened"
              : "neutral";

        modifiedSignerRules.push({
          id,
          matchKind: "id",
          ruleCategory: "signer",
          leftRule: l,
          rightRule: r,
          changedFields,
          trustDirection,
          riskDelta: modRiskDelta,
          severity: severityFromDelta(modRiskDelta),
          affectsKernel: isKernel,
          explanation: explainSignerModified(l, r, changedFields, scopeChange, scenarios, effect),
          signerScopeChange: scopeChange,
        });
      }
      semanticallyMatchedLeftSigner.add(id);
      semanticallyMatchedRightSigner.add(id);
    } else if (l && !r) {
      // Check semantic fingerprint
      const fp = signerSemanticKey(l);
      const rightId = rightIdx.signerByFingerprint.get(fp);
      if (rightId && !semanticallyMatchedRightSigner.has(rightId)) {
        semanticallyMatchedLeftSigner.add(id);
        semanticallyMatchedRightSigner.add(rightId);
        continue;
      }

      if (!semanticallyMatchedLeftSigner.has(id)) {
        const scenarios = signerScenarios(id, leftIdx);
        const isKernel = scenarios.includes("kernel");
        const effect = signerEffect(id, leftIdx);
        const attribs = resolveFileAttribs(l, leftIdx);
        const hasScope = attribs.length > 0;
        const { delta, trustDirection } = signerRiskDelta(hasScope, effect, "removed", isKernel);
        removedSignerRules.push({
          id,
          matchKind: "unmatched",
          ruleCategory: "signer",
          effect,
          signingScenarios: scenarios,
          rule: l,
          fileAttribs: attribs,
          trustDirection,
          riskDelta: delta,
          severity: severityFromDelta(delta),
          affectsKernel: isKernel,
          explanation: explainSignerRemoved(l, effect, scenarios, attribs),
        });
      }
    } else if (!l && r) {
      const fp = signerSemanticKey(r);
      const leftId = leftIdx.signerByFingerprint.get(fp);
      if (leftId && !semanticallyMatchedLeftSigner.has(leftId)) {
        semanticallyMatchedLeftSigner.add(leftId);
        semanticallyMatchedRightSigner.add(id);
        continue;
      }

      if (!semanticallyMatchedRightSigner.has(id)) {
        const scenarios = signerScenarios(id, rightIdx);
        const isKernel = scenarios.includes("kernel");
        const effect = signerEffect(id, rightIdx);
        const attribs = resolveFileAttribs(r, rightIdx);
        const hasScope = attribs.length > 0;
        const { delta, trustDirection } = signerRiskDelta(hasScope, effect, "added", isKernel);
        addedSignerRules.push({
          id,
          matchKind: "unmatched",
          ruleCategory: "signer",
          effect,
          signingScenarios: scenarios,
          rule: r,
          fileAttribs: attribs,
          trustDirection,
          riskDelta: delta,
          severity: severityFromDelta(delta),
          affectsKernel: isKernel,
          explanation: explainSignerAdded(r, effect, scenarios, attribs),
        });
      }
    }
  }

  // -------- Phase 3: Option changes --------

  const optionChanges: OptionSemanticChange[] = [];

  const allOptionNums = new Set<number>([
    ...left.options.map((o) => o.value as number),
    ...right.options.map((o) => o.value as number),
    ...Object.keys(POLICY_RULE_OPTIONS).map(Number),
  ]);

  for (const num of Array.from(allOptionNums).sort((a, b) => a - b)) {
    const leftOpt = left.options.find((o) => (o.value as number) === num);
    const rightOpt = right.options.find((o) => (o.value as number) === num);
    const def = POLICY_RULE_OPTIONS[num as keyof typeof POLICY_RULE_OPTIONS];
    if (!def) continue;

    const leftEnabled = leftOpt?.enabled ?? false;
    const rightEnabled = rightOpt?.enabled ?? false;

    if (leftEnabled === rightEnabled) continue; // No change

    const impact = OPTION_IMPACTS[num];
    const changed = rightEnabled ? impact?.onEnable : impact?.onDisable;

    if (changed) {
      optionChanges.push({
        optionValue: num,
        optionName: def.name,
        enabledBefore: leftEnabled,
        enabledAfter: rightEnabled,
        trustDirection: changed.trustDirection,
        riskDelta: changed.riskDelta,
        severity: changed.severity,
        explanation: changed.explanation,
      });
    } else {
      // Generic option change with neutral risk
      optionChanges.push({
        optionValue: num,
        optionName: def.name,
        enabledBefore: leftEnabled,
        enabledAfter: rightEnabled,
        trustDirection: "neutral",
        riskDelta: 0,
        severity: "info",
        explanation: `Option "${def.name}" changed from ${leftEnabled ? "enabled" : "disabled"} to ${rightEnabled ? "enabled" : "disabled"}.`,
      });
    }
  }

  // -------- Phase 4: Effective mode change --------

  let effectiveModeChange: PolicySemanticDiff["effectiveModeChange"];
  const leftMode = leftIdx.isAuditMode ? "audit" : "enforcement";
  const rightMode = rightIdx.isAuditMode ? "audit" : "enforcement";

  if (leftMode !== rightMode) {
    const toAudit = rightMode === "audit";
    effectiveModeChange = {
      before: leftMode,
      after: rightMode,
      riskDelta: toAudit ? RISK.AUDIT_ENABLED : RISK.ENFORCEMENT_ENABLED,
      explanation: toAudit
        ? "The policy transitioned from ENFORCEMENT to AUDIT mode. Violations will be logged but no longer blocked. " +
          "This change effectively disables blocking enforcement — the policy is now purely observational."
        : "The policy transitioned from AUDIT to ENFORCEMENT mode. Violations will now be blocked. " +
          "The policy is now actively protecting the system.",
    };
  }

  // -------- Phase 5: Risk aggregation --------

  const addedRules = [...addedFileRules, ...addedSignerRules];
  const removedRules = [...removedFileRules, ...removedSignerRules];
  const modifiedRules = [...modifiedFileRules, ...modifiedSignerRules];

  const allChanges = [
    ...addedRules.map((r) => ({ delta: r.riskDelta, dir: r.trustDirection, isKernel: r.affectsKernel, cat: r.ruleCategory })),
    ...removedRules.map((r) => ({ delta: r.riskDelta, dir: r.trustDirection, isKernel: r.affectsKernel, cat: r.ruleCategory })),
    ...modifiedRules.map((r) => ({ delta: r.riskDelta, dir: r.trustDirection, isKernel: r.affectsKernel, cat: r.ruleCategory })),
    ...optionChanges.map((o) => ({ delta: o.riskDelta, dir: o.trustDirection, isKernel: false, cat: "option" as const })),
    ...(effectiveModeChange ? [{ delta: effectiveModeChange.riskDelta, dir: "neutral" as TrustDirection, isKernel: false, cat: "option" as const }] : []),
  ];

  const totalRiskDelta = allChanges.reduce((sum, c) => sum + c.delta, 0);

  const broadeningCount = allChanges.filter((c) => c.dir === "broadened").length;
  const tighteningCount = allChanges.filter((c) => c.dir === "tightened").length;
  const neutralCount = allChanges.filter((c) => c.dir === "neutral").length;
  const kernelImpactCount = allChanges.filter((c) => c.isKernel).length;

  const verdict: RiskVerdict =
    totalRiskDelta <= -20
      ? "improved"
      : totalRiskDelta <= 10
        ? "unchanged"
        : totalRiskDelta <= 40
          ? "degraded"
          : "significantly-degraded";

  // Risk by category
  const fileRuleRisk = [...addedFileRules, ...removedFileRules].reduce((s, r) => s + r.riskDelta, 0) +
    modifiedFileRules.reduce((s, r) => s + r.riskDelta, 0);

  const signerRuleRisk = [...addedSignerRules, ...removedSignerRules].reduce((s, r) => s + r.riskDelta, 0) +
    modifiedSignerRules.reduce((s, r) => s + r.riskDelta, 0);

  const optionRisk = optionChanges.reduce((s, o) => s + o.riskDelta, 0) +
    (effectiveModeChange?.riskDelta ?? 0);

  const scopeRisk = modifiedSignerRules.reduce(
    (s, r) => s + (r.signerScopeChange?.riskDelta ?? 0), 0
  );

  // Critical findings
  const criticalFindings: string[] = [];

  if (effectiveModeChange?.before === "enforcement" && effectiveModeChange.after === "audit") {
    criticalFindings.push("Policy enforcement weakened: transitioned from enforcement to audit mode.");
  }

  for (const r of addedRules) {
    if (r.severity === "critical" || r.severity === "high") {
      criticalFindings.push(
        `[${r.ruleCategory === "signer" ? "Signer" : "File"} Added] ${r.explanation.substring(0, 120)}…`
      );
    }
  }
  for (const r of removedRules) {
    if (r.severity === "critical" || r.severity === "high") {
      criticalFindings.push(
        `[${r.ruleCategory === "signer" ? "Signer" : "File"} Removed] ${r.explanation.substring(0, 120)}…`
      );
    }
  }
  for (const opt of optionChanges) {
    if (opt.severity === "critical" || opt.severity === "high") {
      criticalFindings.push(`[Option Change] ${opt.explanation.substring(0, 120)}…`);
    }
  }

  // Risk factors
  const riskFactors: RiskFactor[] = [];

  const kernelRules = [...addedRules, ...removedRules].filter((r) => r.affectsKernel);
  if (kernelRules.length > 0) {
    riskFactors.push({
      severity: "critical",
      category: "Kernel Mode Changes",
      description: `${kernelRules.length} change(s) affect kernel-mode code. Kernel-level trust grants highest OS privilege.`,
      affectedRuleIds: kernelRules.map((r) => r.id),
    });
  }

  const broadeningSigners = addedSignerRules.filter(
    (r) => r.effect === "Allow" && r.trustDirection === "broadened"
  );
  if (broadeningSigners.length > 0) {
    riskFactors.push({
      severity: "high",
      category: "Unscoped Publisher Trust Added",
      description: `${broadeningSigners.length} unscoped publisher allow rule(s) added — all software from these publishers is now trusted.`,
      affectedRuleIds: broadeningSigners.map((r) => r.id),
    });
  }

  const removedDenyRules = removedRules.filter((r) => r.effect === "Deny");
  if (removedDenyRules.length > 0) {
    riskFactors.push({
      severity: "medium",
      category: "Explicit Deny Rules Removed",
      description: `${removedDenyRules.length} explicit deny rule(s) removed. Previously blocked binaries may now execute.`,
      affectedRuleIds: removedDenyRules.map((r) => r.id),
    });
  }

  const scopeBroadened = modifiedSignerRules.filter(
    (r) => r.signerScopeChange?.direction === "broadened"
  );
  if (scopeBroadened.length > 0) {
    riskFactors.push({
      severity: "medium",
      category: "Signer Scope Broadened",
      description: `${scopeBroadened.length} signer rule(s) had FileAttrib scoping removed or weakened, expanding publisher trust.`,
      affectedRuleIds: scopeBroadened.map((r) => r.id),
    });
  }

  const riskAssessment: RiskAssessment = {
    totalRiskDelta,
    verdict,
    broadeningCount,
    tighteningCount,
    neutralCount,
    kernelImpactCount,
    criticalFindings,
    riskByCategory: {
      fileRules: fileRuleRisk,
      signerRules: signerRuleRisk,
      options: optionRisk,
      scopeChanges: scopeRisk,
    },
    riskFactors,
  };

  // -------- Phase 6: Human explanation --------

  const humanExplanation = buildHumanExplanation(
    addedRules,
    removedRules,
    modifiedRules,
    optionChanges,
    effectiveModeChange,
    riskAssessment,
    left,
    right
  );

  return {
    leftPolicy: {
      policyId: left.policyId,
      friendlyName: left.friendlyName,
      versionEx: left.versionEx,
    },
    rightPolicy: {
      policyId: right.policyId,
      friendlyName: right.friendlyName,
      versionEx: right.versionEx,
    },
    effectiveModeChange,
    addedRules,
    removedRules,
    modifiedRules,
    optionChanges,
    riskAssessment,
    humanExplanation,
  };
}

// ---------------------------------------------------------------------------
// Human explanation builder
// ---------------------------------------------------------------------------

function buildHumanExplanation(
  addedRules: DiffedRule[],
  removedRules: DiffedRule[],
  modifiedRules: ModifiedRule[],
  optionChanges: OptionSemanticChange[],
  effectiveModeChange: PolicySemanticDiff["effectiveModeChange"] | undefined,
  riskAssessment: RiskAssessment,
  left: WdacPolicy,
  right: WdacPolicy
): HumanExplanation {
  const leftName = left.friendlyName ?? left.policyId.substring(0, 16);
  const rightName = right.friendlyName ?? right.policyId.substring(0, 16);

  const totalChanges = addedRules.length + removedRules.length + modifiedRules.length + optionChanges.length;

  const verdictMap: Record<RiskVerdict, string> = {
    improved: "an improvement in security posture",
    unchanged: "no meaningful change in security posture",
    degraded: "a moderate regression in security posture",
    "significantly-degraded": "a significant regression in security posture",
  };

  const summary =
    `Comparing "${leftName}" (baseline) to "${rightName}" (candidate): ` +
    `${totalChanges} change(s) detected — ` +
    `${addedRules.length} rule(s) added, ` +
    `${removedRules.length} rule(s) removed, ` +
    `${modifiedRules.length} rule(s) modified, ` +
    `${optionChanges.length} option change(s). ` +
    `Risk delta: ${riskAssessment.totalRiskDelta > 0 ? "+" : ""}${riskAssessment.totalRiskDelta}. ` +
    `Overall verdict: ${verdictMap[riskAssessment.verdict]}.`;

  const modeChanges: string[] = [];
  if (effectiveModeChange) {
    modeChanges.push(effectiveModeChange.explanation);
  }
  for (const opt of optionChanges) {
    if (opt.optionValue === 3 || opt.optionValue === 0) {
      modeChanges.push(opt.explanation);
    }
  }

  // Significant additions (by severity then risk delta)
  const significantAdditions = addedRules
    .filter((r) => r.severity === "critical" || r.severity === "high" || r.riskDelta >= 15)
    .sort((a, b) => b.riskDelta - a.riskDelta)
    .slice(0, 5)
    .map((r) => r.explanation);

  // Significant removals
  const significantRemovals = removedRules
    .filter((r) => r.severity === "critical" || r.severity === "high" || Math.abs(r.riskDelta) >= 15)
    .sort((a, b) => Math.abs(b.riskDelta) - Math.abs(a.riskDelta))
    .slice(0, 5)
    .map((r) => r.explanation);

  // Significant modifications (scope changes)
  const significantModifications = modifiedRules
    .filter((r) => r.riskDelta !== 0 || r.signerScopeChange?.direction !== "unchanged")
    .sort((a, b) => Math.abs(b.riskDelta) - Math.abs(a.riskDelta))
    .slice(0, 5)
    .map((r) => r.explanation);

  // Kernel impacts
  const kernelImpacts = [
    ...addedRules.filter((r) => r.affectsKernel),
    ...removedRules.filter((r) => r.affectsKernel),
    ...modifiedRules.filter((r) => r.affectsKernel),
  ].map((r) => r.explanation);

  const verdictSentences: Record<RiskVerdict, string> = {
    improved:
      `The candidate policy "${rightName}" is MORE restrictive than the baseline "${leftName}". ` +
      "Trust surface has been narrowed — overall security posture has improved.",
    unchanged:
      `The candidate policy "${rightName}" is effectively equivalent to the baseline "${leftName}" ` +
      "from a security posture perspective. Changes are minimal or self-cancelling.",
    degraded:
      `The candidate policy "${rightName}" is LESS restrictive than the baseline "${leftName}". ` +
      "Trust surface has been broadened — overall security posture has degraded. Review before deploying.",
    "significantly-degraded":
      `SIGNIFICANT REGRESSION: The candidate policy "${rightName}" is substantially more permissive than ` +
      `"${leftName}". Multiple high-risk changes were detected. ` +
      "Carefully review all changes before deploying to production.",
  };

  return {
    summary,
    modeChanges,
    significantAdditions,
    significantRemovals,
    significantModifications,
    kernelImpacts,
    overallAssessment: verdictSentences[riskAssessment.verdict],
  };
}

// ---------------------------------------------------------------------------
// Modification helpers
// ---------------------------------------------------------------------------

function findChangedFileRuleFields(l: WdacFileRule, r: WdacFileRule): string[] {
  if (l.kind !== r.kind) return ["kind"];
  const lRec = l as unknown as Record<string, unknown>;
  const rRec = r as unknown as Record<string, unknown>;
  const allKeys = new Set([...Object.keys(lRec), ...Object.keys(rRec)]);
  allKeys.delete("id");
  return [...allKeys].filter((k) => JSON.stringify(lRec[k]) !== JSON.stringify(rRec[k]));
}

function findChangedSignerFields(l: WdacSignerRule, r: WdacSignerRule): string[] {
  const changed: string[] = [];
  if (l.name !== r.name) changed.push("name");
  if (JSON.stringify(l.certRoot) !== JSON.stringify(r.certRoot)) changed.push("certRoot");
  if (JSON.stringify(l.certEKU) !== JSON.stringify(r.certEKU)) changed.push("certEKU");
  if (l.certIssuer !== r.certIssuer) changed.push("certIssuer");
  if (l.certPublisher !== r.certPublisher) changed.push("certPublisher");
  if (l.certOemID !== r.certOemID) changed.push("certOemID");
  if (
    JSON.stringify((l.fileAttribRefs ?? []).slice().sort()) !==
    JSON.stringify((r.fileAttribRefs ?? []).slice().sort())
  )
    changed.push("fileAttribRefs");
  return changed;
}

function estimateModificationRisk(
  l: WdacFileRule,
  r: WdacFileRule,
  changedFields: string[],
  isKernel: boolean
): { delta: number; trustDirection: TrustDirection } {
  // Kind changed = essentially a full replacement
  if (changedFields.includes("kind")) {
    return { delta: 15, trustDirection: "neutral" };
  }

  // Effect changed (Allow ↔ Deny) is significant
  if (changedFields.includes("effect")) {
    const lEff = (l as { effect?: string }).effect;
    const rEff = (r as { effect?: string }).effect;
    if (lEff === "Deny" && rEff === "Allow") {
      return { delta: isKernel ? 50 : 25, trustDirection: "broadened" };
    }
    if (lEff === "Allow" && rEff === "Deny") {
      return { delta: isKernel ? -40 : -20, trustDirection: "tightened" };
    }
  }

  // Hash changed — new binary version
  if (changedFields.includes("hash")) {
    return { delta: 5, trustDirection: "neutral" };
  }

  // Path changed — could be broader or narrower
  if (changedFields.includes("filePath")) {
    const lPath = (l as WdacPathRule).filePath?.length ?? 0;
    const rPath = (r as WdacPathRule).filePath?.length ?? 0;
    if (rPath < lPath) return { delta: 10, trustDirection: "broadened" }; // shorter = broader
    if (rPath > lPath) return { delta: -5, trustDirection: "tightened" }; // longer = narrower
  }

  // Version range changes
  if (changedFields.some((f) => f.includes("Version"))) {
    return { delta: 5, trustDirection: "neutral" };
  }

  return { delta: 2, trustDirection: "neutral" };
}

function explainFileRuleModified(
  l: WdacFileRule,
  r: WdacFileRule,
  changedFields: string[],
  scenarios: Array<"kernel" | "user">
): string {
  const mode = scenarios.includes("kernel") ? "kernel-mode" : "user-mode";
  const id = l.id;

  if (changedFields.includes("kind")) {
    return `File rule ${id} changed kind from "${l.kind}" to "${r.kind}" in ${mode} context. This is a substantial structural change.`;
  }

  if (changedFields.includes("effect")) {
    const lEff = (l as { effect?: string }).effect;
    const rEff = (r as { effect?: string }).effect;
    return (
      `File rule ${id} changed effect from ${lEff} to ${rEff} in ${mode} context. ` +
      (rEff === "Allow" ? "A previously blocking rule is now an allow rule — trust broadened." :
        "A previously allowing rule is now a deny rule — restriction added.")
    );
  }

  if (changedFields.includes("hash")) {
    const lH = ((l as WdacHashRule).hash ?? "").substring(0, 16);
    const rH = ((r as WdacHashRule).hash ?? "").substring(0, 16);
    return `Hash rule ${id} (${l.kind === "hash" ? (l as WdacHashRule).fileName ?? "unnamed" : id}) had its hash updated from ${lH}… to ${rH}…. This likely reflects a file version update.`;
  }

  if (changedFields.includes("filePath")) {
    return (
      `Path rule ${id} changed path from "${(l as WdacPathRule).filePath}" to "${(r as WdacPathRule).filePath}". ` +
      "Verify the new path is appropriately restricted."
    );
  }

  return `File rule ${id} had field(s) changed: ${changedFields.join(", ")}.`;
}

function explainSignerModified(
  l: WdacSignerRule,
  r: WdacSignerRule,
  changedFields: string[],
  scopeChange: SignerScopeChange,
  scenarios: Array<"kernel" | "user">,
  effect: "Allow" | "Deny"
): string {
  const publisher = r.certPublisher ?? r.name ?? "(unknown)";
  const mode = scenarios.includes("kernel") ? "kernel-mode" : "user-mode";

  if (changedFields.includes("certRoot")) {
    return (
      `Signer rule for "${publisher}" (${mode}) had its CERTIFICATE TRUST ANCHOR changed. ` +
      "This is a fundamentally different trust relationship — the rule now anchors to a different root certificate. " +
      `${scopeChange.detail}`
    );
  }

  if (changedFields.includes("fileAttribRefs")) {
    return (
      `Signer rule for "${publisher}" (${mode}, ${effect}) had its FileAttrib scope changed. ` +
      scopeChange.detail +
      ` Scope before: ${scopeChange.scopeBefore}. Scope after: ${scopeChange.scopeAfter}.`
    );
  }

  if (changedFields.includes("certPublisher")) {
    const oldPub = l.certPublisher ?? l.name ?? "(unknown)";
    const newPub = r.certPublisher ?? r.name ?? "(unknown)";
    return (
      `Signer rule had its publisher name changed from "${oldPub}" to "${newPub}" (${mode}). ` +
      "Verify this change reflects an intentional publisher update and not a trust anchor mismatch."
    );
  }

  return `Signer rule for "${publisher}" (${mode}) had field(s) changed: ${changedFields.join(", ")}.`;
}
