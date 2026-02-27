/**
 * WDAC Policy Explainer
 *
 * Generates human-readable summaries and risk assessments for WDAC policies.
 */

import type { WdacPolicy } from "@appcontrol/shared";
import { POLICY_RULE_OPTIONS } from "@appcontrol/shared";
import type { ExplainPolicyResponse } from "@appcontrol/shared";

export function explainPolicy(policy: WdacPolicy): ExplainPolicyResponse {
  const enabledOptions = new Set(
    policy.options.filter((o) => o.enabled).map((o) => o.value as number)
  );

  const isAuditMode = enabledOptions.has(3);
  const isUmciEnabled = enabledOptions.has(0);
  const isScriptEnforcementDisabled = enabledOptions.has(11);
  const isRuntimePathDisabled = enabledOptions.has(18);
  const isManagedInstaller = enabledOptions.has(13);
  const isIsg = enabledOptions.has(14);
  const isUnsignedAllowed = enabledOptions.has(6);
  const isDebugAllowed = enabledOptions.has(7);
  const isAdvancedBootMenu = enabledOptions.has(9);
  const isFlightSigningDisabled = enabledOptions.has(4);

  // Determine effective mode
  let effectiveMode: ExplainPolicyResponse["effectiveMode"] = "enforcement";
  if (isAuditMode) effectiveMode = "audit";

  // Risk flags
  const riskFlags: ExplainPolicyResponse["riskFlags"] = [];

  if (isAuditMode) {
    riskFlags.push({
      severity: "warning",
      message: "Policy is in Audit Mode",
      detail:
        "Violations are logged but not blocked. Audit mode must be disabled before this policy provides protection.",
    });
  }

  if (!isUmciEnabled) {
    riskFlags.push({
      severity: "critical",
      message: "UMCI (User Mode Code Integrity) is NOT enabled",
      detail:
        "Without Option 0 (Enabled:UMCI), the policy only enforces kernel-mode code. User-mode applications are completely unrestricted.",
    });
  }

  if (isScriptEnforcementDisabled) {
    riskFlags.push({
      severity: "warning",
      message: "Script Enforcement is Disabled",
      detail:
        "Option 11 (Disabled:Script Enforcement) means PowerShell, WSH, and other script hosts bypass App Control enforcement.",
    });
  }

  if (isRuntimePathDisabled) {
    riskFlags.push({
      severity: "warning",
      message: "Runtime FilePath Rule Protection is Disabled",
      detail:
        "Option 18 (Disabled:Runtime FilePath Rule Protection) reduces the security of path-based rules, allowing potential bypass via directory manipulation.",
    });
  }

  if (isDebugAllowed) {
    riskFlags.push({
      severity: "critical",
      message: "Debug Policy Augmented is Allowed",
      detail:
        "Option 7 (Allowed:Debug Policy Augmented) permits the kernel debugger to augment the policy at runtime. This should NEVER be enabled in production.",
    });
  }

  if (isAdvancedBootMenu) {
    riskFlags.push({
      severity: "warning",
      message: "Advanced Boot Options Menu is Enabled",
      detail:
        "Option 9 allows users to access the Advanced Boot Options menu, which may allow bypassing App Control via Safe Mode.",
    });
  }

  if (isUnsignedAllowed) {
    riskFlags.push({
      severity: "warning",
      message: "Unsigned Policy is Allowed",
      detail:
        "Option 6 (Enabled:Unsigned System Integrity Policy) allows unsigned policies to be loaded. Signing policies prevents unauthorized modification.",
    });
  }

  if (isManagedInstaller && isIsg) {
    riskFlags.push({
      severity: "info",
      message: "Both Managed Installer and ISG are enabled",
      detail:
        "Using both trust mechanisms broadens the trust surface. Ensure Managed Installer is properly configured to prevent abuse.",
    });
  }

  if (isIsg) {
    riskFlags.push({
      severity: "info",
      message: "Intelligent Security Graph (ISG) is enabled",
      detail:
        "ISG uses Microsoft cloud reputation. Files must have positive reputation to run. Requires internet connectivity for lookups.",
    });
  }

  // Scenario breakdown
  const kernelSS = policy.signingScenarios.find((s) => s.value === 131);
  const userSS = policy.signingScenarios.find((s) => s.value === 12);

  const ruleBreakdown = {
    kernelMode: {
      allowedSignerCount: kernelSS?.allowedSigners.length ?? 0,
      deniedSignerCount: kernelSS?.deniedSigners.length ?? 0,
      fileRuleCount: kernelSS?.fileRuleRefs.length ?? 0,
    },
    userMode: {
      allowedSignerCount: userSS?.allowedSigners.length ?? 0,
      deniedSignerCount: userSS?.deniedSigners.length ?? 0,
      fileRuleCount: userSS?.fileRuleRefs.length ?? 0,
    },
  };

  // Option descriptions
  const optionDescriptions = policy.options
    .filter((o) => o.enabled)
    .map((o) => {
      const def = POLICY_RULE_OPTIONS[o.value as keyof typeof POLICY_RULE_OPTIONS];
      return {
        optionName: def?.name ?? `Option ${o.value}`,
        enabled: o.enabled,
        description: def?.description ?? "Unknown option.",
      };
    });

  // Build summary
  const summaryParts: string[] = [];
  summaryParts.push(
    `${policy.policyType} policy '${policy.friendlyName ?? policy.policyId}' (v${policy.versionEx}).`
  );
  summaryParts.push(
    effectiveMode === "audit"
      ? "Currently in AUDIT MODE — violations are logged, not blocked."
      : "Currently in ENFORCEMENT MODE — violations are blocked."
  );
  summaryParts.push(
    `Enforces ${isUmciEnabled ? "both kernel and user mode" : "kernel mode only"} code integrity.`
  );
  summaryParts.push(
    `Kernel mode: ${ruleBreakdown.kernelMode.allowedSignerCount} allowed signer(s), ${ruleBreakdown.kernelMode.fileRuleCount} direct file rule(s).`
  );
  summaryParts.push(
    `User mode: ${ruleBreakdown.userMode.allowedSignerCount} allowed signer(s), ${ruleBreakdown.userMode.fileRuleCount} direct file rule(s).`
  );
  const effectRules = policy.fileRules.filter((r) => r.kind !== "fileAttrib");
  const allowCount  = effectRules.filter((r) => (r as { effect: string }).effect === "Allow").length;
  const denyCount   = effectRules.filter((r) => (r as { effect: string }).effect === "Deny").length;
  summaryParts.push(
    `Total file rules: ${effectRules.length} (${allowCount} allow, ${denyCount} deny).`
  );

  return {
    summary: summaryParts.join(" "),
    effectiveMode,
    riskFlags,
    ruleBreakdown,
    optionDescriptions,
  };
}
