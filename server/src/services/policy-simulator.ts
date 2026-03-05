/**
 * WDAC Policy Simulation Engine
 *
 * Evaluates whether a binary would be allowed or blocked by a WDAC policy,
 * following the documented rule evaluation order exactly:
 *
 *   Phase 1 — Deny file rules   (hash → path → attribute)
 *   Phase 2 — Deny signer rules (with optional FileAttrib scoping)
 *   Phase 3 — Allow signer rules (with optional FileAttrib scoping)
 *   Phase 4 — Allow file rules  (hash → attribute → path)
 *   Phase 5 — Default deny
 *
 * Policy options that affect evaluation:
 *   Option 0 (UMCI)       — If disabled, user-mode binaries are not enforced.
 *   Option 3 (Audit Mode) — If enabled, all verdicts are "audit-only".
 *
 * Reference:
 *   https://learn.microsoft.com/en-us/windows/security/application-security/
 *   application-control/app-control-for-business/design/select-types-of-rules-to-create
 */

import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  WdacFileAttrib,
  WdacHashRule,
  WdacPathRule,
  WdacAttributeRule,
  SigningScenarioValue,
} from "@appcontrol/shared";

import type {
  BinaryMetadata,
  EvaluationResult,
  EvalStep,
  EvalPhase,
  SimRuleType,
  MatchedBy,
  StepOutcome,
} from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

export function simulateBinary(
  binary: BinaryMetadata,
  policy: WdacPolicy
): EvaluationResult {
  const steps: EvalStep[] = [];
  const warnings: string[] = [];

  // Build O(1) lookup indices
  const fileRulesById = new Map<string, WdacFileRule>(
    policy.fileRules.map((r) => [r.id, r])
  );
  const signersById = new Map<string, WdacSignerRule>(
    policy.signers.map((s) => [s.id, s])
  );

  // -------------------------------------------------------------------------
  // Pre-flight: policy mode checks
  // -------------------------------------------------------------------------

  const isAuditMode = policy.options.some((o) => o.value === 3 && o.enabled);
  const umciEnabled = policy.options.some((o) => o.value === 0 && o.enabled);
  const policyMode = isAuditMode ? "audit" : ("enforcement" as const);

  pushStep(steps, {
    phase: "mode-check",
    ruleType: isAuditMode ? "audit-passthrough" : "default-deny",
    outcome: "no-match",
    detail: `Policy mode: ${isAuditMode ? "Audit" : "Enforcement"}. UMCI (option 0): ${umciEnabled ? "enabled" : "disabled"}.`,
  });

  // UMCI check — user-mode enforcement requires option 0
  if (!binary.isKernelMode && !umciEnabled) {
    pushStep(steps, {
      phase: "mode-check",
      ruleType: "no-umci",
      outcome: "matched",
      detail:
        "UMCI (Enabled:UMCI, option 0) is not set. User-mode code integrity enforcement is inactive — all user-mode binaries are implicitly allowed.",
    });
    return finalResult(
      "allowed",
      undefined,
      undefined,
      "umci-disabled",
      policyMode,
      undefined,
      steps,
      warnings,
      "Policy option 0 (Enabled:UMCI) is not enabled. User-mode code integrity enforcement is inactive; the binary is not subject to App Control restrictions."
    );
  }

  // -------------------------------------------------------------------------
  // Signing scenario selection
  // -------------------------------------------------------------------------

  const scenarioValue: SigningScenarioValue = binary.isKernelMode ? 131 : 12;
  const scenario = policy.signingScenarios.find(
    (s) => s.value === scenarioValue
  );

  pushStep(steps, {
    phase: "scenario-select",
    ruleType: "default-deny",
    outcome: scenario ? "no-match" : "skipped",
    detail: scenario
      ? `Signing scenario ${scenarioValue} (${scenarioValue === 131 ? "kernel" : "user"} mode) found — proceeding with rule evaluation.`
      : `Signing scenario ${scenarioValue} (${scenarioValue === 131 ? "kernel" : "user"} mode) is not defined in this policy.`,
  });

  if (!scenario) {
    warnings.push(
      `Signing scenario ${scenarioValue} is not defined in this policy. This may indicate an incomplete policy configuration.`
    );
    return finalResult(
      "allowed",
      undefined,
      undefined,
      "no-scenario",
      policyMode,
      scenarioValue as 131 | 12,
      steps,
      warnings,
      `Signing scenario ${scenarioValue} (${scenarioValue === 131 ? "kernel" : "user"} mode) is absent from this policy — the binary is not subject to enforcement under this scenario.`
    );
  }

  // Warn about missing metadata that limits simulation accuracy
  if (!binary.sha256 && !binary.sha1) {
    warnings.push(
      "No hash provided — hash-based deny and allow rules will be skipped."
    );
  }
  if (!binary.signerName && !binary.rootCertTbs) {
    warnings.push(
      "No signing information provided — publisher/signer rules will be skipped."
    );
  }
  if (!binary.filePath) {
    warnings.push(
      "No file path provided — path-based rules will be skipped."
    );
  }

  // Partition scenario's fileRuleRefs into deny and allow buckets
  const denyFileRules: WdacFileRule[] = [];
  const allowFileRules: WdacFileRule[] = [];
  for (const refId of scenario.fileRuleRefs) {
    const rule = fileRulesById.get(refId);
    if (!rule || rule.kind === "fileAttrib") continue;
    const eff = (rule as WdacHashRule | WdacPathRule | WdacAttributeRule)
      .effect;
    if (eff === "Deny") denyFileRules.push(rule);
    else if (eff === "Allow") allowFileRules.push(rule);
  }

  // -------------------------------------------------------------------------
  // Phase 1a — Deny hash rules
  // -------------------------------------------------------------------------

  for (const rule of denyFileRules.filter((r) => r.kind === "hash")) {
    const m = matchHash(rule as WdacHashRule, binary);
    pushStep(steps, {
      phase: "deny-hash",
      ruleId: rule.id,
      ruleName: rule.friendlyName ?? rule.id,
      ruleType: "deny-hash",
      outcome: stepOutcome(m),
      detail: m.detail,
    });
    if (m.matched) {
      return finalResult(
        "blocked",
        rule.id,
        rule.friendlyName ?? rule.id,
        "hash",
        policyMode,
        scenarioValue as 131 | 12,
        steps,
        warnings,
        `Binary explicitly denied by hash rule "${rule.friendlyName ?? rule.id}": ${m.detail}`
      );
    }
  }

  // -------------------------------------------------------------------------
  // Phase 1b — Deny path rules
  // -------------------------------------------------------------------------

  for (const rule of denyFileRules.filter((r) => r.kind === "path")) {
    const m = matchPath(rule as WdacPathRule, binary);
    pushStep(steps, {
      phase: "deny-path",
      ruleId: rule.id,
      ruleName: rule.friendlyName ?? rule.id,
      ruleType: "deny-path",
      outcome: stepOutcome(m),
      detail: m.detail,
    });
    if (m.matched) {
      return finalResult(
        "blocked",
        rule.id,
        rule.friendlyName ?? rule.id,
        "path",
        policyMode,
        scenarioValue as 131 | 12,
        steps,
        warnings,
        `Binary explicitly denied by path rule "${rule.friendlyName ?? rule.id}": ${m.detail}`
      );
    }
  }

  // -------------------------------------------------------------------------
  // Phase 1c — Deny attribute rules
  // -------------------------------------------------------------------------

  for (const rule of denyFileRules.filter((r) => r.kind === "attribute")) {
    const m = matchAttributes(rule as WdacAttributeRule, binary);
    pushStep(steps, {
      phase: "deny-path",
      ruleId: rule.id,
      ruleName: rule.friendlyName ?? rule.id,
      ruleType: "deny-publisher",
      outcome: stepOutcome(m),
      detail: m.detail,
    });
    if (m.matched) {
      return finalResult(
        "blocked",
        rule.id,
        rule.friendlyName ?? rule.id,
        "attribute",
        policyMode,
        scenarioValue as 131 | 12,
        steps,
        warnings,
        `Binary explicitly denied by attribute rule "${rule.friendlyName ?? rule.id}": ${m.detail}`
      );
    }
  }

  // -------------------------------------------------------------------------
  // Phase 2 — Deny signer rules
  // -------------------------------------------------------------------------

  for (const deniedEntry of scenario.deniedSigners) {
    const signer = signersById.get(deniedEntry.signerId);
    if (!signer) continue;

    const m = matchSigner(signer, binary, fileRulesById);
    const ruleType: SimRuleType = signer.fileAttribRefs?.length
      ? "deny-publisher-scoped"
      : "deny-publisher";

    if (m.matched) {
      // exceptAllowRuleIds — deny is overridden if binary also matches one of these allow rules
      const excepted = matchesAnyFileRule(
        deniedEntry.exceptAllowRuleIds ?? [],
        binary,
        fileRulesById
      );
      pushStep(steps, {
        phase: "deny-publisher",
        ruleId: signer.id,
        ruleName: signer.name,
        ruleType,
        outcome: excepted ? "excepted" : "matched",
        detail: excepted
          ? `${m.detail} — overridden by an allow exception rule.`
          : m.detail,
      });
      if (!excepted) {
        return finalResult(
          "blocked",
          signer.id,
          signer.name,
          signer.fileAttribRefs?.length ? "publisher-scoped" : "publisher",
          policyMode,
          scenarioValue as 131 | 12,
          steps,
          warnings,
          `Binary explicitly denied by publisher rule "${signer.name}": ${m.detail}`
        );
      }
    } else {
      pushStep(steps, {
        phase: "deny-publisher",
        ruleId: signer.id,
        ruleName: signer.name,
        ruleType,
        outcome: m.skipped ? "skipped" : "no-match",
        detail: m.detail,
      });
    }
  }

  // -------------------------------------------------------------------------
  // Phase 3 — Allow signer rules
  // -------------------------------------------------------------------------

  for (const allowedEntry of scenario.allowedSigners) {
    const signer = signersById.get(allowedEntry.signerId);
    if (!signer) continue;

    const m = matchSigner(signer, binary, fileRulesById);
    const isScoped = (signer.fileAttribRefs?.length ?? 0) > 0;
    const ruleType: SimRuleType = isScoped
      ? "allow-publisher-scoped"
      : "allow-publisher";
    const phase: EvalPhase = isScoped
      ? "allow-publisher-scoped"
      : "allow-publisher";

    if (m.matched) {
      // exceptDenyRuleIds — allow is overridden if binary also matches one of these deny rules
      const excepted = matchesAnyFileRule(
        allowedEntry.exceptDenyRuleIds ?? [],
        binary,
        fileRulesById
      );
      pushStep(steps, {
        phase,
        ruleId: signer.id,
        ruleName: signer.name,
        ruleType,
        outcome: excepted ? "excepted" : "matched",
        detail: excepted
          ? `${m.detail} — overridden by a deny exception rule.`
          : m.detail,
      });
      if (!excepted) {
        return finalResult(
          "allowed",
          signer.id,
          signer.name,
          isScoped ? "publisher-scoped" : "publisher",
          policyMode,
          scenarioValue as 131 | 12,
          steps,
          warnings,
          `Binary explicitly allowed by publisher rule "${signer.name}": ${m.detail}`
        );
      }
    } else {
      pushStep(steps, {
        phase,
        ruleId: signer.id,
        ruleName: signer.name,
        ruleType,
        outcome: m.skipped ? "skipped" : "no-match",
        detail: m.detail,
      });
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4a — Allow hash rules (most specific file rule)
  // -------------------------------------------------------------------------

  for (const rule of allowFileRules.filter((r) => r.kind === "hash")) {
    const m = matchHash(rule as WdacHashRule, binary);
    pushStep(steps, {
      phase: "allow-hash",
      ruleId: rule.id,
      ruleName: rule.friendlyName ?? rule.id,
      ruleType: "allow-hash",
      outcome: stepOutcome(m),
      detail: m.detail,
    });
    if (m.matched) {
      return finalResult(
        "allowed",
        rule.id,
        rule.friendlyName ?? rule.id,
        "hash",
        policyMode,
        scenarioValue as 131 | 12,
        steps,
        warnings,
        `Binary explicitly allowed by hash rule "${rule.friendlyName ?? rule.id}": ${m.detail}`
      );
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4b — Allow attribute rules
  // -------------------------------------------------------------------------

  for (const rule of allowFileRules.filter((r) => r.kind === "attribute")) {
    const m = matchAttributes(rule as WdacAttributeRule, binary);
    pushStep(steps, {
      phase: "allow-path",
      ruleId: rule.id,
      ruleName: rule.friendlyName ?? rule.id,
      ruleType: "allow-attribute",
      outcome: stepOutcome(m),
      detail: m.detail,
    });
    if (m.matched) {
      return finalResult(
        "allowed",
        rule.id,
        rule.friendlyName ?? rule.id,
        "attribute",
        policyMode,
        scenarioValue as 131 | 12,
        steps,
        warnings,
        `Binary explicitly allowed by attribute rule "${rule.friendlyName ?? rule.id}": ${m.detail}`
      );
    }
  }

  // -------------------------------------------------------------------------
  // Phase 4c — Allow path rules (broadest file rule)
  // -------------------------------------------------------------------------

  for (const rule of allowFileRules.filter((r) => r.kind === "path")) {
    const m = matchPath(rule as WdacPathRule, binary);
    pushStep(steps, {
      phase: "allow-path",
      ruleId: rule.id,
      ruleName: rule.friendlyName ?? rule.id,
      ruleType: "allow-path",
      outcome: stepOutcome(m),
      detail: m.detail,
    });
    if (m.matched) {
      return finalResult(
        "allowed",
        rule.id,
        rule.friendlyName ?? rule.id,
        "path",
        policyMode,
        scenarioValue as 131 | 12,
        steps,
        warnings,
        `Binary explicitly allowed by path rule "${rule.friendlyName ?? rule.id}": ${m.detail}`
      );
    }
  }

  // -------------------------------------------------------------------------
  // Phase 5 — Default deny
  // -------------------------------------------------------------------------

  pushStep(steps, {
    phase: "default",
    ruleType: "default-deny",
    outcome: "matched",
    detail:
      "No matching rule found. App Control implicit default action: deny all unlisted binaries.",
  });

  return finalResult(
    "blocked",
    undefined,
    undefined,
    "default",
    policyMode,
    scenarioValue as 131 | 12,
    steps,
    warnings,
    `No matching allow rule was found. The binary is blocked by the policy's implicit default deny action.`
  );
}

// ---------------------------------------------------------------------------
// Rule matching — hash
// ---------------------------------------------------------------------------

interface MatchOutcome {
  matched: boolean;
  skipped?: boolean;
  detail: string;
}

function matchHash(rule: WdacHashRule, binary: BinaryMetadata): MatchOutcome {
  const isSha256 =
    rule.hashType === "SHA256" || rule.hashType === "SHA256Flat";
  const binaryHash = isSha256 ? binary.sha256 : binary.sha1;
  const hashLabel = isSha256 ? "SHA-256" : "SHA-1";

  if (!binaryHash) {
    return {
      matched: false,
      skipped: true,
      detail: `${hashLabel} hash not provided for binary — rule skipped.`,
    };
  }

  const normalise = (h: string) => h.toLowerCase().replace(/^0+/, "");
  const matched = normalise(binaryHash) === normalise(rule.hash);
  return {
    matched,
    detail: matched
      ? `${hashLabel} hash matched: ${binaryHash.slice(0, 16)}…`
      : `${hashLabel} hash does not match rule value ${rule.hash.slice(0, 16)}… (binary: ${binaryHash.slice(0, 16)}…).`,
  };
}

// ---------------------------------------------------------------------------
// Rule matching — path
// ---------------------------------------------------------------------------

/**
 * Official WDAC path rule macros expanded at runtime by the Windows CI kernel driver.
 *
 * Only these three macros are officially supported by the WDAC path rule engine
 * (cipolicy.xsd, WDAC Policy Wizard Helper.cs). Environment variables such as
 * %PROGRAMFILES% and %COMMONPROGRAMFILES% are NOT expanded by the WDAC kernel
 * driver — policies using them would treat the macro as a literal path string.
 *
 * Reference: App Control for Business path rule documentation and WDAC Toolkit
 * Helper.cs path validation logic.
 */
const WDAC_MACROS: [string, string][] = [
  ["%WINDIR%", "C:\\Windows"],
  ["%SYSTEM32%", "C:\\Windows\\System32"],
  ["%OSDRIVE%", "C:"],
];

function expandMacros(pattern: string): string {
  const upper = pattern.toUpperCase();
  for (const [macro, expansion] of WDAC_MACROS) {
    if (upper.startsWith(macro)) {
      return expansion + pattern.slice(macro.length);
    }
  }
  return pattern;
}

/**
 * Convert a WDAC path pattern to a RegExp.
 * WDAC path semantics: * matches any sequence (including path separators),
 * ? matches any single character. Matching is case-insensitive.
 */
function pathPatternToRegex(pattern: string): RegExp {
  const expanded = expandMacros(pattern);
  // Escape all regex metacharacters except * and ?
  const escaped = expanded
    .replace(/[-[\]{}()+^$.|\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`, "i");
}

function matchPath(rule: WdacPathRule, binary: BinaryMetadata): MatchOutcome {
  if (!binary.filePath) {
    return {
      matched: false,
      skipped: true,
      detail: "File path not provided for binary — rule skipped.",
    };
  }

  const normalised = binary.filePath.replace(/\//g, "\\");
  const re = pathPatternToRegex(rule.filePath);
  const matched = re.test(normalised);
  return {
    matched,
    detail: matched
      ? `Path "${binary.filePath}" matches pattern "${rule.filePath}".`
      : `Path "${binary.filePath}" does not match pattern "${rule.filePath}".`,
  };
}

// ---------------------------------------------------------------------------
// Rule matching — attribute (also used for FileAttrib scoping)
// ---------------------------------------------------------------------------

interface AttribLike {
  fileName?: string;
  internalName?: string;
  fileDescription?: string;
  productName?: string;
  minimumFileVersion?: string;
  maximumFileVersion?: string;
}

function matchAttributes(rule: AttribLike, binary: BinaryMetadata): MatchOutcome {
  const checks: string[] = [];
  let hasConstraint = false;

  function check(label: string, ruleVal: string | undefined, binaryVal: string | undefined): boolean {
    if (!ruleVal) return true; // no constraint → always pass
    hasConstraint = true;
    const ok = ci(binaryVal) === ci(ruleVal);
    checks.push(`${label} "${ruleVal}": ${ok ? "✓" : `✗ (binary: "${binaryVal ?? "—"}")`}`);
    return ok;
  }

  const ok =
    check("OriginalFileName", rule.fileName, binary.originalFileName) &&
    check("InternalName", rule.internalName, binary.internalName) &&
    check("ProductName", rule.productName, binary.productName);

  if (!ok) return { matched: false, detail: checks.join("; ") };

  if (rule.minimumFileVersion) {
    hasConstraint = true;
    const pass =
      compareVersions(binary.fileVersion ?? "0.0.0.0", rule.minimumFileVersion) >= 0;
    checks.push(
      `FileVersion >= ${rule.minimumFileVersion}: ${pass ? "✓" : `✗ (binary: "${binary.fileVersion ?? "—"}")`}`
    );
    if (!pass) return { matched: false, detail: checks.join("; ") };
  }

  if (rule.maximumFileVersion) {
    hasConstraint = true;
    const pass =
      compareVersions(binary.fileVersion ?? "9999.9999.9999.9999", rule.maximumFileVersion) <= 0;
    checks.push(
      `FileVersion <= ${rule.maximumFileVersion}: ${pass ? "✓" : `✗ (binary: "${binary.fileVersion ?? "—"}")`}`
    );
    if (!pass) return { matched: false, detail: checks.join("; ") };
  }

  if (!hasConstraint) {
    return { matched: false, detail: "Attribute rule has no conditions — skipped." };
  }

  return { matched: true, detail: checks.join("; ") };
}

// ---------------------------------------------------------------------------
// Rule matching — signer (publisher)
// ---------------------------------------------------------------------------

function matchSigner(
  signer: WdacSignerRule,
  binary: BinaryMetadata,
  fileRulesById: Map<string, WdacFileRule>
): MatchOutcome {
  const checks: string[] = [];

  // --- certRoot ---
  if (signer.certRoot) {
    if (signer.certRoot.type === "TBS") {
      if (!binary.rootCertTbs) {
        return {
          matched: false,
          skipped: true,
          detail: `Signer "${signer.name}": certRoot TBS requires root certificate hash — not provided for binary.`,
        };
      }
      if (ci(binary.rootCertTbs) !== ci(signer.certRoot.value)) {
        checks.push(`certRoot TBS ${signer.certRoot.value.slice(0, 12)}…: ✗`);
        return { matched: false, detail: `Signer "${signer.name}": ${checks.join("; ")}` };
      }
      checks.push(`certRoot TBS: ✓`);
    } else if (signer.certRoot.type === "Wellknown") {
      // Well-known root IDs (e.g. "1" = Windows Component root) cannot be
      // validated from metadata alone; treat as a soft match if binary is signed.
      if (!binary.signerName && !binary.rootCertTbs) {
        return {
          matched: false,
          skipped: true,
          detail: `Signer "${signer.name}": certRoot Wellknown ID ${signer.certRoot.value} — binary has no signing info to verify against.`,
        };
      }
      checks.push(`certRoot Wellknown ID ${signer.certRoot.value}: assumed ✓ (cannot verify from metadata)`);
    }
  }

  // --- certPublisher (leaf cert CN) ---
  if (signer.certPublisher) {
    if (!binary.signerName) {
      return {
        matched: false,
        skipped: true,
        detail: `Signer "${signer.name}": certPublisher check requires signer name — not provided for binary.`,
      };
    }
    if (ci(binary.signerName) !== ci(signer.certPublisher)) {
      checks.push(
        `certPublisher "${signer.certPublisher}": ✗ (binary: "${binary.signerName}")`
      );
      return { matched: false, detail: `Signer "${signer.name}": ${checks.join("; ")}` };
    }
    checks.push(`certPublisher "${signer.certPublisher}": ✓`);
  }

  // --- certIssuer ---
  if (signer.certIssuer && binary.issuerName) {
    if (ci(binary.issuerName) !== ci(signer.certIssuer)) {
      checks.push(
        `certIssuer "${signer.certIssuer}": ✗ (binary: "${binary.issuerName}")`
      );
      return { matched: false, detail: `Signer "${signer.name}": ${checks.join("; ")}` };
    }
    checks.push(`certIssuer "${signer.certIssuer}": ✓`);
  }

  // Guard: if the signer rule has no cert constraints and the binary has no
  // signing info at all, we cannot assert a match.
  if (!signer.certRoot && !signer.certPublisher && !signer.certIssuer) {
    if (!binary.signerName && !binary.rootCertTbs) {
      return {
        matched: false,
        skipped: true,
        detail: `Signer "${signer.name}": rule has no cert constraints and binary has no signing info — cannot determine match.`,
      };
    }
    checks.push("(no explicit cert constraint — matches any signed binary)");
  }

  // --- FileAttrib scoping ---
  if (signer.fileAttribRefs && signer.fileAttribRefs.length > 0) {
    let anyAttribMatched = false;
    const attribDetails: string[] = [];

    for (const ref of signer.fileAttribRefs) {
      const attrib = fileRulesById.get(ref);
      if (!attrib || attrib.kind !== "fileAttrib") {
        attribDetails.push(`FileAttrib ${ref}: not found in policy`);
        continue;
      }
      const am = matchAttributes(attrib as WdacFileAttrib, binary);
      attribDetails.push(
        `FileAttrib "${attrib.friendlyName ?? ref}": ${am.matched ? "✓" : "✗"} (${am.detail})`
      );
      if (am.matched) {
        anyAttribMatched = true;
        break;
      }
    }

    if (!anyAttribMatched) {
      return {
        matched: false,
        detail: `Signer "${signer.name}" cert constraints matched, but FileAttrib scope did not: ${attribDetails.join("; ")}`,
      };
    }
    checks.push(
      `FileAttrib scope: ✓ (${attribDetails.find((d) => d.includes("✓")) ?? "matched"})`
    );
  }

  return {
    matched: true,
    detail: `Signer "${signer.name}": ${checks.length ? checks.join("; ") : "publisher trust (no explicit cert constraints)"}`,
  };
}

// ---------------------------------------------------------------------------
// Exception check — does the binary match any of the given exception rule IDs?
// ---------------------------------------------------------------------------

function matchesAnyFileRule(
  ruleIds: string[],
  binary: BinaryMetadata,
  fileRulesById: Map<string, WdacFileRule>
): boolean {
  for (const id of ruleIds) {
    const rule = fileRulesById.get(id);
    if (!rule || rule.kind === "fileAttrib") continue;
    let m: MatchOutcome;
    if (rule.kind === "hash") m = matchHash(rule as WdacHashRule, binary);
    else if (rule.kind === "path") m = matchPath(rule as WdacPathRule, binary);
    else m = matchAttributes(rule as WdacAttributeRule, binary);
    if (m.matched) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Result builder
// ---------------------------------------------------------------------------

function finalResult(
  rawVerdict: "allowed" | "blocked",
  ruleId: string | undefined,
  ruleName: string | undefined,
  matchedBy: MatchedBy,
  policyMode: "enforcement" | "audit",
  scenarioValue: 131 | 12 | undefined,
  steps: EvalStep[],
  warnings: string[],
  explanation: string
): EvaluationResult {
  // Derive matchingRuleType from the last "matched" step
  const lastMatch = [...steps].reverse().find(
    (s) => s.outcome === "matched" || s.outcome === "excepted"
  );
  const matchingRuleType = lastMatch?.ruleType;

  if (policyMode === "audit") {
    return {
      verdict: "audit-only",
      enforcementVerdict: rawVerdict,
      matchingRuleId: ruleId,
      matchingRuleName: ruleName,
      matchingRuleType,
      matchedBy,
      scenarioValue,
      policyMode: "audit",
      explanation: `[Audit Mode] ${explanation} In enforcement mode this binary would be ${rawVerdict === "allowed" ? "allowed ✓" : "blocked ✗"}.`,
      steps,
      warnings,
    };
  }

  return {
    verdict: rawVerdict,
    matchingRuleId: ruleId,
    matchingRuleName: ruleName,
    matchingRuleType,
    matchedBy,
    scenarioValue,
    policyMode: "enforcement",
    explanation,
    steps,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function pushStep(steps: EvalStep[], partial: Omit<EvalStep, never>): void {
  steps.push(partial);
}

function stepOutcome(m: MatchOutcome): StepOutcome {
  if (m.matched) return "matched";
  if (m.skipped) return "skipped";
  return "no-match";
}

/** Case-insensitive string normalisation. */
function ci(s: string | undefined): string {
  return s?.toLowerCase() ?? "";
}

/**
 * Compare two version strings in "major.minor.patch.build" format.
 * Returns negative if a < b, zero if a === b, positive if a > b.
 */
function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((p) => parseInt(p, 10) || 0);
  const pb = b.split(".").map((p) => parseInt(p, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
