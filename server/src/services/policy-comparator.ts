/**
 * WDAC Policy Comparator
 *
 * Performs a structured, semantic diff of two WdacPolicy objects.
 * Comparison is by logical identity (ID, type, content) — not textual diff.
 * This allows meaningful comparison even when XML formatting or ordering differs.
 */

import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  PolicyComparisonResult,
  OptionDiff,
  FileRuleDiff,
  SignerDiff,
  ScenarioDiff,
  PolicyRuleOptionNumber,
  SigningScenarioValue,
} from "@appcontrol/shared";
import { POLICY_RULE_OPTIONS } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Main comparison entry point
// ---------------------------------------------------------------------------

export function comparePolicies(
  left: WdacPolicy,
  right: WdacPolicy
): PolicyComparisonResult {
  const optionDiffs = compareOptions(left, right);
  const fileRuleDiffs = compareFileRules(left, right);
  const signerDiffs = compareSigners(left, right);
  const scenarioDiffs = compareScenarios(left, right);

  const totalDifferences =
    optionDiffs.filter((d) => d.status !== "unchanged").length +
    fileRuleDiffs.filter((d) => d.status !== "unchanged").length +
    signerDiffs.filter((d) => d.status !== "unchanged").length +
    scenarioDiffs.reduce(
      (sum, s) =>
        sum +
        s.addedAllowedSigners.length +
        s.removedAllowedSigners.length +
        s.addedDeniedSigners.length +
        s.removedDeniedSigners.length +
        s.addedFileRuleRefs.length +
        s.removedFileRuleRefs.length,
      0
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
    summary: {
      totalDifferences,
      optionChanges: optionDiffs.filter((d) => d.status !== "unchanged").length,
      fileRuleChanges: fileRuleDiffs.filter((d) => d.status !== "unchanged").length,
      signerChanges: signerDiffs.filter((d) => d.status !== "unchanged").length,
      scenarioChanges: scenarioDiffs.reduce(
        (sum, s) =>
          sum +
          s.addedAllowedSigners.length +
          s.removedAllowedSigners.length +
          s.addedDeniedSigners.length +
          s.removedDeniedSigners.length +
          s.addedFileRuleRefs.length +
          s.removedFileRuleRefs.length,
        0
      ),
    },
    optionDiffs,
    fileRuleDiffs,
    signerDiffs,
    scenarioDiffs,
  };
}

// ---------------------------------------------------------------------------
// Option comparison
// ---------------------------------------------------------------------------

function compareOptions(left: WdacPolicy, right: WdacPolicy): OptionDiff[] {
  const diffs: OptionDiff[] = [];
  const allOptionValues = new Set<number>([
    ...left.options.map((o) => o.value as number),
    ...right.options.map((o) => o.value as number),
    ...Object.keys(POLICY_RULE_OPTIONS).map(Number),
  ]);

  for (const num of Array.from(allOptionValues).sort((a, b) => a - b)) {
    const leftOpt = left.options.find((o) => (o.value as number) === num);
    const rightOpt = right.options.find((o) => (o.value as number) === num);
    const def = POLICY_RULE_OPTIONS[num as keyof typeof POLICY_RULE_OPTIONS];
    if (!def) continue;

    const leftEnabled = leftOpt?.enabled ?? false;
    const rightEnabled = rightOpt?.enabled ?? false;

    let status: OptionDiff["status"] = "unchanged";
    if (leftEnabled && !rightEnabled) status = "removed";
    else if (!leftEnabled && rightEnabled) status = "added";
    else if (leftEnabled !== rightEnabled) status = "changed";

    // Only include diffs and options that are set in at least one policy
    if (status !== "unchanged" || leftEnabled || rightEnabled) {
      diffs.push({
        optionValue: num as PolicyRuleOptionNumber,
        optionName: def.name,
        status,
        leftEnabled,
        rightEnabled,
      });
    }
  }

  return diffs;
}

// ---------------------------------------------------------------------------
// File rule comparison — keyed by ID, then by content hash for moved rules
// ---------------------------------------------------------------------------

function fileRuleFingerprint(rule: WdacFileRule): string {
  // Canonical fingerprint for structural equivalence
  return JSON.stringify({
    type: rule.type,
    hash: rule.hash,
    hashType: rule.hashType,
    fileName: rule.fileName,
    internalName: rule.internalName,
    fileDescription: rule.fileDescription,
    productName: rule.productName,
    minimumFileVersion: rule.minimumFileVersion,
    maximumFileVersion: rule.maximumFileVersion,
    filePath: rule.filePath,
    packageFamilyName: rule.packageFamilyName,
    packageVersion: rule.packageVersion,
  });
}

function compareFileRules(left: WdacPolicy, right: WdacPolicy): FileRuleDiff[] {
  const diffs: FileRuleDiff[] = [];
  const leftById = new Map(left.fileRules.map((r) => [r.id, r]));
  const rightById = new Map(right.fileRules.map((r) => [r.id, r]));
  const allIds = new Set([...leftById.keys(), ...rightById.keys()]);

  for (const id of allIds) {
    const l = leftById.get(id);
    const r = rightById.get(id);

    if (l && !r) {
      diffs.push({ id, status: "removed", left: l });
    } else if (!l && r) {
      diffs.push({ id, status: "added", right: r });
    } else if (l && r) {
      const changedFields = findChangedFields(l, r, [
        "type", "hash", "hashType", "fileName", "internalName",
        "fileDescription", "productName", "minimumFileVersion",
        "maximumFileVersion", "filePath", "packageFamilyName",
        "packageVersion", "friendlyName",
      ]);
      const status = changedFields.length > 0 ? "changed" : "unchanged";
      diffs.push({ id, status, left: l, right: r, changedFields });
    }
  }

  return diffs.sort((a, b) => statusOrder(a.status) - statusOrder(b.status));
}

// ---------------------------------------------------------------------------
// Signer comparison
// ---------------------------------------------------------------------------

function signerFingerprint(signer: WdacSignerRule): string {
  return JSON.stringify({
    certRoot: signer.certRoot,
    certEKU: signer.certEKU?.map((e) => e.ekuId).sort(),
    certIssuer: signer.certIssuer,
    certPublisher: signer.certPublisher,
    certOemID: signer.certOemID,
    fileAttribRefs: signer.fileAttribRefs?.sort(),
  });
}

function compareSigners(left: WdacPolicy, right: WdacPolicy): SignerDiff[] {
  const diffs: SignerDiff[] = [];
  const leftById = new Map(left.signers.map((s) => [s.id, s]));
  const rightById = new Map(right.signers.map((s) => [s.id, s]));
  const allIds = new Set([...leftById.keys(), ...rightById.keys()]);

  for (const id of allIds) {
    const l = leftById.get(id);
    const r = rightById.get(id);

    if (l && !r) {
      diffs.push({ id, status: "removed", left: l });
    } else if (!l && r) {
      diffs.push({ id, status: "added", right: r });
    } else if (l && r) {
      const changedFields = findChangedSignerFields(l, r);
      const status = changedFields.length > 0 ? "changed" : "unchanged";
      diffs.push({ id, status, left: l, right: r, changedFields });
    }
  }

  return diffs.sort((a, b) => statusOrder(a.status) - statusOrder(b.status));
}

function findChangedSignerFields(l: WdacSignerRule, r: WdacSignerRule): string[] {
  const changed: string[] = [];
  if (l.name !== r.name) changed.push("name");
  if (JSON.stringify(l.certRoot) !== JSON.stringify(r.certRoot)) changed.push("certRoot");
  if (JSON.stringify(l.certEKU) !== JSON.stringify(r.certEKU)) changed.push("certEKU");
  if (l.certIssuer !== r.certIssuer) changed.push("certIssuer");
  if (l.certPublisher !== r.certPublisher) changed.push("certPublisher");
  if (l.certOemID !== r.certOemID) changed.push("certOemID");
  if (JSON.stringify(l.fileAttribRefs?.sort()) !== JSON.stringify(r.fileAttribRefs?.sort()))
    changed.push("fileAttribRefs");
  return changed;
}

// ---------------------------------------------------------------------------
// Signing scenario comparison
// ---------------------------------------------------------------------------

function compareScenarios(left: WdacPolicy, right: WdacPolicy): ScenarioDiff[] {
  const diffs: ScenarioDiff[] = [];
  const scenarioValues: SigningScenarioValue[] = [131, 12];

  for (const value of scenarioValues) {
    const leftSS = left.signingScenarios.find((s) => s.value === value);
    const rightSS = right.signingScenarios.find((s) => s.value === value);

    if (!leftSS && !rightSS) continue;

    const leftAllowed = new Set((leftSS?.allowedSigners ?? []).map((s) => s.signerId));
    const rightAllowed = new Set((rightSS?.allowedSigners ?? []).map((s) => s.signerId));
    const leftDenied = new Set((leftSS?.deniedSigners ?? []).map((s) => s.signerId));
    const rightDenied = new Set((rightSS?.deniedSigners ?? []).map((s) => s.signerId));
    const leftFiles = new Set(leftSS?.fileRuleRefs ?? []);
    const rightFiles = new Set(rightSS?.fileRuleRefs ?? []);

    diffs.push({
      scenarioValue: value,
      addedAllowedSigners: [...rightAllowed].filter((id) => !leftAllowed.has(id)),
      removedAllowedSigners: [...leftAllowed].filter((id) => !rightAllowed.has(id)),
      addedDeniedSigners: [...rightDenied].filter((id) => !leftDenied.has(id)),
      removedDeniedSigners: [...leftDenied].filter((id) => !rightDenied.has(id)),
      addedFileRuleRefs: [...rightFiles].filter((id) => !leftFiles.has(id)),
      removedFileRuleRefs: [...leftFiles].filter((id) => !rightFiles.has(id)),
    });
  }

  return diffs;
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function findChangedFields(l: Record<string, unknown>, r: Record<string, unknown>, fields: string[]): string[] {
  return fields.filter((f) => {
    const lv = (l as Record<string, unknown>)[f];
    const rv = (r as Record<string, unknown>)[f];
    return JSON.stringify(lv) !== JSON.stringify(rv);
  });
}

function statusOrder(status: string): number {
  const order: Record<string, number> = { changed: 0, added: 1, removed: 2, unchanged: 3 };
  return order[status] ?? 99;
}
