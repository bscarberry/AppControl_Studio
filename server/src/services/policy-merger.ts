/**
 * Policy Merger Service
 *
 * Merges 2–15 WDAC policies into one, following the WDAC Policy Wizard's merge
 * behavior:
 *   - The merged policy inherits PolicyID, FriendlyName, and VersionEx from the
 *     FIRST policy in the input list.
 *   - All file rules, signers, EKUs, and signing scenarios are unioned.
 *   - Duplicate rules are detected by content fingerprint (not just ID) so that
 *     semantically identical rules from different policies are merged cleanly.
 *   - Rule IDs are re-generated with a per-source prefix to avoid collisions.
 *   - Policy rule options are unioned (any policy enabling an option = enabled).
 *   - SigningScenarios are merged: allowedSigners / deniedSigners / fileRuleRefs
 *     are unioned within each scenario value (131 / 12).
 */

import crypto from "crypto";
import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  WdacSigningScenario,
  WdacEku,
  WdacHashRule,
  WdacPathRule,
  WdacPackageRule,
  WdacAttributeRule,
  WdacFileAttrib,
  PolicyRuleOption,
  PolicyRuleOptionNumber,
  AllowedSigner,
  DeniedSigner,
  SigningScenarioValue,
} from "@appcontrol/shared";
import { generateWdacXml } from "./xml-generator.js";

// ---------------------------------------------------------------------------
// Content fingerprints — used for semantic deduplication
// ---------------------------------------------------------------------------

function hashFingerprint(r: WdacHashRule): string {
  return `hash:${r.effect}:${r.hashType}:${r.hash.toUpperCase()}`;
}

function pathFingerprint(r: WdacPathRule): string {
  return `path:${r.effect}:${r.filePath.toLowerCase()}`;
}

function packageFingerprint(r: WdacPackageRule): string {
  return `pkg:${r.effect}:${r.packageFamilyName.toLowerCase()}`;
}

function attributeFingerprint(r: WdacAttributeRule): string {
  const parts = [r.effect, r.fileName ?? "", r.internalName ?? "", r.productName ?? ""];
  return `attr:${parts.join("|").toLowerCase()}`;
}

function fileAttribFingerprint(r: WdacFileAttrib): string {
  const parts = [r.fileName ?? "", r.internalName ?? "", r.productName ?? ""];
  return `fa:${parts.join("|").toLowerCase()}`;
}

function fileRuleFingerprint(r: WdacFileRule): string {
  switch (r.kind) {
    case "hash":      return hashFingerprint(r);
    case "path":      return pathFingerprint(r);
    case "package":   return packageFingerprint(r);
    case "attribute": return attributeFingerprint(r);
    case "fileAttrib":return fileAttribFingerprint(r);
  }
}

function signerFingerprint(s: WdacSignerRule): string {
  const root  = s.certRoot ? `${s.certRoot.type}:${s.certRoot.value.toUpperCase()}` : "";
  const pub   = s.certPublisher?.toLowerCase() ?? "";
  const issuer = s.certIssuer?.toLowerCase() ?? "";
  return `sig:${root}|${pub}|${issuer}`;
}

function ekuFingerprint(e: WdacEku): string {
  return e.value.toUpperCase();
}

// ---------------------------------------------------------------------------
// ID generators
// ---------------------------------------------------------------------------

function shortHex(): string {
  return crypto.randomBytes(3).toString("hex").toUpperCase();
}

function newFileRuleId(kind: WdacFileRule["kind"], effect?: string): string {
  switch (kind) {
    case "hash":      return `ID_ALLOW_A_${shortHex()}`;
    case "path":      return `ID_PATH_P_${shortHex()}`;
    case "package":   return `ID_PKG_K_${shortHex()}`;
    case "attribute": return `ID_ATTR_T_${shortHex()}`;
    case "fileAttrib":return `ID_FILEATTRIB_F_${shortHex()}`;
  }
  return `ID_RULE_${shortHex()}`;
}

function newSignerId(): string {
  return `ID_SIGNER_S_${shortHex()}`;
}

function newEkuId(): string {
  return `ID_EKU_E_${shortHex()}`;
}

// ---------------------------------------------------------------------------
// Main merge function
// ---------------------------------------------------------------------------

export interface MergeResult {
  policy: WdacPolicy;
  log: string[];
  stats: {
    inputPolicies: number;
    totalFileRules: number;
    dedupedFileRules: number;
    totalSigners: number;
    dedupedSigners: number;
  };
}

export function mergePolicies(
  policies: WdacPolicy[],
  friendlyNameOverride?: string
): MergeResult {
  if (policies.length < 2) throw new Error("At least two policies required for merge.");
  if (policies.length > 15) throw new Error("Maximum 15 policies per merge (WDAC limit).");

  const log: string[] = [];
  const base = policies[0];

  log.push(`Merging ${policies.length} policies. Base identity from: "${base.friendlyName ?? base.policyId}"`);

  // ---- 1. Policy options: union (any policy enabling = enabled) ----
  const mergedOptions = new Map<PolicyRuleOptionNumber, PolicyRuleOption>();
  for (const policy of policies) {
    for (const opt of policy.options) {
      const existing = mergedOptions.get(opt.value);
      if (!existing || opt.enabled) {
        mergedOptions.set(opt.value, { ...opt });
      }
    }
  }
  log.push(`Options: ${mergedOptions.size} unique options after union.`);

  // ---- 2. EKUs: deduplicate by value fingerprint ----
  const ekuByFp = new Map<string, WdacEku>();
  const ekuIdMap = new Map<string, string>(); // old ID → new ID

  for (const policy of policies) {
    for (const eku of policy.ekus) {
      const fp = ekuFingerprint(eku);
      if (!ekuByFp.has(fp)) {
        const newId = newEkuId();
        ekuIdMap.set(eku.id, newId);
        ekuByFp.set(fp, { ...eku, id: newId });
      } else {
        ekuIdMap.set(eku.id, ekuByFp.get(fp)!.id);
      }
    }
  }

  // ---- 3. File rules: deduplicate by fingerprint ----
  let totalFileRules = 0;
  const fileRuleByFp = new Map<string, WdacFileRule>();
  const fileRuleIdMap = new Map<string, string>(); // old ID → new ID

  for (const policy of policies) {
    for (const rule of policy.fileRules) {
      totalFileRules++;
      const fp = fileRuleFingerprint(rule);
      if (!fileRuleByFp.has(fp)) {
        const newId = newFileRuleId(rule.kind);
        const retagged = { ...rule, id: newId } as WdacFileRule;
        fileRuleIdMap.set(rule.id, newId);
        fileRuleByFp.set(fp, retagged);
        log.push(`  + FileRule [${rule.kind}] ${rule.id} → ${newId}`);
      } else {
        const existingId = fileRuleByFp.get(fp)!.id;
        fileRuleIdMap.set(rule.id, existingId);
        log.push(`  ~ FileRule [${rule.kind}] ${rule.id} deduplicated → ${existingId}`);
      }
    }
  }

  const mergedFileRules = [...fileRuleByFp.values()];
  log.push(`File rules: ${totalFileRules} total → ${mergedFileRules.length} after dedup.`);

  // ---- 4. Signers: deduplicate by cert fingerprint ----
  let totalSigners = 0;
  const signerByFp = new Map<string, WdacSignerRule>();
  const signerIdMap = new Map<string, string>(); // old ID → new ID

  for (const policy of policies) {
    for (const signer of policy.signers) {
      totalSigners++;
      const fp = signerFingerprint(signer);
      if (!signerByFp.has(fp)) {
        const newId = newSignerId();
        signerIdMap.set(signer.id, newId);
        // Remap fileAttribRefs to new IDs
        const remappedAttribs = signer.fileAttribRefs
          ?.map((ref) => fileRuleIdMap.get(ref) ?? ref)
          .filter((id) => mergedFileRules.some((r) => r.id === id));
        // Remap certEKU IDs
        const remappedEkus = signer.certEKU?.map((e) => ({
          ekuId: ekuIdMap.get(e.ekuId) ?? e.ekuId,
        }));
        signerByFp.set(fp, {
          ...signer,
          id: newId,
          fileAttribRefs: remappedAttribs?.length ? remappedAttribs : undefined,
          certEKU: remappedEkus?.length ? remappedEkus : undefined,
        });
        log.push(`  + Signer ${signer.id} → ${newId} (${signer.name})`);
      } else {
        const existingId = signerByFp.get(fp)!.id;
        signerIdMap.set(signer.id, existingId);
        log.push(`  ~ Signer ${signer.id} deduplicated → ${existingId} (${signer.name})`);
      }
    }
  }

  const mergedSigners = [...signerByFp.values()];
  log.push(`Signers: ${totalSigners} total → ${mergedSigners.length} after dedup.`);

  // ---- 5. Signing scenarios: union per scenario value ----
  const scenarioMap = new Map<SigningScenarioValue, {
    allowedSigners: Map<string, AllowedSigner>;
    deniedSigners: Map<string, DeniedSigner>;
    fileRuleRefs: Set<string>;
    minHashVersion?: string;
  }>();

  for (const policy of policies) {
    for (const sc of policy.signingScenarios) {
      if (!scenarioMap.has(sc.value)) {
        scenarioMap.set(sc.value, {
          allowedSigners: new Map(),
          deniedSigners: new Map(),
          fileRuleRefs: new Set(),
          minHashVersion: sc.minHashVersion,
        });
      }
      const entry = scenarioMap.get(sc.value)!;

      for (const as of sc.allowedSigners) {
        const newSignerId = signerIdMap.get(as.signerId) ?? as.signerId;
        if (mergedSigners.some((s) => s.id === newSignerId)) {
          entry.allowedSigners.set(newSignerId, {
            signerId: newSignerId,
            exceptDenyRuleIds: as.exceptDenyRuleIds
              ?.map((id) => fileRuleIdMap.get(id) ?? id)
              .filter((id) => mergedFileRules.some((r) => r.id === id)),
          });
        }
      }

      for (const ds of sc.deniedSigners) {
        const newSignerId = signerIdMap.get(ds.signerId) ?? ds.signerId;
        if (mergedSigners.some((s) => s.id === newSignerId)) {
          entry.deniedSigners.set(newSignerId, {
            signerId: newSignerId,
            exceptAllowRuleIds: ds.exceptAllowRuleIds
              ?.map((id) => fileRuleIdMap.get(id) ?? id)
              .filter((id) => mergedFileRules.some((r) => r.id === id)),
          });
        }
      }

      for (const ref of sc.fileRuleRefs) {
        const newRef = fileRuleIdMap.get(ref) ?? ref;
        if (mergedFileRules.some((r) => r.id === newRef)) {
          entry.fileRuleRefs.add(newRef);
        }
      }
    }
  }

  const mergedScenarios: WdacSigningScenario[] = [];
  for (const [value, entry] of scenarioMap) {
    mergedScenarios.push({
      value,
      id: value === 131 ? "0" : "1",
      minHashVersion: entry.minHashVersion,
      allowedSigners: [...entry.allowedSigners.values()],
      deniedSigners: [...entry.deniedSigners.values()],
      fileRuleRefs: [...entry.fileRuleRefs],
    });
  }

  // ---- 6. Policy-level signer lists: remap + deduplicate ----
  const remapSignerList = (ids: string[]): string[] => {
    const seen = new Set<string>();
    const result: string[] = [];
    for (const id of ids) {
      const newId = signerIdMap.get(id) ?? id;
      if (mergedSigners.some((s) => s.id === newId) && !seen.has(newId)) {
        seen.add(newId);
        result.push(newId);
      }
    }
    return result;
  };

  const mergedUpdatePolicySigners = remapSignerList(
    policies.flatMap((p) => p.updatePolicySigners)
  );
  const mergedCiSigners = remapSignerList(
    policies.flatMap((p) => p.ciSigners)
  );

  // ---- 7. Assemble merged policy ----
  const merged: WdacPolicy = {
    policyId: base.policyId,
    basePolicyId: base.basePolicyId,
    policyType: base.policyType,
    friendlyName: friendlyNameOverride ?? base.friendlyName,
    settingsId: base.settingsId,
    versionEx: base.versionEx,
    platformId: base.platformId,
    policyTypeId: base.policyTypeId,
    policyFormat: base.policyFormat,
    options: [...mergedOptions.values()],
    ekus: [...ekuByFp.values()],
    fileRules: mergedFileRules,
    signers: mergedSigners,
    signingScenarios: mergedScenarios,
    updatePolicySigners: mergedUpdatePolicySigners,
    ciSigners: mergedCiSigners,
    hvciOptions: base.hvciOptions,
  };

  const xml = generateWdacXml(merged);
  log.push(`Merge complete. Generated XML (${xml.length} bytes).`);

  return {
    policy: merged,
    log,
    stats: {
      inputPolicies: policies.length,
      totalFileRules,
      dedupedFileRules: mergedFileRules.length,
      totalSigners,
      dedupedSigners: mergedSigners.length,
    },
  };
}
