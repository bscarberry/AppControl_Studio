/**
 * Pure policy manipulation helpers — shared by client and server.
 *
 * AppControl Manager "Policy Editor" parity:
 *   - regenerateIds        — fresh, schema-conformant IDs for every rule/signer/EKU
 *   - deduplicatePolicy    — remove semantically identical rules and signers
 *   - clearAllRules        — strip every rule while keeping identity + options
 *   - setPolicyType        — convert Base ⇄ Supplemental (option filtering per docs)
 *   - applyOptionPreset    — pre-configured rule option sets
 *   - applyRuleBundles     — merge file-inspection rule bundles into a policy
 *
 * Every function is referentially transparent: it returns a new WdacPolicy
 * and never mutates its input.
 */

import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  WdacEku,
  WdacSigningScenario,
  PolicyRuleOption,
  PolicyRuleOptionNumber,
  SigningScenarioValue,
  WdacFileAttrib,
} from "./policy";
import { SUPPLEMENTAL_ALLOWED_OPTIONS } from "./policy";
import type { FileRuleBundle } from "./file-inspection";

// ---------------------------------------------------------------------------
// GUID helpers
// ---------------------------------------------------------------------------

/** Strip braces and upper-case a GUID; returns undefined for non-GUID input. */
export function normalizeGuid(value: string | undefined | null): string | undefined {
  if (!value) return undefined;
  const m = value.trim().match(/^\{?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}?$/);
  return m ? m[1].toUpperCase() : undefined;
}

export function isValidGuid(value: string | undefined | null): boolean {
  return normalizeGuid(value) !== undefined;
}

/** The all-zero GUID used as a placeholder in some CI events — never a real base policy. */
export const NIL_GUID = "00000000-0000-0000-0000-000000000000";

/** RFC 4122 v4 GUID (upper-case, no braces). Works in Node and browsers. */
export function newGuid(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string; getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (c?.randomUUID) return c.randomUUID().toUpperCase();
  const bytes = new Uint8Array(16);
  if (c?.getRandomValues) c.getRandomValues(bytes);
  else for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// ---------------------------------------------------------------------------
// ID generation (cipolicy.xsd patterns)
//   Allow:      ID_ALLOW_[A-Z][_A-Z0-9]*
//   Deny:       ID_DENY_[A-Z][_A-Z0-9]*
//   FileAttrib: ID_FILEATTRIB_[A-Z][_A-Z0-9]*
//   Signer:     ID_SIGNER_[A-Z][_A-Z0-9]*
//   EKU:        ID_EKU_[A-Z][_A-Z0-9]*
// ---------------------------------------------------------------------------

function seqTag(n: number): string {
  return String(n).padStart(4, "0");
}

export function fileRuleIdFor(rule: WdacFileRule, seq: number): string {
  if (rule.kind === "fileAttrib") return `ID_FILEATTRIB_F_${seqTag(seq)}`;
  const prefix = rule.effect === "Deny" ? "ID_DENY" : "ID_ALLOW";
  const letter = { hash: "A", path: "P", package: "K", attribute: "T" }[rule.kind];
  const suffix = rule.kind === "hash"
    ? (rule.hashType.startsWith("SHA1") ? "_SHA1" : "_SHA256") + (rule.hashType.endsWith("Page") ? "_PAGE" : "")
    : "";
  return `${prefix}_${letter}_${seqTag(seq)}${suffix}`;
}

export function signerIdFor(seq: number, scoped = false): string {
  return `ID_SIGNER_${scoped ? "F" : "S"}_${seqTag(seq)}`;
}

export function ekuIdFor(seq: number): string {
  return `ID_EKU_E_${seqTag(seq)}`;
}

const SCHEMA_ID_PATTERNS = {
  allow: /^ID_(ALLOW|FILE)_[A-Z][_A-Z0-9]*$/,
  deny: /^ID_(DENY|FILE)_[A-Z][_A-Z0-9]*$/,
  fileAttrib: /^ID_(FILEATTRIB|FILE)_[A-Z][_A-Z0-9]*$/,
  signer: /^ID_SIGNER_[A-Z][_A-Z0-9]*$/,
  eku: /^ID_EKU_[A-Z][_A-Z0-9]*$/,
  scenario: /^ID_SIGNINGSCENARIO_[A-Z][_A-Z0-9]*$/,
} as const;

export function isSchemaValidFileRuleId(rule: WdacFileRule): boolean {
  if (rule.kind === "fileAttrib") return SCHEMA_ID_PATTERNS.fileAttrib.test(rule.id);
  return rule.effect === "Deny"
    ? SCHEMA_ID_PATTERNS.deny.test(rule.id)
    : SCHEMA_ID_PATTERNS.allow.test(rule.id);
}

export function isSchemaValidSignerId(id: string): boolean {
  return SCHEMA_ID_PATTERNS.signer.test(id);
}

export function isSchemaValidEkuId(id: string): boolean {
  return SCHEMA_ID_PATTERNS.eku.test(id);
}

export function isSchemaValidScenarioId(id: string): boolean {
  return SCHEMA_ID_PATTERNS.scenario.test(id);
}

// ---------------------------------------------------------------------------
// Reference remapping
// ---------------------------------------------------------------------------

function remapScenario(
  sc: WdacSigningScenario,
  fileRuleMap: Map<string, string>,
  signerMap: Map<string, string>
): WdacSigningScenario {
  const fr = (id: string) => fileRuleMap.get(id) ?? id;
  const sg = (id: string) => signerMap.get(id) ?? id;
  return {
    ...sc,
    allowedSigners: sc.allowedSigners.map((a) => ({
      signerId: sg(a.signerId),
      ...(a.exceptDenyRuleIds?.length ? { exceptDenyRuleIds: a.exceptDenyRuleIds.map(fr) } : {}),
    })),
    deniedSigners: sc.deniedSigners.map((d) => ({
      signerId: sg(d.signerId),
      ...(d.exceptAllowRuleIds?.length ? { exceptAllowRuleIds: d.exceptAllowRuleIds.map(fr) } : {}),
    })),
    fileRuleRefs: sc.fileRuleRefs.map(fr),
  };
}

/**
 * Assign fresh, schema-valid IDs to every EKU, file rule and signer and remap
 * all references. Mirrors AppControl Manager's "IDs shown are the IDs after
 * saving" behaviour and the Policy Wizard's ID renumbering.
 */
export function regenerateIds(policy: WdacPolicy): WdacPolicy {
  const ekuMap = new Map<string, string>();
  const ekus: WdacEku[] = policy.ekus.map((e, i) => {
    const id = ekuIdFor(i + 1);
    ekuMap.set(e.id, id);
    return { ...e, id };
  });

  const fileRuleMap = new Map<string, string>();
  const fileRules: WdacFileRule[] = policy.fileRules.map((r, i) => {
    const id = fileRuleIdFor(r, i + 1);
    fileRuleMap.set(r.id, id);
    return { ...r, id } as WdacFileRule;
  });

  const signerMap = new Map<string, string>();
  const signers: WdacSignerRule[] = policy.signers.map((s, i) => {
    const id = signerIdFor(i + 1, (s.fileAttribRefs?.length ?? 0) > 0);
    signerMap.set(s.id, id);
    return {
      ...s,
      id,
      ...(s.certEKU ? { certEKU: s.certEKU.map((e) => ({ ekuId: ekuMap.get(e.ekuId) ?? e.ekuId })) } : {}),
      ...(s.fileAttribRefs ? { fileAttribRefs: s.fileAttribRefs.map((r) => fileRuleMap.get(r) ?? r) } : {}),
    };
  });

  const sg = (id: string) => signerMap.get(id) ?? id;

  return {
    ...policy,
    ekus,
    fileRules,
    signers,
    signingScenarios: policy.signingScenarios.map((sc) => remapScenario(sc, fileRuleMap, signerMap)),
    updatePolicySigners: policy.updatePolicySigners.map(sg),
    ciSigners: policy.ciSigners.map(sg),
    ...(policy.supplementalPolicySigners
      ? { supplementalPolicySigners: policy.supplementalPolicySigners.map(sg) }
      : {}),
  };
}

// ---------------------------------------------------------------------------
// Deduplication — semantic fingerprints (same approach as the merger)
// ---------------------------------------------------------------------------

export function fileRuleFingerprint(r: WdacFileRule): string {
  switch (r.kind) {
    case "hash":
      return `hash:${r.effect}:${r.hash.toUpperCase()}`;
    case "path":
      return `path:${r.effect}:${r.filePath.toLowerCase()}:${r.minimumFileVersion ?? ""}:${r.maximumFileVersion ?? ""}`;
    case "package":
      return `pkg:${r.effect}:${r.packageFamilyName.toLowerCase()}:${r.packageVersion ?? ""}`;
    case "attribute":
      return `attr:${r.effect}:${[r.fileName, r.internalName, r.fileDescription, r.productName, r.minimumFileVersion, r.maximumFileVersion].map((x) => (x ?? "").toLowerCase()).join("|")}`;
    case "fileAttrib":
      return `fa:${[r.fileName, r.internalName, r.fileDescription, r.productName, r.minimumFileVersion, r.maximumFileVersion].map((x) => (x ?? "").toLowerCase()).join("|")}`;
  }
}

export function signerFingerprint(s: WdacSignerRule, fileRulesById: Map<string, WdacFileRule>): string {
  const root = s.certRoot ? `${s.certRoot.type}:${s.certRoot.value.toUpperCase()}` : "";
  const ekus = (s.certEKU ?? []).map((e) => e.ekuId).sort().join(",");
  const scopes = (s.fileAttribRefs ?? [])
    .map((ref) => {
      const r = fileRulesById.get(ref);
      return r && r.kind === "fileAttrib" ? fileRuleFingerprint(r) : `missing:${ref}`;
    })
    .sort()
    .join(",");
  return `sig:${root}|${(s.certPublisher ?? "").toLowerCase()}|${(s.certIssuer ?? "").toLowerCase()}|${(s.certOemID ?? "").toLowerCase()}|${ekus}|${scopes}|${s.signTimeAfter ?? ""}`;
}

export interface DeduplicateResult {
  policy: WdacPolicy;
  removedFileRules: number;
  removedSigners: number;
  removedEkus: number;
  /** Rule refs that pointed nowhere and were dropped */
  droppedDanglingRefs: number;
}

/**
 * Remove duplicate EKUs, file rules and signers (by semantic fingerprint) and
 * collapse duplicate references. Also drops references to rules/signers that
 * do not exist ("dangling refs").
 */
export function deduplicatePolicy(policy: WdacPolicy): DeduplicateResult {
  // EKUs by value
  const ekuMap = new Map<string, string>();
  const ekuByValue = new Map<string, WdacEku>();
  for (const e of policy.ekus) {
    const key = e.value.toUpperCase();
    const keep = ekuByValue.get(key);
    if (keep) ekuMap.set(e.id, keep.id);
    else { ekuByValue.set(key, e); ekuMap.set(e.id, e.id); }
  }
  const ekus = [...ekuByValue.values()];

  // File rules by fingerprint
  const fileRuleMap = new Map<string, string>();
  const ruleByFp = new Map<string, WdacFileRule>();
  for (const r of policy.fileRules) {
    const fp = fileRuleFingerprint(r);
    const keep = ruleByFp.get(fp);
    if (keep) fileRuleMap.set(r.id, keep.id);
    else { ruleByFp.set(fp, r); fileRuleMap.set(r.id, r.id); }
  }
  const fileRules = [...ruleByFp.values()];
  const fileRulesById = new Map(fileRules.map((r) => [r.id, r]));

  // Signers by fingerprint (after remapping their refs)
  const signerMap = new Map<string, string>();
  const signerByFp = new Map<string, WdacSignerRule>();
  for (const s of policy.signers) {
    const remapped: WdacSignerRule = {
      ...s,
      ...(s.certEKU ? { certEKU: dedupeBy(s.certEKU.map((e) => ({ ekuId: ekuMap.get(e.ekuId) ?? e.ekuId })), (e) => e.ekuId) } : {}),
      ...(s.fileAttribRefs
        ? { fileAttribRefs: [...new Set(s.fileAttribRefs.map((r) => fileRuleMap.get(r) ?? r).filter((r) => fileRulesById.has(r)))] }
        : {}),
    };
    if (remapped.fileAttribRefs && remapped.fileAttribRefs.length === 0) delete remapped.fileAttribRefs;
    const fp = signerFingerprint(remapped, fileRulesById);
    const keep = signerByFp.get(fp);
    if (keep) signerMap.set(s.id, keep.id);
    else { signerByFp.set(fp, remapped); signerMap.set(s.id, s.id); }
  }
  const signers = [...signerByFp.values()];
  const signerIds = new Set(signers.map((s) => s.id));

  let dropped = 0;
  const fr = (id: string): string | null => {
    const n = fileRuleMap.get(id) ?? id;
    if (!fileRulesById.has(n)) { dropped++; return null; }
    return n;
  };
  const sg = (id: string): string | null => {
    const n = signerMap.get(id) ?? id;
    if (!signerIds.has(n)) { dropped++; return null; }
    return n;
  };

  const signingScenarios = policy.signingScenarios.map((sc) => {
    const allowed = new Map<string, { signerId: string; exceptDenyRuleIds?: string[] }>();
    for (const a of sc.allowedSigners) {
      const id = sg(a.signerId); if (!id) continue;
      const ex = (a.exceptDenyRuleIds ?? []).map(fr).filter((x): x is string => !!x);
      const prev = allowed.get(id);
      const merged = [...new Set([...(prev?.exceptDenyRuleIds ?? []), ...ex])];
      allowed.set(id, { signerId: id, ...(merged.length ? { exceptDenyRuleIds: merged } : {}) });
    }
    const denied = new Map<string, { signerId: string; exceptAllowRuleIds?: string[] }>();
    for (const d of sc.deniedSigners) {
      const id = sg(d.signerId); if (!id) continue;
      const ex = (d.exceptAllowRuleIds ?? []).map(fr).filter((x): x is string => !!x);
      const prev = denied.get(id);
      const merged = [...new Set([...(prev?.exceptAllowRuleIds ?? []), ...ex])];
      denied.set(id, { signerId: id, ...(merged.length ? { exceptAllowRuleIds: merged } : {}) });
    }
    const refs = [...new Set(sc.fileRuleRefs.map(fr).filter((x): x is string => !!x))];
    return { ...sc, allowedSigners: [...allowed.values()], deniedSigners: [...denied.values()], fileRuleRefs: refs };
  });

  const remapList = (ids: string[]) => [...new Set(ids.map(sg).filter((x): x is string => !!x))];

  return {
    policy: {
      ...policy,
      ekus,
      fileRules,
      signers,
      signingScenarios,
      updatePolicySigners: remapList(policy.updatePolicySigners),
      ciSigners: remapList(policy.ciSigners),
      ...(policy.supplementalPolicySigners
        ? { supplementalPolicySigners: remapList(policy.supplementalPolicySigners) }
        : {}),
    },
    removedFileRules: policy.fileRules.length - fileRules.length,
    removedSigners: policy.signers.length - signers.length,
    removedEkus: policy.ekus.length - ekus.length,
    droppedDanglingRefs: dropped,
  };
}

function dedupeBy<T>(arr: T[], key: (t: T) => string): T[] {
  const seen = new Set<string>();
  return arr.filter((t) => { const k = key(t); if (seen.has(k)) return false; seen.add(k); return true; });
}

// ---------------------------------------------------------------------------
// Clear all rules
// ---------------------------------------------------------------------------

export function clearAllRules(policy: WdacPolicy): WdacPolicy {
  return {
    ...policy,
    ekus: [],
    fileRules: [],
    signers: [],
    signingScenarios: policy.signingScenarios.map((sc) => ({
      ...sc, allowedSigners: [], deniedSigners: [], fileRuleRefs: [],
    })),
    updatePolicySigners: [],
    ciSigners: [],
    supplementalPolicySigners: undefined,
  };
}

// ---------------------------------------------------------------------------
// Base ⇄ Supplemental conversion
// ---------------------------------------------------------------------------

export function setPolicyType(
  policy: WdacPolicy,
  type: "Base" | "Supplemental",
  basePolicyId?: string
): WdacPolicy {
  if (type === "Supplemental") {
    const base = normalizeGuid(basePolicyId) ?? normalizeGuid(policy.basePolicyId);
    const options = policy.options.filter((o) => SUPPLEMENTAL_ALLOWED_OPTIONS.has(o.value as number));
    if (!options.some((o) => o.value === 5)) options.push({ value: 5, enabled: true });
    return {
      ...policy,
      policyType: "Supplemental",
      policyFormat: "MultiplePolicy",
      basePolicyId: base && base !== policy.policyId ? base : NIL_GUID,
      options,
      // Supplemental policies cannot carry SupplementalPolicySigners
      supplementalPolicySigners: undefined,
    };
  }
  return {
    ...policy,
    policyType: "Base",
    basePolicyId: policy.policyId,
  };
}

// ---------------------------------------------------------------------------
// Option presets — AppControl Manager "Configure Policy Rule Options" templates
// ---------------------------------------------------------------------------

export interface OptionPreset {
  id: string;
  name: string;
  description: string;
  /** Applies to base, supplemental, or both */
  appliesTo: "base" | "supplemental" | "both";
  options: number[];
}

export const OPTION_PRESETS: OptionPreset[] = [
  {
    id: "base-default",
    name: "Base — Default (recommended)",
    description: "Microsoft Default Windows / Allow Microsoft baseline: UMCI, unsigned policy, update without reboot, dynamic code security, revoked-as-unsigned, supplemental policies.",
    appliesTo: "base",
    options: [0, 6, 16, 17, 19, 20],
  },
  {
    id: "base-audit",
    name: "Base — Audit",
    description: "Default baseline plus Audit Mode (3). Use for initial rollout.",
    appliesTo: "base",
    options: [0, 3, 6, 16, 17, 19, 20],
  },
  {
    id: "base-isg",
    name: "Base — Signed and Reputable (ISG)",
    description: "Default baseline plus Intelligent Security Graph (14) and EA invalidation on reboot (15).",
    appliesTo: "base",
    options: [0, 6, 14, 15, 16, 17, 19, 20],
  },
  {
    id: "base-managed-installer",
    name: "Base — Managed Installer",
    description: "Default baseline plus Managed Installer (13) and EA invalidation on reboot (15).",
    appliesTo: "base",
    options: [0, 6, 13, 15, 16, 17, 19, 20],
  },
  {
    id: "base-strict",
    name: "Base — Strict",
    description: "Enforced, WHQL required for drivers, no advanced boot menu, no unsigned policy (requires policy signing).",
    appliesTo: "base",
    options: [0, 2, 16, 17, 19, 20],
  },
  {
    id: "base-test",
    name: "Base — Test mode",
    description: "Audit + Advanced Boot Options Menu (9) + Boot Audit On Failure (10) for lab devices.",
    appliesTo: "base",
    options: [0, 3, 6, 9, 10, 16, 17, 19, 20],
  },
  {
    id: "supplemental-default",
    name: "Supplemental — Default",
    description: "Only options valid in supplemental policies: Inherit Default Policy (5) and Unsigned System Integrity Policy (6).",
    appliesTo: "supplemental",
    options: [5, 6],
  },
];

export function applyOptionPreset(policy: WdacPolicy, preset: OptionPreset): WdacPolicy {
  const options: PolicyRuleOption[] = preset.options.map((v) => ({
    value: v as PolicyRuleOptionNumber,
    enabled: true,
  }));
  return { ...policy, options };
}

export function setOption(policy: WdacPolicy, value: number, enabled: boolean): WdacPolicy {
  const rest = policy.options.filter((o) => (o.value as number) !== value);
  return {
    ...policy,
    options: enabled ? [...rest, { value: value as PolicyRuleOptionNumber, enabled: true }] : rest,
  };
}

export function hasOption(policy: WdacPolicy, value: number): boolean {
  return policy.options.some((o) => (o.value as number) === value && o.enabled);
}

// ---------------------------------------------------------------------------
// Apply file-inspection rule bundles
// ---------------------------------------------------------------------------

export interface ApplyRuleBundlesOptions {
  /** Override the per-bundle scenario (e.g. force user mode). */
  scenarioOverride?: SigningScenarioValue;
  /** Add user-mode allowed signers to <CiSigners> (matches New-CIPolicy -UserPEs). Default true. */
  addCiSigners?: boolean;
}

export interface ApplyRuleBundlesResult {
  policy: WdacPolicy;
  addedFileRules: number;
  addedSigners: number;
  addedEkus: number;
  skipped: number;
}

function ensureScenario(scenarios: WdacSigningScenario[], value: SigningScenarioValue): WdacSigningScenario[] {
  if (scenarios.some((s) => s.value === value)) return scenarios;
  return [
    ...scenarios,
    {
      value,
      id: value === 131 ? "ID_SIGNINGSCENARIO_DRIVERS" : "ID_SIGNINGSCENARIO_WINDOWS",
      allowedSigners: [],
      deniedSigners: [],
      fileRuleRefs: [],
    },
  ];
}

/**
 * Merge rule bundles (from POST /api/files/rules) into a policy. Rules and
 * signers get fresh sequential IDs continuing from the highest existing
 * sequence, duplicates (by fingerprint) are collapsed onto existing rules,
 * and scenario references / CiSigners are updated.
 */
export function applyRuleBundles(
  policy: WdacPolicy,
  bundles: FileRuleBundle[],
  opts: ApplyRuleBundlesOptions = {}
): ApplyRuleBundlesResult {
  const addCi = opts.addCiSigners ?? true;
  let fileRules = [...policy.fileRules];
  let signers = [...policy.signers];
  let ekus = [...policy.ekus];
  let scenarios = [...policy.signingScenarios];
  let ciSigners = [...policy.ciSigners];

  const ruleByFp = new Map(fileRules.map((r) => [fileRuleFingerprint(r), r]));
  const ekuByValue = new Map(ekus.map((e) => [e.value.toUpperCase(), e]));
  const usedIds = new Set<string>([
    ...fileRules.map((r) => r.id), ...signers.map((s) => s.id), ...ekus.map((e) => e.id),
  ]);
  let seq = fileRules.length + signers.length + ekus.length;
  const nextId = (make: (n: number) => string): string => {
    let id: string;
    do { id = make(++seq); } while (usedIds.has(id));
    usedIds.add(id);
    return id;
  };

  let addedFileRules = 0, addedSigners = 0, addedEkus = 0, skipped = 0;

  for (const b of bundles) {
    if (b.skippedReason) { skipped++; continue; }
    const scenarioValue = opts.scenarioOverride ?? b.scenario;
    scenarios = ensureScenario(scenarios, scenarioValue);

    // EKUs
    const ekuIdMap = new Map<string, string>();
    for (const e of b.ekus) {
      const existing = ekuByValue.get(e.value.toUpperCase());
      if (existing) { ekuIdMap.set(e.id, existing.id); continue; }
      const id = nextId(ekuIdFor);
      const ne = { ...e, id };
      ekus.push(ne); ekuByValue.set(ne.value.toUpperCase(), ne); ekuIdMap.set(e.id, id); addedEkus++;
    }

    // File rules (FileAttribs included)
    const ruleIdMap = new Map<string, string>();
    for (const r of b.fileRules) {
      const fp = fileRuleFingerprint(r);
      const existing = ruleByFp.get(fp);
      if (existing) { ruleIdMap.set(r.id, existing.id); continue; }
      const id = nextId((n) => fileRuleIdFor(r, n));
      const nr = { ...r, id } as WdacFileRule;
      fileRules.push(nr); ruleByFp.set(fp, nr); ruleIdMap.set(r.id, id); addedFileRules++;
    }

    // Signers
    const fileRulesById = new Map(fileRules.map((r) => [r.id, r]));
    const signerByFp = new Map(signers.map((s) => [signerFingerprint(s, fileRulesById), s]));
    for (const s of b.signers) {
      const remapped: WdacSignerRule = {
        ...s,
        ...(s.certEKU ? { certEKU: s.certEKU.map((e) => ({ ekuId: ekuIdMap.get(e.ekuId) ?? e.ekuId })) } : {}),
        ...(s.fileAttribRefs ? { fileAttribRefs: s.fileAttribRefs.map((r) => ruleIdMap.get(r) ?? r) } : {}),
      };
      const fp = signerFingerprint(remapped, fileRulesById);
      let target = signerByFp.get(fp);
      if (!target) {
        const id = nextId((n) => signerIdFor(n, (remapped.fileAttribRefs?.length ?? 0) > 0));
        target = { ...remapped, id };
        signers.push(target); signerByFp.set(fp, target); addedSigners++;
      }
      scenarios = scenarios.map((sc) => {
        if (sc.value !== scenarioValue) return sc;
        const list = b.effect === "Deny" ? sc.deniedSigners : sc.allowedSigners;
        if (list.some((x) => x.signerId === target!.id)) return sc;
        return b.effect === "Deny"
          ? { ...sc, deniedSigners: [...sc.deniedSigners, { signerId: target!.id }] }
          : { ...sc, allowedSigners: [...sc.allowedSigners, { signerId: target!.id }] };
      });
      if (addCi && b.effect === "Allow" && scenarioValue === 12 && !ciSigners.includes(target.id)) {
        ciSigners.push(target.id);
      }
    }

    // Scenario file rule refs (Allow/Deny only — FileAttribs are never referenced directly)
    const effectRuleIds = b.fileRules
      .filter((r) => r.kind !== "fileAttrib")
      .map((r) => ruleIdMap.get(r.id) ?? r.id);
    if (effectRuleIds.length) {
      scenarios = scenarios.map((sc) =>
        sc.value === scenarioValue
          ? { ...sc, fileRuleRefs: [...new Set([...sc.fileRuleRefs, ...effectRuleIds])] }
          : sc
      );
    }
  }

  return {
    policy: { ...policy, fileRules, signers, ekus, signingScenarios: scenarios, ciSigners },
    addedFileRules,
    addedSigners,
    addedEkus,
    skipped,
  };
}

// ---------------------------------------------------------------------------
// EKU encoding
//
// <EKU Value="010a2b0601040182370a0306"> is: 0x01, then the length of the OID
// content bytes, then the DER OID content (without the 0x06 tag). The example
// decodes to 1.3.6.1.4.1.311.10.3.6 (Windows System Component Verification).
// ---------------------------------------------------------------------------

export function ekuValueToOid(hexValue: string): string | undefined {
  const hex = hexValue.replace(/[^0-9a-fA-F]/g, "");
  if (hex.length < 6) return undefined;
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.slice(i, i + 2), 16));
  // bytes[0] = 0x01 marker, bytes[1] = length
  const body = bytes.slice(2, 2 + bytes[1]);
  if (body.length === 0) return undefined;
  const parts: number[] = [];
  let v = 0;
  for (let i = 0; i < body.length; i++) {
    v = v * 128 + (body[i] & 0x7f);
    if (!(body[i] & 0x80)) {
      if (parts.length === 0) { parts.push(Math.floor(v / 40), v % 40); }
      else parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}

export function oidToEkuValue(oid: string): string {
  const nums = oid.split(".").map((n) => parseInt(n, 10));
  const body: number[] = [];
  const encode = (n: number) => {
    const stack: number[] = [n & 0x7f];
    n = Math.floor(n / 128);
    while (n > 0) { stack.unshift((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
    body.push(...stack);
  };
  encode(nums[0] * 40 + nums[1]);
  for (const n of nums.slice(2)) encode(n);
  const hex = (b: number) => b.toString(16).padStart(2, "0");
  return `01${hex(body.length)}${body.map(hex).join("")}`;
}

/** Well-known EKUs that appear in Microsoft base policies. */
export const KNOWN_EKUS: Record<string, { id: string; friendlyName: string }> = {
  "1.3.6.1.4.1.311.10.3.6": { id: "ID_EKU_WINDOWS", friendlyName: "Windows System Component Verification" },
  "1.3.6.1.4.1.311.10.3.5": { id: "ID_EKU_WHQL", friendlyName: "Windows Hardware Driver Verification (WHQL)" },
  "1.3.6.1.4.1.311.61.4.1": { id: "ID_EKU_ELAM", friendlyName: "Early Launch Antimalware Driver" },
  "1.3.6.1.4.1.311.61.5.1": { id: "ID_EKU_HAL_EXT", friendlyName: "HAL Extension" },
  "1.3.6.1.4.1.311.10.3.21": { id: "ID_EKU_RT_EXT", friendlyName: "Windows RT Verification" },
  "1.3.6.1.4.1.311.76.3.1": { id: "ID_EKU_STORE", friendlyName: "Windows Store" },
  "1.3.6.1.4.1.311.76.5.1": { id: "ID_EKU_DCODEGEN", friendlyName: "Dynamic Code Generation" },
  "1.3.6.1.4.1.311.76.11.1": { id: "ID_EKU_AM", friendlyName: "AntiMalware" },
  "1.3.6.1.5.5.7.3.3": { id: "ID_EKU_CODESIGNING", friendlyName: "Code Signing" },
};

// ---------------------------------------------------------------------------
// Convenience: resolved FileAttribs for a signer
// ---------------------------------------------------------------------------

export function resolveFileAttribs(policy: WdacPolicy, signer: WdacSignerRule): WdacFileAttrib[] {
  const byId = new Map(policy.fileRules.map((r) => [r.id, r]));
  return (signer.fileAttribRefs ?? [])
    .map((id) => byId.get(id))
    .filter((r): r is WdacFileAttrib => !!r && r.kind === "fileAttrib");
}
