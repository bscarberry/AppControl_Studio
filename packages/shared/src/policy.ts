/**
 * WDAC Policy Data Models
 *
 * Modeled after Microsoft's App Control for Business (WDAC) XML schema.
 * Reference: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create
 *
 * Schema source: C:\Windows\schemas\CodeIntegrity\cipolicy.xsd
 */

// ---------------------------------------------------------------------------
// Policy Rule Options
// Ref: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/policy-rules
// ---------------------------------------------------------------------------

export const POLICY_RULE_OPTIONS = {
  0: { name: "Enabled:UMCI", description: "Enables user-mode code integrity (UMCI) enforcement. Without this, only kernel-mode code is enforced.", critical: true },
  1: { name: "Enabled:Boot Menu Protection", description: "Protects the boot menu from unauthorized modification." },
  2: { name: "Required:WHQL", description: "Requires that all kernel-mode drivers be WHQL signed." },
  3: { name: "Enabled:Audit Mode", description: "Runs the policy in audit mode — violations are logged but not blocked.", critical: true },
  4: { name: "Disabled:Flight Signing", description: "Disables trust for Microsoft flight-signed (pre-release) code." },
  5: { name: "Enabled:Inherit Default Policy", description: "Inherits rules from the Default Windows mode policy." },
  6: { name: "Enabled:Unsigned System Integrity Policy", description: "Allows unsigned App Control policies to be used." },
  7: { name: "Allowed:Debug Policy Augmented", description: "Allows kernel debugger to augment policies (not recommended for production)." },
  8: { name: "Required:EV Signers", description: "Requires Extended Validation (EV) certificates for drivers." },
  9: { name: "Enabled:Advanced Boot Options Menu", description: "Allows users to access the Advanced Boot Options menu, which may allow disabling App Control." },
  10: { name: "Enabled:Boot Audit On Failure", description: "Causes the system to boot into audit mode if the policy fails to apply." },
  11: { name: "Disabled:Script Enforcement", description: "Disables script enforcement for PowerShell, WSH, and similar interpreters." },
  12: { name: "Required:Enforce Store Applications", description: "Enforces code integrity for Windows Store (UWP) applications." },
  13: { name: "Enabled:Managed Installer", description: "Enables the managed installer trust mechanism." },
  14: { name: "Enabled:Intelligent Security Graph Authorization", description: "Enables Microsoft ISG (cloud-based reputation) as a trust source." },
  15: { name: "Enabled:Invalidate EAs on Reboot", description: "Clears the Managed Installer and ISG extended attribute (EA) cache on reboot, requiring all files to be re-evaluated on the next boot." },
  16: { name: "Enabled:Update Policy No Reboot", description: "Allows policy updates without requiring a reboot." },
  17: { name: "Enabled:Allow Supplemental Policies", description: "Allows this base policy to be extended by supplemental policies." },
  18: { name: "Disabled:Runtime FilePath Rule Protection", description: "Disables path-rule enforcement validation at runtime (security risk)." },
  19: { name: "Enabled:Dynamic Code Security", description: "Enforces App Control for dynamically generated code." },
  20: { name: "Enabled:Revoked Expired As Unsigned", description: "Treats revoked or expired certificates as unsigned." },
  21: { name: "Enabled:Developer Mode Dynamic Code Trust", description: "Trusts UWP apps debugged or sideloaded via Visual Studio or Device Portal when Developer Mode is enabled on the device." },
  22: { name: "Enabled:Secure Setting Policy", description: "Enables enforcement of secure policy settings tied to Secure Boot — restricts policy modification to signed updates only." },
  23: { name: "Enabled:Conditional Windows Lockdown Policy", description: "Enables the conditional Windows Lockdown (S mode) policy behavior on capable editions." },
  24: { name: "Disabled:Default Windows Certificate Remapping", description: "Disables the default remapping of Windows certificates — signers are matched exactly as specified instead of being remapped to updated Windows roots." },
} as const;

export type PolicyRuleOptionNumber = keyof typeof POLICY_RULE_OPTIONS;

export interface PolicyRuleOption {
  value: PolicyRuleOptionNumber;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Signing Scenarios
// ---------------------------------------------------------------------------

// SigningScenario ID attributes are xs:ID values in cipolicy.xsd — they must be
// valid XML NCNames (cannot start with a digit). Use the conventional
// ID_SIGNINGSCENARIO_* identifiers emitted by Microsoft tooling.
export const SIGNING_SCENARIO = {
  KERNEL: { value: 131, id: "ID_SIGNINGSCENARIO_DRIVERS", label: "Kernel Mode (131)" },
  USER:   { value: 12,  id: "ID_SIGNINGSCENARIO_WINDOWS", label: "User Mode (12)" },
} as const;

export type SigningScenarioValue = 131 | 12;

// ---------------------------------------------------------------------------
// EKU (Enhanced Key Usage)
// ---------------------------------------------------------------------------

export interface WdacEku {
  id: string;
  friendlyName?: string;
  /** Hex-encoded OID value, e.g. "010a..." */
  value: string;
}

// ---------------------------------------------------------------------------
// File Rules — discriminated union
//
// Four concrete kinds emitted from XML parsing:
//   hash      → <Allow Hash="..."> / <Deny Hash="...">
//   path      → <Allow FilePath="..."> / <Deny FilePath="...">
//   package   → <Allow PackageFamilyName="..."> / <Deny PackageFamilyName="...">
//   attribute → <Allow FileName="..." ...> with no hash/path/package; also Deny
//   fileAttrib → <FileAttrib ...> — signer-scoping descriptor, no Allow/Deny effect
// ---------------------------------------------------------------------------

export type HashType = "SHA256" | "SHA1" | "SHA256Flat" | "SHA1Page" | "SHA256Page";

/** Effect of an Allow/Deny file rule. WdacFileAttrib descriptors carry no effect. */
export type FileRuleEffect = "Allow" | "Deny";

/** Discriminant field present on all WdacFileRule variants. */
export type FileRuleKind = "hash" | "path" | "package" | "attribute" | "fileAttrib";

/** Matches a file by cryptographic hash. */
export interface WdacHashRule {
  kind: "hash";
  id: string;
  effect: FileRuleEffect;
  friendlyName?: string;
  hash: string;
  hashType: HashType;
  /** Original filename embedded in the rule for informational display only. */
  fileName?: string;
}

/** Matches a file by filesystem path. May contain WDAC macros (%WINDIR%, %OSDRIVE%, etc.). */
export interface WdacPathRule {
  kind: "path";
  id: string;
  effect: FileRuleEffect;
  friendlyName?: string;
  filePath: string;
  /**
   * True when this rule targets a directory and all its subdirectories
   * (a "Folder Path" rule in WDAC Wizard terminology).
   * The filePath will typically end with \* or contain a wildcard.
   */
  isFolder?: boolean;
  minimumFileVersion?: string;
  maximumFileVersion?: string;
}

/** Matches a packaged (UWP/MSIX) app by family name and optional version. */
export interface WdacPackageRule {
  kind: "package";
  id: string;
  effect: FileRuleEffect;
  friendlyName?: string;
  packageFamilyName: string;
  packageVersion?: string;
}

/**
 * An Allow/Deny rule that matches by file metadata attributes only
 * (no hash, path, or package family name). Less common than the other kinds.
 */
export interface WdacAttributeRule {
  kind: "attribute";
  id: string;
  effect: FileRuleEffect;
  friendlyName?: string;
  fileName?: string;
  internalName?: string;
  fileDescription?: string;
  productName?: string;
  minimumFileVersion?: string;
  maximumFileVersion?: string;
}

/**
 * A <FileAttrib> signer-scoping descriptor. Not an independent Allow/Deny rule —
 * only enforced when referenced from a WdacSignerRule via fileAttribRefs.
 */
export interface WdacFileAttrib {
  kind: "fileAttrib";
  id: string;
  friendlyName?: string;
  fileName?: string;
  internalName?: string;
  fileDescription?: string;
  productName?: string;
  minimumFileVersion?: string;
  maximumFileVersion?: string;
}

export type WdacFileRule =
  | WdacHashRule
  | WdacPathRule
  | WdacPackageRule
  | WdacAttributeRule
  | WdacFileAttrib;

/** Type guard: narrows to the four variants that carry an Allow/Deny effect. */
export function isEffectRule(r: WdacFileRule): r is Exclude<WdacFileRule, WdacFileAttrib> {
  return r.kind !== "fileAttrib";
}

// ---------------------------------------------------------------------------
// Signer Rules
// ---------------------------------------------------------------------------

export type CertRootType = "TBS" | "Wellknown";

export interface WdacCertRoot {
  type: CertRootType;
  /** TBS hash hex string, or wellknown identifier number */
  value: string;
}

export interface WdacCertEku {
  ekuId: string;
}

/**
 * Publisher rule specificity — mirrors the WDAC Policy Wizard specificity slider.
 *
 * PCACertificate  (broadest)  — Trust anything signed by this root/PCA CA.
 *                               CertRoot only; no CertPublisher or FileAttrib.
 * Publisher                   — Trust all files from this specific publisher CN.
 *                               CertRoot + CertPublisher; no FileAttrib.
 * FilePublisher   (narrowest) — Trust this specific file from this publisher.
 *                               CertRoot + CertPublisher + FileAttrib (FileName + MinVersion).
 */
export type SignerSpecificity = "PCACertificate" | "Publisher" | "FilePublisher";

export interface WdacSignerRule {
  id: string;
  name: string;
  certRoot?: WdacCertRoot;
  certEKU?: WdacCertEku[];
  certIssuer?: string;
  certPublisher?: string;
  certOemID?: string;
  /** References to FileAttrib rules that scope this signer */
  fileAttribRefs?: string[];
  /**
   * The specificity level of this publisher rule (WDAC Wizard concept).
   * Informational — derived from the cert fields present.
   * Not persisted to XML; set by the UI / rule engine for display guidance.
   */
  specificity?: SignerSpecificity;
}

// ---------------------------------------------------------------------------
// Signing Scenario Rule References
// ---------------------------------------------------------------------------

export interface AllowedSigner {
  signerId: string;
  /** Signer is allowed EXCEPT when matched by these deny rules */
  exceptDenyRuleIds?: string[];
}

export interface DeniedSigner {
  signerId: string;
  /** Signer is denied EXCEPT when matched by these allow rules */
  exceptAllowRuleIds?: string[];
}

export interface WdacSigningScenario {
  value: SigningScenarioValue;
  id: string;
  minHashVersion?: string;
  allowedSigners: AllowedSigner[];
  deniedSigners: DeniedSigner[];
  /** Direct file rule references (Allow/Deny by file rule ID) */
  fileRuleRefs: string[];
}

// ---------------------------------------------------------------------------
// Full Policy
// ---------------------------------------------------------------------------

export type PolicyType = "Base" | "Supplemental";

/**
 * Policy deployment format.
 *
 * MultiplePolicy (modern default) — Supports deploying multiple policies simultaneously.
 *   Required for Windows 10 1903+ multi-policy deployment.
 *   Each policy has a unique PolicyID GUID.
 *
 * SinglePolicy (legacy) — Only one policy allowed on the system.
 *   Uses a fixed reserved PolicyID: {A244370E-44C9-4C06-B551-F6016E563076}.
 *   Required for pre-1903 Windows 10 or UEFI Secure Boot enforcement.
 */
export type PolicyFormat = "MultiplePolicy" | "SinglePolicy";

export interface WdacPolicy {
  /** Unique GUID identifying this policy */
  policyId: string;
  /** For supplemental policies: the GUID of the base policy */
  basePolicyId?: string;
  /** Identifies the type variant of the policy */
  policyTypeId?: string;
  /** Human-readable name — from FriendlyName attr/element or <Settings> Name */
  friendlyName?: string;
  /** Policy identifier from <Settings Provider="PolicyInfo" Key="Information" ValueName="Id"> */
  settingsId?: string;
  /** Policy version string, e.g. "10.0.0.0" */
  versionEx: string;
  /** Platform restriction GUID */
  platformId?: string;

  policyType: PolicyType;
  options: PolicyRuleOption[];
  ekus: WdacEku[];
  fileRules: WdacFileRule[];
  signers: WdacSignerRule[];
  signingScenarios: WdacSigningScenario[];

  /** Signer IDs permitted to sign policy updates */
  updatePolicySigners: string[];
  /** Signer IDs for Code Integrity signers */
  ciSigners: string[];
  /**
   * Signer IDs authorized to sign supplemental policies for this base policy
   * (<SupplementalPolicySigners>). Required for signed base policies that
   * allow supplemental policies without Option 6.
   */
  supplementalPolicySigners?: string[];

  /** Hypervisor Code Integrity options bitmask */
  hvciOptions?: number;

  /**
   * Policy deployment format — MultiplePolicy (modern, default) or SinglePolicy (legacy).
   * Affects the PolicyID used and XML root attributes in the generated file.
   * Defaults to MultiplePolicy when not specified.
   */
  policyFormat?: PolicyFormat;

  /** Parsed from file — source filename for display */
  sourceFileName?: string;
}

// ---------------------------------------------------------------------------
// Parse Diagnostics
// ---------------------------------------------------------------------------

export type DiagnosticSeverity = "error" | "warning" | "info";

export interface ParseDiagnostic {
  severity: DiagnosticSeverity;
  /** Machine-readable code for filtering and UI display */
  code: string;
  message: string;
  /** The XML element or field that triggered this diagnostic */
  context?: string;
}

// ---------------------------------------------------------------------------
// Rule Collection Index
//
// Built after parsing to enable O(1) cross-reference lookups.
// Returned alongside the parsed policy in ParseResult.
// ---------------------------------------------------------------------------

export interface RuleCollectionIndex {
  /** All file rules keyed by their ID attribute */
  fileRulesById: Map<string, WdacFileRule>;
  /** All signer rules keyed by their ID attribute */
  signersById: Map<string, WdacSignerRule>;
  /** All EKUs keyed by their ID attribute */
  ekusById: Map<string, WdacEku>;

  /** Signing scenario value → set of signer IDs referenced in that scenario */
  signerIdsByScenario: Map<SigningScenarioValue, Set<string>>;
  /** Signing scenario value → set of directly-referenced file rule IDs */
  fileRuleIdsByScenario: Map<SigningScenarioValue, Set<string>>;
  /** Signer ID → resolved WdacFileAttrib descriptors scoping that signer */
  fileAttribsBySignerId: Map<string, WdacFileAttrib[]>;

  /** AllowedSigner/DeniedSigner refs that pointed to a non-existent signer */
  unresolvedSignerRefs: Array<{ signerRef: string; inScenario: SigningScenarioValue }>;
  /** FileRuleRef or FileAttribRef entries that pointed to a non-existent rule */
  unresolvedFileRuleRefs: Array<{ ruleRef: string; context: string }>;
}

// ---------------------------------------------------------------------------
// Policy Comparison
// ---------------------------------------------------------------------------

export type DiffStatus = "added" | "removed" | "changed" | "unchanged";

export interface OptionDiff {
  optionValue: PolicyRuleOptionNumber;
  optionName: string;
  status: DiffStatus;
  leftEnabled?: boolean;
  rightEnabled?: boolean;
}

export interface FileRuleDiff {
  id: string;
  status: DiffStatus;
  left?: WdacFileRule;
  right?: WdacFileRule;
  changedFields?: string[];
}

export interface SignerDiff {
  id: string;
  status: DiffStatus;
  left?: WdacSignerRule;
  right?: WdacSignerRule;
  changedFields?: string[];
}

export interface ScenarioDiff {
  scenarioValue: SigningScenarioValue;
  addedAllowedSigners: string[];
  removedAllowedSigners: string[];
  addedDeniedSigners: string[];
  removedDeniedSigners: string[];
  addedFileRuleRefs: string[];
  removedFileRuleRefs: string[];
}

export interface PolicyComparisonResult {
  leftPolicy: { policyId: string; friendlyName?: string; versionEx: string };
  rightPolicy: { policyId: string; friendlyName?: string; versionEx: string };
  summary: {
    totalDifferences: number;
    optionChanges: number;
    fileRuleChanges: number;
    signerChanges: number;
    scenarioChanges: number;
  };
  optionDiffs: OptionDiff[];
  fileRuleDiffs: FileRuleDiff[];
  signerDiffs: SignerDiff[];
  scenarioDiffs: ScenarioDiff[];
}
