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
  10: { name: "Enabled:Boot Audit on Failure", description: "Causes the system to boot into audit mode if the policy fails to apply." },
  11: { name: "Disabled:Script Enforcement", description: "Disables script enforcement for PowerShell, WSH, and similar interpreters." },
  12: { name: "Required:Enforce Store Applications", description: "Enforces code integrity for Windows Store (UWP) applications." },
  13: { name: "Enabled:Managed Installer", description: "Enables the managed installer trust mechanism." },
  14: { name: "Enabled:Intelligent Security Graph Authorization", description: "Enables Microsoft ISG (cloud-based reputation) as a trust source." },
  15: { name: "Invalidated:EA Not Required", description: "Marks the policy as not requiring extended attributes." },
  16: { name: "Enabled:Update Policy No Reboot", description: "Allows policy updates without requiring a reboot." },
  17: { name: "Enabled:Allow Supplemental Policies", description: "Allows this base policy to be extended by supplemental policies." },
  18: { name: "Disabled:Runtime FilePath Rule Protection", description: "Disables path-rule enforcement validation at runtime (security risk)." },
  19: { name: "Enabled:Dynamic Code Security", description: "Enforces App Control for dynamically generated code." },
  20: { name: "Enabled:Revoked Expired As Unsigned", description: "Treats revoked or expired certificates as unsigned." },
  21: { name: "Enabled:Developer Unlockable MSA Apps", description: "Allows MSA-authenticated apps to be unlocked for development." },
  22: { name: "Enabled:Strict WHQL Attestation", description: "Requires strict WHQL attestation for kernel drivers." },
} as const;

export type PolicyRuleOptionNumber = keyof typeof POLICY_RULE_OPTIONS;

export interface PolicyRuleOption {
  value: PolicyRuleOptionNumber;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Signing Scenarios
// ---------------------------------------------------------------------------

export const SIGNING_SCENARIO = {
  KERNEL: { value: 131, id: "0", label: "Kernel Mode (131)" },
  USER:   { value: 12,  id: "1", label: "User Mode (12)" },
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
// File Rules
// ---------------------------------------------------------------------------

export type FileRuleType = "Allow" | "Deny" | "FileAttrib";

export type HashType = "SHA256" | "SHA1" | "SHA256Flat" | "SHA1Page";

export interface WdacFileRule {
  id: string;
  type: FileRuleType;
  friendlyName?: string;

  // Hash-based attributes
  hash?: string;
  hashType?: HashType;

  // File metadata attributes
  fileName?: string;
  internalName?: string;
  fileDescription?: string;
  productName?: string;
  minimumFileVersion?: string;
  maximumFileVersion?: string;

  // Path-based
  filePath?: string;

  // Packaged apps
  packageFamilyName?: string;
  packageVersion?: string;

  // FileAttrib is referenced by signers; not directly enforced
  isFileAttrib?: boolean;
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

export interface WdacPolicy {
  /** Unique GUID identifying this policy */
  policyId: string;
  /** For supplemental policies: the GUID of the base policy */
  basePolicyId?: string;
  /** Identifies the type variant of the policy */
  policyTypeId?: string;
  /** Human-readable name */
  friendlyName?: string;
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

  /** Hypervisor Code Integrity options bitmask */
  hvciOptions?: number;

  /** Parsed from file — source filename for display */
  sourceFileName?: string;
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
