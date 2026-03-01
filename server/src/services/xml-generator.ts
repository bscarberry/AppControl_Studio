/**
 * WDAC XML Generator
 *
 * Converts a normalized WdacPolicy model into a valid, deployable WDAC SiPolicy XML document.
 *
 * The generated XML conforms to the cipolicy.xsd schema and is compatible
 * with ConvertFrom-CIPolicy / CiTool for binary policy conversion.
 *
 * Reference schema: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-intune
 */

import type {
  WdacPolicy,
  WdacFileRule,
  WdacSignerRule,
  WdacSigningScenario,
  WdacEku,
  PolicyRuleOption,
  WdacHashRule,
  WdacPathRule,
  WdacPackageRule,
  WdacAttributeRule,
  WdacFileAttrib,
} from "@appcontrol/shared";
import { POLICY_RULE_OPTIONS } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function indent(level: number): string {
  return "  ".repeat(level);
}

// ---------------------------------------------------------------------------
// Main Generator
// ---------------------------------------------------------------------------

export function generateWdacXml(policy: WdacPolicy): string {
  const lines: string[] = [];

  lines.push('<?xml version="1.0" encoding="utf-8"?>');
  lines.push("<SiPolicy");
  lines.push(`  xmlns="urn:schemas-microsoft-com:sipolicy"`);
  lines.push(`  PolicyID="{${escapeXml(policy.policyId)}}"`);

  if (policy.basePolicyId) {
    lines.push(`  BasePolicyID="{${escapeXml(policy.basePolicyId)}}"`);
  }
  if (policy.policyTypeId) {
    lines.push(`  PolicyTypeID="{${escapeXml(policy.policyTypeId)}}"`);
  }
  if (policy.friendlyName) {
    lines.push(`  FriendlyName="${escapeXml(policy.friendlyName)}"`);
  }
  lines.push(`  VersionEx="${escapeXml(policy.versionEx)}"`);
  if (policy.platformId) {
    lines.push(`  PlatformID="{${escapeXml(policy.platformId)}}"`);
  }
  if (policy.hvciOptions !== undefined) {
    lines.push(`  HvciOptions="${policy.hvciOptions}"`);
  }
  lines.push(">");
  lines.push("");

  // Rules (Policy options)
  lines.push(`${indent(1)}<Rules>`);
  lines.push(...generateRuleOptions(policy.options));
  lines.push(`${indent(1)}</Rules>`);
  lines.push("");

  // EKUs
  if (policy.ekus.length > 0) {
    lines.push(`${indent(1)}<EKUs>`);
    lines.push(...generateEkus(policy.ekus));
    lines.push(`${indent(1)}</EKUs>`);
    lines.push("");
  }

  // FileRules — required element per cipolicy.xsd; always emitted, may be empty
  lines.push(`${indent(1)}<FileRules>`);
  if (policy.fileRules.length > 0) {
    lines.push(...generateFileRules(policy.fileRules));
  }
  lines.push(`${indent(1)}</FileRules>`);
  lines.push("");

  // Signers — required element per cipolicy.xsd; always emitted, may be empty
  lines.push(`${indent(1)}<Signers>`);
  if (policy.signers.length > 0) {
    lines.push(...generateSigners(policy.signers));
  }
  lines.push(`${indent(1)}</Signers>`);
  lines.push("");

  // Signing Scenarios
  lines.push(`${indent(1)}<SigningScenarios>`);
  lines.push(...generateSigningScenarios(policy.signingScenarios));
  lines.push(`${indent(1)}</SigningScenarios>`);
  lines.push("");

  // UpdatePolicySigners
  if (policy.updatePolicySigners.length > 0) {
    lines.push(`${indent(1)}<UpdatePolicySigners>`);
    for (const signerId of policy.updatePolicySigners) {
      lines.push(`${indent(2)}<UpdatePolicySigner SignerId="${escapeXml(signerId)}" />`);
    }
    lines.push(`${indent(1)}</UpdatePolicySigners>`);
    lines.push("");
  }

  // CiSigners
  if (policy.ciSigners.length > 0) {
    lines.push(`${indent(1)}<CiSigners>`);
    for (const signerId of policy.ciSigners) {
      lines.push(`${indent(2)}<CiSigner SignerId="${escapeXml(signerId)}" />`);
    }
    lines.push(`${indent(1)}</CiSigners>`);
    lines.push("");
  }

  lines.push("</SiPolicy>");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Section generators
// ---------------------------------------------------------------------------

function generateRuleOptions(options: PolicyRuleOption[]): string[] {
  const lines: string[] = [];
  for (const opt of options) {
    if (!opt.enabled) continue;
    const def = POLICY_RULE_OPTIONS[opt.value as keyof typeof POLICY_RULE_OPTIONS];
    if (!def) continue;
    lines.push(`${indent(2)}<Rule>`);
    lines.push(`${indent(3)}<Option>${escapeXml(def.name)}</Option>`);
    lines.push(`${indent(2)}</Rule>`);
  }
  return lines;
}

function generateEkus(ekus: WdacEku[]): string[] {
  return ekus.map((eku) => {
    const friendlyAttr = eku.friendlyName
      ? ` FriendlyName="${escapeXml(eku.friendlyName)}"`
      : "";
    return `${indent(2)}<EKU ID="${escapeXml(eku.id)}"${friendlyAttr} Value="${escapeXml(eku.value)}" />`;
  });
}

function generateFileRules(fileRules: WdacFileRule[]): string[] {
  return fileRules.map(serializeFileRule);
}

function serializeFileRule(rule: WdacFileRule): string {
  const I = indent(2);
  switch (rule.kind) {
    case "hash": {
      const r = rule as WdacHashRule;
      const attrs = [
        `ID="${escapeXml(r.id)}"`,
        ...(r.friendlyName ? [`FriendlyName="${escapeXml(r.friendlyName)}"`] : []),
        ...(r.fileName ? [`FileName="${escapeXml(r.fileName)}"`] : []),
        `Hash="${escapeXml(r.hash)}"`,
        `HashType="${escapeXml(r.hashType)}"`,
      ];
      return `${I}<${r.effect} ${attrs.join(" ")} />`;
    }
    case "path": {
      const r = rule as WdacPathRule;
      const attrs = [
        `ID="${escapeXml(r.id)}"`,
        ...(r.friendlyName ? [`FriendlyName="${escapeXml(r.friendlyName)}"`] : []),
        `FilePath="${escapeXml(r.filePath)}"`,
        ...(r.minimumFileVersion ? [`MinimumFileVersion="${escapeXml(r.minimumFileVersion)}"`] : []),
        ...(r.maximumFileVersion ? [`MaximumFileVersion="${escapeXml(r.maximumFileVersion)}"`] : []),
      ];
      return `${I}<${r.effect} ${attrs.join(" ")} />`;
    }
    case "package": {
      const r = rule as WdacPackageRule;
      const attrs = [
        `ID="${escapeXml(r.id)}"`,
        ...(r.friendlyName ? [`FriendlyName="${escapeXml(r.friendlyName)}"`] : []),
        `PackageFamilyName="${escapeXml(r.packageFamilyName)}"`,
        ...(r.packageVersion ? [`PackageVersion="${escapeXml(r.packageVersion)}"`] : []),
      ];
      return `${I}<${r.effect} ${attrs.join(" ")} />`;
    }
    case "attribute": {
      const r = rule as WdacAttributeRule;
      const attrs = [
        `ID="${escapeXml(r.id)}"`,
        ...(r.friendlyName ? [`FriendlyName="${escapeXml(r.friendlyName)}"`] : []),
        ...(r.fileName ? [`FileName="${escapeXml(r.fileName)}"`] : []),
        ...(r.internalName ? [`InternalName="${escapeXml(r.internalName)}"`] : []),
        ...(r.fileDescription ? [`FileDescription="${escapeXml(r.fileDescription)}"`] : []),
        ...(r.productName ? [`ProductName="${escapeXml(r.productName)}"`] : []),
        ...(r.minimumFileVersion ? [`MinimumFileVersion="${escapeXml(r.minimumFileVersion)}"`] : []),
        ...(r.maximumFileVersion ? [`MaximumFileVersion="${escapeXml(r.maximumFileVersion)}"`] : []),
      ];
      return `${I}<${r.effect} ${attrs.join(" ")} />`;
    }
    case "fileAttrib": {
      const r = rule as WdacFileAttrib;
      const attrs = [
        `ID="${escapeXml(r.id)}"`,
        ...(r.friendlyName ? [`FriendlyName="${escapeXml(r.friendlyName)}"`] : []),
        ...(r.fileName ? [`FileName="${escapeXml(r.fileName)}"`] : []),
        ...(r.internalName ? [`InternalName="${escapeXml(r.internalName)}"`] : []),
        ...(r.fileDescription ? [`FileDescription="${escapeXml(r.fileDescription)}"`] : []),
        ...(r.productName ? [`ProductName="${escapeXml(r.productName)}"`] : []),
        ...(r.minimumFileVersion ? [`MinimumFileVersion="${escapeXml(r.minimumFileVersion)}"`] : []),
        ...(r.maximumFileVersion ? [`MaximumFileVersion="${escapeXml(r.maximumFileVersion)}"`] : []),
      ];
      return `${I}<FileAttrib ${attrs.join(" ")} />`;
    }
  }
}

function generateSigners(signers: WdacSignerRule[]): string[] {
  const lines: string[] = [];
  for (const signer of signers) {
    lines.push(`${indent(2)}<Signer ID="${escapeXml(signer.id)}" Name="${escapeXml(signer.name)}">`);

    if (signer.certRoot) {
      lines.push(
        `${indent(3)}<CertRoot Type="${escapeXml(signer.certRoot.type)}" Value="${escapeXml(signer.certRoot.value)}" />`
      );
    }

    if (signer.certEKU) {
      for (const eku of signer.certEKU) {
        lines.push(`${indent(3)}<CertEKU ID="${escapeXml(eku.ekuId)}" />`);
      }
    }

    if (signer.certIssuer) {
      lines.push(`${indent(3)}<CertIssuer Value="${escapeXml(signer.certIssuer)}" />`);
    }

    if (signer.certPublisher) {
      lines.push(`${indent(3)}<CertPublisher Value="${escapeXml(signer.certPublisher)}" />`);
    }

    if (signer.certOemID) {
      lines.push(`${indent(3)}<CertOemID Value="${escapeXml(signer.certOemID)}" />`);
    }

    if (signer.fileAttribRefs) {
      for (const ruleId of signer.fileAttribRefs) {
        lines.push(`${indent(3)}<FileAttribRef RuleID="${escapeXml(ruleId)}" />`);
      }
    }

    lines.push(`${indent(2)}</Signer>`);
  }
  return lines;
}

function generateSigningScenarios(scenarios: WdacSigningScenario[]): string[] {
  const lines: string[] = [];
  for (const ss of scenarios) {
    const hashAttr = ss.minHashVersion
      ? ` MinimumHashAlgorithm="${escapeXml(ss.minHashVersion)}"`
      : "";
    lines.push(
      `${indent(2)}<SigningScenario Value="${ss.value}" ID="${escapeXml(ss.id)}"${hashAttr}>`
    );
    lines.push(`${indent(3)}<ProductSigners>`);

    // AllowedSigners
    if (ss.allowedSigners.length > 0) {
      lines.push(`${indent(4)}<AllowedSigners>`);
      for (const as_ of ss.allowedSigners) {
        if (as_.exceptDenyRuleIds && as_.exceptDenyRuleIds.length > 0) {
          lines.push(`${indent(5)}<AllowedSigner SignerId="${escapeXml(as_.signerId)}">`);
          for (const denyId of as_.exceptDenyRuleIds) {
            lines.push(`${indent(6)}<ExceptDenyRule DenyRuleID="${escapeXml(denyId)}" />`);
          }
          lines.push(`${indent(5)}</AllowedSigner>`);
        } else {
          lines.push(`${indent(5)}<AllowedSigner SignerId="${escapeXml(as_.signerId)}" />`);
        }
      }
      lines.push(`${indent(4)}</AllowedSigners>`);
    }

    // DeniedSigners
    if (ss.deniedSigners.length > 0) {
      lines.push(`${indent(4)}<DeniedSigners>`);
      for (const ds of ss.deniedSigners) {
        if (ds.exceptAllowRuleIds && ds.exceptAllowRuleIds.length > 0) {
          lines.push(`${indent(5)}<DeniedSigner SignerId="${escapeXml(ds.signerId)}">`);
          for (const allowId of ds.exceptAllowRuleIds) {
            lines.push(`${indent(6)}<ExceptAllowRule AllowRuleID="${escapeXml(allowId)}" />`);
          }
          lines.push(`${indent(5)}</DeniedSigner>`);
        } else {
          lines.push(`${indent(5)}<DeniedSigner SignerId="${escapeXml(ds.signerId)}" />`);
        }
      }
      lines.push(`${indent(4)}</DeniedSigners>`);
    }

    // FileRulesRef
    if (ss.fileRuleRefs.length > 0) {
      lines.push(`${indent(4)}<FileRulesRef>`);
      for (const ruleId of ss.fileRuleRefs) {
        lines.push(`${indent(5)}<FileRuleRef RuleID="${escapeXml(ruleId)}" />`);
      }
      lines.push(`${indent(4)}</FileRulesRef>`);
    }

    lines.push(`${indent(3)}</ProductSigners>`);
    lines.push(`${indent(2)}</SigningScenario>`);
  }
  return lines;
}
