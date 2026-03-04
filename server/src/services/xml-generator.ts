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

  // Root element — namespaces + PolicyType on a single line (matches cipolicy schema)
  const policyTypeAttr =
    policy.policyType === "Supplemental" ? "Supplemental Policy" : "Base Policy";
  lines.push(
    `<SiPolicy` +
    ` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"` +
    ` xmlns:xsd="http://www.w3.org/2001/XMLSchema"` +
    ` PolicyType="${policyTypeAttr}"` +
    ` xmlns="urn:schemas-microsoft-com:sipolicy">`
  );

  // VersionEx, PlatformID, PolicyID, BasePolicyID — child elements (not attributes)
  lines.push(`${indent(1)}<VersionEx>${escapeXml(policy.versionEx)}</VersionEx>`);
  if (policy.platformId) {
    lines.push(`${indent(1)}<PlatformID>{${escapeXml(policy.platformId)}}</PlatformID>`);
  }
  lines.push(`${indent(1)}<PolicyID>{${escapeXml(policy.policyId)}}</PolicyID>`);
  if (policy.basePolicyId) {
    lines.push(`${indent(1)}<BasePolicyID>{${escapeXml(policy.basePolicyId)}}</BasePolicyID>`);
  }

  // Rules
  lines.push(`${indent(1)}<Rules>`);
  lines.push(...generateRuleOptions(policy.options));
  lines.push(`${indent(1)}</Rules>`);

  // EKUs — always emitted; self-closing when empty
  if (policy.ekus.length > 0) {
    lines.push(`${indent(1)}<EKUs>`);
    lines.push(...generateEkus(policy.ekus));
    lines.push(`${indent(1)}</EKUs>`);
  } else {
    lines.push(`${indent(1)}<EKUs />`);
  }

  // FileRules — always emitted; self-closing when empty
  if (policy.fileRules.length > 0) {
    lines.push(`${indent(1)}<FileRules>`);
    lines.push(...generateFileRules(policy.fileRules));
    lines.push(`${indent(1)}</FileRules>`);
  } else {
    lines.push(`${indent(1)}<FileRules />`);
  }

  // Signers — always emitted; self-closing when empty
  if (policy.signers.length > 0) {
    lines.push(`${indent(1)}<Signers>`);
    lines.push(...generateSigners(policy.signers));
    lines.push(`${indent(1)}</Signers>`);
  } else {
    lines.push(`${indent(1)}<Signers />`);
  }

  // Signing Scenarios
  const scenarioFriendlyName = policy.friendlyName ?? "Auto generated policy";
  lines.push(`${indent(1)}<SigningScenarios>`);
  lines.push(...generateSigningScenarios(policy.signingScenarios, scenarioFriendlyName));
  lines.push(`${indent(1)}</SigningScenarios>`);

  // UpdatePolicySigners — always emitted; self-closing when empty
  if (policy.updatePolicySigners.length > 0) {
    lines.push(`${indent(1)}<UpdatePolicySigners>`);
    for (const signerId of policy.updatePolicySigners) {
      lines.push(`${indent(2)}<UpdatePolicySigner SignerId="${escapeXml(signerId)}" />`);
    }
    lines.push(`${indent(1)}</UpdatePolicySigners>`);
  } else {
    lines.push(`${indent(1)}<UpdatePolicySigners />`);
  }

  // CiSigners — always emitted; self-closing when empty
  if (policy.ciSigners.length > 0) {
    lines.push(`${indent(1)}<CiSigners>`);
    for (const signerId of policy.ciSigners) {
      lines.push(`${indent(2)}<CiSigner SignerId="${escapeXml(signerId)}" />`);
    }
    lines.push(`${indent(1)}</CiSigners>`);
  } else {
    lines.push(`${indent(1)}<CiSigners />`);
  }

  // HvciOptions — child element (not an attribute on SiPolicy)
  lines.push(`${indent(1)}<HvciOptions>${policy.hvciOptions ?? 0}</HvciOptions>`);

  // Settings — PolicyInfo Name and Id
  const policyLabel = escapeXml(policy.friendlyName ?? policy.policyId);
  lines.push(`${indent(1)}<Settings>`);
  for (const valueName of ["Name", "Id"] as const) {
    lines.push(
      `${indent(2)}<Setting Provider="PolicyInfo" Key="Information" ValueName="${valueName}">`
    );
    lines.push(`${indent(3)}<Value>`);
    lines.push(`${indent(4)}<String>${policyLabel}</String>`);
    lines.push(`${indent(3)}</Value>`);
    lines.push(`${indent(2)}</Setting>`);
  }
  lines.push(`${indent(1)}</Settings>`);

  lines.push(`</SiPolicy>`);

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
    // Name before ID (cipolicy schema order)
    lines.push(
      `${indent(2)}<Signer Name="${escapeXml(signer.name)}" ID="${escapeXml(signer.id)}">`
    );

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

function generateSigningScenarios(
  scenarios: WdacSigningScenario[],
  friendlyName: string
): string[] {
  const lines: string[] = [];
  for (const ss of scenarios) {
    const hashAttr = ss.minHashVersion
      ? ` MinimumHashAlgorithm="${escapeXml(ss.minHashVersion)}"`
      : "";
    // ID, FriendlyName, Value (cipolicy schema order)
    lines.push(
      `${indent(2)}<SigningScenario` +
      ` ID="${escapeXml(ss.id)}"` +
      ` FriendlyName="${escapeXml(friendlyName)}"` +
      ` Value="${ss.value}"` +
      `${hashAttr}>`
    );

    const hasContent =
      ss.allowedSigners.length > 0 ||
      ss.deniedSigners.length > 0 ||
      ss.fileRuleRefs.length > 0;

    if (hasContent) {
      lines.push(`${indent(3)}<ProductSigners>`);

      if (ss.allowedSigners.length > 0) {
        lines.push(`${indent(4)}<AllowedSigners>`);
        for (const as_ of ss.allowedSigners) {
          if (as_.exceptDenyRuleIds && as_.exceptDenyRuleIds.length > 0) {
            lines.push(
              `${indent(5)}<AllowedSigner SignerId="${escapeXml(as_.signerId)}">`
            );
            for (const denyId of as_.exceptDenyRuleIds) {
              lines.push(
                `${indent(6)}<ExceptDenyRule DenyRuleID="${escapeXml(denyId)}" />`
              );
            }
            lines.push(`${indent(5)}</AllowedSigner>`);
          } else {
            lines.push(
              `${indent(5)}<AllowedSigner SignerId="${escapeXml(as_.signerId)}" />`
            );
          }
        }
        lines.push(`${indent(4)}</AllowedSigners>`);
      }

      if (ss.deniedSigners.length > 0) {
        lines.push(`${indent(4)}<DeniedSigners>`);
        for (const ds of ss.deniedSigners) {
          if (ds.exceptAllowRuleIds && ds.exceptAllowRuleIds.length > 0) {
            lines.push(
              `${indent(5)}<DeniedSigner SignerId="${escapeXml(ds.signerId)}">`
            );
            for (const allowId of ds.exceptAllowRuleIds) {
              lines.push(
                `${indent(6)}<ExceptAllowRule AllowRuleID="${escapeXml(allowId)}" />`
              );
            }
            lines.push(`${indent(5)}</DeniedSigner>`);
          } else {
            lines.push(
              `${indent(5)}<DeniedSigner SignerId="${escapeXml(ds.signerId)}" />`
            );
          }
        }
        lines.push(`${indent(4)}</DeniedSigners>`);
      }

      if (ss.fileRuleRefs.length > 0) {
        lines.push(`${indent(4)}<FileRulesRef>`);
        for (const ruleId of ss.fileRuleRefs) {
          lines.push(`${indent(5)}<FileRuleRef RuleID="${escapeXml(ruleId)}" />`);
        }
        lines.push(`${indent(4)}</FileRulesRef>`);
      }

      lines.push(`${indent(3)}</ProductSigners>`);
    } else {
      // Self-closing when no content
      lines.push(`${indent(3)}<ProductSigners />`);
    }

    lines.push(`${indent(2)}</SigningScenario>`);
  }
  return lines;
}
