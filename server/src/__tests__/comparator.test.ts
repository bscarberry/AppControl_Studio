/**
 * Policy Comparator Tests
 */

import { parseWdacXml } from "../services/xml-parser.js";
import { comparePolicies } from "../services/policy-comparator.js";
import * as fs from "fs";
import * as path from "path";

const SAMPLE_XML = fs.readFileSync(
  path.join(__dirname, "../../../fixtures/sample-policy.xml"),
  "utf-8"
);

describe("comparePolicies", () => {
  test("comparing a policy with itself returns zero differences", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    const result = comparePolicies(policy, policy);
    expect(result.summary.totalDifferences).toBe(0);
  });

  test("detects added policy option", () => {
    const { policy: left } = parseWdacXml(SAMPLE_XML);
    const right = {
      ...left,
      options: [
        ...left.options,
        { value: 13 as const, enabled: true }, // Managed Installer
      ],
    };
    const result = comparePolicies(left, right);
    const managedInstallerDiff = result.optionDiffs.find((d) => d.optionValue === 13);
    expect(managedInstallerDiff?.status).toBe("added");
  });

  test("detects removed policy option", () => {
    const { policy: left } = parseWdacXml(SAMPLE_XML);
    const right = {
      ...left,
      options: left.options.filter((o) => o.value !== 3), // remove Audit Mode
    };
    const result = comparePolicies(left, right);
    const auditModeDiff = result.optionDiffs.find((d) => d.optionValue === 3);
    expect(auditModeDiff?.status).toBe("removed");
  });

  test("detects added file rule", () => {
    const { policy: left } = parseWdacXml(SAMPLE_XML);
    const right = {
      ...left,
      fileRules: [
        ...left.fileRules,
        {
          id: "ID_ALLOW_NEW",
          type: "Allow" as const,
          friendlyName: "New allow rule",
          hash: "AABBCC",
        },
      ],
    };
    const result = comparePolicies(left, right);
    const newRuleDiff = result.fileRuleDiffs.find((d) => d.id === "ID_ALLOW_NEW");
    expect(newRuleDiff?.status).toBe("added");
  });

  test("detects removed signer", () => {
    const { policy: left } = parseWdacXml(SAMPLE_XML);
    const right = {
      ...left,
      signers: left.signers.filter((s) => s.id !== "ID_SIGNER_GOOGLE"),
    };
    const result = comparePolicies(left, right);
    const googleDiff = result.signerDiffs.find((d) => d.id === "ID_SIGNER_GOOGLE");
    expect(googleDiff?.status).toBe("removed");
  });

  test("generates a summary with correct counts", () => {
    const { policy: left } = parseWdacXml(SAMPLE_XML);
    const right = {
      ...left,
      options: left.options.filter((o) => o.value !== 3),
    };
    const result = comparePolicies(left, right);
    expect(result.summary.optionChanges).toBeGreaterThan(0);
    expect(result.summary.totalDifferences).toBe(result.summary.optionChanges);
  });
});
