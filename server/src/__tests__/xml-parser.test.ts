/**
 * XML Parser Tests
 *
 * Tests the core WDAC XML -> WdacPolicy model transformation.
 */

import { parseWdacXml } from "../services/xml-parser.js";
import * as fs from "fs";
import * as path from "path";

const FIXTURES_DIR = path.join(__dirname, "../../../fixtures");
const SAMPLE_XML = fs.readFileSync(path.join(FIXTURES_DIR, "sample-policy.xml"), "utf-8");

describe("parseWdacXml", () => {
  test("parses a valid WDAC policy XML without errors", () => {
    const { policy, diagnostics } = parseWdacXml(SAMPLE_XML, "sample-policy.xml");
    expect(policy.policyId).toBeDefined();
    expect(policy.policyId).not.toBe("");
    expect(diagnostics).toBeInstanceOf(Array);
  });

  test("returns index alongside the policy", () => {
    const { index } = parseWdacXml(SAMPLE_XML);
    expect(index.fileRulesById).toBeInstanceOf(Map);
    expect(index.signersById).toBeInstanceOf(Map);
    expect(index.ekusById).toBeInstanceOf(Map);
  });

  test("extracts policy identity fields", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    expect(policy.friendlyName).toBe("AppControl Studio Sample Policy");
    expect(policy.versionEx).toBe("10.0.0.1");
  });

  test("parses policy rule options", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    const optionValues = policy.options.filter((o) => o.enabled).map((o) => o.value as number);
    expect(optionValues).toContain(0); // UMCI
    expect(optionValues).toContain(3); // Audit Mode
    expect(optionValues).toContain(6); // Unsigned allowed
  });

  test("parses EKUs", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    expect(policy.ekus.length).toBeGreaterThan(0);
    const windowsEku = policy.ekus.find((e) => e.id === "ID_EKU_WINDOWS");
    expect(windowsEku).toBeDefined();
    expect(windowsEku?.value).toBe("010a2b0601040182370a0306");
  });

  test("parses file rules of all kinds", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    const allowRules   = policy.fileRules.filter((r) => r.kind !== "fileAttrib" && (r as { effect: string }).effect === "Allow");
    const denyRules    = policy.fileRules.filter((r) => r.kind !== "fileAttrib" && (r as { effect: string }).effect === "Deny");
    const attribRules  = policy.fileRules.filter((r) => r.kind === "fileAttrib");

    expect(allowRules.length).toBeGreaterThan(0);
    expect(denyRules.length).toBeGreaterThan(0);
    expect(attribRules.length).toBeGreaterThan(0);
  });

  test("parses hash-based allow rule with correct kind", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    const rule = policy.fileRules.find((r) => r.id === "ID_ALLOW_NOTEPAD");
    expect(rule).toBeDefined();
    expect(rule?.kind).toBe("hash");
    if (rule?.kind === "hash") {
      expect(rule.hash).toBeDefined();
      expect(rule.hashType).toBe("SHA256");
      expect(rule.effect).toBe("Allow");
    }
  });

  test("parses path-based allow rule with correct kind", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    const rule = policy.fileRules.find((r) => r.id === "ID_ALLOW_WINDIR");
    expect(rule?.kind).toBe("path");
    if (rule?.kind === "path") {
      expect(rule.filePath.toUpperCase()).toContain("%WINDIR%");
      expect(rule.effect).toBe("Allow");
    }
  });

  test("parses FileAttrib descriptor with correct kind", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    const rule = policy.fileRules.find((r) => r.id === "ID_FILEATTRIB_CHROME");
    expect(rule?.kind).toBe("fileAttrib");
    if (rule?.kind === "fileAttrib") {
      expect(rule.productName).toBe("Google Chrome");
      // fileAttrib has no effect field
      expect("effect" in rule).toBe(false);
    }
  });

  test("parses signers with cert attributes", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    expect(policy.signers.length).toBeGreaterThan(0);

    const msSigner = policy.signers.find((s) => s.id === "ID_SIGNER_WINDOWS_PROD_RS1");
    expect(msSigner).toBeDefined();
    expect(msSigner?.certRoot?.type).toBe("TBS");
    expect(msSigner?.certEKU).toBeDefined();
  });

  test("parses signing scenarios with allowed/denied signers", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    const kernelSS = policy.signingScenarios.find((s) => s.value === 131);
    const userSS = policy.signingScenarios.find((s) => s.value === 12);

    expect(kernelSS).toBeDefined();
    expect(userSS).toBeDefined();
    expect(kernelSS!.allowedSigners.length).toBeGreaterThan(0);
    expect(userSS!.fileRuleRefs.length).toBeGreaterThan(0);
  });

  test("index resolves signers by scenario", () => {
    const { index } = parseWdacXml(SAMPLE_XML);
    const userSignerIds = index.signerIdsByScenario.get(12);
    expect(userSignerIds).toBeDefined();
    expect(userSignerIds!.size).toBeGreaterThan(0);
  });

  test("index resolves fileAttribs by signer", () => {
    const { index } = parseWdacXml(SAMPLE_XML);
    const chromeAttribs = index.fileAttribsBySignerId.get("ID_SIGNER_GOOGLE");
    expect(chromeAttribs).toBeDefined();
    expect(chromeAttribs![0].kind).toBe("fileAttrib");
  });

  test("throws for non-XML input", () => {
    expect(() => parseWdacXml("not xml at all")).toThrow();
  });

  test("throws for XML without SiPolicy root", () => {
    expect(() => parseWdacXml("<NotSiPolicy/>")).toThrow(/SiPolicy/);
  });
});
