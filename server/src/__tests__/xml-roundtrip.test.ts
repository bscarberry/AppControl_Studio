/**
 * XML Round-trip Tests
 *
 * Verifies that: parseWdacXml(generateWdacXml(policy)) == policy
 * i.e., the model is losslessly serialized and re-parsed.
 */

import { parseWdacXml } from "../services/xml-parser.js";
import { generateWdacXml } from "../services/xml-generator.js";
import * as fs from "fs";
import * as path from "path";

const SAMPLE_XML = fs.readFileSync(
  path.join(__dirname, "../../../fixtures/sample-policy.xml"),
  "utf-8"
);

describe("XML round-trip", () => {
  test("policy identity is preserved after parse -> generate -> parse", () => {
    const { policy: original } = parseWdacXml(SAMPLE_XML);
    const generated = generateWdacXml(original);
    const { policy: roundtripped } = parseWdacXml(generated);

    expect(roundtripped.policyId).toBe(original.policyId);
    expect(roundtripped.friendlyName).toBe(original.friendlyName);
    expect(roundtripped.versionEx).toBe(original.versionEx);
  });

  test("policy options are preserved", () => {
    const { policy: original } = parseWdacXml(SAMPLE_XML);
    const generated = generateWdacXml(original);
    const { policy: roundtripped } = parseWdacXml(generated);

    const origEnabled = original.options.filter((o) => o.enabled).map((o) => o.value).sort();
    const rtEnabled = roundtripped.options.filter((o) => o.enabled).map((o) => o.value).sort();
    expect(rtEnabled).toEqual(origEnabled);
  });

  test("file rules are preserved", () => {
    const { policy: original } = parseWdacXml(SAMPLE_XML);
    const generated = generateWdacXml(original);
    const { policy: roundtripped } = parseWdacXml(generated);

    expect(roundtripped.fileRules.length).toBe(original.fileRules.length);
    for (const origRule of original.fileRules) {
      const rtRule = roundtripped.fileRules.find((r) => r.id === origRule.id);
      expect(rtRule).toBeDefined();
      expect(rtRule?.kind).toBe(origRule.kind);
      // For hash rules, verify the hash is preserved
      if (origRule.kind === "hash" && rtRule?.kind === "hash") {
        expect(rtRule.hash).toBe(origRule.hash);
      }
    }
  });

  test("signers are preserved", () => {
    const { policy: original } = parseWdacXml(SAMPLE_XML);
    const generated = generateWdacXml(original);
    const { policy: roundtripped } = parseWdacXml(generated);

    expect(roundtripped.signers.length).toBe(original.signers.length);
    for (const origSigner of original.signers) {
      const rtSigner = roundtripped.signers.find((s) => s.id === origSigner.id);
      expect(rtSigner).toBeDefined();
      expect(rtSigner?.name).toBe(origSigner.name);
    }
  });

  test("generated XML contains valid XML declaration", () => {
    const { policy } = parseWdacXml(SAMPLE_XML);
    const generated = generateWdacXml(policy);
    expect(generated).toMatch(/^<\?xml version="1\.0" encoding="utf-8"\?>/);
    expect(generated).toContain("<SiPolicy");
    expect(generated).toContain("</SiPolicy>");
  });
});
