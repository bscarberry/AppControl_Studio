/**
 * WDAC conformance QA tests
 *
 * Regression tests for behaviors validated against the cipolicy.xsd schema,
 * Microsoft's WDAC Policy Wizard (WDAC-Toolkit), and HotCakeX's AppControl
 * Manager:
 *  - SiPolicy header element ordering and multi/single policy formats
 *  - BasePolicyID requirements
 *  - Hash rule serialization (no FileName attribute, hash type inference)
 *  - SupplementalPolicySigners round-trip
 *  - Merge ID-collision correctness and signer scope-aware dedup
 *  - Policy builder fallback chain (no silently dropped files)
 *  - Simulator default-deny semantics
 *  - AppLocker conversion validity
 */

import { parseWdacXml } from "../services/xml-parser.js";
import { generateWdacXml } from "../services/xml-generator.js";
import { mergePolicies } from "../services/policy-merger.js";
import { buildPolicyFromEvents } from "../services/policy-builder.js";
import { simulateBinary } from "../services/policy-simulator.js";
import { convertAppLockerToWdac } from "../services/applocker-converter.js";
import type { WdacPolicy, ParsedCiEvent } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const GUID_A = "11111111-1111-1111-1111-111111111111";
const GUID_B = "22222222-2222-2222-2222-222222222222";

function minimalPolicy(overrides: Partial<WdacPolicy> = {}): WdacPolicy {
  return {
    policyId: GUID_A,
    versionEx: "10.0.0.0",
    policyType: "Base",
    options: [{ value: 0, enabled: true }],
    ekus: [],
    fileRules: [],
    signers: [],
    signingScenarios: [
      {
        value: 131,
        id: "ID_SIGNINGSCENARIO_DRIVERS",
        allowedSigners: [],
        deniedSigners: [],
        fileRuleRefs: [],
      },
      {
        value: 12,
        id: "ID_SIGNINGSCENARIO_WINDOWS",
        allowedSigners: [],
        deniedSigners: [],
        fileRuleRefs: [],
      },
    ],
    updatePolicySigners: [],
    ciSigners: [],
    ...overrides,
  };
}

function ciEvent(overrides: Partial<ParsedCiEvent> = {}): ParsedCiEvent {
  return {
    eventId: 3076,
    timestamp: "2026-01-01T00:00:00Z",
    filePath: "C:\\Apps\\tool.exe",
    fileName: "tool.exe",
    severity: "audit",
    description: "audit",
    source: "evtx",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// XML generator — SiPolicy header conformance
// ---------------------------------------------------------------------------

describe("generateWdacXml header conformance", () => {
  test("emits VersionEx, PolicyID, BasePolicyID, PlatformID in schema order", () => {
    const xml = generateWdacXml(
      minimalPolicy({ platformId: "2E07F7E4-194C-4D20-B7C9-6F44A6C5A234" })
    );
    const order = ["<VersionEx>", "<PolicyID>", "<BasePolicyID>", "<PlatformID>", "<Rules>"];
    const positions = order.map((tag) => xml.indexOf(tag));
    expect(positions.every((p) => p >= 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  test("base policy gets a self-referential BasePolicyID (multi-policy format requires it)", () => {
    const xml = generateWdacXml(minimalPolicy());
    expect(xml).toContain(`<PolicyID>{${GUID_A}}</PolicyID>`);
    expect(xml).toContain(`<BasePolicyID>{${GUID_A}}</BasePolicyID>`);
    expect(xml).toContain('PolicyType="Base Policy"');
  });

  test("supplemental policy without basePolicyId is rejected", () => {
    expect(() =>
      generateWdacXml(minimalPolicy({ policyType: "Supplemental" }))
    ).toThrow(/base/i);
  });

  test("supplemental policy emits its own PolicyID and the base's BasePolicyID", () => {
    const xml = generateWdacXml(
      minimalPolicy({ policyType: "Supplemental", basePolicyId: GUID_B })
    );
    expect(xml).toContain(`<PolicyID>{${GUID_A}}</PolicyID>`);
    expect(xml).toContain(`<BasePolicyID>{${GUID_B}}</BasePolicyID>`);
    expect(xml).toContain('PolicyType="Supplemental Policy"');
  });

  test("single-policy format uses PolicyTypeID and omits PolicyID/BasePolicyID/PolicyType attr", () => {
    const xml = generateWdacXml(minimalPolicy({ policyFormat: "SinglePolicy" }));
    expect(xml).toContain("<PolicyTypeID>{A244370E-44C9-4C06-B551-F6016E563076}</PolicyTypeID>");
    expect(xml).not.toContain("<PolicyID>");
    expect(xml).not.toContain("<BasePolicyID>");
    expect(xml).not.toContain("PolicyType=");
  });

  test("GUIDs are wrapped in exactly one pair of braces", () => {
    const xml = generateWdacXml(minimalPolicy());
    expect(xml).not.toMatch(/\{\{/);
    expect(xml).not.toMatch(/\}\}/);
  });

  test("FriendlyName is emitted as a root attribute and survives round-trip", () => {
    const xml = generateWdacXml(minimalPolicy({ friendlyName: "My Policy" }));
    expect(xml).toMatch(/<SiPolicy[^>]*FriendlyName="My Policy"/);
    const { policy } = parseWdacXml(xml);
    expect(policy.friendlyName).toBe("My Policy");
  });
});

// ---------------------------------------------------------------------------
// Hash rules
// ---------------------------------------------------------------------------

describe("hash rule handling", () => {
  const SHA1 = "A".repeat(40);
  const SHA256 = "B".repeat(64);

  test("generated hash rules carry no FileName attribute (matches Microsoft tooling)", () => {
    const xml = generateWdacXml(
      minimalPolicy({
        fileRules: [
          {
            kind: "hash",
            id: "ID_ALLOW_HASH_1",
            effect: "Allow",
            hash: SHA256,
            hashType: "SHA256",
            fileName: "tool.exe",
          },
        ],
      })
    );
    const ruleLine = xml.split("\n").find((l) => l.includes("ID_ALLOW_HASH_1"))!;
    expect(ruleLine).not.toContain("FileName=");
    expect(ruleLine).toContain(`Hash="${SHA256}"`);
  });

  test("parser infers SHA1 hash type from 40-char digests", () => {
    const xml = generateWdacXml(
      minimalPolicy({
        fileRules: [
          { kind: "hash", id: "ID_ALLOW_HASH_1", effect: "Allow", hash: SHA1, hashType: "SHA1" },
          { kind: "hash", id: "ID_ALLOW_HASH_2", effect: "Allow", hash: SHA256, hashType: "SHA256" },
        ],
      })
    );
    const { policy } = parseWdacXml(xml);
    const r1 = policy.fileRules.find((r) => r.id === "ID_ALLOW_HASH_1");
    const r2 = policy.fileRules.find((r) => r.id === "ID_ALLOW_HASH_2");
    expect(r1?.kind === "hash" && r1.hashType).toBe("SHA1");
    expect(r2?.kind === "hash" && r2.hashType).toBe("SHA256");
  });
});

// ---------------------------------------------------------------------------
// SupplementalPolicySigners round-trip
// ---------------------------------------------------------------------------

describe("SupplementalPolicySigners", () => {
  test("survive a generate -> parse round-trip", () => {
    const policy = minimalPolicy({
      signers: [
        { id: "ID_SIGNER_S_1", name: "Signer", certRoot: { type: "TBS", value: "AA" } },
      ],
      supplementalPolicySigners: ["ID_SIGNER_S_1"],
    });
    const xml = generateWdacXml(policy);
    expect(xml).toContain('<SupplementalPolicySigner SignerId="ID_SIGNER_S_1" />');
    const { policy: rt } = parseWdacXml(xml);
    expect(rt.supplementalPolicySigners).toEqual(["ID_SIGNER_S_1"]);
  });
});

// ---------------------------------------------------------------------------
// New policy rule options
// ---------------------------------------------------------------------------

describe("policy rule options", () => {
  test("parses and round-trips Conditional Windows Lockdown / Certificate Remapping options", () => {
    const xml = generateWdacXml(
      minimalPolicy({
        options: [
          { value: 0, enabled: true },
          { value: 23, enabled: true },
          { value: 24, enabled: true },
        ],
      })
    );
    expect(xml).toContain("<Option>Enabled:Conditional Windows Lockdown Policy</Option>");
    expect(xml).toContain("<Option>Disabled:Default Windows Certificate Remapping</Option>");
    const { policy, diagnostics } = parseWdacXml(xml);
    const values = policy.options.map((o) => o.value as number).sort((a, b) => a - b);
    expect(values).toEqual([0, 23, 24]);
    expect(diagnostics.filter((d) => d.code === "UNKNOWN_RULE_OPTION")).toHaveLength(0);
  });

  test("warns about unsupported sections that would be lost on regeneration", () => {
    const xml = `<?xml version="1.0"?>
      <SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
        <VersionEx>10.0.0.0</VersionEx>
        <PolicyID>{${GUID_A}}</PolicyID>
        <BasePolicyID>{${GUID_A}}</BasePolicyID>
        <Rules><Rule><Option>Enabled:UMCI</Option></Rule></Rules>
        <Macros><Macro Id="M1" Value="C:\\X" /></Macros>
      </SiPolicy>`;
    const { diagnostics } = parseWdacXml(xml);
    expect(diagnostics.some((d) => d.code === "UNSUPPORTED_SECTION" && d.context === "Macros")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Policy merger — ID collision correctness
// ---------------------------------------------------------------------------

describe("mergePolicies", () => {
  const SHA_X = "C".repeat(64);
  const SHA_Y = "D".repeat(64);

  test("policies reusing the same rule IDs keep their own rules referenced", () => {
    const mk = (guid: string, hash: string): WdacPolicy =>
      minimalPolicy({
        policyId: guid,
        fileRules: [
          { kind: "hash", id: "ID_ALLOW_A_1", effect: "Allow", hash, hashType: "SHA256" },
        ],
        signingScenarios: [
          {
            value: 12,
            id: "ID_SIGNINGSCENARIO_WINDOWS",
            allowedSigners: [],
            deniedSigners: [],
            fileRuleRefs: ["ID_ALLOW_A_1"],
          },
        ],
      });

    const { policy: merged } = mergePolicies([mk(GUID_A, SHA_X), mk(GUID_B, SHA_Y)]);

    // Both distinct hash rules must exist and both must be referenced from
    // the user-mode scenario — the shared original ID must not collapse them.
    const hashes = merged.fileRules
      .filter((r) => r.kind === "hash")
      .map((r) => (r as { hash: string }).hash)
      .sort();
    expect(hashes).toEqual([SHA_X, SHA_Y].sort());

    const scenario = merged.signingScenarios.find((s) => s.value === 12)!;
    expect(scenario.fileRuleRefs).toHaveLength(2);
    const referenced = new Set(scenario.fileRuleRefs);
    for (const rule of merged.fileRules) {
      expect(referenced.has(rule.id)).toBe(true);
    }
  });

  test("scoped and unscoped signers with identical certs are NOT deduplicated", () => {
    const scoped = minimalPolicy({
      policyId: GUID_A,
      fileRules: [
        { kind: "fileAttrib", id: "ID_FILEATTRIB_F_1", fileName: "app.exe" },
      ],
      signers: [
        {
          id: "ID_SIGNER_S_1",
          name: "Vendor",
          certRoot: { type: "TBS", value: "AB" },
          certPublisher: "Vendor Inc",
          fileAttribRefs: ["ID_FILEATTRIB_F_1"],
        },
      ],
    });
    const unscoped = minimalPolicy({
      policyId: GUID_B,
      signers: [
        {
          id: "ID_SIGNER_S_1",
          name: "Vendor",
          certRoot: { type: "TBS", value: "AB" },
          certPublisher: "Vendor Inc",
        },
      ],
    });
    const { policy: merged } = mergePolicies([scoped, unscoped]);
    expect(merged.signers).toHaveLength(2);
  });

  test("merged scenario IDs are valid NCNames (not bare digits)", () => {
    const { policy: merged } = mergePolicies([minimalPolicy(), minimalPolicy({ policyId: GUID_B })]);
    for (const sc of merged.signingScenarios) {
      expect(sc.id).toMatch(/^[A-Za-z_][\w.-]*$/);
    }
  });

  test("supplementalPolicySigners are merged and remapped", () => {
    const withSupp = minimalPolicy({
      policyId: GUID_A,
      signers: [{ id: "ID_SIGNER_S_9", name: "Supp Signer", certRoot: { type: "TBS", value: "CD" } }],
      supplementalPolicySigners: ["ID_SIGNER_S_9"],
    });
    const { policy: merged } = mergePolicies([withSupp, minimalPolicy({ policyId: GUID_B })]);
    expect(merged.supplementalPolicySigners).toHaveLength(1);
    expect(merged.signers.some((s) => s.id === merged.supplementalPolicySigners![0])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Policy builder — no silently dropped files
// ---------------------------------------------------------------------------

describe("buildPolicyFromEvents fallbacks", () => {
  test("publisher rule request without issuer TBS falls back to a hash rule", () => {
    const { policy } = buildPolicyFromEvents({
      events: [
        ciEvent({
          sha256FlatHash: "E".repeat(64),
          signerInfo: { publisherName: "CN=Vendor", publisherTbsHash: "F".repeat(64) },
        }),
      ],
      policyName: "Test",
      policyType: "Base",
      preferPublisherRules: true,
      includePathRules: false,
      auditMode: true,
    });
    expect(policy.signers).toHaveLength(0);
    expect(policy.fileRules.some((r) => r.kind === "hash")).toBe(true);
  });

  test("explicit publisher selection without issuer TBS still emits a hash rule (no silent drop)", () => {
    const { policy, buildLog } = buildPolicyFromEvents({
      events: [
        ciEvent({
          sha256FlatHash: "E".repeat(64),
          signerInfo: { publisherName: "CN=Vendor", publisherTbsHash: "F".repeat(64) },
        }),
      ],
      policyName: "Test",
      policyType: "Base",
      ruleSelections: [{ fileKey: "E".repeat(64), ruleType: "publisher" }],
      preferPublisherRules: false,
      includePathRules: false,
      auditMode: true,
    });
    expect(policy.signers).toHaveLength(0);
    expect(policy.fileRules.some((r) => r.kind === "hash")).toBe(true);
    expect(buildLog.join("\n")).toMatch(/falling back to hash/i);
  });

  test("publisher rule with issuer TBS produces an anchored signer", () => {
    const { policy } = buildPolicyFromEvents({
      events: [
        ciEvent({
          signerInfo: {
            publisherName: "CN=Vendor, O=Vendor Inc",
            issuerName: "CN=Some CA",
            issuerTbsHash: "1A".repeat(32),
          },
        }),
      ],
      policyName: "Test",
      policyType: "Base",
      preferPublisherRules: true,
      includePathRules: false,
      auditMode: true,
    });
    expect(policy.signers).toHaveLength(1);
    expect(policy.signers[0].certRoot).toEqual({ type: "TBS", value: "1A".repeat(32) });
    expect(policy.signers[0].certPublisher).toBe("Vendor");
    // User-mode signers should also be listed as CiSigners
    expect(policy.ciSigners).toContain(policy.signers[0].id);
  });

  test("fileAttrib request without OriginalFileName falls back to a hash rule", () => {
    const { policy } = buildPolicyFromEvents({
      events: [ciEvent({ sha256FlatHash: "9".repeat(64) })],
      policyName: "Test",
      policyType: "Base",
      defaultRuleType: "fileAttrib",
      preferPublisherRules: false,
      includePathRules: false,
      auditMode: true,
    });
    expect(policy.fileRules.some((r) => r.kind === "hash")).toBe(true);
  });

  test("FileName attribute rules always carry a MinimumFileVersion floor", () => {
    const { policy } = buildPolicyFromEvents({
      events: [ciEvent({ originalFileName: "TOOL.EXE" })],
      policyName: "Test",
      policyType: "Base",
      defaultRuleType: "fileAttrib",
      preferPublisherRules: false,
      includePathRules: false,
      auditMode: true,
    });
    const attrRule = policy.fileRules.find((r) => r.kind === "attribute");
    expect(attrRule).toBeDefined();
    expect((attrRule as { minimumFileVersion?: string }).minimumFileVersion).toBe("0.0.0.0");
  });

  test("supplemental policy uses options 5+6 only and inherits base policy GUID from events", () => {
    const { policy } = buildPolicyFromEvents({
      events: [ciEvent({ sha256FlatHash: "8".repeat(64), policyGuid: `{${GUID_B}}` })],
      policyName: "Supp",
      policyType: "Supplemental",
      preferPublisherRules: false,
      includePathRules: false,
      auditMode: false,
    });
    const optValues = policy.options.map((o) => o.value as number).sort((a, b) => a - b);
    expect(optValues).toEqual([5, 6]);
    expect(policy.basePolicyId?.toUpperCase()).toContain(GUID_B);
    // Generated XML must be valid (supplemental has a base policy ID)
    expect(() => generateWdacXml(policy)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// cipolicy.xsd ID-pattern and value-range conformance
// ---------------------------------------------------------------------------

describe("cipolicy.xsd conformance", () => {
  // Patterns copied verbatim from cipolicy.xsd simple types
  const ALLOW_ID = /^((ID_ALLOW_[A-Z][_A-Z0-9]*))$|^((ID_FILE_[A-Z][_A-Z0-9]*))$/;
  const DENY_ID = /^((ID_DENY_[A-Z][_A-Z0-9]*))$|^((ID_FILE_[A-Z][_A-Z0-9]*))$/;
  const FILEATTRIB_ID = /^((ID_FILEATTRIB_[A-Z][_A-Z0-9]*))$|^((ID_FILE_[A-Z][_A-Z0-9]*))$/;
  const SIGNER_ID = /^ID_SIGNER_[A-Z][_A-Z0-9]*$/;
  const SCENARIO_ID = /^ID_SIGNINGSCENARIO_[A-Z][_A-Z0-9]*$/;

  function assertPolicyIds(p: WdacPolicy) {
    for (const r of p.fileRules) {
      if (r.kind === "fileAttrib") expect(r.id).toMatch(FILEATTRIB_ID);
      else if (r.effect === "Deny") expect(r.id).toMatch(DENY_ID);
      else expect(r.id).toMatch(ALLOW_ID);
    }
    for (const s of p.signers) expect(s.id).toMatch(SIGNER_ID);
  }

  test("PlatformID is always emitted (required by schema)", () => {
    const xml = generateWdacXml(minimalPolicy());
    expect(xml).toMatch(/<PlatformID>\{[0-9A-F-]{36}\}<\/PlatformID>/);
  });

  test("generated scenario IDs are normalized to the schema pattern", () => {
    const xml = generateWdacXml(
      minimalPolicy({
        signingScenarios: [
          { value: 131, id: "0", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
          { value: 12, id: "1", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
        ],
      })
    );
    const ids = [...xml.matchAll(/SigningScenario ID="([^"]+)"/g)].map((m) => m[1]);
    expect(ids).toHaveLength(2);
    for (const id of ids) expect(id).toMatch(SCENARIO_ID);
  });

  test("merger regenerates IDs that satisfy the schema patterns", () => {
    const input = minimalPolicy({
      fileRules: [
        { kind: "hash", id: "ID_ALLOW_A_1", effect: "Allow", hash: "A".repeat(64), hashType: "SHA256" },
        { kind: "hash", id: "ID_DENY_D_1", effect: "Deny", hash: "B".repeat(64), hashType: "SHA256" },
        { kind: "path", id: "ID_DENY_P_1", effect: "Deny", filePath: "C:\\Temp\\*" },
        { kind: "package", id: "ID_ALLOW_K_1", effect: "Allow", packageFamilyName: "Some.App_8wekyb" },
        { kind: "fileAttrib", id: "ID_FILEATTRIB_F_1", fileName: "x.exe" },
      ],
      signers: [
        { id: "ID_SIGNER_S_1", name: "S", certRoot: { type: "TBS", value: "AB" }, fileAttribRefs: ["ID_FILEATTRIB_F_1"] },
      ],
    });
    const { policy: merged } = mergePolicies([input, minimalPolicy({ policyId: GUID_B })]);
    assertPolicyIds(merged);
  });

  test("builder emits schema-conformant IDs and MinimumHashAlgorithm within unsigned short range", () => {
    const { policy } = buildPolicyFromEvents({
      events: [
        ciEvent({ sha256FlatHash: "A".repeat(64), sha1FlatHash: "B".repeat(40) }),
      ],
      policyName: "P",
      policyType: "Base",
      preferPublisherRules: false,
      includePathRules: false,
      auditMode: true,
    });
    assertPolicyIds(policy);
    const kernel = policy.signingScenarios.find((s) => s.value === 131)!;
    expect(parseInt(kernel.minHashVersion!, 10)).toBeLessThanOrEqual(65535);
  });

  test("AppLocker deny rules get ID_DENY_ prefixed IDs", () => {
    const al = `<AppLockerPolicy Version="1">
      <RuleCollection Type="Exe" EnforcementMode="Enabled">
        <FilePathRule Id="r2" Name="DenyTemp" Action="Deny">
          <Conditions><FilePathCondition Path="%OSDRIVE%\\Temp\\*" /></Conditions>
        </FilePathRule>
      </RuleCollection>
    </AppLockerPolicy>`;
    const { policy } = convertAppLockerToWdac(al, true);
    const denyRule = policy.fileRules.find((r) => r.kind === "path");
    expect(denyRule?.id).toMatch(DENY_ID);
  });
});

// ---------------------------------------------------------------------------
// Simulator — default-deny semantics
// ---------------------------------------------------------------------------

describe("simulateBinary conformance", () => {
  test("missing signing scenario yields default deny, not allow", () => {
    const policy = minimalPolicy({ signingScenarios: [] });
    const result = simulateBinary({ sha256: "A".repeat(64) }, policy);
    expect(result.verdict).toBe("blocked");
    expect(result.matchedBy).toBe("no-scenario");
  });

  test("certIssuer constraint with unknown binary issuer is skipped, not assumed allowed", () => {
    const policy = minimalPolicy({
      signers: [
        {
          id: "ID_SIGNER_S_1",
          name: "Vendor",
          certRoot: { type: "Wellknown", value: "06" },
          certIssuer: "Some CA",
        },
      ],
      signingScenarios: [
        {
          value: 12,
          id: "ID_SIGNINGSCENARIO_WINDOWS",
          allowedSigners: [{ signerId: "ID_SIGNER_S_1" }],
          deniedSigners: [],
          fileRuleRefs: [],
        },
      ],
    });
    const result = simulateBinary({ signerName: "Vendor Inc" }, policy);
    expect(result.verdict).toBe("blocked"); // default deny — signer rule skipped
    const signerStep = result.steps.find((s) => s.ruleId === "ID_SIGNER_S_1");
    expect(signerStep?.outcome).toBe("skipped");
  });

  test("SHA-1 hash rules match against the binary's SHA-1, not SHA-256", () => {
    const sha1 = "F".repeat(40);
    const policy = minimalPolicy({
      fileRules: [
        { kind: "hash", id: "ID_ALLOW_HASH_1", effect: "Allow", hash: sha1, hashType: "SHA1" },
      ],
      signingScenarios: [
        {
          value: 12,
          id: "ID_SIGNINGSCENARIO_WINDOWS",
          allowedSigners: [],
          deniedSigners: [],
          fileRuleRefs: ["ID_ALLOW_HASH_1"],
        },
      ],
    });
    const result = simulateBinary({ sha1, sha256: "0".repeat(64) }, policy);
    expect(result.verdict).toBe("allowed");
    expect(result.matchedBy).toBe("hash");
  });

  test("UMCI disabled leaves user-mode binaries unenforced", () => {
    const policy = minimalPolicy({ options: [] });
    const result = simulateBinary({ sha256: "A".repeat(64) }, policy);
    expect(result.verdict).toBe("allowed");
    expect(result.matchedBy).toBe("umci-disabled");
  });
});

// ---------------------------------------------------------------------------
// AppLocker conversion
// ---------------------------------------------------------------------------

describe("convertAppLockerToWdac", () => {
  const APPLOCKER_XML = `<AppLockerPolicy Version="1">
    <RuleCollection Type="Exe" EnforcementMode="Enabled">
      <FilePublisherRule Id="p1" Name="Allow Contoso" Action="Allow">
        <Conditions>
          <FilePublisherCondition PublisherName="O=CONTOSO, L=SEATTLE" ProductName="*" BinaryName="*">
            <BinaryVersionRange LowSection="*" HighSection="*" />
          </FilePublisherCondition>
        </Conditions>
      </FilePublisherRule>
      <FileHashRule Id="h1" Name="Allow tool" Action="Allow">
        <Conditions>
          <FileHashCondition>
            <FileHash Type="SHA256" Data="0x${"A".repeat(64)}" SourceFileName="tool.exe" />
          </FileHashCondition>
        </Conditions>
      </FileHashRule>
      <FilePathRule Id="r1" Name="Program Files" Action="Allow">
        <Conditions><FilePathCondition Path="%PROGRAMFILES%\\*" /></Conditions>
      </FilePathRule>
    </RuleCollection>
  </AppLockerPolicy>`;

  test("produces XML with single-braced PolicyID and parseable output", () => {
    const { xml } = convertAppLockerToWdac(APPLOCKER_XML);
    expect(xml).not.toMatch(/\{\{/);
    const { policy, diagnostics } = parseWdacXml(xml);
    expect(policy.policyId).toMatch(/^[0-9A-F-]{36}$/);
    expect(diagnostics.filter((d) => d.severity === "error")).toHaveLength(0);
  });

  test("skips publisher rules lacking certificate TBS data instead of emitting invalid signers", () => {
    const { policy, stats, log } = convertAppLockerToWdac(APPLOCKER_XML);
    expect(policy.signers).toHaveLength(0);
    expect(stats.skippedRules).toBeGreaterThanOrEqual(1);
    expect(log.join("\n")).toMatch(/CertRoot/);
  });

  test("expands %PROGRAMFILES% into both Program Files directories using %OSDRIVE%", () => {
    const { policy } = convertAppLockerToWdac(APPLOCKER_XML);
    const paths = policy.fileRules
      .filter((r) => r.kind === "path")
      .map((r) => (r as { filePath: string }).filePath);
    expect(paths).toContain("%OSDRIVE%\\Program Files\\*");
    expect(paths).toContain("%OSDRIVE%\\Program Files (x86)\\*");
    expect(paths.join("|")).not.toContain("%PROGRAMFILES%");
  });

  test("converts hash rules with the 0x prefix stripped", () => {
    const { policy } = convertAppLockerToWdac(APPLOCKER_XML);
    const hashRule = policy.fileRules.find((r) => r.kind === "hash");
    expect(hashRule).toBeDefined();
    expect((hashRule as { hash: string }).hash).toBe("A".repeat(64));
  });
});
