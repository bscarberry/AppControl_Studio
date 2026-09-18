/**
 * File inspector conformance tests.
 *
 * Oracle values were produced on Windows 11 24H2 with the ConfigCI module:
 *   New-CIPolicyRule -Level Hash|Publisher|FilePublisher|LeafCertificate|
 *                    PcaCertificate -DriverFilePath <file>
 *
 * Two real binaries are used when present on the host (skipped otherwise):
 *   C:\Windows\System32\notepad.exe   — catalog-signed (no embedded signature)
 *   <node.exe running the tests>      — embedded-signed (OpenJS Foundation via
 *                                       Microsoft ID Verified CS AOC CA 04)
 *
 * The Authenticode/page-hash algorithm and the "hash TBS with the cert's own
 * signature digest" rule are exercised on synthetic PEs for CI portability.
 */

import * as fs from "fs";
import * as os from "os";
import * as crypto from "crypto";
import { inspectFile, buildRulesForFile } from "../services/file-inspector.js";
import { parsePe } from "../services/pe/pe-parser.js";
import { computeAuthenticodeHashes } from "../services/pe/authenticode.js";
import { simulateBinary } from "../services/policy-simulator.js";
import { applyRuleBundles, ekuValueToOid, oidToEkuValue } from "@appcontrol/shared";
import type { WdacPolicy } from "@appcontrol/shared";

const NOTEPAD = "C:\\Windows\\System32\\notepad.exe";
const NODE_EXE = process.execPath;
const isWin = os.platform() === "win32";
const hasNotepad = isWin && fs.existsSync(NOTEPAD);

// Oracle values from New-CIPolicyRule on the test host (notepad.exe 10.0.26100.9278)
const NOTEPAD_ORACLE = {
  version: "10.0.26100.9278",
  sha1: "479352D44FCDD7BA234A9A68B0021C2358A40704",
  sha256: "27264AAC7BAD8E35F1D48E99221F4D0F0322433A399F9F2D5EB523E1971479EC",
  page1: "6663E4F9849671EB7884E010699FDD4DA68E0125",
  page256: "E742A50A3DDCB5DC04A6DCBF76FAFD066AA3B8AC60A59F3E34CA1DFFAB71A4E3",
};

// ---------------------------------------------------------------------------
// Synthetic PE builder — a minimal PE32+ with one section and a fake
// certificate table so the exclusion ranges are exercised deterministically.
// ---------------------------------------------------------------------------

function buildSyntheticPe(opts: { withCertTable?: boolean } = {}): Buffer {
  const sizeOfHeaders = 0x400;
  const sectionRaw = 0x200;
  const certSize = opts.withCertTable ? 0x40 : 0;
  const buf = Buffer.alloc(sizeOfHeaders + sectionRaw + certSize);
  buf.write("MZ", 0, "ascii");
  const peOff = 0x80;
  buf.writeUInt32LE(peOff, 0x3c);
  buf.writeUInt32LE(0x00004550, peOff);
  const coff = peOff + 4;
  buf.writeUInt16LE(0x8664, coff); // machine
  buf.writeUInt16LE(1, coff + 2); // sections
  buf.writeUInt16LE(240, coff + 16); // optional header size (PE32+)
  buf.writeUInt16LE(0x0022, coff + 18); // exe, large address aware
  const opt = coff + 20;
  buf.writeUInt16LE(0x20b, opt);
  buf.writeUInt32LE(sizeOfHeaders, opt + 60);
  buf.writeUInt32LE(0xdeadbeef, opt + 64); // checksum (must be excluded)
  buf.writeUInt16LE(2, opt + 68); // GUI subsystem
  buf.writeUInt32LE(16, opt + 108); // number of RVA and sizes
  const dir = opt + 112;
  if (opts.withCertTable) {
    buf.writeUInt32LE(sizeOfHeaders + sectionRaw, dir + 4 * 8);
    buf.writeUInt32LE(certSize, dir + 4 * 8 + 4);
  }
  const sec = opt + 240;
  buf.write(".text", sec, "ascii");
  buf.writeUInt32LE(sectionRaw, sec + 8);
  buf.writeUInt32LE(0x1000, sec + 12);
  buf.writeUInt32LE(sectionRaw, sec + 16);
  buf.writeUInt32LE(sizeOfHeaders, sec + 20);
  buf.writeUInt32LE(0x60000020, sec + 36);
  // fill section + cert with pseudo-random but deterministic bytes
  for (let i = sizeOfHeaders; i < buf.length; i++) buf[i] = (i * 31) & 0xff;
  return buf;
}

describe("Authenticode hashing (synthetic PE)", () => {
  test("excludes CheckSum, the certificate directory entry, and the certificate table", () => {
    const withCert = buildSyntheticPe({ withCertTable: true });
    const pe = parsePe(withCert)!;
    expect(pe).not.toBeNull();
    const h = computeAuthenticodeHashes(withCert, pe);

    // Reference: hash the file manually with the documented exclusions
    const ref = crypto.createHash("sha256");
    ref.update(withCert.subarray(0, pe.checksumOffset));
    ref.update(withCert.subarray(pe.checksumOffset + 4, pe.certDirEntryOffset));
    ref.update(withCert.subarray(pe.certDirEntryOffset + 8, pe.sizeOfHeaders));
    ref.update(withCert.subarray(pe.sizeOfHeaders, pe.sizeOfHeaders + 0x200));
    expect(h.sha256).toBe(ref.digest("hex").toUpperCase());

    // Changing the checksum or the certificate bytes must not change the hash
    const mutated = Buffer.from(withCert);
    mutated.writeUInt32LE(0x12345678, pe.checksumOffset);
    mutated[mutated.length - 1] ^= 0xff;
    expect(computeAuthenticodeHashes(mutated, parsePe(mutated)!).sha256).toBe(h.sha256);

    // Changing section content must change it
    const changed = Buffer.from(withCert);
    changed[pe.sizeOfHeaders + 10] ^= 0x01;
    expect(computeAuthenticodeHashes(changed, parsePe(changed)!).sha256).not.toBe(h.sha256);
  });

  test("page hash covers only the header page with the same exclusions", () => {
    const b = buildSyntheticPe();
    const pe = parsePe(b)!;
    const h = computeAuthenticodeHashes(b, pe);
    const changed = Buffer.from(b);
    changed[pe.sizeOfHeaders + 10] ^= 0x01; // section change → page hash unchanged
    expect(computeAuthenticodeHashes(changed, parsePe(changed)!).pageSha256).toBe(h.pageSha256);
    expect(h.pageSha256).not.toBe(h.sha256);
  });

  test("non-PE input yields flat hashes only and never throws", () => {
    const script = Buffer.from("Write-Host 'hello'\n", "utf8");
    const r = inspectFile("deploy.ps1", script);
    expect(r.isPe).toBe(false);
    expect(r.fileType).toBe("script");
    expect(r.hashes.sha256Flat).toBe(crypto.createHash("sha256").update(script).digest("hex").toUpperCase());
    expect(r.hashes.sha256Authenticode).toBeUndefined();
    const rules = buildRulesForFile(r, "Hash");
    expect(rules.fileRules.map((x) => (x as { hashType: string }).hashType)).toEqual(["SHA1", "SHA256"]);
  });
});

describe("EKU encoding", () => {
  test("round-trips Microsoft EKU values from the example policies", () => {
    expect(ekuValueToOid("010a2b0601040182370a0306")).toBe("1.3.6.1.4.1.311.10.3.6");
    expect(ekuValueToOid("010A2B0601040182370A0305")).toBe("1.3.6.1.4.1.311.10.3.5");
    expect(oidToEkuValue("1.3.6.1.4.1.311.10.3.6").toUpperCase()).toBe("010A2B0601040182370A0306");
    expect(oidToEkuValue("1.3.6.1.5.5.7.3.3")).toBe("01082b06010505070303");
  });
});

(hasNotepad ? describe : describe.skip)("notepad.exe vs New-CIPolicyRule oracle", () => {
  const buf = fs.readFileSync(NOTEPAD);
  const file = inspectFile("notepad.exe", buf);

  test("Authenticode and page hashes match -Level Hash output", () => {
    if (file.versionInfo?.fixedFileVersion !== NOTEPAD_ORACLE.version) {
      // Windows Update replaced the binary since the oracle was captured; the
      // algorithm is covered by the synthetic-PE tests above.
      return;
    }
    expect(file.hashes.sha1Authenticode).toBe(NOTEPAD_ORACLE.sha1);
    expect(file.hashes.sha256Authenticode).toBe(NOTEPAD_ORACLE.sha256);
    expect(file.hashes.sha1Page).toBe(NOTEPAD_ORACLE.page1);
    expect(file.hashes.sha256Page).toBe(NOTEPAD_ORACLE.page256);
  });

  test("catalog-signed file has no embedded signature and falls back to Hash", () => {
    expect(file.signature.status).toBe("none");
    expect(file.versionInfo?.originalFileName).toBe("NOTEPAD.EXE");
    const b = buildRulesForFile(file, "Publisher");
    expect(b.effectiveLevel).toBe("Hash");
    expect(b.fileRules).toHaveLength(4);
    expect(b.fileRules.map((r) => r.id)).toEqual([
      "ID_ALLOW_A_0001_SHA1", "ID_ALLOW_A_0002_SHA256", "ID_ALLOW_A_0003_SHA1_PAGE", "ID_ALLOW_A_0004_SHA256_PAGE",
    ]);
  });

  test("FileName level mirrors -Level FileName (OriginalFilename + MinimumFileVersion)", () => {
    const b = buildRulesForFile(file, "FileName");
    expect(b.fileRules).toHaveLength(1);
    const r = b.fileRules[0] as { kind: string; fileName: string; minimumFileVersion: string };
    expect(r.kind).toBe("attribute");
    expect(r.fileName).toBe("NOTEPAD.EXE");
    expect(r.minimumFileVersion).toBe(file.versionInfo!.fixedFileVersion);
  });
});

(isWin && fs.existsSync(NODE_EXE) ? describe : describe.skip)("node.exe (embedded signature) vs New-CIPolicyRule oracle", () => {
  const buf = fs.readFileSync(NODE_EXE);
  const file = inspectFile("node.exe", buf);
  const sig = file.signature.signatures[0];
  const signed = file.signature.status === "embedded";

  test("extracts the leaf and PCA with TBS hashed by the cert's own signature algorithm", () => {
    if (!signed) return; // unsigned node build on this host
    expect(sig.leaf.subjectCN).toBe("OpenJS Foundation");
    expect(sig.pca?.subjectCN).toBe("Microsoft ID Verified Code Signing PCA 2021");
    // Both certs are SHA-384 signed → 96 hex chars, exactly what ConfigCI emits
    expect(sig.leaf.tbsHashAlgorithm).toBe("SHA384");
    expect(sig.pca!.tbsHash).toHaveLength(96);
    expect(sig.leaf.ekus).toContain("1.3.6.1.5.5.7.3.3");
    expect(sig.digestMatches).toBe(true);
    expect(sig.wellknownRootId).toBe("16");
  });

  test("Publisher / PcaCertificate / LeafCertificate / FilePublisher rule shapes match ConfigCI", () => {
    if (!signed) return;
    const pub = buildRulesForFile(file, "Publisher");
    expect(pub.signers).toHaveLength(1);
    expect(pub.signers[0]).toMatchObject({
      id: "ID_SIGNER_S_0001",
      name: "Microsoft ID Verified Code Signing PCA 2021",
      certRoot: { type: "TBS", value: sig.pca!.tbsHash },
      certPublisher: "OpenJS Foundation",
    });
    expect(pub.signers[0].fileAttribRefs).toBeUndefined();

    const pca = buildRulesForFile(file, "PcaCertificate");
    expect(pca.signers[0].certPublisher).toBeUndefined();
    expect(pca.signers[0].certRoot!.value).toBe(sig.pca!.tbsHash);

    const leaf = buildRulesForFile(file, "LeafCertificate");
    expect(leaf.signers[0].name).toBe("OpenJS Foundation");
    expect(leaf.signers[0].certRoot!.value).toBe(sig.leaf.tbsHash);

    const fp = buildRulesForFile(file, "FilePublisher");
    expect(fp.signers[0].id).toBe("ID_SIGNER_F_0001");
    expect(fp.fileRules).toHaveLength(1);
    expect(fp.fileRules[0]).toMatchObject({ kind: "fileAttrib", fileName: "node.exe", minimumFileVersion: file.versionInfo!.fixedFileVersion });
    expect(fp.signers[0].fileAttribRefs).toEqual([fp.fileRules[0].id]);

    const sv = buildRulesForFile(file, "SignedVersion");
    expect(sv.fileRules[0]).toMatchObject({ kind: "fileAttrib", fileName: "*" });
  });

  test("WHQL levels fall back when the WHQL EKU is absent", () => {
    if (!signed) return;
    const b = buildRulesForFile(file, "WHQLFilePublisher");
    expect(b.effectiveLevel).toBe("FilePublisher");
    expect(b.notes.join(" ")).toMatch(/WHQL EKU/);
  });

  test("a FilePublisher rule generated from the file allows the file in the simulator; Deny blocks it", () => {
    if (!signed) return;
    const base: WdacPolicy = {
      policyId: "11111111-1111-1111-1111-111111111111",
      versionEx: "1.0.0.0", policyType: "Base",
      options: [{ value: 0, enabled: true }, { value: 6, enabled: true }],
      ekus: [], fileRules: [], signers: [],
      signingScenarios: [
        { value: 131, id: "ID_SIGNINGSCENARIO_DRIVERS", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
        { value: 12, id: "ID_SIGNINGSCENARIO_WINDOWS", allowedSigners: [], deniedSigners: [], fileRuleRefs: [] },
      ],
      updatePolicySigners: [], ciSigners: [],
    };
    const allow = applyRuleBundles(base, [buildRulesForFile(file, "FilePublisher")]);
    expect(allow.addedSigners).toBe(1);
    expect(allow.policy.ciSigners).toHaveLength(1);
    let r = simulateBinary(file.simulationMetadata, allow.policy);
    expect(r.verdict).toBe("allowed");
    expect(r.matchedBy).toBe("publisher-scoped");

    // A different file name from the same publisher must NOT match a FilePublisher rule
    r = simulateBinary({ ...file.simulationMetadata, originalFileName: "other.exe" }, allow.policy);
    expect(r.verdict).toBe("blocked");

    const deny = applyRuleBundles(allow.policy, [buildRulesForFile(file, "Hash", { effect: "Deny" })]);
    r = simulateBinary(file.simulationMetadata, deny.policy);
    expect(r.verdict).toBe("blocked");
    expect(r.matchedBy).toBe("hash");
  });
});
