/**
 * File Inspector
 *
 * AppControl Manager parity for:
 *   - Get Code Integrity Hashes  (Authenticode / page / flat hashes)
 *   - View File Certificates     (embedded signature chains, TBS hashes)
 *   - Files & Folders scan modes of Create Supplemental / Deny Policy
 *     (rule generation at every New-CIPolicyRule -Level)
 *   - Simulation on real files   (produces BinaryMetadata for the simulator)
 *
 * Rule shapes were validated byte-for-byte against New-CIPolicyRule output
 * for a catalog-signed Windows binary (notepad.exe) and an embedded-signed
 * third-party binary (node.exe) — see __tests__/file-inspector.test.ts.
 */

import type {
  InspectedFile,
  InspectedFileType,
  InspectedSignature,
  InspectedCertificate,
  RuleLevel,
  FileRuleBundle,
  WdacFileRule,
  WdacSignerRule,
  WdacEku,
  WdacFileAttrib,
  BinaryMetadata,
  PeKind,
  HashType,
} from "@appcontrol/shared";
import { KNOWN_EKUS, oidToEkuValue } from "@appcontrol/shared";
import { parsePe, parseVersionInfo, importsKernelModules } from "./pe/pe-parser.js";
import { computeAuthenticodeHashes, extractSignatures, flatHashes } from "./pe/authenticode.js";

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

const SCRIPT_EXT = new Set([".ps1", ".psm1", ".psd1", ".vbs", ".js", ".wsf", ".wsh", ".bat", ".cmd", ".hta"]);
const MSI_EXT = new Set([".msi", ".msp", ".mst"]);

function classify(fileName: string, isPe: boolean): InspectedFileType {
  if (isPe) return "pe";
  const ext = (fileName.match(/\.[^.]+$/)?.[0] ?? "").toLowerCase();
  if (SCRIPT_EXT.has(ext)) return "script";
  if (MSI_EXT.has(ext)) return "msi";
  if (ext === ".cat") return "catalog";
  return "other";
}

function peKindFor(fileName: string, isDll: boolean, isKernel: boolean): PeKind {
  const ext = (fileName.match(/\.[^.]+$/)?.[0] ?? "").toLowerCase();
  if (isKernel || ext === ".sys") return "sys";
  if (isDll || ext === ".dll" || ext === ".ocx") return "dll";
  if (ext === ".exe" || ext === ".scr" || ext === ".com") return "exe";
  return "other";
}

export function inspectFile(fileName: string, buf: Buffer): InspectedFile {
  const warnings: string[] = [];
  const flat = flatHashes(buf);
  const pe = parsePe(buf);

  if (!pe) {
    const fileType = classify(fileName, false);
    return {
      fileName,
      sizeBytes: buf.length,
      fileType,
      isPe: false,
      isKernelMode: false,
      hashes: { sha1Flat: flat.sha1, sha256Flat: flat.sha256 },
      signature: { status: "none", signatures: [] },
      simulationMetadata: { sha1: flat.sha1, sha256: flat.sha256, isKernelMode: false },
      warnings: [
        fileType === "script" || fileType === "msi"
          ? "Non-PE file: WDAC uses the flat SHA-256 as the file hash."
          : "Not a PE image: only flat hashes are available.",
      ],
    };
  }

  const auth = computeAuthenticodeHashes(buf, pe);
  const versionInfo = parseVersionInfo(buf, pe);
  const ext = (fileName.match(/\.[^.]+$/)?.[0] ?? "").toLowerCase();
  const isKernelMode = ext === ".sys" || (pe.isNativeSubsystem && importsKernelModules(buf, pe));
  const signatures = extractSignatures(buf, pe, auth);

  if (signatures.length === 0) {
    warnings.push(
      "No embedded Authenticode signature. The file is either unsigned or catalog-signed " +
      "(Windows components usually are). Signature-based rule levels are unavailable; " +
      "use CodeIntegrity event data (3089) for publisher rules, or a Hash rule."
    );
  }
  for (const s of signatures) {
    if (s.digestMatches === false) {
      warnings.push(
        `Signature #${s.index}: embedded ${s.digestAlgorithm} digest does not match the computed Authenticode hash — the file was modified after signing.`
      );
    }
    if (!s.pca) warnings.push(`Signature #${s.index}: no CA certificate embedded; Publisher-level rules would pin the leaf certificate.`);
  }
  if (!versionInfo?.originalFileName) {
    warnings.push("No OriginalFilename in the version resource — FilePublisher/FileName levels fall back to other levels.");
  }

  const primary = signatures[0];
  const simulationMetadata: BinaryMetadata = {
    sha1: auth.sha1,
    sha256: auth.sha256,
    ...(primary && {
      signerName: primary.leaf.subjectCN,
      issuerName: primary.leaf.issuerCN,
      rootCertTbs: primary.pca?.tbsHash,
      certChainTbs: [...new Set(signatures.flatMap((s) => s.chain.map((c) => c.tbsHash)))],
      leafEkus: primary.leaf.ekus,
      wellknownRootId: primary.wellknownRootId,
    }),
    originalFileName: versionInfo?.originalFileName,
    internalName: versionInfo?.internalName,
    productName: versionInfo?.productName,
    fileVersion: versionInfo?.fixedFileVersion ?? versionInfo?.fileVersion,
    isKernelMode,
  };

  return {
    fileName,
    sizeBytes: buf.length,
    fileType: "pe",
    isPe: true,
    peKind: peKindFor(fileName, pe.isDll, isKernelMode),
    machine: pe.machineName,
    isKernelMode,
    hashes: {
      sha1Authenticode: auth.sha1,
      sha256Authenticode: auth.sha256,
      sha1Page: auth.pageSha1,
      sha256Page: auth.pageSha256,
      sha1Flat: flat.sha1,
      sha256Flat: flat.sha256,
    },
    versionInfo,
    signature: { status: signatures.length ? "embedded" : "none", signatures },
    simulationMetadata,
    warnings,
  };
}

// ---------------------------------------------------------------------------
// Rule generation at a given level
// ---------------------------------------------------------------------------

export interface BuildRulesOptions {
  effect?: "Allow" | "Deny";
  fallbackToHash?: boolean;
  /** FilePath level: the path pattern to use for this file */
  filePath?: string;
}

const WHQL_EKU_OID = "1.3.6.1.4.1.311.10.3.5";

function versionFloor(file: InspectedFile): string {
  return file.versionInfo?.fixedFileVersion ?? "0.0.0.0";
}

function makeSigner(
  seq: number,
  sig: InspectedSignature,
  opts: { publisher: boolean; leaf: boolean; fileAttribId?: string; ekuId?: string }
): WdacSignerRule {
  const anchor: InspectedCertificate = opts.leaf ? sig.leaf : (sig.pca ?? sig.leaf);
  return {
    id: `ID_SIGNER_${opts.fileAttribId ? "F" : "S"}_${String(seq).padStart(4, "0")}`,
    name: anchor.subjectCN,
    certRoot: { type: "TBS", value: anchor.tbsHash },
    ...(opts.ekuId ? { certEKU: [{ ekuId: opts.ekuId }] } : {}),
    ...(opts.publisher ? { certPublisher: sig.leaf.subjectCN } : {}),
    ...(opts.fileAttribId ? { fileAttribRefs: [opts.fileAttribId] } : {}),
  };
}

/** Distinct signatures by (anchor TBS, leaf CN) — dual-signed files yield one signer per pair. */
function distinctSignatures(file: InspectedFile): InspectedSignature[] {
  const seen = new Set<string>();
  const out: InspectedSignature[] = [];
  for (const s of file.signature.signatures) {
    const key = `${(s.pca ?? s.leaf).tbsHash}|${s.leaf.subjectCN}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
  }
  return out;
}

export function buildRulesForFile(
  file: InspectedFile,
  level: RuleLevel,
  opts: BuildRulesOptions = {}
): FileRuleBundle {
  const effect = opts.effect ?? "Allow";
  const fallbackToHash = opts.fallbackToHash ?? true;
  const bundle: FileRuleBundle = {
    fileName: file.fileName,
    requestedLevel: level,
    effectiveLevel: level,
    effect,
    scenario: file.isKernelMode ? 131 : 12,
    fileRules: [],
    signers: [],
    ekus: [],
    notes: [],
  };
  const prefix = effect === "Deny" ? "ID_DENY" : "ID_ALLOW";
  const sigs = distinctSignatures(file);
  const hasSig = sigs.length > 0;
  const origName = file.versionInfo?.originalFileName;

  const hashRules = (): WdacFileRule[] => {
    const rules: WdacFileRule[] = [];
    const push = (tag: string, hash: string | undefined, hashType: HashType, label: string) => {
      if (!hash) return;
      rules.push({
        kind: "hash",
        id: `${prefix}_A_${String(rules.length + 1).padStart(4, "0")}_${tag}`,
        effect,
        friendlyName: `${file.fileName} ${label}`,
        hash,
        hashType,
      } as WdacFileRule);
    };
    if (file.isPe) {
      push("SHA1", file.hashes.sha1Authenticode, "SHA1", "Hash Sha1");
      push("SHA256", file.hashes.sha256Authenticode, "SHA256", "Hash Sha256");
      push("SHA1_PAGE", file.hashes.sha1Page, "SHA1Page", "Hash Page Sha1");
      push("SHA256_PAGE", file.hashes.sha256Page, "SHA256Page", "Hash Page Sha256");
    } else {
      push("SHA1", file.hashes.sha1Flat, "SHA1", "Hash Sha1");
      push("SHA256", file.hashes.sha256Flat, "SHA256", "Hash Sha256");
    }
    return rules;
  };

  const fallback = (reason: string, to: RuleLevel | null): FileRuleBundle => {
    bundle.notes.push(reason);
    if (to === null) {
      bundle.skippedReason = reason;
      return bundle;
    }
    const inner = buildRulesForFile(file, to, { ...opts, fallbackToHash });
    return {
      ...inner,
      requestedLevel: level,
      notes: [...bundle.notes, ...inner.notes],
    };
  };

  const hashFallback = (reason: string) =>
    fallbackToHash ? fallback(reason, "Hash") : fallback(reason + " (hash fallback disabled)", null);

  switch (level) {
    case "Hash": {
      bundle.fileRules = hashRules();
      if (bundle.fileRules.length === 0) bundle.skippedReason = "No hashes available.";
      return bundle;
    }

    case "FileName": {
      if (!origName) return hashFallback("FileName level requires OriginalFilename version metadata.");
      bundle.fileRules = [{
        kind: "attribute",
        id: `${prefix}_T_0001`,
        effect,
        friendlyName: `${file.fileName} FileRule`,
        fileName: origName,
        minimumFileVersion: versionFloor(file),
      }];
      return bundle;
    }

    case "FilePath": {
      if (!opts.filePath) return hashFallback("FilePath level requires a path pattern.");
      if (file.isKernelMode) bundle.notes.push("File path rules have no effect for kernel-mode images.");
      bundle.fileRules = [{
        kind: "path",
        id: `${prefix}_P_0001`,
        effect,
        friendlyName: `${file.fileName} FilePath`,
        filePath: opts.filePath,
      }];
      return bundle;
    }

    case "LeafCertificate": {
      if (!hasSig) return hashFallback("LeafCertificate level requires an embedded signature.");
      bundle.signers = sigs.map((s, i) => makeSigner(i + 1, s, { publisher: false, leaf: true }));
      return bundle;
    }

    case "PcaCertificate":
    case "RootCertificate": {
      if (!hasSig) return hashFallback(`${level} level requires an embedded signature.`);
      if (level === "RootCertificate") bundle.notes.push("RootCertificate uses the highest non-self-signed CA (ConfigCI behaviour).");
      bundle.signers = sigs.map((s, i) => makeSigner(i + 1, s, { publisher: false, leaf: false }));
      return bundle;
    }

    case "Publisher": {
      if (!hasSig) return hashFallback("Publisher level requires an embedded signature.");
      bundle.signers = sigs.map((s, i) => makeSigner(i + 1, s, { publisher: true, leaf: false }));
      return bundle;
    }

    case "SignedVersion": {
      if (!hasSig) return hashFallback("SignedVersion level requires an embedded signature.");
      const fa: WdacFileAttrib = {
        kind: "fileAttrib",
        id: "ID_FILEATTRIB_F_0001",
        friendlyName: `${versionFloor(file)} SignedVersion`,
        fileName: "*",
        minimumFileVersion: versionFloor(file),
      };
      bundle.fileRules = [fa];
      bundle.signers = sigs.map((s, i) => makeSigner(i + 1, s, { publisher: true, leaf: false, fileAttribId: fa.id }));
      return bundle;
    }

    case "FilePublisher": {
      if (!hasSig) return hashFallback("FilePublisher level requires an embedded signature.");
      if (!origName) return fallback("FilePublisher level requires OriginalFilename metadata — using Publisher.", "Publisher");
      const fa: WdacFileAttrib = {
        kind: "fileAttrib",
        id: "ID_FILEATTRIB_F_0001",
        friendlyName: `${file.fileName} FileAttribute`,
        fileName: origName,
        minimumFileVersion: versionFloor(file),
      };
      bundle.fileRules = [fa];
      bundle.signers = sigs.map((s, i) => makeSigner(i + 1, s, { publisher: true, leaf: false, fileAttribId: fa.id }));
      return bundle;
    }

    case "WHQL":
    case "WHQLPublisher":
    case "WHQLFilePublisher": {
      if (!hasSig) return hashFallback(`${level} level requires an embedded signature.`);
      const whqlSigs = sigs.filter((s) => s.leaf.ekus.includes(WHQL_EKU_OID));
      if (whqlSigs.length === 0) {
        const to: RuleLevel = level === "WHQL" ? "PcaCertificate" : level === "WHQLPublisher" ? "Publisher" : "FilePublisher";
        return fallback(`${level} level requires the WHQL EKU (${WHQL_EKU_OID}) on the signing certificate — using ${to}.`, to);
      }
      const eku: WdacEku = {
        id: KNOWN_EKUS[WHQL_EKU_OID].id,
        friendlyName: KNOWN_EKUS[WHQL_EKU_OID].friendlyName,
        value: oidToEkuValue(WHQL_EKU_OID),
      };
      bundle.ekus = [eku];
      let faId: string | undefined;
      if (level === "WHQLFilePublisher") {
        if (!origName) return fallback("WHQLFilePublisher requires OriginalFilename metadata — using WHQLPublisher.", "WHQLPublisher");
        const fa: WdacFileAttrib = {
          kind: "fileAttrib",
          id: "ID_FILEATTRIB_F_0001",
          friendlyName: `${file.fileName} FileAttribute`,
          fileName: origName,
          minimumFileVersion: versionFloor(file),
        };
        bundle.fileRules = [fa];
        faId = fa.id;
      }
      bundle.signers = whqlSigs.map((s, i) =>
        makeSigner(i + 1, s, { publisher: level !== "WHQL", leaf: false, fileAttribId: faId, ekuId: eku.id })
      );
      return bundle;
    }
  }
}
