/**
 * Authenticode hashing and signature extraction.
 *
 * Hash algorithm (Windows Authenticode Portable Executable Signature Format):
 *   1. Hash from the start of the file to the OptionalHeader.CheckSum field.
 *   2. Skip the 4-byte CheckSum.
 *   3. Hash to the Certificate Table data-directory entry.
 *   4. Skip the 8-byte entry.
 *   5. Hash to the end of the headers (SizeOfHeaders).
 *   6. Hash every section's raw data, in PointerToRawData order.
 *   7. Hash any trailing data after the last section, excluding the
 *      certificate table.
 *
 * Page hash (as emitted by New-CIPolicyRule -Level Hash "Hash Page Sha*"):
 *   the header page only — steps 1-5 above — verified against ConfigCI output
 *   for both catalog-signed and embedded-signed binaries.
 *
 * Both algorithms were validated against ConvertFrom-CIPolicy /
 * New-CIPolicyRule output on Windows 11 (see __tests__/file-inspector.test.ts).
 */

import crypto from "crypto";
import type { PeInfo } from "./pe-parser.js";
import {
  readNode, children, content, raw, oidOf, integerHex, isContext, findAll, decodeTime, TAG,
  type DerNode,
} from "./asn1.js";
import type { InspectedCertificate, InspectedSignature, TbsHashAlgorithm } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

type Range = [number, number];

function headerRanges(pe: PeInfo, upTo: number): Range[] {
  return [
    [0, pe.checksumOffset],
    [pe.checksumOffset + 4, pe.certDirEntryOffset],
    [pe.certDirEntryOffset + 8, upTo],
  ];
}

function hashRanges(buf: Buffer, alg: string, ranges: Range[]): string {
  const h = crypto.createHash(alg);
  for (const [s, e] of ranges) {
    if (e > s) h.update(buf.subarray(s, Math.min(e, buf.length)));
  }
  return h.digest("hex").toUpperCase();
}

export interface AuthenticodeHashes {
  sha1: string;
  sha256: string;
  pageSha1: string;
  pageSha256: string;
}

export function computeAuthenticodeHashes(buf: Buffer, pe: PeInfo): AuthenticodeHashes {
  const ranges: Range[] = headerRanges(pe, pe.sizeOfHeaders);
  let sum = pe.sizeOfHeaders;
  const sections = [...pe.sections]
    .filter((s) => s.rawSize > 0)
    .sort((a, b) => a.rawPointer - b.rawPointer);
  for (const s of sections) {
    const end = Math.min(buf.length, s.rawPointer + s.rawSize);
    ranges.push([s.rawPointer, end]);
    sum += end - s.rawPointer;
  }
  if (buf.length > sum) {
    const extra = buf.length - pe.certTableSize - sum;
    if (extra > 0) ranges.push([sum, sum + extra]);
  }
  const page = headerRanges(pe, pe.sizeOfHeaders);
  return {
    sha1: hashRanges(buf, "sha1", ranges),
    sha256: hashRanges(buf, "sha256", ranges),
    pageSha1: hashRanges(buf, "sha1", page),
    pageSha256: hashRanges(buf, "sha256", page),
  };
}

export function flatHashes(buf: Buffer): { sha1: string; sha256: string } {
  return {
    sha1: crypto.createHash("sha1").update(buf).digest("hex").toUpperCase(),
    sha256: crypto.createHash("sha256").update(buf).digest("hex").toUpperCase(),
  };
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

const SIG_ALG_TO_HASH: Record<string, TbsHashAlgorithm> = {
  "1.2.840.113549.1.1.4": "MD5",
  "1.2.840.113549.1.1.5": "SHA1",
  "1.2.840.113549.1.1.11": "SHA256",
  "1.2.840.113549.1.1.12": "SHA384",
  "1.2.840.113549.1.1.13": "SHA512",
  "1.2.840.113549.1.1.10": "SHA256", // RSASSA-PSS — parameters carry the hash; default SHA256
  "1.2.840.10045.4.1": "SHA1",
  "1.2.840.10045.4.3.2": "SHA256",
  "1.2.840.10045.4.3.3": "SHA384",
  "1.2.840.10045.4.3.4": "SHA512",
  "1.3.14.3.2.29": "SHA1",
};

const DIGEST_OID_NAMES: Record<string, string> = {
  "1.2.840.113549.2.5": "MD5",
  "1.3.14.3.2.26": "SHA1",
  "2.16.840.1.101.3.4.2.1": "SHA256",
  "2.16.840.1.101.3.4.2.2": "SHA384",
  "2.16.840.1.101.3.4.2.3": "SHA512",
};

export interface ParsedCert extends InspectedCertificate {
  /** Raw DER of the whole certificate */
  der: Buffer;
  /** DER bytes of the issuer Name (for SignerInfo matching) */
  issuerDer: Buffer;
  /** DER bytes of the subject Name */
  subjectDer: Buffer;
}

function cnOf(dn: string): string {
  // Node renders DN as newline-separated "CN=..." lines
  const line = dn.split("\n").find((l) => l.startsWith("CN="));
  return line ? line.slice(3).trim() : dn.split("\n")[0]?.trim() ?? dn;
}

function dnOneLine(dn: string): string {
  return dn.split("\n").join(", ");
}

/** Parse an X.509 certificate DER blob into the inspection model. */
export function parseCertificate(der: Buffer): ParsedCert | null {
  let x: crypto.X509Certificate;
  try {
    x = new crypto.X509Certificate(der);
  } catch {
    return null;
  }
  try {
    const outer = readNode(der, 0);
    const [tbs, sigAlg] = children(der, outer);
    const tbsBytes = raw(der, tbs);
    const sigOid = oidOf(der, children(der, sigAlg)[0]);
    const alg = SIG_ALG_TO_HASH[sigOid] ?? "SHA256";

    // TBS children: [0] version?, serialNumber, signature, issuer, validity, subject, spki, ...
    const tbsKids = children(der, tbs);
    let i = 0;
    if (isContext(tbsKids[0], 0)) i = 1;
    const serial = tbsKids[i];
    const issuer = tbsKids[i + 2];
    const validity = tbsKids[i + 3];
    const subject = tbsKids[i + 4];
    const [nb, na] = children(der, validity);

    const nodeAlg = alg.toLowerCase();
    const tbsHash = crypto.createHash(nodeAlg).update(tbsBytes).digest("hex").toUpperCase();
    const issuerDer = raw(der, issuer);
    const subjectDer = raw(der, subject);

    return {
      subjectCN: cnOf(x.subject),
      subjectDN: dnOneLine(x.subject),
      issuerCN: cnOf(x.issuer),
      issuerDN: dnOneLine(x.issuer),
      serialNumber: integerHex(der, serial),
      notBefore: decodeTime(der, nb) ?? x.validFrom,
      notAfter: decodeTime(der, na) ?? x.validTo,
      tbsHash,
      tbsHashAlgorithm: alg,
      thumbprint: crypto.createHash("sha1").update(der).digest("hex").toUpperCase(),
      isCa: x.ca,
      isSelfSigned: issuerDer.equals(subjectDer),
      ekus: (x.keyUsage ?? []) as string[],
      der,
      issuerDer,
      subjectDer,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// PKCS#7 / SignedData
// ---------------------------------------------------------------------------

const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4";
const OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1";
const OID_COUNTERSIGNATURE = "1.2.840.113549.1.9.6";
const OID_RFC3161_TIMESTAMP = "1.3.6.1.4.1.311.3.3.1";

interface SignedDataParts {
  certs: ParsedCert[];
  signerIssuerDer?: Buffer;
  signerSerialHex?: string;
  digestAlgorithm?: string;
  embeddedDigest?: string;
  hasTimestamp: boolean;
  nested: Buffer[];
}

function parseSignedData(p7: Buffer): SignedDataParts | null {
  let ci: DerNode;
  try {
    ci = readNode(p7, 0);
  } catch {
    return null;
  }
  const parts: SignedDataParts = { certs: [], hasTimestamp: false, nested: [] };
  try {
    const [ctOid, ctContent] = children(p7, ci);
    if (oidOf(p7, ctOid) !== OID_SIGNED_DATA) return null;
    const signedData = children(p7, ctContent)[0];
    const sdKids = children(p7, signedData);
    // version, digestAlgorithms, contentInfo, [0] certs?, [1] crls?, signerInfos
    const contentInfo = sdKids[2];
    const [innerOid, innerContent] = children(p7, contentInfo);
    if (oidOf(p7, innerOid) === OID_SPC_INDIRECT_DATA) {
      const spc = children(p7, innerContent)[0];
      const [, digestInfo] = children(p7, spc);
      const [dAlg, dVal] = children(p7, digestInfo);
      const dOid = oidOf(p7, children(p7, dAlg)[0]);
      parts.digestAlgorithm = DIGEST_OID_NAMES[dOid] ?? dOid;
      parts.embeddedDigest = content(p7, dVal).toString("hex").toUpperCase();
    }
    for (const k of sdKids.slice(3)) {
      if (isContext(k, 0)) {
        for (const c of children(p7, k)) {
          if (c.tag !== TAG.SEQUENCE) continue;
          const cert = parseCertificate(Buffer.from(raw(p7, c)));
          if (cert) parts.certs.push(cert);
        }
      } else if (k.tag === TAG.SET) {
        // signerInfos
        const signerInfo = children(p7, k)[0];
        if (!signerInfo) continue;
        const siKids = children(p7, signerInfo);
        const ias = siKids[1];
        const [issuerName, serial] = children(p7, ias);
        parts.signerIssuerDer = Buffer.from(raw(p7, issuerName));
        parts.signerSerialHex = integerHex(p7, serial);
        // unauthenticated attributes [1]
        const unauth = siKids.find((n) => isContext(n, 1));
        if (unauth) {
          for (const attr of children(p7, unauth)) {
            const [aOid, aVals] = children(p7, attr);
            const oid = oidOf(p7, aOid);
            if (oid === OID_NESTED_SIGNATURE) {
              for (const v of children(p7, aVals)) parts.nested.push(Buffer.from(raw(p7, v)));
            } else if (oid === OID_COUNTERSIGNATURE || oid === OID_RFC3161_TIMESTAMP) {
              parts.hasTimestamp = true;
            }
          }
        }
      }
    }
  } catch {
    // Partial parse — fall back to scanning for certificates anywhere in the blob
    if (parts.certs.length === 0) {
      for (const n of findAll(p7, ci, (x) => x.tag === TAG.SEQUENCE)) {
        const cert = parseCertificate(Buffer.from(raw(p7, n)));
        if (cert && !parts.certs.some((c) => c.thumbprint === cert.thumbprint)) parts.certs.push(cert);
      }
    }
  }
  return parts;
}

/**
 * Build the chain from the signer leaf upward using issuer→subject matching.
 * Stops at a self-signed certificate or when no issuer is embedded.
 */
function buildChain(leaf: ParsedCert, pool: ParsedCert[]): ParsedCert[] {
  const chain: ParsedCert[] = [leaf];
  const seen = new Set<string>([leaf.thumbprint]);
  let current = leaf;
  for (let guard = 0; guard < 16; guard++) {
    if (current.isSelfSigned) break;
    const issuer = pool.find((c) => !seen.has(c.thumbprint) && c.subjectDer.equals(current.issuerDer));
    if (!issuer) break;
    chain.push(issuer);
    seen.add(issuer.thumbprint);
    current = issuer;
  }
  return chain;
}

/** Root CN → Wellknown ID, for chains that terminate at a Microsoft root. */
const WELLKNOWN_ROOT_BY_CN: Record<string, string> = {
  "microsoft root authority": "04",
  "microsoft root certificate authority": "05",
  "microsoft root certificate authority 2010": "06",
  "microsoft root certificate authority 2011": "07",
  "microsoft code verification root": "08",
  "microsoft testing root certificate authority 2010": "0A",
  "microsoft digital media authority 2005": "0C",
  "microsoft development root certificate authority 2014": "0E",
  "microsoft identity verification root certificate authority 2020": "16",
};

export function wellknownRootIdFor(chain: InspectedCertificate[]): string | undefined {
  const top = chain[chain.length - 1];
  if (!top) return undefined;
  const rootCn = (top.isSelfSigned ? top.subjectCN : top.issuerCN).toLowerCase();
  return WELLKNOWN_ROOT_BY_CN[rootCn];
}

function stripDer(c: ParsedCert): InspectedCertificate {
  const { der: _d, issuerDer: _i, subjectDer: _s, ...rest } = c;
  return rest;
}

/**
 * Extract every Authenticode signature (primary + nested) from the PE's
 * certificate table and resolve each one's certificate chain.
 */
export function extractSignatures(
  buf: Buffer,
  pe: PeInfo,
  computed: AuthenticodeHashes
): InspectedSignature[] {
  const out: InspectedSignature[] = [];
  if (!pe.certTableOffset || !pe.certTableSize) return out;
  const tableEnd = Math.min(buf.length, pe.certTableOffset + pe.certTableSize);
  let p = pe.certTableOffset;
  const blobs: Buffer[] = [];
  // WIN_CERTIFICATE entries: dwLength, wRevision, wCertificateType, bCertificate[]; 8-byte aligned
  while (p + 8 <= tableEnd) {
    const len = buf.readUInt32LE(p);
    const type = buf.readUInt16LE(p + 6);
    if (len < 8 || p + len > tableEnd + 8) break;
    if (type === 0x0002) blobs.push(buf.subarray(p + 8, Math.min(p + len, tableEnd)));
    p += (len + 7) & ~7;
  }

  const queue: Buffer[] = [...blobs];
  let index = 0;
  while (queue.length && index < 8) {
    const blob = queue.shift()!;
    const parts = parseSignedData(blob);
    if (!parts) continue;
    for (const n of parts.nested) queue.push(n);
    if (parts.certs.length === 0) continue;

    // Leaf = the certificate the SignerInfo names; fall back to a non-CA cert
    let leaf = parts.certs.find(
      (c) => parts.signerIssuerDer && c.issuerDer.equals(parts.signerIssuerDer) && c.serialNumber === parts.signerSerialHex
    );
    if (!leaf) {
      leaf = parts.certs.find((c) => !c.isCa && !c.ekus.includes("1.3.6.1.5.5.7.3.8")) ?? parts.certs[0];
    }
    const chain = buildChain(leaf, parts.certs).map(stripDer);
    const pca = [...chain].reverse().find((c) => !c.isSelfSigned) ?? chain[0];
    const embedded = parts.embeddedDigest;
    const digestMatches = embedded
      ? embedded === (parts.digestAlgorithm === "SHA1" ? computed.sha1 : parts.digestAlgorithm === "SHA256" ? computed.sha256 : embedded)
      : undefined;

    out.push({
      index: index++,
      digestAlgorithm: parts.digestAlgorithm,
      embeddedDigest: embedded,
      digestMatches,
      leaf: stripDer(leaf),
      chain,
      pca,
      wellknownRootId: wellknownRootIdFor(chain),
      hasTimestamp: parts.hasTimestamp,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Standalone certificate files (.cer / .crt / .pem / .p7b)
// ---------------------------------------------------------------------------

export function parseCertificateFile(buf: Buffer): ParsedCert[] {
  const text = buf.toString("latin1");
  if (text.includes("-----BEGIN CERTIFICATE-----")) {
    const out: ParsedCert[] = [];
    const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      const der = Buffer.from(m[1].replace(/\s+/g, ""), "base64");
      const c = parseCertificate(der);
      if (c) out.push(c);
    }
    return out;
  }
  const single = parseCertificate(buf);
  if (single) return [single];
  // PKCS#7 bundle
  const sd = parseSignedData(buf);
  return sd?.certs ?? [];
}
