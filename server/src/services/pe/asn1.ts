/**
 * Minimal DER (ASN.1) reader.
 *
 * Only what is needed to walk PKCS#7 SignedData / SpcIndirectDataContent and
 * X.509 TBSCertificate structures. No BER indefinite lengths (Authenticode
 * blobs are DER) and no value decoding beyond OID / INTEGER / OCTET STRING.
 */

export interface DerNode {
  /** Full tag byte (class + constructed bit + number) */
  tag: number;
  /** Tag number without class/constructed bits */
  tagNumber: number;
  constructed: boolean;
  /** Class: 0 universal, 1 application, 2 context-specific, 3 private */
  tagClass: number;
  /** Offset of the tag byte in the source buffer */
  start: number;
  /** Offset of the first content byte */
  contentStart: number;
  /** Offset one past the last content byte */
  end: number;
  /** Content length in bytes */
  length: number;
}

export const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  PRINTABLE_STRING: 0x13,
  IA5_STRING: 0x16,
  BMP_STRING: 0x1e,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

/** Read one TLV at `offset`. Throws on truncated / malformed input. */
export function readNode(buf: Buffer, offset: number): DerNode {
  if (offset + 2 > buf.length) throw new Error(`DER: truncated at ${offset}`);
  const tag = buf[offset];
  const tagClass = tag >> 6;
  const constructed = (tag & 0x20) !== 0;
  let tagNumber = tag & 0x1f;
  let p = offset + 1;
  if (tagNumber === 0x1f) {
    // High tag number form
    tagNumber = 0;
    let b: number;
    do {
      b = buf[p++];
      tagNumber = (tagNumber << 7) | (b & 0x7f);
    } while (b & 0x80);
  }
  let len = buf[p++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error(`DER: unsupported length encoding at ${offset}`);
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[p++];
    len >>>= 0;
  }
  const contentStart = p;
  const end = contentStart + len;
  if (end > buf.length) throw new Error(`DER: element at ${offset} exceeds buffer`);
  return { tag, tagNumber, constructed, tagClass, start: offset, contentStart, end, length: len };
}

/** Read the direct children of a constructed node. */
export function children(buf: Buffer, node: DerNode): DerNode[] {
  const out: DerNode[] = [];
  let p = node.contentStart;
  while (p < node.end) {
    const c = readNode(buf, p);
    out.push(c);
    p = c.end;
  }
  return out;
}

export function content(buf: Buffer, node: DerNode): Buffer {
  return buf.subarray(node.contentStart, node.end);
}

export function raw(buf: Buffer, node: DerNode): Buffer {
  return buf.subarray(node.start, node.end);
}

/** Decode an OBJECT IDENTIFIER content to dotted notation. */
export function decodeOid(bytes: Buffer): string {
  const parts: number[] = [];
  let v = 0;
  for (let i = 0; i < bytes.length; i++) {
    v = v * 128 + (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) {
      if (parts.length === 0) {
        parts.push(Math.floor(v / 40), v % 40);
      } else {
        parts.push(v);
      }
      v = 0;
    }
  }
  return parts.join(".");
}

export function oidOf(buf: Buffer, node: DerNode): string {
  if (node.tag !== TAG.OID) throw new Error(`DER: expected OID at ${node.start}`);
  return decodeOid(content(buf, node));
}

/** Upper-case hex of an INTEGER's content, leading zero byte stripped. */
export function integerHex(buf: Buffer, node: DerNode): string {
  let c = content(buf, node);
  while (c.length > 1 && c[0] === 0x00) c = c.subarray(1);
  return c.toString("hex").toUpperCase();
}

/** Context-specific tag helpers */
export function isContext(node: DerNode, n: number): boolean {
  return node.tagClass === 2 && node.tagNumber === n;
}

/**
 * Walk the tree depth-first and return every node for which `pred` is true.
 * Used to locate nested SignedData (dual signatures) and certificate sets.
 */
export function findAll(buf: Buffer, root: DerNode, pred: (n: DerNode) => boolean, maxDepth = 24): DerNode[] {
  const out: DerNode[] = [];
  const walk = (n: DerNode, depth: number) => {
    if (pred(n)) out.push(n);
    if (!n.constructed || depth >= maxDepth) return;
    let kids: DerNode[];
    try { kids = children(buf, n); } catch { return; }
    for (const k of kids) walk(k, depth + 1);
  };
  walk(root, 0);
  return out;
}

/** Decode a DER time (UTCTime / GeneralizedTime) to ISO-8601. */
export function decodeTime(buf: Buffer, node: DerNode): string | undefined {
  const s = content(buf, node).toString("ascii");
  try {
    if (node.tag === TAG.UTC_TIME) {
      // YYMMDDHHMMSSZ
      const yy = parseInt(s.slice(0, 2), 10);
      const year = yy >= 50 ? 1900 + yy : 2000 + yy;
      return new Date(Date.UTC(year, +s.slice(2, 4) - 1, +s.slice(4, 6), +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12))).toISOString();
    }
    if (node.tag === TAG.GENERALIZED_TIME) {
      return new Date(Date.UTC(+s.slice(0, 4), +s.slice(4, 6) - 1, +s.slice(6, 8), +s.slice(8, 10), +s.slice(10, 12), +s.slice(12, 14))).toISOString();
    }
  } catch {
    /* fall through */
  }
  return undefined;
}
