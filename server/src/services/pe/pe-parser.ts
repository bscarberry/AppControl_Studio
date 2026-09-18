/**
 * Portable Executable (PE) header + version resource parser.
 *
 * Extracts exactly what Code Integrity rule generation needs:
 *   - header geometry (CheckSum offset, Certificate Table directory entry,
 *     SizeOfHeaders, section table) for Authenticode hashing
 *   - the security directory (embedded PKCS#7 signature blob)
 *   - machine / subsystem / characteristics (driver vs user-mode, DLL vs EXE)
 *   - VS_VERSIONINFO strings (OriginalFilename, InternalName, ProductName, …)
 *     and VS_FIXEDFILEINFO numeric file version (used for MinimumFileVersion)
 *
 * References: PE/COFF specification (Microsoft), VS_VERSIONINFO structure docs.
 */

import type { PeVersionInfo } from "@appcontrol/shared";

export interface PeSection {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawPointer: number;
  rawSize: number;
  characteristics: number;
}

export interface PeInfo {
  peOffset: number;
  isPe32Plus: boolean;
  machine: number;
  machineName: string;
  characteristics: number;
  subsystem: number;
  isDll: boolean;
  /** Subsystem == NATIVE (1) — kernel drivers and native images */
  isNativeSubsystem: boolean;
  sizeOfHeaders: number;
  /** File offset of the OptionalHeader.CheckSum field */
  checksumOffset: number;
  /** File offset of the Certificate Table data-directory entry (8 bytes) */
  certDirEntryOffset: number;
  /** Certificate table file offset (0 when unsigned) */
  certTableOffset: number;
  certTableSize: number;
  sections: PeSection[];
  /** Resource directory RVA/size (data directory index 2) */
  resourceRva: number;
  resourceSize: number;
  /** Import directory present — used to detect kernel imports heuristically */
  importRva: number;
}

const MACHINE_NAMES: Record<number, string> = {
  0x014c: "x86",
  0x8664: "x64",
  0x01c0: "ARM",
  0x01c4: "ARMNT",
  0xaa64: "ARM64",
  0x0200: "IA64",
};

/** Parse PE headers. Returns null when the buffer is not a PE image. */
export function parsePe(buf: Buffer): PeInfo | null {
  if (buf.length < 0x40 || buf[0] !== 0x4d || buf[1] !== 0x5a) return null; // "MZ"
  const peOffset = buf.readUInt32LE(0x3c);
  if (peOffset + 24 > buf.length || buf.readUInt32LE(peOffset) !== 0x00004550) return null; // "PE\0\0"

  const coff = peOffset + 4;
  const machine = buf.readUInt16LE(coff);
  const numSections = buf.readUInt16LE(coff + 2);
  const optSize = buf.readUInt16LE(coff + 16);
  const characteristics = buf.readUInt16LE(coff + 18);
  const opt = coff + 20;
  if (opt + optSize > buf.length || optSize < 96) return null;

  const magic = buf.readUInt16LE(opt);
  const isPe32Plus = magic === 0x20b;
  if (!isPe32Plus && magic !== 0x10b) return null;

  const sizeOfHeaders = buf.readUInt32LE(opt + 60);
  const checksumOffset = opt + 64;
  const subsystem = buf.readUInt16LE(opt + 68);
  const dataDirOffset = opt + (isPe32Plus ? 112 : 96);
  const numDirs = buf.readUInt32LE(opt + (isPe32Plus ? 108 : 92));

  const dir = (i: number): [number, number] => {
    if (i >= numDirs) return [0, 0];
    const o = dataDirOffset + i * 8;
    if (o + 8 > buf.length) return [0, 0];
    return [buf.readUInt32LE(o), buf.readUInt32LE(o + 4)];
  };

  const [importRva] = dir(1);
  const [resourceRva, resourceSize] = dir(2);
  const [certTableOffset, certTableSize] = dir(4); // file offset, not RVA
  const certDirEntryOffset = dataDirOffset + 4 * 8;

  const sections: PeSection[] = [];
  const secTable = opt + optSize;
  for (let i = 0; i < numSections; i++) {
    const s = secTable + i * 40;
    if (s + 40 > buf.length) break;
    sections.push({
      name: buf.toString("ascii", s, s + 8).replace(/\0.*$/, ""),
      virtualSize: buf.readUInt32LE(s + 8),
      virtualAddress: buf.readUInt32LE(s + 12),
      rawSize: buf.readUInt32LE(s + 16),
      rawPointer: buf.readUInt32LE(s + 20),
      characteristics: buf.readUInt32LE(s + 36),
    });
  }

  return {
    peOffset,
    isPe32Plus,
    machine,
    machineName: MACHINE_NAMES[machine] ?? `0x${machine.toString(16)}`,
    characteristics,
    subsystem,
    isDll: (characteristics & 0x2000) !== 0,
    isNativeSubsystem: subsystem === 1,
    sizeOfHeaders,
    checksumOffset,
    certDirEntryOffset,
    certTableOffset,
    certTableSize,
    sections,
    resourceRva,
    resourceSize,
    importRva,
  };
}

/** Translate an RVA to a file offset using the section table. */
export function rvaToOffset(pe: PeInfo, rva: number): number | null {
  for (const s of pe.sections) {
    const size = Math.max(s.virtualSize, s.rawSize);
    if (rva >= s.virtualAddress && rva < s.virtualAddress + size) {
      const off = rva - s.virtualAddress + s.rawPointer;
      return off;
    }
  }
  // RVA inside headers
  if (rva < pe.sizeOfHeaders) return rva;
  return null;
}

// ---------------------------------------------------------------------------
// Version resource
// ---------------------------------------------------------------------------

const RT_VERSION = 16;

interface ResourceDataEntry {
  dataRva: number;
  size: number;
}

/** Walk the resource directory tree to the first RT_VERSION data entry. */
function findVersionResource(buf: Buffer, pe: PeInfo): ResourceDataEntry | null {
  if (!pe.resourceRva) return null;
  const base = rvaToOffset(pe, pe.resourceRva);
  if (base === null) return null;

  const readDir = (dirOff: number): Array<{ id: number; isDir: boolean; offset: number }> => {
    if (dirOff + 16 > buf.length) return [];
    const named = buf.readUInt16LE(dirOff + 12);
    const ids = buf.readUInt16LE(dirOff + 14);
    const out: Array<{ id: number; isDir: boolean; offset: number }> = [];
    for (let i = 0; i < named + ids; i++) {
      const e = dirOff + 16 + i * 8;
      if (e + 8 > buf.length) break;
      const id = buf.readUInt32LE(e);
      const off = buf.readUInt32LE(e + 4);
      out.push({ id, isDir: (off & 0x80000000) !== 0, offset: off & 0x7fffffff });
    }
    return out;
  };

  const typeEntries = readDir(base);
  const ver = typeEntries.find((e) => (e.id & 0x80000000) === 0 && e.id === RT_VERSION && e.isDir);
  if (!ver) return null;
  const nameEntries = readDir(base + ver.offset);
  const nameEntry = nameEntries.find((e) => e.isDir) ?? nameEntries[0];
  if (!nameEntry) return null;
  let dataEntryOff: number;
  if (nameEntry.isDir) {
    const langEntries = readDir(base + nameEntry.offset);
    const lang = langEntries[0];
    if (!lang || lang.isDir) return null;
    dataEntryOff = base + lang.offset;
  } else {
    dataEntryOff = base + nameEntry.offset;
  }
  if (dataEntryOff + 16 > buf.length) return null;
  return { dataRva: buf.readUInt32LE(dataEntryOff), size: buf.readUInt32LE(dataEntryOff + 4) };
}

function align4(n: number): number {
  return (n + 3) & ~3;
}

function readUtf16z(buf: Buffer, off: number, limit: number): { text: string; next: number } {
  let p = off;
  const chars: number[] = [];
  while (p + 1 < limit) {
    const c = buf.readUInt16LE(p);
    p += 2;
    if (c === 0) break;
    chars.push(c);
  }
  return { text: String.fromCharCode(...chars), next: p };
}

/**
 * Parse VS_VERSIONINFO into version strings + fixed numeric version.
 * Tolerant of malformed resources: returns whatever could be read.
 */
export function parseVersionInfo(buf: Buffer, pe: PeInfo): PeVersionInfo | undefined {
  const entry = findVersionResource(buf, pe);
  if (!entry) return undefined;
  const start = rvaToOffset(pe, entry.dataRva);
  if (start === null || start + 6 > buf.length) return undefined;
  const end = Math.min(buf.length, start + entry.size);

  const info: PeVersionInfo = {};
  try {
    // VS_VERSIONINFO header
    const wLength = buf.readUInt16LE(start);
    const wValueLength = buf.readUInt16LE(start + 2);
    const blockEnd = Math.min(end, start + wLength);
    const key = readUtf16z(buf, start + 6, blockEnd); // "VS_VERSION_INFO"
    let p = align4(key.next);
    if (wValueLength >= 52 && p + 52 <= blockEnd && buf.readUInt32LE(p) === 0xfeef04bd) {
      const fvMS = buf.readUInt32LE(p + 8), fvLS = buf.readUInt32LE(p + 12);
      const pvMS = buf.readUInt32LE(p + 16), pvLS = buf.readUInt32LE(p + 20);
      info.fixedFileVersion = `${fvMS >>> 16}.${fvMS & 0xffff}.${fvLS >>> 16}.${fvLS & 0xffff}`;
      info.fixedProductVersion = `${pvMS >>> 16}.${pvMS & 0xffff}.${pvLS >>> 16}.${pvLS & 0xffff}`;
    }
    p = align4(p + wValueLength);

    // Children: StringFileInfo / VarFileInfo
    while (p + 6 <= blockEnd) {
      const cLen = buf.readUInt16LE(p);
      if (cLen === 0) break;
      const cEnd = Math.min(blockEnd, p + cLen);
      const cKey = readUtf16z(buf, p + 6, cEnd);
      if (cKey.text === "StringFileInfo") {
        let t = align4(cKey.next);
        while (t + 6 <= cEnd) {
          const tLen = buf.readUInt16LE(t);
          if (tLen === 0) break;
          const tEnd = Math.min(cEnd, t + tLen);
          const tKey = readUtf16z(buf, t + 6, tEnd); // e.g. "040904B0"
          let s = align4(tKey.next);
          while (s + 6 <= tEnd) {
            const sLen = buf.readUInt16LE(s);
            if (sLen === 0) break;
            const sValLen = buf.readUInt16LE(s + 2); // in words for strings
            const sEnd = Math.min(tEnd, s + sLen);
            const sKey = readUtf16z(buf, s + 6, sEnd);
            const vStart = align4(sKey.next);
            const vLimit = Math.min(sEnd, vStart + sValLen * 2);
            const val = sValLen > 0 ? readUtf16z(buf, vStart, vLimit).text.trim() : "";
            assignVersionString(info, sKey.text, val);
            s = align4(s + sLen);
          }
          t = align4(t + tLen);
        }
      }
      p = align4(p + cLen);
    }
  } catch {
    /* return partial info */
  }
  return Object.keys(info).length ? info : undefined;
}

function assignVersionString(info: PeVersionInfo, key: string, value: string): void {
  if (!value) return;
  switch (key) {
    case "OriginalFilename": info.originalFileName = value; break;
    case "InternalName": info.internalName = value; break;
    case "FileDescription": info.fileDescription = value; break;
    case "ProductName": info.productName = value; break;
    case "CompanyName": info.companyName = value; break;
    case "FileVersion": info.fileVersion = value; break;
    case "ProductVersion": info.productVersion = value; break;
  }
}

/**
 * Heuristic kernel-mode detection: NATIVE subsystem images that import from
 * ntoskrnl / hal / wdf are drivers. Plain NATIVE user apps (smss, autochk)
 * import ntdll instead.
 */
export function importsKernelModules(buf: Buffer, pe: PeInfo): boolean {
  if (!pe.importRva) return false;
  const base = rvaToOffset(pe, pe.importRva);
  if (base === null) return false;
  for (let i = 0; i < 64; i++) {
    const d = base + i * 20;
    if (d + 20 > buf.length) break;
    const nameRva = buf.readUInt32LE(d + 12);
    if (nameRva === 0) break;
    const nameOff = rvaToOffset(pe, nameRva);
    if (nameOff === null) continue;
    const end = buf.indexOf(0, nameOff);
    const name = buf.toString("ascii", nameOff, end > 0 ? Math.min(end, nameOff + 64) : nameOff + 64).toLowerCase();
    if (/^(ntoskrnl\.exe|hal\.dll|wdfldr\.sys|fltmgr\.sys|ndis\.sys|ksecdd\.sys|cng\.sys|storport\.sys|ataport\.sys|scsiport\.sys|tdi\.sys|netio\.sys|wmilib\.sys|ci\.dll|bootvid\.dll|clfs\.sys|pshed\.dll|kdcom\.dll)$/.test(name)) {
      return true;
    }
  }
  return false;
}
