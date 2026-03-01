/**
 * Security Configuration
 *
 * Loaded from ~/.appcontrol-studio/security.json at startup.
 * Falls back to safe defaults if the file is absent.
 * Tokens are stored as SHA-256 hex hashes — never in plaintext.
 *
 * To generate a token hash:
 *   node -e "const{createHash}=require('crypto');console.log(createHash('sha256').update('YOUR_TOKEN').digest('hex'))"
 */

import { readFile, writeFile, mkdir } from "fs/promises";
import { join } from "path";
import { homedir } from "os";
import type { RbacRole } from "@appcontrol/shared";

// ---------------------------------------------------------------------------
// Config types (server-only — contain token hashes)
// ---------------------------------------------------------------------------

export interface RbacTokenEntry {
  /** SHA-256 hex hash of the raw token string */
  tokenHash: string;
  role: RbacRole;
  /** Human-readable label for audit log display */
  label: string;
}

export interface RbacConfig {
  /** When false, all requests are granted admin-equivalent access */
  enabled: boolean;
  tokens: RbacTokenEntry[];
}

export interface ValidationConfig {
  /** Maximum XML document size in bytes (default: 20 MB) */
  maxXmlSizeBytes: number;
  /** Maximum number of XML elements (counted by '<' occurrences) */
  maxXmlElements: number;
  /** Maximum XML nesting depth */
  maxXmlNestingDepth: number;
  /** Maximum length of any single XML attribute value */
  maxXmlAttributeLength: number;
}

export interface AuditConfig {
  enabled: boolean;
  /** Directory for JSONL audit log files */
  logDir: string;
  /** Rotate active log file when it reaches this size (bytes) */
  maxFileSizeBytes: number;
  /** Maximum number of rotated files to keep */
  maxFiles: number;
  /** In-memory ring buffer size */
  maxInMemory: number;
}

export interface MemoryConfig {
  /**
   * When true, intermediate processing buffers are explicitly zeroed after use.
   * Policy content is never written to disk regardless of this setting.
   */
  aggressiveClearingEnabled: boolean;
}

export interface SecurityConfig {
  rbac: RbacConfig;
  audit: AuditConfig;
  validation: ValidationConfig;
  memory: MemoryConfig;
}

// ---------------------------------------------------------------------------
// Defaults — safe, functional, no RBAC required for local workstation use
// ---------------------------------------------------------------------------

const CONFIG_DIR = join(homedir(), ".appcontrol-studio");
const CONFIG_FILE = join(CONFIG_DIR, "security.json");

export const DEFAULT_CONFIG: SecurityConfig = {
  rbac: {
    enabled: false,
    tokens: [],
  },
  audit: {
    enabled: true,
    logDir: join(CONFIG_DIR, "audit"),
    maxFileSizeBytes: 10 * 1024 * 1024, // 10 MB per file
    maxFiles: 5,
    maxInMemory: 500,
  },
  validation: {
    maxXmlSizeBytes: 20 * 1024 * 1024, // 20 MB
    maxXmlElements: 100_000,
    maxXmlNestingDepth: 50,
    maxXmlAttributeLength: 8_192,
  },
  memory: {
    aggressiveClearingEnabled: false,
  },
};

// ---------------------------------------------------------------------------
// Load / save
// ---------------------------------------------------------------------------

function deepMerge<T extends object>(base: T, override: Partial<T>): T {
  const result = { ...base };
  for (const key of Object.keys(override) as Array<keyof T>) {
    const val = override[key];
    if (val === undefined || val === null) continue;
    if (
      typeof val === "object" &&
      !Array.isArray(val) &&
      typeof base[key] === "object" &&
      !Array.isArray(base[key])
    ) {
      result[key] = deepMerge(base[key] as object, val as object) as T[keyof T];
    } else {
      result[key] = val as T[keyof T];
    }
  }
  return result;
}

export async function loadSecurityConfig(): Promise<SecurityConfig> {
  try {
    const raw = await readFile(CONFIG_FILE, "utf8");
    const parsed = JSON.parse(raw) as Partial<SecurityConfig>;
    return deepMerge(DEFAULT_CONFIG, parsed);
  } catch {
    // File absent or malformed — use defaults
    return { ...DEFAULT_CONFIG };
  }
}

export async function saveSecurityConfig(config: SecurityConfig): Promise<void> {
  await mkdir(CONFIG_DIR, { recursive: true });
  await writeFile(CONFIG_FILE, JSON.stringify(config, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
}

export { CONFIG_DIR };
