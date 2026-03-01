/**
 * Audit Logger
 *
 * Append-only structured JSONL audit log.
 *
 * Design invariants:
 *  1. Policy content is NEVER written — only SHA-256 hashes and metadata.
 *  2. Write failures are logged to stderr but never propagate to callers.
 *  3. An in-memory ring buffer always holds the most recent N events
 *     regardless of whether disk logging is enabled.
 *  4. File rotation is size-based (not time-based) for simplicity.
 *  5. All log() calls return void synchronously; disk I/O is fire-and-forget.
 */

import { createHash, randomUUID } from "crypto";
import { appendFile, stat, rename, mkdir } from "fs/promises";
import { join } from "path";
import type { AuditEvent, AuditEventType, RbacRole } from "@appcontrol/shared";
import type { AuditConfig } from "../config/security-config.js";

// ---------------------------------------------------------------------------
// Input hashing helper (exported for use in route handlers)
// ---------------------------------------------------------------------------

/**
 * Return the SHA-256 hex hash of a string.
 * Use this to characterise XML inputs in audit events — never log the input itself.
 */
export function hashInput(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

export class AuditLogger {
  private readonly logDir: string;
  private readonly maxFileSizeBytes: number;
  private readonly maxFiles: number;
  private readonly maxInMemory: number;
  private readonly diskEnabled: boolean;
  private readonly activeFile: string;

  /** Circular in-memory ring buffer */
  private readonly buffer: AuditEvent[] = [];
  private totalLogged = 0;

  constructor(config: AuditConfig) {
    this.logDir = config.logDir;
    this.maxFileSizeBytes = config.maxFileSizeBytes;
    this.maxFiles = config.maxFiles;
    this.maxInMemory = config.maxInMemory;
    this.diskEnabled = config.enabled;
    this.activeFile = join(this.logDir, "audit.jsonl");
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /**
   * Record an audit event.
   * Synchronously updates the in-memory buffer; disk write is async fire-and-forget.
   */
  log(
    eventType: AuditEventType,
    details: Partial<Omit<AuditEvent, "id" | "timestamp" | "eventType">> & {
      role?: RbacRole;
      remoteAddr?: string;
    } = {}
  ): void {
    const event: AuditEvent = {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      eventType,
      succeeded: true,
      remoteAddr: "127.0.0.1",
      ...details,
    };

    // Update in-memory ring buffer
    if (this.buffer.length >= this.maxInMemory) {
      this.buffer.shift();
    }
    this.buffer.push(event);
    this.totalLogged++;

    // Async disk write — never awaited by caller
    if (this.diskEnabled) {
      void this.writeToDisk(event);
    }
  }

  /** Return the most recent `count` events from the in-memory buffer */
  recentEvents(count = 100): AuditEvent[] {
    return this.buffer.slice(-Math.min(count, this.buffer.length));
  }

  /** Total events logged since server start */
  get eventCount(): number {
    return this.totalLogged;
  }

  // ---------------------------------------------------------------------------
  // Disk I/O (all errors suppressed — audit failure must not crash the server)
  // ---------------------------------------------------------------------------

  private async writeToDisk(event: AuditEvent): Promise<void> {
    try {
      await mkdir(this.logDir, { recursive: true });
      await this.rotateIfNeeded();
      await appendFile(this.activeFile, JSON.stringify(event) + "\n", {
        encoding: "utf8",
        // Append-only flag — O_APPEND guarantees atomicity on POSIX
        flag: "a",
      });
    } catch (err) {
      console.error("[AuditLogger] Disk write failed:", (err as Error).message);
    }
  }

  private async rotateIfNeeded(): Promise<void> {
    try {
      const s = await stat(this.activeFile);
      if (s.size < this.maxFileSizeBytes) return;
    } catch {
      return; // File doesn't exist yet — nothing to rotate
    }

    try {
      // Shift existing rotated files: audit.4.jsonl → audit.5.jsonl, etc.
      for (let i = this.maxFiles - 1; i >= 1; i--) {
        const src = join(this.logDir, `audit.${i}.jsonl`);
        const dst = join(this.logDir, `audit.${i + 1}.jsonl`);
        try {
          await rename(src, dst);
        } catch {
          /* ok — file may not exist */
        }
      }
      await rename(this.activeFile, join(this.logDir, "audit.1.jsonl"));
    } catch (err) {
      console.error("[AuditLogger] Rotation failed:", (err as Error).message);
    }
  }
}

// ---------------------------------------------------------------------------
// Singleton instance (initialised in app.ts)
// ---------------------------------------------------------------------------

let _logger: AuditLogger | null = null;

export function initAuditLogger(config: AuditConfig): void {
  _logger = new AuditLogger(config);
}

/**
 * Access the singleton audit logger.
 * Returns a no-op stub before initAuditLogger() is called (safe for tests).
 */
export function getAuditLogger(): AuditLogger {
  if (!_logger) {
    // Stub during cold-start / tests — logs go only to memory with 0-length buffer
    _logger = new AuditLogger({
      enabled: false,
      logDir: "/tmp",
      maxFileSizeBytes: 0,
      maxFiles: 0,
      maxInMemory: 100,
    });
  }
  return _logger;
}
