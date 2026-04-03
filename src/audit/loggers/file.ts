import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { AuditEntry, AuditLogger } from "../types.js";

export interface FileLoggerOptions {
  /**
   * Absolute or relative path to the log file.
   * Each entry is written as a single JSON line (JSONL format).
   * The directory is created automatically if it doesn't exist.
   */
  path: string;
  /**
   * Fields to omit from the log entry.
   * Useful for privacy — e.g. omit "prompt" to avoid storing user input.
   */
  omit?: Array<keyof AuditEntry>;
}

/**
 * Appends audit entries to a local file in JSONL format (one JSON object per line).
 * Compatible with log aggregators like Loki, Splunk, Datadog, and jq.
 *
 * @example
 * const firewall = new Firewall()
 *   .withAuditLogger(new FileLogger({ path: "./logs/firewall.jsonl" }));
 *
 * @example
 * // Strip prompts for privacy
 * const firewall = new Firewall()
 *   .withAuditLogger(new FileLogger({ path: "./logs/firewall.jsonl", omit: ["prompt"] }));
 */
export class FileLogger implements AuditLogger {
  private path: string;
  private omit: Set<keyof AuditEntry>;
  private dirEnsured = false;

  constructor(options: FileLoggerOptions) {
    this.path = options.path;
    this.omit = new Set(options.omit ?? []);
  }

  async log(entry: AuditEntry): Promise<void> {
    if (!this.dirEnsured) {
      await mkdir(dirname(this.path), { recursive: true });
      this.dirEnsured = true;
    }

    const record: Partial<AuditEntry> = { ...entry };
    for (const key of this.omit) {
      delete record[key];
    }

    await appendFile(this.path, JSON.stringify(record) + "\n", "utf8");
  }
}
