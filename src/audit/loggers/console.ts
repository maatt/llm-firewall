import type { AuditEntry, AuditLogger } from "../types.js";

export interface ConsoleLoggerOptions {
  /**
   * "json"  — one JSON object per line (default, good for log aggregators)
   * "pretty" — human-readable formatted output
   */
  format?: "json" | "pretty";
  /** Write blocked prompts to stderr instead of stdout. Defaults to true. */
  stderrOnBlock?: boolean;
}

/**
 * Logs audit entries to stdout/stderr.
 *
 * @example
 * const firewall = new Firewall()
 *   .withAuditLogger(new ConsoleLogger({ format: "pretty" }));
 */
export class ConsoleLogger implements AuditLogger {
  private format: "json" | "pretty";
  private stderrOnBlock: boolean;

  constructor(options: ConsoleLoggerOptions = {}) {
    this.format = options.format ?? "json";
    this.stderrOnBlock = options.stderrOnBlock ?? true;
  }

  log(entry: AuditEntry): void {
    const output = this.format === "pretty" ? formatPretty(entry) : JSON.stringify(entry);
    const write = !entry.allowed && this.stderrOnBlock ? process.stderr : process.stdout;
    write.write(output + "\n");
  }
}

function formatPretty(entry: AuditEntry): string {
  const status = entry.allowed ? "ALLOWED" : "BLOCKED";
  const triggered = entry.detections.filter((d) => d.triggered);
  const lines = [
    `[llm-firewall] ${entry.timestamp} ${status} (${entry.durationMs}ms)`,
    `  prompt: ${entry.prompt.slice(0, 120)}${entry.prompt.length > 120 ? "…" : ""}`,
  ];

  if (triggered.length > 0) {
    for (const d of triggered) {
      const cats = d.categories?.join(", ");
      lines.push(`  ↳ ${d.detector} [${d.severity}]${cats ? ` — ${cats}` : ""}${d.reason ? `: ${d.reason}` : ""}`);
      if (d.judgeReasoning) lines.push(`    judge: ${d.judgeReasoning}`);
    }
  }

  if (entry.metadata && Object.keys(entry.metadata).length > 0) {
    lines.push(`  metadata: ${JSON.stringify(entry.metadata)}`);
  }

  return lines.join("\n");
}
