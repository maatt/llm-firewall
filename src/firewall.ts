import { detectInjection, detectPII, detectHarmful } from "./detectors/index.js";
import type { AuditEntry, AuditLogger } from "./audit/types.js";
import type { JudgeProvider } from "./judge/types.js";
import { compileRules, detectPolicy } from "./policy/detector.js";
import type { PolicyRule, CompiledPolicyRule } from "./policy/types.js";
import type { DetectionResult, DetectorName, FirewallConfig, FirewallResult, Severity } from "./types.js";

const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];

const DEFAULT_BLOCK_ON: Severity[] = ["high", "critical"];

export function analyze(
  prompt: string,
  config: FirewallConfig = {},
  policyRules: CompiledPolicyRule[] = []
): FirewallResult {
  const enabledDetectors = config.detectors ?? ["injection", "pii", "harmful"];
  const blockOnSeverity = config.blockOnSeverity ?? DEFAULT_BLOCK_ON;

  const detections = [
    enabledDetectors.includes("injection") ? detectInjection(prompt) : null,
    enabledDetectors.includes("pii") ? detectPII(prompt) : null,
    enabledDetectors.includes("harmful") ? detectHarmful(prompt) : null,
    policyRules.length > 0 ? detectPolicy(prompt, policyRules) : null,
  ].filter((d) => d !== null);

  const triggered = detections.filter((d) => d.triggered);
  const shouldBlock = triggered.some((d) => isBlocked(d.severity, blockOnSeverity));

  return { allowed: !shouldBlock, detections, prompt };
}

export async function analyzeAsync(
  prompt: string,
  judge: JudgeProvider,
  config: FirewallConfig = {},
  policyRules: CompiledPolicyRule[] = []
): Promise<FirewallResult> {
  const blockOnSeverity = config.blockOnSeverity ?? DEFAULT_BLOCK_ON;

  const ruleResult = analyze(prompt, config, policyRules);

  // Skip the (expensive) judge call if rules already block
  if (!ruleResult.allowed) return ruleResult;

  const verdict = await judge.evaluate(prompt);

  const judgeDetection: DetectionResult = {
    detector: "judge",
    triggered: !verdict.safe,
    severity: verdict.severity === "none" ? undefined : verdict.severity,
    reason: verdict.safe ? undefined : "LLM judge flagged prompt as unsafe",
    categories: verdict.categories.length > 0 ? verdict.categories : undefined,
    judgeReasoning: verdict.reasoning,
  };

  const allDetections = [...ruleResult.detections, judgeDetection];
  const shouldBlock = allDetections
    .filter((d) => d.triggered)
    .some((d) => isBlocked(d.severity, blockOnSeverity));

  return { allowed: !shouldBlock, detections: allDetections, prompt };
}

function isBlocked(severity: Severity | undefined, blockOn: Severity[]): boolean {
  if (!severity) return false;
  return blockOn.some((threshold) => SEVERITY_ORDER.indexOf(severity) >= SEVERITY_ORDER.indexOf(threshold));
}

/** Called from sync analyze() — invokes all loggers immediately, floats async ones. */
function fireAuditLoggers(loggers: AuditLogger[], entry: AuditEntry): void {
  for (const logger of loggers) {
    try {
      const result = logger.log(entry);
      if (result instanceof Promise) {
        result.catch((err) => {
          if (process.env.LLM_FIREWALL_DEBUG) {
            process.stderr.write(`[llm-firewall] AuditLogger async error: ${err}\n`);
          }
        });
      }
    } catch (err) {
      if (process.env.LLM_FIREWALL_DEBUG) {
        process.stderr.write(`[llm-firewall] AuditLogger threw: ${err}\n`);
      }
    }
  }
}

/** Called from async analyzeAsync() — awaits each logger in sequence. */
async function runAuditLoggers(loggers: AuditLogger[], entry: AuditEntry): Promise<void> {
  for (const logger of loggers) {
    try {
      await logger.log(entry);
    } catch (err) {
      if (process.env.LLM_FIREWALL_DEBUG) {
        process.stderr.write(`[llm-firewall] AuditLogger threw: ${err}\n`);
      }
    }
  }
}

/**
 * Fluent builder for configuring and reusing a firewall instance.
 *
 * @example
 * // Sync — rule-based only
 * const firewall = new Firewall()
 *   .use("injection", "harmful")
 *   .blockOn("high", "critical")
 *   .withAuditLogger(new ConsoleLogger());
 *
 * firewall.guard(prompt);
 *
 * @example
 * // Async — rules + LLM judge + file audit log
 * const firewall = new Firewall()
 *   .withJudge(new AnthropicJudge(new Anthropic()))
 *   .withAuditLogger(new FileLogger({ path: "./logs/firewall.jsonl" }))
 *   .withAuditLogger(new WebhookLogger({ url: "https://my-siem.example.com/ingest" }));
 *
 * await firewall.guardAsync(prompt);
 */
export class Firewall {
  private config: FirewallConfig = {};
  private judgeProvider?: JudgeProvider;
  private auditLoggers: AuditLogger[] = [];
  private compiledPolicy: CompiledPolicyRule[] = [];

  /** Select which detectors to run (default: all). Does not affect the judge. */
  use(...detectors: DetectorName[]): this {
    this.config.detectors = detectors;
    return this;
  }

  /** Set which severity levels cause a block (default: high, critical). */
  blockOn(...severities: Severity[]): this {
    this.config.blockOnSeverity = severities;
    return this;
  }

  /**
   * Add custom policy rules. Can be called multiple times — rules accumulate.
   *
   * @example
   * const firewall = new Firewall().withPolicy([
   *   { name: "no-competitor", pattern: /acme-corp/i, severity: "medium", reason: "Competitor mention" },
   *   { name: "no-internal-codename", pattern: "project-atlas", severity: "high" },
   * ]);
   */
  withPolicy(rules: PolicyRule[]): this {
    this.compiledPolicy.push(...compileRules(rules));
    return this;
  }

  /** Attach an LLM judge. Required to use analyzeAsync / guardAsync. */
  withJudge(provider: JudgeProvider): this {
    this.judgeProvider = provider;
    return this;
  }

  /**
   * Attach an audit logger. Can be called multiple times to add multiple loggers.
   * All loggers receive every analysis result — both allowed and blocked.
   */
  withAuditLogger(logger: AuditLogger, metadata?: Record<string, unknown>): this {
    this.auditLoggers.push(metadata ? new MetadataLogger(logger, metadata) : logger);
    return this;
  }

  /** Synchronous analysis — rule-based detectors only. */
  analyze(prompt: string, metadata?: Record<string, unknown>): FirewallResult {
    const start = Date.now();
    const result = analyze(prompt, this.config, this.compiledPolicy);

    if (this.auditLoggers.length > 0) {
      fireAuditLoggers(this.auditLoggers, buildEntry(result, Date.now() - start, metadata));
    }

    return result;
  }

  /**
   * Asynchronous analysis — rule-based detectors + LLM judge.
   * The judge is skipped if rules already block the prompt.
   * Requires withJudge() to have been called.
   */
  async analyzeAsync(prompt: string, metadata?: Record<string, unknown>): Promise<FirewallResult> {
    if (!this.judgeProvider) {
      throw new Error("No judge provider configured. Call .withJudge() first.");
    }

    const start = Date.now();
    const result = await analyzeAsync(prompt, this.judgeProvider, this.config, this.compiledPolicy);

    if (this.auditLoggers.length > 0) {
      const entry = buildEntry(result, Date.now() - start, metadata);
      await runAuditLoggers(this.auditLoggers, entry);
    }

    return result;
  }

  /** Synchronous guard — throws FirewallBlockedError if blocked (rule-based only). */
  guard(prompt: string, metadata?: Record<string, unknown>): void {
    const result = this.analyze(prompt, metadata);
    if (!result.allowed) throw new FirewallBlockedError(buildMessage(result), result);
  }

  /**
   * Async guard — throws FirewallBlockedError if blocked (rules + judge).
   * Requires withJudge() to have been called.
   */
  async guardAsync(prompt: string, metadata?: Record<string, unknown>): Promise<void> {
    const result = await this.analyzeAsync(prompt, metadata);
    if (!result.allowed) throw new FirewallBlockedError(buildMessage(result), result);
  }
}

function buildEntry(
  result: FirewallResult,
  durationMs: number,
  metadata?: Record<string, unknown>
): AuditEntry {
  return {
    timestamp: new Date().toISOString(),
    allowed: result.allowed,
    prompt: result.prompt,
    detections: result.detections,
    durationMs,
    ...(metadata ? { metadata } : {}),
  };
}

function buildMessage(result: FirewallResult): string {
  const reasons = result.detections
    .filter((d) => d.triggered)
    .map((d) => d.reason ?? d.detector)
    .join(", ");
  return `Prompt blocked: ${reasons}`;
}

/** Wraps a logger to always merge in static metadata. */
class MetadataLogger implements AuditLogger {
  constructor(
    private inner: AuditLogger,
    private staticMetadata: Record<string, unknown>
  ) {}

  log(entry: AuditEntry): void | Promise<void> {
    return this.inner.log({
      ...entry,
      metadata: { ...this.staticMetadata, ...entry.metadata },
    });
  }
}

export class FirewallBlockedError extends Error {
  constructor(
    message: string,
    public readonly result: FirewallResult
  ) {
    super(message);
    this.name = "FirewallBlockedError";
  }
}
