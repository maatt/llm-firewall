import type { AuditEntry, AuditLogger } from "../types.js";

export interface WebhookLoggerOptions {
  /** The URL to POST audit entries to as JSON. */
  url: string;
  /**
   * Additional headers to include — use this for auth tokens, API keys, etc.
   * Content-Type: application/json is always set automatically.
   */
  headers?: Record<string, string>;
  /**
   * Request timeout in milliseconds. Defaults to 5000.
   * The firewall will not wait beyond this — the request is abandoned on timeout.
   */
  timeoutMs?: number;
  /**
   * Number of retry attempts on network failure or 5xx response. Defaults to 2.
   * Retries use exponential backoff starting at 200ms.
   */
  retries?: number;
  /**
   * Fields to omit from the posted payload.
   * Useful for privacy — e.g. omit "prompt" to avoid sending user input off-device.
   */
  omit?: Array<keyof AuditEntry>;
}

/**
 * POSTs audit entries as JSON to an HTTP endpoint.
 * Compatible with Datadog, Splunk HEC, Loki push API, custom webhooks, etc.
 *
 * @example
 * const firewall = new Firewall().withAuditLogger(
 *   new WebhookLogger({
 *     url: "https://http-intake.logs.datadoghq.com/api/v2/logs",
 *     headers: { "DD-API-KEY": process.env.DD_API_KEY! },
 *   })
 * );
 *
 * @example
 * // Splunk HEC
 * new WebhookLogger({
 *   url: "https://splunk.example.com:8088/services/collector/event",
 *   headers: { Authorization: `Splunk ${process.env.SPLUNK_HEC_TOKEN}` },
 * });
 *
 * @example
 * // Generic webhook with auth
 * new WebhookLogger({
 *   url: "https://my-api.example.com/audit",
 *   headers: { Authorization: `Bearer ${process.env.AUDIT_TOKEN}` },
 *   omit: ["prompt"],  // don't send raw prompts off-device
 * });
 */
export class WebhookLogger implements AuditLogger {
  private url: string;
  private headers: Record<string, string>;
  private timeoutMs: number;
  private retries: number;
  private omit: Set<keyof AuditEntry>;

  constructor(options: WebhookLoggerOptions) {
    this.url = options.url;
    this.headers = { "Content-Type": "application/json", ...options.headers };
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.retries = options.retries ?? 2;
    this.omit = new Set(options.omit ?? []);
  }

  async log(entry: AuditEntry): Promise<void> {
    const record: Partial<AuditEntry> = { ...entry };
    for (const key of this.omit) {
      delete record[key];
    }

    const body = JSON.stringify(record);
    let attempt = 0;
    let lastError: unknown;

    while (attempt <= this.retries) {
      if (attempt > 0) {
        await sleep(200 * 2 ** (attempt - 1)); // 200ms, 400ms, 800ms…
      }

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

        const res = await fetch(this.url, {
          method: "POST",
          headers: this.headers,
          body,
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (res.ok || (res.status >= 400 && res.status < 500)) {
          // 4xx = client error, don't retry (bad config or auth)
          return;
        }

        // 5xx — retry
        lastError = new Error(`Webhook responded with ${res.status}`);
      } catch (err) {
        lastError = err;
      }

      attempt++;
    }

    // All retries exhausted — silently drop (audit failure must not affect firewall)
    if (process.env.LLM_FIREWALL_DEBUG) {
      process.stderr.write(`[llm-firewall] WebhookLogger failed after ${attempt} attempts: ${lastError}\n`);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
