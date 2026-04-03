import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Firewall } from "../src/firewall.js";
import { ConsoleLogger } from "../src/audit/loggers/console.js";
import { FileLogger } from "../src/audit/loggers/file.js";
import { WebhookLogger } from "../src/audit/loggers/webhook.js";
import type { AuditEntry, AuditLogger } from "../src/audit/types.js";
import { rm } from "node:fs/promises";
import { readFileSync, existsSync } from "node:fs";

// ─── ConsoleLogger ────────────────────────────────────────────────────────────

describe("ConsoleLogger", () => {
  it("writes JSON to stdout for allowed prompts", () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const logger = new ConsoleLogger({ format: "json" });
    const entry = makeEntry({ allowed: true });
    logger.log(entry);
    expect(write).toHaveBeenCalledWith(expect.stringContaining('"allowed":true'));
    write.mockRestore();
  });

  it("writes blocked prompts to stderr", () => {
    const write = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    const logger = new ConsoleLogger({ stderrOnBlock: true });
    logger.log(makeEntry({ allowed: false }));
    expect(write).toHaveBeenCalled();
    write.mockRestore();
  });

  it("formats pretty output", () => {
    const write = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const logger = new ConsoleLogger({ format: "pretty", stderrOnBlock: false });
    logger.log(makeEntry({ allowed: true }));
    expect(write).toHaveBeenCalledWith(expect.stringContaining("[llm-firewall]"));
    write.mockRestore();
  });
});

// ─── FileLogger ───────────────────────────────────────────────────────────────

const TMP_LOG = "/tmp/llm-firewall-test.jsonl";

describe("FileLogger", () => {
  afterEach(async () => {
    if (existsSync(TMP_LOG)) await rm(TMP_LOG);
  });

  it("creates the file and writes a JSONL entry", async () => {
    const logger = new FileLogger({ path: TMP_LOG });
    await logger.log(makeEntry({ allowed: true }));

    const lines = readFileSync(TMP_LOG, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.allowed).toBe(true);
    expect(parsed.timestamp).toBeDefined();
  });

  it("appends multiple entries", async () => {
    const logger = new FileLogger({ path: TMP_LOG });
    await logger.log(makeEntry({ allowed: true }));
    await logger.log(makeEntry({ allowed: false }));

    const lines = readFileSync(TMP_LOG, "utf8").trim().split("\n");
    expect(lines).toHaveLength(2);
  });

  it("omits specified fields", async () => {
    const logger = new FileLogger({ path: TMP_LOG, omit: ["prompt"] });
    await logger.log(makeEntry({ allowed: true }));

    const parsed = JSON.parse(readFileSync(TMP_LOG, "utf8").trim());
    expect(parsed.prompt).toBeUndefined();
    expect(parsed.allowed).toBeDefined();
  });
});

// ─── WebhookLogger ────────────────────────────────────────────────────────────

describe("WebhookLogger", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("POSTs entry as JSON", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: true, status: 200 });
    const logger = new WebhookLogger({ url: "https://example.com/audit", retries: 0 });
    await logger.log(makeEntry({ allowed: true }));

    expect(fetch).toHaveBeenCalledWith(
      "https://example.com/audit",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ "Content-Type": "application/json" }),
      })
    );
  });

  it("includes custom headers", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: true, status: 200 });
    const logger = new WebhookLogger({
      url: "https://example.com/audit",
      headers: { Authorization: "Bearer token123" },
      retries: 0,
    });
    await logger.log(makeEntry({ allowed: true }));

    const call = (fetch as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(call.headers["Authorization"]).toBe("Bearer token123");
  });

  it("omits specified fields from payload", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockResolvedValue({ ok: true, status: 200 });
    const logger = new WebhookLogger({ url: "https://example.com/audit", omit: ["prompt"], retries: 0 });
    await logger.log(makeEntry({ allowed: true }));

    const body = JSON.parse((fetch as ReturnType<typeof vi.fn>).mock.calls[0][1].body);
    expect(body.prompt).toBeUndefined();
  });

  it("retries on 5xx then succeeds", async () => {
    (fetch as ReturnType<typeof vi.fn>)
      .mockResolvedValueOnce({ ok: false, status: 503 })
      .mockResolvedValueOnce({ ok: true, status: 200 });

    const logger = new WebhookLogger({ url: "https://example.com/audit", retries: 2, timeoutMs: 1000 });
    await logger.log(makeEntry({ allowed: false }));

    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("does not throw after all retries exhausted", async () => {
    (fetch as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("network error"));
    const logger = new WebhookLogger({ url: "https://example.com/audit", retries: 1, timeoutMs: 100 });
    await expect(logger.log(makeEntry({ allowed: false }))).resolves.toBeUndefined();
  });
});

// ─── Firewall integration ─────────────────────────────────────────────────────

describe("Firewall audit integration", () => {
  it("calls logger after analyze()", () => {
    const logger: AuditLogger = { log: vi.fn() };
    const fw = new Firewall().withAuditLogger(logger);
    fw.analyze("hello world");
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({ allowed: true, prompt: "hello world" })
    );
  });

  it("passes metadata to logger", () => {
    const logger: AuditLogger = { log: vi.fn() };
    const fw = new Firewall().withAuditLogger(logger);
    fw.analyze("hello", { userId: "u_123" });
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({ metadata: { userId: "u_123" } })
    );
  });

  it("merges static metadata from withAuditLogger()", () => {
    const logger: AuditLogger = { log: vi.fn() };
    const fw = new Firewall().withAuditLogger(logger, { service: "chat-api" });
    fw.analyze("hello", { userId: "u_123" });
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({ metadata: { service: "chat-api", userId: "u_123" } })
    );
  });

  it("supports multiple loggers", () => {
    const a: AuditLogger = { log: vi.fn() };
    const b: AuditLogger = { log: vi.fn() };
    const fw = new Firewall().withAuditLogger(a).withAuditLogger(b);
    fw.analyze("hello");
    expect(a.log).toHaveBeenCalled();
    expect(b.log).toHaveBeenCalled();
  });

  it("does not throw if a logger throws", () => {
    const bad: AuditLogger = { log: vi.fn().mockImplementation(() => { throw new Error("oops"); }) };
    const fw = new Firewall().withAuditLogger(bad);
    expect(() => fw.analyze("hello")).not.toThrow();
  });

  it("logs durationMs", () => {
    const logger: AuditLogger = { log: vi.fn() };
    const fw = new Firewall().withAuditLogger(logger);
    fw.analyze("hello");
    const entry = (logger.log as ReturnType<typeof vi.fn>).mock.calls[0][0] as AuditEntry;
    expect(typeof entry.durationMs).toBe("number");
    expect(entry.durationMs).toBeGreaterThanOrEqual(0);
  });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    timestamp: new Date().toISOString(),
    allowed: true,
    prompt: "test prompt",
    detections: [],
    durationMs: 5,
    ...overrides,
  };
}
