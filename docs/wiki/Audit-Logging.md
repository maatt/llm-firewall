# Audit Logging

Every analysis result — allowed or blocked — can be sent to one or more audit loggers. Loggers never affect firewall behaviour: errors are silently swallowed.

## Attaching loggers

```ts
import { Firewall, ConsoleLogger, FileLogger, WebhookLogger } from "llm-firewall";

const firewall = new Firewall()
  .withAuditLogger(new ConsoleLogger({ format: "pretty" }))
  .withAuditLogger(new FileLogger({ path: "./logs/firewall.jsonl" }))
  .withAuditLogger(new WebhookLogger({ url: "https://my-siem.example.com/ingest" }));
```

---

## ConsoleLogger

Writes each entry to stdout (or stderr for blocked prompts).

```ts
new ConsoleLogger({
  format: "json",       // "json" (default) or "pretty"
  stderrOnBlock: true,  // write blocked entries to stderr (default: true)
});
```

---

## FileLogger

Appends entries as JSONL (one JSON object per line). Compatible with Loki, Splunk, Datadog, and `jq`.

```ts
new FileLogger({
  path: "./logs/firewall.jsonl",
  omit: ["prompt"],   // optional — strip fields for privacy
});
```

---

## WebhookLogger

POSTs entries as JSON to any HTTP endpoint.

```ts
// Datadog
new WebhookLogger({
  url: "https://http-intake.logs.datadoghq.com/api/v2/logs",
  headers: { "DD-API-KEY": process.env.DD_API_KEY! },
});

// Splunk HEC
new WebhookLogger({
  url: "https://splunk.example.com:8088/services/collector/event",
  headers: { Authorization: `Splunk ${process.env.SPLUNK_HEC_TOKEN}` },
});

// Generic
new WebhookLogger({
  url: "https://my-api.example.com/audit",
  headers: { Authorization: `Bearer ${process.env.AUDIT_TOKEN}` },
  retries: 2,
  timeoutMs: 5000,
  omit: ["prompt"],
});
```

---

## Custom logger

Implement `AuditLogger`:

```ts
import type { AuditLogger, AuditEntry } from "llm-firewall";

class MyLogger implements AuditLogger {
  async log(entry: AuditEntry): Promise<void> {
    await db.insert("audit_log", entry);
  }
}

const firewall = new Firewall().withAuditLogger(new MyLogger());
```

---

## Metadata

Attach static or per-call metadata to every audit entry.

```ts
// Static — merged into every entry from this instance
const firewall = new Firewall()
  .withAuditLogger(logger, { service: "chat-api", env: "production" });

// Per-call — merged at call time
firewall.analyze(prompt, { userId: "u_123", sessionId: "s_456" });
await firewall.guardAsync(prompt, { requestId: req.id });
```

---

## AuditEntry shape

```ts
interface AuditEntry {
  timestamp: string;      // ISO 8601
  allowed: boolean;
  prompt: string;
  detections: DetectionResult[];
  metadata?: Record<string, unknown>;
}
```
