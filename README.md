# llm-firewall

Detect and block malicious or dangerous AI prompts before they reach your LLM. Works as a lightweight rule-based filter, an LLM-as-judge, or both together.

```ts
import { Firewall, AnthropicJudge } from "llm-firewall";
import Anthropic from "@anthropic-ai/sdk";

const firewall = new Firewall()
  .withJudge(new AnthropicJudge(new Anthropic()));

await firewall.guardAsync(userPrompt); // throws if blocked
```

## Install

```bash
npm install llm-firewall
```

## How it works

Two layers of protection:

1. **Rule-based detectors** — fast, synchronous, zero dependencies. Pattern-match against known injection techniques, credential formats, and harmful content categories.
2. **LLM-as-judge** — optional async layer that sends the prompt to a second LLM for semantic evaluation. Catches threats that pattern matching misses. The judge is skipped entirely if rules already block the prompt.

---

## Quick start

### Sync — rule-based only

```ts
import { Firewall } from "llm-firewall";

const firewall = new Firewall();
const result = firewall.analyze(userPrompt);

if (!result.allowed) {
  console.log(result.detections); // see what triggered
}
```

### Async — rules + LLM judge

```ts
import { Firewall, AnthropicJudge } from "llm-firewall";
import Anthropic from "@anthropic-ai/sdk";

const firewall = new Firewall()
  .withJudge(new AnthropicJudge(new Anthropic()));

const result = await firewall.analyzeAsync(userPrompt);
```

### Guard pattern (throws on block)

```ts
import { Firewall, FirewallBlockedError } from "llm-firewall";

const firewall = new Firewall();

try {
  firewall.guard(userPrompt);          // sync
  await firewall.guardAsync(prompt);   // async (rules + judge)
} catch (e) {
  if (e instanceof FirewallBlockedError) {
    console.log(e.result.detections);
    return res.status(400).json({ error: "Prompt blocked" });
  }
  throw e;
}
```

### Express / Fastify middleware

```ts
import { Firewall, FirewallBlockedError } from "llm-firewall";

const firewall = new Firewall();

app.post("/chat", async (req, res) => {
  try {
    await firewall.guardAsync(req.body.message);
  } catch (e) {
    if (e instanceof FirewallBlockedError) {
      return res.status(400).json({ error: "Message blocked", detections: e.result.detections });
    }
    throw e;
  }
  // safe to forward to your LLM
});
```

---

## Rule-based detectors

Three built-in detectors, all enabled by default.

| Detector | What it catches |
|----------|-----------------|
| `injection` | Jailbreaks, DAN/god mode, system prompt extraction, instruction overrides, token injection, zero-width char obfuscation, indirect injection |
| `pii` | API keys (AWS, GCP, GitHub, Slack, Stripe, Twilio…), passwords, JWTs, connection strings, credit cards, SSNs, IBANs, passports, NHS/NI numbers, crypto private keys |
| `harmful` | Weapons, explosives, chemical/bio/radiological, drugs, malware, phishing, fraud, human trafficking, CSAM, self-harm, terrorism, stalking, infrastructure attacks |

### Configuring detectors

```ts
const firewall = new Firewall()
  .use("injection", "harmful")        // run only these detectors
  .blockOn("high", "critical");       // block only on these severities
```

### Using detectors directly

```ts
import { detectInjection, detectPII, detectHarmful } from "llm-firewall";

const result = detectInjection(prompt);
// {
//   detector: "injection",
//   triggered: true,
//   severity: "critical",
//   reason: "Prompt injection pattern detected",
//   matches: ["Ignore all previous instructions"]
// }
```

---

## LLM-as-judge providers

Seven built-in providers. All use duck-typed client interfaces — no hard peer dependencies on any SDK.

### Anthropic

```ts
import Anthropic from "@anthropic-ai/sdk";
import { AnthropicJudge } from "llm-firewall";

const judge = new AnthropicJudge(new Anthropic(), {
  model: "claude-haiku-4-5-20251001", // default
});
```

### OpenAI

```ts
import OpenAI from "openai";
import { OpenAIJudge } from "llm-firewall";

const judge = new OpenAIJudge(new OpenAI(), {
  model: "gpt-4o-mini", // default
});
```

### Azure OpenAI

```ts
import { AzureOpenAI } from "openai";
import { AzureOpenAIJudge } from "llm-firewall";

const judge = new AzureOpenAIJudge(
  new AzureOpenAI({
    apiKey: process.env.AZURE_OPENAI_API_KEY,
    endpoint: process.env.AZURE_OPENAI_ENDPOINT,
    apiVersion: "2024-02-01",
  }),
  { deployment: "gpt-4o-mini" }
);
```

### GCP Vertex AI

```ts
import { VertexAI } from "@google-cloud/vertexai";
import { VertexAIJudge } from "llm-firewall";

const model = new VertexAI({ project: "my-project", location: "us-central1" })
  .getGenerativeModel({ model: "gemini-1.5-flash" });

const judge = new VertexAIJudge(model);
```

### LangChain

Works with any `BaseChatModel` — `ChatOpenAI`, `ChatAnthropic`, `ChatGoogleGenerativeAI`, `ChatMistralAI`, and more.

```ts
import { ChatOpenAI } from "@langchain/openai";
import { LangChainJudge } from "llm-firewall";

const judge = new LangChainJudge(
  new ChatOpenAI({ model: "gpt-4o-mini", maxTokens: 256 })
);
```

### LlamaIndex

Works with any LlamaIndex `LLM` — `OpenAI`, `Anthropic`, `Groq`, `Mistral`, and more.

```ts
import { Anthropic } from "llamaindex";
import { LlamaIndexJudge } from "llm-firewall";

const judge = new LlamaIndexJudge(
  new Anthropic({ model: "claude-haiku-4-5-20251001" })
);
```

### HuggingFace

Use any instruction-tuned model that supports the chat completion API.

```ts
import { HfInference } from "@huggingface/inference";
import { HuggingFaceJudge } from "llm-firewall";

const judge = new HuggingFaceJudge(new HfInference(process.env.HF_TOKEN), {
  model: "mistralai/Mistral-7B-Instruct-v0.3",
});
```

### Custom provider

Implement the `JudgeProvider` interface to use any LLM:

```ts
import type { JudgeProvider, JudgeVerdict } from "llm-firewall";

class MyCustomJudge implements JudgeProvider {
  async evaluate(prompt: string): Promise<JudgeVerdict> {
    // call your LLM here
    return {
      safe: true,
      severity: "none",
      categories: [],
      reasoning: "looks fine",
    };
  }
}
```

---

## Audit logging

Every analysis result — allowed or blocked — can be sent to one or more audit loggers. Loggers never affect firewall behaviour: errors are silently swallowed.

```ts
import { Firewall, ConsoleLogger, FileLogger, WebhookLogger } from "llm-firewall";

const firewall = new Firewall()
  .withAuditLogger(new ConsoleLogger({ format: "pretty" }))
  .withAuditLogger(new FileLogger({ path: "./logs/firewall.jsonl" }))
  .withAuditLogger(new WebhookLogger({ url: "https://my-siem.example.com/ingest" }));
```

### ConsoleLogger

```ts
new ConsoleLogger({
  format: "json",          // "json" (default) or "pretty"
  stderrOnBlock: true,     // write blocked entries to stderr (default: true)
});
```

### FileLogger

Appends entries as JSONL (one JSON object per line). Compatible with Loki, Splunk, Datadog, and `jq`.

```ts
new FileLogger({
  path: "./logs/firewall.jsonl",
  omit: ["prompt"],   // optional — strip fields for privacy
});
```

### WebhookLogger

POSTs entries as JSON to any HTTP endpoint. Supports auth headers, retries, and timeout.

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

// Generic webhook
new WebhookLogger({
  url: "https://my-api.example.com/audit",
  headers: { Authorization: `Bearer ${process.env.AUDIT_TOKEN}` },
  retries: 2,        // default: 2 (exponential backoff)
  timeoutMs: 5000,   // default: 5000
  omit: ["prompt"],  // don't send raw prompts off-device
});
```

### Custom logger

```ts
import type { AuditLogger, AuditEntry } from "llm-firewall";

class MyLogger implements AuditLogger {
  async log(entry: AuditEntry): Promise<void> {
    await db.insert("audit_log", entry);
  }
}
```

### Metadata

Pass per-call context and static labels to every log entry:

```ts
// Static metadata — merged into every entry from this instance
const firewall = new Firewall()
  .withAuditLogger(logger, { service: "chat-api", env: "production" });

// Per-call metadata — merged at call time
firewall.analyze(prompt, { userId: "u_123", sessionId: "s_456" });
await firewall.guardAsync(prompt, { requestId: req.id });
```

### AuditEntry shape

```ts
interface AuditEntry {
  timestamp: string;                // ISO 8601
  allowed: boolean;
  prompt: string;
  detections: DetectionResult[];
  durationMs: number;
  metadata?: Record<string, unknown>;
}
```

---

## Harm categories

Returned in `detections[].categories` when the `harmful` detector or judge triggers.

| Category | Examples |
|----------|----------|
| `explosives` | Bomb-making, IED assembly, explosive synthesis |
| `firearms` | Auto conversions, ghost guns, Glock switches, trafficking |
| `chemical-weapons` | Nerve agents, ricin, toxic gas dispersal |
| `bioweapons` | Pathogen enhancement, gain-of-function, aerosolization |
| `radiological` | Dirty bombs, uranium enrichment, nuclear devices |
| `drugs` | Fentanyl synthesis, darknet sourcing, drink spiking |
| `cyberattack` | Malware, phishing kits, DDoS tools, infrastructure attacks |
| `fraud` | Scams, deepfakes, SIM swap, fake documents, money laundering |
| `human-trafficking` | Smuggling, forced labor, exploitation |
| `csam` | Sexual content involving minors, grooming |
| `self-harm` | Suicide methods, self-injury, facilitating others |
| `violence` | Murder planning, assault, honor killings |
| `terrorism` | Attack planning, manifestos, mass casualty |
| `extremism` | Radicalization, hate group recruitment |
| `personal-targeting` | Stalking, doxxing, harassment campaigns, stalkerware |
| `financial-crime` | Insider trading, market manipulation, money laundering |
| `weapons` | Illegal weapons trafficking |

---

## Severity levels

| Level | Examples | Blocked by default? |
|-------|----------|---------------------|
| `low` | Email address, phone number, roleplay request | No |
| `medium` | Persona override attempt, disinformation campaign | No |
| `high` | System prompt extraction, self-harm methods, phishing | **Yes** |
| `critical` | Jailbreak, API key, nerve agent synthesis, CSAM | **Yes** |

---

## API reference

### `new Firewall()`

```ts
firewall.use(...detectors)          // select detectors: "injection" | "pii" | "harmful"
firewall.blockOn(...severities)     // select block threshold: "low" | "medium" | "high" | "critical"
firewall.withJudge(provider)        // attach LLM judge for async methods

firewall.analyze(prompt)            // → FirewallResult         (sync, rules only)
firewall.analyzeAsync(prompt)       // → Promise<FirewallResult> (async, rules + judge)
firewall.guard(prompt)              // → void | throws FirewallBlockedError
firewall.guardAsync(prompt)         // → Promise<void> | throws FirewallBlockedError
```

### `FirewallResult`

```ts
interface FirewallResult {
  allowed: boolean;
  prompt: string;
  detections: DetectionResult[];
}

interface DetectionResult {
  detector: "injection" | "pii" | "harmful" | "judge";
  triggered: boolean;
  severity?: "low" | "medium" | "high" | "critical";
  reason?: string;
  matches?: string[];        // matched pattern strings or PII type names
  categories?: HarmCategory[]; // populated for harmful detector and judge
  judgeReasoning?: string;   // populated when detector is "judge"
}
```

### `analyze(prompt, config?)`

Functional alternative to the class API:

```ts
import { analyze, analyzeAsync } from "llm-firewall";

const result = analyze(prompt, {
  detectors: ["injection", "pii", "harmful"],
  blockOnSeverity: ["high", "critical"],
});

const result = await analyzeAsync(prompt, judgeProvider, config);
```

---

## Development

```bash
npm test           # run tests (80 tests, no network calls)
npm run typecheck  # type check without building
npm run build      # compile to dist/
```

---

## Roadmap

- [ ] Redaction mode — strip PII from prompts rather than blocking
- [ ] Custom rule policies via config file
- [ ] CommonJS build (dual ESM/CJS)
- [ ] Rate limiting per identity
