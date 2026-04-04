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

Requires Node.js **>=20**.

---

## How it works

Two layers of protection:

1. **Rule-based detectors** — fast, synchronous, zero dependencies. Pattern-match against known injection techniques, credential formats, and harmful content categories.
2. **LLM-as-judge** — optional async layer that sends the prompt to a second LLM for semantic evaluation. Catches threats that pattern matching misses. Skipped entirely if rules already block the prompt.

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
  firewall.guard(userPrompt);           // sync
  await firewall.guardAsync(prompt);    // async (rules + judge)
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
| `injection` | Jailbreaks, DAN/god mode, named personas, system prompt extraction, instruction overrides, encoding bypass |
| `pii` | API keys (AWS, GCP, GitHub, Slack…), passwords, bearer tokens, JWTs, credit cards, SSNs, passports |
| `harmful` | Weapons, explosives, CBRN, drugs, malware, fraud, CSAM, self-harm, terrorism, sexual solicitation |

```ts
const firewall = new Firewall()
  .use("injection", "harmful")      // run only these detectors
  .blockOn("high", "critical");     // block only on these severities
```

Full detector docs, harm categories, and severity levels: **[Wiki → Detectors](https://github.com/maatt/llm-firewall/wiki/Detectors)**

---

## LLM-as-judge providers

Eight built-in providers. All use duck-typed client interfaces — no hard peer dependencies.

| Provider | Class | Default model |
|----------|-------|---------------|
| Anthropic | `AnthropicJudge` | `claude-haiku-4-5-20251001` |
| OpenAI | `OpenAIJudge` | `gpt-4o-mini` |
| Google Gemini | `GeminiJudge` | — (set at model init) |
| Azure OpenAI | `AzureOpenAIJudge` | — (set via deployment) |
| GCP Vertex AI | `VertexAIJudge` | — (set at model init) |
| LangChain | `LangChainJudge` | any `BaseChatModel` |
| LlamaIndex | `LlamaIndexJudge` | any `LLM` |
| HuggingFace | `HuggingFaceJudge` | configurable |

Full setup for all providers: **[Wiki → Judge Providers](https://github.com/maatt/llm-firewall/wiki/Judge-Providers)**

---

## Redaction

Strip PII from prompts instead of blocking them:

```ts
import { redact } from "llm-firewall";

const { redacted, redactions } = redact("My email is john@acme.com and SSN is 123-45-6789");
// redacted   → "My email is [REDACTED:email] and SSN is [REDACTED:ssn]"
// redactions → [{ type: "email", … }, { type: "ssn", … }]
```

Full redaction docs: **[Wiki → Redaction](https://github.com/maatt/llm-firewall/wiki/Redaction)**

---

## Custom policy rules

```ts
const firewall = new Firewall().withPolicy([
  { name: "no-competitor", pattern: /rival-corp/i, severity: "medium", reason: "Competitor mention" },
  { name: "no-internal-codename", pattern: "project-atlas", severity: "high" },
]);
```

Full docs: **[Wiki → Custom Policy](https://github.com/maatt/llm-firewall/wiki/Custom-Policy)**

---

## Audit logging

```ts
import { ConsoleLogger, FileLogger, WebhookLogger } from "llm-firewall";

const firewall = new Firewall()
  .withAuditLogger(new ConsoleLogger({ format: "pretty" }))
  .withAuditLogger(new FileLogger({ path: "./logs/firewall.jsonl" }))
  .withAuditLogger(new WebhookLogger({ url: "https://my-siem.example.com/ingest" }));
```

Supports Datadog, Splunk HEC, and any HTTP endpoint. Full docs: **[Wiki → Audit Logging](https://github.com/maatt/llm-firewall/wiki/Audit-Logging)**

---

## API reference

Full TypeScript API: **[Wiki → API Reference](https://github.com/maatt/llm-firewall/wiki/API-Reference)**

Quick summary:

```ts
// Firewall builder
firewall.use(...detectors)          // "injection" | "pii" | "harmful"
firewall.blockOn(...severities)     // "low" | "medium" | "high" | "critical"
firewall.withJudge(provider)
firewall.withPolicy(rules)
firewall.withAuditLogger(logger, meta?)

firewall.analyze(prompt, meta?)         // → FirewallResult
firewall.analyzeAsync(prompt, meta?)    // → Promise<FirewallResult>
firewall.guard(prompt, meta?)           // → void | throws FirewallBlockedError
firewall.guardAsync(prompt, meta?)      // → Promise<void> | throws FirewallBlockedError

// Functional API
import { analyze, analyzeAsync, redact } from "llm-firewall";

// Individual detectors
import { detectInjection, detectPII, detectHarmful } from "llm-firewall";
```

---

## Examples

Working examples are in the [`examples/`](./examples) directory.

| Script | What it shows |
|--------|---------------|
| `npm run basic` | `analyze()`, `Firewall` class, `guard()` + error handling |
| `npm run redact` | Strip PII before it reaches the LLM |
| `npm run policy` | Custom regex rules per your domain |
| `npm run judge` | Live LLM judge — set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY` |
| `npm run try` | Interactive terminal demo — type any prompt |

```bash
cd examples
npm install
npm run try
```

---

## Development

```bash
npm test           # run tests
npm run typecheck  # type check without building
npm run build      # compile to dist/
```

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to add detectors, judge providers, or loggers.
