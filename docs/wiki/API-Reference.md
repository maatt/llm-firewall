# API Reference

## `new Firewall()`

Fluent builder for configuring and running the firewall.

```ts
firewall.use(...detectors)          // select detectors: "injection" | "pii" | "harmful"
firewall.blockOn(...severities)     // select block threshold: "low" | "medium" | "high" | "critical"
firewall.withJudge(provider)        // attach LLM judge for async methods
firewall.withPolicy(rules)          // add custom policy rules
firewall.withAuditLogger(logger, meta?)  // attach an audit logger with optional static metadata

firewall.analyze(prompt, meta?)         // → FirewallResult          (sync, rules only)
firewall.analyzeAsync(prompt, meta?)    // → Promise<FirewallResult>  (async, rules + judge)
firewall.guard(prompt, meta?)           // → void | throws FirewallBlockedError  (sync)
firewall.guardAsync(prompt, meta?)      // → Promise<void> | throws FirewallBlockedError
```

---

## `analyze()` / `analyzeAsync()` (functional)

Stateless alternatives to the class API:

```ts
import { analyze, analyzeAsync } from "llm-firewall";

const result = analyze(prompt, {
  detectors: ["injection", "pii", "harmful"],   // default: all
  blockOnSeverity: ["high", "critical"],         // default
});

const result = await analyzeAsync(prompt, judgeProvider, {
  detectors: ["injection", "harmful"],
  blockOnSeverity: ["high", "critical"],
});
```

---

## `FirewallResult`

```ts
interface FirewallResult {
  allowed: boolean;
  prompt: string;
  detections: DetectionResult[];
}
```

---

## `DetectionResult`

```ts
interface DetectionResult {
  detector: "injection" | "pii" | "harmful" | "judge" | "policy";
  triggered: boolean;
  severity?: "low" | "medium" | "high" | "critical";
  reason?: string;
  matches?: string[];
  categories?: HarmCategory[];
  judgeReasoning?: string;    // populated when detector === "judge"
}
```

---

## `FirewallBlockedError`

Thrown by `guard()` and `guardAsync()` when a prompt is blocked.

```ts
import { FirewallBlockedError } from "llm-firewall";

try {
  await firewall.guardAsync(prompt);
} catch (e) {
  if (e instanceof FirewallBlockedError) {
    console.log(e.result.detections);
    console.log(e.result.allowed); // false
  }
}
```

---

## `redact()`

```ts
import { redact } from "llm-firewall";

const { original, redacted, redactions } = redact(prompt);
```

```ts
interface RedactResult {
  original: string;
  redacted: string;
  redactions: Redaction[];
}

interface Redaction {
  type: string;
  original: string;
  start: number;
  end: number;
}
```

---

## Types

```ts
type DetectorName = "injection" | "pii" | "harmful";

type Severity = "low" | "medium" | "high" | "critical";

type HarmCategory =
  | "weapons" | "explosives" | "firearms" | "chemical-weapons"
  | "bioweapons" | "radiological" | "drugs" | "cyberattack"
  | "fraud" | "human-trafficking" | "csam" | "self-harm"
  | "violence" | "terrorism" | "personal-targeting" | "extremism"
  | "financial-crime" | "sexual";

interface FirewallConfig {
  detectors?: DetectorName[];
  blockOnSeverity?: Severity[];
}

interface AnalyzeRequest {
  prompt: string;
  config?: FirewallConfig;
}
```

---

## `JudgeProvider` / `JudgeVerdict`

```ts
interface JudgeProvider {
  evaluate(prompt: string): Promise<JudgeVerdict>;
}

interface JudgeVerdict {
  safe: boolean;
  severity: "none" | "low" | "medium" | "high" | "critical";
  categories: HarmCategory[];
  reasoning: string;
}
```

---

## `AuditLogger` / `AuditEntry`

```ts
interface AuditLogger {
  log(entry: AuditEntry): Promise<void>;
}

interface AuditEntry {
  timestamp: string;
  allowed: boolean;
  prompt: string;
  detections: DetectionResult[];
  metadata?: Record<string, unknown>;
}
```

---

## `PolicyRule`

```ts
interface PolicyRule {
  name: string;
  pattern: RegExp | string;
  severity: Severity;
  reason?: string;
}
```

---

## Exported constants

```ts
import { JUDGE_SYSTEM_PROMPT } from "llm-firewall";
// The shared system prompt string used by all built-in judge providers.
```
