# Custom Policy Rules

Block prompts matching your own patterns alongside the built-in detectors.

## Adding rules

```ts
import { Firewall } from "llm-firewall";

const firewall = new Firewall().withPolicy([
  {
    name: "no-competitor",
    pattern: /rival-corp/i,
    severity: "medium",
    reason: "Competitor mention",
  },
  {
    name: "no-internal-codename",
    pattern: "project-atlas",   // strings are auto-compiled to RegExp
    severity: "high",
  },
]);
```

`withPolicy()` can be called multiple times — rules are accumulated, not replaced.

## PolicyRule shape

```ts
interface PolicyRule {
  name: string;                                        // identifier shown in detections
  pattern: RegExp | string;                            // string → case-insensitive RegExp
  severity: "low" | "medium" | "high" | "critical";
  reason?: string;                                     // shown in DetectionResult.reason
}
```

## Combining with other configuration

Custom rules work alongside all other firewall options:

```ts
const firewall = new Firewall()
  .use("injection", "harmful")
  .blockOn("medium", "high", "critical")
  .withPolicy([
    { name: "no-pii-topic", pattern: /tell me about .* personal data/i, severity: "medium" },
  ])
  .withJudge(new AnthropicJudge(new Anthropic()))
  .withAuditLogger(new FileLogger({ path: "./logs/firewall.jsonl" }));
```

## Detections

Policy violations appear in `result.detections` with `detector: "policy"`:

```ts
{
  detector: "policy",
  triggered: true,
  severity: "medium",
  reason: "Competitor mention",
  matches: ["rival-corp"]
}
```
