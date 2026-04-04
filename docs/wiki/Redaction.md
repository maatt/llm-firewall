# Redaction

Strip PII from prompts instead of blocking them, then pass the sanitised version to your LLM.

## Basic usage

```ts
import { redact } from "llm-firewall";

const { redacted, redactions } = redact("My email is john@acme.com and SSN is 123-45-6789");
// redacted   → "My email is [REDACTED:email] and SSN is [REDACTED:ssn]"
// redactions → [{ type: "email", original: "john@acme.com", start: 12, end: 25 }, …]
```

Each item in `redactions` includes:

```ts
interface Redaction {
  type: string;       // e.g. "email", "ssn", "credit-card"
  original: string;   // the matched value
  start: number;      // character offset in original string
  end: number;
}
```

## Chaining with the firewall

Redact first to strip credentials, then run the firewall to catch injection attempts:

```ts
import { redact, Firewall } from "llm-firewall";

const firewall = new Firewall();

const { redacted } = redact(userPrompt);
firewall.guard(redacted);
// safe to forward to your LLM
```

## In a request handler

```ts
app.post("/chat", async (req, res) => {
  const { redacted, redactions } = redact(req.body.message);

  if (redactions.length > 0) {
    console.log("Redacted PII types:", redactions.map(r => r.type));
  }

  try {
    firewall.guard(redacted);
  } catch (e) {
    if (e instanceof FirewallBlockedError) {
      return res.status(400).json({ error: "Message blocked" });
    }
    throw e;
  }

  // send redacted prompt to your LLM
  const response = await llm.chat(redacted);
  res.json({ response });
});
```

## What gets redacted

`redact()` uses the same pattern set as the `pii` detector. See [Detectors → PII types detected](Detectors#pii-types-detected) for the full list.
