# LLM Judge Providers

The LLM-as-judge layer sends the prompt to a second model for semantic evaluation. It runs **after** rule-based detectors and is skipped entirely if rules already block the prompt.

Eight built-in providers. All use duck-typed client interfaces — no hard peer dependencies.

## Attaching a judge

```ts
const firewall = new Firewall()
  .withJudge(new AnthropicJudge(new Anthropic()));

const result = await firewall.analyzeAsync(prompt);
// or
await firewall.guardAsync(prompt); // throws FirewallBlockedError if blocked
```

---

## Anthropic

```ts
import Anthropic from "@anthropic-ai/sdk";
import { AnthropicJudge } from "llm-firewall";

const judge = new AnthropicJudge(new Anthropic(), {
  model: "claude-haiku-4-5-20251001", // default
});
```

---

## OpenAI

```ts
import OpenAI from "openai";
import { OpenAIJudge } from "llm-firewall";

const judge = new OpenAIJudge(new OpenAI(), {
  model: "gpt-4o-mini", // default
});
```

---

## Google Gemini

The system prompt must be set at model initialisation, not in `generateContent`.

```ts
import { GoogleGenerativeAI } from "@google/generative-ai";
import { GeminiJudge, JUDGE_SYSTEM_PROMPT } from "llm-firewall";

const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY!);
const model = genAI.getGenerativeModel({
  model: "gemini-2.5-flash-lite",
  systemInstruction: JUDGE_SYSTEM_PROMPT,
});

const judge = new GeminiJudge(model);
```

---

## Azure OpenAI

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

---

## GCP Vertex AI

```ts
import { VertexAI } from "@google-cloud/vertexai";
import { VertexAIJudge } from "llm-firewall";

const model = new VertexAI({ project: "my-project", location: "us-central1" })
  .getGenerativeModel({ model: "gemini-2.5-flash-lite" });

const judge = new VertexAIJudge(model);
```

---

## LangChain

Works with any `BaseChatModel` — `ChatOpenAI`, `ChatAnthropic`, `ChatGoogleGenerativeAI`, `ChatMistralAI`, and more.

```ts
import { ChatOpenAI } from "@langchain/openai";
import { LangChainJudge } from "llm-firewall";

const judge = new LangChainJudge(
  new ChatOpenAI({ model: "gpt-4o-mini", maxTokens: 256 })
);
```

---

## LlamaIndex

Works with any LlamaIndex `LLM` — `OpenAI`, `Anthropic`, `Groq`, `Mistral`, and more.

```ts
import { Anthropic } from "llamaindex";
import { LlamaIndexJudge } from "llm-firewall";

const judge = new LlamaIndexJudge(
  new Anthropic({ model: "claude-haiku-4-5-20251001" })
);
```

---

## HuggingFace Inference

```ts
import { HfInference } from "@huggingface/inference";
import { HuggingFaceJudge } from "llm-firewall";

const judge = new HuggingFaceJudge(new HfInference(process.env.HF_TOKEN), {
  model: "mistralai/Mistral-7B-Instruct-v0.3",
});
```

---

## Custom provider

Implement `JudgeProvider` and pass it directly to `.withJudge()`:

```ts
import type { JudgeProvider, JudgeVerdict } from "llm-firewall";

class MyCustomJudge implements JudgeProvider {
  async evaluate(prompt: string): Promise<JudgeVerdict> {
    // call your model, parse the response
    return { safe: true, severity: "none", categories: [], reasoning: "ok" };
  }
}

const firewall = new Firewall().withJudge(new MyCustomJudge());
```

`JudgeVerdict`:

```ts
interface JudgeVerdict {
  safe: boolean;
  severity: "none" | "low" | "medium" | "high" | "critical";
  categories: HarmCategory[];
  reasoning: string;
}
```

---

## Judge system prompt

The shared system prompt used by all built-in providers is exported as `JUDGE_SYSTEM_PROMPT`:

```ts
import { JUDGE_SYSTEM_PROMPT } from "llm-firewall";
```

Use this when you need to pass the system prompt separately (e.g. Gemini, Vertex AI).
