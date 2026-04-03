import { JUDGE_SYSTEM_PROMPT, wrapPrompt } from "../prompt.js";
import type { JudgeProvider, JudgeVerdict } from "../types.js";

/**
 * Minimal duck-typed interface for a LlamaIndex LLM.
 * Compatible with any LLM from llamaindex (OpenAI, Anthropic, Groq, Mistral, etc.)
 */
interface LlamaIndexLLM {
  chat(params: {
    messages: Array<{ role: string; content: string }>;
  }): Promise<{
    message: { content: string };
  }>;
}

/**
 * LLM judge backed by any LlamaIndex LLM.
 *
 * Works with OpenAI, Anthropic, Groq, Mistral, and any other LlamaIndex LLM implementation.
 *
 * @example
 * import { Anthropic } from "llamaindex";
 * import { LlamaIndexJudge } from "llm-firewall";
 *
 * const llm = new Anthropic({ model: "claude-haiku-4-5-20251001", maxTokens: 256 });
 * const judge = new LlamaIndexJudge(llm);
 * const firewall = new Firewall().withJudge(judge);
 *
 * @example
 * import { OpenAI } from "llamaindex";
 * const llm = new OpenAI({ model: "gpt-4o-mini" });
 * const judge = new LlamaIndexJudge(llm);
 */
export class LlamaIndexJudge implements JudgeProvider {
  private llm: LlamaIndexLLM;

  constructor(llm: LlamaIndexLLM) {
    this.llm = llm;
  }

  async evaluate(prompt: string): Promise<JudgeVerdict> {
    const response = await this.llm.chat({
      messages: [
        { role: "system", content: JUDGE_SYSTEM_PROMPT },
        { role: "user", content: wrapPrompt(prompt) },
      ],
    });

    return parseVerdict(response.message.content);
  }
}

function parseVerdict(raw: string): JudgeVerdict {
  try {
    const json = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
    const parsed = JSON.parse(json);
    return {
      safe: Boolean(parsed.safe),
      severity: parsed.severity ?? "none",
      categories: Array.isArray(parsed.categories) ? parsed.categories : [],
      reasoning: parsed.reasoning ?? "",
    };
  } catch {
    return {
      safe: true,
      severity: "none",
      categories: [],
      reasoning: `Judge response could not be parsed: ${raw.slice(0, 100)}`,
    };
  }
}
