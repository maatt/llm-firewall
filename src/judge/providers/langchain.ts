import { JUDGE_SYSTEM_PROMPT, wrapPrompt } from "../prompt.js";
import type { JudgeProvider, JudgeVerdict } from "../types.js";

/**
 * Minimal duck-typed interface for a LangChain chat model.
 * Compatible with any BaseChatModel (ChatOpenAI, ChatAnthropic, ChatGoogleGenerativeAI, etc.)
 */
interface LangChainChatModel {
  invoke(
    messages: Array<{ role: string; content: string }>
  ): Promise<{
    content: string | Array<{ type: string; text?: string }>;
  }>;
}

export interface LangChainJudgeOptions {
  /** Max tokens. Applied via model-level config — set this on the model itself if needed. */
  maxTokens?: number;
}

/**
 * LLM judge backed by any LangChain chat model.
 *
 * Works with ChatOpenAI, ChatAnthropic, ChatGoogleGenerativeAI, ChatMistralAI,
 * ChatCohere, and any other BaseChatModel implementation.
 *
 * @example
 * import { ChatOpenAI } from "@langchain/openai";
 * import { LangChainJudge } from "llm-firewall";
 *
 * const model = new ChatOpenAI({ model: "gpt-4o-mini", maxTokens: 256 });
 * const judge = new LangChainJudge(model);
 * const firewall = new Firewall().withJudge(judge);
 *
 * @example
 * import { ChatAnthropic } from "@langchain/anthropic";
 * const model = new ChatAnthropic({ model: "claude-haiku-4-5-20251001", maxTokens: 256 });
 * const judge = new LangChainJudge(model);
 */
export class LangChainJudge implements JudgeProvider {
  private model: LangChainChatModel;

  constructor(model: LangChainChatModel) {
    this.model = model;
  }

  async evaluate(prompt: string): Promise<JudgeVerdict> {
    const response = await this.model.invoke([
      { role: "system", content: JUDGE_SYSTEM_PROMPT },
      { role: "user", content: wrapPrompt(prompt) },
    ]);

    const text = extractText(response.content);
    return parseVerdict(text);
  }
}

function extractText(content: string | Array<{ type: string; text?: string }>): string {
  if (typeof content === "string") return content;
  return content.find((b) => b.type === "text")?.text ?? "";
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
