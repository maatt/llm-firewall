import { JUDGE_SYSTEM_PROMPT, wrapPrompt } from "../prompt.js";
import type { JudgeProvider, JudgeVerdict } from "../types.js";

/** Minimal duck-typed interface — avoids a hard @anthropic-ai/sdk peer dependency. */
interface AnthropicClient {
  messages: {
    create(params: {
      model: string;
      max_tokens: number;
      system: string;
      messages: Array<{ role: "user"; content: string }>;
    }): Promise<{
      content: Array<{ type: string; text?: string }>;
    }>;
  };
}

export interface AnthropicJudgeOptions {
  /**
   * Model to use. Defaults to claude-haiku-4-5-20251001 — fast and cheap for classification.
   */
  model?: string;
  /** Max tokens for the response. Defaults to 256 — the JSON verdict is short. */
  maxTokens?: number;
}

/**
 * LLM judge backed by Anthropic Claude.
 *
 * @example
 * import Anthropic from "@anthropic-ai/sdk";
 * import { AnthropicJudge } from "llm-firewall";
 *
 * const judge = new AnthropicJudge(new Anthropic(), { model: "claude-haiku-4-5-20251001" });
 * const firewall = new Firewall().withJudge(judge);
 * await firewall.guardAsync(prompt);
 */
export class AnthropicJudge implements JudgeProvider {
  private client: AnthropicClient;
  private model: string;
  private maxTokens: number;

  constructor(client: AnthropicClient, options: AnthropicJudgeOptions = {}) {
    this.client = client;
    this.model = options.model ?? "claude-haiku-4-5-20251001";
    this.maxTokens = options.maxTokens ?? 256;
  }

  async evaluate(prompt: string): Promise<JudgeVerdict> {
    const response = await this.client.messages.create({
      model: this.model,
      max_tokens: this.maxTokens,
      system: JUDGE_SYSTEM_PROMPT,
      messages: [{ role: "user", content: wrapPrompt(prompt) }],
    });

    const text = response.content.find((b) => b.type === "text")?.text ?? "";
    return parseVerdict(text);
  }
}

function parseVerdict(raw: string): JudgeVerdict {
  try {
    // Strip markdown code fences if the model wraps the JSON
    const json = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();
    const parsed = JSON.parse(json);
    return {
      safe: Boolean(parsed.safe),
      severity: parsed.severity ?? "none",
      categories: Array.isArray(parsed.categories) ? parsed.categories : [],
      reasoning: parsed.reasoning ?? "",
    };
  } catch {
    // Unparseable response — treat as uncertain, let rule-based results stand
    return {
      safe: true,
      severity: "none",
      categories: [],
      reasoning: `Judge response could not be parsed: ${raw.slice(0, 100)}`,
    };
  }
}
