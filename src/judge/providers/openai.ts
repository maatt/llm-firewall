import { JUDGE_SYSTEM_PROMPT, wrapPrompt } from "../prompt.js";
import type { JudgeProvider, JudgeVerdict } from "../types.js";

/** Minimal duck-typed interface — avoids a hard openai peer dependency. */
interface OpenAIClient {
  chat: {
    completions: {
      create(params: {
        model: string;
        max_tokens: number;
        response_format?: { type: "json_object" };
        messages: Array<{ role: "system" | "user"; content: string }>;
      }): Promise<{
        choices: Array<{ message: { content: string | null } }>;
      }>;
    };
  };
}

export interface OpenAIJudgeOptions {
  /**
   * Model to use. Defaults to gpt-4o-mini — fast and cheap for classification.
   */
  model?: string;
  /** Max tokens for the response. Defaults to 256. */
  maxTokens?: number;
}

/**
 * LLM judge backed by OpenAI.
 *
 * @example
 * import OpenAI from "openai";
 * import { OpenAIJudge } from "llm-firewall";
 *
 * const judge = new OpenAIJudge(new OpenAI(), { model: "gpt-4o-mini" });
 * const firewall = new Firewall().withJudge(judge);
 * await firewall.guardAsync(prompt);
 */
export class OpenAIJudge implements JudgeProvider {
  private client: OpenAIClient;
  private model: string;
  private maxTokens: number;

  constructor(client: OpenAIClient, options: OpenAIJudgeOptions = {}) {
    this.client = client;
    this.model = options.model ?? "gpt-4o-mini";
    this.maxTokens = options.maxTokens ?? 256;
  }

  async evaluate(prompt: string): Promise<JudgeVerdict> {
    const response = await this.client.chat.completions.create({
      model: this.model,
      max_tokens: this.maxTokens,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: JUDGE_SYSTEM_PROMPT },
        { role: "user", content: wrapPrompt(prompt) },
      ],
    });

    const text = response.choices[0]?.message.content ?? "";
    return parseVerdict(text);
  }
}

function parseVerdict(raw: string): JudgeVerdict {
  try {
    const parsed = JSON.parse(raw.trim());
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
