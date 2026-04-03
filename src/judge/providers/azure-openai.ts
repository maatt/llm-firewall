import { JUDGE_SYSTEM_PROMPT, wrapPrompt } from "../prompt.js";
import type { JudgeProvider, JudgeVerdict } from "../types.js";

/**
 * Minimal duck-typed interface for Azure OpenAI client.
 * Compatible with AzureOpenAI from the openai package.
 */
interface AzureOpenAIClient {
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

export interface AzureOpenAIJudgeOptions {
  /**
   * The Azure deployment name (maps to the `model` field in the API call).
   * e.g. "gpt-4o-mini-deployment"
   */
  deployment: string;
  /** Max tokens for the response. Defaults to 256. */
  maxTokens?: number;
}

/**
 * LLM judge backed by Azure OpenAI.
 *
 * @example
 * import { AzureOpenAI } from "openai";
 * import { AzureOpenAIJudge } from "llm-firewall";
 *
 * const client = new AzureOpenAI({
 *   apiKey: process.env.AZURE_OPENAI_API_KEY,
 *   endpoint: process.env.AZURE_OPENAI_ENDPOINT,
 *   apiVersion: "2024-02-01",
 * });
 *
 * const judge = new AzureOpenAIJudge(client, { deployment: "gpt-4o-mini" });
 * const firewall = new Firewall().withJudge(judge);
 */
export class AzureOpenAIJudge implements JudgeProvider {
  private client: AzureOpenAIClient;
  private deployment: string;
  private maxTokens: number;

  constructor(client: AzureOpenAIClient, options: AzureOpenAIJudgeOptions) {
    this.client = client;
    this.deployment = options.deployment;
    this.maxTokens = options.maxTokens ?? 256;
  }

  async evaluate(prompt: string): Promise<JudgeVerdict> {
    const response = await this.client.chat.completions.create({
      model: this.deployment,
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
