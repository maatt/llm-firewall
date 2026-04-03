import { JUDGE_SYSTEM_PROMPT, wrapPrompt } from "../prompt.js";
import type { JudgeProvider, JudgeVerdict } from "../types.js";

/**
 * Minimal duck-typed interface for the HuggingFace Inference client.
 * Compatible with HfInference from @huggingface/inference.
 */
interface HuggingFaceClient {
  chatCompletion(params: {
    model: string;
    messages: Array<{ role: string; content: string }>;
    max_tokens?: number;
  }): Promise<{
    choices: Array<{ message: { content: string | null } }>;
  }>;
}

export interface HuggingFaceJudgeOptions {
  /**
   * HuggingFace model ID to use for classification.
   * Use a model that supports chat completion and JSON output.
   * e.g. "mistralai/Mistral-7B-Instruct-v0.3", "meta-llama/Meta-Llama-3-8B-Instruct"
   */
  model: string;
  /** Max tokens for the response. Defaults to 256. */
  maxTokens?: number;
}

/**
 * LLM judge backed by HuggingFace Inference API.
 *
 * Use any instruction-tuned model that supports the chat completion API.
 * Smaller models (7B–8B) are typically sufficient for safety classification.
 *
 * @example
 * import { HfInference } from "@huggingface/inference";
 * import { HuggingFaceJudge } from "llm-firewall";
 *
 * const hf = new HfInference(process.env.HF_TOKEN);
 * const judge = new HuggingFaceJudge(hf, {
 *   model: "mistralai/Mistral-7B-Instruct-v0.3",
 * });
 * const firewall = new Firewall().withJudge(judge);
 */
export class HuggingFaceJudge implements JudgeProvider {
  private client: HuggingFaceClient;
  private model: string;
  private maxTokens: number;

  constructor(client: HuggingFaceClient, options: HuggingFaceJudgeOptions) {
    this.client = client;
    this.model = options.model;
    this.maxTokens = options.maxTokens ?? 256;
  }

  async evaluate(prompt: string): Promise<JudgeVerdict> {
    const response = await this.client.chatCompletion({
      model: this.model,
      max_tokens: this.maxTokens,
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
    // Strip markdown code fences — smaller models often wrap JSON in ```
    const json = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "").trim();

    // Some models prefix with commentary before the JSON — try to extract just the object
    const jsonMatch = json.match(/\{[\s\S]*\}/);
    const jsonStr = jsonMatch ? jsonMatch[0] : json;

    const parsed = JSON.parse(jsonStr);
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
