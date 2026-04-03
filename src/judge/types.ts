import type { HarmCategory, Severity } from "../types.js";

export interface JudgeVerdict {
  safe: boolean;
  severity: Severity | "none";
  categories: HarmCategory[];
  reasoning: string;
}

/**
 * Implement this interface to plug in any LLM as a judge.
 * Built-in implementations: AnthropicJudge, OpenAIJudge.
 */
export interface JudgeProvider {
  evaluate(prompt: string): Promise<JudgeVerdict>;
}
