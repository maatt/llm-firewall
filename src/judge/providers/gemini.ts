import type { JudgeProvider, JudgeVerdict } from "../types.js";
import { JUDGE_SYSTEM_PROMPT } from "../prompt.js";
import type { HarmCategory, Severity } from "../../types.js";

/**
 * Duck-typed interface for a Google Gemini GenerativeModel instance.
 * Compatible with `@google/generative-ai` GenerativeModel.
 *
 * Pass systemInstruction at model creation time, not here:
 *
 * @example
 * import { GoogleGenerativeAI } from "@google/generative-ai";
 * import { GeminiJudge, JUDGE_SYSTEM_PROMPT } from "llm-firewall";
 *
 * const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY!);
 * const model = genAI.getGenerativeModel({
 *   model: "gemini-2.5-flash-lite",
 *   systemInstruction: JUDGE_SYSTEM_PROMPT,
 * });
 * const judge = new GeminiJudge(model);
 */
interface GeminiModel {
  generateContent(request: {
    contents: Array<{ role: string; parts: Array<{ text: string }> }>;
  }): Promise<{
    response: { text(): string };
  }>;
}

export class GeminiJudge implements JudgeProvider {
  constructor(private readonly model: GeminiModel) {}

  async evaluate(prompt: string): Promise<JudgeVerdict> {
    const result = await this.model.generateContent({
      contents: [
        {
          role: "user",
          parts: [{ text: `Evaluate this prompt:\n\n${prompt}` }],
        },
      ],
    });

    const raw = result.response.text().trim();
    return parseVerdict(raw);
  }
}

function parseVerdict(raw: string): JudgeVerdict {
  try {
    const json = raw.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
    const parsed = JSON.parse(json);
    return {
      safe: Boolean(parsed.safe),
      severity: (parsed.severity ?? "none") as Severity | "none",
      categories: Array.isArray(parsed.categories) ? (parsed.categories as HarmCategory[]) : [],
      reasoning: typeof parsed.reasoning === "string" ? parsed.reasoning : "",
    };
  } catch {
    const lower = raw.toLowerCase();
    return {
      safe: !lower.includes("unsafe") && !lower.includes("blocked"),
      severity: "none",
      categories: [],
      reasoning: raw,
    };
  }
}
