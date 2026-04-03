import { JUDGE_SYSTEM_PROMPT, wrapPrompt } from "../prompt.js";
import type { JudgeProvider, JudgeVerdict } from "../types.js";

/**
 * Minimal duck-typed interface for a Vertex AI generative model instance.
 * Compatible with GenerativeModel from @google-cloud/vertexai.
 */
interface VertexAIModel {
  generateContent(request: {
    systemInstruction?: { parts: Array<{ text: string }> };
    contents: Array<{
      role: string;
      parts: Array<{ text: string }>;
    }>;
    generationConfig?: {
      maxOutputTokens?: number;
      responseMimeType?: string;
    };
  }): Promise<{
    response: {
      candidates?: Array<{
        content: { parts: Array<{ text: string }> };
      }>;
    };
  }>;
}

export interface VertexAIJudgeOptions {
  /** Max output tokens. Defaults to 256. */
  maxOutputTokens?: number;
}

/**
 * LLM judge backed by GCP Vertex AI.
 *
 * @example
 * import { VertexAI } from "@google-cloud/vertexai";
 * import { VertexAIJudge } from "llm-firewall";
 *
 * const vertexai = new VertexAI({ project: "my-project", location: "us-central1" });
 * const model = vertexai.getGenerativeModel({ model: "gemini-1.5-flash" });
 *
 * const judge = new VertexAIJudge(model);
 * const firewall = new Firewall().withJudge(judge);
 */
export class VertexAIJudge implements JudgeProvider {
  private model: VertexAIModel;
  private maxOutputTokens: number;

  constructor(model: VertexAIModel, options: VertexAIJudgeOptions = {}) {
    this.model = model;
    this.maxOutputTokens = options.maxOutputTokens ?? 256;
  }

  async evaluate(prompt: string): Promise<JudgeVerdict> {
    const response = await this.model.generateContent({
      systemInstruction: {
        parts: [{ text: JUDGE_SYSTEM_PROMPT }],
      },
      contents: [
        {
          role: "user",
          parts: [{ text: wrapPrompt(prompt) }],
        },
      ],
      generationConfig: {
        maxOutputTokens: this.maxOutputTokens,
        responseMimeType: "application/json",
      },
    });

    const text = response.response.candidates?.[0]?.content.parts[0]?.text ?? "";
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
