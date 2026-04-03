import { describe, it, expect, vi } from "vitest";
import { AzureOpenAIJudge } from "../src/judge/providers/azure-openai.js";
import { VertexAIJudge } from "../src/judge/providers/vertex-ai.js";
import { LangChainJudge } from "../src/judge/providers/langchain.js";
import { LlamaIndexJudge } from "../src/judge/providers/llamaindex.js";
import { HuggingFaceJudge } from "../src/judge/providers/huggingface.js";

const SAFE_JSON = JSON.stringify({ safe: true, severity: "none", categories: [], reasoning: "OK" });
const UNSAFE_JSON = JSON.stringify({ safe: false, severity: "critical", categories: ["cyberattack"], reasoning: "Malware request" });

// ─── Azure OpenAI ─────────────────────────────────────────────────────────────

describe("AzureOpenAIJudge", () => {
  it("returns safe verdict", async () => {
    const client = { chat: { completions: { create: vi.fn().mockResolvedValue({ choices: [{ message: { content: SAFE_JSON } }] }) } } };
    const judge = new AzureOpenAIJudge(client, { deployment: "gpt-4o-mini" });
    const verdict = await judge.evaluate("Hello world");
    expect(verdict.safe).toBe(true);
    expect(verdict.severity).toBe("none");
  });

  it("returns unsafe verdict", async () => {
    const client = { chat: { completions: { create: vi.fn().mockResolvedValue({ choices: [{ message: { content: UNSAFE_JSON } }] }) } } };
    const judge = new AzureOpenAIJudge(client, { deployment: "gpt-4o-mini" });
    const verdict = await judge.evaluate("Write malware");
    expect(verdict.safe).toBe(false);
    expect(verdict.categories).toContain("cyberattack");
  });

  it("passes deployment name as model", async () => {
    const create = vi.fn().mockResolvedValue({ choices: [{ message: { content: SAFE_JSON } }] });
    const client = { chat: { completions: { create } } };
    const judge = new AzureOpenAIJudge(client, { deployment: "my-deployment" });
    await judge.evaluate("test");
    expect(create.mock.calls[0][0].model).toBe("my-deployment");
  });
});

// ─── Vertex AI ────────────────────────────────────────────────────────────────

describe("VertexAIJudge", () => {
  it("returns safe verdict", async () => {
    const model = {
      generateContent: vi.fn().mockResolvedValue({
        response: { candidates: [{ content: { parts: [{ text: SAFE_JSON }] } }] },
      }),
    };
    const judge = new VertexAIJudge(model);
    const verdict = await judge.evaluate("Hello world");
    expect(verdict.safe).toBe(true);
  });

  it("returns unsafe verdict", async () => {
    const model = {
      generateContent: vi.fn().mockResolvedValue({
        response: { candidates: [{ content: { parts: [{ text: UNSAFE_JSON }] } }] },
      }),
    };
    const judge = new VertexAIJudge(model);
    const verdict = await judge.evaluate("dangerous prompt");
    expect(verdict.safe).toBe(false);
    expect(verdict.severity).toBe("critical");
  });

  it("handles missing candidates gracefully", async () => {
    const model = {
      generateContent: vi.fn().mockResolvedValue({ response: { candidates: [] } }),
    };
    const judge = new VertexAIJudge(model);
    const verdict = await judge.evaluate("test");
    expect(verdict.safe).toBe(true); // fallback
  });
});

// ─── LangChain ────────────────────────────────────────────────────────────────

describe("LangChainJudge", () => {
  it("handles string content response", async () => {
    const model = { invoke: vi.fn().mockResolvedValue({ content: SAFE_JSON }) };
    const judge = new LangChainJudge(model);
    const verdict = await judge.evaluate("Hello");
    expect(verdict.safe).toBe(true);
  });

  it("handles block array content response", async () => {
    const model = {
      invoke: vi.fn().mockResolvedValue({
        content: [{ type: "text", text: UNSAFE_JSON }],
      }),
    };
    const judge = new LangChainJudge(model);
    const verdict = await judge.evaluate("dangerous");
    expect(verdict.safe).toBe(false);
    expect(verdict.categories).toContain("cyberattack");
  });

  it("strips markdown code fences", async () => {
    const wrapped = `\`\`\`json\n${SAFE_JSON}\n\`\`\``;
    const model = { invoke: vi.fn().mockResolvedValue({ content: wrapped }) };
    const judge = new LangChainJudge(model);
    const verdict = await judge.evaluate("test");
    expect(verdict.safe).toBe(true);
  });
});

// ─── LlamaIndex ───────────────────────────────────────────────────────────────

describe("LlamaIndexJudge", () => {
  it("returns safe verdict", async () => {
    const llm = { chat: vi.fn().mockResolvedValue({ message: { content: SAFE_JSON } }) };
    const judge = new LlamaIndexJudge(llm);
    const verdict = await judge.evaluate("Hello");
    expect(verdict.safe).toBe(true);
  });

  it("returns unsafe verdict", async () => {
    const llm = { chat: vi.fn().mockResolvedValue({ message: { content: UNSAFE_JSON } }) };
    const judge = new LlamaIndexJudge(llm);
    const verdict = await judge.evaluate("dangerous");
    expect(verdict.safe).toBe(false);
    expect(verdict.reasoning).toBe("Malware request");
  });

  it("passes system + user messages", async () => {
    const chat = vi.fn().mockResolvedValue({ message: { content: SAFE_JSON } });
    const llm = { chat };
    const judge = new LlamaIndexJudge(llm);
    await judge.evaluate("test prompt");
    const messages = chat.mock.calls[0][0].messages;
    expect(messages[0].role).toBe("system");
    expect(messages[1].role).toBe("user");
    expect(messages[1].content).toContain("test prompt");
  });
});

// ─── HuggingFace ──────────────────────────────────────────────────────────────

describe("HuggingFaceJudge", () => {
  it("returns safe verdict", async () => {
    const client = { chatCompletion: vi.fn().mockResolvedValue({ choices: [{ message: { content: SAFE_JSON } }] }) };
    const judge = new HuggingFaceJudge(client, { model: "mistralai/Mistral-7B-Instruct-v0.3" });
    const verdict = await judge.evaluate("Hello");
    expect(verdict.safe).toBe(true);
  });

  it("extracts JSON from model preamble", async () => {
    const messyResponse = `Sure! Here is my analysis:\n${UNSAFE_JSON}\nHope that helps.`;
    const client = { chatCompletion: vi.fn().mockResolvedValue({ choices: [{ message: { content: messyResponse } }] }) };
    const judge = new HuggingFaceJudge(client, { model: "mistralai/Mistral-7B-Instruct-v0.3" });
    const verdict = await judge.evaluate("dangerous");
    expect(verdict.safe).toBe(false);
    expect(verdict.categories).toContain("cyberattack");
  });

  it("uses the specified model ID", async () => {
    const chatCompletion = vi.fn().mockResolvedValue({ choices: [{ message: { content: SAFE_JSON } }] });
    const client = { chatCompletion };
    const judge = new HuggingFaceJudge(client, { model: "meta-llama/Meta-Llama-3-8B-Instruct" });
    await judge.evaluate("test");
    expect(chatCompletion.mock.calls[0][0].model).toBe("meta-llama/Meta-Llama-3-8B-Instruct");
  });
});
