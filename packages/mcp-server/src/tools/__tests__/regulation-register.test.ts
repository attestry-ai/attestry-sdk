import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { registerRegulationTools } from "../regulation-register.js";

/**
 * KE2 P4.8 — Build round: execution tests for `registerRegulationTools`.
 * Drives the registrar with a fake MCP server, then invokes the recorded
 * handler adapters — so the four `isError`-propagating adapters (which would
 * otherwise live un-coverable inside `src/index.ts`) are fully exercised.
 *
 * Mirrors the P1.7 `registerEvidencePackLifecycleTools` test: the tools' HTTP
 * layer is exercised via a stubbed `globalThis.fetch` (plus a test API key),
 * so a single fetch stub covers all four tools uniformly.
 */

const ORIG_KEY = process.env.ATTESTRY_API_KEY;
const ORIG_URL = process.env.ATTESTRY_API_URL;

beforeEach(() => {
  process.env.ATTESTRY_API_KEY = "test-key-p48-register";
  process.env.ATTESTRY_API_URL = "https://attestry.test";
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (ORIG_KEY === undefined) delete process.env.ATTESTRY_API_KEY;
  else process.env.ATTESTRY_API_KEY = ORIG_KEY;
  if (ORIG_URL === undefined) delete process.env.ATTESTRY_API_URL;
  else process.env.ATTESTRY_API_URL = ORIG_URL;
});

interface RecordedTool {
  name: string;
  description: string;
  schema: unknown;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
    isError?: boolean;
  }>;
}

/** Fake MCP server that records every `.tool()` registration. */
function makeFakeServer() {
  const tools: RecordedTool[] = [];
  const server = {
    tool: (
      name: string,
      description: string,
      schema: unknown,
      handler: RecordedTool["handler"],
    ) => {
      tools.push({ name, description, schema, handler });
    },
  };
  return { server, tools };
}

/** Minimal valid args per tool, for invoking the recorded handlers. */
const ARGS_BY_TOOL: Record<string, Record<string, unknown>> = {
  attestry_regulation_cite: { framework: "GDPR", identifier: "Art.6" },
  attestry_regulation_crosswalk: { source: "EU AI Act" },
  attestry_regulation_applicability: { geography: "EU" },
  attestry_schedule_deadline: {},
};

/** Stub `globalThis.fetch` so every tool resolves the given JSON body. */
function stubFetch(body: unknown) {
  const mock = vi.fn(() => ({ json: async () => body }));
  vi.stubGlobal("fetch", mock);
  return mock;
}

describe("registerRegulationTools — registration", () => {
  it("registers exactly the four regulation / schedule tools, in order", () => {
    const { server, tools } = makeFakeServer();
    registerRegulationTools(server as never);
    expect(tools.map((t) => t.name)).toEqual([
      "attestry_regulation_cite",
      "attestry_regulation_crosswalk",
      "attestry_regulation_applicability",
      "attestry_schedule_deadline",
    ]);
  });

  it("wires a non-empty description and an object schema for each tool", () => {
    const { server, tools } = makeFakeServer();
    registerRegulationTools(server as never);
    for (const t of tools) {
      expect(typeof t.description).toBe("string");
      expect(t.description.length).toBeGreaterThan(0);
      expect(t.schema).toBeTypeOf("object");
    }
  });
});

describe("registerRegulationTools — handler adapters", () => {
  it("an adapter maps a REST success to a non-error CallToolResult", async () => {
    stubFetch({ success: true, data: { framework: "GDPR", identifier: "Art.6" } });
    const { server, tools } = makeFakeServer();
    registerRegulationTools(server as never);
    const cite = tools.find((t) => t.name === "attestry_regulation_cite")!;

    const result = await cite.handler(ARGS_BY_TOOL[cite.name]);

    expect(result.isError).toBe(false);
    expect(result.content[0].type).toBe("text");
    expect(JSON.parse(result.content[0].text).framework).toBe("GDPR");
  });

  it("an adapter propagates isError:true from a REST failure", async () => {
    stubFetch({ success: false, error: "Unknown source framework: 'xyz'." });
    const { server, tools } = makeFakeServer();
    registerRegulationTools(server as never);
    const crosswalk = tools.find((t) => t.name === "attestry_regulation_crosswalk")!;

    const result = await crosswalk.handler(ARGS_BY_TOOL[crosswalk.name]);

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).error).toContain("Unknown source framework");
  });

  it("every registered handler returns a well-formed CallToolResult", async () => {
    stubFetch({ success: true, data: {} });
    const { server, tools } = makeFakeServer();
    registerRegulationTools(server as never);

    for (const t of tools) {
      const result = await t.handler(ARGS_BY_TOOL[t.name]);
      expect(Array.isArray(result.content)).toBe(true);
      expect(result.content[0].type).toBe("text");
      expect(typeof result.content[0].text).toBe("string");
      expect(typeof result.isError).toBe("boolean");
    }
  });
});
