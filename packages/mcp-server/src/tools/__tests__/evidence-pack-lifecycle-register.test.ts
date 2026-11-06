import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { registerEvidencePackLifecycleTools } from "../evidence-pack-lifecycle-register.js";

/**
 * KE2 P1.7 — Build round: execution tests for
 * `registerEvidencePackLifecycleTools`. Drives the registrar with a fake
 * MCP server, then invokes the recorded handler adapters — so the four
 * `isError`-propagating adapters (which would otherwise live un-coverable
 * inside `src/index.ts`) are fully exercised.
 *
 * The P1.7 tools' HTTP layer is exercised via a stubbed `globalThis.fetch`
 * (plus a test API key) rather than a mocked `client.js`: the supersede tool
 * issues its own header-bearing fetch, so a single fetch stub covers all
 * four tools uniformly (DEV-58).
 */

const PACK_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const ORIG_KEY = process.env.ATTESTRY_API_KEY;
const ORIG_URL = process.env.ATTESTRY_API_URL;

beforeEach(() => {
  process.env.ATTESTRY_API_KEY = "test-key-p17-register";
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
  attestry_evidence_pack_sign: { packId: PACK_ID, confirm: true },
  attestry_evidence_pack_supersede: {
    oldPackId: PACK_ID,
    newPack: { packType: "annex_iv" },
  },
  attestry_evidence_pack_revoke: { packId: PACK_ID, confirm: true },
  attestry_evidence_pack_export: { packId: PACK_ID },
};

/** Stub `globalThis.fetch` so every tool resolves the given JSON body. */
function stubFetch(body: unknown) {
  const mock = vi.fn(() => ({ json: async () => body }));
  vi.stubGlobal("fetch", mock);
  return mock;
}

describe("registerEvidencePackLifecycleTools — registration", () => {
  it("registers exactly the four lifecycle tools, in order", () => {
    const { server, tools } = makeFakeServer();
    registerEvidencePackLifecycleTools(server as never);
    expect(tools.map((t) => t.name)).toEqual([
      "attestry_evidence_pack_sign",
      "attestry_evidence_pack_supersede",
      "attestry_evidence_pack_revoke",
      "attestry_evidence_pack_export",
    ]);
  });

  it("wires a non-empty description and an object schema for each tool", () => {
    const { server, tools } = makeFakeServer();
    registerEvidencePackLifecycleTools(server as never);
    for (const t of tools) {
      expect(typeof t.description).toBe("string");
      expect(t.description.length).toBeGreaterThan(0);
      expect(t.schema).toBeTypeOf("object");
    }
  });
});

describe("registerEvidencePackLifecycleTools — handler adapters", () => {
  it("an adapter maps a REST success to a non-error CallToolResult", async () => {
    stubFetch({ success: true, data: { id: "pack-1", status: "signed" } });
    const { server, tools } = makeFakeServer();
    registerEvidencePackLifecycleTools(server as never);
    const sign = tools.find((t) => t.name === "attestry_evidence_pack_sign")!;

    const result = await sign.handler({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(false);
    expect(result.content[0].type).toBe("text");
    expect(JSON.parse(result.content[0].text).status).toBe("signed");
  });

  it("an adapter propagates isError:true from a REST failure", async () => {
    stubFetch({
      success: false,
      error: "pack not found",
      details: { code: "evidence_pack.not_found" },
    });
    const { server, tools } = makeFakeServer();
    registerEvidencePackLifecycleTools(server as never);
    const revoke = tools.find(
      (t) => t.name === "attestry_evidence_pack_revoke",
    )!;

    const result = await revoke.handler({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).code).toBe(
      "evidence_pack.not_found",
    );
  });

  it("every registered handler returns a well-formed CallToolResult", async () => {
    stubFetch({ success: true, data: {} });
    const { server, tools } = makeFakeServer();
    registerEvidencePackLifecycleTools(server as never);

    for (const t of tools) {
      const result = await t.handler(ARGS_BY_TOOL[t.name]);
      expect(Array.isArray(result.content)).toBe(true);
      expect(result.content[0].type).toBe("text");
      expect(typeof result.content[0].text).toBe("string");
      expect(typeof result.isError).toBe("boolean");
    }
  });
});
