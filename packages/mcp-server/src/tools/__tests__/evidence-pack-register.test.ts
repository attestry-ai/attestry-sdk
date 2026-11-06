import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiGet, apiPost } from "../../client.js";
import { registerEvidencePackTools } from "../evidence-pack-register.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P1.5 — Coverage round: execution tests for `registerEvidencePackTools`.
 * Drives the registrar with a fake MCP server, then invokes the recorded
 * handler adapters — so the four `isError`-propagating adapters (which used
 * to live un-coverable inside `src/index.ts`) are fully exercised (DEV-49).
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiGet = vi.mocked(apiGet);
const mockApiPost = vi.mocked(apiPost);

const PACK_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

interface RecordedTool {
  name: string;
  description: string;
  schema: unknown;
  handler: (
    args: Record<string, unknown>,
  ) => Promise<{
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
  attestry_evidence_pack_create: { packType: "annex_iv" },
  attestry_evidence_pack_get: { packId: PACK_ID },
  attestry_evidence_pack_list: {},
  attestry_evidence_pack_append_bundle: {
    packId: PACK_ID,
    traceContent: [],
    inputsHash: "h1",
    outputsHash: "h2",
  },
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("registerEvidencePackTools — registration", () => {
  it("registers exactly the four evidence-pack tools, in order", () => {
    const { server, tools } = makeFakeServer();
    registerEvidencePackTools(server as never);
    expect(tools.map((t) => t.name)).toEqual([
      "attestry_evidence_pack_create",
      "attestry_evidence_pack_get",
      "attestry_evidence_pack_list",
      "attestry_evidence_pack_append_bundle",
    ]);
  });

  it("wires a non-empty description and an object schema for each tool", () => {
    const { server, tools } = makeFakeServer();
    registerEvidencePackTools(server as never);
    for (const t of tools) {
      expect(typeof t.description).toBe("string");
      expect(t.description.length).toBeGreaterThan(0);
      expect(t.schema).toBeTypeOf("object");
    }
  });
});

describe("registerEvidencePackTools — handler adapters", () => {
  it("create adapter maps a REST success to a non-error CallToolResult", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: true, data: { id: "pack-1" } }),
    );
    const { server, tools } = makeFakeServer();
    registerEvidencePackTools(server as never);
    const create = tools.find(
      (t) => t.name === "attestry_evidence_pack_create",
    )!;

    const result = await create.handler({ packType: "annex_iv" });

    expect(result.isError).toBe(false);
    expect(result.content[0].type).toBe("text");
    expect(JSON.parse(result.content[0].text)).toEqual({ id: "pack-1" });
  });

  it("get adapter propagates isError:true from a REST failure", async () => {
    mockApiGet.mockResolvedValue(
      restBody({
        success: false,
        error: "pack not found",
        details: { code: "evidence_pack.not_found" },
      }),
    );
    const { server, tools } = makeFakeServer();
    registerEvidencePackTools(server as never);
    const get = tools.find((t) => t.name === "attestry_evidence_pack_get")!;

    const result = await get.handler({ packId: PACK_ID });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).code).toBe(
      "evidence_pack.not_found",
    );
  });

  it("every registered handler returns a well-formed CallToolResult", async () => {
    mockApiGet.mockResolvedValue(restBody({ success: true, data: {} }));
    mockApiPost.mockResolvedValue(restBody({ success: true, data: {} }));
    const { server, tools } = makeFakeServer();
    registerEvidencePackTools(server as never);

    for (const t of tools) {
      const result = await t.handler(ARGS_BY_TOOL[t.name]);
      expect(Array.isArray(result.content)).toBe(true);
      expect(result.content[0].type).toBe("text");
      expect(typeof result.content[0].text).toBe("string");
      expect(typeof result.isError).toBe("boolean");
    }
  });
});
