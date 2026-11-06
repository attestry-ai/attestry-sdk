import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiPost } from "../../client.js";
import {
  evidencePackCreate,
  evidencePackCreateSchema,
} from "../evidence-pack-create.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P1.5 — Build round: unit tests for `evidence_pack.create`.
 * `../../client.js` is mocked so `apiPost` never performs real HTTP; the
 * shared `callRest` / `outcomeToResult` logic runs for real.
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiPost = vi.mocked(apiPost);

beforeEach(() => {
  vi.clearAllMocks();
});

const SYSTEM_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

describe("evidence_pack.create — happy path", () => {
  it("posts to /api/v1/evidence-packs and returns the created pack", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: true,
        data: { id: "pack-1", packType: "annex_iv", status: "draft" },
      }),
    );

    const result = await evidencePackCreate({ packType: "annex_iv" });

    expect(mockApiPost).toHaveBeenCalledWith("/api/v1/evidence-packs", {
      packType: "annex_iv",
    });
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text)).toEqual({
      id: "pack-1",
      packType: "annex_iv",
      status: "draft",
    });
  });

  it("forwards every optional field when present", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: true, data: { id: "pack-2" } }),
    );

    await evidencePackCreate({
      packType: "red_team_cycle",
      systemId: SYSTEM_ID,
      frameworkBindings: [{ framework: "eu_ai_act", identifier: "art-11" }],
      metadata: { campaign: "q2" },
    });

    expect(mockApiPost).toHaveBeenCalledWith("/api/v1/evidence-packs", {
      packType: "red_team_cycle",
      systemId: SYSTEM_ID,
      frameworkBindings: [{ framework: "eu_ai_act", identifier: "art-11" }],
      metadata: { campaign: "q2" },
    });
  });

  it("omits optional fields entirely when absent", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: true, data: { id: "pack-3" } }),
    );

    await evidencePackCreate({ packType: "pccp_evidence" });

    const body = mockApiPost.mock.calls[0]?.[1];
    expect(body).toEqual({ packType: "pccp_evidence" });
    expect(Object.keys(body as object)).toEqual(["packType"]);
  });
});

describe("evidence_pack.create — error mapping", () => {
  it("maps a REST 4xx validation error to isError with code", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: false,
        error: "Validation failed.",
        details: {
          code: "evidence_pack.validation_failed",
          issues: [{ path: "packType", message: "Invalid enum value" }],
        },
      }),
    );

    const result = await evidencePackCreate({ packType: "annex_iv" });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.error).toBe("Validation failed.");
    expect(body.code).toBe("evidence_pack.validation_failed");
  });

  it("maps a REST 5xx internal error to isError", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: false,
        error: "An internal error occurred. Please try again later.",
      }),
    );

    const result = await evidencePackCreate({ packType: "annex_iv" });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("internal error");
  });

  it("maps a transport failure to isError", async () => {
    mockApiPost.mockRejectedValue(new Error("fetch failed"));

    const result = await evidencePackCreate({ packType: "annex_iv" });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("fetch failed");
  });
});

describe("evidence_pack.create — schema validation", () => {
  const schema = z.object(evidencePackCreateSchema);

  it("accepts a minimal valid input", () => {
    expect(schema.safeParse({ packType: "annex_iv" }).success).toBe(true);
  });

  it("rejects an unknown packType (closed-enum pre-rejection)", () => {
    expect(schema.safeParse({ packType: "not_a_type" }).success).toBe(false);
  });

  it("rejects a non-UUID systemId (UUID pre-check)", () => {
    expect(
      schema.safeParse({ packType: "annex_iv", systemId: "xyz" }).success,
    ).toBe(false);
  });

  it("lowercases an uppercase systemId at the SDK boundary", () => {
    const parsed = schema.safeParse({
      packType: "annex_iv",
      systemId: "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.systemId).toBe(SYSTEM_ID);
    }
  });
});
