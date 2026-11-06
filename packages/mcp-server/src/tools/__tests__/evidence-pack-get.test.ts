import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiGet } from "../../client.js";
import {
  evidencePackGet,
  evidencePackGetSchema,
} from "../evidence-pack-get.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P1.5 — Build round: unit tests for `evidence_pack.get`.
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiGet = vi.mocked(apiGet);

beforeEach(() => {
  vi.clearAllMocks();
});

const PACK_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

describe("evidence_pack.get — happy path", () => {
  it("gets /api/v1/evidence-packs/{id} and returns {pack, bundles}", async () => {
    mockApiGet.mockResolvedValue(
      restBody({
        success: true,
        data: { pack: { id: PACK_ID, status: "signed" }, bundles: [] },
      }),
    );

    const result = await evidencePackGet({ packId: PACK_ID });

    expect(mockApiGet).toHaveBeenCalledWith(
      `/api/v1/evidence-packs/${PACK_ID}`,
    );
    expect(result.isError).toBe(false);
    const body = JSON.parse(result.text);
    expect(body.pack.id).toBe(PACK_ID);
    expect(body.bundles).toEqual([]);
  });
});

describe("evidence_pack.get — error mapping", () => {
  it("maps a REST 404 to isError with the not_found code", async () => {
    mockApiGet.mockResolvedValue(
      restBody({
        success: false,
        error: "pack not found",
        details: { code: "evidence_pack.not_found" },
      }),
    );

    const result = await evidencePackGet({ packId: PACK_ID });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.error).toBe("pack not found");
    expect(body.code).toBe("evidence_pack.not_found");
  });

  it("maps a REST 5xx internal error to isError", async () => {
    mockApiGet.mockResolvedValue(
      restBody({
        success: false,
        error: "An internal error occurred. Please try again later.",
      }),
    );

    const result = await evidencePackGet({ packId: PACK_ID });

    expect(result.isError).toBe(true);
  });

  it("maps a transport failure to isError", async () => {
    mockApiGet.mockRejectedValue(new Error("ENOTFOUND"));

    const result = await evidencePackGet({ packId: PACK_ID });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("ENOTFOUND");
  });
});

describe("evidence_pack.get — schema validation", () => {
  const schema = z.object(evidencePackGetSchema);

  it("accepts a valid UUID packId", () => {
    expect(schema.safeParse({ packId: PACK_ID }).success).toBe(true);
  });

  it("rejects a non-UUID packId (UUID pre-check)", () => {
    expect(schema.safeParse({ packId: "not-a-uuid" }).success).toBe(false);
  });

  it("lowercases an uppercase packId at the SDK boundary", () => {
    const parsed = schema.safeParse({
      packId: "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.packId).toBe(PACK_ID);
    }
  });
});
