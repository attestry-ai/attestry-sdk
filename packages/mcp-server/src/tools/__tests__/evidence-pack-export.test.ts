import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiGet, type ApiResponse } from "../../client.js";
import {
  evidencePackExport,
  evidencePackExportSchema,
} from "../evidence-pack-export.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P1.7 — Build round: unit tests for `evidence_pack.export`.
 *
 * The export route's success body is the RAW JSON artifact, not the standard
 * `{success, data}` envelope (DEV-53); these tests pin both the artifact
 * pass-through and the `{success:false}` error discrimination.
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

/** A representative kernel JSON export artifact (DEV-53 — NOT an envelope). */
const ARTIFACT = {
  export: {
    format: "json",
    generatedAt: "2026-05-17T00:00:00.000Z",
    schemaVersion: "evidence-pack-export.v1",
  },
  pack: { id: PACK_ID, status: "signed" },
  bundles: [{ id: "bundle-1" }],
};

describe("evidence_pack.export — happy path", () => {
  it("GETs /{id}/export with format=json and returns the raw artifact", async () => {
    mockApiGet.mockResolvedValue(ARTIFACT as unknown as ApiResponse<unknown>);

    const result = await evidencePackExport({ packId: PACK_ID });

    expect(mockApiGet).toHaveBeenCalledWith(
      `/api/v1/evidence-packs/${PACK_ID}/export`,
      { format: "json" },
    );
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text)).toEqual(ARTIFACT);
  });
});

describe("evidence_pack.export — error mapping", () => {
  it("maps a {success:false} error envelope, surfacing details.code", async () => {
    mockApiGet.mockResolvedValue(
      restBody({
        success: false,
        error: "pack not found",
        details: { code: "evidence_pack.not_found" },
      }),
    );

    const result = await evidencePackExport({ packId: PACK_ID });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.error).toBe("pack not found");
    expect(body.code).toBe("evidence_pack.not_found");
  });

  it("maps a {success:false} envelope with no error/details to a fallback isError", async () => {
    mockApiGet.mockResolvedValue(restBody({ success: false }));

    const result = await evidencePackExport({ packId: PACK_ID });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.error).toBe("Failed to export evidence pack.");
    expect(body.code).toBeUndefined();
  });

  it("maps a transport failure to isError", async () => {
    mockApiGet.mockRejectedValue(new Error("connection reset"));

    const result = await evidencePackExport({ packId: PACK_ID });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("connection reset");
  });

  it("maps a literal-null response body to isError", async () => {
    mockApiGet.mockResolvedValue(null as unknown as ApiResponse<unknown>);

    const result = await evidencePackExport({ packId: PACK_ID });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toBe(
      "Failed to export evidence pack.",
    );
  });

  it("maps a non-object response body to isError", async () => {
    mockApiGet.mockResolvedValue(42 as unknown as ApiResponse<unknown>);

    const result = await evidencePackExport({ packId: PACK_ID });

    expect(result.isError).toBe(true);
  });
});

describe("evidence_pack.export — schema validation", () => {
  const schema = z.object(evidencePackExportSchema);

  it("accepts a valid packId", () => {
    expect(schema.safeParse({ packId: PACK_ID }).success).toBe(true);
  });

  it("rejects a non-UUID packId", () => {
    expect(schema.safeParse({ packId: "not-a-uuid" }).success).toBe(false);
  });

  it("exposes only `packId` — no `format` argument (DQ-3)", () => {
    expect(Object.keys(evidencePackExportSchema)).toEqual(["packId"]);
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
