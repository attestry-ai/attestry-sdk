import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiPost } from "../../client.js";
import {
  evidencePackRevoke,
  evidencePackRevokeSchema,
} from "../evidence-pack-revoke.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P1.7 — Build round: unit tests for `evidence_pack.revoke`.
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiPost = vi.mocked(apiPost);

beforeEach(() => {
  vi.clearAllMocks();
});

const PACK_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

describe("evidence_pack.revoke — happy path", () => {
  it("posts to /{id}/revoke with an empty body and returns the revoked pack", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: true, data: { id: PACK_ID, status: "revoked" } }),
    );

    const result = await evidencePackRevoke({ packId: PACK_ID, confirm: true });

    expect(mockApiPost).toHaveBeenCalledWith(
      `/api/v1/evidence-packs/${PACK_ID}/revoke`,
      {},
    );
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text).status).toBe("revoked");
  });

  it("forwards reason when present", async () => {
    mockApiPost.mockResolvedValue(restBody({ success: true, data: {} }));

    await evidencePackRevoke({
      packId: PACK_ID,
      reason: "superseded by a corrected pack",
      confirm: true,
    });

    expect(mockApiPost).toHaveBeenCalledWith(
      `/api/v1/evidence-packs/${PACK_ID}/revoke`,
      { reason: "superseded by a corrected pack" },
    );
  });

  it("never forwards `confirm` in the REST body (MCP-layer-only gate)", async () => {
    mockApiPost.mockResolvedValue(restBody({ success: true, data: {} }));

    await evidencePackRevoke({ packId: PACK_ID, reason: "r", confirm: true });

    const body = mockApiPost.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(body).not.toHaveProperty("confirm");
    expect(Object.keys(body)).toEqual(["reason"]);
  });
});

describe("evidence_pack.revoke — error mapping", () => {
  it("maps a 409 invalid-state error (pack not signed), surfacing currentStatus", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: false,
        error: "pack is in 'draft' state; only signed packs can be revoked",
        details: {
          code: "evidence_pack.invalid_state",
          currentStatus: "draft",
        },
      }),
    );

    const result = await evidencePackRevoke({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.code).toBe("evidence_pack.invalid_state");
    expect(body.details.currentStatus).toBe("draft");
  });

  it("maps a 403 auth error to a clean isError", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: false, error: "Forbidden: admin role required" }),
    );

    const result = await evidencePackRevoke({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("Forbidden");
  });

  it("maps a transport failure to isError", async () => {
    mockApiPost.mockRejectedValue(new Error("socket hang up"));

    const result = await evidencePackRevoke({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("socket hang up");
  });
});

describe("evidence_pack.revoke — schema validation", () => {
  const schema = z.object(evidencePackRevokeSchema);

  it("accepts a minimal valid input (packId + confirm)", () => {
    expect(schema.safeParse({ packId: PACK_ID, confirm: true }).success).toBe(
      true,
    );
  });

  it("rejects a missing confirm", () => {
    expect(schema.safeParse({ packId: PACK_ID }).success).toBe(false);
  });

  it("rejects confirm: false", () => {
    expect(
      schema.safeParse({ packId: PACK_ID, confirm: false }).success,
    ).toBe(false);
  });

  it("rejects an empty-string reason (kernel min(1))", () => {
    expect(
      schema.safeParse({ packId: PACK_ID, reason: "", confirm: true }).success,
    ).toBe(false);
  });

  it("rejects a non-UUID packId", () => {
    expect(
      schema.safeParse({ packId: "not-a-uuid", confirm: true }).success,
    ).toBe(false);
  });

  it("lowercases an uppercase packId at the SDK boundary", () => {
    const parsed = schema.safeParse({
      packId: "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
      confirm: true,
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.packId).toBe(PACK_ID);
    }
  });
});
