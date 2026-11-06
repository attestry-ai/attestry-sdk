import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiPost } from "../../client.js";
import {
  evidencePackSign,
  evidencePackSignSchema,
} from "../evidence-pack-sign.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P1.7 — Build round: unit tests for `evidence_pack.sign`.
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
const CERT_ID = "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e";

describe("evidence_pack.sign — happy path", () => {
  it("posts to /{id}/sign with an empty body and returns the signed pack", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: true, data: { id: PACK_ID, status: "signed" } }),
    );

    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });

    expect(mockApiPost).toHaveBeenCalledWith(
      `/api/v1/evidence-packs/${PACK_ID}/sign`,
      {},
    );
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text).status).toBe("signed");
  });

  it("forwards attestationCertificateId when present", async () => {
    mockApiPost.mockResolvedValue(restBody({ success: true, data: {} }));

    await evidencePackSign({
      packId: PACK_ID,
      attestationCertificateId: CERT_ID,
      confirm: true,
    });

    expect(mockApiPost).toHaveBeenCalledWith(
      `/api/v1/evidence-packs/${PACK_ID}/sign`,
      { attestationCertificateId: CERT_ID },
    );
  });

  it("never forwards `confirm` in the REST body (MCP-layer-only gate)", async () => {
    mockApiPost.mockResolvedValue(restBody({ success: true, data: {} }));

    await evidencePackSign({
      packId: PACK_ID,
      attestationCertificateId: CERT_ID,
      confirm: true,
    });

    const body = mockApiPost.mock.calls[0]?.[1] as Record<string, unknown>;
    expect(body).not.toHaveProperty("confirm");
    expect(Object.keys(body)).toEqual(["attestationCertificateId"]);
  });
});

describe("evidence_pack.sign — error mapping", () => {
  it("maps a 409 EmptyPackError, surfacing details.code", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: false,
        error: "pack has no bundles; cannot sign an empty pack",
        details: { code: "evidence_pack.empty" },
      }),
    );

    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).code).toBe("evidence_pack.empty");
  });

  it("maps a 409 invalid-state error, surfacing currentStatus", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: false,
        error: "pack is already signed",
        details: {
          code: "evidence_pack.invalid_state",
          currentStatus: "signed",
        },
      }),
    );

    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.code).toBe("evidence_pack.invalid_state");
    expect(body.details.currentStatus).toBe("signed");
  });

  it("maps a 403 auth error (no details.code) to a clean isError", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: false, error: "Forbidden: admin role required" }),
    );

    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.error).toBe("Forbidden: admin role required");
    expect(body.code).toBeUndefined();
  });

  it("maps a transport failure to isError", async () => {
    mockApiPost.mockRejectedValue(new Error("connection reset"));

    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("connection reset");
  });
});

describe("evidence_pack.sign — schema validation", () => {
  const schema = z.object(evidencePackSignSchema);

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

  it("rejects confirm: 'true' (string, not boolean)", () => {
    expect(
      schema.safeParse({ packId: PACK_ID, confirm: "true" }).success,
    ).toBe(false);
  });

  it("rejects a non-UUID packId", () => {
    expect(
      schema.safeParse({ packId: "not-a-uuid", confirm: true }).success,
    ).toBe(false);
  });

  it("rejects a non-UUID attestationCertificateId", () => {
    expect(
      schema.safeParse({
        packId: PACK_ID,
        attestationCertificateId: "nope",
        confirm: true,
      }).success,
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
