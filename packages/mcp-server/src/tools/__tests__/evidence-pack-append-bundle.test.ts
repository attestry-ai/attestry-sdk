import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiPost } from "../../client.js";
import {
  evidencePackAppendBundle,
  evidencePackAppendBundleSchema,
} from "../evidence-pack-append-bundle.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P1.5 — Build round: unit tests for `evidence_pack.append_bundle`.
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
const TRACE = [{ action: "invoke", timestamp: "2026-05-17T00:00:00.000Z" }];

describe("evidence_pack.append_bundle — happy path", () => {
  it("posts to /{id}/bundles and returns {bundle, pack, hashCollision}", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: true,
        data: {
          bundle: { id: "bundle-1" },
          pack: { id: PACK_ID },
          hashCollision: { detected: false, count: 0, collidingBundleIds: [] },
        },
      }),
    );

    const result = await evidencePackAppendBundle({
      packId: PACK_ID,
      traceContent: TRACE,
      inputsHash: "sha256:aaa",
      outputsHash: "sha256:bbb",
    });

    expect(mockApiPost).toHaveBeenCalledWith(
      `/api/v1/evidence-packs/${PACK_ID}/bundles`,
      {
        traceContent: TRACE,
        inputsHash: "sha256:aaa",
        outputsHash: "sha256:bbb",
      },
    );
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text).bundle.id).toBe("bundle-1");
  });

  it("forwards every optional field when present", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: true, data: { bundle: {} } }),
    );

    await evidencePackAppendBundle({
      packId: PACK_ID,
      traceContent: TRACE,
      inputsHash: "h1",
      outputsHash: "h2",
      modelBehaviorLog: { model: "claude", version: "4.7" },
      corroborationResults: { checks: 3 },
      storageUri: "https://storage.example.com/blob",
      metadata: { run: "r1" },
    });

    expect(mockApiPost).toHaveBeenCalledWith(
      `/api/v1/evidence-packs/${PACK_ID}/bundles`,
      {
        traceContent: TRACE,
        inputsHash: "h1",
        outputsHash: "h2",
        modelBehaviorLog: { model: "claude", version: "4.7" },
        corroborationResults: { checks: 3 },
        storageUri: "https://storage.example.com/blob",
        metadata: { run: "r1" },
      },
    );
  });

  it("omits optional fields entirely when absent", async () => {
    mockApiPost.mockResolvedValue(
      restBody({ success: true, data: { bundle: {} } }),
    );

    await evidencePackAppendBundle({
      packId: PACK_ID,
      traceContent: TRACE,
      inputsHash: "h1",
      outputsHash: "h2",
    });

    const body = mockApiPost.mock.calls[0]?.[1] as object;
    expect(Object.keys(body).sort()).toEqual([
      "inputsHash",
      "outputsHash",
      "traceContent",
    ]);
  });
});

describe("evidence_pack.append_bundle — error mapping", () => {
  it("maps a REST 409 invalid-state error, surfacing currentStatus", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: false,
        error: "Cannot append a bundle to a signed pack.",
        details: {
          code: "evidence_pack.invalid_state",
          currentStatus: "signed",
        },
      }),
    );

    const result = await evidencePackAppendBundle({
      packId: PACK_ID,
      traceContent: TRACE,
      inputsHash: "h1",
      outputsHash: "h2",
    });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.code).toBe("evidence_pack.invalid_state");
    expect(body.details.currentStatus).toBe("signed");
  });

  it("maps a REST 5xx internal error to isError", async () => {
    mockApiPost.mockResolvedValue(
      restBody({
        success: false,
        error: "An internal error occurred. Please try again later.",
      }),
    );

    const result = await evidencePackAppendBundle({
      packId: PACK_ID,
      traceContent: TRACE,
      inputsHash: "h1",
      outputsHash: "h2",
    });

    expect(result.isError).toBe(true);
  });

  it("maps a transport failure to isError", async () => {
    mockApiPost.mockRejectedValue(new Error("connection reset"));

    const result = await evidencePackAppendBundle({
      packId: PACK_ID,
      traceContent: TRACE,
      inputsHash: "h1",
      outputsHash: "h2",
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("connection reset");
  });
});

describe("evidence_pack.append_bundle — schema validation", () => {
  const schema = z.object(evidencePackAppendBundleSchema);

  it("accepts a minimal valid input", () => {
    expect(
      schema.safeParse({
        packId: PACK_ID,
        traceContent: TRACE,
        inputsHash: "h1",
        outputsHash: "h2",
      }).success,
    ).toBe(true);
  });

  it("rejects a non-UUID packId (UUID pre-check)", () => {
    expect(
      schema.safeParse({
        packId: "not-a-uuid",
        traceContent: TRACE,
        inputsHash: "h1",
        outputsHash: "h2",
      }).success,
    ).toBe(false);
  });

  it("rejects an empty inputsHash or outputsHash (F-HR-1; kernel min(1))", () => {
    expect(
      schema.safeParse({
        packId: PACK_ID,
        traceContent: TRACE,
        inputsHash: "",
        outputsHash: "h2",
      }).success,
    ).toBe(false);
    expect(
      schema.safeParse({
        packId: PACK_ID,
        traceContent: TRACE,
        inputsHash: "h1",
        outputsHash: "",
      }).success,
    ).toBe(false);
  });

  it("rejects a storageUri that is not a URL", () => {
    expect(
      schema.safeParse({
        packId: PACK_ID,
        traceContent: TRACE,
        inputsHash: "h1",
        outputsHash: "h2",
        storageUri: "not a url",
      }).success,
    ).toBe(false);
  });

  it("lowercases an uppercase packId at the SDK boundary", () => {
    const parsed = schema.safeParse({
      packId: "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
      traceContent: TRACE,
      inputsHash: "h1",
      outputsHash: "h2",
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.packId).toBe(PACK_ID);
    }
  });
});
