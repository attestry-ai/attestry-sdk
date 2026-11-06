import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiGet } from "../../client.js";
import {
  evidencePackList,
  evidencePackListSchema,
} from "../evidence-pack-list.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P1.5 — Build round: unit tests for `evidence_pack.list`.
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiGet = vi.mocked(apiGet);

beforeEach(() => {
  vi.clearAllMocks();
});

const SYSTEM_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

describe("evidence_pack.list — happy path", () => {
  it("gets /api/v1/evidence-packs and returns {items, nextCursor}", async () => {
    mockApiGet.mockResolvedValue(
      restBody({
        success: true,
        data: { items: [{ id: "pack-1" }], nextCursor: "cursor-abc" },
      }),
    );

    const result = await evidencePackList({});

    expect(mockApiGet).toHaveBeenCalledWith("/api/v1/evidence-packs", {
      systemId: undefined,
      packType: undefined,
      status: undefined,
      limit: undefined,
      cursor: undefined,
    });
    expect(result.isError).toBe(false);
    const body = JSON.parse(result.text);
    expect(body.items).toHaveLength(1);
    expect(body.nextCursor).toBe("cursor-abc");
  });

  it("forwards every filter, stringifying limit", async () => {
    mockApiGet.mockResolvedValue(
      restBody({ success: true, data: { items: [], nextCursor: null } }),
    );

    await evidencePackList({
      systemId: SYSTEM_ID,
      packType: "annex_iv",
      status: "signed",
      limit: 25,
      cursor: "cursor-xyz",
    });

    expect(mockApiGet).toHaveBeenCalledWith("/api/v1/evidence-packs", {
      systemId: SYSTEM_ID,
      packType: "annex_iv",
      status: "signed",
      limit: "25",
      cursor: "cursor-xyz",
    });
  });
});

describe("evidence_pack.list — error mapping", () => {
  it("maps a REST 400 invalid-cursor error to isError", async () => {
    mockApiGet.mockResolvedValue(
      restBody({
        success: false,
        error: "Malformed pagination cursor.",
        details: { code: "evidence_pack.invalid_cursor" },
      }),
    );

    const result = await evidencePackList({ cursor: "garbage" });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).code).toBe("evidence_pack.invalid_cursor");
  });

  it("maps a transport failure to isError", async () => {
    mockApiGet.mockRejectedValue(new Error("socket hang up"));

    const result = await evidencePackList({});

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("socket hang up");
  });
});

describe("evidence_pack.list — schema validation", () => {
  const schema = z.object(evidencePackListSchema);

  it("accepts an empty input (all filters optional)", () => {
    expect(schema.safeParse({}).success).toBe(true);
  });

  it("accepts a valid status enum value", () => {
    expect(schema.safeParse({ status: "signed" }).success).toBe(true);
  });

  it("rejects an unknown packType (closed-enum pre-rejection)", () => {
    expect(schema.safeParse({ packType: "bogus" }).success).toBe(false);
  });

  it("rejects an unknown status (closed-enum pre-rejection)", () => {
    expect(schema.safeParse({ status: "archived" }).success).toBe(false);
  });

  it("rejects limit below 1", () => {
    expect(schema.safeParse({ limit: -1 }).success).toBe(false);
    expect(schema.safeParse({ limit: 0 }).success).toBe(false);
  });

  it("rejects limit above 200", () => {
    expect(schema.safeParse({ limit: 500 }).success).toBe(false);
  });

  it("accepts limit within 1-200", () => {
    expect(schema.safeParse({ limit: 50 }).success).toBe(true);
  });

  it("rejects a non-UUID systemId", () => {
    expect(schema.safeParse({ systemId: "nope" }).success).toBe(false);
  });
});
