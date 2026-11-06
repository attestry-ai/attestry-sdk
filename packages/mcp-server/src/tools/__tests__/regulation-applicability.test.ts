import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiGet } from "../../client.js";
import {
  regulationApplicability,
  regulationApplicabilitySchema,
} from "../regulation-applicability.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P4.8 — Build round: unit tests for `regulation.applicability`.
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiGet = vi.mocked(apiGet);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("regulation.applicability — happy path", () => {
  it("GETs /api/regulations/applicability with geography only (systemType undefined)", async () => {
    mockApiGet.mockResolvedValue(
      restBody({ success: true, data: [{ framework: "EU AI Act" }] }),
    );

    const result = await regulationApplicability({ geography: "Germany" });

    expect(mockApiGet).toHaveBeenCalledWith("/api/regulations/applicability", {
      geography: "Germany",
      systemType: undefined,
    });
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text)[0].framework).toBe("EU AI Act");
  });

  it("forwards systemType when provided", async () => {
    mockApiGet.mockResolvedValue(restBody({ success: true, data: [] }));

    await regulationApplicability({ geography: "US", systemType: "gpai" });

    expect(mockApiGet).toHaveBeenCalledWith("/api/regulations/applicability", {
      geography: "US",
      systemType: "gpai",
    });
  });
});

describe("regulation.applicability — error mapping", () => {
  it("maps a transport failure to isError", async () => {
    mockApiGet.mockRejectedValue(new Error("ETIMEDOUT"));
    const result = await regulationApplicability({ geography: "EU" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("ETIMEDOUT");
  });

  it("maps a malformed (non-envelope) REST body to isError", async () => {
    mockApiGet.mockResolvedValue(restBody({}));
    const result = await regulationApplicability({ geography: "EU" });
    expect(result.isError).toBe(true);
  });
});

describe("regulation.applicability — schema validation", () => {
  const schema = z.object(regulationApplicabilitySchema);

  it("accepts a geography-only payload", () => {
    expect(schema.safeParse({ geography: "EU" }).success).toBe(true);
  });
  it("accepts a geography + systemType payload", () => {
    expect(schema.safeParse({ geography: "EU", systemType: "high-risk" }).success).toBe(true);
  });
  it("rejects a missing geography", () => {
    expect(schema.safeParse({ systemType: "gpai" }).success).toBe(false);
  });
  it("rejects an empty geography", () => {
    expect(schema.safeParse({ geography: "" }).success).toBe(false);
  });
  it("rejects an over-long geography (>200 chars)", () => {
    expect(schema.safeParse({ geography: "x".repeat(201) }).success).toBe(false);
  });
  it("rejects an over-long systemType (>200 chars)", () => {
    expect(schema.safeParse({ geography: "EU", systemType: "y".repeat(201) }).success).toBe(
      false,
    );
  });
});
