import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiGet } from "../../client.js";
import {
  regulationCrosswalk,
  regulationCrosswalkSchema,
} from "../regulation-crosswalk.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P4.8 — Build round: unit tests for `regulation.crosswalk`.
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiGet = vi.mocked(apiGet);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("regulation.crosswalk — happy path", () => {
  it("GETs /api/regulations/crosswalk with source only (target undefined)", async () => {
    mockApiGet.mockResolvedValue(restBody({ success: true, data: [{ id: "cw-001" }] }));

    const result = await regulationCrosswalk({ source: "EU AI Act" });

    expect(mockApiGet).toHaveBeenCalledWith("/api/regulations/crosswalk", {
      source: "EU AI Act",
      target: undefined,
    });
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text)[0].id).toBe("cw-001");
  });

  it("forwards a target framework when provided", async () => {
    mockApiGet.mockResolvedValue(restBody({ success: true, data: [] }));

    await regulationCrosswalk({ source: "EU AI Act", target: "GDPR" });

    expect(mockApiGet).toHaveBeenCalledWith("/api/regulations/crosswalk", {
      source: "EU AI Act",
      target: "GDPR",
    });
  });
});

describe("regulation.crosswalk — error mapping", () => {
  it("maps a REST 400 (unknown source) to isError", async () => {
    mockApiGet.mockResolvedValue(
      restBody({ success: false, error: "Unknown source framework: 'xyz'." }),
    );
    const result = await regulationCrosswalk({ source: "xyz" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("Unknown source framework");
  });

  it("maps a transport failure to isError", async () => {
    mockApiGet.mockRejectedValue(new Error("ENOTFOUND"));
    const result = await regulationCrosswalk({ source: "EU AI Act" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("ENOTFOUND");
  });
});

describe("regulation.crosswalk — schema validation", () => {
  const schema = z.object(regulationCrosswalkSchema);

  it("accepts a source-only payload", () => {
    expect(schema.safeParse({ source: "EU AI Act" }).success).toBe(true);
  });
  it("accepts a source + target payload", () => {
    expect(schema.safeParse({ source: "EU AI Act", target: "GDPR" }).success).toBe(true);
  });
  it("rejects a missing source", () => {
    expect(schema.safeParse({ target: "GDPR" }).success).toBe(false);
  });
  it("rejects an empty source", () => {
    expect(schema.safeParse({ source: "" }).success).toBe(false);
  });
  it("rejects an over-long source (>200 chars)", () => {
    expect(schema.safeParse({ source: "x".repeat(201) }).success).toBe(false);
  });
  it("rejects an over-long target (>200 chars)", () => {
    expect(schema.safeParse({ source: "EU AI Act", target: "y".repeat(201) }).success).toBe(
      false,
    );
  });
});
