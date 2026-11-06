import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiGet } from "../../client.js";
import { regulationCite, regulationCiteSchema } from "../regulation-cite.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P4.8 — Build round: unit tests for `regulation.cite`.
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiGet = vi.mocked(apiGet);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("regulation.cite — happy path", () => {
  it("GETs /api/regulations/cite with framework + identifier and returns the citation", async () => {
    mockApiGet.mockResolvedValue(
      restBody({
        success: true,
        data: {
          framework: "GDPR",
          version: "2016/679",
          identifier: "Art.6",
          citation: "General Data Protection Regulation — Art.6",
          requirements: [{ id: "art-6" }],
          content_hash: "sha256:" + "a".repeat(64),
        },
      }),
    );

    const result = await regulationCite({ framework: "gdpr", identifier: "Art.6" });

    expect(mockApiGet).toHaveBeenCalledWith("/api/regulations/cite", {
      framework: "gdpr",
      identifier: "Art.6",
    });
    expect(result.isError).toBe(false);
    const body = JSON.parse(result.text);
    expect(body.framework).toBe("GDPR");
    expect(body.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});

describe("regulation.cite — error mapping", () => {
  it("maps a REST 400 (unknown framework) to isError", async () => {
    mockApiGet.mockResolvedValue(
      restBody({ success: false, error: "Unknown framework: 'xyz'." }),
    );
    const result = await regulationCite({ framework: "xyz", identifier: "Art.6" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("Unknown framework");
  });

  it("maps a transport failure to isError", async () => {
    mockApiGet.mockRejectedValue(new Error("ECONNREFUSED"));
    const result = await regulationCite({ framework: "GDPR", identifier: "Art.6" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("ECONNREFUSED");
  });
});

describe("regulation.cite — schema validation", () => {
  const schema = z.object(regulationCiteSchema);

  it("accepts a valid framework + identifier", () => {
    expect(
      schema.safeParse({ framework: "EU AI Act", identifier: "prohibitedPractices" }).success,
    ).toBe(true);
  });
  it("rejects an empty framework", () => {
    expect(schema.safeParse({ framework: "", identifier: "Art.6" }).success).toBe(false);
  });
  it("rejects an empty identifier", () => {
    expect(schema.safeParse({ framework: "GDPR", identifier: "" }).success).toBe(false);
  });
  it("rejects a missing identifier", () => {
    expect(schema.safeParse({ framework: "GDPR" }).success).toBe(false);
  });
  it("rejects an over-long framework (>200 chars)", () => {
    expect(schema.safeParse({ framework: "x".repeat(201), identifier: "Art.6" }).success).toBe(
      false,
    );
  });
  it("rejects an over-long identifier (>200 chars)", () => {
    expect(schema.safeParse({ framework: "GDPR", identifier: "y".repeat(201) }).success).toBe(
      false,
    );
  });
});
