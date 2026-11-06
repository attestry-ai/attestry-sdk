import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";
import { apiGet } from "../../client.js";
import {
  scheduleDeadline,
  scheduleDeadlineSchema,
} from "../schedule-deadline.js";
import { restBody } from "./_rest-fixtures.js";

/**
 * KE2 P4.8 — Build round: unit tests for `schedule.deadline`.
 */

vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiGet = vi.mocked(apiGet);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("schedule.deadline — happy path", () => {
  it("GETs /api/regulatory-calendar with no filters (all undefined)", async () => {
    mockApiGet.mockResolvedValue(
      restBody({ success: true, data: { deadlines: [], total: 0 } }),
    );

    const result = await scheduleDeadline({});

    expect(mockApiGet).toHaveBeenCalledWith("/api/regulatory-calendar", {
      jurisdiction: undefined,
      framework: undefined,
      status: undefined,
      from: undefined,
      to: undefined,
    });
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text).total).toBe(0);
  });

  it("forwards all filters when provided", async () => {
    mockApiGet.mockResolvedValue(
      restBody({ success: true, data: { deadlines: [{ id: "d1" }], total: 1 } }),
    );

    await scheduleDeadline({
      jurisdiction: "EU",
      framework: "EU AI Act",
      status: "upcoming",
      from: "2026-01-01",
      to: "2026-12-31",
    });

    expect(mockApiGet).toHaveBeenCalledWith("/api/regulatory-calendar", {
      jurisdiction: "EU",
      framework: "EU AI Act",
      status: "upcoming",
      from: "2026-01-01",
      to: "2026-12-31",
    });
  });
});

describe("schedule.deadline — error mapping", () => {
  it("maps a transport failure to isError", async () => {
    mockApiGet.mockRejectedValue(new Error("ECONNRESET"));
    const result = await scheduleDeadline({});
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("ECONNRESET");
  });
});

describe("schedule.deadline — schema validation", () => {
  const schema = z.object(scheduleDeadlineSchema);

  it("accepts an empty payload (all filters optional)", () => {
    expect(schema.safeParse({}).success).toBe(true);
  });
  it("accepts a fully-specified payload", () => {
    expect(
      schema.safeParse({
        jurisdiction: "EU",
        framework: "EU AI Act",
        status: "passed",
        from: "2026-01-01",
        to: "2026-12-31",
      }).success,
    ).toBe(true);
  });
  it("accepts any non-empty status string (free-string filter mirroring the route; DEV-92)", () => {
    expect(schema.safeParse({ status: "upcoming" }).success).toBe(true);
    expect(schema.safeParse({ status: "expired" }).success).toBe(true);
  });
  it("rejects an empty status string", () => {
    expect(schema.safeParse({ status: "" }).success).toBe(false);
  });
  it("rejects an empty jurisdiction", () => {
    expect(schema.safeParse({ jurisdiction: "" }).success).toBe(false);
  });
  it("rejects an over-long framework filter (>200 chars)", () => {
    expect(schema.safeParse({ framework: "x".repeat(201) }).success).toBe(false);
  });
});
