import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  BatchSubmitInput,
  BatchSubmitResponse,
  BatchSystemResult,
  BatchConfig,
} from "../batch.js";
import type { FetchLike } from "../../types.js";

// ─── batch.submit — POST + JSON body, sync request/response ─────────────────
//
// Wire shape (from src/app/api/v1/batch/route.ts):
//   POST /api/v1/batch
//   Content-Type: application/json
//   Body: {jobType: "classify" | "assess" | "classify_and_assess",
//          systemIds: <UUID>[] (1-50),
//          config?: {frameworks?: string[] (≤20, each 1-100)}}
//   → 10-field response with per-row results envelope:
//     {id, jobType, status: "completed"|"failed", totalSystems,
//      processedSystems, failedSystems, results: BatchSystemResult[],
//      createdAt, startedAt: string|null, completedAt}
//
// Sixth non-decisions resource. First SDK resource with ASYMMETRIC
// auth between methods on the same resource (POST needs CLASSIFY +
// WRITE_ASSESSMENTS union; GET needs only READ_ASSESSMENTS). First
// SDK route to use a WRITE-side union auth pair. First SDK route
// with a plan-guard 403 surface distinct from the permission 403.
//
// **Multi-permission UNION auth** (carry-forward #45/#54) — kernel
// uses `requireApiKeyWithPermission(req, CLASSIFY, WRITE_ASSESSMENTS)`
// which is `Array.some()`-based. A key with EITHER permission
// succeeds; 403 fires only when the key has NEITHER. Single 403
// test case (the union-auth pattern collapses 3 intuition-suggesting
// cases to 1).
//
// **NEW plan-guard 403 surface** (carry-forward #55 candidate) —
// `requirePlan(org, "hasBatchProcessing")` at route.ts:67 fires
// BEFORE Zod body parsing. The kernel emits `PlanLimitError` →
// 403 with the literal wording 'The "hasBatchProcessing" feature
// is not available on your current plan (<plan>). Please upgrade to
// access this feature.' Distinct from the permission-403's
// 'API key lacks required permission...' wording. SDK surfaces both
// uniformly as AttestryAPIError(403); consumers regex-match the
// message contents to distinguish.
//
// **THIRD SDK route to PRE-VALIDATE every Zod closed-spec rule
// synchronously** (after check.run + gate.evaluate). The SDK
// pre-validates: jobType membership in BATCH_JOB_TYPES, systemIds
// array length [1, 50] + per-element UUID format, config.frameworks
// array length ≤20 + per-element string length [1, 100]. Invariants
// #41 + #49 carry-forward.
//
// **Closed-enum `jobType`** — invariant #41 carry-forward; SDK
// pre-rejects unknown values with TypeError listing the valid set.
//
// **Asymmetric cross-org / not-found error code (404 with EMBEDDED
// IDs)** — `Systems not found or not in your organization: <id>, <id>, ...`.
// NEW shape vs gate's literal 404 (no variable data).
//
// **TWO silent kernel-side truncations** — `orgSystems` capped at
// 500, `batchJobs` GET capped at 1 (defensive). Documented as
// kernel surface gaps; invariant candidate #50.
//
// **`writeAuditLog` side effect** on POST — every successful
// `submit()` call writes one `batch.submitted` audit log entry.
// Time-blocking but error-tolerant (invariant candidate #53 carry-
// forward with session-17 LOW #3 corrected wording).
//
// **Symmetric prototype-pollution defense** — `Object.hasOwn`
// snapshot applied to BOTH input AND response sides; baked in from
// build-round start.
//
// **Partial-success contract** — the call resolves successfully
// even when every row failed; consumers branch on `row.status ===
// "success"` (closed-enum string match, NOT `row.errorMessage ===
// undefined` which is pollution-unsafe).

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

function makeMockedClient(
  responses: Array<{ status?: number; body?: unknown; bodyText?: string }>,
) {
  const calls: MockedRequest[] = [];
  let i = 0;
  const mockFetch: FetchLike = async (url, init) => {
    calls.push({
      url: String(url),
      method: (init?.method as string) ?? "GET",
      headers: init?.headers as Headers,
      body: init?.body as string | undefined,
    });
    const r = responses[i++] ?? {};
    const status = r.status ?? 200;
    const body =
      r.bodyText !== undefined ? r.bodyText : JSON.stringify(r.body ?? {});
    return new Response(body, {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    // Resource tests disable retry so a 429 mock doesn't hang on
    // backoff and accidentally consume the next mock response.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const VALID_UUID_A = "11111111-1111-1111-1111-111111111111";
const VALID_UUID_B = "22222222-2222-2222-2222-222222222222";
const VALID_UUID_C = "33333333-3333-3333-3333-333333333333";

// Representative success-row fixture.
const SAMPLE_SUCCESS_ROW: BatchSystemResult = {
  systemId: VALID_UUID_A,
  systemName: "Test System A",
  status: "success",
  classifications: { eu_ai_act: "limited", iso_42001: "compliant" },
};

// Representative error-row fixture.
const SAMPLE_ERROR_ROW: BatchSystemResult = {
  systemId: VALID_UUID_B,
  systemName: "Test System B",
  status: "error",
  errorMessage: "Classifier failed: invalid systemType",
};

// Happy-path mock baseline. 10 fields; all 3 systems succeeded.
const MOCK_SUBMIT_RESPONSE: BatchSubmitResponse = {
  id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  jobType: "classify",
  status: "completed",
  totalSystems: 1,
  processedSystems: 1,
  failedSystems: 0,
  results: [SAMPLE_SUCCESS_ROW],
  createdAt: "2026-05-12T15:00:00.000Z",
  startedAt: "2026-05-12T15:00:00.500Z",
  completedAt: "2026-05-12T15:00:05.000Z",
};

describe("batch.submit — happy path", () => {
  it("POSTs /api/v1/batch with a JSON body containing jobType + systemIds (no config)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/batch");
    expect(url.search).toBe("");
    expect(calls[0].body).toBeDefined();
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    // Body must NOT include `config` when caller omits it (the
    // kernel's `.optional()` means absent is the correct shape).
    expect("config" in parsed).toBe(false);
    expect(out).toEqual(MOCK_SUBMIT_RESPONSE);
  });

  it("POSTs body with all 3 fields when config is fully provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify_and_assess",
      systemIds: [VALID_UUID_A, VALID_UUID_B, VALID_UUID_C],
      config: { frameworks: ["EU_AI_ACT", "ISO_42001"] },
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      jobType: "classify_and_assess",
      systemIds: [VALID_UUID_A, VALID_UUID_B, VALID_UUID_C],
      config: { frameworks: ["EU_AI_ACT", "ISO_42001"] },
    });
  });

  it("returns the response shape unchanged (envelope unwrapped)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    // Verify envelope was unwrapped: top-level keys are the 10
    // documented submit response fields, NOT success + data.
    expect(Object.keys(out).sort()).toEqual(
      [
        "id",
        "jobType",
        "status",
        "totalSystems",
        "processedSystems",
        "failedSystems",
        "results",
        "createdAt",
        "startedAt",
        "completedAt",
      ].sort(),
    );
  });

  it("forwards x-api-key + Accept + Content-Type headers (POST + body)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("returns all 10 response fields with their documented types (sanity)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(typeof out.id).toBe("string");
    expect(typeof out.jobType).toBe("string");
    expect(typeof out.status).toBe("string");
    expect(out.status === "completed" || out.status === "failed").toBe(true);
    expect(typeof out.totalSystems).toBe("number");
    expect(typeof out.processedSystems).toBe("number");
    expect(typeof out.failedSystems).toBe("number");
    expect(Array.isArray(out.results)).toBe(true);
    expect(typeof out.createdAt).toBe("string");
    expect(out.startedAt === null || typeof out.startedAt === "string").toBe(
      true,
    );
    expect(typeof out.completedAt).toBe("string");
  });
});

describe("batch.submit — input validation: top-level shape", () => {
  it("throws TypeError for null input — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.submit(null as unknown as BatchSubmitInput)).toThrow(
      /must be a non-null object/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit(undefined as unknown as BatchSubmitInput),
    ).toThrow(/must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input (typeof [] === 'object')", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit([] as unknown as BatchSubmitInput),
    ).toThrow(/must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string / number / boolean)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit("hello" as unknown as BatchSubmitInput),
    ).toThrow(/must be a non-null object/);
    expect(() =>
      client.batch.submit(42 as unknown as BatchSubmitInput),
    ).toThrow(/must be a non-null object/);
    expect(() =>
      client.batch.submit(true as unknown as BatchSubmitInput),
    ).toThrow(/must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty object — jobType is required", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.submit({} as unknown as BatchSubmitInput)).toThrow(
      /`jobType` is required/,
    );
    expect(calls).toHaveLength(0);
  });
});

describe("batch.submit — input validation: jobType", () => {
  it("throws TypeError for explicit `jobType: undefined`", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: undefined as unknown as BatchSubmitInput["jobType"],
        systemIds: [VALID_UUID_A],
      }),
    ).toThrow(/`jobType` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string jobType (number / null / object)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: 42 as unknown as BatchSubmitInput["jobType"],
        systemIds: [VALID_UUID_A],
      }),
    ).toThrow(/`jobType` must be a string \(got number\)/);
    // Explicit `null` is treated as a present-but-wrong-type value
    // (own-property TRUE, value not undefined), so the type check
    // fires — NOT the "is required" guard.
    expect(() =>
      client.batch.submit({
        jobType: null as unknown as BatchSubmitInput["jobType"],
        systemIds: [VALID_UUID_A],
      }),
    ).toThrow(/`jobType` must be a string \(got null\)/);
    expect(() =>
      client.batch.submit({
        jobType: {} as unknown as BatchSubmitInput["jobType"],
        systemIds: [VALID_UUID_A],
      }),
    ).toThrow(/`jobType` must be a string \(got object\)/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown jobType (closed-enum SDK pre-rejection — invariant #41)", () => {
    const { client, calls } = makeMockedClient([]);
    // SDK pre-rejects synchronously with TypeError listing the valid
    // set — does NOT round-trip to the kernel and get a 422.
    expect(() =>
      client.batch.submit({
        jobType: "generate_docs" as unknown as BatchSubmitInput["jobType"],
        systemIds: [VALID_UUID_A],
      }),
    ).toThrow(/must be one of \["classify","assess","classify_and_assess"\]/);
    // Also catches the value in the error message for debugging.
    expect(() =>
      client.batch.submit({
        jobType: "evil" as unknown as BatchSubmitInput["jobType"],
        systemIds: [VALID_UUID_A],
      }),
    ).toThrow(/got "evil"/);
    expect(calls).toHaveLength(0);
  });

  it("accepts all 3 valid jobType values", async () => {
    for (const jobType of ["classify", "assess", "classify_and_assess"] as const) {
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: { ...MOCK_SUBMIT_RESPONSE, jobType } } },
      ]);
      await client.batch.submit({
        jobType,
        systemIds: [VALID_UUID_A],
      });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed.jobType).toBe(jobType);
    }
  });
});

describe("batch.submit — input validation: systemIds", () => {
  it("throws TypeError for missing systemIds", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
      } as unknown as BatchSubmitInput),
    ).toThrow(/`systemIds` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for explicit `systemIds: undefined`", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: undefined as unknown as string[],
      }),
    ).toThrow(/`systemIds` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-array systemIds (string / object / null)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: VALID_UUID_A as unknown as string[],
      }),
    ).toThrow(/`systemIds` must be an array \(got string\)/);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: { 0: VALID_UUID_A, length: 1 } as unknown as string[],
      }),
    ).toThrow(/`systemIds` must be an array \(got object\)/);
    // Explicit `null` is treated as a present-but-wrong-type value
    // (own-property TRUE, value not undefined), so the type check
    // fires — NOT the "is required" guard.
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: null as unknown as string[],
      }),
    ).toThrow(/`systemIds` must be an array \(got null\)/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty systemIds (`.min(1)` is NEW vs gate/check)", () => {
    const { client, calls } = makeMockedClient([]);
    // batch's `.min(1)` rejects empty arrays at the Zod level;
    // distinct from gate's `frameworks` which allows empty.
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [],
      }),
    ).toThrow(/`systemIds` must contain at least 1 entry/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when systemIds exceeds 50 entries (Zod .max(50))", () => {
    const { client, calls } = makeMockedClient([]);
    const tooMany = Array.from({ length: 51 }, () => VALID_UUID_A);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: tooMany,
      }),
    ).toThrow(/exceeds the kernel's max length of 50 \(got 51\)/);
    expect(calls).toHaveLength(0);
  });

  it("accepts systemIds at the 1-entry boundary", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(calls).toHaveLength(1);
  });

  it("accepts systemIds at the 50-entry boundary (max inclusive)", async () => {
    const fiftyIds = Array.from({ length: 50 }, () => VALID_UUID_A);
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_SUBMIT_RESPONSE,
            totalSystems: 50,
            processedSystems: 50,
            results: fiftyIds.map(
              (id, i): BatchSystemResult => ({
                systemId: id,
                systemName: `System ${i}`,
                status: "success",
              }),
            ),
          },
        },
      },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: fiftyIds,
    });
    expect(calls).toHaveLength(1);
  });

  it("throws TypeError when a systemIds element is non-string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A, 42 as unknown as string],
      }),
    ).toThrow(/`systemIds\[1\]` must be a string \(got number\)/);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [null as unknown as string, VALID_UUID_B],
      }),
    ).toThrow(/`systemIds\[0\]` must be a string \(got null\)/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a systemIds element is the empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A, ""],
      }),
    ).toThrow(/`systemIds\[1\]` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a systemIds element fails UUID regex (D4 — SDK pre-validates)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A, "not-a-uuid"],
      }),
    ).toThrow(/`systemIds\[1\]` must be an RFC 4122 hyphenated UUID/);
    // Error message includes the offending value for debugging.
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: ["zzzz0000-0000-0000-0000-000000000000"],
      }),
    ).toThrow(/got "zzzz0000-0000-0000-0000-000000000000"/);
    expect(calls).toHaveLength(0);
  });

  it("accepts lowercase and uppercase hex UUIDs (regex is case-insensitive)", async () => {
    const { client: c1, calls: calls1 } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await c1.batch.submit({
      jobType: "classify",
      systemIds: ["abcdef00-1234-5678-9abc-deffedcba987"],
    });
    expect(calls1).toHaveLength(1);

    const { client: c2, calls: calls2 } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await c2.batch.submit({
      jobType: "classify",
      systemIds: ["ABCDEF00-1234-5678-9ABC-DEFFEDCBA987"],
    });
    expect(calls2).toHaveLength(1);
  });

  it("rejects UUID with prefix/suffix non-hex garbage (regex anchored)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [`prefix${VALID_UUID_A}`],
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [`${VALID_UUID_A}suffix`],
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });
});

describe("batch.submit — input validation: config", () => {
  it("accepts config: undefined as omission (body omits config)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect("config" in parsed).toBe(false);
  });

  it("throws TypeError for non-object config (string / number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: "not-an-object" as unknown as BatchConfig,
      }),
    ).toThrow(/`config` must be a non-null object when provided \(got string\)/);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: 42 as unknown as BatchConfig,
      }),
    ).toThrow(/`config` must be a non-null object when provided \(got number\)/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for null config (explicit null is not the same as omission)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: null as unknown as BatchConfig,
      }),
    ).toThrow(/`config` must be a non-null object when provided \(got null\)/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array config (typeof [] === 'object')", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: ["evil"] as unknown as BatchConfig,
      }),
    ).toThrow(/`config` must be a non-null object when provided \(got array\)/);
    expect(calls).toHaveLength(0);
  });

  it("accepts empty config object — body emits empty config", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: {},
    });
    const parsed = JSON.parse(calls[0].body!);
    // Empty config is preserved (consumer's explicit choice — DB
    // column gets `{}` rather than `null`).
    expect(parsed.config).toEqual({});
  });

  it("throws TypeError when config.frameworks is not an array", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: { frameworks: "EU_AI_ACT" as unknown as string[] },
      }),
    ).toThrow(/`config\.frameworks` must be an array when provided \(got string\)/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when config.frameworks contains a non-string element", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: {
          frameworks: ["EU_AI_ACT", 42 as unknown as string],
        },
      }),
    ).toThrow(/`config\.frameworks\[1\]` must be a string \(got number\)/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when config.frameworks contains an empty string (Zod .min(1))", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: { frameworks: ["EU_AI_ACT", ""] },
      }),
    ).toThrow(/`config\.frameworks\[1\]` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when config.frameworks element exceeds 100 chars (Zod .max(100))", () => {
    const { client, calls } = makeMockedClient([]);
    const tooLong = "X".repeat(101);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: { frameworks: [tooLong] },
      }),
    ).toThrow(/`config\.frameworks\[0\]` exceeds the kernel's max length of 100 chars \(got 101\)/);
    expect(calls).toHaveLength(0);
  });

  it("accepts config.frameworks element at the 100-char boundary", async () => {
    const exactMax = "X".repeat(100);
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: { frameworks: [exactMax] },
    });
    expect(calls).toHaveLength(1);
  });

  it("throws TypeError when config.frameworks array exceeds 20 (Zod .max(20))", () => {
    const { client, calls } = makeMockedClient([]);
    const tooMany = Array.from({ length: 21 }, (_, i) => `FW_${i}`);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: { frameworks: tooMany },
      }),
    ).toThrow(/`config\.frameworks` array exceeds the kernel's max length of 20 \(got 21\)/);
    expect(calls).toHaveLength(0);
  });

  it("accepts config.frameworks at the 20-element / 100-char boundary", async () => {
    const twentyFws = Array.from({ length: 20 }, (_, i) => `FW_${i}`);
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: { frameworks: twentyFws },
    });
    expect(calls).toHaveLength(1);
  });

  it("accepts an empty config.frameworks array (kernel `.optional()` `.max(20)` permits length 0)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: { frameworks: [] },
    });
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.config).toEqual({ frameworks: [] });
  });

  it("omits config.frameworks when undefined (body emits empty config)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: { frameworks: undefined },
    });
    const parsed = JSON.parse(calls[0].body!);
    // `config` is present but empty — `frameworks: undefined` is
    // treated as omission of the inner field.
    expect(parsed.config).toEqual({});
  });
});

describe("batch.submit — prototype-pollution defenses (input side)", () => {
  it("defends against prototype pollution on jobType presence (Object.hasOwn defense, generalization of #48)", () => {
    const { client, calls } = makeMockedClient([]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "jobType",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).jobType =
        "classify";
      // Caller passes only systemIds. Without the defense, the
      // SDK would read the polluted value as the jobType and
      // silently submit. With the defense, jobType is "required".
      expect(() =>
        client.batch.submit({
          systemIds: [VALID_UUID_A],
        } as unknown as BatchSubmitInput),
      ).toThrow(/`jobType` is required/);
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "jobType", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>).jobType;
      }
    }
    expect(calls).toHaveLength(0);
  });

  it("defends against prototype pollution on systemIds presence", () => {
    const { client, calls } = makeMockedClient([]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "systemIds",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).systemIds = [
        VALID_UUID_A,
      ];
      expect(() =>
        client.batch.submit({
          jobType: "classify",
        } as unknown as BatchSubmitInput),
      ).toThrow(/`systemIds` is required/);
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "systemIds", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .systemIds;
      }
    }
    expect(calls).toHaveLength(0);
  });

  it("defends against prototype pollution on config presence (body omits config when own-property is false)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "config",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).config = {
        frameworks: ["EVIL_FRAMEWORK"],
      };
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed).toEqual({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      // Own-property check confirms no polluted config landed.
      expect(Object.hasOwn(parsed, "config")).toBe(false);
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "config", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>).config;
      }
    }
  });

  it("defends against prototype pollution on config.frameworks presence (inner own-property check)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "frameworks",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).frameworks = [
        "EVIL_FRAMEWORK",
      ];
      // Pass config: {} — own-property `frameworks` is FALSE. The
      // SDK's inner check on config.frameworks uses objectHasOwn,
      // so the pollution doesn't leak into the body.
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
        config: {},
      });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed.config).toEqual({});
      expect(Object.hasOwn(parsed.config, "frameworks")).toBe(false);
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "frameworks", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .frameworks;
      }
    }
  });
});

describe("batch.submit — body encoding", () => {
  it("body uses Zod-schema field names (jobType, systemIds, config, config.frameworks)", async () => {
    // Pin against camelCase / snake_case / Pascal-case refactor drift.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: { frameworks: ["EU_AI_ACT"] },
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.keys(parsed).sort()).toEqual([
      "config",
      "jobType",
      "systemIds",
    ]);
    expect(Object.keys(parsed.config).sort()).toEqual(["frameworks"]);
  });

  it("does not mutate the input object (read-only)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const input: BatchSubmitInput = Object.freeze({
      jobType: "classify",
      systemIds: Object.freeze([VALID_UUID_A]) as string[],
      config: Object.freeze({
        frameworks: Object.freeze(["EU_AI_ACT"]) as string[],
      }) as BatchConfig,
    });
    const snapshot = JSON.stringify(input);
    await client.batch.submit(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});

describe("batch.submit — error paths", () => {
  it("surfaces a 401 (no/invalid API key) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required" },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 403 (permission branch — key has NEITHER CLASSIFY NOR WRITE_ASSESSMENTS — union-auth) as AttestryAPIError", async () => {
    // **First WRITE-side union-auth pin** (every prior SDK 403 has
    // been READ-side). Kernel emits the literal wording naming the
    // two required permissions.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error:
            "API key lacks required permission. Required: classify or write:assessments. Key has: read:documents.",
        },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
      expect((err as AttestryAPIError).message).toMatch(
        /classify or write:assessments/,
      );
    }
  });

  it("surfaces a 403 (plan-guard branch — `hasBatchProcessing` feature gate) as AttestryAPIError — distinct wording from permission-403 (invariant candidate #55)", async () => {
    // **NEW plan-guard 403 surface pin** (invariant candidate #55).
    // The kernel emits PlanLimitError with a DIFFERENT literal
    // message than the permission-403. Consumers regex-match the
    // message to distinguish "upgrade your plan" from "grant more
    // permissions to your key". SDK exposes both uniformly as
    // AttestryAPIError(403); no SDK-side discriminator helper today.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error:
            'The "hasBatchProcessing" feature is not available on your current plan (free). Please upgrade to access this feature.',
        },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      // Plan-403 wording matches the kernel's PlanLimitError shape.
      expect(apiErr.message).toMatch(/"hasBatchProcessing"/);
      expect(apiErr.message).toMatch(/feature is not available/);
      expect(apiErr.message).toMatch(/Please upgrade/);
      // Distinct from permission-403's wording.
      expect(apiErr.message).not.toMatch(/API key lacks/);
    }
  });

  it("surfaces a 404 (org-not-found branch) as AttestryAPIError — rare path before plan-guard fires", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "Organization not found" },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
      expect((err as AttestryAPIError).message).toMatch(
        /Organization not found/,
      );
    }
  });

  it("surfaces a 404 (systems-not-found branch — EMBEDDED IDs in message) as AttestryAPIError — NEW shape vs gate's literal 404", async () => {
    // **NEW 404 shape with EMBEDDED variable data** (comma-joined
    // invalid UUIDs in the message). SDK does NOT parse the
    // embedded IDs — faithful courier; consumers regex-match if
    // needed.
    const { client } = makeMockedClient([
      {
        status: 404,
        body: {
          success: false,
          error: `Systems not found or not in your organization: ${VALID_UUID_B}, ${VALID_UUID_C}`,
        },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A, VALID_UUID_B, VALID_UUID_C],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.message).toMatch(
        /Systems not found or not in your organization:/,
      );
      // The IDs ARE in the message — consumers can regex-extract
      // if they want. The SDK does not do this — faithful courier.
      expect(apiErr.message).toContain(VALID_UUID_B);
      expect(apiErr.message).toContain(VALID_UUID_C);
    }
  });

  it("surfaces a 422 (kernel Zod schema rejection, only reachable via kernel-side rule changes the SDK hasn't synced to) as AttestryAPIError with actual kernel body shape", async () => {
    // The SDK pre-validates every closed-spec rule — so 422 is
    // reachable only via `as any` casts or kernel-side rule changes.
    // Mock the ACTUAL kernel emit shape from src/lib/api.ts:84-91
    // + 28-42 (verified for session-18 build round per session-17
    // carry-forward).
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            {
              path: "systemIds",
              message: "At least one system ID is required",
            },
          ],
        },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        // Use `as any` to bypass SDK pre-validation and reach the
        // kernel 422 path.
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.message).toBe("Validation failed.");
      const wireBody = apiErr.details as {
        success: false;
        error: string;
        details: Array<{ path: string; message: string }>;
      };
      expect(wireBody.error).toBe("Validation failed.");
      expect(Array.isArray(wireBody.details)).toBe(true);
      expect(wireBody.details).toEqual([
        {
          path: "systemIds",
          message: "At least one system ID is required",
        },
      ]);
    }
  });

  it("surfaces a 429 (rate limit — `assessmentLimiter` 30/min) as AttestryAPIError when retry is disabled", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: { success: false, error: "Too many requests." },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });

  it("surfaces a 500 (internal kernel error, scrubbed message) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 500,
        body: {
          success: false,
          error: "An internal error occurred. Please try again later.",
        },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(500);
    }
  });

  it("P3: wrong content-type (text/plain) throws AttestryAPIError from transport", async () => {
    const callsLocal: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      callsLocal.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      return new Response(
        JSON.stringify({ success: true, data: MOCK_SUBMIT_RESPONSE }),
        {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(200);
      expect(apiErr.message).toMatch(/expected application\/json/);
      expect(apiErr.message).toMatch(/got "text\/plain"/);
    }
    expect(callsLocal).toHaveLength(1);
  });
});

describe("batch.submit — response shape preservation", () => {
  it("preserves all 10 always-present fields", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(out).toEqual(MOCK_SUBMIT_RESPONSE);
  });

  it("results: [] round-trips when totalSystems is 0 — defensive (kernel doesn't permit empty submissions, but verify the wire shape)", async () => {
    // The kernel's `.min(1)` rejects empty submissions at the Zod
    // level, but the SDK's response validator should accept
    // `results: []` as a valid shape for forward-compat.
    const emptyResult: BatchSubmitResponse = {
      ...MOCK_SUBMIT_RESPONSE,
      totalSystems: 0,
      processedSystems: 0,
      failedSystems: 0,
      results: [],
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: emptyResult } },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(out.results).toEqual([]);
  });

  it("results with mixed success+error rows — partial-success contract round-trips", async () => {
    // **The partial-success contract pin** — the SDK does NOT throw
    // on `failedSystems > 0`. Consumers branch on per-row status.
    const mixed: BatchSubmitResponse = {
      ...MOCK_SUBMIT_RESPONSE,
      jobType: "classify_and_assess",
      status: "completed",
      totalSystems: 3,
      processedSystems: 2,
      failedSystems: 1,
      results: [
        SAMPLE_SUCCESS_ROW,
        SAMPLE_ERROR_ROW,
        {
          systemId: VALID_UUID_C,
          systemName: "Test System C",
          status: "success",
          classifications: { eu_ai_act: "minimal" },
        },
      ],
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: mixed } },
    ]);
    const out = await client.batch.submit({
      jobType: "classify_and_assess",
      systemIds: [VALID_UUID_A, VALID_UUID_B, VALID_UUID_C],
    });
    expect(out.failedSystems).toBe(1);
    expect(out.results).toHaveLength(3);
    // Discriminator pin: per-row `status` is the closed-enum string
    // match.
    expect(out.results[0].status).toBe("success");
    expect(out.results[1].status).toBe("error");
    expect(out.results[1].errorMessage).toBe(SAMPLE_ERROR_ROW.errorMessage);
  });

  it("results entirely failed (every row errored) — call STILL resolves successfully (no throw); status is 'failed'", async () => {
    // **The partial-success contract's strongest pin** — when EVERY
    // row failed, the kernel computes `finalStatus = "failed"` and
    // emits a 200 with `status: "failed"`. The SDK resolves
    // successfully — NO throw. Consumers detect via
    // `response.failedSystems === response.totalSystems` OR
    // `response.status === "failed"`.
    const allFailed: BatchSubmitResponse = {
      ...MOCK_SUBMIT_RESPONSE,
      status: "failed",
      totalSystems: 2,
      processedSystems: 0,
      failedSystems: 2,
      results: [
        SAMPLE_ERROR_ROW,
        {
          systemId: VALID_UUID_C,
          systemName: "Test System C",
          status: "error",
          errorMessage: "Classifier failed: timeout",
        },
      ],
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: allFailed } },
    ]);
    // No throw — the call resolves successfully.
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_B, VALID_UUID_C],
    });
    expect(out.status).toBe("failed");
    expect(out.failedSystems).toBe(out.totalSystems);
  });

  it("status: 'completed' round-trips as a literal string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_SUBMIT_RESPONSE, status: "completed" } },
      },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(out.status).toBe("completed");
  });

  it("status: 'failed' round-trips as a literal string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_SUBMIT_RESPONSE, status: "failed" } },
      },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(out.status).toBe("failed");
  });

  it("startedAt: null round-trips (defensive — kernel sets it but the wire shape allows null)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, startedAt: null },
        },
      },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(out.startedAt).toBeNull();
  });

  it("passes through extra unknown top-level fields verbatim (forward-compat)", async () => {
    // Pin against kernel addition of new top-level fields before
    // the SDK is bumped — the new field round-trips at runtime.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_SUBMIT_RESPONSE,
            futureField: "added kernel-side without an SDK bump",
            warnings: ["new warning channel"],
          },
        },
      },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect((out as unknown as Record<string, unknown>).futureField).toBe(
      "added kernel-side without an SDK bump",
    );
    expect((out as unknown as Record<string, unknown>).warnings).toEqual([
      "new warning channel",
    ]);
  });

  it("passes through per-row classifications as `unknown` (open-spec)", async () => {
    // The kernel's `classifySystem` return shape lives in
    // src/lib/classification.ts. The SDK doesn't paranoid-validate
    // — round-trips verbatim.
    const exotic: BatchSubmitResponse = {
      ...MOCK_SUBMIT_RESPONSE,
      results: [
        {
          systemId: VALID_UUID_A,
          systemName: "Test System A",
          status: "success",
          classifications: {
            arbitrary: "shape",
            nested: { array: [1, 2, 3], bool: true },
          },
        },
      ],
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: exotic } },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(out.results[0].classifications).toEqual({
      arbitrary: "shape",
      nested: { array: [1, 2, 3], bool: true },
    });
  });
});

describe("batch.submit — P2 response shape hardening", () => {
  it("P2: throws AttestryError when kernel response is null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected an object response from the kernel \(got null\)/,
    );
  });

  it("P2: throws AttestryError when kernel response is a scalar (string)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: "scalar-instead-of-object" } },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected an object response from the kernel \(got string\)/,
    );
  });

  it("P2: throws AttestryError when kernel response is an array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_SUBMIT_RESPONSE] } },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected an object response from the kernel \(got array\)/,
    );
  });

  it("P2: throws AttestryError when response.id is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_SUBMIT_RESPONSE, id: 42 } },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(/expected response\.id to be a string \(got number\)/);
  });

  it("P2: throws AttestryError when response.jobType is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_SUBMIT_RESPONSE, jobType: 42 } },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.jobType to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.status is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_SUBMIT_RESPONSE, status: 1 } },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.status to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.totalSystems is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, totalSystems: "1" },
        },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.totalSystems to be a number \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.processedSystems is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, processedSystems: null },
        },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.processedSystems to be a number \(got null\)/,
    );
  });

  it("P2: throws AttestryError when response.failedSystems is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, failedSystems: "0" },
        },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.failedSystems to be a number \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.results is not an array", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, results: "not-an-array" },
        },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.results to be an array \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.createdAt is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, createdAt: 1234567890 },
        },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.createdAt to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.startedAt is not string-or-null", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, startedAt: 1234567890 },
        },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.startedAt to be a string or null \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.completedAt is not a string", async () => {
    // completedAt is NOT nullable on POST (asymmetric with GET).
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, completedAt: null },
        },
      },
    ]);
    await expect(
      client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      }),
    ).rejects.toThrow(
      /expected response\.completedAt to be a string \(got null\)/,
    );
  });

  it("P2 error is AttestryError (NOT AttestryAPIError) — distinct surface for kernel-shape regressions", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      expect(err).not.toBeInstanceOf(AttestryAPIError);
    }
  });

  // Per-always-present-field MISSING own-property pins. Exercises
  // the `: undefined` arm of each P2 ternary (`objectHasOwn(obj, "X")
  // ? obj.X : undefined`) — the kernel-regression-drops-field case.
  // The SDK's own-property check returns false → describeType(undefined)
  // → AttestryError with "got undefined" naming the field. Without
  // these pins, the multi-line ternary `: undefined` arms drop branch
  // + line coverage to ~98%. With them, 100/100/100/100 is maintained
  // from build round through final commit (carry-forward lesson from
  // session 17 — front-load the missing-own-property coverage pin).
  it.each([
    ["id", /expected response\.id to be a string \(got undefined\)/],
    [
      "jobType",
      /expected response\.jobType to be a string \(got undefined\)/,
    ],
    [
      "status",
      /expected response\.status to be a string \(got undefined\)/,
    ],
    [
      "totalSystems",
      /expected response\.totalSystems to be a number \(got undefined\)/,
    ],
    [
      "processedSystems",
      /expected response\.processedSystems to be a number \(got undefined\)/,
    ],
    [
      "failedSystems",
      /expected response\.failedSystems to be a number \(got undefined\)/,
    ],
    [
      "results",
      /expected response\.results to be an array \(got undefined\)/,
    ],
    [
      "createdAt",
      /expected response\.createdAt to be a string \(got undefined\)/,
    ],
    [
      "startedAt",
      /expected response\.startedAt to be a string or null \(got undefined\)/,
    ],
    [
      "completedAt",
      /expected response\.completedAt to be a string \(got undefined\)/,
    ],
  ] as const)(
    "P2 missing-%s: own-property false → AttestryError naming the field with 'got undefined'",
    async (fieldName, expectedMsg) => {
      const data: Record<string, unknown> = { ...MOCK_SUBMIT_RESPONSE };
      delete data[fieldName];
      const { client } = makeMockedClient([
        { body: { success: true, data } },
      ]);
      await expect(
        client.batch.submit({
          jobType: "classify",
          systemIds: [VALID_UUID_A],
        }),
      ).rejects.toThrow(expectedMsg);
    },
  );
});

describe("batch.submit — abort + retry semantics", () => {
  it("forwards a pre-aborted AbortSignal through RequestOptions (no fetch)", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.batch.submit(
        { jobType: "classify", systemIds: [VALID_UUID_A] },
        { signal: controller.signal },
      ),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const controller = new AbortController();
    const out = await client.batch.submit(
      { jobType: "classify", systemIds: [VALID_UUID_A] },
      { signal: controller.signal },
    );
    expect(out.id).toBe(MOCK_SUBMIT_RESPONSE.id);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies (independent of resource-helper default)", async () => {
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "x" } },
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ];
    const calls: MockedRequest[] = [];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "POST",
        headers: init?.headers as Headers,
      });
      const r = responses[i++] ?? {};
      return new Response(JSON.stringify(r.body ?? {}), {
        status: r.status ?? 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    vi.useFakeTimers();
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const promise = client.batch.submit(
      { jobType: "classify", systemIds: [VALID_UUID_A] },
      { retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 } },
    );
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out.id).toBe(MOCK_SUBMIT_RESPONSE.id);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });
});

describe("batch.submit — hostile round residual gaps", () => {
  it("H1: TOCTOU on jobType via input-getter — SDK reads exactly once and validates the snapshot", async () => {
    // Hostile concern: a Proxy or getter-defining input could yield
    // DIFFERENT values across multiple reads of `input.jobType`.
    // The SDK validates the snapshot AND sends the snapshot — so a
    // proxy can't slip a malicious value past validation by toggling
    // between "valid" and "evil" across reads.
    //
    // Pin: define an object with a `jobType` getter that returns a
    // valid enum value on the FIRST read and an INVALID value
    // ("generate_docs" — the stale schema-comment value that's
    // NOT in the Zod enum) on subsequent reads. Verify the wire
    // body contains the FIRST-read value (the validated snapshot).
    let getterCallCount = 0;
    const input = { systemIds: [VALID_UUID_A] } as {
      systemIds: string[];
      jobType: BatchSubmitInput["jobType"];
    };
    Object.defineProperty(input, "jobType", {
      configurable: true,
      enumerable: true,
      get() {
        getterCallCount++;
        return getterCallCount === 1
          ? "classify"
          : ("generate_docs" as unknown as BatchSubmitInput["jobType"]);
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit(input);
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    // CONTRACT pin (load-bearing): the value sent on the wire is the
    // value validated. This is the actual security guarantee — a
    // refactor preserving this property is correct regardless of how
    // many times it reads the getter.
    expect(parsed.jobType).toBe("classify");
    // Implementation pin (defensive): today the SDK reads the getter
    // exactly once. A benign refactor (e.g., adding telemetry that
    // logs the input shape) could increase this — if the wire-body
    // assertion above still holds, the security contract is preserved
    // and this count assertion can be loosened. Use
    // `.toBeLessThanOrEqual(N)` (where N is the new expected max)
    // rather than weakening the wire-body assertion. Session-18
    // hostile-review #2 MEDIUM #3 carry-forward.
    expect(getterCallCount).toBe(1);
  });

  it("H2: TOCTOU on systemIds via Proxy-array — Array.from snapshot collapses validate+send to a single read", async () => {
    // Hostile concern: a Proxy whose `.length` and `[i]` return
    // DIFFERENT values across reads could slip past per-element
    // validation. The SDK uses `Array.from(systemIdsRaw)` to
    // materialize the snapshot in ONE pass; subsequent operations
    // (length check, per-element validation, body construction)
    // all read from the snapshot.
    //
    // Session-16 second-hostile-review MEDIUM #2 carry-forward:
    // use a STATE-BASED proxy that returns valid UUIDs on the
    // first N reads (consumed by Array.from inside the SDK) and
    // EVIL values on read N+1+. If the SDK re-reads from the proxy
    // (e.g., a refactor that assigns body.systemIds = systemIdsRaw),
    // JSON.stringify of the proxy would trigger reads N+1+ and the
    // wire body would carry "EVIL_UUID".
    const evilArray = [VALID_UUID_A, VALID_UUID_B];
    let getCallCount = 0;
    const stateFlippingProxy: unknown = new Proxy(evilArray, {
      get(target, prop, receiver) {
        if (typeof prop === "string" && /^\d+$/.test(prop)) {
          getCallCount++;
          const idx = Number(prop);
          if (getCallCount > 2) {
            return "00000000-0000-0000-0000-000000000000";
          }
          return target[idx];
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: stateFlippingProxy as string[],
    });
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    // The wire body MUST contain the FIRST-pass values (the
    // snapshot). If the SDK re-reads from the proxy, JSON.stringify
    // would trigger reads 3+ via the proxy's `get` trap and the
    // body would carry "00000000-..." instead.
    expect(parsed.systemIds).toEqual([VALID_UUID_A, VALID_UUID_B]);
    // Single-pass proof.
    expect(getCallCount).toBe(2);
  });

  it("H3: Object.hasOwn override + Object.prototype.jobType pollution — snapshot defense is what causes rejection", async () => {
    // Hostile concern: a late-loading dep overrides
    // `Object.hasOwn = () => true`. The SDK's module-load snapshot
    // (`const objectHasOwn = Object.hasOwn;`) captured the ORIGINAL
    // implementation, so the override doesn't reach the resource's
    // input checks.
    //
    // The COMBINED pollution + override is the only configuration
    // that ACTUALLY exercises the snapshot defense (session-16
    // second-hostile-review MEDIUM #1 carry-forward). With only the
    // `Object.hasOwn = () => true` override (no prototype pollution),
    // BOTH with-snapshot AND without-snapshot code paths throw
    // "jobType is required" — the snapshot defense isn't exercised
    // because the secondary `jobTypeRaw === undefined` check catches
    // the no-own-property case anyway.
    //
    // With combined pollution + override:
    //   - With snapshot: objectHasOwn(input, "jobType") uses the
    //     ORIGINAL Object.hasOwn (own-only) → returns false →
    //     hasJobType = false → throws "required". ✅ Correct.
    //   - Without snapshot (hypothetical broken refactor):
    //     Object.hasOwn(input, "jobType") is the overridden function
    //     returning true → hasJobType = true → then
    //     jobTypeRaw = input.jobType reads via prototype chain →
    //     gets the polluted value → passes enum check → SDK
    //     silently SENDS the polluted value to the kernel.
    //
    // Pin: SDK throws "required" (the snapshot wins).
    const { client, calls } = makeMockedClient([]);
    const originalHasOwn = Object.hasOwn;
    const originalJobTypeDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "jobType",
    );
    try {
      (Object as { hasOwn: unknown }).hasOwn = () => true;
      (Object.prototype as unknown as Record<string, unknown>).jobType =
        "classify";
      expect((Object.hasOwn as unknown as () => boolean)()).toBe(true);
      expect(
        ({} as unknown as { jobType: string }).jobType,
      ).toBe("classify");
      // Pass systemIds only — SDK's snapshot rejects the polluted
      // jobType.
      expect(() =>
        client.batch.submit({
          systemIds: [VALID_UUID_A],
        } as unknown as BatchSubmitInput),
      ).toThrow(/`jobType` is required/);
    } finally {
      (Object as { hasOwn: typeof originalHasOwn }).hasOwn = originalHasOwn;
      if (originalJobTypeDesc) {
        Object.defineProperty(Object.prototype, "jobType", originalJobTypeDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .jobType;
      }
    }
    expect(calls).toHaveLength(0);
  });

  it("H4: concurrent batch.submit() calls share no state — each promise resolves independently", async () => {
    // Pin against a future refactor that adds shared state
    // (memoization, response caching, request batching). Each call
    // must construct its own promise; the mocked fetch routes them
    // to distinct mock responses by call order.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, id: "111-job", failedSystems: 1 },
        },
      },
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, id: "222-job", failedSystems: 2 },
        },
      },
      {
        body: {
          success: true,
          data: { ...MOCK_SUBMIT_RESPONSE, id: "333-job", failedSystems: 3 },
        },
      },
    ]);
    const [out1, out2, out3] = await Promise.all([
      client.batch.submit({ jobType: "classify", systemIds: [VALID_UUID_A] }),
      client.batch.submit({ jobType: "assess", systemIds: [VALID_UUID_B] }),
      client.batch.submit({
        jobType: "classify_and_assess",
        systemIds: [VALID_UUID_C],
      }),
    ]);
    expect(calls).toHaveLength(3);
    expect(out1.id).toBe("111-job");
    expect(out2.id).toBe("222-job");
    expect(out3.id).toBe("333-job");
  });

  it("H5: parallel concurrent calls with different field combinations don't cross-pollinate bodies", async () => {
    // Stronger contract than H4: each call's body lands on its own
    // request. A future refactor that batches POSTs OR shares a
    // body-builder closure would surface here.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await Promise.all([
      client.batch.submit({ jobType: "classify", systemIds: [VALID_UUID_A] }),
      client.batch.submit({
        jobType: "assess",
        systemIds: [VALID_UUID_B, VALID_UUID_C],
        config: { frameworks: ["EU_AI_ACT"] },
      }),
      client.batch.submit({
        jobType: "classify_and_assess",
        systemIds: [VALID_UUID_A],
      }),
    ]);
    expect(calls).toHaveLength(3);
    expect(JSON.parse(calls[0].body!)).toEqual({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(JSON.parse(calls[1].body!)).toEqual({
      jobType: "assess",
      systemIds: [VALID_UUID_B, VALID_UUID_C],
      config: { frameworks: ["EU_AI_ACT"] },
    });
    expect(JSON.parse(calls[2].body!)).toEqual({
      jobType: "classify_and_assess",
      systemIds: [VALID_UUID_A],
    });
  });

  it("H6: 429 auto-retries when retry is enabled (default) and succeeds on second attempt", async () => {
    // Build round only pinned the retry-disabled path. Hostile
    // round adds the retry-enabled path — invariant #18: SDK auto-
    // retries on 429 with exponential backoff. Mirror of gate /
    // check / regulatoryChanges retry pins.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "rate limited" } },
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ];
    const calls: MockedRequest[] = [];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "POST",
        headers: init?.headers as Headers,
      });
      const r = responses[i++] ?? {};
      return new Response(JSON.stringify(r.body ?? {}), {
        status: r.status ?? 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    vi.useFakeTimers();
    // Default-retry client (NO override). The default config retries
    // up to 3 times.
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
    });
    const promise = client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    await vi.advanceTimersByTimeAsync(2_500);
    const out = await promise;
    expect(out.id).toBe(MOCK_SUBMIT_RESPONSE.id);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });

  it("H7: 422 with NO `details` array (forward-compat defensive — if kernel ever omits `details`, SDK transport still surfaces cleanly)", async () => {
    // Forward-compat defensive pin — today the kernel ALWAYS
    // populates `details` on 422 (parseBody at src/lib/api.ts:84-91
    // unconditionally builds the array). This pin exercises an
    // IMPOSSIBLE-TODAY surface: a 422 with just `error` and no
    // `details` field. The SDK's transport just surfaces
    // AttestryAPIError(422, body) — `extractMessage` reads `error`
    // / `message` but NEVER reads `details` or `fieldErrors`. So
    // whether `details` is present, absent, or a different shape
    // doesn't break the SDK error surface.
    //
    // Carry-forward from gate / check H7. Pin retains defensive
    // value — if a future kernel splits Zod-vs-business errors and
    // emits 422 without `details` on the business path, this pin
    // documents that the SDK transport still surfaces it cleanly.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.message).toBe("Validation failed.");
      const wireBody = apiErr.details as {
        success: false;
        error: string;
      };
      expect(wireBody.error).toBe("Validation failed.");
      expect(Object.hasOwn(wireBody, "details")).toBe(false);
    }
  });

  it("H8: body construction omits unknown input keys (defense vs `as any` extras)", async () => {
    // Hostile concern: a consumer using `as any` could pass extras
    // alongside the documented fields. The body construction in
    // `batch.submit` explicitly assembles a new object with ONLY
    // the documented fields — the extras don't propagate to the wire.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: { frameworks: ["EU_AI_ACT"] },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      evilExtra: "should-not-propagate",
      apiKey: "should-not-propagate-either",
      orgId: "evil-org-id",
    } as unknown as BatchSubmitInput);
    const parsed = JSON.parse(calls[0].body!);
    // Body contains ONLY the 3 documented fields.
    expect(Object.keys(parsed).sort()).toEqual([
      "config",
      "jobType",
      "systemIds",
    ]);
    expect(Object.hasOwn(parsed, "evilExtra")).toBe(false);
    expect(Object.hasOwn(parsed, "apiKey")).toBe(false);
    expect(Object.hasOwn(parsed, "orgId")).toBe(false);
  });

  it("H9: systemIds with sparse array (holes → undefined elements) is rejected", () => {
    // Hostile concern: `new Array(3)` or `[, "x", ,]` creates a
    // sparse array with holes. `Array.from` materializes holes as
    // `undefined` (NOT skipped). Each undefined fails the
    // `typeof === "string"` check; the SDK rejects with a clear
    // index-named TypeError.
    const { client, calls } = makeMockedClient([]);
    // eslint-disable-next-line no-sparse-arrays
    const sparseArr = [VALID_UUID_A, , VALID_UUID_B] as unknown as string[];
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: sparseArr,
      }),
    ).toThrow(/`systemIds\[1\]` must be a string \(got undefined\)/);

    const allHoles = new Array(3) as unknown as string[];
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: allHoles,
      }),
    ).toThrow(/`systemIds\[0\]` must be a string \(got undefined\)/);
    expect(calls).toHaveLength(0);
  });

  it("H10: systemIds with non-Array array-like (Set / Map / arguments-object) is rejected", () => {
    // Hostile concern: a consumer passes a Set, Map, or other
    // array-like (NodeList, arguments object) instead of a true
    // Array. `Array.isArray` returns false for ALL of these.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: new Set([VALID_UUID_A]) as unknown as string[],
      }),
    ).toThrow(/`systemIds` must be an array/);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: new Map([
          [VALID_UUID_A, "x"],
        ]) as unknown as string[],
      }),
    ).toThrow(/`systemIds` must be an array/);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: { 0: VALID_UUID_A, length: 1 } as unknown as string[],
      }),
    ).toThrow(/`systemIds` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("H11: TOCTOU on config via input-getter — SDK reads exactly once", async () => {
    // The SDK snapshots `configRaw` once via objectHasOwn + indexer.
    // A getter that toggles between a valid empty object and an
    // EVIL one with frameworks: ["EVIL"] across reads should be
    // collapsed to the first-read value.
    let getterCallCount = 0;
    const input = {
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    } as BatchSubmitInput;
    Object.defineProperty(input, "config", {
      configurable: true,
      enumerable: true,
      get() {
        getterCallCount++;
        return getterCallCount === 1 ? {} : { frameworks: ["EVIL"] };
      },
    });
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit(input);
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    // CONTRACT pin (load-bearing — security guarantee): the value
    // sent on the wire is the value validated.
    expect(parsed.config).toEqual({});
    // Implementation pin (defensive — see H1's comment). Carry-
    // forward from session-18 hostile-review #2 MEDIUM #3.
    expect(getterCallCount).toBe(1);
  });

  it("H12: TOCTOU on config.frameworks via Proxy-array — Array.from snapshot collapses validate+send to a single read", async () => {
    const evilArray = ["EU_AI_ACT", "ISO_42001"];
    let getCallCount = 0;
    const stateFlippingProxy: unknown = new Proxy(evilArray, {
      get(target, prop, receiver) {
        if (typeof prop === "string" && /^\d+$/.test(prop)) {
          getCallCount++;
          const idx = Number(prop);
          if (getCallCount > 2) {
            return "EVIL_FRAMEWORK";
          }
          return target[idx];
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
      config: { frameworks: stateFlippingProxy as string[] },
    });
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.config.frameworks).toEqual(["EU_AI_ACT", "ISO_42001"]);
    expect(getCallCount).toBe(2);
  });

  it("H13: response-side prototype-pollution defense — full pollution + full drop, snapshot wins", async () => {
    // Carry-forward of session-16 second-hostile-review MEDIUM #3.
    // The P2 validator reads response fields through the module-
    // load `objectHasOwn` snapshot. Without this defense, a kernel
    // regression that drops a field combined with a hostile npm dep
    // polluting `Object.prototype.<field>` would let the polluted
    // value pass typeof-check via prototype walk.
    //
    // Pin: pollute Object.prototype with valid-looking values for
    // ALL 10 always-present submit response fields, mock a kernel
    // response missing ALL of them, and assert the SDK throws on
    // `id` (the FIRST field checked) with "got undefined".
    //
    // The build round's it.each already covers each field's missing-
    // own-property branch individually; THIS pin is the FULL
    // pollution + full-drop combined-attack scenario.
    //
    // **NOTE — pollution-resistant mock fetch**: the global
    // `makeMockedClient` reads `r.status ?? 200` to build the
    // Response; polluting `Object.prototype.status = "completed"`
    // makes that read return "completed" via prototype walk, which
    // the Response constructor rejects as a non-numeric status.
    // **Inline a custom mock fetch** that hard-codes status: 200
    // and ignores the polluted prototype reads.
    const localCalls: MockedRequest[] = [];
    const pollutionSafeFetch: FetchLike = async (url, init) => {
      localCalls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      return new Response(JSON.stringify({ success: true, data: {} }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(pollutionSafeFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const originalDescs = new Map<string, PropertyDescriptor | undefined>();
    const fields = [
      "id",
      "jobType",
      "status",
      "totalSystems",
      "processedSystems",
      "failedSystems",
      "results",
      "createdAt",
      "startedAt",
      "completedAt",
    ] as const;
    try {
      const pollutedValues: Record<(typeof fields)[number], unknown> = {
        id: "polluted-id",
        jobType: "classify",
        status: "completed",
        totalSystems: 1,
        processedSystems: 1,
        failedSystems: 0,
        results: [],
        createdAt: "2026-05-12T15:00:00.000Z",
        startedAt: "2026-05-12T15:00:00.500Z",
        completedAt: "2026-05-12T15:00:05.000Z",
      };
      for (const field of fields) {
        originalDescs.set(
          field,
          Object.getOwnPropertyDescriptor(Object.prototype, field),
        );
        (Object.prototype as unknown as Record<string, unknown>)[field] =
          pollutedValues[field];
      }

      // SDK must throw — own-property check sees no own field, so
      // each is read as undefined; first failure (id) fires the
      // AttestryError. WITHOUT the defense, all typeof-checks would
      // pass via prototype walk and the SDK would silently return
      // the polluted values.
      //
      // **Coverage-scope note (session-18 hostile-review #2 MEDIUM
      // #4)**: this pin only exercises the FIRST validated field's
      // (`id`) snapshot under combined pollution + full-drop. The
      // validator throws on the first failure, so the snapshot
      // defenses for the other 9 fields (`jobType`, `status`,
      // `totalSystems`, `processedSystems`, `failedSystems`,
      // `results`, `createdAt`, `startedAt`, `completedAt`) are
      // unexercised in THIS pin. Per-field snapshot defenses for
      // those fields are exercised individually by the `it.each`
      // missing-own-property pins higher in this file — but only
      // under pollution-ABSENT conditions. The COMBINATION
      // (pollution + drop on a non-first field) is not exhaustively
      // tested today. A regression that drops the snapshot on a
      // non-first field would be caught only by the matching
      // missing-own-property pin (no pollution scenario).
      await expect(
        client.batch.submit({
          jobType: "classify",
          systemIds: [VALID_UUID_A],
        }),
      ).rejects.toThrow(
        /expected response\.id to be a string \(got undefined\)/,
      );
    } finally {
      for (const field of fields) {
        const desc = originalDescs.get(field);
        if (desc) {
          Object.defineProperty(Object.prototype, field, desc);
        } else {
          delete (Object.prototype as unknown as Record<string, unknown>)[
            field
          ];
        }
      }
    }
    expect(localCalls).toHaveLength(1);
  });

  it("H14: response with non-BatchSystemResult elements in `results` round-trips (SDK validates Array.isArray only — faithful courier)", async () => {
    // The build round's P2 validator checks `Array.isArray(results)`
    // but NOT per-element shape (faithful courier — kernel emits
    // structured BatchSystemResult rows reliably, but SDK doesn't
    // paranoid-validate per-element). Pin documents: if the kernel
    // ever emits non-BatchSystemResult elements, they round-trip to
    // consumers (typed as BatchSystemResult[] at the call site, but
    // the runtime types are heterogeneous).
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_SUBMIT_RESPONSE,
            results: [
              SAMPLE_SUCCESS_ROW,
              42 as unknown as BatchSystemResult,
              null as unknown as BatchSystemResult,
              { partial: "shape" } as unknown as BatchSystemResult,
            ],
          },
        },
      },
    ]);
    const out = await client.batch.submit({
      jobType: "classify",
      systemIds: [VALID_UUID_A],
    });
    expect(out.results).toEqual([
      SAMPLE_SUCCESS_ROW,
      42,
      null,
      { partial: "shape" },
    ] as unknown as BatchSystemResult[]);
  });

  it("H15: per-row classifications and errorMessage are pollution-unsafe discriminators — `row.status === \"success\"` is the canonical safe check", async () => {
    // The CRITICAL pin for consumer correctness — documents the
    // pollution-unsafe-discriminator pattern (session-17 first-
    // review MEDIUM #3 carry-forward).
    //
    // Pollute Object.prototype.errorMessage with a string. A consumer
    // doing `if (row.errorMessage === undefined)` would think every
    // row is a "success" row (the equality check reads the polluted
    // value via prototype walk, returning false). But
    // `if (row.status === "success")` is correct — `status` is an
    // own-property on every row.
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_SUBMIT_RESPONSE } },
    ]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "errorMessage",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).errorMessage =
        "polluted-via-prototype";
      const out = await client.batch.submit({
        jobType: "classify",
        systemIds: [VALID_UUID_A],
      });
      const row = out.results[0];
      // The POLLUTION-UNSAFE check is true (would misclassify the
      // success row as an error row IF the consumer used this).
      // Pin documents this as a hazard.
      expect((row.errorMessage as unknown) !== undefined).toBe(true);
      // The POLLUTION-SAFE check (closed-enum string match on
      // status) correctly identifies the row as a success row.
      expect(row.status === "success").toBe(true);
      // Verify the SDK preserved the row's own-property shape — the
      // row's OWN errorMessage is genuinely absent (despite the
      // pollution).
      expect(Object.hasOwn(row, "errorMessage")).toBe(false);
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "errorMessage", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .errorMessage;
      }
    }
  });

  it("H16: UUID with leading/trailing whitespace is rejected on systemIds element (regex is anchored)", () => {
    // Already partially covered in build round; H-round adds
    // tab/newline characters explicitly.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [` ${VALID_UUID_A}`],
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [`${VALID_UUID_A} `],
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.batch.submit({
        jobType: "classify",
        systemIds: [`\t${VALID_UUID_A}\n`],
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("H17: jobType case-sensitivity — uppercase 'CLASSIFY' / mixed 'Classify' is rejected (enum is case-sensitive)", () => {
    // Closed-enum SDK pre-rejection is case-sensitive (the Zod
    // `z.enum([...])` is also case-sensitive). The SDK rejects
    // "CLASSIFY" / "Classify" / etc. with a clear TypeError.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.batch.submit({
        jobType: "CLASSIFY" as unknown as BatchSubmitInput["jobType"],
        systemIds: [VALID_UUID_A],
      }),
    ).toThrow(
      /must be one of \["classify","assess","classify_and_assess"\]/,
    );
    expect(() =>
      client.batch.submit({
        jobType: "Classify" as unknown as BatchSubmitInput["jobType"],
        systemIds: [VALID_UUID_A],
      }),
    ).toThrow(
      /must be one of \["classify","assess","classify_and_assess"\]/,
    );
    expect(calls).toHaveLength(0);
  });
});
