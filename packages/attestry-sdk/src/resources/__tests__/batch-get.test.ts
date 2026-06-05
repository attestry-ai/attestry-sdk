import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  BatchJobStatus,
  BatchSystemResult,
} from "../batch.js";
import type { FetchLike } from "../../types.js";

// ─── batch.get — GET + path param, sync request/response ────────────────────
//
// Wire shape (from src/app/api/v1/batch/[id]/route.ts):
//   GET /api/v1/batch/<UUID>
//   → 11-field response (10 of submit's + config):
//     {id, jobType, status: "pending"|"processing"|"completed"|"failed",
//      totalSystems, processedSystems, failedSystems,
//      results: BatchSystemResult[]|null, config: BatchConfig|null,
//      createdAt, startedAt: string|null, completedAt: string|null}
//
// **Second method on the BatchResource** (sibling to `submit()`).
// **First SDK resource with asymmetric auth between methods on the
// same resource** (invariant candidate #54): `submit()` requires a
// key with CLASSIFY or WRITE_ASSESSMENTS UNION; `get()` requires
// only READ_ASSESSMENTS (single permission, NOT a union).
//
// **No plan-guard surface** on `get()` — `requirePlan` is only
// invoked in `submit()`. A free-tier org can `get()` a job
// submitted earlier (e.g., when the org was on a higher plan that
// has since downgraded). Asymmetric with `submit()`'s plan-403.
//
// **400 surface on malformed UUID** — `isValidUuid(id)` returns
// false → `errorResponse("Invalid batch job ID format", 400)`. The
// SDK pre-validates UUID format synchronously (TypeError), so the
// kernel 400 is reachable only via `as any` casts or kernel-side
// UUID flavor changes. **First 400 on a non-XOR-input SDK route.**
//
// **404 literal string** — `Batch job not found` (no embedded
// variable data; ASYMMETRIC with `submit()`'s 404 which embeds
// invalid UUIDs in the message string).
//
// **No `writeAuditLog` side effect** — status reads are quiet
// (asymmetric with `submit()`'s `batch.submitted` write).
//
// **Defensive `.limit(1)`** on the batchJobs query at route.ts:49 —
// belt-and-suspenders against a hypothetical future composite-PK
// schema. Pinned in spec-diff round.
//
// **Wider `status` enum** than `submit()` — GET observes
// `"pending" | "processing" | "completed" | "failed"` (DB column
// pass-through); POST observes only `"completed" | "failed"`. Both
// drift-pinned.
//
// **Nullable response fields** — `results`, `config`, `startedAt`,
// `completedAt` are ALL nullable on GET (vs POST where `results`
// and `completedAt` are always non-null). Pin each separately.

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
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
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const VALID_UUID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const SYSTEM_UUID_A = "11111111-1111-1111-1111-111111111111";
const SYSTEM_UUID_B = "22222222-2222-2222-2222-222222222222";

const SAMPLE_SUCCESS_ROW: BatchSystemResult = {
  systemId: SYSTEM_UUID_A,
  systemName: "Test System A",
  status: "success",
  classifications: { eu_ai_act: "limited" },
};

// 11-field mock — completed job with results.
const MOCK_COMPLETED_JOB: BatchJobStatus = {
  id: VALID_UUID,
  jobType: "classify",
  status: "completed",
  totalSystems: 1,
  processedSystems: 1,
  failedSystems: 0,
  results: [SAMPLE_SUCCESS_ROW],
  config: null,
  createdAt: "2026-05-12T15:00:00.000Z",
  startedAt: "2026-05-12T15:00:00.500Z",
  completedAt: "2026-05-12T15:00:05.000Z",
};

// 11-field mock — pending job (no work done yet).
const MOCK_PENDING_JOB: BatchJobStatus = {
  id: VALID_UUID,
  jobType: "classify",
  status: "pending",
  totalSystems: 5,
  processedSystems: 0,
  failedSystems: 0,
  results: null,
  config: null,
  createdAt: "2026-05-12T15:00:00.000Z",
  startedAt: null,
  completedAt: null,
};

// 11-field mock — processing (mid-flight).
const MOCK_PROCESSING_JOB: BatchJobStatus = {
  id: VALID_UUID,
  jobType: "assess",
  status: "processing",
  totalSystems: 5,
  processedSystems: 2,
  failedSystems: 0,
  results: null,
  config: { frameworks: ["EU_AI_ACT"] },
  createdAt: "2026-05-12T15:00:00.000Z",
  startedAt: "2026-05-12T15:00:00.500Z",
  completedAt: null,
};

// 11-field mock — failed job.
const MOCK_FAILED_JOB: BatchJobStatus = {
  id: VALID_UUID,
  jobType: "classify_and_assess",
  status: "failed",
  totalSystems: 2,
  processedSystems: 0,
  failedSystems: 2,
  results: [
    {
      systemId: SYSTEM_UUID_A,
      systemName: "Test System A",
      status: "error",
      errorMessage: "Classifier crashed",
    },
    {
      systemId: SYSTEM_UUID_B,
      systemName: "Test System B",
      status: "error",
      errorMessage: "Classifier crashed",
    },
  ],
  config: null,
  createdAt: "2026-05-12T15:00:00.000Z",
  startedAt: "2026-05-12T15:00:00.500Z",
  completedAt: "2026-05-12T15:00:10.000Z",
};

describe("batch.get — happy path", () => {
  it("GETs /api/v1/batch/<UUID> with no body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_COMPLETED_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe(`/api/v1/batch/${VALID_UUID}`);
    expect(url.search).toBe("");
    expect(out).toEqual(MOCK_COMPLETED_JOB);
  });

  it("returns the response shape unchanged (envelope unwrapped) — 11 fields", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_COMPLETED_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(Object.keys(out).sort()).toEqual(
      [
        "id",
        "jobType",
        "status",
        "totalSystems",
        "processedSystems",
        "failedSystems",
        "results",
        "config",
        "createdAt",
        "startedAt",
        "completedAt",
      ].sort(),
    );
  });

  it("forwards x-api-key + Accept headers (no body on GET)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_COMPLETED_JOB } },
    ]);
    await client.batch.get(VALID_UUID);
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
  });

  it("returns all 11 response fields with their documented types (sanity)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_COMPLETED_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(typeof out.id).toBe("string");
    expect(typeof out.jobType).toBe("string");
    expect(typeof out.status).toBe("string");
    expect(typeof out.totalSystems).toBe("number");
    expect(typeof out.processedSystems).toBe("number");
    expect(typeof out.failedSystems).toBe("number");
    expect(out.results === null || Array.isArray(out.results)).toBe(true);
    expect(
      out.config === null ||
        (typeof out.config === "object" && !Array.isArray(out.config)),
    ).toBe(true);
    expect(typeof out.createdAt).toBe("string");
    expect(out.startedAt === null || typeof out.startedAt === "string").toBe(
      true,
    );
    expect(out.completedAt === null || typeof out.completedAt === "string").toBe(
      true,
    );
  });
});

describe("batch.get — input validation: id", () => {
  it("throws TypeError for null id — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.get(null as unknown as string)).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined id", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.get(undefined as unknown as string)).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string id (number / object / array)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.get(42 as unknown as string)).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(() => client.batch.get({} as unknown as string)).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(() => client.batch.get([] as unknown as string)).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty string id", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.get("")).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for malformed UUID id (D7 — SDK pre-validates)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.get("not-a-uuid")).toThrow(
      /`id` must be an RFC 4122 hyphenated UUID/,
    );
    expect(() => client.batch.get("11111111-1111-1111-1111")).toThrow(
      /`id` must be an RFC 4122 hyphenated UUID/,
    );
    expect(() =>
      client.batch.get("zzzz0000-0000-0000-0000-000000000000"),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    // Error message includes the offending value for debugging.
    expect(() => client.batch.get("not-a-uuid")).toThrow(/got "not-a-uuid"/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for UUID with prefix/suffix non-hex garbage (regex anchored)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.get(`prefix${VALID_UUID}`)).toThrow(
      /must be an RFC 4122/,
    );
    expect(() => client.batch.get(`${VALID_UUID}suffix`)).toThrow(
      /must be an RFC 4122/,
    );
    expect(() => client.batch.get(`xx${VALID_UUID}yy`)).toThrow(
      /must be an RFC 4122/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for UUID with leading/trailing whitespace (regex anchored)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.get(` ${VALID_UUID}`)).toThrow(
      /must be an RFC 4122/,
    );
    expect(() => client.batch.get(`${VALID_UUID} `)).toThrow(
      /must be an RFC 4122/,
    );
    expect(() => client.batch.get(`\t${VALID_UUID}\n`)).toThrow(
      /must be an RFC 4122/,
    );
    expect(calls).toHaveLength(0);
  });

  it("accepts lowercase UUID (regex is case-insensitive)", async () => {
    const lower = "abcdef00-1234-5678-9abc-deffedcba987";
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, id: lower },
        },
      },
    ]);
    const out = await client.batch.get(lower);
    expect(calls).toHaveLength(1);
    expect(out.id).toBe(lower);
  });

  it("accepts uppercase UUID (regex is case-insensitive)", async () => {
    const upper = "ABCDEF00-1234-5678-9ABC-DEFFEDCBA987";
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, id: upper },
        },
      },
    ]);
    const out = await client.batch.get(upper);
    expect(calls).toHaveLength(1);
    expect(out.id).toBe(upper);
  });
});

describe("batch.get — error paths", () => {
  it("surfaces a 401 (no/invalid API key) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required" },
      },
    ]);
    try {
      await client.batch.get(VALID_UUID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 403 (key lacks READ_ASSESSMENTS — single-permission, NOT a union) as AttestryAPIError", async () => {
    // **DIFFERENT from submit()'s 403** — get() uses single-permission
    // auth, NOT a union. The kernel emits the single permission in
    // the error message (NOT "X or Y" like submit's union).
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error:
            "API key lacks required permission. Required: read:assessments. Key has: read:documents.",
        },
      },
    ]);
    try {
      await client.batch.get(VALID_UUID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.message).toMatch(/Required: read:assessments\./);
      // get()'s 403 has NO " or " in the Required list — single
      // permission, NOT a union (asymmetric with submit's 403).
      expect(apiErr.message).not.toMatch(/Required: [^.]+ or /);
    }
  });

  it("surfaces a 400 (malformed UUID — only reachable via kernel-side change, SDK pre-validates) as AttestryAPIError", async () => {
    // The SDK pre-validates UUID format synchronously, so this 400
    // path is unreachable in practice today. The pin documents the
    // surface for forward-compat (kernel-side switch to a different
    // UUID flavor would surface here).
    const { client, calls } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Invalid batch job ID format" },
      },
    ]);
    // Bypass SDK pre-validation via `as any` — simulate the future
    // case where SDK and kernel UUID rules diverge.
    const fakeFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      return new Response(
        JSON.stringify({ success: false, error: "Invalid batch job ID format" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      );
    };
    const c2 = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(fakeFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    // Use a valid-by-SDK UUID so we reach the kernel; kernel-side
    // imagined check rejects it as 400.
    try {
      await c2.batch.get(VALID_UUID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.message).toMatch(/Invalid batch job ID format/);
    }
  });

  it("surfaces a 404 (batch job not found — LITERAL string, no embedded data) as AttestryAPIError — ASYMMETRIC with submit's 404 shape", async () => {
    // **NEW shape vs submit()'s 404** — get's 404 is a LITERAL
    // string with no variable data. Cross-org `id` collapses to
    // the same 404 (the where-clause silently filters).
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "Batch job not found" },
      },
    ]);
    try {
      await client.batch.get(VALID_UUID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      // Literal string only — no embedded UUID, no comma-joined list.
      expect(apiErr.message).toBe("Batch job not found");
      // Distinct from submit's 404 wording.
      expect(apiErr.message).not.toMatch(/Systems not found/);
      expect(apiErr.message).not.toMatch(/not in your organization/);
    }
  });

  it("surfaces a 429 (rate limit — `apiLimiter` 60/min, looser than submit's 30/min) as AttestryAPIError when retry is disabled", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: { success: false, error: "Too many requests." },
      },
    ]);
    try {
      await client.batch.get(VALID_UUID);
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
      await client.batch.get(VALID_UUID);
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
        JSON.stringify({ success: true, data: MOCK_COMPLETED_JOB }),
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
      await client.batch.get(VALID_UUID);
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

describe("batch.get — response shape preservation (all batch-job statuses)", () => {
  it("`completed` job round-trips (results array, all dates set)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_COMPLETED_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out).toEqual(MOCK_COMPLETED_JOB);
  });

  it("`pending` job round-trips — `results` is null, `startedAt`/`completedAt` are null", async () => {
    // **The asymmetric-vs-POST pin**: a pending job has null for
    // results / startedAt / completedAt; POST submit responses
    // never have these as null (always-processed inline).
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PENDING_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.status).toBe("pending");
    expect(out.results).toBeNull();
    expect(out.startedAt).toBeNull();
    expect(out.completedAt).toBeNull();
  });

  it("`processing` job round-trips — startedAt set, completedAt null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PROCESSING_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.status).toBe("processing");
    expect(typeof out.startedAt).toBe("string");
    expect(out.completedAt).toBeNull();
  });

  it("`failed` job round-trips — all rows status: 'error', no successful classifications", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_FAILED_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.status).toBe("failed");
    expect(out.results).toHaveLength(2);
    expect(out.results![0].status).toBe("error");
    expect(out.results![1].status).toBe("error");
  });

  it("config: null round-trips when consumer omitted config at submission", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_COMPLETED_JOB, config: null } } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.config).toBeNull();
  });

  it("config: {frameworks: [...]} round-trips when consumer provided config at submission", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_COMPLETED_JOB,
            config: { frameworks: ["EU_AI_ACT", "ISO_42001"] },
          },
        },
      },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.config).toEqual({ frameworks: ["EU_AI_ACT", "ISO_42001"] });
  });

  it("config: {} (empty object) round-trips — distinct from null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_COMPLETED_JOB, config: {} } } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.config).toEqual({});
  });

  it("status: 'pending' round-trips as literal string (wider enum than submit's response)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PENDING_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.status).toBe("pending");
    // GET's wider enum allows pending; submit's narrower enum does
    // NOT. Pin the asymmetry.
    expect((["pending", "processing", "completed", "failed"] as string[]).includes(out.status)).toBe(true);
  });

  it("status: 'processing' round-trips as literal string", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PROCESSING_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.status).toBe("processing");
  });

  it("passes through extra unknown top-level fields verbatim (forward-compat)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_COMPLETED_JOB,
            futureField: "added kernel-side without an SDK bump",
            cursor: "abc123",
          },
        },
      },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect((out as unknown as Record<string, unknown>).futureField).toBe(
      "added kernel-side without an SDK bump",
    );
    expect((out as unknown as Record<string, unknown>).cursor).toBe("abc123");
  });
});

describe("batch.get — P2 response shape hardening", () => {
  it("P2: throws AttestryError when kernel response is null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected an object response from the kernel \(got null\)/,
    );
  });

  it("P2: throws AttestryError when kernel response is a scalar (string)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: "scalar" } },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected an object response from the kernel \(got string\)/,
    );
  });

  it("P2: throws AttestryError when kernel response is an array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_COMPLETED_JOB] } },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected an object response from the kernel \(got array\)/,
    );
  });

  it("P2: throws AttestryError when response.id is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_COMPLETED_JOB, id: 42 } },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.id to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.jobType is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_COMPLETED_JOB, jobType: 1 } },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.jobType to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.status is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_COMPLETED_JOB, status: false } },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.status to be a string \(got boolean\)/,
    );
  });

  it("P2: throws AttestryError when response.totalSystems is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, totalSystems: "1" },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.totalSystems to be a number \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.processedSystems is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, processedSystems: "0" },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.processedSystems to be a number \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.failedSystems is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, failedSystems: [] },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.failedSystems to be a number \(got array\)/,
    );
  });

  it("P2: throws AttestryError when response.results is not array-or-null (string)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, results: "not-an-array" },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.results to be an array or null \(got string\)/,
    );
  });

  it("P2 accepts results: null (pending jobs have no results yet) — distinct from POST where results is always an array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PENDING_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.results).toBeNull();
  });

  it("P2: throws AttestryError when response.config is not object-or-null (string)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, config: "not-an-object" },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.config to be an object or null \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.config is an array (typeof [] === 'object')", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, config: ["evil"] },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.config to be an object or null \(got array\)/,
    );
  });

  it("P2: throws AttestryError when response.createdAt is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, createdAt: 1234567890 },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.createdAt to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.startedAt is not string-or-null", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, startedAt: 12345 },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.startedAt to be a string or null \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.completedAt is not string-or-null (distinct from POST where completedAt is non-nullable)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, completedAt: 12345 },
        },
      },
    ]);
    await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
      /expected response\.completedAt to be a string or null \(got number\)/,
    );
  });

  it("P2 accepts completedAt: null (pending/processing jobs)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PROCESSING_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.completedAt).toBeNull();
  });

  it("P2 error is AttestryError (NOT AttestryAPIError) — distinct surface for kernel-shape regressions", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    try {
      await client.batch.get(VALID_UUID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      expect(err).not.toBeInstanceOf(AttestryAPIError);
    }
  });

  // Per-always-present-field MISSING own-property pins. 11 rows
  // (POST has 10; GET adds config). Earlier-in-the-validation-order
  // fields must be PRESENT in the mock so the SDK reaches the field
  // under test before throwing. CRITICAL: `delete data[fieldName]`
  // (not `data[fieldName] = undefined`) — own-property false is what
  // the test exercises.
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
      /expected response\.results to be an array or null \(got undefined\)/,
    ],
    [
      "config",
      /expected response\.config to be an object or null \(got undefined\)/,
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
      /expected response\.completedAt to be a string or null \(got undefined\)/,
    ],
  ] as const)(
    "P2 missing-%s: own-property false → AttestryError naming the field with 'got undefined'",
    async (fieldName, expectedMsg) => {
      const data: Record<string, unknown> = { ...MOCK_COMPLETED_JOB };
      delete data[fieldName];
      const { client } = makeMockedClient([
        { body: { success: true, data } },
      ]);
      await expect(client.batch.get(VALID_UUID)).rejects.toThrow(expectedMsg);
    },
  );
});

describe("batch.get — abort + retry semantics", () => {
  it("forwards a pre-aborted AbortSignal through RequestOptions (no fetch)", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.batch.get(VALID_UUID, { signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_COMPLETED_JOB } },
    ]);
    const controller = new AbortController();
    const out = await client.batch.get(VALID_UUID, {
      signal: controller.signal,
    });
    expect(out.id).toBe(VALID_UUID);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies (independent of resource-helper default)", async () => {
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "x" } },
      { body: { success: true, data: MOCK_COMPLETED_JOB } },
    ];
    const calls: MockedRequest[] = [];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
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
    const promise = client.batch.get(VALID_UUID, {
      retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 },
    });
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out.id).toBe(VALID_UUID);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });
});

describe("batch.get — hostile round residual gaps", () => {
  it("HG1: concurrent batch.get() calls share no state — each promise resolves independently", async () => {
    // Pin against a future refactor that adds shared state
    // (memoization, response caching). Each call must construct
    // its own promise; the mocked fetch routes them to distinct
    // mock responses by call order.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, status: "completed" },
        },
      },
      {
        body: { success: true, data: MOCK_PENDING_JOB },
      },
      {
        body: { success: true, data: MOCK_PROCESSING_JOB },
      },
    ]);
    const [out1, out2, out3] = await Promise.all([
      client.batch.get(VALID_UUID),
      client.batch.get(VALID_UUID),
      client.batch.get(VALID_UUID),
    ]);
    expect(calls).toHaveLength(3);
    expect(out1.status).toBe("completed");
    expect(out2.status).toBe("pending");
    expect(out3.status).toBe("processing");
  });

  it("HG2: 429 auto-retries when retry is enabled (default) and succeeds on second attempt", async () => {
    // Build round only pinned the retry-disabled path. Hostile
    // round adds the retry-enabled path — invariant #18: SDK auto-
    // retries on 429 with exponential backoff. Mirror of batch-
    // submit's H6.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "rate limited" } },
      { body: { success: true, data: MOCK_COMPLETED_JOB } },
    ];
    const calls: MockedRequest[] = [];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
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
    });
    const promise = client.batch.get(VALID_UUID);
    await vi.advanceTimersByTimeAsync(2_500);
    const out = await promise;
    expect(out.id).toBe(VALID_UUID);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });

  it("HG3: response-side prototype-pollution defense — full pollution + full drop on 11 fields, snapshot wins", async () => {
    // Carry-forward of session-16 second-hostile-review MEDIUM #3
    // applied to the wider 11-field GET response shape (POST had
    // 10 fields; GET adds `config`).
    //
    // Pin: pollute Object.prototype with valid-looking values for
    // ALL 11 always-present GET response fields, mock a kernel
    // response missing ALL of them, and assert the SDK throws on
    // `id` (the FIRST field checked) with "got undefined".
    //
    // **NOTE — pollution-resistant mock fetch**: same caveat as
    // batch-submit's H13; polluting `Object.prototype.status =
    // "completed"` breaks the global makeMockedClient's
    // `r.status ?? 200` Response init read. Inline a mock that
    // hard-codes status: 200 and ignores the prototype.
    const localCalls: MockedRequest[] = [];
    const pollutionSafeFetch: FetchLike = async (url, init) => {
      localCalls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
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
      "config",
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
        config: null,
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
      // **Coverage-scope note (session-18 hostile-review #2 MEDIUM
      // #4)**: this pin only exercises the FIRST validated field's
      // (`id`) snapshot under combined pollution + full-drop. The
      // validator throws on the first failure, so the snapshot
      // defenses for the other 10 fields (jobType, status,
      // totalSystems, processedSystems, failedSystems, results,
      // config, createdAt, startedAt, completedAt) are unexercised
      // in THIS pin. Per-field snapshot defenses for those fields
      // are exercised individually by the `it.each` missing-own-
      // property pins higher in this file — but only under
      // pollution-ABSENT conditions. The COMBINATION (pollution +
      // drop on a non-first field) is not exhaustively tested today.
      await expect(client.batch.get(VALID_UUID)).rejects.toThrow(
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

  it("HG4: response-side pollution on `config` field — own-property false bypasses validation when config is genuinely absent (which shouldn't happen but exercises the defense)", async () => {
    // Edge case: the kernel ALWAYS emits `config` on GET (even if
    // null). But a future regression could drop it. Pin: pollute
    // Object.prototype.config with a valid-looking shape, mock a
    // response missing config (and ONLY config — the SDK still has
    // to validate it; "absent + polluted" must surface as the P2
    // error, not silently succeed via prototype walk).
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_COMPLETED_JOB, config: undefined },
          // CRITICAL: use the explicit-undefined approach to drop
          // own-property via spread. We need a custom data shape
          // without `config` as own-property.
        },
      },
    ]);
    // Override calls: build the data without config as own-property.
    const dataNoConfig: Record<string, unknown> = { ...MOCK_COMPLETED_JOB };
    delete dataNoConfig["config"];
    const { client: c2 } = makeMockedClient([
      {
        body: { success: true, data: dataNoConfig },
      },
    ]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "config",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).config = {
        frameworks: ["POLLUTED"],
      };
      await expect(c2.batch.get(VALID_UUID)).rejects.toThrow(
        /expected response\.config to be an object or null \(got undefined\)/,
      );
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "config", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>).config;
      }
    }
    void client;
    expect(calls).toHaveLength(0);
  });

  it("HG5: response with non-BatchSystemResult elements in `results` round-trips (SDK validates Array.isArray-or-null only — faithful courier)", async () => {
    // Mirror of batch-submit's H14, but verify the GET path's
    // P2 validator also accepts non-BatchSystemResult-shaped rows.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_COMPLETED_JOB,
            results: [
              SAMPLE_SUCCESS_ROW,
              42,
              null,
              { partial: "shape" },
            ],
          },
        },
      },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.results).toEqual([
      SAMPLE_SUCCESS_ROW,
      42,
      null,
      { partial: "shape" },
    ] as unknown as BatchSystemResult[]);
  });

  it("HG6: GET response with `status: \"pending\"` round-trips — wider enum than submit's response (asymmetric documented)", async () => {
    // Pin documents the asymmetric-vs-submit enum width. The wire
    // value `"pending"` would be unreachable on submit's response
    // (kernel computes "completed"|"failed" at handler end), but
    // get() observes it for jobs not yet processed.
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PENDING_JOB } },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.status).toBe("pending");
    // GET's wider enum allows pending; the runtime P2 validator
    // checks typeof === "string" only (faithful courier).
    expect(typeof out.status).toBe("string");
  });

  it("HG7: unknown future `status` value (e.g., 'cancelled') round-trips — type contract closed, runtime open (faithful courier)", async () => {
    // **Type contract is closed (`BatchJobStatusValue` 4-enum);
    // runtime is open** — same pattern as gate's `gate: "pass" |
    // "fail"` runtime asymmetry. The kernel may extend the status
    // enum (e.g., adding "cancelled") before the SDK is bumped;
    // the value round-trips at runtime, typed as the closed union
    // at compile time but holding the new string at runtime.
    //
    // Consumers using exhaustive type-narrowing
    // (`if (status === "completed") ... else /* TS: ... */`)
    // would misclassify an unknown value. The drift suite catches
    // a kernel extension before consumer regressions (Pin 3 in the
    // spec-diff round).
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PENDING_JOB, status: "cancelled" },
        },
      },
    ]);
    const out = await client.batch.get(VALID_UUID);
    expect(out.status as unknown as string).toBe("cancelled");
  });

  it("HG8: empty-string id is rejected — distinct from undefined / null (D7 — non-empty string check fires first)", () => {
    // The build round covered this but the H-round adds the
    // distinction-from-malformed-UUID error wording: empty string
    // gets "must be a non-empty string", malformed but non-empty
    // gets "must be an RFC 4122 hyphenated UUID".
    const { client, calls } = makeMockedClient([]);
    expect(() => client.batch.get("")).toThrow(
      /`id` must be a non-empty string/,
    );
    // Distinction-from-malformed: a non-empty string that's not a
    // UUID gets a different (more specific) error.
    expect(() => client.batch.get("x")).toThrow(
      /`id` must be an RFC 4122 hyphenated UUID/,
    );
    expect(calls).toHaveLength(0);
  });
});
