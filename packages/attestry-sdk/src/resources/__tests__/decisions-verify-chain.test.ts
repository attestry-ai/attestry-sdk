import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  // Result-shape type import — pinned at compile time. If
  // ChainVerificationResult is dropped from `index.ts` or the
  // resource's exports, this file fails to compile and the test run
  // aborts before any pin runs.
  ChainVerificationResult,
} from "../decisions.js";
import type { FetchLike } from "../../types.js";

// ─── decisions.verifyChain — GET hash-chain integrity verdict ───────────────
//
// Wire shape (kernel src/app/api/v1/decisions/verify-chain/[systemId]/route.ts):
//   GET /api/v1/decisions/verify-chain/{systemId}
//   Auth: x-api-key (read:assessments) OR session
//   200 OK on a VALID chain: {success:true, data: ChainVerificationResult{chainValid:true, ...}}
//   200 OK on a TAMPERED chain: {success:true, data: ChainVerificationResult{chainValid:false, ...}}
//   400 invalid systemId format
//   401/403 auth (statusCode propagated from AuthError)
//   404 cross-org collapse (system not found)
//   413 ChainTooLong with details.hint referencing decisions/export
//   429 rate limit
//   500 internal (scrubbed message)
//
// CRITICAL contract: the SDK MUST resolve the Promise on chainValid:false.
// Mirror of decisions.bulk's partial-success contract — the customer asked
// the chain-integrity question and the kernel answered. Top-level structural
// failures (auth, rate limit, system-not-found, ChainTooLong) DO throw.
// Carry-forward invariant #12.

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
    // Resource tests disable retry so a 429 mock doesn't hang on backoff
    // and accidentally consume the next mock response. The retry-semantics
    // describe block below opts back in via per-call options.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const SYSTEM_ID = "11111111-2222-3333-4444-555555555555";

const VALID_RESULT: ChainVerificationResult = {
  systemId: SYSTEM_ID,
  recordCount: 5,
  activeRecordCount: 5,
  tombstonedRecordCount: 0,
  chainValid: true,
  lastVerifiedSequence: 5,
  lastVerifiedAt: "2026-05-07T12:00:00.000Z",
  tamperedRecordIds: [],
  brokenRecordIds: [],
  performanceMetrics: { verificationDurationMs: 12, recordsPerSecond: 416 },
};

const TAMPERED_RESULT: ChainVerificationResult = {
  systemId: SYSTEM_ID,
  recordCount: 5,
  activeRecordCount: 5,
  tombstonedRecordCount: 0,
  chainValid: false,
  lastVerifiedSequence: 2,
  lastVerifiedAt: "2026-05-07T12:00:00.000Z",
  tamperedRecordIds: [
    "33333333-3333-3333-3333-333333333333",
    "44444444-4444-4444-4444-444444444444",
  ],
  brokenRecordIds: [],
  performanceMetrics: { verificationDurationMs: 8, recordsPerSecond: 625 },
};

const BROKEN_RESULT: ChainVerificationResult = {
  systemId: SYSTEM_ID,
  recordCount: 4,
  activeRecordCount: 4,
  tombstonedRecordCount: 0,
  chainValid: false,
  lastVerifiedSequence: 1,
  lastVerifiedAt: "2026-05-07T12:00:00.000Z",
  tamperedRecordIds: [],
  brokenRecordIds: ["55555555-5555-5555-5555-555555555555"],
  performanceMetrics: { verificationDurationMs: 6, recordsPerSecond: 666 },
};

const EMPTY_RESULT: ChainVerificationResult = {
  systemId: SYSTEM_ID,
  recordCount: 0,
  activeRecordCount: 0,
  tombstonedRecordCount: 0,
  chainValid: true,
  lastVerifiedSequence: 0,
  lastVerifiedAt: "2026-05-07T12:00:00.000Z",
  tamperedRecordIds: [],
  brokenRecordIds: [],
  performanceMetrics: { verificationDurationMs: 0, recordsPerSecond: 0 },
};

const CHAIN_TOO_LONG_HINT =
  "Chain exceeds sync verification limit. Use POST /api/v1/decisions/export to download the full chain and verify offline.";

// vi.useFakeTimers() in H9 (mid-backoff abort) needs cleanup so other
// tests (esp. retry-semantics block above, which uses real timers via
// short initialDelayMs) aren't affected. Mirror retry.test.ts:27-29.
// Hostile-review F5: H9 also stubs Math.random — restore mocks here
// so the stub doesn't leak into other tests' jitter calculations.
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("decisions.verifyChain — happy path", () => {
  it("GETs /api/v1/decisions/verify-chain/{systemId} with no body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/decisions/verify-chain/${SYSTEM_ID}`,
    );
    // GET → no body. Transport must NOT send Content-Type either.
    expect(calls[0].body).toBeUndefined();
    expect(calls[0].headers.get("Content-Type")).toBeNull();
    // Transport unwraps the {success:true, data} envelope — bare result.
    expect(out).toEqual(VALID_RESULT);
  });

  it("returns the ChainVerificationResult shape unchanged (envelope unwrapped, D2)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    // Pin every documented field to catch a future refactor that
    // accidentally drops one (the resource doesn't transform; this
    // would only break if the transport lost a field).
    expect(out.systemId).toBe(SYSTEM_ID);
    expect(out.recordCount).toBe(5);
    expect(out.activeRecordCount).toBe(5);
    expect(out.tombstonedRecordCount).toBe(0);
    expect(out.chainValid).toBe(true);
    expect(out.lastVerifiedSequence).toBe(5);
    expect(out.lastVerifiedAt).toBe("2026-05-07T12:00:00.000Z");
    expect(out.tamperedRecordIds).toEqual([]);
    expect(out.brokenRecordIds).toEqual([]);
    expect(out.performanceMetrics).toEqual({
      verificationDurationMs: 12,
      recordsPerSecond: 416,
    });
  });

  it("forwards x-api-key + Accept headers (transport-level smoke)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    await client.decisions.verifyChain(SYSTEM_ID);
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
  });

  it("sends NO query string (path-segment-only — D4)", async () => {
    // Pin: verifyChain has no query parameters. The URL must NOT contain
    // a "?" anywhere — confirms the input rides in the path, not the
    // query string. A future refactor that wrapped systemId in an
    // input-object overload could regress here if it accidentally
    // routed through encodeQuery.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    await client.decisions.verifyChain(SYSTEM_ID);
    expect(calls[0].url).not.toContain("?");
  });

  it("preserves lastVerifiedAt as a string (NOT a Date instance)", async () => {
    // Wire is ISO-8601 string per the kernel. SDK does NOT auto-parse.
    // Consumer parses via `new Date(value)` if needed. Pin: the property
    // is a JS string with the kernel's verbatim format.
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(typeof out.lastVerifiedAt).toBe("string");
    expect(out.lastVerifiedAt).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
    expect(out.lastVerifiedAt).not.toBeInstanceOf(Date);
  });

  it("preserves tamperedRecordIds + brokenRecordIds order verbatim", async () => {
    // Defensive: the SDK does NOT sort, dedupe, or rewrite the ID
    // arrays. Position is meaningful — the kernel orders them by the
    // sequence in which the failure was first detected. A future
    // refactor that ran `.sort()` for "consistency" would break the
    // sequence relationship.
    const result: ChainVerificationResult = {
      ...TAMPERED_RESULT,
      tamperedRecordIds: ["c-id", "a-id", "b-id"],
      brokenRecordIds: ["z-id", "x-id", "y-id"],
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: result } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.tamperedRecordIds).toEqual(["c-id", "a-id", "b-id"]);
    expect(out.brokenRecordIds).toEqual(["z-id", "x-id", "y-id"]);
  });
});

// ─── Input validation (pre-fetch, synchronous) ──────────────────────────────

describe("decisions.verifyChain — input validation (pre-fetch)", () => {
  it("throws TypeError for empty systemId (does not issue a request)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.verifyChain("")).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId (defensive against runtime cast)", async () => {
    // Static typing prevents this; runtime guard catches consumers using
    // `as unknown as string` casts (or unsanitized JSON input). Pinned so
    // the typeof check isn't quietly removed.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.verifyChain(null as unknown as string),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.verifyChain(42 as unknown as string),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.verifyChain(undefined as unknown as string),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.verifyChain({} as unknown as string),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError (NOT URIError) for systemIds containing lone UTF-16 surrogates", async () => {
    // encodeURIComponent throws URIError on malformed UTF-16 (lone
    // surrogate halves). Without the resource's try/catch, that error
    // class would leak to consumers — inconsistent with the TypeError
    // they already get for empty / non-string ids. Mirror of
    // decisions.retrieve's L1 hostile pin (carry-forward invariant #32).
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.verifyChain("\uD800")).toThrowError(
      TypeError,
    );
    try {
      client.decisions.verifyChain("prefix\uD800suffix");
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toContain(
        "decisions.verifyChain: `systemId` contains invalid UTF-16 sequences",
      );
      // Original URIError is preserved as the cause for debugging.
      expect((err as Error).cause).toBeDefined();
      expect((err as Error).cause).toBeInstanceOf(URIError);
    }
    expect(calls).toHaveLength(0);
  });

  it("error message names `decisions.verifyChain:` and the offending field", async () => {
    // Pin the prefix verbatim — consumers may rely on the method-name
    // prefix to route validation errors to the right call site.
    const { client } = makeMockedClient([]);
    try {
      client.decisions.verifyChain("");
    } catch (err) {
      expect((err as TypeError).message).toBe(
        "decisions.verifyChain: `systemId` is required",
      );
    }
  });

  it("does NOT trim leading/trailing whitespace (server's UUID validator rejects)", async () => {
    // Pass-through: SDK forwards the systemId as-is. Trimming would hide
    // bugs in caller code (whitespace isn't valid in a UUID; consumer
    // should fix it at source). The encoded path includes the literal
    // whitespace as %20.
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid systemId format." } },
    ]);
    try {
      await client.decisions.verifyChain(`  ${SYSTEM_ID}  `);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      // %20 is encodeURIComponent's representation of the literal space —
      // confirms the systemId rode the path verbatim, no trimming.
      expect(calls[0].url).toContain("%20");
      expect((err as AttestryAPIError).status).toBe(400);
    }
  });

  it("synchronous: no fetch issued on validation failure", async () => {
    // Pin that the throw happens BEFORE the network call — important
    // for the abort-pre-fetch contract and so a misbehaving caller
    // can't burn through the rate limit by spamming bad inputs.
    const fetchSpy = vi.fn();
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
    });
    expect(() => client.decisions.verifyChain("")).toThrowError(TypeError);
    expect(() => client.decisions.verifyChain("\uD800")).toThrowError(
      TypeError,
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("rejects systemId='..' / '.' / NUL-byte strings (path-traversal under fetch URL normalization)", async () => {
    // Hostile-review F1: encodeURIComponent does NOT encode `.` or `..`,
    // and WHATWG-spec fetch (Node 18+, browsers) normalizes URL paths
    // before sending — `verify-chain/..` collapses to `verify-chain/`'s
    // PARENT (`/api/v1/decisions/`, the LIST endpoint), and `verify-chain/.`
    // collapses to `/api/v1/decisions/verify-chain/`. The kernel happily
    // returns 200 with a list-shaped body and the SDK consumer sees
    // `verdict.chainValid === undefined` — a silent endpoint redirect.
    // Block the exact-match path-segment-traversal characters at the
    // SDK boundary BEFORE fetch can normalize them away. Embedded
    // traversal (e.g. "foo/../bar") is safe because encodeURIComponent
    // encodes the `/` as `%2F` so the path stays a single segment.
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.verifyChain("..")).toThrowError(
      TypeError,
    );
    expect(() => client.decisions.verifyChain(".")).toThrowError(
      TypeError,
    );
    expect(() => client.decisions.verifyChain("foo\0bar")).toThrowError(
      TypeError,
    );
    // Error message names the offending field so consumers route on it.
    try {
      client.decisions.verifyChain("..");
    } catch (err) {
      expect((err as TypeError).message).toContain(
        "decisions.verifyChain: `systemId` contains invalid path-segment characters",
      );
    }
    expect(calls).toHaveLength(0);
  });

  it("does NOT over-block embedded `..` (e.g. 'foo/../bar' is encoded safely as one segment)", async () => {
    // Defensive negative pin: the F1 guard rejects systemId === "."
    // or "..", but embedded path-traversal-looking text is benign
    // because `/` gets encoded as `%2F`, so the URL parser sees a
    // single segment and doesn't normalize. Pin so a future "harden
    // the guard" refactor doesn't accidentally block legitimate
    // (server-rejected) UUID-shaped strings that happen to contain
    // "..".
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid systemId format." } },
    ]);
    let caught: unknown;
    try {
      await client.decisions.verifyChain("foo/../bar");
    } catch (err) {
      caught = err;
    }
    // Encoded — slash + dots are all encoded into one path segment.
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/verify-chain/foo%2F..%2Fbar",
    );
    // Error is the kernel's 400 (server-side UUID rejection), NOT the
    // SDK-side path-traversal TypeError. Confirms the guard is exact-
    // match only.
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(400);
  });
});

// ─── Partial-success envelope (CRITICAL — does NOT throw on chainValid:false) ─

describe("decisions.verifyChain — partial-success envelope (CRITICAL contract)", () => {
  it("200 with chainValid:true → resolves with the verdict body", async () => {
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.chainValid).toBe(true);
    expect(out.tamperedRecordIds).toEqual([]);
    expect(out.brokenRecordIds).toEqual([]);
  });

  it("200 with chainValid:false (tampered) → RESOLVES (NOT rejects) with verdict body", async () => {
    // CRITICAL contract pin. The kernel returns 200 with chainValid:false
    // on detected tampering; the SDK MUST NOT throw. Mirror of
    // decisions.bulk's partial-success contract. Carry-forward invariant
    // #12. A future refactor that interpreted 200 + a "negative" payload
    // field as an error would break here.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: TAMPERED_RESULT } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.chainValid).toBe(false);
    expect(out.tamperedRecordIds).toHaveLength(2);
    expect(out.tamperedRecordIds).toEqual([
      "33333333-3333-3333-3333-333333333333",
      "44444444-4444-4444-4444-444444444444",
    ]);
    expect(out.lastVerifiedSequence).toBe(2);
  });

  it("200 with chainValid:false (broken) → resolves; brokenRecordIds populated, tampered empty", async () => {
    // Distinguish from the tampered case so consumers can branch on
    // SECURITY (tampered) vs OPS (broken) without inspecting both arrays.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: BROKEN_RESULT } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.chainValid).toBe(false);
    expect(out.tamperedRecordIds).toEqual([]);
    expect(out.brokenRecordIds).toEqual([
      "55555555-5555-5555-5555-555555555555",
    ]);
  });

  it("200 with chainValid:false AND both arrays non-empty → both preserved verbatim", async () => {
    // Server fires `chain.tampered` (security takes precedence at
    // webhook dispatch); SDK doesn't see the webhook event. Both
    // arrays appear in the response and the SDK preserves both.
    const both: ChainVerificationResult = {
      ...TAMPERED_RESULT,
      tamperedRecordIds: ["t-1", "t-2"],
      brokenRecordIds: ["b-1", "b-2", "b-3"],
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: both } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.chainValid).toBe(false);
    expect(out.tamperedRecordIds).toHaveLength(2);
    expect(out.brokenRecordIds).toHaveLength(3);
  });

  it("empty chain (recordCount:0) → resolves with chainValid:true, recordsPerSecond:0", async () => {
    // Vacuous truth — an empty chain is valid by definition. The kernel
    // guards divide-by-zero and returns 0 for recordsPerSecond; SDK
    // preserves verbatim (does NOT recompute).
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: EMPTY_RESULT } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.chainValid).toBe(true);
    expect(out.recordCount).toBe(0);
    expect(out.activeRecordCount).toBe(0);
    expect(out.tombstonedRecordCount).toBe(0);
    expect(out.lastVerifiedSequence).toBe(0);
    expect(out.tamperedRecordIds).toEqual([]);
    expect(out.brokenRecordIds).toEqual([]);
    expect(out.performanceMetrics.verificationDurationMs).toBe(0);
    expect(out.performanceMetrics.recordsPerSecond).toBe(0);
  });

  it("sub-millisecond verification → recordsPerSecond:0 preserved verbatim", async () => {
    // Kernel guards 0 records OR 0 ms duration. Pin the divide-by-zero
    // case explicitly so a future SDK-side recompute (NaN, Infinity)
    // would surface here.
    const fast: ChainVerificationResult = {
      ...VALID_RESULT,
      recordCount: 3,
      activeRecordCount: 3,
      performanceMetrics: { verificationDurationMs: 0, recordsPerSecond: 0 },
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: fast } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.performanceMetrics.verificationDurationMs).toBe(0);
    expect(out.performanceMetrics.recordsPerSecond).toBe(0);
    // recordsPerSecond is NEVER NaN/Infinity even when the SDK would
    // naïvely have computed records/0. The kernel is authoritative.
    expect(Number.isFinite(out.performanceMetrics.recordsPerSecond)).toBe(
      true,
    );
  });

  it("extra fields on the result (forward-compat) pass through opaquely", async () => {
    // The transport doesn't strict-check the response. New kernel fields
    // (e.g., `merkleRoot`, `proof`) flow through as extra properties on
    // the returned object — TypeScript-erased but observable at runtime.
    // Pin: SDK still resolves cleanly, documented fields still present.
    const withExtras = {
      ...VALID_RESULT,
      merkleRoot:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      proof: { type: "ed25519", signature: "..." },
      futureCounter: 42,
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: withExtras } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.chainValid).toBe(true);
    expect(out.systemId).toBe(SYSTEM_ID);
    // Extra fields are present on the runtime object (TypeScript-erased
    // but observable) — confirms forward-compat behavior.
    const opaque = out as ChainVerificationResult & {
      merkleRoot?: string;
      proof?: unknown;
      futureCounter?: number;
    };
    expect(opaque.merkleRoot).toMatch(/^sha256:/);
    expect(opaque.futureCounter).toBe(42);
  });
});

// ─── Top-level error paths (these THROW AttestryAPIError) ───────────────────

describe("decisions.verifyChain — top-level error paths", () => {
  it("400 (invalid UUID format) → AttestryAPIError(400)", async () => {
    // Server's `isValidUuid` rejects non-UUID systemIds with 400 (NOT
    // 422 — this endpoint has no Zod query schema). Distinct from the
    // bulk/ingest 422 surface.
    const { client } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Invalid systemId format." },
      },
    ]);
    try {
      await client.decisions.verifyChain("not-a-uuid");
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.message).toBe("Invalid systemId format.");
    }
  });

  it("401 (auth required) → AttestryAPIError(401)", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required." },
      },
    ]);
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("403 (custom AuthError statusCode propagated) → AttestryAPIError(403)", async () => {
    // The route's catch passes `error.statusCode` through verbatim, so
    // an upstream AuthError thrown with statusCode:403 (e.g.,
    // "API key missing read:assessments scope") flows through as-is.
    // Pin both 401 and 403 branches so the distinction is preserved.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error: "API key missing required permission: read:assessments.",
        },
      },
    ]);
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
      expect((err as AttestryAPIError).message).toContain(
        "read:assessments",
      );
    }
  });

  it("404 (system not found OR cross-org) → AttestryAPIError(404), single body shape", async () => {
    // Cross-org enumeration safety: "doesn't exist" and "exists but
    // belongs to another org" collapse into a single 404 with one
    // canonical body. Pin: the body does NOT distinguish the two cases.
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "System not found." },
      },
    ]);
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.message).toBe("System not found.");
    }
  });

  it("413 (ChainTooLong) → AttestryAPIError(413) with details.hint referencing decisions/export", async () => {
    // The kernel's errorResponse for 413 carries a structured hint
    // pointing the consumer at the export endpoint for offline
    // verification. Pin verbatim regex `/decisions\/export/` — a kernel
    // rewording that preserves the route reference still passes; one
    // that drops it fails. This is the consumer's signal to switch
    // endpoints.
    // Mock body matches kernel's actual ChainTooLongError emission
    // verbatim (src/lib/decisions/chain-verification.ts:62-64) — the
    // constructor produces "Chain length exceeds sync limit 50000"
    // (no record-count prefix; the cap value comes from
    // MAX_SYNC_CHAIN_LENGTH). Spec-diff round B1 fix.
    const { client } = makeMockedClient([
      {
        status: 413,
        body: {
          success: false,
          error: "Chain length exceeds sync limit 50000",
          details: { hint: CHAIN_TOO_LONG_HINT },
        },
      },
    ]);
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(413);
      expect(apiErr.message).toBe(
        "Chain length exceeds sync limit 50000",
      );
      // Transport stores the full parsed error body on `.details`
      // (success/error/details). The kernel's structured `details`
      // (carrying the export hint) lives under `.details.details` —
      // mirror the bulk/ingest 402 + 422 detail-routing pattern.
      expect(apiErr.details).toMatchObject({
        details: { hint: CHAIN_TOO_LONG_HINT },
      });
      // Verbatim regex on the route reference — a kernel rewording
      // that preserves /decisions/export still passes; one that drops
      // it fails (which is the right signal — consumers can't auto-
      // route to the export endpoint without that anchor).
      const inner = (apiErr.details as { details: { hint: string } }).details;
      expect(inner.hint).toMatch(/decisions\/export/);
      expect(inner.hint).toBe(CHAIN_TOO_LONG_HINT);
    }
  });

  it("429 (rate limit) → AttestryAPIError(429) when retry disabled", async () => {
    // Resource-level pin: a 429 surfaces as AttestryAPIError when
    // retries are disabled (the per-call options.retry override
    // suppresses the default invariant #18 retry). The retry-semantics
    // describe block below covers the default-on path.
    const { client } = makeMockedClient([
      {
        status: 429,
        body: {
          success: false,
          error: "Too many requests. Please try again later.",
        },
      },
    ]);
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });

  it("500 (internal) → AttestryAPIError(500) with SCRUBBED message (no kernel error leak)", async () => {
    // The kernel's internalErrorResponse scrubs the underlying error
    // detail to prevent information disclosure. The SDK surfaces the
    // scrubbed message verbatim — pin that the message does NOT contain
    // raw internal text (e.g., DB error codes, stack-trace shrapnel).
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
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.message).toBe(
        "An internal error occurred. Please try again later.",
      );
      // Negative pins — confirm raw kernel error text doesn't leak.
      expect(apiErr.message).not.toContain("ECONNREFUSED");
      expect(apiErr.message).not.toContain("postgres");
      expect(apiErr.message).not.toContain("verifyChainForSystem");
    }
  });
});

// ─── Path-segment encoding ──────────────────────────────────────────────────

describe("decisions.verifyChain — path-segment encoding (D4)", () => {
  it("URL-encodes systemIds containing path-injection chars; 400 still surfaces", async () => {
    // Adversarial systemId with slash, hash, and query separators. None
    // are valid UUIDs (server will 400) but the SDK MUST encode them
    // before sending so the path is unambiguous and the request lands
    // at /api/v1/decisions/verify-chain/<encoded> rather than splattering
    // across the URL. Pin the exact encoded form so a regression
    // (e.g., switching to encodeURI which doesn't encode `/` and `?`)
    // would fail. ALSO assert AttestryAPIError(400) propagates — spec
    // test-pattern path-segment-encoding #3 ("server-side rejection
    // (400) for non-UUID still surfaces" — combined encoding + server
    // rejection pin).
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid systemId format." } },
    ]);
    let caught: unknown;
    try {
      await client.decisions.verifyChain("a/b#c?d=e");
    } catch (err) {
      caught = err;
    }
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/verify-chain/a%2Fb%23c%3Fd%3De",
    );
    // Encoding succeeded (URL above); server rejected as expected; the
    // error class + status propagates rather than being swallowed.
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(400);
  });

  it("encoded path is /api/v1/decisions/verify-chain/<encoded> (NOT a query string)", async () => {
    // Path-segment endpoint — the systemId rides in the URL path, NOT
    // as ?systemId=<uuid>. A regression that wrapped the input in
    // encodeQuery would emit `verify-chain?systemId=...` and this pin
    // would fire.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    await client.decisions.verifyChain(SYSTEM_ID);
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/decisions/verify-chain/${SYSTEM_ID}`,
    );
    expect(calls[0].url).not.toContain("?systemId=");
  });

  it("encodes spaces as %20, not + (encodeURIComponent vs querystring)", async () => {
    // Subtle: query-string libs sometimes emit `+` for space; path
    // segments MUST use %20 per RFC 3986. encodeURIComponent does the
    // right thing — pin so a future "helper" doesn't regress.
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid systemId format." } },
    ]);
    try {
      await client.decisions.verifyChain("a b c");
    } catch {
      // expected
    }
    expect(calls[0].url).toContain("%20");
    expect(calls[0].url).not.toMatch(/\+|%2B/);
  });

  it("encodes unicode characters via percent-escape (not unicode escapes)", async () => {
    // encodeURIComponent translates non-ASCII to UTF-8 byte sequences
    // and percent-encodes each byte (e.g., emoji → 4-byte UTF-8 → 4
    // %XX pairs). Pin: the encoded URL contains percent-escapes, NOT
    // raw unicode or \u escapes.
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid systemId format." } },
    ]);
    try {
      // 'é' = U+00E9 → UTF-8 0xC3 0xA9 → %C3%A9
      await client.decisions.verifyChain("café");
    } catch {
      // expected — server rejects non-UUID
    }
    expect(calls[0].url).toContain("%C3%A9");
    expect(calls[0].url).not.toContain("é");
  });

  it("lone-surrogate guard fires BEFORE fetch (synchronous, no request issued)", async () => {
    // Symmetric with retrieve's L1 pattern. Catch the URIError that
    // encodeURIComponent throws on lone surrogates, wrap as TypeError
    // with cause:err. No fetch call should be issued.
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.verifyChain("\uDC00")).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });
});

// ─── Retry semantics (default-on, opt-out via per-call options) ─────────────

describe("decisions.verifyChain — retry semantics", () => {
  it("429 retried once by default (carry-forward invariant #18)", async () => {
    // Default retry config: maxRetries:3, base:1s, cap:30s, Retry-After
    // honored. The retry middleware sleeps before the next attempt;
    // tests opt out via fetch with no Retry-After header (sleeps base
    // delay). Pin the 429-then-success path with the default config.
    const calls: MockedRequest[] = [];
    let i = 0;
    const responses = [
      // First call: 429 with no Retry-After → sleeps 1s base before retry
      // (tests below override base via DEFAULT_RETRY_OPTIONS would be
      // load-bearing for prod; here we use a deterministic small base).
      {
        status: 429 as const,
        body: { success: false, error: "Too many requests." },
      },
      {
        status: 200 as const,
        body: { success: true, data: VALID_RESULT },
      },
    ];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      const r = responses[i++];
      return new Response(JSON.stringify(r.body), {
        status: r.status,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      // Override default base delay to keep the test fast.
      retry: { initialDelayMs: 1, maxDelayMs: 1, maxRetries: 1 },
    });
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(calls).toHaveLength(2);
    expect(out.chainValid).toBe(true);
  });

  it("429 NOT retried when options.retry: {maxRetries: 0}", async () => {
    // Per-call override suppresses retry. Pin: exactly one fetch, then
    // AttestryAPIError(429) bubbles up.
    const calls: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      return new Response(
        JSON.stringify({ success: false, error: "Too many requests." }),
        { status: 429, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
    });
    try {
      await client.decisions.verifyChain(SYSTEM_ID, {
        retry: { maxRetries: 0 },
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
    expect(calls).toHaveLength(1);
  });

  it("5xx NOT retried (only 429 — invariant #18)", async () => {
    // Carry-forward: only 429 is retried. A 500 surfaces immediately
    // even with default retry config — pin so a future generalization
    // ("retry all 5xx") would surface here.
    const calls: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      return new Response(
        JSON.stringify({
          success: false,
          error: "An internal error occurred. Please try again later.",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
    });
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(500);
    }
    // Exactly one fetch — no retry on 5xx.
    expect(calls).toHaveLength(1);
  });

  it("429 exhausting all retries → final AttestryAPIError(429) (hostile #23 branch B)", async () => {
    // Spec hostile #23: "Default retry on 429 — One retry, eventual
    // success or final failure. Pin both branches." Branch A (eventual
    // success after retry) is pinned above; THIS is branch B — every
    // retry returns 429, the SDK exhausts the retry budget, and
    // surfaces the final 429 as AttestryAPIError. Fake timers keep
    // the test fast + deterministic under coverage.
    vi.useFakeTimers();
    let fetchCount = 0;
    const mockFetch: FetchLike = async () => {
      fetchCount++;
      return new Response(
        JSON.stringify({ success: false, error: "Too many requests." }),
        { status: 429, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 2, initialDelayMs: 1, maxDelayMs: 1 },
    });
    const promise = client.decisions.verifyChain(SYSTEM_ID);
    const observer = promise.catch(() => undefined);
    // Advance enough to drain all backoff sleeps.
    await vi.advanceTimersByTimeAsync(1000);
    await observer;
    // Final rejection is AttestryAPIError(429) — the budget exhausted.
    await expect(promise).rejects.toBeInstanceOf(AttestryAPIError);
    await expect(promise).rejects.toMatchObject({ status: 429 });
    // Initial + 2 retries = 3 total attempts.
    expect(fetchCount).toBe(3);
  });

  it("retry preserves the partial-success contract (200 with chainValid:false survives a 429 retry)", async () => {
    // After a 429 + retry, the server's eventual 200-with-chainValid:false
    // is still surfaced as a resolved Promise (not a thrown error). Pin
    // that the retry path doesn't accidentally re-interpret the negative
    // verdict as a failure.
    const calls: MockedRequest[] = [];
    let i = 0;
    const responses = [
      {
        status: 429 as const,
        body: { success: false, error: "Too many requests." },
      },
      {
        status: 200 as const,
        body: { success: true, data: TAMPERED_RESULT },
      },
    ];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      const r = responses[i++];
      return new Response(JSON.stringify(r.body), {
        status: r.status,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { initialDelayMs: 1, maxDelayMs: 1, maxRetries: 1 },
    });
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(calls).toHaveLength(2);
    expect(out.chainValid).toBe(false);
    expect(out.tamperedRecordIds).toHaveLength(2);
  });
});

// ─── Abort semantics ────────────────────────────────────────────────────────

describe("decisions.verifyChain — abort semantics", () => {
  it("pre-aborted signal → AttestryError synchronously, no fetch", async () => {
    // Carry-forward invariant #3: pre-aborted signals reject in the
    // transport BEFORE any fetch is issued. Pin: the mock receives no
    // call, the rejection message names "aborted by caller".
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.decisions.verifyChain(SYSTEM_ID, { signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("non-aborted signal → request completes normally (coverage)", async () => {
    // Symmetric happy-path: signal exists, is wired through, but never
    // fires. Pin so the resource-level branch where options.signal is
    // a live signal that gets attached to the transport's
    // AbortController and then cleanly removed in the finally block
    // stays exercised.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const controller = new AbortController();
    const out = await client.decisions.verifyChain(SYSTEM_ID, {
      signal: controller.signal,
    });
    expect(out).toEqual(VALID_RESULT);
    expect(calls).toHaveLength(1);
    // Signal still listenable — SDK does NOT consume it.
    expect(controller.signal.aborted).toBe(false);
  });

  it("mid-flight abort → AttestryError with the abort cause (transport-level)", async () => {
    // The transport composes the caller's signal with its internal one;
    // a mid-flight abort fires the fetch's AbortController and surfaces
    // as AttestryError. Pin so the wrap is preserved (a regression that
    // leaked DOMException/AbortError through would fail here).
    const calls: MockedRequest[] = [];
    const controller = new AbortController();
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      // Fire the abort during the fetch — the transport wires the
      // caller's signal so this surfaces as an aborted request.
      controller.abort(new Error("mid-flight cancellation"));
      // Mimic platform behavior: fetch with an aborted signal rejects.
      const err = new DOMException("aborted", "AbortError");
      throw err;
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    try {
      await client.decisions.verifyChain(SYSTEM_ID, {
        signal: controller.signal,
      });
      throw new Error("expected throw");
    } catch (err) {
      // AttestryError (or its API subclass) — NOT raw DOMException.
      expect(err).toBeInstanceOf(AttestryError);
    }
    expect(calls).toHaveLength(1);
  });
});

// ─── Hostile round (residual gaps) ──────────────────────────────────────────

describe("decisions.verifyChain — hostile round (residual gaps)", () => {
  it("H1: result body missing a documented field — passes through as undefined (forward-compat)", async () => {
    // Transport doesn't strict-check the response body — only confirms
    // the envelope shape and unwraps. A future kernel that drops a
    // field during refactor (or one that hasn't yet rolled out a new
    // field) shouldn't fail SDK consumer code at the transport layer;
    // it should surface as TypeScript-typed `undefined` at the
    // consumer site, where the consumer already needs to handle
    // null/undefined for optional fields.
    const partial = { chainValid: true } as unknown as ChainVerificationResult;
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: partial } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.chainValid).toBe(true);
    // Consumer sees undefined for documented fields not in the response.
    // TypeScript-erased; runtime-observable.
    expect(out.recordCount).toBeUndefined();
    expect(out.tamperedRecordIds).toBeUndefined();
    expect(out.performanceMetrics).toBeUndefined();
  });

  it("H2: result body field with wrong type — value preserved verbatim (no coercion)", async () => {
    // Faithful courier: SDK does NOT coerce 1 → true or "5" → 5. A
    // consumer relying on `if (result.chainValid)` would treat 1 as
    // truthy (matching boolean-true semantics by accident); strict-
    // equality consumers (`result.chainValid === true`) would
    // correctly flag the mismatch. Pin so a future "type-cleanup"
    // refactor that adds runtime type coercion would surface here.
    const wrongType = {
      ...VALID_RESULT,
      chainValid: 1,
      recordCount: "5",
    } as unknown as ChainVerificationResult;
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: wrongType } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect((out as unknown as { chainValid: number }).chainValid).toBe(1);
    expect((out as unknown as { recordCount: string }).recordCount).toBe(
      "5",
    );
  });

  it("H3: 200 with `{success:true}` only (no data field) — transport does NOT unwrap an absent data", async () => {
    // The transport's unwrap discrimination is strict: it requires
    // BOTH `success === true` AND `"data" in parsed`. Without `data`,
    // it falls through to `return parsed as T` — consumer sees the
    // bare envelope shape `{success: true}`, not the unwrapped data.
    // Defensive against a kernel that emits `success:true` but
    // accidentally drops `data`.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    // `data` was never unwrapped — consumer sees the envelope as-is.
    // Documented fields (chainValid etc.) are undefined; the bare
    // envelope's `success` is observable at runtime.
    expect((out as unknown as { success: boolean }).success).toBe(true);
    expect(out.chainValid).toBeUndefined();
  });

  it("H4: frozen RequestOptions object — SDK does NOT mutate options (deep)", async () => {
    // Symmetric to export's H9 ("frozen input"). The verifyChain method
    // passes `options` straight through to `_request<T>`; nothing in
    // the resource layer touches the options object.
    //
    // Hostile-review F4 fix: deep-freeze the inner `retry` object too —
    // shallow Object.freeze leaves nested mutables, so a future
    // regression that did `options.retry.maxRetries = 999` would slip
    // past a shallow check. Asserting Object.isFrozen on BOTH the outer
    // and inner objects pins the deep no-mutation contract.
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const controller = new AbortController();
    const retry = Object.freeze({ maxRetries: 0 });
    const options = Object.freeze({
      signal: controller.signal,
      retry,
    });
    await client.decisions.verifyChain(SYSTEM_ID, options);
    // Both layers still frozen — confirms no shallow OR deep mutation.
    expect(Object.isFrozen(options)).toBe(true);
    expect(Object.isFrozen(options.retry)).toBe(true);
    expect(options.signal).toBe(controller.signal);
    expect(options.retry.maxRetries).toBe(0);
  });

  it("H5: concurrent verifyChain() calls share no state — independent fetches", async () => {
    // DecisionsResource.verifyChain() issues a fresh fetch per call.
    // No instance state between calls. Two concurrent calls on
    // different systemIds should produce independent fetches with
    // independent results.
    const SYSTEM_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const SYSTEM_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const calls: MockedRequest[] = [];
    const responses = [
      { systemId: SYSTEM_A, chainValid: true },
      { systemId: SYSTEM_B, chainValid: false },
    ];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      // Match URL to response by systemId — order-independent.
      const matched = responses.find((r) =>
        String(url).endsWith(`/verify-chain/${r.systemId}`),
      );
      const result = { ...VALID_RESULT, ...matched };
      return new Response(
        JSON.stringify({ success: true, data: result }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const [outA, outB] = await Promise.all([
      client.decisions.verifyChain(SYSTEM_A),
      client.decisions.verifyChain(SYSTEM_B),
    ]);
    // Each call got its own response; no cross-contamination.
    expect(outA.systemId).toBe(SYSTEM_A);
    expect(outA.chainValid).toBe(true);
    expect(outB.systemId).toBe(SYSTEM_B);
    expect(outB.chainValid).toBe(false);
    expect(calls).toHaveLength(2);
    // URLs distinguished — confirms independent fetches.
    const urls = new Set(calls.map((c) => c.url));
    expect(urls.size).toBe(2);
  });

  it("H6: systemId with literal `%` char — encoded as %25 (no double-decode)", async () => {
    // Subtle: a systemId containing `%41` looks like an already-encoded
    // "A", but encodeURIComponent correctly treats the literal `%` as
    // a character that itself needs encoding (`%41` → `%2541`). The
    // SDK does NOT silently double-decode or pre-decode — preserving
    // byte-level semantics. A consumer who passes a malformed systemId
    // gets the kernel's UUID rejection, not silent semantic shift.
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid systemId format." } },
    ]);
    try {
      await client.decisions.verifyChain("abc%41def");
    } catch {
      // expected — kernel rejects non-UUID
    }
    // The literal `%` becomes `%25`; the `%41` becomes `%2541`, NOT `A`.
    expect(calls[0].url).toContain("abc%2541def");
    expect(calls[0].url).not.toContain("abcAdef");
  });

  it("H7: empty body `{}` — resolves with `{}` (forward-compat extreme-degenerate)", async () => {
    // Transport's unwrap-discrimination falls through:
    //   parsed.success !== true → return parsed as T directly.
    // Consumer sees `result = {}` with all documented fields undefined.
    // Same forward-compat behavior as H1, but at the
    // extreme-degenerate end. Defensive against a misconfigured
    // proxy or kernel bug emitting an empty JSON body at 200.
    const { client } = makeMockedClient([
      { status: 200, body: {} },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out).toEqual({});
    expect(out.chainValid).toBeUndefined();
    expect(out.recordCount).toBeUndefined();
  });

  it("H8: tamperedRecordIds with duplicate IDs — preserved verbatim (faithful courier)", async () => {
    // The kernel's if-else if-else structure at chain-verification.ts:
    // 211-217 guarantees a record lands in at most one array per
    // iteration, so in-array dupes shouldn't occur. But the SDK is a
    // faithful courier — if the kernel ever did emit dupes (regression,
    // or a future kernel that allows the same record ID to appear in
    // multiple positions of the same chain), the SDK should preserve
    // them verbatim and let the consumer dedupe.
    const dupes: ChainVerificationResult = {
      ...TAMPERED_RESULT,
      tamperedRecordIds: ["dr-1", "dr-1", "dr-2", "dr-1"],
      brokenRecordIds: ["dr-3", "dr-3"],
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: dupes } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.tamperedRecordIds).toEqual([
      "dr-1",
      "dr-1",
      "dr-2",
      "dr-1",
    ]);
    expect(out.brokenRecordIds).toEqual(["dr-3", "dr-3"]);
    // Length preserved exactly — no dedupe.
    expect(out.tamperedRecordIds.length).toBe(4);
    expect(out.brokenRecordIds.length).toBe(2);
  });

  it("H9: mid-flight abort during retry backoff — cancels backoff, no second fetch", async () => {
    // Carry-forward invariant #22 (`sleepWithSignal` cleans up
    // listener in BOTH paths — timer-fires AND abort-fires) is the
    // load-bearing transport behavior. Pin: a 429 → backoff sleep →
    // abort fires mid-sleep → AttestryError thrown synchronously,
    // NO second fetch was issued.
    //
    // Uses fake timers (mirroring retry.test.ts:511-547's
    // incidents.create equivalent) for determinism — real-timer
    // versions are flaky under coverage instrumentation slowdowns
    // (the 5ms-after-fetch race shifts unpredictably under v8 cov).
    //
    // Hostile-review F5 fix: also stub Math.random to a non-zero
    // value. retry.ts:sleepWithSignal early-returns via
    // `await Promise.resolve()` when ms<=0, BEFORE registering the
    // abort listener — so an unstubbed Math.random producing < 0.001
    // (~0.1% probability with initialDelayMs:1_000) would yield
    // delay=0, the listener wouldn't register, and the abort
    // wouldn't cancel the sleep. Stubbing to 0.5 guarantees a
    // non-zero delay (Math.floor(0.5 * 1000) = 500) so the listener
    // always registers and the abort path is exercised
    // deterministically under coverage AND production runs.
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0.5);
    let fetchCount = 0;
    const ac = new AbortController();
    const mockFetch: FetchLike = async () => {
      fetchCount++;
      return new Response(
        JSON.stringify({ success: false, error: "Too many requests." }),
        { status: 429, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { initialDelayMs: 1_000, maxDelayMs: 10_000, maxRetries: 3 },
    });
    const promise = client.decisions.verifyChain(SYSTEM_ID, {
      signal: ac.signal,
    });
    // Eager rejection observer — prevents vitest's "uncaught
    // rejection" warning during the synchronous abort dispatch.
    // (See retry.test.ts:529-535 for the equivalent rationale.)
    const observer = promise.catch(() => undefined);
    // Schedule abort to fire mid-backoff. STRING reason (NOT Error)
    // — vitest's fake-timer + AbortController dispatch re-throws
    // Error reasons; strings don't trigger that path.
    setTimeout(() => ac.abort("user cancelled"), 0);
    await vi.advanceTimersByTimeAsync(10);
    await observer;
    await expect(promise).rejects.toThrow(/aborted/);
    // Only the initial 429 was fetched; the backoff was cancelled
    // before the retry could fire.
    expect(fetchCount).toBe(1);
  });

  it("H10: result with internally inconsistent state — preserved verbatim (no normalization)", async () => {
    // The kernel's verification logic produces consistent results by
    // construction, but the SDK should be a faithful courier even
    // when the kernel violates its own invariants (kernel regression,
    // version skew, or even a malicious-server testing scenario). A
    // result with `{chainValid: true, tamperedRecordIds: ["dr-1"]}`
    // is logically inconsistent (chain shouldn't be valid if a
    // record was tampered). The SDK preserves the contradiction
    // verbatim; the consumer can detect it via cross-field
    // validation if they care. SDK does NOT silently coerce/validate
    // cross-field invariants.
    const inconsistent: ChainVerificationResult = {
      ...VALID_RESULT,
      chainValid: true,
      tamperedRecordIds: ["dr-1"],
      brokenRecordIds: [],
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: inconsistent } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    // Both fields preserved as-given — SDK does NOT normalize the
    // contradiction. Consumer-side validation responsibility.
    expect(out.chainValid).toBe(true);
    expect(out.tamperedRecordIds).toEqual(["dr-1"]);
  });
});

// ─── Coverage round (defensive paths) ──────────────────────────────────────

describe("decisions.verifyChain — coverage round (defensive paths)", () => {
  it("C1: TypeError verbatim message for empty systemId", async () => {
    // Build round pinned `instanceof TypeError`; this freezes the
    // exact message string. Consumers who route validation errors
    // by `err.message.startsWith("decisions.verifyChain:")` would
    // break if a future refactor changed the prefix or punctuation.
    const { client } = makeMockedClient([]);
    try {
      client.decisions.verifyChain("");
      throw new Error("expected throw");
    } catch (err) {
      expect((err as TypeError).message).toBe(
        "decisions.verifyChain: `systemId` is required",
      );
    }
  });

  it("C2: TypeError verbatim message format + cause for lone-surrogate systemId", async () => {
    // Pin: prefix matches verbatim; cause is preserved as a URIError
    // instance (consumers can `err.cause instanceof URIError` for
    // debugging — e.g., to detect a malformed input source).
    const { client } = makeMockedClient([]);
    try {
      client.decisions.verifyChain("\uD800");
      throw new Error("expected throw");
    } catch (err) {
      const te = err as TypeError;
      expect(te.message).toContain(
        "decisions.verifyChain: `systemId` contains invalid UTF-16 sequences",
      );
      // Trailing parenthesis with the URIError's own message echoed.
      expect(te.message).toMatch(/\(.*\)/);
      // Cause is the original URIError — preserved for cause-chain
      // consumers (logging libraries that follow `.cause`).
      expect((te as Error).cause).toBeInstanceOf(URIError);
    }
  });

  it("C3: recordCount: null preserved verbatim (kernel intermediary serializing NaN as null doesn't get coerced)", async () => {
    // Hostile H2 pinned chainValid:1 and recordCount:"5". This pin
    // extends to null — JSON cannot represent NaN directly, so a
    // kernel intermediary serializing NaN would either omit the field
    // or emit `null`. The SDK preserves whatever value lands without
    // coercion — does NOT replace null with 0 or NaN. Hostile-review
    // F3 fixed: prior version of this test was named "NaN preserved"
    // but body always tested null; rename clarifies the actual
    // assertion.
    const withNullCount = JSON.stringify({
      success: true,
      data: { ...VALID_RESULT, recordCount: 0 },
    }).replace('"recordCount":0', '"recordCount":null');
    const calls: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      return new Response(withNullCount, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    // null preserved as-given — SDK doesn't coerce to 0 or NaN.
    expect(out.recordCount as unknown).toBeNull();
  });

  it("C4: recordCount: MAX_SAFE_INTEGER preserved verbatim", async () => {
    // JSON.parse correctly decodes 9007199254740991 as a number.
    // SDK forwards. Pin: extreme-but-valid integer survives the
    // round-trip with full precision.
    const huge: ChainVerificationResult = {
      ...VALID_RESULT,
      recordCount: Number.MAX_SAFE_INTEGER,
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: huge } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.recordCount).toBe(Number.MAX_SAFE_INTEGER);
    expect(Number.isSafeInteger(out.recordCount)).toBe(true);
  });

  it("C5: 5000-element tamperedRecordIds preserved verbatim (no truncation, no dedupe)", async () => {
    // Performance / memory boundary — SDK doesn't materialize,
    // doesn't truncate, doesn't dedupe. Pin: array length and
    // element values survive intact through JSON parse + transport
    // unwrap. Catches a future "performance optimization" that
    // truncates large arrays without the consumer's consent.
    const ids = Array.from({ length: 5000 }, (_, i) => `dr-${i}`);
    const big: ChainVerificationResult = {
      ...TAMPERED_RESULT,
      tamperedRecordIds: ids,
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: big } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.tamperedRecordIds).toHaveLength(5000);
    expect(out.tamperedRecordIds[0]).toBe("dr-0");
    expect(out.tamperedRecordIds[4999]).toBe("dr-4999");
  });

  it("C6: 401 error body without `details` field — AttestryAPIError(401) with details carrying parsed body", async () => {
    // The kernel doesn't always emit `details` (e.g., simple
    // AuthError responses just have `error`). Pin: a 401 with body
    // {success:false, error:"..."} (no `details` key) surfaces as
    // AttestryAPIError(401) with `apiErr.details` set to the parsed
    // body. Consumers distinguish details-bearing errors (402, 413,
    // 422) from bare errors via `apiErr.details?.details === undefined`.
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required." },
      },
    ]);
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(401);
      // .details holds the parsed body (success/error fields), with
      // no nested `details` field. Consumer detects via optional
      // chaining.
      expect(apiErr.details).toMatchObject({
        success: false,
        error: "Authentication required.",
      });
      expect(
        (apiErr.details as { details?: unknown }).details,
      ).toBeUndefined();
    }
  });

  it("C7: 413 error body with details:null — AttestryAPIError(413), consumer detects missing hint", async () => {
    // Defensive pin: kernel could emit {success:false, error:"...",
    // details:null} if a future internal refactor accidentally
    // clears the hint object. The SDK still surfaces
    // AttestryAPIError(413) but `apiErr.details.details` is null —
    // consumers should defend against this with optional-chaining
    // (which handles null gracefully).
    const { client } = makeMockedClient([
      {
        status: 413,
        body: {
          success: false,
          error: "Chain length exceeds sync limit 50000",
          details: null,
        },
      },
    ]);
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(413);
      // Consumer's `apiErr.details?.details?.hint` resolves to
      // undefined (optional chaining on null short-circuits).
      const hint = (
        apiErr.details as { details?: { hint?: string } | null }
      )?.details?.hint;
      expect(hint).toBeUndefined();
    }
  });

  it("C8: repeated verifyChain() calls with same systemId produce byte-identical URL (no hidden cache)", async () => {
    // Idempotent at the URL-shape level. Catches a future regression
    // that adds a request-id query param, lowercases the path, or
    // memoizes encoding state across calls.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
      { body: { success: true, data: VALID_RESULT } },
    ]);
    await client.decisions.verifyChain(SYSTEM_ID);
    await client.decisions.verifyChain(SYSTEM_ID);
    expect(calls).toHaveLength(2);
    expect(calls[0].url).toBe(calls[1].url);
    // Sanity check the URL shape itself.
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/decisions/verify-chain/${SYSTEM_ID}`,
    );
  });

  it("C9: lastVerifiedAt as empty string — preserved verbatim (faithful courier)", async () => {
    // Kernel always emits a non-empty ISO string. Defensive pin: if
    // a future kernel bug produced lastVerifiedAt: "", the SDK
    // forwards verbatim. Consumer's `new Date("")` returns Invalid
    // Date; the consumer detects via Number.isNaN(date.getTime()).
    const empty: ChainVerificationResult = {
      ...VALID_RESULT,
      lastVerifiedAt: "",
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: empty } },
    ]);
    const out = await client.decisions.verifyChain(SYSTEM_ID);
    expect(out.lastVerifiedAt).toBe("");
    // Confirm the consumer-side detection pattern.
    expect(Number.isNaN(new Date(out.lastVerifiedAt).getTime())).toBe(
      true,
    );
  });

  it("C10: 500 with non-scrubbed body — AttestryAPIError(500), body forwarded as-given", async () => {
    // The kernel's internalErrorResponse SCRUBS the underlying error,
    // but a proxy / LB returning its own 500 page (HTML, plain text,
    // or a JSON body without the scrubbed message) doesn't go
    // through that path. Pin: the SDK doesn't try to detect or
    // re-scrub — it forwards whatever the body contained.
    const { client } = makeMockedClient([
      {
        status: 500,
        body: {
          success: false,
          error: "upstream service unavailable: ECONNREFUSED 127.0.0.1:5432",
        },
      },
    ]);
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(500);
      // SDK forwards the non-scrubbed message verbatim — proxy / LB
      // bypassed the kernel's scrubbing path. Consumer's defensive
      // logging should redact aggressively if they suspect a leak.
      expect(apiErr.message).toContain("ECONNREFUSED");
    }
  });

  it("F1 (P2 sweep): throws AttestryError when kernel response is null", async () => {
    // P2 extension to verifyChain: extracted-data envelope with
    // null payload. The kernel can't legitimately produce this
    // (route either returns ChainVerificationResult or errors),
    // but a misbehaving proxy / cache could. The SDK rejects
    // before the consumer's `.chainValid` deref crashes.
    //
    // Hostile-review session-14 H1: pin the error class — NOT just
    // the message. A future regression that swapped
    // `throw new AttestryError(...)` for a different class with the
    // same message would still satisfy `rejects.toThrow(/regex/)`.
    // Carry-forward invariant #12: verifyChain ONLY throws on
    // structural failures (auth, rate limit, system-not-found,
    // ChainTooLong) AND on bad shape — chainValid:false is NOT a
    // structural failure. The class identity here is the contract.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: null } },
    ]);
    let caught: unknown;
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    // Strict: NOT the AttestryAPIError subclass — P2 is an SDK-layer
    // shape rejection, NOT a transport-layer status-code error.
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /decisions\.verifyChain: expected an object response from the kernel \(got null\)/,
    );
  });

  it("F1 (P2 sweep): throws AttestryError when kernel response is an array (not object)", async () => {
    // P2 extension: arrays are typeof "object" but not the kernel's
    // declared shape. Without Array.isArray pre-check, the consumer's
    // `.chainValid` would silently be `undefined` and `for…of` over
    // ChainVerificationResult would iterate the array's elements.
    //
    // Hostile-review session-14 H1: pin error class.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: [] } },
    ]);
    let caught: unknown;
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /decisions\.verifyChain: expected an object response from the kernel \(got array\)/,
    );
  });

  it("F1 (P2 sweep): throws AttestryError when kernel response is a scalar (string)", async () => {
    // P2 extension: scalar (string) where an object was expected.
    // describeType resolves to "string". Mirrors the retrieve sweep
    // for parity: every sync GET resource method that expects an
    // object now rejects on a non-object payload.
    //
    // Hostile-review session-14 H1: pin error class.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: "not-an-object" } },
    ]);
    let caught: unknown;
    try {
      await client.decisions.verifyChain(SYSTEM_ID);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /decisions\.verifyChain: expected an object response from the kernel \(got string\)/,
    );
  });
});
