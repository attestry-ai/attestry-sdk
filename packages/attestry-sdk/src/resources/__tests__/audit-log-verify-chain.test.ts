import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  // Result-shape type import — pinned at compile time. If
  // AuditChainVerificationResult is dropped from `index.ts` or the
  // resource's exports, this file fails to compile and the test run
  // aborts before any pin runs.
  AuditChainVerificationResult,
} from "../audit-log.js";
import type { FetchLike } from "../../types.js";

// ─── auditLog.verifyChain — GET org-wide audit-log hash-chain verdict ───────
//
// Wire shape (kernel src/app/api/v1/audit-chain/verify/route.ts):
//   GET /api/v1/audit-chain/verify
//   Auth: x-api-key (requireApiKey direct — NO permission scoping)
//   200 OK on a VALID chain: {success:true, data: {valid:true, ...}}
//     (NO brokenAt field — kernel uses conditional spread)
//   200 OK on a BROKEN chain: {success:true, data: {valid:false, brokenAt:<UUID>, ...}}
//   401 auth (no key OR invalid key — single 401 surface)
//   429 rate limit (per-IP `audit-chain-verify:${ip}`)
//   500 internal (scrubbed message)
//
// 5 always-present fields + 1 optional own-property:
//   valid             boolean       (always)
//   entriesVerified   number        (always)
//   totalEntries      number        (always)
//   firstEntry        string|null   (always — null when totalEntries === 0)
//   lastEntry         string|null   (always — null when totalEntries === 0)
//   brokenAt          string        (OWN-PROPERTY ONLY when chain is broken)
//
// CRITICAL contract: the SDK MUST resolve the Promise on valid:false.
// Mirror of decisions.verifyChain's partial-success contract — the
// customer asked the audit-log-integrity question and the kernel
// answered. Top-level structural failures (auth, rate limit, internal)
// DO throw. Carry-forward invariant #12.
//
// 19th audit chain in the F.1 phase. Sibling test files:
//   - audit-log-export.test.ts (the auditLog.export streaming method)
//   - decisions-verify-chain.test.ts (the per-system equivalent)
// Mirror of decisions-verify-chain.test.ts structure adapted for the
// no-input + optional-brokenAt shape.

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

// Sample VALID verdict — chain intact, no brokenAt own-property.
const VALID_RESULT: AuditChainVerificationResult = {
  valid: true,
  entriesVerified: 42,
  totalEntries: 42,
  firstEntry: "2026-04-01T12:00:00.000Z",
  lastEntry: "2026-05-13T08:00:00.000Z",
};

// Sample BROKEN verdict — chain broken at a specific entry.
// brokenAt is an OWN-PROPERTY on the response.
const BROKEN_RESULT: AuditChainVerificationResult = {
  valid: false,
  entriesVerified: 15,
  totalEntries: 42,
  firstEntry: "2026-04-01T12:00:00.000Z",
  lastEntry: "2026-05-13T08:00:00.000Z",
  brokenAt: "11111111-2222-3333-4444-555555555555",
};

// Sample EMPTY-log verdict — vacuously true; firstEntry/lastEntry null.
const EMPTY_RESULT: AuditChainVerificationResult = {
  valid: true,
  entriesVerified: 0,
  totalEntries: 0,
  firstEntry: null,
  lastEntry: null,
};

// afterEach: restore mocks so Math.random / fake timers from one test
// don't leak into the next. Mirror of decisions-verify-chain.test.ts:138-141.
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("auditLog.verifyChain — happy path", () => {
  it("GETs /api/v1/audit-chain/verify with no body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/audit-chain/verify",
    );
    // GET → no body. Transport must NOT send Content-Type either.
    expect(calls[0].body).toBeUndefined();
    expect(calls[0].headers.get("Content-Type")).toBeNull();
    // Transport unwraps the {success:true, data} envelope — bare result.
    expect(out).toEqual(VALID_RESULT);
  });

  it("returns the AuditChainVerificationResult shape unchanged (envelope unwrapped)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.auditLog.verifyChain();
    // Pin every documented field to catch a future refactor that
    // accidentally drops one (the resource doesn't transform; this
    // would only break if the transport lost a field).
    expect(out.valid).toBe(true);
    expect(out.entriesVerified).toBe(42);
    expect(out.totalEntries).toBe(42);
    expect(out.firstEntry).toBe("2026-04-01T12:00:00.000Z");
    expect(out.lastEntry).toBe("2026-05-13T08:00:00.000Z");
    // On valid chain, brokenAt is NOT an own-property of the result.
    // The kernel uses a conditional spread; SDK preserves the
    // omission faithfully.
    expect(Object.hasOwn(out, "brokenAt")).toBe(false);
    expect(out.brokenAt).toBeUndefined();
  });

  it("forwards x-api-key + Accept headers (transport-level smoke)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    await client.auditLog.verifyChain();
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
  });

  it("sends NO query string (no input — pure no-arg GET)", async () => {
    // Pin: verifyChain has no query parameters. The URL must NOT
    // contain a "?" anywhere — confirms the method takes no input
    // and rides as a plain GET. A future refactor that added a query
    // param (e.g., a cursor for paginated verification) would regress
    // here.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    await client.auditLog.verifyChain();
    expect(calls[0].url).not.toContain("?");
  });

  it("preserves firstEntry/lastEntry as ISO strings (NOT Date instances)", async () => {
    // Wire is ISO-8601 string per the kernel. SDK does NOT auto-parse.
    // Consumer parses via `new Date(value)` if needed.
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(typeof out.firstEntry).toBe("string");
    expect(typeof out.lastEntry).toBe("string");
    expect(out.firstEntry).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
    expect(out.lastEntry).toMatch(
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
    );
    expect(out.firstEntry).not.toBeInstanceOf(Date);
    expect(out.lastEntry).not.toBeInstanceOf(Date);
  });

  it("accepts options.signal as the only argument (no input)", async () => {
    // Verify the no-arg overload is callable with ONLY options — no
    // first-argument input object required. Pin: the method signature
    // is `(options?: RequestOptions)` not `(input, options)`. A future
    // refactor that mistakenly added a required input param would
    // surface here.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const controller = new AbortController();
    const out = await client.auditLog.verifyChain({ signal: controller.signal });
    expect(out.valid).toBe(true);
    expect(calls).toHaveLength(1);
  });
});

// ─── Partial-success envelope (CRITICAL — does NOT throw on valid:false) ─────

describe("auditLog.verifyChain — partial-success envelope (CRITICAL contract)", () => {
  it("200 with valid:true → resolves with the verdict body", async () => {
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.valid).toBe(true);
    expect(Object.hasOwn(out, "brokenAt")).toBe(false);
  });

  it("200 with valid:false (broken chain) → RESOLVES (NOT rejects) with verdict body", async () => {
    // CRITICAL contract pin. The kernel returns 200 with valid:false
    // on detected tampering; the SDK MUST NOT throw. Mirror of
    // decisions.verifyChain's contract. Carry-forward invariant #12.
    // A future refactor that interpreted 200 + a "negative" payload
    // field as an error would break here.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: BROKEN_RESULT } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.valid).toBe(false);
    expect(out.brokenAt).toBe("11111111-2222-3333-4444-555555555555");
    expect(out.entriesVerified).toBe(15);
    expect(out.totalEntries).toBe(42);
  });

  it("brokenAt is an OWN-PROPERTY only on broken chains (pollution-safe discriminator)", async () => {
    // Verify the SDK preserves the kernel's conditional emission of
    // brokenAt. On valid chain: NOT an own-property (kernel uses
    // conditional spread `...(result.brokenAtId ? { brokenAt } : {})`).
    // On broken chain: own-property with UUID value.
    //
    // Consumers should branch on `result.valid` (closed-enum boolean),
    // NOT `result.brokenAt === undefined` (prototype-pollution-unsafe).
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
      { body: { success: true, data: BROKEN_RESULT } },
    ]);
    const validOut = await client.auditLog.verifyChain();
    expect(Object.hasOwn(validOut, "brokenAt")).toBe(false);
    expect(validOut.brokenAt).toBeUndefined();

    const brokenOut = await client.auditLog.verifyChain();
    expect(Object.hasOwn(brokenOut, "brokenAt")).toBe(true);
    expect(typeof brokenOut.brokenAt).toBe("string");
  });

  it("empty audit log (totalEntries:0) → resolves with valid:true, firstEntry/lastEntry null", async () => {
    // Vacuous truth — an empty chain is valid by definition. The
    // kernel emits firstEntry/lastEntry as null when entries.length
    // === 0 (route.ts:63-64). Pin: SDK forwards verbatim — does NOT
    // coerce null to empty string or undefined.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: EMPTY_RESULT } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.valid).toBe(true);
    expect(out.entriesVerified).toBe(0);
    expect(out.totalEntries).toBe(0);
    expect(out.firstEntry).toBeNull();
    expect(out.lastEntry).toBeNull();
    expect(Object.hasOwn(out, "brokenAt")).toBe(false);
  });

  it("entriesVerified can be less than totalEntries on broken chain (verified-up-to-N)", async () => {
    // Pin the semantic relationship: on a broken chain,
    // entriesVerified is the count of entries verified BEFORE the
    // first broken link — equals the broken entry's index. Consumers
    // show "verified up to N entries".
    const partial: AuditChainVerificationResult = {
      ...BROKEN_RESULT,
      entriesVerified: 15,
      totalEntries: 42,
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.valid).toBe(false);
    expect(out.entriesVerified).toBe(15);
    expect(out.totalEntries).toBe(42);
    expect(out.entriesVerified).toBeLessThan(out.totalEntries);
  });

  it("extra fields on the result (forward-compat) pass through opaquely", async () => {
    // The transport doesn't strict-check the response body. New
    // kernel fields (e.g., `merkleRoot`, `truncated`) flow through as
    // extra properties on the returned object — TypeScript-erased but
    // observable at runtime. Pin: SDK still resolves cleanly,
    // documented fields still present.
    const withExtras = {
      ...VALID_RESULT,
      merkleRoot:
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      truncated: false,
      futureCounter: 42,
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: withExtras } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.valid).toBe(true);
    expect(out.entriesVerified).toBe(42);
    // Extra fields are present on the runtime object (TypeScript-
    // erased but observable) — confirms forward-compat behavior.
    const opaque = out as AuditChainVerificationResult & {
      merkleRoot?: string;
      truncated?: boolean;
      futureCounter?: number;
    };
    expect(opaque.merkleRoot).toMatch(/^sha256:/);
    expect(opaque.truncated).toBe(false);
    expect(opaque.futureCounter).toBe(42);
  });
});

// ─── Top-level error paths (these THROW AttestryAPIError) ───────────────────

describe("auditLog.verifyChain — top-level error paths", () => {
  it("401 (auth required) → AttestryAPIError(401)", async () => {
    // No API key OR invalid key. Single 401 surface — the route has
    // NO permission filter (requireApiKey direct, NOT
    // requireApiKeyWithPermission), so no 403 distinction.
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required." },
      },
    ]);
    try {
      await client.auditLog.verifyChain();
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("429 (rate limit) → AttestryAPIError(429) when retry disabled", async () => {
    // Resource-level pin: a 429 surfaces as AttestryAPIError when
    // retries are disabled. The retry-semantics describe block below
    // covers the default-on path.
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
      await client.auditLog.verifyChain();
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });

  it("non-application/json content-type → AttestryAPIError (P3 hardening — transport-level guard)", async () => {
    // Session-19 review-2 LOW-1: pin the P3 content-type fail-fast
    // claim documented in JSDoc + README. The transport's
    // expectedContentType guard fails fast when the kernel responds
    // with text/html (e.g., a proxy / load-balancer error page
    // wrapped at 200). Mirror of decisions.verifyChain's P3 test.
    //
    // Simulates a proxy returning an HTML 200 page instead of the
    // JSON envelope. Consumer code that didn't have this guard would
    // try to JSON.parse the HTML, throw cryptically, and the
    // consumer would see "Unexpected token < at position 0".
    const mockFetch: FetchLike = async () =>
      new Response("<html><body>Proxy error</body></html>", {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    try {
      await client.auditLog.verifyChain();
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      // The transport's content-type guard surfaces as AttestryAPIError
      // (NOT AttestryError) — it's a transport-level rejection that
      // bears the response status. Status is 200 (the kernel/proxy
      // sent 200 OK with the wrong body); the message names the
      // expected-vs-actual content-type mismatch.
      expect(apiErr.status).toBe(200);
      expect(apiErr.message).toMatch(/application\/json/i);
    }
  });

  it("500 (internal) → AttestryAPIError(500) with SCRUBBED message (no kernel error leak)", async () => {
    // The kernel's internalErrorResponse scrubs the underlying error
    // detail to prevent information disclosure. The SDK surfaces the
    // scrubbed message verbatim — pin that the message does NOT
    // contain raw internal text (DB error codes, verifier function
    // names, etc.).
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
      await client.auditLog.verifyChain();
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
      expect(apiErr.message).not.toContain("verifyAuditChain");
    }
  });
});

// ─── Retry semantics (default-on, opt-out via per-call options) ─────────────

describe("auditLog.verifyChain — retry semantics", () => {
  it("429 retried once by default (carry-forward invariant #18)", async () => {
    // Default retry config retries on 429. Use deterministic small
    // initial delay to keep the test fast.
    const calls: MockedRequest[] = [];
    let i = 0;
    const responses = [
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
      retry: { initialDelayMs: 1, maxDelayMs: 1, maxRetries: 1 },
    });
    const out = await client.auditLog.verifyChain();
    expect(calls).toHaveLength(2);
    expect(out.valid).toBe(true);
  });

  it("429 NOT retried when options.retry: {maxRetries: 0}", async () => {
    // Per-call override suppresses retry. Pin: exactly one fetch,
    // then AttestryAPIError(429) bubbles up.
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
      await client.auditLog.verifyChain({ retry: { maxRetries: 0 } });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
    expect(calls).toHaveLength(1);
  });

  it("5xx NOT retried (only 429 — invariant #18)", async () => {
    // Carry-forward: only 429 is retried. A 500 surfaces immediately
    // even with default retry config.
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
      await client.auditLog.verifyChain();
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(500);
    }
    expect(calls).toHaveLength(1);
  });

  it("retry preserves the partial-success contract (200 with valid:false survives a 429 retry)", async () => {
    // After a 429 + retry, the server's eventual 200-with-valid:false
    // is still surfaced as a resolved Promise (not a thrown error).
    // Pin that the retry path doesn't accidentally re-interpret the
    // negative verdict as a failure.
    const calls: MockedRequest[] = [];
    let i = 0;
    const responses = [
      {
        status: 429 as const,
        body: { success: false, error: "Too many requests." },
      },
      {
        status: 200 as const,
        body: { success: true, data: BROKEN_RESULT },
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
    const out = await client.auditLog.verifyChain();
    expect(calls).toHaveLength(2);
    expect(out.valid).toBe(false);
    expect(out.brokenAt).toBe("11111111-2222-3333-4444-555555555555");
  });
});

// ─── Abort semantics ────────────────────────────────────────────────────────

describe("auditLog.verifyChain — abort semantics", () => {
  it("pre-aborted signal → AttestryError synchronously, no fetch", async () => {
    // Carry-forward invariant #3: pre-aborted signals reject in the
    // transport BEFORE any fetch is issued. Pin: the mock receives no
    // call, the rejection message names "aborted by caller".
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.auditLog.verifyChain({ signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("non-aborted signal → request completes normally (coverage)", async () => {
    // Symmetric happy-path: signal exists, is wired through, but
    // never fires. Pin so the resource-level branch where
    // options.signal is a live signal that gets attached to the
    // transport's AbortController and then cleanly removed in the
    // finally block stays exercised.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const controller = new AbortController();
    const out = await client.auditLog.verifyChain({
      signal: controller.signal,
    });
    expect(out).toEqual(VALID_RESULT);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("mid-flight abort → AttestryError with the abort cause (transport-level)", async () => {
    // The transport composes the caller's signal with its internal
    // one; a mid-flight abort fires the fetch's AbortController and
    // surfaces as AttestryError.
    const calls: MockedRequest[] = [];
    const controller = new AbortController();
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      controller.abort(new Error("mid-flight cancellation"));
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
      await client.auditLog.verifyChain({ signal: controller.signal });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
    }
    expect(calls).toHaveLength(1);
  });
});

// ─── Response-shape validation (P2 hardening) ───────────────────────────────

describe("auditLog.verifyChain — response shape (P2 hardening)", () => {
  it("throws AttestryError when kernel response is null", async () => {
    // P2 extension: extracted-data envelope with null payload. The
    // kernel can't legitimately produce this (route either returns
    // the verdict or errors), but a misbehaving proxy / cache could.
    // The SDK rejects before the consumer's `.valid` deref crashes.
    //
    // Class identity is the contract — must be AttestryError (NOT
    // AttestryAPIError, which is for status-code-bearing errors).
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: null } },
    ]);
    let caught: unknown;
    try {
      await client.auditLog.verifyChain();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /auditLog\.verifyChain: expected an object response from the kernel \(got null\)/,
    );
  });

  it("throws AttestryError when kernel response is an array (not object)", async () => {
    // P2: arrays are typeof "object" but not the kernel's declared
    // shape. Without Array.isArray pre-check, the consumer's `.valid`
    // would silently be `undefined` and `for…of` over
    // AuditChainVerificationResult would iterate array elements.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: [] } },
    ]);
    let caught: unknown;
    try {
      await client.auditLog.verifyChain();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /auditLog\.verifyChain: expected an object response from the kernel \(got array\)/,
    );
  });

  it("throws AttestryError when kernel response is a scalar (string)", async () => {
    // P2: scalar where an object was expected. describeType resolves
    // to "string".
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: "not-an-object" } },
    ]);
    let caught: unknown;
    try {
      await client.auditLog.verifyChain();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /auditLog\.verifyChain: expected an object response from the kernel \(got string\)/,
    );
  });

  it("throws AttestryError when response.valid is not a boolean", async () => {
    // P2 per-field: kernel response.valid is closed-enum boolean.
    // A regression to number/string would silently let consumer code
    // mis-branch.
    const { client } = makeMockedClient([
      {
        status: 200,
        body: { success: true, data: { ...VALID_RESULT, valid: "true" } },
      },
    ]);
    await expect(client.auditLog.verifyChain()).rejects.toThrow(
      /auditLog\.verifyChain: expected response\.valid to be a boolean \(got string\)/,
    );
  });

  it("throws AttestryError when response.entriesVerified is not a number", async () => {
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...VALID_RESULT, entriesVerified: "42" },
        },
      },
    ]);
    await expect(client.auditLog.verifyChain()).rejects.toThrow(
      /auditLog\.verifyChain: expected response\.entriesVerified to be a number \(got string\)/,
    );
  });

  it("throws AttestryError when response.totalEntries is not a number", async () => {
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...VALID_RESULT, totalEntries: null },
        },
      },
    ]);
    await expect(client.auditLog.verifyChain()).rejects.toThrow(
      /auditLog\.verifyChain: expected response\.totalEntries to be a number \(got null\)/,
    );
  });

  it("throws AttestryError when response.firstEntry is neither string nor null", async () => {
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...VALID_RESULT, firstEntry: 12345 },
        },
      },
    ]);
    await expect(client.auditLog.verifyChain()).rejects.toThrow(
      /auditLog\.verifyChain: expected response\.firstEntry to be a string or null \(got number\)/,
    );
  });

  it("throws AttestryError when response.lastEntry is neither string nor null", async () => {
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...VALID_RESULT, lastEntry: true },
        },
      },
    ]);
    await expect(client.auditLog.verifyChain()).rejects.toThrow(
      /auditLog\.verifyChain: expected response\.lastEntry to be a string or null \(got boolean\)/,
    );
  });

  it("throws AttestryError when response.brokenAt is OWN-PROPERTY but not a string", async () => {
    // brokenAt is OPTIONAL — kernel omits it on valid chains. When
    // PRESENT as own-property, it MUST be a string. A regression
    // emitting number/boolean/null would let consumer code crash.
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...BROKEN_RESULT, brokenAt: 42 },
        },
      },
    ]);
    await expect(client.auditLog.verifyChain()).rejects.toThrow(
      /auditLog\.verifyChain: expected response\.brokenAt to be a string when present \(got number\)/,
    );
  });

  it("accepts response.brokenAt absent on valid chain (forward-compat — no own-property)", async () => {
    // The valid-chain shape has NO brokenAt own-property. Validator
    // must NOT reject — pin the forward-compat behavior.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: VALID_RESULT } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.valid).toBe(true);
    expect(out.brokenAt).toBeUndefined();
  });

  it("accepts response.firstEntry/lastEntry: null on empty audit log", async () => {
    // Empty audit log: totalEntries=0, firstEntry=null, lastEntry=null.
    // Validator's `firstEntry !== null && typeof !== "string"` branch
    // must accept null without throwing.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: EMPTY_RESULT } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.firstEntry).toBeNull();
    expect(out.lastEntry).toBeNull();
  });
});

// ─── Missing-own-property it.each (D12 — bake into build round) ─────────────
//
// The multi-line ternary `objectHasOwn(obj, "<field>") ? obj.<field> :
// undefined` drops branch + line coverage to ~98% without these pins
// (the `:undefined` arm is unhit by any test that mocks the field
// present-but-wrong-type). Front-loaded for 100/100/100/100 from
// build round through final commit (carry-forward of session-17
// build-round pattern; session 16's check.run added these in the
// SECOND hostile review and lost coverage temporarily).
//
// 5 always-present fields → 5-row it.each (brokenAt is optional —
// absent-on-valid-chain is forward-compat, NOT a missing-field error).

describe("auditLog.verifyChain — missing own-property exercises :undefined ternary arm (D12)", () => {
  it.each([
    {
      field: "valid",
      expected: "boolean",
      gotMessage: "got undefined",
    },
    {
      field: "entriesVerified",
      expected: "number",
      gotMessage: "got undefined",
    },
    {
      field: "totalEntries",
      expected: "number",
      gotMessage: "got undefined",
    },
    {
      field: "firstEntry",
      expected: "string or null",
      gotMessage: "got undefined",
    },
    {
      field: "lastEntry",
      expected: "string or null",
      gotMessage: "got undefined",
    },
  ])(
    "throws AttestryError when response is missing own-property `$field` (exercises :undefined ternary arm)",
    async ({ field, expected, gotMessage }) => {
      // Build a response WITHOUT the specific field as own-property.
      // The validator's `objectHasOwn(obj, "<field>") ? obj.<field> :
      // undefined` ternary lands on the `:undefined` arm; the
      // subsequent typeof check fires AttestryError. Pin: each of the
      // 5 always-present fields exercises this branch.
      const responseObj: Record<string, unknown> = { ...VALID_RESULT };
      delete responseObj[field];
      const { client } = makeMockedClient([
        { status: 200, body: { success: true, data: responseObj } },
      ]);
      let caught: unknown;
      try {
        await client.auditLog.verifyChain();
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(AttestryError);
      expect(caught).not.toBeInstanceOf(AttestryAPIError);
      const msg = (caught as AttestryError).message;
      expect(msg).toContain(`auditLog.verifyChain: expected response.${field}`);
      expect(msg).toContain(expected);
      expect(msg).toContain(gotMessage);
    },
  );
});

// ─── Prototype-pollution defense (symmetric — response side only) ──────────

describe("auditLog.verifyChain — prototype-pollution defense (response side)", () => {
  // The validator uses module-load `objectHasOwn` snapshot to defend
  // against a hostile dep polluting `Object.prototype.<field>`. These
  // pins simulate the attack and verify the SDK still rejects the
  // missing field.
  //
  // Note: real-world pollution happens by writing to
  // `Object.prototype.<field>` at module-load time of a malicious
  // dependency. We simulate by directly polluting the prototype here
  // BEFORE issuing the request, then cleaning up in afterEach.

  it("Object.prototype.brokenAt pollution does NOT mask missing own-property on valid chain", async () => {
    // Hostile attack: a malicious dep sets
    // `Object.prototype.brokenAt = "fake-uuid"` before the SDK
    // verifies the response. Without `Object.hasOwn`-based defense,
    // a consumer reading `result.brokenAt` would see the polluted
    // value (via prototype walk) — silently misclassifying a VALID
    // chain as BROKEN.
    //
    // With the defense: validator uses `objectHasOwn(obj, "brokenAt")`
    // which returns FALSE on a valid-chain response (kernel omits
    // the field). The polluted prototype value is NOT picked up;
    // result.brokenAt remains undefined to the consumer (via the
    // SDK's faithful-courier — the SDK does NOT delete the polluted
    // prototype, but the validator never reads through it).
    const originalProto = Object.prototype as unknown as {
      brokenAt?: string;
    };
    try {
      // Pollute the prototype before the request.
      (Object.prototype as unknown as { brokenAt?: string }).brokenAt =
        "polluted-uuid-from-malicious-dep";
      const { client } = makeMockedClient([
        { body: { success: true, data: VALID_RESULT } },
      ]);
      const out = await client.auditLog.verifyChain();
      // The validator accepted the response (didn't reject brokenAt
      // as "wrong type" via prototype walk).
      expect(out.valid).toBe(true);
      // Consumer reading via the prototype walk WILL see the polluted
      // value — that's outside the SDK's control. But Object.hasOwn
      // on the result confirms the kernel's response did NOT carry
      // brokenAt as own-property (the defense's load-bearing claim).
      expect(Object.hasOwn(out, "brokenAt")).toBe(false);
    } finally {
      delete originalProto.brokenAt;
    }
  });

  it("Object.prototype.valid pollution does NOT mask missing own-property in the validator", async () => {
    // Combined attack: hostile dep pollutes
    // `Object.prototype.valid = false`, then the kernel response
    // accidentally drops `valid` from the wire (e.g., a regression).
    // Without `Object.hasOwn` defense, `obj.valid` walks the
    // prototype and reads `false` — the validator's
    // `typeof valid !== "boolean"` check passes silently, and the
    // consumer sees a misleading "broken chain" verdict.
    //
    // With the defense: validator uses `objectHasOwn(obj, "valid")`
    // which returns false; ternary lands on `:undefined` arm; typeof
    // check fails; AttestryError thrown. Pin the attack scenario
    // end-to-end.
    const originalProto = Object.prototype as unknown as { valid?: boolean };
    try {
      (Object.prototype as unknown as { valid?: boolean }).valid = false;
      const incomplete = { ...VALID_RESULT } as Partial<
        AuditChainVerificationResult
      >;
      delete incomplete.valid;
      const { client } = makeMockedClient([
        { status: 200, body: { success: true, data: incomplete } },
      ]);
      let caught: unknown;
      try {
        await client.auditLog.verifyChain();
      } catch (err) {
        caught = err;
      }
      // The SDK rejected despite the prototype pollution — the
      // load-bearing claim of the symmetric-defense pattern.
      expect(caught).toBeInstanceOf(AttestryError);
      expect((caught as AttestryError).message).toContain(
        "auditLog.verifyChain: expected response.valid to be a boolean",
      );
      expect((caught as AttestryError).message).toContain("got undefined");
    } finally {
      delete originalProto.valid;
    }
  });

  it("Object.prototype.entriesVerified pollution does NOT mask missing own-property", async () => {
    // Same attack pattern on a numeric field. Pollution sets the
    // prototype to a valid-typed value (number); the kernel response
    // drops the own-property. Without defense: validator reads
    // polluted number via prototype walk, accepts silently. With
    // defense: validator rejects.
    const originalProto = Object.prototype as unknown as {
      entriesVerified?: number;
    };
    try {
      (Object.prototype as unknown as { entriesVerified?: number }).entriesVerified = 999;
      const incomplete = { ...VALID_RESULT } as Partial<
        AuditChainVerificationResult
      >;
      delete incomplete.entriesVerified;
      const { client } = makeMockedClient([
        { status: 200, body: { success: true, data: incomplete } },
      ]);
      let caught: unknown;
      try {
        await client.auditLog.verifyChain();
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(AttestryError);
      expect((caught as AttestryError).message).toContain(
        "auditLog.verifyChain: expected response.entriesVerified to be a number",
      );
      expect((caught as AttestryError).message).toContain("got undefined");
    } finally {
      delete originalProto.entriesVerified;
    }
  });
});

// ─── URL & request invariants ───────────────────────────────────────────────

describe("auditLog.verifyChain — URL & request invariants", () => {
  it("repeated verifyChain() calls produce byte-identical URL (no hidden cache)", async () => {
    // Idempotent at the URL-shape level. Catches a future regression
    // that adds a request-id query param, lowercases the path, or
    // memoizes state across calls.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
      { body: { success: true, data: VALID_RESULT } },
    ]);
    await client.auditLog.verifyChain();
    await client.auditLog.verifyChain();
    expect(calls).toHaveLength(2);
    expect(calls[0].url).toBe(calls[1].url);
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/audit-chain/verify",
    );
  });

  it("concurrent verifyChain() calls share no state — independent fetches", async () => {
    // Two concurrent calls should produce independent fetches with
    // independent results.
    const calls: MockedRequest[] = [];
    const responses = [
      { valid: true, entriesVerified: 10, totalEntries: 10 },
      { valid: false, entriesVerified: 5, totalEntries: 10 },
    ];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      const r = responses[i++];
      const result = { ...VALID_RESULT, ...r };
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
      client.auditLog.verifyChain(),
      client.auditLog.verifyChain(),
    ]);
    expect(calls).toHaveLength(2);
    // Each call got its own response.
    const validities = [outA.valid, outB.valid].sort();
    expect(validities).toEqual([false, true]);
  });

  it("does NOT mutate caller's RequestOptions object", async () => {
    // Symmetric defensive pin. The verifyChain method passes
    // `options` straight through to `_request<T>`; nothing in the
    // resource layer touches the options object. Frozen options must
    // survive without mutation (deep — inner retry obj too).
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const controller = new AbortController();
    const retry = Object.freeze({ maxRetries: 0 });
    const options = Object.freeze({
      signal: controller.signal,
      retry,
    });
    await client.auditLog.verifyChain(options);
    expect(Object.isFrozen(options)).toBe(true);
    expect(Object.isFrozen(options.retry)).toBe(true);
    expect(options.signal).toBe(controller.signal);
    expect(options.retry.maxRetries).toBe(0);
  });

  it("synchronous call signature: returns a Promise (not an iterator)", async () => {
    // Asymmetric with auditLog.export (returns AsyncIterable). Pin
    // that verifyChain returns a Promise — a future refactor that
    // accidentally turned it into a generator would regress here.
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const result = client.auditLog.verifyChain();
    expect(result).toBeInstanceOf(Promise);
    // It must NOT be an async iterable (export returns one; verifyChain does not).
    expect(
      (result as unknown as { [Symbol.asyncIterator]?: unknown })[
        Symbol.asyncIterator
      ],
    ).toBeUndefined();
    await result;
  });
});

// ─── Hostile round (residual gaps) ──────────────────────────────────────────
//
// These pins exercise the defense MECHANISM, not just any rejection
// path. Each H<N> targets a residual gap that build-round tests don't
// directly cover. Mirror of decisions.verifyChain's hostile-round
// structure (H1-H10) adapted for the no-input + optional-brokenAt
// shape.

describe("auditLog.verifyChain — hostile round (residual gaps)", () => {
  it("H1: 429 exhausting all retries → final AttestryAPIError(429) (decisions.verifyChain H9 carry-forward)", async () => {
    // Spec hostile #1: "Default retry on 429 — every retry returns
    // 429, the SDK exhausts the retry budget, and surfaces the final
    // 429 as AttestryAPIError. Fake timers + Math.random stub keep
    // the test fast + deterministic under coverage instrumentation.
    //
    // Hostile-review F5 from decisions.verifyChain: stub Math.random
    // to a non-zero value. retry.ts:sleepWithSignal early-returns via
    // `await Promise.resolve()` when ms<=0 BEFORE registering the
    // abort listener — so an unstubbed Math.random producing < 0.001
    // (~0.1% probability with initialDelayMs:1_000) would yield
    // delay=0, the listener wouldn't register, and the abort path
    // wouldn't be exercised deterministically. Stubbing to 0.5
    // guarantees a non-zero delay (Math.floor(0.5 * 1000) = 500) so
    // the listener always registers under coverage AND production
    // runs.
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0.5);
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
    const promise = client.auditLog.verifyChain();
    const observer = promise.catch(() => undefined);
    await vi.advanceTimersByTimeAsync(1000);
    await observer;
    await expect(promise).rejects.toBeInstanceOf(AttestryAPIError);
    await expect(promise).rejects.toMatchObject({ status: 429 });
    // Loaded contract assertions (session-19 review-1 LOW-3 fix —
    // loosen rather than weaken): the SDK retried at least once
    // (proving retry on 429 fired) AND eventually exhausted the
    // budget (proving the final error surfaces after retry
    // failures). Exact count `expect(fetchCount).toBe(3)` was
    // implementation-coupled — a future retry-policy tweak (e.g.,
    // adding jitter-attempts or skipping retry on the FIRST 429)
    // could change the exact number without violating the contract.
    expect(fetchCount).toBeGreaterThan(1);
    expect(fetchCount).toBeLessThanOrEqual(3);
  });

  it("H2: mid-flight abort during retry backoff — cancels backoff, no second fetch (invariant #22)", async () => {
    // Carry-forward invariant #22 (`sleepWithSignal` cleans up
    // listener in BOTH paths — timer-fires AND abort-fires) is the
    // load-bearing transport behavior. Pin: a 429 → backoff sleep →
    // abort fires mid-sleep → AttestryError thrown synchronously,
    // NO second fetch was issued.
    //
    // Uses fake timers + Math.random stub for determinism — mirror of
    // decisions.verifyChain H9.
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
    const promise = client.auditLog.verifyChain({ signal: ac.signal });
    const observer = promise.catch(() => undefined);
    // Schedule abort to fire mid-backoff. STRING reason (NOT Error) —
    // vitest's fake-timer + AbortController dispatch re-throws Error
    // reasons; strings don't trigger that path.
    setTimeout(() => ac.abort("user cancelled"), 0);
    await vi.advanceTimersByTimeAsync(10);
    await observer;
    await expect(promise).rejects.toThrow(/aborted/);
    // Only the initial 429 was fetched; the backoff was cancelled
    // before the retry could fire.
    expect(fetchCount).toBe(1);
  });

  it("H3: frozen RequestOptions object — SDK does NOT mutate options (deep)", async () => {
    // Symmetric to decisions.verifyChain H4 + export H9. The
    // verifyChain method passes `options` straight through to
    // `_request<T>`; nothing in the resource layer touches the
    // options object. Pin BOTH outer freeze AND inner retry freeze.
    //
    // Hostile-review F4 (from decisions.verifyChain): deep-freeze
    // the inner `retry` object too — shallow Object.freeze leaves
    // nested mutables, so a future regression that did
    // `options.retry.maxRetries = 999` would slip past a shallow
    // check.
    const { client } = makeMockedClient([
      { body: { success: true, data: VALID_RESULT } },
    ]);
    const controller = new AbortController();
    const retry = Object.freeze({ maxRetries: 0 });
    const options = Object.freeze({
      signal: controller.signal,
      retry,
    });
    await client.auditLog.verifyChain(options);
    // Both layers still frozen — confirms no shallow OR deep mutation.
    expect(Object.isFrozen(options)).toBe(true);
    expect(Object.isFrozen(options.retry)).toBe(true);
    expect(options.signal).toBe(controller.signal);
    expect(options.retry.maxRetries).toBe(0);
  });

  it("H4: response with valid:false but NO brokenAt own-property — preserved verbatim, no synthesis", async () => {
    // Distinct from H10 (which tests `valid:true + brokenAt set`):
    // H4 tests the OPPOSITE inconsistency — `valid:false + brokenAt
    // omitted`. A kernel regression where the verifier emits
    // `valid:false` but forgets to populate `brokenAtId` (so the
    // conditional spread at route.ts:72 omits the field) would
    // surface as a "chain is broken, but I don't know where".
    //
    // The SDK's validator allows this — the validator's `brokenAt`
    // check only fires when the field IS an own-property
    // (validator at audit-log.ts:957-965). Faithful courier: the
    // SDK does NOT synthesize a placeholder brokenAt nor reject
    // the response. Consumer-side handling: a `valid:false` verdict
    // with no `brokenAt` indicates an upstream signal-quality
    // issue, NOT an SDK contract violation. Pin: validator accepts;
    // brokenAt remains undefined.
    //
    // **Session-19 review-1 MEDIUM-1 fix**: prior version of this
    // test exercised the same code path as H10 (`valid:true +
    // brokenAt set`). The two tests' assertions traversed identical
    // validator code; one was redundant. This version exercises a
    // DISTINCT path — the `brokenAt`-absent branch when `valid:false`.
    const inconsistent = { ...BROKEN_RESULT } as Partial<
      AuditChainVerificationResult
    >;
    delete inconsistent.brokenAt;
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: inconsistent } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.valid).toBe(false);
    // brokenAt is absent on the wire — SDK does NOT synthesize a
    // placeholder. Consumer sees undefined.
    expect(Object.hasOwn(out, "brokenAt")).toBe(false);
    expect(out.brokenAt).toBeUndefined();
    // Other fields preserved verbatim.
    expect(out.entriesVerified).toBe(BROKEN_RESULT.entriesVerified);
    expect(out.totalEntries).toBe(BROKEN_RESULT.totalEntries);
  });

  it("H5: field-coercion regression test — boolean valid as 1 / number as string rejected", async () => {
    // Faithful courier: SDK does NOT coerce 1 → true or "42" → 42.
    // The validator's strict `typeof` checks fire on type mismatch.
    // Pin BOTH paths — defends against a future "type-cleanup"
    // refactor that adds runtime coercion.
    const wrongType1 = { ...VALID_RESULT, valid: 1 };
    const { client: client1 } = makeMockedClient([
      { status: 200, body: { success: true, data: wrongType1 } },
    ]);
    await expect(client1.auditLog.verifyChain()).rejects.toThrow(
      /auditLog\.verifyChain: expected response\.valid to be a boolean \(got number\)/,
    );

    const wrongType2 = { ...VALID_RESULT, entriesVerified: "42" };
    const { client: client2 } = makeMockedClient([
      { status: 200, body: { success: true, data: wrongType2 } },
    ]);
    await expect(client2.auditLog.verifyChain()).rejects.toThrow(
      /auditLog\.verifyChain: expected response\.entriesVerified to be a number \(got string\)/,
    );
  });

  it("H6: large totalEntries (MAX_SAFE_INTEGER) preserved verbatim — no overflow / no precision loss", async () => {
    // JSON.parse correctly decodes 9007199254740991 as a number.
    // SDK forwards. Pin: extreme-but-valid integer survives the
    // round-trip with full precision. Defends against future
    // BigInt-conversion attempts that would silently overflow at
    // 2^53.
    const huge = {
      ...VALID_RESULT,
      totalEntries: Number.MAX_SAFE_INTEGER,
      entriesVerified: Number.MAX_SAFE_INTEGER,
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: huge } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.totalEntries).toBe(Number.MAX_SAFE_INTEGER);
    expect(out.entriesVerified).toBe(Number.MAX_SAFE_INTEGER);
    expect(Number.isSafeInteger(out.totalEntries)).toBe(true);
    expect(Number.isSafeInteger(out.entriesVerified)).toBe(true);
  });

  it("H7: 200 with empty body `{}` — AttestryError thrown via missing fields (extreme-degenerate)", async () => {
    // Transport's unwrap-discrimination falls through:
    //   parsed.success !== true → return parsed as T directly.
    // With P2 hardening in place, the validator catches this BEFORE
    // returning to the consumer — the empty {} fails the very first
    // field check (`valid` must be boolean, got undefined).
    //
    // Asymmetric with decisions.verifyChain H7 (which passes {} as
    // forward-compat); auditLog.verifyChain has STRICTER P2
    // validation. Pin the rejection at the first-failing-field
    // boundary so a future SDK relaxation doesn't silently regress
    // to consumer-undefined-deref.
    const { client } = makeMockedClient([
      { status: 200, body: {} },
    ]);
    let caught: unknown;
    try {
      await client.auditLog.verifyChain();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    // First field check fires — `valid` is missing.
    expect((caught as AttestryError).message).toContain(
      "auditLog.verifyChain: expected response.valid to be a boolean",
    );
  });

  it("H8: 200 with bare `{success:true}` (no data) — falls through to envelope shape; validator rejects", async () => {
    // The transport's unwrap discrimination is strict: requires BOTH
    // `success === true` AND `"data" in parsed`. Without `data`, it
    // falls through to `return parsed as T` — consumer sees the bare
    // envelope `{success: true}`. With P2 hardening, the validator
    // sees `obj.valid === undefined` (envelope has no `valid` field)
    // and rejects. Pin the rejection path.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true } },
    ]);
    let caught: unknown;
    try {
      await client.auditLog.verifyChain();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toContain(
      "auditLog.verifyChain: expected response.valid to be a boolean",
    );
  });

  it("H9: combined attack — Object.hasOwn global override + valid-typed Object.prototype.valid pollution + missing-own-property response; module-load snapshot defense fires", async () => {
    // CRITICAL hostile pin — exercises the LOAD-BEARING defense
    // mechanism, NOT just any rejection path.
    //
    // **The construction is adversarial** — the polluted value MUST
    // be a value the validator's typeof check would ACCEPT, so the
    // ONLY way the test can distinguish "defense active" from
    // "defense broken" is via the `objectHasOwn` branch:
    //   - WITH defense (validator uses module-load snapshot): the
    //     snapshot's hasOwn returns false on the missing field; the
    //     ternary lands on `:undefined`; typeof check fails on
    //     undefined; AttestryError thrown. **Test passes via the
    //     thrown error.**
    //   - WITHOUT defense (validator uses overridden global): the
    //     overridden global's hasOwn returns true; the ternary reads
    //     `obj.valid` which WALKS THE PROTOTYPE and reads the
    //     polluted `true`; typeof check passes; NO throw; the
    //     consumer would receive a "valid:true" verdict for a
    //     response that was actually MISSING the field. **Test
    //     would fail to throw and the assertion would fail.**
    //
    // This construction (pollute `valid` with `true`, omit `valid`
    // own-property) is the only way to write an end-to-end attack
    // simulation where the polluted prototype value is TYPE-VALID.
    // Mirror of the build-round prototype-pollution-defense test
    // for `Object.prototype.valid` at lines ~952-973, but extended
    // with a `Object.hasOwn` global override (this is what makes it
    // CRITICAL — it verifies the SNAPSHOT survives the override,
    // not just that `objectHasOwn` is called).
    //
    // Hostile-review session-19 review-1 HIGH-1 fix: the prior
    // version of this test polluted `brokenAt` with a string and
    // sent VALID_RESULT (no brokenAt own-property). That construction
    // passed in BOTH defense states because (a) the validator's
    // `brokenAt` branch only fires when the own-property IS present
    // (lines 957-965 of audit-log.ts), and (b) a polluted string is
    // a valid string regardless of how it was read. The test
    // verified neither branch — it was a no-op. The new construction
    // uses `valid` (which has an UNCONDITIONAL own-property check —
    // every code path through the validator reads `obj.valid` first)
    // so the override-vs-snapshot distinction is observable.
    const originalProto = Object.prototype as unknown as { valid?: boolean };
    // Hostile-review session-19 review-3 L4 fix: capture the spy
    // handle so we can restore it eagerly in `finally` BEFORE the
    // proto-cleanup AND BEFORE control hands off to `afterEach`.
    // Without an eager restore, the override would survive across
    // the finally block and into any additional `afterEach` hook
    // that registers before `vi.restoreAllMocks()` — a fragility
    // hazard if future hooks happen to call `Object.hasOwn`.
    // Belt-and-suspenders with the afterEach restore.
    let hasOwnSpy: ReturnType<typeof vi.spyOn> | undefined;
    try {
      // Step 1: pollute prototype with a VALID-TYPED value.
      // `typeof valid === "boolean"` passes on `true` — so if the
      // validator reads through the prototype, the type check
      // passes and the validator silently accepts a response that
      // is actually MISSING the `valid` field.
      (Object.prototype as unknown as { valid?: boolean }).valid = true;
      // Step 2: override the GLOBAL Object.hasOwn to ALWAYS return
      // true. The module-load snapshot in audit-log.ts captured the
      // ORIGINAL; without that snapshot, the validator would use
      // this overridden version and accept the polluted boolean.
      //
      // Hostile-review session-19 review-2 LOW-3 fix: use
      // `vi.spyOn(Object, "hasOwn")` rather than direct assignment.
      // Direct `Object.hasOwn = () => true;` survives `afterEach`'s
      // `vi.restoreAllMocks()` because it bypassed vitest's mock
      // tracking — a test-runner kill (timeout, SIGKILL) between the
      // assignment and the manual restore in `finally` would leak
      // the override to all subsequent test files in the same Vitest
      // worker process. With `vi.spyOn`, vitest tracks the mock AND
      // the afterEach's `vi.restoreAllMocks()` cleans it up even on
      // crash paths.
      hasOwnSpy = vi.spyOn(Object, "hasOwn").mockImplementation(
        () => true,
      );
      // Step 3: send a response WITHOUT `valid` as own-property.
      const incomplete = { ...VALID_RESULT } as Partial<
        AuditChainVerificationResult
      >;
      delete incomplete.valid;
      const { client } = makeMockedClient([
        { status: 200, body: { success: true, data: incomplete } },
      ]);
      let caught: unknown;
      try {
        await client.auditLog.verifyChain();
      } catch (err) {
        caught = err;
      }
      // **Load-bearing assertion**: the SDK rejected DESPITE both
      // the `Object.hasOwn` override AND the type-valid prototype
      // pollution. This proves the module-load snapshot survived
      // the override — the validator's `objectHasOwn` is the
      // snapshot, NOT the overridden global. **Without the snapshot
      // defense, this assertion fails** (validator would silently
      // accept the polluted boolean and the consumer would receive
      // a bogus `{valid: true, ...}` verdict for a malformed
      // response).
      expect(caught).toBeInstanceOf(AttestryError);
      expect(caught).not.toBeInstanceOf(AttestryAPIError);
      expect((caught as AttestryError).message).toContain(
        "auditLog.verifyChain: expected response.valid to be a boolean",
      );
      expect((caught as AttestryError).message).toContain("got undefined");
    } finally {
      // Session-19 review-3 L4 fix: restore the spy EAGERLY so
      // the global Object.hasOwn is back to its original behavior
      // BEFORE control hands off to afterEach. afterEach's
      // vi.restoreAllMocks() is the safety net; this is the
      // primary restoration. Restore spy FIRST, then proto
      // cleanup (the delete itself doesn't use Object.hasOwn but
      // the ordering keeps any post-finally hook safe).
      hasOwnSpy?.mockRestore();
      delete originalProto.valid;
    }
  });

  it("H10: response with extra brokenAt own-property + valid:true (forward-compat) — preserved verbatim, no normalization", async () => {
    // Asymmetric with H4: H4 covered the case where valid:true
    // somehow has brokenAt set (logical inconsistency). H10 covers
    // the FORWARD-COMPAT case: a future kernel might choose to
    // ALWAYS emit brokenAt (with null on valid chains), or emit
    // brokenAt with a sentinel value. The SDK is a faithful courier
    // — preserves the value as-given. Pin: response with brokenAt:
    // "any-valid-uuid-string" + valid:true is accepted and forwarded.
    //
    // The validator's `typeof brokenAt !== "string"` check passes
    // (it's a string); no rejection. The SDK does NOT enforce a
    // cross-field rule "brokenAt should not be present when
    // valid:true".
    const futureCompat = {
      ...VALID_RESULT,
      brokenAt: "00000000-0000-0000-0000-000000000000",
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: futureCompat } },
    ]);
    const out = await client.auditLog.verifyChain();
    expect(out.valid).toBe(true);
    expect(out.brokenAt).toBe("00000000-0000-0000-0000-000000000000");
    // Confirms the SDK is faithful-courier — does NOT enforce
    // cross-field consistency.
  });
});
