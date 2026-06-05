import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError } from "../../errors.js";
import type {
  DecisionListItem,
  DecisionsListInput,
  DecisionsListResponse,
} from "../decisions.js";
import type { FetchLike } from "../../types.js";

// ─── decisions.list — paginated cursor GET ─────────────────────────────────
//
// Wire shape (from src/lib/decisions/list-query.ts queryDecisionRecords):
//   GET /api/v1/decisions?systemId=…&from=…&to=…&framework=…&article=…
//                       &tool=…&cursor=…&limit=…&includeTombstoned=…
//   → { items: DecisionListItem[], nextCursor: string | null }
//
// Symmetric to incidents.list. Cursor format is opaque to the SDK; the
// kernel encodes (base64url JSON {c: ISO, i: UUID}) and decodes server-side.
// Pagination is keyset over (createdAt DESC, id DESC).

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
    // and accidentally consume the next mock response.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const MOCK_ITEM: DecisionListItem = {
  id: "11111111-1111-1111-1111-111111111111",
  systemId: "33333333-3333-3333-3333-333333333333",
  sequenceNumber: 1,
  inputDigest:
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  outputDigest: null,
  frameworkClaims: [],
  toolInvocations: [],
  delegationChain: [],
  humanOversightState: null,
  policyOutcome: null,
  recordHash:
    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  prevRecordHash: null,
  createdAt: "2026-04-27T00:00:00.000Z",
  tombstoned: false,
};

const MOCK_ITEM_2: DecisionListItem = {
  ...MOCK_ITEM,
  id: "22222222-2222-2222-2222-222222222222",
  sequenceNumber: 2,
  prevRecordHash: MOCK_ITEM.recordHash,
  recordHash:
    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
  createdAt: "2026-04-27T00:00:01.000Z",
};

const CURSOR_1 = "eyJjIjoiMjAyNi0wNC0yN1QwMDowMDowMS4wMDBaIiwiaSI6IjIyMjIyMjIyLTIyMjItMjIyMi0yMjIyLTIyMjIyMjIyMjIyMiJ9";

describe("decisions.list — happy path", () => {
  it("GETs /api/v1/decisions with no body and no query when no input given", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: [MOCK_ITEM], nextCursor: null },
        },
      },
    ]);
    const out = await client.decisions.list();
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe("https://test.attestry.local/api/v1/decisions");
    expect(calls[0].body).toBeUndefined();
    expect(out).toEqual({ items: [MOCK_ITEM], nextCursor: null });
  });

  it("returns the slim item shape unchanged (envelope unwrapped)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: [MOCK_ITEM, MOCK_ITEM_2], nextCursor: CURSOR_1 },
        },
      },
    ]);
    const out = await client.decisions.list();
    expect(out.items).toHaveLength(2);
    expect(out.items[0].id).toBe(MOCK_ITEM.id);
    expect(out.items[1].id).toBe(MOCK_ITEM_2.id);
    expect(out.nextCursor).toBe(CURSOR_1);
  });

  it("encodes systemId as URL query parameter", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({
      systemId: "33333333-3333-3333-3333-333333333333",
    });
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions?systemId=33333333-3333-3333-3333-333333333333",
    );
  });

  it("encodes every documented filter on the URL when provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({
      systemId: "33333333-3333-3333-3333-333333333333",
      from: "2026-04-01T00:00:00.000Z",
      to: "2026-05-01T00:00:00.000Z",
      framework: "eu_ai_act",
      article: "Art.13",
      tool: "vector-store-query",
      cursor: CURSOR_1,
      limit: 100,
      includeTombstoned: true,
    });
    const url = new URL(calls[0].url);
    expect(url.searchParams.get("systemId")).toBe(
      "33333333-3333-3333-3333-333333333333",
    );
    expect(url.searchParams.get("from")).toBe("2026-04-01T00:00:00.000Z");
    expect(url.searchParams.get("to")).toBe("2026-05-01T00:00:00.000Z");
    expect(url.searchParams.get("framework")).toBe("eu_ai_act");
    expect(url.searchParams.get("article")).toBe("Art.13");
    expect(url.searchParams.get("tool")).toBe("vector-store-query");
    expect(url.searchParams.get("cursor")).toBe(CURSOR_1);
    expect(url.searchParams.get("limit")).toBe("100");
    expect(url.searchParams.get("includeTombstoned")).toBe("true");
  });

  it("URL-encodes filter values containing special characters", async () => {
    // Defensive: a tool name like "search/v2#latest" must be URL-encoded
    // so it doesn't break the query string parser server-side.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({ tool: "search/v2#latest?q=x" });
    // encodeURIComponent replaces `/`, `#`, `?`, `=` with %2F, %23, %3F, %3D.
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions?tool=search%2Fv2%23latest%3Fq%3Dx",
    );
  });

  it("forwards x-api-key + Accept (no Content-Type — GET, no body)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list();
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBeNull();
  });

  it("does NOT send query params for undefined fields (clean URL)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    // Only systemId provided — other fields should NOT appear on the URL.
    await client.decisions.list({
      systemId: "33333333-3333-3333-3333-333333333333",
    });
    const url = new URL(calls[0].url);
    expect([...url.searchParams.keys()]).toEqual(["systemId"]);
  });

  it("supports cursor round-trip — pass back nextCursor as cursor", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: [MOCK_ITEM, MOCK_ITEM_2], nextCursor: CURSOR_1 },
        },
      },
      {
        body: { success: true, data: { items: [], nextCursor: null } },
      },
    ]);
    const page1 = await client.decisions.list({ limit: 2 });
    expect(page1.nextCursor).toBe(CURSOR_1);
    const page2 = await client.decisions.list({
      limit: 2,
      cursor: page1.nextCursor!,
    });
    expect(page2.items).toHaveLength(0);
    expect(page2.nextCursor).toBeNull();
    expect(calls).toHaveLength(2);
    expect(new URL(calls[1].url).searchParams.get("cursor")).toBe(CURSOR_1);
  });
});

describe("decisions.list — input validation (pre-fetch)", () => {
  it("throws TypeError for empty systemId — does NOT issue a request", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.list({ systemId: "" })).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.list({ systemId: 42 as unknown as string }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.list({ systemId: null as unknown as string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty cursor", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.list({ cursor: "" })).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty from / to / framework / article / tool", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.list({ from: "" })).toThrowError(TypeError);
    expect(() => client.decisions.list({ to: "" })).toThrowError(TypeError);
    expect(() => client.decisions.list({ framework: "" })).toThrowError(
      TypeError,
    );
    expect(() => client.decisions.list({ article: "" })).toThrowError(
      TypeError,
    );
    expect(() => client.decisions.list({ tool: "" })).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-number limit", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.list({ limit: "50" as unknown as number }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.list({ limit: null as unknown as number }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-boolean includeTombstoned", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.list({
        includeTombstoned: "true" as unknown as boolean,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.list({
        includeTombstoned: 1 as unknown as boolean,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("does NOT pre-validate format — server validates UUID, ISO dates, etc.", async () => {
    // SDK-side: type-check only (string non-empty). Format check (UUID,
    // ISO date) deferred to server. Pin: a non-UUID systemId still goes
    // through to the server, which 422s it. Without this pin, a future
    // "be helpful" SDK refactor adding UUID validation would diverge
    // from the server's actual error path.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Invalid query parameters." },
      },
    ]);
    try {
      await client.decisions.list({ systemId: "not-a-uuid" });
    } catch {
      /* ignore — verifying the request was issued */
    }
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0].url).searchParams.get("systemId")).toBe(
      "not-a-uuid",
    );
  });
});

describe("decisions.list — error paths", () => {
  it("surfaces a 400 (malformed cursor) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Cursor is not valid base64url" },
      },
    ]);
    try {
      await client.decisions.list({ cursor: "not-a-cursor" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.message).toMatch(/Cursor/);
    }
  });

  it("surfaces a 422 (invalid query params) as AttestryAPIError with field errors", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Invalid query parameters.",
          details: [{ path: "limit", message: "Number must be ≤ 200" }],
        },
      },
    ]);
    try {
      await client.decisions.list({ limit: 1000 });
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.details).toMatchObject({
        details: [{ path: "limit", message: "Number must be ≤ 200" }],
      });
    }
  });

  it("surfaces a 401 as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Auth required." },
      },
    ]);
    try {
      await client.decisions.list();
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 403 (insufficient permissions) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 403,
        body: { success: false, error: "Forbidden." },
      },
    ]);
    try {
      await client.decisions.list();
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
    }
  });

  it("surfaces a 429 (rate limit) as AttestryAPIError when retry is disabled", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: { success: false, error: "Too many requests." },
      },
    ]);
    try {
      await client.decisions.list();
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });
});

describe("decisions.list — P2 response shape validation", () => {
  it("throws AttestryError when kernel response is null (post-envelope-unwrap)", async () => {
    // P2 hardening: the kernel emits {success:true, data:{items, nextCursor}}
    // and the transport unwraps to {items, nextCursor}. A regression
    // that emits `data: null` would let consumers crash on `out.items`
    // with a confusing TypeError. Resource-layer validator catches it.
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(client.decisions.list()).rejects.toThrow(
      /expected an object response from the kernel \(got null\)/,
    );
  });

  it("throws AttestryError when kernel response is an array instead of object", async () => {
    // A kernel-side mistake that emits `successResponse([items])` instead
    // of `successResponse({items: [...], nextCursor: null})` would slip
    // through TypeScript-typed access (`out.items` returns undefined).
    // Validator catches.
    const { client } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await expect(client.decisions.list()).rejects.toThrow(
      /expected an object response from the kernel \(got array\)/,
    );
  });

  it("throws AttestryError when `items` is missing (or not an array)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { nextCursor: null } } },
    ]);
    await expect(client.decisions.list()).rejects.toThrow(
      /missing or invalid `items` array \(got undefined\)/,
    );
  });

  it("throws AttestryError when `items` is a non-array (e.g., string)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: "scalar", nextCursor: null } } },
    ]);
    await expect(client.decisions.list()).rejects.toThrow(
      /missing or invalid `items` array \(got string\)/,
    );
  });

  it("throws AttestryError when `nextCursor` is undefined (must be string or null per kernel contract)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [] } } },
    ]);
    await expect(client.decisions.list()).rejects.toThrow(
      /`nextCursor` must be string or null \(got undefined\)/,
    );
  });

  it("throws AttestryError when `nextCursor` is a number (must be string or null)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: 42 } } },
    ]);
    await expect(client.decisions.list()).rejects.toThrow(
      /`nextCursor` must be string or null \(got number\)/,
    );
  });

  it("ACCEPTS valid response: empty items + null nextCursor (boundary case)", async () => {
    // Symmetric pin: confirms the validator does NOT reject valid
    // edge-of-spec responses. Empty list + last-page cursor is a
    // legitimate kernel response.
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    const out = await client.decisions.list();
    expect(out).toEqual({ items: [], nextCursor: null });
  });

  it("P2 forward-compat: extra unknown top-level fields on response pass through (validator accepts)", async () => {
    // The validator checks `items` is array and `nextCursor` is
    // string|null. Other properties on the response object are
    // ignored — forward-compat for kernel additions like a future
    // `total` count or `pageSize` echo. Pin documents this; a
    // future "be helpful" tightening that strips unknown fields
    // would surface here.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            items: [],
            nextCursor: null,
            total: 42, // hypothetical future addition
            schemaVersion: "v2",
          },
        },
      },
    ]);
    const out = await client.decisions.list();
    expect(out.items).toEqual([]);
    expect(out.nextCursor).toBeNull();
    expect(
      (out as unknown as Record<string, unknown>).total,
    ).toBe(42);
    expect(
      (out as unknown as Record<string, unknown>).schemaVersion,
    ).toBe("v2");
  });
});

describe("decisions.list — abort + retry semantics", () => {
  it("forwards the caller's AbortSignal through RequestOptions", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.decisions.list({}, { signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally (coverage)", async () => {
    // Symmetric to decisions.retrieve coverage pin.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    const controller = new AbortController();
    const out = await client.decisions.list(
      {},
      { signal: controller.signal },
    );
    expect(out).toEqual({ items: [], nextCursor: null });
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies (independent of resource-helper default)", async () => {
    // The makeMockedClient helper sets retry: {maxRetries: 0} by default.
    // Per-call override should re-enable retry for this single call.
    // Pin against the retry middleware's per-call precedence.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "x" } },
      { body: { success: true, data: { items: [MOCK_ITEM], nextCursor: null } } },
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
      retry: { maxRetries: 0 }, // client says 0…
    });
    // …per-call says 1 with tight backoff.
    const promise = client.decisions.list(
      {},
      { retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 } },
    );
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out.items).toHaveLength(1);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });
});

describe("decisions.list — hostile-round defenses", () => {
  it("H1: `includeTombstoned: false` is OMITTED from the URL (workaround for kernel z.coerce.boolean bug)", async () => {
    // The kernel uses `z.coerce.boolean()` which delegates to
    // `Boolean(value)` — Boolean("false") === true. So a literal
    // `?includeTombstoned=false` would be coerced server-side to TRUE,
    // returning tombstoned records against the user's explicit wishes.
    // Workaround: SDK omits the param when the caller passes `false`,
    // letting the server's `default(false)` apply (same intended
    // behavior). Pin: URL has NO `includeTombstoned` query param.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({ includeTombstoned: false });
    const url = new URL(calls[0].url);
    expect(url.searchParams.has("includeTombstoned")).toBe(false);
  });

  it("H1 (cont.): `includeTombstoned: true` IS sent (server coerces correctly for true)", async () => {
    // Symmetric: when the caller explicitly wants tombstoned records,
    // we DO send the param. `Boolean("true") === true` server-side ✓.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({ includeTombstoned: true });
    expect(new URL(calls[0].url).searchParams.get("includeTombstoned")).toBe(
      "true",
    );
  });

  it("H2: empty filter values via toString shenanigans (e.g. empty array) are rejected at validation", async () => {
    // Defense in depth: `decisions.list({ systemId: [] as any })` — the
    // typeof check sees 'object', not 'string', so the validator throws.
    // Without this, `String([])` = "" would land on the URL as
    // `?systemId=` — server may interpret as undefined or 422; either
    // way, subtle bug. Pin the SDK-side rejection.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.list({ systemId: [] as unknown as string }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.list({ systemId: {} as unknown as string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("H3: hostile cursor (looks valid but is malformed) → 400 from server, surfaces as AttestryAPIError", async () => {
    // Server's decodeCursor() rejects malformed base64url + missing
    // fields + invalid date/UUID via CursorParseError → 400. Pin the
    // SDK error path: AttestryAPIError(400) with the server's message.
    const { client } = makeMockedClient([
      {
        status: 400,
        body: {
          success: false,
          error: "Cursor.c must be a valid ISO datetime",
        },
      },
    ]);
    try {
      // Hand-crafted base64url that decodes to invalid JSON cursor.
      await client.decisions.list({ cursor: "eyJjIjoiTk9QRSIsImkiOiJOT1QtVVVJRCJ9" });
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(400);
      expect((err as AttestryAPIError).message).toMatch(/ISO datetime/);
    }
  });

  it("H4: limit = NaN / Infinity flows through; server rejects via Zod int() check", async () => {
    // SDK validates `limit` is a number — NaN and Infinity ARE numbers
    // (typeof NaN === 'number'), so they pass the SDK's typeof gate.
    // String(NaN) = 'NaN', String(Infinity) = 'Infinity'. Server's
    // z.coerce.number().int() rejects both → 422. Pin: SDK forwards
    // (no client-side range guard) and server rejects.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Invalid query parameters." },
      },
    ]);
    try {
      await client.decisions.list({ limit: NaN });
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0].url).searchParams.get("limit")).toBe("NaN");
  });

  it("H5: cursor reuse / replay returns the same page (SDK side stateless)", async () => {
    // Cursors are unsigned and stateless. Reusing the same cursor
    // returns the same page deterministically (server side). Pin SDK
    // statelessness: two calls with the same cursor produce two
    // separate fetches with identical query strings.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({ cursor: CURSOR_1 });
    await client.decisions.list({ cursor: CURSOR_1 });
    expect(calls).toHaveLength(2);
    expect(calls[0].url).toBe(calls[1].url);
  });

  it("H6: very long filter value passes through to server (server enforces length cap)", async () => {
    // SDK has no length cap on filter values; server's Zod schemas do
    // (1-100 / 1-200 / 1-500 chars). Pin: a 1000-char tool name is
    // forwarded; server returns 422.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Invalid query parameters." },
      },
    ]);
    const huge = "x".repeat(1000);
    try {
      await client.decisions.list({ tool: huge });
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0].url).searchParams.get("tool")).toBe(huge);
  });
});

describe("decisions.list — coverage-round defensive pins", () => {
  it("C1: limit at the lower boundary (1) flows through faithfully", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({ limit: 1 });
    expect(new URL(calls[0].url).searchParams.get("limit")).toBe("1");
  });

  it("C1 (cont.): limit at the upper boundary (200) flows through faithfully", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({ limit: 200 });
    expect(new URL(calls[0].url).searchParams.get("limit")).toBe("200");
  });

  it("C2: explicit `includeTombstoned: undefined` is treated identically to omission", async () => {
    // The H1 workaround uses `=== true` strict-equality, so `undefined`
    // falls into the `: undefined` branch (omits param). Pin: explicit
    // undefined produces the same URL as omitting the field entirely.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({ includeTombstoned: undefined });
    await client.decisions.list({});
    expect(new URL(calls[0].url).searchParams.has("includeTombstoned")).toBe(
      false,
    );
    expect(new URL(calls[1].url).searchParams.has("includeTombstoned")).toBe(
      false,
    );
    expect(calls[0].url).toBe(calls[1].url);
  });

  it("C3: combined cursor + filters preserves both on the URL", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.decisions.list({
      cursor: CURSOR_1,
      systemId: "33333333-3333-3333-3333-333333333333",
      limit: 25,
      from: "2026-04-01T00:00:00.000Z",
    });
    const url = new URL(calls[0].url);
    expect(url.searchParams.get("cursor")).toBe(CURSOR_1);
    expect(url.searchParams.get("systemId")).toBe(
      "33333333-3333-3333-3333-333333333333",
    );
    expect(url.searchParams.get("limit")).toBe("25");
    expect(url.searchParams.get("from")).toBe("2026-04-01T00:00:00.000Z");
  });

  it("C4: validateOptionalNonEmptyString — non-string types comprehensively rejected", async () => {
    // Walks every JS primitive + structural type past the helper to
    // ensure the typeof guard rejects each consistently. Build round
    // pinned a couple cases (number, null) — coverage round closes
    // the rest (boolean, function, array, Symbol).
    const { client } = makeMockedClient([]);
    const cases: Array<unknown> = [
      true, // boolean
      false,
      Symbol("x"), // symbol
      () => "x", // function
      ["x"], // array
      { toString: () => "x" }, // object with custom toString
    ];
    for (const v of cases) {
      expect(() =>
        client.decisions.list({ systemId: v as unknown as string }),
      ).toThrowError(TypeError);
    }
  });

  it("C5: validateOptionalNonEmptyString — error message names the offending field", async () => {
    // Build round pinned the throw; this round pins the MESSAGE shape.
    // Ensures the error tells the consumer WHICH field was invalid
    // (not just "validation failed" for one of seven optional fields).
    const { client } = makeMockedClient([]);
    try {
      client.decisions.list({ framework: "" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toMatch(/`framework`/);
    }
    try {
      client.decisions.list({ tool: "" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toMatch(/`tool`/);
    }
  });

  it("C6: TypeError message preserves `decisions.list:` method-name prefix (refactor backward-compat)", async () => {
    // The decisions.ingest build round (audit-prompt-F.1-decisions-ingest.md
    // D8) refactored `validateOptionalNonEmptyString` to take an
    // optional `methodName` parameter, defaulting to `"decisions.list"`
    // so existing call sites here surface the original prefix unchanged.
    //
    // Without this pin, a future refactor that changes the default
    // (e.g., to `"validation"` or accidentally to `""`) would slip
    // past every existing list test — they only assert field-name
    // matches like /`framework`/, not the method-name prefix.
    //
    // Pin: every TypeError surfaced from a `decisions.list` validation
    // failure starts with the literal `"decisions.list:"`. Mirrors
    // the `decisions.ingest:` prefix coverage pin (C7 in
    // decisions-ingest.test.ts).
    const { client } = makeMockedClient([]);
    const optionalStringFields: Array<[
      keyof DecisionsListInput,
      string | object,
    ]> = [
      ["systemId", ""],
      ["from", ""],
      ["to", ""],
      ["framework", ""],
      ["article", ""],
      ["tool", ""],
      ["cursor", ""],
      // Non-string types also flow through the same helper — pin
      // the message format for those too.
      ["framework", 42 as unknown as string],
    ];
    for (const [field, value] of optionalStringFields) {
      try {
        client.decisions.list({
          [field]: value,
        } as unknown as DecisionsListInput);
        throw new Error(`expected throw for ${String(field)}`);
      } catch (err) {
        expect(err).toBeInstanceOf(TypeError);
        const msg = (err as TypeError).message;
        // Prefix is load-bearing — guard against silent default drift.
        expect(msg.startsWith("decisions.list:")).toBe(true);
        expect(msg).toContain(`\`${String(field)}\``);
        expect(msg).toContain("non-empty string when provided");
      }
    }
  });
});

describe("decisions.list — pagination edge cases", () => {
  it("empty result set: items=[], nextCursor=null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    const out = await client.decisions.list();
    expect(out.items).toEqual([]);
    expect(out.nextCursor).toBeNull();
  });

  it("single page: items < limit, nextCursor=null", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: [MOCK_ITEM], nextCursor: null },
        },
      },
    ]);
    const out = await client.decisions.list({ limit: 50 });
    expect(out.items).toHaveLength(1);
    expect(out.nextCursor).toBeNull();
  });

  it("multi-page: items = limit, nextCursor=cursor", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: [MOCK_ITEM, MOCK_ITEM_2], nextCursor: CURSOR_1 },
        },
      },
    ]);
    const out: DecisionsListResponse = await client.decisions.list({
      limit: 2,
    });
    expect(out.items).toHaveLength(2);
    expect(out.nextCursor).toBe(CURSOR_1);
  });

  it("preserves item ordering (DESC by createdAt) on the wire", async () => {
    // Pin: SDK doesn't reshuffle items. Server returns DESC; SDK
    // preserves order so cursor logic stays meaningful.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          // Server returns most-recent first (sequenceNumber 2 before 1).
          data: { items: [MOCK_ITEM_2, MOCK_ITEM], nextCursor: null },
        },
      },
    ]);
    const out = await client.decisions.list();
    expect(out.items[0].sequenceNumber).toBe(2);
    expect(out.items[1].sequenceNumber).toBe(1);
  });
});

// ─── lone-surrogate URIError guard (cross-phase follow-up) ────────────────
//
// Pinned alongside decisions.export's URIError guard (commit 0428777).
// Without `assertEncodableQueryString` in `list()`, the underlying
// `encodeQuery` → `encodeURIComponent` would leak a raw `URIError` for
// any malformed UTF-16 (lone surrogate) input, inconsistent with
// `decisions.retrieve` (which converts URIError → TypeError) and with
// `decisions.export` (now guarded). All 7 string filter fields are
// passed through encodeURIComponent and need the same treatment.

describe("decisions.list — lone-surrogate URIError guard (cross-phase fix)", () => {
  const LONE_HIGH = "\uD800"; // unpaired high surrogate
  const LONE_LOW = "\uDFFF"; // unpaired low surrogate
  const VALID_EMOJI = "✓"; // proper character — positive control

  function makeNoFetchClient() {
    return new AttestryClient({
      apiKey: "k",
      baseUrl: "https://test.attestry.local",
      // Mock fetch that fails the test if called — input validation
      // must throw synchronously before any request fires.
      fetch: (() => {
        throw new Error("fetch should not be called");
      }) as unknown as FetchLike,
    });
  }

  const FIELDS = [
    "systemId",
    "from",
    "to",
    "framework",
    "article",
    "tool",
    "cursor",
  ] as const;

  for (const field of FIELDS) {
    it(`throws TypeError for lone surrogate in \`${field}\` — does NOT issue a request`, () => {
      const client = makeNoFetchClient();
      const input: DecisionsListInput = { [field]: LONE_HIGH } as DecisionsListInput;
      let caught: unknown = null;
      try {
        void client.decisions.list(input);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(TypeError);
      expect((caught as TypeError).message).toContain(
        `decisions.list: \`${field}\``,
      );
      expect((caught as TypeError).message).toContain("invalid UTF-16");
      // Cause is the underlying URIError.
      expect((caught as TypeError).cause).toBeInstanceOf(Error);
    });
  }

  it("throws for a lone LOW surrogate as well as HIGH", () => {
    const client = makeNoFetchClient();
    expect(() =>
      client.decisions.list({ systemId: LONE_LOW }),
    ).toThrowError(TypeError);
  });

  it("ACCEPTS a properly-paired surrogate / valid emoji (positive control)", async () => {
    // The guard must NOT false-positive on legitimate Unicode. A real
    // surrogate pair encoded as a single character is valid UTF-16
    // and must round-trip through encodeURIComponent without error.
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { items: [], nextCursor: null } },
      },
    ]);
    await expect(
      client.decisions.list({ framework: VALID_EMOJI }),
    ).resolves.toBeDefined();
  });
});

// ─── Hostile review #3 — MEDIUM-1 throwing-getter fix (decisions.list) ──────
//
// Session-22 hostile review #3 completes the SDK-wide MEDIUM-1 getter-
// throws contract fix. Reviews #1-#2 converted `decisions.ingest` /
// `.bulk` but MISSED the three `decisions` query methods (`.list` /
// `.stream` / `.export`) — their input-field validation still read each
// field with a bare `input.x` access, so a throwing accessor leaked the
// getter's raw exception instead of the documented synchronous
// `TypeError`. `decisions.list` now snapshots every query field via
// `readInputField`. These pins fail if that snapshot is ever reverted.

describe("decisions.list — hostile review #3: throwing-getter MEDIUM-1 fix", () => {
  it("converts a throwing `systemId` getter into a TypeError (NOT the getter's raw error)", () => {
    const { client, calls } = makeMockedClient([]);
    const evil = {
      get systemId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as DecisionsListInput;
    let caught: unknown;
    try {
      client.decisions.list(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).message).toContain("decisions.list");
    expect((caught as Error).message).toContain("systemId");
    // The getter's OWN message is not the SDK's contract message...
    expect((caught as Error).message).not.toContain("getter boom");
    // ...but the original error is preserved on `.cause`.
    expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(Error);
    expect(calls).toHaveLength(0);
  });

  it("converts a throwing getter on the LAST query field (`includeTombstoned`) into a TypeError", () => {
    // Proves the fix is not first-field-only — every one of the nine
    // snapshot reads is wrapped, not just `systemId`. A RangeError from
    // the getter still surfaces as the documented TypeError class.
    const { client, calls } = makeMockedClient([]);
    const evil = {
      get includeTombstoned(): unknown {
        throw new RangeError("range boom");
      },
    } as unknown as DecisionsListInput;
    let caught: unknown;
    try {
      client.decisions.list(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught).not.toBeInstanceOf(RangeError);
    expect((caught as Error).message).toContain("includeTombstoned");
    expect(calls).toHaveLength(0);
  });
});
