import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError } from "../../errors.js";
import type {
  RegulatoryChange,
  RegulatoryChangesListInput,
} from "../regulatory-changes.js";
import type { FetchLike } from "../../types.js";

// ─── regulatoryChanges.list — sync JSON list GET ──────────────────────────
//
// Wire shape (from src/app/api/v1/regulatory-changes/route.ts):
//   GET /api/v1/regulatory-changes?framework=…&severity=…&status=…
//                                  &from=…&to=…&limit=…
//   → { success: true, data: RegulatoryChange[] }
//
// Second non-decisions resource on the SDK; sibling to
// IncidentsResource / DecisionsResource / ChatResource / AuditLogResource.
// READ_SYSTEMS api-key auth — returns 401 for no/invalid key, 403 for an
// authenticated key that lacks READ_SYSTEMS. auditLog.export (ADMIN-only
// dual-auth) shares the same 401-vs-403 surface — the auth models differ,
// not the surface (corrected session-22 hostile review #2).
//
// Sync JSON list — reuses client._request and the existing
// {success:true, data} envelope-unwrap (carry-forward invariant #9). NO
// new SDK primitive needed.
//
// Two closed enums: severity (critical/high/medium/low) and status
// (new/reviewed/actioned/dismissed). SDK pre-rejects unknown values
// synchronously as TypeError (carry-forward invariant #41 — closed-enum
// SDK pre-rejection; build-round D5).
//
// Default-excludes-dismissed gotcha: when `status` is omitted, the
// kernel filters dismissed rows OUT (`WHERE status != 'dismissed'`).
// Explicit `status: "dismissed"` returns ONLY dismissed rows. The SDK
// pin asserts the URL matches the kernel's expectation: omitted-status
// sends NO `status=` param; explicit-status sends the param verbatim.

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

// A representative wire-shape row covering every documented field
// (20 total). Used as a sanity reference for happy-path + row-shape
// pins.
const MOCK_ROW: RegulatoryChange = {
  id: "11111111-1111-1111-1111-111111111111",
  framework: "EU_AI_ACT",
  title: "Article 13 amendment — transparency obligations",
  description: "Updated language clarifying provider disclosure scope.",
  changeType: "amendment",
  severity: "high",
  effectiveDate: "2026-08-01T00:00:00.000Z",
  affectedRequirements: ["Art.13", "Annex IV.1"],
  sourceUrl: "https://eur-lex.europa.eu/example",
  publishedAt: "2026-05-01T00:00:00.000Z",
  sourceId: "eur_lex",
  sourceReferenceId: "OJ/L/2026/123",
  ingestedAt: "2026-05-01T00:05:12.000Z",
  authorityPublisher: "European Commission",
  aiAnalysis: { summary: "Tightens scope.", relevance: 0.91 },
  notifiedAt: null,
  billStatus: "enacted",
  statusTransitions: [
    { status: "introduced", date: "2026-04-01", source: "eur-lex" },
    { status: "passed_one_chamber", date: "2026-04-20", source: "eur-lex" },
    { status: "enacted", date: "2026-05-01", source: "eur-lex" },
  ],
  status: "new",
  relevance: "high",
  createdAt: "2026-05-01T00:05:12.000Z",
};

const MOCK_ROW_2: RegulatoryChange = {
  ...MOCK_ROW,
  id: "22222222-2222-2222-2222-222222222222",
  title: "Article 13 clarification — small-provider exemption",
  changeType: "clarification",
  severity: "medium",
  publishedAt: "2026-04-15T00:00:00.000Z",
  status: "reviewed",
};

describe("regulatoryChanges.list — happy path", () => {
  it("GETs /api/v1/regulatory-changes with no query when no input given", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [MOCK_ROW] } },
    ]);
    const out = await client.regulatoryChanges.list();
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    // No `?` at all when every query value is undefined — the
    // transport's encodeQuery skips undefined values and returns "" for
    // an empty record, so the URL is the bare path.
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/regulatory-changes",
    );
    expect(calls[0].body).toBeUndefined();
    expect(out).toEqual([MOCK_ROW]);
  });

  it("`.list(undefined)` is equivalent to `.list()` — no query params", async () => {
    // The top-level shape guard skips when `input === undefined`; the
    // resource still issues a request with all-undefined query values,
    // which encodeQuery normalizes to no query string.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list(undefined);
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/regulatory-changes",
    );
  });

  it("resolves with empty array on empty result set (no 404)", async () => {
    // The kernel never returns 404; an empty filter set returns 200
    // with `data: []`. Pin: SDK resolves with `[]`, not throws.
    const { client } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    const out = await client.regulatoryChanges.list({ framework: "NONESUCH" });
    expect(out).toEqual([]);
  });

  it("returns the row shape unchanged (envelope unwrapped)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_ROW, MOCK_ROW_2] } },
    ]);
    const out = await client.regulatoryChanges.list();
    expect(out).toHaveLength(2);
    expect(out[0].id).toBe(MOCK_ROW.id);
    expect(out[1].id).toBe(MOCK_ROW_2.id);
  });

  it("forwards x-api-key + Accept (no Content-Type — GET, no body)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list();
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBeNull();
  });
});

describe("regulatoryChanges.list — input validation (pre-fetch)", () => {
  it("throws TypeError for null input — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list(
        null as unknown as RegulatoryChangesListInput,
      ),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input (typeof [] === 'object')", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list(
        [] as unknown as RegulatoryChangesListInput,
      ),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string / number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list(
        "all" as unknown as RegulatoryChangesListInput,
      ),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list(
        42 as unknown as RegulatoryChangesListInput,
      ),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty framework", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.regulatoryChanges.list({ framework: "" })).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string framework", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list({ framework: 42 as unknown as string }),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list({ framework: null as unknown as string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for framework with lone UTF-16 surrogates (URIError defense, carry-forward #32)", () => {
    // `encodeURIComponent("\uD800")` throws URIError — without the
    // `assertEncodableQueryString` guard, that URIError would leak into
    // the consumer instead of the named TypeError. Symmetric to
    // decisions.list / incidents.list / audit-log.export defenses.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list({ framework: "\uD800" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list({ framework: "valid\uDFFFlone" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for severity not in enum (closed-enum #41)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list({
        severity: "urgent" as unknown as "critical",
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list({
        severity: "" as unknown as "critical",
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string severity", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list({
        severity: 1 as unknown as "critical",
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list({
        severity: null as unknown as "critical",
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for status not in enum (closed-enum #41)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list({
        status: "reopened" as unknown as "new",
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list({ status: "" as unknown as "new" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string status", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list({ status: 0 as unknown as "new" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list({ status: null as unknown as "new" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty from / empty to", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.regulatoryChanges.list({ from: "" })).toThrowError(
      TypeError,
    );
    expect(() => client.regulatoryChanges.list({ to: "" })).toThrowError(
      TypeError,
    );
    expect(() =>
      client.regulatoryChanges.list({ from: 42 as unknown as string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for invalid limit (non-number / NaN / Infinity / <= 0 / fractional)", () => {
    const { client, calls } = makeMockedClient([]);
    // typeof check — string slips past Number coercion.
    expect(() =>
      client.regulatoryChanges.list({ limit: "50" as unknown as number }),
    ).toThrowError(TypeError);
    // NaN and Infinity are typeof "number" but Number.isInteger() === false.
    expect(() => client.regulatoryChanges.list({ limit: NaN })).toThrowError(
      TypeError,
    );
    expect(() =>
      client.regulatoryChanges.list({ limit: Infinity }),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list({ limit: -Infinity }),
    ).toThrowError(TypeError);
    // Zero and negatives.
    expect(() => client.regulatoryChanges.list({ limit: 0 })).toThrowError(
      TypeError,
    );
    expect(() => client.regulatoryChanges.list({ limit: -10 })).toThrowError(
      TypeError,
    );
    // Fractional.
    expect(() => client.regulatoryChanges.list({ limit: 5.5 })).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });
});

describe("regulatoryChanges.list — query encoding", () => {
  it("encodes every documented filter on the URL when provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({
      framework: "EU_AI_ACT",
      severity: "critical",
      status: "new",
      from: "2026-04-01T00:00:00Z",
      to: "2026-05-01T00:00:00Z",
      limit: 100,
    });
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/regulatory-changes");
    expect(url.searchParams.get("framework")).toBe("EU_AI_ACT");
    expect(url.searchParams.get("severity")).toBe("critical");
    expect(url.searchParams.get("status")).toBe("new");
    expect(url.searchParams.get("from")).toBe("2026-04-01T00:00:00Z");
    expect(url.searchParams.get("to")).toBe("2026-05-01T00:00:00Z");
    expect(url.searchParams.get("limit")).toBe("100");
  });

  it("URL-encodes filter values containing special characters", async () => {
    // A framework string like "evil&injection" must be percent-encoded
    // so it doesn't break the query string parser server-side. encodeURIComponent
    // replaces `&`, `=`, `?`, `/`, `#` with %26, %3D, %3F, %2F, %23.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({ framework: "evil&injection?q=x" });
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/regulatory-changes?framework=evil%26injection%3Fq%3Dx",
    );
  });

  it("does NOT pre-validate from/to format — server validates date strings (D6)", async () => {
    // SDK-side: type-check only (string non-empty). Format check is
    // deferred to the kernel's `new Date(...)` parser, which is lenient
    // and accepts non-ISO formats. Pin: a malformed `from` still goes
    // through to the server, which returns 400.
    const { client, calls } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Invalid 'from' date format" },
      },
    ]);
    try {
      await client.regulatoryChanges.list({ from: "not-a-date" });
    } catch {
      /* ignore — verifying the request was issued */
    }
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0].url).searchParams.get("from")).toBe("not-a-date");
  });

  it("does NOT pre-cap limit at 200 — server returns 400 for out-of-range (D4)", async () => {
    // Kernel's MAX_LIMIT is 200; > 200 returns 400 with
    // "Invalid limit. Must be between 1 and 200." Pin: SDK forwards
    // the value verbatim (NOT silently clamps); kernel's authority.
    const { client, calls } = makeMockedClient([
      {
        status: 400,
        body: {
          success: false,
          error: "Invalid limit. Must be between 1 and 200.",
        },
      },
    ]);
    try {
      await client.regulatoryChanges.list({ limit: 500 });
    } catch {
      /* ignore — verifying the request was issued */
    }
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0].url).searchParams.get("limit")).toBe("500");
  });

  it("does not mutate the input object (read-only)", async () => {
    // Defensive: a caller passing a frozen object must not see the SDK
    // crash. The resource reads `input?.framework` etc. without
    // assignment.
    const { client } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    const input: RegulatoryChangesListInput = Object.freeze({
      framework: "EU_AI_ACT",
      severity: "high",
      limit: 50,
    });
    const snapshot = JSON.stringify(input);
    await client.regulatoryChanges.list(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});

describe("regulatoryChanges.list — default-excludes-dismissed semantics (D7)", () => {
  it("omitted status sends NO `status=` param on the URL (kernel default applies)", async () => {
    // Build-round D7: the kernel filters dismissed rows OUT when
    // `status` is omitted. The URL must contain NO `status=` param —
    // NOT `status=undefined` — so the kernel's default branch fires.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({ framework: "EU_AI_ACT" });
    const url = new URL(calls[0].url);
    expect(url.searchParams.has("status")).toBe(false);
    expect([...url.searchParams.keys()]).toEqual(["framework"]);
  });

  it("explicit status=`dismissed` sends `status=dismissed` on the URL", async () => {
    // The ONLY way to retrieve dismissed rows is to pass
    // `status: "dismissed"` explicitly. Pin: the URL contains it.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({ status: "dismissed" });
    expect(new URL(calls[0].url).searchParams.get("status")).toBe("dismissed");
  });

  it("each non-dismissed status value forwards verbatim (`new` / `reviewed` / `actioned`)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
      { body: { success: true, data: [] } },
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({ status: "new" });
    await client.regulatoryChanges.list({ status: "reviewed" });
    await client.regulatoryChanges.list({ status: "actioned" });
    expect(new URL(calls[0].url).searchParams.get("status")).toBe("new");
    expect(new URL(calls[1].url).searchParams.get("status")).toBe("reviewed");
    expect(new URL(calls[2].url).searchParams.get("status")).toBe("actioned");
  });
});

describe("regulatoryChanges.list — error paths", () => {
  it("surfaces a 400 (invalid date format from kernel) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Invalid 'from' date format" },
      },
    ]);
    try {
      await client.regulatoryChanges.list({ from: "garbage" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.message).toMatch(/from.*date format/);
    }
  });

  it("surfaces a 401 (no/invalid API key) as AttestryAPIError", async () => {
    // READ_SYSTEMS auth: 401 is the no/invalid-key branch
    // (`requireApiKey`). Distinct from 403 below.
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required" },
      },
    ]);
    try {
      await client.regulatoryChanges.list();
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 403 (insufficient permission — distinct from 401) as AttestryAPIError", async () => {
    // READ_SYSTEMS auth: 403 is the "authenticated but lacks permission"
    // branch (`requireApiKeyWithPermission`). `auditLog.export`
    // (ADMIN-only dual-auth) shares the SAME 401-vs-403 split — the
    // auth models differ, the status surface does not (corrected
    // session-22 hostile review #2; carry-forward invariant #42's
    // "401 for both" framing was wrong).
    // Consumers must distinguish 401 (re-auth) from 403 (need different
    // key) at the call site.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: { success: false, error: "Insufficient permissions" },
      },
    ]);
    try {
      await client.regulatoryChanges.list();
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
    }
  });

  it("surfaces a 429 (rate limit) as AttestryAPIError when retry is disabled", async () => {
    // makeMockedClient sets retry: {maxRetries: 0} — so the 429
    // surfaces immediately rather than auto-retrying. With retry
    // enabled (the default), invariant #18 covers the auto-retry
    // path; pinned in retry.test.ts.
    const { client } = makeMockedClient([
      {
        status: 429,
        body: { success: false, error: "Too many requests" },
      },
    ]);
    try {
      await client.regulatoryChanges.list();
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });

  it("surfaces a 500 (internal kernel error, scrubbed message) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 500,
        body: { success: false, error: "Internal server error" },
      },
    ]);
    try {
      await client.regulatoryChanges.list();
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(500);
    }
  });

  it("P3: wrong content-type (text/plain) throws AttestryAPIError from transport (was soft-fail pre-P3)", async () => {
    // **P3 hardening surface** (history: G6 documented the OLD
    // soft-fail; P2 hardened the unparseable-body case at the
    // resource layer; P3 hardens BOTH cases at the transport layer
    // — text/plain with parseable JSON is now rejected BEFORE the
    // body is even parsed).
    //
    // After P3, the transport's sync content-type guard fires on
    // any 2xx response whose Content-Type MIME prefix isn't
    // `application/json` (parameter-tolerant for `; charset=utf-8`).
    // Throws `AttestryAPIError` with the response status (typically
    // 200) and a message naming the expected and actual content-type.
    //
    // This is a behavior change from pre-P3 — consumers relying on
    // the old soft-fail would silently receive different surfaces.
    // The P3 cluster bump (0.4.1 → 0.5.0) signals the change.
    const callsLocal: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      callsLocal.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      return new Response(
        JSON.stringify({ success: true, data: [MOCK_ROW] }),
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
      await client.regulatoryChanges.list();
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

  it("P2: throws AttestryError when kernel response is not an array (e.g., scalar)", async () => {
    // P2 hardening: the kernel route emits `successResponse(changes)`
    // where `changes` always comes from Drizzle's `db.select()...
    // limit(N)` — always an array. A future kernel-side regression
    // that emits a scalar (e.g., `successResponse("error")`) would
    // surface as `string` cast as `RegulatoryChange[]` to the consumer
    // — `out.length` returns 5 (string length), `out[0]` returns
    // first character, totally wrong. The resource-layer `Array.isArray`
    // validator catches this and throws with a clear message.
    const { client } = makeMockedClient([
      { body: { success: true, data: "scalar-instead-of-array" } },
    ]);
    await expect(client.regulatoryChanges.list()).rejects.toThrow(
      /expected an array response from the kernel \(got string\)/,
    );
  });

  it("P2: throws AttestryError when kernel response is an object (not array)", async () => {
    // Defensive: a kernel-side mistake that emits
    // `successResponse({rows: [...]})` instead of `successResponse([...])`
    // would slip through TypeScript-typed access. Validator catches.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { rows: [MOCK_ROW], total: 1 },
        },
      },
    ]);
    await expect(client.regulatoryChanges.list()).rejects.toThrow(
      /expected an array response from the kernel \(got object\)/,
    );
  });

  it("P2 forward-compat: extra unknown TOP-LEVEL fields would be N/A (bare-array response has no envelope siblings)", async () => {
    // The kernel returns `successResponse(changes)` which the
    // transport unwraps to the bare array — there are no sibling
    // fields for the kernel to add at the top level. This pin
    // documents that asymmetry vs decisions.list / incidents.list
    // (which return wrapper objects whose top-level fields ARE
    // forward-compatible with future additions). For
    // regulatoryChanges, forward-compat lives at the row level
    // (extras within each row are passed through, pinned in the
    // build round's "passes through extra unknown fields verbatim"
    // pin).
    //
    // This pin asserts the array-itself happy path round-trips an
    // extras-bearing row, paralleling the docstring contract.
    const rowWithExtra = {
      ...MOCK_ROW,
      futureRowField: "kernel added this without an SDK bump",
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: [rowWithExtra] } },
    ]);
    const out = await client.regulatoryChanges.list();
    expect(Array.isArray(out)).toBe(true);
    expect(
      (out[0] as unknown as Record<string, unknown>).futureRowField,
    ).toBe("kernel added this without an SDK bump");
  });

  it("P2: throws AttestryError when kernel response is null (deliberate null vs unparseable-body — same outcome)", async () => {
    // Symmetric with the wrong-content-type pin above. Whether the
    // kernel deliberately emits `data: null` (kernel bug) or the
    // transport's readBody returns null (unparseable body), the
    // resource-layer validator surfaces the same clear AttestryError.
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(client.regulatoryChanges.list()).rejects.toThrow(
      /expected an array response from the kernel \(got null\)/,
    );
  });

  it("P3: wrong content-type (text/html) throws AttestryAPIError from transport (covers parseable AND unparseable bodies)", async () => {
    // **P3 hardening surface** (history: G6 documented the OLD soft-
    // fail; P2 inverted to AttestryError-from-resource for the
    // unparseable-body case; P3 supersedes both with AttestryAPIError-
    // from-transport for ALL wrong-content-type cases).
    //
    // The transport's sync content-type guard fires BEFORE readBody,
    // so neither parseable JSON in wrong-content-type nor unparseable
    // HTML reaches the resource layer. AttestryAPIError carries the
    // response status (200 here — the worst case where a proxy / LB
    // returns 200 OK with an HTML error page).
    const callsLocal: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      callsLocal.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      return new Response(
        "<html><body>502 Bad Gateway</body></html>",
        {
          status: 200,
          headers: { "Content-Type": "text/html" },
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
      await client.regulatoryChanges.list();
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(200);
      expect(apiErr.message).toMatch(/expected application\/json/);
      expect(apiErr.message).toMatch(/got "text\/html"/);
    }
    expect(callsLocal).toHaveLength(1);
  });
});

describe("regulatoryChanges.list — row shape preservation", () => {
  it("preserves all 20 documented fields on a happy-path row", async () => {
    // Sanity check: every field in the documented `RegulatoryChange`
    // interface round-trips. Drift on this test = kernel-side schema
    // change OR SDK interface drift; cross-check sdk-drift.test.ts.
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_ROW] } },
    ]);
    const out = await client.regulatoryChanges.list();
    expect(out[0]).toEqual(MOCK_ROW);
    // Spot-check field count via Object.keys to catch silent
    // drops/renames.
    expect(Object.keys(out[0]).sort()).toEqual(
      [
        "id",
        "framework",
        "title",
        "description",
        "changeType",
        "severity",
        "effectiveDate",
        "affectedRequirements",
        "sourceUrl",
        "publishedAt",
        "sourceId",
        "sourceReferenceId",
        "ingestedAt",
        "authorityPublisher",
        "aiAnalysis",
        "notifiedAt",
        "billStatus",
        "statusTransitions",
        "status",
        "relevance",
        "createdAt",
      ].sort(),
    );
  });

  it("preserves jsonb fields verbatim (affectedRequirements / aiAnalysis / statusTransitions)", async () => {
    // jsonb fields are typed as `unknown` (D3); the SDK must NOT
    // re-shape or strip them. A row with array `affectedRequirements`,
    // object `aiAnalysis`, and array-of-objects `statusTransitions`
    // round-trips intact.
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_ROW] } },
    ]);
    const out = await client.regulatoryChanges.list();
    expect(out[0].affectedRequirements).toEqual(["Art.13", "Annex IV.1"]);
    expect(out[0].aiAnalysis).toEqual({ summary: "Tightens scope.", relevance: 0.91 });
    expect(out[0].statusTransitions).toEqual([
      { status: "introduced", date: "2026-04-01", source: "eur-lex" },
      { status: "passed_one_chamber", date: "2026-04-20", source: "eur-lex" },
      { status: "enacted", date: "2026-05-01", source: "eur-lex" },
    ]);
  });

  it("preserves null nullable timestamp fields (effectiveDate / publishedAt / ingestedAt / notifiedAt)", async () => {
    // Drizzle returns `null` for nullable timestamp columns, NOT
    // `undefined` or empty string. JSON.stringify preserves null. Pin:
    // a row with all nullable timestamps as null arrives intact.
    const sparse: RegulatoryChange = {
      ...MOCK_ROW,
      effectiveDate: null,
      publishedAt: null,
      ingestedAt: null,
      notifiedAt: null,
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: [sparse] } },
    ]);
    const out = await client.regulatoryChanges.list();
    expect(out[0].effectiveDate).toBeNull();
    expect(out[0].publishedAt).toBeNull();
    expect(out[0].ingestedAt).toBeNull();
    expect(out[0].notifiedAt).toBeNull();
  });

  it("passes through extra unknown fields verbatim (forward-compat)", async () => {
    // If the kernel adds a new column before the SDK is bumped, the
    // extra field must round-trip — faithful courier. Pin: an unknown
    // field arrives at the consumer (typed as `unknown` at the call
    // site, but present at runtime).
    const withExtra = {
      ...MOCK_ROW,
      futureField: "added kernel-side without an SDK bump",
      futureNestedField: { nested: 42 },
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: [withExtra] } },
    ]);
    const out = await client.regulatoryChanges.list();
    expect((out[0] as unknown as Record<string, unknown>).futureField).toBe(
      "added kernel-side without an SDK bump",
    );
    expect(
      (out[0] as unknown as Record<string, unknown>).futureNestedField,
    ).toEqual({ nested: 42 });
  });

  it("preserves DESC order from the kernel response", async () => {
    // Kernel sorts DESC by `publishedAt`. The SDK does NOT re-sort —
    // it forwards the array verbatim. Pin: items arrive in the same
    // order as the kernel emits them.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          // MOCK_ROW publishedAt 2026-05-01 > MOCK_ROW_2 2026-04-15.
          data: [MOCK_ROW, MOCK_ROW_2],
        },
      },
    ]);
    const out = await client.regulatoryChanges.list();
    expect(out[0].publishedAt).toBe("2026-05-01T00:00:00.000Z");
    expect(out[1].publishedAt).toBe("2026-04-15T00:00:00.000Z");
  });
});

describe("regulatoryChanges.list — abort + retry semantics", () => {
  it("forwards a pre-aborted AbortSignal through RequestOptions (no fetch)", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.regulatoryChanges.list({}, { signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally (coverage)", async () => {
    // Symmetric to decisions.list / decisions.retrieve coverage pin —
    // exercises the "signal exists but never fires" branch in the
    // transport's signal forwarding. Without this, a refactor that
    // accidentally aborted on signal presence would silently break
    // every caller that constructs an AbortController defensively.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    const controller = new AbortController();
    const out = await client.regulatoryChanges.list(
      {},
      { signal: controller.signal },
    );
    expect(out).toEqual([]);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies (independent of resource-helper default)", async () => {
    // The makeMockedClient helper sets retry: {maxRetries: 0} by
    // default. Per-call override should re-enable retry for this
    // single call. Pin against the retry middleware's per-call
    // precedence (matches decisions.list pattern).
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "x" } },
      { body: { success: true, data: [MOCK_ROW] } },
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
    const promise = client.regulatoryChanges.list(
      {},
      { retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 } },
    );
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out).toHaveLength(1);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });
});

describe("regulatoryChanges.list — hostile round residual gaps", () => {
  it("H1: concurrent list() calls share no state — each promise resolves independently", async () => {
    // Build round covered "concurrent calls" only transitively via
    // decisions.list. Pin it explicitly here: two parallel calls
    // against the same client must NOT share request/response state
    // (which a future refactor adding memoization or response caching
    // would break). Each call constructs its own promise; the mocked
    // fetch routes them to distinct mock responses by call order.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [MOCK_ROW] } },
      { body: { success: true, data: [MOCK_ROW_2] } },
    ]);
    const [out1, out2] = await Promise.all([
      client.regulatoryChanges.list({ framework: "EU_AI_ACT" }),
      client.regulatoryChanges.list({ framework: "COLORADO_AI_ACT" }),
    ]);
    expect(calls).toHaveLength(2);
    expect(out1).toEqual([MOCK_ROW]);
    expect(out2).toEqual([MOCK_ROW_2]);
    // Each call landed on its own URL — no cross-pollination.
    const url1 = new URL(calls[0].url);
    const url2 = new URL(calls[1].url);
    expect(url1.searchParams.get("framework")).toBe("EU_AI_ACT");
    expect(url2.searchParams.get("framework")).toBe("COLORADO_AI_ACT");
  });

  it("H2: caller-provided input object is NOT mutated by the SDK (snapshot identity)", async () => {
    // Build round confirmed a frozen object doesn't crash the SDK.
    // Hostile round adds the explicit no-mutation contract — a future
    // refactor that "normalizes" the input (e.g., trims framework, or
    // sets a default limit) would surface here. Pin: the input object
    // and its enumerable properties are byte-for-byte identical
    // before and after the call.
    const { client } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    const input: RegulatoryChangesListInput = {
      framework: "EU_AI_ACT",
      severity: "high",
      status: "new",
      from: "2026-04-01T00:00:00Z",
      to: "2026-05-01T00:00:00Z",
      limit: 50,
    };
    const before = { ...input };
    await client.regulatoryChanges.list(input);
    expect(input).toEqual(before);
    expect(Object.keys(input).sort()).toEqual(
      ["framework", "severity", "status", "from", "to", "limit"].sort(),
    );
  });

  it("H3: URL has NO bare `?` when every query param is undefined (clean URL)", async () => {
    // Defensive: a refactor that switches encodeQuery to always emit
    // `?` (e.g., for a future signed-request feature) would produce
    // `/api/v1/regulatory-changes?` — semantically the same as no
    // query, but a sloppier wire. Pin the clean URL form explicitly.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list();
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/regulatory-changes",
    );
    // Also assert no trailing `?` defensively — toBe above covers it,
    // but an explicit check guards against a regex-based URL builder.
    expect(calls[0].url.endsWith("?")).toBe(false);
  });

  it("H4: explicit `status: undefined` is equivalent to omission (URL omits the param)", async () => {
    // Corner case: a caller writing `list({ status: undefined })`
    // (instead of `list({})` or `list()`) should produce the same URL
    // as omission. The SDK's `if (input.status !== undefined)` guard
    // skips the validator; encodeQuery's undefined skip omits the
    // param. Pin: kernel default-excludes-dismissed branch fires for
    // both styles. (TS forbids `null` here via the literal-union, but
    // explicit `undefined` is a real-world corner case from spread
    // operators / partial defaults.)
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({ status: undefined });
    const url = new URL(calls[0].url);
    expect(url.searchParams.has("status")).toBe(false);
    // No query string at all — same as the bare `.list()` call in H3.
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/regulatory-changes",
    );
  });

  it("H5: limit at exact boundaries (1 and 200) accepted and forwarded verbatim", async () => {
    // Build-round "invalid limit" pin covers the rejection cases. Pin
    // the ACCEPT cases at the boundaries: 1 (kernel's MIN) and 200
    // (kernel's MAX_LIMIT) both pass SDK validation and arrive at the
    // server as plain integers (no scientific notation, no decimal).
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({ limit: 1 });
    await client.regulatoryChanges.list({ limit: 200 });
    expect(new URL(calls[0].url).searchParams.get("limit")).toBe("1");
    expect(new URL(calls[1].url).searchParams.get("limit")).toBe("200");
  });

  it("H6: 429 auto-retries when retry is enabled (default) and succeeds on second attempt", async () => {
    // Build round only pinned the retry-disabled path (where 429
    // surfaces immediately). Hostile round adds the retry-enabled
    // path — invariant #18: SDK auto-retries on 429 with exponential
    // backoff. Pin against the retry middleware integration: a 429 →
    // 200 sequence resolves with the 200 body when retry is on.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "rate limited" } },
      { body: { success: true, data: [MOCK_ROW] } },
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
    // Default-retry client (NO override). The default config retries
    // up to 3 times.
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { initialDelayMs: 1, maxDelayMs: 10 }, // tight backoff for test
    });
    const promise = client.regulatoryChanges.list();
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out).toEqual([MOCK_ROW]);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });

  it("H7: parallel concurrent calls with different filters don't cross-pollinate URLs", async () => {
    // Symmetric to H1 with a stronger contract: even when issued in
    // tight succession, each call's filters land on its own URL. A
    // future refactor that batches requests or shares a query-builder
    // closure would surface here.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
      { body: { success: true, data: [] } },
      { body: { success: true, data: [] } },
    ]);
    await Promise.all([
      client.regulatoryChanges.list({ severity: "critical" }),
      client.regulatoryChanges.list({ severity: "low" }),
      client.regulatoryChanges.list({ status: "actioned" }),
    ]);
    expect(calls).toHaveLength(3);
    expect(new URL(calls[0].url).searchParams.get("severity")).toBe("critical");
    expect(new URL(calls[0].url).searchParams.has("status")).toBe(false);
    expect(new URL(calls[1].url).searchParams.get("severity")).toBe("low");
    expect(new URL(calls[1].url).searchParams.has("status")).toBe(false);
    expect(new URL(calls[2].url).searchParams.has("severity")).toBe(false);
    expect(new URL(calls[2].url).searchParams.get("status")).toBe("actioned");
  });

  it("H8: extra unknown fields on input are silently dropped (forward-compat)", async () => {
    // TS forbids extra fields via the type, but runtime cast as `any`
    // would let them slip through. SDK reads only the documented
    // fields; extras must NOT appear on the URL. Forward-compat for
    // a future kernel filter (e.g., `?relevance=high`) added before
    // the SDK is bumped — TS-typed callers can't pass it, but a
    // hand-rolled untyped caller (tests, CLIs) might. Pin: the URL
    // has only documented filters.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({
      framework: "EU_AI_ACT",
      // Future field added kernel-side that doesn't exist in this
      // SDK version — a typed caller would fail to compile, but a
      // runtime-typed caller could pass it.
      relevance: "high",
      futureField: "added kernel-side",
    } as unknown as RegulatoryChangesListInput);
    const url = new URL(calls[0].url);
    expect([...url.searchParams.keys()]).toEqual(["framework"]);
    expect(url.searchParams.has("relevance")).toBe(false);
    expect(url.searchParams.has("futureField")).toBe(false);
  });

  it("H9: lone-surrogate guard applies to `from` AND `to` (URIError defense extends to date fields)", async () => {
    // Build round only pinned lone-surrogate on `framework`. Hostile
    // round extends the URIError-defense pin to the date fields —
    // the same defect class affects every string field that flows
    // into encodeQuery → encodeURIComponent. Without the per-field
    // guard, a `from: "\uD800"` would surface as a raw URIError from
    // the transport instead of the named TypeError from the resource.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.regulatoryChanges.list({ from: "\uD800" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.regulatoryChanges.list({ to: "valid\uDFFFlone" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("H10: whitespace-only framework string is forwarded URL-encoded (SDK does NOT trim)", async () => {
    // Faithful courier: SDK forwards the input verbatim. A
    // whitespace-only framework ("   ") has length 3 — passes the
    // non-empty check. SDK does NOT trim; the kernel's filter
    // (`WHERE framework = '   '`) just won't match anything. Pin:
    // URL contains the encoded whitespace. A future "be helpful"
    // refactor adding a `.trim()` would surface here.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    await client.regulatoryChanges.list({ framework: "   " });
    expect(new URL(calls[0].url).searchParams.get("framework")).toBe("   ");
    // The raw URL contains the percent-encoded whitespace (`%20`).
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/regulatory-changes?framework=%20%20%20",
    );
  });
});
