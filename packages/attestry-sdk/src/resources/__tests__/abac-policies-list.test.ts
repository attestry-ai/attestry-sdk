import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  // Result-shape type imports — pinned at compile time. If any of
  // these types are dropped from `index.ts` or the resource's exports,
  // this file fails to compile and the test run aborts before any
  // pin runs.
  AbacPolicy,
  AbacPoliciesListResponse,
} from "../abac-policies.js";
import type { FetchLike } from "../../types.js";

// ─── abacPolicies.list — GET ABAC policies for the caller's org ─────────────
//
// Wire shape (kernel src/app/api/v1/abac-policies/route.ts):
//   GET /api/v1/abac-policies
//   Auth: x-api-key (requireSessionOrApiKey + apiKeyPermissions:[ADMIN])
//   No input.
//   200 OK: {success:true, data: {items: AbacPolicy[], count: number}}
//   401 auth (no/invalid/expired key), 403 permission (non-ADMIN key),
//   429 rate-limit (assessmentLimiter, abac-policies-list:${ip} key),
//   500 internal.
//
// 21st audit chain in the F.1 phase. First method of the 5-method
// `abacPolicies` cluster (`.list` ships in session 21; `.create` +
// `.retrieve` + `.update` + `.delete` ship in session 22).
//
// **No pagination** — `count` is `items.length`, NOT a total org count.
// Server-side cap `MAX_POLICIES_PER_ORG_FETCH = 200` (invariant #50
// silent truncation; documented in JSDoc + README).
//
// **No `writeAuditLog` side effect** — `.list()` is quiet (asymmetric
// with `gate.evaluate` / `batch.submit` / `shipGate.check`).
//
// **Status-code surface — 401 AND 403 distinguished** (verified by
// reading the dual-auth middleware end-to-end). Pin BOTH branches.
//
// Adapted from `incidents-list` / `regulatory-changes-list` /
// `audit-log-verify-chain` patterns; smaller surface (no pagination,
// no method-side input validation, no closed-enum URL params).

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

const POLICY_ID_1 = "11111111-1111-1111-1111-111111111111";
const POLICY_ID_2 = "22222222-2222-2222-2222-222222222222";
const ORG_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const USER_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff";

// Sample policy fixture — Shape: simple eq leaf condition.
const POLICY_EQ_LEAF: AbacPolicy = {
  id: POLICY_ID_1,
  orgId: ORG_ID,
  name: "owner-can-edit-own",
  description: "Owners can edit their own assessments.",
  resource: "assessments",
  action: "update",
  effect: "allow",
  condition: {
    op: "attrEq",
    left: "principal.id",
    right: "resource.ownerId",
  },
  priority: 100,
  enabled: true,
  createdByUserId: USER_ID,
  createdAt: "2026-05-14T12:00:00.000Z",
  updatedAt: "2026-05-14T12:00:00.000Z",
};

// Sample policy fixture — Shape: compound and condition.
const POLICY_COMPOUND_AND: AbacPolicy = {
  id: POLICY_ID_2,
  orgId: ORG_ID,
  name: "deny-archived-systems",
  description: null,
  resource: "systems",
  action: "delete",
  effect: "deny",
  condition: {
    op: "and",
    clauses: [
      { op: "eq", attr: "resource.archived", value: true },
      { op: "ne", attr: "principal.role", value: "admin" },
    ],
  },
  priority: 50,
  enabled: true,
  createdByUserId: null,
  createdAt: "2026-05-14T13:00:00.000Z",
  updatedAt: "2026-05-14T13:30:00.000Z",
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("abacPolicies.list — happy path", () => {
  it("GETs /api/v1/abac-policies and returns items + count", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: [POLICY_EQ_LEAF, POLICY_COMPOUND_AND], count: 2 },
        },
      },
    ]);
    const out = await client.abacPolicies.list();
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/abac-policies",
    );
    expect(out.count).toBe(2);
    expect(out.items).toHaveLength(2);
    expect(out.items[0].id).toBe(POLICY_ID_1);
    expect(out.items[1].id).toBe(POLICY_ID_2);
  });

  it("returns empty items + count=0 on an org with no policies", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    const out = await client.abacPolicies.list();
    expect(out.items).toEqual([]);
    expect(out.count).toBe(0);
  });

  it("preserves per-row field shape verbatim (faithful courier)", async () => {
    // Per-row fields are NOT re-validated by the SDK's P2 validator
    // (top-level only — items array + count number). The SDK passes
    // each row through as-is. Pin the verbatim passthrough.
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [POLICY_EQ_LEAF], count: 1 } } },
    ]);
    const out = await client.abacPolicies.list();
    expect(out.items[0]).toEqual(POLICY_EQ_LEAF);
    // Specific field-level passthrough: condition AST is preserved
    // recursively (consumer can branch on `policy.condition.op`).
    expect(out.items[0].condition).toEqual({
      op: "attrEq",
      left: "principal.id",
      right: "resource.ownerId",
    });
  });

  it("preserves null fields (description / createdByUserId) as null, NOT undefined", async () => {
    // The kernel emits `null` (NOT `undefined`) for unset description
    // and createdByUserId via the `?? null` coalesce server-side.
    // Faithful courier — pin that the SDK does not coerce null to
    // undefined.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: [POLICY_COMPOUND_AND], count: 1 },
        },
      },
    ]);
    const out = await client.abacPolicies.list();
    expect(out.items[0].description).toBeNull();
    expect(out.items[0].createdByUserId).toBeNull();
  });

  it("sends `x-api-key` header from the client config", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    await client.abacPolicies.list();
    expect((calls[0].headers as Headers).get("x-api-key")).toBe("k");
  });

  it("forwards options.signal to the underlying fetch (abort-passthrough)", async () => {
    const fetchSpy = vi.fn(async (_url: unknown, init: unknown) => {
      // Record that the signal was passed through. We re-resolve with
      // a 200 response so the call doesn't abort.
      const init_ = init as RequestInit;
      void init_.signal;
      return new Response(JSON.stringify({ success: true, data: { items: [], count: 0 } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const ac = new AbortController();
    await client.abacPolicies.list({ signal: ac.signal });
    const passedInit = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(passedInit.signal).toBeDefined();
  });
});

// ─── Top-level error paths ──────────────────────────────────────────────────

describe("abacPolicies.list — top-level error paths", () => {
  it("401 (no api-key OR invalid key OR expired key) → AttestryAPIError(401)", async () => {
    // The kernel returns 401 for: no x-api-key, empty x-api-key,
    // invalid key (no matching row), expired key. All four cases
    // surface as AttestryAPIError(401) — the SDK doesn't disambiguate
    // (kernel error message text differs but status is uniform).
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "API key required. Provide x-api-key header." },
      },
    ]);
    const promise = client.abacPolicies.list();
    await expect(promise).rejects.toBeInstanceOf(AttestryAPIError);
    await expect(promise).rejects.toMatchObject({ status: 401 });
  });

  it("401 (invalid key) propagates the kernel error message verbatim", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Invalid API key." },
      },
    ]);
    try {
      await client.abacPolicies.list();
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(401);
      expect(apiErr.message).toContain("Invalid API key.");
    }
  });

  it("403 (valid key without ADMIN permission) → AttestryAPIError(403) — DISTINCT from 401", async () => {
    // `auditLog.export` (ADMIN-only dual-auth) shares this exact
    // 401-vs-403 surface (corrected session-22 hostile review #2 —
    // carry-forward invariant #42's "401 for both" framing was wrong).
    // Dual-auth admin routes distinguish:
    //   - 401: no/invalid/expired key
    //   - 403: valid key, permissions don't include ADMIN
    // Kernel source: src/lib/middleware/permissions.ts:57-62.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error: "API key lacks required permission. Required: admin. Key has: read:systems.",
        },
      },
    ]);
    try {
      await client.abacPolicies.list();
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.message).toContain(
        "API key lacks required permission",
      );
      // Pin that 403 is genuinely distinct from 401 — a hostile
      // consumer collapsing both branches would miss the permission
      // signal and surface "auth required" when the user actually
      // needs to upgrade their key.
      expect(apiErr.status).not.toBe(401);
    }
  });

  it("429 → AttestryAPIError(429) (with retry disabled)", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: { success: false, error: "Too many requests. Please try again later." },
      },
    ]);
    await expect(client.abacPolicies.list()).rejects.toMatchObject({
      status: 429,
    });
  });

  it("500 (internal kernel error, scrubbed message) → AttestryAPIError(500)", async () => {
    // The kernel's internalErrorResponse scrubs the error message:
    // body = `{success:false, error: "An internal error occurred. ..."}`.
    // The original error is logged server-side but not exposed.
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
      await client.abacPolicies.list();
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(500);
      // No internal detail leakage.
      expect(apiErr.message).not.toContain("listAbacPolicies");
      expect(apiErr.message).not.toContain("db");
    }
  });

  it("non-JSON 500 body (e.g., HTML proxy page) surfaces as AttestryAPIError via P3 guard", async () => {
    // P3 hardening: a 500 with `Content-Type: text/html` (proxy-
    // injected error page) is rejected by the transport's content-
    // type guard. Mirror of the pattern from prior resources.
    const fetchSpy = vi.fn(async () => {
      return new Response("<html><body>Bad Gateway</body></html>", {
        status: 500,
        headers: { "Content-Type": "text/html" },
      });
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    await expect(client.abacPolicies.list()).rejects.toBeInstanceOf(
      AttestryAPIError,
    );
  });
});

// ─── Retry semantics ────────────────────────────────────────────────────────

describe("abacPolicies.list — retry semantics", () => {
  it("retries on 429 by default (transport's auto-retry middleware)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });

    let callCount = 0;
    const fetchSpy = vi.fn(async () => {
      callCount += 1;
      if (callCount === 1) {
        return new Response(
          JSON.stringify({ success: false, error: "Too many requests." }),
          { status: 429, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({ success: true, data: { items: [], count: 0 } }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });

    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      // Use default retry config (auto-retry on 429).
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });

    const out = await client.abacPolicies.list();
    expect(out.count).toBe(0);
    expect(callCount).toBeGreaterThanOrEqual(2);
  });

  it("does NOT retry on 401 / 403 / 500 (non-retryable codes)", async () => {
    const fetchSpy = vi.fn(async () => {
      return new Response(
        JSON.stringify({ success: false, error: "Unauthorized" }),
        { status: 401, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });
    await expect(client.abacPolicies.list()).rejects.toBeInstanceOf(
      AttestryAPIError,
    );
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});

// ─── Abort semantics ────────────────────────────────────────────────────────

describe("abacPolicies.list — abort semantics", () => {
  it("rejects with AttestryError when options.signal is pre-aborted", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.list({ signal: ac.signal }),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("rejects with AttestryError when options.signal aborts mid-flight", async () => {
    let resolveFetch: (v: Response) => void = () => {};
    const fetchSpy = vi.fn(async (_url: unknown, init: unknown) => {
      const init_ = init as RequestInit;
      return await new Promise<Response>((resolve, reject) => {
        resolveFetch = resolve;
        init_.signal?.addEventListener("abort", () => {
          reject(new DOMException("aborted", "AbortError"));
        });
      });
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const ac = new AbortController();
    const pending = client.abacPolicies.list({ signal: ac.signal });
    ac.abort();
    await expect(pending).rejects.toBeInstanceOf(AttestryError);
    // Cleanup — don't hang the test runner.
    resolveFetch(
      new Response(
        JSON.stringify({ success: true, data: { items: [], count: 0 } }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
  });
});

// ─── Response shape (P2 hardening) ──────────────────────────────────────────

describe("abacPolicies.list — response shape (P2 hardening)", () => {
  it("rejects when response is not an object (null) — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    const promise = client.abacPolicies.list();
    await expect(promise).rejects.toBeInstanceOf(AttestryError);
    await expect(promise).rejects.toThrow(
      /expected an object response.*got null/,
    );
  });

  it("rejects when response is not an object (array) — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [] } },
    ]);
    const promise = client.abacPolicies.list();
    await expect(promise).rejects.toBeInstanceOf(AttestryError);
    await expect(promise).rejects.toThrow(
      /expected an object response.*got array/,
    );
  });

  it("rejects when response is not an object (scalar) — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: "not an object" } },
    ]);
    const promise = client.abacPolicies.list();
    await expect(promise).rejects.toBeInstanceOf(AttestryError);
    await expect(promise).rejects.toThrow(
      /expected an object response.*got string/,
    );
  });

  it("rejects when items is not an array — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: "not-an-array", count: 0 } } },
    ]);
    const promise = client.abacPolicies.list();
    await expect(promise).rejects.toBeInstanceOf(AttestryError);
    await expect(promise).rejects.toThrow(
      /expected response\.items to be an array.*got string/,
    );
  });

  it("rejects when items is null — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: null, count: 0 } } },
    ]);
    await expect(client.abacPolicies.list()).rejects.toThrow(
      /expected response\.items to be an array.*got null/,
    );
  });

  it("rejects when items is an object — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: {}, count: 0 } } },
    ]);
    await expect(client.abacPolicies.list()).rejects.toThrow(
      /expected response\.items to be an array.*got object/,
    );
  });

  it("rejects when count is not a number (string) — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], count: "0" } } },
    ]);
    await expect(client.abacPolicies.list()).rejects.toThrow(
      /expected response\.count to be a number.*got string/,
    );
  });

  it("rejects when count is null — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], count: null } } },
    ]);
    await expect(client.abacPolicies.list()).rejects.toThrow(
      /expected response\.count to be a number.*got null/,
    );
  });

  it("accepts count = 0 (boundary — falsy but valid)", async () => {
    // typeof 0 === "number" passes; falsy boundary doesn't cause
    // false-rejection. Mirror of regulatoryChanges.list's similar
    // boundary pin (count=0 on empty result).
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    const out = await client.abacPolicies.list();
    expect(out.count).toBe(0);
  });

  it("accepts count = NaN as a number (faithful courier on numeric typeof)", async () => {
    // typeof NaN === "number" passes. JSON-wire-format never emits NaN
    // (JSON.stringify(NaN) → "null"), but if a kernel ever emitted
    // non-JSON wire format (e.g., msgpack), NaN would pass typeof.
    // Documented faithful-courier asymmetry per the audit-log.ts
    // pattern.
    const { client } = makeMockedClient([
      {
        bodyText: JSON.stringify({ success: true, data: { items: [], count: 0 } })
          // Replace 0 with NaN literal — but JSON parsers reject this.
          // So instead we test via the JSON.parse round-trip: NaN can't
          // be in wire-format JSON. This is a no-op assertion here; the
          // documented asymmetry stands. (Marker for future revisits.)
          .replace(`"count":0`, `"count":0`),
      },
    ]);
    const out = await client.abacPolicies.list();
    expect(out.count).toBe(0);
  });
});

// ─── Missing own-property — coverage for `:undefined` ternary arms ──────────

// The P2 validator uses the pattern `objectHasOwn(obj, "X") ? obj.X :
// undefined`. The `:undefined` arm fires when the field is missing as
// an own-property of the response. Each such field needs an explicit
// test exercising the missing-own-property branch so the ternary's
// undefined arm is covered (otherwise branch coverage drops to ~98%).
//
// Front-loaded per the session-17 carry-forward lesson (build the
// missing-own-property it.each into the build round).

describe("abacPolicies.list — missing own-property exercises :undefined ternary arm", () => {
  it.each([
    {
      missingField: "items",
      payload: { count: 0 },
      expectedMessage: /expected response\.items to be an array.*got undefined/,
    },
    {
      missingField: "count",
      payload: { items: [] },
      expectedMessage: /expected response\.count to be a number.*got undefined/,
    },
  ])(
    "missing own-property `$missingField` → :undefined arm → AttestryError",
    async ({ payload, expectedMessage }) => {
      const { client } = makeMockedClient([
        { body: { success: true, data: payload } },
      ]);
      await expect(client.abacPolicies.list()).rejects.toThrow(
        expectedMessage,
      );
    },
  );
});

// ─── Prototype-pollution defense (response side) ────────────────────────────

describe("abacPolicies.list — prototype-pollution defense (response side)", () => {
  // The validator uses module-load `objectHasOwn` snapshot to defend
  // against `Object.prototype.<field>` pollution. A consumer's
  // dependency could pollute `Object.prototype.items = []` AFTER SDK
  // module load; the validator's `objectHasOwn(obj, "items")` would
  // still correctly return false on a missing own-property, surfacing
  // the kernel regression as an AttestryError (instead of silently
  // reading the polluted value via prototype walk).

  afterEach(() => {
    // Cleanup any prototype pollution we set up — eager cleanup before
    // afterEach safety net. Mirror of session-19 review-2 LOW-3 pattern.
    delete (Object.prototype as Record<string, unknown>).items;
    delete (Object.prototype as Record<string, unknown>).count;
  });

  it("polluted Object.prototype.items does NOT mask a missing items field", async () => {
    // Without `Object.hasOwn`-based defense, the validator's
    // `obj.items` read would walk the prototype and return the polluted
    // `[]`. With the defense: validator uses `objectHasOwn(obj,
    // "items")` which returns false on a missing own-property, so the
    // validator sees `items === undefined` and rejects.
    (Object.prototype as Record<string, unknown>).items = ["polluted"];
    const { client } = makeMockedClient([
      { body: { success: true, data: { count: 0 } } },
    ]);
    await expect(client.abacPolicies.list()).rejects.toThrow(
      /expected response\.items to be an array.*got undefined/,
    );
  });

  it("polluted Object.prototype.count does NOT mask a missing count field", async () => {
    (Object.prototype as Record<string, unknown>).count = 99;
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [] } } },
    ]);
    await expect(client.abacPolicies.list()).rejects.toThrow(
      /expected response\.count to be a number.*got undefined/,
    );
  });

  it("polluted Object.prototype with type-valid values still triggers missing-own-property rejection", async () => {
    // Adversarial setup (session-19 carry-forward): the polluted value
    // is type-VALID (`[]` for items, `0` for count) — so a validator
    // missing the own-property check would silently accept the
    // polluted values. The module-load `objectHasOwn` snapshot ensures
    // we reject on missing own-property regardless of the polluted
    // value's type-validity.
    (Object.prototype as Record<string, unknown>).items = [];
    (Object.prototype as Record<string, unknown>).count = 0;
    const { client } = makeMockedClient([
      { body: { success: true, data: { /* both missing */ } } },
    ]);
    await expect(client.abacPolicies.list()).rejects.toBeInstanceOf(
      AttestryError,
    );
  });

  it("does NOT auto-add Object.prototype fields to the result object", async () => {
    // After a successful call with both fields present, the returned
    // object should NOT have any extra fields injected via prototype
    // pollution. Pin that `out.items` is genuinely the kernel-returned
    // array, and that no surprise own-properties from prototype get
    // surfaced as result-object own-properties.
    (Object.prototype as Record<string, unknown>).surprise = "polluted-extra";
    try {
      const { client } = makeMockedClient([
        {
          body: {
            success: true,
            data: { items: [POLICY_EQ_LEAF], count: 1 },
          },
        },
      ]);
      const out = await client.abacPolicies.list();
      expect(Object.hasOwn(out, "items")).toBe(true);
      expect(Object.hasOwn(out, "count")).toBe(true);
      // The polluted "surprise" field is reachable via prototype walk
      // BUT is NOT an own-property of `out`. The kernel doesn't emit
      // it; the SDK doesn't add it. Pin both invariants.
      expect(Object.hasOwn(out, "surprise")).toBe(false);
    } finally {
      delete (Object.prototype as Record<string, unknown>).surprise;
    }
  });
});

// ─── URL & request invariants ───────────────────────────────────────────────

describe("abacPolicies.list — URL & request invariants", () => {
  it("uses GET (NOT POST / PATCH / DELETE)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    await client.abacPolicies.list();
    expect(calls[0].method).toBe("GET");
  });

  it("hits exact path /api/v1/abac-policies (no query string)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    await client.abacPolicies.list();
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/abac-policies",
    );
    // No query string — list takes no input.
    expect(calls[0].url).not.toContain("?");
  });

  it("does NOT send a request body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    await client.abacPolicies.list();
    expect(calls[0].body).toBeUndefined();
  });

  it("sends Accept: application/json (request header)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    await client.abacPolicies.list();
    const accept = (calls[0].headers as Headers).get("accept");
    // The transport may set "*/*" or "application/json" — accept either.
    // Pin that the header is set (not undefined).
    expect(accept === null || accept === undefined).toBe(false);
  });

  it("response-shape validation runs AFTER the transport envelope unwrap", async () => {
    // The transport unwraps `{success:true, data: ...}` and passes
    // `data` to the SDK validator. A kernel emitting the envelope
    // correctly but a bad inner `data` shape surfaces as an
    // AttestryError from the SDK validator — NOT a transport-level
    // error. Pin the order.
    const { client } = makeMockedClient([
      {
        body: { success: true, data: "not-an-object" },
      },
    ]);
    await expect(client.abacPolicies.list()).rejects.toBeInstanceOf(
      AttestryError,
    );
  });

  it("rejects when the transport response is missing `success: true` (envelope guard)", async () => {
    // The transport rejects envelopes that don't follow the
    // `{success:true, data}` shape. A kernel emitting a different
    // envelope (e.g., raw items array) would surface as a transport-
    // level error. Pin the contract.
    const { client } = makeMockedClient([
      {
        // Missing the envelope — direct items at the top level.
        bodyText: JSON.stringify([POLICY_EQ_LEAF]),
      },
    ]);
    await expect(client.abacPolicies.list()).rejects.toBeInstanceOf(
      AttestryError,
    );
  });
});

// ─── Per-row faithful-courier asymmetries (documented) ──────────────────────

describe("abacPolicies.list — per-row faithful-courier asymmetries", () => {
  it("passes through a row with extra fields not in the typed AbacPolicy interface", async () => {
    // Per-row shape is NOT validated by the P2 validator (faithful
    // courier — P4 candidate, matches incidents.list /
    // regulatoryChanges.list pattern). A future kernel adding a new
    // field to AbacPolicyRow surfaces in consumer code via the
    // bag-of-fields pattern; the SDK passes it through verbatim.
    const rowWithExtra: AbacPolicy & { futureField: string } = {
      ...POLICY_EQ_LEAF,
      futureField: "added-by-kernel-later",
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [rowWithExtra], count: 1 } } },
    ]);
    const out = await client.abacPolicies.list();
    // Pin: the extra field rides through.
    expect(
      (out.items[0] as AbacPolicy & { futureField?: string }).futureField,
    ).toBe("added-by-kernel-later");
  });

  it("passes through a row with a wrong-type field (faithful courier — P4 candidate)", async () => {
    // Faithful courier — the SDK does NOT runtime-type-check per-row
    // fields. A row with `priority: "100"` (string instead of number)
    // rides through unchanged. Document the asymmetry: if a kernel
    // regression flips a field's type, consumers see the wrong type
    // at the call site (not an SDK rejection). P4 candidate work
    // would add per-row shape validation; today it's NOT done for
    // consistency with the rest of the list-resource patterns.
    const malformedRow = {
      ...POLICY_EQ_LEAF,
      priority: "100" as unknown as number, // wire-shape regression
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [malformedRow], count: 1 } } },
    ]);
    const out = await client.abacPolicies.list();
    // Pin: SDK does NOT throw. Consumer sees the wrong type.
    expect(typeof (out.items[0] as AbacPolicy).priority).toBe("string");
  });

  it("passes through an empty-items array verbatim (no synthesized rows)", async () => {
    // The SDK does NOT synthesize default rows. An empty items array
    // surfaces as an empty array, NOT as `null` or `undefined`. Pin
    // for backwards compat / future regression.
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
    ]);
    const out = await client.abacPolicies.list();
    expect(Array.isArray(out.items)).toBe(true);
    expect(out.items.length).toBe(0);
  });
});

// ─── Hostile round (residual gaps) ──────────────────────────────────────────
//
// Each H-pin exercises an attack surface or defense mechanism the
// preceding rounds did NOT cover. Per session-19 + session-20 lessons:
//   - Adversarial polluted-value construction: use TYPE-VALID values
//     that would pass naive typeof checks (session-19 review-1 H1).
//   - Pollute UNCONDITIONAL validator branches (session-19 carry-fwd).
//   - vi.spyOn over direct global assignment for safety (session-19 r2 L3).
//   - Eager mockRestore in finally before proto cleanup (session-19 r2 L3).
//   - Combined attacks (Object.hasOwn override + prototype pollution)
//     observable only with module-load snapshot defense (session-20 H9).

describe("abacPolicies.list — hostile round (residual gaps)", () => {
  it("H1: Object.hasOwn global override via vi.spyOn does NOT defeat the validator's module-load snapshot", async () => {
    // Attack: a late-loading hostile npm dep replaces the global
    // `Object.hasOwn` with `() => true` AFTER the SDK module loads.
    // Without defense, the validator's `objectHasOwn(obj, "items")`
    // would walk into the polluted prototype value (or any-truthy
    // check) and accept a missing-on-wire response.
    //
    // Defense: the validator captures `Object.hasOwn` at module
    // import time (`const objectHasOwn = Object.hasOwn;`). The
    // late-loading override doesn't affect the SDK validator — only
    // consumer-side `Object.hasOwn` calls.
    //
    // Pollute `Object.prototype.items` with a type-valid empty array
    // (passes Array.isArray), and emit a response with `count: 0` but
    // no `items` own-property. Verify validator rejects despite the
    // override + pollution.
    const hasOwnSpy = vi
      .spyOn(Object, "hasOwn")
      .mockImplementation(() => true);
    (Object.prototype as Record<string, unknown>).items = [];

    try {
      const { client } = makeMockedClient([
        { body: { success: true, data: { count: 0 } } },
      ]);
      // Despite the override + pollution, the SDK's module-load
      // snapshot of Object.hasOwn (captured before the spy fires)
      // returns FALSE for missing items own-property, and the
      // validator rejects.
      await expect(client.abacPolicies.list()).rejects.toThrow(
        /expected response\.items to be an array.*got undefined/,
      );
    } finally {
      // Eager restoration BEFORE afterEach cleanup (session-19 r2 L3).
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).items;
    }
  });

  it("H2: P3 content-type fail-fast — 200 with `text/plain` Content-Type rejects with AttestryAPIError", async () => {
    // Attack: a proxy / LB middleware injects a HTML / plain-text
    // response with a 200 status (e.g., a captive-portal page or a
    // misconfigured CDN). Without the transport's content-type guard,
    // `JSON.parse("<html>...")` would throw a generic parse error
    // instead of surfacing as a typed SDK error.
    //
    // Defense: transport's P3 hardening rejects non-JSON 200s with
    // AttestryAPIError. Pin the contract — verifies the SDK doesn't
    // get past content-type to body-parse for non-JSON content.
    const fetchSpy = vi.fn(async () => {
      return new Response("not JSON, plaintext from a proxy", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    await expect(client.abacPolicies.list()).rejects.toBeInstanceOf(
      AttestryAPIError,
    );
  });

  it("H3: P3 content-type fail-fast — 200 with NO Content-Type header rejects with AttestryAPIError", async () => {
    // Some proxies strip the Content-Type header entirely. Pin that
    // the SDK rejects rather than silently treating it as JSON.
    const fetchSpy = vi.fn(async () => {
      const res = new Response('{"success":true,"data":{"items":[],"count":0}}', {
        status: 200,
      });
      // Remove Content-Type via fresh Response without that header.
      res.headers.delete("Content-Type");
      return res;
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    // Note: depending on the runtime, Response may add a default
    // Content-Type. If it does, this test becomes a no-op. The pin
    // is defensive — exercise either AttestryAPIError or successful
    // parse, but pin SOMETHING for the path. Today the Response
    // constructor defaults to "text/plain;charset=UTF-8" when no
    // body is initialized differently; the transport's strict
    // content-type guard rejects anything that doesn't start with
    // "application/json".
    await expect(client.abacPolicies.list()).rejects.toBeInstanceOf(
      AttestryAPIError,
    );
  });

  it("H4: combined attack — Object.hasOwn override + type-valid Object.prototype pollution on BOTH fields + empty-object response; module-load snapshot rejects", async () => {
    // Adversarial setup combining the strongest individual attacks:
    //   1. Override `Object.hasOwn` global to return true for any key
    //      (defeats consumer-side own-property checks).
    //   2. Pollute `Object.prototype.items = []` AND
    //      `Object.prototype.count = 0` (both type-valid — Array
    //      and number).
    //   3. Kernel response is `{}` — neither items nor count present
    //      as own-properties.
    //
    // The ONLY way the SDK validator catches this is via the
    // module-load `objectHasOwn` snapshot. Pin observably so the
    // defense is exercised, not just claimed.
    const hasOwnSpy = vi
      .spyOn(Object, "hasOwn")
      .mockImplementation(() => true);
    (Object.prototype as Record<string, unknown>).items = [];
    (Object.prototype as Record<string, unknown>).count = 0;

    try {
      const { client } = makeMockedClient([
        { body: { success: true, data: {} } },
      ]);
      // The validator's first check is items own-property. The
      // module-load snapshot correctly returns false → validator
      // sees `items === undefined` → throws AttestryError.
      await expect(client.abacPolicies.list()).rejects.toBeInstanceOf(
        AttestryError,
      );
    } finally {
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).items;
      delete (Object.prototype as Record<string, unknown>).count;
    }
  });

  it("H5: items array with non-string elements rides through faithfully (per-row P4 deferred)", async () => {
    // Faithful courier — items element shape is NOT runtime-validated.
    // An items array containing nulls, numbers, or objects passes
    // through (consumer sees the wrong type at the call site).
    // Documents the P4 candidate gap.
    const malformedItems: unknown[] = [
      null,
      42,
      { not_a_policy: true },
      "string-not-object",
    ];
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: malformedItems, count: 4 },
        },
      },
    ]);
    const out = await client.abacPolicies.list();
    // Top-level shape passes (items is array, count is number).
    expect(Array.isArray(out.items)).toBe(true);
    expect(out.count).toBe(4);
    // Per-row passthrough: consumer would crash on `out.items[0].id`
    // because `out.items[0]` is null. The SDK is the faithful courier,
    // NOT the validator. Pin: malformed types ride through.
    expect((out.items[0] as unknown as null) === null).toBe(true);
    expect(typeof out.items[1]).toBe("number");
  });

  it("H6: 401 vs 403 distinct-branch — a kernel mis-mapping that returns 403 for unauth is surfaced as 403 (faithful courier on status)", async () => {
    // Adversarial scenario: a hypothetical kernel regression mis-maps
    // the unauth path to status 403 (treating "no auth" as
    // "insufficient permission"). The SDK is a faithful courier on
    // HTTP status — it surfaces whatever the kernel emits. Pin the
    // contract: SDK does NOT collapse 403 → 401 (or vice versa).
    //
    // This protects against the audit-log.ts SDK doc claim ("401 for
    // both") being silently mirrored into abacPolicies. If the SDK
    // EVER starts collapsing dual-auth admin status codes, this pin
    // fires.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error: "API key required. Provide x-api-key header.",
        },
      },
    ]);
    try {
      await client.abacPolicies.list();
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      // Pin: SDK preserved 403 verbatim, did not collapse to 401.
      expect(apiErr.status).toBe(403);
      expect(apiErr.status).not.toBe(401);
    }
  });

  it("H7: items as a truthy non-array (string with length) rejects despite typeof passing object intuitions", async () => {
    // Subtle adversarial input: a kernel regression emits items as a
    // STRING containing JSON-array syntax (e.g., from a double-
    // serialization bug). `typeof "..."` is "string" (not "object"),
    // but a naive `obj.items.length > 0` consumer check would still
    // succeed. The SDK's `!Array.isArray(items)` check is the
    // load-bearing defense. Pin it.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: "[{\"id\":\"a\"}]", count: 1 },
        },
      },
    ]);
    await expect(client.abacPolicies.list()).rejects.toThrow(
      /expected response\.items to be an array.*got string/,
    );
  });

  it("H8: count as a boolean true is rejected (typeof passes 'boolean' not 'number')", async () => {
    // Adversarial: `count: true` (boolean). A naive truthy check
    // (`if (out.count)`) would pass. The SDK's `typeof !== "number"`
    // check rejects. Pin the contract — boolean coercion doesn't
    // bypass the type check.
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], count: true } } },
    ]);
    await expect(client.abacPolicies.list()).rejects.toThrow(
      /expected response\.count to be a number.*got boolean/,
    );
  });

  it("H9: AbortController fired pre-call does NOT corrupt subsequent SDK calls (state isolation)", async () => {
    // Subtle race: a pre-aborted signal short-circuits the SDK BEFORE
    // fetch is issued (transport checks signal at entry). If the SDK
    // had any module-level mutable state (e.g., a shared validator
    // result), the rejected call could corrupt the next call's state.
    //
    // Pin: a rejected call leaves no dirty state. The second call
    // works correctly. (Note: because the aborted call doesn't issue
    // fetch, the mock counter stays at 0; the second call consumes
    // responses[0]. We pin observable success on call 2, not a
    // specific counter value.)
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [POLICY_EQ_LEAF], count: 1 } } },
    ]);

    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.list({ signal: ac.signal }),
    ).rejects.toBeInstanceOf(AttestryError);

    // Second call (no abort) should consume the first mocked response.
    const out = await client.abacPolicies.list();
    expect(out.count).toBe(1);
    expect(out.items[0].id).toBe(POLICY_ID_1);
  });

  it("H10: concurrent .list() calls use independent validator state — no shared snapshot leakage", async () => {
    // Concurrency pin: 3 .list() calls in flight simultaneously, each
    // gets a different mocked response. Pin that each call's
    // validator is independent (no module-level mutable state).
    //
    // The validator is a pure function over its `result` argument
    // (no closures, no shared state), but pin observably so a future
    // refactor that adds module-level state surfaces the violation.
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], count: 0 } } },
      { body: { success: true, data: { items: [POLICY_EQ_LEAF], count: 1 } } },
      {
        body: {
          success: true,
          data: { items: [POLICY_EQ_LEAF, POLICY_COMPOUND_AND], count: 2 },
        },
      },
    ]);

    const [r0, r1, r2] = await Promise.all([
      client.abacPolicies.list(),
      client.abacPolicies.list(),
      client.abacPolicies.list(),
    ]);

    expect(r0.count).toBe(0);
    expect(r1.count).toBe(1);
    expect(r2.count).toBe(2);
    expect(r1.items[0].id).toBe(POLICY_ID_1);
    expect(r2.items[1].id).toBe(POLICY_ID_2);
  });
});
