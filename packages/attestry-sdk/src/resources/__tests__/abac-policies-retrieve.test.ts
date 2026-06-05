import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  // Result-shape type imports — pinned at compile time. If `AbacPolicy`
  // is dropped from `index.ts` or the resource's exports, this file
  // fails to compile and the test run aborts before any pin runs.
  AbacPolicy,
} from "../abac-policies.js";
import type { FetchLike } from "../../types.js";

// ─── abacPolicies.retrieve — GET one ABAC policy by id ──────────────────────
//
// Wire shape (kernel src/app/api/v1/abac-policies/[id]/route.ts):
//   GET /api/v1/abac-policies/[id]
//   Auth: x-api-key (requireSessionOrApiKey + apiKeyPermissions:[ADMIN])
//   No body.
//   200 OK: {success:true, data: <AbacPolicy row>}
//   400 malformed UUID (kernel `badId` — SDK-pre-empted),
//   401 auth (no/invalid/expired key), 403 permission (non-ADMIN key),
//   404 not-found (inline "ABAC policy not found." — missing OR cross-org),
//   429 rate-limit (assessmentLimiter, abac-policies-get:${ip} key),
//   500 internal.
//
// 23rd audit chain in the F.1 phase. Third method of the 5-method
// `abacPolicies` CRUD cluster (`.list` + `.create` shipped in session
// 21; `.retrieve` + `.update` + `.delete` ship in session 22).
//
// **FIRST `abacPolicies` method with a UUID path segment** — `id` is
// interpolated into the request path. The SDK pre-validates `id`
// against `UUID_REGEX` synchronously (mirror of `batch.get`); the
// kernel's 400 is reachable only via an `as any` cast.
//
// **No `writeAuditLog` side effect** — `.retrieve()` is a quiet read
// (same as `.list()`; asymmetric with `.create` / `.update` /
// `.delete`).
//
// **Status-code surface — 401 AND 403 distinguished** (dual-auth admin
// route — same surface as `.list` / `.create`). Pin BOTH branches.
//
// Adapted from `abac-policies-list` (GET shape) + `batch.get` (UUID
// path-segment pre-validation) patterns.

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

const POLICY_ID = "11111111-1111-1111-1111-111111111111";
const ORG_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const USER_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff";

// Sample policy fixture — simple attrEq leaf condition, all 13 fields.
const RETRIEVED_POLICY: AbacPolicy = {
  id: POLICY_ID,
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
  createdAt: "2026-05-15T12:00:00.000Z",
  updatedAt: "2026-05-15T12:00:00.000Z",
};

// Sample policy fixture — compound `and` condition, null description +
// null createdByUserId (kernel `?? null` coalesce on unset values).
const RETRIEVED_POLICY_NULLS: AbacPolicy = {
  id: "22222222-2222-2222-2222-222222222222",
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
  createdAt: "2026-05-15T13:00:00.000Z",
  updatedAt: "2026-05-15T13:30:00.000Z",
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("abacPolicies.retrieve — happy path", () => {
  it("GETs /api/v1/abac-policies/<id> and returns the policy row", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    const out = await client.abacPolicies.retrieve(POLICY_ID);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${POLICY_ID}`,
    );
    expect(out.id).toBe(POLICY_ID);
    expect(out.name).toBe("owner-can-edit-own");
  });

  it("interpolates the id into the path verbatim (UUID is URL-safe, no encoding)", async () => {
    // A validated UUID is ASCII hex + hyphens — the SDK interpolates it
    // raw (no encodeURIComponent). Pin that the path segment is the id
    // unchanged. Uppercase-hex id confirms the regex's case-insensitivity
    // AND that the raw segment is byte-identical to the input.
    const upperId = "ABCDEF01-2345-6789-ABCD-EF0123456789";
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...RETRIEVED_POLICY, id: upperId },
        },
      },
    ]);
    await client.abacPolicies.retrieve(upperId);
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${upperId}`,
    );
  });

  it("returns the full 13-field row verbatim (faithful courier on per-row shape)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    const out = await client.abacPolicies.retrieve(POLICY_ID);
    expect(out).toEqual(RETRIEVED_POLICY);
  });

  it("preserves the recursive condition AST verbatim (consumer branches on .op)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY_NULLS } },
    ]);
    const out = await client.abacPolicies.retrieve(
      "22222222-2222-2222-2222-222222222222",
    );
    expect(out.condition).toEqual({
      op: "and",
      clauses: [
        { op: "eq", attr: "resource.archived", value: true },
        { op: "ne", attr: "principal.role", value: "admin" },
      ],
    });
  });

  it("preserves null fields (description / createdByUserId) as null, NOT undefined", async () => {
    // The kernel emits `null` (NOT `undefined`) for unset description
    // and createdByUserId via the `?? null` coalesce in `rowToPolicy`.
    const { client } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY_NULLS } },
    ]);
    const out = await client.abacPolicies.retrieve(
      "22222222-2222-2222-2222-222222222222",
    );
    expect(out.description).toBeNull();
    expect(out.createdByUserId).toBeNull();
  });

  it("sends `x-api-key` header from the client config", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    await client.abacPolicies.retrieve(POLICY_ID);
    expect((calls[0].headers as Headers).get("x-api-key")).toBe("k");
  });

  it("forwards options.signal to the underlying fetch (abort-passthrough)", async () => {
    const fetchSpy = vi.fn(async (_url: unknown, init: unknown) => {
      const init_ = init as RequestInit;
      void init_.signal;
      return new Response(
        JSON.stringify({ success: true, data: RETRIEVED_POLICY }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const ac = new AbortController();
    await client.abacPolicies.retrieve(POLICY_ID, { signal: ac.signal });
    const passedInit = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(passedInit.signal).toBeDefined();
  });
});

// ─── Input validation: id (synchronous TypeError; NO fetch issued) ─────────

describe("abacPolicies.retrieve — input validation: id", () => {
  it("throws TypeError when id is undefined (no fetch issued)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.retrieve(undefined as unknown as string),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is null", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.retrieve(null as unknown as string),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is not a string (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.retrieve(42 as unknown as string),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is an empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.abacPolicies.retrieve("")).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is a non-UUID string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.abacPolicies.retrieve("not-a-uuid")).toThrow(
      /`id` must be an RFC 4122 hyphenated UUID/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is a UUID with wrong segment lengths", () => {
    const { client, calls } = makeMockedClient([]);
    // 7-4-4-4-12 instead of 8-4-4-4-12.
    expect(() =>
      client.abacPolicies.retrieve("1111111-1111-1111-1111-111111111111"),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id has a non-hex character", () => {
    const { client, calls } = makeMockedClient([]);
    // 'g' is not a hex digit.
    expect(() =>
      client.abacPolicies.retrieve("g1111111-1111-1111-1111-111111111111"),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id has surrounding whitespace (anchored regex)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.retrieve(` ${POLICY_ID} `),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("the malformed-id TypeError message echoes the offending value", () => {
    const { client } = makeMockedClient([]);
    expect(() => client.abacPolicies.retrieve("nope")).toThrow(/"nope"/);
  });

  it("accepts a lowercase-hex UUID", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    await client.abacPolicies.retrieve(
      "0123abcd-4567-89ef-0123-456789abcdef",
    );
  });

  it("accepts an uppercase-hex UUID (regex is case-insensitive)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    await client.abacPolicies.retrieve(
      "0123ABCD-4567-89EF-0123-456789ABCDEF",
    );
  });
});

// ─── Top-level error paths ──────────────────────────────────────────────────

describe("abacPolicies.retrieve — top-level error paths", () => {
  it("401 (no/invalid/expired api-key) → AttestryAPIError(401)", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Invalid API key." },
      },
    ]);
    const promise = client.abacPolicies.retrieve(POLICY_ID);
    await expect(promise).rejects.toBeInstanceOf(AttestryAPIError);
    await expect(promise).rejects.toMatchObject({ status: 401 });
  });

  it("403 (valid key without ADMIN permission) → AttestryAPIError(403) — DISTINCT from 401", async () => {
    // Dual-auth admin route distinguishes 401 (no/invalid key) from
    // 403 (valid key, permissions lack ADMIN). Asymmetric with
    // carry-forward invariant #42's ADMIN-only 401-collapse.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error:
            "API key lacks required permission. Required: admin. Key has: read:systems.",
        },
      },
    ]);
    try {
      await client.abacPolicies.retrieve(POLICY_ID);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.message).toContain("API key lacks required permission");
      expect(apiErr.status).not.toBe(401);
    }
  });

  it("404 (policy not found OR cross-org id) → AttestryAPIError(404)", async () => {
    // The kernel's getAbacPolicyById returns null for a missing id OR
    // a cross-org id (the eq(orgId) clause silently filters other
    // orgs' policies). The GET handler maps both to the same inline
    // "ABAC policy not found." 404.
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "ABAC policy not found." },
      },
    ]);
    try {
      await client.abacPolicies.retrieve(POLICY_ID);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.message).toContain("not found");
    }
  });

  it("429 → AttestryAPIError(429) (with retry disabled)", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: {
          success: false,
          error: "Too many requests. Please try again later.",
        },
      },
    ]);
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toMatchObject({ status: 429 });
  });

  it("500 (internal kernel error, scrubbed message) → AttestryAPIError(500)", async () => {
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
      await client.abacPolicies.retrieve(POLICY_ID);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(500);
      // No internal detail leakage.
      expect(apiErr.message).not.toContain("getAbacPolicyById");
      expect(apiErr.message).not.toContain("db");
    }
  });

  it("non-JSON 500 body (HTML proxy page) surfaces as AttestryAPIError via P3 guard", async () => {
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
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });
});

// ─── 400 surface (SDK-pre-empted) ───────────────────────────────────────────

describe("abacPolicies.retrieve — 400 surface (SDK-pre-empted)", () => {
  it("kernel 400 'Invalid policy id.' is reachable only via an `as any` bypass of UUID pre-validation", async () => {
    // The SDK pre-validates the UUID format, so a well-typed call can
    // never reach the kernel's `badId` 400. To exercise the 400 path
    // a consumer must bypass the validation — which the SDK's
    // `assertValidPolicyId` prevents for any real string. This pin
    // documents that the 400 is genuinely SDK-pre-empted: a malformed
    // id is rejected synchronously (TypeError), never as a 400.
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid policy id." } },
    ]);
    // A malformed id throws synchronously BEFORE any fetch — the 400
    // mock is never consumed.
    expect(() => client.abacPolicies.retrieve("malformed")).toThrow(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });
});

// ─── Retry semantics ────────────────────────────────────────────────────────

describe("abacPolicies.retrieve — retry semantics", () => {
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
        JSON.stringify({ success: true, data: RETRIEVED_POLICY }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });
    const out = await client.abacPolicies.retrieve(POLICY_ID);
    expect(out.id).toBe(POLICY_ID);
    expect(callCount).toBeGreaterThanOrEqual(2);
  });

  it("does NOT retry on 404 (not-found is a permanent state)", async () => {
    const fetchSpy = vi.fn(async () => {
      return new Response(
        JSON.stringify({ success: false, error: "ABAC policy not found." }),
        { status: 404, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryAPIError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry on 401 / 403 (non-retryable codes)", async () => {
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
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryAPIError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});

// ─── Abort semantics ────────────────────────────────────────────────────────

describe("abacPolicies.retrieve — abort semantics", () => {
  it("rejects with AttestryError when options.signal is pre-aborted", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.retrieve(POLICY_ID, { signal: ac.signal }),
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
    const pending = client.abacPolicies.retrieve(POLICY_ID, {
      signal: ac.signal,
    });
    ac.abort();
    await expect(pending).rejects.toBeInstanceOf(AttestryError);
    // Cleanup — don't hang the test runner.
    resolveFetch(
      new Response(
        JSON.stringify({ success: true, data: RETRIEVED_POLICY }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
  });
});

// ─── Response shape (P2 hardening — shared validateAbacPolicy) ──────────────

describe("abacPolicies.retrieve — response shape (P2 hardening)", () => {
  it("rejects when response is not an object (null) — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    const promise = client.abacPolicies.retrieve(POLICY_ID);
    await expect(promise).rejects.toBeInstanceOf(AttestryError);
    await expect(promise).rejects.toThrow(/expected an object response/);
  });

  it("the response-validator error message names `abacPolicies.retrieve` (not `.create`)", async () => {
    // The shared validateAbacPolicy validator takes a `methodName`
    // argument so a malformed response names the method the consumer
    // called. Pin that `.retrieve()` passes its own method name.
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(client.abacPolicies.retrieve(POLICY_ID)).rejects.toThrow(
      /abacPolicies\.retrieve:/,
    );
  });

  it.each([
    { field: "id", value: 42, type: "number" },
    { field: "orgId", value: null, type: "null" },
    { field: "name", value: true, type: "boolean" },
    { field: "resource", value: 1, type: "number" },
    { field: "action", value: [], type: "array" },
    { field: "effect", value: null, type: "null" },
    { field: "priority", value: "100", type: "string" },
    { field: "enabled", value: 1, type: "number" },
    { field: "createdAt", value: 123, type: "number" },
    { field: "updatedAt", value: false, type: "boolean" },
  ])(
    "rejects when response.$field is wrong type ($type)",
    async ({ field, value, type }) => {
      const malformed = { ...RETRIEVED_POLICY, [field]: value };
      const { client } = makeMockedClient([
        { body: { success: true, data: malformed } },
      ]);
      const promise = client.abacPolicies.retrieve(POLICY_ID);
      await expect(promise).rejects.toBeInstanceOf(AttestryError);
      await expect(promise).rejects.toThrow(
        new RegExp(`response\\.${field}.*${type}`),
      );
    },
  );

  it("accepts response.description = null (boundary; string | null)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...RETRIEVED_POLICY, description: null },
        },
      },
    ]);
    const out = await client.abacPolicies.retrieve(POLICY_ID);
    expect(out.description).toBeNull();
  });

  it("rejects when response.description is a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...RETRIEVED_POLICY, description: 42 },
        },
      },
    ]);
    await expect(client.abacPolicies.retrieve(POLICY_ID)).rejects.toThrow(
      /response\.description.*string or null.*number/,
    );
  });

  it("accepts response.createdByUserId = null (boundary; string | null)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...RETRIEVED_POLICY, createdByUserId: null },
        },
      },
    ]);
    const out = await client.abacPolicies.retrieve(POLICY_ID);
    expect(out.createdByUserId).toBeNull();
  });

  it("rejects when response.condition is null", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...RETRIEVED_POLICY, condition: null },
        },
      },
    ]);
    await expect(client.abacPolicies.retrieve(POLICY_ID)).rejects.toThrow(
      /response\.condition.*non-null object/,
    );
  });

  it("rejects when response.condition is an array", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...RETRIEVED_POLICY, condition: [] },
        },
      },
    ]);
    await expect(client.abacPolicies.retrieve(POLICY_ID)).rejects.toThrow(
      /response\.condition.*non-null object.*array/,
    );
  });

  it("validates the condition shape only as a non-null object (recursive AST is faithful courier)", async () => {
    // The P2 validator confirms `condition` is a non-null object but
    // does NOT re-validate the recursive AST grammar — a malformed-AST
    // object rides through (the kernel is the AST source of truth).
    const malformedAst = { not_a_valid_op: "garbage" };
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...RETRIEVED_POLICY, condition: malformedAst },
        },
      },
    ]);
    const out = await client.abacPolicies.retrieve(POLICY_ID);
    expect(out.condition).toEqual(malformedAst);
  });
});

// ─── Missing own-property — coverage for `:undefined` ternary arms ──────────
//
// The shared validateAbacPolicy validator reads each field via
// `objectHasOwn(obj, "X") ? obj.X : undefined`. The `:undefined` arm
// fires when the field is genuinely absent as an own-property. Each
// of the 13 fields needs an explicit missing-own-property test so the
// ternary's undefined arm is covered. Front-loaded into the build
// round per the session-17 carry-forward lesson.

describe("abacPolicies.retrieve — missing own-property exercises :undefined ternary arm", () => {
  it.each([
    "id",
    "orgId",
    "name",
    "description",
    "resource",
    "action",
    "effect",
    "condition",
    "priority",
    "enabled",
    "createdByUserId",
    "createdAt",
    "updatedAt",
  ])("missing own-property `%s` → :undefined arm → AttestryError", async (field) => {
    const partial = { ...RETRIEVED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>)[field];
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ─── URL & request invariants ───────────────────────────────────────────────

describe("abacPolicies.retrieve — URL & request invariants", () => {
  it("uses GET (NOT POST / PATCH / DELETE)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    await client.abacPolicies.retrieve(POLICY_ID);
    expect(calls[0].method).toBe("GET");
  });

  it("hits exact path /api/v1/abac-policies/<id> (with id segment, no query string)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    await client.abacPolicies.retrieve(POLICY_ID);
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${POLICY_ID}`,
    );
    expect(calls[0].url).not.toContain("?");
  });

  it("does NOT send a request body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    await client.abacPolicies.retrieve(POLICY_ID);
    expect(calls[0].body).toBeUndefined();
  });

  it("response-shape validation runs AFTER the transport envelope unwrap", async () => {
    // The transport unwraps `{success:true, data}` and passes `data`
    // to validateAbacPolicy. A correct envelope wrapping a bad inner
    // shape surfaces as an AttestryError from the SDK validator.
    const { client } = makeMockedClient([
      { body: { success: true, data: "not-an-object" } },
    ]);
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("passes a bare (non-enveloped) response body through the transport, then rejects a malformed one via validateAbacPolicy", async () => {
    // The transport unwraps `{success:true, data}` when the envelope is
    // present and otherwise passes the parsed body through verbatim
    // (forward-compat for hypothetical non-conforming endpoints — see
    // transport.ts). So a 200 body lacking the envelope reaches
    // `validateAbacPolicy` directly; a non-policy bare body (here, an
    // object with no `id`) is rejected there as an AttestryError.
    const { client } = makeMockedClient([
      { bodyText: JSON.stringify({ unexpected: "shape" }) },
    ]);
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ─── Prototype-pollution defense (response side) ────────────────────────────

describe("abacPolicies.retrieve — prototype-pollution defense (response side)", () => {
  // validateAbacPolicy reads each field via the module-load
  // `objectHasOwn` snapshot. A consumer's dependency could pollute
  // `Object.prototype.<field>` AFTER SDK module load; the validator's
  // `objectHasOwn(obj, "<field>")` still correctly returns false on a
  // missing own-property, surfacing the kernel regression as an
  // AttestryError instead of reading the polluted value.

  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).id;
    delete (Object.prototype as Record<string, unknown>).name;
    delete (Object.prototype as Record<string, unknown>).condition;
  });

  it("polluted Object.prototype.id does NOT mask a missing id field", async () => {
    (Object.prototype as Record<string, unknown>).id = "polluted-id";
    const partial = { ...RETRIEVED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).id;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(client.abacPolicies.retrieve(POLICY_ID)).rejects.toThrow(
      /response\.id to be a string.*undefined/,
    );
  });

  it("polluted Object.prototype.name (type-valid string) does NOT mask a missing name field", async () => {
    // Adversarial: the polluted value is type-VALID (a string) — a
    // validator missing the own-property check would silently accept
    // it. The module-load objectHasOwn snapshot rejects regardless.
    (Object.prototype as Record<string, unknown>).name = "polluted-name";
    const partial = { ...RETRIEVED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).name;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(client.abacPolicies.retrieve(POLICY_ID)).rejects.toThrow(
      /response\.name to be a string.*undefined/,
    );
  });

  it("polluted Object.prototype.condition (type-valid object) does NOT mask a missing condition field", async () => {
    (Object.prototype as Record<string, unknown>).condition = {
      op: "exists",
      attr: "principal.id",
    };
    const partial = { ...RETRIEVED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).condition;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(client.abacPolicies.retrieve(POLICY_ID)).rejects.toThrow(
      /response\.condition.*non-null object.*undefined/,
    );
  });

  it("does NOT surface Object.prototype fields as own-properties of the result", async () => {
    (Object.prototype as Record<string, unknown>).surprise = "polluted-extra";
    try {
      const { client } = makeMockedClient([
        { body: { success: true, data: RETRIEVED_POLICY } },
      ]);
      const out = await client.abacPolicies.retrieve(POLICY_ID);
      expect(Object.hasOwn(out, "id")).toBe(true);
      expect(Object.hasOwn(out, "surprise")).toBe(false);
    } finally {
      delete (Object.prototype as Record<string, unknown>).surprise;
    }
  });
});

// ─── Hostile round (residual gaps) ──────────────────────────────────────────
//
// Each H-pin exercises an attack surface or defense mechanism the build
// + spec-diff rounds did NOT cover. Per session-19 + session-20 lessons:
//   - Adversarial polluted-value construction: TYPE-VALID values that
//     would pass naive typeof checks (session-19 review-1 H1).
//   - Pollute UNCONDITIONAL validator branches (session-19 carry-fwd).
//   - vi.spyOn over direct global assignment; eager mockRestore in
//     finally before proto cleanup (session-19 r2 L3).
//   - Combined attacks (Object.hasOwn override + prototype pollution)
//     observable only with the module-load snapshot defense.
//
// **H5 + H6 stress the design-#2 decision** — `.retrieve()` interpolates
// the `id` into the path RAW (no `encodeURIComponent`, no URIError
// defense), mirroring `batch.get`. That is only safe because
// `assertValidPolicyId` pre-rejects any non-UUID `id` synchronously.
// H5 (path-traversal-shaped id) and H6 (lone-surrogate id) prove the
// pre-validation is the load-bearing defense: an adversarial id never
// reaches the URL.

describe("abacPolicies.retrieve — hostile round (residual gaps)", () => {
  it("H1: Object.hasOwn global override + polluted Object.prototype.id + missing-own-property response; module-load snapshot rejects", async () => {
    // Attack: override `Object.hasOwn` to return true for any key, and
    // pollute `Object.prototype.id` with a TYPE-VALID string. Emit a
    // response with no `id` own-property. `id` is the validator's
    // FIRST (unconditional) field check — pollute an unconditional
    // branch so the override-vs-snapshot distinction is observable.
    //
    // Defense: validateAbacPolicy reads via the module-load
    // `objectHasOwn` snapshot (captured at SDK import, before the spy
    // fires) → correctly returns false on the missing own-property →
    // rejects with AttestryError.
    const hasOwnSpy = vi
      .spyOn(Object, "hasOwn")
      .mockImplementation(() => true);
    (Object.prototype as Record<string, unknown>).id = "polluted-id";
    try {
      const partial = { ...RETRIEVED_POLICY } as Partial<AbacPolicy>;
      delete (partial as Record<string, unknown>).id;
      const { client } = makeMockedClient([
        { body: { success: true, data: partial } },
      ]);
      await expect(client.abacPolicies.retrieve(POLICY_ID)).rejects.toThrow(
        /response\.id to be a string.*undefined/,
      );
    } finally {
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).id;
    }
  });

  it("H2: P3 content-type fail-fast — 200 success with `text/plain` rejects with AttestryAPIError", async () => {
    // The transport's P3 content-type guard runs on the SUCCESS path
    // too. A 200 with `Content-Type: text/plain` (proxy injection on
    // the success path) rejects with AttestryAPIError — NOT a silent
    // soft-fail into a wrong-shape response.
    const fetchSpy = vi.fn(async () => {
      return new Response("not JSON", {
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
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("H3: P3 content-type fail-fast — 200 with NO Content-Type header rejects with AttestryAPIError", async () => {
    const fetchSpy = vi.fn(async () => {
      const res = new Response(
        JSON.stringify({ success: true, data: RETRIEVED_POLICY }),
        { status: 200 },
      );
      res.headers.delete("Content-Type");
      return res;
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    await expect(
      client.abacPolicies.retrieve(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("H4: combined attack — Object.hasOwn override + type-valid prototype pollution on multiple fields + empty-object response; module-load snapshot rejects", async () => {
    // Strongest combined attack: override `Object.hasOwn`, pollute
    // `Object.prototype` with TYPE-VALID values for several fields,
    // and emit `{}`. The validator's first field check (`id`) fires:
    // the module-load snapshot returns false on the missing own-
    // property regardless of the override + pollution.
    const hasOwnSpy = vi
      .spyOn(Object, "hasOwn")
      .mockImplementation(() => true);
    (Object.prototype as Record<string, unknown>).id = "polluted-id";
    (Object.prototype as Record<string, unknown>).orgId = "polluted-org";
    (Object.prototype as Record<string, unknown>).name = "polluted-name";
    try {
      const { client } = makeMockedClient([
        { body: { success: true, data: {} } },
      ]);
      await expect(
        client.abacPolicies.retrieve(POLICY_ID),
      ).rejects.toBeInstanceOf(AttestryError);
    } finally {
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).id;
      delete (Object.prototype as Record<string, unknown>).orgId;
      delete (Object.prototype as Record<string, unknown>).name;
    }
  });

  it("H5: a path-traversal-shaped id is rejected synchronously by assertValidPolicyId — no fetch, no path-traversal vector", async () => {
    // `.retrieve()` interpolates `id` into the path RAW (no
    // `encodeURIComponent`). That is safe ONLY because a non-UUID id
    // is pre-rejected. A path-traversal-shaped id (`..`, slashes,
    // `%2e`) contains characters absent from `UUID_REGEX`'s hex +
    // hyphen alphabet, so `assertValidPolicyId` throws synchronously
    // BEFORE any URL is built. No fetch is issued — there is no
    // path-traversal collapse to a sibling endpoint (the concern that
    // `decisions.retrieve`'s `encodePathSegment` `.`/`..` guard
    // exists for; abacPolicies' strict-UUID regex subsumes it).
    const { client, calls } = makeMockedClient([]);
    for (const evil of [
      "..",
      ".",
      "../../../../etc/passwd",
      "11111111-1111-1111-1111-111111111111/../../secrets",
      "%2e%2e%2f",
    ]) {
      expect(() => client.abacPolicies.retrieve(evil)).toThrow(TypeError);
      expect(() => client.abacPolicies.retrieve(evil)).toThrow(
        /RFC 4122/,
      );
    }
    expect(calls).toHaveLength(0);
  });

  it("H6: a lone-surrogate id is rejected synchronously as a TypeError (NOT a URIError) — no fetch", async () => {
    // `.retrieve()` does NO `encodeURIComponent` on the path segment
    // (design #2). The URIError defect class (`encodeURIComponent`
    // throws `URIError` on lone UTF-16 surrogates — carry-forward
    // invariant #32) therefore has no surface here: a lone-surrogate
    // id is not hex, so `UUID_REGEX` rejects it and `assertValidPolicyId`
    // throws a `TypeError` — the same error class the consumer
    // already expects from id-validation. No `URIError` can ever
    // leak, because no code path calls `encodeURIComponent`.
    const { client, calls } = makeMockedClient([]);
    for (const surrogate of [
      "\uD800",
      "\uDFFF",
      `${POLICY_ID}\uD800`,
    ]) {
      let caught: unknown;
      try {
        client.abacPolicies.retrieve(surrogate);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(TypeError);
      expect(caught).not.toBeInstanceOf(URIError);
      expect((caught as Error).message).toMatch(/RFC 4122/);
    }
    expect(calls).toHaveLength(0);
  });

  it("H7: a BigInt id is rejected synchronously (typeof 'bigint' is not 'string') — no fetch", async () => {
    // `typeof BigInt(1) === "bigint"`, NOT "number" / "string". A
    // consumer passing a BigInt id (e.g., from a numeric-id system)
    // is caught by `assertValidPolicyId`'s `typeof id !== "string"`
    // check — it does NOT slip through via coercion.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.retrieve(BigInt(1) as unknown as string),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("H8: kernel returns 403 for what should be 401 — SDK is a faithful courier on status (no client-side collapse)", async () => {
    // Adversarial: a hypothetical kernel regression mis-maps the
    // unauth path to 403 (treating "no auth" as "insufficient
    // permission"). The SDK surfaces whatever the kernel emits — it
    // does NOT collapse 403 → 401. This protects against the stale
    // `audit-log.ts` "401 for both" claim being mirrored into
    // abacPolicies; dual-auth admin routes keep 401 and 403 distinct.
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
      await client.abacPolicies.retrieve(POLICY_ID);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.status).not.toBe(401);
    }
  });

  it("H9: a pre-aborted call leaves no dirty state — a subsequent call succeeds (state isolation)", async () => {
    // A pre-aborted signal short-circuits the SDK BEFORE fetch is
    // issued. If the SDK had module-level mutable state, the rejected
    // call could corrupt the next call. Pin: the rejected call leaves
    // no dirty state; the second (clean) call consumes responses[0].
    const { client } = makeMockedClient([
      { body: { success: true, data: RETRIEVED_POLICY } },
    ]);
    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.retrieve(POLICY_ID, { signal: ac.signal }),
    ).rejects.toBeInstanceOf(AttestryError);

    const out = await client.abacPolicies.retrieve(POLICY_ID);
    expect(out.id).toBe(POLICY_ID);
  });

  it("H10: concurrent .retrieve() calls with distinct ids use independent URL construction — no id bleed", async () => {
    // Concurrency pin: 3 .retrieve() calls fired via Promise.all with
    // distinct ids. Each must hit its OWN id's path and resolve its
    // OWN response — no shared mutable state, no id bleed between
    // calls.
    const id0 = "00000000-0000-0000-0000-000000000001";
    const id1 = "00000000-0000-0000-0000-000000000002";
    const id2 = "00000000-0000-0000-0000-000000000003";
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { ...RETRIEVED_POLICY, id: id0 } } },
      { body: { success: true, data: { ...RETRIEVED_POLICY, id: id1 } } },
      { body: { success: true, data: { ...RETRIEVED_POLICY, id: id2 } } },
    ]);
    const [r0, r1, r2] = await Promise.all([
      client.abacPolicies.retrieve(id0),
      client.abacPolicies.retrieve(id1),
      client.abacPolicies.retrieve(id2),
    ]);
    expect(r0.id).toBe(id0);
    expect(r1.id).toBe(id1);
    expect(r2.id).toBe(id2);
    expect(calls).toHaveLength(3);
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${id0}`,
    );
    expect(calls[1].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${id1}`,
    );
    expect(calls[2].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${id2}`,
    );
  });
});
