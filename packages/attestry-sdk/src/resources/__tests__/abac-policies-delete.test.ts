import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  // Result-shape type import — pinned at compile time.
  AbacPolicy,
} from "../abac-policies.js";
import type { FetchLike } from "../../types.js";

// ─── abacPolicies.delete — DELETE one ABAC policy by id ─────────────────────
//
// Wire shape (kernel src/app/api/v1/abac-policies/[id]/route.ts):
//   DELETE /api/v1/abac-policies/[id]
//   Auth: x-api-key (requireSessionOrApiKey + apiKeyPermissions:[ADMIN])
//   No body.
//   200 OK: {success:true, data: <AbacPolicy row>}  — the DELETED row.
//   400 malformed UUID (kernel `badId` — SDK-pre-empted),
//   401 auth (no/invalid/expired key), 403 permission (non-ADMIN key),
//   404 not-found (AbacPolicyNotFoundError — id-embedded message
//       "ABAC policy <id> not found in this organization."),
//   429 rate-limit (assessmentLimiter, abac-policies-delete:${ip} key),
//   500 internal.
//
// 24th audit chain in the F.1 phase. Fourth method of the 5-method
// `abacPolicies` CRUD cluster (`.list` + `.create` shipped session 21;
// `.retrieve` + `.delete` ship session 22; `.update` follows).
//
// **FIRST SDK method using the HTTP DELETE verb** — every prior SDK
// route is GET / POST / PATCH.
//
// **Returns the DELETED row, NOT void** — the kernel emits
// `successResponse(row, 200)` carrying the just-deleted AbacPolicy.
//
// **writeAuditLog side effect** — every successful `.delete()` writes
// one `abac_policy.delete` audit-log entry (kernel-side; the SDK is a
// faithful courier and does not observe the write).
//
// **404 message is id-embedded** — `AbacPolicyNotFoundError` →
// "ABAC policy <id> not found in this organization." (distinct from
// `.retrieve()`'s INLINE "ABAC policy not found.").
//
// Adapted from `abac-policies-retrieve` (the GET-by-id sibling).

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
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const POLICY_ID = "11111111-1111-1111-1111-111111111111";
const ORG_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const USER_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff";

// The deleted row — the policy as it existed immediately before deletion.
const DELETED_POLICY: AbacPolicy = {
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

const DELETED_POLICY_NULLS: AbacPolicy = {
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

// The kernel `AbacPolicyNotFoundError` message — id-embedded.
const NOT_FOUND_MESSAGE = `ABAC policy ${POLICY_ID} not found in this organization.`;

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("abacPolicies.delete — happy path", () => {
  it("DELETEs /api/v1/abac-policies/<id> and returns the deleted row", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    const out = await client.abacPolicies.delete(POLICY_ID);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("DELETE");
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${POLICY_ID}`,
    );
    expect(out.id).toBe(POLICY_ID);
    expect(out.name).toBe("owner-can-edit-own");
  });

  it("returns the deleted row (a full AbacPolicy), NOT void / NOT {deleted:true}", async () => {
    // The resolved value is the complete 13-field policy as it existed
    // before deletion — a caller can log / audit / undo-prompt with it.
    const { client } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    const out = await client.abacPolicies.delete(POLICY_ID);
    expect(out).toEqual(DELETED_POLICY);
    expect(out).not.toBeUndefined();
  });

  it("interpolates the id into the path verbatim (UUID is URL-safe, no encoding)", async () => {
    const upperId = "ABCDEF01-2345-6789-ABCD-EF0123456789";
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { ...DELETED_POLICY, id: upperId } } },
    ]);
    await client.abacPolicies.delete(upperId);
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${upperId}`,
    );
  });

  it("preserves the recursive condition AST of the deleted row verbatim", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY_NULLS } },
    ]);
    const out = await client.abacPolicies.delete(
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

  it("preserves null fields (description / createdByUserId) as null on the deleted row", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY_NULLS } },
    ]);
    const out = await client.abacPolicies.delete(
      "22222222-2222-2222-2222-222222222222",
    );
    expect(out.description).toBeNull();
    expect(out.createdByUserId).toBeNull();
  });

  it("sends `x-api-key` header from the client config", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    await client.abacPolicies.delete(POLICY_ID);
    expect((calls[0].headers as Headers).get("x-api-key")).toBe("k");
  });

  it("forwards options.signal to the underlying fetch (abort-passthrough)", async () => {
    const fetchSpy = vi.fn(async (_url: unknown, init: unknown) => {
      const init_ = init as RequestInit;
      void init_.signal;
      return new Response(
        JSON.stringify({ success: true, data: DELETED_POLICY }),
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
    await client.abacPolicies.delete(POLICY_ID, { signal: ac.signal });
    const passedInit = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(passedInit.signal).toBeDefined();
  });
});

// ─── Input validation: id (synchronous TypeError; NO fetch issued) ─────────

describe("abacPolicies.delete — input validation: id", () => {
  it("throws TypeError when id is undefined (no fetch issued)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.delete(undefined as unknown as string),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is null", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.delete(null as unknown as string),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is not a string (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.delete(42 as unknown as string),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is an empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.abacPolicies.delete("")).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is a non-UUID string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.abacPolicies.delete("not-a-uuid")).toThrow(
      /`id` must be an RFC 4122 hyphenated UUID/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is a UUID with wrong segment lengths", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.delete("1111111-1111-1111-1111-111111111111"),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id has a non-hex character", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.delete("g1111111-1111-1111-1111-111111111111"),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id has surrounding whitespace (anchored regex)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.abacPolicies.delete(` ${POLICY_ID} `)).toThrow(
      /`id` must be an RFC 4122 hyphenated UUID/,
    );
    expect(calls).toHaveLength(0);
  });

  it("the malformed-id TypeError message echoes the offending value", () => {
    const { client } = makeMockedClient([]);
    expect(() => client.abacPolicies.delete("nope")).toThrow(/"nope"/);
  });

  it("accepts a lowercase-hex UUID", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    await client.abacPolicies.delete("0123abcd-4567-89ef-0123-456789abcdef");
  });

  it("accepts an uppercase-hex UUID (regex is case-insensitive)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    await client.abacPolicies.delete("0123ABCD-4567-89EF-0123-456789ABCDEF");
  });
});

// ─── Top-level error paths ──────────────────────────────────────────────────

describe("abacPolicies.delete — top-level error paths", () => {
  it("401 (no/invalid/expired api-key) → AttestryAPIError(401)", async () => {
    const { client } = makeMockedClient([
      { status: 401, body: { success: false, error: "Invalid API key." } },
    ]);
    const promise = client.abacPolicies.delete(POLICY_ID);
    await expect(promise).rejects.toBeInstanceOf(AttestryAPIError);
    await expect(promise).rejects.toMatchObject({ status: 401 });
  });

  it("403 (valid key without ADMIN permission) → AttestryAPIError(403) — DISTINCT from 401", async () => {
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
      await client.abacPolicies.delete(POLICY_ID);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.message).toContain("API key lacks required permission");
      expect(apiErr.status).not.toBe(401);
    }
  });

  it("404 (not found OR cross-org id) → AttestryAPIError(404) with the id-embedded message", async () => {
    // The kernel's deleteAbacPolicy throws AbacPolicyNotFoundError when
    // the (id, orgId)-scoped delete matches zero rows. The message
    // EMBEDS the id — distinct from `.retrieve()`'s inline message.
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: NOT_FOUND_MESSAGE },
      },
    ]);
    try {
      await client.abacPolicies.delete(POLICY_ID);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.message).toContain("not found in this organization");
      // The id is embedded in the message (AbacPolicyNotFoundError),
      // unlike `.retrieve()`'s inline "ABAC policy not found.".
      expect(apiErr.message).toContain(POLICY_ID);
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
      client.abacPolicies.delete(POLICY_ID),
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
      await client.abacPolicies.delete(POLICY_ID);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.message).not.toContain("deleteAbacPolicy");
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
      client.abacPolicies.delete(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });
});

// ─── 400 surface (SDK-pre-empted) ───────────────────────────────────────────

describe("abacPolicies.delete — 400 surface (SDK-pre-empted)", () => {
  it("a malformed id throws synchronously (TypeError) BEFORE any fetch — the kernel 400 is never reached", async () => {
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid policy id." } },
    ]);
    expect(() => client.abacPolicies.delete("malformed")).toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});

// ─── Retry semantics ────────────────────────────────────────────────────────

describe("abacPolicies.delete — retry semantics", () => {
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
        JSON.stringify({ success: true, data: DELETED_POLICY }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });
    const out = await client.abacPolicies.delete(POLICY_ID);
    expect(out.id).toBe(POLICY_ID);
    expect(callCount).toBeGreaterThanOrEqual(2);
  });

  it("does NOT retry on 404 (not-found is a permanent state)", async () => {
    const fetchSpy = vi.fn(async () => {
      return new Response(
        JSON.stringify({ success: false, error: NOT_FOUND_MESSAGE }),
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
      client.abacPolicies.delete(POLICY_ID),
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
      client.abacPolicies.delete(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryAPIError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});

// ─── Abort semantics ────────────────────────────────────────────────────────

describe("abacPolicies.delete — abort semantics", () => {
  it("rejects with AttestryError when options.signal is pre-aborted", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.delete(POLICY_ID, { signal: ac.signal }),
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
    const pending = client.abacPolicies.delete(POLICY_ID, {
      signal: ac.signal,
    });
    ac.abort();
    await expect(pending).rejects.toBeInstanceOf(AttestryError);
    resolveFetch(
      new Response(
        JSON.stringify({ success: true, data: DELETED_POLICY }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
  });
});

// ─── Response shape (P2 hardening — shared validateAbacPolicy) ──────────────

describe("abacPolicies.delete — response shape (P2 hardening)", () => {
  it("rejects when the deleted-row response is not an object (null) — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    const promise = client.abacPolicies.delete(POLICY_ID);
    await expect(promise).rejects.toBeInstanceOf(AttestryError);
    await expect(promise).rejects.toThrow(/expected an object response/);
  });

  it("the response-validator error message names `abacPolicies.delete` (not `.create`)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(client.abacPolicies.delete(POLICY_ID)).rejects.toThrow(
      /abacPolicies\.delete:/,
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
    "rejects when the deleted row's $field is wrong type ($type)",
    async ({ field, value, type }) => {
      const malformed = { ...DELETED_POLICY, [field]: value };
      const { client } = makeMockedClient([
        { body: { success: true, data: malformed } },
      ]);
      const promise = client.abacPolicies.delete(POLICY_ID);
      await expect(promise).rejects.toBeInstanceOf(AttestryError);
      await expect(promise).rejects.toThrow(
        new RegExp(`response\\.${field}.*${type}`),
      );
    },
  );

  it("accepts the deleted row's description = null (boundary; string | null)", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...DELETED_POLICY, description: null } },
      },
    ]);
    const out = await client.abacPolicies.delete(POLICY_ID);
    expect(out.description).toBeNull();
  });

  it("rejects when the deleted row's description is a number", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...DELETED_POLICY, description: 42 } },
      },
    ]);
    await expect(client.abacPolicies.delete(POLICY_ID)).rejects.toThrow(
      /response\.description.*string or null.*number/,
    );
  });

  it("accepts the deleted row's createdByUserId = null (boundary; string | null)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...DELETED_POLICY, createdByUserId: null },
        },
      },
    ]);
    const out = await client.abacPolicies.delete(POLICY_ID);
    expect(out.createdByUserId).toBeNull();
  });

  it("rejects when the deleted row's condition is null", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...DELETED_POLICY, condition: null } },
      },
    ]);
    await expect(client.abacPolicies.delete(POLICY_ID)).rejects.toThrow(
      /response\.condition.*non-null object/,
    );
  });

  it("rejects when the deleted row's condition is an array", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...DELETED_POLICY, condition: [] } },
      },
    ]);
    await expect(client.abacPolicies.delete(POLICY_ID)).rejects.toThrow(
      /response\.condition.*non-null object.*array/,
    );
  });
});

// ─── Missing own-property — coverage for `:undefined` ternary arms ──────────

describe("abacPolicies.delete — missing own-property exercises :undefined ternary arm", () => {
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
    const partial = { ...DELETED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>)[field];
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(
      client.abacPolicies.delete(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ─── URL & request invariants ───────────────────────────────────────────────

describe("abacPolicies.delete — URL & request invariants", () => {
  it("uses DELETE (NOT GET / POST / PATCH)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    await client.abacPolicies.delete(POLICY_ID);
    expect(calls[0].method).toBe("DELETE");
  });

  it("hits exact path /api/v1/abac-policies/<id> (with id segment, no query string)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    await client.abacPolicies.delete(POLICY_ID);
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${POLICY_ID}`,
    );
    expect(calls[0].url).not.toContain("?");
  });

  it("does NOT send a request body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    await client.abacPolicies.delete(POLICY_ID);
    expect(calls[0].body).toBeUndefined();
  });

  it("response-shape validation runs AFTER the transport envelope unwrap", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: "not-an-object" } },
    ]);
    await expect(
      client.abacPolicies.delete(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("passes a bare (non-enveloped) response body through the transport, then rejects a malformed one via validateAbacPolicy", async () => {
    // The transport unwraps `{success:true, data}` only when the
    // envelope is present and otherwise passes the parsed body through
    // verbatim (forward-compat — see transport.ts). A non-policy bare
    // body is rejected by validateAbacPolicy.
    const { client } = makeMockedClient([
      { bodyText: JSON.stringify({ unexpected: "shape" }) },
    ]);
    await expect(
      client.abacPolicies.delete(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ─── Prototype-pollution defense (response side) ────────────────────────────

describe("abacPolicies.delete — prototype-pollution defense (response side)", () => {
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).id;
    delete (Object.prototype as Record<string, unknown>).name;
    delete (Object.prototype as Record<string, unknown>).condition;
  });

  it("polluted Object.prototype.id does NOT mask a missing id field", async () => {
    (Object.prototype as Record<string, unknown>).id = "polluted-id";
    const partial = { ...DELETED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).id;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(client.abacPolicies.delete(POLICY_ID)).rejects.toThrow(
      /response\.id to be a string.*undefined/,
    );
  });

  it("polluted Object.prototype.name (type-valid string) does NOT mask a missing name field", async () => {
    (Object.prototype as Record<string, unknown>).name = "polluted-name";
    const partial = { ...DELETED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).name;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(client.abacPolicies.delete(POLICY_ID)).rejects.toThrow(
      /response\.name to be a string.*undefined/,
    );
  });

  it("polluted Object.prototype.condition (type-valid object) does NOT mask a missing condition field", async () => {
    (Object.prototype as Record<string, unknown>).condition = {
      op: "exists",
      attr: "principal.id",
    };
    const partial = { ...DELETED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).condition;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(client.abacPolicies.delete(POLICY_ID)).rejects.toThrow(
      /response\.condition.*non-null object.*undefined/,
    );
  });

  it("does NOT surface Object.prototype fields as own-properties of the deleted row", async () => {
    (Object.prototype as Record<string, unknown>).surprise = "polluted-extra";
    try {
      const { client } = makeMockedClient([
        { body: { success: true, data: DELETED_POLICY } },
      ]);
      const out = await client.abacPolicies.delete(POLICY_ID);
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
// **H5 + H6 stress the design-#2 decision** — `.delete()` interpolates
// the `id` into the path RAW (no `encodeURIComponent`, no URIError
// defense), mirroring `batch.get`. That is only safe because
// `assertValidPolicyId` pre-rejects any non-UUID `id` synchronously.
// H5 (path-traversal-shaped id) and H6 (lone-surrogate id) prove the
// pre-validation is the load-bearing defense: an adversarial id never
// reaches the URL — and `.delete()` is the FIRST DELETE-verb method,
// so a path-traversal collapse would be especially dangerous (a stray
// `..` could turn a delete-by-id into a delete against a sibling
// endpoint).
//
// **H11 is `.delete`-specific** — the 404 message is id-embedded
// (`AbacPolicyNotFoundError`), unlike `.retrieve()`'s inline message.
// H11 pins that the SDK is a faithful courier on that message body.

describe("abacPolicies.delete — hostile round (residual gaps)", () => {
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
      const partial = { ...DELETED_POLICY } as Partial<AbacPolicy>;
      delete (partial as Record<string, unknown>).id;
      const { client } = makeMockedClient([
        { body: { success: true, data: partial } },
      ]);
      await expect(client.abacPolicies.delete(POLICY_ID)).rejects.toThrow(
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
      client.abacPolicies.delete(POLICY_ID),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("H3: P3 content-type fail-fast — 200 with NO Content-Type header rejects with AttestryAPIError", async () => {
    const fetchSpy = vi.fn(async () => {
      const res = new Response(
        JSON.stringify({ success: true, data: DELETED_POLICY }),
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
      client.abacPolicies.delete(POLICY_ID),
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
        client.abacPolicies.delete(POLICY_ID),
      ).rejects.toBeInstanceOf(AttestryError);
    } finally {
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).id;
      delete (Object.prototype as Record<string, unknown>).orgId;
      delete (Object.prototype as Record<string, unknown>).name;
    }
  });

  it("H5: a path-traversal-shaped id is rejected synchronously by assertValidPolicyId — no fetch, no path-traversal vector", async () => {
    // `.delete()` interpolates `id` into the path RAW (no
    // `encodeURIComponent`). That is safe ONLY because a non-UUID id
    // is pre-rejected. A path-traversal-shaped id (`..`, slashes,
    // `%2e`) contains characters absent from `UUID_REGEX`'s hex +
    // hyphen alphabet, so `assertValidPolicyId` throws synchronously
    // BEFORE any URL is built. No fetch is issued — there is no
    // path-traversal collapse to a sibling endpoint. This matters
    // most for `.delete()`: a stray `..` reaching the URL could turn
    // a delete-by-id into a destructive call against another path.
    const { client, calls } = makeMockedClient([]);
    for (const evil of [
      "..",
      ".",
      "../../../../etc/passwd",
      "11111111-1111-1111-1111-111111111111/../../secrets",
      "%2e%2e%2f",
    ]) {
      expect(() => client.abacPolicies.delete(evil)).toThrow(TypeError);
      expect(() => client.abacPolicies.delete(evil)).toThrow(/RFC 4122/);
    }
    expect(calls).toHaveLength(0);
  });

  it("H6: a lone-surrogate id is rejected synchronously as a TypeError (NOT a URIError) — no fetch", async () => {
    // `.delete()` does NO `encodeURIComponent` on the path segment
    // (design #2). The URIError defect class (`encodeURIComponent`
    // throws `URIError` on lone UTF-16 surrogates — carry-forward
    // invariant #32) therefore has no surface here: a lone-surrogate
    // id is not hex, so `UUID_REGEX` rejects it and `assertValidPolicyId`
    // throws a `TypeError` — the same error class the consumer
    // already expects from id-validation. No `URIError` can ever
    // leak, because no code path calls `encodeURIComponent`.
    const { client, calls } = makeMockedClient([]);
    for (const surrogate of ["\uD800", "\uDFFF", `${POLICY_ID}\uD800`]) {
      let caught: unknown;
      try {
        client.abacPolicies.delete(surrogate);
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
      client.abacPolicies.delete(BigInt(1) as unknown as string),
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
      await client.abacPolicies.delete(POLICY_ID);
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
      { body: { success: true, data: DELETED_POLICY } },
    ]);
    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.delete(POLICY_ID, { signal: ac.signal }),
    ).rejects.toBeInstanceOf(AttestryError);

    const out = await client.abacPolicies.delete(POLICY_ID);
    expect(out.id).toBe(POLICY_ID);
  });

  it("H10: concurrent .delete() calls with distinct ids use independent URL construction — no id bleed", async () => {
    // Concurrency pin: 3 .delete() calls fired via Promise.all with
    // distinct ids. Each must hit its OWN id's path and resolve its
    // OWN response — no shared mutable state, no id bleed between
    // calls.
    const id0 = "00000000-0000-0000-0000-000000000001";
    const id1 = "00000000-0000-0000-0000-000000000002";
    const id2 = "00000000-0000-0000-0000-000000000003";
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { ...DELETED_POLICY, id: id0 } } },
      { body: { success: true, data: { ...DELETED_POLICY, id: id1 } } },
      { body: { success: true, data: { ...DELETED_POLICY, id: id2 } } },
    ]);
    const [r0, r1, r2] = await Promise.all([
      client.abacPolicies.delete(id0),
      client.abacPolicies.delete(id1),
      client.abacPolicies.delete(id2),
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

  it("H11: the kernel's id-embedded 404 message is surfaced VERBATIM — the SDK does not reconstruct it client-side from the requested id", async () => {
    // `.delete()`'s 404 comes from `AbacPolicyNotFoundError`, whose
    // message EMBEDS an id (distinct from `.retrieve()`'s inline
    // "ABAC policy not found."). Adversarial: a kernel regression (or
    // a body-rewriting proxy) emits a 404 whose embedded id is a
    // DIFFERENT uuid than the one the consumer requested. The SDK is
    // a faithful courier on the error body — it surfaces the kernel's
    // `error` string as-is (AttestryAPIError.message = extractMessage
    // of the parsed body; the requested id lives only in the URL,
    // never in the message). If the SDK had instead synthesized the
    // message client-side from the requested id, the kernel's id
    // would be absent and the requested id present. Pin the courier
    // contract: the kernel's id appears, the requested id does not.
    const kernelEmbeddedId = "99999999-9999-9999-9999-999999999999";
    const kernelMessage = `ABAC policy ${kernelEmbeddedId} not found in this organization.`;
    const { client } = makeMockedClient([
      { status: 404, body: { success: false, error: kernelMessage } },
    ]);
    try {
      await client.abacPolicies.delete(POLICY_ID);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      // The kernel's id-embedded message is surfaced verbatim...
      expect(apiErr.message).toContain(kernelEmbeddedId);
      expect(apiErr.message).toContain("not found in this organization");
      // ...and the SDK did NOT reconstruct the message from the
      // requested id (POLICY_ID shares no substring with the kernel's
      // id, so its absence proves no client-side synthesis).
      expect(apiErr.message).not.toContain(POLICY_ID);
    }
  });
});
