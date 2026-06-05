import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  // Result-shape + input-shape type imports — pinned at compile time.
  // If `AbacPolicy` / `AbacPolicyUpdateInput` is dropped from the
  // resource's exports, this file fails to compile and the test run
  // aborts before any pin runs.
  AbacPolicy,
  AbacPolicyUpdateInput,
  AbacCondition,
} from "../abac-policies.js";
import type { FetchLike } from "../../types.js";

// ─── abacPolicies.update — PATCH one ABAC policy by id ──────────────────────
//
// Wire shape (kernel src/app/api/v1/abac-policies/[id]/route.ts):
//   PATCH /api/v1/abac-policies/[id]
//   Auth: x-api-key (requireSessionOrApiKey + apiKeyPermissions:[ADMIN])
//   Body: updateAbacPolicySchema (Zod .strict() — 8 OPTIONAL fields +
//     a .refine() rejecting an all-undefined body)
//   200 OK: {success:true, data: <AbacPolicy row>}  — the UPDATED row.
//   400 malformed UUID (kernel `badId` — SDK-pre-empted),
//   401 auth (no/invalid/expired key), 403 permission (non-ADMIN key),
//   404 not-found (AbacPolicyNotFoundError — id-embedded message
//       "ABAC policy <id> not found in this organization."),
//   409 name conflict (AbacPolicyNameConflictError),
//   422 validation (3 paths: BodyParseError / ZodError dead-arm /
//       AbacPolicyValidationError),
//   429 rate-limit (assessmentLimiter, abac-policies-patch:${ip} key),
//   500 internal.
//
// 25th audit chain in the F.1 phase. FIFTH and final method of the
// 5-method `abacPolicies` CRUD cluster — completes list / create /
// retrieve / update / delete.
//
// **SECOND SDK method using the HTTP PATCH verb** (`incidents.update`
// is the first).
//
// **Partial update — every input field is optional.** The SDK builds
// the body from the present-and-not-undefined fields only.
//
// **Empty-patch pre-validation** — the kernel's updateAbacPolicySchema
// `.refine()` rejects a body with no updatable field; the SDK
// pre-rejects an empty patch synchronously with a TypeError.
//
// **6 named-error catch arms — the LARGEST on the SDK** (AuthError,
// BodyParseError, ZodError, AbacPolicyValidationError,
// AbacPolicyNameConflictError, AbacPolicyNotFoundError).
//
// **404 message is id-embedded** — `AbacPolicyNotFoundError` →
// "ABAC policy <id> not found in this organization." (same shape as
// `.delete()`; distinct from `.retrieve()`'s INLINE message).
//
// Adapted from `abac-policies-create` (POST body + 422 fan-out) +
// `abac-policies-delete` (PATCH-by-id path + id pre-validation).

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

// The updated row — the policy as it exists AFTER the patch is
// applied. `updatedAt` is later than `createdAt` (a patch happened).
const UPDATED_POLICY: AbacPolicy = {
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
  updatedAt: "2026-05-15T14:30:00.000Z",
};

// An updated row with a compound `and` condition + null description +
// null createdByUserId (kernel `?? null` coalesce on unset values).
const UPDATED_POLICY_NULLS: AbacPolicy = {
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

describe("abacPolicies.update — happy path", () => {
  it("PATCHes /api/v1/abac-policies/<id> and returns the updated row", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    const out = await client.abacPolicies.update(POLICY_ID, {
      enabled: false,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("PATCH");
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${POLICY_ID}`,
    );
    expect(out.id).toBe(POLICY_ID);
  });

  it("sends ONLY the patched fields in the body (single-field patch)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { enabled: false });
    expect(JSON.parse(calls[0].body as string)).toEqual({ enabled: false });
  });

  it("sends ONLY the patched fields in the body (multi-field patch)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, {
      name: "renamed-policy",
      priority: 5,
      effect: "deny",
    });
    expect(JSON.parse(calls[0].body as string)).toEqual({
      name: "renamed-policy",
      priority: 5,
      effect: "deny",
    });
  });

  it("INCLUDES description=null in the body (clears the description)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY_NULLS } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { description: null });
    expect(JSON.parse(calls[0].body as string)).toEqual({ description: null });
  });

  it("patches the recursive condition AST and returns the updated row", async () => {
    const newCondition: AbacCondition = {
      op: "or",
      clauses: [
        { op: "exists", attr: "principal.id" },
        { op: "eq", attr: "resource.public", value: true },
      ],
    };
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...UPDATED_POLICY, condition: newCondition },
        },
      },
    ]);
    const out = await client.abacPolicies.update(POLICY_ID, {
      condition: newCondition,
    });
    expect(JSON.parse(calls[0].body as string)).toEqual({
      condition: newCondition,
    });
    expect(out.condition).toEqual(newCondition);
  });

  it("returns the full 13-field row verbatim (faithful courier on per-row shape)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    const out = await client.abacPolicies.update(POLICY_ID, { priority: 100 });
    expect(out).toEqual(UPDATED_POLICY);
  });

  it("preserves null fields (description / createdByUserId) as null on the updated row", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY_NULLS } },
    ]);
    const out = await client.abacPolicies.update(POLICY_ID, {
      enabled: true,
    });
    expect(out.description).toBeNull();
    expect(out.createdByUserId).toBeNull();
  });

  it("interpolates the id into the path verbatim (UUID is URL-safe, no encoding)", async () => {
    const upperId = "ABCDEF01-2345-6789-ABCD-EF0123456789";
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { ...UPDATED_POLICY, id: upperId } } },
    ]);
    await client.abacPolicies.update(upperId, { enabled: false });
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${upperId}`,
    );
  });

  it("sets request Content-Type to application/json", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { enabled: false });
    expect((calls[0].headers as Headers).get("content-type")).toBe(
      "application/json",
    );
  });

  it("sends `x-api-key` header from the client config", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { enabled: false });
    expect((calls[0].headers as Headers).get("x-api-key")).toBe("k");
  });

  it("forwards options.signal to the underlying fetch (abort-passthrough)", async () => {
    const fetchSpy = vi.fn(async (_url: unknown, init: unknown) => {
      const init_ = init as RequestInit;
      void init_.signal;
      return new Response(
        JSON.stringify({ success: true, data: UPDATED_POLICY }),
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
    await client.abacPolicies.update(
      POLICY_ID,
      { enabled: false },
      { signal: ac.signal },
    );
    const passedInit = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(passedInit.signal).toBeDefined();
  });

  it("patches all 8 fields at once (full-overwrite patch)", async () => {
    const fullPatch: AbacPolicyUpdateInput = {
      name: "fully-rewritten",
      description: "new description",
      resource: "documents",
      action: "manage",
      effect: "deny",
      condition: { op: "exists", attr: "principal.id" },
      priority: 999,
      enabled: false,
    };
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, fullPatch);
    expect(JSON.parse(calls[0].body as string)).toEqual(fullPatch);
  });
});

// ─── Input validation: id (synchronous TypeError; NO fetch issued) ─────────

describe("abacPolicies.update — input validation: id", () => {
  it("throws TypeError when id is undefined (no fetch issued)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(undefined as unknown as string, {
        enabled: false,
      }),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is null", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(null as unknown as string, {
        enabled: false,
      }),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is not a string (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(42 as unknown as string, { enabled: false }),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is an empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.abacPolicies.update("", { enabled: false })).toThrow(
      /`id` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is a non-UUID string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update("not-a-uuid", { enabled: false }),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id is a UUID with wrong segment lengths", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update("1111111-1111-1111-1111-111111111111", {
        enabled: false,
      }),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id has a non-hex character", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update("g1111111-1111-1111-1111-111111111111", {
        enabled: false,
      }),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when id has surrounding whitespace (anchored regex)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(` ${POLICY_ID} `, { enabled: false }),
    ).toThrow(/`id` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("the malformed-id TypeError message echoes the offending value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update("nope", { enabled: false }),
    ).toThrow(/"nope"/);
  });

  it("validates the id BEFORE the input body (id-first precedence)", () => {
    // A malformed id + an empty patch — the id error fires first,
    // mirror of the kernel PATCH handler (`badId` before `parseBody`).
    const { client, calls } = makeMockedClient([]);
    expect(() => client.abacPolicies.update("bad-id", {})).toThrow(
      /`id` must be an RFC 4122 hyphenated UUID/,
    );
    expect(calls).toHaveLength(0);
  });

  it("accepts a lowercase-hex UUID", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(
      "0123abcd-4567-89ef-0123-456789abcdef",
      { enabled: false },
    );
  });

  it("accepts an uppercase-hex UUID (regex is case-insensitive)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(
      "0123ABCD-4567-89EF-0123-456789ABCDEF",
      { enabled: false },
    );
  });
});

// ─── Input validation: top-level input shape ────────────────────────────────

describe("abacPolicies.update — input validation: top-level shape", () => {
  it("throws TypeError when input is null", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(
        POLICY_ID,
        null as unknown as AbacPolicyUpdateInput,
      ),
    ).toThrow(/`input` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when input is undefined (no second argument)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(
        POLICY_ID,
        undefined as unknown as AbacPolicyUpdateInput,
      ),
    ).toThrow(/`input` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when input is an array", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(
        POLICY_ID,
        [] as unknown as AbacPolicyUpdateInput,
      ),
    ).toThrow(/`input` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when input is a primitive (string)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(
        POLICY_ID,
        "not-an-object" as unknown as AbacPolicyUpdateInput,
      ),
    ).toThrow(/`input` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });
});

// ─── Empty-patch pre-validation (synchronous TypeError; NO fetch) ──────────

describe("abacPolicies.update — empty-patch pre-validation", () => {
  it("throws TypeError when input is an empty object {}", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.abacPolicies.update(POLICY_ID, {})).toThrow(
      /at least one updatable field/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a single field is present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, { name: undefined }),
    ).toThrow(/at least one updatable field/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when ALL 8 fields are present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        name: undefined,
        description: undefined,
        resource: undefined,
        action: undefined,
        effect: undefined,
        condition: undefined,
        priority: undefined,
        enabled: undefined,
      }),
    ).toThrow(/at least one updatable field/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when the patch carries ONLY unknown keys", () => {
    // The SDK builds the body from the 8 known fields only; a patch
    // with no known field produces a zero-key body → empty-patch
    // TypeError (the kernel's `.strict()` would 422 it; the SDK
    // pre-rejects it as an empty patch — both reject, the SDK earlier).
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        totallyUnknown: 1,
        anotherTypo: true,
      } as unknown as AbacPolicyUpdateInput),
    ).toThrow(/at least one updatable field/);
    expect(calls).toHaveLength(0);
  });

  it("the empty-patch TypeError is a TypeError instance", () => {
    const { client } = makeMockedClient([]);
    expect(() => client.abacPolicies.update(POLICY_ID, {})).toThrow(
      TypeError,
    );
  });

  it("does NOT throw empty-patch when at least one field is present and defined", async () => {
    // `description: null` is a present field — a valid non-empty patch.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY_NULLS } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { description: null });
    expect(calls).toHaveLength(1);
  });
});

// ─── Input validation: name (optional string 1-128) ─────────────────────────

describe("abacPolicies.update — input validation: name", () => {
  it("throws TypeError when name is present but not a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        name: 123 as unknown as string,
      }),
    ).toThrow(/`name` must be a string when present/);
  });

  it("throws TypeError when name is an empty string", () => {
    const { client } = makeMockedClient([]);
    expect(() => client.abacPolicies.update(POLICY_ID, { name: "" })).toThrow(
      /`name` must be a non-empty string when present/,
    );
  });

  it("throws TypeError when name exceeds 128 chars (kernel MAX_POLICY_NAME_LENGTH)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, { name: "x".repeat(129) }),
    ).toThrow(/max length of 128 chars/);
  });

  it("accepts name at exactly 128 chars (boundary)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { name: "x".repeat(128) });
  });
});

// ─── Input validation: description (optional string | null) ─────────────────

describe("abacPolicies.update — input validation: description", () => {
  it("throws TypeError when description is present and a number", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        description: 42 as unknown as string,
      }),
    ).toThrow(/`description` must be a string or null when present/);
  });

  it("throws TypeError when description exceeds 2000 chars (kernel max)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, { description: "x".repeat(2001) }),
    ).toThrow(/`description` exceeds the kernel's max length of 2000 chars/);
  });

  it("accepts description at exactly 2000 chars (boundary)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, {
      description: "x".repeat(2000),
    });
  });

  it("accepts description = null (clears the field)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY_NULLS } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { description: null });
  });
});

// ─── Input validation: resource (optional closed-enum) ──────────────────────

describe("abacPolicies.update — input validation: resource", () => {
  it("throws TypeError when resource is present but not a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        resource: 42 as unknown as "systems",
      }),
    ).toThrow(/`resource` must be a string when present/);
  });

  it("throws TypeError when resource is an unknown enum value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        resource: "made-up-resource" as unknown as "systems",
      }),
    ).toThrow(/`resource` must be one of \[.+\] \(got "made-up-resource"\)/);
  });

  it.each([
    "systems",
    "assessments",
    "documents",
    "attestations",
    "evidence",
    "users",
    "api_keys",
    "audit_log",
    "organization",
    "regulations",
  ])("accepts resource '%s' (closed-enum member)", async (resource) => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, {
      resource: resource as AbacPolicyUpdateInput["resource"],
    });
  });
});

// ─── Input validation: action (optional closed-enum) ────────────────────────

describe("abacPolicies.update — input validation: action", () => {
  it("throws TypeError when action is present but not a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        action: 42 as unknown as "read",
      }),
    ).toThrow(/`action` must be a string when present/);
  });

  it("throws TypeError when action is an unknown enum value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        action: "made-up-action" as unknown as "read",
      }),
    ).toThrow(/`action` must be one of \[.+\] \(got "made-up-action"\)/);
  });

  it.each(["create", "read", "update", "delete", "manage"])(
    "accepts action '%s' (closed-enum member)",
    async (action) => {
      const { client } = makeMockedClient([
        { body: { success: true, data: UPDATED_POLICY } },
      ]);
      await client.abacPolicies.update(POLICY_ID, {
        action: action as AbacPolicyUpdateInput["action"],
      });
    },
  );
});

// ─── Input validation: effect (optional closed-enum) ────────────────────────

describe("abacPolicies.update — input validation: effect", () => {
  it("throws TypeError when effect is present but not a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        effect: 1 as unknown as "allow",
      }),
    ).toThrow(/`effect` must be a string when present/);
  });

  it("throws TypeError when effect is an unknown enum value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        effect: "maybe" as unknown as "allow",
      }),
    ).toThrow(/`effect` must be one of \[allow, deny\] \(got "maybe"\)/);
  });

  it.each(["allow", "deny"])(
    "accepts effect '%s' (closed-enum member)",
    async (effect) => {
      const { client } = makeMockedClient([
        { body: { success: true, data: UPDATED_POLICY } },
      ]);
      await client.abacPolicies.update(POLICY_ID, {
        effect: effect as AbacPolicyUpdateInput["effect"],
      });
    },
  );
});

// ─── Input validation: condition (optional; AST defers to server) ───────────

describe("abacPolicies.update — input validation: condition", () => {
  it("throws TypeError when condition is null", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        condition: null as unknown as AbacCondition,
      }),
    ).toThrow(/`condition` must be a non-null object when present/);
  });

  it("throws TypeError when condition is an array", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        condition: [] as unknown as AbacCondition,
      }),
    ).toThrow(/`condition` must be a non-null object when present/);
  });

  it("throws TypeError when condition is a scalar (string)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        condition: "exists" as unknown as AbacCondition,
      }),
    ).toThrow(/`condition` must be a non-null object when present/);
  });

  it("accepts a valid leaf condition object", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, {
      condition: { op: "exists", attr: "principal.id" },
    });
  });

  it("does NOT pre-validate the AST grammar — an invalid-looking object rides through verbatim", async () => {
    // The SDK checks only "is this a non-null object". The recursive
    // AST grammar is the kernel canonical validator's responsibility.
    const malformedAst = { not_a_valid_op: "garbage" };
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, {
      condition: malformedAst as unknown as AbacCondition,
    });
    expect(JSON.parse(calls[0].body as string)).toEqual({
      condition: malformedAst,
    });
  });
});

// ─── Input validation: priority (optional int 0-1000) ───────────────────────

describe("abacPolicies.update — input validation: priority", () => {
  it("throws TypeError when priority is present but not a number", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        priority: "100" as unknown as number,
      }),
    ).toThrow(/`priority` must be a finite number when present/);
  });

  it("throws TypeError when priority is NaN", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, { priority: NaN }),
    ).toThrow(/`priority` must be a finite number when present/);
  });

  it("throws TypeError when priority is Infinity", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, { priority: Infinity }),
    ).toThrow(/`priority` must be a finite number when present/);
  });

  it("throws TypeError when priority is a float (non-integer)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, { priority: 12.5 }),
    ).toThrow(/`priority` must be an integer when present/);
  });

  it("throws TypeError when priority is below MIN_PRIORITY (0)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, { priority: -1 }),
    ).toThrow(/`priority` must be in range \[0, 1000\]/);
  });

  it("throws TypeError when priority is above MAX_PRIORITY (1000)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, { priority: 1001 }),
    ).toThrow(/`priority` must be in range \[0, 1000\]/);
  });

  it.each([0, 100, 500, 1000])(
    "accepts priority %i (in-range integer)",
    async (priority) => {
      const { client } = makeMockedClient([
        { body: { success: true, data: UPDATED_POLICY } },
      ]);
      await client.abacPolicies.update(POLICY_ID, { priority });
    },
  );
});

// ─── Input validation: enabled (optional boolean) ───────────────────────────

describe("abacPolicies.update — input validation: enabled", () => {
  it("throws TypeError when enabled is present but a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        enabled: "true" as unknown as boolean,
      }),
    ).toThrow(/`enabled` must be a boolean when present/);
  });

  it("throws TypeError when enabled is a number (1)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(POLICY_ID, {
        enabled: 1 as unknown as boolean,
      }),
    ).toThrow(/`enabled` must be a boolean when present/);
  });

  it.each([true, false])("accepts enabled=%s", async (enabled) => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { enabled });
  });
});

// ─── Body construction ──────────────────────────────────────────────────────

describe("abacPolicies.update — body construction", () => {
  it("OMITS a field explicitly set to undefined (alongside a present field)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, {
      name: undefined,
      enabled: false,
    });
    // `name: undefined` is treated as omission — only `enabled` rides.
    expect(JSON.parse(calls[0].body as string)).toEqual({ enabled: false });
  });

  it("distinguishes description=undefined (omit) from description=null (clear)", async () => {
    const { client: c1, calls: calls1 } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await c1.abacPolicies.update(POLICY_ID, {
      description: undefined,
      priority: 7,
    });
    // undefined → omitted entirely.
    expect(JSON.parse(calls1[0].body as string)).toEqual({ priority: 7 });

    const { client: c2, calls: calls2 } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await c2.abacPolicies.update(POLICY_ID, {
      description: null,
      priority: 7,
    });
    // null → present in the body (explicit clear).
    expect(JSON.parse(calls2[0].body as string)).toEqual({
      description: null,
      priority: 7,
    });
  });

  it("INCLUDES priority=0 in the body (boundary; preserves intent)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { priority: 0 });
    expect(JSON.parse(calls[0].body as string)).toEqual({ priority: 0 });
  });

  it("INCLUDES enabled=false in the body (boundary; preserves intent)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { enabled: false });
    expect(JSON.parse(calls[0].body as string)).toEqual({ enabled: false });
  });

  it("DROPS unknown keys from the body (only the 8 known fields ride)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, {
      enabled: true,
      bogusKey: "ignored",
    } as unknown as AbacPolicyUpdateInput);
    expect(JSON.parse(calls[0].body as string)).toEqual({ enabled: true });
  });
});

// ─── Top-level error paths ──────────────────────────────────────────────────

describe("abacPolicies.update — top-level error paths", () => {
  it("401 (no/invalid/expired api-key) → AttestryAPIError(401)", async () => {
    const { client } = makeMockedClient([
      { status: 401, body: { success: false, error: "Invalid API key." } },
    ]);
    const promise = client.abacPolicies.update(POLICY_ID, { enabled: false });
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
      await client.abacPolicies.update(POLICY_ID, { enabled: false });
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
    const { client } = makeMockedClient([
      { status: 404, body: { success: false, error: NOT_FOUND_MESSAGE } },
    ]);
    try {
      await client.abacPolicies.update(POLICY_ID, { enabled: false });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.message).toContain("not found in this organization");
      // The id is embedded in the message (AbacPolicyNotFoundError),
      // same shape as `.delete()`'s 404.
      expect(apiErr.message).toContain(POLICY_ID);
    }
  });

  it("409 (name conflict — patching to a taken name) → AttestryAPIError(409)", async () => {
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error:
            'An ABAC policy named "taken-name" already exists in this organization.',
        },
      },
    ]);
    try {
      await client.abacPolicies.update(POLICY_ID, { name: "taken-name" });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(409);
      expect(apiErr.message).toContain("already exists in this organization");
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
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
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
      await client.abacPolicies.update(POLICY_ID, { enabled: false });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.message).not.toContain("updateAbacPolicy");
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
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });
});

// ─── 422 wire-shape fan-out (three distinct details shapes) ─────────────────

describe("abacPolicies.update — 422 wire-shape fan-out", () => {
  it("BodyParseError (Zod via parseBody) → 422 with details: Array<{path, message}>", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            { path: "priority", message: "Number must be less than or equal to 1000" },
          ],
        },
      },
    ]);
    try {
      await client.abacPolicies.update(POLICY_ID, { enabled: false });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      const wireBody = apiErr.details as {
        error: string;
        details: Array<{ path: string; message: string }>;
      };
      expect(wireBody.error).toBe("Validation failed.");
      expect(Array.isArray(wireBody.details)).toBe(true);
      expect(wireBody.details[0].path).toBe("priority");
    }
  });

  it("BodyParseError empty-patch refine → 422 (the kernel `.refine()` rejection — SDK normally pre-empts this)", async () => {
    // The kernel's updateAbacPolicySchema `.refine()` emits
    // "PATCH body must include at least one updatable field". The SDK
    // pre-rejects an empty patch synchronously, so this 422 is
    // reachable from a consumer only via an `as any` bypass — pin the
    // wire shape regardless, as a stable contract.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            {
              path: "",
              message: "PATCH body must include at least one updatable field",
            },
          ],
        },
      },
    ]);
    try {
      await client.abacPolicies.update(POLICY_ID, { enabled: false });
      throw new Error("should have thrown");
    } catch (err) {
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
    }
  });

  it("AbacPolicyValidationError (canonical AST validator) → 422 with details: {errors: string[]}", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error:
            'ABAC policy validation failed: $.clauses[0].op: unknown operator "foobar"',
          details: {
            errors: ['$.clauses[0].op: unknown operator "foobar"'],
          },
        },
      },
    ]);
    try {
      await client.abacPolicies.update(POLICY_ID, {
        condition: { op: "exists", attr: "principal.id" },
      });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      const wireBody = apiErr.details as {
        error: string;
        details: { errors: string[] };
      };
      expect(wireBody.error).toContain("ABAC policy validation failed");
      expect(Array.isArray(wireBody.details)).toBe(false);
      expect(Array.isArray(wireBody.details.errors)).toBe(true);
    }
  });

  it("ZodError defensive arm (DEAD on happy path) → 422 with details: ZodIssue[]", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            {
              code: "invalid_type",
              expected: "string",
              received: "number",
              path: ["name"],
              message: "Expected string, received number",
            },
          ],
        },
      },
    ]);
    try {
      await client.abacPolicies.update(POLICY_ID, { enabled: false });
      throw new Error("should have thrown");
    } catch (err) {
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      const wireBody = apiErr.details as {
        details: Array<Record<string, unknown>>;
      };
      expect(Array.isArray(wireBody.details)).toBe(true);
      expect(wireBody.details[0]).toHaveProperty("code");
    }
  });
});

// ─── 400 surface (SDK-pre-empted) ───────────────────────────────────────────

describe("abacPolicies.update — 400 surface (SDK-pre-empted)", () => {
  it("a malformed id throws synchronously (TypeError) BEFORE any fetch — the kernel 400 is never reached", () => {
    const { client, calls } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid policy id." } },
    ]);
    expect(() =>
      client.abacPolicies.update("malformed", { enabled: false }),
    ).toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});

// ─── Retry semantics ────────────────────────────────────────────────────────

describe("abacPolicies.update — retry semantics", () => {
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
        JSON.stringify({ success: true, data: UPDATED_POLICY }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });
    const out = await client.abacPolicies.update(POLICY_ID, {
      enabled: false,
    });
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
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry on 409 (name conflict is a permanent client error)", async () => {
    const fetchSpy = vi.fn(async () => {
      return new Response(
        JSON.stringify({ success: false, error: "name taken" }),
        { status: 409, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });
    await expect(
      client.abacPolicies.update(POLICY_ID, { name: "taken" }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry on 422 (validation is a permanent client error)", async () => {
    const fetchSpy = vi.fn(async () => {
      return new Response(
        JSON.stringify({ success: false, error: "Validation failed." }),
        { status: 422, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
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
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});

// ─── Abort semantics ────────────────────────────────────────────────────────

describe("abacPolicies.update — abort semantics", () => {
  it("rejects with AttestryError when options.signal is pre-aborted", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.update(
        POLICY_ID,
        { enabled: false },
        { signal: ac.signal },
      ),
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
    const pending = client.abacPolicies.update(
      POLICY_ID,
      { enabled: false },
      { signal: ac.signal },
    );
    ac.abort();
    await expect(pending).rejects.toBeInstanceOf(AttestryError);
    resolveFetch(
      new Response(
        JSON.stringify({ success: true, data: UPDATED_POLICY }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
  });
});

// ─── Response shape (P2 hardening — shared validateAbacPolicy) ──────────────

describe("abacPolicies.update — response shape (P2 hardening)", () => {
  it("rejects when the updated-row response is not an object (null) — AttestryError", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    const promise = client.abacPolicies.update(POLICY_ID, { enabled: false });
    await expect(promise).rejects.toBeInstanceOf(AttestryError);
    await expect(promise).rejects.toThrow(/expected an object response/);
  });

  it("the response-validator error message names `abacPolicies.update` (not `.create`)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toThrow(/abacPolicies\.update:/);
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
    "rejects when the updated row's $field is wrong type ($type)",
    async ({ field, value, type }) => {
      const malformed = { ...UPDATED_POLICY, [field]: value };
      const { client } = makeMockedClient([
        { body: { success: true, data: malformed } },
      ]);
      const promise = client.abacPolicies.update(POLICY_ID, {
        enabled: false,
      });
      await expect(promise).rejects.toBeInstanceOf(AttestryError);
      await expect(promise).rejects.toThrow(
        new RegExp(`response\\.${field}.*${type}`),
      );
    },
  );

  it("accepts the updated row's description = null (boundary; string | null)", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...UPDATED_POLICY, description: null } },
      },
    ]);
    const out = await client.abacPolicies.update(POLICY_ID, {
      enabled: false,
    });
    expect(out.description).toBeNull();
  });

  it("accepts the updated row's createdByUserId = null (boundary; string | null)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...UPDATED_POLICY, createdByUserId: null },
        },
      },
    ]);
    const out = await client.abacPolicies.update(POLICY_ID, {
      enabled: false,
    });
    expect(out.createdByUserId).toBeNull();
  });

  it("rejects when the updated row's description is a number", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...UPDATED_POLICY, description: 42 } },
      },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toThrow(/response\.description.*string or null.*number/);
  });

  it("rejects when the updated row's condition is null", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...UPDATED_POLICY, condition: null } },
      },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toThrow(/response\.condition.*non-null object/);
  });

  it("rejects when the updated row's condition is an array", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...UPDATED_POLICY, condition: [] } },
      },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toThrow(/response\.condition.*non-null object.*array/);
  });
});

// ─── Missing own-property — coverage for `:undefined` ternary arms ──────────

describe("abacPolicies.update — missing own-property exercises :undefined ternary arm", () => {
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
    const partial = { ...UPDATED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>)[field];
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ─── URL & request invariants ───────────────────────────────────────────────

describe("abacPolicies.update — URL & request invariants", () => {
  it("uses PATCH (NOT GET / POST / DELETE)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { enabled: false });
    expect(calls[0].method).toBe("PATCH");
  });

  it("hits exact path /api/v1/abac-policies/<id> (with id segment, no query string)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { enabled: false });
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/abac-policies/${POLICY_ID}`,
    );
    expect(calls[0].url).not.toContain("?");
  });

  it("sends a JSON request body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, { enabled: false });
    expect(calls[0].body).toBeDefined();
    expect(() => JSON.parse(calls[0].body as string)).not.toThrow();
  });

  it("response-shape validation runs AFTER the transport envelope unwrap", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: "not-an-object" } },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("passes a bare (non-enveloped) response body through the transport, then rejects a malformed one via validateAbacPolicy", async () => {
    const { client } = makeMockedClient([
      { bodyText: JSON.stringify({ unexpected: "shape" }) },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ─── Prototype-pollution defense (response side) ────────────────────────────

describe("abacPolicies.update — prototype-pollution defense (response side)", () => {
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).id;
    delete (Object.prototype as Record<string, unknown>).name;
    delete (Object.prototype as Record<string, unknown>).condition;
  });

  it("polluted Object.prototype.id does NOT mask a missing id field", async () => {
    (Object.prototype as Record<string, unknown>).id = "polluted-id";
    const partial = { ...UPDATED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).id;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toThrow(/response\.id to be a string.*undefined/);
  });

  it("polluted Object.prototype.name (type-valid string) does NOT mask a missing name field", async () => {
    (Object.prototype as Record<string, unknown>).name = "polluted-name";
    const partial = { ...UPDATED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).name;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toThrow(/response\.name to be a string.*undefined/);
  });

  it("polluted Object.prototype.condition (type-valid object) does NOT mask a missing condition field", async () => {
    (Object.prototype as Record<string, unknown>).condition = {
      op: "exists",
      attr: "principal.id",
    };
    const partial = { ...UPDATED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>).condition;
    const { client } = makeMockedClient([
      { body: { success: true, data: partial } },
    ]);
    await expect(
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toThrow(/response\.condition.*non-null object.*undefined/);
  });

  it("does NOT surface Object.prototype fields as own-properties of the updated row", async () => {
    (Object.prototype as Record<string, unknown>).surprise = "polluted-extra";
    try {
      const { client } = makeMockedClient([
        { body: { success: true, data: UPDATED_POLICY } },
      ]);
      const out = await client.abacPolicies.update(POLICY_ID, {
        enabled: false,
      });
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
// **H5 + H6 stress the design-#2 decision** — `.update()` interpolates
// the `id` into the path RAW (no `encodeURIComponent`), mirroring
// `batch.get`. That is only safe because `assertValidPolicyId`
// pre-rejects any non-UUID `id` synchronously.
//
// **H11 + H12 are `.update`-specific** — `.update()` is the only
// cluster method with a non-trivial INPUT surface (8 optional fields +
// the empty-patch pre-validation). H11 proves the empty-patch check
// survives a combined Object.hasOwn-override + input-side prototype-
// pollution attack; H12 proves the per-field snapshot is read EXACTLY
// once (TOCTOU defense against a value-changing getter).
//
// NOT covered here: a THROWING getter on an input field (session-21
// hostile review MEDIUM-1) — that gap is SDK-wide and is assessed +
// fixed in the post-cluster-bump hostile reviews, not pinned here.

describe("abacPolicies.update — hostile round (residual gaps)", () => {
  it("H1: Object.hasOwn global override + polluted Object.prototype.id + missing-own-property response; module-load snapshot rejects", async () => {
    // Attack: override `Object.hasOwn` to return true for any key, and
    // pollute `Object.prototype.id` with a TYPE-VALID string. Emit a
    // response with no `id` own-property. `id` is the validator's
    // FIRST (unconditional) field check. The module-load `objectHasOwn`
    // snapshot returns false on the missing own-property → rejects.
    const hasOwnSpy = vi
      .spyOn(Object, "hasOwn")
      .mockImplementation(() => true);
    (Object.prototype as Record<string, unknown>).id = "polluted-id";
    try {
      const partial = { ...UPDATED_POLICY } as Partial<AbacPolicy>;
      delete (partial as Record<string, unknown>).id;
      const { client } = makeMockedClient([
        { body: { success: true, data: partial } },
      ]);
      await expect(
        client.abacPolicies.update(POLICY_ID, { enabled: false }),
      ).rejects.toThrow(/response\.id to be a string.*undefined/);
    } finally {
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).id;
    }
  });

  it("H2: P3 content-type fail-fast — 200 success with `text/plain` rejects with AttestryAPIError", async () => {
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
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("H3: P3 content-type fail-fast — 200 with NO Content-Type header rejects with AttestryAPIError", async () => {
    const fetchSpy = vi.fn(async () => {
      const res = new Response(
        JSON.stringify({ success: true, data: UPDATED_POLICY }),
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
      client.abacPolicies.update(POLICY_ID, { enabled: false }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("H4: combined attack — Object.hasOwn override + type-valid prototype pollution on multiple fields + empty-object response; module-load snapshot rejects", async () => {
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
        client.abacPolicies.update(POLICY_ID, { enabled: false }),
      ).rejects.toBeInstanceOf(AttestryError);
    } finally {
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).id;
      delete (Object.prototype as Record<string, unknown>).orgId;
      delete (Object.prototype as Record<string, unknown>).name;
    }
  });

  it("H5: a path-traversal-shaped id is rejected synchronously by assertValidPolicyId — no fetch, no path-traversal vector", () => {
    // `.update()` interpolates `id` into the path RAW (no
    // `encodeURIComponent`). A path-traversal-shaped id contains
    // characters absent from `UUID_REGEX`'s hex + hyphen alphabet, so
    // `assertValidPolicyId` throws synchronously BEFORE any URL is
    // built — no fetch, no collapse to a sibling endpoint.
    const { client, calls } = makeMockedClient([]);
    for (const evil of [
      "..",
      ".",
      "../../../../etc/passwd",
      "11111111-1111-1111-1111-111111111111/../../secrets",
      "%2e%2e%2f",
    ]) {
      expect(() =>
        client.abacPolicies.update(evil, { enabled: false }),
      ).toThrow(TypeError);
      expect(() =>
        client.abacPolicies.update(evil, { enabled: false }),
      ).toThrow(/RFC 4122/);
    }
    expect(calls).toHaveLength(0);
  });

  it("H6: a lone-surrogate id is rejected synchronously as a TypeError (NOT a URIError) — no fetch", () => {
    // `.update()` does NO `encodeURIComponent` on the path segment
    // (design #2). A lone-surrogate id is not hex, so `UUID_REGEX`
    // rejects it and `assertValidPolicyId` throws a `TypeError` — no
    // `URIError` can leak, because no code path calls
    // `encodeURIComponent`.
    const { client, calls } = makeMockedClient([]);
    for (const surrogate of ["\uD800", "\uDFFF", `${POLICY_ID}\uD800`]) {
      let caught: unknown;
      try {
        client.abacPolicies.update(surrogate, { enabled: false });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(TypeError);
      expect(caught).not.toBeInstanceOf(URIError);
      expect((caught as Error).message).toMatch(/RFC 4122/);
    }
    expect(calls).toHaveLength(0);
  });

  it("H7: a BigInt id is rejected synchronously (typeof 'bigint' is not 'string') — no fetch", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.update(BigInt(1) as unknown as string, {
        enabled: false,
      }),
    ).toThrow(/`id` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("H8: kernel returns 403 for what should be 401 — SDK is a faithful courier on status (no client-side collapse)", async () => {
    // A hypothetical kernel regression mis-maps the unauth path to
    // 403. The SDK surfaces whatever the kernel emits — it does NOT
    // collapse 403 → 401. Dual-auth admin routes keep 401 and 403
    // distinct.
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
      await client.abacPolicies.update(POLICY_ID, { enabled: false });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.status).not.toBe(401);
    }
  });

  it("H9: a pre-aborted call leaves no dirty state — a subsequent call succeeds (state isolation)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.update(
        POLICY_ID,
        { enabled: false },
        { signal: ac.signal },
      ),
    ).rejects.toBeInstanceOf(AttestryError);

    const out = await client.abacPolicies.update(POLICY_ID, {
      enabled: false,
    });
    expect(out.id).toBe(POLICY_ID);
  });

  it("H10: concurrent .update() calls with distinct ids + distinct patches — independent URL + body construction, no bleed", async () => {
    // Concurrency pin: 3 .update() calls via Promise.all with distinct
    // ids AND distinct patch bodies. Each must hit its OWN id's path
    // with its OWN body — no shared mutable state, no id bleed, no
    // body bleed between calls.
    const id0 = "00000000-0000-0000-0000-000000000001";
    const id1 = "00000000-0000-0000-0000-000000000002";
    const id2 = "00000000-0000-0000-0000-000000000003";
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { ...UPDATED_POLICY, id: id0 } } },
      { body: { success: true, data: { ...UPDATED_POLICY, id: id1 } } },
      { body: { success: true, data: { ...UPDATED_POLICY, id: id2 } } },
    ]);
    const [r0, r1, r2] = await Promise.all([
      client.abacPolicies.update(id0, { enabled: false }),
      client.abacPolicies.update(id1, { priority: 7 }),
      client.abacPolicies.update(id2, { name: "renamed" }),
    ]);
    expect(r0.id).toBe(id0);
    expect(r1.id).toBe(id1);
    expect(r2.id).toBe(id2);
    expect(calls).toHaveLength(3);
    // Each call hit its own id's path.
    expect(calls[0].url).toContain(id0);
    expect(calls[1].url).toContain(id1);
    expect(calls[2].url).toContain(id2);
    // Each call carried its own patch body — no body bleed.
    expect(JSON.parse(calls[0].body as string)).toEqual({ enabled: false });
    expect(JSON.parse(calls[1].body as string)).toEqual({ priority: 7 });
    expect(JSON.parse(calls[2].body as string)).toEqual({ name: "renamed" });
  });

  it("H11: empty-patch check survives an Object.hasOwn override + input-side prototype pollution", async () => {
    // `.update`-specific. Attack: override `Object.hasOwn` to return
    // true for any key, and pollute `Object.prototype.enabled` with a
    // TYPE-VALID boolean. Call `update(id, {})`.
    //
    // If the SDK used the (overridden) global `Object.hasOwn`, then
    // `hasEnabled` would be true, `enabledRaw` would read the polluted
    // `Object.prototype.enabled` (= true, a valid boolean), the body
    // would become `{ enabled: true }` (non-empty), the empty-patch
    // check would PASS, and a fetch would be issued with a SMUGGLED
    // field the consumer never set.
    //
    // Defense: the SDK reads input own-properties via the module-load
    // `objectHasOwn` snapshot → `objectHasOwn({}, "enabled")` is false
    // → `hasEnabled` false → `enabled` is NOT in the body → the body
    // is empty → the empty-patch `TypeError` fires synchronously, no
    // fetch issued. The combined attack cannot smuggle a polluted
    // field into the patch.
    const hasOwnSpy = vi
      .spyOn(Object, "hasOwn")
      .mockImplementation(() => true);
    (Object.prototype as Record<string, unknown>).enabled = true;
    try {
      const { client, calls } = makeMockedClient([]);
      expect(() => client.abacPolicies.update(POLICY_ID, {})).toThrow(
        /at least one updatable field/,
      );
      expect(calls).toHaveLength(0);
    } finally {
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).enabled;
    }
  });

  it("H12: a getter-bearing input field is read EXACTLY once — the body carries the first-read value (TOCTOU defense)", async () => {
    // `.update`-specific. The SDK snapshots each input field EXACTLY
    // once via the own-property indexer, then operates on the local.
    // An adversarial input with a value-CHANGING getter on `priority`
    // — 100 on the first read (valid), 9999 on any later read (out of
    // range) — proves the snapshot discipline: per-field validation
    // AND body construction both read the SAME local. The getter
    // fires once; the body carries 100, never the validated-clean-
    // then-poisoned 9999.
    let getterCalls = 0;
    const trickyInput: AbacPolicyUpdateInput = {
      get priority() {
        getterCalls += 1;
        return getterCalls === 1 ? 100 : 9999;
      },
    };
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: UPDATED_POLICY } },
    ]);
    await client.abacPolicies.update(POLICY_ID, trickyInput);
    // The getter was invoked exactly once (single snapshot read).
    expect(getterCalls).toBe(1);
    // The body carries the first-read value — no TOCTOU poisoning.
    expect(JSON.parse(calls[0].body as string)).toEqual({ priority: 100 });
  });
});

// ─── Hostile review #1 — MEDIUM-1 throwing-getter fix ───────────────────────
//
// Session-22 hostile review #1: the SDK-wide MEDIUM-1 getter-throws
// contract gap. `.update()` reads each input field via `readInputField`,
// which converts a throwing accessor's exception into the documented
// synchronous `TypeError`.

describe("abacPolicies.update — hostile review #1: throwing-getter MEDIUM-1 fix", () => {
  it("converts a throwing `enabled` getter into a TypeError (NOT the getter's raw error)", () => {
    const { client, calls } = makeMockedClient([]);
    const evil = {
      get enabled(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as AbacPolicyUpdateInput;
    let caught: unknown;
    try {
      client.abacPolicies.update(POLICY_ID, evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).message).toContain("abacPolicies.update");
    expect((caught as Error).message).toContain("enabled");
    expect((caught as Error).message).not.toContain("getter boom");
    expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(
      Error,
    );
    expect(calls).toHaveLength(0);
  });

  it("converts a throwing `name` getter into a TypeError", () => {
    const { client, calls } = makeMockedClient([]);
    const evil = {
      get name(): unknown {
        throw new Error("name boom");
      },
    } as unknown as AbacPolicyUpdateInput;
    expect(() => client.abacPolicies.update(POLICY_ID, evil)).toThrow(
      TypeError,
    );
    expect(() => client.abacPolicies.update(POLICY_ID, evil)).toThrow(/name/);
    expect(calls).toHaveLength(0);
  });

  it("the id is still validated BEFORE the input — a bad id + a throwing getter throws the id error first", () => {
    // `assertValidPolicyId` runs before the input snapshot, so a
    // malformed id pre-empts the throwing-getter read entirely.
    const { client, calls } = makeMockedClient([]);
    const evil = {
      get enabled(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as AbacPolicyUpdateInput;
    expect(() => client.abacPolicies.update("bad-id", evil)).toThrow(
      /`id` must be an RFC 4122 hyphenated UUID/,
    );
    expect(calls).toHaveLength(0);
  });
});
