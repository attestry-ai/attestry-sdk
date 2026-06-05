import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  // Result-shape + input-shape type imports — pinned at compile time.
  AbacPolicy,
  AbacPolicyCreateInput,
  AbacCondition,
} from "../abac-policies.js";
import type { FetchLike } from "../../types.js";

// ─── abacPolicies.create — POST a new ABAC policy ──────────────────────────
//
// Wire shape (kernel src/app/api/v1/abac-policies/route.ts):
//   POST /api/v1/abac-policies
//   Auth: x-api-key (requireSessionOrApiKey + apiKeyPermissions:[ADMIN])
//   Body: createAbacPolicySchema (Zod .strict() — 8 fields, 4 required +
//     4 with defaults)
//   201 OK: {success:true, data: <AbacPolicy row>}
//   401 auth, 403 permission, 409 name conflict, 422 validation (3 paths),
//   429 rate-limit, 500 internal.
//
// 22nd audit chain in the F.1 phase. Second method of the 5-method
// abacPolicies CRUD cluster (.create after .list in session 21;
// .retrieve / .update / .delete in session 22).
//
// FIRST SDK route with HTTP 201 success status.
// FIRST SDK route with HTTP 409 Conflict surface.
// FIRST SDK route with three-way 422 fan-out (BodyParseError +
//   ZodError dead-arm + AbacPolicyValidationError, distinct details
//   shapes).
// FIRST SDK route with PARTIAL Zod pre-validation (7 closed-spec rules
//   pre-validated; condition AST deferred to server canonical validator).
//
// **Status-code surface — 401 AND 403 distinguished** (dual-auth admin
// route — same surface as .list). Pin BOTH branches.

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

const VALID_CONDITION_EQ: AbacCondition = {
  op: "attrEq",
  left: "principal.id",
  right: "resource.ownerId",
};

const VALID_INPUT: AbacPolicyCreateInput = {
  name: "owner-can-edit-own",
  description: "Owners can edit their own assessments.",
  resource: "assessments",
  action: "update",
  effect: "allow",
  condition: VALID_CONDITION_EQ,
  priority: 100,
  enabled: true,
};

const MIN_INPUT: AbacPolicyCreateInput = {
  name: "minimal-policy",
  resource: "systems",
  action: "read",
  condition: { op: "exists", attr: "principal.id" },
};

const CREATED_POLICY: AbacPolicy = {
  id: POLICY_ID,
  orgId: ORG_ID,
  name: "owner-can-edit-own",
  description: "Owners can edit their own assessments.",
  resource: "assessments",
  action: "update",
  effect: "allow",
  condition: VALID_CONDITION_EQ,
  priority: 100,
  enabled: true,
  createdByUserId: USER_ID,
  createdAt: "2026-05-14T12:00:00.000Z",
  updatedAt: "2026-05-14T12:00:00.000Z",
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("abacPolicies.create — happy path", () => {
  it("POSTs /api/v1/abac-policies with the body and returns the created row", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    const out = await client.abacPolicies.create(VALID_INPUT);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/abac-policies",
    );
    expect(out.id).toBe(POLICY_ID);
    expect(out.name).toBe("owner-can-edit-own");
  });

  it("sends the body with all provided fields verbatim", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create(VALID_INPUT);
    const body = JSON.parse(calls[0].body!);
    expect(body.name).toBe(VALID_INPUT.name);
    expect(body.description).toBe(VALID_INPUT.description);
    expect(body.resource).toBe(VALID_INPUT.resource);
    expect(body.action).toBe(VALID_INPUT.action);
    expect(body.effect).toBe(VALID_INPUT.effect);
    expect(body.condition).toEqual(VALID_INPUT.condition);
    expect(body.priority).toBe(VALID_INPUT.priority);
    expect(body.enabled).toBe(VALID_INPUT.enabled);
  });

  it("OMITS effect from body when consumer omits it (so kernel applies default 'allow') — invariant #52", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create(MIN_INPUT);
    const body = JSON.parse(calls[0].body!);
    // Pin: required fields are present.
    expect(body.name).toBe(MIN_INPUT.name);
    expect(body.resource).toBe(MIN_INPUT.resource);
    expect(body.action).toBe(MIN_INPUT.action);
    expect(body.condition).toEqual(MIN_INPUT.condition);
    // Pin: defaults are NOT in body — kernel applies them.
    expect(body).not.toHaveProperty("effect");
    expect(body).not.toHaveProperty("priority");
    expect(body).not.toHaveProperty("enabled");
    expect(body).not.toHaveProperty("description");
  });

  it("OMITS priority from body when consumer omits it (kernel applies 100)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({
      ...MIN_INPUT,
      effect: "deny",
      // priority omitted
    });
    const body = JSON.parse(calls[0].body!);
    expect(body.effect).toBe("deny");
    expect(body).not.toHaveProperty("priority");
  });

  it("OMITS enabled from body when consumer omits it (kernel applies true)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({
      ...MIN_INPUT,
      // enabled omitted
    });
    const body = JSON.parse(calls[0].body!);
    expect(body).not.toHaveProperty("enabled");
  });

  it("INCLUDES description=null in body when caller explicitly passes null (preserves caller intent vs omit)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({
      ...MIN_INPUT,
      description: null,
    });
    const body = JSON.parse(calls[0].body!);
    // Pin: explicit null is preserved (NOT stripped to omit).
    expect(body).toHaveProperty("description");
    expect(body.description).toBeNull();
  });

  it("INCLUDES priority=0 in body when caller explicitly passes 0 (boundary; preserves intent vs omit)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...MIN_INPUT, priority: 0 });
    const body = JSON.parse(calls[0].body!);
    expect(body.priority).toBe(0);
  });

  it("INCLUDES enabled=false in body when caller explicitly passes false (boundary; preserves intent vs omit)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...MIN_INPUT, enabled: false });
    const body = JSON.parse(calls[0].body!);
    expect(body.enabled).toBe(false);
  });

  it("sets request Content-Type to application/json", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create(VALID_INPUT);
    expect((calls[0].headers as Headers).get("content-type")).toContain(
      "application/json",
    );
  });

  it("sends `x-api-key` header from the client config", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create(VALID_INPUT);
    expect((calls[0].headers as Headers).get("x-api-key")).toBe("k");
  });

  it("accepts a complex recursive AND condition AST", async () => {
    const complexCondition: AbacCondition = {
      op: "and",
      clauses: [
        { op: "eq", attr: "principal.dept", value: "Engineering" },
        { op: "not", clause: { op: "eq", attr: "resource.archived", value: true } },
        {
          op: "or",
          clauses: [
            { op: "in", attr: "principal.role", values: ["admin", "lead"] },
            { op: "attrEq", left: "principal.id", right: "resource.ownerId" },
          ],
        },
      ],
    };
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...MIN_INPUT, condition: complexCondition });
    const body = JSON.parse(calls[0].body!);
    // Pin: complex AST passes through verbatim (faithful courier on
    // the recursive structure; server canonical validator handles it).
    expect(body.condition).toEqual(complexCondition);
  });
});

// ─── Input validation (synchronous TypeError; NO fetch issued) ─────────────

describe("abacPolicies.create — input validation: top-level shape", () => {
  it("throws TypeError when input is null", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create(null as unknown as AbacPolicyCreateInput),
    ).toThrow(TypeError);
    expect(calls).toHaveLength(0); // no fetch issued
  });

  it("throws TypeError when input is an array", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create([] as unknown as AbacPolicyCreateInput),
    ).toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when input is undefined", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create(undefined as unknown as AbacPolicyCreateInput),
    ).toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when input is a primitive (string)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create("not-an-object" as unknown as AbacPolicyCreateInput),
    ).toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});

describe("abacPolicies.create — input validation: name", () => {
  it("throws TypeError when name is missing", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, name: undefined as unknown as string }),
    ).toThrow(/`name` is required/);
  });

  it("throws TypeError when name is not a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, name: 123 as unknown as string }),
    ).toThrow(/`name` must be a string/);
  });

  it("throws TypeError when name is empty string", () => {
    const { client } = makeMockedClient([]);
    expect(() => client.abacPolicies.create({ ...VALID_INPUT, name: "" })).toThrow(
      /`name` must be a non-empty string/,
    );
  });

  it("throws TypeError when name exceeds 128 chars (kernel MAX_POLICY_NAME_LENGTH)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, name: "x".repeat(129) }),
    ).toThrow(/max length of 128 chars/);
  });

  it("accepts name at exactly 128 chars (boundary)", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...VALID_INPUT, name: "x".repeat(128) });
  });
});

describe("abacPolicies.create — input validation: resource (closed-enum)", () => {
  it("throws TypeError when resource is missing (own-property absent — :undefined ternary arm)", () => {
    // Pass an object with NO `resource` key (omit, not `undefined`).
    // This exercises the `:undefined` arm of the `hasResource ? ... :
    // undefined` ternary in the SDK source (line 798), distinct from
    // the `resource: undefined` case which exercises the `hasResource
    // = true` arm.
    const { client } = makeMockedClient([]);
    const inputWithoutResource = {
      name: "x",
      action: "read",
      condition: { op: "exists", attr: "principal.id" },
    } as unknown as AbacPolicyCreateInput;
    expect(() => client.abacPolicies.create(inputWithoutResource)).toThrow(
      /`resource` is required/,
    );
  });

  it("throws TypeError when resource is own-property with undefined value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, resource: undefined as unknown as "systems" }),
    ).toThrow(/`resource` is required/);
  });

  it("throws TypeError when resource is not a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, resource: 42 as unknown as "systems" }),
    ).toThrow(/`resource` must be a string/);
  });

  it("throws TypeError when resource is unknown enum value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, resource: "made-up-resource" as unknown as "systems" }),
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
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({
      ...VALID_INPUT,
      resource: resource as AbacPolicyCreateInput["resource"],
    });
  });
});

describe("abacPolicies.create — input validation: action (closed-enum)", () => {
  it("throws TypeError when action is missing (own-property absent — :undefined ternary arm)", () => {
    const { client } = makeMockedClient([]);
    const inputWithoutAction = {
      name: "x",
      resource: "systems",
      condition: { op: "exists", attr: "principal.id" },
    } as unknown as AbacPolicyCreateInput;
    expect(() => client.abacPolicies.create(inputWithoutAction)).toThrow(
      /`action` is required/,
    );
  });

  it("throws TypeError when action is own-property with undefined value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, action: undefined as unknown as "update" }),
    ).toThrow(/`action` is required/);
  });

  it("throws TypeError when action is not a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, action: true as unknown as "update" }),
    ).toThrow(/`action` must be a string/);
  });

  it("throws TypeError when action is unknown enum value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, action: "purge" as unknown as "update" }),
    ).toThrow(/`action` must be one of \[.+\] \(got "purge"\)/);
  });

  it.each(["create", "read", "update", "delete", "manage"])(
    "accepts action '%s' (closed-enum member)",
    async (action) => {
      const { client } = makeMockedClient([
        { status: 201, body: { success: true, data: CREATED_POLICY } },
      ]);
      await client.abacPolicies.create({
        ...VALID_INPUT,
        action: action as AbacPolicyCreateInput["action"],
      });
    },
  );
});

describe("abacPolicies.create — input validation: condition (defers AST to server)", () => {
  it("throws TypeError when condition is missing (own-property absent — :undefined ternary arm)", () => {
    const { client } = makeMockedClient([]);
    const inputWithoutCondition = {
      name: "x",
      resource: "systems",
      action: "read",
    } as unknown as AbacPolicyCreateInput;
    expect(() => client.abacPolicies.create(inputWithoutCondition)).toThrow(
      /`condition` is required/,
    );
  });

  it("throws TypeError when condition is own-property with undefined value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, condition: undefined as unknown as AbacCondition }),
    ).toThrow(/`condition` is required/);
  });

  it("throws TypeError when condition is null", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, condition: null as unknown as AbacCondition }),
    ).toThrow(/`condition` must be a non-null object/);
  });

  it("throws TypeError when condition is an array", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, condition: [] as unknown as AbacCondition }),
    ).toThrow(/`condition` must be a non-null object.*array/);
  });

  it("throws TypeError when condition is a scalar (string)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, condition: "not-ast" as unknown as AbacCondition }),
    ).toThrow(/`condition` must be a non-null object.*string/);
  });

  it("does NOT pre-validate the AST grammar — passes through invalid-looking object verbatim", async () => {
    // SDK only checks that condition is a non-null object. The AST
    // grammar (op / attr / values / etc.) is the kernel's job. Pin
    // the partial-pre-validation pattern.
    const malformedAst = { not_a_valid_op: "garbage" } as unknown as AbacCondition;
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...VALID_INPUT, condition: malformedAst });
    const body = JSON.parse(calls[0].body!);
    // Pin: malformed AST passes through to server.
    expect(body.condition).toEqual(malformedAst);
  });
});

describe("abacPolicies.create — input validation: description (optional string|null)", () => {
  it("throws TypeError when description is a number", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, description: 42 as unknown as string }),
    ).toThrow(/`description` must be a string or null/);
  });

  it("throws TypeError when description exceeds 2000 chars (kernel max)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, description: "x".repeat(2001) }),
    ).toThrow(/max length of 2000 chars/);
  });

  it("accepts description at exactly 2000 chars (boundary)", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...VALID_INPUT, description: "x".repeat(2000) });
  });

  it("accepts description = null", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...VALID_INPUT, description: null });
  });

  // ─── HIGH-1 hostile-review fix: explicit `undefined` accepted as omission ─

  it("accepts description = undefined (explicit own-property) — treated as omission per JSDoc contract (hostile-review HIGH-1)", async () => {
    // Regression pin: a consumer doing
    //   `client.abacPolicies.create({...form, description: form.maybeStr})`
    // where `form.maybeStr: string | undefined` would previously hit a
    // confusing TypeError despite the JSDoc claim "Accepts `string`,
    // `null`, or `undefined` (omitted)". The kernel's Zod is
    // `.optional().nullable()` so undefined is accepted server-side,
    // AND JSON.stringify drops undefined keys anyway. Symmetric with
    // the existing effect/priority/enabled handling (which all use the
    // `if (hasX && xRaw !== undefined)` guard).
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({
      ...VALID_INPUT,
      description: undefined,
    });
    // Pin: did not throw. The call reaches the network.
    expect(calls).toHaveLength(1);
  });

  it("OMITS description from body when caller passes undefined (matches `effect: undefined` / `priority: undefined` / `enabled: undefined` symmetry — hostile-review HIGH-1)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({
      ...MIN_INPUT,
      description: undefined,
    });
    const rawBody = calls[0].body!;
    // Pin against raw wire text: the body must NOT contain a
    // "description" key. JSON.stringify drops undefined fields, but
    // pinning the raw text catches a regression where the SDK
    // accidentally includes `"description":null` (changing caller intent).
    expect(rawBody).not.toContain('"description"');
    // Cross-check via JSON.parse: parsed body has no own-description.
    const body = JSON.parse(rawBody);
    expect(Object.hasOwn(body, "description")).toBe(false);
  });

  it("distinguishes description=undefined (omit) from description=null (explicit null in body) — hostile-review HIGH-1", async () => {
    // Behavior contract: `undefined` → field omitted; `null` → field
    // present with null value. Verify both happen in a single test so
    // future regressions on either path surface immediately.
    const { client: client1, calls: calls1 } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client1.abacPolicies.create({
      ...MIN_INPUT,
      description: undefined,
    });
    const body1 = JSON.parse(calls1[0].body!);
    expect(Object.hasOwn(body1, "description")).toBe(false);

    const { client: client2, calls: calls2 } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client2.abacPolicies.create({
      ...MIN_INPUT,
      description: null,
    });
    const body2 = JSON.parse(calls2[0].body!);
    expect(Object.hasOwn(body2, "description")).toBe(true);
    expect(body2.description).toBeNull();
  });
});

describe("abacPolicies.create — input validation: effect (optional closed-enum)", () => {
  it("throws TypeError when effect is not a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, effect: 1 as unknown as "allow" }),
    ).toThrow(/`effect` must be a string/);
  });

  it("throws TypeError when effect is unknown enum value", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, effect: "warn" as unknown as "allow" }),
    ).toThrow(/`effect` must be one of \[allow, deny\]/);
  });

  it.each(["allow", "deny"])(
    "accepts effect '%s' (closed-enum member)",
    async (effect) => {
      const { client } = makeMockedClient([
        { status: 201, body: { success: true, data: CREATED_POLICY } },
      ]);
      await client.abacPolicies.create({
        ...VALID_INPUT,
        effect: effect as AbacPolicyCreateInput["effect"],
      });
    },
  );
});

describe("abacPolicies.create — input validation: priority (optional int 0-1000)", () => {
  it("throws TypeError when priority is not a number", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, priority: "100" as unknown as number }),
    ).toThrow(/`priority` must be a finite number/);
  });

  it("throws TypeError when priority is NaN", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, priority: NaN }),
    ).toThrow(/`priority` must be a finite number/);
  });

  it("throws TypeError when priority is Infinity", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, priority: Infinity }),
    ).toThrow(/`priority` must be a finite number/);
  });

  it("throws TypeError when priority is a float (non-integer)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, priority: 3.14 }),
    ).toThrow(/`priority` must be an integer/);
  });

  it("throws TypeError when priority is below MIN_PRIORITY (0)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, priority: -1 }),
    ).toThrow(/`priority` must be in range \[0, 1000\] \(got -1\)/);
  });

  it("throws TypeError when priority is above MAX_PRIORITY (1000)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, priority: 1001 }),
    ).toThrow(/`priority` must be in range \[0, 1000\] \(got 1001\)/);
  });

  it.each([0, 100, 500, 1000])(
    "accepts priority=%i (boundary + middle values)",
    async (priority) => {
      const { client } = makeMockedClient([
        { status: 201, body: { success: true, data: CREATED_POLICY } },
      ]);
      await client.abacPolicies.create({ ...VALID_INPUT, priority });
    },
  );
});

describe("abacPolicies.create — input validation: enabled (optional boolean)", () => {
  it("throws TypeError when enabled is a string", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, enabled: "true" as unknown as boolean }),
    ).toThrow(/`enabled` must be a boolean/);
  });

  it("throws TypeError when enabled is a number (1 or 0)", () => {
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({ ...VALID_INPUT, enabled: 1 as unknown as boolean }),
    ).toThrow(/`enabled` must be a boolean/);
  });

  it.each([true, false])("accepts enabled=%s", async (enabled) => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...VALID_INPUT, enabled });
  });
});

// ─── Top-level error paths ──────────────────────────────────────────────────

describe("abacPolicies.create — top-level error paths", () => {
  it("201 → returns the created row (FIRST SDK route with 201 success)", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    const out = await client.abacPolicies.create(VALID_INPUT);
    expect(out.id).toBe(POLICY_ID);
  });

  it("401 (no/invalid/expired api-key) → AttestryAPIError(401)", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Invalid API key." },
      },
    ]);
    const promise = client.abacPolicies.create(VALID_INPUT);
    await expect(promise).rejects.toBeInstanceOf(AttestryAPIError);
    await expect(promise).rejects.toMatchObject({ status: 401 });
  });

  it("403 (valid key without ADMIN) → AttestryAPIError(403) — DISTINCT from 401", async () => {
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
      await client.abacPolicies.create(VALID_INPUT);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.status).not.toBe(401);
    }
  });

  it("409 conflict (name already taken) → AttestryAPIError(409) — FIRST SDK 409", async () => {
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: 'An ABAC policy named "owner-can-edit-own" already exists in this organization.',
        },
      },
    ]);
    try {
      await client.abacPolicies.create(VALID_INPUT);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(409);
      expect(apiErr.message).toContain("already exists");
    }
  });

  it("429 → AttestryAPIError(429) (with retry disabled)", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: { success: false, error: "Too many requests. Please try again later." },
      },
    ]);
    await expect(
      client.abacPolicies.create(VALID_INPUT),
    ).rejects.toMatchObject({ status: 429 });
  });

  it("500 (internal kernel error, scrubbed) → AttestryAPIError(500)", async () => {
    const { client } = makeMockedClient([
      {
        status: 500,
        body: {
          success: false,
          error: "An internal error occurred. Please try again later.",
        },
      },
    ]);
    const promise = client.abacPolicies.create(VALID_INPUT);
    await expect(promise).rejects.toBeInstanceOf(AttestryAPIError);
    await expect(promise).rejects.toMatchObject({ status: 500 });
  });
});

// ─── Three-way 422 fan-out ──────────────────────────────────────────────────

describe("abacPolicies.create — 422 wire-shape fan-out (three distinct details shapes)", () => {
  it("BodyParseError (Zod via parseBody) → 422 with details: Array<{path, message}>", async () => {
    // Kernel parseBody catches ZodError and maps to BodyParseError;
    // route emits errorResponse(error.message, 422, error.fieldErrors)
    // where fieldErrors is Array<{path, message}>.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            { path: "name", message: "String must contain at least 1 character(s)" },
            { path: "priority", message: "Number must be less than or equal to 1000" },
          ],
        },
      },
    ]);
    try {
      await client.abacPolicies.create(VALID_INPUT);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      // apiErr.details is the FULL parsed wire body (per transport's
      // contract: `{success:false, error, details: [...]}`). The
      // kernel's `details` array nests one level deep.
      const wireBody = apiErr.details as {
        success: false;
        error: string;
        details: Array<{ path: string; message: string }>;
      };
      expect(wireBody.error).toBe("Validation failed.");
      expect(Array.isArray(wireBody.details)).toBe(true);
      expect(wireBody.details).toHaveLength(2);
      expect(wireBody.details[0].path).toBe("name");
    }
  });

  it("AbacPolicyValidationError (canonical AST validator) → 422 with details: {errors: string[]}", async () => {
    // Kernel route emits errorResponse(error.message, 422,
    // { errors: error.errors }) where errors is string[].
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "ABAC policy validation failed: $.clauses: must have at least one entry; $.clauses[0].op: unknown operator \"foobar\"",
          details: {
            errors: [
              "$.clauses: must have at least one entry",
              "$.clauses[0].op: unknown operator \"foobar\"",
            ],
          },
        },
      },
    ]);
    try {
      await client.abacPolicies.create(VALID_INPUT);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      // apiErr.details is the FULL parsed wire body. Inner `details`
      // is the `{errors: string[]}` object emitted by the route's
      // AbacPolicyValidationError catch arm.
      const wireBody = apiErr.details as {
        success: false;
        error: string;
        details: { errors: string[] };
      };
      expect(wireBody.error).toContain("ABAC policy validation failed");
      // Inner details is an OBJECT (not an array).
      expect(Array.isArray(wireBody.details)).toBe(false);
      expect(Array.isArray(wireBody.details.errors)).toBe(true);
      expect(wireBody.details.errors).toHaveLength(2);
      expect(wireBody.details.errors[0]).toContain("clauses");
    }
  });

  it("ZodError defensive arm (DEAD on happy path) → 422 with details: ZodIssue[] (would have code/expected/received)", async () => {
    // The route's catch block has a defensive `instanceof ZodError`
    // arm that's DEAD on the happy path (parseBody catches Zod and
    // converts to BodyParseError). The arm exists as defense-in-depth
    // — if some other code path threw raw ZodError, it would land
    // with the richer ZodIssue[] shape. Pin the surface as a stable
    // contract.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            {
              code: "too_small",
              minimum: 1,
              type: "string",
              inclusive: true,
              exact: false,
              message: "String must contain at least 1 character(s)",
              path: ["name"],
            },
          ],
        },
      },
    ]);
    try {
      await client.abacPolicies.create(VALID_INPUT);
      throw new Error("should have thrown");
    } catch (err) {
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      // apiErr.details is the FULL parsed wire body. The inner
      // details array would carry the richer ZodIssue shape if a
      // raw ZodError ever surfaced (today defensive — parseBody
      // catches and converts to BodyParseError).
      const wireBody = apiErr.details as {
        details: Array<Record<string, unknown>>;
      };
      expect(Array.isArray(wireBody.details)).toBe(true);
      expect(wireBody.details[0]).toHaveProperty("code");
    }
  });

  it("Consumer-side 422 discriminator pattern — Array vs {errors} branching works", async () => {
    // Document the consumer pattern as a stable contract.
    const cases = [
      {
        name: "BodyParseError shape",
        bodyDetails: [{ path: "x", message: "y" }],
        expectedBranch: "array",
      },
      {
        name: "AbacPolicyValidationError shape",
        bodyDetails: { errors: ["AST error"] },
        expectedBranch: "errors-object",
      },
    ];
    for (const c of cases) {
      const { client } = makeMockedClient([
        {
          status: 422,
          body: { success: false, error: "Validation failed.", details: c.bodyDetails },
        },
      ]);
      try {
        await client.abacPolicies.create(VALID_INPUT);
      } catch (err) {
        const apiErr = err as AttestryAPIError;
        // apiErr.details is the FULL parsed wire body; the inner
        // details field carries the discriminator (array vs object).
        const wireBody = apiErr.details as { details: unknown };
        const innerDetails = wireBody.details;
        if (Array.isArray(innerDetails)) {
          expect(c.expectedBranch).toBe("array");
        } else if (
          innerDetails &&
          typeof innerDetails === "object" &&
          Array.isArray((innerDetails as { errors?: unknown }).errors)
        ) {
          expect(c.expectedBranch).toBe("errors-object");
        }
      }
    }
  });
});

// ─── Retry semantics ────────────────────────────────────────────────────────

describe("abacPolicies.create — retry semantics", () => {
  it("retries on 429 by default", async () => {
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
        JSON.stringify({ success: true, data: CREATED_POLICY }),
        { status: 201, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 1, maxDelayMs: 1 },
    });
    const out = await client.abacPolicies.create(VALID_INPUT);
    expect(out.id).toBe(POLICY_ID);
    expect(callCount).toBeGreaterThanOrEqual(2);
  });

  it("does NOT retry on 409 (non-retryable; conflict is a permanent state)", async () => {
    const fetchSpy = vi.fn(async () => {
      return new Response(
        JSON.stringify({
          success: false,
          error: 'An ABAC policy named "X" already exists.',
        }),
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
      client.abacPolicies.create(VALID_INPUT),
    ).rejects.toBeInstanceOf(AttestryAPIError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry on 422 (validation is a permanent client error)", async () => {
    const fetchSpy = vi.fn(async () => {
      return new Response(
        JSON.stringify({ success: false, error: "Validation failed.", details: [] }),
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
      client.abacPolicies.create(VALID_INPUT),
    ).rejects.toBeInstanceOf(AttestryAPIError);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});

// ─── Abort semantics ────────────────────────────────────────────────────────

describe("abacPolicies.create — abort semantics", () => {
  it("rejects with AttestryError when options.signal is pre-aborted", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    const ac = new AbortController();
    ac.abort();
    await expect(
      client.abacPolicies.create(VALID_INPUT, { signal: ac.signal }),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ─── Response shape (P2 hardening) ──────────────────────────────────────────

describe("abacPolicies.create — response shape (P2 hardening)", () => {
  it("rejects when response is not an object — AttestryError", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: null } },
    ]);
    const promise = client.abacPolicies.create(VALID_INPUT);
    await expect(promise).rejects.toBeInstanceOf(AttestryError);
    await expect(promise).rejects.toThrow(/expected an object response/);
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
      const malformed = { ...CREATED_POLICY, [field]: value };
      const { client } = makeMockedClient([
        { status: 201, body: { success: true, data: malformed } },
      ]);
      const promise = client.abacPolicies.create(VALID_INPUT);
      await expect(promise).rejects.toBeInstanceOf(AttestryError);
      await expect(promise).rejects.toThrow(
        new RegExp(`response\\.${field}.*${type}`),
      );
    },
  );

  it("accepts response.description = null (boundary; string | null)", async () => {
    const { client } = makeMockedClient([
      {
        status: 201,
        body: { success: true, data: { ...CREATED_POLICY, description: null } },
      },
    ]);
    const out = await client.abacPolicies.create(VALID_INPUT);
    expect(out.description).toBeNull();
  });

  it("accepts response.createdByUserId = null (boundary; string | null)", async () => {
    const { client } = makeMockedClient([
      {
        status: 201,
        body: { success: true, data: { ...CREATED_POLICY, createdByUserId: null } },
      },
    ]);
    const out = await client.abacPolicies.create(VALID_INPUT);
    expect(out.createdByUserId).toBeNull();
  });

  it("rejects when response.description is a number", async () => {
    const { client } = makeMockedClient([
      {
        status: 201,
        body: { success: true, data: { ...CREATED_POLICY, description: 42 } },
      },
    ]);
    await expect(client.abacPolicies.create(VALID_INPUT)).rejects.toThrow(
      /response\.description.*string or null.*number/,
    );
  });

  it("rejects when response.condition is null", async () => {
    const { client } = makeMockedClient([
      {
        status: 201,
        body: { success: true, data: { ...CREATED_POLICY, condition: null } },
      },
    ]);
    await expect(client.abacPolicies.create(VALID_INPUT)).rejects.toThrow(
      /response\.condition.*non-null object/,
    );
  });
});

// ─── Missing own-property exercises (`:undefined` ternary arms) ─────────────

describe("abacPolicies.create — missing own-property exercises :undefined ternary arm", () => {
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
    const partial = { ...CREATED_POLICY } as Partial<AbacPolicy>;
    delete (partial as Record<string, unknown>)[field];
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: partial } },
    ]);
    await expect(client.abacPolicies.create(VALID_INPUT)).rejects.toBeInstanceOf(
      AttestryError,
    );
  });
});

// ─── URL & request invariants ───────────────────────────────────────────────

describe("abacPolicies.create — URL & request invariants", () => {
  it("uses POST (NOT GET / PATCH / DELETE)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create(VALID_INPUT);
    expect(calls[0].method).toBe("POST");
  });

  it("hits exact path /api/v1/abac-policies (NO trailing /id)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create(VALID_INPUT);
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/abac-policies",
    );
  });

  it("sends a JSON request body", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create(VALID_INPUT);
    expect(calls[0].body).toBeDefined();
    expect(() => JSON.parse(calls[0].body!)).not.toThrow();
  });
});

// ─── Prototype-pollution defense (input side — generalization of #48) ──────

describe("abacPolicies.create — prototype-pollution defense (input side)", () => {
  afterEach(() => {
    delete (Object.prototype as Record<string, unknown>).name;
    delete (Object.prototype as Record<string, unknown>).resource;
    delete (Object.prototype as Record<string, unknown>).effect;
  });

  it("polluted Object.prototype.name does NOT inject value when consumer passes {}", () => {
    // Attack: polluted prototype could make objectHasOwn return false
    // but obj.name return a polluted value if the SDK used `in` or
    // direct property access. Defense: SDK uses objectHasOwn snapshot,
    // sees name as missing-own-property, throws "name is required".
    (Object.prototype as Record<string, unknown>).name = "polluted-name";
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({
        resource: "systems",
        action: "read",
        condition: { op: "exists", attr: "principal.id" },
      } as unknown as AbacPolicyCreateInput),
    ).toThrow(/`name` is required/);
  });

  it("polluted Object.prototype.effect does NOT silently fill in for omitted optional", async () => {
    // Attack: pollute effect with a type-valid string "deny" and pass
    // an input without effect. SDK should NOT include effect in the
    // serialized body (kernel applies its default "allow") —
    // invariant #52.
    (Object.prototype as Record<string, unknown>).effect = "deny";
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create(MIN_INPUT);
    // Pin against the RAW SERIALIZED body string. JSON.parse-then-
    // toHaveProperty would walk into the polluted prototype (which
    // is still alive at this point — afterEach cleans up later) and
    // surface "effect" as a property of the parsed object even
    // though it's NOT in the wire string. The wire string is what
    // the kernel actually sees, so the load-bearing assertion is on
    // the raw text.
    const rawBody = calls[0].body!;
    expect(rawBody).not.toContain('"effect"');
    expect(rawBody).not.toContain('"deny"');
  });
});

// ─── Hostile round (residual gaps) ──────────────────────────────────────────
//
// Each H-pin targets an attack surface or defense mechanism not
// exercised by build + spec-diff rounds. Per session-19 + session-20
// carry-forwards:
//   - Adversarial polluted-value construction with type-VALID values
//     that pass naive typeof checks.
//   - Pollute UNCONDITIONAL validator branches.
//   - vi.spyOn over direct global assignment.
//   - Eager mockRestore in finally before proto cleanup.
//   - Module-load snapshot defense observable only via combined attacks.

describe("abacPolicies.create — hostile round (residual gaps)", () => {
  it("H1: Object.hasOwn global override + polluted Object.prototype.name + missing-own-property input; module-load snapshot rejects", async () => {
    // Attack: override Object.hasOwn to return true; pollute
    // Object.prototype.name with a type-valid string. Call .create()
    // with an input missing `name` as own-property.
    //
    // Without defense: the consumer-side Object.hasOwn override and
    // prototype pollution combine to make naive checks pass. With
    // defense: SDK's module-load `objectHasOwn` snapshot (taken at
    // import time, before consumer-graph deps load) correctly returns
    // FALSE on missing name → SDK throws "name is required".
    const hasOwnSpy = vi
      .spyOn(Object, "hasOwn")
      .mockImplementation(() => true);
    (Object.prototype as Record<string, unknown>).name = "polluted-name";

    try {
      const { client } = makeMockedClient([]);
      expect(() =>
        client.abacPolicies.create({
          resource: "systems",
          action: "read",
          condition: { op: "exists", attr: "principal.id" },
        } as unknown as AbacPolicyCreateInput),
      ).toThrow(/`name` is required/);
    } finally {
      hasOwnSpy.mockRestore();
      delete (Object.prototype as Record<string, unknown>).name;
    }
  });

  it("H2: P3 content-type fail-fast on 201 success with text/plain — defense fires on the SUCCESS path too", async () => {
    // The transport's P3 content-type guard runs on BOTH success
    // and error responses. A 201 with `Content-Type: text/plain`
    // (proxy injection on the success path) should reject with
    // AttestryAPIError — NOT silently soft-fail with a wrong-shape
    // response. Pin the contract for the FIRST SDK 201 route.
    const fetchSpy = vi.fn(async () => {
      return new Response("not JSON", {
        status: 201,
        headers: { "Content-Type": "text/plain" },
      });
    });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: fetchSpy as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    await expect(client.abacPolicies.create(VALID_INPUT)).rejects.toBeInstanceOf(
      AttestryAPIError,
    );
  });

  it("H3: condition AST with adversarial __proto__ keys rides through verbatim — SDK does NOT pre-validate, server canonical validator rejects", async () => {
    // The SDK only checks condition is a non-null object. The
    // canonical validator at src/lib/auth/abac-policies.ts:143-154
    // rejects paths containing __proto__ / constructor / prototype.
    // Pin that the SDK passes the malformed AST through (faithful
    // courier on the recursive grammar) — server rejects with
    // AbacPolicyValidationError → 422.
    const adversarialCondition = {
      op: "eq",
      attr: "principal.__proto__.polluted",
      value: "x",
    } as unknown as AbacCondition;
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "ABAC policy validation failed: $.attr: must be a valid attr path",
          details: { errors: ["$.attr: must be a valid attr path"] },
        },
      },
    ]);
    try {
      await client.abacPolicies.create({
        ...VALID_INPUT,
        condition: adversarialCondition,
      });
      throw new Error("should have thrown");
    } catch (err) {
      // Pin: SDK passed through, server caught.
      const body = JSON.parse(calls[0].body!);
      expect(body.condition).toEqual(adversarialCondition);
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(422);
    }
  });

  it("H4: kernel returns 422 for what should be 409 — SDK is faithful courier on status (no client-side override)", async () => {
    // Adversarial scenario: hypothetical kernel regression maps a
    // name conflict to 422 (treating it as validation rather than
    // conflict). The SDK should NOT collapse 422 → 409 (or vice
    // versa) — surface whatever the kernel emits. Pin that the
    // SDK is a faithful courier on HTTP status.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed: name already exists",
          details: { errors: ["name already exists"] },
        },
      },
    ]);
    try {
      await client.abacPolicies.create(VALID_INPUT);
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      // Pin: SDK preserved 422 verbatim, didn't normalize to 409.
      expect(apiErr.status).toBe(422);
      expect(apiErr.status).not.toBe(409);
    }
  });

  it("H5: BigInt priority is rejected synchronously (no fetch issued)", async () => {
    // BigInt typeof is "bigint", NOT "number". A consumer passing
    // a BigInt would defeat naive `typeof === "number"` if the SDK
    // accepted BigInt as a number. Pin: BigInt is rejected by the
    // typeof check.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({
        ...VALID_INPUT,
        priority: BigInt(100) as unknown as number,
      }),
    ).toThrow(/`priority` must be a finite number/);
    expect(calls).toHaveLength(0);
  });

  it("H6: Number.MAX_SAFE_INTEGER as priority is rejected (out of range, not silently accepted)", async () => {
    // Number.MAX_SAFE_INTEGER is a finite integer but FAR exceeds
    // MAX_PRIORITY = 1000. Naive `Number.isFinite` + `Number.isInteger`
    // would pass; the range check is load-bearing.
    const { client } = makeMockedClient([]);
    expect(() =>
      client.abacPolicies.create({
        ...VALID_INPUT,
        priority: Number.MAX_SAFE_INTEGER,
      }),
    ).toThrow(/`priority` must be in range \[0, 1000\]/);
  });

  it("H7: negative-zero priority is accepted (valid integer 0 equivalent)", async () => {
    // -0 is a valid integer (Object.is(-0, 0) is false but
    // Number.isInteger(-0) is true). It IS in range [0, 1000].
    // Pin: SDK accepts -0 verbatim. Document the corner-case.
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: CREATED_POLICY } },
    ]);
    await client.abacPolicies.create({ ...VALID_INPUT, priority: -0 });
  });

  it("H8: concurrent .create() calls use independent body construction — no shared state leakage", async () => {
    // Concurrency pin: 3 .create() calls fired via Promise.all with
    // different inputs. Each gets a different mocked response.
    // Pin that each call's body construction + validator state is
    // independent (no module-level mutable state).
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: { ...CREATED_POLICY, id: "00000000-0000-0000-0000-000000000001" } } },
      { status: 201, body: { success: true, data: { ...CREATED_POLICY, id: "00000000-0000-0000-0000-000000000002" } } },
      { status: 201, body: { success: true, data: { ...CREATED_POLICY, id: "00000000-0000-0000-0000-000000000003" } } },
    ]);

    const [r0, r1, r2] = await Promise.all([
      client.abacPolicies.create({ ...MIN_INPUT, name: "p0" }),
      client.abacPolicies.create({ ...MIN_INPUT, name: "p1", priority: 50 }),
      client.abacPolicies.create({ ...MIN_INPUT, name: "p2", effect: "deny" }),
    ]);

    // Pin: each response is independent.
    expect(r0.id).toBe("00000000-0000-0000-0000-000000000001");
    expect(r1.id).toBe("00000000-0000-0000-0000-000000000002");
    expect(r2.id).toBe("00000000-0000-0000-0000-000000000003");
    // Pin: each body is independent (no body bleed between calls).
    expect(calls).toHaveLength(3);
    const body0 = JSON.parse(calls[0].body!);
    const body1 = JSON.parse(calls[1].body!);
    const body2 = JSON.parse(calls[2].body!);
    expect(body0.name).toBe("p0");
    expect(body1.name).toBe("p1");
    expect(body2.name).toBe("p2");
    expect(body1.priority).toBe(50);
    expect(body2.effect).toBe("deny");
    // Pin: bodies don't share inappropriate keys.
    expect(body0).not.toHaveProperty("priority");
    expect(body0).not.toHaveProperty("effect");
  });

  it("H9: Object.prototype.priority polluted with type-valid 500 does NOT leak into body when consumer omits priority", async () => {
    // Adversarial: pollute priority with a TYPE-VALID integer 500
    // (in range [0, 1000]). Pass an input without priority. SDK
    // should NOT include the polluted value in the body.
    (Object.prototype as Record<string, unknown>).priority = 500;
    try {
      const { client, calls } = makeMockedClient([
        { status: 201, body: { success: true, data: CREATED_POLICY } },
      ]);
      await client.abacPolicies.create(MIN_INPUT);
      const rawBody = calls[0].body!;
      // Pin against raw text — JSON.parse-then-toHaveProperty would
      // walk into the polluted prototype.
      expect(rawBody).not.toContain('"priority"');
      expect(rawBody).not.toContain("500");
    } finally {
      delete (Object.prototype as Record<string, unknown>).priority;
    }
  });

  it("H10: ABAC_POLICY_RESOURCES is frozen at runtime — push attempt throws TypeError (P1 hardening)", () => {
    // Closed-enum runtime arrays must be Object.freeze'd to prevent
    // hostile npm deps from mutating them (e.g., to inject a new
    // resource that the SDK pre-validation would then accept).
    // Pin the freeze observably — a push attempt throws TypeError
    // in strict mode (TS-emitted modules are strict by default).
    expect(() => {
      // Import via dynamic-require so the test runs even if the
      // top-level import had a fresh `as readonly [...]` cast.
      const sdk = require("../../../dist/index.js");
      (sdk.ABAC_POLICY_RESOURCES as unknown as string[]).push("evil-resource");
    }).toThrowError(TypeError);
  });
});

// ─── Hostile review #1 — MEDIUM-1 throwing-getter fix ───────────────────────
//
// Session-22 hostile review #1: the SDK-wide MEDIUM-1 getter-throws
// contract gap. `.create()` reads each input field via `readInputField`
// (the shared defensive-read helper), which converts a throwing
// accessor's exception into the documented synchronous `TypeError`.

describe("abacPolicies.create — hostile review #1: throwing-getter MEDIUM-1 fix", () => {
  it("converts a throwing `name` getter into a TypeError (NOT the getter's raw error)", () => {
    const { client, calls } = makeMockedClient([]);
    const evil = {
      get name(): unknown {
        throw new Error("getter boom");
      },
      resource: "systems",
      action: "read",
      condition: { op: "exists", attr: "principal.id" },
    } as unknown as AbacPolicyCreateInput;
    let caught: unknown;
    try {
      client.abacPolicies.create(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).message).toContain("abacPolicies.create");
    expect((caught as Error).message).toContain("name");
    // The getter's OWN message is not the SDK's contract message...
    expect((caught as Error).message).not.toContain("getter boom");
    // ...but the original error is preserved on `.cause`.
    expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(
      Error,
    );
    expect(calls).toHaveLength(0);
  });

  it("converts a throwing getter on a LATER field (`priority`) into a TypeError", () => {
    // Proves the fix is not first-field-only — every snapshot read is
    // wrapped, not just the first.
    const { client, calls } = makeMockedClient([]);
    const evil = {
      name: "ok",
      resource: "systems",
      action: "read",
      condition: { op: "exists", attr: "principal.id" },
      get priority(): unknown {
        throw new Error("priority boom");
      },
    } as unknown as AbacPolicyCreateInput;
    expect(() => client.abacPolicies.create(evil)).toThrow(TypeError);
    expect(() => client.abacPolicies.create(evil)).toThrow(/priority/);
    expect(calls).toHaveLength(0);
  });

  it("a throwing getter does NOT leak as a non-TypeError exception class", () => {
    // The getter throws a RangeError; the SDK still surfaces a
    // TypeError (the documented input-contract class), not RangeError.
    const { client } = makeMockedClient([]);
    const evil = {
      get name(): unknown {
        throw new RangeError("range boom");
      },
      resource: "systems",
      action: "read",
      condition: { op: "exists", attr: "principal.id" },
    } as unknown as AbacPolicyCreateInput;
    let caught: unknown;
    try {
      client.abacPolicies.create(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught).not.toBeInstanceOf(RangeError);
  });
});
