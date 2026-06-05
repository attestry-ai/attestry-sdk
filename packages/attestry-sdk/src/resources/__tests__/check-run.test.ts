import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type { CheckInput, CheckResponse } from "../check.js";
import type { FetchLike } from "../../types.js";

// ─── check.run — POST + JSON body, sync request/response ────────────────────
//
// Wire shape (from src/app/api/v1/check/route.ts):
//   POST /api/v1/check
//   Content-Type: application/json
//   Body: {systemId: <UUID>, frameworks?: string[]}
//   → {success: true, data: {compliant, score, issues, activeAttestations,
//                            lastAssessedAt, checkedAt}}
//
// Fourth non-decisions resource on the SDK; sibling to
// IncidentsResource / DecisionsResource / ChatResource /
// AuditLogResource / RegulatoryChangesResource /
// ComplianceCheckResource.
//
// **Multi-permission UNION auth** (carry-forward #45) — kernel uses
// `requireApiKeyWithPermission(req, READ_ASSESSMENTS, READ_SYSTEMS)`
// which is `Array.some()`-based. A key with EITHER permission
// succeeds; 403 fires only when the key has NEITHER. Single 403 test
// case (the union-auth pattern collapses what intuition suggests as
// 3 cases to 1).
//
// **FIRST SDK route to PRE-VALIDATE every Zod closed-spec rule
// synchronously** — kernel uses `parseBody(request, checkSchema)`,
// same as `incidents.create` etc. (so 422 from Zod has been a
// consumer-visible surface since v0.1 for non-pre-validating routes).
// In `check.run` the SDK pre-validates every Zod closed-spec rule
// (UUID format on systemId, framework string length 1-100, array
// length cap 20) synchronously. The runtime checks always run
// regardless of TypeScript types — `as any` casts do NOT bypass
// them. So 422 reaches consumers ONLY via kernel rule changes the
// SDK hasn't synced to. New invariant candidates #49 (Zod input →
// SDK pre-validates closed-spec rules) and #51 (POST + Zod body →
// SDK TypeError is primary path, kernel 422 is fallback for
// un-pre-validated rules).
//
// **Asymmetric cross-org error code (partial #47 carry-forward)** —
// cross-org systemId collapses to 404 "System not found" (mirror of
// decisions.retrieve / compliance-check). No orgName twin here, so
// only the 404 half applies.
//
// **THREE silent kernel-side truncations** (faithful courier; new
// invariant candidate #50) — `issues` slice(0, 20), `assessments`
// limit(100), `attestations` limit(50). Each documented in JSDoc +
// README + drift-pinned.
//
// **`score` defaults to 0 (NOT null)** — kernel surface gap.
// Consumers MUST check `lastAssessedAt === null` to distinguish "no
// completed assessment" from "scored zero". Asymmetric with
// compliance-check.
//
// **NO URIError defense on body fields** — POST body uses
// JSON.stringify (not encodeURIComponent), so lone UTF-16 surrogates
// in framework strings pass through verbatim as `\uDxxx` escapes.
// Asymmetric with compliance-check / decisions / incidents / audit-
// log / regulatory-changes which DO need the URIError guard (query-
// string paths). systemId is still pre-validated as a UUID, which
// happens to also reject lone-surrogate-only strings (they don't
// match the hex regex).

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
    // Resource tests disable retry so a 429 mock doesn't hang on
    // backoff and accidentally consume the next mock response.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const VALID_UUID = "11111111-1111-1111-1111-111111111111";

// A representative wire-shape response covering every documented
// field (6 top-level fields). Used as the happy-path mock baseline.
const MOCK_RESPONSE: CheckResponse = {
  compliant: true,
  score: 87,
  issues: [],
  activeAttestations: 2,
  lastAssessedAt: "2026-04-21T12:34:56.000Z",
  checkedAt: "2026-05-11T15:00:00.000Z",
};

describe("check.run — happy path", () => {
  it("POSTs /api/v1/check with a JSON body containing systemId", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/check");
    expect(url.search).toBe("");
    // Body is the JSON-serialized input — systemId required, no
    // frameworks key when omitted by the caller (kernel's Zod schema
    // marks it optional).
    expect(calls[0].body).toBeDefined();
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({ systemId: VALID_UUID });
    expect(out).toEqual(MOCK_RESPONSE);
  });

  it("POSTs body with systemId AND frameworks when provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: ["EU_AI_ACT", "ISO_42001"],
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      systemId: VALID_UUID,
      frameworks: ["EU_AI_ACT", "ISO_42001"],
    });
  });

  it("returns the response shape unchanged (envelope unwrapped)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    // Verify envelope was unwrapped: top-level keys are the 6
    // documented fields, NOT success + data.
    expect(Object.keys(out).sort()).toEqual(
      [
        "compliant",
        "score",
        "issues",
        "activeAttestations",
        "lastAssessedAt",
        "checkedAt",
      ].sort(),
    );
  });

  it("forwards x-api-key + Accept + Content-Type headers (POST + body)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({ systemId: VALID_UUID });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("returns all 6 documented fields with their documented types", async () => {
    // Sanity check: every field in the documented CheckResponse
    // interface round-trips. Drift on this test = kernel-side route
    // emits new field name OR SDK interface drift; cross-check
    // sdk-drift.test.ts.
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(typeof out.compliant).toBe("boolean");
    expect(typeof out.score).toBe("number");
    expect(Array.isArray(out.issues)).toBe(true);
    expect(typeof out.activeAttestations).toBe("number");
    expect(typeof out.lastAssessedAt === "string" || out.lastAssessedAt === null).toBe(true);
    expect(typeof out.checkedAt).toBe("string");
  });
});

describe("check.run — input validation (pre-fetch)", () => {
  it("throws TypeError for null input — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run(null as unknown as CheckInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run(undefined as unknown as CheckInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input (typeof [] === 'object')", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run([] as unknown as CheckInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string / number / boolean)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run("uuid" as unknown as CheckInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.check.run(42 as unknown as CheckInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.check.run(true as unknown as CheckInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty object — systemId is required", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({} as unknown as CheckInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.check.run({} as unknown as CheckInput),
    ).toThrow(/`systemId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for explicit `systemId: undefined`", () => {
    // Distinct from "no systemId key at all" — TS users may pass
    // `{systemId: undefined}` via spread of a partial object. The
    // SDK treats own-but-undefined as not-provided (same as missing
    // key) and rejects with the "required" message.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({
        systemId: undefined,
      } as unknown as CheckInput),
    ).toThrow(/`systemId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty systemId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({ systemId: "" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.check.run({ systemId: "" }),
    ).toThrow(/`systemId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId (number / null / object)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({
        systemId: 42 as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.check.run({
        systemId: null as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.check.run({
        systemId: { nested: true } as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for systemId with invalid UUID format (D2 — SDK pre-validates)", () => {
    // **D2 deviation from complianceCheck.check** which deferred UUID
    // format validation to the kernel (returning 400). Here the SDK
    // pre-validates the RFC 4122 hyphenated form synchronously,
    // giving consumers a faster + clearer error than waiting for the
    // kernel's 422 with `fieldErrors`. Codifies new invariant #49
    // (Zod-schema-validated input → pre-validate closed-spec rules).
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({ systemId: "not-a-uuid" }),
    ).toThrow(/must be an RFC 4122 hyphenated UUID/);
    expect(() =>
      client.check.run({ systemId: "00000000-0000-0000-0000" }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      // Wrong segment lengths.
      client.check.run({ systemId: "1111111-1111-1111-1111-111111111111" }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for systemId without hyphens (32-char hex)", () => {
    // The Zod regex requires hyphens at positions 8/13/18/23. A
    // hyphen-stripped 32-char hex string fails the regex. SDK
    // pre-validation catches it.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({
        systemId: "11111111111111111111111111111111",
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("accepts lowercase UUID (regex is case-insensitive)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: "abcdef12-3456-7890-abcd-ef1234567890",
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).systemId).toBe(
      "abcdef12-3456-7890-abcd-ef1234567890",
    );
  });

  it("accepts uppercase UUID (regex is case-insensitive)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: "ABCDEF12-3456-7890-ABCD-EF1234567890",
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).systemId).toBe(
      "ABCDEF12-3456-7890-ABCD-EF1234567890",
    );
  });

  it("throws TypeError for systemId containing lone UTF-16 surrogates (incidentally fails UUID regex)", () => {
    // POST body uses JSON.stringify (not encodeURIComponent), so the
    // URIError defense class (carry-forward #32) doesn't apply
    // directly to body fields. **The rejection here is INCIDENTAL**:
    // lone-surrogate characters (U+D800-U+DFFF) aren't valid hex
    // characters, so they fail the UUID regex `[0-9a-fA-F]`. If a
    // future kernel relaxes `systemId` from RFC 4122 UUID to a
    // free-form string (e.g., to support ULID / KSUID / external
    // IDs), the SDK's UUID pre-validation would be removed AND this
    // incidental defense would disappear. JSON.stringify still
    // handles lone surrogates by emitting `\uDxxx` escapes (no
    // URIError), so the kernel would receive the lone surrogate
    // verbatim — semantically faithful courier, but the SDK's
    // explicit reject of lone-surrogate `systemId` would no longer
    // hold.
    //
    // Session-16 hostile review LOW #3 flagged this dependency for
    // documentation. If a future schema relaxation happens, this
    // pin needs to be either removed (faithful courier, kernel
    // accepts) or replaced with an explicit lone-surrogate guard
    // (if the SDK decides to keep rejecting them for clarity).
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({ systemId: "\uD800" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.check.run({
        systemId: "11111111-1111-1111-1111-11111111111\uD800",
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworks is not an array (string / object)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: "EU_AI_ACT" as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: { 0: "EU_AI_ACT", length: 1 } as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworks is null (explicitly set, not omitted)", () => {
    // Session-16 hostile review MEDIUM #1: the
    // `if (hasFrameworks && frameworksRaw !== undefined)` guard
    // SHOULD let `null` enter the Array.isArray branch (since
    // null !== undefined), producing a "must be an array (got
    // null)" TypeError. Pin this so a refactor that changes the
    // guard to `hasFrameworks` alone (dropping the `!== undefined`)
    // doesn't silently let `null` slip through to the kernel.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: null as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array when provided.*got null/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworks contains a non-string element", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: [42 as unknown as string],
      }),
    ).toThrow(/`frameworks\[0\]` must be a string/);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: ["EU_AI_ACT", null as unknown as string],
      }),
    ).toThrow(/`frameworks\[1\]` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworks contains an empty string (Zod .min(1))", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: [""],
      }),
    ).toThrow(/must be a non-empty string/);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: ["EU_AI_ACT", ""],
      }),
    ).toThrow(/`frameworks\[1\]` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworks element exceeds 100 chars (Zod .max(100))", () => {
    const { client, calls } = makeMockedClient([]);
    const tooLong = "x".repeat(101);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: [tooLong],
      }),
    ).toThrow(/exceeds the kernel's max length of 100 chars/);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: [tooLong],
      }),
    ).toThrow(/got 101/);
    expect(calls).toHaveLength(0);
  });

  it("accepts frameworks element at the 100-char boundary", async () => {
    // Boundary case: exactly 100 chars is accepted (Zod .max(100) is
    // inclusive). 101 fails (pinned above).
    const exactly100 = "x".repeat(100);
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: [exactly100],
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).frameworks).toEqual([exactly100]);
  });

  it("throws TypeError when frameworks array length exceeds 20 (Zod .max(20))", () => {
    const { client, calls } = makeMockedClient([]);
    const tooMany = Array.from({ length: 21 }, (_, i) => `fw${i}`);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: tooMany,
      }),
    ).toThrow(/exceeds the kernel's max length of 20/);
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: tooMany,
      }),
    ).toThrow(/got 21/);
    expect(calls).toHaveLength(0);
  });

  it("accepts frameworks at the 20-element / 100-char boundary", async () => {
    // Combined boundary: 20 elements, each 100 chars. Zod's nested
    // bounds are both inclusive, so this is the largest valid input.
    const exactly20 = Array.from({ length: 20 }, () => "x".repeat(100));
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: exactly20,
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).frameworks).toHaveLength(20);
  });

  it("accepts an empty frameworks array (kernel treats as no filter)", async () => {
    // Zod's .max(20) accepts arrays of length 0..20. An empty array
    // is valid input; the kernel's filter logic at route.ts:66-71
    // short-circuits when `body.frameworks.length === 0` and uses all
    // assessments. Pin: SDK passes empty array through unchanged.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: [],
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).frameworks).toEqual([]);
  });

  it("omits frameworks from the body when caller omits it", async () => {
    // `frameworks: undefined` is treated as not-provided. The body
    // JSON does NOT include a `frameworks` key — distinct from
    // explicit `frameworks: []`.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({ systemId: VALID_UUID });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({ systemId: VALID_UUID });
    expect("frameworks" in parsed).toBe(false);
  });

  it("explicit `frameworks: undefined` is equivalent to omission", async () => {
    // TS allows `{systemId, frameworks: undefined}`. The SDK's
    // `Object.hasOwn` returns true (the key is an own property), but
    // the value-undefined check short-circuits before the array
    // validation. Pin: same behavior as no frameworks key at all.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({ systemId: VALID_UUID });
    expect("frameworks" in parsed).toBe(false);
  });

  it("defends against prototype pollution on systemId presence (Object.hasOwn defense, generalization of #48)", () => {
    // If `Object.prototype.systemId = "<some-uuid>"` were set
    // elsewhere in the process, a consumer's
    // `client.check.run({})` would otherwise read the polluted
    // prototype value via the indexer (`(input as any).systemId`)
    // and silently submit it to the kernel. The SDK uses
    // `Object.hasOwn` to defend: own properties only count as
    // "provided". Test pin: pollute Object.prototype, pass `{}`,
    // confirm the SDK throws "required" (not silently passes).
    //
    // Symmetric to compliance-check's hostile finding F.H1
    // (prototype-pollution gap on the XOR `in` check) — same defense
    // mechanism, generalized to single-required-field routes.
    //
    // CRITICAL: clean up the polluted prototype in a finally block
    // so subsequent tests aren't affected.
    const { client, calls } = makeMockedClient([]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "systemId",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).systemId =
        "11111111-1111-1111-1111-111111111111";
      // Passing {} — should reject as "required" despite the
      // prototype-polluted systemId.
      expect(() =>
        client.check.run({} as unknown as CheckInput),
      ).toThrow(/`systemId` is required/);
      // Also defend against pollution on `frameworks` — passing
      // {systemId: valid} should NOT pick up a polluted frameworks
      // array. Verified by checking the wire body has no
      // `frameworks` key.
      (Object.prototype as unknown as Record<string, unknown>).frameworks =
        ["EVIL_FRAMEWORK"];
      // We can't call .run() and check the body without a mock fetch
      // that succeeds — but the validation step we care about is the
      // `objectHasOwn` check, which returns false for the polluted
      // frameworks key. The body construction in the resource
      // depends on `validatedFrameworks` being undefined when the
      // own-property check fails. Indirect verification via a
      // separate mock.
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "systemId", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .systemId;
      }
      delete (Object.prototype as unknown as Record<string, unknown>)
        .frameworks;
    }
    expect(calls).toHaveLength(0);
  });

  it("prototype-polluted frameworks does NOT inject into body (Object.hasOwn defense, generalization of #48)", async () => {
    // Symmetric to the systemId pollution pin above, but with a
    // mocked-success fetch so we can inspect the wire body. If the
    // SDK uses `objectHasOwn` consistently, a prototype-polluted
    // `frameworks` does NOT leak into the body when the caller
    // provides `{systemId: valid}` only.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "frameworks",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).frameworks =
        ["EVIL_FRAMEWORK"];
      await client.check.run({ systemId: VALID_UUID });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed).toEqual({ systemId: VALID_UUID });
      // CRITICAL: use Object.hasOwn (own-property only), NOT `in`
      // (prototype-walking) — `parsed` is a plain object that
      // inherits Object.prototype's polluted `frameworks` via `in`,
      // even though JSON.stringify only emits own enumerable
      // properties (and JSON.parse only creates own ones). The bug
      // we're defending against is the SDK putting `frameworks` in
      // the wire body — own-property check is the correct
      // assertion.
      expect(Object.hasOwn(parsed, "frameworks")).toBe(false);
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "frameworks", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .frameworks;
      }
    }
  });
});

describe("check.run — body encoding", () => {
  it("body uses Zod-schema field names (systemId, frameworks)", async () => {
    // Sanity pin against camelCase / snake_case / Pascal-case
    // refactor drift. The kernel's Zod schema uses systemId +
    // frameworks; the SDK body must use the same keys.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: ["EU_AI_ACT"],
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.keys(parsed).sort()).toEqual(["frameworks", "systemId"]);
  });

  it("accepts lone-surrogate strings in frameworks (faithful courier — JSON.stringify handles them)", async () => {
    // **D4 — NO URIError defense on body fields**. POST body uses
    // JSON.stringify, which emits lone UTF-16 surrogates as literal
    // `\uDxxx` escapes (per JSON spec). Zod's `.string().min(1).max(100)`
    // accepts any string of length 1-100 — lone surrogates are
    // length-1 strings. SDK does NOT reject; kernel processes them.
    // Asymmetric with compliance-check / decisions / incidents /
    // audit-log / regulatory-changes which DO reject lone surrogates
    // (those resources use query-string paths through
    // encodeURIComponent, which throws URIError).
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: ["\uD800"],
    });
    expect(calls).toHaveLength(1);
    // JSON.stringify emits the lone surrogate as a literal escape
    // sequence; the kernel JSON.parse decodes it back. The wire body
    // contains the literal escape representation.
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.frameworks).toEqual(["\uD800"]);
  });

  it("does not mutate the input object (read-only)", async () => {
    // A caller passing a frozen object must not see the SDK crash.
    // The resource reads `input.systemId` / `input.frameworks` and
    // creates a fresh body object — no in-place assignment.
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    const input: CheckInput = Object.freeze({
      systemId: VALID_UUID,
      frameworks: Object.freeze(["EU_AI_ACT", "ISO_42001"]) as string[],
    });
    const snapshot = JSON.stringify(input);
    await client.check.run(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});

describe("check.run — error paths", () => {
  it("surfaces a 401 (no/invalid API key) as AttestryAPIError", async () => {
    // Multi-permission UNION auth: 401 is the no/invalid-key branch
    // (`requireApiKey` fires first inside
    // `requireApiKeyWithPermission`). Distinct from 403 below.
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required" },
      },
    ]);
    try {
      await client.check.run({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 403 (key has NEITHER READ_ASSESSMENTS NOR READ_SYSTEMS — union-auth) as AttestryAPIError", async () => {
    // Multi-permission UNION auth (#45 carry-forward): 403 fires
    // ONLY when the key has NEITHER required permission. A key with
    // EITHER permission would succeed (200), not 403. Single test
    // case — the union-auth pattern collapses three
    // intuition-suggesting cases to one.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error:
            "API key lacks required permission. Required: read:assessments or read:systems. Key has: read:documents.",
        },
      },
    ]);
    try {
      await client.check.run({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
      expect((err as AttestryAPIError).message).toMatch(
        /read:assessments or read:systems/,
      );
    }
  });

  it("surfaces a 404 (system not found OR cross-org systemId collapsed) as AttestryAPIError", async () => {
    // **Asymmetric cross-org error code pin** (partial #47 carry-
    // forward). The kernel's `and(eq id, eq orgId)` at route.ts:42-51
    // collapses cross-org systemId to 404 "System not found" (mirror
    // of decisions.retrieve). Consumers writing defensive error-
    // handling logic must recognize: a 404 may be "not your org" OR
    // "genuine missing UUID".
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "System not found" },
      },
    ]);
    try {
      await client.check.run({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
      expect((err as AttestryAPIError).message).toMatch(/System not found/);
    }
  });

  it("surfaces a 422 (kernel Zod schema rejection, only reachable via kernel-side rule changes the SDK hasn't synced to) as AttestryAPIError with actual kernel body shape", async () => {
    // **First SDK route to PRE-VALIDATE every Zod closed-spec rule
    // synchronously**. The SDK's runtime checks always run regardless
    // of TypeScript types (`as any` casts don't bypass them), so 422
    // normally doesn't reach consumers. To test the kernel surface,
    // we mock the ACTUAL kernel emit shape from
    // src/lib/api.ts:84-91 + 38-40:
    //
    //   const fieldErrors = result.error.errors.map((e) => ({
    //     path: e.path.join("."),
    //     message: e.message,
    //   }));
    //   throw new BodyParseError("Validation failed.", fieldErrors);
    //   // ...
    //   if (error instanceof BodyParseError) {
    //     return errorResponse(error.message, 422, error.fieldErrors);
    //   }
    //
    // And errorResponse at src/lib/api.ts:28-42 builds:
    //   {success: false, error: <message>, details: <fieldErrors>}
    //
    // So the wire body on 422 is:
    //   {success: false, error: "Validation failed.",
    //    details: [{path: "<dotted-path>", message: "<zod-msg>"}, ...]}
    //
    // **NOT** `{error: "Invalid request body", fieldErrors: {key:
    // [string, ...]}}` (the build-round mock was fictional — found
    // by session-16 independent hostile review HIGH #1; fixed here).
    //
    // The SDK's `AttestryAPIError.details` field carries the FULL
    // parsed body, so consumers reading the field errors should
    // iterate `apiErr.details.details` (kernel's `details` array
    // nested under the SDK's parsed-body wrapper).
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            { path: "systemId", message: "Invalid uuid" },
          ],
        },
      },
    ]);
    try {
      await client.check.run({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      // `error` string from the wire body — exact match including
      // trailing period (the literal kernel emit).
      expect(apiErr.message).toBe("Validation failed.");
      // `apiErr.details` is the full parsed body; the kernel's
      // `details` array nests under it. Consumers reading
      // field-by-field errors iterate `apiErr.details.details`.
      const wireBody = apiErr.details as {
        success: false;
        error: string;
        details: Array<{ path: string; message: string }>;
      };
      expect(wireBody.error).toBe("Validation failed.");
      expect(Array.isArray(wireBody.details)).toBe(true);
      expect(wireBody.details).toEqual([
        { path: "systemId", message: "Invalid uuid" },
      ]);
    }
  });

  it("surfaces a 429 (rate limit) as AttestryAPIError when retry is disabled", async () => {
    // makeMockedClient sets retry: {maxRetries: 0} — so the 429
    // surfaces immediately rather than auto-retrying. With retry
    // enabled (the default), invariant #18 covers the auto-retry
    // path; pinned in the abort + retry section below.
    const { client } = makeMockedClient([
      {
        status: 429,
        body: { success: false, error: "Too many requests" },
      },
    ]);
    try {
      await client.check.run({ systemId: VALID_UUID });
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
        body: { success: false, error: "Internal server error" },
      },
    ]);
    try {
      await client.check.run({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(500);
    }
  });

  it("P3: wrong content-type (text/plain) throws AttestryAPIError from transport", async () => {
    // P3 hardening: the transport's sync content-type guard fires
    // BEFORE readBody, so wrong content-type rejects before the
    // resource layer's P2 shape validator. AttestryAPIError carries
    // the response status (200 here — the worst case where a proxy
    // / LB returns 200 OK with a non-JSON body).
    const callsLocal: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      callsLocal.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      return new Response(JSON.stringify({ success: true, data: MOCK_RESPONSE }), {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    try {
      await client.check.run({ systemId: VALID_UUID });
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

describe("check.run — response shape preservation", () => {
  it("score=0 round-trips as 0 (NOT null, NOT undefined) — kernel surface gap D8", async () => {
    // **The non-obvious gotcha pin**. Kernel uses `score: 0` as the
    // default when no completed assessment exists (route.ts:84 —
    // `typeof scores?.overallScore === "number" ? scores.overallScore : 0`).
    // Consumers cannot distinguish "scored zero / fails compliance"
    // from "no completed assessment yet" via `score` alone — they
    // MUST check `lastAssessedAt === null` to differentiate.
    // **Asymmetric with compliance-check** which used `null` for "no
    // data". Pin: SDK does NOT mask (faithful courier — kernel
    // surface gap is the consumer's to interpret).
    const noAssessment: CheckResponse = {
      compliant: false,
      score: 0,
      issues: [],
      activeAttestations: 0,
      lastAssessedAt: null,
      checkedAt: "2026-05-11T15:00:00.000Z",
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: noAssessment } },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.score).toBe(0);
    expect(typeof out.score).toBe("number");
    expect(out.lastAssessedAt).toBeNull();
    // Pinned-together: the SDK preserves the (score=0, lastAssessedAt=null)
    // tuple so consumers can apply the documented disambiguation.
  });

  it("score>0 round-trips with the documented numeric value", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_RESPONSE, score: 87 } } },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.score).toBe(87);
  });

  it("lastAssessedAt=null round-trips (no completed assessment exists)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, lastAssessedAt: null },
        },
      },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.lastAssessedAt).toBeNull();
  });

  it("lastAssessedAt=ISO string round-trips when a completed assessment exists", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.lastAssessedAt).toBe("2026-04-21T12:34:56.000Z");
  });

  it("issues=[] round-trips (no compliance gaps)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_RESPONSE, issues: [] } } },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.issues).toEqual([]);
  });

  it("issues with elements round-trips (non-empty array preservation)", async () => {
    const issues = [
      "Missing risk classification",
      "No human-oversight policy",
      "Incomplete training data documentation",
    ];
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_RESPONSE, issues } } },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.issues).toEqual(issues);
  });

  it("issues at the 20-element cap round-trips WITHOUT a truncation indicator (D9 — invariant #50)", async () => {
    // **Kernel surface gap pin** — the kernel hardcodes
    // `gaps.slice(0, 20)` at route.ts:90. If the latest completed
    // assessment has >20 gaps, the SDK consumer sees a truncated
    // array with NO indicator. No `total` field, no `hasMore` cursor,
    // no `truncated` boolean. Faithful courier; documented in JSDoc
    // + README + drift-pinned. New invariant candidate #50.
    const twentyIssues = Array.from(
      { length: 20 },
      (_, i) => `Issue ${i + 1}`,
    );
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, issues: twentyIssues },
        },
      },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.issues).toHaveLength(20);
    // No truncation indicator — consumers cannot detect from the
    // wire shape alone that they've hit the cap.
    expect(out).not.toHaveProperty("total");
    expect(out).not.toHaveProperty("hasMore");
    expect(out).not.toHaveProperty("issuesTruncated");
  });

  it("activeAttestations=0 round-trips as 0 (numeric, not undefined)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, activeAttestations: 0 },
        },
      },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.activeAttestations).toBe(0);
    expect(typeof out.activeAttestations).toBe("number");
  });

  it("compliant=true and compliant=false round-trip as booleans", async () => {
    const { client: c1 } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_RESPONSE, compliant: true } },
      },
    ]);
    expect((await c1.check.run({ systemId: VALID_UUID })).compliant).toBe(
      true,
    );

    const { client: c2 } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_RESPONSE, compliant: false } },
      },
    ]);
    expect((await c2.check.run({ systemId: VALID_UUID })).compliant).toBe(
      false,
    );
  });

  it("passes through extra unknown top-level fields verbatim (forward-compat)", async () => {
    // If the kernel adds a new field before the SDK is bumped, the
    // extra field must round-trip — faithful courier. Pin: the
    // unknown field arrives at the consumer (typed as `unknown` at
    // the call site, but present at runtime). Mirror of the
    // regulatoryChanges / compliance-check forward-compat pins.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_RESPONSE,
            futureField: "added kernel-side without an SDK bump",
            truncated: true,
          },
        },
      },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect((out as unknown as Record<string, unknown>).futureField).toBe(
      "added kernel-side without an SDK bump",
    );
    expect((out as unknown as Record<string, unknown>).truncated).toBe(true);
  });
});

describe("check.run — P2 response shape hardening", () => {
  it("P2: throws AttestryError when kernel response is null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected an object response from the kernel \(got null\)/);
  });

  it("P2: throws AttestryError when kernel response is a scalar (string)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: "scalar-instead-of-object" } },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected an object response from the kernel \(got string\)/);
  });

  it("P2: throws AttestryError when kernel response is an array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_RESPONSE] } },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected an object response from the kernel \(got array\)/);
  });

  it("P2: throws AttestryError when response.compliant is not a boolean", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, compliant: "yes" },
        },
      },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected response\.compliant to be a boolean \(got string\)/);
  });

  it("P2: throws AttestryError when response.score is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_RESPONSE, score: "87" } },
      },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected response\.score to be a number \(got string\)/);
  });

  it("P2: throws AttestryError when response.issues is not an array", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, issues: "not-an-array" },
        },
      },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected response\.issues to be an array \(got string\)/);
  });

  it("P2: throws AttestryError when response.activeAttestations is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, activeAttestations: "2" },
        },
      },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.activeAttestations to be a number \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.lastAssessedAt is not string-or-null (number)", async () => {
    // lastAssessedAt's documented type is `string | null`. A number
    // is neither — must reject. Number is the bug class that masks
    // as "this thing has a timestamp" but isn't ISO-shaped.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, lastAssessedAt: 1234567890 },
        },
      },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.lastAssessedAt to be a string or null \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.checkedAt is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, checkedAt: 12345 },
        },
      },
    ]);
    await expect(
      client.check.run({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected response\.checkedAt to be a string \(got number\)/);
  });

  it("P2 error is AttestryError (NOT AttestryAPIError) — distinct surface for kernel-shape regressions", async () => {
    // Pin the error CLASS on the P2 path. AttestryAPIError carries
    // an HTTP status; AttestryError does not. A kernel-shape
    // regression isn't an "API error" in the HTTP sense — the
    // server returned 200 with a malformed body. Consumers'
    // defensive try/catch can distinguish.
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    try {
      await client.check.run({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      // AttestryAPIError extends AttestryError, so the negative
      // assertion is the meaningful one.
      expect(err).not.toBeInstanceOf(AttestryAPIError);
    }
  });
});

describe("check.run — abort + retry semantics", () => {
  it("forwards a pre-aborted AbortSignal through RequestOptions (no fetch)", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.check.run(
        { systemId: VALID_UUID },
        { signal: controller.signal },
      ),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally", async () => {
    // Mirror of compliance-check / regulatoryChanges / decisions
    // signal-forwarding pins. Exercises the "signal exists but never
    // fires" branch in the transport's signal composition.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    const controller = new AbortController();
    const out = await client.check.run(
      { systemId: VALID_UUID },
      { signal: controller.signal },
    );
    expect(out.score).toBe(87);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies (independent of resource-helper default)", async () => {
    // The makeMockedClient helper sets retry: {maxRetries: 0} by
    // default. Per-call override should re-enable retry for this
    // single call. Pin against the retry middleware's per-call
    // precedence (matches decisions / regulatoryChanges /
    // compliance-check patterns).
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "x" } },
      { body: { success: true, data: MOCK_RESPONSE } },
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
    const promise = client.check.run(
      { systemId: VALID_UUID },
      { retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 } },
    );
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out.score).toBe(87);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });
});

describe("check.run — hostile round residual gaps", () => {
  it("H1: TOCTOU on systemId via input-getter — SDK reads exactly once and validates the snapshot", async () => {
    // Hostile concern: a Proxy or getter-defining input could yield
    // DIFFERENT values across multiple reads of `input.systemId`.
    // The SDK validates the snapshot AND sends the snapshot — so a
    // proxy can't slip a malicious value past validation by toggling
    // between "valid" and "evil" across reads.
    //
    // Pin: define an object with a `systemId` getter that returns a
    // valid UUID on the FIRST read and a different value on
    // subsequent reads. Verify the wire body contains the FIRST-read
    // value (the validated snapshot), not any subsequent value.
    let getterCallCount = 0;
    const input = {} as { systemId: string };
    Object.defineProperty(input, "systemId", {
      configurable: true,
      enumerable: true,
      get() {
        getterCallCount++;
        return getterCallCount === 1 ? VALID_UUID : "22222222-2222-2222-2222-222222222222";
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run(input);
    expect(calls).toHaveLength(1);
    // The wire body MUST contain the first-read value — proof the
    // SDK validated the snapshot and sent the snapshot (not a
    // re-read).
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.systemId).toBe(VALID_UUID);
    // Confirm the getter was called exactly ONCE during the SDK's
    // own work — defense-in-depth: any extra read after the
    // validation snapshot would have re-invoked the getter.
    expect(getterCallCount).toBe(1);
  });

  it("H2: TOCTOU on frameworks via Proxy-array — Array.from snapshot collapses validate+send to a single read", async () => {
    // Hostile concern: a Proxy whose `.length` and `[i]` return
    // DIFFERENT values across reads could slip past per-element
    // validation. The SDK uses `Array.from(frameworksRaw)` to
    // materialize the snapshot in ONE pass; subsequent operations
    // (length check, per-element validation, body construction)
    // all read from the snapshot.
    //
    // **Session-16 second-hostile-review MEDIUM #2 fix**: the
    // previous H2 had a "evil proxy" with `readsAfterSnapshot`
    // counter that was declared but NEVER incremented — the
    // evil-branch was dead code, and the bookend assertion at the
    // end just tested a benign proxy. Real TOCTOU defense was only
    // partially proven (the counting proxy proved single-pass, but
    // the evil-flip case was unexercised).
    //
    // Fix: use a STATE-BASED proxy that returns valid values on the
    // first N reads (consumed by Array.from inside the SDK) and
    // EVIL values on read N+1 onward. If the SDK is correct (uses
    // the snapshot for everything downstream), only the first N
    // reads happen and the wire body has valid values. If the SDK
    // re-reads from the proxy (e.g., a refactor that assigns
    // `body.frameworks = frameworksRaw` instead of the snapshot),
    // JSON.stringify of the proxy would trigger reads N+1+ and the
    // wire body would carry EVIL values.
    const evilArray = ["EU_AI_ACT", "ISO_42001"];
    let getCallCount = 0;
    const stateFlippingProxy: unknown = new Proxy(evilArray, {
      get(target, prop, receiver) {
        if (typeof prop === "string" && /^\d+$/.test(prop)) {
          getCallCount++;
          const idx = Number(prop);
          // First 2 reads (one per element via Array.from inside
          // the SDK): return valid. Reads 3+ would only happen if
          // the SDK re-reads from the proxy (broken refactor) —
          // return EVIL so the wire body carries detectable
          // tampering.
          if (getCallCount > 2) {
            return "EVIL_FRAMEWORK";
          }
          return target[idx];
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: stateFlippingProxy as string[],
    });
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    // The wire body MUST contain the FIRST-pass values (the
    // snapshot). If the SDK re-reads from the proxy (e.g., in a
    // broken refactor where body.frameworks = frameworksRaw),
    // JSON.stringify would trigger reads 3+ via the proxy's `get`
    // trap and the body would carry ["EVIL_FRAMEWORK", ...].
    expect(parsed.frameworks).toEqual(["EU_AI_ACT", "ISO_42001"]);
    // Proof of single-pass: getCallCount === 2 means Array.from
    // read each element ONCE, and no downstream operation
    // re-read the proxy. A future refactor that adds a re-read
    // would bump this past 2 and the assertion fires.
    expect(getCallCount).toBe(2);
  });

  it("H3: Object.hasOwn override + Object.prototype.systemId pollution — snapshot defense is what causes rejection (not the secondary undefined-check)", async () => {
    // Hostile concern: a late-loading dep overrides
    // `Object.hasOwn = () => true`. The SDK's module-load snapshot
    // (`const objectHasOwn = Object.hasOwn;`) captured the ORIGINAL
    // implementation, so the override doesn't reach the resource's
    // input checks.
    //
    // **Session-16 second-hostile-review MEDIUM #1 fix**: the previous
    // H3 test passed for the wrong reason. With only the
    // `Object.hasOwn = () => true` override (no prototype pollution),
    // BOTH with-snapshot AND without-snapshot code paths throw
    // "systemId is required" — the snapshot defense isn't actually
    // exercised because the secondary `systemIdRaw === undefined`
    // check catches the no-own-property case anyway (a polluted
    // `Object.hasOwn` returning true + a plain `{}` input means the
    // property read returns undefined, which trips the secondary
    // check).
    //
    // To actually exercise the snapshot defense, we ALSO pollute
    // `Object.prototype.systemId` with a valid-looking UUID. Now:
    //   - With snapshot: `objectHasOwn(input, "systemId")` uses the
    //     original Object.hasOwn (own-only) → returns false →
    //     `hasSystemId = false` → throws "required". ✅ Correct.
    //   - Without snapshot (hypothetical broken refactor):
    //     `Object.hasOwn(input, "systemId")` is the overridden
    //     function returning true → `hasSystemId = true` → then
    //     `systemIdRaw = input.systemId` reads via prototype chain →
    //     gets the polluted UUID → passes UUID regex → SDK silently
    //     SENDS THE POLLUTED VALUE to the kernel.
    //
    // The combined pollution + override is the only configuration
    // that ACTUALLY exercises the snapshot defense. Pin: SDK throws
    // "required" (the snapshot wins). Mirror of session-15
    // hostile-review H15 strengthening on compliance-check.
    const { client, calls } = makeMockedClient([
      // Mock response in case a broken refactor accidentally sends the
      // polluted value — we WANT this to never be consumed.
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    const originalHasOwn = Object.hasOwn;
    const originalSystemIdDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "systemId",
    );
    try {
      // Override the global Object.hasOwn AND pollute Object.prototype.systemId.
      (Object as { hasOwn: unknown }).hasOwn = () => true;
      (Object.prototype as unknown as Record<string, unknown>).systemId =
        VALID_UUID;
      // Sanity: confirm the global is overridden and the polluted
      // value would be readable via prototype walk.
      expect((Object.hasOwn as unknown as () => boolean)()).toBe(true);
      expect(({} as unknown as { systemId: string }).systemId).toBe(
        VALID_UUID,
      );
      // SDK MUST throw "required" — the snapshot defense rejects
      // before the prototype-polluted value can be read.
      expect(() =>
        client.check.run({} as unknown as CheckInput),
      ).toThrow(/`systemId` is required/);
    } finally {
      (Object as { hasOwn: typeof originalHasOwn }).hasOwn = originalHasOwn;
      if (originalSystemIdDesc) {
        Object.defineProperty(
          Object.prototype,
          "systemId",
          originalSystemIdDesc,
        );
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .systemId;
      }
    }
    // No fetch was issued — proof the SDK rejected at the snapshot
    // boundary, not after constructing a body with the polluted value.
    expect(calls).toHaveLength(0);
  });

  it("H4: concurrent check.run() calls share no state — each promise resolves independently", async () => {
    // Pin against a future refactor that adds shared state
    // (memoization, response caching, request batching). Each call
    // must construct its own promise; the mocked fetch routes them
    // to distinct mock responses by call order.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_RESPONSE, score: 11 } } },
      { body: { success: true, data: { ...MOCK_RESPONSE, score: 22 } } },
      { body: { success: true, data: { ...MOCK_RESPONSE, score: 33 } } },
    ]);
    const [out1, out2, out3] = await Promise.all([
      client.check.run({ systemId: VALID_UUID }),
      client.check.run({ systemId: VALID_UUID, frameworks: ["EU_AI_ACT"] }),
      client.check.run({ systemId: VALID_UUID, frameworks: ["ISO_42001"] }),
    ]);
    expect(calls).toHaveLength(3);
    expect(out1.score).toBe(11);
    expect(out2.score).toBe(22);
    expect(out3.score).toBe(33);
  });

  it("H5: parallel concurrent calls with different framework filters don't cross-pollinate bodies", async () => {
    // Stronger contract than H4: even when issued in tight
    // succession, each call's body lands on its own request. A
    // future refactor that batches POSTs into a single request OR
    // shares a body-builder closure would surface here.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
      { body: { success: true, data: MOCK_RESPONSE } },
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await Promise.all([
      client.check.run({ systemId: VALID_UUID, frameworks: ["A"] }),
      client.check.run({ systemId: VALID_UUID, frameworks: ["B", "C"] }),
      client.check.run({ systemId: VALID_UUID }),
    ]);
    expect(calls).toHaveLength(3);
    expect(JSON.parse(calls[0].body!).frameworks).toEqual(["A"]);
    expect(JSON.parse(calls[1].body!).frameworks).toEqual(["B", "C"]);
    expect(Object.hasOwn(JSON.parse(calls[2].body!), "frameworks")).toBe(
      false,
    );
  });

  it("H6: 429 auto-retries when retry is enabled (default) and succeeds on second attempt", async () => {
    // Build round only pinned the retry-disabled path. Hostile round
    // adds the retry-enabled path — invariant #18: SDK auto-retries
    // on 429 with exponential backoff. Pin against the retry
    // middleware integration: a 429 → 200 sequence resolves with
    // the 200 body when retry is on. Mirror of regulatoryChanges /
    // compliance-check retry pins.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "rate limited" } },
      { body: { success: true, data: MOCK_RESPONSE } },
    ];
    const calls: MockedRequest[] = [];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "POST",
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
    });
    const promise = client.check.run({ systemId: VALID_UUID });
    // Advance through the retry backoff — DEFAULT_RETRY_OPTIONS has
    // initialDelayMs 1_000, so 2s covers attempt 2.
    await vi.advanceTimersByTimeAsync(2_500);
    const out = await promise;
    expect(out.score).toBe(87);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });

  it("H7: 422 with NO `details` array (forward-compat defensive — kernel ALWAYS includes details today)", async () => {
    // **Forward-compat defensive pin** — today the kernel ALWAYS
    // populates `details` on 422 (parseBody at src/lib/api.ts:84-91
    // unconditionally builds the array, and errorResponse at line
    // 38-40 always passes it through when `details !== undefined`).
    // So this pin exercises an IMPOSSIBLE-TODAY surface: a 422 with
    // just an `error` string and no `details` field. The SDK's
    // transport just surfaces `AttestryAPIError(422, body)` —
    // `extractMessage` reads `error.message` / `error` / `message`
    // (transport.ts:563-577) but NEVER reads `details` or
    // `fieldErrors`. So whether `details` is present, absent, or a
    // different shape doesn't break the SDK error surface.
    //
    // Session-16 independent hostile review MEDIUM #2 + LOW #2:
    // re-framed from "without a fieldErrors body" (build-round
    // wording — based on the fictional `fieldErrors` key) to
    // "without a `details` array (forward-compat)". Pin retains
    // defensive value — if a future kernel splits Zod-vs-business
    // errors and emits 422 without `details` on the business path,
    // this pin documents that the SDK transport still surfaces it
    // cleanly.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.check.run({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.message).toBe("Validation failed.");
      // `apiErr.details` is the parsed body — present even though
      // there's no `details` key inside.
      const wireBody = apiErr.details as {
        success: false;
        error: string;
      };
      expect(wireBody.error).toBe("Validation failed.");
      expect(Object.hasOwn(wireBody, "details")).toBe(false);
    }
  });

  it("H8: body construction omits unknown input keys (defense vs `as any` extras)", async () => {
    // Hostile concern: a consumer using `as any` could pass
    // {systemId, frameworks, evilExtra: "x"} to the SDK. The body
    // construction in `check.run` explicitly assembles a new object
    // with ONLY the documented fields — the extra wouldn't propagate
    // to the wire. This is defensive: a future kernel might reject
    // unknown body keys, OR an `as any` could carry sensitive
    // consumer data unexpectedly.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RESPONSE } },
    ]);
    await client.check.run({
      systemId: VALID_UUID,
      frameworks: ["EU_AI_ACT"],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      evilExtra: "should-not-propagate",
      apiKey: "should-not-propagate-either",
    } as unknown as CheckInput);
    const parsed = JSON.parse(calls[0].body!);
    // Body contains ONLY the documented fields. The extras are
    // dropped by the SDK's explicit body construction.
    expect(Object.keys(parsed).sort()).toEqual(["frameworks", "systemId"]);
    expect(Object.hasOwn(parsed, "evilExtra")).toBe(false);
    expect(Object.hasOwn(parsed, "apiKey")).toBe(false);
  });

  it("H9: UUID with leading/trailing whitespace is rejected (regex is anchored)", () => {
    // Hostile concern: a consumer trims user input to a UUID but
    // misses a trailing space. The SDK's UUID regex uses `^...$`
    // anchors, so any surrounding whitespace fails the pre-validation.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({ systemId: ` ${VALID_UUID}` }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.check.run({ systemId: `${VALID_UUID} ` }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.check.run({ systemId: `\t${VALID_UUID}\n` }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("H10: UUID with prefix/suffix non-hex garbage is rejected (regex anchored)", () => {
    // Hostile concern: a consumer concatenates a UUID with extra
    // bytes (debug prefix, version suffix). The regex anchors reject
    // both forms.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.check.run({ systemId: `prefix${VALID_UUID}` }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.check.run({ systemId: `${VALID_UUID}suffix` }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.check.run({ systemId: `xx${VALID_UUID}yy` }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("H11: frameworks with sparse array (holes → undefined elements) is rejected", () => {
    // Hostile concern: `new Array(3)` or `[, "x", ,]` creates a
    // sparse array with holes. `Array.from` materializes holes as
    // `undefined` (NOT skipped). Each undefined fails the
    // `typeof === "string"` check; the SDK rejects with a clear
    // index-named TypeError.
    const { client, calls } = makeMockedClient([]);
    // eslint-disable-next-line no-sparse-arrays
    const sparseArr = ["EU_AI_ACT", , "ISO_42001"] as unknown as string[];
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: sparseArr,
      }),
    ).toThrow(/`frameworks\[1\]` must be a string \(got undefined\)/);

    // Pure-hole array (length 3, no defined elements).
    const allHoles = new Array(3) as unknown as string[];
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: allHoles,
      }),
    ).toThrow(/`frameworks\[0\]` must be a string \(got undefined\)/);
    expect(calls).toHaveLength(0);
  });

  it("H12: frameworks with non-Array array-like (Set / arguments-object) is rejected", () => {
    // Hostile concern: a consumer passes a Set, Map, or other
    // array-like (NodeList, arguments object) instead of a true
    // Array. `Array.isArray` returns false for ALL of these (only
    // true for instances of Array, including subclasses). The SDK
    // rejects before reaching Array.from, with a clear TypeError.
    const { client, calls } = makeMockedClient([]);

    // Set is iterable but not Array.
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: new Set(["EU_AI_ACT"]) as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);

    // Map is iterable but not Array.
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: new Map([["a", "b"]]) as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);

    // Array-like object with length + indexed properties — NOT an
    // Array per Array.isArray.
    expect(() =>
      client.check.run({
        systemId: VALID_UUID,
        frameworks: { 0: "EU_AI_ACT", length: 1 } as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("H13: response with negative / out-of-range score round-trips faithfully (NaN/Infinity unreachable via JSON wire)", async () => {
    // Hostile concern: the SDK's P2 validator (`typeof obj.score
    // !== "number"`) accepts ANY number including negatives,
    // out-of-range positives, NaN, and ±Infinity. The kernel won't
    // emit these values in practice (it computes `overallScore`
    // from finite jsonb values via `typeof === "number" ? x : 0`),
    // but the SDK doesn't paranoid-reject — faithful courier.
    //
    // **NaN and Infinity are unreachable via the JSON wire**:
    // `JSON.stringify(NaN)` and `JSON.stringify(Infinity)` both
    // emit the literal string "null"; `JSON.parse("null")` →
    // `null`, which the SDK's P2 validator REJECTS (`typeof null
    // !== "number"`). So the test exercises the two reachable
    // edges: a negative score and a large-positive score (both
    // typeof === "number" and parse cleanly).
    //
    // Session-16 hostile review HIGH #2 caught the prior title's
    // false claim of "NaN / Infinity" coverage. If the SDK ever
    // tightens to `Number.isFinite` (excluding NaN/Infinity but
    // also rejecting any future non-finite score from a custom
    // serializer like MessagePack), this test gains a sibling
    // pinning the rejection.
    const { client: c1, calls: calls1 } = makeMockedClient([
      {
        bodyText: JSON.stringify({
          success: true,
          data: { ...MOCK_RESPONSE, score: -1 },
        }),
      },
    ]);
    const r1 = await c1.check.run({ systemId: VALID_UUID });
    expect(r1.score).toBe(-1);
    expect(calls1).toHaveLength(1);

    const { client: c2 } = makeMockedClient([
      {
        bodyText: JSON.stringify({
          success: true,
          data: { ...MOCK_RESPONSE, score: 9999 },
        }),
      },
    ]);
    const r2 = await c2.check.run({ systemId: VALID_UUID });
    expect(r2.score).toBe(9999);
  });

  it("H14: response with non-string elements in `issues` array round-trips (SDK validates Array.isArray only)", async () => {
    // The build round's P2 validator checks `Array.isArray(issues)`
    // but NOT per-element type (faithful courier — kernel emits
    // strings reliably, but SDK doesn't paranoid-validate). Pin
    // documents: if the kernel ever emits non-string elements,
    // they round-trip to consumers (typed as `string[]` at the call
    // site, but the runtime types are heterogeneous).
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_RESPONSE,
            issues: ["valid string", 42, null, { obj: "true" }],
          },
        },
      },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.issues).toEqual([
      "valid string",
      42,
      null,
      { obj: "true" },
    ] as unknown as string[]);
  });

  it("H16: response-side prototype-pollution defense — kernel-regression-drops-field + Object.prototype.<field>=value cannot mask the regression", async () => {
    // **Second independent hostile review MEDIUM #3 regression pin**.
    // The P2 validator used to read response fields via direct
    // property access (`obj.compliant`, `obj.score`, etc.) which
    // WALKS THE PROTOTYPE CHAIN. Attack surface:
    //   1. Hostile npm dep pollutes `Object.prototype.compliant = true`
    //      (and similar for other fields).
    //   2. Kernel regresses to drop one of the response fields.
    //   3. SDK reads `obj.compliant` → returns the polluted prototype
    //      value (true) → typeof boolean → validation passes → consumer
    //      silently gets the polluted value.
    //
    // Fix: P2 validator now reads each response field through
    // `objectHasOwn(obj, "<field>") ? obj.<field> : undefined` (the
    // same module-load snapshot pattern used for input fields).
    // With this defense, a kernel-regression-dropped field reads as
    // undefined (not the polluted prototype value), and the SDK
    // throws AttestryError("expected response.<field> to be <type>
    // (got undefined)").
    //
    // Pin: pollute Object.prototype for each of the 6 response
    // fields, then mock a kernel response missing ALL of them.
    // SDK should throw on the first missing field (compliant) with
    // an AttestryError naming "got undefined" — NOT silently accept
    // the polluted values.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            // Missing: compliant, score, issues, activeAttestations,
            // lastAssessedAt, checkedAt — kernel regression case.
          },
        },
      },
    ]);
    const originalDescs = new Map<string, PropertyDescriptor | undefined>();
    const fields = [
      "compliant",
      "score",
      "issues",
      "activeAttestations",
      "lastAssessedAt",
      "checkedAt",
    ] as const;
    try {
      // Pollute Object.prototype with valid-looking values for each
      // response field. If the SDK reads via prototype walk, all
      // typeof-checks pass.
      const pollutedValues: Record<(typeof fields)[number], unknown> = {
        compliant: true,
        score: 87,
        issues: [],
        activeAttestations: 2,
        lastAssessedAt: "2026-04-21T12:34:56.000Z",
        checkedAt: "2026-05-11T15:00:00.000Z",
      };
      for (const field of fields) {
        originalDescs.set(
          field,
          Object.getOwnPropertyDescriptor(Object.prototype, field),
        );
        (Object.prototype as unknown as Record<string, unknown>)[field] =
          pollutedValues[field];
      }

      // SDK must throw — own-property check sees no own field, so
      // each is read as undefined; first failure (compliant) fires
      // the AttestryError. WITHOUT the defense, all typeof-checks
      // would pass via prototype walk and the SDK would silently
      // return the polluted values.
      await expect(client.check.run({ systemId: VALID_UUID })).rejects.toThrow(
        /expected response\.compliant to be a boolean \(got undefined\)/,
      );
    } finally {
      // CRITICAL: clean up all Object.prototype mutations so
      // subsequent tests aren't affected.
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
    expect(calls).toHaveLength(1);
  });

  // H16-per-field-corollary: own-property defense exercised on EACH
  // remaining response field independently. The base H16 test fails
  // on `compliant` first (so the per-field branches for the OTHER 5
  // fields are unexercised by that test alone). Each it.each row
  // covers one field's own-property fallback branch — pollutes a
  // valid-looking value on Object.prototype, emits a response with
  // ALL OTHER fields present but THIS field missing, and asserts
  // the SDK rejects with "got undefined" naming the right field.
  // Without these, branch + line coverage on check.ts drop to ~98%
  // (the `: undefined` arms of three multi-line ternaries are
  // unhit). With them, 100/100/100/100 is maintained.
  it.each([
    [
      "score",
      87 as unknown,
      /expected response\.score to be a number \(got undefined\)/,
    ],
    [
      "issues",
      [] as unknown,
      /expected response\.issues to be an array \(got undefined\)/,
    ],
    [
      "activeAttestations",
      2 as unknown,
      /expected response\.activeAttestations to be a number \(got undefined\)/,
    ],
    [
      "lastAssessedAt",
      "2026-04-21T12:34:56.000Z" as unknown,
      /expected response\.lastAssessedAt to be a string or null \(got undefined\)/,
    ],
    [
      "checkedAt",
      "2026-05-11T15:00:00.000Z" as unknown,
      /expected response\.checkedAt to be a string \(got undefined\)/,
    ],
  ] as const)(
    "H16-%s: own-property check rejects polluted-prototype + kernel-dropped-field combo",
    async (fieldName, pollutedValue, expectedMsg) => {
      // Build a response where ALL fields are valid OWN properties
      // EXCEPT the target field. This way the SDK's earlier
      // own-property checks (for fields before the target in the
      // run() validation order) pass via own-property reads, and
      // we reach the target field's check.
      const data: Record<string, unknown> = {
        compliant: true,
        score: 87,
        issues: [],
        activeAttestations: 2,
        lastAssessedAt: "2026-04-21T12:34:56.000Z",
        checkedAt: "2026-05-11T15:00:00.000Z",
      };
      // CRITICAL: use delete (not assignment) so the field is not
      // an own property; the SDK's `objectHasOwn` must return false
      // for this field, falling back to undefined.
      delete data[fieldName];

      const originalDesc = Object.getOwnPropertyDescriptor(
        Object.prototype,
        fieldName,
      );
      const { client } = makeMockedClient([
        { body: { success: true, data } },
      ]);
      try {
        (Object.prototype as unknown as Record<string, unknown>)[fieldName] =
          pollutedValue;
        // SDK must throw with "got undefined" — proof the
        // own-property check rejected the polluted prototype value.
        // WITHOUT the defense, the SDK would read via prototype walk,
        // see the polluted valid-looking value, pass the typeof
        // check, and silently return the polluted response.
        await expect(
          client.check.run({ systemId: VALID_UUID }),
        ).rejects.toThrow(expectedMsg);
      } finally {
        // CRITICAL: restore Object.prototype so subsequent tests
        // aren't affected.
        if (originalDesc) {
          Object.defineProperty(Object.prototype, fieldName, originalDesc);
        } else {
          delete (Object.prototype as unknown as Record<string, unknown>)[
            fieldName
          ];
        }
      }
    },
  );

  it("H16-corollary: prototype-pollution on a SINGLE response field (one missing, five emitted) still rejects via own-property check", async () => {
    // **Tighter version of H16**: kernel emits 5 of 6 fields
    // correctly, but `compliant` regresses to missing. Hostile dep
    // pollutes Object.prototype.compliant = true. SDK must reject
    // because own-property check sees no own `compliant`.
    //
    // This is the more realistic regression case (partial
    // kernel emit failure) and exercises the same defense.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            // compliant missing — but the others are present.
            score: 87,
            issues: [],
            activeAttestations: 2,
            lastAssessedAt: "2026-04-21T12:34:56.000Z",
            checkedAt: "2026-05-11T15:00:00.000Z",
          },
        },
      },
    ]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "compliant",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).compliant =
        true;
      await expect(client.check.run({ systemId: VALID_UUID })).rejects.toThrow(
        /expected response\.compliant to be a boolean \(got undefined\)/,
      );
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "compliant", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .compliant;
      }
    }
    expect(calls).toHaveLength(1);
  });

  it("H15: empty-string lastAssessedAt passes through (typeof string — faithful courier)", async () => {
    // typeof "" === "string", so the SDK's P2 validator accepts.
    // The kernel will never emit "" (it emits ISO-8601 or null),
    // but the SDK doesn't paranoid-validate ISO shape. Pin documents
    // the surface — a future SDK hardening release could tighten
    // this, but TODAY's behavior is faithful courier.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_RESPONSE, lastAssessedAt: "" },
        },
      },
    ]);
    const out = await client.check.run({ systemId: VALID_UUID });
    expect(out.lastAssessedAt).toBe("");
  });
});

// ─── Hostile review #1 — MEDIUM-1 throwing-getter fix ───────────────────────
//
// Session-22 hostile review #1: the SDK-wide MEDIUM-1 getter-throws
// contract gap. `check.run` snapshots each input field via
// `readInputField`, which converts a throwing accessor's exception
// into the documented synchronous `TypeError` input contract.

describe("check.run — hostile review #1: throwing-getter MEDIUM-1 fix", () => {
  it("converts a throwing `systemId` getter into a TypeError (NOT the getter's raw error)", () => {
    const { client, calls } = makeMockedClient([]);
    const evil = {
      get systemId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as CheckInput;
    let caught: unknown;
    try {
      client.check.run(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).message).toContain("check.run");
    expect((caught as Error).message).toContain("systemId");
    expect((caught as Error).message).not.toContain("getter boom");
    expect(calls).toHaveLength(0);
  });

  it("converts a throwing `frameworks` getter into a TypeError", () => {
    const { client, calls } = makeMockedClient([]);
    const evil = {
      systemId: VALID_UUID,
      get frameworks(): unknown {
        throw new Error("frameworks boom");
      },
    } as unknown as CheckInput;
    expect(() => client.check.run(evil)).toThrow(TypeError);
    expect(() => client.check.run(evil)).toThrow(/frameworks/);
    expect(calls).toHaveLength(0);
  });
});
