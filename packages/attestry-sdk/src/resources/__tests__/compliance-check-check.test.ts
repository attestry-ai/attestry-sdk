import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  ComplianceCheckInput,
  ComplianceCheckResponse,
  ComplianceCheckResult,
} from "../compliance-check.js";
import type { FetchLike } from "../../types.js";

// ─── complianceCheck.check — sync JSON request/response ─────────────────────
//
// Wire shape (from src/app/api/v1/compliance-check/route.ts):
//   GET /api/v1/compliance-check?systemId=<UUID>
//   GET /api/v1/compliance-check?orgName=<string>
//   → { success: true, data: { systems: ComplianceCheckResult[], checkedAt: string } }
//
// Third non-decisions resource on the SDK; sibling to
// IncidentsResource / DecisionsResource / ChatResource /
// AuditLogResource / RegulatoryChangesResource.
//
// **Multi-permission UNION auth** — kernel uses
// `requireApiKeyWithPermission(req, READ_SYSTEMS, READ_ASSESSMENTS)`
// which is `Array.some()`-based at permissions.ts:53-55. A key with
// EITHER permission succeeds; 403 fires only when the key has
// NEITHER. Pin BOTH 401 (unauth) AND 403 (insufficient) branches.
// auditLog.export (ADMIN-only dual-auth) shares the same 401-vs-403
// status surface — the auth models differ, not the surface
// (corrected session-22 hostile review #2). (The handoff doc
// described this as intersection auth; kernel verification showed
// it's union — see audit doc for the faithful-courier finding.)
//
// **XOR input mode** — exactly one of `systemId` or `orgName` must
// be provided. SDK is STRICTER than the kernel — kernel silently
// picks systemId when both are provided; SDK rejects with TypeError.
// Modeled as a TypeScript discriminated union for compile-time XOR.
//
// **Asymmetric cross-org error codes** — cross-org systemId returns
// 404 (kernel collapses); cross-org orgName returns 403. Pin both as
// opposite-of-the-other.
//
// **Silent .limit(100) on orgName path** — kernel hardcodes
// `.limit(100)` at route.ts:107; >100 systems silently truncated.
// SDK does NOT mask this — JSDoc + README call it out (faithful
// courier).

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

// A representative wire-shape result covering every documented
// field (7 result fields + 3 nested frameworkCoverage fields).
// Used as a sanity reference for happy-path + row-shape pins.
const MOCK_RESULT: ComplianceCheckResult = {
  systemId: "11111111-1111-1111-1111-111111111111",
  systemName: "RetentionRecommender v3",
  compliant: true,
  score: 87,
  frameworkCoverage: {
    applicable: ["EU_AI_ACT", "ISO_42001"],
    assessed: ["EU_AI_ACT", "ISO_42001", "NIST_AI_RMF"],
    coveragePct: 100,
  },
  activeAttestations: 2,
  lastAssessedAt: "2026-04-21T12:34:56.000Z",
};

const MOCK_RESULT_2: ComplianceCheckResult = {
  systemId: "22222222-2222-2222-2222-222222222222",
  systemName: "FraudScoring v1",
  compliant: false,
  score: 62,
  frameworkCoverage: {
    applicable: ["EU_AI_ACT"],
    assessed: [],
    coveragePct: 0,
  },
  activeAttestations: 0,
  lastAssessedAt: "2026-03-01T08:00:00.000Z",
};

const MOCK_CHECKED_AT = "2026-05-10T15:00:00.000Z";

describe("complianceCheck.check — happy path", () => {
  it("GETs /api/v1/compliance-check?systemId=<uuid> on systemId path", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/compliance-check");
    expect(url.searchParams.get("systemId")).toBe(MOCK_RESULT.systemId);
    expect(url.searchParams.has("orgName")).toBe(false);
    expect(calls[0].body).toBeUndefined();
    expect(out).toEqual({
      systems: [MOCK_RESULT],
      checkedAt: MOCK_CHECKED_AT,
    });
  });

  it("GETs /api/v1/compliance-check?orgName=<encoded> on orgName path", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            systems: [MOCK_RESULT, MOCK_RESULT_2],
            checkedAt: MOCK_CHECKED_AT,
          },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      orgName: "Acme Corp",
    });
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/compliance-check");
    expect(url.searchParams.get("orgName")).toBe("Acme Corp");
    expect(url.searchParams.has("systemId")).toBe(false);
    expect(out.systems).toHaveLength(2);
    expect(out.checkedAt).toBe(MOCK_CHECKED_AT);
  });

  it("resolves with empty systems array on orgName path with no systems (no 404)", async () => {
    // The orgName path returns 200 with `systems: []` when the org
    // exists (matches the API key's org) but has no aiSystems. Pin:
    // SDK resolves with empty array, NOT throws. Distinct from
    // systemId path which returns 404 if not found.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({ orgName: "EmptyCorp" });
    expect(out.systems).toEqual([]);
    expect(out.checkedAt).toBe(MOCK_CHECKED_AT);
  });

  it("returns the response shape unchanged (envelope unwrapped)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
    });
    // Verify envelope was unwrapped: top-level keys are systems +
    // checkedAt, NOT success + data.
    expect(Object.keys(out).sort()).toEqual(["checkedAt", "systems"]);
    expect(out.systems[0]).toEqual(MOCK_RESULT);
  });

  it("forwards x-api-key + Accept (no Content-Type — GET, no body)", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check({ systemId: MOCK_RESULT.systemId });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBeNull();
  });
});

describe("complianceCheck.check — input validation (pre-fetch)", () => {
  it("throws TypeError for null input — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check(
        null as unknown as ComplianceCheckInput,
      ),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input (typeof [] === 'object')", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check([] as unknown as ComplianceCheckInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string / number / undefined)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check(
        "uuid" as unknown as ComplianceCheckInput,
      ),
    ).toThrowError(TypeError);
    expect(() =>
      client.complianceCheck.check(42 as unknown as ComplianceCheckInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.complianceCheck.check(undefined as unknown as ComplianceCheckInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when neither systemId nor orgName provided (empty object)", () => {
    // Kernel returns 400 with "Provide either systemId or orgName
    // query parameter" — but the SDK pre-rejects synchronously so
    // this kernel branch is unreachable through the SDK.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({} as unknown as ComplianceCheckInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.complianceCheck.check(
        { unrelated: "field" } as unknown as ComplianceCheckInput,
      ),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when both systemId AND orgName provided (XOR — SDK stricter than kernel)", () => {
    // **D3 deviation**: kernel's XOR is NOT strict — when both are
    // provided, kernel uses `systemId` and silently ignores
    // `orgName` (route.ts:80-87). The SDK is STRICTER and rejects
    // synchronously to prevent shadow-of-orgName bugs that would
    // otherwise pass kernel-side and produce confusing results.
    // Invariant candidate #46.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({
        systemId: "11111111-1111-1111-1111-111111111111",
        orgName: "Acme Corp",
      } as unknown as ComplianceCheckInput),
    ).toThrowError(TypeError);
    // Error message names the kernel quirk so consumers debugging
    // the rejection understand WHY the SDK is stricter.
    expect(() =>
      client.complianceCheck.check({
        systemId: "11111111-1111-1111-1111-111111111111",
        orgName: "Acme Corp",
      } as unknown as ComplianceCheckInput),
    ).toThrow(/either.*systemId.*or.*orgName.*not both/i);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty systemId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({ systemId: "" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({
        systemId: 42 as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.complianceCheck.check({
        systemId: null as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.complianceCheck.check({
        systemId: { nested: true } as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for systemId with lone UTF-16 surrogates (URIError defense, carry-forward #32)", () => {
    // `encodeURIComponent("\uD800")` throws URIError — without the
    // `assertEncodableQueryString` guard, that URIError would leak
    // into the consumer instead of the named TypeError. Symmetric
    // to decisions / incidents / audit-log / regulatory-changes
    // defenses.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({ systemId: "\uD800" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.complianceCheck.check({ systemId: "valid\uDFFFlone" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty orgName", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({ orgName: "" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string orgName", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({
        orgName: 42 as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.complianceCheck.check({
        orgName: null as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for orgName with lone UTF-16 surrogates (URIError defense, carry-forward #32)", () => {
    // Carry-forward invariant #32 — extends URIError defense to
    // both XOR branches uniformly. Without per-field guards, a
    // `orgName: "\uD800"` would surface as a raw URIError from the
    // transport instead of the named TypeError from the resource.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({ orgName: "\uD800" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.complianceCheck.check({ orgName: "valid\uDFFFlone" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("empty systemId is rejected even when XOR partner orgName is also present (XOR check fires first)", () => {
    // Corner case: a caller provides BOTH `systemId: ""` AND
    // `orgName: "valid"`. The XOR-rejection path fires before the
    // per-field empty check — the SDK's first guard is "exactly one
    // must be provided", which sees BOTH provided (the empty string
    // counts as provided per the `in` operator + undefined-only
    // check). Pin: TypeError (the both-provided variant), not the
    // empty-systemId variant. Order-of-checks pin.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({
        systemId: "",
        orgName: "valid",
      } as unknown as ComplianceCheckInput),
    ).toThrow(/either.*systemId.*or.*orgName.*not both/i);
    expect(calls).toHaveLength(0);
  });

  it("explicit `orgName: undefined` with valid systemId is equivalent to systemId-only", async () => {
    // TS allows `{ systemId: "...", orgName: undefined }` via the
    // `orgName?: never` branch (undefined IS the never-equivalent
    // when paired with `?:`). The runtime guard's `in` operator +
    // `!== undefined` check correctly classifies this as
    // systemId-only, NOT both-provided. Pin: request goes through;
    // URL has only `systemId=`.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
      orgName: undefined,
    } as unknown as ComplianceCheckInput);
    const url = new URL(calls[0].url);
    expect(url.searchParams.get("systemId")).toBe(MOCK_RESULT.systemId);
    expect(url.searchParams.has("orgName")).toBe(false);
  });

  it("explicit `systemId: undefined` with valid orgName is equivalent to orgName-only", async () => {
    // Symmetric to the prior pin — explicit-undefined on the OTHER
    // XOR branch. Mirror coverage.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check({
      systemId: undefined,
      orgName: "Acme Corp",
    } as unknown as ComplianceCheckInput);
    const url = new URL(calls[0].url);
    expect(url.searchParams.get("orgName")).toBe("Acme Corp");
    expect(url.searchParams.has("systemId")).toBe(false);
  });

  it("rejects `{systemId: undefined, orgName: undefined}` as no-input", () => {
    // Both fields explicitly undefined — neither qualifies as
    // "provided" per the runtime check. Pin: TypeError (neither),
    // NOT TypeError (both).
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.complianceCheck.check({
        systemId: undefined,
        orgName: undefined,
      } as unknown as ComplianceCheckInput),
    ).toThrow(/exactly one of `systemId` or `orgName`/);
    expect(calls).toHaveLength(0);
  });
});

describe("complianceCheck.check — query encoding", () => {
  it("does NOT pre-validate UUID format — server validates (D2)", async () => {
    // SDK-side: type-check only (string non-empty, lone-surrogate
    // guard). UUID-format check is deferred to the kernel's
    // `isValidUuid`, which returns 400 for malformed values. Pin: a
    // malformed `systemId: "not-a-uuid"` still goes through to the
    // server, which returns 400.
    const { client, calls } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Invalid systemId format" },
      },
    ]);
    try {
      await client.complianceCheck.check({ systemId: "not-a-uuid" });
    } catch {
      /* ignore — verifying the request was issued */
    }
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0].url).searchParams.get("systemId")).toBe(
      "not-a-uuid",
    );
  });

  it("URL-encodes orgName containing reserved URL chars (`&`, `=`, `?`, `/`, `#`, space)", async () => {
    // A literal org name like "C&P Org / Branch?2" must be
    // percent-encoded so it doesn't break the query string parser
    // server-side. encodeURIComponent replaces `&`, `=`, `?`, `/`,
    // `#`, ` ` with %26, %3D, %3F, %2F, %23, %20.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check({
      orgName: "C&P Org / Branch?2",
    });
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/compliance-check?orgName=C%26P%20Org%20%2F%20Branch%3F2",
    );
  });

  it("URL-encodes systemId verbatim (no transformation)", async () => {
    // Sanity: a real UUID is hex+hyphen ASCII so encodeURIComponent
    // is a no-op. Pin: the URL contains the exact UUID string.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check({
      systemId: "11111111-1111-1111-1111-111111111111",
    });
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/compliance-check?systemId=11111111-1111-1111-1111-111111111111",
    );
  });

  it("does not mutate the input object (read-only)", async () => {
    // Defensive: a caller passing a frozen object must not see the
    // SDK crash. The resource reads `input.systemId` etc. without
    // assignment.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const input: ComplianceCheckInput = Object.freeze({
      systemId: MOCK_RESULT.systemId,
    });
    const snapshot = JSON.stringify(input);
    await client.complianceCheck.check(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});

describe("complianceCheck.check — XOR + asymmetric error codes (cross-org)", () => {
  it("cross-org systemId surfaces as AttestryAPIError(404) — kernel collapses to 'System not found' (route.ts:76)", async () => {
    // **Asymmetric error code pin** (D7 / invariant candidate #47).
    // Cross-org systemId returns 404 — kernel collapses cross-org
    // to 404 to avoid leaking "this UUID exists but belongs to
    // another org" (mirror of decisions.retrieve). Asymmetric with
    // cross-org orgName which returns 403.
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "System not found" },
      },
    ]);
    try {
      await client.complianceCheck.check({
        systemId: "33333333-3333-3333-3333-333333333333",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.message).toMatch(/System not found/);
    }
  });

  it("cross-org orgName surfaces as AttestryAPIError(403) — kernel emits 'Access denied' (route.ts:95)", async () => {
    // **Asymmetric error code pin** (D7 / invariant candidate #47).
    // Cross-org orgName returns 403 — the org name lookup
    // intentionally surfaces "the org exists but you can't see its
    // systems". Asymmetric with cross-org systemId which collapses
    // to 404. Consumers writing defensive error-handling logic must
    // distinguish the two.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: { success: false, error: "Access denied" },
      },
    ]);
    try {
      await client.complianceCheck.check({ orgName: "Other Corp" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect(apiErr.message).toMatch(/Access denied/);
    }
  });

  it("orgName response can return up to 100 systems (kernel hardcodes .limit(100); SDK does NOT paginate or warn)", async () => {
    // **Silent .limit(100) pin** (D8). The kernel hardcodes
    // `.limit(100)` at route.ts:107 on the orgName branch's
    // target-systems lookup. The SDK does NOT mask this — no
    // warning log, no auto-paginate, no `hasMore` field. Faithful
    // courier. Pin: a 100-element response round-trips intact;
    // there's no field on the response that would let consumers
    // detect truncation (consumers must know up-front via JSDoc).
    const hundredSystems = Array.from({ length: 100 }, (_, i) => ({
      ...MOCK_RESULT,
      systemId: `${i.toString().padStart(8, "0")}-1111-1111-1111-111111111111`,
      systemName: `System ${i}`,
    }));
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: hundredSystems, checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      orgName: "Megacorp",
    });
    expect(out.systems).toHaveLength(100);
    // No truncation indicator on the response — consumers can't
    // detect "this is page 1 of N" from the wire shape. Pin
    // documents the gap.
    expect(out).not.toHaveProperty("total");
    expect(out).not.toHaveProperty("hasMore");
    expect(out).not.toHaveProperty("nextCursor");
  });
});

describe("complianceCheck.check — error paths", () => {
  it("surfaces a 400 (invalid systemId UUID format) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Invalid systemId format" },
      },
    ]);
    try {
      await client.complianceCheck.check({ systemId: "not-a-uuid" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.message).toMatch(/Invalid systemId format/);
    }
  });

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
      await client.complianceCheck.check({
        systemId: MOCK_RESULT.systemId,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 403 (key has NEITHER READ_SYSTEMS NOR READ_ASSESSMENTS — union-auth) as AttestryAPIError", async () => {
    // Multi-permission UNION auth: 403 fires ONLY when the key has
    // NEITHER required permission (kernel uses `Array.some()` at
    // permissions.ts:53-55). A key with EITHER permission would
    // succeed (200), not 403. `auditLog.export` (ADMIN-only dual-auth)
    // shares the SAME 401-vs-403 split — the auth models differ, the
    // status surface does not (corrected session-22 hostile review #2;
    // carry-forward invariant #42's "401 for both" framing was wrong).
    // Single test case — handoff's "3 cases"
    // (missing READ_SYSTEMS, missing READ_ASSESSMENTS, missing both)
    // was based on intersection-auth misreading; only the
    // missing-both case actually 403s.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error:
            "API key lacks required permission. Required: read:systems or read:assessments. Key has: read:documents.",
        },
      },
    ]);
    try {
      await client.complianceCheck.check({
        systemId: MOCK_RESULT.systemId,
      });
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
      expect((err as AttestryAPIError).message).toMatch(
        /read:systems or read:assessments/,
      );
    }
  });

  it("surfaces a 404 (systemId not found) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "System not found" },
      },
    ]);
    try {
      await client.complianceCheck.check({
        systemId: "99999999-9999-9999-9999-999999999999",
      });
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
    }
  });

  it("surfaces a 404 (orgName not found) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "Organization not found" },
      },
    ]);
    try {
      await client.complianceCheck.check({
        orgName: "DefinitelyNotARealOrg",
      });
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
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
      await client.complianceCheck.check({
        systemId: MOCK_RESULT.systemId,
      });
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
      await client.complianceCheck.check({
        systemId: MOCK_RESULT.systemId,
      });
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
      return new Response(
        JSON.stringify({
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        }),
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
      await client.complianceCheck.check({
        systemId: MOCK_RESULT.systemId,
      });
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

  it("P2: throws AttestryError when kernel response is null (deliberate null vs unparseable-body — same outcome)", async () => {
    // Symmetric with the wrong-content-type pin. Whether the kernel
    // deliberately emits `data: null` (kernel bug) or the transport's
    // readBody returns null (unparseable body for application/json),
    // the resource-layer validator surfaces the same clear
    // AttestryError.
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
    ).rejects.toThrow(/expected an object response from the kernel \(got null\)/);
  });

  it("P2: throws AttestryError when kernel response is a scalar (not an object)", async () => {
    // P2 hardening: kernel-side regression that emits
    // `successResponse("ok")` instead of the object shape would
    // surface as `string` cast as `ComplianceCheckResponse` to the
    // consumer — `out.systems.length` reads `length` of the string
    // (returning a number that's a length-of-the-string, totally
    // wrong). Resource-layer validator catches this.
    const { client } = makeMockedClient([
      { body: { success: true, data: "scalar-instead-of-object" } },
    ]);
    await expect(
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
    ).rejects.toThrow(/expected an object response from the kernel \(got string\)/);
  });

  it("P2: throws AttestryError when kernel response is an array (not an object)", async () => {
    // P2 hardening: kernel-side mistake that emits
    // `successResponse([row1, row2])` instead of the wrapped object
    // shape would slip through TypeScript-typed access (Arrays ARE
    // objects per typeof). Resource-layer validator catches this.
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_RESULT] } },
    ]);
    await expect(
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
    ).rejects.toThrow(/expected an object response from the kernel \(got array\)/);
  });

  it("P2: throws AttestryError when response.systems is not an array", async () => {
    // P2 hardening: top-level shape is correct (object with
    // systems + checkedAt), but `systems` is the wrong type. Pin:
    // resource-layer validator names the specific field.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: "not-an-array", checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await expect(
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
    ).rejects.toThrow(/expected response\.systems to be an array \(got string\)/);
  });

  it("P2: throws AttestryError when response.checkedAt is not a string", async () => {
    // P2 hardening: top-level shape is correct (object with
    // systems + checkedAt), but `checkedAt` is the wrong type. Pin:
    // resource-layer validator names the specific field.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: 12345 },
        },
      },
    ]);
    await expect(
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
    ).rejects.toThrow(/expected response\.checkedAt to be a string \(got number\)/);
  });

  it("P2: throws AttestryError when response.checkedAt is missing entirely (undefined)", async () => {
    // P2 hardening: kernel-side regression that drops the
    // checkedAt field. typeof undefined === "undefined", which the
    // describeType helper renders as "undefined".
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT] },
        },
      },
    ]);
    await expect(
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
    ).rejects.toThrow(/expected response\.checkedAt to be a string \(got undefined\)/);
  });

  it("P2 error is AttestryError (NOT AttestryAPIError) — distinct surface for kernel-shape regressions vs HTTP errors", async () => {
    // Pin the error CLASS on the P2 path. AttestryAPIError carries
    // an HTTP status; AttestryError does not. A kernel-shape
    // regression isn't an "API error" in the HTTP sense — the
    // server returned 200 with a malformed body. Consumers'
    // defensive try/catch can distinguish.
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    try {
      await client.complianceCheck.check({
        systemId: MOCK_RESULT.systemId,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      // AttestryAPIError extends AttestryError, so the negative
      // assertion is the meaningful one.
      expect(err).not.toBeInstanceOf(AttestryAPIError);
    }
  });
});

describe("complianceCheck.check — response shape preservation", () => {
  it("preserves all 7 ComplianceCheckResult fields on a happy-path row", async () => {
    // Sanity check: every field in the documented
    // `ComplianceCheckResult` interface round-trips. Drift on this
    // test = kernel-side route emits new field name OR SDK
    // interface drift; cross-check sdk-drift.test.ts.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
    });
    expect(out.systems[0]).toEqual(MOCK_RESULT);
    // Spot-check field count via Object.keys to catch silent
    // drops/renames.
    expect(Object.keys(out.systems[0]).sort()).toEqual(
      [
        "systemId",
        "systemName",
        "compliant",
        "score",
        "frameworkCoverage",
        "activeAttestations",
        "lastAssessedAt",
      ].sort(),
    );
  });

  it("preserves all 3 ComplianceCheckFrameworkCoverage fields", async () => {
    // Nested shape pin — same drift surface as the row-level pin.
    // Kernel emits `frameworkCoverage: { applicable, assessed,
    // coveragePct }` inline; a future kernel addition (e.g.,
    // `nonCompliantCount`) would surface here.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
    });
    expect(Object.keys(out.systems[0].frameworkCoverage).sort()).toEqual(
      ["applicable", "assessed", "coveragePct"].sort(),
    );
    expect(out.systems[0].frameworkCoverage.applicable).toEqual([
      "EU_AI_ACT",
      "ISO_42001",
    ]);
    expect(out.systems[0].frameworkCoverage.assessed).toEqual([
      "EU_AI_ACT",
      "ISO_42001",
      "NIST_AI_RMF",
    ]);
    expect(out.systems[0].frameworkCoverage.coveragePct).toBe(100);
  });

  it("preserves null nullable fields (score / lastAssessedAt) — D6 implicit-threshold-of-70 trail", async () => {
    // Per JSDoc on ComplianceCheckResult.score: kernel emits
    // `null` when no completed assessment exists OR when
    // `scores.overallScore` is missing/non-numeric. lastAssessedAt
    // is `null` when no completed assessment exists. Pin: both
    // round-trip as `null`, NOT `undefined`, NOT `0`, NOT `""`.
    const sparse: ComplianceCheckResult = {
      ...MOCK_RESULT,
      score: null,
      lastAssessedAt: null,
    };
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [sparse], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
    });
    expect(out.systems[0].score).toBeNull();
    expect(out.systems[0].lastAssessedAt).toBeNull();
  });

  it("passes through extra unknown fields verbatim (forward-compat)", async () => {
    // If the kernel adds a new column before the SDK is bumped,
    // the extra field must round-trip — faithful courier. Pin: an
    // unknown field arrives at the consumer (typed as `unknown` at
    // the call site, but present at runtime). Mirror of the
    // regulatoryChanges.list forward-compat pin.
    const withExtra = {
      ...MOCK_RESULT,
      futureField: "added kernel-side without an SDK bump",
      futureNestedField: { nested: 42 },
    };
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [withExtra], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
    });
    expect(
      (out.systems[0] as unknown as Record<string, unknown>).futureField,
    ).toBe("added kernel-side without an SDK bump");
    expect(
      (out.systems[0] as unknown as Record<string, unknown>)
        .futureNestedField,
    ).toEqual({ nested: 42 });
  });

  it("passes through extra unknown TOP-LEVEL fields verbatim (forward-compat)", async () => {
    // Asymmetric with regulatoryChanges (which has no top-level
    // wrapper). complianceCheck DOES have a top-level wrapper
    // ({systems, checkedAt}); a future kernel addition (e.g.,
    // `total: number` or `truncated: boolean`) at the top level
    // must round-trip.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            systems: [MOCK_RESULT],
            checkedAt: MOCK_CHECKED_AT,
            futureTopLevel: "kernel added this",
            truncated: true,
          },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
    });
    // Top-level extras pass through (typed as `unknown` at the
    // call site).
    expect((out as unknown as Record<string, unknown>).futureTopLevel).toBe(
      "kernel added this",
    );
    expect((out as unknown as Record<string, unknown>).truncated).toBe(true);
  });

  it("preserves multi-system orgName response order and contents", async () => {
    // The orgName path emits up to 100 systems. Order is the
    // kernel's iteration order over the org's systems (DB result
    // order, no kernel-side sort). Pin: items arrive in the same
    // order as the kernel emits them.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            systems: [MOCK_RESULT, MOCK_RESULT_2],
            checkedAt: MOCK_CHECKED_AT,
          },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      orgName: "Acme Corp",
    });
    expect(out.systems).toHaveLength(2);
    expect(out.systems[0].systemId).toBe(MOCK_RESULT.systemId);
    expect(out.systems[1].systemId).toBe(MOCK_RESULT_2.systemId);
  });

  it("preserves coveragePct integer type (NOT string) including edge cases (0 and >100)", async () => {
    // Per ComplianceCheckFrameworkCoverage docstring:
    //   - `applicable: []` always yields `coveragePct: 0`.
    //   - If `assessed.size > applicable.length`, the percentage
    //     exceeds 100 (kernel does NOT clamp).
    // Pin: both edge cases round-trip as numbers (NOT clamped, NOT
    // coerced to string).
    const edgeRow: ComplianceCheckResult = {
      ...MOCK_RESULT,
      frameworkCoverage: {
        applicable: [],
        assessed: ["EU_AI_ACT", "ISO_42001"],
        coveragePct: 0, // applicable.length === 0 short-circuits to 0
      },
    };
    const overcoveredRow: ComplianceCheckResult = {
      ...MOCK_RESULT_2,
      frameworkCoverage: {
        applicable: ["EU_AI_ACT"],
        assessed: ["EU_AI_ACT", "ISO_42001", "NIST_AI_RMF"],
        coveragePct: 300, // assessed > applicable → can exceed 100
      },
    };
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            systems: [edgeRow, overcoveredRow],
            checkedAt: MOCK_CHECKED_AT,
          },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      orgName: "Mixed",
    });
    expect(out.systems[0].frameworkCoverage.coveragePct).toBe(0);
    expect(typeof out.systems[0].frameworkCoverage.coveragePct).toBe("number");
    expect(out.systems[1].frameworkCoverage.coveragePct).toBe(300);
    expect(typeof out.systems[1].frameworkCoverage.coveragePct).toBe("number");
  });
});

describe("complianceCheck.check — abort + retry semantics", () => {
  it("forwards a pre-aborted AbortSignal through RequestOptions (no fetch)", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.complianceCheck.check(
        { systemId: MOCK_RESULT.systemId },
        { signal: controller.signal },
      ),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally (coverage)", async () => {
    // Symmetric to decisions.list / regulatoryChanges.list coverage
    // pin — exercises the "signal exists but never fires" branch in
    // the transport's signal forwarding.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const controller = new AbortController();
    const out = await client.complianceCheck.check(
      { systemId: MOCK_RESULT.systemId },
      { signal: controller.signal },
    );
    expect(out.systems).toHaveLength(1);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies (independent of resource-helper default)", async () => {
    // The makeMockedClient helper sets retry: {maxRetries: 0} by
    // default. Per-call override should re-enable retry for this
    // single call. Pin against the retry middleware's per-call
    // precedence (matches decisions / regulatoryChanges patterns).
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "x" } },
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
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
    const promise = client.complianceCheck.check(
      { systemId: MOCK_RESULT.systemId },
      { retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 } },
    );
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out.systems).toHaveLength(1);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });
});

describe("complianceCheck.check — hostile round residual gaps", () => {
  it("H1: concurrent check() calls share no state — each promise resolves independently", async () => {
    // Build round covered "concurrent calls" only transitively via
    // decisions / regulatoryChanges. Pin it explicitly here: two
    // parallel calls against the same client must NOT share request /
    // response state (which a future refactor adding memoization or
    // response caching would break). Each call constructs its own
    // promise; the mocked fetch routes them to distinct mock
    // responses by call order.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT_2], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const [out1, out2] = await Promise.all([
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
      client.complianceCheck.check({ systemId: MOCK_RESULT_2.systemId }),
    ]);
    expect(calls).toHaveLength(2);
    expect(out1.systems[0].systemId).toBe(MOCK_RESULT.systemId);
    expect(out2.systems[0].systemId).toBe(MOCK_RESULT_2.systemId);
    // Each call landed on its own URL — no cross-pollination.
    const url1 = new URL(calls[0].url);
    const url2 = new URL(calls[1].url);
    expect(url1.searchParams.get("systemId")).toBe(MOCK_RESULT.systemId);
    expect(url2.searchParams.get("systemId")).toBe(MOCK_RESULT_2.systemId);
  });

  it("H2: parallel concurrent calls with different XOR branches don't cross-pollinate URLs", async () => {
    // Symmetric to H1 with a stronger contract: even when issued in
    // tight succession, each call's XOR branch lands on its own URL.
    // A future refactor that batches requests or shares a
    // query-builder closure would surface here.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT_2], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await Promise.all([
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
      client.complianceCheck.check({ orgName: "EmptyCorp" }),
      client.complianceCheck.check({ systemId: MOCK_RESULT_2.systemId }),
    ]);
    expect(calls).toHaveLength(3);
    expect(new URL(calls[0].url).searchParams.get("systemId")).toBe(
      MOCK_RESULT.systemId,
    );
    expect(new URL(calls[0].url).searchParams.has("orgName")).toBe(false);
    expect(new URL(calls[1].url).searchParams.get("orgName")).toBe(
      "EmptyCorp",
    );
    expect(new URL(calls[1].url).searchParams.has("systemId")).toBe(false);
    expect(new URL(calls[2].url).searchParams.get("systemId")).toBe(
      MOCK_RESULT_2.systemId,
    );
    expect(new URL(calls[2].url).searchParams.has("orgName")).toBe(false);
  });

  it("H3: 429 auto-retries when retry is enabled (default) and succeeds on second attempt", async () => {
    // Build round only pinned the retry-disabled path (where 429
    // surfaces immediately). Hostile round adds the retry-enabled
    // path — invariant #18: SDK auto-retries on 429 with exponential
    // backoff. Pin against the retry middleware integration: a 429 →
    // 200 sequence resolves with the 200 body when retry is on.
    // Mirror of regulatoryChanges H6 + decisions retry pins.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "rate limited" } },
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
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
    const promise = client.complianceCheck.check({
      systemId: MOCK_RESULT.systemId,
    });
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out.systems).toEqual([MOCK_RESULT]);
    expect(calls).toHaveLength(2);
    vi.useRealTimers();
  });

  it("H4: prototype-pollution defense — `Object.prototype.systemId = 'evil'` does NOT shadow the user's input", () => {
    // **Hostile finding fixed in this round.** Build round used
    // `"systemId" in input` for the XOR check — which walks the
    // prototype chain. If `Object.prototype.systemId` is polluted
    // (set somewhere else in the consumer's process), the SDK would
    // think systemId was provided even when the user only passed
    // `{orgName: "..."}`, then read the polluted value via
    // `input.systemId` and fire a request with the attacker-
    // controlled UUID.
    //
    // Hostile-round fix: switch to `Object.hasOwn(input, "systemId")`
    // (ES2022, own-property only). This pin asserts the defense is
    // load-bearing — pollution on Object.prototype does NOT reach
    // the SDK's XOR decision.
    //
    // Setup + teardown: pollute, run SDK, clean up. The cleanup
    // MUST run even if the assertion fails — wrap in try/finally.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    // Pollute Object.prototype with both XOR fields. After the fix,
    // the SDK should ignore both (only own properties count).
    const proto = Object.prototype as unknown as Record<string, unknown>;
    proto.systemId = "evil-attacker-uuid";
    proto.orgName = "Evil Corp";
    try {
      // User passes ONLY orgName (own property). Without the fix,
      // the SDK would see hasSystemId=true (from prototype),
      // hasOrgName=true (own), and throw "both provided". With the
      // fix, hasSystemId=false (Object.hasOwn returns false for
      // prototype-only props), hasOrgName=true (own), and the
      // request fires with orgName only.
      void client.complianceCheck.check({ orgName: "RealCorp" });
      expect(calls).toHaveLength(1);
      const url = new URL(calls[0].url);
      expect(url.searchParams.get("orgName")).toBe("RealCorp");
      // Critical: systemId must NOT appear on the URL — pollution
      // didn't leak.
      expect(url.searchParams.has("systemId")).toBe(false);
    } finally {
      delete proto.systemId;
      delete proto.orgName;
    }
  });

  it("H4 corollary: pollution does NOT cause `{}` to look like `{systemId: ..., orgName: ...}` (no false both-provided)", () => {
    // Companion to H4. With pollution on BOTH XOR fields, an empty
    // `{}` from the user MUST still throw "neither provided" — NOT
    // "both provided". Without the Object.hasOwn fix, both checks
    // would see prototype-only values and the SDK would
    // mis-classify the request as both-provided.
    const { client, calls } = makeMockedClient([]);
    const proto = Object.prototype as unknown as Record<string, unknown>;
    proto.systemId = "evil-attacker-uuid";
    proto.orgName = "Evil Corp";
    try {
      expect(() =>
        client.complianceCheck.check({} as unknown as ComplianceCheckInput),
      ).toThrow(/exactly one of `systemId` or `orgName`/);
      expect(calls).toHaveLength(0);
    } finally {
      delete proto.systemId;
      delete proto.orgName;
    }
  });

  it("H5: whitespace-only orgName / systemId is forwarded URL-encoded (SDK does NOT trim)", async () => {
    // Faithful courier: SDK forwards the input verbatim. A
    // whitespace-only orgName ("   ") has length 3 — passes the
    // non-empty check. SDK does NOT trim; the kernel's filter
    // (`WHERE name = '   '`) just won't match anything. Pin: URL
    // contains the encoded whitespace. A future "be helpful"
    // refactor adding a `.trim()` would surface here. Mirror of
    // regulatoryChanges H10 pattern.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
      {
        status: 400,
        body: { success: false, error: "Invalid systemId format" },
      },
    ]);
    await client.complianceCheck.check({ orgName: "   " });
    expect(new URL(calls[0].url).searchParams.get("orgName")).toBe("   ");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/compliance-check?orgName=%20%20%20",
    );
    // Symmetric on the systemId branch — whitespace-only fails the
    // kernel's UUID validator with 400, but SDK forwards verbatim.
    try {
      await client.complianceCheck.check({ systemId: "   " });
    } catch {
      /* expected 400 from the kernel */
    }
    expect(new URL(calls[1].url).searchParams.get("systemId")).toBe("   ");
  });

  it("H6: 4096-char orgName forwarded verbatim — SDK does NOT clamp string length", async () => {
    // Faithful courier: SDK does NOT impose a max length on
    // orgName. The kernel doesn't either (text column, no max
    // length). A future "be helpful" refactor that clamps at e.g.
    // 256 chars would silently truncate consumer input — surface
    // here. Pin: a 4096-char orgName arrives at the URL verbatim.
    const longName = "A".repeat(4096);
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check({ orgName: longName });
    expect(new URL(calls[0].url).searchParams.get("orgName")).toBe(longName);
    expect(new URL(calls[0].url).searchParams.get("orgName")?.length).toBe(
      4096,
    );
  });

  it("H7: Proxy-wrapped frozen input cannot be mutated mid-call (defense-in-depth on read-only contract)", async () => {
    // Build round confirmed a frozen object doesn't crash the SDK.
    // Hostile round adds a stronger contract: even a Proxy wrapper
    // that throws on any `set` operation passes through the SDK
    // unchanged. Without the read-only contract, a future refactor
    // that "normalizes" input (e.g., trims orgName, sets a default)
    // would surface as a Proxy-set throw.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const target: ComplianceCheckInput = { systemId: MOCK_RESULT.systemId };
    let setAttempts = 0;
    const proxy = new Proxy(target, {
      set() {
        setAttempts++;
        throw new TypeError("input is read-only");
      },
      deleteProperty() {
        setAttempts++;
        throw new TypeError("input is read-only");
      },
      defineProperty() {
        setAttempts++;
        throw new TypeError("input is read-only");
      },
    });
    const out = await client.complianceCheck.check(proxy);
    expect(out.systems).toHaveLength(1);
    // SDK must NOT have attempted any mutation on the input.
    expect(setAttempts).toBe(0);
  });

  it("H8: case-sensitive systemId forwarded verbatim — SDK does NOT lowercase UUIDs", async () => {
    // Faithful courier: kernel uses `eq(schema.aiSystems.id, systemId)`
    // (Drizzle exact equality, case-sensitive). UUIDs are
    // canonically lowercase in v4 but uppercase variants exist in
    // the wild. SDK does NOT normalize — forwards whatever the
    // caller passes. Pin: an uppercase-hex systemId arrives at the
    // URL with original casing intact. A future "be helpful"
    // refactor that lowercases would surface here.
    const upperUuid = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check({ systemId: upperUuid });
    expect(new URL(calls[0].url).searchParams.get("systemId")).toBe(upperUuid);
  });

  it("H9: Map / Set as input — typeof 'object' but no own systemId / orgName keys → 'neither provided'", () => {
    // Edge case: `new Map([["systemId", "uuid"]])` is typeof
    // "object", non-null, non-Array. Map's items live in an internal
    // slot, NOT as own enumerable properties. So
    // `Object.hasOwn(map, "systemId")` returns false. Pin: the SDK
    // rejects with "neither provided" (NOT "type error", NOT
    // success). Documents the contract that input must be a plain
    // object — Maps don't qualify.
    const { client, calls } = makeMockedClient([]);
    const map = new Map<string, string>([
      ["systemId", "11111111-1111-1111-1111-111111111111"],
    ]);
    expect(() =>
      client.complianceCheck.check(map as unknown as ComplianceCheckInput),
    ).toThrow(/exactly one of `systemId` or `orgName`/);
    expect(calls).toHaveLength(0);
  });

  it("H10: class instance with own systemId field — accepted (faithful)", async () => {
    // Symmetric to H9: a class instance with `this.systemId = "..."`
    // (own enumerable property) IS accepted. Documents the contract
    // that ANY object with own `systemId` or `orgName` properties
    // is valid input — not just literal objects.
    class CheckInput {
      constructor(public systemId: string) {}
    }
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const inst = new CheckInput(MOCK_RESULT.systemId);
    const out = await client.complianceCheck.check(
      inst as unknown as ComplianceCheckInput,
    );
    expect(calls).toHaveLength(1);
    expect(out.systems).toHaveLength(1);
    expect(new URL(calls[0].url).searchParams.get("systemId")).toBe(
      MOCK_RESULT.systemId,
    );
  });

  it("H11: URL has NO bare `?` when only one XOR field is provided (clean URL)", async () => {
    // Defensive: a refactor that switches encodeQuery to always
    // emit `?` would produce `/api/v1/compliance-check?systemId=...&orgName=`
    // — semantically the same as systemId-only, but a sloppier wire
    // and could trigger kernel's "both provided" silent-pick branch
    // depending on `searchParams.get()` semantics for empty values.
    // Pin the clean URL form explicitly.
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check({ systemId: MOCK_RESULT.systemId });
    // No `&orgName=` and no trailing `?orgName=` either.
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/compliance-check?systemId=${MOCK_RESULT.systemId}`,
    );
    expect(calls[0].url).not.toMatch(/orgName/);
  });

  it("H12: response with sparse systems array (some rows null/undefined) — SDK does NOT validate per-row, faithful courier (forward-looking)", async () => {
    // P2 hardening only validates the TOP-LEVEL shape (object,
    // systems is array, checkedAt is string). Per-row validation is
    // NOT part of the SDK contract (P4 candidate). Pin: a response
    // with malformed per-row entries (e.g., `null` mixed in)
    // round-trips intact — the consumer is responsible for
    // per-row validation. This documents the gap explicitly so a
    // future P4 round can pick it up without surprise.
    //
    // **Hostile-review LOW #5 caveat**: today's kernel route at
    // src/app/api/v1/compliance-check/route.ts:113-165 cannot
    // structurally emit `null` rows — every `results.push` is
    // unconditional and synthesizes a complete object. This pin
    // is forward-looking: it documents what the SDK does IF a
    // future kernel adds a path that emits null (e.g., for
    // forbidden rows the user shouldn't see — hypothetical). The
    // SDK forwards faithfully even for shapes the kernel can't
    // currently produce, which is the SDK's contract.
    const sparseSystems = [
      MOCK_RESULT,
      null as unknown as ComplianceCheckResult,
      MOCK_RESULT_2,
    ];
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: sparseSystems, checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    const out = await client.complianceCheck.check({
      orgName: "Mixed Corp",
    });
    expect(out.systems).toHaveLength(3);
    // The null arrives at the consumer — they're responsible for
    // null-checking per-row.
    expect(out.systems[1]).toBeNull();
    expect(out.systems[0]).toEqual(MOCK_RESULT);
    expect(out.systems[2]).toEqual(MOCK_RESULT_2);
  });

  it("H13: response object with `systems` shadowed via prototype is NOT accepted (P2 hardening uses own-property)", async () => {
    // The transport / readBody pipeline returns plain JSON.parse'd
    // objects. JSON.parse never produces objects with prototype-
    // chain properties — so this concern is theoretical. But the
    // SDK's P2 validator should be robust regardless. Pin: a
    // response object whose `systems` lives ONLY on the prototype
    // (not own) is rejected as "not an array".
    //
    // Constructed via Object.create(parent) where parent has the
    // systems field. JSON.parse can't produce this shape, but a
    // hand-crafted mock can. The validator currently uses
    // `Array.isArray(obj.systems)` which DOES walk the prototype
    // chain — so a prototype-only systems would be seen as an
    // array. This pin documents that the SDK doesn't currently
    // defend against this exotic case (it's a P4 candidate); the
    // pin asserts the EXISTING behavior so a future hardening
    // change is intentional.
    const parent = { systems: [MOCK_RESULT] };
    const wrapped = Object.create(parent) as { checkedAt: string };
    wrapped.checkedAt = MOCK_CHECKED_AT;
    // Mock returns the wrapped object directly via bodyText to
    // bypass JSON.stringify normalization (which would flatten the
    // prototype chain).
    const callsLocal: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      callsLocal.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      // JSON.stringify of the prototype-shadowed object only
      // serializes own properties — produces `{"checkedAt":"..."}`
      // (NO `systems`). That's the ACTUAL on-wire shape after
      // serialization. Pin: the SDK's P2 validator catches the
      // missing `systems` field as "not an array (got undefined)".
      const wireJson = JSON.stringify({
        success: true,
        data: wrapped,
      });
      return new Response(wireJson, {
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
    await expect(
      client.complianceCheck.check({ systemId: MOCK_RESULT.systemId }),
    ).rejects.toThrow(/expected response\.systems to be an array \(got undefined\)/);
  });
});

describe("complianceCheck.check — hostile review session 15 residual gaps", () => {
  it("H14: TOCTOU defense — Proxy with side-effecting `get` cannot send a different value than what passed validation", async () => {
    // **Hostile-review session 15 finding LOW #1.** Build round read
    // `input.systemId` THREE separate times (XOR check, validation,
    // query construction). A Proxy with a counting `get` could
    // return "valid-uuid" to the validator and "evil-uuid" to the
    // query builder. Fix: snapshot to local once, validate the
    // snapshot, send the snapshot. This pin asserts the snapshot
    // contract — the URL contains the FIRST-read value and only the
    // first-read value, regardless of how many times a hostile
    // input's getter is called.
    //
    // Construction: the Proxy returns "real-uuid" on the first
    // `.systemId` access and "evil-uuid" on every subsequent access.
    // Without the fix: validation reads "real-uuid" → passes; query
    // reads "evil-uuid" → URL ships "evil-uuid". With the fix: only
    // one read → URL ships "real-uuid".
    //
    // The Proxy must ALSO satisfy `Object.hasOwn` (which calls
    // `getOwnPropertyDescriptor`), so we provide a `getOwnPropertyDescriptor`
    // trap. Returning a plain descriptor with `enumerable: true`
    // makes hasOwn return true.
    let getCount = 0;
    const realUuid = "11111111-1111-1111-1111-111111111111";
    const evilUuid = "deadbeef-beef-beef-beef-beefdeadbeef";
    const proxyInput = new Proxy(
      {} as { systemId: string },
      {
        getOwnPropertyDescriptor(_target, key) {
          if (key === "systemId") {
            return {
              value: realUuid,
              writable: true,
              enumerable: true,
              configurable: true,
            };
          }
          return undefined;
        },
        get(_target, key) {
          if (key === "systemId") {
            getCount++;
            return getCount === 1 ? realUuid : evilUuid;
          }
          return undefined;
        },
      },
    );
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check(proxyInput);
    expect(calls).toHaveLength(1);
    // Critical: the URL contains the validated value, NOT the
    // post-validation value. Without the snapshot fix, this would
    // fail with `evilUuid` on the URL.
    expect(new URL(calls[0].url).searchParams.get("systemId")).toBe(realUuid);
    expect(calls[0].url).not.toMatch(/deadbeef/);
    // Sanity: the Proxy's `get` was called exactly once (the
    // post-`Object.hasOwn` snapshot pull). Asserting `getCount === 1`
    // is what makes the TOCTOU defense load-bearing — if a future
    // refactor adds a second read, this count rises and the pin
    // fires.
    expect(getCount).toBe(1);
  });

  it("H14 corollary: TOCTOU defense extends to orgName branch (mirror)", async () => {
    // Symmetric H14 on the orgName XOR branch. Same construction;
    // same snapshot contract.
    let getCount = 0;
    const realName = "RealCorp";
    const evilName = "EvilCorp";
    const proxyInput = new Proxy(
      {} as { orgName: string },
      {
        getOwnPropertyDescriptor(_target, key) {
          if (key === "orgName") {
            return {
              value: realName,
              writable: true,
              enumerable: true,
              configurable: true,
            };
          }
          return undefined;
        },
        get(_target, key) {
          if (key === "orgName") {
            getCount++;
            return getCount === 1 ? realName : evilName;
          }
          return undefined;
        },
      },
    );
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    await client.complianceCheck.check(proxyInput);
    expect(new URL(calls[0].url).searchParams.get("orgName")).toBe(realName);
    expect(calls[0].url).not.toMatch(/EvilCorp/);
    expect(getCount).toBe(1);
  });

  it("H15: Object.hasOwn snapshot defense — combined override + prototype pollution attack does NOT defeat the H4 fix", async () => {
    // **Hostile-review session 15 finding LOW #2.** The H4 fix calls
    // `Object.hasOwn(input, "systemId")` at request time. A
    // hostile/buggy npm dependency that runs AFTER @attestry/sdk is
    // imported can override the global to defeat the H4 defense
    // ONLY when the override is combined with prototype pollution
    // (override-alone is already short-circuited by the
    // `!== undefined` check on the read result; the snapshot's
    // load-bearing role only emerges when pollution would otherwise
    // make the post-`hasOwn` read return a non-undefined value).
    //
    // The full attack:
    //   1. `Object.hasOwn = () => true` (defeat the own-only check).
    //   2. `Object.prototype.systemId = "evil"` (provide a
    //      non-undefined value the SDK reads via prototype lookup).
    //   3. User calls `{orgName: "Acme"}`.
    //
    // Without the snapshot:
    //   - `Object.hasOwn(input, "systemId")` → true (overridden).
    //   - `input.systemId` → "evil" (prototype lookup).
    //   - `"evil" !== undefined` → true.
    //   - hasSystemId = true.
    //   - hasOrgName = true (own).
    //   - Throws "both provided" — DoS on legitimate input.
    //
    // With the snapshot (`const objectHasOwn = Object.hasOwn` at
    // module load):
    //   - `objectHasOwn(input, "systemId")` calls the ORIGINAL
    //     `Object.hasOwn`, which returns false for prototype-only
    //     properties.
    //   - Short-circuit: hasSystemId = false.
    //   - hasOrgName = true (own property, original hasOwn returns
    //     true; "Acme" !== undefined).
    //   - Routes correctly to the orgName branch — request fires
    //     with `?orgName=Acme`, NO `systemId=evil` leak.
    //
    // This pin asserts the snapshot is load-bearing — it would FAIL
    // (URL would contain `systemId=evil` or the SDK would throw
    // "both provided") if the snapshot were removed.
    const realHasOwn = Object.hasOwn;
    const proto = Object.prototype as unknown as Record<string, unknown>;
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    try {
      // Pollute Object.prototype.systemId (the value an attacker
      // wants the SDK to read instead of the user's intent).
      proto.systemId = "evil-attacker-uuid";
      // Override Object.hasOwn AFTER module load (the SDK module
      // captured the original at import time). Cast through unknown
      // to satisfy the strict typing on Object.
      (Object as unknown as { hasOwn: typeof Object.hasOwn }).hasOwn =
        () => true;

      // Legitimate caller: just the orgName.
      await client.complianceCheck.check({ orgName: "Acme" });

      // Critical: SDK must have routed to the orgName branch, NOT
      // thrown "both provided" (which would happen if the snapshot
      // weren't load-bearing — see trace above).
      expect(calls).toHaveLength(1);
      const url = new URL(calls[0].url);
      expect(url.searchParams.get("orgName")).toBe("Acme");
      // The polluted systemId did NOT leak into the request.
      expect(url.searchParams.has("systemId")).toBe(false);
      expect(calls[0].url).not.toMatch(/evil-attacker-uuid/);
    } finally {
      (Object as unknown as { hasOwn: typeof Object.hasOwn }).hasOwn =
        realHasOwn;
      delete proto.systemId;
    }
  });

  it("H15 corollary: snapshot defense protects the systemId branch from polluted-orgName + override (mirror)", async () => {
    // Symmetric H15 on the OTHER branch. With pollution on
    // orgName + override, a user passing `{systemId: "real-uuid"}`
    // should still route to the systemId branch (NOT throw
    // "both provided"). This is the reverse of H15's primary
    // direction.
    const realHasOwn = Object.hasOwn;
    const proto = Object.prototype as unknown as Record<string, unknown>;
    const realUuid = "11111111-1111-1111-1111-111111111111";
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { systems: [MOCK_RESULT], checkedAt: MOCK_CHECKED_AT },
        },
      },
    ]);
    try {
      proto.orgName = "Evil Corp";
      (Object as unknown as { hasOwn: typeof Object.hasOwn }).hasOwn =
        () => true;
      await client.complianceCheck.check({ systemId: realUuid });
      expect(calls).toHaveLength(1);
      const url = new URL(calls[0].url);
      expect(url.searchParams.get("systemId")).toBe(realUuid);
      expect(url.searchParams.has("orgName")).toBe(false);
      expect(calls[0].url).not.toMatch(/Evil Corp/);
    } finally {
      (Object as unknown as { hasOwn: typeof Object.hasOwn }).hasOwn =
        realHasOwn;
      delete proto.orgName;
    }
  });
});
