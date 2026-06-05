import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type { GateInput, GateResponse, GateGap } from "../gate.js";
import type { FetchLike } from "../../types.js";

// ─── gate.evaluate — POST + JSON body, sync request/response ────────────────
//
// Wire shape (from src/app/api/v1/gate/route.ts):
//   POST /api/v1/gate
//   Content-Type: application/json
//   Body: {systemId: <UUID>, minScore?: int 0-100, frameworks?: string[],
//          failOnMissingAssessment?: boolean}
//   → THREE distinct emit paths:
//     - Path 1 (normal pass/fail, assessment found): 14 fields including
//       `assessmentId`, `assessmentDate`, `gapCount`, `criticalGaps`, `highGaps`.
//     - Path 2 (fail-on-missing): 9 fields, `gate: "fail"`, `score: null`,
//       `gaps: []`.
//     - Path 3 (pass-on-missing): 9 fields, `gate: "pass"`, `score: null`,
//       `gaps: []`.
//
// Fifth non-decisions resource on the SDK; sibling to IncidentsResource /
// DecisionsResource / ChatResource / AuditLogResource / RegulatoryChangesResource
// / ComplianceCheckResource / CheckResource.
//
// **Multi-permission UNION auth** (carry-forward #45) — kernel uses
// `requireApiKeyWithPermission(req, READ_ASSESSMENTS, READ_SYSTEMS)`
// which is `Array.some()`-based. A key with EITHER permission
// succeeds; 403 fires only when the key has NEITHER. Single 403 test
// case (the union-auth pattern collapses what intuition suggests as
// 3 cases to 1).
//
// **SECOND SDK route to PRE-VALIDATE every Zod closed-spec rule
// synchronously** (first was check.run). Four pre-validated fields:
// UUID format on systemId, integer + range [0, 100] on minScore,
// boolean on failOnMissingAssessment, array length cap + per-element
// string length on frameworks. The runtime checks always run
// regardless of TypeScript types — `as any` casts do NOT bypass
// them. So 422 reaches consumers ONLY via kernel rule changes the
// SDK hasn't synced to. Invariants #49 + new candidate #52
// (closed-default field pre-validation: when Zod has `.default(<v>)`,
// SDK pre-validates AND omits from body so kernel applies default).
//
// **Asymmetric cross-org error code (partial #47 carry-forward)** —
// cross-org systemId collapses to 404 "System not found or access
// denied" (literal string is LONGER than check.run's "System not
// found"; pin separately).
//
// **TWO silent kernel-side truncations** (faithful courier; invariant
// candidate #50) — `assessments` limit(10) [tighter than check.run's
// 100], `remediationTasks` limit(100). Each documented in JSDoc +
// README + drift-pinned with ANCHORED regex per session-16 second-
// review MEDIUM #4.
//
// **`score` defaults to `null` (NOT 0) in no-assessment paths** —
// asymmetric with check.run's `0`. Gate preserves the distinction at
// the type level. Consumers use `score === null` to detect Paths 2 +
// 3.
//
// **`gate` is a STRING ENUM ("pass" | "fail"), NOT a boolean** —
// pre-build handoff predicted `passed: boolean`; route source
// contradicts that. SDK contract uses the string-enum form.
//
// **`frameworks` filter is substring + case-insensitive** —
// asymmetric with check.run's OR-overlap exact-equality. Documented
// as a kernel surface behavior.
//
// **`writeAuditLog` side effect** — every call writes one
// `gate.checked` audit log entry (NEW for a read-shaped SDK route;
// invariant candidate #53).
//
// **NO URIError defense on body fields** — POST body uses
// JSON.stringify (not encodeURIComponent), so lone UTF-16 surrogates
// in framework strings pass through verbatim as `\uDxxx` escapes.
// Asymmetric with compliance-check / decisions / incidents / audit-
// log / regulatory-changes which DO need the URIError guard (query-
// string paths). systemId is still pre-validated as a UUID, which
// happens to also reject lone-surrogate-only strings.
//
// **Symmetric prototype-pollution defense** — `Object.hasOwn`
// snapshot applied to BOTH input AND response sides (session-16
// second-hostile-review MEDIUM #3 carry-forward, baked in from
// build-round start).

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

// Representative GateGap fixture (4 fields, all open-spec strings).
const SAMPLE_GAP: GateGap = {
  requirementKey: "EU_AI_ACT_5_2_a",
  title: "Risk classification missing",
  priority: "critical",
  status: "open",
};

// Path 1 wire-shape — happy-path mock baseline. 14 fields, including
// all 5 emit-only fields. Use for any test that doesn't specifically
// exercise the no-assessment branches.
const MOCK_PATH1_RESPONSE: GateResponse = {
  gate: "pass",
  systemId: VALID_UUID,
  systemName: "Test System",
  score: 87,
  minScore: 70,
  frameworks: ["EU_AI_ACT", "ISO_42001"],
  gaps: [],
  reason: "Score 87 meets minimum threshold of 70.",
  timestamp: "2026-05-11T15:00:00.000Z",
  assessmentId: "22222222-2222-2222-2222-222222222222",
  assessmentDate: "2026-04-21T12:34:56.000Z",
  gapCount: 0,
  criticalGaps: 0,
  highGaps: 0,
};

// Path 2 (fail-on-missing) wire-shape — 9 fields, no emit-only.
const MOCK_PATH2_RESPONSE: GateResponse = {
  gate: "fail",
  systemId: VALID_UUID,
  systemName: "Test System",
  score: null,
  minScore: 70,
  frameworks: [],
  gaps: [],
  reason: "No completed assessment found for this system.",
  timestamp: "2026-05-11T15:00:00.000Z",
};

// Path 3 (pass-on-missing) wire-shape — 9 fields, no emit-only.
const MOCK_PATH3_RESPONSE: GateResponse = {
  gate: "pass",
  systemId: VALID_UUID,
  systemName: "Test System",
  score: null,
  minScore: 70,
  frameworks: [],
  gaps: [],
  reason: "No assessment found but failOnMissingAssessment is false.",
  timestamp: "2026-05-11T15:00:00.000Z",
};

describe("gate.evaluate — happy path", () => {
  it("POSTs /api/v1/gate with a JSON body containing only systemId (defaults applied kernel-side)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/gate");
    expect(url.search).toBe("");
    // Body is the JSON-serialized input — systemId required, none of
    // the optional fields included when omitted (kernel applies
    // defaults: minScore=70, failOnMissingAssessment=true; frameworks
    // means "no filter"). Invariant candidate #52.
    expect(calls[0].body).toBeDefined();
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({ systemId: VALID_UUID });
    expect(out).toEqual(MOCK_PATH1_RESPONSE);
  });

  it("POSTs body with all 4 fields when fully provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      minScore: 85,
      frameworks: ["EU_AI_ACT", "ISO_42001"],
      failOnMissingAssessment: false,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      systemId: VALID_UUID,
      minScore: 85,
      frameworks: ["EU_AI_ACT", "ISO_42001"],
      failOnMissingAssessment: false,
    });
  });

  it("returns the response shape unchanged (envelope unwrapped) for Path 1", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    // Verify envelope was unwrapped: top-level keys are the 14
    // documented Path-1 fields, NOT success + data.
    expect(Object.keys(out).sort()).toEqual(
      [
        "gate",
        "systemId",
        "systemName",
        "score",
        "minScore",
        "frameworks",
        "gaps",
        "reason",
        "timestamp",
        "assessmentId",
        "assessmentDate",
        "gapCount",
        "criticalGaps",
        "highGaps",
      ].sort(),
    );
  });

  it("forwards x-api-key + Accept + Content-Type headers (POST + body)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({ systemId: VALID_UUID });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("returns all Path-1 fields with their documented types (sanity)", async () => {
    // Sanity check: every field in the documented GateResponse
    // interface round-trips with its declared type. Drift on this
    // test = kernel-side route emits new field name OR SDK interface
    // drift; cross-check sdk-drift.test.ts.
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(typeof out.gate).toBe("string");
    expect(out.gate === "pass" || out.gate === "fail").toBe(true);
    expect(typeof out.systemId).toBe("string");
    expect(typeof out.systemName).toBe("string");
    expect(typeof out.score === "number" || out.score === null).toBe(true);
    expect(typeof out.minScore).toBe("number");
    expect(Array.isArray(out.frameworks)).toBe(true);
    expect(Array.isArray(out.gaps)).toBe(true);
    expect(typeof out.reason).toBe("string");
    expect(typeof out.timestamp).toBe("string");
    // Emit-only fields (Path 1).
    expect(typeof out.assessmentId).toBe("string");
    expect(
      typeof out.assessmentDate === "string" || out.assessmentDate === null,
    ).toBe(true);
    expect(typeof out.gapCount).toBe("number");
    expect(typeof out.criticalGaps).toBe("number");
    expect(typeof out.highGaps).toBe("number");
  });
});

describe("gate.evaluate — input validation (pre-fetch)", () => {
  it("throws TypeError for null input — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate(null as unknown as GateInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate(undefined as unknown as GateInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input (typeof [] === 'object')", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate([] as unknown as GateInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string / number / boolean)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate("uuid" as unknown as GateInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.gate.evaluate(42 as unknown as GateInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.gate.evaluate(true as unknown as GateInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty object — systemId is required", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({} as unknown as GateInput),
    ).toThrow(/`systemId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for explicit `systemId: undefined`", () => {
    // TS users may pass `{systemId: undefined}` via spread of a partial
    // object. The SDK treats own-but-undefined as not-provided (same
    // as missing key) and rejects with the "required" message.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: undefined,
      } as unknown as GateInput),
    ).toThrow(/`systemId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty systemId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: "" }),
    ).toThrow(/`systemId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId (number / null / object)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: 42 as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.gate.evaluate({
        systemId: null as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.gate.evaluate({
        systemId: { nested: true } as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for systemId with invalid UUID format (D2 — SDK pre-validates)", () => {
    // **D2 — SDK pre-validates the closed-spec rule** (mirror of
    // check.run's D2; codifies invariant #49). Faster + clearer than
    // waiting for the kernel's 422 with `details` array.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: "not-a-uuid" }),
    ).toThrow(/must be an RFC 4122 hyphenated UUID/);
    expect(() =>
      client.gate.evaluate({ systemId: "00000000-0000-0000-0000" }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.gate.evaluate({ systemId: "1111111-1111-1111-1111-111111111111" }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for systemId without hyphens (32-char hex)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: "11111111111111111111111111111111",
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("accepts lowercase UUID (regex is case-insensitive)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: "abcdef12-3456-7890-abcd-ef1234567890",
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).systemId).toBe(
      "abcdef12-3456-7890-abcd-ef1234567890",
    );
  });

  it("accepts uppercase UUID (regex is case-insensitive)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
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
    // lone-surrogate characters aren't valid hex characters, so they
    // fail the UUID regex `[0-9a-fA-F]`. If a future kernel relaxes
    // `systemId` from RFC 4122 UUID to a free-form string, the SDK's
    // UUID pre-validation would be removed AND this incidental
    // defense would disappear. Mirror of check.run's lone-surrogate
    // pin.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: "\uD800" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.gate.evaluate({
        systemId: "11111111-1111-1111-1111-11111111111\uD800",
      }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when minScore is non-integer number (D3 — SDK pre-validates)", () => {
    // **D3 — SDK pre-validates** `z.number().int().min(0).max(100)`
    // synchronously. `Number.isInteger` rejects floats; invariant #49.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: 1.5 }),
    ).toThrow(/must be a finite integer/);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: 99.999 }),
    ).toThrow(/must be a finite integer/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when minScore is below 0 (Zod .min(0))", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: -1 }),
    ).toThrow(/must be in the range \[0, 100\]/);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: -100 }),
    ).toThrow(/must be in the range \[0, 100\]/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when minScore is above 100 (Zod .max(100))", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: 101 }),
    ).toThrow(/must be in the range \[0, 100\]/);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: 1000 }),
    ).toThrow(/must be in the range \[0, 100\]/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when minScore is a string (e.g., '70')", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        minScore: "70" as unknown as number,
      }),
    ).toThrow(/`minScore` must be a number when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when minScore is NaN (Number.isInteger rejects)", () => {
    // NaN: typeof === "number" but Number.isInteger returns false.
    // The "must be a finite integer" branch fires.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: NaN }),
    ).toThrow(/must be a finite integer/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when minScore is +Infinity or -Infinity (Number.isInteger rejects)", () => {
    // ±Infinity: typeof === "number" but Number.isInteger returns
    // false. The "must be a finite integer" branch fires.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: Infinity }),
    ).toThrow(/must be a finite integer/);
    expect(() =>
      client.gate.evaluate({ systemId: VALID_UUID, minScore: -Infinity }),
    ).toThrow(/must be a finite integer/);
    expect(calls).toHaveLength(0);
  });

  it("accepts minScore at the 0 boundary (Zod .min(0) inclusive)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({ systemId: VALID_UUID, minScore: 0 });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).minScore).toBe(0);
  });

  it("accepts minScore at the 100 boundary (Zod .max(100) inclusive)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({ systemId: VALID_UUID, minScore: 100 });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).minScore).toBe(100);
  });

  it("omits minScore from the body when caller omits it (kernel applies default 70)", async () => {
    // **Invariant candidate #52** — closed-default field omission.
    // The Zod schema marks `minScore` with `.default(70)`; a missing
    // key is the cleanest representation that triggers the kernel
    // default. Pin: body has NO minScore key.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({ systemId: VALID_UUID });
    const parsed = JSON.parse(calls[0].body!);
    expect("minScore" in parsed).toBe(false);
  });

  it("explicit `minScore: undefined` is equivalent to omission", async () => {
    // TS allows `{systemId, minScore: undefined}`. The SDK's
    // `Object.hasOwn` returns true (the key is an own property), but
    // the value-undefined short-circuits before the type/range
    // validation. Pin: same body as no minScore key.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      minScore: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect("minScore" in parsed).toBe(false);
  });

  it("throws TypeError when failOnMissingAssessment is a string (D4 — SDK pre-validates)", () => {
    // **D4 — SDK pre-validates** `z.boolean()` synchronously.
    // Mirrors invariant #49. Rejects truthy/falsy non-booleans
    // (`"true"`, `1`, `null`).
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        failOnMissingAssessment: "true" as unknown as boolean,
      }),
    ).toThrow(/`failOnMissingAssessment` must be a boolean/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when failOnMissingAssessment is a number (truthy 1 / falsy 0)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        failOnMissingAssessment: 1 as unknown as boolean,
      }),
    ).toThrow(/must be a boolean/);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        failOnMissingAssessment: 0 as unknown as boolean,
      }),
    ).toThrow(/must be a boolean/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when failOnMissingAssessment is null", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        failOnMissingAssessment: null as unknown as boolean,
      }),
    ).toThrow(/must be a boolean.*got null/);
    expect(calls).toHaveLength(0);
  });

  it("accepts failOnMissingAssessment: true (boundary)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      failOnMissingAssessment: true,
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).failOnMissingAssessment).toBe(true);
  });

  it("accepts failOnMissingAssessment: false (boundary)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH3_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      failOnMissingAssessment: false,
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).failOnMissingAssessment).toBe(false);
  });

  it("omits failOnMissingAssessment from the body when caller omits it (kernel applies default true)", async () => {
    // Same invariant-#52 pin as minScore: the Zod schema marks
    // `.default(true)`; missing key triggers the kernel default.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({ systemId: VALID_UUID });
    const parsed = JSON.parse(calls[0].body!);
    expect("failOnMissingAssessment" in parsed).toBe(false);
  });

  it("explicit `failOnMissingAssessment: undefined` is equivalent to omission", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      failOnMissingAssessment: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect("failOnMissingAssessment" in parsed).toBe(false);
  });

  it("throws TypeError when frameworks is not an array (string / object)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: "EU_AI_ACT" as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: { 0: "EU_AI_ACT", length: 1 } as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworks is null (explicitly set, not omitted)", () => {
    // Carry-forward from check.run's session-16 hostile-review MEDIUM
    // #1: the `if (hasFrameworks && frameworksRaw !== undefined)`
    // guard SHOULD let `null` enter the Array.isArray branch (since
    // null !== undefined), producing a "must be an array (got null)"
    // TypeError. Pin so a refactor doesn't silently let null slip
    // through.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: null as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array when provided.*got null/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworks contains a non-string element", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: [42 as unknown as string],
      }),
    ).toThrow(/`frameworks\[0\]` must be a string/);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: ["EU_AI_ACT", null as unknown as string],
      }),
    ).toThrow(/`frameworks\[1\]` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworks contains an empty string (Zod .min(1))", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: [""],
      }),
    ).toThrow(/must be a non-empty string/);
    expect(() =>
      client.gate.evaluate({
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
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: [tooLong],
      }),
    ).toThrow(/exceeds the kernel's max length of 100 chars/);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: [tooLong],
      }),
    ).toThrow(/got 101/);
    expect(calls).toHaveLength(0);
  });

  it("accepts frameworks element at the 100-char boundary", async () => {
    const exactly100 = "x".repeat(100);
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
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
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: tooMany,
      }),
    ).toThrow(/exceeds the kernel's max length of 20/);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: tooMany,
      }),
    ).toThrow(/got 21/);
    expect(calls).toHaveLength(0);
  });

  it("accepts frameworks at the 20-element / 100-char boundary", async () => {
    const exactly20 = Array.from({ length: 20 }, () => "x".repeat(100));
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      frameworks: exactly20,
    });
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).frameworks).toHaveLength(20);
  });

  it("accepts an empty frameworks array (kernel treats as no filter)", async () => {
    // Zod's .max(20) accepts arrays of length 0..20. An empty array
    // is valid input; the kernel's filter logic at route.ts:90
    // short-circuits when `body.frameworks.length === 0` and uses
    // all assessments. Pin: SDK passes empty array through unchanged.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
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
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({ systemId: VALID_UUID });
    const parsed = JSON.parse(calls[0].body!);
    expect("frameworks" in parsed).toBe(false);
  });

  it("explicit `frameworks: undefined` is equivalent to omission", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      frameworks: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect("frameworks" in parsed).toBe(false);
  });

  it("defends against prototype pollution on systemId presence (Object.hasOwn defense, generalization of #48)", () => {
    // **Build-round defense pin** (mirror of check.run's pattern).
    // If `Object.prototype.systemId = "<some-uuid>"` were set
    // elsewhere in the process, a consumer's `client.gate.evaluate({})`
    // would otherwise read the polluted prototype value via the
    // indexer and silently submit it. The SDK uses `Object.hasOwn`
    // to defend: own properties only count as "provided".
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
        client.gate.evaluate({} as unknown as GateInput),
      ).toThrow(/`systemId` is required/);
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "systemId", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .systemId;
      }
    }
    expect(calls).toHaveLength(0);
  });

  it("defends against prototype pollution on minScore / failOnMissingAssessment / frameworks (Object.hasOwn defense on all optional fields)", async () => {
    // Symmetric to the systemId pollution pin, but on all THREE
    // optional fields simultaneously. If the SDK uses `objectHasOwn`
    // consistently, prototype-polluted values do NOT leak into the
    // body when the caller provides only `{systemId: valid}`.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    const originalMinScoreDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "minScore",
    );
    const originalFomaDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "failOnMissingAssessment",
    );
    const originalFrameworksDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "frameworks",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).minScore = 99;
      (
        Object.prototype as unknown as Record<string, unknown>
      ).failOnMissingAssessment = false;
      (Object.prototype as unknown as Record<string, unknown>).frameworks = [
        "EVIL_FRAMEWORK",
      ];
      await client.gate.evaluate({ systemId: VALID_UUID });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed).toEqual({ systemId: VALID_UUID });
      // Own-property check (NOT `in`-walk) confirms no polluted keys
      // landed on the wire body.
      expect(Object.hasOwn(parsed, "minScore")).toBe(false);
      expect(Object.hasOwn(parsed, "failOnMissingAssessment")).toBe(false);
      expect(Object.hasOwn(parsed, "frameworks")).toBe(false);
    } finally {
      if (originalMinScoreDesc) {
        Object.defineProperty(
          Object.prototype,
          "minScore",
          originalMinScoreDesc,
        );
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .minScore;
      }
      if (originalFomaDesc) {
        Object.defineProperty(
          Object.prototype,
          "failOnMissingAssessment",
          originalFomaDesc,
        );
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .failOnMissingAssessment;
      }
      if (originalFrameworksDesc) {
        Object.defineProperty(
          Object.prototype,
          "frameworks",
          originalFrameworksDesc,
        );
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .frameworks;
      }
    }
  });
});

describe("gate.evaluate — body encoding", () => {
  it("body uses Zod-schema field names (systemId, minScore, frameworks, failOnMissingAssessment)", async () => {
    // Sanity pin against camelCase / snake_case / Pascal-case
    // refactor drift. The kernel's Zod schema uses these exact keys;
    // the SDK body must use the same.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      minScore: 85,
      frameworks: ["EU_AI_ACT"],
      failOnMissingAssessment: false,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.keys(parsed).sort()).toEqual([
      "failOnMissingAssessment",
      "frameworks",
      "minScore",
      "systemId",
    ]);
  });

  it("accepts lone-surrogate strings in frameworks (faithful courier — JSON.stringify handles them)", async () => {
    // **D6 — NO URIError defense on body fields**. POST body uses
    // JSON.stringify, which emits lone UTF-16 surrogates as literal
    // `\uDxxx` escapes (per JSON spec). Zod's
    // `.string().min(1).max(100)` accepts any string of length 1-100
    // — lone surrogates are length-1 strings. SDK does NOT reject;
    // kernel processes them. Asymmetric with compliance-check /
    // decisions / incidents / audit-log / regulatory-changes (those
    // use query-string paths through encodeURIComponent, which
    // throws URIError).
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      frameworks: ["\uD800"],
    });
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.frameworks).toEqual(["\uD800"]);
  });

  it("does not mutate the input object (read-only)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    const input: GateInput = Object.freeze({
      systemId: VALID_UUID,
      minScore: 85,
      frameworks: Object.freeze(["EU_AI_ACT", "ISO_42001"]) as string[],
      failOnMissingAssessment: false,
    });
    const snapshot = JSON.stringify(input);
    await client.gate.evaluate(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });

  it("body omits each unprovided optional field individually (so kernel applies its default for each)", async () => {
    // Combinatorial pin: caller provides systemId + frameworks, but
    // not minScore or failOnMissingAssessment. Each of the two
    // omitted fields should be ABSENT from the body — both kernel
    // defaults (70, true) apply. Invariant candidate #52 carry-
    // forward.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      frameworks: ["EU_AI_ACT"],
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      systemId: VALID_UUID,
      frameworks: ["EU_AI_ACT"],
    });
    expect("minScore" in parsed).toBe(false);
    expect("failOnMissingAssessment" in parsed).toBe(false);
  });
});

describe("gate.evaluate — error paths", () => {
  it("surfaces a 401 (no/invalid API key) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required" },
      },
    ]);
    try {
      await client.gate.evaluate({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 403 (key has NEITHER READ_ASSESSMENTS NOR READ_SYSTEMS — union-auth) as AttestryAPIError", async () => {
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
      await client.gate.evaluate({ systemId: VALID_UUID });
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
    // **Asymmetric cross-org error code pin** (partial #47).
    // Kernel emits the literal string `"System not found or access
    // denied"` (LONGER than check.run's `"System not found"`).
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "System not found or access denied" },
      },
    ]);
    try {
      await client.gate.evaluate({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
      expect((err as AttestryAPIError).message).toMatch(
        /System not found or access denied/,
      );
    }
  });

  it("surfaces a 422 (kernel Zod schema rejection, only reachable via kernel-side rule changes the SDK hasn't synced to) as AttestryAPIError with actual kernel body shape", async () => {
    // **The SDK pre-validates every closed-spec rule** — so 422 is
    // reachable only via `as any` casts or kernel-side rule changes.
    // Mock the ACTUAL kernel emit shape from src/lib/api.ts:84-91
    // + 28-42 (verified for session-17 build round per session-16
    // first-hostile-review HIGH #1 lesson):
    //
    //   {success: false, error: "Validation failed.",
    //    details: [{path: "<dotted-path>", message: "<zod-msg>"}, ...]}
    //
    // NOT `{error: "Invalid request body", fieldErrors: {key: [...]}}`
    // — that shape was the fictional handoff claim from session 15/16
    // and was corrected in session 16 HIGH #1. Session-17 handoff
    // verified this shape against api.ts before writing this mock.
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
            { path: "minScore", message: "Number must be less than or equal to 100" },
          ],
        },
      },
    ]);
    try {
      await client.gate.evaluate({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.message).toBe("Validation failed.");
      const wireBody = apiErr.details as {
        success: false;
        error: string;
        details: Array<{ path: string; message: string }>;
      };
      expect(wireBody.error).toBe("Validation failed.");
      expect(Array.isArray(wireBody.details)).toBe(true);
      expect(wireBody.details).toEqual([
        { path: "minScore", message: "Number must be less than or equal to 100" },
      ]);
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
      await client.gate.evaluate({ systemId: VALID_UUID });
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
        body: {
          success: false,
          error: "An internal error occurred. Please try again later.",
        },
      },
    ]);
    try {
      await client.gate.evaluate({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(500);
    }
  });

  it("P3: wrong content-type (text/plain) throws AttestryAPIError from transport", async () => {
    // P3 hardening: the transport's sync content-type guard fires
    // BEFORE readBody, so wrong content-type rejects before the
    // resource layer's P2 shape validator.
    const callsLocal: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      callsLocal.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      return new Response(
        JSON.stringify({ success: true, data: MOCK_PATH1_RESPONSE }),
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
      await client.gate.evaluate({ systemId: VALID_UUID });
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

describe("gate.evaluate — response shape preservation (three emit paths)", () => {
  it("Path 1 (normal pass/fail, assessment found): all 14 fields round-trip", async () => {
    const path1WithGap: GateResponse = {
      ...MOCK_PATH1_RESPONSE,
      gate: "fail",
      score: 65,
      gaps: [SAMPLE_GAP],
      gapCount: 1,
      criticalGaps: 1,
      highGaps: 0,
      reason: "Score 65 is below minimum threshold of 70. 1 unresolved gaps.",
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: path1WithGap } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out).toEqual(path1WithGap);
  });

  it("Path 2 (fail-on-missing, no assessment): 9 fields, emit-only ABSENT", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH2_RESPONSE } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out).toEqual(MOCK_PATH2_RESPONSE);
    // Emit-only fields are ABSENT (not just undefined). Own-property
    // false is the canonical "no assessment" shape — pins that the
    // SDK preserves the kernel's distinction rather than synthesizing
    // emit-only fields with placeholders.
    expect(Object.hasOwn(out, "assessmentId")).toBe(false);
    expect(Object.hasOwn(out, "assessmentDate")).toBe(false);
    expect(Object.hasOwn(out, "gapCount")).toBe(false);
    expect(Object.hasOwn(out, "criticalGaps")).toBe(false);
    expect(Object.hasOwn(out, "highGaps")).toBe(false);
  });

  it("Path 3 (pass-on-missing, no assessment): 9 fields, emit-only ABSENT", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH3_RESPONSE } },
    ]);
    const out = await client.gate.evaluate({
      systemId: VALID_UUID,
      failOnMissingAssessment: false,
    });
    expect(out).toEqual(MOCK_PATH3_RESPONSE);
    expect(Object.hasOwn(out, "assessmentId")).toBe(false);
  });

  it("gate: 'pass' round-trips as the literal string (NOT coerced to boolean)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_PATH1_RESPONSE, gate: "pass" } } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.gate).toBe("pass");
    expect(typeof out.gate).toBe("string");
    // Defense pin: a consumer accidentally comparing against `true`
    // sees `false` (string-vs-boolean comparison). Documents the
    // string-enum contract.
    expect((out.gate as unknown) === true).toBe(false);
  });

  it("gate: 'fail' round-trips as the literal string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, gate: "fail", score: 50 },
        },
      },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.gate).toBe("fail");
  });

  it("score: null round-trips as null (NOT 0, NOT undefined) — kernel surface gap D8, asymmetric with check.run", async () => {
    // **The non-obvious gotcha pin** — asymmetric with check.run.
    // check.run uses score: 0 as the no-assessment default; gate
    // uses score: null. Consumers should use `score === null`
    // (NOT `score === 0`) to detect Paths 2 + 3.
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH2_RESPONSE } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.score).toBeNull();
    // Distinction-from-zero pin: out.score is explicitly null, not
    // the number 0 (and `out.score === 0` returns false).
    expect((out.score as unknown) === 0).toBe(false);
  });

  it("score: 87 (number) round-trips as 87 in Path 1", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_PATH1_RESPONSE, score: 87 } } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.score).toBe(87);
    expect(typeof out.score).toBe("number");
  });

  it("score: 0 round-trips as 0 (assessment exists but scored literally zero — distinct from score: null)", async () => {
    // Important distinction: in Path 1, a system that legitimately
    // scored 0 (`scoresObj.overall === 0`) has `score: 0` (NOT null).
    // The kernel's null vs 0 distinction is preserved.
    const zeroScored: GateResponse = {
      ...MOCK_PATH1_RESPONSE,
      gate: "fail",
      score: 0,
      reason: "Score 0 is below minimum threshold of 70. 0 unresolved gaps.",
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: zeroScored } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.score).toBe(0);
    expect(typeof out.score).toBe("number");
    // Disambiguation: score === 0 is distinct from score === null;
    // use `score === null` (the pollution-safe discriminator — see
    // gate.ts top-level GateResponse JSDoc) to detect Paths 2 + 3 —
    // NOT `score === 0`, and NOT `assessmentId === undefined` (which
    // reads via prototype walk and is unsafe under
    // `Object.prototype.assessmentId` pollution).
    expect(out.score === null).toBe(false);
  });

  it("gaps: [] round-trips in all three paths", async () => {
    // Path 1 with no unresolved gaps.
    const { client: c1 } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_PATH1_RESPONSE, gaps: [] } } },
    ]);
    expect((await c1.gate.evaluate({ systemId: VALID_UUID })).gaps).toEqual(
      [],
    );

    // Path 2 (fail-on-missing) — gaps is always [] kernel-side.
    const { client: c2 } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH2_RESPONSE } },
    ]);
    expect((await c2.gate.evaluate({ systemId: VALID_UUID })).gaps).toEqual(
      [],
    );

    // Path 3 (pass-on-missing) — gaps is always [] kernel-side.
    const { client: c3 } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH3_RESPONSE } },
    ]);
    expect(
      (
        await c3.gate.evaluate({
          systemId: VALID_UUID,
          failOnMissingAssessment: false,
        })
      ).gaps,
    ).toEqual([]);
  });

  it("gaps with GateGap-shaped elements round-trip (4 fields per gap)", async () => {
    // Each GateGap has 4 fields: requirementKey, title, priority,
    // status. All open-spec strings (faithful courier — kernel
    // doesn't enforce closed enum on priority/status).
    const multiGap: GateResponse = {
      ...MOCK_PATH1_RESPONSE,
      gate: "fail",
      score: 50,
      gaps: [
        SAMPLE_GAP,
        {
          requirementKey: "ISO_42001_6_1",
          title: "Risk register stale",
          priority: "high",
          status: "in_progress",
        },
        {
          requirementKey: "EU_AI_ACT_9_3",
          title: "Post-market monitoring policy",
          priority: "medium",
          status: "open",
        },
      ],
      gapCount: 3,
      criticalGaps: 1,
      highGaps: 1,
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: multiGap } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.gaps).toEqual(multiGap.gaps);
    expect(out.gaps[0].requirementKey).toBe("EU_AI_ACT_5_2_a");
    expect(out.gaps[1].priority).toBe("high");
    expect(out.gaps[2].status).toBe("open");
  });

  it("gaps at the 100-element kernel cap round-trips WITHOUT a truncation indicator (D9 — invariant #50)", async () => {
    // **Kernel surface gap pin** — the kernel's `remediationTasks
    // .limit(100)` at route.ts:154 silently caps row-population.
    // If the assessment has >100 unresolved gaps, the 101st+ are
    // invisible. No `total`, no `hasMore`, no truncation indicator.
    // Faithful courier; documented in JSDoc + README + drift-pinned.
    const hundredGaps: GateGap[] = Array.from({ length: 100 }, (_, i) => ({
      requirementKey: `REQ_${i}`,
      title: `Gap ${i + 1}`,
      priority: i === 0 ? "critical" : "medium",
      status: "open",
    }));
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_PATH1_RESPONSE,
            gate: "fail",
            score: 50,
            gaps: hundredGaps,
            gapCount: 100,
            criticalGaps: 1,
            highGaps: 0,
          },
        },
      },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.gaps).toHaveLength(100);
    // No truncation indicator — consumers cannot detect from the
    // wire shape alone that they've hit the cap.
    expect(out).not.toHaveProperty("total");
    expect(out).not.toHaveProperty("hasMore");
    expect(out).not.toHaveProperty("gapsTruncated");
  });

  it("assessmentDate: null round-trips as null (assessment.completedAt is nullable)", async () => {
    // The kernel emits `assessmentDate: relevantAssessment.completedAt?.toISOString() ?? null`
    // (route.ts:190). A completed assessment with a NULL completedAt
    // (rare but possible) emits assessmentDate: null in Path 1.
    const nullDated: GateResponse = {
      ...MOCK_PATH1_RESPONSE,
      assessmentDate: null,
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: nullDated } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.assessmentDate).toBeNull();
  });

  it("assessmentDate: ISO string round-trips when present in Path 1", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.assessmentDate).toBe("2026-04-21T12:34:56.000Z");
  });

  it("frameworks: response array round-trips faithfully (echoed from kernel — could be input echo OR assessment frameworks)", async () => {
    // Note: in Paths 2 + 3 (no assessment) the kernel echoes the
    // input frameworks (or [] if omitted). In Path 1 the kernel emits
    // the ASSESSMENT's frameworks (NOT the consumer's filter).
    // Documented for completeness; the SDK contract is just
    // `frameworks: string[]` — semantic source differs by path.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_PATH1_RESPONSE,
            frameworks: ["EU_AI_ACT", "ISO_42001"],
          },
        },
      },
    ]);
    const out = await client.gate.evaluate({
      systemId: VALID_UUID,
      frameworks: ["GDPR"], // Different from the response's echo
    });
    // Response carries the kernel's emitted frameworks (NOT the
    // consumer's input echo). Faithful courier — SDK does not
    // remap.
    expect(out.frameworks).toEqual(["EU_AI_ACT", "ISO_42001"]);
  });

  it("passes through extra unknown top-level fields verbatim (forward-compat)", async () => {
    // Mirror of regulatoryChanges / compliance-check / check
    // forward-compat pins: if the kernel adds a new field before
    // the SDK is bumped, it round-trips.
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_PATH1_RESPONSE,
            futureField: "added kernel-side without an SDK bump",
            warnings: ["new warning channel"],
          },
        },
      },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect((out as unknown as Record<string, unknown>).futureField).toBe(
      "added kernel-side without an SDK bump",
    );
    expect(
      (out as unknown as Record<string, unknown>).warnings,
    ).toEqual(["new warning channel"]);
  });
});

describe("gate.evaluate — P2 response shape hardening", () => {
  it("P2: throws AttestryError when kernel response is null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected an object response from the kernel \(got null\)/,
    );
  });

  it("P2: throws AttestryError when kernel response is a scalar (string)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: "scalar-instead-of-object" } },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected an object response from the kernel \(got string\)/,
    );
  });

  it("P2: throws AttestryError when kernel response is an array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_PATH1_RESPONSE] } },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected an object response from the kernel \(got array\)/,
    );
  });

  it("P2: throws AttestryError when response.gate is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, gate: true },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected response\.gate to be a string \(got boolean\)/);
  });

  it("P2: throws AttestryError when response.systemId is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, systemId: 42 },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.systemId to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.systemName is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, systemName: null },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.systemName to be a string \(got null\)/,
    );
  });

  it("P2: throws AttestryError when response.score is not number-or-null (string)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, score: "87" },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.score to be a number or null \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.minScore is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, minScore: "70" },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.minScore to be a number \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.frameworks is not an array", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, frameworks: "EU_AI_ACT" },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.frameworks to be an array \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.gaps is not an array", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, gaps: "not-an-array" },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(/expected response\.gaps to be an array \(got string\)/);
  });

  it("P2: throws AttestryError when response.reason is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, reason: 42 },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.reason to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.timestamp is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, timestamp: 12345 },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.timestamp to be a string \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.assessmentId (when own-present) is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, assessmentId: 42 },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.assessmentId to be a string when present \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.assessmentDate (when own-present) is not string-or-null", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, assessmentDate: 1234567890 },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.assessmentDate to be a string or null when present \(got number\)/,
    );
  });

  it("P2: throws AttestryError when response.gapCount (when own-present) is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, gapCount: "0" },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.gapCount to be a number when present \(got string\)/,
    );
  });

  it("P2: throws AttestryError when response.criticalGaps (when own-present) is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, criticalGaps: null },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.criticalGaps to be a number when present \(got null\)/,
    );
  });

  it("P2: throws AttestryError when response.highGaps (when own-present) is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, highGaps: [] },
        },
      },
    ]);
    await expect(
      client.gate.evaluate({ systemId: VALID_UUID }),
    ).rejects.toThrow(
      /expected response\.highGaps to be a number when present \(got array\)/,
    );
  });

  it("P2 absent emit-only field is OK (Path 2 / Path 3 shape — own-property false bypasses validation)", async () => {
    // Symmetric pin: emit-only fields are validated ONLY when
    // own-present. Their ABSENCE is the canonical "no assessment"
    // shape and must NOT trigger a P2 error. If the SDK incorrectly
    // strict-validated emit-only fields, every Path 2 / Path 3
    // response would throw. Pin: a Path 2 wire response WITHOUT
    // any emit-only field round-trips cleanly.
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH2_RESPONSE } },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.gate).toBe("fail");
    expect(Object.hasOwn(out, "assessmentId")).toBe(false);
  });

  it("P2 error is AttestryError (NOT AttestryAPIError) — distinct surface for kernel-shape regressions", async () => {
    // Pin the error CLASS on the P2 path. AttestryAPIError carries
    // an HTTP status; AttestryError does not. A kernel-shape
    // regression isn't an "API error" in the HTTP sense — the
    // server returned 200 with a malformed body.
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    try {
      await client.gate.evaluate({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      expect(err).not.toBeInstanceOf(AttestryAPIError);
    }
  });

  // Per-always-present-field MISSING own-property pins. Exercises the
  // `: undefined` arm of each P2 ternary (`objectHasOwn(obj, "X") ?
  // obj.X : undefined`) — the kernel-regression-drops-field case. The
  // SDK's own-property check returns false → describeType(undefined)
  // → AttestryError with "got undefined" naming the field. Without
  // these pins, the multi-line ternary `: undefined` arms drop branch
  // + line coverage to ~98% (the `: undefined` arms are unhit by
  // tests that mock the field present-but-wrong-type). With them,
  // 100/100/100/100 is maintained.
  //
  // Earlier-in-the-validation-order fields must be PRESENT in the
  // mock so the SDK reaches the field under test before throwing.
  // CRITICAL: `delete data[fieldName]` (not just `data[fieldName] =
  // undefined`) — own-property false is what the test exercises.
  it.each([
    [
      "gate",
      /expected response\.gate to be a string \(got undefined\)/,
    ],
    [
      "systemId",
      /expected response\.systemId to be a string \(got undefined\)/,
    ],
    [
      "systemName",
      /expected response\.systemName to be a string \(got undefined\)/,
    ],
    [
      "score",
      /expected response\.score to be a number or null \(got undefined\)/,
    ],
    [
      "minScore",
      /expected response\.minScore to be a number \(got undefined\)/,
    ],
    [
      "frameworks",
      /expected response\.frameworks to be an array \(got undefined\)/,
    ],
    [
      "gaps",
      /expected response\.gaps to be an array \(got undefined\)/,
    ],
    [
      "reason",
      /expected response\.reason to be a string \(got undefined\)/,
    ],
    [
      "timestamp",
      /expected response\.timestamp to be a string \(got undefined\)/,
    ],
  ] as const)(
    "P2 missing-%s: own-property false → AttestryError naming the field with 'got undefined'",
    async (fieldName, expectedMsg) => {
      const data: Record<string, unknown> = { ...MOCK_PATH1_RESPONSE };
      // CRITICAL: delete (not assignment) so the field is not an own
      // property; the SDK's `objectHasOwn` must return false.
      delete data[fieldName];

      const { client } = makeMockedClient([
        { body: { success: true, data } },
      ]);
      await expect(
        client.gate.evaluate({ systemId: VALID_UUID }),
      ).rejects.toThrow(expectedMsg);
    },
  );
});

describe("gate.evaluate — abort + retry semantics", () => {
  it("forwards a pre-aborted AbortSignal through RequestOptions (no fetch)", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.gate.evaluate(
        { systemId: VALID_UUID },
        { signal: controller.signal },
      ),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    const controller = new AbortController();
    const out = await client.gate.evaluate(
      { systemId: VALID_UUID },
      { signal: controller.signal },
    );
    expect(out.score).toBe(87);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies (independent of resource-helper default)", async () => {
    // Mirror of check.run / regulatoryChanges / compliance-check
    // retry pins. The mocked client sets retry: {maxRetries: 0}; the
    // per-call override re-enables retry for this single call.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "x" } },
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
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
      retry: { maxRetries: 0 },
    });
    const promise = client.gate.evaluate(
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

describe("gate.evaluate — hostile round residual gaps", () => {
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
        return getterCallCount === 1
          ? VALID_UUID
          : "22222222-2222-2222-2222-222222222222";
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate(input);
    expect(calls).toHaveLength(1);
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
    // **Session-16 second-hostile-review MEDIUM #2 carry-forward**:
    // use a STATE-BASED proxy that returns valid values on the first
    // N reads (consumed by Array.from inside the SDK) and EVIL values
    // on read N+1+. If the SDK is correct (uses the snapshot for
    // everything downstream), only the first N reads happen and the
    // wire body has valid values. If the SDK re-reads from the proxy
    // (e.g., a refactor that assigns body.frameworks = frameworksRaw
    // instead of the snapshot), JSON.stringify of the proxy would
    // trigger reads N+1+ and the wire body would carry EVIL values.
    const evilArray = ["EU_AI_ACT", "ISO_42001"];
    let getCallCount = 0;
    const stateFlippingProxy: unknown = new Proxy(evilArray, {
      get(target, prop, receiver) {
        if (typeof prop === "string" && /^\d+$/.test(prop)) {
          getCallCount++;
          const idx = Number(prop);
          if (getCallCount > 2) {
            return "EVIL_FRAMEWORK";
          }
          return target[idx];
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      frameworks: stateFlippingProxy as string[],
    });
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    // The wire body MUST contain the FIRST-pass values (the snapshot).
    // If the SDK re-reads from the proxy, JSON.stringify would trigger
    // reads 3+ via the proxy's `get` trap and the body would carry
    // ["EVIL_FRAMEWORK", ...].
    expect(parsed.frameworks).toEqual(["EU_AI_ACT", "ISO_42001"]);
    // Proof of single-pass: getCallCount === 2 means Array.from read
    // each element ONCE, and no downstream operation re-read the proxy.
    expect(getCallCount).toBe(2);
  });

  it("H3: Object.hasOwn override + Object.prototype.systemId pollution — snapshot defense is what causes rejection (not the secondary undefined-check)", async () => {
    // Hostile concern: a late-loading dep overrides
    // `Object.hasOwn = () => true`. The SDK's module-load snapshot
    // (`const objectHasOwn = Object.hasOwn;`) captured the ORIGINAL
    // implementation, so the override doesn't reach the resource's
    // input checks.
    //
    // **Session-16 second-hostile-review MEDIUM #1 carry-forward**:
    // the COMBINED pollution + override is the only configuration that
    // ACTUALLY exercises the snapshot defense. With only the
    // `Object.hasOwn = () => true` override (no prototype pollution),
    // BOTH with-snapshot AND without-snapshot code paths throw
    // "systemId is required" — the snapshot defense isn't actually
    // exercised because the secondary `systemIdRaw === undefined`
    // check catches the no-own-property case anyway.
    //
    // With combined pollution + override:
    //   - With snapshot: `objectHasOwn(input, "systemId")` uses the
    //     ORIGINAL Object.hasOwn (own-only) → returns false →
    //     `hasSystemId = false` → throws "required". ✅ Correct.
    //   - Without snapshot (hypothetical broken refactor):
    //     `Object.hasOwn(input, "systemId")` is the overridden function
    //     returning true → `hasSystemId = true` → then
    //     `systemIdRaw = input.systemId` reads via prototype chain →
    //     gets the polluted UUID → passes UUID regex → SDK silently
    //     SENDS THE POLLUTED VALUE to the kernel.
    //
    // Pin: SDK throws "required" (the snapshot wins). Mirror of
    // check.run's H3 strengthening.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    const originalHasOwn = Object.hasOwn;
    const originalSystemIdDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "systemId",
    );
    try {
      (Object as { hasOwn: unknown }).hasOwn = () => true;
      (Object.prototype as unknown as Record<string, unknown>).systemId =
        VALID_UUID;
      expect((Object.hasOwn as unknown as () => boolean)()).toBe(true);
      expect(({} as unknown as { systemId: string }).systemId).toBe(
        VALID_UUID,
      );
      expect(() =>
        client.gate.evaluate({} as unknown as GateInput),
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
    expect(calls).toHaveLength(0);
  });

  it("H4: concurrent gate.evaluate() calls share no state — each promise resolves independently", async () => {
    // Pin against a future refactor that adds shared state
    // (memoization, response caching, request batching). Each call
    // must construct its own promise; the mocked fetch routes them to
    // distinct mock responses by call order.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_PATH1_RESPONSE, score: 11 } } },
      { body: { success: true, data: { ...MOCK_PATH1_RESPONSE, score: 22 } } },
      { body: { success: true, data: { ...MOCK_PATH1_RESPONSE, score: 33 } } },
    ]);
    const [out1, out2, out3] = await Promise.all([
      client.gate.evaluate({ systemId: VALID_UUID }),
      client.gate.evaluate({ systemId: VALID_UUID, minScore: 80 }),
      client.gate.evaluate({ systemId: VALID_UUID, failOnMissingAssessment: false }),
    ]);
    expect(calls).toHaveLength(3);
    expect(out1.score).toBe(11);
    expect(out2.score).toBe(22);
    expect(out3.score).toBe(33);
  });

  it("H5: parallel concurrent calls with different field combinations don't cross-pollinate bodies", async () => {
    // Stronger contract than H4: even when issued in tight succession,
    // each call's body lands on its own request. A future refactor
    // that batches POSTs into a single request OR shares a body-
    // builder closure would surface here.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await Promise.all([
      client.gate.evaluate({ systemId: VALID_UUID, minScore: 50 }),
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: ["A", "B"],
        failOnMissingAssessment: false,
      }),
      client.gate.evaluate({ systemId: VALID_UUID }),
    ]);
    expect(calls).toHaveLength(3);
    expect(JSON.parse(calls[0].body!)).toEqual({
      systemId: VALID_UUID,
      minScore: 50,
    });
    expect(JSON.parse(calls[1].body!)).toEqual({
      systemId: VALID_UUID,
      frameworks: ["A", "B"],
      failOnMissingAssessment: false,
    });
    expect(JSON.parse(calls[2].body!)).toEqual({ systemId: VALID_UUID });
  });

  it("H6: 429 auto-retries when retry is enabled (default) and succeeds on second attempt", async () => {
    // Build round only pinned the retry-disabled path. Hostile round
    // adds the retry-enabled path — invariant #18: SDK auto-retries
    // on 429 with exponential backoff. Pin against the retry
    // middleware integration: a 429 → 200 sequence resolves with the
    // 200 body when retry is on. Mirror of check.run / regulatoryChanges
    // / compliance-check retry pins.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "rate limited" } },
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
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
    const promise = client.gate.evaluate({ systemId: VALID_UUID });
    // Advance through the retry backoff — DEFAULT_RETRY_OPTIONS has
    // initialDelayMs 1_000, so 2.5s covers attempt 2.
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
    // but NEVER reads `details` or `fieldErrors`. So whether
    // `details` is present, absent, or a different shape doesn't
    // break the SDK error surface.
    //
    // Carry-forward from check.run's H7 (session-16 first-review
    // MEDIUM #2 + LOW #2): re-framed from "without a fieldErrors
    // body" to "without a `details` array (forward-compat)". Pin
    // retains defensive value — if a future kernel splits Zod-vs-
    // business errors and emits 422 without `details` on the business
    // path, this pin documents that the SDK transport still surfaces
    // it cleanly.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.gate.evaluate({ systemId: VALID_UUID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.message).toBe("Validation failed.");
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
    // {systemId, minScore, frameworks, failOnMissingAssessment,
    // evilExtra: "x"} to the SDK. The body construction in
    // `gate.evaluate` explicitly assembles a new object with ONLY
    // the documented fields — the extra wouldn't propagate to the
    // wire.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate({
      systemId: VALID_UUID,
      minScore: 80,
      frameworks: ["EU_AI_ACT"],
      failOnMissingAssessment: false,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      evilExtra: "should-not-propagate",
      apiKey: "should-not-propagate-either",
    } as unknown as GateInput);
    const parsed = JSON.parse(calls[0].body!);
    // Body contains ONLY the 4 documented fields. The extras are
    // dropped by the SDK's explicit body construction.
    expect(Object.keys(parsed).sort()).toEqual([
      "failOnMissingAssessment",
      "frameworks",
      "minScore",
      "systemId",
    ]);
    expect(Object.hasOwn(parsed, "evilExtra")).toBe(false);
    expect(Object.hasOwn(parsed, "apiKey")).toBe(false);
  });

  it("H9: UUID with leading/trailing whitespace is rejected (regex is anchored)", () => {
    // Hostile concern: a consumer trims user input to a UUID but
    // misses a trailing space. The SDK's UUID regex uses `^...$`
    // anchors, so any surrounding whitespace fails the pre-validation.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: ` ${VALID_UUID}` }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.gate.evaluate({ systemId: `${VALID_UUID} ` }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.gate.evaluate({ systemId: `\t${VALID_UUID}\n` }),
    ).toThrow(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("H10: UUID with prefix/suffix non-hex garbage is rejected (regex anchored)", () => {
    // Hostile concern: a consumer concatenates a UUID with extra
    // bytes (debug prefix, version suffix). The regex anchors reject
    // both forms.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({ systemId: `prefix${VALID_UUID}` }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.gate.evaluate({ systemId: `${VALID_UUID}suffix` }),
    ).toThrow(/must be an RFC 4122/);
    expect(() =>
      client.gate.evaluate({ systemId: `xx${VALID_UUID}yy` }),
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
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: sparseArr,
      }),
    ).toThrow(/`frameworks\[1\]` must be a string \(got undefined\)/);

    const allHoles = new Array(3) as unknown as string[];
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: allHoles,
      }),
    ).toThrow(/`frameworks\[0\]` must be a string \(got undefined\)/);
    expect(calls).toHaveLength(0);
  });

  it("H12: frameworks with non-Array array-like (Set / Map / arguments-object) is rejected", () => {
    // Hostile concern: a consumer passes a Set, Map, or other
    // array-like (NodeList, arguments object) instead of a true
    // Array. `Array.isArray` returns false for ALL of these.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: new Set(["EU_AI_ACT"]) as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: new Map([["a", "b"]]) as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);
    expect(() =>
      client.gate.evaluate({
        systemId: VALID_UUID,
        frameworks: { 0: "EU_AI_ACT", length: 1 } as unknown as string[],
      }),
    ).toThrow(/`frameworks` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("H13: TOCTOU on minScore via input-getter — SDK reads exactly once and validates the snapshot (gate-specific)", async () => {
    // **Gate-specific TOCTOU pin** — the new closed-spec `minScore`
    // field is a number, but the same TOCTOU surface applies: a
    // getter could yield a VALID value (e.g., 70) on the first read
    // and an out-of-range value (e.g., -1 or 101) on subsequent
    // reads. The SDK snapshots `minScoreRaw` exactly once (gate.ts:
    // `const minScoreRaw: unknown = hasMinScore ? input.minScore :
    // undefined`); validation + body construction read the local.
    let getterCallCount = 0;
    const input = { systemId: VALID_UUID } as {
      systemId: string;
      minScore: number;
    };
    Object.defineProperty(input, "minScore", {
      configurable: true,
      enumerable: true,
      get() {
        getterCallCount++;
        // First read: VALID 80. Subsequent reads: out-of-range -1
        // (would fail Zod kernel-side if it reached the wire).
        return getterCallCount === 1 ? 80 : -1;
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH1_RESPONSE } },
    ]);
    await client.gate.evaluate(input);
    expect(calls).toHaveLength(1);
    // The wire body MUST contain the FIRST-read value (80) — proof
    // the SDK validated the snapshot and sent the snapshot.
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.minScore).toBe(80);
    // Confirm the getter was called exactly ONCE.
    expect(getterCallCount).toBe(1);
  });

  it("H14: TOCTOU on failOnMissingAssessment via input-getter — SDK reads exactly once (gate-specific)", async () => {
    // **Gate-specific TOCTOU pin** — boolean field, same defense
    // pattern as H13. A getter could yield `true` on the first read
    // (validation passes Zod boolean check) and a truthy non-boolean
    // like `"yes"` on subsequent reads. Snapshot defense ensures the
    // FIRST-read value lands on the wire.
    let getterCallCount = 0;
    const input = { systemId: VALID_UUID } as {
      systemId: string;
      failOnMissingAssessment: boolean;
    };
    Object.defineProperty(input, "failOnMissingAssessment", {
      configurable: true,
      enumerable: true,
      get() {
        getterCallCount++;
        // First read: VALID `false`. Subsequent reads: non-boolean
        // `"yes"` (would fail Zod kernel-side if it reached the
        // wire).
        return getterCallCount === 1
          ? false
          : ("yes" as unknown as boolean);
      },
    });

    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH3_RESPONSE } },
    ]);
    await client.gate.evaluate(input);
    expect(calls).toHaveLength(1);
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.failOnMissingAssessment).toBe(false);
    expect(getterCallCount).toBe(1);
  });

  it("H15: response with negative / out-of-range score round-trips faithfully in Path 1 (NaN/Infinity unreachable via JSON wire)", async () => {
    // Hostile concern: the SDK's P2 validator
    // (`score !== null && typeof score !== "number"`) accepts ANY
    // number including negatives, out-of-range positives. The kernel
    // emits `score: number | null` in Path 1 (computes via `typeof
    // === "number" ? x : 0`), so non-finite values are unreachable
    // via the JSON wire (`JSON.stringify(NaN)` → "null" → parsed back
    // to `null` which is also valid per the SDK's `number | null`
    // type).
    //
    // Pin documents the reachable edges: a negative score and a
    // large-positive score (both typeof === "number" and parse
    // cleanly). Mirror of check.run's H13.
    const { client: c1, calls: calls1 } = makeMockedClient([
      {
        bodyText: JSON.stringify({
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, score: -1 },
        }),
      },
    ]);
    const r1 = await c1.gate.evaluate({ systemId: VALID_UUID });
    expect(r1.score).toBe(-1);
    expect(calls1).toHaveLength(1);

    const { client: c2 } = makeMockedClient([
      {
        bodyText: JSON.stringify({
          success: true,
          data: { ...MOCK_PATH1_RESPONSE, score: 9999 },
        }),
      },
    ]);
    const r2 = await c2.gate.evaluate({ systemId: VALID_UUID });
    expect(r2.score).toBe(9999);
  });

  it("H16: response with non-GateGap-shaped elements in `gaps` round-trips (SDK validates Array.isArray only)", async () => {
    // The build round's P2 validator checks `Array.isArray(gaps)` but
    // NOT per-element shape (faithful courier — kernel emits
    // structured GateGap rows reliably, but SDK doesn't paranoid-
    // validate per-element). Pin documents: if the kernel ever emits
    // non-GateGap elements, they round-trip to consumers (typed as
    // `GateGap[]` at the call site, but the runtime types are
    // heterogeneous).
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_PATH1_RESPONSE,
            gaps: [
              SAMPLE_GAP,
              42 as unknown as GateGap,
              null as unknown as GateGap,
              { partial: "shape" } as unknown as GateGap,
            ],
          },
        },
      },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.gaps).toEqual([
      SAMPLE_GAP,
      42,
      null,
      { partial: "shape" },
    ] as unknown as GateGap[]);
  });

  it("H17: empty-string assessmentId / timestamp passes through (typeof string — faithful courier)", async () => {
    // typeof "" === "string", so the SDK's P2 validators accept.
    // The kernel will never emit "" (it emits a UUID for assessmentId
    // and an ISO-8601 for timestamp), but the SDK doesn't paranoid-
    // validate. Pin documents the surface — a future SDK hardening
    // could tighten this (e.g., UUID regex on assessmentId, ISO regex
    // on timestamp).
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_PATH1_RESPONSE,
            assessmentId: "",
            timestamp: "",
          },
        },
      },
    ]);
    const out = await client.gate.evaluate({ systemId: VALID_UUID });
    expect(out.assessmentId).toBe("");
    expect(out.timestamp).toBe("");
  });

  it("H18: response-side prototype-pollution defense — kernel-regression-drops-field + Object.prototype.<field>=value cannot mask the regression (symmetric to input-side, mirror of check.run's H16)", async () => {
    // **Carry-forward of session-16 second-hostile-review MEDIUM #3**.
    // The P2 validator reads response fields through the module-load
    // `objectHasOwn` snapshot — `objectHasOwn(obj, "<field>") ?
    // obj.<field> : undefined`. Without this defense (if the SDK
    // used direct property access), a kernel regression that drops a
    // field combined with a hostile npm dep polluting
    // `Object.prototype.<field>` would let the polluted value pass
    // typeof-check via prototype walk and silently reach consumers.
    //
    // With the defense: missing own-property → undefined →
    // describeType(undefined) → AttestryError("got undefined") naming
    // the first dropped field.
    //
    // Pin: pollute Object.prototype with valid-looking values for ALL
    // 9 always-present response fields, mock a kernel response missing
    // ALL of them, and assert the SDK throws on `gate` (the FIRST
    // field checked) with "got undefined".
    //
    // The build round's it.each already covers each field's missing-
    // own-property branch individually; THIS pin is the FULL pollution
    // + full-drop combined-attack scenario (the only configuration
    // that EXERCISES the snapshot defense vs the per-field own-
    // property check).
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            // Missing: all 9 always-present fields — kernel regression
            // case.
          },
        },
      },
    ]);
    const originalDescs = new Map<string, PropertyDescriptor | undefined>();
    const fields = [
      "gate",
      "systemId",
      "systemName",
      "score",
      "minScore",
      "frameworks",
      "gaps",
      "reason",
      "timestamp",
    ] as const;
    try {
      const pollutedValues: Record<(typeof fields)[number], unknown> = {
        gate: "pass",
        systemId: VALID_UUID,
        systemName: "Polluted System",
        score: 99,
        minScore: 70,
        frameworks: [],
        gaps: [],
        reason: "polluted prototype",
        timestamp: "2026-05-11T15:00:00.000Z",
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
      // each is read as undefined; first failure (gate) fires the
      // AttestryError. WITHOUT the defense, all typeof-checks would
      // pass via prototype walk and the SDK would silently return
      // the polluted values.
      await expect(client.gate.evaluate({ systemId: VALID_UUID })).rejects.toThrow(
        /expected response\.gate to be a string \(got undefined\)/,
      );
    } finally {
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

  it("H19: response-side prototype pollution on EMIT-ONLY field — own-property false bypasses validation even with pollution", async () => {
    // **Gate-specific hostile pin** (no check.run equivalent — gate
    // has emit-only fields that check.run doesn't). The SDK's P2
    // validator for emit-only fields (assessmentId, assessmentDate,
    // gapCount, criticalGaps, highGaps) uses `if
    // (objectHasOwn(obj, "X")) { ... }`. The KEY property: the
    // `objectHasOwn` check returns FALSE when the emit-only field is
    // absent from the wire (Paths 2 + 3 case), even when
    // Object.prototype is polluted with that field name. This is the
    // CORRECT shape — no error fires; the emit-only field is simply
    // not present on the response object.
    //
    // Pin: pollute Object.prototype.assessmentId with a valid UUID
    // string. Mock a Path-2 wire response (no own assessmentId).
    // SDK must NOT throw a P2 error (own-property check returns
    // false → if-block skipped → no validation runs). Consumer sees
    // the Path-2 response normally; they can detect the no-assessment
    // branch via `score === null`.
    //
    // **Defense mechanism exercised**: this is the symmetric pin to
    // H18 — emit-only fields validated only when own-present means
    // pollution can't INJECT a fake assessmentId into Path-2/3
    // responses (own-property false → field is undefined on the
    // response object, NOT the polluted value).
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PATH2_RESPONSE } },
    ]);
    const originalDesc = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "assessmentId",
    );
    try {
      (Object.prototype as unknown as Record<string, unknown>).assessmentId =
        "ffffffff-ffff-ffff-ffff-ffffffffffff";
      const out = await client.gate.evaluate({ systemId: VALID_UUID });
      // No error fires — emit-only field's own-property check returned
      // false; if-block skipped.
      expect(out.gate).toBe("fail");
      // CRITICAL: the response object does NOT have assessmentId as
      // an own property, even though Object.prototype was polluted.
      // The consumer's `Object.hasOwn(out, "assessmentId")` returns
      // false — proof the SDK didn't synthesize the polluted value.
      expect(Object.hasOwn(out, "assessmentId")).toBe(false);
      // The prototype-walked `in` check still finds the pollution —
      // this is a JS-engine fact, NOT an SDK gap. The defense is
      // that the SDK respected own-property semantics; consumers'
      // own-property checks see the correct "no own assessmentId"
      // truth.
    } finally {
      if (originalDesc) {
        Object.defineProperty(Object.prototype, "assessmentId", originalDesc);
      } else {
        delete (Object.prototype as unknown as Record<string, unknown>)
          .assessmentId;
      }
    }
    expect(calls).toHaveLength(1);
  });
});
