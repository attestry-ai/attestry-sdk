import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  DecisionIngestInput,
  DecisionRecord,
  // Sub-shape type imports — pinned at compile time. If any of these
  // is dropped from `index.ts` or the resource's exports, this file
  // fails to compile and the test run aborts before any pin runs.
  FrameworkClaim,
  ToolInvocation,
  DelegationEntry,
  ZkProof,
} from "../decisions.js";
import type { FetchLike } from "../../types.js";

// ─── decisions.ingest — POST with deep input validation ──────────────────────
//
// Wire shape (from src/lib/validation/decision-schemas.ts decisionCreateSchema
// and src/app/api/v1/decisions/route.ts POST handler):
//   POST /api/v1/decisions
//   Headers: x-api-key, Content-Type: application/json, Accept: application/json
//   Body: DecisionIngestInput (mirrors decisionCreateSchema field-for-field)
//   → 201 Created (fresh insert) OR 200 OK (idempotent replay)
//   → { success: true, data: <DecisionRecord without canonicalPayload> }
//
// Status-code distinction (200 vs 201) is internal to the kernel — the SDK
// surfaces both as `Promise<DecisionRecord>` (build-round D3). Idempotent
// replay returns the prior record; conflict (same key, different body)
// throws AttestryAPIError(409).
//
// First SDK encounter with HTTP 402 (PaymentRequired) — plan-limit signal
// with structured `details.feature` / `details.currentPlan` /
// `details.upgradeRequired` body. B.1 carry-forward.

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

const SYSTEM_ID = "33333333-3333-3333-3333-333333333333";
const INPUT_DIGEST =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const OUTPUT_DIGEST =
  "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const RECORD_HASH =
  "sha256:abababababababababababababababababababababababababababababababab";

const MIN_INPUT: DecisionIngestInput = {
  systemId: SYSTEM_ID,
  inputDigest: INPUT_DIGEST,
};

const FULL_INPUT: DecisionIngestInput = {
  systemId: SYSTEM_ID,
  inputDigest: INPUT_DIGEST,
  outputDigest: OUTPUT_DIGEST,
  attestationId: "44444444-4444-4444-4444-444444444444",
  frameworkClaims: [
    {
      framework: "eu_ai_act",
      article: "Art.13",
      claim: "human oversight provided",
    },
  ],
  toolInvocations: [
    {
      name: "vector-store-query",
      inputHash: INPUT_DIGEST,
      outputHash: OUTPUT_DIGEST,
    },
  ],
  delegationChain: [
    {
      agentId: "agent-007",
      delegationToken: "opaque-token-data",
    },
  ],
  humanOversightState: "approved",
  policyOutcome: "permitted",
  clientSignature: "MEUCIQDx...base64...AgMA==",
  clientKeyId: "key-2026-q2",
  idempotencyKey: "ingest-2026-05-06-trace-789",
  zkProof: {
    type: "groth16",
    proof: "0x" + "a".repeat(200),
    publicSignals: ["sig-1", "sig-2"],
  },
};

const MOCK_RECORD: DecisionRecord = {
  id: "11111111-1111-1111-1111-111111111111",
  orgId: "22222222-2222-2222-2222-222222222222",
  systemId: SYSTEM_ID,
  manifestVersionId: "55555555-5555-5555-5555-555555555555",
  attestationId: null,
  sequenceNumber: 1,
  inputDigest: INPUT_DIGEST,
  outputDigest: null,
  frameworkClaims: [],
  toolInvocations: [],
  delegationChain: [],
  humanOversightState: null,
  policyOutcome: null,
  prevRecordHash: null,
  recordHash: RECORD_HASH,
  clientSignature: null,
  clientKeyId: null,
  idempotencyKey: null,
  zkProof: null,
  tombstoned: false,
  tombstonedAt: null,
  tombstonedReason: null,
  createdAt: "2026-05-06T00:00:00.000Z",
};

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("decisions.ingest — happy path", () => {
  it("POSTs /api/v1/decisions with the minimal input body", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const out = await client.decisions.ingest(MIN_INPUT);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions",
    );
    // Body is serialized JSON of the input.
    expect(JSON.parse(calls[0].body!)).toEqual(MIN_INPUT);
    // Transport unwraps the {success:true, data} envelope — bare record.
    expect(out).toEqual(MOCK_RECORD);
  });

  it("returns the DecisionRecord shape unchanged (envelope unwrapped, 201 fresh insert)", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const out = await client.decisions.ingest(MIN_INPUT);
    // Every documented field on the record reaches the consumer.
    expect(out.id).toBe(MOCK_RECORD.id);
    expect(out.orgId).toBe(MOCK_RECORD.orgId);
    expect(out.systemId).toBe(MOCK_RECORD.systemId);
    expect(out.sequenceNumber).toBe(MOCK_RECORD.sequenceNumber);
    expect(out.inputDigest).toBe(MOCK_RECORD.inputDigest);
    expect(out.recordHash).toBe(MOCK_RECORD.recordHash);
    expect(out.tombstoned).toBe(false);
    expect(out.createdAt).toBe(MOCK_RECORD.createdAt);
  });

  it("forwards x-api-key + Accept + Content-Type headers (POST with body)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.ingest(MIN_INPUT);
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    // Content-Type IS set on POST (transport adds it whenever a body
    // is present). Symmetric to `incidents.create` POST tests.
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("includes every documented optional field in the body when provided", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.ingest(FULL_INPUT);
    const sent = JSON.parse(calls[0].body!);
    expect(sent.systemId).toBe(FULL_INPUT.systemId);
    expect(sent.inputDigest).toBe(FULL_INPUT.inputDigest);
    expect(sent.outputDigest).toBe(FULL_INPUT.outputDigest);
    expect(sent.attestationId).toBe(FULL_INPUT.attestationId);
    expect(sent.frameworkClaims).toEqual(FULL_INPUT.frameworkClaims);
    expect(sent.toolInvocations).toEqual(FULL_INPUT.toolInvocations);
    expect(sent.delegationChain).toEqual(FULL_INPUT.delegationChain);
    expect(sent.humanOversightState).toBe(FULL_INPUT.humanOversightState);
    expect(sent.policyOutcome).toBe(FULL_INPUT.policyOutcome);
    expect(sent.clientSignature).toBe(FULL_INPUT.clientSignature);
    expect(sent.clientKeyId).toBe(FULL_INPUT.clientKeyId);
    expect(sent.idempotencyKey).toBe(FULL_INPUT.idempotencyKey);
    expect(sent.zkProof).toEqual(FULL_INPUT.zkProof);
  });

  it("does NOT add a query string to the URL (POST takes body, not query)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.ingest(FULL_INPUT);
    const url = new URL(calls[0].url);
    expect([...url.searchParams.keys()]).toEqual([]);
  });

  it("200 idempotent replay returns the same record shape (no SDK-visible distinction from 201)", async () => {
    // Build-round D3: the kernel returns 200 on idempotent replay vs 201
    // on fresh insert, but the SDK does NOT surface that distinction in
    // its return type — both 2xx resolve the same Promise<DecisionRecord>.
    // Pin: a 200 mock yields the same record without throwing.
    const replayRecord: DecisionRecord = {
      ...MOCK_RECORD,
      idempotencyKey: "ingest-2026-05-06-trace-789",
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: replayRecord } },
    ]);
    const out = await client.decisions.ingest({
      ...MIN_INPUT,
      idempotencyKey: "ingest-2026-05-06-trace-789",
    });
    expect(out).toEqual(replayRecord);
    expect(out.idempotencyKey).toBe("ingest-2026-05-06-trace-789");
  });

  it("returns the FULL DecisionRecord including every nullable field set to null", async () => {
    // Pin: when the server returns null for outputDigest / attestationId /
    // humanOversightState etc., the SDK preserves the literal null (not
    // undefined). Important for downstream JSON-stringify round-trips.
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const out = await client.decisions.ingest(MIN_INPUT);
    expect(out.outputDigest).toBeNull();
    expect(out.attestationId).toBeNull();
    expect(out.humanOversightState).toBeNull();
    expect(out.policyOutcome).toBeNull();
    expect(out.prevRecordHash).toBeNull();
    expect(out.clientSignature).toBeNull();
    expect(out.clientKeyId).toBeNull();
    expect(out.idempotencyKey).toBeNull();
    expect(out.zkProof).toBeNull();
    expect(out.tombstonedAt).toBeNull();
    expect(out.tombstonedReason).toBeNull();
  });
});

// ─── Input validation (pre-fetch — synchronous TypeError, no fetch issued) ──

describe("decisions.ingest — input validation (pre-fetch)", () => {
  it("throws TypeError for a non-object input (null, array, string, number)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest(null as unknown as DecisionIngestInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest([] as unknown as DecisionIngestInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest("input" as unknown as DecisionIngestInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest(42 as unknown as DecisionIngestInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest(undefined as unknown as DecisionIngestInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty systemId — does NOT issue a request", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({ ...MIN_INPUT, systemId: "" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId (null, number, undefined)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        systemId: null as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        systemId: 42 as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        systemId: undefined as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty inputDigest", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({ ...MIN_INPUT, inputDigest: "" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string inputDigest", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        inputDigest: 0 as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        inputDigest: null as unknown as string,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty optional string fields when provided", async () => {
    // Each of the seven optional string fields rejects empty when
    // explicitly provided. Same convention as decisions.list.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({ ...MIN_INPUT, outputDigest: "" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({ ...MIN_INPUT, attestationId: "" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        humanOversightState: "" as unknown as "approved",
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        policyOutcome: "" as unknown as "permitted",
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({ ...MIN_INPUT, clientSignature: "" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({ ...MIN_INPUT, clientKeyId: "" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({ ...MIN_INPUT, idempotencyKey: "" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-array nested fields (frameworkClaims / toolInvocations / delegationChain)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: "string" as unknown as never,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        toolInvocations: {} as unknown as never,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        delegationChain: 42 as unknown as never,
      }),
    ).toThrowError(TypeError);
    // null is NOT an array (Array.isArray(null) === false).
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: null as unknown as never,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("accepts empty arrays for nested fields (passes through faithfully)", async () => {
    // Build-round hostile #6: empty arrays match the server's `.default([])`
    // semantics — same persisted result. Pin: the body carries the
    // empty arrays verbatim (server doesn't see them as undefined).
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.ingest({
      ...MIN_INPUT,
      frameworkClaims: [],
      toolInvocations: [],
      delegationChain: [],
    });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.frameworkClaims).toEqual([]);
    expect(sent.toolInvocations).toEqual([]);
    expect(sent.delegationChain).toEqual([]);
  });

  it("throws TypeError for non-object zkProof (null, array, string)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        zkProof: null as unknown as never,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        zkProof: [] as unknown as never,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        zkProof: "proof-string" as unknown as never,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("does NOT pre-validate format — server validates UUIDs / hash regex / enum membership", async () => {
    // Build-round D5: the SDK enforces TYPES only, not formats. A
    // non-UUID systemId is forwarded; the server returns 422. Pin:
    // the request reaches the server, doesn't throw at the SDK boundary.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [{ path: "systemId", message: "Invalid uuid" }],
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        systemId: "not-a-uuid",
      });
    } catch {
      /* ignore — verifying the request was issued */
    }
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).systemId).toBe("not-a-uuid");
  });

  it("does NOT pre-validate inner array shape — server's .strict() is the authority", async () => {
    // Hostile-table #5 + handoff: the SDK forwards nested arrays
    // faithfully, even when the items are obviously malformed. The
    // server's Zod `.strict()` rejects bad inner shapes with 422.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: [
          { wrongField: "missing required keys" } as unknown as never,
        ],
      });
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).frameworkClaims).toEqual([
      { wrongField: "missing required keys" },
    ]);
  });

  it("error message names the offending field for input-validation failures", async () => {
    // Build-round defensive — the TypeError tells the consumer WHICH
    // field was invalid (not just "validation failed" for one of N
    // optional fields). Pin a sample of fields.
    const { client } = makeMockedClient([]);
    try {
      client.decisions.ingest({ ...MIN_INPUT, outputDigest: "" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toContain("outputDigest");
      expect((err as TypeError).message).toContain("decisions.ingest");
    }
    try {
      client.decisions.ingest({
        ...MIN_INPUT,
        toolInvocations: "string" as unknown as never,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toContain("toolInvocations");
      expect((err as TypeError).message).toContain("decisions.ingest");
    }
  });
});

// ─── Error paths ─────────────────────────────────────────────────────────────

describe("decisions.ingest — error paths", () => {
  it("surfaces a 401 (auth required) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required." },
      },
    ]);
    try {
      await client.decisions.ingest(MIN_INPUT);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 402 (PlanLimitError) with structured details preserved (B.1 carry-forward)", async () => {
    // First SDK encounter with HTTP 402. The kernel route includes a
    // structured body with `feature` / `currentPlan` / `upgradeRequired`
    // so dashboards can route the user straight to the upgrade flow.
    // Pin: the SDK preserves these fields via AttestryAPIError.details.
    const { client } = makeMockedClient([
      {
        status: 402,
        body: {
          success: false,
          error:
            "You have reached your decisions limit on the free plan. Used: 100/100. Please upgrade to continue.",
          details: {
            feature: "decisions",
            currentPlan: "free",
            upgradeRequired: true,
          },
        },
      },
    ]);
    try {
      await client.decisions.ingest(MIN_INPUT);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(402);
      expect(apiErr.message).toMatch(/decisions limit/);
      // Structured details preserved — this is what dashboards consume
      // to render the upgrade CTA.
      expect(apiErr.details).toMatchObject({
        details: {
          feature: "decisions",
          currentPlan: "free",
          upgradeRequired: true,
        },
      });
    }
  });

  it("surfaces a 404 (system or cross-org attestation not found) as AttestryAPIError", async () => {
    // The kernel collapses system-not-found AND cross-org-attestation
    // into the same 404 to prevent enumeration. SDK forwards faithfully.
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "System not found" },
      },
    ]);
    try {
      await client.decisions.ingest(MIN_INPUT);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.message).toBe("System not found");
    }
  });

  it("surfaces a 409 (idempotency conflict) with the kernel's exact message", async () => {
    // ERROR_MESSAGES.md `decision.idempotency_conflict` — verbatim
    // string. SDK passes it through.
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: "Idempotency key already used with different payload",
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        idempotencyKey: "key-already-used",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(409);
      expect(apiErr.message).toBe(
        "Idempotency key already used with different payload",
      );
    }
  });

  it("surfaces a 413 (PayloadTooLarge) with the kernel's exact 256KB message", async () => {
    // ERROR_MESSAGES.md `decision.payload_too_large` — verbatim.
    const { client } = makeMockedClient([
      {
        status: 413,
        body: {
          success: false,
          error: "Decision payload exceeds maximum size of 256KB",
        },
      },
    ]);
    try {
      await client.decisions.ingest(MIN_INPUT);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(413);
      expect(apiErr.message).toBe(
        "Decision payload exceeds maximum size of 256KB",
      );
    }
  });

  it("surfaces a 422 (BodyParseError / Zod field errors) with details preserved", async () => {
    // BodyParseError flow: kernel's parseBody throws with `fieldErrors`,
    // route maps to errorResponse(message, 422, error.fieldErrors).
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            {
              path: "inputDigest",
              message:
                "Invalid input digest format. Must match pattern sha256:[a-f0-9]{64}",
            },
          ],
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        inputDigest: "wrong-format-but-non-empty",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.details).toMatchObject({
        details: [{ path: "inputDigest" }],
      });
    }
  });

  it("surfaces a 422 (IJsonError) with details.path naming the offending field", async () => {
    // IJsonError fires when canonical-payload computation hits NaN /
    // Infinity / BigInt / undefined / Symbol. The route maps it to 422
    // with details:{path}. Pin: SDK preserves the path so consumers can
    // pinpoint which field violated I-JSON.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error:
            "Input contains non-I-JSON values (NaN, Infinity, BigInt, undefined, or Symbol)",
          details: { path: "frameworkClaims[0].claim" },
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: [
          {
            framework: "x",
            article: "y",
            // NaN passes JSON.stringify (becomes null), so it reaches
            // the kernel; the canonicalize step then rejects it.
            claim: NaN as unknown as string,
          },
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.details).toMatchObject({
        details: { path: "frameworkClaims[0].claim" },
      });
    }
  });

  it("surfaces a 422 (refine clause — clientSignature without clientKeyId) as AttestryAPIError", async () => {
    // Build-round D4: SDK does NOT pre-validate the pairing rule;
    // server's `.refine()` enforces it. Pin: a violating input reaches
    // the server, which 422s.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error:
            "clientSignature and clientKeyId must both be provided or both omitted",
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        clientSignature: "MEUCIQ...",
        // clientKeyId deliberately omitted
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.message).toMatch(/clientSignature.*clientKeyId/);
    }
    // The request DID reach the server (SDK didn't intercept).
    expect(calls).toHaveLength(1);
  });

  it("surfaces a 500 (ChainHeadMissingError) as AttestryAPIError", async () => {
    // Internal invariant violation — should never fire in practice.
    // Pin so a future kernel change that surfaces this status doesn't
    // mask it as a generic 500.
    const { client } = makeMockedClient([
      {
        status: 500,
        body: {
          success: false,
          error: "Internal error: chain head row missing after lazy init",
        },
      },
    ]);
    try {
      await client.decisions.ingest(MIN_INPUT);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.message).toMatch(/chain head/);
    }
  });

  it("surfaces a 429 (rate limit) as AttestryAPIError when retry is disabled", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: {
          success: false,
          error: "Too many requests. Please try again later.",
        },
      },
    ]);
    try {
      await client.decisions.ingest(MIN_INPUT);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });
});

// ─── Body serialization (transport-level pin via this resource) ─────────────

describe("decisions.ingest — body serialization", () => {
  it("BigInt inside an inner array item throws AttestryError BEFORE fetch (carry-forward invariant #4)", async () => {
    // BigInt at the top level of a known-string field would be caught
    // by SDK validation (TypeError, no fetch) — invariant. But inner
    // array items are NOT validated by the SDK (build-round D5 — kernel
    // .strict() is the schema authority; SDK forwards faithfully).
    // So a BigInt buried inside a frameworkClaims item slips past the
    // SDK type checks, hits transport's body-serialize step, and
    // JSON.stringify throws TypeError "Do not know how to serialize a
    // BigInt". Transport wraps that as AttestryError("invalid request
    // body: ..."). Pin: the request never reaches the mock (calls=0)
    // and the error class is AttestryError, not AttestryAPIError.
    const { client, calls } = makeMockedClient([]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: [
          {
            framework: "x",
            article: "y",
            claim: 42n as unknown as string,
          },
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      expect((err as AttestryError).message).toMatch(/invalid request body/);
      // BigInt-specific inner message — verifies the cause was the JSON
      // stringify failure, not something else.
      expect((err as AttestryError).message).toMatch(/BigInt/i);
    }
    expect(calls).toHaveLength(0);
  });

  it("circular reference in input throws AttestryError BEFORE fetch", async () => {
    // Node's JSON.stringify throws TypeError on circular refs. Carry-
    // forward: transport surfaces this as AttestryError pre-network.
    const { client, calls } = makeMockedClient([]);
    const circular: Record<string, unknown> = { ...MIN_INPUT };
    circular.zkProof = { type: "x", proof: "y", publicSignals: [] };
    (circular.zkProof as { self?: unknown }).self = circular;
    try {
      await client.decisions.ingest(circular as DecisionIngestInput);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      expect((err as AttestryError).message).toMatch(/invalid request body/);
    }
    expect(calls).toHaveLength(0);
  });

  it("NaN passes JSON.stringify (serializes to null), reaches the server", async () => {
    // Asymmetric to BigInt: JSON.stringify({a: NaN}) returns '{"a":null}'.
    // The SDK's typeof guard does NOT catch NaN (typeof NaN === 'number',
    // and the field's TS type guides developers away). The server's
    // canonicalize step is what rejects it via IJsonError. Pin: the
    // SDK forwards faithfully (no client-side guard against numbers
    // landing in optional string-typed payloads — TypeScript catches
    // those at compile time).
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Input contains non-I-JSON values",
          details: { path: "frameworkClaims[0].claim" },
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: [
          {
            framework: "x",
            article: "y",
            claim: NaN as unknown as string,
          },
        ],
      });
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    // NaN serialized as null on the wire. (Server's canonical-bytes
    // step is where it gets rejected.)
    const sent = JSON.parse(calls[0].body!);
    expect(sent.frameworkClaims[0].claim).toBeNull();
  });
});

// ─── Abort + retry semantics ────────────────────────────────────────────────

describe("decisions.ingest — abort + retry semantics", () => {
  it("forwards a pre-aborted AbortSignal: AttestryError synchronous, no fetch", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.decisions.ingest(MIN_INPUT, { signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally (coverage)", async () => {
    // Symmetric to decisions.list / retrieve coverage pin — exercises
    // the resource branch where a live signal is forwarded but never
    // fires. Confirms the transport's signal cleanup path.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const controller = new AbortController();
    const out = await client.decisions.ingest(MIN_INPUT, {
      signal: controller.signal,
    });
    expect(out).toEqual(MOCK_RECORD);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies to ingest — 429 retried, body re-stringified each attempt", async () => {
    // Retry middleware composes with new resources. POST is retried on
    // 429 only (carry-forward #18); the body is re-serialized per
    // attempt (no shared mutable buffer). Pin both the count and the
    // identical-body invariant.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "Too many requests." } },
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ];
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
    const promise = client.decisions.ingest(MIN_INPUT, {
      retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 },
    });
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out).toEqual(MOCK_RECORD);
    expect(calls).toHaveLength(2);
    // Body re-stringified per attempt; both attempts carry the same
    // payload (no mutation, no concatenation, no leakage).
    expect(calls[0].body).toBe(calls[1].body);
    expect(JSON.parse(calls[0].body!)).toEqual(MIN_INPUT);
    vi.useRealTimers();
  });
});

// ─── Idempotency replay ─────────────────────────────────────────────────────

describe("decisions.ingest — idempotency replay", () => {
  it("two sequential calls with the same idempotencyKey both resolve to the same record (server dedupes)", async () => {
    // Server-side dedupe: the kernel re-reads the prior row when the
    // idempotency-unique-violation fires (or finds it via the in-tx
    // pre-check). Both calls receive the SAME record. SDK forwards.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
      { status: 200, body: { success: true, data: MOCK_RECORD } },
    ]);
    const inputWithKey: DecisionIngestInput = {
      ...MIN_INPUT,
      idempotencyKey: "ingest-trace-001",
    };
    const a = await client.decisions.ingest(inputWithKey);
    const b = await client.decisions.ingest(inputWithKey);
    expect(a.id).toBe(b.id);
    expect(a.recordHash).toBe(b.recordHash);
    expect(a.sequenceNumber).toBe(b.sequenceNumber);
    expect(calls).toHaveLength(2);
  });

  it("different body with the SAME idempotencyKey → 409 IdempotencyConflictError", async () => {
    // The server compares canonical bytes, not the raw input. Different
    // body → conflict. Pin: SDK surfaces the verbatim 409 message.
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: "Idempotency key already used with different payload",
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        outputDigest: OUTPUT_DIGEST,
        idempotencyKey: "ingest-trace-001",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(409);
      expect(apiErr.message).toBe(
        "Idempotency key already used with different payload",
      );
    }
  });

  it("idempotencyKey with URL-unsafe characters is sent verbatim in the BODY (no encoding)", async () => {
    // Hostile-table #23: idempotencyKey lives in the BODY, not the URL.
    // No encoding applied or needed. Pin: the literal string lands in
    // the JSON body unchanged.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const wildKey = "key/with#special?chars=&plus more";
    await client.decisions.ingest({
      ...MIN_INPUT,
      idempotencyKey: wildKey,
    });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.idempotencyKey).toBe(wildKey);
    // URL has no idempotencyKey query param.
    const url = new URL(calls[0].url);
    expect(url.searchParams.has("idempotencyKey")).toBe(false);
  });
});

// ─── Hostile-round defenses anticipated up front ────────────────────────────

describe("decisions.ingest — hostile-round defenses", () => {
  it("H1: large zkProof.proof (100KB) flows through; server enforces the cap", async () => {
    // Hostile-table #19: the kernel caps zkProof.proof at 100_000 chars
    // server-side. SDK forwards faithfully — no length cap. A 100KB
    // proof is a real Groth16/PLONK/STARK ceiling, not a synthetic case.
    // Pin: the proof reaches the server intact.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const bigProof = "a".repeat(99_000);
    await client.decisions.ingest({
      ...MIN_INPUT,
      zkProof: {
        type: "stark",
        proof: bigProof,
        publicSignals: [],
      },
    });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.zkProof.proof).toBe(bigProof);
    expect(sent.zkProof.proof.length).toBe(99_000);
  });

  it("H2: zkProof.proof above 100KB is forwarded; server returns 422", async () => {
    // Symmetric H1 — past the cap. The kernel's z.string().max(100_000)
    // rejects with 422. Pin: SDK passes through; AttestryAPIError(422).
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        zkProof: {
          type: "stark",
          proof: "a".repeat(100_001),
          publicSignals: [],
        },
      });
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    const sent = JSON.parse(calls[0].body!);
    expect(sent.zkProof.proof.length).toBe(100_001);
  });

  it("H3: nested array at the cap (50 frameworkClaims) flows through", async () => {
    // Pin: 50-item arrays (the kernel's max) pass through without
    // truncation. Catches a future "be helpful" SDK refactor that adds
    // an array-length cap and silently drops items.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const claims = Array.from({ length: 50 }, (_, i) => ({
      framework: "eu_ai_act",
      article: `Art.${i}`,
      claim: `claim-${i}`,
    }));
    await client.decisions.ingest({
      ...MIN_INPUT,
      frameworkClaims: claims,
    });
    expect(JSON.parse(calls[0].body!).frameworkClaims).toHaveLength(50);
  });

  it("H4: extra unknown keys at top level are forwarded (server's .strict() rejects with 422)", async () => {
    // Build-round D5: SDK does NOT pre-strip unknown keys — the kernel's
    // .strict() Zod schema rejects them with 422 (load-bearing for hash
    // chain non-malleability). Pin: SDK forwards the unknown key
    // faithfully so the server has the full payload to reject. A
    // would-be helpful client-side strip would mask malformed inputs
    // and produce inconsistent error surfaces.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [{ path: "extraneousField", message: "Unrecognized key(s)" }],
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        extraneousField: "should be rejected by .strict()",
      } as unknown as DecisionIngestInput);
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).extraneousField).toBe(
      "should be rejected by .strict()",
    );
  });

  it("H5: empty input object — required-field check fires before any fetch", async () => {
    // Boundary: even a totally-empty object {} fails synchronously
    // (systemId check). Verifies the precedence: object-shape check
    // passes, but the systemId required-field check throws BEFORE we
    // touch the network.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({} as unknown as DecisionIngestInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("H6: input is the same object as a referenced sub-shape (pure forward, no SDK clone)", async () => {
    // Pin: the SDK does NOT clone the caller's input. The body sent
    // to the server is JSON.stringify(input) — direct serialization.
    // Mutation after the call CAN race against ongoing fetch but
    // post-await mutation is fine. This pin is mostly insurance for
    // a future "let me normalize fields first" refactor that would
    // alter the contract.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const claim: { framework: string; article: string; claim: string } = {
      framework: "eu_ai_act",
      article: "Art.13",
      claim: "x",
    };
    await client.decisions.ingest({
      ...MIN_INPUT,
      frameworkClaims: [claim],
    });
    // Body reflects the claim AS PROVIDED, byte-for-byte.
    expect(JSON.parse(calls[0].body!).frameworkClaims).toEqual([claim]);
  });
});

// ─── Hostile-round defenses (genuine gaps from build) ──────────────────────

describe("decisions.ingest — hostile round (genuine gaps)", () => {
  it("H7: whitespace-only systemId passes SDK length-check, server 422s on UUID format", async () => {
    // The SDK's `length === 0` guard does NOT consider whitespace —
    // `"   "` has length 3. So it passes the SDK type check, reaches
    // the server, where `z.string().uuid()` rejects. Pin the SDK
    // forwarding behavior so a future "be helpful" trim() refactor
    // doesn't quietly break callers who use whitespace-tagged ids.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.decisions.ingest({ ...MIN_INPUT, systemId: "   " });
    } catch {
      /* ignore — verifying the request was issued */
    }
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).systemId).toBe("   ");
  });

  it("H8: idempotencyKey at the 1-char minimum is forwarded faithfully", async () => {
    // Server's z.string().min(1).max(200). Pin the lower boundary so
    // a degenerate 1-char key (e.g., "x" — valid) reaches the server.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.ingest({ ...MIN_INPUT, idempotencyKey: "x" });
    expect(JSON.parse(calls[0].body!).idempotencyKey).toBe("x");
  });

  it("H8 (cont.): idempotencyKey at the 200-char maximum is forwarded faithfully", async () => {
    // Pin the upper boundary — 200 chars exactly. The SDK has no
    // length cap of its own, so the kernel's max(200) is the
    // authority. A 200-char key passes; 201 server-422s.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const key200 = "k".repeat(200);
    await client.decisions.ingest({ ...MIN_INPUT, idempotencyKey: key200 });
    expect(JSON.parse(calls[0].body!).idempotencyKey).toBe(key200);
    expect(JSON.parse(calls[0].body!).idempotencyKey.length).toBe(200);
  });

  it("H9: frameworkClaims with 51 items (over the cap of 50) is forwarded; server 422s", async () => {
    // Hostile-symmetric to H3 (50 items at the cap). The SDK has no
    // length cap on the array; the kernel's max(50) Zod is the
    // schema authority. Pin the SDK's forwarding behavior so a
    // future "be defensive" SDK refactor doesn't silently truncate.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    const claims = Array.from({ length: 51 }, (_, i) => ({
      framework: "eu_ai_act",
      article: `Art.${i}`,
      claim: `claim-${i}`,
    }));
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: claims,
      });
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).frameworkClaims).toHaveLength(51);
  });

  it("H10: frozen input passes through unchanged (SDK reads, never mutates)", async () => {
    // Caller might `Object.freeze(input)` to assert immutability.
    // SDK code only reads input fields — no assignment, no
    // mutation. Pin: a frozen input flows through to the server
    // intact; no error is thrown by the validation path.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const frozen = Object.freeze({
      ...FULL_INPUT,
      frameworkClaims: Object.freeze([
        Object.freeze({
          framework: "eu_ai_act",
          article: "Art.13",
          claim: "x",
        }),
      ]) as readonly { framework: string; article: string; claim: string }[],
    });
    await client.decisions.ingest(frozen as DecisionIngestInput);
    expect(calls).toHaveLength(1);
    const sent = JSON.parse(calls[0].body!);
    expect(sent.frameworkClaims[0].framework).toBe("eu_ai_act");
  });

  it("H11: inherited (prototype-chain) properties are NOT serialized into the wire body", async () => {
    // Adversarial: a caller constructs the input via `Object.create`
    // with a polluted prototype carrying extra fields. JSON.stringify
    // only serializes the object's OWN enumerable properties — not
    // properties inherited via the prototype chain. Pin: properties
    // on `evilProto` do NOT leak through to the body.
    //
    // Note: using `Object.defineProperty(obj, "__proto__", {value,
    // enumerable: true})` would create an OWN enumerable key called
    // "__proto__" — which JSON.stringify DOES serialize, but that's
    // just an unknown key (server rejects via .strict() as a 422
    // refuse, equivalent to H4). The genuine pollution surface is
    // prototype-chain inheritance, exercised below.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const evilProto = { evilField: "polluted-via-prototype" };
    const polluted = Object.assign(
      Object.create(evilProto),
      MIN_INPUT,
    );
    await client.decisions.ingest(polluted);
    expect(calls).toHaveLength(1);
    expect(calls[0].body).not.toContain("evilField");
    expect(calls[0].body).not.toContain("polluted-via-prototype");
    // Confirm the OWN keys did serialize correctly.
    expect(JSON.parse(calls[0].body!).systemId).toBe(MIN_INPUT.systemId);
  });

  it("H12: 422 IJsonError verbatim catalog message is preserved end-to-end", async () => {
    // ERROR_MESSAGES.md `decision.ijson_validation_failed` ships this
    // exact string. Build round pinned the 422 status + details.path
    // shape; this round pins the verbatim message so a future kernel
    // catalog edit (or an SDK transport regression that rewraps the
    // message) is caught.
    const verbatim =
      "Input contains non-I-JSON values (NaN, Infinity, BigInt, undefined, or Symbol)";
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: verbatim,
          details: { path: "frameworkClaims[0].claim" },
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: [
          { framework: "x", article: "y", claim: NaN as unknown as string },
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).message).toBe(verbatim);
    }
  });

  it("H13: 422 decision.invalid_input_digest verbatim catalog message is preserved", async () => {
    // ERROR_MESSAGES.md `decision.invalid_input_digest` — the kernel's
    // Zod schema embeds the exact string in its regex error. Pin the
    // verbatim catalog string preservation through the SDK error path.
    const verbatim =
      "Invalid input digest format. Must match pattern sha256:[a-f0-9]{64}";
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [{ path: "inputDigest", message: verbatim }],
        },
      },
    ]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        inputDigest: "wrong-format-still-non-empty",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      // Top-level message is the route's "Validation failed." wrapper.
      // Verbatim catalog string lives in details.
      expect(apiErr.details).toMatchObject({
        details: [{ message: verbatim }],
      });
    }
  });

  it("H14: BigInt body-serialize failure preserves the original TypeError as `cause`", async () => {
    // Build round pinned the AttestryError class + the "invalid
    // request body" message + that "BigInt" appears in the inner
    // message. Hostile pin extends: the original `cause` chain is
    // preserved (ES2022). Without this, debugging tooling (Sentry,
    // structured loggers) would see only the outer wrapper without
    // the JSON.stringify TypeError it wrapped.
    const { client } = makeMockedClient([]);
    try {
      await client.decisions.ingest({
        ...MIN_INPUT,
        frameworkClaims: [
          { framework: "x", article: "y", claim: 42n as unknown as string },
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      const e = err as Error & { cause?: unknown };
      expect(e.cause).toBeDefined();
      // The inner cause is the TypeError JSON.stringify threw.
      expect(e.cause).toBeInstanceOf(Error);
      expect((e.cause as Error).message).toMatch(/BigInt/i);
    }
  });

  it("H15: retry exhaustion — all attempts 429 → final AttestryAPIError(429) with the last response's body", async () => {
    // maxRetries=2 means up to 3 total attempts. If all 3 return
    // 429, the SDK gives up and re-throws the last AttestryAPIError.
    // Pin: 3 fetches, terminal error class is AttestryAPIError(429),
    // and the message comes from the LAST response body.
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "Too many requests (attempt 1)." } },
      { status: 429, body: { error: "Too many requests (attempt 2)." } },
      { status: 429, body: { error: "Too many requests (attempt 3)." } },
    ];
    const calls: MockedRequest[] = [];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      const r = responses[i++] ?? { status: 200, body: {} };
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
      retry: { maxRetries: 2, initialDelayMs: 1, maxDelayMs: 10 },
    });
    const promise = client.decisions.ingest(MIN_INPUT);
    // Attach error handler before advancing timers — otherwise the
    // exhaustion throw lands as an unhandled rejection during the
    // first tick of the timer advance.
    const result = expect(promise).rejects.toMatchObject({
      status: 429,
      message: "Too many requests (attempt 3).",
    });
    await vi.advanceTimersByTimeAsync(100);
    await result;
    expect(calls).toHaveLength(3);
    vi.useRealTimers();
  });

  it("H16: Date / Map / Symbol passed as zkProof — typeof passes the object guard, server rejects shape", async () => {
    // Hostile gap from build: zkProof's typeof check (`typeof === 'object'
    // && !null && !Array.isArray`) ALSO accepts Date / Map / Set / RegExp
    // / arbitrary object instances. JSON.stringify(Date) → ISO string;
    // JSON.stringify(Map) → "{}" (Map's own enumerable keys are empty);
    // JSON.stringify(Set) → "{}" (same). Server's z.object({type, proof,
    // publicSignals}) rejects each — 422.
    //
    // Pin the SDK forwarding behavior. A future SDK refactor that
    // adds `Object.getPrototypeOf(input.zkProof) === Object.prototype`
    // would CHANGE this contract; the pin catches that drift.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      // Map serializes as "{}" — the SDK passes it; server rejects
      // the missing required fields (type/proof/publicSignals).
      await client.decisions.ingest({
        ...MIN_INPUT,
        zkProof: new Map() as unknown as never,
      });
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    // Body shows zkProof as an empty object (Map's serialization).
    const sent = JSON.parse(calls[0].body!);
    expect(sent.zkProof).toEqual({});
  });

  it("H17: Symbol-typed nested array field — Array.isArray check catches it", async () => {
    // typeof Symbol() === 'symbol', NOT 'object'. Array.isArray returns
    // false. The validateOptionalArray helper rejects via TypeError.
    // Pin: Symbol-as-array slot is rejected synchronously, no fetch.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.ingest({
        ...MIN_INPUT,
        toolInvocations: Symbol("not-array") as unknown as never,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });
});

// ─── Coverage-round defensive pins ──────────────────────────────────────────

describe("decisions.ingest — coverage round (defensive pins)", () => {
  it("C1: every valid humanOversightState value flows through faithfully", async () => {
    // Build round pinned only "approved" (in FULL_INPUT). Coverage
    // round walks every literal-union value the SDK type advertises:
    // approved | bypassed | not_required. If the kernel's z.enum
    // shrinks (e.g., removes "bypassed"), the drift pin in
    // sdk-drift.test.ts surfaces it; this pin is the runtime
    // companion that confirms each value reaches the wire intact.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
      { status: 201, body: { success: true, data: MOCK_RECORD } },
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const states: DecisionIngestInput["humanOversightState"][] = [
      "approved",
      "bypassed",
      "not_required",
    ];
    for (const state of states) {
      await client.decisions.ingest({ ...MIN_INPUT, humanOversightState: state });
    }
    expect(calls).toHaveLength(3);
    expect(JSON.parse(calls[0].body!).humanOversightState).toBe("approved");
    expect(JSON.parse(calls[1].body!).humanOversightState).toBe("bypassed");
    expect(JSON.parse(calls[2].body!).humanOversightState).toBe("not_required");
  });

  it("C2: every valid policyOutcome value flows through faithfully", async () => {
    // Symmetric to C1 — policyOutcome's literal-union covers
    // permitted | denied | escalated. Drift trip-wire pinned in
    // sdk-drift.test.ts; runtime forwarding pinned here.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
      { status: 201, body: { success: true, data: MOCK_RECORD } },
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    const outcomes: DecisionIngestInput["policyOutcome"][] = [
      "permitted",
      "denied",
      "escalated",
    ];
    for (const outcome of outcomes) {
      await client.decisions.ingest({ ...MIN_INPUT, policyOutcome: outcome });
    }
    expect(calls).toHaveLength(3);
    expect(JSON.parse(calls[0].body!).policyOutcome).toBe("permitted");
    expect(JSON.parse(calls[1].body!).policyOutcome).toBe("denied");
    expect(JSON.parse(calls[2].body!).policyOutcome).toBe("escalated");
  });

  it("C3: validateOptionalArray rejects Map / Set / Date / function (non-Array objects)", async () => {
    // Build round pinned the obvious non-array shapes (string, {},
    // 42, null). Hostile pinned Symbol. Coverage closes the rest:
    // Map / Set / Date / function — each `typeof === "object"` (or
    // "function" for fn), Array.isArray = false. The helper rejects.
    const { client, calls } = makeMockedClient([]);
    const cases: Array<unknown> = [
      new Map(),
      new Set(),
      new Date(),
      () => "fn",
    ];
    for (const v of cases) {
      expect(() =>
        client.decisions.ingest({
          ...MIN_INPUT,
          frameworkClaims: v as unknown as never,
        }),
      ).toThrowError(TypeError);
    }
    expect(calls).toHaveLength(0);
  });

  it("C4: sub-shape types compile + runtime-flow correctly via typed input", async () => {
    // Compile-time pin: the imports at the top of this file
    // (FrameworkClaim, ToolInvocation, DelegationEntry, ZkProof)
    // resolve only if the resource exports them. If any export is
    // dropped, `npx tsc --noEmit` or `npm test` fails to compile.
    // Runtime pin: typed values flow through the wire body intact.
    const claim: FrameworkClaim = {
      framework: "eu_ai_act",
      article: "Art.13",
      claim: "human oversight provided",
    };
    const tool: ToolInvocation = {
      name: "vector-store-query",
      inputHash: INPUT_DIGEST,
    };
    const delegation: DelegationEntry = {
      agentId: "agent-007",
      delegationToken: "opaque",
    };
    const zk: ZkProof = {
      type: "groth16",
      proof: "0xdeadbeef",
      publicSignals: ["sig-1"],
    };
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.ingest({
      ...MIN_INPUT,
      frameworkClaims: [claim],
      toolInvocations: [tool],
      delegationChain: [delegation],
      zkProof: zk,
    });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.frameworkClaims).toEqual([claim]);
    expect(sent.toolInvocations).toEqual([tool]);
    expect(sent.delegationChain).toEqual([delegation]);
    expect(sent.zkProof).toEqual(zk);
  });

  it("C5: explicitly undefined optional fields are OMITTED from the body (not serialized as null)", async () => {
    // JSON.stringify omits keys with undefined values entirely (vs
    // serializing as `null`, the way it does for `outputDigest:
    // null`). Pin the omission semantics so a future refactor that
    // routes optional fields through a helper which forces null
    // doesn't silently change wire shape (which would break the
    // server's .strict() schema or alter canonical-payload bytes).
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.ingest({
      ...MIN_INPUT,
      outputDigest: undefined,
      attestationId: undefined,
      humanOversightState: undefined,
      policyOutcome: undefined,
    });
    const sent = JSON.parse(calls[0].body!);
    // Keys with undefined value are NOT in the parsed body.
    expect(Object.keys(sent)).not.toContain("outputDigest");
    expect(Object.keys(sent)).not.toContain("attestationId");
    expect(Object.keys(sent)).not.toContain("humanOversightState");
    expect(Object.keys(sent)).not.toContain("policyOutcome");
    // Required keys remain.
    expect(sent.systemId).toBe(MIN_INPUT.systemId);
    expect(sent.inputDigest).toBe(MIN_INPUT.inputDigest);
  });

  it("C6: zkProof with empty publicSignals (minimal valid zkProof) passes through", async () => {
    // Boundary: the kernel allows publicSignals: [] (no min cap on
    // length, only max(100)). A minimal zkProof with type, proof,
    // and an empty publicSignals array is accepted server-side.
    // Pin: SDK forwards the minimal shape; server's z.array
    // validates the length cap; empty arrays pass.
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.ingest({
      ...MIN_INPUT,
      zkProof: {
        type: "groth16",
        proof: "0xshortproof",
        publicSignals: [],
      },
    });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.zkProof).toEqual({
      type: "groth16",
      proof: "0xshortproof",
      publicSignals: [],
    });
  });

  it("C7: validateOptionalNonEmptyString surfaces TypeError messages with `decisions.ingest:` prefix", async () => {
    // Build round defensive pin checked the prefix for outputDigest
    // + toolInvocations. Coverage closes a wider sample to defend
    // the validateOptionalNonEmptyString refactor (build round D8 —
    // shared helper takes optional methodName param). If a future
    // call site forgets to pass "decisions.ingest" or a refactor
    // changes the helper's default to something other than
    // "decisions.list", these pins surface the regression.
    const { client } = makeMockedClient([]);
    const optionalStringFields: Array<keyof DecisionIngestInput> = [
      "attestationId",
      "humanOversightState",
      "policyOutcome",
      "clientSignature",
      "clientKeyId",
      "idempotencyKey",
    ];
    for (const field of optionalStringFields) {
      try {
        client.decisions.ingest({
          ...MIN_INPUT,
          [field]: "",
        } as DecisionIngestInput);
        throw new Error(`expected throw for ${String(field)}`);
      } catch (err) {
        expect(err).toBeInstanceOf(TypeError);
        const msg = (err as TypeError).message;
        expect(msg).toContain("decisions.ingest:");
        expect(msg).toContain(`\`${String(field)}\``);
        expect(msg).toContain("non-empty string when provided");
      }
    }
  });
});

// ─── Hostile review #1 — MEDIUM-1 throwing-getter fix ───────────────────────
//
// Session-22 hostile review #1: the SDK-wide MEDIUM-1 getter-throws
// contract gap. `decisions.ingest` snapshots each input field via
// `readInputField`, which converts a throwing accessor's exception
// into the documented synchronous `TypeError` input contract.

describe("decisions.ingest — hostile review #1: throwing-getter MEDIUM-1 fix", () => {
  it("converts a throwing `systemId` getter into a TypeError (NOT the getter's raw error)", () => {
    const { client, calls } = makeMockedClient([]);
    const evil = {
      get systemId(): unknown {
        throw new Error("getter boom");
      },
      inputDigest: "sha256:abc",
    } as unknown as DecisionIngestInput;
    let caught: unknown;
    try {
      client.decisions.ingest(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).message).toContain("decisions.ingest");
    expect((caught as Error).message).toContain("systemId");
    expect((caught as Error).message).not.toContain("getter boom");
    expect(calls).toHaveLength(0);
  });

  it("converts a throwing getter on an OPTIONAL field (`zkProof`) into a TypeError", () => {
    // Proves the snapshot wraps every field, not just the required ones.
    const { client, calls } = makeMockedClient([]);
    const evil = {
      systemId: "11111111-1111-1111-1111-111111111111",
      inputDigest: "sha256:abc",
      get zkProof(): unknown {
        throw new Error("zkProof boom");
      },
    } as unknown as DecisionIngestInput;
    expect(() => client.decisions.ingest(evil)).toThrow(TypeError);
    expect(() => client.decisions.ingest(evil)).toThrow(/zkProof/);
    expect(calls).toHaveLength(0);
  });
});
