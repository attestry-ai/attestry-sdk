import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  DecisionBulkInput,
  DecisionIngestInput,
  // Result-shape type imports — pinned at compile time. If any of these
  // is dropped from `index.ts` or the resource's exports, this file
  // fails to compile and the test run aborts before any pin runs.
  BulkInsertedSummary,
  BulkFailedSummary,
  BulkIngestResult,
} from "../decisions.js";
import type { FetchLike } from "../../types.js";

// ─── decisions.bulk — POST batch with partial-success envelope ──────────────
//
// Wire shape (from src/lib/validation/decision-schemas.ts decisionBulkCreateSchema
// and src/app/api/v1/decisions/bulk/route.ts POST handler):
//   POST /api/v1/decisions/bulk
//   Headers: x-api-key, Content-Type: application/json, Accept: application/json
//   Body: DecisionBulkInput  =>  { items: DecisionIngestInput[] }
//   → ALWAYS 200 OK on success (even when every record failed)
//   → { success: true, data: BulkIngestResult }
//
// First SDK encounter with a partial-success envelope. The CRITICAL contract
// distinction vs decisions.ingest: the SDK MUST NOT throw based on
// `totalFailed > 0`. Partial success is the entire point of the endpoint.
// The transport unwraps the {success:true, data} JSON envelope as usual; the
// caller branches on `result.failed.length > 0` if they care.
//
// Top-level errors (401 / 402 / 413 / 422 / 429) DO throw AttestryAPIError.
// Notably ABSENT vs single-ingest: NO top-level 404 (system_not_found is
// per-record), NO 409 (idempotency_conflict per-record), NO 500
// (chain_head_missing per-record). Per-record conditions land in
// failed[i].code via classifyChunkError (kernel src/lib/decisions/bulk-ingest.ts:114-156).

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

const SYSTEM_ID_A = "33333333-3333-3333-3333-333333333333";
const SYSTEM_ID_B = "44444444-4444-4444-4444-444444444444";
const SYSTEM_ID_C = "55555555-5555-5555-5555-555555555555";
const INPUT_DIGEST =
  "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const RECORD_HASH_A =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RECORD_HASH_B =
  "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ISO_NOW = "2026-05-06T00:00:00.000Z";

const MIN_ITEM: DecisionIngestInput = {
  systemId: SYSTEM_ID_A,
  inputDigest: INPUT_DIGEST,
};

function makeInsertedSummary(
  index: number,
  overrides?: Partial<BulkInsertedSummary>,
): BulkInsertedSummary {
  return {
    index,
    id: `id-${index}`,
    systemId: SYSTEM_ID_A,
    sequenceNumber: index + 1,
    recordHash: index % 2 === 0 ? RECORD_HASH_A : RECORD_HASH_B,
    createdAt: ISO_NOW,
    ...overrides,
  };
}

function makeFailedSummary(
  index: number,
  code: string,
  overrides?: Partial<BulkFailedSummary>,
): BulkFailedSummary {
  return {
    index,
    systemId: SYSTEM_ID_A,
    error: `failure-${index}`,
    code,
    ...overrides,
  };
}

function makeResult(opts: {
  submitted: number;
  inserted?: BulkInsertedSummary[];
  failed?: BulkFailedSummary[];
}): BulkIngestResult {
  const inserted = opts.inserted ?? [];
  const failed = opts.failed ?? [];
  return {
    totalSubmitted: opts.submitted,
    totalInserted: inserted.length,
    totalFailed: failed.length,
    inserted,
    failed,
  };
}

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("decisions.bulk — happy path", () => {
  it("POSTs /api/v1/decisions/bulk with the {items} wrapper body", async () => {
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/bulk",
    );
    // Body is the {items: [...]} wrapper, NOT a bare array.
    expect(JSON.parse(calls[0].body!)).toEqual({ items: [MIN_ITEM] });
    // Transport unwraps the {success:true, data} envelope — bare result.
    expect(out).toEqual(result);
  });

  it("returns the BulkIngestResult shape unchanged (envelope unwrapped)", async () => {
    const result = makeResult({
      submitted: 2,
      inserted: [makeInsertedSummary(0), makeInsertedSummary(1)],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM, MIN_ITEM] });
    expect(out.totalSubmitted).toBe(2);
    expect(out.totalInserted).toBe(2);
    expect(out.totalFailed).toBe(0);
    expect(out.inserted).toHaveLength(2);
    expect(out.failed).toEqual([]);
  });

  it("forwards x-api-key + Accept + Content-Type headers (POST with body)", async () => {
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    // Content-Type IS set on POST (transport adds it whenever a body is
    // present). Symmetric to decisions.ingest POST pin.
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("sends the items array verbatim (size + order preserved)", async () => {
    // Pin: the SDK does NOT reorder, dedupe, or rewrite items[]. The body
    // mirrors the input array exactly, position-for-position.
    const items: DecisionIngestInput[] = [
      { systemId: SYSTEM_ID_A, inputDigest: INPUT_DIGEST, idempotencyKey: "k-0" },
      { systemId: SYSTEM_ID_B, inputDigest: INPUT_DIGEST, idempotencyKey: "k-1" },
      { systemId: SYSTEM_ID_C, inputDigest: INPUT_DIGEST, idempotencyKey: "k-2" },
    ];
    const result = makeResult({
      submitted: 3,
      inserted: [
        makeInsertedSummary(0, { systemId: SYSTEM_ID_A }),
        makeInsertedSummary(1, { systemId: SYSTEM_ID_B }),
        makeInsertedSummary(2, { systemId: SYSTEM_ID_C }),
      ],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    await client.decisions.bulk({ items });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.items).toHaveLength(3);
    expect(sent.items[0].idempotencyKey).toBe("k-0");
    expect(sent.items[1].idempotencyKey).toBe("k-1");
    expect(sent.items[2].idempotencyKey).toBe("k-2");
  });

  it("all-success response: totalInserted = items.length, failed = []", async () => {
    const result = makeResult({
      submitted: 3,
      inserted: [
        makeInsertedSummary(0),
        makeInsertedSummary(1),
        makeInsertedSummary(2),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({
      items: [MIN_ITEM, MIN_ITEM, MIN_ITEM],
    });
    expect(out.totalInserted).toBe(3);
    expect(out.totalFailed).toBe(0);
    expect(out.failed).toEqual([]);
    expect(out.inserted).toHaveLength(3);
  });

  it("inserted summary carries every documented field (id, systemId, sequenceNumber, recordHash, createdAt)", async () => {
    // Pin: the SDK preserves the full per-record summary shape end-to-
    // end. A future kernel response shape change that drops a field
    // would surface here before silently producing `undefined as string`
    // in consumer code.
    const summary: BulkInsertedSummary = {
      index: 0,
      id: "11111111-1111-1111-1111-111111111111",
      systemId: SYSTEM_ID_A,
      sequenceNumber: 42,
      recordHash: RECORD_HASH_A,
      createdAt: ISO_NOW,
    };
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: makeResult({ submitted: 1, inserted: [summary] }),
        },
      },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.inserted[0]).toEqual(summary);
    expect(out.inserted[0].id).toBe(summary.id);
    expect(out.inserted[0].sequenceNumber).toBe(42);
    expect(out.inserted[0].recordHash).toBe(RECORD_HASH_A);
    expect(out.inserted[0].createdAt).toBe(ISO_NOW);
  });

  it("totalSubmitted / totalInserted / totalFailed are numbers (not strings)", async () => {
    // Defensive: the kernel emits these as JSON numbers. A future
    // serialization regression that strings them would silently break
    // consumer arithmetic. Pin the types.
    const result = makeResult({
      submitted: 2,
      inserted: [makeInsertedSummary(0)],
      failed: [makeFailedSummary(1, "chunk_failed")],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM, MIN_ITEM] });
    expect(typeof out.totalSubmitted).toBe("number");
    expect(typeof out.totalInserted).toBe("number");
    expect(typeof out.totalFailed).toBe("number");
    expect(out.totalSubmitted).toBe(2);
    expect(out.totalInserted).toBe(1);
    expect(out.totalFailed).toBe(1);
  });
});

// ─── Input validation (pre-fetch — synchronous TypeError, no fetch issued) ──

describe("decisions.bulk — input validation (pre-fetch)", () => {
  it("throws TypeError for non-object input (null, array, string, number, undefined)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.bulk(null as unknown as DecisionBulkInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.bulk([] as unknown as DecisionBulkInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.bulk("input" as unknown as DecisionBulkInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.bulk(42 as unknown as DecisionBulkInput),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.bulk(undefined as unknown as DecisionBulkInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for missing items field", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.bulk({} as unknown as DecisionBulkInput),
    ).toThrowError(TypeError);
    // Explicit `items: undefined` also fails (Array.isArray(undefined) === false).
    expect(() =>
      client.decisions.bulk({
        items: undefined,
      } as unknown as DecisionBulkInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-array items (string, plain object, number, null, Symbol)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.bulk({
        items: "not-array" as unknown as DecisionIngestInput[],
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.bulk({
        items: {} as unknown as DecisionIngestInput[],
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.bulk({
        items: 42 as unknown as DecisionIngestInput[],
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.bulk({
        items: null as unknown as DecisionIngestInput[],
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.bulk({
        items: Symbol("not-array") as unknown as DecisionIngestInput[],
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("accepts empty items array — forwards faithfully (server's min(1) rejects with 422)", async () => {
    // SDK does NOT pre-cap. Empty array passes Array.isArray, reaches
    // the server, which 422s via z.array(...).min(1). Pin: SDK does NOT
    // intercept; the request is issued and the server's catalog message
    // surfaces as AttestryAPIError(422).
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "items must contain at least one record",
        },
      },
    ]);
    try {
      await client.decisions.bulk({ items: [] });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(422);
    }
    // The empty array DID reach the server in the body.
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!)).toEqual({ items: [] });
  });

  it("does NOT pre-validate inner item shapes — server's .strict() is the authority", async () => {
    // Symmetric to ingest's D5 — SDK forwards malformed items without
    // recursing. Server's Zod rejects with 422.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    const malformed = [
      { systemId: "not-a-uuid", inputDigest: "wrong-format" },
      { wrongField: "missing required keys" },
    ] as unknown as DecisionIngestInput[];
    try {
      await client.decisions.bulk({ items: malformed });
    } catch {
      /* ignore — verifying request was issued */
    }
    expect(calls).toHaveLength(1);
    const sent = JSON.parse(calls[0].body!);
    expect(sent.items).toHaveLength(2);
    expect(sent.items[0].systemId).toBe("not-a-uuid");
    expect(sent.items[1].wrongField).toBe("missing required keys");
  });

  it("error messages name `decisions.bulk:` and the offending field", () => {
    const { client } = makeMockedClient([]);
    try {
      client.decisions.bulk(null as unknown as DecisionBulkInput);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toContain("decisions.bulk:");
      expect((err as TypeError).message).toContain("`input`");
    }
    try {
      client.decisions.bulk({
        items: "not-array" as unknown as DecisionIngestInput[],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toContain("decisions.bulk:");
      expect((err as TypeError).message).toContain("`items`");
    }
  });
});

// ─── Partial-success envelope (CRITICAL — does NOT throw) ───────────────────

describe("decisions.bulk — partial-success envelope (CRITICAL — does NOT throw)", () => {
  it("all-failed response (totalInserted = 0) RESOLVES, does NOT throw", async () => {
    // CRITICAL bulk-specific contract: even when EVERY record failed,
    // the SDK call resolves with the envelope. Caller branches on
    // result.totalFailed > 0 if they care. A future regression that
    // adds `if (totalFailed > 0) throw` would silently break this.
    const result = makeResult({
      submitted: 3,
      failed: [
        makeFailedSummary(0, "chunk_failed"),
        makeFailedSummary(1, "chunk_failed"),
        makeFailedSummary(2, "chunk_failed"),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    // No try/catch — this MUST resolve.
    const out = await client.decisions.bulk({
      items: [MIN_ITEM, MIN_ITEM, MIN_ITEM],
    });
    expect(out.totalInserted).toBe(0);
    expect(out.totalFailed).toBe(3);
    expect(out.inserted).toEqual([]);
    expect(out.failed).toHaveLength(3);
  });

  it("mixed response (some inserted, some failed) RESOLVES with both arrays populated and sorted by index", async () => {
    // Pin: kernel sorts both arrays by original input index (line 456-457
    // of bulk-ingest.ts). SDK preserves order. Future regression that
    // reorders or drops the sort would surface here.
    const result = makeResult({
      submitted: 5,
      inserted: [
        makeInsertedSummary(0),
        makeInsertedSummary(2),
        makeInsertedSummary(4),
      ],
      failed: [
        makeFailedSummary(1, "system_not_found"),
        makeFailedSummary(3, "payload_too_large"),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({
      items: [MIN_ITEM, MIN_ITEM, MIN_ITEM, MIN_ITEM, MIN_ITEM],
    });
    expect(out.totalSubmitted).toBe(5);
    expect(out.totalInserted).toBe(3);
    expect(out.totalFailed).toBe(2);
    // Sorted by original index.
    expect(out.inserted.map((r) => r.index)).toEqual([0, 2, 4]);
    expect(out.failed.map((r) => r.index)).toEqual([1, 3]);
  });

  it("failed[i].code === 'idempotency_conflict' (same key, different bytes within chunk)", async () => {
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "idempotency_conflict", {
          error: "Idempotency key already used with different payload",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].code).toBe("idempotency_conflict");
    expect(out.failed[0].error).toMatch(/Idempotency key already used/);
  });

  it("failed[i].code === 'payload_too_large' (one record's canonical bytes >256KB)", async () => {
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "payload_too_large", {
          error: "Decision payload exceeds maximum size of 256KB",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].code).toBe("payload_too_large");
    expect(out.failed[0].error).toBe(
      "Decision payload exceeds maximum size of 256KB",
    );
  });

  it("failed[i].code === 'chain_head_missing' (internal invariant — surfaces per-record, not as 500)", async () => {
    // Notably ABSENT vs single-ingest: chain_head_missing is per-record
    // here, not a top-level 500. Pin: SDK resolves the envelope.
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "chain_head_missing", {
          error: "Chain head missing for system",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].code).toBe("chain_head_missing");
  });

  it("failed[i].code === 'system_not_found' (cross-org system OR cross-system attestation)", async () => {
    // Notably ABSENT vs single-ingest: system_not_found is per-record
    // here, not a top-level 404. The kernel's classifyChunkError
    // collapses cross-org + cross-system-attestation into the same
    // code for enumeration safety.
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "system_not_found", {
          error: "System not found",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].code).toBe("system_not_found");
    expect(out.failed[0].error).toBe("System not found");
  });

  it("failed[i].code === 'ijson_validation_failed' (NaN/BigInt/etc. in record)", async () => {
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "ijson_validation_failed", {
          error:
            "Input contains non-I-JSON values (NaN, Infinity, BigInt, undefined, or Symbol)",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].code).toBe("ijson_validation_failed");
    expect(out.failed[0].error).toMatch(/non-I-JSON/);
  });

  it("failed[i].code === 'idempotency_unique_violation' (race — caller retries via single-record)", async () => {
    // Documented in the resource docstring as the recovery path:
    // bulk does NOT auto-recover; caller retries failed items
    // individually via decisions.ingest to invoke per-record race
    // recovery. Notably ABSENT vs single-ingest: no top-level 409.
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "idempotency_unique_violation", {
          error:
            "Idempotency key collision (use single-record endpoint to recover)",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].code).toBe("idempotency_unique_violation");
    expect(out.failed[0].error).toMatch(/single-record/);
  });

  it("failed[i].code === 'chunk_failed' (catch-all for unclassified chunk-tx failures)", async () => {
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "chunk_failed", {
          error: "Unexpected DB error",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].code).toBe("chunk_failed");
  });

  it("failed summary carries every documented field (index, systemId, error, code)", async () => {
    // Symmetric to the inserted-summary completeness pin in happy-path.
    // A future kernel response shape change that drops a field would
    // surface here.
    const failed: BulkFailedSummary = {
      index: 7,
      systemId: SYSTEM_ID_B,
      error: "Specific error text",
      code: "system_not_found",
    };
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: makeResult({ submitted: 8, failed: [failed] }),
        },
      },
    ]);
    const items = Array.from({ length: 8 }, () => MIN_ITEM);
    const out = await client.decisions.bulk({ items });
    expect(out.failed[0]).toEqual(failed);
    expect(out.failed[0].index).toBe(7);
    expect(out.failed[0].systemId).toBe(SYSTEM_ID_B);
    expect(out.failed[0].error).toBe("Specific error text");
    expect(out.failed[0].code).toBe("system_not_found");
  });
});

// ─── Top-level error paths ──────────────────────────────────────────────────

describe("decisions.bulk — top-level error paths", () => {
  it("surfaces a 401 (auth required) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required." },
      },
    ]);
    try {
      await client.decisions.bulk({ items: [MIN_ITEM] });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces a 402 (PlanLimitError) with structured details preserved (B.1 carry-forward)", async () => {
    // Bulk's plan-limit check uses amount=items.length — the FULL batch
    // counts against quota wholesale (none persisted). Pin the same
    // {feature, currentPlan, upgradeRequired} shape as decisions.ingest.
    const { client } = makeMockedClient([
      {
        status: 402,
        body: {
          success: false,
          error:
            "You have reached your decisions limit on the starter plan. Used: 950/1000.",
          details: {
            feature: "decisions",
            currentPlan: "starter",
            upgradeRequired: true,
          },
        },
      },
    ]);
    try {
      await client.decisions.bulk({
        items: Array.from({ length: 100 }, () => MIN_ITEM),
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(402);
      expect(apiErr.message).toMatch(/decisions limit/);
      expect(apiErr.details).toMatchObject({
        details: {
          feature: "decisions",
          currentPlan: "starter",
          upgradeRequired: true,
        },
      });
    }
  });

  it("surfaces a 413 (PayloadTooLargeError) with verbatim catalog message (defensive path)", async () => {
    // 413 is the kernel's defensive top-level guard
    // (bulk-ingest.ts:349-353) for >500 items if Zod is somehow
    // bypassed. In practice the route's Zod fires first with 422 — see
    // boundary-cases test below — but the error class mapping is in
    // place. Pin the verbatim catalog string from
    // IMPLEMENTATION/ERROR_MESSAGES.md `decision.bulk_too_large`.
    const verbatim = "Bulk ingest limited to 500 records per request";
    const { client } = makeMockedClient([
      { status: 413, body: { success: false, error: verbatim } },
    ]);
    try {
      await client.decisions.bulk({ items: [MIN_ITEM] });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(413);
      expect(apiErr.message).toBe(verbatim);
    }
  });

  it("surfaces a 422 (Zod top-level — items field) with details preserved", async () => {
    // BodyParseError flow: kernel's parseBody throws with `fieldErrors`,
    // route maps to errorResponse(message, 422, error.fieldErrors).
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            { path: "items", message: "Bulk ingest limited to 500 records per request" },
          ],
        },
      },
    ]);
    try {
      await client.decisions.bulk({ items: [MIN_ITEM] });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.details).toMatchObject({
        details: [{ path: "items" }],
      });
    }
  });

  it("surfaces a 422 (Zod inner — malformed item) with field errors in details", async () => {
    // Mixed-validity batches: server's BodyParseError fires before any
    // insert (Zod runs on whole body). NOT a partial-success scenario —
    // a single bad item rejects the entire batch.
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            { path: "items.0.systemId", message: "Invalid uuid" },
          ],
        },
      },
    ]);
    try {
      await client.decisions.bulk({
        items: [{ systemId: "not-a-uuid", inputDigest: INPUT_DIGEST }],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      expect(apiErr.details).toMatchObject({
        details: [{ path: "items.0.systemId" }],
      });
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
      await client.decisions.bulk({ items: [MIN_ITEM] });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });
});

// ─── Body serialization (transport-level pin via this resource) ─────────────

describe("decisions.bulk — body serialization", () => {
  it("BigInt inside an item throws AttestryError BEFORE fetch (carry-forward invariant #4)", async () => {
    // BigInt buried inside an item slips past the SDK validation (which
    // doesn't recurse into items[i] — D4), hits transport's body-
    // serialize step, JSON.stringify throws TypeError "Do not know how
    // to serialize a BigInt", transport wraps as
    // AttestryError("invalid request body: ..."). Pin: no fetch, error
    // class is AttestryError (not AttestryAPIError).
    const { client, calls } = makeMockedClient([]);
    try {
      await client.decisions.bulk({
        items: [
          {
            ...MIN_ITEM,
            frameworkClaims: [
              { framework: "x", article: "y", claim: 42n as unknown as string },
            ],
          },
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      expect((err as AttestryError).message).toMatch(/invalid request body/);
      expect((err as AttestryError).message).toMatch(/BigInt/i);
    }
    expect(calls).toHaveLength(0);
  });

  it("circular reference in input throws AttestryError BEFORE fetch", async () => {
    const { client, calls } = makeMockedClient([]);
    const circular: Record<string, unknown> = { items: [{ ...MIN_ITEM }] };
    (circular.items as unknown[])[0] = {
      ...(circular.items as Array<Record<string, unknown>>)[0],
      self: circular,
    };
    try {
      await client.decisions.bulk(circular as unknown as DecisionBulkInput);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      expect((err as AttestryError).message).toMatch(/invalid request body/);
    }
    expect(calls).toHaveLength(0);
  });

  it("NaN inside an item passes JSON.stringify (serializes as null), reaches the server", async () => {
    // Asymmetric to BigInt: JSON.stringify({a: NaN}) returns '{"a":null}'.
    // The kernel's per-record canonicalize step rejects the resulting
    // null/NaN at runtime, surfacing as failed[i].code ===
    // 'ijson_validation_failed'. Pin: SDK forwards faithfully (no
    // client-side guard against NaN-in-string-typed fields).
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "ijson_validation_failed", {
          error:
            "Input contains non-I-JSON values (NaN, Infinity, BigInt, undefined, or Symbol)",
        }),
      ],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({
      items: [
        {
          ...MIN_ITEM,
          frameworkClaims: [
            { framework: "x", article: "y", claim: NaN as unknown as string },
          ],
        },
      ],
    });
    expect(calls).toHaveLength(1);
    // NaN serialized as null on the wire.
    const sent = JSON.parse(calls[0].body!);
    expect(sent.items[0].frameworkClaims[0].claim).toBeNull();
    // SDK does NOT throw — surfaces as per-record failure.
    expect(out.totalFailed).toBe(1);
    expect(out.failed[0].code).toBe("ijson_validation_failed");
  });
});

// ─── Abort + retry semantics ────────────────────────────────────────────────

describe("decisions.bulk — abort + retry semantics", () => {
  it("forwards a pre-aborted AbortSignal: AttestryError synchronous, no fetch", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.decisions.bulk({ items: [MIN_ITEM] }, { signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted signal and the request completes normally (coverage)", async () => {
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const controller = new AbortController();
    const out = await client.decisions.bulk(
      { items: [MIN_ITEM] },
      { signal: controller.signal },
    );
    expect(out).toEqual(result);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("per-call retry override applies — 429 retried, body re-stringified each attempt", async () => {
    // Retry middleware composes with new resources. POST is retried on
    // 429 only (carry-forward #18); body re-serialized per attempt
    // (no shared mutable buffer). Pin both the count and the
    // identical-body invariant — important for bulk because the body is
    // larger and any buffer reuse could leak data across attempts.
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const responses: Array<{ status?: number; body?: unknown }> = [
      { status: 429, body: { error: "Too many requests." } },
      { status: 200, body: { success: true, data: result } },
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
    const promise = client.decisions.bulk(
      { items: [MIN_ITEM] },
      { retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 } },
    );
    await vi.advanceTimersByTimeAsync(50);
    const out = await promise;
    expect(out).toEqual(result);
    expect(calls).toHaveLength(2);
    // Body re-stringified per attempt; both attempts identical.
    expect(calls[0].body).toBe(calls[1].body);
    expect(JSON.parse(calls[0].body!)).toEqual({ items: [MIN_ITEM] });
    vi.useRealTimers();
  });
});

// ─── Boundary cases ────────────────────────────────────────────────────────

describe("decisions.bulk — boundary cases", () => {
  it("1-item batch (lower boundary above min(1)) flows through", async () => {
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.totalSubmitted).toBe(1);
    expect(JSON.parse(calls[0].body!).items).toHaveLength(1);
  });

  it("500-item batch at the cap flows through (server accepts)", async () => {
    // Pin the upper boundary — kernel's max(500) Zod accepts exactly
    // 500. The SDK has no length cap of its own (D3); a future
    // 'be defensive' SDK refactor that adds a 500 cap would surface
    // here when the kernel later raises the cap.
    const items = Array.from({ length: 500 }, () => MIN_ITEM);
    const inserted = Array.from({ length: 500 }, (_, i) =>
      makeInsertedSummary(i),
    );
    const { client, calls } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: makeResult({ submitted: 500, inserted }),
        },
      },
    ]);
    const out = await client.decisions.bulk({ items });
    expect(JSON.parse(calls[0].body!).items).toHaveLength(500);
    expect(out.totalInserted).toBe(500);
  });

  it("501-item batch over the cap is forwarded; server returns 422 (Zod), NOT 413", async () => {
    // Reality check: kernel route test
    // (src/app/api/v1/decisions/bulk/__tests__/route.test.ts:184) confirms
    // 501 items returns 422 — Zod's max(500) fires before the helper's
    // top-level guard. The 413 path exists as a defensive fallback only
    // (helper's PayloadTooLargeError throw at bulk-ingest.ts:349-353)
    // and is exercised separately in the top-level error-paths section.
    // SDK does NOT pre-cap (D3) — full body forwarded so the server's
    // verbatim catalog message is the source of truth.
    const items = Array.from({ length: 501 }, () => MIN_ITEM);
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            {
              path: "items",
              message: "Bulk ingest limited to 500 records per request",
            },
          ],
        },
      },
    ]);
    try {
      await client.decisions.bulk({ items });
    } catch {
      /* ignore — verifying request was issued */
    }
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).items).toHaveLength(501);
  });

  it("mixed-system batch (3 systems × N items each) flows through faithfully", async () => {
    // Server-side: groups by systemId, processes each system's chunks
    // independently. SDK forwards the array as-is. Pin: the 3-system
    // mix lands on the server with each item's systemId preserved.
    const items: DecisionIngestInput[] = [
      { systemId: SYSTEM_ID_A, inputDigest: INPUT_DIGEST },
      { systemId: SYSTEM_ID_A, inputDigest: INPUT_DIGEST },
      { systemId: SYSTEM_ID_B, inputDigest: INPUT_DIGEST },
      { systemId: SYSTEM_ID_C, inputDigest: INPUT_DIGEST },
      { systemId: SYSTEM_ID_C, inputDigest: INPUT_DIGEST },
    ];
    const inserted = [
      makeInsertedSummary(0, { systemId: SYSTEM_ID_A }),
      makeInsertedSummary(1, { systemId: SYSTEM_ID_A }),
      makeInsertedSummary(2, { systemId: SYSTEM_ID_B }),
      makeInsertedSummary(3, { systemId: SYSTEM_ID_C }),
      makeInsertedSummary(4, { systemId: SYSTEM_ID_C }),
    ];
    const { client, calls } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: makeResult({ submitted: 5, inserted }),
        },
      },
    ]);
    const out = await client.decisions.bulk({ items });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.items.map((it: { systemId: string }) => it.systemId)).toEqual([
      SYSTEM_ID_A,
      SYSTEM_ID_A,
      SYSTEM_ID_B,
      SYSTEM_ID_C,
      SYSTEM_ID_C,
    ]);
    expect(out.inserted.map((r) => r.systemId)).toEqual([
      SYSTEM_ID_A,
      SYSTEM_ID_A,
      SYSTEM_ID_B,
      SYSTEM_ID_C,
      SYSTEM_ID_C,
    ]);
  });

  it("response with empty inserted + empty failed (degenerate but valid envelope) RESOLVES", async () => {
    // Defensive pin: a kernel response that returns the envelope shape
    // with both arrays empty (e.g., totalSubmitted: 0 if the helper
    // were invoked with an empty list — currently not reachable since
    // Zod's min(1) fires first, but the SDK should tolerate the shape).
    // Pin: SDK does not throw, returns the empty envelope.
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: {
            totalSubmitted: 0,
            totalInserted: 0,
            totalFailed: 0,
            inserted: [],
            failed: [],
          },
        },
      },
    ]);
    // Use a non-empty input on the SDK side so SDK validation passes;
    // the pin is on the SDK's tolerance for a degenerate response shape.
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.totalSubmitted).toBe(0);
    expect(out.inserted).toEqual([]);
    expect(out.failed).toEqual([]);
  });
});

// ─── Hostile-round defenses (genuine gaps from build) ──────────────────────

describe("decisions.bulk — hostile round (genuine gaps)", () => {
  it("H1: whitespace-only systemId in items[0] passes SDK, server 422s on UUID format", async () => {
    // The SDK does NOT recurse into items[i] (D4). A whitespace-only
    // systemId passes the wire (Array.isArray check is the only
    // structural gate at the SDK boundary). Server's z.string().uuid()
    // rejects with 422. Pin defends against a future "be helpful"
    // trim() refactor that would silently mask whitespace-tagged ids
    // before reaching the server.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.decisions.bulk({
        items: [
          {
            systemId: "   ",
            inputDigest: INPUT_DIGEST,
          } as unknown as DecisionIngestInput,
        ],
      });
    } catch {
      /* ignore — verifying the request was issued */
    }
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!).items[0].systemId).toBe("   ");
  });

  it("H2: frozen input and frozen items array pass through unchanged (SDK reads, never mutates)", async () => {
    // Caller might Object.freeze(input) to assert immutability. SDK
    // code only reads input.items / input fields — no assignment, no
    // mutation. Pin: frozen input flows through; no error from the
    // validation path. Symmetric to ingest H10.
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const frozenItems = Object.freeze([
      Object.freeze({ ...MIN_ITEM, idempotencyKey: "frozen-1" }),
    ]) as readonly DecisionIngestInput[];
    const frozen = Object.freeze({
      items: frozenItems,
    }) as Readonly<DecisionBulkInput>;
    await client.decisions.bulk(frozen);
    expect(calls).toHaveLength(1);
    const sent = JSON.parse(calls[0].body!);
    expect(sent.items[0].idempotencyKey).toBe("frozen-1");
  });

  it("H3: inherited (prototype-chain) properties on input are NOT serialized into the wire body", async () => {
    // Adversarial: a caller constructs the input via Object.create with
    // a polluted prototype carrying extra fields. JSON.stringify only
    // serializes the object's OWN enumerable properties — not
    // properties inherited via the prototype chain. Pin: properties on
    // `evilProto` do NOT leak through to the body. Symmetric to
    // ingest H11.
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const evilProto = { evilField: "polluted-via-prototype" };
    const polluted = Object.assign(Object.create(evilProto), {
      items: [MIN_ITEM],
    });
    await client.decisions.bulk(polluted);
    expect(calls).toHaveLength(1);
    expect(calls[0].body).not.toContain("evilField");
    expect(calls[0].body).not.toContain("polluted-via-prototype");
    // Confirm the OWN keys did serialize correctly.
    expect(JSON.parse(calls[0].body!).items[0].systemId).toBe(
      MIN_ITEM.systemId,
    );
  });

  it("H4: BigInt body-serialize failure preserves the original TypeError as `cause`", async () => {
    // Build round pinned the AttestryError class + the "invalid
    // request body" message + that "BigInt" appears in the inner
    // message. Hostile pin extends: the original `cause` chain is
    // preserved (ES2022). Without this, debugging tooling (Sentry,
    // structured loggers) would see only the outer wrapper without
    // the JSON.stringify TypeError it wrapped. Symmetric to ingest H14.
    const { client } = makeMockedClient([]);
    try {
      await client.decisions.bulk({
        items: [
          {
            ...MIN_ITEM,
            frameworkClaims: [
              {
                framework: "x",
                article: "y",
                claim: 42n as unknown as string,
              },
            ],
          },
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      const e = err as Error & { cause?: unknown };
      expect(e.cause).toBeDefined();
      expect(e.cause).toBeInstanceOf(Error);
      expect((e.cause as Error).message).toMatch(/BigInt/i);
    }
  });

  it("H5: retry exhaustion — all attempts 429 → final AttestryAPIError(429) with the last response's body", async () => {
    // maxRetries=2 means up to 3 total attempts. If all 3 return 429,
    // the SDK gives up and re-throws the last AttestryAPIError. Pin:
    // 3 fetches, terminal error class is AttestryAPIError(429), and
    // the message comes from the LAST response body. Symmetric to
    // ingest H15.
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
    const promise = client.decisions.bulk({ items: [MIN_ITEM] });
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

  it("H6: items[i].idempotencyKey at the 1-char minimum is forwarded faithfully", async () => {
    // Server's per-item z.string().min(1).max(200). Pin the lower
    // boundary so a degenerate 1-char key (e.g., "x" — valid) reaches
    // the server. SDK does NOT recurse into items, but the byte-for-
    // byte forwarding is what matters. Symmetric to ingest H8.
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    await client.decisions.bulk({
      items: [{ ...MIN_ITEM, idempotencyKey: "x" }],
    });
    expect(JSON.parse(calls[0].body!).items[0].idempotencyKey).toBe("x");
  });

  it("H7: items[i].idempotencyKey at the 200-char maximum is forwarded faithfully", async () => {
    // Pin the upper boundary — 200 chars exactly. The SDK has no
    // length cap of its own; the kernel's max(200) is the authority.
    // A 200-char key passes; 201 server-422s.
    const result = makeResult({
      submitted: 1,
      inserted: [makeInsertedSummary(0)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const key200 = "k".repeat(200);
    await client.decisions.bulk({
      items: [{ ...MIN_ITEM, idempotencyKey: key200 }],
    });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.items[0].idempotencyKey).toBe(key200);
    expect(sent.items[0].idempotencyKey.length).toBe(200);
  });

  it("H8: 422 verbatim catalog message — 'items must contain at least one record' — preserved", async () => {
    // ERROR_MESSAGES.md / decisionBulkCreateSchema:109 ships this
    // exact min(1) message. Pin verbatim string preservation through
    // the SDK error path so a future kernel catalog edit (or transport
    // regression that rewraps) is caught.
    const verbatim = "items must contain at least one record";
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [{ path: "items", message: verbatim }],
        },
      },
    ]);
    try {
      await client.decisions.bulk({ items: [] });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      // Top-level message is the route's "Validation failed." wrapper.
      // Verbatim catalog string lives in details.
      expect(apiErr.details).toMatchObject({
        details: [{ message: verbatim }],
      });
    }
  });

  it("H9: Symbol in items array slot — JSON.stringify converts to null on the wire", async () => {
    // typeof Symbol() === 'symbol', NOT 'object'. Array.isArray returns
    // TRUE for `[Symbol(), {...}]` (it's still an array). The SDK
    // forwards. JSON.stringify of a Symbol value in an array slot
    // emits `null` (vs object slot, where the key is omitted). Server
    // sees `items: [null, {...}]` → z.array(decisionCreateSchema) 422s.
    // Pin the SDK forwarding behavior + the JSON.stringify(Symbol)
    // wire conversion.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.decisions.bulk({
        items: [
          Symbol("not-item") as unknown as DecisionIngestInput,
          MIN_ITEM,
        ],
      });
    } catch {
      /* ignore */
    }
    expect(calls).toHaveLength(1);
    const sent = JSON.parse(calls[0].body!);
    expect(sent.items).toHaveLength(2);
    // Symbol value in an array slot becomes null on the wire.
    expect(sent.items[0]).toBeNull();
    // Sibling item serializes normally.
    expect(sent.items[1].systemId).toBe(MIN_ITEM.systemId);
  });

  it("H10: same idempotencyKey across two items in one batch surfaces as failed[i].code === 'idempotency_conflict'", async () => {
    // Within-chunk conflict: kernel groups by systemId then chunks of
    // 20. Two records in the same chunk that share an idempotencyKey
    // BUT differ in canonical bytes trip the in-chunk dedupe check —
    // classifyChunkError emits `idempotency_conflict`. (Same key +
    // same bytes is deduped silently — that's the replay path.)
    // Pin: the SDK surfaces both indices as failed entries with the
    // verbatim code. The build round pinned the code in isolation;
    // hostile pins the realistic two-item scenario.
    const result = makeResult({
      submitted: 2,
      failed: [
        makeFailedSummary(0, "idempotency_conflict", {
          error: "Idempotency key already used with different payload",
        }),
        makeFailedSummary(1, "idempotency_conflict", {
          error: "Idempotency key already used with different payload",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({
      items: [
        { ...MIN_ITEM, idempotencyKey: "shared-key", outputDigest: undefined },
        {
          ...MIN_ITEM,
          idempotencyKey: "shared-key",
          outputDigest:
            "sha256:9999999999999999999999999999999999999999999999999999999999999999",
        },
      ],
    });
    expect(out.totalFailed).toBe(2);
    expect(out.failed[0].code).toBe("idempotency_conflict");
    expect(out.failed[1].code).toBe("idempotency_conflict");
    expect(out.failed.map((f) => f.index)).toEqual([0, 1]);
  });
});

// ─── Coverage-round defensive pins ──────────────────────────────────────────

describe("decisions.bulk — coverage round (defensive pins)", () => {
  it("C1: per-record code 'ijson_validation_failed' carries the verbatim catalog error message", async () => {
    // classifyChunkError (bulk-ingest.ts:131-140) hardcodes the
    // verbatim message when wrapping IJsonError. Build round pinned
    // the code value; coverage extends to the verbatim string —
    // catches a future kernel catalog drift OR an SDK transport
    // regression that rewraps the error field.
    const verbatim =
      "Input contains non-I-JSON values (NaN, Infinity, BigInt, undefined, or Symbol)";
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "ijson_validation_failed", { error: verbatim }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].error).toBe(verbatim);
  });

  it("C2: per-record code 'idempotency_unique_violation' carries the verbatim recovery-hint message", async () => {
    // classifyChunkError (bulk-ingest.ts:146-150) hardcodes the
    // verbatim message that names the recovery path
    // (single-record endpoint). The hint is load-bearing: consumers
    // route failed items back through `decisions.ingest` to invoke
    // per-record race recovery. Pin verbatim so a kernel edit that
    // rewrites the hint is caught immediately.
    const verbatim =
      "Idempotency key collision (use single-record endpoint to recover)";
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "idempotency_unique_violation", {
          error: verbatim,
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].error).toBe(verbatim);
    expect(out.failed[0].error).toContain("single-record");
  });

  it("C3: per-record code 'system_not_found' carries the verbatim 'System not found' OR 'Attestation not found' message", async () => {
    // Cross-org system + cross-system attestation collapse to the
    // same code (enumeration safety) but to different messages from
    // the originating throw site (bulk-ingest.ts:207 vs :243). Pin
    // both — the SDK preserves whichever the kernel emits.
    const result1 = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "system_not_found", { error: "System not found" }),
      ],
    });
    const result2 = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "system_not_found", {
          error: "Attestation not found",
        }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result1 } },
      { status: 200, body: { success: true, data: result2 } },
    ]);
    const out1 = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out1.failed[0].error).toBe("System not found");
    const out2 = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out2.failed[0].error).toBe("Attestation not found");
  });

  it("C4: per-record code 'payload_too_large' carries the verbatim 256KB ceiling message", async () => {
    // Kernel processChunk throws PayloadTooLargeError with this exact
    // string when canonicalBytes > MAX_CANONICAL_PAYLOAD_BYTES
    // (bulk-ingest.ts:267-269). Same wording as decisions.ingest's
    // top-level 413 message. Pin verbatim.
    const verbatim = "Decision payload exceeds maximum size of 256KB";
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "payload_too_large", { error: verbatim }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].error).toBe(verbatim);
  });

  it("C5: per-record code 'idempotency_conflict' carries the verbatim conflict message", async () => {
    // IdempotencyConflictError's message ships through classifyChunkError
    // unchanged (bulk-ingest.ts:115-117). The verbatim string is
    // "Idempotency key already used with different payload" —
    // catalog code `decision.idempotency_conflict`. Same wording as
    // single-ingest's 409 — pin verbatim.
    const verbatim = "Idempotency key already used with different payload";
    const result = makeResult({
      submitted: 1,
      failed: [
        makeFailedSummary(0, "idempotency_conflict", { error: verbatim }),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items: [MIN_ITEM] });
    expect(out.failed[0].error).toBe(verbatim);
  });

  it("C6: 21-item single-system batch (2 server chunks) — all 21 succeed and are sorted", async () => {
    // Server CHUNK_SIZE = 20 (bulk-ingest.ts:43). A 21-item single-
    // system batch forces TWO chunks: items 0-19 in chunk 1, item 20
    // in chunk 2. Both chunks succeed independently under separate
    // chain_heads FOR UPDATE locks. Pin: the response sorts all 21
    // by original input index — chunk-2's lone item lands at index 20.
    // Defends the SDK's preservation of the kernel's sort.
    const items = Array.from({ length: 21 }, () => MIN_ITEM);
    const inserted = Array.from({ length: 21 }, (_, i) =>
      makeInsertedSummary(i),
    );
    const result = makeResult({ submitted: 21, inserted });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({ items });
    expect(out.totalSubmitted).toBe(21);
    expect(out.totalInserted).toBe(21);
    expect(out.inserted.map((r) => r.index)).toEqual(
      Array.from({ length: 21 }, (_, i) => i),
    );
    expect(JSON.parse(calls[0].body!).items).toHaveLength(21);
  });

  it("C7: empty items: [] body serializes as {\"items\":[]} (NOT {} or omitted)", async () => {
    // Defensive on JSON.stringify behavior with empty arrays. An
    // empty array IS an own enumerable property; JSON.stringify
    // includes the key with `[]`, NOT omits it. Pin: the wire body
    // carries `{"items":[]}` literally. A future SDK refactor that
    // routes the body through a helper which omits empty arrays
    // would silently change wire shape and the server would 422
    // with "Required" instead of "items must contain at least one
    // record" — that catalog drift is surfaced here.
    const { client, calls } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "items must contain at least one record",
        },
      },
    ]);
    try {
      await client.decisions.bulk({ items: [] });
    } catch {
      /* ignore */
    }
    expect(calls[0].body).toBe('{"items":[]}');
    // Re-parse to confirm structure (defensive against future
    // serialization-order changes).
    expect(JSON.parse(calls[0].body!)).toEqual({ items: [] });
  });

  it("C8: input.items reference identity — SDK does NOT clone the caller's array", async () => {
    // Pin: the SDK does NOT clone the caller's input. The body sent
    // to the server is JSON.stringify(input) — direct serialization
    // of the same items array object. Mutation BEFORE the call is
    // observable; mutation AFTER the await returns is fine. Pin
    // protects against a future "let me normalize first" refactor
    // that would clone + mutate, altering the contract. Symmetric
    // to ingest H6.
    const result = makeResult({
      submitted: 2,
      inserted: [makeInsertedSummary(0), makeInsertedSummary(1)],
    });
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const items: DecisionIngestInput[] = [
      { ...MIN_ITEM, idempotencyKey: "k-0" },
      { ...MIN_ITEM, idempotencyKey: "k-1" },
    ];
    await client.decisions.bulk({ items });
    // Wire body reflects items AS PROVIDED, byte-for-byte.
    const sent = JSON.parse(calls[0].body!);
    expect(sent.items).toEqual(items);
    // Mutating items AFTER the call doesn't retroactively change the
    // already-serialized body (JSON.stringify ran during the call).
    items[0].idempotencyKey = "mutated-after-call";
    expect(JSON.parse(calls[0].body!).items[0].idempotencyKey).toBe("k-0");
  });

  it("C9: sub-shape types compile + runtime-flow correctly via typed input/output", async () => {
    // Compile-time pin: the imports at the top of this file
    // (DecisionBulkInput, BulkInsertedSummary, BulkFailedSummary,
    // BulkIngestResult) resolve only if the resource exports them.
    // If any export is dropped, `npx tsc --noEmit` or `npm test`
    // fails to compile. Runtime pin: typed values flow through the
    // wire body and response intact. Symmetric to ingest C4.
    const item: DecisionIngestInput = {
      systemId: SYSTEM_ID_A,
      inputDigest: INPUT_DIGEST,
      idempotencyKey: "typed-1",
    };
    const inserted: BulkInsertedSummary = {
      index: 0,
      id: "typed-id-1",
      systemId: SYSTEM_ID_A,
      sequenceNumber: 99,
      recordHash: RECORD_HASH_A,
      createdAt: ISO_NOW,
    };
    const failed: BulkFailedSummary = {
      index: 1,
      systemId: SYSTEM_ID_A,
      error: "typed failure",
      code: "chunk_failed",
    };
    const result: BulkIngestResult = {
      totalSubmitted: 2,
      totalInserted: 1,
      totalFailed: 1,
      inserted: [inserted],
      failed: [failed],
    };
    const input: DecisionBulkInput = { items: [item, item] };
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk(input);
    expect(out).toEqual(result);
    expect(out.inserted[0]).toEqual(inserted);
    expect(out.failed[0]).toEqual(failed);
    // Wire body carries the typed input verbatim.
    expect(JSON.parse(calls[0].body!).items).toEqual([item, item]);
  });

  it("C10: totalSubmitted / totalInserted / totalFailed are non-negative integers", async () => {
    // Defensive: the kernel emits these as JSON numbers (number type
    // already pinned in build's happy-path). Coverage extends to
    // domain assertions: non-negative integers (kernel's
    // result.inserted.length / failed.length is always ≥ 0; the sum
    // doesn't have to equal totalSubmitted because some records can
    // be silently dropped if a chunk's attestation pre-check throws,
    // but the values are always ints ≥ 0). Pin defends against a
    // future kernel regression that emits floats / negatives /
    // strings disguised as numbers.
    const result = makeResult({
      submitted: 3,
      inserted: [makeInsertedSummary(0)],
      failed: [
        makeFailedSummary(1, "chunk_failed"),
        makeFailedSummary(2, "system_not_found"),
      ],
    });
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: result } },
    ]);
    const out = await client.decisions.bulk({
      items: [MIN_ITEM, MIN_ITEM, MIN_ITEM],
    });
    expect(Number.isInteger(out.totalSubmitted)).toBe(true);
    expect(Number.isInteger(out.totalInserted)).toBe(true);
    expect(Number.isInteger(out.totalFailed)).toBe(true);
    expect(out.totalSubmitted).toBeGreaterThanOrEqual(0);
    expect(out.totalInserted).toBeGreaterThanOrEqual(0);
    expect(out.totalFailed).toBeGreaterThanOrEqual(0);
    // Inserted / failed lengths match their respective totals.
    expect(out.inserted.length).toBe(out.totalInserted);
    expect(out.failed.length).toBe(out.totalFailed);
  });
});
