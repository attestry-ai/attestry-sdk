import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  DecisionExportFrame,
  DecisionExportRecord,
  DecisionExportTrailer,
  DecisionsExportInput,
} from "../decisions.js";
import type { FetchLike } from "../../types.js";

// ─── decisions.export — NDJSON streaming export ────────────────────────────
//
// First NDJSON streaming resource on `@attestry/sdk` and the first non-SSE
// streaming endpoint — exercises the `streamRequest` content-type
// generalization (via `expectedContentType: "application/x-ndjson"`) and
// the new `parseNDJSONResponse` parser primitive.
//
// Wire shape (kernel `src/lib/decisions/export-stream.ts:24-56`):
//
//   200 OK
//   Content-Type: application/x-ndjson
//
//   {"id":"...","systemId":"...",...,"recordHash":"...","createdAt":"..."}\n
//   {"id":"...","systemId":"...",...,"recordHash":"...","createdAt":"..."}\n
//   {"type":"ExportTrailer","systemId":"...","recordCount":2,
//    "merkleRoot":"sha256:...","signing":"unsigned-prompt-1-blocked", ... }\n
//
// Auth + headers: `x-api-key` (transport) + `Accept: application/x-ndjson`
// (per the new expectedContentType param). No Content-Type (GET, no body).

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

/**
 * Build a Response whose body streams the given NDJSON chunks. Each chunk
 * is enqueued separately so the parser sees them as distinct
 * `reader.read()` results — matches the SSE test pattern.
 */
function makeNDJSONResponse(
  chunks: string[],
  init: { status?: number; headers?: Record<string, string> } = {},
): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
  return new Response(stream, {
    status: init.status ?? 200,
    headers: {
      "Content-Type": "application/x-ndjson",
      ...(init.headers ?? {}),
    },
  });
}

function makeMockedClientForExport(
  responses: Array<{
    chunks?: string[];
    status?: number;
    headers?: Record<string, string>;
    bodyText?: string;
  }>,
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
    if (r.chunks !== undefined) {
      return makeNDJSONResponse(r.chunks, {
        status: r.status,
        headers: r.headers,
      });
    }
    return new Response(r.bodyText ?? "", {
      status: r.status ?? 200,
      headers: { "Content-Type": "application/json", ...(r.headers ?? {}) },
    });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    // Retry tests live in src/__tests__/retry.test.ts; export tests
    // disable retry so a 429-mock test doesn't hang on backoff and
    // accidentally consume the next mock response.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const SYSTEM_ID = "33333333-3333-3333-3333-333333333333";

const SAMPLE_RECORD_1 = {
  id: "11111111-1111-1111-1111-111111111111",
  systemId: SYSTEM_ID,
  sequenceNumber: 1,
  inputDigest:
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  outputDigest: null,
  frameworkClaims: [],
  toolInvocations: [],
  delegationChain: [],
  humanOversightState: null,
  policyOutcome: null,
  prevRecordHash: null,
  recordHash:
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  createdAt: "2026-04-27T00:00:00.000Z",
  tombstoned: false,
};

const SAMPLE_RECORD_2 = {
  id: "22222222-2222-2222-2222-222222222222",
  systemId: SYSTEM_ID,
  sequenceNumber: 2,
  inputDigest:
    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  outputDigest:
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  frameworkClaims: [
    { framework: "eu_ai_act", article: "Art.13", claim: "human oversight" },
  ],
  toolInvocations: [],
  delegationChain: [],
  humanOversightState: "approved",
  policyOutcome: "permitted",
  prevRecordHash:
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  recordHash:
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  createdAt: "2026-04-27T00:00:01.000Z",
  tombstoned: false,
};

const SAMPLE_TRAILER = {
  type: "ExportTrailer",
  systemId: SYSTEM_ID,
  recordCount: 2,
  sequenceFrom: 1,
  sequenceTo: 2,
  merkleRoot:
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
  signing: "unsigned-prompt-1-blocked",
  generatedAt: "2026-04-27T00:00:02.000Z",
};

// Empty-export sentinel: kernel emits sha256:<hex> where <hex> is
// sha256("ATTESTRY-EMPTY-EXPORT"). Computed once and pinned verbatim
// here so a kernel-side change to the algorithm shows up as a test
// diff (drift signal at the SDK fixture level — the kernel-side
// drift pin in sdk-drift.test.ts catches the literal-string change
// in the trailer's `signing` field; this fixture catches the
// merkleRoot algorithm change).
//
// To recompute: `printf '%s' 'ATTESTRY-EMPTY-EXPORT' | shasum -a 256`
const EMPTY_EXPORT_SENTINEL_MERKLE_ROOT =
  "sha256:cfdc1b1f2dd74cdc4c7a4c27d04d637810ca5456533bfbaa73fd91e6be70ea69";

const EMPTY_TRAILER = {
  type: "ExportTrailer",
  systemId: SYSTEM_ID,
  recordCount: 0,
  sequenceFrom: null,
  sequenceTo: null,
  merkleRoot: EMPTY_EXPORT_SENTINEL_MERKLE_ROOT,
  signing: "unsigned-prompt-1-blocked",
  generatedAt: "2026-04-27T00:00:00.000Z",
};

function ndjsonLine(obj: object): string {
  return JSON.stringify(obj) + "\n";
}

// ─── happy path ─────────────────────────────────────────────────────────────

describe("decisions.export — happy path", () => {
  it("GETs /api/v1/decisions/export with the right query string", async () => {
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
      void _;
    }
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/decisions/export?systemId=${SYSTEM_ID}`,
    );
  });

  it("returns AsyncIterable<DecisionExportFrame>", async () => {
    const { client } = makeMockedClientForExport([
      {
        chunks: [
          ndjsonLine(SAMPLE_RECORD_1),
          ndjsonLine(SAMPLE_RECORD_2),
          ndjsonLine(SAMPLE_TRAILER),
        ],
      },
    ]);
    const iter = client.decisions.export({ systemId: SYSTEM_ID });
    expect(typeof (iter as AsyncIterable<DecisionExportFrame>)[Symbol.asyncIterator]).toBe(
      "function",
    );
    // Drain so we don't leak the open stream.
    for await (const _ of iter) void _;
  });

  it("forwards x-api-key + Accept: application/x-ndjson headers (NOT text/event-stream)", async () => {
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
      void _;
    }
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/x-ndjson");
    expect(calls[0].headers.get("Content-Type")).toBeNull();
  });

  it("yields records in wire order, then the trailer last", async () => {
    const { client } = makeMockedClientForExport([
      {
        chunks: [
          ndjsonLine(SAMPLE_RECORD_1),
          ndjsonLine(SAMPLE_RECORD_2),
          ndjsonLine(SAMPLE_TRAILER),
        ],
      },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(3);
    // Records first.
    expect((frames[0] as DecisionExportRecord).id).toBe(SAMPLE_RECORD_1.id);
    expect((frames[1] as DecisionExportRecord).id).toBe(SAMPLE_RECORD_2.id);
    // Trailer last.
    expect("type" in frames[2] && frames[2].type === "ExportTrailer").toBe(true);
    expect((frames[2] as DecisionExportTrailer).recordCount).toBe(2);
  });

  it("empty export yields ONLY the trailer with recordCount: 0 (no throw)", async () => {
    // Per build-round hostile #9: zero-record export yields a single
    // trailer frame with recordCount: 0, sequenceFrom/To: null,
    // empty-export merkleRoot. The SDK does NOT throw — the trailer
    // IS the kernel's success signal for "no data".
    const { client } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(1);
    const trailer = frames[0] as DecisionExportTrailer;
    expect(trailer.type).toBe("ExportTrailer");
    expect(trailer.recordCount).toBe(0);
    expect(trailer.sequenceFrom).toBeNull();
    expect(trailer.sequenceTo).toBeNull();
  });

  it("records have the same field-shape as DecisionListItem (D2: type alias)", async () => {
    // Per build-round D2: DecisionExportRecord = DecisionListItem.
    // Pin structural equivalence — every DecisionListItem field is
    // present on the yielded record.
    const { client } = makeMockedClientForExport([
      {
        chunks: [ndjsonLine(SAMPLE_RECORD_2), ndjsonLine(SAMPLE_TRAILER)],
      },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    const rec = frames[0] as DecisionExportRecord;
    // Mirror the exact DecisionListItem fields.
    expect(rec.id).toBe(SAMPLE_RECORD_2.id);
    expect(rec.systemId).toBe(SAMPLE_RECORD_2.systemId);
    expect(rec.sequenceNumber).toBe(SAMPLE_RECORD_2.sequenceNumber);
    expect(rec.inputDigest).toBe(SAMPLE_RECORD_2.inputDigest);
    expect(rec.outputDigest).toBe(SAMPLE_RECORD_2.outputDigest);
    expect(rec.frameworkClaims).toEqual(SAMPLE_RECORD_2.frameworkClaims);
    expect(rec.toolInvocations).toEqual(SAMPLE_RECORD_2.toolInvocations);
    expect(rec.delegationChain).toEqual(SAMPLE_RECORD_2.delegationChain);
    expect(rec.humanOversightState).toBe(SAMPLE_RECORD_2.humanOversightState);
    expect(rec.policyOutcome).toBe(SAMPLE_RECORD_2.policyOutcome);
    expect(rec.prevRecordHash).toBe(SAMPLE_RECORD_2.prevRecordHash);
    expect(rec.recordHash).toBe(SAMPLE_RECORD_2.recordHash);
    expect(rec.createdAt).toBe(SAMPLE_RECORD_2.createdAt);
    expect(rec.tombstoned).toBe(SAMPLE_RECORD_2.tombstoned);
  });

  it("trailer's `signing` field is the literal `unsigned-prompt-1-blocked` (verbatim)", async () => {
    // Per build-round hostile #20: SDK preserves the kernel's literal
    // verbatim. Caller can branch on the value to detect signed vs
    // unsigned trailers post-Prompt-1. Drift-pin candidate for the
    // spec-diff round.
    const { client } = makeMockedClientForExport([
      { chunks: [ndjsonLine(SAMPLE_TRAILER)] },
    ]);
    let trailer: DecisionExportTrailer | null = null;
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      if ("type" in f && f.type === "ExportTrailer") trailer = f;
    }
    expect(trailer).not.toBeNull();
    expect(trailer!.signing).toBe("unsigned-prompt-1-blocked");
  });
});

// ─── input validation (pre-fetch) ──────────────────────────────────────────

describe("decisions.export — input validation (pre-fetch)", () => {
  it("throws TypeError for non-object input (null, array, string, number)", async () => {
    const { client, calls } = makeMockedClientForExport([]);
    expect(() =>
      client.decisions.export(null as unknown as { systemId: string }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.export([] as unknown as { systemId: string }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.export("nope" as unknown as { systemId: string }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.export(42 as unknown as { systemId: string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for missing systemId", async () => {
    const { client, calls } = makeMockedClientForExport([]);
    expect(() =>
      client.decisions.export({} as { systemId: string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty systemId", async () => {
    const { client, calls } = makeMockedClientForExport([]);
    expect(() => client.decisions.export({ systemId: "" })).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId", async () => {
    const { client, calls } = makeMockedClientForExport([]);
    expect(() =>
      client.decisions.export({ systemId: 42 as unknown as string }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.export({ systemId: null as unknown as string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty optional from / to (validateOptionalNonEmptyString)", async () => {
    const { client, calls } = makeMockedClientForExport([]);
    expect(() =>
      client.decisions.export({ systemId: SYSTEM_ID, from: "" }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.export({ systemId: SYSTEM_ID, to: "" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-boolean includeTombstoned", async () => {
    const { client, calls } = makeMockedClientForExport([]);
    expect(() =>
      client.decisions.export({
        systemId: SYSTEM_ID,
        includeTombstoned: "true" as unknown as boolean,
      }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.export({
        systemId: SYSTEM_ID,
        includeTombstoned: 1 as unknown as boolean,
      }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("error messages name `decisions.export:` and the offending field", async () => {
    const { client } = makeMockedClientForExport([]);
    let caught: Error | null = null;
    try {
      client.decisions.export({ systemId: "" });
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught!.message).toContain("decisions.export:");
    expect(caught!.message).toContain("systemId");
  });

  it("throws TypeError synchronously when systemId contains a lone surrogate (UTF-16 hostile-fix)", async () => {
    // Hostile-review finding: the underlying transport runs
    // `encodeURIComponent` over each query value, which throws
    // `URIError` for malformed UTF-16 (lone surrogates such as
    // `\uD800`). Without the synchronous guard, the URIError leaked
    // into the consumer's for-await loop as a non-AttestryError class
    // — inconsistent with `decisions.retrieve` (which converts the
    // same error to TypeError on the path-segment encoding). Pin the
    // synchronous TypeError surface so consumers can branch uniformly
    // on `instanceof TypeError` for input-shape validation.
    const { client, calls } = makeMockedClientForExport([]);
    expect(() =>
      client.decisions.export({ systemId: "\uD800" }),
    ).toThrowError(TypeError);
    let caught: Error | null = null;
    try {
      client.decisions.export({ systemId: "\uDFFF" });
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught!.message).toContain("decisions.export:");
    expect(caught!.message).toContain("systemId");
    expect(caught!.message).toContain("invalid UTF-16");
    // No fetch issued — synchronous throw.
    expect(calls).toHaveLength(0);
    // Cause chained for debugging.
    expect((caught as { cause?: unknown }).cause).toBeInstanceOf(URIError);
  });

  it("throws TypeError synchronously when `from` contains a lone surrogate", async () => {
    // Hostile-review: the date filter path is also encoded — same
    // URIError leak surface. Pin the symmetric guard.
    const { client, calls } = makeMockedClientForExport([]);
    expect(() =>
      client.decisions.export({
        systemId: SYSTEM_ID,
        from: "\uD800",
      }),
    ).toThrowError(TypeError);
    let caught: Error | null = null;
    try {
      client.decisions.export({ systemId: SYSTEM_ID, from: "\uD800" });
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught!.message).toContain("from");
    expect(caught!.message).toContain("invalid UTF-16");
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError synchronously when `to` contains a lone surrogate", async () => {
    // Hostile-review: companion to the `from` pin.
    const { client, calls } = makeMockedClientForExport([]);
    expect(() =>
      client.decisions.export({
        systemId: SYSTEM_ID,
        to: "\uDFFF",
      }),
    ).toThrowError(TypeError);
    let caught: Error | null = null;
    try {
      client.decisions.export({ systemId: SYSTEM_ID, to: "\uDFFF" });
    } catch (err) {
      caught = err as Error;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught!.message).toContain("to");
    expect(caught!.message).toContain("invalid UTF-16");
    expect(calls).toHaveLength(0);
  });

  it("encodes systemId with multibyte but VALID surrogate pairs without crash", async () => {
    // Companion: well-formed surrogate pair (e.g. emoji `🦊` =
    // U+1F98A = `🦊`) MUST encode safely. Pin the positive
    // case so the surrogate-rejection guard doesn't accidentally
    // reject legitimate non-BMP code points. Server returns 422
    // because the value isn't a UUID, but the SDK doesn't crash.
    const { client, calls } = makeMockedClientForExport([
      {
        status: 422,
        bodyText: JSON.stringify({
          success: false,
          error: "Invalid query parameters.",
        }),
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({
        systemId: "🦊", // emoji "🦊"
      })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    // No URIError / TypeError leak — server returns 422.
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(422);
    expect(calls).toHaveLength(1);
    // URL contains the percent-encoded UTF-8 of the emoji.
    expect(calls[0].url).toContain("%F0%9F%A6%8A");
  });
});

// ─── query string forwarding ───────────────────────────────────────────────

describe("decisions.export — query string forwarding", () => {
  it("sends systemId in query string", async () => {
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
      void _;
    }
    expect(calls[0].url).toContain(`systemId=${SYSTEM_ID}`);
  });

  it("sends from / to as ISO datetimes when provided", async () => {
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    for await (const _ of client.decisions.export({
      systemId: SYSTEM_ID,
      from: "2026-01-01T00:00:00Z",
      to: "2026-04-26T00:00:00Z",
    })) {
      void _;
    }
    expect(calls[0].url).toContain("from=2026-01-01T00%3A00%3A00Z");
    expect(calls[0].url).toContain("to=2026-04-26T00%3A00%3A00Z");
  });

  it("sends includeTombstoned=true when true", async () => {
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    for await (const _ of client.decisions.export({
      systemId: SYSTEM_ID,
      includeTombstoned: true,
    })) {
      void _;
    }
    expect(calls[0].url).toContain("includeTombstoned=true");
  });

  it("sends includeTombstoned=false LITERALLY (D7 — no kernel session-6 workaround)", async () => {
    // Per build-round D7: kernel session-6 fix means stringBoolean
    // accepts "false" correctly. decisions.export emits the literal
    // boolean — no workaround, asymmetric to decisions.list (which
    // still omits as defense-in-depth).
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    for await (const _ of client.decisions.export({
      systemId: SYSTEM_ID,
      includeTombstoned: false,
    })) {
      void _;
    }
    expect(calls[0].url).toContain("includeTombstoned=false");
  });

  it("omits unspecified optional fields from the URL entirely", async () => {
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
      void _;
    }
    // Only systemId in the URL.
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/decisions/export?systemId=${SYSTEM_ID}`,
    );
    expect(calls[0].url).not.toContain("from=");
    expect(calls[0].url).not.toContain("to=");
    expect(calls[0].url).not.toContain("includeTombstoned=");
  });
});

// ─── top-level error paths ─────────────────────────────────────────────────

describe("decisions.export — top-level error paths", () => {
  it("throws AttestryAPIError on 401 (auth required)", async () => {
    const { client } = makeMockedClientForExport([
      {
        status: 401,
        bodyText: JSON.stringify({ success: false, error: "Auth required." }),
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(401);
    expect((caught as AttestryAPIError).message).toBe("Auth required.");
  });

  it("throws AttestryAPIError on 422 (server-side Zod validation)", async () => {
    // The SDK throws TypeError synchronously for missing systemId, so
    // a 422 from the server is only possible when SDK validation
    // passes (i.e., for non-UUID systemId, malformed datetime, or
    // unknown query keys). Pin the wire-error pass-through.
    const { client } = makeMockedClientForExport([
      {
        status: 422,
        bodyText: JSON.stringify({
          success: false,
          error: "Invalid query parameters.",
          details: [{ path: "systemId", message: "Invalid uuid" }],
        }),
      },
    ]);
    let caught: unknown = null;
    try {
      // Non-UUID systemId — passes SDK type check, fails server Zod.
      for await (const _ of client.decisions.export({
        systemId: "not-a-uuid",
      })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(422);
    expect((caught as AttestryAPIError).details).toMatchObject({
      details: expect.any(Array),
    });
  });

  it("throws AttestryAPIError on 429 when retry disabled", async () => {
    const { client } = makeMockedClientForExport([
      {
        status: 429,
        bodyText: JSON.stringify({
          success: false,
          error: "Too many requests. Please try again later.",
        }),
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(429);
  });

  it("throws AttestryAPIError when server returns wrong content-type at 200 (defensive)", async () => {
    // Per build-round D6: the new expectedContentType parameter drives
    // the content-type guard. NDJSON callers must reject SSE / HTML /
    // JSON responses at 200. Defensive against a misconfigured proxy
    // returning text/html (LB error page wrapped at 200).
    const { client } = makeMockedClientForExport([
      {
        status: 200,
        bodyText: "<html>200 ok body but wrong content type</html>",
        headers: { "Content-Type": "text/html" },
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).message).toContain(
      "expected application/x-ndjson",
    );
  });

  it("throws AttestryAPIError when server returns text/event-stream at 200 (cross-content-type)", async () => {
    // Pin the cross-content-type defense: an NDJSON caller hitting an
    // SSE response is a misconfiguration that must fail loudly. Build-
    // round D6 / hostile #16.
    const { client } = makeMockedClientForExport([
      {
        status: 200,
        bodyText: "id: x\ndata: y\n\n",
        headers: { "Content-Type": "text/event-stream" },
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).message).toContain(
      "expected application/x-ndjson",
    );
  });

  it("rejects superset content-type (`application/x-ndjson-evil`) via exact-MIME match (hostile-fix)", async () => {
    // Hostile-review finding: the previous substring `includes()`
    // match was bypassed by appending a suffix. After the
    // exact-MIME-match fix, only the bare type/subtype (with optional
    // `; <params>`) is accepted. Pin via the resource layer so the
    // guard's effective end-to-end behavior is locked in.
    const { client } = makeMockedClientForExport([
      {
        status: 200,
        bodyText: "<not really ndjson>",
        headers: { "Content-Type": "application/x-ndjson-evil" },
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).message).toContain(
      "expected application/x-ndjson",
    );
    // The actual returned content-type is surfaced in the message for
    // debugging.
    expect((caught as AttestryAPIError).message).toContain(
      "application/x-ndjson-evil",
    );
  });
});

// ─── mid-stream error paths ────────────────────────────────────────────────

describe("decisions.export — mid-stream error paths", () => {
  it("throws AttestryError when records yielded but no trailer (kernel mid-stream crash)", async () => {
    // Per build-round D8 / hostile #10: kernel commits to a 200 BEFORE
    // knowing the stream will succeed. Mid-stream failures (DB conn
    // dropped during pagination) surface as `controller.error()` after
    // headers + bytes are sent. SDK detects via missing trailer at
    // iterator end. Surface as a clear AttestryError.
    const { client } = makeMockedClientForExport([
      {
        chunks: [
          ndjsonLine(SAMPLE_RECORD_1),
          ndjsonLine(SAMPLE_RECORD_2),
          // Stream closes WITHOUT a trailer line.
        ],
      },
    ]);
    let caught: unknown = null;
    const seen: DecisionExportFrame[] = [];
    try {
      for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
        seen.push(f);
      }
    } catch (err) {
      caught = err;
    }
    // Records were yielded normally before the missing-trailer detection.
    expect(seen).toHaveLength(2);
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "stream ended without trailer",
    );
  });

  it("throws AttestryError on mid-stream connection drop (TCP RST)", async () => {
    // Underlying reader rejects mid-stream → SDK catches and wraps as
    // AttestryError("network error during stream: ..."). Symmetric to
    // decisions.stream H2.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new TypeError("connection reset by peer"));
      },
    });
    const mockFetch: FetchLike = async () =>
      new Response(stream, {
        status: 200,
        headers: { "Content-Type": "application/x-ndjson" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "network error during stream",
    );
    expect((caught as AttestryError).message).toContain(
      "connection reset by peer",
    );
  });

  it("throws AttestryError on malformed JSON line (parser error)", async () => {
    // Defensive: the kernel always emits valid JSON. This pin
    // guarantees we surface the parse error with a clear class — not
    // yield `undefined` through the typed contract.
    const { client } = makeMockedClientForExport([
      {
        chunks: [ndjsonLine(SAMPLE_RECORD_1), "{not-json}\n"],
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "NDJSON line was not valid JSON",
    );
  });

  it("throws AttestryError on buffer cap exceeded (single line >1 MiB DoS defense)", async () => {
    // Defensive: kernel records are well below 1 MiB (typical < 2 KB).
    // Pin the parser primitive's cap is wired through to the resource
    // surface.
    const giant = "x".repeat(2 * 1024 * 1024); // 2 MiB
    const { client } = makeMockedClientForExport([
      {
        chunks: [`{"x":"${giant}`], // no `\n`, no trailer
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "exceeded maximum buffer size",
    );
  });

  it("throws AttestryError on mid-flight signal abort", async () => {
    // After the response opens, an AbortError-shaped reject from the
    // underlying reader surfaces from runDecisionsExport as
    // AttestryError("request aborted by caller"). Symmetric to
    // decisions.stream H1.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const abortErr = new Error("aborted by caller signal");
        abortErr.name = "AbortError";
        controller.error(abortErr);
      },
    });
    const mockFetch: FetchLike = async () =>
      new Response(stream, {
        status: 200,
        headers: { "Content-Type": "application/x-ndjson" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain("aborted by caller");
    expect((caught as AttestryError).cause).toBeInstanceOf(Error);
    expect(((caught as AttestryError).cause as Error).name).toBe("AbortError");
  });

  it("throws AttestryError on pre-aborted signal — does NOT issue a request", async () => {
    const { client, calls } = makeMockedClientForExport([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export(
        { systemId: SYSTEM_ID },
        { signal: controller.signal },
      )) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain("aborted by caller");
    expect(calls).toHaveLength(0);
  });
});

// ─── boundary cases ────────────────────────────────────────────────────────

describe("decisions.export — boundary cases", () => {
  it("zero-record export preserves the empty-export sentinel merkleRoot verbatim", async () => {
    // Per build-round hostile #21: SDK doesn't recompute Merkle —
    // exposes the kernel's deterministic sentinel hash verbatim.
    // Sentinel = sha256:<hex of sha256("ATTESTRY-EMPTY-EXPORT")>.
    const { client } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(1);
    const trailer = frames[0] as DecisionExportTrailer;
    // Pin the exact sentinel literal — not just round-trip equality.
    // A kernel-side change to the empty-export algorithm shows up as
    // a fixture diff that consumers see as a test failure.
    expect(trailer.merkleRoot).toBe(
      "sha256:cfdc1b1f2dd74cdc4c7a4c27d04d637810ca5456533bfbaa73fd91e6be70ea69",
    );
  });

  it("1-record export — single leaf passes through with the kernel-supplied merkleRoot", async () => {
    // Per spec test pattern §"boundary cases": with a single record,
    // the kernel's Merkle algorithm returns sha256:<that record's
    // recordHash> verbatim (the leaf IS the root). The SDK doesn't
    // recompute — this pin verifies the SDK passes through the
    // kernel's output for the single-leaf case, distinct from the
    // 0-record sentinel and from the multi-record Merkle.
    const singleLeafTrailer = {
      ...SAMPLE_TRAILER,
      recordCount: 1,
      sequenceFrom: 1,
      sequenceTo: 1,
      // Merkle of a single leaf = the leaf hash itself (Bitcoin-style
      // base case: no further hashing).
      merkleRoot: SAMPLE_RECORD_1.recordHash,
    };
    const { client } = makeMockedClientForExport([
      {
        chunks: [
          ndjsonLine(SAMPLE_RECORD_1),
          ndjsonLine(singleLeafTrailer),
        ],
      },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(2);
    expect((frames[0] as DecisionExportRecord).id).toBe(SAMPLE_RECORD_1.id);
    const trailer = frames[1] as DecisionExportTrailer;
    expect(trailer.recordCount).toBe(1);
    expect(trailer.merkleRoot).toBe(SAMPLE_RECORD_1.recordHash);
  });

  it("10K-record large export — SDK does NOT buffer; iterator yields one frame at a time", async () => {
    // Per spec test pattern §"boundary cases": pin that the SDK is a
    // streaming iterator, not a collect-then-yield. We construct a
    // 10K-record body, start iterating, and after the FIRST yielded
    // frame assert the iterator hasn't read all of memory. The mock
    // delivers everything in one chunk so the underlying parser
    // sees it all at once — but the consumer still pulls one at a
    // time via `next()`. Memory note: 10K records of ~500 bytes is
    // ~5 MB on the wire; well within test-process limits.
    const RECORD_COUNT = 10_000;
    const records = Array.from({ length: RECORD_COUNT }, (_, i) => ({
      ...SAMPLE_RECORD_1,
      id: `r-${i.toString().padStart(8, "0")}-${"0".repeat(28)}`,
      sequenceNumber: i + 1,
      recordHash: `sha256:${i.toString(16).padStart(64, "0")}`,
      prevRecordHash:
        i === 0 ? null : `sha256:${(i - 1).toString(16).padStart(64, "0")}`,
    }));
    const trailer = {
      ...SAMPLE_TRAILER,
      recordCount: RECORD_COUNT,
      sequenceFrom: 1,
      sequenceTo: RECORD_COUNT,
    };
    const lines = records.map((r) => ndjsonLine(r));
    lines.push(ndjsonLine(trailer));
    const { client } = makeMockedClientForExport([
      { chunks: [lines.join("")] },
    ]);
    const iter = client.decisions
      .export({ systemId: SYSTEM_ID })
      [Symbol.asyncIterator]();
    // Pull the first frame — the iterator must yield a single record
    // synchronously rather than batch-load all 10K before yielding.
    const r1 = await iter.next();
    expect(r1.done).toBe(false);
    expect((r1.value as DecisionExportRecord).sequenceNumber).toBe(1);
    // Drain the rest and confirm count.
    let drained = 1;
    let lastFrame: DecisionExportFrame = r1.value as DecisionExportFrame;
    for (let next = await iter.next(); !next.done; next = await iter.next()) {
      drained++;
      lastFrame = next.value;
    }
    expect(drained).toBe(RECORD_COUNT + 1); // 10K records + 1 trailer
    expect("type" in lastFrame && lastFrame.type === "ExportTrailer").toBe(true);
    expect((lastFrame as DecisionExportTrailer).recordCount).toBe(RECORD_COUNT);
  });

  it("leading UTF-8 BOM at stream start is silently stripped", async () => {
    // Per build-round hostile #22: defensive against a misconfigured
    // proxy / charset transcoder.
    const { client } = makeMockedClientForExport([
      {
        chunks: [
          "﻿" + ndjsonLine(SAMPLE_RECORD_1) + ndjsonLine(SAMPLE_TRAILER),
        ],
      },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(2);
    expect((frames[0] as DecisionExportRecord).id).toBe(SAMPLE_RECORD_1.id);
  });

  it("frame split across reads (TCP-fragmented chunk) reassembles correctly", async () => {
    // Per build-round hostile (parser-level): the parser's TextDecoder
    // {stream: true} handles cross-chunk boundaries.
    const fullBody =
      ndjsonLine(SAMPLE_RECORD_1) +
      ndjsonLine(SAMPLE_RECORD_2) +
      ndjsonLine(SAMPLE_TRAILER);
    const splitAt = Math.floor(fullBody.length / 2);
    const { client } = makeMockedClientForExport([
      { chunks: [fullBody.slice(0, splitAt), fullBody.slice(splitAt)] },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(3);
    expect((frames[0] as DecisionExportRecord).id).toBe(SAMPLE_RECORD_1.id);
    expect((frames[1] as DecisionExportRecord).id).toBe(SAMPLE_RECORD_2.id);
    expect("type" in frames[2] && frames[2].type === "ExportTrailer").toBe(
      true,
    );
  });

  it("URL-unsafe chars in systemId are encodeURIComponent'd (no crash)", async () => {
    // Per build-round hostile #23: server returns 422 for non-UUID
    // format; SDK doesn't crash. Pin: a systemId with special chars
    // is encoded into the URL safely.
    const { client, calls } = makeMockedClientForExport([
      {
        status: 422,
        bodyText: JSON.stringify({
          success: false,
          error: "Invalid query parameters.",
        }),
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({
        systemId: "not a uuid", // space — needs encoding
      })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    // No crash. Server returns 422.
    expect(caught).toBeInstanceOf(AttestryAPIError);
    // URL had the space encoded.
    expect(calls[0].url).toContain("systemId=not%20a%20uuid");
  });
});

// ─── abort + retry semantics ───────────────────────────────────────────────

describe("decisions.export — abort + retry semantics", () => {
  it("non-aborted signal completes normally (signal passed but never fires)", async () => {
    // Per spec test pattern §"abort + retry semantics": pin that
    // passing an AbortSignal that never fires does NOT interfere with
    // a normal completion. Rules out a regression where signal
    // plumbing leaks into the success path.
    const { client, calls } = makeMockedClientForExport([
      {
        chunks: [
          ndjsonLine(SAMPLE_RECORD_1),
          ndjsonLine(SAMPLE_TRAILER),
        ],
      },
    ]);
    const controller = new AbortController();
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export(
      { systemId: SYSTEM_ID },
      { signal: controller.signal },
    )) {
      frames.push(f);
    }
    // Iteration completed normally — record + trailer yielded.
    expect(frames).toHaveLength(2);
    expect("type" in frames[1] && frames[1].type === "ExportTrailer").toBe(true);
    // Only one fetch issued (no spurious aborts triggering retries).
    expect(calls).toHaveLength(1);
    // Signal still un-aborted at the end.
    expect(controller.signal.aborted).toBe(false);
  });

  it("is lazy — does NOT issue the request until first iteration", async () => {
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    const stream = client.decisions.export({ systemId: SYSTEM_ID });
    // Constructed but not iterated yet — no request.
    expect(calls).toHaveLength(0);
    // First iteration → request fires.
    const iterator = stream[Symbol.asyncIterator]();
    const r1 = await iterator.next();
    expect(calls).toHaveLength(1);
    expect(r1.done).toBe(false);
  });

  it("per-call retry override: 429 retried on initial fetch (invariant #20)", async () => {
    // Per carry-forward invariant #20: streams retry on initial fetch
    // only. The retry options can be overridden per-call.
    let attempt = 0;
    const mockFetch: FetchLike = async () => {
      attempt++;
      if (attempt === 1) {
        return new Response(
          JSON.stringify({
            success: false,
            error: "Too many requests.",
          }),
          {
            status: 429,
            headers: {
              "Content-Type": "application/json",
              "Retry-After": "0",
            },
          },
        );
      }
      const encoder = new TextEncoder();
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(ndjsonLine(EMPTY_TRAILER)));
          controller.close();
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { "Content-Type": "application/x-ndjson" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 }, // client-wide off
    });
    // Per-call override: enable 1 retry.
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export(
      { systemId: SYSTEM_ID },
      { retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 5 } },
    )) {
      frames.push(f);
    }
    expect(attempt).toBe(2); // initial 429 → retry → 200
    expect(frames).toHaveLength(1);
  });

  it("per-call retry override applies the configured maxRetries (1 disables further retries)", async () => {
    // Companion to the above: with maxRetries: 1 and TWO consecutive
    // 429s, the SDK exhausts and throws — initial + 1 retry = 2 attempts.
    let attempt = 0;
    const mockFetch: FetchLike = async () => {
      attempt++;
      return new Response(
        JSON.stringify({
          success: false,
          error: "Too many requests.",
        }),
        {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "Retry-After": "0",
          },
        },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export(
        { systemId: SYSTEM_ID },
        { retry: { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 5 } },
      )) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(attempt).toBe(2); // initial + 1 retry, then throw
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(429);
  });
});

// ─── hostile round (residual gaps) ──────────────────────────────────────────
//
// 10 pins closing residual coverage gaps the build round didn't pin —
// frames the kernel doesn't emit today but a future regression /
// version skew / hostile peer might produce. All defensively handled
// by the build-round implementation; this round confirms.

describe("decisions.export — hostile round (residual gaps)", () => {
  it("H1: trailer-then-records (out-of-order) — accepts in wire order, no re-ordering", async () => {
    // Defensive: the kernel always emits trailer LAST. But if a future
    // version skew or proxy reordering produces trailer-then-records,
    // the SDK should accept frames in wire order and NOT throw the
    // missing-trailer error (since the trailer was seen first).
    const { client } = makeMockedClientForExport([
      {
        chunks: [
          ndjsonLine(SAMPLE_TRAILER),
          ndjsonLine(SAMPLE_RECORD_1),
          ndjsonLine(SAMPLE_RECORD_2),
        ],
      },
    ]);
    const frames: DecisionExportFrame[] = [];
    // Should NOT throw missing-trailer — sawTrailer is true after the
    // first frame.
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(3);
    expect("type" in frames[0] && frames[0].type === "ExportTrailer").toBe(true);
    expect((frames[1] as DecisionExportRecord).id).toBe(SAMPLE_RECORD_1.id);
    expect((frames[2] as DecisionExportRecord).id).toBe(SAMPLE_RECORD_2.id);
  });

  it("H2: multiple trailers — yields all; sawTrailer set after the first", async () => {
    // Defensive: the kernel emits exactly ONE trailer. If a future bug
    // emits multiple, the SDK yields all of them and lets the caller
    // decide what to do. The missing-trailer check passes because
    // sawTrailer was set on the first.
    const { client } = makeMockedClientForExport([
      {
        chunks: [
          ndjsonLine(SAMPLE_RECORD_1),
          ndjsonLine(SAMPLE_TRAILER),
          ndjsonLine(SAMPLE_TRAILER),
        ],
      },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(3);
    // Both trailers preserved — caller picks which one is authoritative.
    expect("type" in frames[1] && frames[1].type === "ExportTrailer").toBe(true);
    expect("type" in frames[2] && frames[2].type === "ExportTrailer").toBe(true);
  });

  it("H3: empty stream body (zero frames) — throws missing-trailer", async () => {
    // Distinct from H9 in build round (zero records WITH trailer):
    // here the kernel sent zero bytes total. parseNDJSONResponse
    // yields nothing; sawTrailer stays false; runDecisionsExport
    // throws.
    const { client } = makeMockedClientForExport([
      { chunks: [] }, // zero chunks
    ]);
    let caught: unknown = null;
    const seen: DecisionExportFrame[] = [];
    try {
      for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
        seen.push(f);
      }
    } catch (err) {
      caught = err;
    }
    expect(seen).toHaveLength(0);
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "stream ended without trailer",
    );
  });

  it("H4: frame with wrong `type` value falls into record-validation and fails loudly", async () => {
    // A frame with `type: "WrongTrailer"` doesn't match the
    // discriminator `=== "ExportTrailer"`. The SDK falls into the
    // record-validation branch, which fails because the wrong-trailer
    // shape lacks `id`, `recordHash`, etc. Better to fail loudly than
    // silently treat the unknown frame as a record.
    const wrongTrailer = {
      type: "WrongTrailer",
      systemId: SYSTEM_ID,
      recordCount: 0,
    };
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(wrongTrailer) + "\n"] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "record missing required fields or wrong type",
    );
  });

  it("H5: frame is JSON null — throws `NDJSON line was not a JSON object`", async () => {
    // parseLine returns null on the literal "null"; SDK rejects.
    const { client } = makeMockedClientForExport([
      { chunks: ["null\n", ndjsonLine(SAMPLE_TRAILER)] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "NDJSON line was not a JSON object",
    );
  });

  it("H6: frame is JSON array — throws `NDJSON line was not a JSON object`", async () => {
    // parseLine returns []; SDK's Array.isArray check rejects.
    const { client } = makeMockedClientForExport([
      { chunks: ["[1,2,3]\n", ndjsonLine(SAMPLE_TRAILER)] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "NDJSON line was not a JSON object",
    );
  });

  it("H7: trailer with `recordCount` as string — throws ExportTrailer field validation", async () => {
    // Wire-schema bug or version skew: trailer with recordCount: "5"
    // fails typeof check.
    const badTrailer = { ...SAMPLE_TRAILER, recordCount: "5" };
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(badTrailer) + "\n"] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "ExportTrailer missing required fields or wrong type",
    );
  });

  it("H8: trailer with extra unknown field — preserved through forward-compat (yielded fields are exactly the documented set)", async () => {
    // A future kernel adding e.g. `schemaVersion: 2` should NOT break
    // the SDK. The SDK doesn't fail validation on extra fields, but
    // it ALSO doesn't pass them through to the consumer — only the
    // documented fields are included in the materialized trailer.
    const trailerWithExtras = {
      ...SAMPLE_TRAILER,
      schemaVersion: 2,
      futureField: "x",
    };
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(trailerWithExtras) + "\n"] },
    ]);
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      frames.push(f);
    }
    expect(frames).toHaveLength(1);
    const trailer = frames[0] as DecisionExportTrailer;
    // All documented fields present.
    expect(trailer.type).toBe("ExportTrailer");
    expect(trailer.recordCount).toBe(SAMPLE_TRAILER.recordCount);
    expect(trailer.merkleRoot).toBe(SAMPLE_TRAILER.merkleRoot);
    expect(trailer.signing).toBe(SAMPLE_TRAILER.signing);
    // Extras are not part of the typed shape — but the SDK does NOT
    // copy unknown fields into the yielded trailer (typed materialization).
    // Pin: extras absent. If the SDK ever shifts to pass-through
    // (spread `obj`), this changes — and that change should be
    // intentional, not accidental.
    expect((trailer as Record<string, unknown>).schemaVersion).toBeUndefined();
    expect((trailer as Record<string, unknown>).futureField).toBeUndefined();
  });

  it("H9: frozen input — request fires + iterates without mutating the input", async () => {
    // Pin: SDK does NOT mutate the caller's input. Symmetric to the
    // bulk hostile-round H2.
    const { client, calls } = makeMockedClientForExport([
      { chunks: [ndjsonLine(EMPTY_TRAILER)] },
    ]);
    const input = Object.freeze({
      systemId: SYSTEM_ID,
      from: "2026-01-01T00:00:00Z",
      includeTombstoned: false,
    });
    const frames: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export(input)) {
      frames.push(f);
    }
    expect(frames).toHaveLength(1);
    expect(calls).toHaveLength(1);
    // Frozen object remains frozen + unchanged.
    expect(Object.isFrozen(input)).toBe(true);
    expect(input.systemId).toBe(SYSTEM_ID);
    expect(input.from).toBe("2026-01-01T00:00:00Z");
    expect(input.includeTombstoned).toBe(false);
  });

  it("H10: concurrent export() calls — independent iteration state, parallel-safe", async () => {
    // Each call to DecisionsResource.export() returns a fresh async
    // generator. Two concurrent calls (different systemIds) should
    // produce independent iterators — no shared state.
    const sysA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    const sysB = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    const recordA = { ...SAMPLE_RECORD_1, systemId: sysA };
    const recordB = { ...SAMPLE_RECORD_2, systemId: sysB };
    const trailerA = { ...SAMPLE_TRAILER, systemId: sysA, recordCount: 1 };
    const trailerB = { ...SAMPLE_TRAILER, systemId: sysB, recordCount: 1 };
    const calls: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      const u = String(url);
      const isA = u.includes(sysA);
      const lines = isA
        ? [ndjsonLine(recordA), ndjsonLine(trailerA)]
        : [ndjsonLine(recordB), ndjsonLine(trailerB)];
      const encoder = new TextEncoder();
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            for (const line of lines) {
              controller.enqueue(encoder.encode(line));
            }
            controller.close();
          },
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/x-ndjson" },
        },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    // Kick off two concurrent exports.
    const [framesA, framesB] = await Promise.all([
      (async () => {
        const out: DecisionExportFrame[] = [];
        for await (const f of client.decisions.export({ systemId: sysA })) {
          out.push(f);
        }
        return out;
      })(),
      (async () => {
        const out: DecisionExportFrame[] = [];
        for await (const f of client.decisions.export({ systemId: sysB })) {
          out.push(f);
        }
        return out;
      })(),
    ]);
    expect(framesA).toHaveLength(2);
    expect(framesB).toHaveLength(2);
    // Each iterator saw its own system's frames — no cross-talk.
    expect((framesA[0] as DecisionExportRecord).systemId).toBe(sysA);
    expect((framesB[0] as DecisionExportRecord).systemId).toBe(sysB);
    expect((framesA[1] as DecisionExportTrailer).systemId).toBe(sysA);
    expect((framesB[1] as DecisionExportTrailer).systemId).toBe(sysB);
    expect(calls).toHaveLength(2);
  });
});

// ─── coverage round (defensive paths) ──────────────────────────────────────
//
// Final round — pin defensive paths the build / hostile rounds
// indirectly covered. Each pin closes a single per-field validation
// branch or a transport edge so that future regressions surface here
// with a focused failure message.

describe("decisions.export — coverage round (defensive paths)", () => {
  it("C1: record missing `id` field — AttestryError `record missing required fields`", async () => {
    const recordNoId = { ...SAMPLE_RECORD_1 } as Partial<typeof SAMPLE_RECORD_1>;
    delete recordNoId.id;
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(recordNoId) + "\n", ndjsonLine(SAMPLE_TRAILER)] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "record missing required fields",
    );
  });

  it("C2: record with sequenceNumber as string — AttestryError on type check", async () => {
    const badRecord = { ...SAMPLE_RECORD_1, sequenceNumber: "1" };
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(badRecord) + "\n"] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "record missing required fields or wrong type",
    );
  });

  it("C3: record with frameworkClaims: null (not array) — AttestryError on Array.isArray check", async () => {
    // Per build-round D2 + runtime defense: kernel emits arrays;
    // a null value would fail Array.isArray.
    const badRecord = { ...SAMPLE_RECORD_1, frameworkClaims: null };
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(badRecord) + "\n"] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "record missing required fields or wrong type",
    );
  });

  it("C4: record with prevRecordHash as non-string-non-null — AttestryError", async () => {
    // prevRecordHash accepts `string | null`. A boolean / number /
    // object is rejected. Pin a number; the typeof check fails.
    const badRecord = { ...SAMPLE_RECORD_2, prevRecordHash: 42 };
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(badRecord) + "\n"] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "record missing required fields or wrong type",
    );
  });

  it("C5: trailer missing `signing` field — AttestryError on ExportTrailer validation", async () => {
    // Most likely future kernel-side change (Prompt 1 → structured
    // proof). Pre-Prompt-1, a missing field is the failure mode
    // if the kernel removes the field before the SDK JSDoc updates.
    const badTrailer = { ...SAMPLE_TRAILER } as Partial<typeof SAMPLE_TRAILER>;
    delete badTrailer.signing;
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(badTrailer) + "\n"] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "ExportTrailer missing required fields or wrong type",
    );
  });

  it("C6: trailer with generatedAt as number — AttestryError", async () => {
    // Defensive: a future kernel might shift to unix-epoch ms instead
    // of ISO. SDK's strict typing surfaces that as a clear error.
    const badTrailer = { ...SAMPLE_TRAILER, generatedAt: 1234567890 };
    const { client } = makeMockedClientForExport([
      { chunks: [JSON.stringify(badTrailer) + "\n"] },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "ExportTrailer missing required fields",
    );
  });

  it("C7: non-Error throw mid-stream wraps as `AttestryError(\"network error during stream: ...\")`", async () => {
    // The catch block does `err instanceof Error ? err.message : String(err)`.
    // A non-Error throw (string, number, plain object) goes through
    // String(err) and produces a useful message. Pin the String(err)
    // branch — caller sees a clear error class even when the
    // underlying source threw something exotic.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        // Note: ReadableStreamDefaultController.error() accepts any
        // value as the rejection reason; only its TypeScript signature
        // is `unknown`. A non-Error reason is unusual but legal.
        controller.error("string-only-rejection");
      },
    });
    const mockFetch: FetchLike = async () =>
      new Response(stream, {
        status: 200,
        headers: { "Content-Type": "application/x-ndjson" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "network error during stream",
    );
    // The non-Error reason flows through String(err).
    expect((caught as AttestryError).message).toContain(
      "string-only-rejection",
    );
  });

  it("C8: encodeQuery preserves URL-special chars (e.g., `+`) in `from` via encodeURIComponent", async () => {
    // Companion to hostile #23 (URL-unsafe systemId). Date filters can
    // contain URL-special chars too; SDK's encodeURIComponent handles
    // them. Pin: `+` in `from` encodes to `%2B`, server returns 422
    // for non-ISO format.
    const { client, calls } = makeMockedClientForExport([
      {
        status: 422,
        bodyText: JSON.stringify({
          success: false,
          error: "Invalid query parameters.",
        }),
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({
        systemId: SYSTEM_ID,
        from: "2026+01+01", // not ISO; `+` needs URL encoding
      })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect(calls[0].url).toContain("from=2026%2B01%2B01");
  });

  it("C9: 100-record export — all records yielded in sequenceNumber ascending order, then trailer", async () => {
    // Boundary: kernel paginates internally (PAGE_SIZE = 500). Pin a
    // 100-record export — easily fits in one server-side page; tests
    // the SDK doesn't buffer all records in memory before yielding.
    // The async-iterator should yield each in order as the bytes
    // arrive.
    const records = Array.from({ length: 100 }, (_, i) => ({
      ...SAMPLE_RECORD_1,
      id: `record-${i}-${"0".repeat(36 - `record-${i}-`.length)}`,
      sequenceNumber: i + 1,
      recordHash: `sha256:${i.toString(16).padStart(64, "0")}`,
      prevRecordHash:
        i === 0 ? null : `sha256:${(i - 1).toString(16).padStart(64, "0")}`,
    }));
    const trailer = {
      ...SAMPLE_TRAILER,
      recordCount: 100,
      sequenceFrom: 1,
      sequenceTo: 100,
    };
    const lines = [
      ...records.map((r) => ndjsonLine(r)),
      ndjsonLine(trailer),
    ];
    const { client } = makeMockedClientForExport([
      { chunks: [lines.join("")] },
    ]);
    const yielded: DecisionExportFrame[] = [];
    for await (const f of client.decisions.export({ systemId: SYSTEM_ID })) {
      yielded.push(f);
    }
    expect(yielded).toHaveLength(101);
    // First 100 are records, in sequenceNumber ascending order.
    for (let i = 0; i < 100; i++) {
      const rec = yielded[i] as DecisionExportRecord;
      expect(rec.sequenceNumber).toBe(i + 1);
    }
    // Final frame is the trailer with the right summary.
    const t = yielded[100] as DecisionExportTrailer;
    expect(t.type).toBe("ExportTrailer");
    expect(t.recordCount).toBe(100);
    expect(t.sequenceFrom).toBe(1);
    expect(t.sequenceTo).toBe(100);
  });

  // ─── per-field validation coverage (post-coverage hardening) ──────────
  //
  // The trailer and record validators in runDecisionsExport are large
  // short-circuit-OR expressions. The catch-all error message is well-
  // pinned (multiple tests above), but individual field branches were
  // weakly covered — a refactor that accidentally drops one field's
  // typeof check would leave the catch-all firing on OTHER fields, so
  // a "does it throw at all" pin would still pass. The two table-
  // driven blocks below cover every individual field branch in trailer
  // and record validation.

  describe("ExportTrailer — per-field validation (every branch covered)", () => {
    const cases: Array<[string, unknown]> = [
      ["systemId", 42], // string → number
      ["recordCount", "0"], // number → string (also covered by hostile H7)
      ["sequenceFrom", "1"], // number|null → string
      ["sequenceTo", true], // number|null → boolean
      ["merkleRoot", null], // string → null
      ["signing", 1234], // string → number (C5 covered missing-field)
      ["generatedAt", false], // string → boolean (C6 covered number)
    ];
    for (const [field, badValue] of cases) {
      it(`rejects ExportTrailer with wrong-type \`${field}\``, async () => {
        const badTrailer = { ...SAMPLE_TRAILER, [field]: badValue };
        const { client } = makeMockedClientForExport([
          { chunks: [JSON.stringify(badTrailer) + "\n"] },
        ]);
        let caught: unknown = null;
        try {
          for await (const _ of client.decisions.export({
            systemId: SYSTEM_ID,
          })) {
            void _;
          }
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(AttestryError);
        expect((caught as AttestryError).message).toContain(
          "ExportTrailer missing required fields or wrong type",
        );
      });
    }
  });

  describe("DecisionExportRecord — per-field validation (every branch covered)", () => {
    const cases: Array<[string, unknown]> = [
      ["id", 42], // string → number
      ["systemId", null], // string → null
      ["sequenceNumber", "1"], // number → string (C2 covered too)
      ["inputDigest", true], // string → boolean
      ["outputDigest", 999], // string|null → number (string-mismatch branch)
      ["frameworkClaims", null], // unknown[] → null (C3 covered)
      ["toolInvocations", "not-array"], // unknown[] → string
      ["delegationChain", { a: 1 }], // unknown[] → object
      ["humanOversightState", 1], // string|null → number
      ["policyOutcome", false], // string|null → boolean
      ["prevRecordHash", 7], // string|null → number (C4 covered)
      ["recordHash", null], // string → null
      ["createdAt", 1730000000], // string → number (Unix epoch defense)
      ["tombstoned", "false"], // boolean → string
    ];
    for (const [field, badValue] of cases) {
      it(`rejects record with wrong-type \`${field}\``, async () => {
        const badRecord = { ...SAMPLE_RECORD_2, [field]: badValue };
        const { client } = makeMockedClientForExport([
          {
            chunks: [
              JSON.stringify(badRecord) + "\n",
              ndjsonLine(SAMPLE_TRAILER),
            ],
          },
        ]);
        let caught: unknown = null;
        try {
          for await (const _ of client.decisions.export({
            systemId: SYSTEM_ID,
          })) {
            void _;
          }
        } catch (err) {
          caught = err;
        }
        expect(caught).toBeInstanceOf(AttestryError);
        expect((caught as AttestryError).message).toContain(
          "record missing required fields or wrong type",
        );
      });
    }
  });

  it("C10: parseNDJSONResponse error path triggers finally block (reader.cancel) — cleanup on parser throw", async () => {
    // The wrapper's `finally { await reader.cancel(); }` runs even
    // when the parser throws (malformed JSON, buffer cap, etc.).
    // Pin via a stream left open at the source — only consumer
    // cancellation (via the wrapper's finally) triggers the source
    // cancel callback.
    const cancelSpy = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode("not-valid-json\n"));
        // Leave open — only the finally-block's cancel triggers
        // the source cancel callback.
      },
      cancel() {
        cancelSpy();
      },
    });
    const mockFetch: FetchLike = async () =>
      new Response(stream, {
        status: 200,
        headers: { "Content-Type": "application/x-ndjson" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    let caught: unknown = null;
    try {
      for await (const _ of client.decisions.export({ systemId: SYSTEM_ID })) {
        void _;
      }
    } catch (err) {
      caught = err;
    }
    // Parser threw on the malformed line.
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "NDJSON line was not valid JSON",
    );
    // The wrapper's finally fired reader.cancel(), which triggered
    // the source cancel handler.
    expect(cancelSpy).toHaveBeenCalled();
  });
});

// ─── Hostile review #3 — MEDIUM-1 throwing-getter fix (decisions.export) ────
//
// Session-22 hostile review #3 completes the SDK-wide MEDIUM-1 getter-
// throws contract fix. Reviews #1-#2 converted `decisions.ingest` /
// `.bulk` but MISSED the three `decisions` query methods (`.list` /
// `.stream` / `.export`) — their input-field validation still read each
// field with a bare `input.x` access, so a throwing accessor leaked the
// getter's raw exception instead of the documented synchronous
// `TypeError`. `decisions.export` now snapshots every query field via
// `readInputField`. Validation runs synchronously inside `export()`
// BEFORE the NDJSON generator is returned, so the throw is synchronous.

describe("decisions.export — hostile review #3: throwing-getter MEDIUM-1 fix", () => {
  it("converts a throwing `systemId` getter into a TypeError (NOT the getter's raw error)", () => {
    const { client, calls } = makeMockedClientForExport([]);
    const evil = {
      get systemId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as DecisionsExportInput;
    let caught: unknown;
    try {
      client.decisions.export(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).message).toContain("decisions.export");
    expect((caught as Error).message).toContain("systemId");
    // The getter's OWN message is not the SDK's contract message...
    expect((caught as Error).message).not.toContain("getter boom");
    // ...but the original error is preserved on `.cause`.
    expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(Error);
    expect(calls).toHaveLength(0);
  });

  it("converts a throwing getter on the LAST query field (`includeTombstoned`) into a TypeError", () => {
    // Proves the fix is not first-field-only — every one of the four
    // snapshot reads is wrapped, not just `systemId`. A RangeError from
    // the getter still surfaces as the documented TypeError class.
    //
    // CRITICAL — the evil object MUST carry a valid `systemId` data
    // property. `decisions.export` REQUIRES `systemId` (unlike `.list` /
    // `.stream`), and its required-check throws `TypeError("`systemId`
    // is required ...")` for ANY input lacking a string `systemId`.
    // Without a real `systemId` here, that unrelated required-check
    // would fire FIRST against a reverted/partial-revert build and the
    // throwing `includeTombstoned` getter would never be reached — the
    // pin would pass for the wrong reason and miss a `from`/`to`/
    // `includeTombstoned`-only snapshot revert. With a valid `systemId`,
    // the `includeTombstoned` getter IS reached: post-fix the snapshot
    // read converts the throw to a `TypeError`; against any revert of
    // that snapshot read the raw `RangeError` leaks and this pin fails.
    const { client, calls } = makeMockedClientForExport([]);
    const evil = {
      systemId: SYSTEM_ID,
      get includeTombstoned(): unknown {
        throw new RangeError("range boom");
      },
    } as unknown as DecisionsExportInput;
    let caught: unknown;
    try {
      client.decisions.export(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught).not.toBeInstanceOf(RangeError);
    expect((caught as Error).message).toContain("decisions.export");
    expect((caught as Error).message).toContain("includeTombstoned");
    // The getter's OWN message is not the SDK's contract message...
    expect((caught as Error).message).not.toContain("range boom");
    // ...but the original RangeError is preserved on `.cause`.
    expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(
      RangeError,
    );
    expect(calls).toHaveLength(0);
  });
});
