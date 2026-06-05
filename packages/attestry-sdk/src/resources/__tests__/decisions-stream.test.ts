import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  DecisionStreamEvent,
  DecisionsStreamInput,
} from "../decisions.js";
import type { FetchLike } from "../../types.js";

// ─── decisions.stream — SSE async-iterator ─────────────────────────────────
//
// First real SSE-backed resource on `@attestry/sdk`. Validates the
// `Response.body!.getReader()` + `TextDecoder` parser pattern that
// future streaming resources will reuse.
//
// Wire shape (from `src/lib/decisions/stream-cursor.ts` `formatSSEFrame`):
//
//   id: <base64url-cursor>\nevent: decision.appended\ndata: <json>\n\n
//
// Heartbeat: `: heartbeat\n\n` (comment frame, parser-suppressed).
//
// Auth + headers: `x-api-key` (transport) + `Accept: text/event-stream`
// (stream transport). No Content-Type (GET, no body).

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

/**
 * Build a Response whose body streams the given SSE chunks (each chunk
 * is one or more frames, possibly split mid-frame). The chunks ARE NOT
 * concatenated client-side — each shows up to the parser as a separate
 * `reader.read()` value, so this is the right tool to test
 * "frame split across reads" semantics.
 */
function makeSSEStreamResponse(
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
    headers: { "Content-Type": "text/event-stream", ...(init.headers ?? {}) },
  });
}

function makeMockedClientForStream(
  responses: Array<{ chunks?: string[]; status?: number; headers?: Record<string, string>; bodyText?: string }>,
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
      return makeSSEStreamResponse(r.chunks, {
        status: r.status,
        headers: r.headers,
      });
    }
    // Non-SSE response (used for error-path tests).
    return new Response(r.bodyText ?? "", {
      status: r.status ?? 200,
      headers: { "Content-Type": "application/json", ...(r.headers ?? {}) },
    });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    // Retry tests live in src/__tests__/retry.test.ts. Stream tests
    // disable retry so a 429-mock test doesn't hang on backoff and then
    // accidentally consume the next mock response.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const SAMPLE_EVENT_1 = {
  id: "11111111-1111-1111-1111-111111111111",
  systemId: "33333333-3333-3333-3333-333333333333",
  sequenceNumber: 1,
  recordHash:
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  prevRecordHash: null,
  tombstoned: false,
  createdAt: "2026-04-27T00:00:00.000Z",
};
const SAMPLE_EVENT_2 = {
  id: "22222222-2222-2222-2222-222222222222",
  systemId: "33333333-3333-3333-3333-333333333333",
  sequenceNumber: 2,
  recordHash:
    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  prevRecordHash:
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  tombstoned: false,
  createdAt: "2026-04-27T00:00:01.000Z",
};

const CURSOR_1 = "eyJjIjoiMjAyNi0wNC0yN1QwMDowMDowMC4wMDBaIiwiaSI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSJ9";
const CURSOR_2 = "eyJjIjoiMjAyNi0wNC0yN1QwMDowMDowMS4wMDBaIiwiaSI6IjIyMjIyMjIyLTIyMjItMjIyMi0yMjIyLTIyMjIyMjIyMjIyMiJ9";

function frame(cursor: string, data: object, type = "decision.appended"): string {
  return `id: ${cursor}\nevent: ${type}\ndata: ${JSON.stringify(data)}\n\n`;
}

describe("decisions.stream — happy path", () => {
  it("yields each SSE event as a typed DecisionStreamEvent", async () => {
    const { client, calls } = makeMockedClientForStream([
      {
        chunks: [
          frame(CURSOR_1, SAMPLE_EVENT_1),
          frame(CURSOR_2, SAMPLE_EVENT_2),
        ],
      },
    ]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(2);
    expect(events[0]).toEqual({
      ...SAMPLE_EVENT_1,
      eventId: CURSOR_1,
      eventType: "decision.appended",
    });
    expect(events[1]).toEqual({
      ...SAMPLE_EVENT_2,
      eventId: CURSOR_2,
      eventType: "decision.appended",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/stream",
    );
  });

  it("sends Accept: text/event-stream + x-api-key (NOT Content-Type — GET, no body)", async () => {
    const { client, calls } = makeMockedClientForStream([{ chunks: [] }]);
    for await (const _e of client.decisions.stream()) {
      void _e;
    }
    expect(calls[0].headers.get("Accept")).toBe("text/event-stream");
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Content-Type")).toBeNull();
  });

  it("encodes systemId as ?systemId=<value> on the URL", async () => {
    const { client, calls } = makeMockedClientForStream([{ chunks: [] }]);
    for await (const _e of client.decisions.stream({
      systemId: "abc-123",
    })) {
      void _e;
    }
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/stream?systemId=abc-123",
    );
  });

  it("forwards lastEventId as the Last-Event-ID header", async () => {
    const { client, calls } = makeMockedClientForStream([{ chunks: [] }]);
    for await (const _e of client.decisions.stream({
      lastEventId: CURSOR_1,
    })) {
      void _e;
    }
    expect(calls[0].headers.get("Last-Event-ID")).toBe(CURSOR_1);
    // No query string — lastEventId rides on the header, not the URL.
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/stream",
    );
  });

  it("supports systemId + lastEventId together (filtered resume)", async () => {
    const { client, calls } = makeMockedClientForStream([{ chunks: [] }]);
    for await (const _e of client.decisions.stream({
      systemId: "33333333-3333-3333-3333-333333333333",
      lastEventId: CURSOR_1,
    })) {
      void _e;
    }
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/stream?systemId=33333333-3333-3333-3333-333333333333",
    );
    expect(calls[0].headers.get("Last-Event-ID")).toBe(CURSOR_1);
  });
});

describe("decisions.stream — heartbeat + frame edge cases", () => {
  it("silently skips heartbeat (`: heartbeat`) frames", async () => {
    // Pin the kernel's HEARTBEAT_FRAME (`: heartbeat\n\n`) is consumed
    // and never yielded as an event. Without this, every 30s the
    // consumer would get an undefined-looking event.
    const { client } = makeMockedClientForStream([
      {
        chunks: [
          ": heartbeat\n\n",
          frame(CURSOR_1, SAMPLE_EVENT_1),
          ": heartbeat\n\n",
          frame(CURSOR_2, SAMPLE_EVENT_2),
          ": heartbeat\n\n",
        ],
      },
    ]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.id)).toEqual([
      SAMPLE_EVENT_1.id,
      SAMPLE_EVENT_2.id,
    ]);
  });

  it("reassembles a frame split across multiple reads (TCP-fragmented chunk)", async () => {
    // The TCP layer can deliver any byte split. Without the parser's
    // buffer carry-over, a frame split mid-`data:` would either error
    // or silently drop. Pin: the SDK reassembles correctly.
    const fullFrame = frame(CURSOR_1, SAMPLE_EVENT_1);
    const splitAt = Math.floor(fullFrame.length / 2);
    const { client } = makeMockedClientForStream([
      {
        chunks: [fullFrame.slice(0, splitAt), fullFrame.slice(splitAt)],
      },
    ]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(1);
    expect(events[0].id).toBe(SAMPLE_EVENT_1.id);
  });

  it("reassembles a multibyte UTF-8 character split across reads", async () => {
    // `TextDecoder({stream: true})` is required to preserve continuation
    // bytes that span chunk boundaries. Smoke-test: emit an event whose
    // (synthetic) data field includes a 4-byte UTF-8 char and split the
    // bytes mid-character.
    const eventWithEmoji = {
      ...SAMPLE_EVENT_1,
      systemId: "system-✓-validated",
    };
    const fullFrame = frame(CURSOR_1, eventWithEmoji);
    const fullBytes = new TextEncoder().encode(fullFrame);
    // Locate the ✓ byte sequence (e2 9c 93) and split mid-sequence.
    let splitIdx = -1;
    for (let i = 0; i < fullBytes.length - 2; i++) {
      if (
        fullBytes[i] === 0xe2 &&
        fullBytes[i + 1] === 0x9c &&
        fullBytes[i + 2] === 0x93
      ) {
        splitIdx = i + 1; // mid-character split
        break;
      }
    }
    expect(splitIdx).toBeGreaterThan(0);
    const chunk1 = fullBytes.slice(0, splitIdx);
    const chunk2 = fullBytes.slice(splitIdx);
    // Re-create as a Response with two raw-byte chunks.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(chunk1);
        controller.enqueue(chunk2);
        controller.close();
      },
    });
    const calls: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      return new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 }, // see helper above for rationale
    });
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(1);
    expect(events[0].systemId).toBe("system-✓-validated");
  });

  it("ends iterator cleanly on empty stream (server returns no frames)", async () => {
    const { client } = makeMockedClientForStream([{ chunks: [] }]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(0);
  });
});

describe("decisions.stream — error paths", () => {
  it("throws AttestryAPIError on 401 — before any event is yielded", async () => {
    const { client } = makeMockedClientForStream([
      {
        status: 401,
        bodyText: JSON.stringify({ success: false, error: "Auth required." }),
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(401);
    expect((caught as AttestryAPIError).message).toBe("Auth required.");
  });

  it("throws AttestryAPIError on 429 (rate limit)", async () => {
    const { client } = makeMockedClientForStream([
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
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(429);
  });

  it("throws AttestryAPIError on 400 (malformed Last-Event-ID — server-side validation)", async () => {
    const { client } = makeMockedClientForStream([
      {
        status: 400,
        bodyText: JSON.stringify({
          success: false,
          error: "Invalid Last-Event-ID: Cursor is not valid base64url",
        }),
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream({
        lastEventId: "not-a-cursor",
      })) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(400);
    expect((caught as AttestryAPIError).message).toMatch(/Last-Event-ID/);
  });

  it("throws AttestryAPIError when server returns wrong content-type (defensive proxy guard)", async () => {
    // A misconfigured proxy returning text/html (e.g. a load-balancer
    // 200-with-error-page) at status 200 would otherwise silently feed
    // garbage to the SSE parser. The transport's content-type check
    // fails fast.
    const { client } = makeMockedClientForStream([
      {
        status: 200,
        bodyText: "<html>200 ok body but wrong content type</html>",
        headers: { "Content-Type": "text/html" },
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).message).toContain(
      "expected text/event-stream",
    );
  });

  it("throws AttestryError on pre-aborted signal — does NOT issue a request", async () => {
    const { client, calls } = makeMockedClientForStream([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream(undefined, {
        signal: controller.signal,
      })) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain("aborted by caller");
    expect(calls).toHaveLength(0);
  });

  it("throws AttestryError on network failure (ECONNREFUSED, DNS fail)", async () => {
    const failingClient = new AttestryClient({
      apiKey: "k",
      baseUrl: "https://test.attestry.local",
      fetch: vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }) as unknown as FetchLike,
    });
    let caught: unknown = null;
    try {
      for await (const _e of failingClient.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain("ECONNREFUSED");
  });

  it("throws AttestryError when SSE frame data is invalid JSON", async () => {
    // Defensive: kernel always emits valid JSON. This pin guarantees we
    // surface the parse error with a clear class — not yield `undefined`
    // through the typed contract.
    const { client } = makeMockedClientForStream([
      {
        chunks: [`id: ${CURSOR_1}\nevent: decision.appended\ndata: {not-json}\n\n`],
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "SSE frame data was not valid JSON",
    );
  });

  it("throws AttestryError when SSE frame is missing the `id:` line (spec-diff S2)", async () => {
    // Defensive: the kernel's formatSSEFrame ALWAYS emits `id: <cursor>`,
    // but if a future server change ever drops it, the SDK should
    // fail-fast rather than silently set eventId to "" (which would
    // crash the consumer's reconnection attempt with our own
    // "lastEventId must be a non-empty string" guard at the next call).
    const { client } = makeMockedClientForStream([
      {
        chunks: [
          // Frame with NO `id:` line — only event + data.
          `event: decision.appended\ndata: ${JSON.stringify(SAMPLE_EVENT_1)}\n\n`,
        ],
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "missing required `id:` field",
    );
  });

  it("throws AttestryError when SSE payload is missing required fields", async () => {
    // Pin: SDK is the typed boundary. A schema-broken server payload
    // produces a clear error, not a `yield` of `undefined as string`.
    const { client } = makeMockedClientForStream([
      {
        chunks: [
          `id: ${CURSOR_1}\nevent: decision.appended\ndata: {"id":"x"}\n\n`,
        ],
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "missing required fields",
    );
  });
});

describe("decisions.stream — input validation (pre-fetch)", () => {
  it("throws TypeError for empty systemId — does NOT issue a request", async () => {
    const { client, calls } = makeMockedClientForStream([]);
    expect(() => client.decisions.stream({ systemId: "" })).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId — does NOT issue a request", async () => {
    const { client, calls } = makeMockedClientForStream([]);
    expect(() =>
      client.decisions.stream({ systemId: 42 as unknown as string }),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.stream({ systemId: null as unknown as string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty lastEventId — does NOT issue a request", async () => {
    const { client, calls } = makeMockedClientForStream([]);
    expect(() =>
      client.decisions.stream({ lastEventId: "" }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string lastEventId — does NOT issue a request", async () => {
    const { client, calls } = makeMockedClientForStream([]);
    expect(() =>
      client.decisions.stream({ lastEventId: 7 as unknown as string }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });
});

describe("decisions.stream — hostile-round defenses", () => {
  it("H1: mid-iteration AbortError surfaces as AttestryError, not raw DOMException", async () => {
    // Reader.read() rejects with `{name: "AbortError"}` when fetch's
    // signal fires after the body started streaming. Without the
    // wrapping try/catch in runDecisionsStream, that AbortError would
    // bubble up untyped to the consumer — inconsistent with the
    // pre-aborted path which surfaces as AttestryError.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        // Error the controller with an AbortError-shaped exception —
        // simulates `signal.abort()` propagating to the underlying
        // reader DURING iteration (post-getReader, pre-first-read).
        // The previous build-round pin covered pre-fetch abort
        // (synchronous throw before `fetch` is called); this one
        // covers post-fetch / pre-first-frame abort, which goes
        // through a different error path entirely (rejected read()
        // rather than rejected fetch).
        const abortErr = new Error("aborted by caller signal");
        abortErr.name = "AbortError";
        controller.error(abortErr);
      },
    });
    const mockFetch: FetchLike = async () =>
      new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 }, // see helper above for rationale
    });
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    // The pin: AbortError gets wrapped as AttestryError, not bubbled raw.
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain("aborted by caller");
    // Original error preserved as cause for debugging.
    expect((caught as AttestryError).cause).toBeInstanceOf(Error);
    expect(((caught as AttestryError).cause as Error).name).toBe(
      "AbortError",
    );
  });

  it("H2: mid-iteration network error surfaces as AttestryError with `network error during stream` prefix", async () => {
    // TCP RST / proxy hang-up mid-stream: reader.read() rejects with
    // a generic Error (not AbortError). Pin: this surfaces as
    // AttestryError("network error during stream: ..."), distinct from
    // the pre-iteration network-error path which says just
    // "network error: ...".
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new TypeError("connection reset by peer"));
      },
    });
    const mockFetch: FetchLike = async () =>
      new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 }, // see helper above for rationale
    });
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
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

  it("H3: unbounded frame (no boundary) is rejected — DoS defense", async () => {
    // Server emits a single `data:` line that just keeps growing — no
    // `\n\n` terminator. Without the buffer cap, the parser would
    // accumulate until the consumer's process OOMs. Pin: the parser
    // throws AttestryError when buffer exceeds 1 MiB (default).
    const giantPayload = "x".repeat(2 * 1024 * 1024); // 2 MiB
    const { client } = makeMockedClientForStream([
      {
        chunks: [`id: ${CURSOR_1}\nevent: decision.appended\ndata: ${giantPayload}`],
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "exceeded maximum buffer size",
    );
  });

  it("H4: BOM at start of stream is silently stripped", async () => {
    // A misconfigured proxy / character-set transcoder might prepend
    // U+FEFF (UTF-8 BOM) to the response body. Without stripping,
    // the first frame's first field would be `﻿id` rather than
    // `id`, the field would be unrecognized, and the frame would lose
    // its eventId — falling through to the H4 fallback. Pin: BOM is
    // stripped, frame parses cleanly.
    const { client } = makeMockedClientForStream([
      {
        chunks: ["﻿" + frame(CURSOR_1, SAMPLE_EVENT_1)],
      },
    ]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(1);
    expect(events[0].id).toBe(SAMPLE_EVENT_1.id);
    expect(events[0].eventId).toBe(CURSOR_1);
  });

  it("H5: validation error during iteration releases the underlying reader", async () => {
    // Pin: the parser's `finally` cleanup chain runs even when the
    // iteration's user code (our payload validator) throws. Without
    // it, a malformed-payload error would leak the reader.
    const cancelSpy = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        // Frame with valid SSE structure but malformed JSON payload —
        // throws AttestryError inside the validation block.
        controller.enqueue(
          encoder.encode(
            `id: ${CURSOR_1}\nevent: decision.appended\ndata: {"id":"x"}\n\n`,
          ),
        );
        // Intentionally don't close — forces the test to rely on the
        // parser's cleanup chain.
      },
      cancel() {
        cancelSpy();
      },
    });
    const mockFetch: FetchLike = async () =>
      new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 }, // see helper above for rationale
    });
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    // The for-await's finally → iter.return() → parseSSEResponse's
    // finally → reader.cancel() → underlying-stream cancel callback.
    expect(cancelSpy).toHaveBeenCalled();
  });
});

describe("decisions.stream — coverage-round defensive paths", () => {
  it("C1: empty `data:` frame is silently skipped (branch: frame.data.length === 0)", async () => {
    // Defensive: kernel's formatSSEFrame always emits a non-empty data
    // line, but a future kernel patch (or a proxy stripping body) could
    // produce a frame with `data:` and nothing after the colon. The
    // resource's `if (frame.data.length === 0) continue` skips —
    // pinning so this path stays defensive.
    const { client } = makeMockedClientForStream([
      {
        chunks: [
          // Frame with empty data line.
          `id: ${CURSOR_1}\nevent: decision.appended\ndata:\n\n`,
          // Then a real frame so the iterator yields something.
          frame(CURSOR_2, SAMPLE_EVENT_2),
        ],
      },
    ]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(1);
    expect(events[0].id).toBe(SAMPLE_EVENT_2.id);
  });

  it("C2: response with null body (204-equivalent) yields zero events cleanly", async () => {
    // parseSSEResponse short-circuits when response.body === null. The
    // browser fetch spec says 204 / 205 / 304 produce null body, but
    // these aren't valid for an SSE GET. Pin: if a misconfigured
    // upstream returns a null body at 200, the iterator ends cleanly
    // rather than crashing on getReader().
    const mockFetch: FetchLike = async () => {
      // Construct a Response with body: null (the platform allows this
      // for "no body" responses).
      return new Response(null, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 }, // see helper above for rationale
    });
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(0);
  });

  it("C3: content-type with `; charset=utf-8` parameter passes the SSE check", async () => {
    // Production proxies often append charset / boundary parameters.
    // The transport's content-type check uses `.includes("text/event-stream")`
    // — pin that "text/event-stream; charset=utf-8" and similar variants
    // pass without false-rejection.
    const { client } = makeMockedClientForStream([
      {
        chunks: [frame(CURSOR_1, SAMPLE_EVENT_1)],
        headers: { "Content-Type": "text/event-stream; charset=utf-8" },
      },
    ]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(1);
    expect(events[0].id).toBe(SAMPLE_EVENT_1.id);
  });

  it("C4: SSE `id:` value containing U+0000 NULL is dropped per W3C spec § 9.2.6", async () => {
    // Per spec: "If the field value does not contain U+0000 NULL, then
    // set the last event ID buffer to the field value. Otherwise,
    // ignore the field." Pin the dropped path: a frame with `id:`
    // containing a NULL character has its id silently discarded, then
    // falls through to runDecisionsStream's missing-`id:` validation
    // (S2 spec-diff). Throws AttestryError.
    const idWithNull = "abc" + " " + "def";
    const { client } = makeMockedClientForStream([
      {
        chunks: [
          `id: ${idWithNull}\nevent: decision.appended\ndata: ${JSON.stringify(SAMPLE_EVENT_1)}\n\n`,
        ],
      },
    ]);
    let caught: unknown = null;
    try {
      for await (const _e of client.decisions.stream()) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "missing required `id:` field",
    );
  });

  it("C4 (cont.): SSE `id:` value with spaces is ACCEPTED per spec (no over-restrictive filter)", async () => {
    // Symmetric to C4: pin that the parser does NOT reject ids with
    // spaces. The kernel emits base64url cursors (no spaces) today,
    // but the spec only forbids U+0000 NULL — and a future cursor
    // format (or a forward-compat use) shouldn't be silently broken
    // by an over-aggressive parser.
    const cursorWithSpace = "abc 123";
    const { client } = makeMockedClientForStream([
      {
        chunks: [
          `id: ${cursorWithSpace}\nevent: decision.appended\ndata: ${JSON.stringify(SAMPLE_EVENT_1)}\n\n`,
        ],
      },
    ]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(1);
    expect(events[0].eventId).toBe(cursorWithSpace);
  });

  it("C5: final unterminated frame at end-of-stream is emitted (defensive)", async () => {
    // Per SSE spec § 9.2.4: at EOF, dispatch any pending event.
    // Implementation: parseSSE's done branch flushes the trailing
    // buffer if non-empty. This handles the common case of
    // HTTP/1.1 connection-close mid-frame — better to emit an
    // under-defined event than silently drop. Pin a frame WITHOUT a
    // trailing `\n\n`: the parser still yields it.
    const { client } = makeMockedClientForStream([
      {
        chunks: [
          // NOTE: no trailing `\n\n`. Stream closes immediately after.
          `id: ${CURSOR_1}\nevent: decision.appended\ndata: ${JSON.stringify(SAMPLE_EVENT_1)}`,
        ],
      },
    ]);
    const events: DecisionStreamEvent[] = [];
    for await (const event of client.decisions.stream()) {
      events.push(event);
    }
    expect(events).toHaveLength(1);
    expect(events[0].id).toBe(SAMPLE_EVENT_1.id);
  });

  it("C6: caller can override the default buffer cap via parser options (forward-compat)", async () => {
    // Not directly exposed via decisions.stream — but the parser
    // primitive accepts maxBufferBytes. Pin via direct parseSSE call:
    // a tiny cap forces the same H3 throw on a payload that would
    // otherwise be fine under the 1 MiB default.
    const { parseSSE } = await import("../../sse-parser.js");
    const encoder = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        // 100-byte payload; the cap is set to 50.
        controller.enqueue(
          encoder.encode("id: x\ndata: " + "y".repeat(100)),
        );
        controller.close();
      },
    });
    const reader = stream.getReader();
    let caught: unknown = null;
    try {
      for await (const _f of parseSSE(reader, { maxBufferBytes: 50 })) {
        void _f;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "exceeded maximum buffer size (50 bytes)",
    );
  });
});

describe("decisions.stream — laziness + iterator semantics", () => {
  it("does NOT issue the request until first iteration (lazy)", async () => {
    const { client, calls } = makeMockedClientForStream([
      { chunks: [frame(CURSOR_1, SAMPLE_EVENT_1)] },
    ]);
    const stream = client.decisions.stream();
    // Constructed but not iterated yet — no request.
    expect(calls).toHaveLength(0);
    // First iteration → request fires.
    const iterator = stream[Symbol.asyncIterator]();
    const r1 = await iterator.next();
    expect(calls).toHaveLength(1);
    expect(r1.done).toBe(false);
    expect((r1.value as DecisionStreamEvent).id).toBe(SAMPLE_EVENT_1.id);
  });

  it("iterator ends naturally after the last frame (next() returns done: true)", async () => {
    const { client } = makeMockedClientForStream([
      { chunks: [frame(CURSOR_1, SAMPLE_EVENT_1)] },
    ]);
    const iterator = client.decisions.stream()[Symbol.asyncIterator]();
    const r1 = await iterator.next();
    expect(r1.done).toBe(false);
    const r2 = await iterator.next();
    expect(r2.done).toBe(true);
    // Subsequent calls remain done — generator exhausted.
    const r3 = await iterator.next();
    expect(r3.done).toBe(true);
  });

  it("releases the underlying reader when consumer breaks early (no leak)", async () => {
    // Pin: the parser's `finally` block calls `reader.cancel()` even
    // when the for-await loop exits via `break`. Without the wrapper's
    // finally, an early break would lock the underlying ReadableStream
    // forever.
    const cancelSpy = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode(frame(CURSOR_1, SAMPLE_EVENT_1)));
        controller.enqueue(encoder.encode(frame(CURSOR_2, SAMPLE_EVENT_2)));
        // Don't close — simulate a long-lived connection.
      },
      cancel() {
        cancelSpy();
      },
    });
    const mockFetch: FetchLike = async () =>
      new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 }, // see helper above for rationale
    });
    let count = 0;
    for await (const event of client.decisions.stream()) {
      count++;
      void event;
      if (count === 1) break; // early exit
    }
    expect(count).toBe(1);
    // The parser's finally block triggers reader.cancel(), which in
    // turn fires the underlying stream's cancel callback.
    expect(cancelSpy).toHaveBeenCalled();
  });
});

// ─── lone-surrogate URIError guard (cross-phase follow-up) ────────────────
//
// Pinned alongside decisions.export's URIError guard (commit 0428777).
// `runDecisionsStream` builds a query record `{ systemId }` and threads
// it through `encodeQuery` → `encodeURIComponent`, which throws raw
// URIError for malformed UTF-16. The SDK now guards in `stream()`,
// converting URIError → TypeError synchronously (no fetch issued).
// `lastEventId` rides on the Last-Event-ID header — Headers.set
// throws TypeError on its own for invalid values, so no URIError
// concern there.

describe("decisions.stream — lone-surrogate URIError guard (cross-phase fix)", () => {
  const LONE_HIGH = "\uD800";

  it("throws TypeError synchronously for lone surrogate in systemId — does NOT issue a request", () => {
    const { client, calls } = makeMockedClientForStream([]);
    let caught: unknown = null;
    try {
      // The synchronous throw happens at validation time, before
      // `runDecisionsStream` constructs an iterator.
      client.decisions.stream({ systemId: LONE_HIGH });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as TypeError).message).toContain(
      "decisions.stream: `systemId`",
    );
    expect((caught as TypeError).message).toContain("invalid UTF-16");
    expect((caught as TypeError).cause).toBeInstanceOf(Error);
    expect(calls).toHaveLength(0);
  });

  it("ACCEPTS a properly-paired surrogate / valid emoji in systemId (positive control)", async () => {
    // Round-trip through encodeURIComponent works for legitimate
    // Unicode. Pin so the guard isn't over-aggressive.
    const { client, calls } = makeMockedClientForStream([{ chunks: [] }]);
    for await (const _e of client.decisions.stream({
      systemId: "system-✓-validated",
    })) {
      void _e;
    }
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toContain("systemId=system-%E2%9C%93-validated");
  });
});

// ─── Hostile review #3 — MEDIUM-1 throwing-getter fix (decisions.stream) ────
//
// Session-22 hostile review #3 completes the SDK-wide MEDIUM-1 getter-
// throws contract fix. Reviews #1-#2 converted `decisions.ingest` /
// `.bulk` but MISSED the three `decisions` query methods (`.list` /
// `.stream` / `.export`) — their input-field validation still read each
// field with a bare `input.x` access, so a throwing accessor leaked the
// getter's raw exception instead of the documented synchronous
// `TypeError`. `decisions.stream` now snapshots `systemId` / `lastEventId`
// via `readInputField`. Validation runs synchronously inside `stream()`
// BEFORE the async generator is returned, so the throw is synchronous.

describe("decisions.stream — hostile review #3: throwing-getter MEDIUM-1 fix", () => {
  it("converts a throwing `systemId` getter into a TypeError (NOT the getter's raw error)", () => {
    const { client, calls } = makeMockedClientForStream([]);
    const evil = {
      get systemId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as DecisionsStreamInput;
    let caught: unknown;
    try {
      client.decisions.stream(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error).message).toContain("decisions.stream");
    expect((caught as Error).message).toContain("systemId");
    // The getter's OWN message is not the SDK's contract message...
    expect((caught as Error).message).not.toContain("getter boom");
    // ...but the original error is preserved on `.cause`.
    expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(Error);
    expect(calls).toHaveLength(0);
  });

  it("converts a throwing `lastEventId` getter into a TypeError", () => {
    // Proves both stream fields are snapshot-wrapped, not just systemId.
    // A RangeError from the getter still surfaces as the documented
    // TypeError input-contract class — never RangeError.
    const { client, calls } = makeMockedClientForStream([]);
    const evil = {
      get lastEventId(): unknown {
        throw new RangeError("range boom");
      },
    } as unknown as DecisionsStreamInput;
    let caught: unknown;
    try {
      client.decisions.stream(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught).not.toBeInstanceOf(RangeError);
    expect((caught as Error).message).toContain("lastEventId");
    expect(calls).toHaveLength(0);
  });
});
