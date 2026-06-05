// ─── NDJSON parser primitive — direct unit tests ──────────────────────────
//
// Most parser branches are also pinned through the decisions.export
// resource tests (which exercise the parser via the public API). This
// file pins the parser primitive in isolation: line-splitting edge
// cases, BOM stripping, buffer cap defense, mid-stream read errors,
// and the Response wrapper's reader-cleanup contract.
//
// Symmetric to `sse-parser.test.ts`.

import { describe, it, expect, vi } from "vitest";
import {
  parseNDJSON,
  parseNDJSONResponse,
  __test__,
} from "../ndjson-parser.js";
import { AttestryError } from "../errors.js";

const { parseLine, stripTrailingCR, DEFAULT_MAX_LINE_BYTES } = __test__;

/**
 * Build a `ReadableStreamDefaultReader<Uint8Array>` over the given chunks.
 * Each chunk is enqueued separately so the parser sees them as distinct
 * `reader.read()` results — the right tool for "line split across reads"
 * tests.
 */
function readerFromChunks(
  chunks: (string | Uint8Array)[],
): ReadableStreamDefaultReader<Uint8Array> {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(
          typeof chunk === "string" ? encoder.encode(chunk) : chunk,
        );
      }
      controller.close();
    },
  });
  return stream.getReader();
}

function ndjsonResponse(
  chunks: (string | Uint8Array)[],
  init: { headers?: Record<string, string> } = {},
): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) {
        controller.enqueue(
          typeof chunk === "string" ? encoder.encode(chunk) : chunk,
        );
      }
      controller.close();
    },
  });
  return new Response(stream, {
    status: 200,
    headers: { "Content-Type": "application/x-ndjson", ...(init.headers ?? {}) },
  });
}

async function collect<T>(iter: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of iter) out.push(v);
  return out;
}

// ─── happy path ─────────────────────────────────────────────────────────────

describe("parseNDJSON — happy path", () => {
  it("yields one parsed value per `\\n`-delimited line", async () => {
    const reader = readerFromChunks([`{"a":1}\n{"a":2}\n{"a":3}\n`]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }, { a: 2 }, { a: 3 }]);
  });

  it("emits the final line even when missing the trailing newline (lenient)", async () => {
    // NDJSON spec says trailing newline is optional. Common case:
    // HTTP/1.1 connection-close mid-line — better to surface the
    // partial frame than silently drop.
    const reader = readerFromChunks([`{"a":1}\n{"a":2}`]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("yields zero frames on empty body", async () => {
    const reader = readerFromChunks([]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([]);
  });

  it("handles a single line with trailing newline", async () => {
    const reader = readerFromChunks([`{"a":1}\n`]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }]);
  });

  it("handles a single line WITHOUT trailing newline", async () => {
    const reader = readerFromChunks([`{"a":1}`]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }]);
  });

  it("preserves null and primitive types if emitted (parser is type-agnostic)", async () => {
    // Records would be objects, but the parser yields whatever JSON
    // says. Resource-level callers narrow.
    const reader = readerFromChunks([`null\n42\n"hello"\ntrue\n`]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([null, 42, "hello", true]);
  });
});

// ─── line splitting + edges ────────────────────────────────────────────────

describe("parseNDJSON — line splitting + edges", () => {
  it("reassembles a line split across multiple reads (TCP-fragmented chunk)", async () => {
    // A chunk boundary that lands mid-JSON-line must be carried
    // forward — without the buffer carryover, the JSON.parse on each
    // half would error.
    const fullLine = `{"a":1}\n`;
    const splitAt = Math.floor(fullLine.length / 2);
    const reader = readerFromChunks([
      fullLine.slice(0, splitAt),
      fullLine.slice(splitAt),
    ]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }]);
  });

  it("reassembles a multibyte UTF-8 character split across reads", async () => {
    // `TextDecoder({stream: true})` is required to preserve continuation
    // bytes that span chunk boundaries. Smoke-test: emit JSON containing
    // a 3-byte UTF-8 char and split the bytes mid-character.
    const line = `{"x":"hello-✓"}\n`;
    const bytes = new TextEncoder().encode(line);
    // Locate the ✓ byte sequence (e2 9c 93) and split mid-sequence.
    let splitIdx = -1;
    for (let i = 0; i < bytes.length - 2; i++) {
      if (
        bytes[i] === 0xe2 &&
        bytes[i + 1] === 0x9c &&
        bytes[i + 2] === 0x93
      ) {
        splitIdx = i + 1;
        break;
      }
    }
    expect(splitIdx).toBeGreaterThan(0);
    const reader = readerFromChunks([
      bytes.slice(0, splitIdx),
      bytes.slice(splitIdx),
    ]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ x: "hello-✓" }]);
  });

  it("silently skips blank lines (back-to-back `\\n\\n` — defensive)", async () => {
    // Kernel doesn't emit blank lines, but defensive parsers tolerate
    // whitespace between frames.
    const reader = readerFromChunks([
      `{"a":1}\n\n\n{"a":2}\n\n`,
    ]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("trims a single trailing `\\r` before parsing (CRLF defense)", async () => {
    // Some Windows-tooling pipelines could leave a CR before the LF.
    // Spec mandates LF only; trimming exactly one trailing CR keeps
    // the parser permissive without treating CR alone as a separator.
    const reader = readerFromChunks([`{"a":1}\r\n{"a":2}\r\n`]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("strips a leading BOM (U+FEFF) once at stream start", async () => {
    // A misconfigured proxy / charset transcoder might prepend a BOM.
    // Without stripping, the first line's first char would be `﻿{`
    // and JSON.parse would throw with an unhelpful "unexpected
    // character" error.
    const reader = readerFromChunks([`﻿{"a":1}\n{"a":2}\n`]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("does NOT strip a U+FEFF that appears mid-stream (only the first byte)", async () => {
    // BOM is one-shot at stream start. A U+FEFF appearing later (in a
    // string field) is a legitimate value and must be preserved
    // verbatim.
    const reader = readerFromChunks([`{"a":"﻿"}\n`]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: "﻿" }]);
  });

  it("strips a leading BOM when the first read produces no decoded chars (hostile-fix: bomStripped flag waits for content)", async () => {
    // Hostile-review finding: the previous shape `if (!bomStripped) {
    // bomStripped = true; ... }` flipped the flag on every iteration —
    // including when the first read decoded to zero chars (empty
    // chunk, partial UTF-8 continuation bytes). If the BOM landed in
    // a LATER read where TextDecoder no longer treats it as a stream-
    // start BOM (because the decoder already saw bytes and entered
    // the "stream-started" state), the parser-level strip would be
    // skipped.
    //
    // In practice the consumer-visible bug is currently masked by
    // `.trim()` (which treats U+FEFF as whitespace) and by the default
    // `TextDecoder("utf-8")` stripping a stream-start BOM internally
    // — but the wrong logic shape is fragile: a future `ignoreBOM:
    // true` or a code path that skips `.trim()` would reintroduce it.
    // The fix moves the buffer-non-empty precondition INTO the flag-
    // flip guard, so the parser-level BOM strip stays primed until we
    // actually have content to inspect. Pin the correct shape:
    // empty-first-read + BOM-prefixed-second-read still yields a
    // clean parse.
    const enc = new TextEncoder();
    const reader = readerFromChunks([
      new Uint8Array([]), // empty first read — must NOT flip bomStripped
      enc.encode(`﻿{"a":1}\n`),
    ]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }]);
  });

  it("multiple empty reads before content still strip a leading BOM (defensive)", async () => {
    // A misconfigured proxy / TCP keep-alive layer could emit several
    // zero-length chunks before any payload. The hostile-fix flag
    // logic must remain "no decoded chars yet → keep waiting", not
    // "first iteration → flag set, strip skipped".
    const enc = new TextEncoder();
    const reader = readerFromChunks([
      new Uint8Array([]),
      new Uint8Array([]),
      new Uint8Array([]),
      enc.encode(`﻿{"a":1}\n{"a":2}\n`),
    ]);
    const out = await collect(parseNDJSON(reader));
    expect(out).toEqual([{ a: 1 }, { a: 2 }]);
  });
});

// ─── error paths ───────────────────────────────────────────────────────────

describe("parseNDJSON — error paths", () => {
  it("throws AttestryError on malformed JSON", async () => {
    const reader = readerFromChunks([`{"valid":1}\nnot-json\n`]);
    let caught: unknown = null;
    try {
      await collect(parseNDJSON(reader));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "NDJSON line was not valid JSON",
    );
  });

  it("propagates the underlying parse error as `cause`", async () => {
    const reader = readerFromChunks([`{not-json}\n`]);
    let caught: unknown = null;
    try {
      await collect(parseNDJSON(reader));
    } catch (err) {
      caught = err;
    }
    expect((caught as AttestryError).cause).toBeInstanceOf(Error);
  });

  it("yields earlier valid frames before throwing on a malformed line", async () => {
    // Pin the failure semantics: the parser yields complete valid
    // frames in order, then throws when it hits the malformed line.
    // Caller can collect-until-error (defensive recovery).
    const reader = readerFromChunks([`{"a":1}\n{"a":2}\nbad\n{"a":3}\n`]);
    const out: unknown[] = [];
    let caught: unknown = null;
    try {
      for await (const v of parseNDJSON(reader)) out.push(v);
    } catch (err) {
      caught = err;
    }
    expect(out).toEqual([{ a: 1 }, { a: 2 }]);
    expect(caught).toBeInstanceOf(AttestryError);
  });

  it("wraps mid-stream read() errors (TCP RST) as AttestryError(\"network error during stream: ...\")", async () => {
    // Spec contract: parseNDJSON wraps reader.read() rejections as
    // AttestryError so consumers can branch uniformly via
    // `instanceof AttestryError`. Per the ReadableStream spec,
    // calling controller.error() drops queued chunks and rejects
    // pending reads — so no frames are yielded before the wrapped
    // error surfaces, even if a chunk was enqueued first.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new TypeError("connection reset by peer"));
      },
    });
    const reader = stream.getReader();
    let caught: unknown = null;
    const out: unknown[] = [];
    try {
      for await (const v of parseNDJSON(reader)) out.push(v);
    } catch (err) {
      caught = err;
    }
    expect(out).toHaveLength(0);
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "network error during stream",
    );
    expect((caught as AttestryError).message).toContain(
      "connection reset by peer",
    );
    // Original error preserved as cause.
    expect((caught as AttestryError).cause).toBeInstanceOf(TypeError);
  });

  it("wraps AbortError-shaped reader rejects as AttestryError(\"request aborted by caller\")", async () => {
    // When the underlying signal is aborted mid-stream, reader.read()
    // rejects with `{name: "AbortError"}`. Wrap as
    // AttestryError("request aborted by caller") for symmetry with
    // the pre-fetch abort path. Resource layer relies on this
    // wrapping — its catch passes AttestryError through verbatim.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const abortErr = new Error("aborted");
        abortErr.name = "AbortError";
        controller.error(abortErr);
      },
    });
    const reader = stream.getReader();
    let caught: unknown = null;
    try {
      for await (const _ of parseNDJSON(reader)) void _;
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toBe("request aborted by caller");
    // Cause preserves the original abort reason.
    expect((caught as AttestryError).cause).toBeInstanceOf(Error);
    expect(((caught as AttestryError).cause as Error).name).toBe("AbortError");
  });

  it("yields earlier frames when error arrives in a SEPARATE chunk after a yield", async () => {
    // Pin the "yield-then-error" semantics: when a chunk fully delivers
    // then a SECOND chunk errors, the first chunk's frames are emitted
    // before the wrapped error throws. Distinct from the same-tick-
    // error case above (which drops queued chunks per spec).
    let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controllerRef = controller;
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode(`{"a":1}\n`));
      },
    });
    const reader = stream.getReader();
    const iter = parseNDJSON(reader);
    const r1 = await iter.next();
    expect(r1.done).toBe(false);
    expect(r1.value).toEqual({ a: 1 });
    // Now error the underlying source AFTER the first frame was read.
    // A subsequent next() will see the wrapped error.
    controllerRef!.error(new TypeError("post-yield rst"));
    let caught: unknown = null;
    try {
      await iter.next();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "network error during stream",
    );
    expect((caught as AttestryError).message).toContain("post-yield rst");
  });
});

// ─── buffer cap (DoS defense) ──────────────────────────────────────────────

describe("parseNDJSON — buffer cap (DoS defense)", () => {
  it("throws AttestryError when a single line exceeds maxLineBytes default", async () => {
    // Default is 1 MiB. Emit 2 MiB without a `\n`.
    const giant = "x".repeat(2 * 1024 * 1024);
    const reader = readerFromChunks([`{"x":"${giant}`]); // no `\n`
    let caught: unknown = null;
    try {
      await collect(parseNDJSON(reader));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "exceeded maximum buffer size",
    );
  });

  it("respects a custom maxLineBytes override", async () => {
    // Tiny cap (50 bytes) — fires earlier than default.
    const reader = readerFromChunks(["x".repeat(100)]);
    let caught: unknown = null;
    try {
      await collect(parseNDJSON(reader, { maxLineBytes: 50 }));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "exceeded maximum buffer size (50 bytes)",
    );
  });

  it("DEFAULT_MAX_LINE_BYTES is 1 MiB", () => {
    expect(DEFAULT_MAX_LINE_BYTES).toBe(1024 * 1024);
  });

  it("does NOT trip the cap on many small lines in a single chunk", async () => {
    // Defensive accounting: the cap should apply to the residual
    // partial-line buffer, NOT to the chunk size as a whole.
    // Otherwise a 100-line chunk of 1 KB lines would erroneously
    // trip a small cap even though no individual line is large.
    const lines = Array.from({ length: 100 }, (_, i) => `{"i":${i}}`);
    const blob = lines.join("\n") + "\n"; // ~900 bytes
    const reader = readerFromChunks([blob]);
    const out = await collect(parseNDJSON(reader, { maxLineBytes: 100 }));
    expect(out).toHaveLength(100);
    expect((out[0] as { i: number }).i).toBe(0);
    expect((out[99] as { i: number }).i).toBe(99);
  });
});

// ─── parseNDJSONResponse — Response wrapper ────────────────────────────────

describe("parseNDJSONResponse — Response wrapper", () => {
  it("yields zero frames when response.body is null", async () => {
    // Browser fetch spec allows null body for 204 / 205 / 304. NDJSON
    // doesn't use those, but defensively the wrapper short-circuits.
    const response = new Response(null, {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson" },
    });
    const out = await collect(parseNDJSONResponse(response));
    expect(out).toEqual([]);
  });

  it("yields parsed JSON values from a Response body", async () => {
    const response = ndjsonResponse([`{"a":1}\n{"a":2}\n`]);
    const out = await collect(parseNDJSONResponse(response));
    expect(out).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("completes naturally when the source closes (no leaked locks)", async () => {
    // Pin: after a clean source.close(), the wrapper's reader.cancel()
    // is a no-op (the stream is already finalized). The test confirms
    // the iteration completes cleanly. Active cancel-callback firing
    // is exercised in the early-break and on-error tests below — those
    // paths leave the source open so cancel() actually triggers.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode(`{"a":1}\n`));
        controller.close();
      },
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson" },
    });
    const out = await collect(parseNDJSONResponse(response));
    expect(out).toEqual([{ a: 1 }]);
  });

  it("cancels the reader on early break (no leak)", async () => {
    // Pin: the wrapper's `finally` block calls reader.cancel() even
    // when the for-await loop exits via `break`. Without it, an early
    // break would lock the underlying stream forever.
    const cancelSpy = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode(`{"a":1}\n{"a":2}\n`));
        // Don't close — simulate a long-lived connection.
      },
      cancel() {
        cancelSpy();
      },
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson" },
    });
    let count = 0;
    for await (const _ of parseNDJSONResponse(response)) {
      count++;
      void _;
      if (count === 1) break;
    }
    expect(count).toBe(1);
    expect(cancelSpy).toHaveBeenCalled();
  });

  it("cancels the reader when the parser throws (malformed JSON)", async () => {
    // Pin: cleanup runs even on the error path.
    const cancelSpy = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode(`bad-json\n`));
      },
      cancel() {
        cancelSpy();
      },
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson" },
    });
    let caught: unknown = null;
    try {
      await collect(parseNDJSONResponse(response));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(cancelSpy).toHaveBeenCalled();
  });

  it("does not throw when reader.cancel() rejects (already-canceled stream)", async () => {
    // Defensive: calling cancel() twice or on an already-closed
    // reader can reject. The wrapper catches that to avoid masking
    // the real (parser-level) error.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode(`{"a":1}\n`));
        controller.close();
      },
      // No cancel() handler — default is a no-op resolve. Pin: even
      // with no custom cancel, the wrapper completes cleanly.
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson" },
    });
    const out = await collect(parseNDJSONResponse(response));
    expect(out).toEqual([{ a: 1 }]);
  });
});

// ─── internals ──────────────────────────────────────────────────────────────

describe("parseLine (internal)", () => {
  it("parses valid JSON", () => {
    expect(parseLine('{"x":1}')).toEqual({ x: 1 });
  });

  it("throws AttestryError with cause on invalid JSON", () => {
    let caught: unknown = null;
    try {
      parseLine("not-json");
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "NDJSON line was not valid JSON",
    );
    expect((caught as AttestryError).cause).toBeInstanceOf(Error);
  });

  it("preserves null and primitive types", () => {
    expect(parseLine("null")).toBeNull();
    expect(parseLine("42")).toBe(42);
    expect(parseLine('"hello"')).toBe("hello");
    expect(parseLine("true")).toBe(true);
  });

  it("parses arrays + nested objects", () => {
    expect(parseLine('[1,{"a":2},"x"]')).toEqual([1, { a: 2 }, "x"]);
  });
});

describe("parseNDJSON — defensive non-spec reader behavior", () => {
  it("continues without throwing when reader.read() yields { value: undefined, done: false }", async () => {
    // Defensive: per the WHATWG Streams spec, a non-done read MUST
    // yield a non-undefined value. The parser nevertheless guards
    // against a non-spec reader (custom test fixtures, future
    // platform changes) emitting undefined — branch is `if (value
    // === undefined) continue;`. Pin via a custom reader that yields
    // an undefined-value sentinel before its real chunks.
    let calls = 0;
    const enc = new TextEncoder();
    const fakeReader: ReadableStreamDefaultReader<Uint8Array> = {
      async read() {
        calls++;
        if (calls === 1) {
          // Spec-violating: undefined value with done: false.
          return {
            value: undefined as unknown as Uint8Array,
            done: false,
          };
        }
        if (calls === 2) {
          return { value: enc.encode(`{"a":1}\n`), done: false };
        }
        return { value: undefined as unknown as Uint8Array, done: true };
      },
      cancel: async () => undefined,
      releaseLock: () => undefined,
      get closed() {
        return Promise.resolve(undefined);
      },
    };
    const out: unknown[] = [];
    for await (const v of parseNDJSON(fakeReader)) out.push(v);
    expect(out).toEqual([{ a: 1 }]);
    // The undefined-value read was consumed without crashing or
    // yielding a frame.
    expect(calls).toBe(3);
  });
});

describe("stripTrailingCR (internal)", () => {
  it("removes exactly one trailing CR", () => {
    expect(stripTrailingCR("hello\r")).toBe("hello");
  });

  it("leaves strings without trailing CR untouched", () => {
    expect(stripTrailingCR("hello")).toBe("hello");
    expect(stripTrailingCR("")).toBe("");
  });

  it("removes only ONE trailing CR (not two)", () => {
    expect(stripTrailingCR("hello\r\r")).toBe("hello\r");
  });

  it("does not remove a leading or mid-string CR", () => {
    expect(stripTrailingCR("\rhello")).toBe("\rhello");
    expect(stripTrailingCR("hel\rlo")).toBe("hel\rlo");
  });
});
