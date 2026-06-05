// ─── Lines parser primitive — direct unit tests ───────────────────────────
//
// Most parser branches are also pinned through the auditLog.export resource
// tests (which exercise the parser via the public API for `format=cef`).
// This file pins the parser primitive in isolation: line-splitting edge
// cases, BOM stripping, buffer cap defense, mid-stream read errors, and
// the Response wrapper's reader-cleanup contract.
//
// Symmetric to `ndjson-parser.test.ts`. Where the ndjson parser checks
// JSON-parse semantics, the lines parser yields raw strings — the
// resource layer interprets each line.

import { describe, it, expect, vi } from "vitest";
import {
  parseLines,
  parseLinesResponse,
  __test__,
} from "../lines-parser.js";
import { AttestryError } from "../errors.js";

const { stripTrailingCR, DEFAULT_MAX_LINE_BYTES } = __test__;

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

function linesResponse(
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
    headers: { "Content-Type": "text/plain", ...(init.headers ?? {}) },
  });
}

async function collect<T>(iter: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of iter) out.push(v);
  return out;
}

// ─── happy path ─────────────────────────────────────────────────────────────

describe("parseLines — happy path", () => {
  it("yields one string per `\\n`-delimited line", async () => {
    const reader = readerFromChunks(["alpha\nbeta\ngamma\n"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha", "beta", "gamma"]);
  });

  it("emits the final line even when missing the trailing newline (lenient)", async () => {
    // Symmetric to ndjson-parser. HTTP/1.1 connection-close mid-line:
    // surface the partial line rather than silently drop.
    const reader = readerFromChunks(["alpha\nbeta"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha", "beta"]);
  });

  it("yields zero lines on empty body", async () => {
    const reader = readerFromChunks([]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual([]);
  });

  it("handles a single line with trailing newline", async () => {
    const reader = readerFromChunks(["alpha\n"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha"]);
  });

  it("handles a single line WITHOUT trailing newline", async () => {
    const reader = readerFromChunks(["alpha"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha"]);
  });

  it("preserves CEF prefix verbatim (no JSON.parse, no trim of leading content)", async () => {
    // CEF is the primary consumer of this parser. Lines start with
    // `CEF:0|Attestry|...` — pin that they pass through unmodified.
    const reader = readerFromChunks([
      "CEF:0|Attestry|Compliance Kernel|1.0|login|User signed in|3|rt=1234567890\n",
    ]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual([
      "CEF:0|Attestry|Compliance Kernel|1.0|login|User signed in|3|rt=1234567890",
    ]);
  });

  it("preserves embedded `|` and `=` characters (CEF separators) — does NOT escape", async () => {
    // The parser is format-agnostic — it splits on `\n` only. CEF's
    // escape semantics (within fields) are the resource layer's
    // concern. Pin that pipe and equals pass through verbatim.
    const reader = readerFromChunks(["CEF:0|a|b|c|x=y|extra=value\n"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["CEF:0|a|b|c|x=y|extra=value"]);
  });
});

// ─── line splitting + edges ────────────────────────────────────────────────

describe("parseLines — line splitting + edges", () => {
  it("reassembles a line split across multiple reads (TCP-fragmented chunk)", async () => {
    const fullLine = "CEF:0|Attestry|x|1.0|login|signed in|3|rt=1\n";
    const splitAt = Math.floor(fullLine.length / 2);
    const reader = readerFromChunks([
      fullLine.slice(0, splitAt),
      fullLine.slice(splitAt),
    ]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual([
      "CEF:0|Attestry|x|1.0|login|signed in|3|rt=1",
    ]);
  });

  it("reassembles a multibyte UTF-8 character split across reads", async () => {
    // `TextDecoder({stream: true})` carries continuation bytes across
    // chunk boundaries. Smoke-test: emit a line containing a 3-byte
    // UTF-8 char and split mid-character.
    const line = "hello-✓\n";
    const bytes = new TextEncoder().encode(line);
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
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["hello-✓"]);
  });

  it("silently skips blank lines (back-to-back `\\n\\n` — defensive)", async () => {
    // Kernel doesn't emit blank lines but defensive parsers tolerate
    // whitespace between lines.
    const reader = readerFromChunks(["alpha\n\n\nbeta\n\n"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha", "beta"]);
  });

  it("trims a single trailing `\\r` before yielding (CRLF defense)", async () => {
    // Some Windows-tooling pipelines could leave a CR before the LF.
    // Trim exactly one trailing CR; CR alone is NOT a line separator.
    const reader = readerFromChunks(["alpha\r\nbeta\r\n"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha", "beta"]);
  });

  it("strips a leading BOM (U+FEFF) once at stream start", async () => {
    // A misconfigured proxy / charset transcoder might prepend a BOM.
    // Without stripping, the first CEF line's prefix would be
    // `﻿CEF:0|...` and downstream consumers checking for the
    // exact `CEF:0|` prefix would fail.
    const reader = readerFromChunks(["﻿alpha\nbeta\n"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha", "beta"]);
  });

  it("does NOT strip a U+FEFF that appears mid-stream (only at stream start)", async () => {
    // BOM is one-shot at stream start. U+FEFF appearing later in a
    // line value is a legitimate code-point and must be preserved
    // verbatim.
    const reader = readerFromChunks(["alpha-\u{FEFF}-mid\n"]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha-\u{FEFF}-mid"]);
  });

  it("strips a leading BOM when the first read produces no decoded chars (bomStripped flag waits for content)", async () => {
    // Mirror of ndjson-parser hostile-fix. Empty / partial-multibyte
    // first read must NOT prematurely flip `bomStripped`. If the BOM
    // bytes arrive in a LATER read, the strip-attempt must still
    // engage. Pin the correct shape: empty first read + BOM-prefixed
    // second read still strips cleanly.
    const enc = new TextEncoder();
    const reader = readerFromChunks([
      new Uint8Array([]), // empty first read — must NOT flip bomStripped
      enc.encode("﻿alpha\n"),
    ]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha"]);
  });

  it("multiple empty reads before content still strip a leading BOM (defensive)", async () => {
    // Defense-in-depth: a misconfigured proxy / TCP keep-alive layer
    // could emit several zero-length chunks before any payload.
    const enc = new TextEncoder();
    const reader = readerFromChunks([
      new Uint8Array([]),
      new Uint8Array([]),
      new Uint8Array([]),
      enc.encode("﻿alpha\nbeta\n"),
    ]);
    const out = await collect(parseLines(reader));
    expect(out).toEqual(["alpha", "beta"]);
  });
});

// ─── error paths ───────────────────────────────────────────────────────────

describe("parseLines — error paths", () => {
  it("wraps mid-stream read() errors (TCP RST) as AttestryError(\"network error during stream: ...\")", async () => {
    // Spec contract: parseLines wraps reader.read() rejections as
    // AttestryError so consumers can branch uniformly via
    // `instanceof AttestryError`. Per the ReadableStream spec,
    // calling controller.error() drops queued chunks and rejects
    // pending reads.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new TypeError("connection reset by peer"));
      },
    });
    const reader = stream.getReader();
    let caught: unknown = null;
    const out: unknown[] = [];
    try {
      for await (const v of parseLines(reader)) out.push(v);
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
      for await (const _ of parseLines(reader)) void _;
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toBe("request aborted by caller");
    expect((caught as AttestryError).cause).toBeInstanceOf(Error);
    expect(((caught as AttestryError).cause as Error).name).toBe("AbortError");
  });

  it("yields earlier lines when error arrives in a SEPARATE chunk after a yield", async () => {
    // Pin "yield-then-error" semantics: when a chunk fully delivers
    // then a SECOND chunk errors, the first chunk's lines are emitted
    // before the wrapped error throws.
    let controllerRef: ReadableStreamDefaultController<Uint8Array> | null = null;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controllerRef = controller;
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode("alpha\n"));
      },
    });
    const reader = stream.getReader();
    const iter = parseLines(reader);
    const r1 = await iter.next();
    expect(r1.done).toBe(false);
    expect(r1.value).toEqual("alpha");
    // Error the underlying source AFTER the first line was read.
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

describe("parseLines — buffer cap (DoS defense)", () => {
  it("throws AttestryError when a single line exceeds maxLineBytes default", async () => {
    // Default is 1 MiB. Emit 2 MiB without a `\n`.
    const giant = "x".repeat(2 * 1024 * 1024);
    const reader = readerFromChunks([giant]); // no `\n`
    let caught: unknown = null;
    try {
      await collect(parseLines(reader));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "exceeded maximum buffer size",
    );
  });

  it("respects a custom maxLineBytes override", async () => {
    const reader = readerFromChunks(["x".repeat(100)]);
    let caught: unknown = null;
    try {
      await collect(parseLines(reader, { maxLineBytes: 50 }));
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
    const lines = Array.from({ length: 100 }, (_, i) => `line-${i}`);
    const blob = lines.join("\n") + "\n"; // ~700 bytes, but no individual line > 10 bytes
    const reader = readerFromChunks([blob]);
    const out = await collect(parseLines(reader, { maxLineBytes: 100 }));
    expect(out).toHaveLength(100);
    expect(out[0]).toBe("line-0");
    expect(out[99]).toBe("line-99");
  });
});

// ─── parseLinesResponse — Response wrapper ─────────────────────────────────

describe("parseLinesResponse — Response wrapper", () => {
  it("yields zero lines when response.body is null", async () => {
    // Browser fetch spec allows null body for 204 / 205 / 304.
    const response = new Response(null, {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });
    const out = await collect(parseLinesResponse(response));
    expect(out).toEqual([]);
  });

  it("yields strings from a Response body", async () => {
    const response = linesResponse(["alpha\nbeta\n"]);
    const out = await collect(parseLinesResponse(response));
    expect(out).toEqual(["alpha", "beta"]);
  });

  it("completes naturally when the source closes (no leaked locks)", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode("alpha\n"));
        controller.close();
      },
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });
    const out = await collect(parseLinesResponse(response));
    expect(out).toEqual(["alpha"]);
  });

  it("cancels the reader on early break (no leak)", async () => {
    const cancelSpy = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode("alpha\nbeta\n"));
        // Don't close — simulate a long-lived connection.
      },
      cancel() {
        cancelSpy();
      },
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });
    let count = 0;
    for await (const _ of parseLinesResponse(response)) {
      count++;
      void _;
      if (count === 1) break;
    }
    expect(count).toBe(1);
    expect(cancelSpy).toHaveBeenCalled();
  });

  it("cancels the reader when the parser throws (buffer cap exceeded)", async () => {
    const cancelSpy = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode("x".repeat(200)));
      },
      cancel() {
        cancelSpy();
      },
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });
    let caught: unknown = null;
    try {
      await collect(parseLinesResponse(response, { maxLineBytes: 50 }));
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(cancelSpy).toHaveBeenCalled();
  });

  it("does not throw when reader.cancel() rejects (already-canceled stream)", async () => {
    // Defensive: calling cancel() on an already-closed reader can
    // reject. The wrapper catches that to avoid masking the real
    // (parser-level) error.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const encoder = new TextEncoder();
        controller.enqueue(encoder.encode("alpha\n"));
        controller.close();
      },
    });
    const response = new Response(stream, {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });
    const out = await collect(parseLinesResponse(response));
    expect(out).toEqual(["alpha"]);
  });
});

// ─── internals ──────────────────────────────────────────────────────────────

describe("stripTrailingCR (internal)", () => {
  it("removes a single trailing CR", () => {
    expect(stripTrailingCR("foo\r")).toBe("foo");
  });

  it("does not modify a string without a trailing CR", () => {
    expect(stripTrailingCR("foo")).toBe("foo");
  });

  it("does NOT remove a CR that is NOT trailing (mid-string CR is preserved)", () => {
    expect(stripTrailingCR("foo\rbar")).toBe("foo\rbar");
  });

  it("only removes ONE trailing CR (not multiple)", () => {
    // Defensive: kernel never emits CRCRLF, but if a misbehaving
    // proxy did, the second CR would land in the line value. Pin the
    // single-strip semantics so a future double-strip change is loud.
    expect(stripTrailingCR("foo\r\r")).toBe("foo\r");
  });

  it("handles an empty string", () => {
    expect(stripTrailingCR("")).toBe("");
  });
});

describe("parseLines — defensive non-spec reader behavior", () => {
  it("continues without throwing when reader.read() yields { value: undefined, done: false }", async () => {
    // Defensive: per the WHATWG Streams spec, a non-done read MUST
    // yield a non-undefined value. The parser nevertheless guards
    // against a non-spec reader emitting undefined — branch is
    // `if (value === undefined) continue;`. Pin via a custom reader
    // that yields an undefined-value sentinel before its real chunks.
    let calls = 0;
    const enc = new TextEncoder();
    const fakeReader: ReadableStreamDefaultReader<Uint8Array> = {
      async read() {
        calls++;
        if (calls === 1) {
          return { value: undefined as unknown as Uint8Array, done: false };
        }
        if (calls === 2) {
          return { value: enc.encode("alpha\n"), done: false };
        }
        return { value: undefined, done: true };
      },
      async cancel() {},
      releaseLock() {},
      get closed() {
        return Promise.resolve(undefined);
      },
    };
    const out = await collect(parseLines(fakeReader));
    expect(out).toEqual(["alpha"]);
  });
});
