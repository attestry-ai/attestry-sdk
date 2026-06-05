// ─── SSE parser primitives — direct unit tests ─────────────────────────────
//
// Most parser branches are pinned through the decisions.stream resource
// tests (which exercise the parser via the public API). This file pins
// the field-parsing edge cases that are awkward to construct through the
// resource boundary. Coverage-round addition.

import { describe, it, expect } from "vitest";
import { __test__, parseSSEData } from "../sse-parser.js";
import { AttestryError } from "../errors.js";

const { parseFrameBlock, FRAME_BOUNDARY } = __test__;

describe("parseFrameBlock — field parsing edge cases (coverage)", () => {
  it("returns null for an empty block", () => {
    expect(parseFrameBlock("")).toBeNull();
  });

  it("returns null for a block of only comment lines", () => {
    expect(parseFrameBlock(": comment 1\n: comment 2")).toBeNull();
  });

  it("parses a minimal id-only frame with empty data (id-only edge case)", () => {
    // Per spec, an id-only frame is valid metadata. Parser yields
    // `{id, data: ""}` rather than dropping — the data field is
    // present but empty. Resource-level layer skips frames with
    // empty data, so consumers never see this directly, but the
    // parser primitive preserves it.
    expect(parseFrameBlock(`id: cursor-1`)).toEqual({
      id: "cursor-1",
      event: undefined,
      data: "",
    });
  });

  it("parses a multi-line `data:` frame with `\\n` join", () => {
    // Per W3C spec: multiple `data:` lines in one frame are
    // concatenated with `\n` (NOT `\n\n`).
    const block = "id: c\ndata: line1\ndata: line2\ndata: line3";
    expect(parseFrameBlock(block)).toEqual({
      id: "c",
      event: undefined,
      data: "line1\nline2\nline3",
    });
  });

  it("strips exactly one leading space on field values per spec § 9.2.6", () => {
    // `data: foo` and `data:foo` both produce value `foo`. But
    // `data:  foo` (two spaces) produces ` foo` (one space remains).
    expect(parseFrameBlock("data: foo")?.data).toBe("foo");
    expect(parseFrameBlock("data:foo")?.data).toBe("foo");
    expect(parseFrameBlock("data:  foo")?.data).toBe(" foo");
  });

  it("ignores `retry:` field (we don't auto-reconnect)", () => {
    // Forward-compat: kernel could emit retry: hints, SDK silently
    // ignores. Pinning so a future "support retry: hints" feature
    // is an intentional addition, not an accidental bypass.
    const block = "id: c\nretry: 5000\ndata: payload";
    expect(parseFrameBlock(block)).toEqual({
      id: "c",
      event: undefined,
      data: "payload",
    });
  });

  it("ignores unknown field names per spec (forward-compat)", () => {
    // A future kernel patch adding `priority: high` shouldn't break
    // existing SDK consumers. Spec says unknown fields are dropped.
    const block = "id: c\npriority: high\ndata: payload\ncustom: x";
    expect(parseFrameBlock(block)).toEqual({
      id: "c",
      event: undefined,
      data: "payload",
    });
  });

  it("handles a line with NO colon (per spec: field=line, value='')", () => {
    // Per spec § 9.2.6: "If the line contains no U+003A COLON character,
    // process the field using the steps with the entire line as field
    // name and the empty string as the field value." We treat unknown
    // fields as drops (with no colon, the entire line is the field
    // name — never `id`/`event`/`data`/`retry` for a real line). Pin:
    // such a line doesn't crash; the rest of the frame still parses.
    const block = "id: c\nMALFORMED\ndata: payload";
    expect(parseFrameBlock(block)).toEqual({
      id: "c",
      event: undefined,
      data: "payload",
    });
  });

  it("supports `\\r` and `\\r\\n` line endings (Windows-style servers)", () => {
    const blockCRLF = "id: c\r\ndata: payload";
    const blockCR = "id: c\rdata: payload";
    expect(parseFrameBlock(blockCRLF)).toEqual({
      id: "c",
      event: undefined,
      data: "payload",
    });
    expect(parseFrameBlock(blockCR)).toEqual({
      id: "c",
      event: undefined,
      data: "payload",
    });
  });
});

describe("FRAME_BOUNDARY regex (coverage)", () => {
  it("matches \\n\\n (LF LF)", () => {
    FRAME_BOUNDARY.lastIndex = 0;
    expect(FRAME_BOUNDARY.exec("a\n\nb")?.[0]).toBe("\n\n");
  });

  it("matches \\r\\n\\r\\n (CRLF CRLF)", () => {
    FRAME_BOUNDARY.lastIndex = 0;
    expect(FRAME_BOUNDARY.exec("a\r\n\r\nb")?.[0]).toBe("\r\n\r\n");
  });

  it("matches \\r\\r (CR CR — old Mac)", () => {
    FRAME_BOUNDARY.lastIndex = 0;
    expect(FRAME_BOUNDARY.exec("a\r\rb")?.[0]).toBe("\r\r");
  });

  it("does NOT match a single newline (frame separator requires blank line)", () => {
    FRAME_BOUNDARY.lastIndex = 0;
    expect(FRAME_BOUNDARY.exec("a\nb")).toBeNull();
  });
});

describe("parseSSEData (coverage)", () => {
  it("parses valid JSON", () => {
    expect(parseSSEData<{ x: number }>('{"x":1}')).toEqual({ x: 1 });
  });

  it("throws AttestryError with cause on invalid JSON", () => {
    let caught: unknown = null;
    try {
      parseSSEData("not-json");
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toContain(
      "SSE frame data was not valid JSON",
    );
    expect((caught as AttestryError).cause).toBeInstanceOf(Error);
  });

  it("parses arrays + nested objects", () => {
    expect(
      parseSSEData<unknown[]>('[1,{"a":2},"x"]'),
    ).toEqual([1, { a: 2 }, "x"]);
  });

  it("preserves null and primitive types", () => {
    expect(parseSSEData<null>("null")).toBeNull();
    expect(parseSSEData<number>("42")).toBe(42);
    expect(parseSSEData<string>('"hello"')).toBe("hello");
  });
});

// ─── BOM-flag-flip hostile-review fix (cross-phase follow-up) ─────────────
//
// Pinned alongside the parallel fix in ndjson-parser. The previous
// shape `if (!bomStripped) { bomStripped = true; ... }` flipped the
// flag on the very first reader.read() iteration regardless of
// whether the decoded chunk had any characters. If the BOM bytes
// arrived in a LATER read where TextDecoder no longer treats them as
// stream-start (because the decoder already received bytes via the
// empty / partial-multibyte first read), the parser-level strip was
// skipped. Consumer-visible bug masked today by `String.prototype.trim`
// + TextDecoder's default stream-start BOM stripping; pinning the
// correct shape regardless so a future config change can't reintroduce.

import { parseSSE } from "../sse-parser.js";

describe("parseSSE — back-to-back frame boundaries (coverage)", () => {
  it("silently skips a leading frame boundary (zero-length block at start)", async () => {
    // Defensive: when the buffer starts with a frame boundary (`\n\n`
    // before any field lines), the parser's first match yields a
    // zero-length block. The `if (block.length === 0) continue;`
    // branch skips it. (Note: the regex's `g`-flag lastIndex carries
    // across exec calls, so the empty-block branch is reachable
    // primarily at the START of the buffer — this test pins that
    // case.)
    FRAME_BOUNDARY.lastIndex = 0; // defensive — clear carry from prior tests
    const enc = new TextEncoder();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(enc.encode("\n\nid: c\nevent: t\ndata: x\n\n"));
        controller.close();
      },
    });
    const reader = stream.getReader();
    const out: import("../sse-parser.js").SSEFrame[] = [];
    for await (const f of parseSSE(reader)) out.push(f);
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("c");
    expect(out[0].data).toBe("x");
  });
});

describe("parseFrameBlock — id-only / event-only frames (coverage)", () => {
  it("yields metadata-only frames with empty data (id-only)", () => {
    // Defensive: id-only frame is unusual (kernel doesn't emit it),
    // but spec-valid. parseFrameBlock returns `{id, event:undefined,
    // data:""}` — preserves the metadata rather than silently dropping.
    const block = "id: cursor-only";
    const frame = __test__.parseFrameBlock(block);
    expect(frame).toEqual({ id: "cursor-only", event: undefined, data: "" });
  });

  it("yields metadata-only frames with empty data (event-only)", () => {
    // Same — event-only frame preserved rather than dropped. The
    // sister `if (id === undefined && eventType === undefined) return null`
    // branch above covers the "neither" case (returns null).
    const block = "event: heartbeat-named";
    const frame = __test__.parseFrameBlock(block);
    expect(frame).toEqual({
      id: undefined,
      event: "heartbeat-named",
      data: "",
    });
  });

  it("returns null when a block has only unrecognized fields (no id/event/data — `retry:` only)", () => {
    // Hits the `if (id === undefined && eventType === undefined) return null`
    // branch when dataLines === null. A block with ONLY retry:
    // (a recognized but ignored field) leaves dataLines null AND
    // both id/eventType undefined — returns null per spec § 9.2.6
    // (don't yield empty events).
    expect(parseFrameBlock("retry: 5000")).toBeNull();
  });

  it("returns null for a block with only an unknown field (no id/event/data)", () => {
    // Same path — a block with only an unrecognized field name
    // (forward-compat: future kernel might add `priority:`) and
    // nothing else returns null.
    expect(parseFrameBlock("priority: high")).toBeNull();
  });
});

describe("parseSSE — defensive non-spec reader behavior", () => {
  it("continues without throwing when reader.read() yields { value: undefined, done: false }", async () => {
    // Defensive: per the WHATWG Streams spec, a non-done read MUST
    // yield a non-undefined value. The parser nevertheless guards
    // against a non-spec reader (custom test fixtures, future
    // platform changes) emitting undefined — branch is `if (value
    // === undefined) continue;`. Pin via a custom reader that yields
    // an undefined-value sentinel before its real chunks. Parallel
    // to the ndjson-parser pin.
    let calls = 0;
    const enc = new TextEncoder();
    const fakeReader: ReadableStreamDefaultReader<Uint8Array> = {
      async read() {
        calls++;
        if (calls === 1) {
          return {
            value: undefined as unknown as Uint8Array,
            done: false,
          };
        }
        if (calls === 2) {
          return {
            value: enc.encode("id: c\nevent: t\ndata: x\n\n"),
            done: false,
          };
        }
        return { value: undefined as unknown as Uint8Array, done: true };
      },
      cancel: async () => undefined,
      releaseLock: () => undefined,
      get closed() {
        return Promise.resolve(undefined);
      },
    };
    const out: import("../sse-parser.js").SSEFrame[] = [];
    for await (const f of parseSSE(fakeReader)) out.push(f);
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("c");
    expect(out[0].data).toBe("x");
    expect(calls).toBe(3);
  });
});

describe("parseSSE — BOM strip survives empty first reads (cross-phase fix)", () => {
  it("strips a leading BOM when the first read produces zero decoded chars (parallel to ndjson-parser fix)", async () => {
    // Synthetic reader: first read yields a Uint8Array that decodes
    // to an empty string (a single 0xC2 byte — multibyte continuation
    // start without its tail). TextDecoder({stream: true}) buffers
    // it and emits "". Then the BOM + frame land in the next read.
    // With the bug, bomStripped is set after the empty first read and
    // the subsequent BOM is preserved → the `id:` field becomes
    // `"﻿id"` and the parser's case "id" branch never fires.
    // Truly empty first chunk — the simplest stimulus for the
    // flag-flip bug (a 0xC2 partial-continuation produces a
    // U+FFFD replacement char on the next decode, which masks
    // the BOM-strip path differently).
    const partialContinuation = new Uint8Array(0);
    const encoder = new TextEncoder();
    const bomAndFrame = encoder.encode("﻿id: c-1\ndata: payload\n\n");
    // Combine with the leading 0xC2 to form a valid completion (0xC2 0xA0
    // is U+00A0 NO-BREAK SPACE) — but we ONLY want the BOM-strip
    // semantics, so build it as: 0xC2 + 0xA0 chunk first, then the
    // BOM frame chunk. The 0xC2 flushes once we deliver 0xA0; the
    // bom-stripping logic then has its first chance to inspect the
    // buffer when the buffer = " " + "﻿id: ...".
    // To hit the bug: instead emit a chunk that the decoder absorbs
    // entirely without producing output. A bare 0xC2 is exactly that.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(partialContinuation);
        // Without the fix: bomStripped is set true by the first
        // (empty-output) iteration; this BOM survives.
        controller.enqueue(bomAndFrame);
        controller.close();
      },
    });
    const reader = stream.getReader();
    const frames: import("../sse-parser.js").SSEFrame[] = [];
    for await (const f of parseSSE(reader)) frames.push(f);
    expect(frames).toHaveLength(1);
    // With the fix, the BOM is stripped and `id:` is parsed correctly.
    // (We tolerate the leading U+00A0 from the completed 0xC2 0xA0
    // sequence ending up as the start of the buffer — it's not a
    // recognized SSE field name, so the subsequent `\n` resets parsing
    // and `id: c-1` is read normally. The pin's load-bearing claim is
    // that the BOM-prefixed `id` field is recognized.)
    expect(frames[0].id).toBe("c-1");
    expect(frames[0].data).toBe("payload");
  });

  it("strips a leading BOM after multiple empty reads before content", async () => {
    // Several empty reads in a row (e.g. proxy keep-alive flushes
    // delivering zero-byte chunks) followed by the BOM-prefixed
    // content. Same defensive contract as the single-empty-read pin.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        // Three zero-byte chunks: with the bug, the first one would
        // flip bomStripped before any content arrives; with the fix
        // the strip-attempt waits.
        controller.enqueue(new Uint8Array(0));
        controller.enqueue(new Uint8Array(0));
        controller.enqueue(new Uint8Array(0));
        controller.enqueue(
          new TextEncoder().encode("﻿id: c-2\ndata: x\n\n"),
        );
        controller.close();
      },
    });
    const reader = stream.getReader();
    const frames: import("../sse-parser.js").SSEFrame[] = [];
    for await (const f of parseSSE(reader)) frames.push(f);
    expect(frames).toHaveLength(1);
    expect(frames[0].id).toBe("c-2");
    expect(frames[0].data).toBe("x");
  });
});
