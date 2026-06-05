// ─── Server-Sent Events parser ──────────────────────────────────────────────
//
// Generic SSE frame parser used by streaming resources (today: decisions.stream;
// future: any other text/event-stream endpoint). Reads from a
// `ReadableStreamDefaultReader<Uint8Array>` and yields parsed frames.
//
// Spec: https://html.spec.whatwg.org/multipage/server-sent-events.html
// Subset implemented:
//   - `id:`, `event:`, `data:` field lines (the three the kernel emits today)
//   - Multi-`data:` line concatenation (joined with `\n` per spec)
//   - Comment lines (`:` prefix) — silently dropped (heartbeat handling)
//   - Frames separated by blank line (`\n\n`, `\r\n\r\n`, or `\r\r`)
//   - UTF-8 decoded with `{stream: true}` so multibyte chars split across
//     reads recombine correctly
// Subset deliberately NOT implemented:
//   - `retry:` field (would map to a reconnect-delay hint; we don't
//     auto-reconnect today — caller manages reconnection by passing the
//     last seen event id back as `lastEventId`)
//   - `BOM` stripping at the very first byte (the kernel's text/event-stream
//     never emits a BOM; defensive at the parser level would be over-spec)
//
// The parser is INTENTIONALLY lax about the optional space after the colon:
// `data:foo` and `data: foo` both yield `foo`. The W3C spec (§ 9.2.6) says
// "If value starts with a U+0020 SPACE character, remove it." — implemented.

import { AttestryError } from "./errors.js";

/**
 * One parsed SSE frame. `data` is a string (consumer parses JSON if
 * applicable). `id` and `event` are present iff the frame had those
 * fields. Empty frames (only whitespace, or only comments) are NOT
 * yielded — comments / heartbeats are filtered at the parser level.
 */
export interface SSEFrame {
  /** Value of the `id:` field if present; else undefined. */
  id?: string;
  /** Value of the `event:` field if present; else undefined. */
  event?: string;
  /** Concatenated `data:` lines, joined by `\n`. May be empty string. */
  data: string;
}

/**
 * Maximum buffer size before the parser bails. Defense against a server
 * that emits an unbounded frame (no `\n\n` boundary) — without a cap, the
 * parser would buffer until the consumer's process runs out of memory.
 * 1 MiB is generous: the kernel's frame payload is ~500 bytes today, so
 * 1 MiB is ~2000× headroom. A real-world SSE event larger than this is
 * either a server bug or a hostile peer.
 *
 * Configurable via `parseSSE`'s `maxBufferBytes` option for callers
 * with legitimate large-frame use cases (none today). Hostile-review H3.
 */
const DEFAULT_MAX_BUFFER_BYTES = 1024 * 1024;

/**
 * Async generator: reads from a stream of UTF-8-encoded SSE bytes and
 * yields each complete frame. Ends when the underlying reader signals
 * `done`. Defensive: a caller that breaks early out of the for-await
 * loop leaves the reader open — call `reader.cancel()` from your finally
 * block (or use the `parseSSEResponse` wrapper below which handles it).
 *
 * @throws AttestryError if a frame line is malformed past recovery (no
 *         such case in the kernel's emitter today; future-proofing); OR
 *         if the buffer exceeds `maxBufferBytes` (defense against
 *         unbounded-frame DoS — hostile-review H3).
 */
export async function* parseSSE(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  options: { maxBufferBytes?: number } = {},
): AsyncGenerator<SSEFrame, void, unknown> {
  const maxBufferBytes = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES;
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  let bomStripped = false;

  while (true) {
    const { value, done } = await reader.read();
    if (done) {
      // Flush any final bytes (no-op if value was always complete).
      buffer += decoder.decode();
      // A final unterminated frame is dropped per SSE spec § 9.2.4
      // ("If the end of the file is reached, then dispatch the event and
      // proceed."). Be permissive and emit the trailing block if it has
      // content — an HTTP/1.1 connection-close mid-frame is the most
      // common failure mode and dropping the partial event silently is
      // worse than emitting an under-defined one.
      if (buffer.length > 0) {
        const frame = parseFrameBlock(buffer);
        if (frame !== null) yield frame;
      }
      return;
    }
    if (value === undefined) continue;
    // `{stream: true}` carries multi-byte boundaries across chunks.
    buffer += decoder.decode(value, { stream: true });

    // Strip a leading BOM (U+FEFF) if present. Kernel doesn't emit BOM
    // today, but a misconfigured proxy / character-set transcoder
    // could prepend one. Without this strip, the first frame's first
    // field would be e.g. `"﻿id"` instead of `"id"` and silently
    // drop. Hostile-review H4. One-shot — only at the very first
    // decoded codepoint of the stream.
    //
    // Hostile-review fix (parallel to ndjson-parser): `bomStripped` is
    // only flipped once we've actually decoded at least one character.
    // Otherwise an empty / partial-multibyte first read would set the
    // flag prematurely; if the BOM bytes arrived in a later read, the
    // strip-attempt would be skipped. Defense-in-depth — String.prototype.trim
    // and TextDecoder("utf-8")'s default stream-start BOM handling
    // mask the consumer-visible bug today, but a future TextDecoder
    // change (e.g. `ignoreBOM: true`) would unmask it.
    if (!bomStripped && buffer.length > 0) {
      bomStripped = true;
      // Defense-in-depth dead path: same rationale as
      // ndjson-parser.ts — TextDecoder strips stream-start BOM
      // internally, so the slice below is unreachable in Node 18+.
      // Marked for v8 coverage to make the intentional defense visible;
      // a future `{ignoreBOM: true}` decoder OR a buffer path that
      // bypasses TextDecoder would unmask it.
      /* v8 ignore next 3 */
      if (buffer.charCodeAt(0) === 0xfeff) {
        buffer = buffer.slice(1);
      }
    }

    // Defense in depth: if the buffer grew past the cap WITHOUT
    // a frame boundary, abort rather than spin until OOM. Hostile-
    // review H3.
    if (buffer.length > maxBufferBytes) {
      throw new AttestryError(
        `SSE frame exceeded maximum buffer size (${maxBufferBytes} bytes) — server emitted an unbounded frame or omitted the boundary delimiter`,
      );
    }

    // Find frame boundaries. Spec allows `\r\n\r\n`, `\n\n`, or `\r\r`
    // as the separator. Scan with a regex that accepts any.
    while (true) {
      const match = FRAME_BOUNDARY.exec(buffer);
      if (match === null) break;
      const block = buffer.slice(0, match.index);
      buffer = buffer.slice(match.index + match[0].length);
      if (block.length === 0) continue; // back-to-back blank lines
      const frame = parseFrameBlock(block);
      if (frame !== null) yield frame;
    }
  }
}

/**
 * Convenience wrapper around `parseSSE` that accepts a `Response`,
 * derives the reader, and ALWAYS calls `reader.cancel()` in a `finally`
 * block — including when a caller breaks out of the for-await loop
 * early. Without this, an early `break` leaks the underlying connection.
 *
 * Resources should call this rather than `parseSSE` directly.
 */
export async function* parseSSEResponse(
  response: Response,
  options: { maxBufferBytes?: number } = {},
): AsyncGenerator<SSEFrame, void, unknown> {
  if (response.body === null) {
    // 204 No Content / empty body — iterator ends with zero frames.
    // Consumer's for-await loop runs zero times. (Throwing here would
    // be over-strict; the server may legitimately close before any data.)
    return;
  }
  const reader = response.body.getReader();
  try {
    yield* parseSSE(reader, options);
  } finally {
    // Release the lock + signal cancellation upstream. Wrapped in
    // try/catch because cancel() on an already-closed reader rejects.
    try {
      await reader.cancel();
    } catch {
      // Already canceled / closed — nothing to do.
    }
  }
}

// ─── Internals ──────────────────────────────────────────────────────────────

/**
 * One block of SSE text (delimited by blank line) → a parsed frame, or
 * `null` if the block was nothing but comments / whitespace.
 *
 * Per spec:
 *   - Lines beginning with `:` are comments, ignored.
 *   - Otherwise split on first `:` into `field` + `value`.
 *   - If `value` starts with U+0020 SPACE, remove ONE leading space.
 *   - Multiple `data:` lines accumulate, joined by `\n`.
 *   - Field names other than `id`, `event`, `data`, `retry` are ignored.
 */
function parseFrameBlock(block: string): SSEFrame | null {
  let id: string | undefined;
  let eventType: string | undefined;
  let dataLines: string[] | null = null;
  let sawNonComment = false;

  // Split on any of `\r\n`, `\n`, or `\r` per spec. Use a character
  // class regex so we don't hit the trailing-empty-string edge case
  // that String.split with a multi-char separator can produce.
  for (const line of block.split(/\r\n|\n|\r/)) {
    if (line.length === 0) continue;
    if (line[0] === ":") continue; // comment
    sawNonComment = true;
    const colonIdx = line.indexOf(":");
    let field: string;
    let value: string;
    if (colonIdx === -1) {
      // Per spec: "If line contains no U+003A COLON character, set field to
      // line and value to the empty string." — we don't recognize any
      // value-less fields today, so silently drop these.
      field = line;
      value = "";
    } else {
      field = line.slice(0, colonIdx);
      value = line.slice(colonIdx + 1);
      if (value.length > 0 && value[0] === " ") value = value.slice(1);
    }
    switch (field) {
      case "id":
        // Per spec: "If the field value does not contain U+0000 NULL,
        // then set the last event ID buffer to the field value."
        if (!value.includes(" ")) id = value;
        break;
      case "event":
        eventType = value;
        break;
      case "data":
        if (dataLines === null) dataLines = [];
        dataLines.push(value);
        break;
      case "retry":
        // Reconnect-delay hint. Not implemented — see file header.
        break;
      default:
        // Unknown field — silently ignored per spec. Don't throw; future
        // server-side fields shouldn't break consumers.
        break;
    }
  }

  if (!sawNonComment) return null;

  // Defense in depth: if EVERY non-comment line was an unrecognized
  // field, we still produced no data. Emitting an empty-data event is
  // confusing — drop. Consumer never has to handle a frame with no
  // content. (SSE spec strictly says emit anyway, but our wire shape
  // always carries data.)
  if (dataLines === null) {
    if (id === undefined && eventType === undefined) return null;
    // id-only or event-only is unusual but valid — the kernel doesn't
    // emit these today, but defensively pass them through with empty data
    // rather than swallowing the metadata entirely.
    return { id, event: eventType, data: "" };
  }

  return {
    id,
    event: eventType,
    data: dataLines.join("\n"),
  };
}

/**
 * Frame-boundary regex — matches `\r\n\r\n`, `\n\n`, or `\r\r` per spec.
 * Exported only for tests.
 */
const FRAME_BOUNDARY = /\r\n\r\n|\n\n|\r\r/g;

/**
 * Parse a `data:` payload as JSON. Throws `AttestryError` (with the
 * underlying error as `cause`) if the payload isn't valid JSON. Resources
 * call this when the wire shape is documented as JSON-encoded.
 */
export function parseSSEData<T>(data: string): T {
  try {
    return JSON.parse(data) as T;
  } catch (err) {
    throw new AttestryError(
      `SSE frame data was not valid JSON: ${
        // JSON.parse always throws SyntaxError (an Error subclass), so
        // the String(err) branch is unreachable. Defense-in-depth.
        /* v8 ignore next */
        err instanceof Error ? err.message : String(err)
      }`,
      { cause: err },
    );
  }
}

// Test-only handles for direct pinning of internals.
export const __test__ = {
  FRAME_BOUNDARY,
  parseFrameBlock,
};
