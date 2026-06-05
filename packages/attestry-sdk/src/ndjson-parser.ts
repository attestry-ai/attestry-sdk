// ─── NDJSON parser ──────────────────────────────────────────────────────────
//
// Parses application/x-ndjson (newline-delimited JSON) streams. One JSON
// value per `\n`-delimited line. Symmetric to `sse-parser.ts` but
// simpler — no event/id/data headers, no multi-line frame join, no
// optional retry: hint.
//
// Used by streaming endpoints whose payload is a sequence of opaque JSON
// frames (today: `decisions.export`; future: `audit-log/export`,
// `bundles/export`). The parser yields raw `unknown` values; the
// resource-level caller validates frame shape.
//
// Spec:
//   https://github.com/ndjson/ndjson-spec
//
// Subset implemented:
//   - One JSON value per line, separated by U+000A LINE FEED (`\n`).
//   - UTF-8 decoded with `{stream: true}` so multibyte chars split
//     across reads recombine correctly.
//   - Leading BOM (U+FEFF) stripped once at stream start.
//   - Blank lines silently skipped (lenient — kernel doesn't emit them
//     but defensive parsers should tolerate whitespace).
//   - Final unterminated line (no trailing `\n`) is emitted (lenient —
//     handles HTTP/1.1 connection-close mid-line).
//   - Buffer cap (1 MiB default) on the residual partial-line buffer,
//     defending against an unbounded line attack.
//
// Subset deliberately NOT implemented:
//   - `\r` / `\r\n` line endings — strict NDJSON spec mandates `\n`
//     only. The parser trims trailing `\r` defensively before parsing
//     (Windows-tooling artifact) but does NOT treat `\r` alone as a
//     line separator.
//   - Comment lines — ndjson has no comment syntax.

import { AttestryError } from "./errors.js";

/**
 * Maximum residual buffer size before the parser bails. Defends against
 * a server / proxy emitting an unbounded line (no `\n` boundary) — the
 * parser would otherwise accumulate until OOM.
 *
 * 1 MiB is generous: the kernel's `decisions.export` per-record line is
 * ~1 KB today (a record with empty jsonb arrays serialises near 500
 * bytes; with claims/invocations populated, ~2 KB). 1 MiB is ~1000×
 * headroom.
 *
 * Configurable via `parseNDJSON`'s `maxLineBytes` option for callers
 * with legitimate large-line use cases (none today).
 */
const DEFAULT_MAX_LINE_BYTES = 1024 * 1024;

/**
 * Async generator: reads from a stream of UTF-8-encoded NDJSON bytes
 * and yields each parsed JSON value. Ends when the underlying reader
 * signals `done`. Defensive: a caller that breaks early out of the
 * for-await loop leaves the reader open — call `reader.cancel()` from
 * your finally block (or use `parseNDJSONResponse` below which handles
 * cleanup automatically).
 *
 * Mid-stream read errors are wrapped as
 * `AttestryError("network error during stream: <reason>")` with the
 * original error chained as `cause`. AbortError-shaped rejects (caller
 * cancelled the underlying signal) are wrapped as
 * `AttestryError("request aborted by caller")` for symmetry with the
 * pre-fetch abort surface. The resource layer can rely on these
 * wrappings — `runDecisionsExport`'s catch passes any `AttestryError`
 * through verbatim.
 *
 * @throws AttestryError if a JSON line fails to parse, OR the residual
 *         line buffer exceeds `maxLineBytes` (defense against unbounded-
 *         line DoS), OR the underlying reader rejects mid-iteration
 *         (network drop, abort).
 */
export async function* parseNDJSON(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  options: { maxLineBytes?: number } = {},
): AsyncGenerator<unknown, void, unknown> {
  const maxLineBytes = options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES;
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  let bomStripped = false;

  while (true) {
    let result: ReadableStreamReadResult<Uint8Array>;
    try {
      result = await reader.read();
    } catch (err) {
      // Mid-stream reader rejects: TCP RST, proxy hang-up, signal-
      // aborted fetch. Wrap with a clear AttestryError so consumers
      // can branch uniformly via `instanceof AttestryError` rather
      // than having to type-narrow on raw DOMException / TypeError.
      // Resource-layer wrapper passes AttestryError through verbatim.
      if (isAbortErrorShape(err)) {
        throw new AttestryError("request aborted by caller", { cause: err });
      }
      throw new AttestryError(
        `network error during stream: ${
          err instanceof Error ? err.message : String(err)
        }`,
        { cause: err },
      );
    }
    const { value, done } = result;
    if (done) {
      // Flush any final bytes (no-op if value was always complete).
      buffer += decoder.decode();
      // Per NDJSON spec, the final newline is optional — emit any
      // trailing partial line if non-empty after trimming. This handles
      // HTTP/1.1 connection-close mid-line: better to surface the
      // partial frame to the caller (who can then validate its shape)
      // than silently drop it.
      const trimmed = stripTrailingCR(buffer).trim();
      if (trimmed.length > 0) yield parseLine(trimmed);
      return;
    }
    if (value === undefined) continue;
    // `{stream: true}` carries multi-byte UTF-8 boundaries across chunks.
    buffer += decoder.decode(value, { stream: true });

    // Strip a leading BOM (U+FEFF) if present. Kernel doesn't emit a
    // BOM today, but a misconfigured proxy / charset transcoder could
    // prepend one. Without this strip, the first frame's first char
    // would be `﻿{` and `JSON.parse` would throw with an
    // unhelpful "unexpected character" error. One-shot: only at the
    // very first decoded codepoint of the stream.
    //
    // Hostile-review fix: `bomStripped` is now only flipped once we've
    // actually decoded at least one character. Otherwise an empty /
    // partial-multibyte first read would set the flag prematurely; if
    // the BOM bytes (or a continuation that the decoder treats as
    // mid-stream-data BOM) arrived in a later read, the strip-attempt
    // would be skipped. Defense-in-depth — `String.prototype.trim()`
    // happens to treat U+FEFF as whitespace and the default
    // `TextDecoder("utf-8")` strips a stream-start BOM internally, so
    // the consumer-visible bug is masked today. Pinning the correct
    // shape regardless so a future change (`ignoreBOM: true`, or a
    // line that doesn't run through `.trim()`) doesn't reintroduce it.
    if (!bomStripped && buffer.length > 0) {
      bomStripped = true;
      // Defense-in-depth dead path: in Node 18+ / browsers,
      // `TextDecoder("utf-8")` defaults to `ignoreBOM: false` and
      // strips a stream-start BOM internally — by the time the byte
      // reaches our buffer, the BOM is already gone. The two lines
      // below are reachable only if a future refactor passes
      // `{ignoreBOM: true}` to TextDecoder OR processes the buffer
      // through some path that bypasses TextDecoder's strip. Marked
      // for v8 coverage to make the intentional defense visible.
      /* v8 ignore next 3 */
      if (buffer.charCodeAt(0) === 0xfeff) {
        buffer = buffer.slice(1);
      }
    }

    // Yield each complete line. We split on `\n` rather than using
    // String.split to keep the indexing explicit (and to make the
    // residual-buffer accounting visible).
    while (true) {
      const newlineIdx = buffer.indexOf("\n");
      if (newlineIdx === -1) break;
      const line = buffer.slice(0, newlineIdx);
      buffer = buffer.slice(newlineIdx + 1);
      const trimmed = stripTrailingCR(line).trim();
      if (trimmed.length === 0) continue; // blank line — skip silently
      yield parseLine(trimmed);
    }

    // Defense in depth: after consuming all complete lines, the residual
    // buffer holds at most a partial line. If THAT exceeds the cap, the
    // server emitted an unbounded line (or omitted the delimiter) — bail
    // before we OOM. Checking after the yield-loop avoids tripping on a
    // single huge chunk that contains many small complete lines.
    if (buffer.length > maxLineBytes) {
      throw new AttestryError(
        `NDJSON line exceeded maximum buffer size (${maxLineBytes} bytes) — server emitted an unbounded line or omitted the line delimiter`,
      );
    }
  }
}

/**
 * Convenience wrapper around `parseNDJSON` that accepts a `Response`,
 * derives the reader, and ALWAYS calls `reader.cancel()` in a `finally`
 * block — including when a caller breaks out of the for-await loop
 * early. Without this, an early `break` leaks the underlying connection.
 *
 * Resources should call this rather than `parseNDJSON` directly.
 *
 * Symmetric to `parseSSEResponse`.
 */
export async function* parseNDJSONResponse(
  response: Response,
  options: { maxLineBytes?: number } = {},
): AsyncGenerator<unknown, void, unknown> {
  if (response.body === null) {
    // 204 No Content / empty body — iterator ends with zero frames.
    // (Throwing would be over-strict; the server may legitimately close
    // before any data — symmetric to parseSSEResponse.)
    return;
  }
  const reader = response.body.getReader();
  try {
    yield* parseNDJSON(reader, options);
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
 * Trim a single trailing `\r` (CR). Defensive: NDJSON spec mandates LF
 * only, but a Windows-tooling artifact could leave a CR before the LF.
 * Trimming exactly one CR keeps the parser permissive without treating
 * CR alone as a line separator.
 */
function stripTrailingCR(s: string): string {
  return s.length > 0 && s.charCodeAt(s.length - 1) === 0x0d ? s.slice(0, -1) : s;
}

/**
 * True if `err` is an AbortError-shaped exception (DOMException or
 * Error with `name === "AbortError"`). Both browsers and Node 18+
 * produce this shape when `fetch` / `reader.read()` is aborted via
 * `AbortController.abort()`. Type-narrowing on DOMException alone is
 * too broad (it includes other DOM error types); check by name. Same
 * helper signature as `isAbortError` in `resources/decisions.ts`.
 */
function isAbortErrorShape(err: unknown): boolean {
  return (
    err !== null &&
    typeof err === "object" &&
    "name" in err &&
    (err as { name: unknown }).name === "AbortError"
  );
}

/**
 * Parse one trimmed line as JSON. Throws `AttestryError` (with the
 * underlying error as `cause`) if the payload isn't valid JSON.
 */
function parseLine(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch (err) {
    throw new AttestryError(
      `NDJSON line was not valid JSON: ${
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
  DEFAULT_MAX_LINE_BYTES,
  parseLine,
  stripTrailingCR,
};
