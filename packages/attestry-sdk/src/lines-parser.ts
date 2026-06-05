// ─── Lines parser ───────────────────────────────────────────────────────────
//
// Parses a stream of UTF-8-encoded text bytes into newline-delimited line
// strings. Symmetric to `ndjson-parser.ts` but does NOT JSON.parse — yields
// each line raw. Used by streaming endpoints whose payload is line-oriented
// but NOT JSON (today: `audit-log.export?format=cef`; future: any other
// text/plain-line format such as CSV or syslog).
//
// Subset implemented (mirrors the strict ndjson subset for symmetry):
//   - One value per line, separated by U+000A LINE FEED (`\n`).
//   - UTF-8 decoded with `{stream: true}` so multibyte chars split across
//     reads recombine correctly.
//   - Leading BOM (U+FEFF) stripped once at stream start.
//   - Blank lines silently skipped (lenient — the kernel's CEF path doesn't
//     emit them but defensive parsers should tolerate whitespace artifacts).
//   - Final unterminated line (no trailing `\n`) is emitted (lenient —
//     handles HTTP/1.1 connection-close mid-line).
//   - Buffer cap (1 MiB default) on the residual partial-line buffer,
//     defending against an unbounded line attack.
//   - Trailing `\r` (CRLF artifact) trimmed defensively before yielding.
//   - Mid-stream reader rejections wrapped as `AttestryError` (`AbortError`
//     becomes "request aborted by caller"; everything else becomes
//     "network error during stream: ..."). Symmetric to ndjson-parser
//     post hostile-fix.
//
// The parser yields raw strings; the resource-level caller decides how to
// interpret each line (CEF lines start with "CEF:0|...", but this parser
// doesn't enforce that — forward-compatible with future text formats).

import { AttestryError } from "./errors.js";

/**
 * Maximum residual buffer size before the parser bails. Defends against
 * a server / proxy emitting an unbounded line (no `\n` boundary) — the
 * parser would otherwise accumulate until OOM.
 *
 * 1 MiB matches `ndjson-parser.ts`'s cap. The kernel's CEF emitter caps
 * the `Name` field at 512 bytes and the structured extensions at a
 * handful of KB total; a real audit-log row CEF line is ~1 KB. 1 MiB
 * is ~1000× headroom.
 *
 * Configurable via `parseLines`'s `maxLineBytes` option for callers
 * with legitimate large-line use cases (none today).
 */
const DEFAULT_MAX_LINE_BYTES = 1024 * 1024;

/**
 * Async generator: reads from a stream of UTF-8-encoded line-oriented
 * bytes and yields each `\n`-delimited line as a raw string. Ends when
 * the underlying reader signals `done`. Defensive: a caller that breaks
 * early out of the for-await loop leaves the reader open — call
 * `reader.cancel()` from your finally block (or use `parseLinesResponse`
 * below which handles cleanup automatically).
 *
 * Mid-stream read errors are wrapped as
 * `AttestryError("network error during stream: <reason>")` with the
 * original error chained as `cause`. AbortError-shaped rejects (caller
 * cancelled the underlying signal) are wrapped as
 * `AttestryError("request aborted by caller")` for symmetry with the
 * pre-fetch abort surface and with the ndjson-parser. The resource layer
 * can rely on these wrappings — `runAuditLogExport`'s loop passes any
 * `AttestryError` through verbatim.
 *
 * @throws AttestryError if the residual line buffer exceeds `maxLineBytes`
 *         (defense against unbounded-line DoS), OR the underlying reader
 *         rejects mid-iteration (network drop, abort).
 */
export async function* parseLines(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  options: { maxLineBytes?: number } = {},
): AsyncGenerator<string, void, unknown> {
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
      // The final newline is optional — emit any trailing partial line
      // if non-empty after stripping CR. This handles HTTP/1.1
      // connection-close mid-line: better to surface the partial line
      // to the caller than silently drop it. Symmetric to ndjson-parser.
      const stripped = stripTrailingCR(buffer);
      if (stripped.length > 0) yield stripped;
      return;
    }
    if (value === undefined) continue;
    // `{stream: true}` carries multi-byte UTF-8 boundaries across chunks.
    buffer += decoder.decode(value, { stream: true });

    // Strip a leading BOM (U+FEFF) if present. Kernel doesn't emit a
    // BOM today, but a misconfigured proxy / charset transcoder could
    // prepend one. Without this strip, the first line's first char
    // would be `﻿CEF:0|...` and downstream consumers parsing the
    // CEF prefix would silently fail. One-shot: only at the very first
    // decoded codepoint of the stream.
    //
    // Mirror of ndjson-parser fix: `bomStripped` is only flipped once
    // we've actually decoded at least one character. Otherwise an empty
    // / partial-multibyte first read would set the flag prematurely; if
    // the BOM bytes arrived in a later read, the strip-attempt would
    // be skipped.
    if (!bomStripped && buffer.length > 0) {
      bomStripped = true;
      // Defense-in-depth dead path: in Node 18+ / browsers,
      // `TextDecoder("utf-8")` defaults to `ignoreBOM: false` and
      // strips a stream-start BOM internally — by the time the byte
      // reaches our buffer, the BOM is already gone. Marked for v8
      // coverage to make the intentional defense visible.
      /* v8 ignore next 3 */
      if (buffer.charCodeAt(0) === 0xfeff) {
        buffer = buffer.slice(1);
      }
    }

    // Yield each complete line. We split on `\n` rather than using
    // String.split to keep the indexing explicit (and to make the
    // residual-buffer accounting visible). Symmetric to ndjson-parser.
    while (true) {
      const newlineIdx = buffer.indexOf("\n");
      if (newlineIdx === -1) break;
      const line = buffer.slice(0, newlineIdx);
      buffer = buffer.slice(newlineIdx + 1);
      const stripped = stripTrailingCR(line);
      if (stripped.length === 0) continue; // blank line — skip silently
      yield stripped;
    }

    // Defense in depth: after consuming all complete lines, the residual
    // buffer holds at most a partial line. If THAT exceeds the cap, the
    // server emitted an unbounded line (or omitted the delimiter) — bail
    // before we OOM. Checking after the yield-loop avoids tripping on a
    // single huge chunk that contains many small complete lines.
    if (buffer.length > maxLineBytes) {
      throw new AttestryError(
        `line exceeded maximum buffer size (${maxLineBytes} bytes) — server emitted an unbounded line or omitted the line delimiter`,
      );
    }
  }
}

/**
 * Convenience wrapper around `parseLines` that accepts a `Response`,
 * derives the reader, and ALWAYS calls `reader.cancel()` in a `finally`
 * block — including when a caller breaks out of the for-await loop
 * early. Without this, an early `break` leaks the underlying connection.
 *
 * Resources should call this rather than `parseLines` directly.
 *
 * Symmetric to `parseNDJSONResponse` and `parseSSEResponse`.
 */
export async function* parseLinesResponse(
  response: Response,
  options: { maxLineBytes?: number } = {},
): AsyncGenerator<string, void, unknown> {
  if (response.body === null) {
    // 204 No Content / empty body — iterator ends with zero lines.
    // (Throwing would be over-strict; the server may legitimately close
    // before any data — symmetric to parseNDJSONResponse / parseSSEResponse.)
    return;
  }
  const reader = response.body.getReader();
  try {
    yield* parseLines(reader, options);
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
 * Trim a single trailing `\r` (CR). Defensive: line-oriented streaming
 * formats mandate LF only, but a Windows-tooling artifact could leave
 * a CR before the LF. Trimming exactly one CR keeps the parser permissive
 * without treating CR alone as a line separator.
 */
function stripTrailingCR(s: string): string {
  return s.length > 0 && s.charCodeAt(s.length - 1) === 0x0d ? s.slice(0, -1) : s;
}

/**
 * True if `err` is an AbortError-shaped exception (DOMException or
 * Error with `name === "AbortError"`). Both browsers and Node 18+
 * produce this shape when `fetch` / `reader.read()` is aborted via
 * `AbortController.abort()`. Same helper signature as the one in
 * `ndjson-parser.ts`.
 */
function isAbortErrorShape(err: unknown): boolean {
  return (
    err !== null &&
    typeof err === "object" &&
    "name" in err &&
    (err as { name: unknown }).name === "AbortError"
  );
}

// Test-only handles for direct pinning of internals.
export const __test__ = {
  DEFAULT_MAX_LINE_BYTES,
  stripTrailingCR,
};
