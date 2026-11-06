// ─── HTTP transport ─────────────────────────────────────────────────────────
//
// `request` is the single-entry point for every API call. Resources call
// it via the client. Behavior:
//
//   - Adds `x-api-key` header from the client's options.
//   - Adds `Content-Type: application/json` when sending a body.
//   - Adds `Accept: application/json` always.
//   - Composes the final URL from `baseUrl + path` with safe slash handling.
//   - Times out via `AbortController` after `timeoutMs` (default 30s;
//     per-call `options.timeoutMs` overrides); caller can also pass their
//     own `signal` which is composed with the timeout signal. Both stay in
//     force until the response BODY has been fully read, not just until
//     the headers arrive (0.8.0).
//   - Never follows redirects (`redirect: "manual"`), so `x-api-key` is
//     never forwarded to another URL. A 3xx — or a 2xx whose
//     Content-Type is not the expected one (e.g. an HTML login / gate
//     page) — fails with an `AttestryAPIError` naming the URL and
//     pointing at `baseUrl` (0.8.0).
//   - Decodes 2xx JSON responses to `T`. 204 / empty body returns `null
//     as T` — caller types tell the truth.
//   - Unwraps the kernel's `successResponse` envelope (`{success:true, data}`)
//     when present; bare bodies pass through.
//   - Throws `AttestryAPIError` for any non-2xx status with the parsed
//     body (or `null` if the body wasn't JSON / was empty).
//   - Throws `AttestryError` for fetch failures (network down, DNS fail,
//     timeout). The original error is attached as `cause`.
//   - Automatically retries on HTTP 429 (default 3 retries, exponential
//     backoff with full jitter, honors `Retry-After` header). Configurable
//     via `AttestryClientOptions.retry` and `RequestOptions.retry`. See
//     `retry.ts` and `audit-prompt-F.1-retry-middleware.md` for design.
//     Retry on other transient statuses (5xx) is NOT implemented — adding
//     it requires HTTP-level idempotency-key support on the kernel side
//     to safely re-send POSTs.

import { AttestryAPIError, AttestryError } from "./errors.js";
import {
  attachRetryAfter,
  isRetryableError,
  computeRetryDelay,
  resolveRetryOptions,
  sleepWithSignal,
  type RetryOptions,
} from "./retry.js";
import type {
  AttestryClientOptions,
  FetchLike,
  RequestOptions,
} from "./types.js";

const DEFAULT_BASE_URL = "https://attestry.ai";
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Largest delay `setTimeout` honours. Larger values overflow to ~1ms in
 * Node and browsers (the timer would fire immediately), so a very large
 * `timeoutMs` is clamped to this (~24.8 days) rather than misfiring.
 */
const MAX_TIMER_MS = 2_147_483_647;

/** Leading / trailing HTTP whitespace (HTAB, LF, CR, SP) — what fetch's header normalization strips. */
const LEADING_HTTP_WS = /^[\t\n\r ]+/;
const TRAILING_HTTP_WS = /[\t\n\r ]+$/;
/** Visible ASCII (`VCHAR`, 0x21–0x7E) — the only characters an API key may contain. */
const VISIBLE_ASCII = /^[\x21-\x7e]+$/;

interface ResolvedClientConfig {
  apiKey: string;
  baseUrl: string;
  fetchImpl: FetchLike;
  timeoutMs: number;
  /**
   * True when the caller passed `timeoutMs` to the constructor. An explicit
   * client-wide timeout beats a per-method default (e.g. the 300s default
   * of `annexIv.generate`); the SDK's 30s fallback does not.
   */
  timeoutMsExplicit: boolean;
  retry: Partial<RetryOptions> | undefined;
}

/**
 * Validates the API key as an HTTP header value and returns it with
 * leading / trailing HTTP whitespace removed (the same normalization
 * `Headers.set` applies, so a key read from a file with a trailing newline
 * keeps working). Anything else outside visible ASCII — an embedded
 * CR/LF, a space or tab, a control character, or a non-ASCII character
 * such as a pasted smart quote — throws `AttestryError` here instead of a
 * raw `TypeError` on every request. The key itself is never echoed.
 */
function validateApiKey(raw: unknown): string {
  if (typeof raw !== "string" || raw.length === 0) {
    throw new AttestryError("AttestryClient: `apiKey` is required");
  }
  const apiKey = raw.replace(LEADING_HTTP_WS, "").replace(TRAILING_HTTP_WS, "");
  if (apiKey.length === 0) {
    throw new AttestryError(
      "AttestryClient: `apiKey` is required (got only whitespace)",
    );
  }
  if (!VISIBLE_ASCII.test(apiKey)) {
    let bad = "";
    for (const ch of apiKey) {
      const cp = ch.codePointAt(0) as number;
      if (cp < 0x21 || cp > 0x7e) {
        bad = `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
        break;
      }
    }
    throw new AttestryError(
      `AttestryClient: \`apiKey\` is not a valid HTTP header value — it contains ${bad}, but API keys are visible ASCII only (check for a stray newline, space, or smart quote from copy/paste)`,
    );
  }
  return apiKey;
}

/**
 * Validates options at construction time. Surfaces every misconfiguration
 * as `AttestryError` BEFORE any request is made — fail-fast beats failing
 * deep in the resource methods. Used by `AttestryClient` constructor.
 */
export function resolveClientConfig(
  options: AttestryClientOptions,
): ResolvedClientConfig {
  const apiKey = validateApiKey(options.apiKey);

  const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  if (baseUrl.length === 0) {
    throw new AttestryError("AttestryClient: `baseUrl` cannot be empty");
  }

  const fetchImpl = options.fetch ?? (globalThis.fetch as FetchLike | undefined);
  if (typeof fetchImpl !== "function") {
    throw new AttestryError(
      "AttestryClient: no `fetch` implementation available — pass `options.fetch` or run on Node 20.19+",
    );
  }

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
    throw new AttestryError(
      "AttestryClient: `timeoutMs` must be a non-negative finite number",
    );
  }

  // Validate retry option at construction time too — `resolveRetryOptions`
  // throws on invalid values (negative maxRetries, non-finite delay, etc.).
  // Calling it here means a misconfigured client surfaces fast, not on
  // first request. We discard the result; per-call `resolveRetryOptions`
  // re-merges with any RequestOptions.retry override.
  if (options.retry !== undefined) {
    resolveRetryOptions(options.retry, undefined);
  }

  return {
    apiKey,
    baseUrl,
    fetchImpl,
    timeoutMs,
    timeoutMsExplicit: options.timeoutMs !== undefined,
    retry: options.retry,
  };
}

/**
 * Resolves the timeout for one call. Precedence: per-call
 * `options.timeoutMs` → an explicitly configured client `timeoutMs` → the
 * method's own default (`methodDefaultTimeoutMs`, e.g. 300s for
 * `annexIv.generate`) → the SDK default (30s). `0` disables the timeout.
 */
function resolveTimeoutMs(
  config: ResolvedClientConfig,
  options: RequestOptions | undefined,
  methodDefaultTimeoutMs: number | undefined,
): number {
  const perCall = options?.timeoutMs;
  if (perCall !== undefined) {
    if (typeof perCall !== "number" || !Number.isFinite(perCall) || perCall < 0) {
      throw new AttestryError(
        "`options.timeoutMs` must be a non-negative finite number",
      );
    }
    return perCall;
  }
  if (methodDefaultTimeoutMs !== undefined && !config.timeoutMsExplicit) {
    return methodDefaultTimeoutMs;
  }
  return config.timeoutMs;
}

/**
 * One request's cancellation scope: the `timeoutMs` deadline composed with
 * the caller's `AbortSignal`. `dispose()` MUST be called once the response
 * body has been fully read (or the request has failed) — NOT when `fetch`
 * resolves, which only means the headers arrived. Disposing at that point
 * left the body read unguarded: a stalled body hung forever despite
 * `timeoutMs`, and the caller's `signal` was ignored (0.8.0 P2-9).
 */
interface RequestScope {
  signal: AbortSignal;
  dispose(): void;
}

function openRequestScope(
  timeoutMs: number,
  callerSignal: AbortSignal | undefined,
): RequestScope {
  const abort = new AbortController();
  const timeoutHandle =
    timeoutMs > 0
      ? setTimeout(
          () => abort.abort(new Error("request timed out")),
          Math.min(timeoutMs, MAX_TIMER_MS),
        )
      : null;
  // Compose caller signal with our timeout signal: abort if either fires.
  const onCallerAbort = () => abort.abort(callerSignal?.reason);
  if (callerSignal) {
    callerSignal.addEventListener("abort", onCallerAbort, { once: true });
  }
  let disposed = false;
  return {
    signal: abort.signal,
    dispose() {
      if (disposed) return;
      disposed = true;
      if (timeoutHandle !== null) clearTimeout(timeoutHandle);
      if (callerSignal) callerSignal.removeEventListener("abort", onCallerAbort);
    },
  };
}

/**
 * Internal — exported for tests. Composes a URL safely from baseUrl + path.
 * Caller-supplied `path` may or may not start with `/`; either way works.
 */
export function composeUrl(baseUrl: string, path: string): string {
  const sep = path.startsWith("/") ? "" : "/";
  return baseUrl + sep + path;
}

interface InternalRequestArgs {
  config: ResolvedClientConfig;
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  options?: RequestOptions;
  /**
   * P3 hardening: expected response Content-Type for the 2xx success
   * path. Defaults to `"application/json"`. The transport's success
   * path checks the response's Content-Type header against this value
   * (MIME-type prefix only, parameter-tolerant for `; charset=utf-8`)
   * and throws `AttestryAPIError` on mismatch — fail-fast against a
   * misbehaving proxy / load balancer that returns 200 OK with an
   * HTML error page or text/plain body. Pre-P3 the SDK silently
   * resolved with `null` (or whatever JSON.parse returned) for
   * wrong-content-type responses; consumers crashed downstream with
   * a confusing TypeError. Now consumers receive a clear
   * AttestryAPIError naming the expected and actual content-type.
   *
   * Skipped for 204 No Content and 304 Not Modified (no body to
   * validate). Error path (non-2xx) is unchanged — the existing
   * error-body parser still falls back to raw text for non-JSON
   * error bodies (see hostile-review H1 pin in transport.test.ts).
   *
   * Symmetric with `streamRequestOnce`'s `expectedContentType` param
   * (which defaults to `text/event-stream` for SSE). Both use the
   * same MIME-type-extraction algorithm to defend against superset /
   * parameter-injection / structured-suffix attacks.
   */
  expectedContentType?: string;
  /**
   * Per-method default timeout (ms) for slow routes, e.g. 300_000 for
   * `annexIv.generate`. Used only when neither `options.timeoutMs` nor an
   * explicit client-wide `timeoutMs` is set — see `resolveTimeoutMs`.
   */
  defaultTimeoutMs?: number;
}

/**
 * Public request runner. Wraps the single-attempt `requestOnce` with the
 * retry loop. Resources should NOT import this directly — they go
 * through `AttestryClient._request`.
 *
 * Retry behavior: on 429 only (today). The retry loop honors the caller's
 * abort signal — `signal.abort()` during the backoff sleep rejects with
 * `AttestryError("request aborted by caller")` rather than completing
 * the wait.
 */
export async function request<T>(args: InternalRequestArgs): Promise<T> {
  const retry = resolveRetryOptions(args.config.retry, args.options?.retry);
  const callerSignal = args.options?.signal;
  let attempt = 0;
  // Loop bounded by retry.maxRetries (validated 0-100 at construction).
  // No-retry case: max=0, body runs once, errors throw out of the catch.
  while (true) {
    try {
      return await requestOnce<T>(args);
    } catch (err) {
      if (
        isRetryableError(err) &&
        attempt < retry.maxRetries
      ) {
        const delay = computeRetryDelay(err, attempt, retry);
        await sleepWithSignal(delay, callerSignal);
        attempt++;
        continue;
      }
      throw err;
    }
  }
}

/**
 * Internal single-attempt request runner. Exposed under `__test__` for
 * unit pinning.
 */
export async function requestOnce<T>(args: InternalRequestArgs): Promise<T> {
  const { config, method, path, body, query, options } = args;

  const callerSignal = options?.signal;
  // Reject upfront on a pre-aborted caller signal. Real `fetch` rejects
  // synchronously in this case but mock / alternative fetch impls often
  // do not — making this explicit keeps the SDK contract uniform across
  // transports.
  if (callerSignal?.aborted) {
    throw new AttestryError("request aborted by caller", {
      cause: callerSignal.reason,
    });
  }

  const queryString = encodeQuery(query);
  const url = composeUrl(config.baseUrl, path) + queryString;

  const headers = new Headers();
  headers.set("x-api-key", config.apiKey);
  headers.set("Accept", "application/json");
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
  }

  const timeoutMs = resolveTimeoutMs(config, options, args.defaultTimeoutMs);

  // Serialize the body up front so a circular-ref / BigInt throw doesn't
  // get masked as "network error" by the catch around fetchImpl. Hostile-
  // review L2. Done BEFORE the timeout is armed and the caller-signal
  // listener attached, so a serialization throw leaks neither (0.8.0 — the
  // timer used to keep the process alive for `timeoutMs` after the throw).
  let serializedBody: string | undefined;
  if (body !== undefined) {
    try {
      serializedBody = JSON.stringify(body);
    } catch (err) {
      throw new AttestryError(
        // JSON.stringify throws TypeError (Error subclass) for circular
        // refs / BigInts, so the String(err) branch is unreachable.
        // Defense-in-depth marker for the v8 coverage tool.
        /* v8 ignore next */
        `invalid request body: ${err instanceof Error ? err.message : String(err)}`,
        { cause: err },
      );
    }
  }

  // Timeout + caller signal stay armed until the body has been read; the
  // single cleanup site is the `finally` below (0.8.0 P2-9).
  const scope = openRequestScope(timeoutMs, callerSignal);
  try {
    let response: Response;
    try {
      response = await config.fetchImpl(url, {
        method,
        headers,
        body: serializedBody,
        signal: scope.signal,
        // Never follow redirects: fetch strips only `Authorization` on a
        // cross-origin redirect, NOT the custom `x-api-key` header.
        redirect: "manual",
      });
    } catch (err) {
      throw new AttestryError(
        describeFetchFailure(err, scope.signal.aborted, callerSignal?.aborted ?? false),
        { cause: err },
      );
    }

    assertNotRedirected(response, method, url, config.baseUrl);

    if (response.ok) {
      // P3 hardening: content-type guard for sync GET. Symmetric with
      // streamRequest's expectedContentType guard. Skipped for 204 (No
      // Content) — has no body to validate. (304 Not Modified is also
      // bodyless but `response.ok` is false for 304 (status range
      // 200-299), so it never reaches this branch — handled by the
      // error path instead.) Without this guard, a proxy / LB that
      // wraps a 200 OK around an HTML error page would silently
      // produce `null` (JSON.parse fails → readBody returns parsed:null
      // → consumer gets null cast as T). Pre-P3 G6 documented this
      // soft-fail surface; P3 replaces it with a clear AttestryAPIError
      // naming the expected vs actual content-type — and, since 0.8.0,
      // the URL and a pointer at `baseUrl`.
      if (response.status !== 204) {
        assertContentType(
          response,
          args.expectedContentType ?? "application/json",
          method,
          url,
          config.baseUrl,
        );
      }

      const { parsed } = await readBodyInScope(response, scope.signal, callerSignal);
      // Kernel routes use successResponse() which emits {success:true, data}.
      // Unwrap when the envelope is present; pass through bare for forward-
      // compat with hypothetical non-conforming endpoints (none currently
      // exist). 204 / empty 200 keeps returning null — readBody already
      // short-circuits parsed:null in that case.
      if (
        parsed !== null &&
        typeof parsed === "object" &&
        (parsed as { success?: unknown }).success === true &&
        "data" in parsed
      ) {
        return (parsed as { data: T }).data;
      }
      return parsed as T;
    }

    // Hostile-review H1: non-JSON error bodies (LB 502 HTML, plain-text
    // proxy errors) used to surface as `details: null`, leaving consumers
    // no way to debug. Fall back to the raw text when the body can't be
    // parsed as JSON.
    const { parsed, raw } = await readBodyInScope(response, scope.signal, callerSignal);
    const detail: unknown = parsed ?? (raw.length > 0 ? raw : null);
    const apiErr = new AttestryAPIError(
      extractMessage(detail) ?? `Attestry API returned ${response.status}`,
      response.status,
      detail,
    );
    // Attach Retry-After header (if any) for the retry middleware. Stored
    // as a non-enumerable property — doesn't pollute JSON.stringify or
    // user-facing console.log of the error.
    attachRetryAfter(apiErr, response.headers.get("retry-after"));
    throw apiErr;
  } finally {
    scope.dispose();
  }
}

/**
 * Streaming-response request — used for any long-lived streaming endpoint
 * (SSE, NDJSON). Mirrors `request` for header / signal / URL composition
 * but:
 *
 *   - Hardcodes `method: "GET"` (streaming endpoints today are read-only).
 *   - Sends `Accept: <expectedContentType>` (default `text/event-stream`
 *     for SSE backward-compat; NDJSON callers pass
 *     `application/x-ndjson`).
 *   - Does NOT arm an internal timeout by default — streams are
 *     long-lived; the 30s default would kill them after half a minute.
 *     Caller controls duration via `options.signal`. (`decisions.export`
 *     runs up to 5 minutes server-side.) One-shot downloads opt in with
 *     `applyTimeout: true` (`annexIv.downloadPdf`, `evidencePack.export`):
 *     the resolved `timeoutMs` then covers the fetch AND the caller's read
 *     of the returned body (0.8.0).
 *   - Never follows redirects (`redirect: "manual"`); a 3xx throws, as on
 *     the JSON path.
 *   - Returns the un-consumed `Response` so the resource can read
 *     `response.body` as a stream of bytes (for an SSE / NDJSON parser).
 *   - On non-2xx, drains the body and throws `AttestryAPIError` exactly
 *     like the JSON path so consumers see the same error shape.
 *   - On a 2xx with the WRONG content-type, throws with a clear message —
 *     defensive against a misconfigured proxy returning `text/html` (LB
 *     error page) or `text/plain`. The kernel always sets the right
 *     content-type for each route, so this is a fail-fast guard. The
 *     `expectedContentType` parameter (default `text/event-stream`)
 *     drives both the `Accept:` request header AND this guard, so SSE
 *     callers reject NDJSON responses and vice versa — a single source
 *     of truth.
 *
 * Retry semantics: the INITIAL fetch goes through the retry wrapper
 * (same 429 logic as `request<T>`). Once the response is open,
 * mid-iteration errors do NOT retry — events would be lost or
 * duplicated without per-event idempotency. Caller manages reconnection
 * by passing the last seen cursor back (e.g., SSE `lastEventId`,
 * NDJSON: re-issue with adjusted filters).
 */
export async function streamRequest(args: {
  config: ResolvedClientConfig;
  path: string;
  query?: Record<string, string | number | boolean | undefined | null>;
  headers?: Record<string, string>;
  options?: RequestOptions;
  /**
   * Substring (case-insensitive) the response's `Content-Type` header
   * must contain to pass the fail-fast guard. ALSO drives the request's
   * `Accept:` header. Defaults to `"text/event-stream"` for SSE
   * backward-compat. NDJSON callers (`decisions.export`) pass
   * `"application/x-ndjson"`. Single source of truth — same value
   * everywhere keeps SSE callers from accidentally accepting NDJSON
   * responses and vice versa.
   */
  expectedContentType?: string;
  /**
   * Opt in to the request timeout for a ONE-SHOT download (not a
   * long-lived stream). The resolved timeout (`options.timeoutMs` →
   * client `timeoutMs`) and the caller's signal then stay in force until
   * the returned body has been fully read or canceled; on expiry the
   * body read rejects with `AttestryError("request timed out")`.
   */
  applyTimeout?: boolean;
  /**
   * With `applyTimeout`: a per-method default timeout (ms) for slow
   * downloads (e.g. `evidencePack.export`). Same precedence as on the
   * JSON path — see `resolveTimeoutMs`.
   */
  defaultTimeoutMs?: number;
}): Promise<Response> {
  // Retry on the INITIAL fetch only. Once the response is open and
  // we've started reading frames, any error (mid-stream 429 from a
  // proxy, network drop, server timeout) bubbles to the consumer for
  // them to decide whether to reconnect. Auto-retrying mid-stream
  // would risk dropping or duplicating events.
  const retry = resolveRetryOptions(args.config.retry, args.options?.retry);
  const callerSignal = args.options?.signal;
  let attempt = 0;
  while (true) {
    try {
      return await streamRequestOnce(args);
    } catch (err) {
      if (
        isRetryableError(err) &&
        attempt < retry.maxRetries
      ) {
        const delay = computeRetryDelay(err, attempt, retry);
        await sleepWithSignal(delay, callerSignal);
        attempt++;
        continue;
      }
      throw err;
    }
  }
}

/**
 * Internal single-attempt streaming request. Same shape as `streamRequest`
 * but runs exactly one fetch; the outer wrapper handles retry.
 */
async function streamRequestOnce(args: {
  config: ResolvedClientConfig;
  path: string;
  query?: Record<string, string | number | boolean | undefined | null>;
  headers?: Record<string, string>;
  options?: RequestOptions;
  expectedContentType?: string;
  applyTimeout?: boolean;
  defaultTimeoutMs?: number;
}): Promise<Response> {
  const { config, path, query, headers: extraHeaders, options } = args;
  // Default for SSE backward-compat. NDJSON callers pass
  // `"application/x-ndjson"`; future content-types slot in here too.
  const expectedContentType =
    args.expectedContentType ?? "text/event-stream";

  const callerSignal = options?.signal;
  if (callerSignal?.aborted) {
    throw new AttestryError("request aborted by caller", {
      cause: callerSignal.reason,
    });
  }

  const queryString = encodeQuery(query);
  const url = composeUrl(config.baseUrl, path) + queryString;

  const headers = new Headers();
  headers.set("x-api-key", config.apiKey);
  headers.set("Accept", expectedContentType);
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  }

  // Long-lived streams: no internal abort controller, no timeout — pass
  // the caller's signal straight through (a stream lives until the server
  // closes it OR the caller aborts). One-shot downloads (`applyTimeout`)
  // get a request scope whose deadline outlives `fetch` and is handed to
  // the returned body (see `bindBodyToScope`).
  const timeoutMs = args.applyTimeout
    ? resolveTimeoutMs(config, options, args.defaultTimeoutMs)
    : 0;
  const scope = timeoutMs > 0 ? openRequestScope(timeoutMs, callerSignal) : null;
  const signal = scope?.signal ?? callerSignal;
  let bodyOwnsScope = false;

  try {
    let response: Response;
    try {
      response = await config.fetchImpl(url, {
        method: "GET",
        headers,
        signal,
        // Never follow redirects — see `requestOnce`.
        redirect: "manual",
      });
    } catch (err) {
      throw new AttestryError(
        describeFetchFailure(
          err,
          scope?.signal.aborted ?? false,
          // `?? false` defends against an undefined caller signal — both
          // branches reachable but the false-fallback only fires when no
          // options.signal was passed AND the fetch rejected. Marginal
          // pin value; defense-in-depth marker for v8.
          /* v8 ignore next */
          callerSignal?.aborted ?? false,
        ),
        { cause: err },
      );
    }

    assertNotRedirected(response, "GET", url, config.baseUrl);

    if (!response.ok) {
      // Same body-extraction contract as the JSON path: parsed JSON if
      // possible, raw text fallback. Non-JSON error bodies (LB 502 HTML,
      // proxy text) surface as `details` rather than `null`.
      const { parsed, raw } = await readBodyInScope(response, signal, callerSignal);
      // Defensive ?? fallbacks: `parsed` is null when the body isn't
      // JSON; `raw.length > 0 ? raw : null` selects between the raw text
      // and explicit null. `extractMessage(detail) ??` falls back to a
      // generic "Attestry API returned N" when the body has no
      // message/error field. All branches reachable in principle but a
      // 4xx with neither JSON body nor extractable message is exotic —
      // covered defensively.
      /* v8 ignore next */
      const detail: unknown = parsed ?? (raw.length > 0 ? raw : null);
      const apiErr = new AttestryAPIError(
        /* v8 ignore next */
        extractMessage(detail) ?? `Attestry API returned ${response.status}`,
        response.status,
        detail,
      );
      attachRetryAfter(apiErr, response.headers.get("retry-after"));
      throw apiErr;
    }

    // Defensive content-type check (see `assertContentType`). The kernel
    // always emits the expected content-type for each route. If a proxy /
    // load balancer / access gate rewrites the response (e.g. an HTML
    // page at 200), the downstream parser would produce nonsense or hang.
    assertContentType(response, expectedContentType, "GET", url, config.baseUrl);

    if (scope === null) return response;
    // One-shot download: the deadline now travels with the body and is
    // released when the caller finishes (or cancels) reading it.
    bodyOwnsScope = true;
    return bindBodyToScope(response, scope, callerSignal);
  } finally {
    if (scope !== null && !bodyOwnsScope) scope.dispose();
  }
}

function encodeQuery(
  q: Record<string, string | number | boolean | undefined | null> | undefined,
): string {
  if (!q) return "";
  const params: string[] = [];
  for (const [key, value] of Object.entries(q)) {
    if (value === undefined || value === null) continue;
    params.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  }
  return params.length > 0 ? `?${params.join("&")}` : "";
}

/**
 * Reads the response body and tries to parse as JSON. Returns BOTH the
 * parsed value (or null on parse failure / empty body) AND the raw text.
 * Callers on the success path use only `parsed`; callers on the error
 * path fall back to `raw` when `parsed` is null so non-JSON error bodies
 * (LB 502 HTML, plain-text proxy errors) are surfaced as
 * `AttestryAPIError.details` rather than silently lost. (Hostile-review
 * H1.)
 *
 * With a `signal`, the read is abortable: when the signal fires, the body
 * stream is canceled (releasing the connection, whatever the `fetch`
 * implementation does with its own signal) and the promise rejects with
 * `signal.reason`. Callers map that via `readBodyInScope`.
 */
async function readBody(
  response: Response,
  signal?: AbortSignal,
): Promise<{ parsed: unknown; raw: string }> {
  if (response.status === 204) return { parsed: null, raw: "" };
  const text = await readText(response, signal);
  if (text.length === 0) return { parsed: null, raw: "" };
  try {
    return { parsed: JSON.parse(text), raw: text };
  } catch {
    return { parsed: null, raw: text };
  }
}

async function readText(
  response: Response,
  signal: AbortSignal | undefined,
): Promise<string> {
  const body = response.body;
  if (signal === undefined) return response.text();
  if (signal.aborted) {
    discardBody(response);
    throw signal.reason;
  }
  if (body === null || typeof body.getReader !== "function") {
    // Non-WHATWG body (exotic `fetch` impl): race `text()` against the
    // signal. The losing `text()` promise is settled into a no-op.
    return new Promise<string>((resolve, reject) => {
      const onAbort = () => reject(signal.reason);
      signal.addEventListener("abort", onAbort, { once: true });
      response.text().then(
        (t) => {
          signal.removeEventListener("abort", onAbort);
          resolve(t);
        },
        (err: unknown) => {
          signal.removeEventListener("abort", onAbort);
          reject(err);
        },
      );
    });
  }
  const reader = body.getReader();
  // Canceling the reader resolves a pending `read()` with `done: true` and
  // cancels the underlying source; the `signal.aborted` check after each
  // read turns that into a rejection.
  const onAbort = () => {
    reader.cancel(signal.reason).catch(() => undefined);
  };
  signal.addEventListener("abort", onAbort, { once: true });
  const decoder = new TextDecoder("utf-8");
  let text = "";
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (signal.aborted) throw signal.reason;
      if (done) break;
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    signal.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }
}

/**
 * `readBody` under a request scope: a failure while reading the body — the
 * scope's deadline, the caller's abort, or the connection dropping
 * mid-body — becomes an `AttestryError` with the same messages as a
 * failure during `fetch` itself ("request timed out" / "request aborted
 * by caller" / "network error: …").
 */
async function readBodyInScope(
  response: Response,
  signal: AbortSignal | undefined,
  callerSignal: AbortSignal | undefined,
): Promise<{ parsed: unknown; raw: string }> {
  try {
    return await readBody(response, signal);
  } catch (err) {
    throw new AttestryError(
      describeFetchFailure(err, signal?.aborted ?? false, callerSignal?.aborted ?? false),
      { cause: err },
    );
  }
}

/** Best-effort release of an unread body (and its connection). Never throws. */
function discardBody(response: Response): void {
  try {
    const body = response.body;
    if (body !== null && !body.locked) body.cancel().catch(() => undefined);
  } catch {
    // Exotic body — nothing more we can do.
  }
}

/** The request URL without its query string, for error messages. */
function describeUrl(url: string): string {
  const q = url.indexOf("?");
  return q === -1 ? url : url.slice(0, q);
}

/**
 * Rejects any redirect. Requests are sent with `redirect: "manual"`, so a
 * 3xx (or, from a browser-style fetch, an `opaqueredirect` response) is
 * the server's redirect itself; `response.redirected` catches a custom
 * `fetch` that followed one anyway. 304 Not Modified is not a redirect and
 * keeps going through the normal non-2xx error path.
 *
 * Why not follow: fetch strips only `Authorization` on a cross-origin
 * redirect, NOT the custom `x-api-key` header, so following would hand the
 * org API key to whatever host the redirect names. And the redirect seen
 * in practice is an access gate / login page answering in place of the
 * API, which no amount of following fixes.
 */
function assertNotRedirected(
  response: Response,
  method: string,
  url: string,
  baseUrl: string,
): void {
  const status = response.status;
  const isRedirectStatus = status >= 300 && status < 400 && status !== 304;
  if (
    !isRedirectStatus &&
    response.type !== "opaqueredirect" &&
    response.redirected !== true
  ) {
    return;
  }
  discardBody(response);
  const location = isRedirectStatus
    ? response.headers.get("location")
    : response.redirected
      ? response.url || null
      : null;
  const what =
    isRedirectStatus
      ? `returned HTTP ${status} (redirect)${location ? ` to ${location}` : ""}`
      : response.redirected
        ? `was redirected${location ? ` to ${location}` : ""} by the fetch implementation`
        : "returned a redirect";
  throw new AttestryAPIError(
    `${method} ${describeUrl(url)} ${what}. The SDK does not follow redirects, so your API key is never forwarded to another URL. Check that \`baseUrl\` (${baseUrl}) is the Attestry API origin.`,
    status,
    location !== null ? { location } : null,
  );
}

/**
 * Fail-fast Content-Type guard for 2xx responses.
 *
 * Hostile-review fix: parse the MIME type out of the header (per
 * RFC 7231 §3.1.1.1, `media-type = type "/" subtype *( OWS ";" OWS
 * parameter )`) and compare for exact equality with `expectedContentType`.
 * The previous substring `includes()` match was bypassed by:
 *   - superset attacks (`application/x-ndjson-evil` matches
 *     `application/x-ndjson`),
 *   - parameter-injection attacks (`text/html; x-real-content=
 *     application/x-ndjson` matches), and
 *   - structured-suffix attacks (`application/foo+x-ndjson`).
 * Pulling the type/subtype before the first `;`, trimming OWS, and
 * exact-matching closes all three while still accepting legitimate
 * parameters such as `; charset=utf-8`.
 *
 * The message keeps its `expected X response, got "Y"` prefix and (0.8.0)
 * adds the URL plus a pointer at `baseUrl`: the usual cause is a proxy,
 * login or access-gate page answering instead of the Attestry API.
 */
function assertContentType(
  response: Response,
  expectedContentType: string,
  method: string,
  url: string,
  baseUrl: string,
): void {
  // `?? ""` defends against a null Content-Type header — the kernel
  // always sets it, so the null branch is exotic. Defense-in-depth.
  /* v8 ignore next */
  const contentType = response.headers.get("content-type") ?? "";
  const semicolonIdx = contentType.indexOf(";");
  const contentTypeMime = (
    semicolonIdx === -1 ? contentType : contentType.slice(0, semicolonIdx)
  )
    .trim()
    .toLowerCase();
  const expectedMime = expectedContentType.trim().toLowerCase();
  if (contentTypeMime === expectedMime) return;
  discardBody(response);
  throw new AttestryAPIError(
    `expected ${expectedContentType} response, got "${contentType}" from ${method} ${describeUrl(url)}. Something other than the Attestry API answered (a proxy, login or access-gate page?) — check that \`baseUrl\` (${baseUrl}) is the Attestry API origin.`,
    response.status,
    null,
  );
}

/**
 * Hands a request scope to the body of a one-shot download: returns a
 * `Response` (same status / headers / url) whose body re-streams the
 * original one while the scope's deadline and the caller's signal stay
 * armed. Reading the body to the end, or canceling it, disposes the scope.
 * If the scope aborts first, the body errors with `AttestryError("request
 * timed out")` / `AttestryError("request aborted by caller")` and the
 * original body is canceled (releasing the connection).
 */
function bindBodyToScope(
  response: Response,
  scope: RequestScope,
  callerSignal: AbortSignal | undefined,
): Response {
  const source = response.body;
  if (source === null) {
    scope.dispose();
    return response;
  }
  const reader = source.getReader();
  const signal = scope.signal;
  let settled = false;
  const settle = (): boolean => {
    if (settled) return false;
    settled = true;
    signal.removeEventListener("abort", onAbort);
    scope.dispose();
    return true;
  };
  let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
  function onAbort(): void {
    if (!settle()) return;
    const err = new AttestryError(
      describeFetchFailure(signal.reason, true, callerSignal?.aborted ?? false),
      { cause: signal.reason },
    );
    try {
      controller?.error(err);
    } catch {
      // Stream already closed.
    }
    reader.cancel(err).catch(() => undefined);
  }
  const body = new ReadableStream<Uint8Array>(
    {
      start(c) {
        controller = c;
      },
      async pull(c) {
        let result: ReadableStreamReadResult<Uint8Array>;
        try {
          result = await reader.read();
        } catch (err) {
          // Already errored by `onAbort` when the scope fired first.
          if (!settle()) return;
          c.error(
            new AttestryError(
              describeFetchFailure(err, signal.aborted, callerSignal?.aborted ?? false),
              { cause: err },
            ),
          );
          return;
        }
        if (settled) return;
        if (result.done) {
          settle();
          c.close();
          return;
        }
        c.enqueue(result.value);
      },
      cancel(reason) {
        settle();
        return reader.cancel(reason);
      },
    },
    // Pull only on demand — never read ahead of the consumer.
    { highWaterMark: 0 },
  );
  // A custom `fetch` that ignores its signal can resolve after the scope
  // already fired — error the body right away in that case.
  if (signal.aborted) onAbort();
  else signal.addEventListener("abort", onAbort, { once: true });
  const wrapped = new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  // Keep `response.url` faithful (a constructed Response has url "").
  if (response.url) {
    try {
      Object.defineProperty(wrapped, "url", { value: response.url });
    } catch {
      // Non-configurable in some exotic runtime — cosmetic only.
    }
  }
  return wrapped;
}

function extractMessage(detail: unknown): string | null {
  if (detail && typeof detail === "object" && "error" in detail) {
    const err = (detail as { error: unknown }).error;
    if (typeof err === "string") return err;
    if (err && typeof err === "object" && "message" in err) {
      const m = (err as { message: unknown }).message;
      if (typeof m === "string") return m;
    }
  }
  if (detail && typeof detail === "object" && "message" in detail) {
    const m = (detail as { message: unknown }).message;
    if (typeof m === "string") return m;
  }
  return null;
}

function describeFetchFailure(
  err: unknown,
  abortFired: boolean,
  callerAborted: boolean,
): string {
  if (callerAborted) return "request aborted by caller";
  if (abortFired) return "request timed out";
  if (err instanceof Error) return `network error: ${err.message}`;
  return "network error";
}

// Test-only handles for direct pinning of internals.
export const __test__ = {
  DEFAULT_BASE_URL,
  DEFAULT_TIMEOUT_MS,
  MAX_TIMER_MS,
  encodeQuery,
  readBody,
  extractMessage,
  resolveTimeoutMs,
};
