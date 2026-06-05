// ─── HTTP transport ─────────────────────────────────────────────────────────
//
// `request` is the single-entry point for every API call. Resources call
// it via the client. Behavior:
//
//   - Adds `x-api-key` header from the client's options.
//   - Adds `Content-Type: application/json` when sending a body.
//   - Adds `Accept: application/json` always.
//   - Composes the final URL from `baseUrl + path` with safe slash handling.
//   - Times out via `AbortController` after `timeoutMs` (default 30s);
//     caller can also pass their own `signal` which is composed with the
//     timeout signal.
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

const DEFAULT_BASE_URL = "https://app.attestry.ai";
const DEFAULT_TIMEOUT_MS = 30_000;

interface ResolvedClientConfig {
  apiKey: string;
  baseUrl: string;
  fetchImpl: FetchLike;
  timeoutMs: number;
  retry: Partial<RetryOptions> | undefined;
}

/**
 * Validates options at construction time. Surfaces every misconfiguration
 * as `AttestryError` BEFORE any request is made — fail-fast beats failing
 * deep in the resource methods. Used by `AttestryClient` constructor.
 */
export function resolveClientConfig(
  options: AttestryClientOptions,
): ResolvedClientConfig {
  if (typeof options.apiKey !== "string" || options.apiKey.length === 0) {
    throw new AttestryError("AttestryClient: `apiKey` is required");
  }

  const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  if (baseUrl.length === 0) {
    throw new AttestryError("AttestryClient: `baseUrl` cannot be empty");
  }

  const fetchImpl = options.fetch ?? (globalThis.fetch as FetchLike | undefined);
  if (typeof fetchImpl !== "function") {
    throw new AttestryError(
      "AttestryClient: no `fetch` implementation available — pass `options.fetch` or run on Node 18+",
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
    apiKey: options.apiKey,
    baseUrl,
    fetchImpl,
    timeoutMs,
    retry: options.retry,
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

  const abort = new AbortController();
  const timeoutHandle =
    config.timeoutMs > 0
      ? setTimeout(() => abort.abort(new Error("request timed out")), config.timeoutMs)
      : null;

  // Compose caller signal with our timeout signal: abort if either fires.
  const onCallerAbort = () => abort.abort(callerSignal?.reason);
  if (callerSignal) {
    callerSignal.addEventListener("abort", onCallerAbort, { once: true });
  }

  // Serialize the body up front so a circular-ref / BigInt throw doesn't
  // get masked as "network error" by the catch around fetchImpl. Hostile-
  // review L2.
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

  let response: Response;
  try {
    response = await config.fetchImpl(url, {
      method,
      headers,
      body: serializedBody,
      signal: abort.signal,
    });
  } catch (err) {
    throw new AttestryError(
      describeFetchFailure(err, abort.signal.aborted, callerSignal?.aborted ?? false),
      { cause: err },
    );
  } finally {
    // Single cleanup site — finally always runs even after a throw in
    // catch, so the prior catch-block duplicates were dead code.
    if (timeoutHandle !== null) clearTimeout(timeoutHandle);
    if (callerSignal) callerSignal.removeEventListener("abort", onCallerAbort);
  }

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
    // naming the expected vs actual content-type.
    if (response.status !== 204) {
      const expectedContentType = args.expectedContentType ?? "application/json";
      // `?? ""` defends against a null Content-Type header — defense-in-
      // depth (the kernel always sets it, so the null branch is exotic).
      /* v8 ignore next */
      const contentType = response.headers.get("content-type") ?? "";
      const semicolonIdx = contentType.indexOf(";");
      const contentTypeMime = (
        semicolonIdx === -1 ? contentType : contentType.slice(0, semicolonIdx)
      )
        .trim()
        .toLowerCase();
      const expectedMime = expectedContentType.trim().toLowerCase();
      if (contentTypeMime !== expectedMime) {
        throw new AttestryAPIError(
          `expected ${expectedContentType} response, got "${contentType}"`,
          response.status,
          null,
        );
      }
    }

    const { parsed } = await readBody(response);
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
  const { parsed, raw } = await readBody(response);
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
 *   - Does NOT arm an internal timeout — streams are long-lived; the
 *     30s default would kill them after half a minute. Caller controls
 *     duration via `options.signal`. (`decisions.export` runs up to
 *     5 minutes server-side.)
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

  let response: Response;
  try {
    response = await config.fetchImpl(url, {
      method: "GET",
      headers,
      // Pass the caller's signal through directly — no internal abort
      // controller, no timeout. A stream lives until the server closes
      // it OR the caller aborts.
      signal: callerSignal,
    });
  } catch (err) {
    throw new AttestryError(
      describeFetchFailure(
        err,
        false,
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

  if (!response.ok) {
    // Same body-extraction contract as the JSON path: parsed JSON if
    // possible, raw text fallback. Non-JSON error bodies (LB 502 HTML,
    // proxy text) surface as `details` rather than `null`.
    const { parsed, raw } = await readBody(response);
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

  // Defensive content-type check. The kernel always emits the
  // expected content-type for each route. If a proxy / load balancer
  // rewrites the response (e.g. an HTML error page wrapped at 200), the
  // downstream parser would produce nonsense or hang. Fail-fast with a
  // clear error class so consumers can branch on it.
  //
  // Hostile-review fix: parse the MIME type out of the header (per
  // RFC 7231 §3.1.1.1, `media-type = type "/" subtype *( OWS ";" OWS
  // parameter )`) and compare for exact equality with `expectedContentType`.
  // The previous substring `includes()` match was bypassed by:
  //   - superset attacks (`application/x-ndjson-evil` matches
  //     `application/x-ndjson`),
  //   - parameter-injection attacks (`text/html; x-real-content=
  //     application/x-ndjson` matches), and
  //   - structured-suffix attacks (`application/foo+x-ndjson`).
  // Pulling the type/subtype before the first `;`, trimming OWS, and
  // exact-matching closes all three while still accepting legitimate
  // parameters such as `; charset=utf-8`.
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
  if (contentTypeMime !== expectedMime) {
    throw new AttestryAPIError(
      `expected ${expectedContentType} response, got "${contentType}"`,
      response.status,
      null,
    );
  }

  return response;
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
 */
async function readBody(
  response: Response,
): Promise<{ parsed: unknown; raw: string }> {
  if (response.status === 204) return { parsed: null, raw: "" };
  const text = await response.text();
  if (text.length === 0) return { parsed: null, raw: "" };
  try {
    return { parsed: JSON.parse(text), raw: text };
  } catch {
    return { parsed: null, raw: text };
  }
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
  encodeQuery,
  readBody,
  extractMessage,
};
