// ─── Retry middleware ───────────────────────────────────────────────────────
//
// Automatic retry on HTTP 429 (Too Many Requests). Applied transparently
// to every JSON request and to the initial fetch of every SSE stream.
// Mid-iteration retries on streams are deliberately NOT supported — events
// would be lost or duplicated without idempotency design surface.
//
// Why only 429 in v0:
//   - 429 means "rejected before processing" — by definition safe to retry,
//     even for non-idempotent POSTs (the server didn't run anything).
//   - 5xx errors might indicate persistent bugs; auto-retrying could mask
//     them. Caller can retry manually after inspecting `err.status`.
//   - 408 (Request Timeout) is rare at the API layer and ambiguous.
//   - 503 in our kernel can mean "permanent config issue" (chat without
//     Anthropic key) — auto-retry would loop forever.
// Future expansion to 503/502/504 with idempotency-key support is forward-
// compat — see spec-diff round.
//
// Backoff strategy: exponential with full jitter. Default base 1000ms,
// multiplier 2x, cap 30s. Server-supplied `Retry-After` header (RFC 7231)
// takes precedence when present and is capped at maxDelayMs (a hostile
// server can't park the client for an hour).

import { AttestryAPIError, AttestryError } from "./errors.js";

/**
 * Tunable retry behavior. Pass to `AttestryClient` for client-wide config
 * or per-call via `RequestOptions.retry`. Per-call overrides client-level;
 * client-level overrides defaults.
 */
export interface RetryOptions {
  /**
   * Maximum number of retry attempts on 429. The initial request is NOT
   * counted — `maxRetries: 3` means up to 4 total attempts.
   * Set to `0` to disable retries entirely.
   * Default: `3`.
   */
  maxRetries: number;
  /**
   * Initial backoff delay in milliseconds. Doubled on each retry, then
   * full-jittered. Default: `1000`.
   */
  initialDelayMs: number;
  /**
   * Maximum backoff delay (cap). Both the exponential schedule and the
   * server-supplied `Retry-After` are capped at this value. Default: `30_000`.
   */
  maxDelayMs: number;
  /**
   * If true, an HTTP `Retry-After` header on the 429 response takes
   * precedence over the exponential schedule (still capped at `maxDelayMs`).
   * Both delta-seconds (`Retry-After: 60`) and HTTP-date forms are
   * supported. Default: `true`.
   */
  honorRetryAfter: boolean;
}

/**
 * Defaults. Conservative — retry-on by default with a small cap, honoring
 * server hints. Three retries (4 attempts total) with 1s base, 30s cap is
 * the industry norm (Stripe, Anthropic SDK, AWS SDK all sit in that range).
 */
export const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxRetries: 3,
  initialDelayMs: 1_000,
  maxDelayMs: 30_000,
  honorRetryAfter: true,
};

/**
 * Merge per-call > client > defaults. Returns a fully-resolved
 * `RetryOptions` with no undefined fields. Validates the merged values
 * — negative numbers, non-finite, or non-integer `maxRetries` throw
 * `AttestryError` so a bad config is caught at first call.
 */
export function resolveRetryOptions(
  clientLevel: Partial<RetryOptions> | undefined,
  perCall: Partial<RetryOptions> | undefined,
): RetryOptions {
  const merged: RetryOptions = {
    ...DEFAULT_RETRY_OPTIONS,
    ...clientLevel,
    ...perCall,
  };
  if (
    !Number.isInteger(merged.maxRetries) ||
    merged.maxRetries < 0 ||
    merged.maxRetries > 100
  ) {
    throw new AttestryError(
      "retry: `maxRetries` must be a non-negative integer ≤ 100",
    );
  }
  if (!Number.isFinite(merged.initialDelayMs) || merged.initialDelayMs < 0) {
    throw new AttestryError(
      "retry: `initialDelayMs` must be a non-negative finite number",
    );
  }
  if (!Number.isFinite(merged.maxDelayMs) || merged.maxDelayMs < 0) {
    throw new AttestryError(
      "retry: `maxDelayMs` must be a non-negative finite number",
    );
  }
  if (typeof merged.honorRetryAfter !== "boolean") {
    throw new AttestryError(
      "retry: `honorRetryAfter` must be a boolean",
    );
  }
  return merged;
}

/**
 * Parse an HTTP `Retry-After` header value into a delay in milliseconds.
 * Supports both forms per RFC 7231 § 7.1.3:
 *
 *   - delta-seconds: `Retry-After: 120` → 120_000ms
 *   - HTTP-date: `Retry-After: Mon, 04 May 2026 14:30:00 GMT` → (date - now)
 *
 * Returns `null` for missing / unparseable / negative-or-zero / NaN input.
 * Caller decides what to do with `null` (typically: fall back to the
 * exponential schedule). Defensive against hostile servers — a value
 * returning a real positive number can still be `Infinity` if the header
 * is huge; that's the caller's `maxDelayMs` cap to enforce.
 */
export function parseRetryAfter(headerValue: string | null): number | null {
  if (headerValue === null) return null;
  const trimmed = headerValue.trim();
  if (trimmed.length === 0) return null;
  // Try delta-seconds first. RFC 7231 specifies the value is a non-negative
  // decimal integer, but be slightly permissive: leading/trailing whitespace
  // is trimmed; pure-numeric strings parse via Number.
  if (/^\d+(\.\d+)?$/.test(trimmed)) {
    const seconds = Number(trimmed);
    if (!Number.isFinite(seconds) || seconds <= 0) return null;
    return Math.floor(seconds * 1_000);
  }
  // Otherwise: HTTP-date. `Date.parse` handles RFC 5322 / RFC 7231 forms.
  const t = Date.parse(trimmed);
  if (Number.isNaN(t)) return null;
  const delayMs = t - Date.now();
  if (delayMs <= 0) return null;
  return delayMs;
}

/**
 * Compute the next backoff delay in milliseconds.
 *
 * Order of precedence:
 *   1. If `honorRetryAfter` and the 429 response carried a parseable
 *      `Retry-After` header, use that value (capped at `maxDelayMs`).
 *   2. Otherwise: exponential `initialDelayMs * 2^attempt`, full-jittered
 *      to `random_between(0, exponential_value)`, capped at `maxDelayMs`.
 *
 * `attempt` is the zero-indexed retry number (0 = first retry).
 *
 * Full jitter is the AWS-recommended pattern for client-side throttling:
 * https://aws.amazon.com/blogs/architecture/exponential-backoff-and-jitter/.
 * Prevents thundering herd when many clients all 429 at the same instant.
 */
export function computeRetryDelay(
  err: AttestryAPIError,
  attempt: number,
  options: RetryOptions,
  rng: () => number = Math.random,
): number {
  if (options.honorRetryAfter) {
    const headerValue = extractRetryAfter(err);
    const parsed = parseRetryAfter(headerValue);
    if (parsed !== null) {
      return Math.min(parsed, options.maxDelayMs);
    }
  }
  // Exponential. Cap the exponent at 30 to avoid Math.pow overflow on
  // pathological maxRetries values; the caller's resolveRetryOptions
  // already caps maxRetries at 100, but full jitter's input is computed
  // pre-cap and could otherwise overflow.
  const safeExponent = Math.min(attempt, 30);
  const exponential = options.initialDelayMs * Math.pow(2, safeExponent);
  const cappedExp = Math.min(exponential, options.maxDelayMs);
  // Full jitter: `random_between(0, cappedExp)`. The lower bound 0 is
  // intentional — over many clients, the average delay across a cohort
  // is cappedExp/2 with low cross-correlation.
  return Math.floor(rng() * cappedExp);
}

/**
 * Sleep for `ms` milliseconds, but reject early with `AttestryError` if
 * the caller's signal aborts. Without the signal hook, `await new Promise
 * (r => setTimeout(r, ms))` would block the abort path until the timer
 * fires — defeating the purpose of cancellation.
 *
 * Pre-aborted signal rejects synchronously (well, after one microtask)
 * — symmetric to transport.request's pre-abort guard.
 *
 * Cleanup invariant: the abort listener is removed in BOTH paths
 * (timer-fires-first AND abort-fires-first). Without removal on the
 * timer path, a long-lived caller signal would accumulate listeners
 * across many retries — small leak per call but real, and EventTarget
 * has no built-in cap.
 */
export async function sleepWithSignal(
  ms: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (signal?.aborted) {
    throw new AttestryError("request aborted by caller", {
      cause: signal.reason,
    });
  }
  // Zero / negative delay: resolve immediately on next microtask so callers
  // don't synchronously starve the event loop. (Hostile rng can produce
  // negative — the cap also handles NaN by failing the comparison and
  // falling to setTimeout, where Node's setTimeout(NaN) coerces to 1ms.)
  if (ms <= 0) {
    await Promise.resolve();
    return;
  }
  await new Promise<void>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout>;
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(
        new AttestryError("request aborted by caller", {
          cause: signal!.reason,
        }),
      );
    };
    timer = setTimeout(() => {
      // Remove the listener BEFORE resolving — symmetric cleanup with
      // the abort path's clearTimeout. Hostile-round H1 fix.
      if (signal !== undefined) {
        signal.removeEventListener("abort", onAbort);
      }
      resolve();
    }, ms);
    if (signal !== undefined) {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

/**
 * Internal — extract the `Retry-After` header from an AttestryAPIError's
 * details, when present. The transport's error path stores the response
 * body in `details`; the response headers aren't currently captured. We
 * special-case Retry-After by stashing it under a private key when the
 * request fires.
 *
 * For the build round, we extract from a "_retryAfter" property on the
 * AttestryAPIError instance set by the transport. Tracked in the build
 * doc as a deliberate departure from the existing AttestryAPIError
 * shape — we add ONE non-enumerable property rather than restructuring
 * the public details.
 */
function extractRetryAfter(err: AttestryAPIError): string | null {
  const value = (err as unknown as { _retryAfter?: unknown })._retryAfter;
  return typeof value === "string" ? value : null;
}

/**
 * Internal — attach a `Retry-After` header value to an AttestryAPIError
 * for retry-delay computation. Set as a non-enumerable property so it
 * doesn't show up in JSON.stringify or in user-facing console.log.
 */
export function attachRetryAfter(
  err: AttestryAPIError,
  headerValue: string | null,
): void {
  if (headerValue === null) return;
  Object.defineProperty(err, "_retryAfter", {
    value: headerValue,
    enumerable: false,
    writable: false,
    configurable: false,
  });
}

/**
 * True iff the error is a retryable HTTP status. Today: 429 only. See
 * file header for rationale.
 */
export function isRetryableError(err: unknown): err is AttestryAPIError {
  return err instanceof AttestryAPIError && err.status === 429;
}
