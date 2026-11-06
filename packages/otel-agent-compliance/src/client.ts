/**
 * HTTP client for the Attestry bulk decision ingest endpoint
 * (`POST /api/v1/decisions/bulk`).
 *
 * Contract:
 *  - **Never throws** to the caller. The exporter runs in the
 *    customer's request path; an uncaught throw here would surface as
 *    an unhandled rejection on Node and crash long-running workers.
 *    Every failure mode resolves with `{ ok: false, ... }` and is
 *    surfaced via the configured logger.
 *  - **Success is proven, not assumed.** A response only counts as
 *    accepted when it is a 2xx, `application/json`, and carries the
 *    kernel envelope `{ success: true, data: { totalInserted,
 *    totalFailed, failed[] } }` (`successResponse()` in the kernel's
 *    `src/lib/api.ts`). An HTML page served with 200 (a login / gate /
 *    captive-portal page in front of the API), `success: false`, or an
 *    unrecognised body is a logged failure — never a silent "ok".
 *  - **Per-record rejections are surfaced.** The bulk route answers 200
 *    even when some records in the batch fail; those are listed in
 *    `data.failed[]` with a machine-readable `code`. We log a warning
 *    with the codes and return them in `failures`.
 *  - **Redirects are never followed** (`redirect: "manual"`). The fetch
 *    spec strips only `Authorization` on a cross-origin redirect, not
 *    custom headers, so following one would forward `x-api-key` to
 *    whatever host the `Location` names. A 3xx from the ingest endpoint
 *    means `apiUrl` is wrong (or a gate fronts the API); it is logged as
 *    a permanent failure.
 *  - **Bounded retries, driven by `RETRYABLE_STATUS`.** Up to three
 *    attempts, but only for transient failures: network errors /
 *    timeouts and the statuses in `RETRYABLE_STATUS` (408, 429, 500,
 *    502, 503, 504), with capped exponential backoff (250ms, 750ms)
 *    + 50ms full jitter. Everything else (other 4xx, 501/505, 3xx,
 *    non-JSON 2xx, `success: false`) is permanent: replaying the same
 *    body cannot succeed, so we log and drop after one attempt.
 *  - **Honors `Retry-After`.** On a retryable response with a
 *    Retry-After header we use the server's value (capped at 60s)
 *    instead of our own backoff. Hammering a server that just told us
 *    to slow down is the canonical way to escalate from "rate-limited"
 *    to "blocked".
 *  - **AbortController timeout.** The native `fetch` has no built-in
 *    request timeout; without one a hung server holds the queue
 *    forever. Default 10s.
 *  - **http:// guard.** Construction warns if `apiUrl` is HTTP and
 *    not localhost — the API key would otherwise traverse the network
 *    in cleartext. We don't *reject* HTTP because dev environments
 *    legitimately use it; we surface the warning so it gets caught
 *    in code review.
 *
 * Why fetch instead of a richer client (axios/got)? `LIBRARY_LOCK.md`
 * pins this package to native fetch — adding axios would be a new
 * top-level dep across the kernel. fetch is good enough for a
 * single-endpoint POST with a JSON body.
 */

import type {
  AttestryExporterConfig,
  DecisionInput,
  ExporterLogger,
} from "./types.js";
import { PACKAGE_USER_AGENT } from "./version.js";

/**
 * One record the server rejected inside an otherwise-processed batch —
 * an entry of the bulk route's `data.failed[]`.
 */
export interface BatchRecordFailure {
  /** Index of the record in the submitted batch. */
  index: number;
  /** Machine-readable failure code, e.g. `ijson_validation_failed`. */
  code: string;
  /** Server-provided message, when present. */
  error?: string;
}

export interface BatchSendResult {
  /**
   * `true` only when the server confirmed that EVERY record in the
   * batch was inserted. A partially rejected batch is `ok: false` with
   * `inserted > 0` and the rejections listed in `failures`.
   */
  ok: boolean;
  /** HTTP status of the last attempt (0 = network error / timeout). */
  status: number;
  /** Number of records the server confirmed as inserted. */
  inserted: number;
  /** Number of records not recorded (rejected by the server, or the
   *  whole batch when the request itself failed). */
  failed: number;
  /** Per-record rejections reported by the server (`data.failed[]`). */
  failures?: BatchRecordFailure[];
  /** Error description for logging, never thrown. */
  error?: string;
}

/** Outcome of one HTTP attempt. `accepted` = the server answered with a
 *  valid success envelope (possibly with per-record rejections), so the
 *  batch is done; `failed` = the request did not provably succeed. */
interface FailedAttempt {
  kind: "failed";
  result: BatchSendResult;
  retryable: boolean;
  retryAfterMs: number | null;
}
type AttemptOutcome =
  | { kind: "accepted"; result: BatchSendResult }
  | FailedAttempt;

const DEFAULT_RETRIES = 3;
const DEFAULT_TIMEOUT_MS = 10_000;
const BACKOFF_BASE_MS = 250;
const BACKOFF_JITTER_MS = 50;
/** Cap honored Retry-After at 60s. A misbehaving server shouldn't be
 * able to wedge the customer's flush queue for arbitrary durations. */
const RETRY_AFTER_CAP_MS = 60_000;
/** Max per-record failures echoed into a single log line. The full list
 *  is always returned in `BatchSendResult.failures`. */
const LOGGED_FAILURES_CAP = 50;

/** The ONLY HTTP statuses that are retried. Network errors / timeouts
 *  (no status) are retried too; every other status is permanent. */
const RETRYABLE_STATUS: ReadonlySet<number> = new Set([
  408, 429, 500, 502, 503, 504,
]);

const consoleLogger: ExporterLogger = {
  warn(message, meta) {
    if (meta) {
      console.warn(`[attestry/otel] ${message}`, meta);
    } else {
      console.warn(`[attestry/otel] ${message}`);
    }
  },
  error(message, meta) {
    if (meta) {
      console.error(`[attestry/otel] ${message}`, meta);
    } else {
      console.error(`[attestry/otel] ${message}`);
    }
  },
};

/** Wrap a logger call so a misbehaved customer logger that throws can't
 *  bubble up and crash the customer's process. The exporter contract
 *  is "never throws" — that contract is only as strong as our weakest
 *  side-effect. */
export function safeLog(
  logger: ExporterLogger,
  level: "warn" | "error",
  message: string,
  meta?: Record<string, unknown>,
): void {
  try {
    logger[level](message, meta);
  } catch {
    // Last-resort: try the bundled console logger. If even THAT throws
    // (it won't — it's just `console.warn`), we drop silently.
    try {
      consoleLogger[level](message, meta);
    } catch {
      /* swallow */
    }
  }
}

export class AttestryClient {
  private readonly logger: ExporterLogger;
  private readonly fetchTimeoutMs: number;

  constructor(private readonly config: AttestryExporterConfig) {
    this.logger = config.logger ?? consoleLogger;
    this.fetchTimeoutMs = config.fetchTimeoutMs ?? DEFAULT_TIMEOUT_MS;

    if (isInsecureUrl(config.apiUrl)) {
      safeLog(
        this.logger,
        "warn",
        "apiUrl uses http:// — API key will be sent in cleartext. Use https:// in production.",
        { apiUrl: redactUrl(config.apiUrl) },
      );
    }
  }

  async recordDecisionsBatch(
    decisions: DecisionInput[],
  ): Promise<BatchSendResult> {
    if (decisions.length === 0) {
      return { ok: true, status: 200, inserted: 0, failed: 0 };
    }

    let failure: FailedAttempt | null = null;
    let attempts = 0;

    for (let attempt = 0; attempt < DEFAULT_RETRIES; attempt++) {
      attempts = attempt + 1;
      const outcome = await this.sendOnce(decisions);

      if (outcome.kind === "accepted") {
        const { result } = outcome;
        if (result.failed > 0) {
          const failures = result.failures ?? [];
          safeLog(
            this.logger,
            "warn",
            "Decision batch partially rejected by server — rejected records were not recorded",
            {
              status: result.status,
              submitted: decisions.length,
              inserted: result.inserted,
              failed: result.failed,
              failedCodes: [...new Set(failures.map((f) => f.code))].sort(),
              failures: failures
                .slice(0, LOGGED_FAILURES_CAP)
                .map(({ index, code }) => ({ index, code })),
            },
          );
        }
        return result;
      }

      failure = outcome;
      // Permanent failure (or out of attempts) — stop and log below.
      if (!failure.retryable || attempt === DEFAULT_RETRIES - 1) break;

      await this.backoff(attempt, failure.retryAfterMs);
    }

    if (failure === null) {
      // Unreachable (DEFAULT_RETRIES >= 1); keeps the types honest.
      return {
        ok: false,
        status: 0,
        inserted: 0,
        failed: decisions.length,
        error: "no attempts made",
      };
    }
    safeLog(this.logger, "warn", "Decision batch failed — records dropped", {
      status: failure.result.status,
      error: failure.result.error,
      retryable: failure.retryable,
      attempts,
      droppedCount: decisions.length,
    });
    return failure.result;
  }

  private async sendOnce(decisions: DecisionInput[]): Promise<AttemptOutcome> {
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      this.fetchTimeoutMs,
    );

    // Retryability is decided by RETRYABLE_STATUS unless overridden
    // (network errors: always retryable; redirects: never).
    const fail = (
      status: number,
      error: string,
      opts: { retryAfterMs?: number | null; retryable?: boolean } = {},
    ): FailedAttempt => ({
      kind: "failed",
      result: {
        ok: false,
        status,
        inserted: 0,
        failed: decisions.length,
        error,
      },
      retryable: opts.retryable ?? RETRYABLE_STATUS.has(status),
      retryAfterMs: opts.retryAfterMs ?? null,
    });

    try {
      const res = await fetch(this.config.apiUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": this.config.apiKey,
          "User-Agent": PACKAGE_USER_AGENT,
        },
        body: JSON.stringify({ items: decisions }),
        // Never follow: a followed cross-origin redirect would carry
        // x-api-key to the redirect target. See the header comment.
        redirect: "manual",
        signal: controller.signal,
      });

      const status = res.status;
      const retryAfterMs = parseRetryAfter(res.headers.get("retry-after"));

      // Redirect. Node's fetch exposes the 3xx itself under
      // `redirect: "manual"`; browsers return an opaque-redirect
      // response with status 0. Both are permanent failures.
      if (res.type === "opaqueredirect" || (status >= 300 && status < 400)) {
        await discardBody(res);
        const location = describeLocation(
          res.headers.get("location"),
          this.config.apiUrl,
        );
        return fail(
          status,
          `unexpected redirect (HTTP ${status})${location ? ` to ${location}` : ""}; ` +
            "redirects are not followed so the API key is never forwarded — " +
            "set apiUrl to the final ingest URL",
          { retryable: false },
        );
      }

      if (status >= 200 && status < 300) {
        const contentType = res.headers.get("content-type");
        if (!isJsonContentType(contentType)) {
          await discardBody(res);
          return fail(
            status,
            `expected application/json response, got "${contentType ?? "(none)"}"; ` +
              "apiUrl may point at a web page (login / gate) instead of the ingest API",
            { retryAfterMs },
          );
        }
        const envelope = parseBulkEnvelope(await safeJson(res));
        if (envelope.kind === "error") {
          return fail(status, envelope.error, { retryAfterMs });
        }
        return {
          kind: "accepted",
          result: {
            ok: envelope.failed === 0,
            status,
            inserted: envelope.inserted,
            failed: envelope.failed,
            failures: envelope.failures,
            ...(envelope.failed > 0
              ? {
                  error: `server rejected ${envelope.failed} of ${decisions.length} records`,
                }
              : {}),
          },
        };
      }

      // Non-2xx — a structured failure; retried only if RETRYABLE_STATUS.
      const errorBody = (await safeJson(res)) as
        | { error?: unknown }
        | undefined;
      return fail(
        status,
        typeof errorBody?.error === "string" && errorBody.error
          ? errorBody.error
          : `HTTP ${status}`,
        { retryAfterMs },
      );
    } catch (err) {
      // Network error, abort, DNS — all map here, and all are transient.
      const isAbort =
        (err as { name?: string })?.name === "AbortError" ||
        (err as { name?: string })?.name === "TimeoutError";
      return fail(
        0,
        isAbort
          ? `request timeout after ${this.fetchTimeoutMs}ms`
          : err instanceof Error
            ? err.message
            : String(err),
        { retryable: true },
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  private async backoff(
    attempt: number,
    retryAfterMs: number | null,
  ): Promise<void> {
    // If the server told us when to come back, honor it (capped). The
    // exponential backoff is the fallback for "no signal".
    if (retryAfterMs !== null && retryAfterMs > 0) {
      const wait = Math.min(retryAfterMs, RETRY_AFTER_CAP_MS);
      await new Promise((resolve) => setTimeout(resolve, wait));
      return;
    }
    // 250ms, 750ms — the caller never sleeps after the final attempt.
    const base = BACKOFF_BASE_MS * 3 ** attempt;
    const jitter = Math.random() * BACKOFF_JITTER_MS;
    await new Promise((resolve) => setTimeout(resolve, base + jitter));
  }
}

type ParsedEnvelope =
  | {
      kind: "ok";
      inserted: number;
      failed: number;
      failures: BatchRecordFailure[];
    }
  | { kind: "error"; error: string };

/**
 * Validate the kernel's bulk-ingest envelope:
 * `{ success: true, data: { totalSubmitted, totalInserted, totalFailed,
 * inserted: [...], failed: [{ index, systemId, error, code }] } }`
 * (kernel `src/app/api/v1/decisions/bulk/route.ts` → `successResponse`).
 */
export function parseBulkEnvelope(body: unknown): ParsedEnvelope {
  if (body === null || typeof body !== "object") {
    return { kind: "error", error: "response body is not a JSON object" };
  }
  const env = body as { success?: unknown; data?: unknown; error?: unknown };
  if (env.success !== true) {
    const serverError =
      typeof env.error === "string" && env.error ? `: ${env.error}` : "";
    return {
      kind: "error",
      error:
        env.success === false
          ? `server returned success:false${serverError}`
          : "unrecognised response envelope (missing success:true) — records may not have been recorded",
    };
  }
  const data = env.data as
    | { totalInserted?: unknown; totalFailed?: unknown; failed?: unknown }
    | null
    | undefined;
  if (
    data === null ||
    typeof data !== "object" ||
    !isCount(data.totalInserted) ||
    !isCount(data.totalFailed)
  ) {
    return {
      kind: "error",
      error:
        "unrecognised response envelope (data.totalInserted / data.totalFailed missing) — records may not have been recorded",
    };
  }
  const failures: BatchRecordFailure[] = Array.isArray(data.failed)
    ? data.failed.map((raw, i): BatchRecordFailure => {
        const f = (raw ?? {}) as {
          index?: unknown;
          code?: unknown;
          error?: unknown;
        };
        return {
          index: typeof f.index === "number" ? f.index : i,
          code: typeof f.code === "string" && f.code ? f.code : "unknown",
          ...(typeof f.error === "string" ? { error: f.error } : {}),
        };
      })
    : [];
  return {
    kind: "ok",
    inserted: data.totalInserted,
    failed: Math.max(data.totalFailed, failures.length),
    failures,
  };
}

function isCount(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0;
}

/** `application/json`, optionally with parameters (`; charset=utf-8`),
 *  or a structured-syntax `+json` type. */
export function isJsonContentType(raw: string | null): boolean {
  if (!raw) return false;
  const mediaType = raw.split(";")[0]?.trim().toLowerCase() ?? "";
  return (
    mediaType === "application/json" ||
    /^application\/[a-z0-9.!#$&^_-]+\+json$/.test(mediaType)
  );
}

/** Redacted, absolute form of a redirect `Location` for logging. */
function describeLocation(raw: string | null, base: string): string | null {
  if (!raw) return null;
  try {
    return redactUrl(new URL(raw, base).href);
  } catch {
    return "[unparseable]";
  }
}

/** Release the connection for a body we are not going to read. */
async function discardBody(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    /* ignore */
  }
}

async function safeJson(res: Response): Promise<unknown> {
  try {
    const text = await res.text();
    return text ? JSON.parse(text) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Parse an HTTP `Retry-After` header value. Per RFC 7231 §7.1.3 the
 * value is either an HTTP date or a delta-seconds integer. Returns
 * milliseconds-from-now, or `null` if unparseable / negative.
 */
export function parseRetryAfter(raw: string | null): number | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (trimmed === "") return null;

  // Delta-seconds: a non-negative integer (no leading sign, no decimal).
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number.parseInt(trimmed, 10);
    if (!Number.isFinite(seconds) || seconds < 0) return null;
    return seconds * 1000;
  }

  // HTTP date — must contain at least one alpha character to be a
  // recognizable date string. Without this filter, `Date.parse("-5")`
  // would return a valid (negative) timestamp on some engines and we'd
  // misclassify it as a date in the past.
  if (!/[A-Za-z]/.test(trimmed)) return null;
  const ts = Date.parse(trimmed);
  if (Number.isNaN(ts)) return null;
  const delta = ts - Date.now();
  return delta > 0 ? delta : 0;
}

/** True if URL is http:// and not pointing at localhost / 127.0.0.1 / ::1. */
export function isInsecureUrl(rawUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    // Malformed URL — let fetch report the error at call time.
    return false;
  }
  if (parsed.protocol !== "http:") return false;
  const host = parsed.hostname;
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" ||
    host === "::1"
  ) {
    return false;
  }
  return true;
}

/** Strip query strings and userinfo from a URL before logging. */
export function redactUrl(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return "[unparseable]";
  }
}

export const __test__ = {
  RETRYABLE_STATUS,
  DEFAULT_RETRIES,
  DEFAULT_TIMEOUT_MS,
  RETRY_AFTER_CAP_MS,
  LOGGED_FAILURES_CAP,
};
