/**
 * HTTP client for the Attestry batch ingest endpoint.
 *
 * Contract:
 *  - **Never throws** to the caller. The exporter runs in the
 *    customer's request path; an uncaught throw here would surface as
 *    an unhandled rejection on Node and crash long-running workers.
 *    Every failure mode resolves with `{ ok: false, ... }` and is
 *    surfaced via the configured logger.
 *  - **Bounded retries.** Three attempts on transient errors (network,
 *    5xx, 429) with capped exponential backoff (250ms, 750ms, 2_250ms)
 *    + 50ms full jitter. Gives up after the third attempt rather than
 *    spinning indefinitely against a permanently-broken server.
 *  - **Honors `Retry-After`.** On 429 / 503 with a Retry-After header
 *    we use the server's value (capped at 60s) instead of our own
 *    backoff. Hammering a server that just told us to slow down is
 *    the canonical way to escalate from "rate-limited" to "blocked".
 *  - **No retries on 4xx (other than 429).** A 400/422 means the body
 *    is malformed; replaying it cannot succeed. We log and drop.
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
 * top-level dep across the kernel. fetch (Node 18+) is good enough
 * for a single-endpoint POST with a JSON body.
 */

import type {
  AttestryExporterConfig,
  DecisionInput,
  ExporterLogger,
} from "./types.js";
import { PACKAGE_USER_AGENT } from "./version.js";

interface BatchSendResult {
  ok: boolean;
  status: number;
  /** Number of records the server accepted (best-effort, may be 0). */
  inserted: number;
  /** Number of records the server rejected. */
  failed: number;
  /** Error class for logging, never propagated. */
  error?: string;
}

const DEFAULT_RETRIES = 3;
const DEFAULT_TIMEOUT_MS = 10_000;
const BACKOFF_BASE_MS = 250;
const BACKOFF_JITTER_MS = 50;
/** Cap honored Retry-After at 60s. A misbehaving server shouldn't be
 * able to wedge the customer's flush queue for arbitrary durations. */
const RETRY_AFTER_CAP_MS = 60_000;

const RETRYABLE_STATUS = new Set([408, 429, 500, 502, 503, 504]);

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

    let lastResult: BatchSendResult = {
      ok: false,
      status: 0,
      inserted: 0,
      failed: decisions.length,
      error: "no attempts made",
    };
    let lastRetryAfterMs: number | null = null;

    for (let attempt = 0; attempt < DEFAULT_RETRIES; attempt++) {
      const sent = await this.sendOnce(decisions);
      lastResult = sent.result;
      lastRetryAfterMs = sent.retryAfterMs;
      if (lastResult.ok) return lastResult;

      // Don't retry on 4xx other than 429; the body is bad and the
      // server will keep saying so. Logged once below.
      if (
        lastResult.status >= 400 &&
        lastResult.status < 500 &&
        lastResult.status !== 429
      ) {
        break;
      }

      // Don't retry on the final attempt — fall through to log.
      if (attempt === DEFAULT_RETRIES - 1) break;

      await this.backoff(attempt, lastRetryAfterMs);
    }

    safeLog(this.logger, "warn", "Decision batch failed after retries", {
      status: lastResult.status,
      error: lastResult.error,
      droppedCount: decisions.length,
    });
    return lastResult;
  }

  private async sendOnce(
    decisions: DecisionInput[],
  ): Promise<{ result: BatchSendResult; retryAfterMs: number | null }> {
    const controller = new AbortController();
    const timeout = setTimeout(
      () => controller.abort(),
      this.fetchTimeoutMs,
    );

    try {
      const res = await fetch(this.config.apiUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": this.config.apiKey,
          "User-Agent": PACKAGE_USER_AGENT,
        },
        body: JSON.stringify({ items: decisions }),
        signal: controller.signal,
      });

      const status = res.status;
      const retryAfterMs = parseRetryAfter(res.headers.get("retry-after"));

      if (status >= 200 && status < 300) {
        const body = (await safeJson(res)) as
          | { totalInserted?: number; totalFailed?: number }
          | undefined;
        return {
          result: {
            ok: true,
            status,
            inserted: body?.totalInserted ?? decisions.length,
            failed: body?.totalFailed ?? 0,
          },
          retryAfterMs,
        };
      }

      // Non-2xx — return a structured failure for the retry loop.
      const errorBody = (await safeJson(res)) as
        | { error?: string }
        | undefined;
      return {
        result: {
          ok: false,
          status,
          inserted: 0,
          failed: decisions.length,
          error: errorBody?.error ?? `HTTP ${status}`,
        },
        retryAfterMs,
      };
    } catch (err) {
      // Network error, abort, DNS — all map here.
      const isAbort =
        (err as { name?: string })?.name === "AbortError" ||
        (err as { name?: string })?.name === "TimeoutError";
      return {
        result: {
          ok: false,
          status: 0,
          inserted: 0,
          failed: decisions.length,
          error: isAbort
            ? `request timeout after ${this.fetchTimeoutMs}ms`
            : err instanceof Error
              ? err.message
              : String(err),
        },
        retryAfterMs: null,
      };
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
    // 250ms, 750ms, 2_250ms cap — caller already breaks on attempt 3.
    const base = BACKOFF_BASE_MS * 3 ** attempt;
    const jitter = Math.random() * BACKOFF_JITTER_MS;
    await new Promise((resolve) => setTimeout(resolve, base + jitter));
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
};
