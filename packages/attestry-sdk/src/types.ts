// ─── Shared SDK types ───────────────────────────────────────────────────────

import type { RetryOptions } from "./retry.js";

/**
 * Minimal subset of the standard `fetch` signature. The SDK accepts any
 * implementation that matches this shape so consumers can inject a custom
 * `fetch` (testing, retry middleware, observability instrumentation, etc.)
 * without depending on the global `fetch`.
 */
export type FetchLike = (
  input: string | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface AttestryClientOptions {
  /**
   * API key from the Attestry org settings page. Sent as the `x-api-key`
   * header on every request. Required.
   */
  apiKey: string;

  /**
   * Base URL of the Attestry API. Defaults to `https://app.attestry.ai`.
   * Override for self-hosted, EU residency, or local dev.
   */
  baseUrl?: string;

  /**
   * Custom fetch implementation. Defaults to the global `fetch`. Throws at
   * construction time if neither is available.
   */
  fetch?: FetchLike;

  /**
   * Request timeout in milliseconds. Defaults to 30_000 (30s). Set `0` to
   * disable. The SDK aborts via `AbortController` when the timeout elapses
   * and surfaces the abort as `AttestryError` ("request timed out").
   *
   * Note: NOT applied to streaming requests (`*.stream()` methods).
   * Streams are long-lived; the caller controls duration via `options.signal`.
   */
  timeoutMs?: number;

  /**
   * Automatic retry configuration for HTTP 429 responses. Per-call
   * `RequestOptions.retry` overrides this. Set `{maxRetries: 0}` to
   * disable retries client-wide.
   *
   * Defaults: `{maxRetries: 3, initialDelayMs: 1000, maxDelayMs: 30_000,
   * honorRetryAfter: true}`.
   *
   * Applied to all JSON requests AND to the initial fetch of streaming
   * requests. Mid-stream errors are NEVER retried (would risk lost or
   * duplicated events).
   */
  retry?: Partial<RetryOptions>;
}

/**
 * Per-request overrides.
 */
export interface RequestOptions {
  /** Caller-provided abort signal — composed with the SDK's internal timeout. */
  signal?: AbortSignal;
  /**
   * Per-call retry override. Same shape as `AttestryClientOptions.retry`
   * but takes precedence. Useful for one-off "do not retry this" calls
   * or for tightening retries on a latency-sensitive call.
   */
  retry?: Partial<RetryOptions>;
}
