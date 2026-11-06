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
   * header on every request. Required. Must be visible ASCII; leading /
   * trailing whitespace (e.g. a trailing newline from a file) is trimmed,
   * anything else (embedded CR/LF, spaces, control or non-ASCII
   * characters such as a pasted smart quote) throws `AttestryError` at
   * construction.
   */
  apiKey: string;

  /**
   * Base URL of the Attestry API. Defaults to `https://attestry.ai`.
   * Override for self-hosted, EU residency, or local dev. The SDK never
   * follows redirects (so the API key is never forwarded to another URL):
   * a 3xx, or a 2xx that is not the expected content type (e.g. an HTML
   * login / gate page), fails with an `AttestryAPIError` that names the
   * URL — usually a sign this points at the wrong host.
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
   * and surfaces the abort as `AttestryError` ("request timed out"). The
   * timeout covers the whole call — including reading the response body,
   * not just waiting for the headers.
   *
   * Some slow methods have their own longer default (`annexIv.generate`:
   * 300_000; `evidencePack.export`: 120_000). Setting `timeoutMs` here
   * overrides those too; per-call `RequestOptions.timeoutMs` overrides both.
   *
   * Note: NOT applied to long-lived streaming requests (`*.stream()`,
   * `decisions.export()`, `auditLog.export()`). Streams are long-lived; the
   * caller controls duration via `options.signal`. It IS applied to the
   * one-shot downloads `annexIv.downloadPdf` and `evidencePack.export`,
   * until the returned body has been read.
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
   * Per-call timeout in milliseconds (`0` disables). Overrides the client's
   * `timeoutMs` and any per-method default (e.g. `annexIv.generate`'s
   * 300_000). Must be a non-negative finite number. Ignored by long-lived
   * streaming methods (`*.stream()`, `decisions.export()`,
   * `auditLog.export()`), which have no timeout.
   */
  timeoutMs?: number;
  /**
   * Per-call retry override. Same shape as `AttestryClientOptions.retry`
   * but takes precedence. Useful for one-off "do not retry this" calls
   * or for tightening retries on a latency-sensitive call.
   */
  retry?: Partial<RetryOptions>;
}
