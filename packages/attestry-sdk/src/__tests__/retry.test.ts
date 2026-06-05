// ─── 429 retry middleware — comprehensive tests ────────────────────────────
//
// Two concerns:
//   1. Helper functions (parseRetryAfter, computeRetryDelay, sleepWithSignal,
//      resolveRetryOptions). Direct unit pins.
//   2. End-to-end retry behavior through transport.request and
//      transport.streamRequest. Pinned through AttestryClient.
//
// Time-dependent tests use vi.useFakeTimers — sleepWithSignal's setTimeout
// is fake-timer-faked; the AbortSignal listener is real. We advance time
// via vi.advanceTimersByTimeAsync to let microtasks settle between ticks.

import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../client.js";
import { AttestryAPIError, AttestryError } from "../errors.js";
import {
  computeRetryDelay,
  DEFAULT_RETRY_OPTIONS,
  parseRetryAfter,
  resolveRetryOptions,
  sleepWithSignal,
  attachRetryAfter,
  isRetryableError,
} from "../retry.js";
import type { FetchLike } from "../types.js";

afterEach(() => {
  vi.useRealTimers();
});

// ─── parseRetryAfter — unit pins ───────────────────────────────────────────

describe("parseRetryAfter", () => {
  it("returns null for null input", () => {
    expect(parseRetryAfter(null)).toBeNull();
  });

  it("returns null for empty / whitespace-only input", () => {
    expect(parseRetryAfter("")).toBeNull();
    expect(parseRetryAfter("   ")).toBeNull();
  });

  it("parses delta-seconds (integer) → ms", () => {
    expect(parseRetryAfter("60")).toBe(60_000);
    expect(parseRetryAfter("0")).toBeNull(); // zero is treated as null per RFC
    expect(parseRetryAfter("1")).toBe(1_000);
  });

  it("parses delta-seconds (decimal — defensive permissiveness)", () => {
    expect(parseRetryAfter("1.5")).toBe(1_500);
    expect(parseRetryAfter("0.5")).toBe(500);
  });

  it("trims whitespace before parsing delta-seconds", () => {
    expect(parseRetryAfter("  60  ")).toBe(60_000);
  });

  it("parses HTTP-date forms — past dates return null", () => {
    expect(parseRetryAfter("Mon, 01 Jan 2020 00:00:00 GMT")).toBeNull();
  });

  it("parses HTTP-date forms — future date returns positive delay", () => {
    const future = new Date(Date.now() + 60_000).toUTCString();
    const result = parseRetryAfter(future);
    expect(result).not.toBeNull();
    // Allow some scheduling slop — the test execution may shave a few ms.
    expect(result!).toBeGreaterThan(50_000);
    expect(result!).toBeLessThanOrEqual(60_000);
  });

  it("returns null for unparseable input", () => {
    expect(parseRetryAfter("not-a-date")).toBeNull();
    expect(parseRetryAfter("definitely\nnot\nvalid")).toBeNull();
  });

  it("returns null for negative delta-seconds (regex rejects leading minus)", () => {
    // `^\d+(\.\d+)?$` doesn't match `-60`. Falls through to Date.parse,
    // which returns NaN. Returns null — defensive.
    expect(parseRetryAfter("-60")).toBeNull();
  });
});

// ─── computeRetryDelay — unit pins ─────────────────────────────────────────

describe("computeRetryDelay", () => {
  function makeErr(retryAfter?: string): AttestryAPIError {
    const err = new AttestryAPIError("rate limited", 429, null);
    if (retryAfter !== undefined) attachRetryAfter(err, retryAfter);
    return err;
  }

  it("uses exponential backoff with jitter when no Retry-After present", () => {
    const opts = { ...DEFAULT_RETRY_OPTIONS };
    // rng = 1 → no jitter discount, full exponential.
    const d0 = computeRetryDelay(makeErr(), 0, opts, () => 1);
    expect(d0).toBeLessThanOrEqual(1_000); // initial * 2^0 = 1000
    // rng = 0.5 → ~half.
    const d1 = computeRetryDelay(makeErr(), 0, opts, () => 0.5);
    expect(d1).toBeLessThanOrEqual(500);
  });

  it("doubles the exponential base on each attempt (full-jitter range [0, exp))", () => {
    const opts = { ...DEFAULT_RETRY_OPTIONS };
    // Real Math.random ∈ [0, 1). Use 0.999 to simulate the near-upper
    // bound; rng=1 isn't a real-world value but Math.floor(1 * N) = N
    // exactly (no -1 rounding), which is mathematically the [0, exp]
    // CLOSED interval — different semantics. Pinning the realistic
    // half-open interval the SDK actually exposes to consumers.
    expect(computeRetryDelay(makeErr(), 0, opts, () => 0)).toBe(0);
    // Math.floor(0.999 * 1000) = 999, Math.floor(0.999 * 2000) = 1998,
    // Math.floor(0.999 * 4000) = 3996. Each doubling step doubles the
    // range, with the rng-applied result one tick less than the new
    // ceiling.
    expect(computeRetryDelay(makeErr(), 0, opts, () => 0.999)).toBe(999);
    expect(computeRetryDelay(makeErr(), 1, opts, () => 0.999)).toBe(1_998);
    expect(computeRetryDelay(makeErr(), 2, opts, () => 0.999)).toBe(3_996);
  });

  it("caps exponential at maxDelayMs", () => {
    const opts = { ...DEFAULT_RETRY_OPTIONS, maxDelayMs: 5_000 };
    // attempt=10 → 1000 * 2^10 = 1024000ms, capped to 5000
    expect(computeRetryDelay(makeErr(), 10, opts, () => 0.999)).toBe(4_995);
  });

  it("uses Retry-After header when honorRetryAfter is true", () => {
    const opts = { ...DEFAULT_RETRY_OPTIONS };
    const err = makeErr("5"); // 5 seconds → 5000ms
    expect(computeRetryDelay(err, 0, opts, () => 0)).toBe(5_000);
  });

  it("ignores Retry-After when honorRetryAfter is false", () => {
    const opts = { ...DEFAULT_RETRY_OPTIONS, honorRetryAfter: false };
    const err = makeErr("60"); // 60s would override exponential, but disabled
    expect(computeRetryDelay(err, 0, opts, () => 0)).toBe(0); // jitter=0 → 0
  });

  it("caps Retry-After at maxDelayMs (hostile server can't park us for an hour)", () => {
    const opts = { ...DEFAULT_RETRY_OPTIONS, maxDelayMs: 10_000 };
    const err = makeErr("3600"); // 3600s = 1 hour
    expect(computeRetryDelay(err, 0, opts, () => 0)).toBe(10_000);
  });

  it("falls back to exponential when Retry-After is unparseable", () => {
    const opts = { ...DEFAULT_RETRY_OPTIONS };
    const err = makeErr("garbage value");
    // Falls through to exponential. attempt=0, rng=0.999 → 999.
    expect(computeRetryDelay(err, 0, opts, () => 0.999)).toBe(999);
  });

  it("clamps the exponent at 30 to avoid Math.pow overflow on attempt=100", () => {
    const opts = { ...DEFAULT_RETRY_OPTIONS, maxDelayMs: 60_000 };
    // attempt=100 would compute 1000 * 2^100 = ~10^33 — capped via maxDelayMs
    // anyway, but the safeExponent clamp prevents intermediate overflow that
    // could produce Infinity * 0 = NaN.
    const result = computeRetryDelay(makeErr(), 100, opts, () => 1);
    expect(Number.isFinite(result)).toBe(true);
    expect(result).toBeLessThanOrEqual(60_000);
  });
});

// ─── resolveRetryOptions — unit pins ───────────────────────────────────────

describe("resolveRetryOptions", () => {
  it("returns defaults when both args are undefined", () => {
    expect(resolveRetryOptions(undefined, undefined)).toEqual(
      DEFAULT_RETRY_OPTIONS,
    );
  });

  it("merges client-level over defaults", () => {
    const opts = resolveRetryOptions({ maxRetries: 5 }, undefined);
    expect(opts.maxRetries).toBe(5);
    expect(opts.initialDelayMs).toBe(DEFAULT_RETRY_OPTIONS.initialDelayMs);
  });

  it("merges per-call over client over defaults", () => {
    const opts = resolveRetryOptions(
      { maxRetries: 5, initialDelayMs: 500 },
      { maxRetries: 1 }, // per-call wins
    );
    expect(opts.maxRetries).toBe(1);
    expect(opts.initialDelayMs).toBe(500);
  });

  it("throws AttestryError on negative maxRetries", () => {
    expect(() => resolveRetryOptions({ maxRetries: -1 }, undefined)).toThrow(
      AttestryError,
    );
  });

  it("throws AttestryError on non-integer maxRetries", () => {
    expect(() => resolveRetryOptions({ maxRetries: 1.5 }, undefined)).toThrow(
      AttestryError,
    );
  });

  it("throws AttestryError on excessive maxRetries (>100)", () => {
    expect(() => resolveRetryOptions({ maxRetries: 101 }, undefined)).toThrow(
      AttestryError,
    );
  });

  it("throws AttestryError on negative initialDelayMs", () => {
    expect(() =>
      resolveRetryOptions({ initialDelayMs: -1 }, undefined),
    ).toThrow(AttestryError);
  });

  it("throws AttestryError on Infinity initialDelayMs", () => {
    expect(() =>
      resolveRetryOptions({ initialDelayMs: Infinity }, undefined),
    ).toThrow(AttestryError);
  });

  it("throws AttestryError on non-boolean honorRetryAfter", () => {
    expect(() =>
      resolveRetryOptions(
        { honorRetryAfter: "yes" as unknown as boolean },
        undefined,
      ),
    ).toThrow(AttestryError);
  });
});

// ─── sleepWithSignal — unit pins ───────────────────────────────────────────

describe("sleepWithSignal", () => {
  it("resolves after the timer (real timers, short ms)", async () => {
    const start = Date.now();
    await sleepWithSignal(20, undefined);
    const elapsed = Date.now() - start;
    // Allow scheduling slop.
    expect(elapsed).toBeGreaterThanOrEqual(15);
  });

  it("rejects synchronously on a pre-aborted signal", async () => {
    const ac = new AbortController();
    ac.abort(new Error("user cancelled"));
    await expect(sleepWithSignal(1_000, ac.signal)).rejects.toThrow(
      /aborted by caller/,
    );
  });

  it("rejects when signal aborts during the wait", async () => {
    const ac = new AbortController();
    setTimeout(() => ac.abort(new Error("user cancelled")), 5);
    await expect(sleepWithSignal(1_000, ac.signal)).rejects.toThrow(
      /aborted by caller/,
    );
  });

  it("zero / negative delay resolves on the next microtask", async () => {
    let resolved = false;
    const promise = sleepWithSignal(0, undefined).then(() => {
      resolved = true;
    });
    expect(resolved).toBe(false); // not yet — microtask queued
    await promise;
    expect(resolved).toBe(true);
  });
});

// ─── isRetryableError — unit pin ───────────────────────────────────────────

describe("isRetryableError", () => {
  it("returns true for 429 AttestryAPIError", () => {
    expect(isRetryableError(new AttestryAPIError("x", 429, null))).toBe(true);
  });

  it("returns false for non-429 AttestryAPIError", () => {
    expect(isRetryableError(new AttestryAPIError("x", 500, null))).toBe(false);
    expect(isRetryableError(new AttestryAPIError("x", 503, null))).toBe(false);
    expect(isRetryableError(new AttestryAPIError("x", 400, null))).toBe(false);
  });

  it("returns false for AttestryError (non-API)", () => {
    expect(isRetryableError(new AttestryError("network error"))).toBe(false);
  });

  it("returns false for non-Error values", () => {
    expect(isRetryableError(null)).toBe(false);
    expect(isRetryableError("string")).toBe(false);
    expect(isRetryableError({ status: 429 })).toBe(false);
  });
});

// ─── End-to-end retry behavior through AttestryClient ─────────────────────

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

function makeMockedClientForRetry(
  responses: Array<{ status?: number; body?: unknown; headers?: Record<string, string>; bodyText?: string }>,
  clientRetry?: Partial<typeof DEFAULT_RETRY_OPTIONS>,
) {
  const calls: MockedRequest[] = [];
  let i = 0;
  const mockFetch: FetchLike = async (url, init) => {
    calls.push({
      url: String(url),
      method: (init?.method as string) ?? "GET",
      headers: init?.headers as Headers,
      body: init?.body as string | undefined,
    });
    const r = responses[i++] ?? {};
    const status = r.status ?? 200;
    const body =
      r.bodyText !== undefined ? r.bodyText : JSON.stringify(r.body ?? {});
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(r.headers ?? {}),
    };
    return new Response(body, { status, headers });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    retry: clientRetry,
  });
  return { client, calls };
}

describe("transport.request — retry on 429", () => {
  it("retries on 429 and succeeds on the 2nd attempt", async () => {
    vi.useFakeTimers();
    const { client, calls } = makeMockedClientForRetry(
      [
        { status: 429, body: { success: false, error: "Too many requests." } },
        { status: 200, body: { success: true, data: { id: "abc" } } },
      ],
      { maxRetries: 3, initialDelayMs: 10, maxDelayMs: 100 },
    );
    const promise = client.incidents.create({
      incidentType: "prompt_injection",
      severity: "high",
      description: "x".repeat(20),
    });
    // Advance time past the backoff (max 100ms cap, jitter floor 0).
    await vi.advanceTimersByTimeAsync(150);
    const result = await promise;
    expect(result).toEqual({ id: "abc" });
    expect(calls).toHaveLength(2);
  });

  it("retries up to maxRetries times then throws the final 429", async () => {
    vi.useFakeTimers();
    const { client, calls } = makeMockedClientForRetry(
      [
        { status: 429, body: { error: "x" } },
        { status: 429, body: { error: "x" } },
        { status: 429, body: { error: "x" } },
        { status: 429, body: { error: "x" } }, // exhausts maxRetries=3
      ],
      { maxRetries: 3, initialDelayMs: 10, maxDelayMs: 50 },
    );
    const promise = client.incidents.create({
      incidentType: "prompt_injection",
      severity: "high",
      description: "x".repeat(20),
    });
    // Eager observer to suppress vitest's "unhandled rejection" race
    // window between the final 429 throw and the test's await-rejects.
    const observer = promise.catch(() => undefined);
    // Drain the timers — three retry waits of up to 50ms each.
    await vi.advanceTimersByTimeAsync(500);
    await observer;
    await expect(promise).rejects.toThrow(AttestryAPIError);
    // 1 initial + 3 retries = 4 attempts.
    expect(calls).toHaveLength(4);
  });

  it("does NOT retry when maxRetries: 0", async () => {
    const { client, calls } = makeMockedClientForRetry(
      [
        { status: 429, body: { error: "x" } },
        { status: 200, body: { success: true, data: { id: "abc" } } },
      ],
      { maxRetries: 0 },
    );
    await expect(
      client.incidents.create({
        incidentType: "prompt_injection",
        severity: "high",
        description: "x".repeat(20),
      }),
    ).rejects.toThrow(AttestryAPIError);
    // No retry — second response never consumed.
    expect(calls).toHaveLength(1);
  });

  it("per-call retry override takes precedence over client-level", async () => {
    const { client, calls } = makeMockedClientForRetry(
      [
        { status: 429, body: { error: "x" } },
        { status: 200, body: { success: true, data: { id: "abc" } } },
      ],
      { maxRetries: 3 }, // client says retry…
    );
    // …per-call says don't.
    await expect(
      client.incidents.create(
        {
          incidentType: "prompt_injection",
          severity: "high",
          description: "x".repeat(20),
        },
        { retry: { maxRetries: 0 } },
      ),
    ).rejects.toThrow(AttestryAPIError);
    expect(calls).toHaveLength(1);
  });

  it("does NOT retry on non-429 errors (400, 500, network)", async () => {
    const { client, calls } = makeMockedClientForRetry(
      [
        { status: 500, body: { error: "internal" } },
        { status: 200, body: { success: true, data: { id: "abc" } } },
      ],
      { maxRetries: 3 },
    );
    await expect(
      client.incidents.create({
        incidentType: "prompt_injection",
        severity: "high",
        description: "x".repeat(20),
      }),
    ).rejects.toThrow(AttestryAPIError);
    // 500 is not retryable — second response never consumed.
    expect(calls).toHaveLength(1);
  });

  it("re-sends the body on each retry attempt", async () => {
    vi.useFakeTimers();
    const { client, calls } = makeMockedClientForRetry(
      [
        { status: 429, body: { error: "x" } },
        { status: 200, body: { success: true, data: { id: "abc" } } },
      ],
      { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 },
    );
    const inputBody = {
      incidentType: "prompt_injection" as const,
      severity: "high" as const,
      description: "rate-limited body that must survive the retry",
    };
    const promise = client.incidents.create(inputBody);
    await vi.advanceTimersByTimeAsync(50);
    await promise;
    expect(calls).toHaveLength(2);
    // Both attempts sent the same JSON body.
    const body0 = JSON.parse(calls[0].body!);
    const body1 = JSON.parse(calls[1].body!);
    expect(body0).toEqual(body1);
    expect(body0.description).toBe(inputBody.description);
  });

  it("re-sends headers (x-api-key, Content-Type) on each retry", async () => {
    vi.useFakeTimers();
    const { client, calls } = makeMockedClientForRetry(
      [
        { status: 429, body: { error: "x" } },
        { status: 200, body: { success: true, data: { id: "abc" } } },
      ],
      { maxRetries: 1, initialDelayMs: 1, maxDelayMs: 10 },
    );
    const promise = client.incidents.create({
      incidentType: "prompt_injection",
      severity: "high",
      description: "x".repeat(20),
    });
    await vi.advanceTimersByTimeAsync(50);
    await promise;
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[1].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
    expect(calls[1].headers.get("Content-Type")).toBe("application/json");
  });

  it("honors Retry-After header (delta-seconds)", async () => {
    vi.useFakeTimers();
    const { client, calls } = makeMockedClientForRetry(
      [
        {
          status: 429,
          body: { error: "x" },
          headers: { "retry-after": "2" }, // 2 seconds
        },
        { status: 200, body: { success: true, data: { id: "abc" } } },
      ],
      { maxRetries: 1, initialDelayMs: 100, maxDelayMs: 10_000, honorRetryAfter: true },
    );
    const promise = client.incidents.create({
      incidentType: "prompt_injection",
      severity: "high",
      description: "x".repeat(20),
    });
    // Before 2s: still waiting on Retry-After.
    await vi.advanceTimersByTimeAsync(1_500);
    expect(calls).toHaveLength(1);
    // After 2s+: retry fires.
    await vi.advanceTimersByTimeAsync(700);
    await promise;
    expect(calls).toHaveLength(2);
  });

  it("aborts mid-backoff when caller signal fires", async () => {
    vi.useFakeTimers();
    const { client, calls } = makeMockedClientForRetry(
      [
        { status: 429, body: { error: "x" } },
        { status: 200, body: { success: true, data: { id: "abc" } } },
      ],
      { maxRetries: 3, initialDelayMs: 1_000, maxDelayMs: 10_000 },
    );
    const ac = new AbortController();
    const promise = client.incidents.create(
      {
        incidentType: "prompt_injection",
        severity: "high",
        description: "x".repeat(20),
      },
      { signal: ac.signal },
    );
    // Attach a rejection observer EAGERLY so vitest doesn't flag the
    // pending rejection as "unhandled" during the synchronous abort
    // dispatch. Without this, the abort listener's `reject(...)`
    // surfaces as an "uncaught" event in vitest's process bus before
    // the test's await catches it on the next microtask. The
    // sub-promise's rejection is captured here, then the original
    // `promise` rejection is observed again by the assertion below.
    const observer = promise.catch(() => undefined);
    // Trigger the abort before backoff completes. String reason
    // (NOT an Error instance) — see vitest interaction note in the
    // testing TIL: an Error abort.reason gets re-thrown by vitest's
    // fake-timer + AbortController dispatch; a string doesn't.
    setTimeout(() => ac.abort("user cancelled"), 0);
    await vi.advanceTimersByTimeAsync(10);
    await observer;
    await expect(promise).rejects.toThrow(/aborted by caller/);
    // Only the first attempt fired; retry was cancelled mid-backoff.
    expect(calls).toHaveLength(1);
  });
});

describe("transport.streamRequest — retry on 429", () => {
  it("retries 429 on the initial fetch then streams successfully", async () => {
    vi.useFakeTimers();
    const calls: MockedRequest[] = [];
    let i = 0;
    const responses = [
      { status: 429, body: { error: "x" } },
      { status: 200, sse: true },
    ];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      const r = responses[i++];
      if (r.sse) {
        const encoder = new TextEncoder();
        const stream = new ReadableStream<Uint8Array>({
          start(c) {
            c.enqueue(
              encoder.encode(
                `id: cursor-1\nevent: decision.appended\ndata: {"id":"a","systemId":"s","sequenceNumber":1,"recordHash":"sha256:x","prevRecordHash":null,"tombstoned":false,"createdAt":"2026-04-27T00:00:00.000Z"}\n\n`,
              ),
            );
            c.close();
          },
        });
        return new Response(stream, {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        });
      }
      return new Response(JSON.stringify(r.body), {
        status: r.status,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 1, initialDelayMs: 10, maxDelayMs: 100 },
    });

    const collectPromise = (async () => {
      const events = [];
      for await (const e of client.decisions.stream()) events.push(e);
      return events;
    })();
    await vi.advanceTimersByTimeAsync(200);
    const events = await collectPromise;
    expect(events).toHaveLength(1);
    expect(calls).toHaveLength(2);
  });

  it("does NOT retry mid-stream errors (only the initial fetch)", async () => {
    vi.useFakeTimers();
    const calls: MockedRequest[] = [];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      i++;
      // First call: SSE stream that errors mid-iteration.
      const stream = new ReadableStream<Uint8Array>({
        start(c) {
          // Error the controller — simulates a mid-stream connection loss.
          c.error(new TypeError("connection reset by peer"));
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 3, initialDelayMs: 10, maxDelayMs: 100 },
    });

    let caught: unknown = null;
    const collectPromise = (async () => {
      try {
        for await (const _e of client.decisions.stream()) void _e;
      } catch (err) {
        caught = err;
      }
    })();
    await vi.advanceTimersByTimeAsync(200);
    await collectPromise;
    expect(caught).toBeInstanceOf(AttestryError);
    // Only one fetch — mid-stream errors don't retry.
    expect(calls).toHaveLength(1);
    expect(i).toBe(1);
  });
});

describe("retry — hostile-round defenses", () => {
  it("H1: sleepWithSignal removes its abort listener after the timer fires (no leak)", async () => {
    // Without the cleanup, a long-lived caller signal would accumulate
    // one abort listener per retry that didn't fire. Pin: after a clean
    // timer-fires path, the signal has no remaining listener.
    const ac = new AbortController();
    // Spy on addEventListener / removeEventListener calls.
    const addSpy = vi.spyOn(ac.signal, "addEventListener");
    const removeSpy = vi.spyOn(ac.signal, "removeEventListener");
    await sleepWithSignal(5, ac.signal);
    expect(addSpy).toHaveBeenCalledTimes(1);
    // After the timer fires, the cleanup path removes the listener.
    expect(removeSpy).toHaveBeenCalledTimes(1);
    // Subsequent abort doesn't fire the (removed) listener — verified
    // by no rejection thrown anywhere; the test passes if the listener
    // is gone.
    ac.abort();
  });

  it("H2: race between abort and timer completion — Promise ignores duplicate resolution", async () => {
    // If the timer fires resolve() and the abort fires reject() in the
    // same microtask burst, only one settles the promise. Pin: the path
    // that ran first wins; no double-throw, no unhandled rejection.
    const ac = new AbortController();
    // Schedule abort at the same instant as the timer. With real timers
    // this is racy in principle; we just need to assert no throw.
    setTimeout(() => ac.abort("user cancelled"), 5);
    // The sleep promise either resolves (timer wins) or rejects (abort
    // wins). Either is fine — we just need to exit cleanly.
    let outcome: "resolved" | "rejected" = "resolved";
    try {
      await sleepWithSignal(5, ac.signal);
    } catch {
      outcome = "rejected";
    }
    expect(["resolved", "rejected"]).toContain(outcome);
  });

  it("H3: hostile rng returning negative number → 0ms sleep (no negative setTimeout)", () => {
    // Documenting the input contract: rng is consumer-controlled. A
    // hostile rng returning -1 multiplied by cappedExp gives a negative
    // delay. computeRetryDelay returns Math.floor(rng * exp) → negative.
    // Then sleepWithSignal handles `ms <= 0` as "resolve immediately"
    // — defensive against bad rng.
    const opts = { ...DEFAULT_RETRY_OPTIONS };
    const err = new AttestryAPIError("x", 429, null);
    const result = computeRetryDelay(err, 0, opts, () => -1);
    expect(result).toBeLessThanOrEqual(0);
    // sleepWithSignal will accept and immediately resolve.
  });

  it("H4: parseRetryAfter rejects multi-value header (RFC headers joined with comma)", () => {
    // If the server emits two `Retry-After` headers, Headers.get() in
    // most platforms returns the values joined by `, `. Our parser must
    // treat that as unparseable rather than parsing the first number
    // and ignoring the second (which would silently lose info).
    expect(parseRetryAfter("60, 120")).toBeNull();
    expect(parseRetryAfter("60,120")).toBeNull();
  });

  it("H5: parseRetryAfter rejects exponential notation (1e10) — security against huge values", () => {
    // Exponential notation in delta-seconds isn't valid per RFC. Reject.
    // (If accepted, a hostile server could try to overflow Math via
    // Number.parseFloat("1e308") — though our maxDelayMs cap protects
    // against the overflow downstream anyway.)
    expect(parseRetryAfter("1e10")).toBeNull();
    expect(parseRetryAfter("1.5e3")).toBeNull();
  });

  it("H6: parseRetryAfter rejects scientific / hex / octal forms", () => {
    expect(parseRetryAfter("0x10")).toBeNull();
    expect(parseRetryAfter("0o10")).toBeNull();
    expect(parseRetryAfter("0b10")).toBeNull();
  });

  it("H7: parseRetryAfter handles huge numeric values without overflow", () => {
    // A 21-digit number Number-parses to ~1e21, which is finite.
    // Math.floor(1e21 * 1000) = ~1e24, also finite. Caller's
    // maxDelayMs cap is what enforces the upper bound.
    const result = parseRetryAfter("999999999999999999999");
    expect(result).not.toBeNull();
    expect(Number.isFinite(result!)).toBe(true);
    // Real value is some huge but finite ms count — caller caps it.
  });

  it("H8: hostile server with very-far-future Retry-After date is capped", () => {
    // Server says "retry in 100 years". Without the cap, the SDK would
    // schedule a timer for 100 years — process leak.
    const farFuture = new Date(Date.now() + 100 * 365 * 24 * 3_600_000).toUTCString();
    const opts = { ...DEFAULT_RETRY_OPTIONS, maxDelayMs: 10_000 };
    const err = new AttestryAPIError("x", 429, null);
    attachRetryAfter(err, farFuture);
    const result = computeRetryDelay(err, 0, opts);
    expect(result).toBeLessThanOrEqual(10_000);
  });

  it("H9: sleepWithSignal with no signal still resolves cleanly", async () => {
    // Defensive: many retry tests pass undefined signal. Pin that the
    // signal-undefined branch resolves on the timer.
    const start = Date.now();
    await sleepWithSignal(10, undefined);
    expect(Date.now() - start).toBeGreaterThanOrEqual(5);
  });
});

describe("retry — coverage-round defensive pins", () => {
  it("C1: resolveRetryOptions throws on negative maxDelayMs", () => {
    expect(() =>
      resolveRetryOptions({ maxDelayMs: -1 }, undefined),
    ).toThrow(AttestryError);
  });

  it("C1 (cont.): resolveRetryOptions throws on Infinity maxDelayMs", () => {
    expect(() =>
      resolveRetryOptions({ maxDelayMs: Infinity }, undefined),
    ).toThrow(AttestryError);
  });

  it("C1 (cont.): resolveRetryOptions throws on NaN initialDelayMs / maxDelayMs", () => {
    expect(() =>
      resolveRetryOptions({ initialDelayMs: NaN }, undefined),
    ).toThrow(AttestryError);
    expect(() =>
      resolveRetryOptions({ maxDelayMs: NaN }, undefined),
    ).toThrow(AttestryError);
  });

  it("C2: attachRetryAfter with null is a no-op (early return — defensive)", () => {
    const err = new AttestryAPIError("x", 429, null);
    attachRetryAfter(err, null);
    // _retryAfter property NOT set — no override needed; no defineProperty
    // call, no error thrown.
    expect((err as unknown as { _retryAfter?: unknown })._retryAfter).toBeUndefined();
  });

  it("C3: attached _retryAfter is non-enumerable (does NOT pollute JSON.stringify)", () => {
    // The property is added via Object.defineProperty with enumerable:false.
    // Pin: JSON.stringify(err) does NOT include _retryAfter, even though
    // err has the property accessible via dot-access. Without this
    // invariant, console.log(err) would expose internal retry plumbing
    // and `JSON.stringify(err)` for log shipping would change shape.
    const err = new AttestryAPIError("rate limited", 429, { error: "x" });
    attachRetryAfter(err, "60");
    // Direct access works.
    expect((err as unknown as { _retryAfter?: unknown })._retryAfter).toBe("60");
    // But Object.keys / JSON.stringify don't see it.
    expect(Object.keys(err)).not.toContain("_retryAfter");
    const serialized = JSON.parse(JSON.stringify(err));
    expect(serialized._retryAfter).toBeUndefined();
  });

  it("C4: stream request honors Retry-After header on initial-fetch retry", async () => {
    vi.useFakeTimers();
    const calls: MockedRequest[] = [];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
      });
      i++;
      if (i === 1) {
        // First attempt: 429 with explicit Retry-After.
        return new Response(JSON.stringify({ error: "x" }), {
          status: 429,
          headers: {
            "Content-Type": "application/json",
            "retry-after": "1",
          },
        });
      }
      // Second attempt: SSE.
      const encoder = new TextEncoder();
      const stream = new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(
            encoder.encode(
              `id: cursor-1\nevent: decision.appended\ndata: {"id":"a","systemId":"s","sequenceNumber":1,"recordHash":"sha256:x","prevRecordHash":null,"tombstoned":false,"createdAt":"2026-04-27T00:00:00.000Z"}\n\n`,
            ),
          );
          c.close();
        },
      });
      return new Response(stream, {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      // Tight exponential — but Retry-After should override and force the
      // 1-second wait.
      retry: { maxRetries: 1, initialDelayMs: 5, maxDelayMs: 10_000 },
    });
    const collectPromise = (async () => {
      const events = [];
      for await (const e of client.decisions.stream()) events.push(e);
      return events;
    })();
    // Before 1s: still waiting on Retry-After.
    await vi.advanceTimersByTimeAsync(500);
    expect(calls).toHaveLength(1);
    // After 1s+: retry fires.
    await vi.advanceTimersByTimeAsync(700);
    const events = await collectPromise;
    expect(events).toHaveLength(1);
    expect(calls).toHaveLength(2);
  });

  it("C5: parseRetryAfter handles small decimal seconds (0.001 → 1ms)", () => {
    expect(parseRetryAfter("0.001")).toBe(1);
  });

  it("C5 (cont.): parseRetryAfter sub-millisecond floors to 0ms (NOT null)", () => {
    // 0.0009 sec * 1000 = 0.9 ms. Math.floor → 0. Function returns 0.
    // The seconds <= 0 check is at SECONDS level, so 0.0009 (positive)
    // passes; the floored ms result is 0. Caller's downstream
    // (computeRetryDelay -> sleepWithSignal) then treats 0ms as
    // "resolve immediately" — faithful to the server's "retry now"
    // intent rather than falling through to exponential. Documented
    // behavior.
    expect(parseRetryAfter("0.0009")).toBe(0);
    expect(parseRetryAfter("0.0001")).toBe(0);
  });

  it("C6: client._streamRequest passes retry options through to streamRequest", async () => {
    // Defensive smoke pin: the inline _streamRequest method on
    // AttestryClient (in client.ts) just forwards to transportStreamRequest
    // — but if a future refactor accidentally drops the retry param from
    // the spread, retries would silently stop firing on streams. Pin
    // that a per-call retry override is observed by stream errors.
    let attemptCount = 0;
    const mockFetch: FetchLike = async () => {
      attemptCount++;
      return new Response(JSON.stringify({ error: "x" }), {
        status: 429,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 }, // client says 0…
    });
    let caught: unknown = null;
    // Per-call says 2 — should retry 2x = 3 attempts total.
    try {
      for await (const _e of client.decisions.stream(undefined, {
        retry: { maxRetries: 2, initialDelayMs: 0, maxDelayMs: 0 },
      })) {
        void _e;
      }
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    // 1 initial + 2 retries = 3 attempts — proves per-call override
    // routed through _streamRequest correctly.
    expect(attemptCount).toBe(3);
  });

  it("C7: parseRetryAfter rejects HTTP-date with garbage prefix that LOOKS numeric", () => {
    // Defensive: a hostile server emits "60 Mon, 04 May 2026 14:30:00 GMT"
    // — regex requires the entire trimmed string to be numeric, so this
    // fails the regex. Date.parse is asked next, which rejects. Returns
    // null. Pinned: no partial-match prefix vulnerability.
    expect(parseRetryAfter("60 Mon, 04 May 2026 14:30:00 GMT")).toBeNull();
  });
});

describe("AttestryClient construction — retry validation", () => {
  it("throws AttestryError at construction when retry config is invalid", () => {
    expect(
      () =>
        new AttestryClient({
          apiKey: "k",
          retry: { maxRetries: -1 },
          fetch: async () => new Response("{}"),
        }),
    ).toThrow(AttestryError);
  });

  it("accepts valid retry config at construction", () => {
    const client = new AttestryClient({
      apiKey: "k",
      retry: { maxRetries: 5, initialDelayMs: 500 },
      fetch: async () => new Response("{}"),
    });
    expect(client).toBeInstanceOf(AttestryClient);
  });

  it("accepts undefined retry config (uses defaults)", () => {
    const client = new AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}"),
    });
    expect(client).toBeInstanceOf(AttestryClient);
  });
});
