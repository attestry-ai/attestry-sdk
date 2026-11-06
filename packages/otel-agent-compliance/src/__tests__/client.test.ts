import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// Import the native setTimeout from `node:timers` so the Retry-After
// tests can capture the requested sleep duration WITHOUT being affected
// by the suite's `vi.useFakeTimers()` setup. The fake timers replace
// `globalThis.setTimeout` but not `node:timers.setTimeout`.
import { setTimeout as nativeSetTimeout } from "node:timers";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  AttestryClient,
  __test__ as clientTest,
  isJsonContentType,
  parseBulkEnvelope,
  parseRetryAfter,
  isInsecureUrl,
  redactUrl,
  safeLog,
} from "../client.js";
import type { DecisionInput, ExporterLogger } from "../types.js";
import { kernelBulkResponse, kernelErrorResponse } from "./fakes.js";

const SAMPLE_DECISION: DecisionInput = {
  systemId: "00000000-0000-0000-0000-000000000001",
  inputDigest:
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  frameworkClaims: [],
  toolInvocations: [],
  delegationChain: [],
};

function makeLogger(): ExporterLogger & {
  warns: { msg: string; meta?: Record<string, unknown> }[];
  errors: { msg: string; meta?: Record<string, unknown> }[];
} {
  const warns: { msg: string; meta?: Record<string, unknown> }[] = [];
  const errors: { msg: string; meta?: Record<string, unknown> }[] = [];
  return {
    warn: (msg, meta) => warns.push({ msg, meta }),
    error: (msg, meta) => errors.push({ msg, meta }),
    warns,
    errors,
  };
}

describe("AttestryClient", () => {
  const ORIGINAL_FETCH = globalThis.fetch;

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("returns ok and reports inserted count on 200", async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(kernelBulkResponse({ submitted: 1 }));

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
    });
    const result = await client.recordDecisionsBatch([SAMPLE_DECISION]);
    expect(result.ok).toBe(true);
    expect(result.inserted).toBe(1);
  });

  it("short-circuits on empty batch (no fetch)", async () => {
    const fetchSpy = vi.fn();
    globalThis.fetch = fetchSpy;

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
    });
    const result = await client.recordDecisionsBatch([]);
    expect(result.ok).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("does not throw on network error — returns ok=false", async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("ECONNRESET"));
    const logger = makeLogger();
    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
      logger,
    });

    const promise = client.recordDecisionsBatch([SAMPLE_DECISION]);
    // Drain the backoff timers so we don't await forever.
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.ok).toBe(false);
    expect(result.error).toContain("ECONNRESET");
    expect(logger.warns.length).toBeGreaterThanOrEqual(1);
    // Network errors are transient — all three attempts are used.
    expect(globalThis.fetch).toHaveBeenCalledTimes(3);
  });

  it("retries on 503 and succeeds on the second attempt", async () => {
    let attempt = 0;
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      attempt++;
      if (attempt === 1) {
        return new Response("upstream", { status: 503 });
      }
      return kernelBulkResponse({ submitted: 1 });
    });

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
    });
    const promise = client.recordDecisionsBatch([SAMPLE_DECISION]);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.ok).toBe(true);
    expect(attempt).toBe(2);
  });

  it("does NOT retry on 422 (permanent client error)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ error: "validation failed" }), {
        status: 422,
        headers: { "Content-Type": "application/json" },
      }),
    );
    globalThis.fetch = fetchMock;
    const logger = makeLogger();

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
      logger,
    });
    const promise = client.recordDecisionsBatch([SAMPLE_DECISION]);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.ok).toBe(false);
    expect(result.status).toBe(422);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("DOES retry on 429 (rate limited)", async () => {
    let attempt = 0;
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      attempt++;
      if (attempt < 2) return new Response("slow down", { status: 429 });
      return kernelBulkResponse({ submitted: 1 });
    });

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
    });
    const promise = client.recordDecisionsBatch([SAMPLE_DECISION]);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.ok).toBe(true);
    expect(attempt).toBe(2);
  });

  it("gives up after 3 attempts on persistent 503", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response("nope", { status: 503 }));
    globalThis.fetch = fetchMock;
    const logger = makeLogger();

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
      logger,
    });
    const promise = client.recordDecisionsBatch([SAMPLE_DECISION]);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.ok).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(logger.warns).toHaveLength(1);
    expect(logger.warns[0]?.meta?.droppedCount).toBe(1);
  });

  it("times out long requests via AbortController", async () => {
    globalThis.fetch = vi.fn().mockImplementation(
      async (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const err = new Error("aborted");
            (err as { name: string }).name = "AbortError";
            reject(err);
          });
          // never resolves
        }),
    );
    const logger = makeLogger();

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
      logger,
      fetchTimeoutMs: 100,
    });
    const promise = client.recordDecisionsBatch([SAMPLE_DECISION]);
    await vi.runAllTimersAsync();
    const result = await promise;

    expect(result.ok).toBe(false);
    expect(result.error).toContain("timeout");
  });

  it("includes x-api-key + content-type in request headers", async () => {
    let captured: RequestInit | undefined;
    globalThis.fetch = vi
      .fn()
      .mockImplementation(async (_url: string, init?: RequestInit) => {
        captured = init;
        return kernelBulkResponse({ submitted: 1 });
      });

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "secret-key",
      systemId: "s",
    });
    await client.recordDecisionsBatch([SAMPLE_DECISION]);

    const headers = captured?.headers as Record<string, string> | undefined;
    expect(headers?.["x-api-key"]).toBe("secret-key");
    expect(headers?.["Content-Type"]).toBe("application/json");
    expect(headers?.["User-Agent"]).toMatch(
      /^attestry-otel-agent-compliance\/\d+\.\d+\.\d+$/,
    );
    const body = JSON.parse(captured?.body as string);
    expect(body.items).toEqual([SAMPLE_DECISION]);
  });

  it("never follows redirects (redirect: 'manual')", async () => {
    let captured: RequestInit | undefined;
    globalThis.fetch = vi
      .fn()
      .mockImplementation(async (_url: string, init?: RequestInit) => {
        captured = init;
        return kernelBulkResponse({ submitted: 1 });
      });
    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
    });
    await client.recordDecisionsBatch([SAMPLE_DECISION]);
    expect(captured?.redirect).toBe("manual");
  });

  // ─── Hostile r2 (H1): Honors Retry-After header ─────────────────

  it("honors Retry-After delta-seconds on 429", async () => {
    // Run with REAL timers in this test; the suite-level useFakeTimers
    // would deadlock the backoff sleep. We observe what was scheduled
    // by spying on globalThis.setTimeout and short-circuiting the wait.
    vi.useRealTimers();
    let attempt = 0;
    const sleepMs: number[] = [];
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      attempt++;
      if (attempt === 1) {
        return new Response("slow", {
          status: 429,
          headers: { "Retry-After": "2" }, // server says wait 2 seconds
        });
      }
      return kernelBulkResponse({ submitted: 1 });
    });

    // Spy on globalThis.setTimeout, captured after useRealTimers so
    // nativeSetTimeout reaches the actual Node binding.
    vi.spyOn(globalThis, "setTimeout").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ((fn: any, ms?: number) => {
        if (typeof ms === "number") sleepMs.push(ms);
        return nativeSetTimeout(fn, 0);
      }) as unknown as typeof setTimeout,
    );

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
    });
    const result = await client.recordDecisionsBatch([SAMPLE_DECISION]);
    expect(result.ok).toBe(true);
    // sleepMs records the timeout-controller (10_000) and the backoff.
    // The backoff value should be 2000ms (Retry-After: 2 seconds), NOT
    // the default 250ms exponential backoff.
    expect(sleepMs).toContain(2000);
    expect(attempt).toBe(2);
  });

  it("caps honored Retry-After at 60s", async () => {
    vi.useRealTimers();
    let attempt = 0;
    const sleepMs: number[] = [];
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      attempt++;
      if (attempt === 1) {
        return new Response("slow", {
          status: 429,
          headers: { "Retry-After": "3600" }, // 1 hour — too long
        });
      }
      return kernelBulkResponse({ submitted: 1 });
    });

    vi.spyOn(globalThis, "setTimeout").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      ((fn: any, ms?: number) => {
        if (typeof ms === "number") sleepMs.push(ms);
        return nativeSetTimeout(fn, 0);
      }) as unknown as typeof setTimeout,
    );

    const client = new AttestryClient({
      apiUrl: "https://example.com/x",
      apiKey: "k",
      systemId: "s",
    });
    await client.recordDecisionsBatch([SAMPLE_DECISION]);
    // 60s cap — never wait the literal hour the server requested.
    expect(sleepMs).toContain(60_000);
    expect(sleepMs).not.toContain(3_600_000);
  });

  // ─── Hostile r2 (H3): http:// URLs warn at construction ─────────

  it("warns at construction when apiUrl is http:// (non-localhost)", () => {
    const logger = makeLogger();
    new AttestryClient({
      apiUrl: "http://prod.example.com/ingest",
      apiKey: "k",
      systemId: "s",
      logger,
    });
    expect(
      logger.warns.some((w) => w.msg.toLowerCase().includes("cleartext")),
    ).toBe(true);
  });

  it("does NOT warn for http://localhost (dev environment)", () => {
    const logger = makeLogger();
    new AttestryClient({
      apiUrl: "http://localhost:3000/ingest",
      apiKey: "k",
      systemId: "s",
      logger,
    });
    expect(
      logger.warns.some((w) => w.msg.toLowerCase().includes("cleartext")),
    ).toBe(false);
  });

  it("does NOT warn for https://", () => {
    const logger = makeLogger();
    new AttestryClient({
      apiUrl: "https://attestry.app/ingest",
      apiKey: "k",
      systemId: "s",
      logger,
    });
    expect(logger.warns).toHaveLength(0);
  });
});

// ─── Hostile r2 helpers ───────────────────────────────────────────

describe("parseRetryAfter", () => {
  it("returns null for null/empty/whitespace", () => {
    expect(parseRetryAfter(null)).toBeNull();
    expect(parseRetryAfter("")).toBeNull();
    expect(parseRetryAfter("   ")).toBeNull();
  });

  it("parses delta-seconds integer", () => {
    expect(parseRetryAfter("5")).toBe(5_000);
    expect(parseRetryAfter("0")).toBe(0);
  });

  it("rejects negative or fractional delta-seconds", () => {
    expect(parseRetryAfter("-5")).toBeNull();
    expect(parseRetryAfter("1.5")).not.toBe(1_500); // not parsed as integer
  });

  it("parses HTTP date (future)", () => {
    const future = new Date(Date.now() + 30_000).toUTCString();
    const ms = parseRetryAfter(future);
    expect(ms).not.toBeNull();
    expect(ms).toBeGreaterThan(20_000);
    expect(ms).toBeLessThan(40_000);
  });

  it("returns 0 for HTTP date in the past (don't sleep negative)", () => {
    const past = new Date(Date.now() - 30_000).toUTCString();
    expect(parseRetryAfter(past)).toBe(0);
  });

  it("returns null for malformed input", () => {
    expect(parseRetryAfter("not a date")).toBeNull();
    expect(parseRetryAfter("abc123")).toBeNull();
  });
});

describe("isInsecureUrl", () => {
  it("returns true for http:// non-localhost", () => {
    expect(isInsecureUrl("http://example.com")).toBe(true);
    expect(isInsecureUrl("http://10.0.0.1/x")).toBe(true);
  });

  it("returns false for http:// localhost variants", () => {
    expect(isInsecureUrl("http://localhost:3000")).toBe(false);
    expect(isInsecureUrl("http://127.0.0.1:8080")).toBe(false);
    expect(isInsecureUrl("http://[::1]:3000")).toBe(false);
  });

  it("returns false for https://", () => {
    expect(isInsecureUrl("https://example.com")).toBe(false);
  });

  it("returns false for malformed URLs (let fetch report)", () => {
    expect(isInsecureUrl("not a url")).toBe(false);
  });
});

describe("redactUrl", () => {
  it("strips query string and userinfo", () => {
    expect(redactUrl("https://user:pass@host.com/path?key=secret")).toBe(
      "https://host.com/path",
    );
  });

  it("returns [unparseable] on garbage input", () => {
    expect(redactUrl("garbage")).toBe("[unparseable]");
  });
});

// ─── Hostile r2 (H2): safeLog never throws ────────────────────────

describe("safeLog", () => {
  it("invokes the underlying logger when it doesn't throw", () => {
    const calls: string[] = [];
    safeLog(
      {
        warn: (msg) => calls.push(`warn:${msg}`),
        error: (msg) => calls.push(`error:${msg}`),
      },
      "warn",
      "hello",
    );
    expect(calls).toEqual(["warn:hello"]);
  });

  it("never throws when the customer logger throws", () => {
    const broken: ExporterLogger = {
      warn: () => {
        throw new Error("logger blew up");
      },
      error: () => {
        throw new Error("logger blew up");
      },
    };
    // Should not throw, should not propagate.
    expect(() => safeLog(broken, "warn", "msg", { x: 1 })).not.toThrow();
    expect(() => safeLog(broken, "error", "msg")).not.toThrow();
  });
});

// ─── 0.2.0 (P1-4): kernel envelope, partial failures ─────────────

function decisions(n: number): DecisionInput[] {
  return Array.from({ length: n }, () => ({ ...SAMPLE_DECISION }));
}

function newClient(logger: ExporterLogger) {
  return new AttestryClient({
    apiUrl: "https://example.com/api/v1/decisions/bulk",
    apiKey: "k",
    systemId: "s",
    logger,
  });
}

describe("AttestryClient — kernel bulk envelope (P1-4)", () => {
  const ORIGINAL_FETCH = globalThis.fetch;
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("unwraps { success, data } and reports data.totalInserted", async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(kernelBulkResponse({ submitted: 3 }));
    const logger = makeLogger();
    const result = await newClient(logger).recordDecisionsBatch(decisions(3));
    expect(result).toMatchObject({
      ok: true,
      status: 200,
      inserted: 3,
      failed: 0,
      failures: [],
    });
    expect(logger.warns).toHaveLength(0);
  });

  it("totalFailed>0: returns ok=false + failures[] and warns with the failed[] codes (no retry)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      kernelBulkResponse({
        submitted: 3,
        failed: [
          { index: 1, code: "ijson_validation_failed" },
          { index: 2, code: "idempotency_unique_violation" },
        ],
      }),
    );
    globalThis.fetch = fetchMock;
    const logger = makeLogger();

    const promise = newClient(logger).recordDecisionsBatch(decisions(3));
    await vi.runAllTimersAsync();
    const result = await promise;

    // 0.1.1 reported this exact response as { ok: true, inserted: 3,
    // failed: 0 } with zero log lines.
    expect(result.ok).toBe(false);
    expect(result.inserted).toBe(1);
    expect(result.failed).toBe(2);
    expect(result.failures?.map((f) => [f.index, f.code])).toEqual([
      [1, "ijson_validation_failed"],
      [2, "idempotency_unique_violation"],
    ]);
    expect(result.failures?.[0]?.error).toBe("record 1 rejected");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    expect(logger.warns).toHaveLength(1);
    const warn = logger.warns[0]!;
    expect(warn.msg).toMatch(/partially rejected/);
    expect(warn.meta).toMatchObject({
      status: 200,
      submitted: 3,
      inserted: 1,
      failed: 2,
      failedCodes: ["idempotency_unique_violation", "ijson_validation_failed"],
      failures: [
        { index: 1, code: "ijson_validation_failed" },
        { index: 2, code: "idempotency_unique_violation" },
      ],
    });
  });

  it("caps the per-record failures echoed into one log line", async () => {
    const n = clientTest.LOGGED_FAILURES_CAP + 10;
    globalThis.fetch = vi.fn().mockResolvedValue(
      kernelBulkResponse({
        submitted: n,
        failed: Array.from({ length: n }, (_, index) => ({
          index,
          code: "chunk_failed",
        })),
      }),
    );
    const logger = makeLogger();
    const result = await newClient(logger).recordDecisionsBatch(decisions(n));
    expect(result.failures).toHaveLength(n);
    expect(logger.warns[0]?.meta?.failures).toHaveLength(
      clientTest.LOGGED_FAILURES_CAP,
    );
    expect(logger.warns[0]?.meta?.failedCodes).toEqual(["chunk_failed"]);
  });

  it("0.1.x wrong-shape body ({ totalInserted } at top level) is a logged failure, not success", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ totalInserted: 1, totalFailed: 0 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    globalThis.fetch = fetchMock;
    const logger = makeLogger();
    const result = await newClient(logger).recordDecisionsBatch(decisions(1));
    expect(result.ok).toBe(false);
    expect(result.inserted).toBe(0);
    expect(result.error).toMatch(/unrecognised response envelope/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logger.warns).toHaveLength(1);
    expect(logger.warns[0]?.meta?.droppedCount).toBe(1);
  });

  it("success:true without numeric data counts is a logged failure", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ success: true, data: {} }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    const logger = makeLogger();
    const result = await newClient(logger).recordDecisionsBatch(decisions(1));
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/data\.totalInserted/);
    expect(logger.warns).toHaveLength(1);
  });

  it("2xx with success:false is a logged failure (not retried)", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        new Response(
          JSON.stringify({ success: false, error: "something went wrong" }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
      );
    globalThis.fetch = fetchMock;
    const logger = makeLogger();
    const promise = newClient(logger).recordDecisionsBatch(decisions(1));
    await vi.runAllTimersAsync();
    const result = await promise;
    expect(result.ok).toBe(false);
    expect(result.error).toBe("server returned success:false: something went wrong");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logger.warns).toHaveLength(1);
  });

  it("surfaces the kernel error message from a non-2xx { success:false, error }", async () => {
    globalThis.fetch = vi
      .fn()
      .mockResolvedValue(kernelErrorResponse(401, "Authentication required"));
    const logger = makeLogger();
    const result = await newClient(logger).recordDecisionsBatch(decisions(1));
    expect(result).toMatchObject({
      ok: false,
      status: 401,
      error: "Authentication required",
    });
    expect(logger.warns[0]?.meta).toMatchObject({
      status: 401,
      retryable: false,
      attempts: 1,
    });
  });
});

// ─── 0.2.0 (P1-4): redirects + non-JSON 2xx ──────────────────────

describe("AttestryClient — redirects and HTML responses (P1-4)", () => {
  const ORIGINAL_FETCH = globalThis.fetch;
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it.each([301, 302, 303, 307, 308])(
    "HTTP %i is a logged, non-retried failure with a redacted Location",
    async (status) => {
      const fetchMock = vi.fn().mockResolvedValue(
        new Response(null, {
          status,
          headers: {
            Location: "/gate?next=%2Fapi%2Fv1%2Fdecisions%2Fbulk",
          },
        }),
      );
      globalThis.fetch = fetchMock;
      const logger = makeLogger();
      const promise = newClient(logger).recordDecisionsBatch(decisions(2));
      await vi.runAllTimersAsync();
      const result = await promise;

      expect(result.ok).toBe(false);
      expect(result.status).toBe(status);
      expect(result.inserted).toBe(0);
      expect(result.failed).toBe(2);
      expect(result.error).toContain(`unexpected redirect (HTTP ${status})`);
      // Location is resolved against apiUrl and its query string dropped.
      expect(result.error).toContain("to https://example.com/gate;");
      expect(result.error).not.toContain("next=");
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(logger.warns).toHaveLength(1);
      expect(logger.warns[0]?.meta).toMatchObject({
        status,
        retryable: false,
        droppedCount: 2,
      });
    },
  );

  it("an opaque-redirect response (browser fetch, status 0) is a non-retried failure", async () => {
    const opaque = {
      type: "opaqueredirect",
      status: 0,
      headers: new Headers(),
      body: null,
      text: async () => "",
    } as unknown as Response;
    const fetchMock = vi.fn().mockResolvedValue(opaque);
    globalThis.fetch = fetchMock;
    const logger = makeLogger();
    const promise = newClient(logger).recordDecisionsBatch(decisions(1));
    await vi.runAllTimersAsync();
    const result = await promise;
    expect(result.ok).toBe(false);
    expect(result.error).toContain("unexpected redirect");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logger.warns).toHaveLength(1);
  });

  it("200 text/html (e.g. a gate / login page) is a logged failure, not ok", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("<!doctype html><title>Private beta</title>", {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      }),
    );
    globalThis.fetch = fetchMock;
    const logger = makeLogger();
    const promise = newClient(logger).recordDecisionsBatch(decisions(1));
    await vi.runAllTimersAsync();
    const result = await promise;

    // 0.1.1: { ok: true, status: 200, inserted: 1, failed: 0 }, no log.
    expect(result.ok).toBe(false);
    expect(result.inserted).toBe(0);
    expect(result.failed).toBe(1);
    expect(result.error).toContain('got "text/html; charset=utf-8"');
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(logger.warns).toHaveLength(1);
    expect(logger.warns[0]?.meta?.droppedCount).toBe(1);
  });

  it("2xx with no Content-Type is a logged failure", async () => {
    const res = new Response(null, { status: 204 });
    globalThis.fetch = vi.fn().mockResolvedValue(res);
    const logger = makeLogger();
    const result = await newClient(logger).recordDecisionsBatch(decisions(1));
    expect(result.ok).toBe(false);
    expect(result.error).toContain('got "(none)"');
    expect(logger.warns).toHaveLength(1);
  });
});

// ─── 0.2.0 (P1-4): retries are driven by RETRYABLE_STATUS ────────

describe("AttestryClient — retry policy (RETRYABLE_STATUS)", () => {
  const ORIGINAL_FETCH = globalThis.fetch;
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("RETRYABLE_STATUS is exactly 408, 429, 500, 502, 503, 504", () => {
    expect([...clientTest.RETRYABLE_STATUS].sort((a, b) => a - b)).toEqual([
      408, 429, 500, 502, 503, 504,
    ]);
  });

  it.each([...clientTest.RETRYABLE_STATUS])(
    "retries HTTP %i and succeeds on the next attempt",
    async (status) => {
      let attempt = 0;
      globalThis.fetch = vi.fn().mockImplementation(async () => {
        attempt++;
        if (attempt === 1) return kernelErrorResponse(status, "transient");
        return kernelBulkResponse({ submitted: 1 });
      });
      const logger = makeLogger();
      const promise = newClient(logger).recordDecisionsBatch(decisions(1));
      await vi.runAllTimersAsync();
      const result = await promise;
      expect(result.ok).toBe(true);
      expect(attempt).toBe(2);
      expect(logger.warns).toHaveLength(0);
    },
  );

  // 0.1.1 did NOT retry 408 and DID retry 501/505 (it hard-coded
  // "4xx except 429 = permanent, every 5xx = retry").
  it.each([400, 401, 402, 403, 404, 405, 409, 413, 422, 501, 505])(
    "does not retry HTTP %i",
    async (status) => {
      const fetchMock = vi
        .fn()
        .mockResolvedValue(kernelErrorResponse(status, "permanent"));
      globalThis.fetch = fetchMock;
      const logger = makeLogger();
      const promise = newClient(logger).recordDecisionsBatch(decisions(1));
      await vi.runAllTimersAsync();
      const result = await promise;
      expect(result.ok).toBe(false);
      expect(result.status).toBe(status);
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(logger.warns).toHaveLength(1);
      expect(logger.warns[0]?.meta).toMatchObject({
        retryable: false,
        attempts: 1,
      });
    },
  );

  it("gives up after 3 attempts on a persistent retryable status and says so", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(kernelErrorResponse(504, "gateway timeout"));
    globalThis.fetch = fetchMock;
    const logger = makeLogger();
    const promise = newClient(logger).recordDecisionsBatch(decisions(1));
    await vi.runAllTimersAsync();
    const result = await promise;
    expect(result.ok).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(clientTest.DEFAULT_RETRIES);
    expect(logger.warns[0]?.meta).toMatchObject({
      status: 504,
      retryable: true,
      attempts: clientTest.DEFAULT_RETRIES,
    });
  });
});

// ─── 0.2.0 (P1-4): x-api-key never crosses a redirect (real HTTP) ─

describe("AttestryClient — real fetch against local servers", () => {
  const servers: Server[] = [];

  function listen(
    handler: Parameters<typeof createServer>[1],
  ): Promise<string> {
    const server = createServer(handler);
    servers.push(server);
    return new Promise((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        resolve(`${(server.address() as AddressInfo).port}`);
      });
    });
  }

  afterEach(async () => {
    await Promise.all(
      servers.splice(0).map(
        (s) => new Promise<void>((resolve) => s.close(() => resolve())),
      ),
    );
  });

  it("a cross-origin 307 is not followed, so the API key never reaches the target", async () => {
    const landed: IncomingHttpHeaders[] = [];
    const targetPort = await listen((req, res) => {
      landed.push(req.headers);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, data: {} }));
    });
    const apiPort = await listen((req, res) => {
      req.resume();
      res.writeHead(307, {
        Location: `http://localhost:${targetPort}/landed?next=x`,
      });
      res.end();
    });

    const logger = makeLogger();
    const client = new AttestryClient({
      apiUrl: `http://127.0.0.1:${apiPort}/api/v1/decisions/bulk`,
      apiKey: "SECRET-KEY-123",
      systemId: "s",
      logger,
    });
    const result = await client.recordDecisionsBatch([SAMPLE_DECISION]);

    expect(landed).toHaveLength(0);
    expect(result.ok).toBe(false);
    expect(result.status).toBe(307);
    expect(result.error).toContain(`to http://localhost:${targetPort}/landed;`);
    expect(JSON.stringify(logger.warns)).not.toContain("SECRET-KEY-123");
  });

  it("accepts a real kernel-shaped JSON response", async () => {
    let seenKey: string | undefined;
    const apiPort = await listen((req, res) => {
      seenKey = req.headers["x-api-key"] as string | undefined;
      req.resume();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          success: true,
          data: {
            totalSubmitted: 1,
            totalInserted: 1,
            totalFailed: 0,
            inserted: [],
            failed: [],
          },
        }),
      );
    });
    const client = new AttestryClient({
      apiUrl: `http://127.0.0.1:${apiPort}/api/v1/decisions/bulk`,
      apiKey: "k-123",
      systemId: "s",
    });
    const result = await client.recordDecisionsBatch([SAMPLE_DECISION]);
    expect(seenKey).toBe("k-123");
    expect(result).toMatchObject({ ok: true, inserted: 1, failed: 0 });
  });
});

describe("isJsonContentType", () => {
  it("accepts application/json with or without parameters, and +json", () => {
    expect(isJsonContentType("application/json")).toBe(true);
    expect(isJsonContentType("application/json; charset=utf-8")).toBe(true);
    expect(isJsonContentType("Application/JSON")).toBe(true);
    expect(isJsonContentType("application/problem+json")).toBe(true);
  });

  it("rejects HTML, text, missing and look-alike types", () => {
    expect(isJsonContentType(null)).toBe(false);
    expect(isJsonContentType("")).toBe(false);
    expect(isJsonContentType("text/html; charset=utf-8")).toBe(false);
    expect(isJsonContentType("text/plain;charset=UTF-8")).toBe(false);
    expect(isJsonContentType("application/jsonx")).toBe(false);
  });
});

describe("parseBulkEnvelope", () => {
  it("defaults a missing failed[].code to 'unknown' and index to position", () => {
    const parsed = parseBulkEnvelope({
      success: true,
      data: { totalInserted: 0, totalFailed: 1, failed: [{}] },
    });
    expect(parsed).toEqual({
      kind: "ok",
      inserted: 0,
      failed: 1,
      failures: [{ index: 0, code: "unknown" }],
    });
  });

  it("rejects non-objects and negative / fractional counts", () => {
    expect(parseBulkEnvelope(undefined).kind).toBe("error");
    expect(parseBulkEnvelope("ok").kind).toBe("error");
    expect(
      parseBulkEnvelope({
        success: true,
        data: { totalInserted: -1, totalFailed: 0 },
      }).kind,
    ).toBe("error");
    expect(
      parseBulkEnvelope({
        success: true,
        data: { totalInserted: 1.5, totalFailed: 0 },
      }).kind,
    ).toBe("error");
  });
});
