import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
// Import the native setTimeout from `node:timers` so the Retry-After
// tests can capture the requested sleep duration WITHOUT being affected
// by the suite's `vi.useFakeTimers()` setup. The fake timers replace
// `globalThis.setTimeout` but not `node:timers.setTimeout`.
import { setTimeout as nativeSetTimeout } from "node:timers";
import {
  AttestryClient,
  parseRetryAfter,
  isInsecureUrl,
  redactUrl,
  safeLog,
} from "../client.js";
import type { DecisionInput, ExporterLogger } from "../types.js";

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
    globalThis.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ totalInserted: 1, totalFailed: 0 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

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
  });

  it("retries on 503 and succeeds on the second attempt", async () => {
    let attempt = 0;
    globalThis.fetch = vi.fn().mockImplementation(async () => {
      attempt++;
      if (attempt === 1) {
        return new Response("upstream", { status: 503 });
      }
      return new Response(JSON.stringify({ totalInserted: 1 }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
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
      return new Response(JSON.stringify({ totalInserted: 1 }), {
        status: 200,
      });
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
        return new Response("{}", { status: 200 });
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
      return new Response(JSON.stringify({ totalInserted: 1 }), {
        status: 200,
      });
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
      return new Response(JSON.stringify({ totalInserted: 1 }), {
        status: 200,
      });
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
