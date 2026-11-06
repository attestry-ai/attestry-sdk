// ─── 0.8.0 transport hardening ──────────────────────────────────────────────
//
// Regression pins for the 0.8.0 release (which folds in the planned 0.7.1 patch):
//
//   - P2-9  `timeoutMs` and the caller's AbortSignal stay in force until the
//           response BODY has been read (0.7.0 disarmed both as soon as
//           `fetch` resolved, i.e. on headers — a stalled body hung forever).
//   - P2-9  no timer / listener leak when the request body fails to serialize.
//   - P1-3  `redirect: "manual"`: a 3xx fails with a clear AttestryAPIError and
//           `x-api-key` is never forwarded across a cross-origin redirect.
//   - P1-3  a non-JSON 2xx (HTML gate / login page) names the URL + `baseUrl`.
//   - apiKey must be a legal header value — AttestryError at construction.
//
// Mock-fetch tests pin the SDK's own guarantees (they hold even for a custom
// `fetch` that ignores its signal after the headers); the real-HTTP tests at
// the bottom pin the same behaviour against Node's built-in fetch.

import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { AttestryClient } from "../client.js";
import { AttestryAPIError, AttestryError } from "../errors.js";
import { request, resolveClientConfig, streamRequest } from "../transport.js";
import type { FetchLike } from "../types.js";
import { trackTimersWithDelay } from "./timer-tracker.js";

afterEach(() => {
  vi.restoreAllMocks();
});

/** Rejects with "TEST-DEADLINE" if `p` has not settled within `ms`. */
function within<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return Promise.race([
    p.finally(() => clearTimeout(timer)),
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("TEST-DEADLINE")), ms);
    }),
  ]);
}

/**
 * A 2xx (or other status) Response whose body delivers `firstChunk` and
 * then stalls forever — the server sent the headers and part of the body,
 * then went silent. Records whether the SDK canceled the body.
 */
function stalledBodyResponse(
  firstChunk: string,
  init: { status?: number; contentType?: string } = {},
): { response: Response; canceled: () => boolean } {
  let canceled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      c.enqueue(new TextEncoder().encode(firstChunk));
    },
    cancel() {
      canceled = true;
    },
  });
  return {
    response: new Response(stream, {
      status: init.status ?? 200,
      headers: { "Content-Type": init.contentType ?? "application/json" },
    }),
    canceled: () => canceled,
  };
}

/** A fetch that resolves with `response` and IGNORES its signal entirely. */
function signalIgnoringFetch(response: Response): FetchLike {
  return async () => response;
}

describe("P2-9: timeoutMs covers the response body (not just the headers)", () => {
  it("a stalled 2xx body with timeoutMs=500 rejects with AttestryError('request timed out')", async () => {
    const { response, canceled } = stalledBodyResponse('{"success":true,"data":');
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: signalIgnoringFetch(response),
      timeoutMs: 500,
      retry: { maxRetries: 0 },
    });
    const started = Date.now();
    const err = await within(
      request({ config, method: "GET", path: "/x" }).then(
        () => null,
        (e: unknown) => e,
      ),
      3_000,
    );
    expect(err).toBeInstanceOf(AttestryError);
    expect(err).not.toBeInstanceOf(AttestryAPIError);
    expect((err as AttestryError).message).toBe("request timed out");
    expect(Date.now() - started).toBeGreaterThanOrEqual(450);
    // The SDK released the body (and with it the connection).
    expect(canceled()).toBe(true);
  });

  it("a stalled NON-2xx error body is covered by the timeout too", async () => {
    const { response } = stalledBodyResponse('{"error":', { status: 500 });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: signalIgnoringFetch(response),
      timeoutMs: 300,
      retry: { maxRetries: 0 },
    });
    const err = await within(
      request({ config, method: "GET", path: "/x" }).catch((e: unknown) => e),
      3_000,
    );
    expect(err).toBeInstanceOf(AttestryError);
    expect((err as AttestryError).message).toBe("request timed out");
  });

  it("the caller's AbortSignal still cancels after the headers arrived (timeoutMs: 0)", async () => {
    const { response, canceled } = stalledBodyResponse('{"a":');
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: signalIgnoringFetch(response),
      timeoutMs: 0,
    });
    const ac = new AbortController();
    const p = request({ config, method: "GET", path: "/x", options: { signal: ac.signal } });
    setTimeout(() => ac.abort(), 100);
    const err = await within(p.catch((e: unknown) => e), 3_000);
    expect(err).toBeInstanceOf(AttestryError);
    expect((err as AttestryError).message).toBe("request aborted by caller");
    expect(canceled()).toBe(true);
  });

  it("a connection drop mid-body surfaces as AttestryError('network error: …'), not a raw TypeError", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode('{"a":'));
        c.error(new TypeError("terminated"));
      },
    });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: signalIgnoringFetch(
        new Response(stream, { headers: { "Content-Type": "application/json" } }),
      ),
    });
    const err = await request({ config, method: "GET", path: "/x" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestryError);
    expect((err as AttestryError).message).toBe("network error: terminated");
    expect((err as Error & { cause?: unknown }).cause).toBeInstanceOf(TypeError);
  });

  it("clears the timer and detaches the caller listener once the body has been read", async () => {
    const timers = trackTimersWithDelay(43_210);
    const ac = new AbortController();
    const addSpy = vi.spyOn(ac.signal, "addEventListener");
    const removeSpy = vi.spyOn(ac.signal, "removeEventListener");
    const config = resolveClientConfig({
      apiKey: "k",
      timeoutMs: 43_210,
      fetch: async () =>
        new Response(JSON.stringify({ success: true, data: { ok: 1 } }), {
          headers: { "Content-Type": "application/json" },
        }),
    });
    await expect(
      request({ config, method: "GET", path: "/x", options: { signal: ac.signal } }),
    ).resolves.toEqual({ ok: 1 });
    const armed = timers.armed();
    expect(armed).toHaveLength(1);
    expect(timers.isCleared(armed[0])).toBe(true);
    const added = addSpy.mock.calls.filter((c) => c[0] === "abort").map((c) => c[1]);
    expect(added).toHaveLength(1);
    expect(removeSpy).toHaveBeenCalledWith("abort", added[0]);
  });

  it("the timer is still armed while the body is being read (released only after)", async () => {
    // Body arrives in two chunks ~150ms apart. The transport's timer must
    // not fire, and must be cleared only AFTER the second chunk. Follows the
    // transport's OWN timer handle (distinctive delay, identity check). A
    // global clearTimeout count is perturbed under --sequence.shuffle by
    // other tests' timers (e.g. undici's internal timers after the real-HTTP
    // tests).
    const TIMEOUT_MS = 8_765;
    const timers = trackTimersWithDelay(TIMEOUT_MS);
    let pushRest!: () => void;
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new TextEncoder().encode('{"success":true,'));
        pushRest = () => {
          c.enqueue(new TextEncoder().encode('"data":{"v":2}}'));
          c.close();
        };
      },
    });
    const config = resolveClientConfig({
      apiKey: "k",
      timeoutMs: TIMEOUT_MS,
      fetch: async () =>
        new Response(stream, { headers: { "Content-Type": "application/json" } }),
    });
    const p = request({ config, method: "GET", path: "/x" });
    await new Promise((r) => setTimeout(r, 150));
    const armed = timers.armed();
    expect(armed).toHaveLength(1);
    // Headers are in, the body is half-read: the deadline must still be armed.
    expect(timers.isCleared(armed[0])).toBe(false);
    pushRest();
    await expect(p).resolves.toEqual({ v: 2 });
    // Released once the body has been read.
    expect(timers.isCleared(armed[0])).toBe(true);
  });
});

describe("P2-9: no timer / listener leak when the request body fails to serialize", () => {
  it("a BigInt body rejects without arming the timeout or attaching to the caller signal", async () => {
    const timers = trackTimersWithDelay(54_321);
    const ac = new AbortController();
    const addSpy = vi.spyOn(ac.signal, "addEventListener");
    const removeSpy = vi.spyOn(ac.signal, "removeEventListener");
    const fetchSpy = vi.fn(async () => new Response("{}"));
    const config = resolveClientConfig({
      apiKey: "k",
      timeoutMs: 54_321,
      fetch: fetchSpy as FetchLike,
    });
    const err = await request({
      config,
      method: "POST",
      path: "/x",
      body: { n: 1n },
      options: { signal: ac.signal },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestryError);
    expect((err as AttestryError).message).toMatch(/^invalid request body/);
    expect(fetchSpy).not.toHaveBeenCalled();
    // 0.7.0 armed a 54_321ms timer here and never cleared it (kept the
    // process alive) and left the caller-signal listener attached.
    expect(timers.armed()).toHaveLength(0);
    const added = addSpy.mock.calls.filter((c) => c[0] === "abort").length;
    const removed = removeSpy.mock.calls.filter((c) => c[0] === "abort").length;
    expect(added).toBe(removed);
  });
});

describe("RequestOptions.timeoutMs (per-call override)", () => {
  it("a per-call timeoutMs overrides the client timeout", async () => {
    const config = resolveClientConfig({
      apiKey: "k",
      timeoutMs: 60_000,
      fetch: (_url, init) =>
        new Promise((_, reject) =>
          init?.signal?.addEventListener("abort", () => reject(init.signal!.reason)),
        ),
    });
    const err = await within(
      request({ config, method: "GET", path: "/x", options: { timeoutMs: 50 } }).catch(
        (e: unknown) => e,
      ),
      3_000,
    );
    expect(err).toBeInstanceOf(AttestryError);
    expect((err as AttestryError).message).toBe("request timed out");
  });

  it.each([-1, Number.NaN, Number.POSITIVE_INFINITY, "100" as unknown as number])(
    "rejects an invalid per-call timeoutMs (%s) with AttestryError before any fetch",
    async (bad) => {
      const fetchSpy = vi.fn(async () => new Response("{}"));
      const config = resolveClientConfig({ apiKey: "k", fetch: fetchSpy as FetchLike });
      const err = await request({
        config,
        method: "GET",
        path: "/x",
        options: { timeoutMs: bad },
      }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AttestryError);
      expect((err as AttestryError).message).toMatch(/timeoutMs/);
      expect(fetchSpy).not.toHaveBeenCalled();
    },
  );
});

describe("P1-3: redirects are never followed", () => {
  it("sends every request with redirect: 'manual' (JSON and streaming paths)", async () => {
    const inits: RequestInit[] = [];
    const fetchImpl: FetchLike = async (_url, init) => {
      inits.push(init ?? {});
      // Answer with whatever the request Accepts (JSON or SSE).
      const accept = (init?.headers as Headers).get("accept") ?? "application/json";
      return new Response(JSON.stringify({ ok: true }), {
        headers: { "Content-Type": accept },
      });
    };
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    await request({ config, method: "POST", path: "/x", body: {} });
    await streamRequest({ config, path: "/s" });
    expect(inits.map((i) => i.redirect)).toEqual(["manual", "manual"]);
  });

  it("a 307 fails with AttestryAPIError(307) naming the URL, the Location and baseUrl", async () => {
    const fetchSpy = vi.fn(
      async () =>
        new Response("Temporary Redirect", {
          status: 307,
          headers: { Location: "https://evil.example/gate?next=%2Fapi%2Fv1%2Fx" },
        }),
    );
    const config = resolveClientConfig({
      apiKey: "k",
      baseUrl: "https://attestry.example",
      fetch: fetchSpy as FetchLike,
    });
    const err = await request({
      config,
      method: "GET",
      path: "/api/v1/x",
      query: { q: "secret-ish" },
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err).toBeInstanceOf(AttestryError);
    const apiErr = err as AttestryAPIError;
    expect(apiErr.status).toBe(307);
    expect(apiErr.details).toEqual({ location: "https://evil.example/gate?next=%2Fapi%2Fv1%2Fx" });
    expect(apiErr.message).toContain("GET https://attestry.example/api/v1/x");
    expect(apiErr.message).toContain("HTTP 307");
    expect(apiErr.message).toContain("https://evil.example/gate");
    expect(apiErr.message).toContain("baseUrl");
    // The query string is not echoed into the message.
    expect(apiErr.message).not.toContain("secret-ish");
    // Not retried, not followed: exactly one fetch.
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it.each([301, 302, 303, 308])("a %d redirect is rejected the same way", async (status) => {
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: async () =>
        new Response(null, { status, headers: { Location: "https://elsewhere.example/" } }),
    });
    const err = await request({ config, method: "POST", path: "/x", body: {} }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect((err as AttestryAPIError).status).toBe(status);
    expect((err as AttestryAPIError).message).toMatch(/does not follow redirects/);
  });

  it("a custom fetch that followed a redirect anyway (response.redirected) is rejected", async () => {
    const followed = new Response(JSON.stringify({ success: true, data: {} }), {
      headers: { "Content-Type": "application/json" },
    });
    Object.defineProperty(followed, "redirected", { value: true });
    Object.defineProperty(followed, "url", { value: "https://elsewhere.example/landed" });
    const config = resolveClientConfig({ apiKey: "k", fetch: async () => followed });
    const err = await request({ config, method: "GET", path: "/x" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect((err as AttestryAPIError).message).toContain("https://elsewhere.example/landed");
    expect((err as AttestryAPIError).message).toMatch(/does not follow redirects/);
  });

  it("an opaque-redirect response (browser-style fetch) is rejected", async () => {
    const opaque = new Response(null, { status: 200 });
    Object.defineProperty(opaque, "type", { value: "opaqueredirect" });
    Object.defineProperty(opaque, "status", { value: 0 });
    const config = resolveClientConfig({ apiKey: "k", fetch: async () => opaque });
    const err = await request({ config, method: "GET", path: "/x" }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect((err as AttestryAPIError).message).toMatch(/does not follow redirects/);
  });

  it("streaming requests reject a redirect too (decisions.stream)", async () => {
    const client = new AttestryClient({
      apiKey: "k",
      retry: { maxRetries: 0 },
      fetch: async () =>
        new Response(null, { status: 307, headers: { Location: "/gate" } }),
    });
    const it = client.decisions.stream()[Symbol.asyncIterator]();
    const err = await it.next().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect((err as AttestryAPIError).status).toBe(307);
    expect((err as AttestryAPIError).message).toMatch(/does not follow redirects/);
    expect((err as AttestryAPIError).details).toEqual({ location: "/gate" });
  });
});

describe("P1-3: a non-JSON 2xx names the URL and points at baseUrl", () => {
  it("an HTML gate page at 200 fails with a message naming the URL + baseUrl", async () => {
    const config = resolveClientConfig({
      apiKey: "k",
      baseUrl: "https://attestry.example/",
      fetch: async () =>
        new Response("<!doctype html><title>Private beta</title>", {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        }),
    });
    const err = await request({ config, method: "GET", path: "/api/v1/health" }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AttestryAPIError);
    const apiErr = err as AttestryAPIError;
    expect(apiErr.status).toBe(200);
    expect(apiErr.details).toBeNull();
    // Backward-compatible prefix …
    expect(apiErr.message).toMatch(/^expected application\/json response, got "text\/html; charset=utf-8"/);
    // … plus the URL and the baseUrl hint.
    expect(apiErr.message).toContain("GET https://attestry.example/api/v1/health");
    expect(apiErr.message).toContain("baseUrl");
  });

  it("the streaming content-type guard says the same (SSE got HTML)", async () => {
    const config = resolveClientConfig({
      apiKey: "k",
      baseUrl: "https://attestry.example",
      fetch: async () =>
        new Response("<html></html>", { headers: { "Content-Type": "text/html" } }),
    });
    const err = await streamRequest({ config, path: "/api/v1/decisions/stream" }).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect((err as AttestryAPIError).message).toMatch(/^expected text\/event-stream response, got "text\/html"/);
    expect((err as AttestryAPIError).message).toContain(
      "GET https://attestry.example/api/v1/decisions/stream",
    );
    expect((err as AttestryAPIError).message).toContain("baseUrl");
  });
});

describe("apiKey must be a legal HTTP header value (AttestryError at construction)", () => {
  const fetchImpl: FetchLike = async () => new Response("{}");

  it.each([
    ["an embedded LF", "sk_live_abc\ndef"],
    ["an embedded CR", "sk_live_abc\rdef"],
    ["a CRLF header-injection attempt", "sk_live_abc\r\nX-Evil: 1"],
    ["an embedded space", "sk_live abc"],
    ["an embedded tab", "sk_live\tabc"],
    ["a NUL", "sk_live\u0000abc"],
    ["a DEL", "sk_live\u007fabc"],
    ["a pasted smart quote", "sk_live_abc’def"],
    ["a non-breaking space", "sk_live_abc "],
  ])("rejects %s", (_label, apiKey) => {
    let caught: unknown;
    try {
      new AttestryClient({ apiKey, fetch: fetchImpl });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toMatch(/apiKey.*not a valid HTTP header value/);
    // Never echo the key.
    expect((caught as AttestryError).message).not.toContain("sk_live");
  });

  it("names the offending code point", () => {
    expect(() => new AttestryClient({ apiKey: "abc’def", fetch: fetchImpl })).toThrowError(
      /U\+2019/,
    );
    expect(() => new AttestryClient({ apiKey: "abc\ndef", fetch: fetchImpl })).toThrowError(
      /U\+000A/,
    );
  });

  it("trims leading/trailing HTTP whitespace (a key read from a file with a trailing newline keeps working)", async () => {
    const seen: string[] = [];
    const client = new AttestryClient({
      apiKey: "  sk_live_abc\r\n",
      fetch: async (_url, init) => {
        seen.push((init?.headers as Headers).get("x-api-key") ?? "");
        return new Response(JSON.stringify({ success: true, data: {} }), {
          headers: { "Content-Type": "application/json" },
        });
      },
    });
    await client.annexIv.getBind({ technicalFileId: "11111111-1111-1111-1111-111111111111" });
    expect(seen).toEqual(["sk_live_abc"]);
  });

  it("rejects a whitespace-only key as missing", () => {
    expect(() => new AttestryClient({ apiKey: " \n\t ", fetch: fetchImpl })).toThrowError(
      /apiKey.*required/,
    );
  });
});

// ─── Real HTTP (Node's built-in fetch, 127.0.0.1 only) ─────────────────────

interface Recorded {
  path: string;
  headers: IncomingHttpHeaders;
}

async function listen(
  handler: (req: { url?: string; headers: IncomingHttpHeaders }, res: import("node:http").ServerResponse) => void,
): Promise<{ server: Server; origin: (host?: string) => string; seen: Recorded[] }> {
  const seen: Recorded[] = [];
  const server = createServer((req, res) => {
    seen.push({ path: req.url ?? "", headers: req.headers });
    handler(req, res);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  return { server, origin: (host = "127.0.0.1") => `http://${host}:${port}`, seen };
}

function close(server: Server): Promise<void> {
  server.closeAllConnections?.();
  return new Promise((r) => server.close(() => r()));
}

describe("real HTTP: redirect + stalled body against Node's fetch", () => {
  it("x-api-key is never sent to the target of a cross-origin 307", async () => {
    const target = await listen((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: true, data: { leaked: true } }));
    });
    const api = await listen((_req, res) => {
      // Cross-origin: different host name (localhost vs 127.0.0.1) + port.
      res.writeHead(307, { Location: `${target.origin("localhost")}/landed` });
      res.end();
    });
    try {
      const client = new AttestryClient({
        apiKey: "SECRET-KEY-123",
        baseUrl: api.origin(),
        retry: { maxRetries: 0 },
      });
      const err = await client.annexIv
        .getBind({ technicalFileId: "11111111-1111-1111-1111-111111111111" })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(307);
      expect((err as AttestryAPIError).message).toContain("/landed");
      expect(api.seen).toHaveLength(1);
      expect(api.seen[0].headers["x-api-key"]).toBe("SECRET-KEY-123");
      // The redirect target never saw a request at all — so never the key.
      expect(target.seen).toHaveLength(0);
    } finally {
      await close(api.server);
      await close(target.server);
    }
  });

  it("a server that sends headers + part of the body then stalls: timeoutMs=500 rejects 'request timed out'", async () => {
    const api = await listen((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.write('{"success":true,"data":{"partial":');
      // …and never ends.
    });
    try {
      const client = new AttestryClient({
        apiKey: "k",
        baseUrl: api.origin(),
        timeoutMs: 500,
        retry: { maxRetries: 0 },
      });
      const err = await within(
        client.annexIv
          .getBind({ technicalFileId: "11111111-1111-1111-1111-111111111111" })
          .catch((e: unknown) => e),
        5_000,
      );
      expect(err).toBeInstanceOf(AttestryError);
      expect((err as AttestryError).message).toBe("request timed out");
    } finally {
      await close(api.server);
    }
  });
});
