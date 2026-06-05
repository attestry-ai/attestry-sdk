import { describe, it, expect, vi } from "vitest";
import { AttestryAPIError, AttestryError } from "../errors.js";
import {
  __test__,
  composeUrl,
  request,
  resolveClientConfig,
  streamRequest,
} from "../transport.js";
import type { FetchLike } from "../types.js";

const fakeOk = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

const fakeErr = (body: unknown, status: number) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });

describe("resolveClientConfig", () => {
  const makeFetch: FetchLike = () => Promise.resolve(new Response(""));

  it("requires a non-empty apiKey", () => {
    expect(() =>
      resolveClientConfig({ apiKey: "", fetch: makeFetch }),
    ).toThrowError(AttestryError);
    expect(() =>
      resolveClientConfig({ apiKey: 123 as unknown as string, fetch: makeFetch }),
    ).toThrowError(AttestryError);
  });

  it("defaults baseUrl when omitted", () => {
    const cfg = resolveClientConfig({ apiKey: "k", fetch: makeFetch });
    expect(cfg.baseUrl).toBe(__test__.DEFAULT_BASE_URL);
  });

  it("strips trailing slashes from baseUrl", () => {
    const cfg = resolveClientConfig({
      apiKey: "k",
      fetch: makeFetch,
      baseUrl: "https://example.com///",
    });
    expect(cfg.baseUrl).toBe("https://example.com");
  });

  it("rejects empty baseUrl after stripping", () => {
    expect(() =>
      resolveClientConfig({ apiKey: "k", fetch: makeFetch, baseUrl: "/" }),
    ).toThrowError(AttestryError);
  });

  it("requires a fetch implementation when global fetch is unavailable", () => {
    // Save and clear globalThis.fetch.
    const original = globalThis.fetch;
    (globalThis as { fetch?: unknown }).fetch = undefined;
    try {
      expect(() => resolveClientConfig({ apiKey: "k" })).toThrowError(
        AttestryError,
      );
    } finally {
      globalThis.fetch = original;
    }
  });

  it("rejects non-finite or negative timeoutMs", () => {
    expect(() =>
      resolveClientConfig({ apiKey: "k", fetch: makeFetch, timeoutMs: -1 }),
    ).toThrowError(AttestryError);
    expect(() =>
      resolveClientConfig({ apiKey: "k", fetch: makeFetch, timeoutMs: NaN }),
    ).toThrowError(AttestryError);
    expect(() =>
      resolveClientConfig({
        apiKey: "k",
        fetch: makeFetch,
        timeoutMs: Infinity,
      }),
    ).toThrowError(AttestryError);
  });
});

describe("composeUrl", () => {
  it("inserts a slash when path is missing one", () => {
    expect(composeUrl("https://x.com", "api/v1")).toBe("https://x.com/api/v1");
  });
  it("does not double-slash when path starts with /", () => {
    expect(composeUrl("https://x.com", "/api/v1")).toBe("https://x.com/api/v1");
  });
});

describe("encodeQuery (internal)", () => {
  it("returns empty string for undefined input", () => {
    expect(__test__.encodeQuery(undefined)).toBe("");
  });
  it("returns empty string when every value is null/undefined", () => {
    expect(__test__.encodeQuery({ a: undefined, b: null })).toBe("");
  });
  it("encodes string + number + boolean", () => {
    const q = __test__.encodeQuery({ s: "hi", n: 42, b: true });
    expect(q).toBe("?s=hi&n=42&b=true");
  });
  it("URL-encodes special chars in keys and values", () => {
    expect(__test__.encodeQuery({ "k 1": "v&v" })).toBe("?k%201=v%26v");
  });
});

describe("readBody (internal — Hostile-review H1)", () => {
  it("returns null + empty raw on 204", async () => {
    const res = new Response(null, { status: 204 });
    expect(await __test__.readBody(res)).toEqual({ parsed: null, raw: "" });
  });
  it("returns null + empty raw on empty body", async () => {
    const res = new Response("", { status: 200 });
    expect(await __test__.readBody(res)).toEqual({ parsed: null, raw: "" });
  });
  it("returns null + raw text when body is not JSON (does not throw)", async () => {
    const res = new Response("<html>502</html>", { status: 502 });
    expect(await __test__.readBody(res)).toEqual({
      parsed: null,
      raw: "<html>502</html>",
    });
  });
  it("returns parsed + raw text when body is valid JSON", async () => {
    const body = '{"a":1}';
    const res = new Response(body, { status: 200 });
    expect(await __test__.readBody(res)).toEqual({
      parsed: { a: 1 },
      raw: body,
    });
  });
});

describe("extractMessage (internal)", () => {
  it("pulls a string error", () => {
    expect(__test__.extractMessage({ error: "bad" })).toBe("bad");
  });
  it("pulls a nested error.message", () => {
    expect(__test__.extractMessage({ error: { message: "deep" } })).toBe(
      "deep",
    );
  });
  it("pulls a top-level message", () => {
    expect(__test__.extractMessage({ message: "top" })).toBe("top");
  });
  it("returns null when neither shape matches", () => {
    expect(__test__.extractMessage({ foo: "bar" })).toBeNull();
    expect(__test__.extractMessage(null)).toBeNull();
    expect(__test__.extractMessage(undefined)).toBeNull();
    expect(__test__.extractMessage(42)).toBeNull();
  });
});

describe("request — success path", () => {
  it("sends x-api-key + Accept on every request", async () => {
    const mockFetch = vi.fn(async (_url, _init) => fakeOk({ success: true, data: { ok: true } }));
    const config = resolveClientConfig({
      apiKey: "secret",
      fetch: mockFetch as FetchLike,
    });
    await request({ config, method: "GET", path: "/x" });

    const init = mockFetch.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Headers;
    expect(headers.get("x-api-key")).toBe("secret");
    expect(headers.get("Accept")).toBe("application/json");
  });

  it("adds Content-Type only when a body is present", async () => {
    const mockFetch = vi.fn(async () => fakeOk({ success: true, data: {} }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });

    await request({ config, method: "GET", path: "/no-body" });
    const noBodyHeaders = (mockFetch.mock.calls[0][1] as RequestInit)
      .headers as Headers;
    expect(noBodyHeaders.get("Content-Type")).toBeNull();

    await request({ config, method: "POST", path: "/yes", body: { a: 1 } });
    const withBodyHeaders = (mockFetch.mock.calls[1][1] as RequestInit)
      .headers as Headers;
    expect(withBodyHeaders.get("Content-Type")).toBe("application/json");
  });

  it("serializes body as JSON", async () => {
    const mockFetch = vi.fn(async () => fakeOk({ success: true, data: {} }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    await request({
      config,
      method: "POST",
      path: "/x",
      body: { hello: "world" },
    });
    const init = mockFetch.mock.calls[0][1] as RequestInit;
    expect(init.body).toBe('{"hello":"world"}');
  });

  it("appends query string from `query`", async () => {
    const mockFetch = vi.fn(async () => fakeOk({ success: true, data: {} }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    await request({
      config,
      method: "GET",
      path: "/list",
      query: { limit: 10, scope: "shared" },
    });
    const url = mockFetch.mock.calls[0][0];
    expect(String(url)).toContain("/list?limit=10&scope=shared");
  });

  it("unwraps the kernel envelope on 2xx (success:true + data)", async () => {
    const mockFetch = vi.fn(async () => fakeOk({ success: true, data: { a: 1 } }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    const out = await request<{ a: number }>({
      config,
      method: "GET",
      path: "/x",
    });
    expect(out).toEqual({ a: 1 });
  });

  it("passes through bare JSON on 2xx when no envelope is present (fallback)", async () => {
    const mockFetch = vi.fn(async () => fakeOk({ bare: "value" }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    const out = await request<{ bare: string }>({
      config,
      method: "GET",
      path: "/x",
    });
    expect(out).toEqual({ bare: "value" });
  });

  it("falls through when envelope has success:true but no data key (coverage)", async () => {
    // Pins the `"data" in parsed` guard: {success: true} alone is NOT
    // an unwrappable envelope — the caller gets the raw object.
    const mockFetch = vi.fn(async () => fakeOk({ success: true }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    const out = await request<{ success: boolean }>({
      config,
      method: "GET",
      path: "/x",
    });
    expect(out).toEqual({ success: true });
  });

  it("unwraps envelope even when data is null (coverage)", async () => {
    // Pins the unwrap path when `data` is explicitly `null` — distinct
    // from the 204/empty-body fallback where `parsed` itself is null.
    const mockFetch = vi.fn(async () => fakeOk({ success: true, data: null }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    const out = await request<null>({
      config,
      method: "GET",
      path: "/x",
    });
    expect(out).toBeNull();
  });

  it("returns null on a successful empty body (coverage)", async () => {
    // P3: 2xx responses now require Content-Type: application/json
    // (or 204 No Content / 304 Not Modified — neither has a body).
    // Set the header explicitly here to keep this test focused on the
    // empty-body parse path (parsed:null branch in readBody).
    const mockFetch = vi.fn(
      async () =>
        new Response("", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    const out = await request<unknown>({ config, method: "GET", path: "/x" });
    expect(out).toBeNull();
  });

  it("returns null on a 204 No Content response (coverage)", async () => {
    const mockFetch = vi.fn(async () => new Response(null, { status: 204 }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    const out = await request<unknown>({
      config,
      method: "DELETE",
      path: "/x",
    });
    expect(out).toBeNull();
  });

  it("does not arm a timeout when timeoutMs is 0 (coverage)", async () => {
    // With timeoutMs: 0, the `> 0` branch is false → setTimeout never called.
    // The fetch implementation here resolves on its own; if a timeout were
    // armed at 0ms it would fire immediately and abort the request.
    let resolveFetch!: (value: Response) => void;
    const fetchPromise = new Promise<Response>((r) => (resolveFetch = r));
    const mockFetch = vi.fn(async () => fetchPromise);
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
      timeoutMs: 0,
    });
    const requestPromise = request<unknown>({
      config,
      method: "GET",
      path: "/x",
    });
    // Yield twice — if a timeout were armed at 0ms it'd fire on the first
    // microtask drain. Resolve only after that to confirm it didn't fire.
    await Promise.resolve();
    await Promise.resolve();
    resolveFetch(
      new Response(JSON.stringify({ success: true, data: { ok: true } }), {
        status: 200,
        // P3: 2xx success requires Content-Type: application/json.
        headers: { "Content-Type": "application/json" },
      }),
    );
    await expect(requestPromise).resolves.toEqual({ ok: true });
  });
});

// ─── P3: sync content-type guard on 2xx responses ──────────────────────────
//
// P3 hardening: the transport's sync `request<T>` now checks the response
// Content-Type header against `expectedContentType` (default
// "application/json") on every 2xx response, mirroring the streaming
// guard. Rejects with `AttestryAPIError` carrying the response status
// (typically 200) and a descriptive message. Skipped for 204/304 (no
// body to validate). The MIME-type extraction is parameter-tolerant
// (`; charset=utf-8` accepted) and defends against superset / parameter-
// injection / structured-suffix attacks via exact MIME match.

describe("request — P3 sync content-type guard (2xx responses)", () => {
  function jsonOkFetch(body: string, contentType: string): FetchLike {
    return async () =>
      new Response(body, {
        status: 200,
        headers: { "Content-Type": contentType },
      });
  }

  it("ACCEPTS bare application/json", async () => {
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: jsonOkFetch(
        JSON.stringify({ success: true, data: { ok: true } }),
        "application/json",
      ),
    });
    const out = await request<unknown>({ config, method: "GET", path: "/x" });
    expect(out).toEqual({ ok: true });
  });

  it("ACCEPTS application/json; charset=utf-8 (parameter-tolerant)", async () => {
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: jsonOkFetch(
        JSON.stringify({ success: true, data: { ok: true } }),
        "application/json; charset=utf-8",
      ),
    });
    const out = await request<unknown>({ config, method: "GET", path: "/x" });
    expect(out).toEqual({ ok: true });
  });

  it("ACCEPTS Application/JSON (case-insensitive)", async () => {
    // RFC 7231 §3.1.1.1 — media types are case-insensitive.
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: jsonOkFetch(
        JSON.stringify({ success: true, data: { ok: true } }),
        "Application/JSON",
      ),
    });
    const out = await request<unknown>({ config, method: "GET", path: "/x" });
    expect(out).toEqual({ ok: true });
  });

  it("REJECTS text/plain with AttestryAPIError(200, expected application/json)", async () => {
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: jsonOkFetch(
        JSON.stringify({ success: true, data: { ok: true } }),
        "text/plain",
      ),
    });
    let caught: unknown;
    try {
      await request<unknown>({ config, method: "GET", path: "/x" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    const apiErr = caught as AttestryAPIError;
    expect(apiErr.status).toBe(200);
    expect(apiErr.message).toMatch(/expected application\/json/);
    expect(apiErr.message).toMatch(/got "text\/plain"/);
  });

  it("REJECTS text/html (LB error page wrapped at 200) with AttestryAPIError", async () => {
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: jsonOkFetch(
        "<html><body>Bad Gateway</body></html>",
        "text/html",
      ),
    });
    let caught: unknown;
    try {
      await request<unknown>({ config, method: "GET", path: "/x" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(200);
  });

  it("REJECTS application/x-ndjson (streaming format on a sync endpoint)", async () => {
    // A consumer mistake or kernel regression that emits NDJSON for a
    // sync endpoint should fail-fast. Pin both the MIME-prefix
    // extraction and the exact-match comparison.
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: jsonOkFetch(
        '{"success":true}\n',
        "application/x-ndjson",
      ),
    });
    await expect(
      request<unknown>({ config, method: "GET", path: "/x" }),
    ).rejects.toThrow(/expected application\/json/);
  });

  it("REJECTS structured-suffix attack: application/json+evil", async () => {
    // Hostile-review parity with streamRequest: ensure exact MIME
    // comparison rejects suffix variants. The MIME prefix is
    // "application/json+evil" which !== "application/json".
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: jsonOkFetch(
        JSON.stringify({ success: true, data: {} }),
        "application/json+evil",
      ),
    });
    await expect(
      request<unknown>({ config, method: "GET", path: "/x" }),
    ).rejects.toThrow(/expected application\/json/);
  });

  it("REJECTS parameter-injection attack: text/html; x-real-content=application/json", async () => {
    // Hostile-review parity: parameter values cannot smuggle the
    // expected MIME past the check.
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: jsonOkFetch(
        JSON.stringify({ success: true, data: {} }),
        "text/html; x-real-content=application/json",
      ),
    });
    await expect(
      request<unknown>({ config, method: "GET", path: "/x" }),
    ).rejects.toThrow(/expected application\/json/);
  });

  it("REJECTS missing Content-Type header (defensive)", async () => {
    // The kernel always sets Content-Type, but a hypothetical proxy
    // stripping it should fail-fast (empty content-type !== expected).
    const mockFetch: FetchLike = async () =>
      new Response(JSON.stringify({ success: true, data: {} }), {
        status: 200,
        // No headers set; Response constructor with string body sets
        // `Content-Type: text/plain;charset=UTF-8` by default. Use a
        // raw construction to confirm the empty case still throws.
        headers: {},
      });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch,
    });
    await expect(
      request<unknown>({ config, method: "GET", path: "/x" }),
    ).rejects.toThrow(/expected application\/json/);
  });

  it("SKIPS check on 204 No Content (no body to validate)", async () => {
    // 204 / 304 have no body; readBody short-circuits to parsed:null.
    // The content-type guard must skip these to avoid spurious
    // rejections when the response correctly omits Content-Type.
    const mockFetch: FetchLike = async () =>
      new Response(null, { status: 204 });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch,
    });
    const out = await request<unknown>({
      config,
      method: "DELETE",
      path: "/x",
    });
    expect(out).toBeNull();
  });

  it("304 Not Modified is handled by the error path (NOT the content-type guard) — pre-P3 behavior unchanged", async () => {
    // `response.ok` is true only for status 200-299. 304 is in the
    // redirection class and goes to the existing error path,
    // surfacing as AttestryAPIError(304). The P3 content-type guard
    // is only reachable via 2xx and skips 204 (the only bodyless 2xx
    // status). Pinned to make this asymmetry explicit — a future
    // refactor that adds 304 to the success path would surface here.
    const mockFetch: FetchLike = async () =>
      new Response(null, { status: 304 });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch,
    });
    let caught: unknown;
    try {
      await request<unknown>({ config, method: "GET", path: "/x" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(304);
  });

  it("HONORS custom expectedContentType (forward-compat: future CSV/etc. endpoints)", async () => {
    // Pin the parameter is honored — a future SDK addition that wraps
    // a sync CSV endpoint could pass `expectedContentType: "text/csv"`
    // and have the same guard apply. Default is application/json;
    // explicit override accepted.
    const mockFetch: FetchLike = async () =>
      new Response("col1,col2\nval1,val2", {
        status: 200,
        headers: { "Content-Type": "text/csv" },
      });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch,
    });
    const out = await request<unknown>({
      config,
      method: "GET",
      path: "/x",
      expectedContentType: "text/csv",
    });
    // text/csv body isn't JSON, so JSON.parse fails → readBody returns
    // parsed:null. The success path returns null. The guard accepts
    // text/csv as the expected MIME.
    expect(out).toBeNull();
  });

  it("HOSTILE H1: leading/trailing whitespace in Content-Type accepted (RFC 7231 OWS tolerance)", async () => {
    // The MIME extraction calls .trim() on the type/subtype before
    // comparison. Accepts "  application/json  " and "  application/
    // json;charset=utf-8  ". RFC 7231 §3.2 — OWS allowed around field
    // values.
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: async () =>
        new Response(JSON.stringify({ success: true, data: { ok: true } }), {
          status: 200,
          headers: { "Content-Type": "  application/json  " },
        }),
    });
    const out = await request<unknown>({ config, method: "GET", path: "/x" });
    expect(out).toEqual({ ok: true });
  });

  it("HOSTILE H2: trailing semicolon with no parameters accepted (`application/json;`)", async () => {
    // Defensive: a misbehaving server might emit "application/json;"
    // with a trailing semicolon and no parameter body. Split-on-`;`
    // takes the prefix "application/json" → trim → match. Pinned.
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: async () =>
        new Response(JSON.stringify({ success: true, data: { ok: true } }), {
          status: 200,
          headers: { "Content-Type": "application/json;" },
        }),
    });
    const out = await request<unknown>({ config, method: "GET", path: "/x" });
    expect(out).toEqual({ ok: true });
  });

  it("HOSTILE H3: spec violation — internal whitespace in MIME (`application /json`) is rejected", async () => {
    // The MIME extraction trims leading/trailing OWS but does NOT
    // strip whitespace inside the MIME (e.g., between type and `/`).
    // RFC 7231 §3.1.1.1 forbids this; reject. Pin documents the
    // strictness.
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: async () =>
        new Response(JSON.stringify({ success: true, data: { ok: true } }), {
          status: 200,
          headers: { "Content-Type": "application /json" },
        }),
    });
    await expect(
      request<unknown>({ config, method: "GET", path: "/x" }),
    ).rejects.toThrow(/expected application\/json/);
  });

  it("does NOT apply guard on error responses (4xx/5xx fall through to existing error-body parser)", async () => {
    // Pin the asymmetry: the content-type guard fires only on 2xx.
    // For 4xx/5xx, the existing error-body parser (hostile-review H1)
    // handles non-JSON error bodies (e.g., HTML LB errors) by
    // surfacing them as `AttestryAPIError.details`. P3 must not
    // change that behavior.
    const html = "<html><body>500 Internal</body></html>";
    const mockFetch: FetchLike = async () =>
      new Response(html, {
        status: 500,
        headers: { "Content-Type": "text/html" },
      });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch,
    });
    let caught: unknown;
    try {
      await request<unknown>({ config, method: "GET", path: "/x" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    const apiErr = caught as AttestryAPIError;
    expect(apiErr.status).toBe(500);
    expect(apiErr.details).toBe(html); // raw HTML preserved as details
    // NOT the P3 "expected application/json" message — error-path
    // takes over.
    expect(apiErr.message).toBe("Attestry API returned 500");
  });
});

describe("describeFetchFailure — non-Error fetch reject (coverage)", () => {
  it("surfaces 'network error' (no descriptor) when fetch throws a non-Error value", async () => {
    // Defensive branch: real fetch implementations always reject with
    // an Error subclass (TypeError, AbortError, DOMException), so the
    // String(err) / fall-through to bare "network error" path is
    // unreachable via the platform's `fetch`. A custom FetchLike that
    // throws a primitive (e.g. a synthetic test mock) would hit it.
    // Pin so refactors don't drop the fallback silently.
    const mockFetch: FetchLike = async () => {
      // eslint-disable-next-line @typescript-eslint/no-throw-literal
      throw "string-rejection-not-an-error";
    };
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    let caught: unknown = null;
    try {
      await request({ config, method: "GET", path: "/x" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    // Falls through to the bare "network error" message — the err
    // wasn't an Error instance, so describeFetchFailure returns
    // "network error" without an err.message tail. The original
    // string is preserved as `cause` for debugging.
    expect((caught as AttestryError).message).toBe("network error");
    expect((caught as AttestryError).cause).toBe(
      "string-rejection-not-an-error",
    );
  });
});

describe("request — error path", () => {
  it("throws AttestryAPIError with the parsed body and status on 4xx", async () => {
    const mockFetch = vi.fn(async () =>
      fakeErr({ error: "bad input" }, 400),
    );
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    let caught: unknown;
    try {
      await request({ config, method: "GET", path: "/x" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    const apiErr = caught as AttestryAPIError;
    expect(apiErr.status).toBe(400);
    expect(apiErr.message).toBe("bad input");
    expect(apiErr.details).toEqual({ error: "bad input" });
  });

  it("falls back to a generic message when body has no error/message", async () => {
    const mockFetch = vi.fn(async () => fakeErr({ unrelated: 1 }, 500));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    try {
      await request({ config, method: "GET", path: "/x" });
    } catch (err) {
      expect((err as AttestryAPIError).message).toBe(
        "Attestry API returned 500",
      );
      expect((err as AttestryAPIError).status).toBe(500);
    }
  });

  it("wraps fetch failures as AttestryError with cause", async () => {
    const cause = new Error("ECONNREFUSED");
    const mockFetch = vi.fn(async () => {
      throw cause;
    });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    try {
      await request({ config, method: "GET", path: "/x" });
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
      expect(err).not.toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryError).message).toContain("network error");
      expect((err as Error & { cause?: unknown }).cause).toBe(cause);
    }
  });

  it("aborts and surfaces 'request timed out' when timeoutMs elapses", async () => {
    const mockFetch: FetchLike = (_url, init) =>
      new Promise((_, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(init.signal!.reason ?? new Error("aborted")),
        );
      });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch,
      timeoutMs: 5,
    });
    let caught: unknown;
    try {
      await request({ config, method: "GET", path: "/x" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toBe("request timed out");
  });

  it("aborts when caller-provided signal fires", async () => {
    const mockFetch: FetchLike = (_url, init) =>
      new Promise((_, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new Error("aborted")),
        );
      });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch,
      timeoutMs: 30_000,
    });
    const ac = new AbortController();
    const p = request({
      config,
      method: "GET",
      path: "/x",
      options: { signal: ac.signal },
    });
    ac.abort();
    let caught: unknown;
    try {
      await p;
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toBe("request aborted by caller");
  });

  it("surfaces non-JSON error body as `details` (Hostile-review H1)", async () => {
    const html = "<html><body>502 Bad Gateway</body></html>";
    const mockFetch = vi.fn(
      async () =>
        new Response(html, {
          status: 502,
          headers: { "Content-Type": "text/html" },
        }),
    );
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    let caught: unknown;
    try {
      await request({ config, method: "GET", path: "/x" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    const apiErr = caught as AttestryAPIError;
    expect(apiErr.status).toBe(502);
    // Without the fix, details was `null`; now consumers can debug.
    expect(apiErr.details).toBe(html);
    // extractMessage on a string returns null → generic message.
    expect(apiErr.message).toBe("Attestry API returned 502");
  });

  it("falls back to `details: null` when the error body is empty", async () => {
    const mockFetch = vi.fn(async () => new Response("", { status: 500 }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    try {
      await request({ config, method: "GET", path: "/x" });
    } catch (err) {
      const apiErr = err as AttestryAPIError;
      expect(apiErr.details).toBeNull();
      expect(apiErr.message).toBe("Attestry API returned 500");
    }
  });

  it("throws AttestryError (NOT 'network error') when body fails to serialize (Hostile-review L2)", async () => {
    // Circular reference defeats JSON.stringify. Without the fix, this
    // would surface as "network error: Converting circular structure to
    // JSON" — misleading because the call never reached the network.
    const circular: { self?: unknown } = {};
    circular.self = circular;
    const mockFetch = vi.fn(async () => new Response("{}", { status: 200 }));
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    let caught: unknown;
    try {
      await request({ config, method: "POST", path: "/x", body: circular });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(/^invalid request body:/);
    expect(mockFetch).not.toHaveBeenCalled(); // request never reached fetch
  });

  it("rejects immediately when caller signal is already aborted", async () => {
    const mockFetch: FetchLike = (_url, init) =>
      new Promise((_, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(new Error("aborted")),
        );
      });
    const config = resolveClientConfig({
      apiKey: "k",
      fetch: mockFetch,
    });
    const ac = new AbortController();
    ac.abort();
    let caught: unknown;
    try {
      await request({
        config,
        method: "GET",
        path: "/x",
        options: { signal: ac.signal },
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toBe("request aborted by caller");
  });
});

// ─── streamRequest content-type generalization (build round D6) ────────────
//
// Pre-export, `streamRequestOnce` hardcoded `Accept: text/event-stream` AND
// the response content-type guard. The new `expectedContentType` parameter
// drives BOTH — single source of truth. SSE callers default to
// `text/event-stream` (backward-compat for decisions.stream / chat.stream
// — though chat.stream uses `_request` not `_streamRequest` today). NDJSON
// callers (decisions.export) pass `application/x-ndjson`.

describe("streamRequest — content-type generalization (build round D6)", () => {
  function makeFetchReturning(
    response: Response,
  ): { fetchImpl: FetchLike; calls: { headers: Headers; url: string }[] } {
    const calls: { headers: Headers; url: string }[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        headers: init?.headers as Headers,
      });
      return response;
    };
    return { fetchImpl, calls };
  }

  function ndjsonBody(payload = `{"a":1}\n`): Response {
    const encoder = new TextEncoder();
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(payload));
          controller.close();
        },
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/x-ndjson" },
      },
    );
  }

  function sseBody(payload = "id: 1\ndata: x\n\n"): Response {
    const encoder = new TextEncoder();
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(encoder.encode(payload));
          controller.close();
        },
      }),
      {
        status: 200,
        headers: { "Content-Type": "text/event-stream" },
      },
    );
  }

  it("defaults Accept to text/event-stream when expectedContentType is not provided (SSE backward-compat)", async () => {
    const { fetchImpl, calls } = makeFetchReturning(sseBody());
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    await streamRequest({ config, path: "/sse" });
    expect(calls[0].headers.get("Accept")).toBe("text/event-stream");
  });

  it("uses expectedContentType as the Accept header value when provided", async () => {
    const { fetchImpl, calls } = makeFetchReturning(ndjsonBody());
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    await streamRequest({
      config,
      path: "/x/export",
      expectedContentType: "application/x-ndjson",
    });
    expect(calls[0].headers.get("Accept")).toBe("application/x-ndjson");
  });

  it("accepts application/x-ndjson at 200 when expectedContentType matches", async () => {
    const { fetchImpl } = makeFetchReturning(ndjsonBody());
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    const res = await streamRequest({
      config,
      path: "/x/export",
      expectedContentType: "application/x-ndjson",
    });
    expect(res.status).toBe(200);
  });

  it("rejects text/event-stream at 200 when expectedContentType is application/x-ndjson (cross-content-type)", async () => {
    // NDJSON caller hitting an SSE-typed response is a misconfiguration
    // — fail-fast with a clear message.
    const { fetchImpl } = makeFetchReturning(sseBody());
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    let caught: unknown = null;
    try {
      await streamRequest({
        config,
        path: "/x/export",
        expectedContentType: "application/x-ndjson",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).message).toContain(
      "expected application/x-ndjson",
    );
  });

  it("rejects application/x-ndjson at 200 when expectedContentType defaults to text/event-stream (cross-content-type)", async () => {
    // SSE caller hitting an NDJSON response — symmetric protection.
    // Pin the existing decisions.stream behavior when no
    // expectedContentType is passed.
    const { fetchImpl } = makeFetchReturning(ndjsonBody());
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    let caught: unknown = null;
    try {
      await streamRequest({ config, path: "/sse" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).message).toContain(
      "expected text/event-stream",
    );
  });

  it("accepts content-type with parameters (e.g. `; charset=utf-8`)", async () => {
    // Production proxies often append `; charset=utf-8` and similar
    // parameters. After the hostile-review fix to exact-MIME match,
    // parameters are still accepted (the parameter list after `;` is
    // stripped before comparison) — this preserves backward-compat
    // with the previous substring behavior for the legitimate case.
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`{"a":1}\n`));
        controller.close();
      },
    });
    const response = new Response(body, {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson; charset=utf-8" },
    });
    const { fetchImpl } = makeFetchReturning(response);
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    const res = await streamRequest({
      config,
      path: "/x/export",
      expectedContentType: "application/x-ndjson",
    });
    expect(res.status).toBe(200);
  });

  it("rejects a superset content-type (`application/x-ndjson-evil`) — hostile-fix: exact MIME match", async () => {
    // Hostile-review finding: the previous substring `includes()`
    // match passed `application/x-ndjson-evil` (the expected string
    // appears as a prefix of the malicious one). After the
    // exact-match fix, only the bare `application/x-ndjson` (with or
    // without `; <params>`) is accepted. A malicious / misconfigured
    // server cannot bypass the guard by appending a suffix.
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`{"a":1}\n`));
        controller.close();
      },
    });
    const response = new Response(body, {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson-evil" },
    });
    const { fetchImpl } = makeFetchReturning(response);
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    let caught: unknown = null;
    try {
      await streamRequest({
        config,
        path: "/x/export",
        expectedContentType: "application/x-ndjson",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).message).toContain(
      "expected application/x-ndjson",
    );
    expect((caught as AttestryAPIError).message).toContain(
      "application/x-ndjson-evil",
    );
  });

  it("rejects parameter-injection (`text/html; x-real-content=application/x-ndjson`) — hostile-fix", async () => {
    // Hostile-review finding: the previous substring `includes()`
    // match was bypassed by stuffing the expected MIME type inside a
    // parameter of an unrelated type. After the fix, we strip
    // parameters and compare type/subtype only.
    const response = new Response("<html>error page</html>", {
      status: 200,
      headers: {
        "Content-Type": "text/html; x-real-content=application/x-ndjson",
      },
    });
    const { fetchImpl } = makeFetchReturning(response);
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    let caught: unknown = null;
    try {
      await streamRequest({
        config,
        path: "/x/export",
        expectedContentType: "application/x-ndjson",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).message).toContain(
      "expected application/x-ndjson",
    );
  });

  it("accepts content-type with leading whitespace before the type (`  application/x-ndjson`)", async () => {
    // Trim handling: a producer that emits `Content-Type:   application/
    // x-ndjson` (extra OWS before the type) should still pass after
    // trim().toLowerCase().
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(`{"a":1}\n`));
        controller.close();
      },
    });
    const response = new Response(body, {
      status: 200,
      headers: { "Content-Type": "  application/x-ndjson  " },
    });
    const { fetchImpl } = makeFetchReturning(response);
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    const res = await streamRequest({
      config,
      path: "/x/export",
      expectedContentType: "application/x-ndjson",
    });
    expect(res.status).toBe(200);
  });

  it("rejects structured-suffix injection (`application/foo+x-ndjson`) — hostile-fix: exact match", async () => {
    // Hostile-review finding: a malicious suffix `+x-ndjson` would
    // pass the previous substring match. After exact-match, only
    // `application/x-ndjson` (the bare type/subtype) is accepted.
    const response = new Response("not-ndjson", {
      status: 200,
      headers: { "Content-Type": "application/foo+x-ndjson" },
    });
    const { fetchImpl } = makeFetchReturning(response);
    const config = resolveClientConfig({ apiKey: "k", fetch: fetchImpl });
    let caught: unknown = null;
    try {
      await streamRequest({
        config,
        path: "/x/export",
        expectedContentType: "application/x-ndjson",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
  });
});
