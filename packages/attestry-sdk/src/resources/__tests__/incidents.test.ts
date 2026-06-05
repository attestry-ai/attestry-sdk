import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import type { FetchLike } from "../../types.js";

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

function makeMockedClient(responses: unknown[]) {
  const calls: MockedRequest[] = [];
  let i = 0;
  const mockFetch: FetchLike = async (url, init) => {
    calls.push({
      url: String(url),
      method: (init?.method as string) ?? "GET",
      headers: init?.headers as Headers,
      body: init?.body as string | undefined,
    });
    const body = responses[i++] ?? {};
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    // Retry tests live in src/__tests__/retry.test.ts. Resource tests
    // disable retry so a 429-mock test doesn't hang on backoff and then
    // accidentally consume the next mock response.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

describe("incidents.create", () => {
  it("POSTs /api/v1/incidents with the input body", async () => {
    const { client, calls } = makeMockedClient([{ success: true, data: { id: "i1" } }]);
    const out = await client.incidents.create({
      incidentType: "prompt_injection",
      severity: "high",
      description: "x",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe("https://test.attestry.local/api/v1/incidents");
    expect(JSON.parse(calls[0].body!)).toEqual({
      incidentType: "prompt_injection",
      severity: "high",
      description: "x",
    });
    expect(out).toEqual({ id: "i1" });
  });
});

describe("incidents.list", () => {
  it("GETs /api/v1/incidents with serialized query params", async () => {
    const { client, calls } = makeMockedClient([
      { success: true, data: { items: [], nextCursor: null } },
    ]);
    await client.incidents.list({
      scope: "mine",
      incidentType: "data_leak",
      limit: 25,
    });
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toContain("scope=mine");
    expect(calls[0].url).toContain("incidentType=data_leak");
    expect(calls[0].url).toContain("limit=25");
    expect(calls[0].body).toBeUndefined();
  });

  it("omits undefined params from the query string", async () => {
    // P2 hardening: the kernel always emits `nextCursor` per the
    // IncidentListResponse contract (string OR null, never missing);
    // mock responses must include it. Without it, the SDK now throws
    // AttestryError per the response-shape validator.
    const { client, calls } = makeMockedClient([
      { success: true, data: { items: [], nextCursor: null } },
    ]);
    await client.incidents.list();
    // Empty input → no query string at all
    expect(calls[0].url).toBe("https://test.attestry.local/api/v1/incidents");
  });

  it("passes through resolved=false (does not treat falsy as undefined)", async () => {
    const { client, calls } = makeMockedClient([
      { success: true, data: { items: [], nextCursor: null } },
    ]);
    await client.incidents.list({ resolved: false });
    expect(calls[0].url).toContain("resolved=false");
  });

  it("P2: throws AttestryError when kernel response is an array (not object)", async () => {
    const { client } = makeMockedClient([{ success: true, data: [] }]);
    await expect(client.incidents.list()).rejects.toThrow(
      /expected an object response from the kernel \(got array\)/,
    );
  });

  it("P2: throws AttestryError when kernel response is null", async () => {
    // P2 hardening: same surface as decisions.list and
    // regulatoryChanges.list. A kernel-side regression to scalar/null
    // surfaces as AttestryError at the SDK boundary.
    const { client } = makeMockedClient([{ success: true, data: null }]);
    await expect(client.incidents.list()).rejects.toThrow(
      /expected an object response from the kernel \(got null\)/,
    );
  });

  it("P2: throws AttestryError when `items` is missing", async () => {
    const { client } = makeMockedClient([
      { success: true, data: { nextCursor: null } },
    ]);
    await expect(client.incidents.list()).rejects.toThrow(
      /missing or invalid `items` array \(got undefined\)/,
    );
  });

  it("P2: throws AttestryError when `nextCursor` is wrong type", async () => {
    const { client } = makeMockedClient([
      { success: true, data: { items: [], nextCursor: 0 } },
    ]);
    await expect(client.incidents.list()).rejects.toThrow(
      /`nextCursor` must be string or null \(got number\)/,
    );
  });

  it("P2: ACCEPTS valid response (empty items + null nextCursor)", async () => {
    const { client } = makeMockedClient([
      { success: true, data: { items: [], nextCursor: null } },
    ]);
    const out = await client.incidents.list();
    expect(out).toEqual({ items: [], nextCursor: null });
  });

  it("P2 forward-compat: extra unknown top-level fields on response pass through", async () => {
    // Forward-compat (mirror of decisions.list pin): validator only
    // checks the documented fields. Future kernel additions like a
    // `total` count are accepted.
    const { client } = makeMockedClient([
      {
        success: true,
        data: { items: [], nextCursor: null, total: 7, scope: "shared" },
      },
    ]);
    const out = await client.incidents.list();
    expect(out.items).toEqual([]);
    expect(out.nextCursor).toBeNull();
    expect((out as unknown as Record<string, unknown>).total).toBe(7);
  });
});

describe("incidents.update", () => {
  it("PATCHes the resource path with the body", async () => {
    const { client, calls } = makeMockedClient([{ success: true, data: { id: "abc" } }]);
    await client.incidents.update("abc", { resolved: true });
    expect(calls[0].method).toBe("PATCH");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/incidents/abc",
    );
    expect(JSON.parse(calls[0].body!)).toEqual({ resolved: true });
  });

  it("URL-encodes ids that contain special characters", async () => {
    const { client, calls } = makeMockedClient([{ success: true, data: {} }]);
    await client.incidents.update("a/b#c", { optInShare: true });
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/incidents/a%2Fb%23c",
    );
  });

  it("throws TypeError for empty id (does not issue a request)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.incidents.update("", { resolved: true })).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError (NOT URIError) for ids containing lone UTF-16 surrogates", async () => {
    // Symmetric carry-forward from decisions hostile L1: encodeURIComponent
    // throws URIError on malformed UTF-16. The resource catches and
    // rethrows as TypeError so consumers' id-validation handling is
    // uniform across resources.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.incidents.update("\uD800", { resolved: true }),
    ).toThrowError(TypeError);
    try {
      client.incidents.update("prefix\uD800suffix", { resolved: true });
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toContain(
        "incidents.update: `id` contains invalid UTF-16 sequences",
      );
      expect((err as Error).cause).toBeDefined();
    }
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string id (defensive against runtime cast — coverage)", async () => {
    // Static type rejects this; runtime check catches it when callers
    // bypass typing via `as unknown as string`. Pinning so the typeof
    // guard isn't quietly removed in a future refactor.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.incidents.update(null as unknown as string, { resolved: true }),
    ).toThrowError(TypeError);
    expect(() =>
      client.incidents.update(42 as unknown as string, { resolved: true }),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });
});

describe("incidents.search", () => {
  it("POSTs /api/ai/incidents/search with the body", async () => {
    const { client, calls } = makeMockedClient([
      { success: true, data: { clusters: [], count: 0, truncated: false } },
    ]);
    const out = await client.incidents.search({
      query: "leak",
      limit: 10,
    });
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/ai/incidents/search",
    );
    expect(JSON.parse(calls[0].body!)).toEqual({
      query: "leak",
      limit: 10,
    });
    expect(out).toEqual({ clusters: [], count: 0, truncated: false });
  });
});

// ─── lone-surrogate URIError guard (cross-phase follow-up) ────────────────
//
// Pinned alongside decisions.list / decisions.stream / decisions.export
// guards (commits 0428777, 85064c0). Without `assertEncodableIncidentQueryString`
// in `incidents.list()`, encodeQuery → encodeURIComponent leaks raw
// URIError for any malformed-UTF-16 string filter (lone surrogates).
// Inconsistent with `incidents.update` (already guards path-segment).
// All 7 string filter fields are hardened.

describe("incidents.list — lone-surrogate URIError guard (cross-phase fix)", () => {
  const LONE_HIGH = "\uD800";
  const LONE_LOW = "\uDFFF";
  const VALID_EMOJI = "✓";

  function makeNoFetchClient() {
    return new AttestryClient({
      apiKey: "k",
      baseUrl: "https://test.attestry.local",
      fetch: (() => {
        throw new Error("fetch should not be called");
      }) as unknown as FetchLike,
    });
  }

  const FIELDS = [
    "scope",
    "incidentType",
    "severity",
    "framework",
    "from",
    "to",
    "cursor",
  ] as const;

  for (const field of FIELDS) {
    it(`throws TypeError for lone surrogate in \`${field}\` — does NOT issue a request`, () => {
      const client = makeNoFetchClient();
      const input = { [field]: LONE_HIGH } as Parameters<
        typeof client.incidents.list
      >[0];
      let caught: unknown = null;
      try {
        void client.incidents.list(input);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(TypeError);
      expect((caught as TypeError).message).toContain(
        `incidents.list: \`${field}\``,
      );
      expect((caught as TypeError).message).toContain("invalid UTF-16");
      expect((caught as TypeError).cause).toBeInstanceOf(Error);
    });
  }

  it("throws for a lone LOW surrogate as well as HIGH", () => {
    const client = makeNoFetchClient();
    expect(() =>
      client.incidents.list({ scope: LONE_LOW }),
    ).toThrowError(TypeError);
  });

  it("ACCEPTS a properly-paired surrogate / valid emoji (positive control)", async () => {
    const { client } = makeMockedClient([
      { success: true, data: { items: [], nextCursor: null } },
    ]);
    await expect(
      client.incidents.list({ framework: VALID_EMOJI }),
    ).resolves.toBeDefined();
  });
});
