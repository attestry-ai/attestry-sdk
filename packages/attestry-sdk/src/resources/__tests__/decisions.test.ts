import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type { FetchLike } from "../../types.js";

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

function makeMockedClient(
  responses: Array<{ status?: number; body?: unknown; bodyText?: string }>,
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
    return new Response(body, {
      status,
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

const MOCK_RECORD = {
  id: "11111111-1111-1111-1111-111111111111",
  orgId: "22222222-2222-2222-2222-222222222222",
  systemId: "33333333-3333-3333-3333-333333333333",
  manifestVersionId: "44444444-4444-4444-4444-444444444444",
  attestationId: null,
  sequenceNumber: 1,
  inputDigest:
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  outputDigest: null,
  frameworkClaims: [],
  toolInvocations: [],
  delegationChain: [],
  humanOversightState: null,
  policyOutcome: null,
  prevRecordHash: null,
  recordHash:
    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  clientSignature: null,
  clientKeyId: null,
  idempotencyKey: null,
  zkProof: null,
  tombstoned: false,
  tombstonedAt: null,
  tombstonedReason: null,
  createdAt: "2026-05-05T00:00:00.000Z",
};

describe("decisions.retrieve", () => {
  it("GETs /api/v1/decisions/{id} with no body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RECORD } },
    ]);
    const out = await client.decisions.retrieve(MOCK_RECORD.id);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/decisions/${MOCK_RECORD.id}`,
    );
    // GET → no body. The transport must NOT send Content-Type either.
    expect(calls[0].body).toBeUndefined();
    expect(calls[0].headers.get("Content-Type")).toBeNull();
    // Transport unwraps the {success:true, data} envelope — bare record.
    expect(out).toEqual(MOCK_RECORD);
  });

  it("URL-encodes ids that contain special characters (path-injection guard)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RECORD } },
    ]);
    // Adversarial id with slash, hash, and query separators. None of these
    // are valid UUIDs (server will 400) but the SDK must ENCODE them before
    // sending so the path is unambiguous and the request lands at
    // /api/v1/decisions/<encoded> rather than splattering across the URL.
    await client.decisions.retrieve("a/b#c?d=e");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/a%2Fb%23c%3Fd%3De",
    );
  });

  it("forwards the x-api-key + Accept headers (transport-level smoke)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RECORD } },
    ]);
    await client.decisions.retrieve(MOCK_RECORD.id);
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
  });

  it("throws TypeError for empty id (does not issue a request)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.retrieve("")).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError (NOT URIError) for ids containing lone UTF-16 surrogates", async () => {
    // encodeURIComponent throws URIError on malformed UTF-16 (lone
    // surrogate halves). Without the resource's try/catch, that error
    // class would leak to consumers — inconsistent with the TypeError
    // they already get for empty / non-string ids. Hostile L1 pin.
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.retrieve("\uD800")).toThrowError(TypeError);
    try {
      client.decisions.retrieve("prefix\uD800suffix");
    } catch (err) {
      expect(err).toBeInstanceOf(TypeError);
      expect((err as TypeError).message).toContain(
        "decisions.retrieve: `id` contains invalid UTF-16 sequences",
      );
      // Original URIError is preserved as the cause.
      expect((err as Error).cause).toBeDefined();
    }
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string id (defensive against runtime cast)", async () => {
    // Static typing prevents this; runtime guard catches consumers using
    // `as unknown as string` casts (or unsanitized JSON input). Pinned so
    // the typeof check isn't quietly removed.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.decisions.retrieve(null as unknown as string),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.retrieve(42 as unknown as string),
    ).toThrowError(TypeError);
    expect(() =>
      client.decisions.retrieve(undefined as unknown as string),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("rejects id='..' / '.' / NUL-byte strings (path-traversal under fetch URL normalization)", async () => {
    // Hostile-review F1 (cross-resource fix): encodeURIComponent does
    // NOT encode `.` or `..`, and WHATWG-spec fetch normalizes URL
    // paths. `retrieve("..")` would produce `/api/v1/decisions/..`,
    // which the URL parser collapses to `/api/v1/`'s parent — silently
    // redirecting to a different endpoint. The kernel returns whatever
    // is at that path, the SDK consumer's `result.id` is `undefined`,
    // and the failure mode is silent. Block exact-match traversal
    // segments at the SDK boundary via the shared `encodePathSegment`
    // helper.
    const { client, calls } = makeMockedClient([]);
    expect(() => client.decisions.retrieve("..")).toThrowError(TypeError);
    expect(() => client.decisions.retrieve(".")).toThrowError(TypeError);
    expect(() => client.decisions.retrieve("foo\0bar")).toThrowError(
      TypeError,
    );
    // Error message names the offending field so consumers can route on it.
    try {
      client.decisions.retrieve("..");
    } catch (err) {
      expect((err as TypeError).message).toContain(
        "decisions.retrieve: `id` contains invalid path-segment characters",
      );
    }
    expect(calls).toHaveLength(0);
  });

  it("does NOT over-block embedded `..` (e.g. 'foo/../bar' is encoded safely as one segment)", async () => {
    // Defensive negative pin: the F1 guard rejects exact `.` / `..`
    // / NUL-byte strings, but embedded path-traversal-looking text
    // is benign because `/` gets encoded as `%2F`, so the URL parser
    // sees a single segment and doesn't normalize. Pin so a future
    // "harden the guard" refactor doesn't accidentally block
    // legitimate (server-rejected) UUID-shaped strings that happen
    // to contain "..".
    const { client, calls } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Invalid decision record id format." },
      },
    ]);
    let caught: unknown;
    try {
      await client.decisions.retrieve("foo/../bar");
    } catch (err) {
      caught = err;
    }
    // Encoded — slash + dots all encoded into one path segment.
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/decisions/foo%2F..%2Fbar",
    );
    // Error is the kernel's 400 (server-side UUID rejection), NOT
    // the SDK-side path-traversal TypeError. Confirms the guard is
    // exact-match only.
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(400);
  });

  it("surfaces a 404 as AttestryAPIError (not-found OR cross-org — deliberate conflation)", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: { success: false, error: "Decision record not found." },
      },
    ]);
    try {
      await client.decisions.retrieve(MOCK_RECORD.id);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(404);
      expect(apiErr.message).toBe("Decision record not found.");
    }
  });

  it("surfaces a 400 (malformed UUID) as AttestryAPIError with the server's message", async () => {
    const { client } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Invalid decision record id format." },
      },
    ]);
    try {
      await client.decisions.retrieve(MOCK_RECORD.id);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(400);
      expect(apiErr.message).toBe("Invalid decision record id format.");
    }
  });

  it("forwards the caller's AbortSignal through RequestOptions", async () => {
    // Use a pre-aborted controller — the transport rejects synchronously
    // BEFORE issuing any fetch call, so the mock never logs a request.
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.decisions.retrieve(MOCK_RECORD.id, { signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted AbortSignal and the request completes normally (coverage)", async () => {
    // The pre-abort case is pinned above; this pins the symmetric
    // happy path where the signal exists, is passed through, but never
    // fires. Closes the resource-level branch where `options.signal`
    // is a live signal that gets attached to the transport's
    // AbortController and then cleanly removed in the finally block.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_RECORD } },
    ]);
    const controller = new AbortController();
    const out = await client.decisions.retrieve(MOCK_RECORD.id, {
      signal: controller.signal,
    });
    expect(out).toEqual(MOCK_RECORD);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    // Signal is still listenable (not consumed by the SDK).
    expect(controller.signal.aborted).toBe(false);
  });

  it("F1 (P2 sweep): throws AttestryError when kernel response is null", async () => {
    // F1 P2 extension: sync GET responses are validated as non-null
    // objects at the SDK boundary. A kernel-side regression that
    // emits `data: null` would let consumers crash on `result.id`
    // with a confusing TypeError. Resource-layer validator catches
    // it and throws a clear AttestryError instead.
    //
    // Hostile-review session-14 H1: pin the error class — NOT just
    // the message. A future regression that swapped `throw new
    // AttestryError(...)` for `throw new TypeError(...)` (or a bare
    // `new Error(...)`) would still satisfy `rejects.toThrow(/regex/)`,
    // silently violating the P2 contract. Consumers branch on
    // `err instanceof AttestryError` to distinguish SDK-layer
    // validation rejections from API errors / native exceptions.
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    let caught: unknown;
    try {
      await client.decisions.retrieve(MOCK_RECORD.id);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    // Strict: NOT the AttestryAPIError subclass. P2 is an SDK-layer
    // shape rejection, NOT a transport-layer status-code error.
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /decisions.retrieve: expected an object response from the kernel \(got null\)/,
    );
  });

  it("F1 (P2 sweep): throws AttestryError when kernel response is an array (not object)", async () => {
    // Hostile-review session-14 H1: pin error class.
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_RECORD] } },
    ]);
    let caught: unknown;
    try {
      await client.decisions.retrieve(MOCK_RECORD.id);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /decisions.retrieve: expected an object response from the kernel \(got array\)/,
    );
  });

  it("F1 (P2 sweep): throws AttestryError when kernel response is a scalar (string)", async () => {
    // Hostile-review session-14 H1: pin error class.
    const { client } = makeMockedClient([
      { body: { success: true, data: "scalar-instead-of-object" } },
    ]);
    let caught: unknown;
    try {
      await client.decisions.retrieve(MOCK_RECORD.id);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /decisions.retrieve: expected an object response from the kernel \(got string\)/,
    );
  });
});
