import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type { AnnexIvGenerateResult } from "../annex-iv.js";
import type { FetchLike } from "../../types.js";

// ─── annexIv.generate — POST + EMPTY body, JSON envelope ────────────────────
//
// Wire shape (from src/app/api/v1/technical-files/[id]/annex-iv/route.ts):
//   POST /api/v1/technical-files/{id}/annex-iv
//   Content-Type: application/json
//   Body: {} (the route is z.object({}).strict() — ANY field 422s)
//   → 201 {success:true, data:{technicalFileId, pdfByteSha256, signingKeyId,
//          statusListRef, statusListIndex, sidecarJws, pdfUrl, bindUrl}}
//
// The SDK sends an EMPTY body and pre-validates the UUID synchronously.

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
    // Disable retry so a 429 mock doesn't hang on backoff.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const VALID_UUID = "11111111-1111-1111-1111-111111111111";

const SAMPLE_GENERATE: AnnexIvGenerateResult = {
  technicalFileId: VALID_UUID,
  pdfByteSha256: `sha256:${"a".repeat(64)}`,
  signingKeyId: "key-2026-05",
  statusListRef: "https://regseal.ai/.well-known/status-list",
  statusListIndex: 7,
  sidecarJws: "eyJ.eyJ.sig",
  pdfUrl: `/api/v1/technical-files/${VALID_UUID}/annex-iv/pdf`,
  bindUrl: `/api/v1/technical-files/${VALID_UUID}/annex-iv/bind`,
};

describe("annexIv.generate — happy path", () => {
  it("POSTs the correct path with an EMPTY body, no query string", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: SAMPLE_GENERATE } },
    ]);
    const res = await client.annexIv.generate({ technicalFileId: VALID_UUID });

    expect(res).toEqual(SAMPLE_GENERATE);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const u = new URL(calls[0].url);
    expect(u.pathname).toBe(`/api/v1/technical-files/${VALID_UUID}/annex-iv`);
    expect(u.search).toBe("");
    // The body is the empty object — NO fields (the route is strict-empty).
    expect(calls[0].body).toBe("{}");
    expect(JSON.parse(calls[0].body as string)).toEqual({});
  });

  it("sets x-api-key, Accept, and Content-Type headers", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: SAMPLE_GENERATE } },
    ]);
    await client.annexIv.generate({ technicalFileId: VALID_UUID });

    const h = calls[0].headers;
    expect(h.get("x-api-key")).toBe("k");
    expect(h.get("accept")).toBe("application/json");
    expect(h.get("content-type")).toBe("application/json");
  });

  it("auto-unwraps the {success,data} envelope — resolved keys are the 8-field set, NOT [success,data]", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: SAMPLE_GENERATE } },
    ]);
    const res = await client.annexIv.generate({ technicalFileId: VALID_UUID });
    expect(Object.keys(res).sort()).toEqual(
      [
        "bindUrl",
        "pdfByteSha256",
        "pdfUrl",
        "sidecarJws",
        "signingKeyId",
        "statusListIndex",
        "statusListRef",
        "technicalFileId",
      ].sort(),
    );
    expect(Object.keys(res)).not.toContain("success");
    expect(Object.keys(res)).not.toContain("data");
  });
});

describe("annexIv.generate — input pre-validation (synchronous TypeError, NO request)", () => {
  it("throws TypeError for null input — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([{ status: 201 }]);
    expect(() => client.annexIv.generate(null as never)).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input (typeof [] === 'object')", () => {
    const { client, calls } = makeMockedClient([{ status: 201 }]);
    expect(() => client.annexIv.generate([] as never)).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty object — technicalFileId is required", () => {
    const { client, calls } = makeMockedClient([{ status: 201 }]);
    expect(() => client.annexIv.generate({} as never)).toThrowError(
      /`technicalFileId` is required/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for a non-UUID technicalFileId", () => {
    const { client, calls } = makeMockedClient([{ status: 201 }]);
    expect(() =>
      client.annexIv.generate({ technicalFileId: "not-a-uuid" }),
    ).toThrowError(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("converts a throwing getter into a TypeError (safe-input-read contract)", () => {
    const { client, calls } = makeMockedClient([{ status: 201 }]);
    const hostile = {
      get technicalFileId(): string {
        throw new Error("boom");
      },
    };
    expect(() => client.annexIv.generate(hostile as never)).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });
});

describe("annexIv.generate — typed error branches (AttestryAPIError w/ status + details)", () => {
  it("401 → AttestryAPIError(401) with details", async () => {
    const { client } = makeMockedClient([
      { status: 401, body: { success: false, error: "unauthorized" } },
    ]);
    const err = await client.annexIv
      .generate({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(401);
    expect(err.details).toEqual({ success: false, error: "unauthorized" });
  });

  it("403 → AttestryAPIError(403)", async () => {
    const { client } = makeMockedClient([
      { status: 403, body: { success: false, error: "forbidden" } },
    ]);
    const err = await client.annexIv
      .generate({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(403);
  });

  it("404 → AttestryAPIError(404)", async () => {
    const { client } = makeMockedClient([
      { status: 404, body: { success: false, error: "not found" } },
    ]);
    const err = await client.annexIv
      .generate({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(404);
  });

  it("422 → AttestryAPIError(422) carrying the annex_iv.* {code} in details", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "cannot bind",
          details: { code: "annex_iv.cryptobind_invalid_input" },
        },
      },
    ]);
    const err = await client.annexIv
      .generate({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(422);
    expect((err.details as { details: { code: string } }).details.code).toBe(
      "annex_iv.cryptobind_invalid_input",
    );
  });

  it("429 (retry disabled) → AttestryAPIError(429), exactly one call", async () => {
    const { client, calls } = makeMockedClient([
      { status: 429, body: { success: false, error: "rate limited" } },
    ]);
    const err = await client.annexIv
      .generate({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(429);
    expect(calls).toHaveLength(1);
  });

  it("500 → AttestryAPIError(500) (scrubbed body)", async () => {
    const { client } = makeMockedClient([
      { status: 500, body: { success: false, error: "internal error" } },
    ]);
    const err = await client.annexIv
      .generate({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(500);
  });

  it("a network failure → AttestryError (not AttestryAPIError)", async () => {
    const mockFetch: FetchLike = async () => {
      throw new TypeError("network down");
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const err = await client.annexIv
      .generate({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryError);
    expect(err).not.toBeInstanceOf(AttestryAPIError);
  });
});

// ─── 0.8.0 P2-10: generate defaults to a 300s timeout ──────────────────────
//
// The route's `maxDuration` is 300s. Under 0.7.0 the client-wide 30s
// default aborted `generate` while the server kept working — and the
// natural retry then failed 422 `annex_iv.already_bound` (metered). 0.8.0
// gives `generate` its own 300_000ms default. Precedence: per-call
// `options.timeoutMs` → explicit client `timeoutMs` → 300_000.

describe("annexIv.generate — per-method default timeout (0.8.0 P2-10)", () => {
  /** A client whose fetch never answers but honours its abort signal. */
  function hungClient(timeoutMs?: number) {
    const mockFetch: FetchLike = (_url, init) =>
      new Promise((_, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal!.reason));
      });
    return new AttestryClient({
      apiKey: "k",
      fetch: mockFetch,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    });
  }

  function track<T>(p: Promise<T>) {
    const state: { settled: boolean; error: unknown } = { settled: false, error: undefined };
    p.then(
      () => {
        state.settled = true;
      },
      (e: unknown) => {
        state.settled = true;
        state.error = e;
      },
    );
    return state;
  }

  it("default client: still running at 30s and 299.9s, times out at 300s", async () => {
    vi.useFakeTimers();
    try {
      const s = track(hungClient().annexIv.generate({ technicalFileId: VALID_UUID }));
      await vi.advanceTimersByTimeAsync(30_001);
      expect(s.settled).toBe(false); // 0.7.0 aborted here
      await vi.advanceTimersByTimeAsync(299_900 - 30_001);
      expect(s.settled).toBe(false);
      await vi.advanceTimersByTimeAsync(100);
      expect(s.settled).toBe(true);
      expect(s.error).toBeInstanceOf(AttestryError);
      expect((s.error as AttestryError).message).toBe("request timed out");
    } finally {
      vi.useRealTimers();
    }
  });

  it("the 300s default is scoped to generate — getBind keeps the 30s default", async () => {
    vi.useFakeTimers();
    try {
      const s = track(hungClient().annexIv.getBind({ technicalFileId: VALID_UUID }));
      await vi.advanceTimersByTimeAsync(30_000);
      expect(s.settled).toBe(true);
      expect((s.error as AttestryError).message).toBe("request timed out");
    } finally {
      vi.useRealTimers();
    }
  });

  it("an explicit client-wide timeoutMs wins over the method default", async () => {
    vi.useFakeTimers();
    try {
      const s = track(hungClient(10_000).annexIv.generate({ technicalFileId: VALID_UUID }));
      await vi.advanceTimersByTimeAsync(9_999);
      expect(s.settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(s.settled).toBe(true);
      expect((s.error as AttestryError).message).toBe("request timed out");
    } finally {
      vi.useRealTimers();
    }
  });

  it("client timeoutMs: 0 still disables the timeout for generate", async () => {
    vi.useFakeTimers();
    try {
      const s = track(hungClient(0).annexIv.generate({ technicalFileId: VALID_UUID }));
      await vi.advanceTimersByTimeAsync(60 * 60_000);
      expect(s.settled).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a per-call options.timeoutMs wins over both (shorter and longer)", async () => {
    vi.useFakeTimers();
    try {
      const shorter = track(
        hungClient().annexIv.generate({ technicalFileId: VALID_UUID }, { timeoutMs: 1_000 }),
      );
      const longer = track(
        hungClient(10_000).annexIv.generate(
          { technicalFileId: VALID_UUID },
          { timeoutMs: 600_000 },
        ),
      );
      await vi.advanceTimersByTimeAsync(1_000);
      expect(shorter.settled).toBe(true);
      expect((shorter.error as AttestryError).message).toBe("request timed out");
      await vi.advanceTimersByTimeAsync(598_999);
      expect(longer.settled).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      expect(longer.settled).toBe(true);
      expect((longer.error as AttestryError).message).toBe("request timed out");
    } finally {
      vi.useRealTimers();
    }
  });
});
