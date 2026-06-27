import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type { AnnexIvBindResult } from "../annex-iv.js";
import type { FetchLike } from "../../types.js";

// ─── annexIv.getBind — GET, 5-field JSON envelope (4 nullable) ──────────────
//
// Wire shape (from …/annex-iv/bind/route.ts:71-79):
//   GET /api/v1/technical-files/{id}/annex-iv/bind
//   → 200 {success:true, data:{sidecarJws, pdfByteSha256, signingKeyId,
//          statusListRef, statusListIndex}}  (4 nullable)
//
// DISTINCT from generate's 8-field shape — no URLs, four nullable.

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
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
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const VALID_UUID = "11111111-1111-1111-1111-111111111111";

const SAMPLE_BIND: AnnexIvBindResult = {
  sidecarJws: "eyJ.eyJ.sig",
  pdfByteSha256: `sha256:${"b".repeat(64)}`,
  signingKeyId: "key-2026-05",
  statusListRef: "https://regseal.ai/.well-known/status-list",
  statusListIndex: 3,
};

describe("annexIv.getBind — happy path", () => {
  it("GETs the bind path, no query string, returns the 5-field shape", async () => {
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: SAMPLE_BIND } },
    ]);
    const res = await client.annexIv.getBind({ technicalFileId: VALID_UUID });

    expect(res).toEqual(SAMPLE_BIND);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    const u = new URL(calls[0].url);
    expect(u.pathname).toBe(
      `/api/v1/technical-files/${VALID_UUID}/annex-iv/bind`,
    );
    expect(u.search).toBe("");
  });

  it("sets x-api-key + Accept: application/json", async () => {
    const { client, calls } = makeMockedClient([
      { status: 200, body: { success: true, data: SAMPLE_BIND } },
    ]);
    await client.annexIv.getBind({ technicalFileId: VALID_UUID });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("accept")).toBe("application/json");
  });

  it("auto-unwraps the envelope — resolved keys are the 5-field set, NOT [success,data]", async () => {
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: SAMPLE_BIND } },
    ]);
    const res = await client.annexIv.getBind({ technicalFileId: VALID_UUID });
    expect(Object.keys(res).sort()).toEqual(
      [
        "pdfByteSha256",
        "sidecarJws",
        "signingKeyId",
        "statusListIndex",
        "statusListRef",
      ].sort(),
    );
    expect(Object.keys(res)).not.toContain("data");
  });

  it("preserves the four nullable fields when null (only sidecarJws is non-null)", async () => {
    const partial: AnnexIvBindResult = {
      sidecarJws: "eyJ.eyJ.sig",
      pdfByteSha256: null,
      signingKeyId: null,
      statusListRef: null,
      statusListIndex: null,
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: partial } },
    ]);
    const res = await client.annexIv.getBind({ technicalFileId: VALID_UUID });
    expect(res.pdfByteSha256).toBeNull();
    expect(res.signingKeyId).toBeNull();
    expect(res.statusListRef).toBeNull();
    expect(res.statusListIndex).toBeNull();
    expect(res.sidecarJws).toBe("eyJ.eyJ.sig");
  });
});

describe("annexIv.getBind — input pre-validation (synchronous TypeError, NO request)", () => {
  it("throws TypeError for null input synchronously", () => {
    const { client, calls } = makeMockedClient([{ status: 200 }]);
    expect(() => client.annexIv.getBind(null as never)).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for a non-UUID technicalFileId synchronously", () => {
    const { client, calls } = makeMockedClient([{ status: 200 }]);
    expect(() =>
      client.annexIv.getBind({ technicalFileId: "xx" }),
    ).toThrowError(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });
});

describe("annexIv.getBind — typed error branches", () => {
  it("401 → AttestryAPIError(401) with details", async () => {
    const { client } = makeMockedClient([
      { status: 401, body: { success: false, error: "unauthorized" } },
    ]);
    const err = await client.annexIv
      .getBind({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(401);
    expect(err.details).toEqual({ success: false, error: "unauthorized" });
  });

  it("404 → AttestryAPIError(404)", async () => {
    const { client } = makeMockedClient([
      { status: 404, body: { success: false, error: "not found" } },
    ]);
    const err = await client.annexIv
      .getBind({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(404);
  });

  it("429 (retry disabled) → AttestryAPIError(429), exactly one call", async () => {
    const { client, calls } = makeMockedClient([
      { status: 429, body: { success: false, error: "rate limited" } },
    ]);
    const err = await client.annexIv
      .getBind({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(429);
    expect(calls).toHaveLength(1);
  });

  it("500 → AttestryAPIError(500)", async () => {
    const { client } = makeMockedClient([
      { status: 500, body: { success: false, error: "internal" } },
    ]);
    const err = await client.annexIv
      .getBind({ technicalFileId: VALID_UUID })
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
      .getBind({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryError);
    expect(err).not.toBeInstanceOf(AttestryAPIError);
  });
});
