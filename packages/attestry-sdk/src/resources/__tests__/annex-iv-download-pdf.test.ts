import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type { FetchLike } from "../../types.js";

// ─── annexIv.downloadPdf — GET, raw application/pdf bytes (NOT an envelope) ──
//
// Wire shape (from …/annex-iv/pdf/route.ts):
//   GET /api/v1/technical-files/{id}/annex-iv/pdf
//   → 200 raw application/pdf bytes (Content-Disposition: attachment; …)
//
// The SDK routes through _streamRequest (returns the un-consumed Response;
// sets Accept: application/pdf; on non-2xx drains + throws AttestryAPIError
// BEFORE the content-type guard; a wrong-content-type 2xx → AttestryAPIError).
// Mirrors `evidencePack.export`'s export arm.

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
}

function makeStreamMockedClient(
  responder: (n: number) => Response,
) {
  const calls: MockedRequest[] = [];
  let i = 0;
  const mockFetch: FetchLike = async (url, init) => {
    calls.push({
      url: String(url),
      method: (init?.method as string) ?? "GET",
      headers: init?.headers as Headers,
    });
    return responder(i++);
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
const PDF_BYTES = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]); // "%PDF-"

function pdfResponse(): Response {
  return new Response(PDF_BYTES, {
    status: 200,
    headers: {
      "content-type": "application/pdf",
      "content-disposition": 'attachment; filename="annex-iv.pdf"',
    },
  });
}

describe("annexIv.downloadPdf — happy path (faithful-courier wrapper)", () => {
  it("GETs the pdf path, sets Accept: application/pdf, returns the wrapper shape", async () => {
    const { client, calls } = makeStreamMockedClient(() => pdfResponse());
    const res = await client.annexIv.downloadPdf({ technicalFileId: VALID_UUID });

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    const u = new URL(calls[0].url);
    expect(u.pathname).toBe(
      `/api/v1/technical-files/${VALID_UUID}/annex-iv/pdf`,
    );
    expect(calls[0].headers.get("accept")).toBe("application/pdf");
    expect(calls[0].headers.get("x-api-key")).toBe("k");

    // The wrapper fields.
    expect(res.contentType).toBe("application/pdf");
    expect(res.contentDisposition).toBe('attachment; filename="annex-iv.pdf"');
    expect(res.response).toBeInstanceOf(Response);
  });

  it("returns the UN-consumed Response — the SDK does not read the body", async () => {
    const { client } = makeStreamMockedClient(() => pdfResponse());
    const res = await client.annexIv.downloadPdf({ technicalFileId: VALID_UUID });
    expect(res.response.bodyUsed).toBe(false);
    // The caller can read the bytes themselves.
    const bytes = new Uint8Array(await res.response.arrayBuffer());
    expect(Array.from(bytes)).toEqual(Array.from(PDF_BYTES));
  });

  it("contentDisposition is null when the header is absent", async () => {
    const { client } = makeStreamMockedClient(
      () =>
        new Response(PDF_BYTES, {
          status: 200,
          headers: { "content-type": "application/pdf" },
        }),
    );
    const res = await client.annexIv.downloadPdf({ technicalFileId: VALID_UUID });
    expect(res.contentDisposition).toBeNull();
  });
});

describe("annexIv.downloadPdf — error branches", () => {
  it("a 2xx with the WRONG content-type → AttestryAPIError(status, null)", async () => {
    const { client } = makeStreamMockedClient(
      () =>
        new Response("<html>not a pdf</html>", {
          status: 200,
          headers: { "content-type": "text/html" },
        }),
    );
    const err = await client.annexIv
      .downloadPdf({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(200);
    expect(err.details).toBeNull();
  });

  it("404 (not generated) → AttestryAPIError(404), body drained as details", async () => {
    const { client } = makeStreamMockedClient(
      () =>
        new Response(JSON.stringify({ success: false, error: "not found" }), {
          status: 404,
          headers: { "content-type": "application/json" },
        }),
    );
    const err = await client.annexIv
      .downloadPdf({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(404);
    expect(err.details).toEqual({ success: false, error: "not found" });
  });

  it("502 (object missing) → AttestryAPIError(502)", async () => {
    const { client } = makeStreamMockedClient(
      () =>
        new Response(JSON.stringify({ success: false, error: "object missing" }), {
          status: 502,
          headers: { "content-type": "application/json" },
        }),
    );
    const err = await client.annexIv
      .downloadPdf({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.status).toBe(502);
  });

  it("500 (integrity mismatch) → AttestryAPIError(500)", async () => {
    const { client } = makeStreamMockedClient(
      () =>
        new Response(JSON.stringify({ success: false, error: "integrity" }), {
          status: 500,
          headers: { "content-type": "application/json" },
        }),
    );
    const err = await client.annexIv
      .downloadPdf({ technicalFileId: VALID_UUID })
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
      .downloadPdf({ technicalFileId: VALID_UUID })
      .catch((e) => e);
    expect(err).toBeInstanceOf(AttestryError);
    expect(err).not.toBeInstanceOf(AttestryAPIError);
  });

  it("throws TypeError for a non-UUID synchronously (NO request)", () => {
    const { client, calls } = makeStreamMockedClient(() => pdfResponse());
    expect(() =>
      client.annexIv.downloadPdf({ technicalFileId: "nope" }),
    ).toThrowError(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });
});
