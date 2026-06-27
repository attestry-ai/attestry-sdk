// ─── The offline-verifiable demo (C-D7 — the exit-gate pin) ─────────────────-
//
// The genuinely-offline floor: an injected `FetchLike` returns a REAL
// kernel-minted golden vector's responses (no DB, no network, no kernel
// import); the SDK resource methods compose/parse those exact route shapes; the
// bundled `verifyAnnexIvBindOffline` then verifies the exact bytes. This is the
// form the PUBLISHED 0.7.0 exit-gate re-runs against a fresh install (H).
//
// CR-3 (no C-C-4 false-pass): the positive demo uses a SINGLE COHERENT vector
// pair (V2 — its OWN sidecar + its OWN list, so id/issuer/index align by
// construction) and asserts `revocation.checked === true && revoked === false`
// (NOT just valid:true — for a good bind valid stays true even when checked:false
// from ANY id/issuer/index mismatch bail, so the revocation leg would never be
// exercised). The revoked negative (V3) asserts checked && revoked && reason.
//
// CR-7: the FetchLike response shapes match the transport's guards — the pdf
// response carries content-type application/pdf + content-disposition (the
// _streamRequest 2xx guard exact-matches); the POST/GET-bind responses are the
// {success,data} envelope the transport auto-unwraps.

import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../client.js";
import { verifyAnnexIvBindOffline } from "../annex-iv-verify/index.js";
import type { Ed25519PublicJwk } from "../annex-iv-verify/index.js";
import type { FetchLike } from "../types.js";
import goldenVectors from "../annex-iv-verify/__tests__/golden-vectors.json" with { type: "json" };

interface GoldenVector {
  id: string;
  sidecarJws: string;
  pdfBytesB64: string;
  publicKeyJwk: Ed25519PublicJwk;
  cachedStatusListCredential?: unknown;
}
const VECTORS = goldenVectors as unknown as GoldenVector[];
const V2 = VECTORS.find((v) => v.id === "V2")!; // coherent good bind + not-revoked list
const V3 = VECTORS.find((v) => v.id === "V3")!; // good bind + bit SET (revoked)

const VALID_UUID = "11111111-1111-1111-1111-111111111111";
const bytes = (b64: string): Uint8Array => new Uint8Array(Buffer.from(b64, "base64"));

/** Parse the bind payload out of a compact sidecar JWS (decode the 2nd segment). */
function bindPayload(sidecarJws: string): Record<string, unknown> {
  const seg = sidecarJws.split(".")[1];
  return JSON.parse(Buffer.from(seg, "base64url").toString("utf8")) as Record<string, unknown>;
}

/**
 * Build a FetchLike that maps the three Annex IV route paths to a chosen
 * vector's REAL responses (the 201 generate envelope, the raw pdf, the bind
 * envelope). No network, no DB.
 */
function makeVectorFetch(v: GoldenVector): FetchLike {
  const payload = bindPayload(v.sidecarJws);
  const generateData = {
    technicalFileId: VALID_UUID,
    pdfByteSha256: payload.pdf_byte_sha256 as string,
    signingKeyId: payload.kid as string,
    statusListRef: payload.status_list_ref as string,
    statusListIndex: payload.status_list_index as number,
    sidecarJws: v.sidecarJws,
    pdfUrl: `/api/v1/technical-files/${VALID_UUID}/annex-iv/pdf`,
    bindUrl: `/api/v1/technical-files/${VALID_UUID}/annex-iv/bind`,
  };
  const bindData = {
    sidecarJws: v.sidecarJws,
    pdfByteSha256: payload.pdf_byte_sha256 as string,
    signingKeyId: payload.kid as string,
    statusListRef: payload.status_list_ref as string,
    statusListIndex: payload.status_list_index as number,
  };
  return async (url) => {
    const u = new URL(String(url));
    if (u.pathname.endsWith("/annex-iv/pdf")) {
      return new Response(bytes(v.pdfBytesB64), {
        status: 200,
        headers: {
          "content-type": "application/pdf",
          "content-disposition": 'attachment; filename="annex-iv.pdf"',
        },
      });
    }
    if (u.pathname.endsWith("/annex-iv/bind")) {
      return new Response(JSON.stringify({ success: true, data: bindData }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    // POST .../annex-iv (the generate route).
    return new Response(JSON.stringify({ success: true, data: generateData }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  };
}

function clientFor(v: GoldenVector): AttestryClient {
  return new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(makeVectorFetch(v)) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    retry: { maxRetries: 0 },
  });
}

describe("offline-verifiable demo — generate → downloadPdf → getBind → verify", () => {
  it("POSITIVE (V2, coherent pair): valid:true AND revocation.checked && !revoked", async () => {
    const client = clientFor(V2);

    const g = await client.annexIv.generate({ technicalFileId: VALID_UUID });
    const pdf = new Uint8Array(
      await (await client.annexIv.downloadPdf({ technicalFileId: VALID_UUID })).response.arrayBuffer(),
    );
    const b = await client.annexIv.getBind({ technicalFileId: VALID_UUID });

    // The SDK parsed the REAL route shapes.
    expect(g.sidecarJws).toBe(V2.sidecarJws);
    expect(b.sidecarJws).toBe(V2.sidecarJws);
    expect(g.pdfByteSha256).toBe(b.pdfByteSha256);

    // Verify the EXACT bytes with the bundled offline verifier + V2's OWN list.
    const r = verifyAnnexIvBindOffline({
      sidecarJws: g.sidecarJws,
      pdfBytes: pdf,
      cachedStatusListCredential: V2.cachedStatusListCredential,
      jwks: [V2.publicKeyJwk],
    });
    expect(r.valid).toBe(true);
    // The revocation leg WAS exercised (CR-3 — not inferred from valid alone).
    expect(r.revocation.checked).toBe(true);
    expect(r.revocation.revoked).toBe(false);
  });

  it("NEGATIVE (1-byte PDF mutation): valid:false (byteBinding)", async () => {
    const client = clientFor(V2);
    const g = await client.annexIv.generate({ technicalFileId: VALID_UUID });
    const pdf = new Uint8Array(
      await (await client.annexIv.downloadPdf({ technicalFileId: VALID_UUID })).response.arrayBuffer(),
    );
    pdf[0] = pdf[0] ^ 0x01; // mutate one byte

    const r = verifyAnnexIvBindOffline({
      sidecarJws: g.sidecarJws,
      pdfBytes: pdf,
      cachedStatusListCredential: V2.cachedStatusListCredential,
      jwks: [V2.publicKeyJwk],
    });
    expect(r.valid).toBe(false);
    expect(r.signatureOk).toBe(true);
    expect(r.byteBindingOk).toBe(false);
  });

  it("NEGATIVE (V3, revoked): valid:false AND revocation.checked && revoked && reason='revoked'", async () => {
    const client = clientFor(V3);
    const g = await client.annexIv.generate({ technicalFileId: VALID_UUID });
    const pdf = new Uint8Array(
      await (await client.annexIv.downloadPdf({ technicalFileId: VALID_UUID })).response.arrayBuffer(),
    );

    const r = verifyAnnexIvBindOffline({
      sidecarJws: g.sidecarJws,
      pdfBytes: pdf,
      cachedStatusListCredential: V3.cachedStatusListCredential,
      jwks: [V3.publicKeyJwk],
    });
    expect(r.valid).toBe(false);
    expect(r.revocation.checked).toBe(true);
    expect(r.revocation.revoked).toBe(true);
    expect(r.reason).toBe("revoked");
  });

  it("BINDING: the parsed sidecar's evidence_pack_content_hashes is non-empty + the cited set", async () => {
    const client = clientFor(V2);
    const g = await client.annexIv.generate({ technicalFileId: VALID_UUID });
    const payload = bindPayload(g.sidecarJws);
    const hashes = payload.evidence_pack_content_hashes as string[];
    // The evidence-pack binding is exercised (non-empty, deduped + sorted ascending).
    expect(Array.isArray(hashes)).toBe(true);
    expect(hashes.length).toBeGreaterThan(0);
    expect(hashes).toEqual([...hashes].sort());
    for (const h of hashes) expect(h).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
