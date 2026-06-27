// ─── The bundled verifier — HOSTILE / untrusted-input boundary (security lens) -
//
// The verifier is a NEW untrusted-input boundary in the published SDK. This
// pins the fail-closed contract on malformed/forged artifact input + the
// resolver-throw PROPAGATION (verdict-identity, C-C-2/MF-3) + the per-guard
// tampered-status-list table (C-C-8 — each fixture OTHERWISE-valid so ONLY the
// target guard fires; a tampered list is NEVER a false not-revoked, NEVER flips
// valid).
//
// The two distinct bad-input surfaces (do NOT conflate):
//   - artifact input (sidecar/pdf/list) → fail-closed `valid:false` (NO throw);
//   - a caller-supplied resolver that THROWS → PROPAGATES (the kernel calls the
//     resolver bare at both legs; the SDK re-throws). This is `toThrow`, NOT
//     `valid:false`. Distinct again from a resolver that RETURNS null
//     (→ `valid:false` "public key did not resolve offline").

import { describe, it, expect } from "vitest";
import { verifyAnnexIvBindOffline } from "../verify.js";
import { jwkToEd25519PublicKey, type Ed25519PublicJwk } from "../jwk.js";
import goldenVectors from "./golden-vectors.json" with { type: "json" };
import hostileFixtures from "./hostile-fixtures.json" with { type: "json" };

interface GoldenVector {
  id: string;
  resolverKind: string;
  sidecarJws: string;
  pdfBytesB64: string;
  publicKeyJwk: Ed25519PublicJwk;
  cachedStatusListCredential?: unknown;
}
interface HostileFixtures {
  base: {
    sidecarJws: string;
    pdfBytesB64: string;
    publicKeyJwk: Ed25519PublicJwk;
    statusListIndex: number;
  };
  guards: Array<{
    guard: string;
    statusListCredential: unknown;
    expectedReason: string;
    sidecarJws?: string;
    pdfBytesB64?: string;
  }>;
}

const VECTORS = goldenVectors as unknown as GoldenVector[];
const FX = hostileFixtures as unknown as HostileFixtures;

const bytes = (b64: string): Uint8Array => new Uint8Array(Buffer.from(b64, "base64"));
// A valid base bind (V2 — a coherent good bind with a list) for the malformed-
// sidecar cases, and the hostile-fixtures base for the per-guard table.
const V2 = VECTORS.find((v) => v.id === "V2")!;
const BASE_PDF = bytes(FX.base.pdfBytesB64);
const BASE_JWKS = [FX.base.publicKeyJwk];

describe("verify-hostile — malformed/forged artifact input → fail-closed valid:false (NO throw)", () => {
  it("a non-JWS sidecar (wrong segment count) → valid:false on the tag/parse", () => {
    const r = verifyAnnexIvBindOffline({
      sidecarJws: "not.a.jws.at.all",
      pdfBytes: BASE_PDF,
      jwks: BASE_JWKS,
    });
    expect(r.valid).toBe(false);
    expect(r.tagOk).toBe(false);
    expect(r.reason).toMatch(/domain tag \/ parse/);
  });

  it("a non-JSON sidecar segment → valid:false (no throw)", () => {
    const r = verifyAnnexIvBindOffline({
      sidecarJws: "%%%.%%%.%%%",
      pdfBytes: BASE_PDF,
      jwks: BASE_JWKS,
    });
    expect(r.valid).toBe(false);
    expect(r.tagOk).toBe(false);
  });

  it("the empty string → valid:false (no throw)", () => {
    const r = verifyAnnexIvBindOffline({ sidecarJws: "", pdfBytes: BASE_PDF, jwks: BASE_JWKS });
    expect(r.valid).toBe(false);
  });

  it("a forged verificationMethod the resolver can't match → valid:false 'public key did not resolve offline'", () => {
    // jwks with a DIFFERENT kid than the sidecar's vm → no match → null → fail-closed.
    const wrongKidJwk: Ed25519PublicJwk = { ...FX.base.publicKeyJwk, kid: "no-such-kid" };
    const r = verifyAnnexIvBindOffline({
      sidecarJws: FX.base.sidecarJws,
      pdfBytes: BASE_PDF,
      jwks: [wrongKidJwk],
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("public key did not resolve offline");
    expect(r.fieldsOk).toBe(true);
  });

  it("a 1-byte PDF mutation → valid:false (byteBinding)", () => {
    const mutated = Uint8Array.from(BASE_PDF);
    mutated[0] = mutated[0] ^ 0x01;
    const r = verifyAnnexIvBindOffline({
      sidecarJws: FX.base.sidecarJws,
      pdfBytes: mutated,
      jwks: BASE_JWKS,
    });
    expect(r.valid).toBe(false);
    expect(r.signatureOk).toBe(true);
    expect(r.byteBindingOk).toBe(false);
  });
});

describe("verify-hostile — resolver-throw PROPAGATES (verdict-identity, C-C-2/MF-3 — toThrow, NOT valid:false)", () => {
  it("a resolvePublicKey that throws at the SIGNATURE leg → propagates (toThrow)", () => {
    expect(() =>
      verifyAnnexIvBindOffline({
        sidecarJws: FX.base.sidecarJws,
        pdfBytes: BASE_PDF,
        resolvePublicKey: () => {
          throw new Error("resolver boom (sig leg)");
        },
      }),
    ).toThrow(/resolver boom/);
  });

  it("a resolvePublicKey that RETURNS the key at the sig leg but THROWS on the REVOCATION leg → propagates (toThrow)", () => {
    // The base bind + a coherent list (from the per-guard table's id-match doc is
    // tampered; use V2's own coherent list shape). Reuse the hostile base bind
    // with V2's own list would mismatch ids — instead use V2 (a coherent pair).
    const pk = jwkToEd25519PublicKey(V2.publicKeyJwk);
    let calls = 0;
    expect(() =>
      verifyAnnexIvBindOffline({
        sidecarJws: V2.sidecarJws,
        pdfBytes: bytes(V2.pdfBytesB64),
        cachedStatusListCredential: V2.cachedStatusListCredential,
        resolvePublicKey: () => {
          calls += 1;
          if (calls >= 2) throw new Error("resolver boom (rev leg)");
          return pk;
        },
      }),
    ).toThrow(/resolver boom \(rev leg\)/);
    expect(calls).toBeGreaterThanOrEqual(2);
  });
});

describe("verify-hostile — per-guard tampered status-list table (C-C-8: valid:true && checked:false + exact reason)", () => {
  for (const g of FX.guards) {
    it(`${g.guard} → valid:true, revocation.checked:false, reason="${g.expectedReason}"`, () => {
      const r = verifyAnnexIvBindOffline({
        sidecarJws: g.sidecarJws ?? FX.base.sidecarJws,
        pdfBytes: g.pdfBytesB64 ? bytes(g.pdfBytesB64) : BASE_PDF,
        cachedStatusListCredential: g.statusListCredential,
        jwks: BASE_JWKS,
      });
      // A tampered list is NEVER a false not-revoked, NEVER flips valid.
      expect(r.valid).toBe(true);
      expect(r.revocation.checked).toBe(false);
      expect(r.revocation.revoked).toBe(false);
      expect(r.revocation.reason).toBe(g.expectedReason);
    });
  }

  it("the gzip-bomb row returns PROMPTLY (no OOM / hang) — bounded by the decode cap", () => {
    const bomb = FX.guards.find((g) => g.guard.includes("gzip-bomb"))!;
    const start = Date.now();
    const r = verifyAnnexIvBindOffline({
      sidecarJws: FX.base.sidecarJws,
      pdfBytes: BASE_PDF,
      cachedStatusListCredential: bomb.statusListCredential,
      jwks: BASE_JWKS,
    });
    expect(r.valid).toBe(true);
    expect(r.revocation.checked).toBe(false);
    // The cap makes gunzip throw immediately — well under a second.
    expect(Date.now() - start).toBeLessThan(5000);
  });
});
