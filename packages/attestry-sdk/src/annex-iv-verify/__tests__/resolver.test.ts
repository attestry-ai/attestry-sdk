// ─── makeJwksResolver + the missing-key-material precondition (C-C-9 / C-D2) ─-
//
// makeJwksResolver is OUR resolver's deliberate fail-closed-to-null contract
// (DISTINCT from the caller-supplied-resolver propagation). A bad/absent jwks
// entry → null → the verifier's `valid:false` "public key did not resolve
// offline" path; it NEVER throws. Each hostile case is non-tautological (it
// drives the verifier to valid:false via a real null return).
//
// The missing-key-material precondition (no resolvePublicKey AND no jwks) is the
// ONLY throw the verifier emits — a typed AttestryError (C-D2), not a bare
// TypeError, not a verification failure.

import { describe, it, expect } from "vitest";
import { makeJwksResolver, kidFromVerificationMethod } from "../resolver.js";
import { verifyAnnexIvBindOffline } from "../verify.js";
import { AttestryError } from "../../errors.js";
import { ed25519PublicKeyToJwk, type Ed25519PublicJwk } from "../jwk.js";
import { ed25519GetPublicKey } from "../ed25519.js";
import goldenVectors from "./golden-vectors.json" with { type: "json" };

interface GoldenVector {
  id: string;
  sidecarJws: string;
  pdfBytesB64: string;
  publicKeyJwk: Ed25519PublicJwk;
}
const VECTORS = goldenVectors as unknown as GoldenVector[];
const V1 = VECTORS.find((v) => v.id === "V1")!;
const KID = V1.publicKeyJwk.kid;
const VM = `https://attestry.test/.well-known/keys#${KID}`;
const bytes = (b64: string): Uint8Array => new Uint8Array(Buffer.from(b64, "base64"));

describe("kidFromVerificationMethod", () => {
  it("extracts the fragment after the last #", () => {
    expect(kidFromVerificationMethod("https://x/.well-known/keys#key-2026-05")).toBe(
      "key-2026-05",
    );
  });
  it("returns null when there is no fragment", () => {
    expect(kidFromVerificationMethod("https://x/.well-known/keys")).toBeNull();
  });
  it("returns null for a trailing-# (empty fragment)", () => {
    expect(kidFromVerificationMethod("https://x#")).toBeNull();
  });
});

describe("makeJwksResolver — kid-match (hit / miss / array vs {keys})", () => {
  it("resolves the matching kid from an ARRAY jwks", () => {
    const resolver = makeJwksResolver([V1.publicKeyJwk]);
    const key = resolver(VM);
    expect(key).not.toBeNull();
    expect(key!.length).toBe(32);
  });

  it("resolves the matching kid from a {keys} object", () => {
    const resolver = makeJwksResolver({ keys: [V1.publicKeyJwk] });
    const key = resolver(VM);
    expect(key).not.toBeNull();
    expect(key!.length).toBe(32);
  });

  it("returns null when no kid matches (miss)", () => {
    const resolver = makeJwksResolver([{ ...V1.publicKeyJwk, kid: "other-kid" }]);
    expect(resolver(VM)).toBeNull();
  });

  it("returns null when the vm has no fragment", () => {
    const resolver = makeJwksResolver([V1.publicKeyJwk]);
    expect(resolver("https://attestry.test/.well-known/keys")).toBeNull();
  });
});

describe("makeJwksResolver — fail-closed-to-null on a bad entry (C-C-9, NEVER throws)", () => {
  it("a present jwk with x.length > 100 → null (does not propagate the throw)", () => {
    const bad: Ed25519PublicJwk = { ...V1.publicKeyJwk, x: "A".repeat(200) };
    const resolver = makeJwksResolver([bad]);
    expect(resolver(VM)).toBeNull();
  });

  it("a jwk decoding to ≠ 32 bytes → null", () => {
    // 'AAAA' decodes to 3 bytes ≠ 32.
    const bad: Ed25519PublicJwk = { ...V1.publicKeyJwk, x: "AAAA" };
    const resolver = makeJwksResolver([bad]);
    expect(resolver(VM)).toBeNull();
  });

  it("a non-OKP jwk → null", () => {
    const bad = { ...V1.publicKeyJwk, kty: "EC" } as unknown as Ed25519PublicJwk;
    const resolver = makeJwksResolver([bad]);
    expect(resolver(VM)).toBeNull();
  });
});

describe("makeJwksResolver — fail-closed-to-null on a malformed CONTAINER (C-C-9 — NEVER throws)", () => {
  // The C-C-9 fix made a bad ENTRY fail-closed-to-null; this pins the SAME
  // "NEVER throws" contract for a malformed CONTAINER shape (a JWKS fetched
  // from a URL can arrive empty/garbled). Each must resolve to null → the
  // verifier's valid:false path, NEVER a bare untyped TypeError.
  const cases: Array<[string, unknown]> = [
    ["empty object {} (no keys)", {}],
    ["{ keys: null }", { keys: null }],
    ["{ keys: 'notarray' }", { keys: "notarray" }],
    ["an array with a null entry [null]", [null]],
    ["an array with an undefined entry", [undefined]],
    ["an array with a primitive entry [42]", [42]],
    ["a bare string", "stringjwks"],
    ["a bare number", 42],
  ];
  for (const [label, jwks] of cases) {
    it(`${label} → resolver returns null (no throw)`, () => {
      const resolver = makeJwksResolver(jwks as never);
      expect(resolver(VM)).toBeNull();
    });
  }

  it("end-to-end: a malformed container drives the verifier to valid:false (not a bare throw)", () => {
    const r = verifyAnnexIvBindOffline({
      sidecarJws: V1.sidecarJws,
      pdfBytes: bytes(V1.pdfBytesB64),
      jwks: {} as never,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("public key did not resolve offline");
  });
});

describe("makeJwksResolver — end-to-end: a bad entry drives the verifier to valid:false (non-tautological)", () => {
  it("an over-long x → null → verifier valid:false 'public key did not resolve offline'", () => {
    const bad: Ed25519PublicJwk = { ...V1.publicKeyJwk, x: "A".repeat(200) };
    const r = verifyAnnexIvBindOffline({
      sidecarJws: V1.sidecarJws,
      pdfBytes: bytes(V1.pdfBytesB64),
      jwks: [bad],
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("public key did not resolve offline");
  });

  it("a WRONG (valid, different) key → null is NOT hit (kid matches) → sig fails instead", () => {
    // A different keypair but the SAME kid → the resolver RESOLVES it (kid match),
    // and the signature check fails — distinct from the null path.
    const otherSk = Uint8Array.from({ length: 32 }, (_, i) => (i + 7) % 251);
    const otherJwk = ed25519PublicKeyToJwk(ed25519GetPublicKey(otherSk), KID);
    const r = verifyAnnexIvBindOffline({
      sidecarJws: V1.sidecarJws,
      pdfBytes: bytes(V1.pdfBytesB64),
      jwks: [otherJwk],
    });
    expect(r.valid).toBe(false);
    expect(r.signatureOk).toBe(false);
    // NOT the resolve-null path — the key DID resolve (kid matched), the sig failed.
    expect(r.reason).toBe("signature invalid over the received octets");
  });

  it("the {keys}-normalization end-to-end resolves the correct key → valid:true", () => {
    const r = verifyAnnexIvBindOffline({
      sidecarJws: V1.sidecarJws,
      pdfBytes: bytes(V1.pdfBytesB64),
      jwks: { keys: [V1.publicKeyJwk] },
    });
    expect(r.valid).toBe(true);
  });
});

describe("verifyAnnexIvBindOffline — missing-key-material precondition (C-D2)", () => {
  it("throws a typed AttestryError when neither resolvePublicKey nor jwks is given", () => {
    expect(() =>
      verifyAnnexIvBindOffline({
        sidecarJws: V1.sidecarJws,
        pdfBytes: bytes(V1.pdfBytesB64),
      }),
    ).toThrow(AttestryError);
  });

  it("the missing-key-material error message names the two ways to supply keys", () => {
    expect(() =>
      verifyAnnexIvBindOffline({
        sidecarJws: V1.sidecarJws,
        pdfBytes: bytes(V1.pdfBytesB64),
      }),
    ).toThrow(/requires key material.*resolvePublicKey.*jwks/);
  });
});
