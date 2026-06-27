// VERIFY-only faithful port of `src/lib/crypto/jwk.ts` — the kernel is the
// source of truth; the golden cross-vectors (`__tests__/golden-vectors.json`)
// break first on any divergence. Do NOT edit semantics independently.
//
// Copied VERBATIM. Uses Node `Buffer` (the SDK is a Node package,
// engines.node>=18) — REQUIRED for byte-identity; do NOT web-ify. No `@/lib`
// imports to rewrite.
/**
 * Ed25519 JWK (RFC 8037 / OKP) helpers + base64url codec.
 *
 * The JWK representation is the dual-use publication surface advertised at
 * `/.well-known/keys` (consumed by the P3 Consumer API + attestry-atlassian),
 * alongside the Multikey representation the off-the-shelf eddsa-jcs-2022 verifier
 * resolves through the controller document. Same key, two encodings.
 */

// ─── base64url (unpadded) ────────────────────────────────────────────────────

/** Encode bytes as unpadded base64url. */
export function bytesToBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Decode unpadded (or padded) base64url back to bytes. Fails closed on garbage. */
export function base64urlToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(value)) {
    throw new Error("Invalid base64url string");
  }
  return new Uint8Array(Buffer.from(value, "base64url"));
}

// ─── Ed25519 OKP JWK ─────────────────────────────────────────────────────────

export interface Ed25519PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  /** base64url of the raw 32-byte public key. */
  x: string;
  /** Key id — unique, never reused, matches the credential's verificationMethod fragment. */
  kid: string;
  use?: "sig";
  alg?: "EdDSA";
}

/** Build a public Ed25519 JWK from a raw 32-byte public key + kid. */
export function ed25519PublicKeyToJwk(publicKey: Uint8Array, kid: string): Ed25519PublicJwk {
  if (publicKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKey.length}`);
  }
  return {
    kty: "OKP",
    crv: "Ed25519",
    x: bytesToBase64url(publicKey),
    kid,
    use: "sig",
    alg: "EdDSA",
  };
}

/** Extract the raw 32-byte public key from an Ed25519 OKP JWK. Fails closed. */
export function jwkToEd25519PublicKey(jwk: Partial<Ed25519PublicJwk> | null | undefined): Uint8Array {
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("Not an Ed25519 OKP JWK");
  }
  // A 32-byte key is ~43 base64url chars; bound before decoding caller-supplied `x`.
  if (jwk.x.length > 100) {
    throw new Error("Ed25519 JWK 'x' is too long");
  }
  const key = base64urlToBytes(jwk.x);
  if (key.length !== 32) {
    throw new Error(`Decoded Ed25519 public key must be 32 bytes, got ${key.length}`);
  }
  return key;
}
