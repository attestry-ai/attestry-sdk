// SDK-only JWKS → resolver bridge for the offline Annex IV bind verifier.
//
// This file is NOT a kernel port — it is the SDK's caller-facing key-resolution
// convenience (the kernel resolves from its env key-registry, which the SDK does
// NOT ship). `kidFromVerificationMethod` IS lifted verbatim from
// `src/lib/crypto/key-registry.ts:105` (a pure string fn — the ONLY symbol
// lifted from key-registry; the rest of that module is server-only).

import {
  jwkToEd25519PublicKey,
  type Ed25519PublicJwk,
} from "./jwk.js";
import type { PublicKeyResolver } from "./data-integrity.js";

export type { Ed25519PublicJwk } from "./jwk.js";

/** Extract the kid (fragment) from a verificationMethod URL, or null. (Verbatim from key-registry.) */
export function kidFromVerificationMethod(verificationMethod: string): string | null {
  const hashIdx = verificationMethod.lastIndexOf("#");
  if (hashIdx < 0) return null;
  return verificationMethod.slice(hashIdx + 1) || null;
}

/**
 * Build a {@link PublicKeyResolver} from a JWKS (an array of public JWKs, or a
 * `{ keys }` object). The resolver matches the verificationMethod's **kid
 * fragment ONLY** against `jwk.kid` and returns the raw 32-byte public key — it
 * does NOT validate the verificationMethod's origin / base-URL (unlike the
 * kernel's server-side registry resolver). Key TRUST is the caller's: supply
 * ONLY JWKs you trust as this issuer's; the Ed25519 signature is still required.
 *
 * **Fail-closed-to-null (C-C-9), NEVER throws** — this is OUR resolver's
 * deliberate contract, DISTINCT from the caller-supplied-resolver propagation:
 * an absent kid match → `null`; a PRESENT-but-malformed jwk → `null` (the
 * `jwkToEd25519PublicKey` throw is caught — it throws on a non-OKP jwk, an
 * over-long `x`, or a decode ≠ 32 bytes); a malformed CONTAINER (not an array
 * and no `keys` array, or a null / primitive entry) → `null` (normalized to an
 * empty list / skipped — never a bare `TypeError`). A `null` return drives the
 * verifier's `valid:false` "public key did not resolve offline" path —
 * kernel-consistent (the kernel's own default resolver returns null on failure,
 * never throws).
 */
export function makeJwksResolver(
  jwks: Ed25519PublicJwk[] | { keys: Ed25519PublicJwk[] },
): PublicKeyResolver {
  return (vm: string) => {
    // Normalize to a list FIRST — fail-closed-to-null on ANY malformed container
    // shape (not an array, no `keys` array): resolve to [] → null, NEVER a bare
    // TypeError. Do NOT call `.find` on a `{keys}` object or a non-array.
    const list: unknown[] = Array.isArray(jwks)
      ? jwks
      : Array.isArray((jwks as { keys?: unknown } | null | undefined)?.keys)
        ? (jwks as { keys: unknown[] }).keys
        : [];
    const kid = kidFromVerificationMethod(vm);
    // Skip null / primitive entries so a malformed entry can never throw on `.kid`.
    const jwk = list.find(
      (j): j is Ed25519PublicJwk =>
        j != null && typeof j === "object" && (j as { kid?: unknown }).kid === kid,
    );
    if (!jwk) return null;
    try {
      return jwkToEd25519PublicKey(jwk);
    } catch {
      return null;
    }
  };
}
