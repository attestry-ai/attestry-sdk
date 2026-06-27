// VERIFY-only faithful port of `src/lib/crypto/ed25519.ts` — the kernel is the
// source of truth; the golden cross-vectors (`__tests__/golden-vectors.json`)
// break first on any divergence. Do NOT edit semantics independently.
//
// Copied VERBATIM (the sign-side `ed25519Sign` / `generateEd25519SecretKey` /
// `ed25519GetPublicKey` carried here are dead-but-private — the only verifier-
// reachable exports are `ed25519Verify` + `sha256`; tree-shaking drops the rest).
// Package imports (`@noble/*`) are unchanged; there are no `@/lib` imports to
// rewrite under the SDK's `module:"Node16"` resolution.
/**
 * Ed25519 primitives — a thin, portable wrapper over `@noble/ed25519` v3.
 *
 * `@noble/ed25519` v3 ships with its SHA-512 hash slot UNSET; we wire it once
 * here (synchronously, from `@noble/hashes`) so the sync sign/verify/derive API
 * works in every runtime — Node server routes, tests, and a future standalone
 * verifier — with zero per-call setup.
 *
 * This module is deliberately free of any DB / Vault / env dependency. It is
 * the cryptographic floor the DB-free offline verifier and the JWKS / controller
 * routes stand on (W2.5a). Asymmetric, public-key verifiable — no shared secret.
 */
import * as ed from "@noble/ed25519";
import { sha512, sha256 as nobleSha256 } from "@noble/hashes/sha2.js";

// ─── One-time hash wiring (required by @noble/ed25519 v3) ────────────────────
// Populating the sha512 slot enables the synchronous API. Assigning a property
// on the (mutable) `hashes` object is idempotent; importing this module anywhere
// in the crypto stack guarantees the primitives are usable.
ed.hashes.sha512 = sha512;

export const ED25519_PUBLIC_KEY_LENGTH = 32;
export const ED25519_SECRET_KEY_LENGTH = 32;
export const ED25519_SIGNATURE_LENGTH = 64;

// ─── Key generation / derivation ─────────────────────────────────────────────

/** Generate a fresh 32-byte Ed25519 secret key (CSPRNG). */
export function generateEd25519SecretKey(): Uint8Array {
  return ed.utils.randomSecretKey();
}

/** Derive the 32-byte public key from a 32-byte secret key. */
export function ed25519GetPublicKey(secretKey: Uint8Array): Uint8Array {
  return ed.getPublicKey(secretKey);
}

// ─── Sign / verify ───────────────────────────────────────────────────────────

/** Deterministically sign `message`, returning the 64-byte signature. */
export function ed25519Sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return ed.sign(message, secretKey);
}

/**
 * Verify a 64-byte Ed25519 signature over `message` against `publicKey`.
 *
 * Returns a boolean and NEVER throws: noble raises on malformed inputs
 * (wrong-length signature/key, non-canonical encodings, …). For a verifier,
 * every such failure is a plain "invalid" — surfacing it as an exception would
 * be a fail-OPEN footgun, so we trap it and return false.
 */
export function ed25519Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  try {
    return ed.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

// ─── Hashing ───────────────────────────────────────────────────────────────--

/** SHA-256 over `data` (used by the eddsa-jcs-2022 hashing step + status list). */
export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}
