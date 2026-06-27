// VERIFY-only faithful port of `src/lib/crypto/multibase.ts` — the kernel is the
// source of truth; the golden cross-vectors (`__tests__/golden-vectors.json`)
// break first on any divergence. Do NOT edit semantics independently.
//
// Copied VERBATIM. Dependency-free (no imports). The sign-side encoders carried
// here are dead-but-private; only `decodeMultibaseBase58btc` is verifier-reached.
/**
 * Multibase / multicodec encodings used by the W3C VC Data Integrity stack.
 *
 * Two distinct encodings live here, both base58btc with the multibase `z`
 * prefix but with different payloads — keeping them straight matters:
 *
 *  - **proofValue** (eddsa-jcs-2022): `z` + base58btc(rawSignatureBytes). No
 *    multicodec prefix. This is exactly what `@digitalbazaar/data-integrity`
 *    emits/consumes.
 *  - **publicKeyMultibase** (Multikey): `z` + base58btc(0xed01 ‖ rawPublicKey).
 *    The `0xed01` multicodec header is what makes it render as `z6Mk…` and is
 *    what `@digitalbazaar/ed25519-multikey` requires to resolve the key.
 *
 * Implemented dependency-free (no Buffer, no external base58 pkg) so the same
 * code can power a standalone offline verifier later. Cross-checked against
 * `base58-universal` + `@digitalbazaar/ed25519-multikey` in the conformance test.
 */

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Reverse lookup: char code -> value (255 = invalid).
const BASE58_MAP: Int16Array = (() => {
  const map = new Int16Array(128).fill(-1);
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    map[BASE58_ALPHABET.charCodeAt(i)] = i;
  }
  return map;
})();

/** Encode raw bytes as base58btc (Bitcoin alphabet), preserving leading zeros. */
export function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Upper bound on output size: log(256)/log(58) ≈ 1.3658.
  const size = Math.floor((bytes.length - zeros) * 138 / 100) + 1;
  const buffer = new Uint8Array(size);
  let length = 0;

  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    let j = size - 1;
    for (; (carry !== 0 || j >= size - length) && j >= 0; j--) {
      carry += 256 * buffer[j];
      buffer[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    length = size - 1 - j;
  }

  let it = size - length;
  while (it < size && buffer[it] === 0) it++;

  let out = "1".repeat(zeros);
  for (; it < size; it++) out += BASE58_ALPHABET[buffer[it]];
  return out;
}

/** Decode a base58btc string back to raw bytes, preserving leading-`1` zeros. */
export function base58btcDecode(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;

  const size = Math.floor((str.length - zeros) * 733 / 1000) + 1; // log(58)/log(256)
  const buffer = new Uint8Array(size);
  let length = 0;

  for (let i = zeros; i < str.length; i++) {
    const code = str.charCodeAt(i);
    const value = code < 128 ? BASE58_MAP[code] : -1;
    if (value < 0) {
      throw new Error(`Invalid base58 character "${str[i]}" at index ${i}`);
    }
    let carry = value;
    let j = size - 1;
    for (; (carry !== 0 || j >= size - length) && j >= 0; j--) {
      carry += 58 * buffer[j];
      buffer[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    length = size - 1 - j;
  }

  let it = size - length;
  const out = new Uint8Array(zeros + (size - it));
  // leading zeros are already 0 in `out`
  let k = zeros;
  for (; it < size; it++, k++) out[k] = buffer[it];
  return out;
}

// ─── Multibase (base58btc, `z` prefix) ───────────────────────────────────────

export const MULTIBASE_BASE58BTC_PREFIX = "z";

/** `z` + base58btc(bytes) — multibase base58btc, the proofValue encoding. */
export function encodeMultibaseBase58btc(bytes: Uint8Array): string {
  return MULTIBASE_BASE58BTC_PREFIX + base58btcEncode(bytes);
}

/** Decode a multibase base58btc (`z`-prefixed) string. Fails closed otherwise. */
export function decodeMultibaseBase58btc(value: string): Uint8Array {
  if (value[0] !== MULTIBASE_BASE58BTC_PREFIX) {
    throw new Error(
      `Unsupported multibase prefix "${value[0] ?? ""}" (only base58btc "z" is supported)`,
    );
  }
  return base58btcDecode(value.slice(1));
}

// ─── Ed25519 publicKeyMultibase (Multikey, 0xed01 multicodec) ────────────────

// Varint encoding of the multicodec `ed25519-pub` code (0xed) -> [0xed, 0x01].
const MULTICODEC_ED25519_PUB_HEADER = Uint8Array.from([0xed, 0x01]);

/** Encode a raw 32-byte Ed25519 public key as `z6Mk…` publicKeyMultibase. */
export function encodeEd25519PublicKeyMultibase(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKey.length}`);
  }
  const prefixed = new Uint8Array(MULTICODEC_ED25519_PUB_HEADER.length + publicKey.length);
  prefixed.set(MULTICODEC_ED25519_PUB_HEADER, 0);
  prefixed.set(publicKey, MULTICODEC_ED25519_PUB_HEADER.length);
  return encodeMultibaseBase58btc(prefixed);
}

/** Decode a `z6Mk…` publicKeyMultibase back to the raw 32-byte public key. */
export function decodeEd25519PublicKeyMultibase(value: string): Uint8Array {
  const bytes = decodeMultibaseBase58btc(value);
  if (
    bytes.length !== 34 ||
    bytes[0] !== MULTICODEC_ED25519_PUB_HEADER[0] ||
    bytes[1] !== MULTICODEC_ED25519_PUB_HEADER[1]
  ) {
    throw new Error("Not a valid Ed25519 publicKeyMultibase (expected 0xed01 multicodec header)");
  }
  return bytes.slice(2);
}
