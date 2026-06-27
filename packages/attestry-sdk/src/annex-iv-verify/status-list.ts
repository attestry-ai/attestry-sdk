// VERIFY-only faithful port of `src/lib/crypto/status-list.ts` — the kernel is
// the source of truth; the golden cross-vectors (`__tests__/golden-vectors.json`)
// break first on any divergence. Do NOT edit semantics independently.
//
// Copied VERBATIM, with the ONLY change being the relative-import rewrite to an
// EXPLICIT `.js` extension (the SDK is `module:"Node16"`). The `node:zlib`
// import is unchanged — REQUIRED for byte-identity (incl. the gzip-bomb cap on
// the attacker-controlled `encodedList`); do NOT web-ify. The sign-side
// (`createBitstring`/`setBit`/`encodeBitstring`/`signStatusListCredential`) is
// dead-but-private — only `checkRevocationOffline` + `decodeBitstring` + `getBit`
// + `issuerId` + `asEntries` are verifier-reached.
//
// VERBATIM-COPY FENCE (do NOT narrow): the verify-side status-purpose predicate
// (the `|| e.statusPurpose === 'suspension'` arm), the `subject.statusPurpose ===
// entry.statusPurpose` equality, and `asEntries` (array handling + the `.find`
// skip-non-matching) are load-bearing — the golden vectors V10 (suspension) and
// V11 (multi-entry array) break first if any of them is pruned.
/**
 * W3C **Bitstring Status List v1.0** — issuer-signed revocation infrastructure.
 *
 * Decision-RVK (ratified): ship the issuer-signed status list so offline
 * `/verify` is a TWO-check contract — *signature-over-bytes valid AND status-bit
 * == not-revoked*. A pure signature check returns VALID for a cryptographically
 * intact file the issuer has since revoked; on a 10-yr Article-18 technical file
 * that is a falsifiable "verifiable" claim. The status-list VC is signed with the
 * SAME Ed25519 key + kid and may be fetched out-of-band / cached by the verifier.
 *
 * The revocation STATE source here is config/env (DB-free, consistent with the
 * rest of W2.5a); wiring the bit population from live DB revocation state — and
 * pinning `status_list_ref` + index into the signed `ANNEX-IV-BIND-v1` payload —
 * is W2.
 */
import { gzipSync, gunzipSync } from "node:zlib";
import { bytesToBase64url, base64urlToBytes } from "./jwk.js";
import {
  signDocument,
  verifyDocument,
  type JsonLdDocument,
  type SecuredDocument,
  type PublicKeyResolver,
  type SignOptions,
} from "./data-integrity.js";

/** Minimum list length per spec: 16 KiB = 131,072 single-bit entries. */
export const DEFAULT_STATUS_LIST_LENGTH = 131072;
/**
 * Hard cap on a DECODED status-list bitstring (10 MiB ≈ 83M entries). The offline
 * verifier gunzips an attacker-supplied `encodedList`; this bounds a gzip bomb.
 */
export const MAX_DECODED_STATUS_LIST_BYTES = 10 * 1024 * 1024;
export const MULTIBASE_BASE64URL_NOPAD_PREFIX = "u";
export const BITSTRING_STATUS_LIST_ENTRY = "BitstringStatusListEntry";
export const BITSTRING_STATUS_LIST = "BitstringStatusList";

export type StatusPurpose = "revocation" | "suspension";

// ─── Bitstring ─────────────────────────────────────────────────────────────--

export function createBitstring(numEntries = DEFAULT_STATUS_LIST_LENGTH): Uint8Array {
  if (numEntries <= 0 || numEntries % 8 !== 0) {
    throw new Error("Bitstring length must be a positive multiple of 8");
  }
  return new Uint8Array(numEntries / 8);
}

function assertIndex(bitstring: Uint8Array, index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= bitstring.length * 8) {
    throw new Error(`Status index ${index} out of range`);
  }
}

/** Set/clear the status bit at `index`. Bits are MSB-first within each byte (per spec). */
export function setBit(bitstring: Uint8Array, index: number, value: boolean): void {
  assertIndex(bitstring, index);
  const byte = index >> 3;
  const mask = 1 << (7 - (index & 7));
  if (value) bitstring[byte] |= mask;
  else bitstring[byte] &= ~mask;
}

export function getBit(bitstring: Uint8Array, index: number): boolean {
  assertIndex(bitstring, index);
  const byte = index >> 3;
  const mask = 1 << (7 - (index & 7));
  return (bitstring[byte] & mask) !== 0;
}

/** `u` + base64url(GZIP(bitstring)) — the spec's `encodedList` multibase form. */
export function encodeBitstring(bitstring: Uint8Array): string {
  return MULTIBASE_BASE64URL_NOPAD_PREFIX + bytesToBase64url(gzipSync(bitstring));
}

export function decodeBitstring(encodedList: string): Uint8Array {
  if (encodedList[0] !== MULTIBASE_BASE64URL_NOPAD_PREFIX) {
    throw new Error("encodedList must be multibase base64url ('u' prefix)");
  }
  // `maxOutputLength` makes gunzip throw rather than expand a gzip bomb to
  // exhaust memory — `encodedList` is attacker-controlled in the offline route.
  return new Uint8Array(
    gunzipSync(base64urlToBytes(encodedList.slice(1)), {
      maxOutputLength: MAX_DECODED_STATUS_LIST_BYTES,
    }),
  );
}

// ─── Status-list credential ────────────────────────────────────────────────--

export interface BuildStatusListCredentialInput {
  /** Stable URL where the status list VC is published. */
  id: string;
  issuer: string;
  statusPurpose: StatusPurpose;
  encodedList: string;
  validFrom?: string;
}

export function buildStatusListCredential(input: BuildStatusListCredentialInput): JsonLdDocument {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: input.id,
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: input.issuer,
    validFrom: input.validFrom ?? new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    credentialSubject: {
      id: `${input.id}#list`,
      type: BITSTRING_STATUS_LIST,
      statusPurpose: input.statusPurpose,
      encodedList: input.encodedList,
    },
  };
}

/** Convenience: build + sign a status-list credential with the active key. */
export function signStatusListCredential(
  input: BuildStatusListCredentialInput,
  signOptions: SignOptions,
): SecuredDocument {
  return signDocument(buildStatusListCredential(input), signOptions);
}

// ─── Offline revocation check (the second of the two checks) ─────────────────

export interface CredentialStatusEntry {
  id?: string;
  type: string;
  statusPurpose: string;
  statusListIndex: string | number;
  statusListCredential: string;
}

export interface RevocationCheck {
  /** Whether revocation/suspension status was actually evaluated (false ⇒ offline + no status list). */
  checked: boolean;
  /** True iff the status bit is set (revoked OR suspended → not currently valid). */
  revoked: boolean;
  /** The status purpose that was evaluated, when checked. */
  statusPurpose?: StatusPurpose;
  reason?: string;
}

function asEntries(
  credentialStatus: CredentialStatusEntry | CredentialStatusEntry[] | undefined,
): CredentialStatusEntry[] {
  if (!credentialStatus) return [];
  return Array.isArray(credentialStatus) ? credentialStatus : [credentialStatus];
}

/** Normalize a VC `issuer` (a string or a `{ id }` object) to its string id, or undefined. */
export function issuerId(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (value && typeof value === "object" && typeof (value as { id?: unknown }).id === "string") {
    return (value as { id: string }).id;
  }
  return undefined;
}

/**
 * Evaluate the revocation bit OFFLINE: verify the status-list credential's own
 * signature (same issuer key), bind it to the entry, then read the bit. Fails
 * SAFE — any defect returns `checked:false` (status unknown), never a false
 * "not revoked". `checked:false` is honest ("verifiable as of issuance; status
 * not checked"), distinct from a confirmed `revoked:false`.
 */
export function checkRevocationOffline(
  credentialStatus: CredentialStatusEntry | CredentialStatusEntry[] | undefined,
  statusListCredential: unknown,
  resolvePublicKey: PublicKeyResolver,
  credentialIssuer?: string,
): RevocationCheck {
  const entry = asEntries(credentialStatus).find(
    (e) =>
      e?.type === BITSTRING_STATUS_LIST_ENTRY &&
      (e.statusPurpose === "revocation" || e.statusPurpose === "suspension"),
  );
  if (!entry) return { checked: false, revoked: false, reason: "no status entry" };
  if (!statusListCredential || typeof statusListCredential !== "object") {
    return { checked: false, revoked: false, reason: "status list not provided (offline)" };
  }

  const sig = verifyDocument(statusListCredential, resolvePublicKey);
  if (!sig.verified) {
    return { checked: false, revoked: false, reason: `status list signature invalid: ${sig.reason ?? "unknown"}` };
  }

  const list = statusListCredential as Record<string, unknown>;
  if (!Array.isArray(list.type) || !list.type.includes("BitstringStatusListCredential")) {
    return { checked: false, revoked: false, reason: "not a BitstringStatusListCredential" };
  }
  if (list.id !== entry.statusListCredential) {
    return { checked: false, revoked: false, reason: "status list id does not match credentialStatus" };
  }
  // Defense-in-depth issuer↔issuer binding — an Attestry single-issuer policy, NOT a
  // W3C requirement: the Bitstring Status List spec (§2.2) explicitly PERMITS a status
  // list whose issuer differs from the credential's, and its Validate algorithm (§3.2)
  // has no issuer-match step. We nonetheless refuse to consult a DIFFERENT issuer's list
  // if cross-tenant / multi-issuer signing is ever introduced. Single-issuer today, so
  // not currently reachable. Enforced only when the caller knows the credential's issuer
  // (otherwise left to the prior checks).
  if (credentialIssuer !== undefined && issuerId(list.issuer) !== credentialIssuer) {
    return { checked: false, revoked: false, reason: "status list issuer does not match credential issuer" };
  }
  const subject = list.credentialSubject as Record<string, unknown> | undefined;
  if (!subject || subject.type !== BITSTRING_STATUS_LIST) {
    return { checked: false, revoked: false, reason: "not a BitstringStatusList" };
  }
  if (subject.statusPurpose !== entry.statusPurpose) {
    return { checked: false, revoked: false, reason: "statusPurpose mismatch" };
  }

  let bitstring: Uint8Array;
  try {
    bitstring = decodeBitstring(subject.encodedList as string);
  } catch {
    return { checked: false, revoked: false, reason: "invalid encodedList" };
  }
  // Strict base-10 statusListIndex (W3C Bitstring Status List v1.0 §2.1): reject
  // non-conformant values rather than letting Number() silently read bit 0 / a wrong bit.
  const idxRaw = String(entry.statusListIndex).trim();
  if (!/^(0|[1-9][0-9]*)$/.test(idxRaw)) {
    return { checked: false, revoked: false, reason: "malformed statusListIndex" };
  }
  const index = parseInt(idxRaw, 10);
  try {
    return { checked: true, revoked: getBit(bitstring, index), statusPurpose: entry.statusPurpose as StatusPurpose };
  } catch {
    return { checked: false, revoked: false, reason: "status index out of range" };
  }
}
