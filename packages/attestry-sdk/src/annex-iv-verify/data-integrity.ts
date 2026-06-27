// VERIFY-only faithful port of `src/lib/crypto/data-integrity.ts` — the kernel
// is the source of truth; the golden cross-vectors (`__tests__/golden-vectors.json`)
// break first on any divergence. Do NOT edit semantics independently.
//
// Copied VERBATIM, with the ONLY change being the relative-import rewrite to an
// EXPLICIT `.js` extension (the SDK is `module:"Node16"` — a bare relative
// specifier emits TS2835). Package imports (`canonicalize`) are unchanged. The
// sign-side (`signDocument`, `ed25519Sign`) is dead-but-private — only
// `verifyDocument` / `eddsaJcsVerifyData` / the types are verifier-reached.
/**
 * W3C Verifiable Credential **Data Integrity** proofs — `eddsa-jcs-2022`.
 *
 * A conformant, dependency-light implementation of the `eddsa-jcs-2022`
 * cryptosuite (W3C VC-DI-EdDSA v1.0). It is byte-compatible with
 * `@digitalbazaar/eddsa-jcs-2022-cryptosuite` (pinned in the conformance test):
 *
 *   verifyData = SHA-256( JCS(proofConfig without proofValue) )
 *              ‖ SHA-256( JCS(document without proof) )
 *   proofValue = "z" + base58btc( Ed25519.sign(verifyData) )
 *
 * where JCS = RFC-8785 (`canonicalize`, the same package + call the reference
 * uses) and the proof's `@context` mirrors the document's (matching the
 * reference's sign/verify behaviour).
 *
 * Pure + resolver-injected: it never reads a DB, a Vault, or env. Signing takes
 * a raw private key; verification takes a public-key resolver. This is what lets
 * `/verify` run **offline** — public key + credential in, valid/invalid out.
 */
import canonicalize from "canonicalize";
import { ed25519Sign, ed25519Verify, sha256 } from "./ed25519.js";
import { encodeMultibaseBase58btc, decodeMultibaseBase58btc } from "./multibase.js";

export const EDDSA_JCS_2022 = "eddsa-jcs-2022";
export const DATA_INTEGRITY_PROOF = "DataIntegrityProof";
export const ASSERTION_METHOD = "assertionMethod";

export interface DataIntegrityProof {
  type: typeof DATA_INTEGRITY_PROOF;
  cryptosuite: typeof EDDSA_JCS_2022;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  /** Mirrors the secured document's `@context` (per the cryptosuite). */
  "@context"?: unknown;
}

export type JsonLdDocument = Record<string, unknown> & { "@context": unknown };
export type SecuredDocument<T extends JsonLdDocument = JsonLdDocument> = T & {
  proof: DataIntegrityProof;
};

export interface SignOptions {
  /** Raw 32-byte Ed25519 secret key. */
  privateKey: Uint8Array;
  /** e.g. `https://attestry.ai/.well-known/keys#key-2026-05`. */
  verificationMethod: string;
  /** ISO-8601 `created`; injectable for deterministic tests. Defaults to now (seconds precision). */
  created?: string;
  proofPurpose?: string;
}

export interface VerifyResult {
  verified: boolean;
  reason?: string;
  verificationMethod?: string;
}

/** Resolve a verificationMethod URL to its raw 32-byte Ed25519 public key. Return null/undefined ⇒ fail closed. */
export type PublicKeyResolver = (
  verificationMethod: string,
) => Uint8Array | null | undefined;

// ─── Internals ───────────────────────────────────────────────────────────────

const textEncoder = new TextEncoder();

function jcsHash(value: unknown): Uint8Array {
  const jcs = canonicalize(value);
  if (typeof jcs !== "string") {
    throw new Error("JCS canonicalization produced no output");
  }
  return sha256(textEncoder.encode(jcs));
}

/** verifyData = H(JCS(proofConfig)) ‖ H(JCS(document)); proofConfig must already exclude proofValue, document must exclude proof. */
function createVerifyData(
  unsecuredDocument: JsonLdDocument,
  proofConfig: Record<string, unknown>,
): Uint8Array {
  const proofHash = jcsHash(proofConfig);
  const docHash = jcsHash(unsecuredDocument);
  const out = new Uint8Array(proofHash.length + docHash.length);
  out.set(proofHash, 0);
  out.set(docHash, proofHash.length);
  return out;
}

/**
 * The `eddsa-jcs-2022` pre-signature hash: H(JCS(proofConfig)) ‖ H(JCS(document)).
 * `proofConfig` must already exclude `proofValue`; `document` must exclude `proof`.
 * Exposed so the conformance test can byte-compare against the reference cryptosuite.
 */
export const eddsaJcsVerifyData = createVerifyData;

function toW3cDate(date: Date): string {
  // VC `created` convention: second-precision UTC (drop milliseconds).
  return date.toISOString().replace(/\.\d{1,}Z$/, "Z");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asContextArray(ctx: unknown): unknown[] {
  return Array.isArray(ctx) ? ctx : [ctx];
}

/** True iff `docCtx` begins with every entry of `proofCtx`, in order (the cryptosuite's safety check). */
function contextStartsWith(docCtx: unknown, proofCtx: unknown): boolean {
  const d = asContextArray(docCtx);
  const p = asContextArray(proofCtx);
  if (p.length > d.length) return false;
  for (let i = 0; i < p.length; i++) {
    if (JSON.stringify(p[i]) !== JSON.stringify(d[i])) return false;
  }
  return true;
}

// ─── Sign ──────────────────────────────────────────────────────────────────--

/**
 * Attach an `eddsa-jcs-2022` DataIntegrityProof to a JSON-LD document.
 * Any pre-existing `proof` on the input is excluded from the signed bytes.
 */
export function signDocument<T extends JsonLdDocument>(
  document: T,
  options: SignOptions,
): SecuredDocument<T> {
  if (document["@context"] === undefined) {
    throw new Error("Document must have an @context to sign");
  }
  // Document without any existing proof — these are the bytes we hash.
  const { proof: _existingProof, ...unsecured } = document as Record<string, unknown>;

  const proofConfig: Record<string, unknown> = {
    "@context": (unsecured as JsonLdDocument)["@context"],
    type: DATA_INTEGRITY_PROOF,
    cryptosuite: EDDSA_JCS_2022,
    created: options.created ?? toW3cDate(new Date()),
    verificationMethod: options.verificationMethod,
    proofPurpose: options.proofPurpose ?? ASSERTION_METHOD,
  };

  const verifyData = createVerifyData(unsecured as JsonLdDocument, proofConfig);
  const signature = ed25519Sign(verifyData, options.privateKey);

  const proof: DataIntegrityProof = {
    ...(proofConfig as Omit<DataIntegrityProof, "proofValue">),
    proofValue: encodeMultibaseBase58btc(signature),
  };

  return { ...(unsecured as T), proof };
}

// ─── Verify (DB-free) ─────────────────────────────────────────────────────────

/**
 * Verify an `eddsa-jcs-2022` secured document against a resolver-supplied public
 * key. No DB, no network: the caller decides how the verificationMethod resolves
 * (inline JWK, fetched controller doc, or the config key-registry). Fails CLOSED
 * on every structural defect, unresolved key, or signature mismatch.
 */
export function verifyDocument(
  securedDocument: unknown,
  resolvePublicKey: PublicKeyResolver,
): VerifyResult {
  if (!isObject(securedDocument)) {
    return { verified: false, reason: "Secured document is not an object" };
  }
  const proof = securedDocument.proof;
  if (!isObject(proof)) {
    return { verified: false, reason: "Missing or malformed proof" };
  }
  if (proof.type !== DATA_INTEGRITY_PROOF) {
    return { verified: false, reason: `Unsupported proof type: ${String(proof.type)}` };
  }
  if (proof.cryptosuite !== EDDSA_JCS_2022) {
    return { verified: false, reason: `Unsupported cryptosuite: ${String(proof.cryptosuite)}` };
  }
  if (proof.proofPurpose !== ASSERTION_METHOD) {
    return { verified: false, reason: `Unsupported proofPurpose: ${String(proof.proofPurpose)}` };
  }
  if (typeof proof.verificationMethod !== "string") {
    return { verified: false, reason: "Missing verificationMethod" };
  }
  if (typeof proof.proofValue !== "string" || proof.proofValue.length > 120) {
    // A valid Ed25519 proofValue is ~89 chars; bound it before the O(n²) base58
    // decode so an oversized string can't burn CPU (DoS) on the public route.
    return { verified: false, reason: "Missing or oversized proofValue", verificationMethod: proof.verificationMethod };
  }

  const verificationMethod = proof.verificationMethod;
  const publicKey = resolvePublicKey(verificationMethod);
  if (!publicKey) {
    return { verified: false, reason: `Unresolved verificationMethod: ${verificationMethod}`, verificationMethod };
  }

  let signature: Uint8Array;
  try {
    signature = decodeMultibaseBase58btc(proof.proofValue);
  } catch {
    return { verified: false, reason: "Invalid proofValue encoding", verificationMethod };
  }

  const { proof: _p, ...unsecured } = securedDocument as Record<string, unknown>;
  const { proofValue: _pv, ...proofConfig } = proof as Record<string, unknown>;

  // Mirror the reference: a proof.@context must be a prefix of the document's,
  // and the document is hashed under the proof's @context.
  if (proofConfig["@context"] !== undefined) {
    if (!contextStartsWith((unsecured as JsonLdDocument)["@context"], proofConfig["@context"])) {
      return {
        verified: false,
        reason: "Document @context does not start with proof @context",
        verificationMethod,
      };
    }
    (unsecured as Record<string, unknown>)["@context"] = proofConfig["@context"];
  }

  const verifyData = createVerifyData(unsecured as JsonLdDocument, proofConfig);
  const ok = ed25519Verify(signature, verifyData, publicKey);
  return ok
    ? { verified: true, verificationMethod }
    : { verified: false, reason: "Signature verification failed", verificationMethod };
}
