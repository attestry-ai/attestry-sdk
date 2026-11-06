// VERIFY-only faithful port of the bind verify-core of
// `src/lib/annex-iv/cryptobind.ts` — the kernel `verifyAnnexIvBind` is the
// source of truth; the golden cross-vectors (`__tests__/golden-vectors.json`)
// break first on any divergence. Do NOT edit semantics independently.
//
// This is the ONE HAND-WRITTEN file in the port (the 5 crypto files are
// verbatim copies). It carries the verify-core ONLY — the sign-side
// (`signAnnexIvBind`, `buildAnnexIvBindPayload`, `cryptobindTechnicalFilePdf`,
// the renderer, the key-registry) is NOT ported; the SDK never mints. Imports
// are rewritten to explicit `.js` extensions (the SDK is `module:"Node16"`).
//
// Two intentional divergences from the kernel SOURCE TEXT that are NOT semantic
// divergences (verdict-identity is preserved — the probe proved it):
//   1. `AnnexIvBindError` is a LOCAL `class extends Error` (the kernel's extends
//      the abstract `AnnexIvError` with `code`/`httpStatus`; the verify path
//      reads ONLY `e.message` via the step-0 catch, never class identity / code /
//      httpStatus). Every thrown MESSAGE string is preserved VERBATIM.
//   2. `verifyAnnexIvBindOffline` has NO env-registry default resolver — it
//      requires caller-supplied key material (`resolvePublicKey` or `jwks`) per
//      the SDK contract; the kernel's default `resolvePublicKeyByVerificationMethod`
//      is server-only.
//   3. A caller USAGE error in the options (`requireRevocationCheck` not a
//      boolean; a bad `now` / `maxStatusListAgeMs` / `clockToleranceMs`) is
//      re-thrown as a typed `AttestryError` carrying the kernel's message (the
//      kernel throws the bare `TypeError`/`RangeError`). Same precondition, same
//      point (before step 0), never a verdict.

import { AttestryError } from "../errors.js";
import { base64urlToBytes } from "./jwk.js";
import { ed25519Verify, sha256 } from "./ed25519.js";
import { type PublicKeyResolver } from "./data-integrity.js";
import {
  BITSTRING_STATUS_LIST_ENTRY,
  checkRevocationOffline,
  resolveRevocationCheckOptions,
  type CredentialStatusEntry,
  type ResolvedRevocationCheckOptions,
  type RevocationCheck,
} from "./status-list.js";
import { makeJwksResolver, type Ed25519PublicJwk } from "./resolver.js";

// ─── Constants (verbatim from cryptobind.ts) ───────────────────────────────--

/** The domain-separation tag — verifier-ENFORCED (step 0). */
export const ANNEX_IV_BIND_TYPE = "ANNEX-IV-BIND-v1";
/** The JWS protected-header `typ` — a second, header-level domain tag. */
export const ANNEX_IV_BIND_JWS_TYP = "application/annex-iv-bind-v1+jws";
/** The JWS signature algorithm (Ed25519). */
export const ANNEX_IV_BIND_ALG = "EdDSA";
/** The honest temporal label for the JWS path (declared N/A by design). */
export const ANNEX_IV_BIND_SIGNING_TIME_LABEL =
  "issuer-asserted signing time, not independently timestamped";

// ─── Local typed error (C-C-1) ──────────────────────────────────────────────-
//
// The kernel's `AnnexIvBindError extends AnnexIvError` (an abstract base with
// `code`/`httpStatus`, used by the route mapper). The verify path NEVER reads
// class identity / `code` / `httpStatus` — only `e.message` (via the step-0
// catch below) — so a minimal local `extends Error` is verdict-identical. The
// thrown message strings are preserved verbatim from `parseAnnexIvBindJws`.
class AnnexIvBindError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnnexIvBindError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ─── Payload + envelope shapes (verbatim) ──────────────────────────────────--

/** The signed `ANNEX-IV-BIND-v1` payload — the full triple + binding fields. */
export interface AnnexIvBindPayload {
  /** Domain-separation tag (literal {@link ANNEX_IV_BIND_TYPE}). */
  type: typeof ANNEX_IV_BIND_TYPE;
  /** The Attestry issuer id (the same value the status-list VC carries). */
  issuer: string;
  /** `"sha256:" + 64hex` of the EXACT emitted PDF Buffer. */
  pdf_byte_sha256: string;
  /** `attestations.certificateHash` for the file's current attestation cert. */
  attestation_certificate_hash: string;
  /** `evidencePacks.contentHash[]` (`sha256:<hex>`) — DEDUPED then sorted ascending. */
  evidence_pack_content_hashes: string[];
  /** The file's `signedAt`, ISO-8601 UTC second-precision (issuer-asserted signing time). */
  issued_at: string;
  /** The active signing-key id. */
  kid: string;
  /** The FULL `verificationMethod` URL: `<keysBaseUrl>#<kid>`. */
  verificationMethod: string;
  /** The published status-list VC URL. */
  status_list_ref: string;
  /** The per-file UNIQUE revocation index. */
  status_list_index: number;
  /** A `BitstringStatusListEntry`-shaped object driving offline revocation. */
  credentialStatus: CredentialStatusEntry;
}

/** A parsed compact JWS (the three base64url segments + decoded header/payload). */
export interface ParsedAnnexIvBindJws {
  protectedB64: string;
  payloadB64: string;
  signatureB64: string;
  header: Record<string, unknown>;
  payload: AnnexIvBindPayload;
}

// ─── Internals (verbatim) ──────────────────────────────────────────────────--

const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
const BIND_HASH_RE = /^sha256:[0-9a-f]{64}$/;
const textEncoder = new TextEncoder();

/** Lowercase 64-hex SHA-256 of `bytes`, prefixed `sha256:` (the repo convention). */
function sha256Prefixed(bytes: Uint8Array): string {
  const hashBytes = sha256(bytes);
  let hex = "";
  for (const b of hashBytes) hex += b.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

/**
 * Parse a compact `ANNEX-IV-BIND-v1` JWS into its segments + decoded
 * header/payload. Fails closed on a malformed serialization, wrong segment
 * count, absent domain tags, a protected-header `alg` other than `EdDSA`, or any
 * `crit` header. Does NOT verify the signature.
 */
export function parseAnnexIvBindJws(jws: string): ParsedAnnexIvBindJws {
  if (typeof jws !== "string") {
    throw new AnnexIvBindError("JWS must be a string");
  }
  const parts = jws.split(".");
  if (parts.length !== 3) {
    throw new AnnexIvBindError(`compact JWS must have 3 segments, got ${parts.length}`);
  }
  const [protectedB64, payloadB64, signatureB64] = parts;
  let header: Record<string, unknown>;
  let payload: AnnexIvBindPayload;
  try {
    header = JSON.parse(Buffer.from(base64urlToBytes(protectedB64)).toString("utf8")) as Record<string, unknown>;
    payload = JSON.parse(Buffer.from(base64urlToBytes(payloadB64)).toString("utf8")) as AnnexIvBindPayload;
  } catch (e) {
    throw new AnnexIvBindError(`malformed JWS segment: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (header === null || typeof header !== "object" || Array.isArray(header)) {
    throw new AnnexIvBindError("malformed JWS protected header: not a JSON object");
  }
  if (header.typ !== ANNEX_IV_BIND_JWS_TYP) {
    throw new AnnexIvBindError(`unexpected JWS typ: ${JSON.stringify(header.typ)}`);
  }
  // RFC 7515 §4.1.1 / RFC 8725 §3.1: the verifier PINS the algorithm — it never
  // takes it from the attacker-controlled header. Only `EdDSA` (Ed25519) is
  // accepted; `none`, `HS256`, an absent `alg`, etc. are rejected outright, even
  // over an otherwise-valid Ed25519 signature.
  if (header.alg !== ANNEX_IV_BIND_ALG) {
    throw new AnnexIvBindError(
      `unexpected JWS alg: ${JSON.stringify(header.alg)} (only ${JSON.stringify(ANNEX_IV_BIND_ALG)} is accepted)`,
    );
  }
  // RFC 7515 §4.1.11: a `crit` header names extensions the recipient MUST
  // understand. This verifier implements none, so any `crit` is rejected.
  if (header.crit !== undefined) {
    throw new AnnexIvBindError(`unsupported JWS crit header: ${JSON.stringify(header.crit)}`);
  }
  if (payload?.type !== ANNEX_IV_BIND_TYPE) {
    throw new AnnexIvBindError(`unexpected payload type: ${JSON.stringify(payload?.type)}`);
  }
  return { protectedB64, payloadB64, signatureB64, header, payload };
}

/**
 * The MINIMAL internal signature verify: `ed25519Verify` over the RECEIVED
 * `protected_b64 ‖ "." ‖ payload_b64` octets (RFC-7515 §5.2 — NEVER
 * re-canonicalize/re-encode at verify), against the resolver-supplied public
 * key. Returns a boolean; never throws.
 */
export function verifyAnnexIvBindReceivedOctets(
  parsed: ParsedAnnexIvBindJws,
  publicKey: Uint8Array | null | undefined,
): boolean {
  if (!publicKey) return false;
  let signature: Uint8Array;
  try {
    signature = base64urlToBytes(parsed.signatureB64);
  } catch {
    return false;
  }
  const signingInput = textEncoder.encode(`${parsed.protectedB64}.${parsed.payloadB64}`);
  return ed25519Verify(signature, signingInput, publicKey);
}

// ─── The verifier result + input (verbatim result; SDK-tailored input) ──────--

/** The structured, fail-closed result of {@link verifyAnnexIvBindOffline}. */
export interface VerifyAnnexIvBindResult {
  /**
   * Overall verdict: tag ∧ fields ∧ signature ∧ byte-hash ∧ not-a-confirmed-revocation
   * ∧ a well-formed supplied status list (∧ a CHECKED revocation status when
   * `requireRevocationCheck` is set). NOTE: by default `valid:true` does NOT mean
   * "not revoked" — act on {@link VerifyAnnexIvBindResult.trustworthy}.
   */
  valid: boolean;
  /** The first failing step (0–4) or the revocation-leg failure — for diagnostics. */
  reason?: string;
  /**
   * The single safe-to-act-on verdict (P2-11): `valid && revocation.checked &&
   * !revocation.revoked` — the artifact verifies AND a fresh, authentic status
   * list confirmed it is NOT revoked. `valid:true` with `trustworthy:false` means
   * "intact as issued, revocation status unknown".
   */
  trustworthy: boolean;
  /** True once the protected-header + payload domain tags both matched (step 0). */
  tagOk: boolean;
  /** True once every bind field was present + well-typed (step 1). */
  fieldsOk: boolean;
  /** True once `ed25519Verify` over the RECEIVED octets passed (step 3). */
  signatureOk: boolean;
  /** True once `sha256(suppliedPdfBytes) === payload.pdf_byte_sha256` (step 4). */
  byteBindingOk: boolean;
  /**
   * The two-check revocation result (step 6). `checked:false` is the honest
   * "status not evaluated" label (no cached list / offline) — never a false
   * "not revoked".
   */
  revocation: RevocationCheck;
  /**
   * Temporal is declared N/A for the JWS path: a 10-yr Art-18 artifact has no
   * validity window — invalidation is revocation, and `issued_at` is the
   * labelled issuer-asserted signing time, not a window.
   */
  temporal: {
    applicable: false;
    issuedAt: string | null;
    /** {@link ANNEX_IV_BIND_SIGNING_TIME_LABEL}. */
    label: string;
  };
}

/**
 * Inputs to {@link verifyAnnexIvBindOffline} — sidecar + PDF bytes + key
 * material, NO DB, NO network.
 *
 * Key resolution precedence: `resolvePublicKey` (if given) → else a resolver
 * built from `jwks` → else a typed `AttestryError` (missing key material).
 */
export interface VerifyAnnexIvBindOfflineInput {
  /** The compact RFC-7515 sidecar JWS (the `bind_artifact` / `sidecarJws`). */
  sidecarJws: string;
  /** The PDF bytes to byte-bind against `payload.pdf_byte_sha256` (step 4). */
  pdfBytes: Uint8Array;
  /**
   * A cached/out-of-band status-list VC for the two-check revocation (step 6) —
   * the PARSED JSON object (`await res.json()`, not `res.text()`). Omitted (or
   * `null`) ⇒ `revocation.checked = false` (honest "status not evaluated"). A
   * supplied value that is not a JSON object or lacks `proof`/`type`/
   * `credentialSubject` ⇒ `valid:false` with `revocation.malformed: true` (P2-11).
   */
  cachedStatusListCredential?: unknown;
  /**
   * How the envelope's FULL `verificationMethod` URL resolves to a raw public
   * key (step 2). Takes precedence over `jwks`. A resolver that returns
   * null/undefined ⇒ fail-closed `valid:false`. A resolver that THROWS
   * PROPAGATES (verdict-identity with the kernel — it calls the resolver bare).
   */
  resolvePublicKey?: PublicKeyResolver;
  /**
   * A JWKS (an array of public JWKs, or a `{ keys }` object). When
   * `resolvePublicKey` is absent, a fail-closed resolver is built from this via
   * `makeJwksResolver` (kid-match → `null` on a bad/absent entry, never throws).
   */
  jwks?: Ed25519PublicJwk[] | { keys: Ed25519PublicJwk[] };
  /**
   * P2-11: when `true`, a revocation status that could NOT be checked (no list,
   * an untrusted / mismatched / expired / stale list, …) is a hard failure —
   * `valid:false`, `reason: "revocation not checked: …"`. Default `false`
   * (backward compatible: unchecked leaves `valid` standing; read `trustworthy`).
   */
  requireRevocationCheck?: boolean;
  /** P2-12: the instant the status-list validity window is evaluated at (epoch ms or Date). Default: now. */
  now?: number | Date;
  /** P2-12: reject (as unchecked) a status list whose `validFrom` is older than this many ms. */
  maxStatusListAgeMs?: number;
  /** P2-12: clock-skew tolerance (ms) on the status-list window bounds. Default 60 000. */
  clockToleranceMs?: number;
}

// ─── Fail-closed result helpers (verbatim) ──────────────────────────────────-

/** A fail-closed INVALID result carrying the failing step + the (partial) flags. */
function bindInvalid(
  reason: string,
  flags: Partial<VerifyAnnexIvBindResult> = {},
): VerifyAnnexIvBindResult {
  return {
    valid: false,
    reason,
    trustworthy: false,
    tagOk: false,
    fieldsOk: false,
    signatureOk: false,
    byteBindingOk: false,
    revocation: { checked: false, revoked: false, reason: "not evaluated" },
    temporal: { applicable: false, issuedAt: null, label: ANNEX_IV_BIND_SIGNING_TIME_LABEL },
    ...flags,
  };
}

/** True iff every bind field on the parsed payload is present + well-typed (step 1). */
function allBindFieldsWellTyped(p: AnnexIvBindPayload): boolean {
  return (
    typeof p.pdf_byte_sha256 === "string" &&
    BIND_HASH_RE.test(p.pdf_byte_sha256) &&
    typeof p.attestation_certificate_hash === "string" &&
    p.attestation_certificate_hash.length > 0 &&
    Array.isArray(p.evidence_pack_content_hashes) &&
    p.evidence_pack_content_hashes.every((h) => typeof h === "string" && SHA256_HEX_RE.test(h)) &&
    typeof p.issued_at === "string" &&
    p.issued_at.length > 0 &&
    typeof p.kid === "string" &&
    p.kid.length > 0 &&
    typeof p.verificationMethod === "string" &&
    p.verificationMethod.length > 0 &&
    typeof p.status_list_ref === "string" &&
    p.status_list_ref.length > 0 &&
    Number.isInteger(p.status_list_index) &&
    p.status_list_index >= 0 &&
    typeof p.issuer === "string" &&
    p.issuer.length > 0 &&
    p.credentialStatus != null &&
    typeof p.credentialStatus === "object"
  );
}

// ─── The OFFLINE verifier (verbatim logic; SDK key-resolution) ──────────────--

/**
 * The OFFLINE Annex IV bind verifier: sidecar + PDF bytes + key material →
 * valid/invalid, **NO DB, NO network**. The faithful SDK port of the kernel's
 * `verifyAnnexIvBind` (same ordered, fail-closed steps; the kernel is the
 * source of truth and the golden cross-vectors break first on divergence):
 *
 *   0. Domain-tag assert — the protected-header `typ` AND the payload `type`
 *      both match (parse fails closed otherwise). A validly-signed attestation /
 *      status-list VC fed here is rejected ON THE TAG, not the hash.
 *   1. Every bind field present + well-typed — fail-closed on ANY absence.
 *   2. Resolve the key OFFLINE from the envelope's FULL `verificationMethod` URL
 *      (precedence: `resolvePublicKey` → `jwks`→`makeJwksResolver` → typed throw).
 *   3. `ed25519Verify` over the RECEIVED `protected_b64 ‖ "." ‖ payload_b64`
 *      octets — NEVER re-canonicalize/re-encode at verify (RFC-7515 §5.2).
 *   4. Byte-binding (AFTER 0–3): `sha256(suppliedPdfBytes)` vs `pdf_byte_sha256`.
 *   5. Temporal — declared N/A (10-yr artifact; invalidation = revocation).
 *   6. Two-check revocation — `checkRevocationOffline(credentialStatus, cached,
 *      resolver, issuer, window)` (the issuer-binding + validity-window legs);
 *      VALID requires signature-valid AND bit-not-revoked; no cached list ⇒
 *      `checked:false`. A SUPPLIED-but-malformed list ⇒ INVALID (P2-11); an
 *      unchecked status ⇒ INVALID only under `requireRevocationCheck`.
 *      `trustworthy` is `valid ∧ checked ∧ ¬revoked`.
 *
 * THROW/NEVER-THROW CONTRACT (the single source of truth):
 *   - Throws ONLY the typed usage-error preconditions (`AttestryError`) —
 *     missing key material, or a bad `requireRevocationCheck` / `now` /
 *     `maxStatusListAgeMs` / `clockToleranceMs` — NOT a verification failure.
 *   - NEVER throws on a malformed/forged JSON ARTIFACT (sidecar / pdf /
 *     statusList → fail-closed `valid:false`; the per-guard hostile table pins
 *     the tampered-list cases). CAVEAT: a `cachedStatusListCredential` HAND-BUILT
 *     with a non-JSON-representable value (NaN / Infinity / BigInt / a circular
 *     ref) in a canonicalized field propagates the JCS `canonicalize` throw —
 *     verdict-IDENTICAL with the kernel oracle (a JSON-sourced cached VC, the
 *     documented path, cannot carry these); a loud catchable error, NEVER a
 *     false `valid:true`.
 *   - A caller-supplied `resolvePublicKey` that THROWS **propagates** (the
 *     kernel calls the resolver bare at both the signature leg and the
 *     revocation leg — the SDK re-throws to stay verdict-identical). This is
 *     DISTINCT from a resolver that RETURNS null (→ `valid:false` "public key
 *     did not resolve offline") and from `makeJwksResolver`'s deliberate
 *     fail-closed-to-null on a bad/absent jwks entry.
 */
export function verifyAnnexIvBindOffline(
  input: VerifyAnnexIvBindOfflineInput,
): VerifyAnnexIvBindResult {
  // Key-resolution precedence (C-D2). A missing-key-material precondition is a
  // loud, typed usage error — never a bare TypeError, never a verification fail.
  let resolvePublicKey: PublicKeyResolver;
  if (input.resolvePublicKey) {
    resolvePublicKey = input.resolvePublicKey;
  } else if (input.jwks) {
    resolvePublicKey = makeJwksResolver(input.jwks);
  } else {
    throw new AttestryError(
      "verifyAnnexIvBindOffline requires key material: pass `resolvePublicKey` or `jwks`",
    );
  }
  // The window/policy options — the same usage-error preconditions, in the same
  // order, as the kernel (divergence 3: re-thrown as a typed AttestryError).
  let requireRevocationCheck: boolean;
  let revocationWindow: ResolvedRevocationCheckOptions;
  try {
    if (input.requireRevocationCheck !== undefined && typeof input.requireRevocationCheck !== "boolean") {
      throw new TypeError("`requireRevocationCheck` must be a boolean");
    }
    requireRevocationCheck = input.requireRevocationCheck === true;
    revocationWindow = resolveRevocationCheckOptions({
      now: input.now,
      maxStatusListAgeMs: input.maxStatusListAgeMs,
      clockToleranceMs: input.clockToleranceMs,
    });
  } catch (e) {
    throw new AttestryError(`verifyAnnexIvBindOffline: ${e instanceof Error ? e.message : String(e)}`);
  }

  // Step 0 — parse + domain-tag assert. `parseAnnexIvBindJws` fails closed on a
  // wrong segment count, malformed JSON, a mismatched/absent `typ`/`type` tag, a
  // header `alg` other than EdDSA, or any `crit` header.
  let parsed: ParsedAnnexIvBindJws;
  try {
    parsed = parseAnnexIvBindJws(input.sidecarJws);
  } catch (e) {
    return bindInvalid(`domain tag / parse: ${e instanceof Error ? e.message : String(e)}`);
  }
  const payload = parsed.payload;

  // Step 1 — every bind field present + well-typed (fail-closed on ANY absence).
  if (!allBindFieldsWellTyped(payload)) {
    return bindInvalid("missing or ill-typed bind field", {
      tagOk: true,
      temporal: {
        applicable: false,
        issuedAt: typeof payload.issued_at === "string" ? payload.issued_at : null,
        label: ANNEX_IV_BIND_SIGNING_TIME_LABEL,
      },
    });
  }

  const temporal = {
    applicable: false as const,
    issuedAt: payload.issued_at,
    label: ANNEX_IV_BIND_SIGNING_TIME_LABEL,
  };

  // Step 2 — resolve the key OFFLINE from the FULL verificationMethod URL. A
  // caller-supplied resolver that throws PROPAGATES (bare call — verdict-identity).
  const publicKey = resolvePublicKey(payload.verificationMethod);
  if (!publicKey) {
    return bindInvalid("public key did not resolve offline", { tagOk: true, fieldsOk: true, temporal });
  }

  // Step 3 — verify over the RECEIVED octets (no re-canonicalization).
  const signatureOk = verifyAnnexIvBindReceivedOctets(parsed, publicKey);
  if (!signatureOk) {
    return bindInvalid("signature invalid over the received octets", {
      tagOk: true,
      fieldsOk: true,
      temporal,
    });
  }

  // Step 4 — byte-binding (AFTER 0–3): sha256(supplied bytes) vs pdf_byte_sha256.
  const byteBindingOk = sha256Prefixed(input.pdfBytes) === payload.pdf_byte_sha256;
  if (!byteBindingOk) {
    return bindInvalid("PDF byte-hash does not match the signed pdf_byte_sha256", {
      tagOk: true,
      fieldsOk: true,
      signatureOk: true,
      temporal,
    });
  }

  // Step 6 — two-check revocation (incl. the issuer-binding + validity-window
  // legs). The revocation leg also calls the resolver bare (a throw propagates).
  // A confirmed revocation (checked AND revoked) FAILS; a supplied list that is
  // structurally MALFORMED fails loudly (P2-11 — a caller error such as passing
  // the response text, never a silent "unchecked"); an unchecked status
  // otherwise leaves the verdict standing, honestly labelled `checked:false` —
  // unless the caller set `requireRevocationCheck`.
  const revocation = checkRevocationOffline(
    payload.credentialStatus,
    input.cachedStatusListCredential,
    resolvePublicKey,
    payload.issuer,
    {
      now: revocationWindow.nowMs,
      maxStatusListAgeMs: revocationWindow.maxStatusListAgeMs,
      clockToleranceMs: revocationWindow.clockToleranceMs,
    },
  );
  let failure: string | undefined;
  if (revocation.checked && revocation.revoked) {
    failure = "revoked";
  } else if (revocation.malformed === true) {
    failure = revocation.reason ?? "malformed status list";
  } else if (requireRevocationCheck && !revocation.checked) {
    failure = `revocation not checked: ${revocation.reason ?? "unknown"}`;
  }
  const valid = failure === undefined;

  return {
    valid,
    reason: failure,
    trustworthy: valid && revocation.checked && !revocation.revoked,
    tagOk: true,
    fieldsOk: true,
    signatureOk: true,
    byteBindingOk: true,
    revocation,
    temporal,
  };
}

// Re-export the entry-shaped type + the revocation-check shape for consumers
// that want the full structured result types.
export { BITSTRING_STATUS_LIST_ENTRY };
export type { CredentialStatusEntry, RevocationCheck };
