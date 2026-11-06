// VERIFY-only faithful port of `src/lib/crypto/status-list.ts` — the kernel is
// the source of truth; the golden cross-vectors (`__tests__/golden-vectors.json`)
// break first on any divergence. Do NOT edit semantics independently.
//
// Copied VERBATIM, with the ONLY changes being import specifiers: relative
// imports take an EXPLICIT `.js` extension (the SDK is `module:"Node16"`), and
// `node:zlib` is imported through the package's conditional subpath import
// `#annex-iv-verify/zlib` (package.json "imports"): under the "node" condition
// it IS `node:zlib` (`zlib-node.ts` — byte-identical decoding, incl. the
// gzip-bomb cap on the attacker-controlled `encodedList`); under any other
// condition (browser / worker / edge bundles) it is `zlib-portable.ts`, which
// loads `node:zlib` lazily on first use, so the ROOT `import "@attestry/sdk"`
// no longer pulls `node:zlib` into a non-Node bundle. Do NOT web-ify the codec.
// The sign-side (`createBitstring`/`setBit`/`encodeBitstring`/
// `signStatusListCredential`) is dead-but-private — only `checkRevocationOffline`
// + `resolveRevocationCheckOptions` + `decodeBitstring` + `getBit` + `issuerId` +
// `asEntries` (+ the window/malformed helpers) are verifier-reached.
//
// VERBATIM-COPY FENCE (do NOT narrow): the verify-side status-purpose predicate
// (the `|| e.statusPurpose === 'suspension'` arm), the `subject.statusPurpose ===
// entry.statusPurpose` equality, and `asEntries` (array handling + the `.find`
// skip-non-matching) are load-bearing — the golden vectors V10 (suspension) and
// V11 (multi-entry array) break first if any of them is pruned. Likewise the
// validity-window leg incl. its revocation asymmetry (V12–V16, V23–V25 + the
// hostile P2-12 rows and `outOfWindowRevocations` table) and the malformed-list
// pre-check (V18/V19 + the hostile `malformedLists` table).
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
import { gzipSync, gunzipSync } from "#annex-iv-verify/zlib";
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

/**
 * The issuer-side validity window of a published status-list VC (P2-12):
 * `validUntil = validFrom + STATUS_LIST_VALIDITY_MS` (24 h).
 *
 * Why 24 h: `/.well-known/status-list` is SIGN-ON-SERVE — every request re-signs
 * a fresh list with `validFrom = now`, and the CDN caches a copy for at most
 * `max-age=300` + `stale-while-revalidate=60` (≈ 6 min). An honestly fetched list
 * is therefore minutes old, far inside the window. The window's job is the
 * OTHER direction: it bounds how long a captured PRE-revocation snapshot can be
 * replayed to hide a later revocation (a signed list is otherwise valid
 * forever). 24 h keeps a day of legitimate offline caching for verifiers (the
 * bind is a 10-yr artifact; a verifier may fetch the list once and check many
 * files) while capping that replay window at one day. Verifiers that need a
 * tighter bound pass `maxStatusListAgeMs` to {@link checkRevocationOffline}.
 */
export const STATUS_LIST_VALIDITY_MS = 24 * 60 * 60 * 1000;

/**
 * Default clock-skew tolerance (ms) applied to the status-list `validFrom` /
 * `validUntil` bounds. A sign-on-serve list carries `validFrom = <issuer now>`,
 * so a verifier whose clock runs a few seconds behind the issuer's would
 * otherwise see a freshly fetched list as "not yet valid". 60 s; pass
 * `clockToleranceMs: 0` for the exact `validFrom <= now < validUntil` window.
 */
export const DEFAULT_STATUS_LIST_CLOCK_TOLERANCE_MS = 60_000;

export interface BuildStatusListCredentialInput {
  /** Stable URL where the status list VC is published. */
  id: string;
  issuer: string;
  statusPurpose: StatusPurpose;
  encodedList: string;
  validFrom?: string;
  /** The end of the list's validity window (emitted only when supplied). */
  validUntil?: string;
}

export function buildStatusListCredential(input: BuildStatusListCredentialInput): JsonLdDocument {
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: input.id,
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: input.issuer,
    validFrom: input.validFrom ?? new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    ...(input.validUntil !== undefined ? { validUntil: input.validUntil } : {}),
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
  /**
   * Why the status is unchecked — or, on a revocation confirmed by an authentic
   * list that is outside its validity window, a note saying so.
   */
  reason?: string;
  /**
   * The evaluated list's own `validFrom` / `validUntil` (verbatim strings), surfaced
   * once the list is authenticated + bound to the entry (P2-12) — so a caller can
   * see WHICH window the verdict rests on. Absent when the list never got that far
   * or does not carry the field.
   */
  validFrom?: string;
  validUntil?: string;
  /**
   * True iff the SUPPLIED status list is structurally malformed — not a parsed JSON
   * object (e.g. the raw response TEXT, an array, a number), or an object missing
   * `proof` / `type` / `credentialSubject` (e.g. `{}` or an API envelope). That is
   * a caller error, distinct from an authentic-but-unusable list; the bind
   * verifier treats it as a hard failure (`valid:false`, P2-11). Absent otherwise.
   */
  malformed?: boolean;
}

/** Options for {@link checkRevocationOffline} — the status-list validity window (P2-12). */
export interface RevocationCheckOptions {
  /** The evaluation instant (epoch ms or a `Date`). Default: `Date.now()`. */
  now?: number | Date;
  /**
   * Maximum acceptable list age in ms, measured from the list's `validFrom`. A
   * list older than this — or one without a `validFrom` — is treated as stale ⇒
   * `checked:false`. Default: unbounded (only the list's own window applies).
   */
  maxStatusListAgeMs?: number;
  /** Clock-skew tolerance (ms) on the `validFrom`/`validUntil` bounds. Default {@link DEFAULT_STATUS_LIST_CLOCK_TOLERANCE_MS}. */
  clockToleranceMs?: number;
}

/** {@link RevocationCheckOptions} validated + normalized (the evaluation instant fixed). */
export interface ResolvedRevocationCheckOptions {
  nowMs: number;
  maxStatusListAgeMs: number | undefined;
  clockToleranceMs: number;
}

/**
 * Validate + normalize {@link RevocationCheckOptions}. THROWS a `TypeError` /
 * `RangeError` on a caller usage error (a non-finite `now`, a negative age or
 * tolerance) — never on artifact input. Callers that must surface usage errors
 * before any verification step (the bind verifiers) call this up front.
 */
export function resolveRevocationCheckOptions(options?: RevocationCheckOptions): ResolvedRevocationCheckOptions {
  const opts = options ?? {};
  let nowMs: number;
  if (opts.now === undefined) {
    nowMs = Date.now();
  } else if (opts.now instanceof Date) {
    nowMs = opts.now.getTime();
  } else if (typeof opts.now === "number") {
    nowMs = opts.now;
  } else {
    throw new TypeError("`now` must be an epoch-ms number or a Date");
  }
  if (!Number.isFinite(nowMs)) {
    throw new RangeError("`now` must be a finite epoch-ms number or a valid Date");
  }
  const maxStatusListAgeMs = opts.maxStatusListAgeMs;
  if (
    maxStatusListAgeMs !== undefined &&
    (typeof maxStatusListAgeMs !== "number" || !Number.isFinite(maxStatusListAgeMs) || maxStatusListAgeMs < 0)
  ) {
    throw new RangeError("`maxStatusListAgeMs` must be a finite, non-negative number of milliseconds");
  }
  const clockToleranceMs = opts.clockToleranceMs ?? DEFAULT_STATUS_LIST_CLOCK_TOLERANCE_MS;
  if (typeof clockToleranceMs !== "number" || !Number.isFinite(clockToleranceMs) || clockToleranceMs < 0) {
    throw new RangeError("`clockToleranceMs` must be a finite, non-negative number of milliseconds");
  }
  return { nowMs, maxStatusListAgeMs, clockToleranceMs };
}

// XML-Schema `dateTimeStamp` (VC 2.0 `validFrom`/`validUntil`): a full date-time
// WITH an explicit offset. A zone-less value would parse as verifier-LOCAL time
// (a different instant on every machine), so it is rejected, not guessed.
const DATE_TIME_STAMP_RE = /^(\d{4})-(\d{2})-(\d{2})T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

/** Parse a VC `dateTimeStamp` strictly → epoch ms, or `undefined` if not one. */
function parseDateTimeStamp(value: unknown): number | undefined {
  if (typeof value !== "string") return undefined;
  const m = DATE_TIME_STAMP_RE.exec(value);
  if (!m) return undefined;
  const t = Date.parse(value);
  if (Number.isNaN(t)) return undefined;
  // `Date.parse` silently rolls an impossible calendar date over (2026-02-30 →
  // 2026-03-02); reject it instead of reinterpreting a signed field.
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const cal = new Date(Date.UTC(y, mo - 1, d));
  if (cal.getUTCFullYear() !== y || cal.getUTCMonth() !== mo - 1 || cal.getUTCDate() !== d) return undefined;
  return t;
}

/**
 * The status-list validity-window leg (P2-12): `validFrom <= now < validUntil`
 * (each bound only when present, widened by `clockToleranceMs`), plus the
 * verifier's own `maxStatusListAgeMs` freshness bound. Returns the failure
 * reason, or `undefined` when the list is inside its window. (A failure only
 * withholds a "not revoked" answer — see {@link checkRevocationOffline}.)
 */
function statusListWindowFailure(
  list: Record<string, unknown>,
  opts: ResolvedRevocationCheckOptions,
): string | undefined {
  let validFromMs: number | undefined;
  if (list.validFrom !== undefined) {
    validFromMs = parseDateTimeStamp(list.validFrom);
    if (validFromMs === undefined) return "status list validFrom is not a valid date-time";
  }
  let validUntilMs: number | undefined;
  if (list.validUntil !== undefined) {
    validUntilMs = parseDateTimeStamp(list.validUntil);
    if (validUntilMs === undefined) return "status list validUntil is not a valid date-time";
  }
  if (validFromMs !== undefined && opts.nowMs + opts.clockToleranceMs < validFromMs) {
    return `status list not yet valid (validFrom ${String(list.validFrom)})`;
  }
  if (validUntilMs !== undefined && opts.nowMs - opts.clockToleranceMs >= validUntilMs) {
    return `status list expired (validUntil ${String(list.validUntil)})`;
  }
  if (opts.maxStatusListAgeMs !== undefined) {
    if (validFromMs === undefined) {
      return "status list has no validFrom, so maxStatusListAgeMs cannot be enforced";
    }
    if (opts.nowMs - validFromMs > opts.maxStatusListAgeMs) {
      return `status list is stale (validFrom ${String(list.validFrom)} is older than maxStatusListAgeMs=${opts.maxStatusListAgeMs})`;
    }
  }
  return undefined;
}

/**
 * Structural pre-check of a SUPPLIED status list (P2-11): the reason it is
 * malformed — a non-object, or an object that cannot be a signed status-list VC
 * in any form — or `undefined` when it is shaped like one (authenticity and
 * binding are judged later by the signature + binding legs).
 */
function malformedStatusListReason(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    const kind = Array.isArray(value) ? "an array" : `a ${typeof value}`;
    const hint = typeof value === "string" ? " (pass the parsed JSON object, not the response text)" : "";
    return `malformed status list: expected a JSON object, got ${kind}${hint}`;
  }
  const doc = value as Record<string, unknown>;
  const missing = (["proof", "type", "credentialSubject"] as const).filter(
    (k) => doc[k] === undefined || doc[k] === null,
  );
  if (missing.length > 0) {
    return `malformed status list: missing ${missing.join(", ")}`;
  }
  return undefined;
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
 * signature (same issuer key), bind it to the entry, check the list's validity
 * window (P2-12), then read the bit. Fails SAFE — any defect returns
 * `checked:false` (status unknown), never a false "not revoked". `checked:false`
 * is honest ("verifiable as of issuance; status not checked"), distinct from a
 * confirmed `revoked:false`. The window is asymmetric: outside it a list can no
 * longer confirm "not revoked", but an authentic `revocation` bit is still a
 * confirmed revocation (irreversible). A SUPPLIED list that is structurally
 * malformed is additionally flagged `malformed:true` (P2-11) so callers can fail
 * loudly.
 *
 * Throws only on a caller usage error in `options` (see
 * {@link resolveRevocationCheckOptions}); never on artifact input.
 */
export function checkRevocationOffline(
  credentialStatus: CredentialStatusEntry | CredentialStatusEntry[] | undefined,
  statusListCredential: unknown,
  resolvePublicKey: PublicKeyResolver,
  credentialIssuer?: string,
  options?: RevocationCheckOptions,
): RevocationCheck {
  const opts = resolveRevocationCheckOptions(options);
  const entry = asEntries(credentialStatus).find(
    (e) =>
      e?.type === BITSTRING_STATUS_LIST_ENTRY &&
      (e.statusPurpose === "revocation" || e.statusPurpose === "suspension"),
  );
  if (!entry) return { checked: false, revoked: false, reason: "no status entry" };
  if (statusListCredential === undefined || statusListCredential === null) {
    return { checked: false, revoked: false, reason: "status list not provided (offline)" };
  }
  const malformed = malformedStatusListReason(statusListCredential);
  if (malformed !== undefined) {
    return { checked: false, revoked: false, reason: malformed, malformed: true };
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

  // The list is authenticated + bound: surface its window from here on (P2-12).
  const listWindow: { validFrom?: string; validUntil?: string } = {};
  if (typeof list.validFrom === "string") listWindow.validFrom = list.validFrom;
  if (typeof list.validUntil === "string") listWindow.validUntil = list.validUntil;
  const windowFailure = statusListWindowFailure(list, opts);
  const bit = readStatusBit(subject.encodedList, entry.statusListIndex);

  // Validity window (P2-12) — ASYMMETRIC. An out-of-window (expired /
  // not-yet-valid / stale / unparseable-window) list cannot vouch for "NOT
  // revoked": an earlier signed snapshot would otherwise replay away a later
  // revocation, so that answer becomes unchecked. But a `revocation` bit SET in
  // an AUTHENTIC list is a CONFIRMED revocation regardless of the window: the
  // issuer's signature cannot be forged, and W3C `revocation` is irreversible
  // ("this status is not reversible", Bitstring Status List v1.0 §2.1). A
  // `suspension` bit IS reversible, so an out-of-window suspension stays unchecked.
  if (windowFailure !== undefined) {
    if (bit.ok && bit.set && entry.statusPurpose === "revocation") {
      return {
        checked: true,
        revoked: true,
        statusPurpose: "revocation",
        reason: `revocation confirmed by an authentic status list outside its validity window (${windowFailure})`,
        ...listWindow,
      };
    }
    return { checked: false, revoked: false, reason: windowFailure, ...listWindow };
  }
  if (!bit.ok) return { checked: false, revoked: false, reason: bit.reason, ...listWindow };
  return {
    checked: true,
    revoked: bit.set,
    statusPurpose: entry.statusPurpose as StatusPurpose,
    ...listWindow,
  };
}

/**
 * Decode `encodedList` and read the entry's bit — the reason on any defect
 * (gzip-bomb cap / bad encoding, non-base-10 index, index out of range).
 */
function readStatusBit(
  encodedList: unknown,
  statusListIndex: string | number,
): { ok: true; set: boolean } | { ok: false; reason: string } {
  let bitstring: Uint8Array;
  try {
    bitstring = decodeBitstring(encodedList as string);
  } catch {
    return { ok: false, reason: "invalid encodedList" };
  }
  // Strict base-10 statusListIndex (W3C Bitstring Status List v1.0 §2.1): reject
  // non-conformant values rather than letting Number() silently read bit 0 / a wrong bit.
  const idxRaw = String(statusListIndex).trim();
  if (!/^(0|[1-9][0-9]*)$/.test(idxRaw)) {
    return { ok: false, reason: "malformed statusListIndex" };
  }
  const index = parseInt(idxRaw, 10);
  try {
    return { ok: true, set: getBit(bitstring, index) };
  } catch {
    return { ok: false, reason: "status index out of range" };
  }
}
