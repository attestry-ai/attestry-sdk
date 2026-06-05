// ─── EvidencePack resource ──────────────────────────────────────────────────
//
// Wraps the KE2 P1 evidence-pack surface (P1.2 + P1.3 generator + REST,
// + the P1.4 lifecycle/export routes added to the SDK in P1.8):
//
//   - POST /api/v1/evidence-packs                     create a draft pack
//   - GET  /api/v1/evidence-packs/{id}                get pack + bundle list
//   - GET  /api/v1/evidence-packs                     list packs (cursor-paginated)
//   - POST /api/v1/evidence-packs/{id}/bundles        append a reperformance bundle
//   - POST /api/v1/evidence-packs/{id}/sign           sign a draft pack            (P1.8)
//   - POST /api/v1/evidence-packs/{id}/supersede      supersede a signed pack      (P1.8)
//   - POST /api/v1/evidence-packs/{id}/revoke         revoke a signed pack         (P1.8)
//   - GET  /api/v1/evidence-packs/{id}/export         export an artifact (json/pdf/zip) (P1.8)
//
// Tenth resource on `@attestry/sdk`. Sibling to `IncidentsResource`,
// `DecisionsResource`, `ChatResource`, `AuditLogResource`,
// `RegulatoryChangesResource`, `ComplianceCheckResource`, `CheckResource`,
// `GateResource`, `VisionResource`. Resource-class-per-kernel-resource
// convention (carry-forward invariant #43).
//
// **Scope** — P1.6 (2026-05-18) shipped the 4 core methods (`create`,
// `get`, `list`, `addBundle`). P1.8 (founder-ratified 2026-05-23) adds
// the 4 P1.4 lifecycle/export methods (`sign` / `supersede` / `revoke`
// / `export`), mirroring the shipped REST routes (P1.4) + MCP tools
// (P1.7) — eight methods total. The MCP `confirm` intentionality gate on
// `sign`/`revoke` (P1.7 DQ-1) is an MCP-layer affordance with NO
// REST/SDK equivalent and is NOT mirrored here.
//
// **`export` returns a non-JSON artifact** (P1.8 DEV-73) — unlike every
// other method (JSON `{success,data}` envelope via `_request`), the
// kernel export route returns the RAW artifact on success (json =
// `{export,pack,bundles}`; pdf = `Uint8Array`; zip = `ReadableStream`)
// with a download `Content-Disposition`, and the standard error
// envelope on failure. `export` therefore routes through the transport's
// `_streamRequest` (un-consumed `Response`; per-format content-type
// guard; non-2xx → `AttestryAPIError`) and returns a faithful-courier
// wrapper `EvidencePackExportResult` — it does NOT consume/`validatePack`
// the body (same discipline as `decisions.export` / `auditLog.export`).
//
// **`list` is single-page per call** (DEV-63) — cursor in / `nextCursor`
// out. The P1.6 spec's hostile concern #3 asked for an auto-paginating
// async iterator "per existing SDK convention" — but that misdiagnoses
// the convention. The SDK reserves async iterators for STREAMING
// endpoints (`chat.send` stream, `decisions.stream`, `decisions.export`,
// `auditLog.export`); every CURSOR-PAGINATED list method
// (`incidents.list`, `decisions.list`, and now `evidencePack.list`)
// returns a single page `{items, nextCursor}` and the caller pages
// manually. Auto-paginating ONLY `evidencePack.list` would make it the
// lone inconsistent paginated resource — the opposite of "per existing
// SDK convention". Cross-resource auto-pagination, if wanted, belongs
// in a dedicated SDK-wide prompt (residual R-1).
//
// **Method name `addBundle`** (DEV-62) — short verb matching the kernel
// internal fn (`addBundleToPack`). The MCP wire tool name is
// `append_bundle` (P1.5 wire-shape choice); the SDK reserves the shorter
// `addBundle` for the method to align with the SDK's verb-method
// convention (`decisions.ingest`, `chat.send`, `gate.evaluate`, etc.).
//
// **`Idempotency-Key` HTTP header is NOT exposed in P1.6** — same
// carry-forward as `vision.ts`. The kernel accepts `Idempotency-Key` on
// `POST /evidence-packs` and `POST /{id}/bundles`; the SDK's
// `RequestOptions` does not surface extra headers for JSON POSTs. Clean
// future extension; consumers who need idempotency today should retry
// with their own client-side dedupe.
//
// **Symmetric prototype-pollution defense** — module-load snapshot of
// `Object.hasOwn` applied to BOTH input AND response sides (carry-
// forward of session-16 second-hostile-review MEDIUM #3 generalization,
// freshest implementation in `gate.ts` / `vision.ts`). Without the
// snapshot, a late-loading hostile/buggy npm dep that overrides the
// global would defeat the defense.
//
// **No URIError defense on body fields** — POST bodies use
// `JSON.stringify` (handles lone UTF-16 surrogates as `\uDxxx` escapes).
// URL-path segments (`get`, `addBundle`) carry `packId` which the SDK
// pre-validates as a hyphen-only RFC 4122 UUID BEFORE
// `encodeURIComponent` runs — so a malformed input rejects with
// `TypeError` before the encoder sees it.
//
// **P3 content-type guard** — already in the SDK transport
// (`packages/attestry-sdk/src/transport.ts:271-291`). A non-JSON 200
// response surfaces as `AttestryAPIError`, NOT an opaque `SyntaxError`.
// HR-4(b) carry-forward applies to `mcp-server/src/client.ts`, NOT to
// the SDK transport.

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

// Module-load snapshot of `Object.hasOwn`. Mirror of `gate.ts`/`vision.ts`.
// Used symmetrically on input AND response sides — defense on both
// boundaries against a late-loading hostile/buggy dep overriding the
// global.
const objectHasOwn = Object.hasOwn;

// RFC 4122 hyphenated UUID (8-4-4-4-12 hex, case-insensitive). Matches
// Zod's `z.string().uuid()` regex effectively. Mirror of `gate.ts`'s
// `UUID_REGEX`; drift-pinned in `evidence-pack.drift.test.ts` (Round 2)
// so a kernel-side switch to a different UUID flavor (ULID, KSUID) fires
// before consumer regressions.
const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// ─── Closed-enum frozen tuples (drift-pinned in Round 2) ────────────────────

/**
 * The five evidence-pack types the kernel accepts. Mirrors
 * `PACK_TYPES` in kernel `src/lib/evidence-pack/types.ts:150-156`.
 * Frozen so consumer code can safely use
 * `PACK_TYPES.includes(...)` without mutation risk (P1 hardening —
 * defends against a hostile/buggy npm dep mutating the array between
 * SDK import and method call).
 *
 * Drift-pinned in the spec-diff round (`evidence-pack.drift.test.ts`)
 * by text-comparing this declaration with the kernel's. An addition /
 * removal / reordering on either side trips the test, **satisfying P1
 * checkpoint AC7** ("SDK drift pin: `pack_type` enum in SDK matches
 * kernel").
 */
export const PACK_TYPES = Object.freeze([
  "annex_iv",
  "agentic_reperformance",
  "red_team_cycle",
  "pccp_evidence",
  "underwriting_evidence",
] as const);
export type PackType = (typeof PACK_TYPES)[number];

/**
 * The five pack-status values the kernel emits + accepts as a filter.
 * Mirrors `PACK_STATUSES` in kernel `src/lib/evidence-pack/types.ts:160-166`.
 * Frozen; drift-pinned identically to `PACK_TYPES`.
 */
export const PACK_STATUSES = Object.freeze([
  "draft",
  "signed",
  "superseded",
  "revoked",
  "expired",
] as const);
export type PackStatus = (typeof PACK_STATUSES)[number];

/**
 * The three artifact formats `evidencePack.export` accepts. Mirrors
 * `EXPORT_FORMATS` in kernel `src/lib/evidence-pack/types.ts:584`
 * (`["json","pdf","zip"] as const`). Frozen; drift-pinned byte-equal to
 * the kernel in `evidence-pack.drift.test.ts` (P1.8 DEV-76).
 *
 * The kernel route's `exportQuerySchema` requires `format` (no default,
 * spec concern E1 — unknown/absent → 422). The SDK pre-validates
 * `format` against this frozen tuple, so an absent/unknown format
 * rejects with a synchronous `TypeError` before the request is sent.
 */
export const EXPORT_FORMATS = Object.freeze(["json", "pdf", "zip"] as const);
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

/**
 * Per-format `Content-Type` the kernel export route emits on success.
 * Mirrors `EXPORT_CONTENT_TYPES` in kernel
 * `src/lib/evidence-pack/export.ts:38-42`. Module-local (the consumer
 * gets the value via `EvidencePackExportResult.contentType`); drift-
 * pinned against the kernel mapping in `evidence-pack.drift.test.ts`.
 *
 * Used as `export`'s per-format `expectedContentType` for the transport
 * `_streamRequest` content-type guard (a wrong-content-type 200 → a
 * clear `AttestryAPIError`, not an opaque downstream parse crash) AND
 * as the canonical `contentType` surfaced on the result — the guard
 * guarantees the response MIME equals this value, so it is accurate.
 */
const EXPORT_CONTENT_TYPES: Record<ExportFormat, string> = {
  json: "application/json",
  pdf: "application/pdf",
  zip: "application/zip",
};

// ─── Closed-spec ceiling constants (drift-pinned in Round 2) ────────────────

/**
 * Maximum `limit` accepted by `GET /api/v1/evidence-packs`. Mirrors the
 * kernel `listEvidencePacksQuerySchema` `z.coerce.number().int().min(1)
 * .max(200)` cap. The SDK rejects an over-cap `limit` synchronously to
 * save a billed 422 round-trip.
 */
const MAX_LIST_LIMIT = 200;

/**
 * Maximum length of `inputsHash` / `outputsHash` on `addBundleToPack`.
 * Mirrors the kernel `addBundleToPackInputSchema` `z.string().min(1)
 * .max(500)` rule.
 */
const MAX_HASH_LENGTH = 500;

/**
 * Maximum length of `traceContent` array on `addBundleToPack`. Mirrors
 * the kernel `z.array(traceEntrySchema).max(1000)` rule.
 */
const MAX_TRACE_CONTENT_LENGTH = 1000;

/**
 * Maximum length of `storageUri` on `addBundleToPack`. Mirrors the
 * kernel `httpsOnlyUrl(2000)` length cap. Scheme validation
 * (`http(s)://`) is kernel-authoritative (faithful courier — the SDK
 * does not duplicate the regex; same convention as
 * `vision.extract.imageUri`).
 */
const MAX_STORAGE_URI_LENGTH = 2000;

/**
 * Maximum length of `frameworkBindings` array on `createEvidencePack`.
 * Mirrors the kernel `z.array(frameworkBindingSchema).max(50)` rule.
 */
const MAX_FRAMEWORK_BINDINGS_LENGTH = 50;

/**
 * Maximum length of `reason` on `revoke`. Mirrors the kernel
 * `revokePackInputSchema` `z.string().min(1).max(500)` rule (P1.8).
 */
const MAX_REASON_LENGTH = 500;

// ─── Input shapes ───────────────────────────────────────────────────────────

/**
 * Input for `evidencePack.create`. Mirrors the wire body of
 * `POST /api/v1/evidence-packs` (kernel `createEvidencePackInputSchema`
 * minus the auth-derived `orgId` and `userId` fields).
 *
 * P1.6-scope fields (4) — matches the P1.5 MCP `attestry_evidence_pack_create`
 * surface for SDK ↔ MCP parity (DEV-67). The kernel route ALSO accepts
 * `consumerHints` (P3 future) and `parentPackId` (P1.4 supersede surface);
 * P1.6 deliberately omits both to match MCP parity. A future SDK
 * extension may add them without breaking the 4-field surface.
 */
export interface CreateEvidencePackInput {
  /**
   * One of the five `PACK_TYPES` values. Pre-validated by the SDK against
   * the local frozen tuple; rejection is a synchronous `TypeError`
   * (P1.6 spec hostile concern #1).
   */
  packType: PackType;
  /**
   * Optional UUID of the AI system the pack is scoped to. Omit for an
   * org-level pack (kernel column is nullable; org-level packs are
   * legitimate for underwriting / cross-system evidence). Pre-validated
   * against `UUID_REGEX` when provided.
   */
  systemId?: string;
  /**
   * Optional array of regulatory framework bindings (up to 50). Each
   * binding's inner shape is open-spec to the SDK (faithful courier —
   * kernel `frameworkBindingSchema` is the deep validator with
   * `.strict()` enforcement of `framework` + `identifier` +
   * `jurisdiction?` + `effective_date?`).
   */
  frameworkBindings?: unknown[];
  /**
   * Optional free-form metadata object (string-keyed). Capped by the
   * kernel at 64 KiB serialized (`MAX_METADATA_BYTES`); the SDK does
   * NOT pre-validate the size cap (no extra `JSON.stringify` cost on
   * the happy path), leaving the kernel as the authority — same
   * faithful-courier discipline as `vision.extract` deep field shapes.
   */
  metadata?: Record<string, unknown>;
}

/**
 * Input for `evidencePack.get`. Mirrors the URL-path param of
 * `GET /api/v1/evidence-packs/{id}` — single field.
 */
export interface GetEvidencePackInput {
  /**
   * UUID of the evidence pack to retrieve. RFC 4122 hyphenated form
   * (8-4-4-4-12 hex, case-insensitive). Pre-validated by the SDK before
   * the URL is constructed.
   */
  packId: string;
}

/**
 * Input for `evidencePack.list`. Mirrors the query-string of
 * `GET /api/v1/evidence-packs` (kernel `listEvidencePacksQuerySchema`
 * MINUS `parentPackId` — see DEV-67; the SDK matches the P1.5 MCP
 * surface parity, not the wider kernel route surface).
 *
 * **Single page per call** (DEV-63) — pass the response's `nextCursor`
 * back as `cursor` on a subsequent call to fetch the next page. No
 * async-iterator today; a future SDK-wide prompt may add cross-resource
 * iteration.
 *
 * **`limit` default applied kernel-side**: when omitted, the kernel
 * applies `.default(50)` (carry-forward invariant #52 — closed-default
 * field pre-validation; the SDK omits the field from the query string
 * so the kernel's default fires).
 */
export interface ListEvidencePacksInput {
  /** Optional UUID filter — return only packs scoped to this AI system. */
  systemId?: string;
  /** Optional closed-enum filter on `pack_type`. */
  packType?: PackType;
  /** Optional closed-enum filter on `status`. */
  status?: PackStatus;
  /**
   * Optional page size. Integer in [1, 200] inclusive. Omitted →
   * kernel-side default of 50.
   */
  limit?: number;
  /**
   * Optional opaque pagination cursor. Pass the `nextCursor` from a
   * previous call to fetch the next page. Base64url-encoded JSON
   * `{c, i}` (kernel format; the SDK passes through verbatim and does
   * NOT decode).
   */
  cursor?: string;
}

/**
 * Input for `evidencePack.addBundle`. Mirrors the wire body + URL-path
 * param of `POST /api/v1/evidence-packs/{id}/bundles` (kernel
 * `addBundleToPackInputSchema` minus the auth-derived `orgId` and
 * `userId`; `packId` rides the URL path, not the body).
 *
 * 8 fields total (DEV-67) — 4 required + 4 optional, matching the
 * P1.5 MCP `attestry_evidence_pack_append_bundle` surface.
 */
export interface AddBundleInput {
  /**
   * UUID of the draft pack to append the bundle to. RFC 4122 hyphenated.
   * Pre-validated by the SDK before the URL is constructed.
   */
  packId: string;
  /**
   * Ordered array of trace entries (up to 1000). Per-entry shape is
   * open-spec to the SDK (kernel `traceEntrySchema` deep-validates
   * `action` / `timestamp` / `refs?` with `.strict()`).
   */
  traceContent: unknown[];
  /**
   * Non-empty hash string identifying the bundle's inputs. Length
   * 1-500 chars. Format is open-spec to the SDK (kernel accepts any
   * non-empty length-bounded string; the project convention is
   * `sha256:<hex>` but the kernel does NOT enforce it).
   */
  inputsHash: string;
  /**
   * Non-empty hash string identifying the bundle's outputs. Length
   * 1-500 chars; same open-spec rule as `inputsHash`.
   */
  outputsHash: string;
  /**
   * Optional model-behavior log. Open-spec inner shape (kernel
   * `modelBehaviorLogSchema` deep-validates `model` / `version` /
   * `sampling_params?` / `response_hash?`).
   */
  modelBehaviorLog?: Record<string, unknown>;
  /**
   * Optional corroboration-results object (free-form jsonb). Depth-
   * capped server-side at 64 levels (kernel `MAX_HASHED_JSONB_DEPTH`);
   * the SDK does NOT pre-validate depth.
   */
  corroborationResults?: Record<string, unknown>;
  /**
   * Optional `http(s)://` URI of bundle binary content in storage.
   * Length-capped at 2000 chars (kernel `httpsOnlyUrl(2000)`). Scheme
   * validation (`^https?://`) is kernel-authoritative; the SDK
   * validates length only (faithful courier).
   */
  storageUri?: string;
  /**
   * Optional free-form metadata. Capped by the kernel at 64 KiB
   * serialized; SDK does NOT pre-validate the size.
   */
  metadata?: Record<string, unknown>;
}

// ─── P1.8 lifecycle/export input shapes ─────────────────────────────────────

/**
 * Input for `evidencePack.sign`. Mirrors the URL-path param + wire body
 * of `POST /api/v1/evidence-packs/{id}/sign` (kernel `signPackInputSchema`
 * minus the auth-derived `orgId` / `userId`; `packId` rides the URL
 * path). Matches the P1.7 MCP `attestry_evidence_pack_sign` surface
 * (the MCP `confirm` gate is MCP-layer-only and NOT mirrored here).
 */
export interface SignEvidencePackInput {
  /**
   * UUID of the **draft** pack to sign. RFC 4122 hyphenated. Pre-validated
   * by the SDK before the URL is constructed.
   */
  packId: string;
  /**
   * Optional UUID of an attestation certificate to bind to the signed
   * pack. When provided, the kernel verifies it belongs to the caller's
   * org (and, for a system-scoped pack, matches the pack's system).
   * Omit to sign without an attestation cert (`content_hash` is the
   * signing primitive). Pre-validated against `UUID_REGEX` when provided.
   */
  attestationCertificateId?: string;
}

/**
 * Inner-payload shape for the new draft pack a `supersede` creates.
 * Mirrors the kernel `supersedeNewPackPayloadSchema` and the P1.7 MCP
 * `supersede` tool's `newPack` shape.
 *
 * **Includes `consumerHints`** (P1.8 DEV-74) — unlike P1.6's `create`
 * input, which deliberately omitted it (DEV-67) to match the MCP
 * **create** tool. The MCP **supersede** tool's `newPack` includes
 * `consumerHints`, so the SDK supersede mirrors it.
 */
export interface SupersedeEvidencePackNewPack {
  /**
   * One of the five `PACK_TYPES` values. Pre-validated against the local
   * frozen tuple; rejection is a synchronous `TypeError`.
   */
  packType: PackType;
  /**
   * Optional UUID of the AI system the new pack is scoped to. Omit for
   * an org-level pack. Pre-validated against `UUID_REGEX` when provided.
   */
  systemId?: string;
  /**
   * Optional array of regulatory framework bindings (up to 50). Inner
   * shape is open-spec to the SDK (kernel `frameworkBindingSchema` is the
   * `.strict()` deep validator) — same faithful-courier discipline as
   * `create`'s `frameworkBindings`.
   */
  frameworkBindings?: unknown[];
  /**
   * Optional consumer-consumption hints object (kernel
   * `consumerHintsSchema` = `{allowPublicRetrieval?, suggestedVerifier?,
   * expectedQueryPatterns?}`, `.strict()`). The SDK validates only that
   * it is a non-null non-array object and forwards it as-is; the kernel
   * deep-validates the keys + the `https`-only verifier URL + caps.
   */
  consumerHints?: Record<string, unknown>;
  /**
   * Optional free-form metadata object (string-keyed). Capped kernel-side
   * at 64 KiB serialized; the SDK does NOT pre-validate the size.
   */
  metadata?: Record<string, unknown>;
}

/**
 * Input for `evidencePack.supersede`. Mirrors the URL-path param + wire
 * body of `POST /api/v1/evidence-packs/{id}/supersede` (kernel
 * `supersedePackInputSchema` minus the auth-derived `orgId` / `userId`;
 * the old pack's id rides the URL path as `packId`).
 */
export interface SupersedeEvidencePackInput {
  /**
   * UUID of the **signed** pack to supersede (the OLD pack). RFC 4122
   * hyphenated. Rides the URL path. Pre-validated by the SDK.
   */
  packId: string;
  /**
   * Payload for the NEW draft pack the supersede creates. Required. The
   * kernel splices in `orgId` / `userId` (auth) + `parentPackId` (= the
   * old `packId`) at the transaction layer.
   */
  newPack: SupersedeEvidencePackNewPack;
}

/**
 * Input for `evidencePack.revoke`. Mirrors the URL-path param + wire body
 * of `POST /api/v1/evidence-packs/{id}/revoke` (kernel
 * `revokePackInputSchema` minus the auth-derived `orgId` / `userId`;
 * `packId` rides the URL path).
 */
export interface RevokeEvidencePackInput {
  /**
   * UUID of the **signed** pack to revoke. RFC 4122 hyphenated.
   * Pre-validated by the SDK before the URL is constructed.
   */
  packId: string;
  /**
   * Optional human-readable revocation reason, recorded verbatim in the
   * pack's audit-log entry. Length 1-500 chars (kernel
   * `z.string().min(1).max(500)`). Pre-validated when provided.
   */
  reason?: string;
}

/**
 * Input for `evidencePack.export`. Mirrors the URL-path param + query
 * string of `GET /api/v1/evidence-packs/{id}/export?format={json|pdf|zip}`.
 */
export interface ExportEvidencePackInput {
  /**
   * UUID of the pack to export. RFC 4122 hyphenated. Rides the URL path.
   * Pre-validated by the SDK.
   */
  packId: string;
  /**
   * One of the three `EXPORT_FORMATS` values (`json` / `pdf` / `zip`).
   * **Required** — the kernel `exportQuerySchema` has no default (spec
   * concern E1). Pre-validated against the frozen tuple; an absent or
   * unknown format rejects with a synchronous `TypeError`.
   */
  format: ExportFormat;
}

// ─── Response shapes ────────────────────────────────────────────────────────

/**
 * An evidence-pack record. Mirrors `EvidencePack` (kernel
 * `InferSelectModel<typeof evidencePacks>`) projected through
 * `successResponse` (`NextResponse.json` serializes Drizzle `Date`
 * columns as ISO-8601 strings — wire shape).
 *
 * Closed-enum fields (`packType`, `status`) are typed as the SDK's
 * closed unions for compile-time narrowing but the runtime P2 validator
 * checks `typeof === "string"` only (faithful courier — same
 * convention as `gate.gate` / `vision.packIntegration.status` /
 * `BulkFailedSummary.code`). A kernel-side enum addition before the
 * SDK is bumped will round-trip at runtime (typed as the closed union
 * at compile time but holding the new string); the drift pin
 * (`evidence-pack.drift.test.ts`) fires in CI before that scenario
 * reaches consumers.
 *
 * Nullable columns surface as `T | null` on the wire (kernel column
 * definitions with `.nullable()` semantics — see
 * `src/lib/db/schema.ts`).
 */
export interface EvidencePack {
  /** UUID of the pack. */
  id: string;
  /** Pack type closed enum (typed-closed, runtime-open). */
  packType: PackType;
  /** UUID of the owning organization. */
  orgId: string;
  /** UUID of the scoped AI system, or `null` for org-level packs. */
  systemId: string | null;
  /** Pack status closed enum (typed-closed, runtime-open). */
  status: PackStatus;
  /**
   * Framework bindings JSONB. Runtime shape is an array of binding
   * objects (kernel default `[]::jsonb`); typed as `unknown` here so
   * consumers can deep-validate per their needs without a tight SDK
   * coupling. The P2 validator requires an array (the kernel column
   * is `notNull` with a default empty array; any other shape would be
   * a kernel regression).
   */
  frameworkBindings: unknown[];
  /** UUID of the parent pack when this pack supersedes one, else `null`. */
  parentPackId: string | null;
  /** UUID of the pack that supersedes this one, else `null`. */
  supersededById: string | null;
  /**
   * Consumer-hints JSONB. Runtime shape is `{allowPublicRetrieval?,
   * suggestedVerifier?, expectedQueryPatterns?}` (kernel default
   * `{}::jsonb`). Typed as `unknown` for the same reason as
   * `frameworkBindings`; P2 validator requires a non-null non-array
   * object.
   */
  consumerHints: unknown;
  /** UUID of the linked attestation certificate, or `null` when unsigned. */
  attestationCertificateId: string | null;
  /** SHA-256 hash of the canonical bundle list, or `null` in `draft` state. */
  contentHash: string | null;
  /** ISO-8601 timestamp of `sign` transition, or `null` when unsigned. */
  signedAt: string | null;
  /** UUID of the signing user, or `null` when unsigned. */
  signedByUserId: string | null;
  /**
   * Free-form metadata JSONB. Default `{}::jsonb`. Typed `unknown`; P2
   * validator requires a non-null non-array object.
   */
  metadata: unknown;
  /** ISO-8601 timestamp of pack creation. */
  createdAt: string;
}

/**
 * A reperformance-bundle record. Mirrors `ReperformanceBundle` (kernel
 * `InferSelectModel<typeof reperformanceBundles>`) projected through
 * `successResponse` (Drizzle `Date` → ISO-8601 string).
 */
export interface ReperformanceBundle {
  /** UUID of the bundle. */
  id: string;
  /** UUID of the parent pack. */
  evidencePackId: string;
  /**
   * Trace-content array (kernel `notNull` jsonb). Per-entry shape is
   * `{action, timestamp, refs?}` runtime; typed `unknown` here.
   */
  traceContent: unknown[];
  /** Caller-supplied inputs hash. */
  inputsHash: string;
  /** Caller-supplied outputs hash. */
  outputsHash: string;
  /** Optional model-behavior-log object, or `null`. */
  modelBehaviorLog: unknown;
  /** Optional corroboration-results object, or `null`. */
  corroborationResults: unknown;
  /** Optional storage URI, or `null`. */
  storageUri: string | null;
  /** Free-form metadata (kernel default `{}::jsonb`). */
  metadata: unknown;
  /** ISO-8601 timestamp of bundle creation. */
  createdAt: string;
}

/**
 * Response for `evidencePack.get`. Mirrors the kernel's
 * `GetEvidencePackResult` (`{pack, bundles}`) — the pack plus its
 * full bundle list ordered `(created_at, id) ASC` (kernel
 * `queries.ts:275-278`).
 */
export interface GetEvidencePackResponse {
  pack: EvidencePack;
  bundles: ReperformanceBundle[];
}

/**
 * Response for `evidencePack.list`. Mirrors the kernel's
 * `ListEvidencePacksResult` (`{items, nextCursor}`) — newest-first
 * keyset pagination over `(created_at DESC, id DESC)`. `nextCursor`
 * is `null` when no more pages.
 */
export interface ListEvidencePacksResponse {
  items: EvidencePack[];
  /** Opaque cursor for the next page, or `null` when no more pages. */
  nextCursor: string | null;
}

/**
 * `hashCollision` block on the `addBundle` response. The kernel
 * detects same-`(inputs_hash, outputs_hash)` collisions with prior
 * bundles on the SAME pack and FLAGS (does NOT block — P1.2 DEV-17).
 *
 * `count` is the total number of colliding prior bundles;
 * `collidingBundleIds` is a bounded sample of up to 10 ids (kernel
 * hostile-redux F-14 — capped so the response doesn't grow
 * unboundedly under dup-heavy packs).
 */
export interface HashCollision {
  detected: boolean;
  count: number;
  collidingBundleIds: string[];
}

/**
 * Response for `evidencePack.addBundle`. Mirrors the kernel's
 * `AddBundleToPackResult` — the newly-appended bundle, the updated
 * pack (with recomputed `content_hash`), and the collision flag.
 */
export interface AddBundleResponse {
  bundle: ReperformanceBundle;
  pack: EvidencePack;
  hashCollision: HashCollision;
}

/**
 * Response for `evidencePack.supersede`. Mirrors the kernel
 * `supersedePack` return (`{newPack, oldPack}`, HTTP 201). `newPack` is
 * the freshly-created draft (status `draft`, `parentPackId` = the old
 * pack); `oldPack` is the now-`superseded` old pack (with
 * `supersededById` set). Both are full `EvidencePack` records (each
 * P2-validated via `validatePack`).
 */
export interface SupersedeEvidencePackResponse {
  newPack: EvidencePack;
  oldPack: EvidencePack;
}

/**
 * Result of `evidencePack.export` (P1.8 DEV-73). The kernel export route
 * returns a downloadable artifact, NOT the `{success, data}` JSON
 * envelope — so the SDK is a faithful courier: it surfaces the
 * un-consumed `Response` and lets the consumer read the body in the form
 * the format dictates.
 *
 *   - `json` → `response.json()` yields the raw artifact
 *     `{export:{format,generatedAt,schemaVersion}, pack, bundles}`.
 *   - `pdf`  → `await response.arrayBuffer()` (or `.bytes()`) yields the
 *     PDF bytes.
 *   - `zip`  → `response.body` is a `ReadableStream<Uint8Array>` (stream
 *     it to disk for large packs), or `await response.blob()`.
 *
 * The transport's `_streamRequest` has already verified the HTTP status
 * (a non-2xx threw `AttestryAPIError`) and that the response's
 * `Content-Type` MIME matches the requested format — so reading `body`
 * will not surprise the consumer with an HTML error page.
 */
export interface EvidencePackExportResult {
  /** The requested export format, echoed back. */
  format: ExportFormat;
  /**
   * The kernel `Content-Type` for this artifact
   * (`application/json` | `application/pdf` | `application/zip`).
   * Guaranteed to equal the response's MIME (the transport's content-type
   * guard threw otherwise).
   */
  contentType: string;
  /**
   * The kernel `Content-Disposition` download header
   * (`attachment; filename="evidence-pack-<id>.<fmt>"`), or `null` if a
   * proxy stripped it (the kernel always sets it).
   */
  contentDisposition: string | null;
  /**
   * The un-consumed `Response`. Call `.json()` / `.arrayBuffer()` /
   * `.blob()` or read `.body` as a stream.
   */
  response: Response;
}

// ─── Resource class ─────────────────────────────────────────────────────────

/**
 * `evidencePack` resource — sibling to `IncidentsResource`,
 * `DecisionsResource`, `ChatResource`, `AuditLogResource`,
 * `RegulatoryChangesResource`, `ComplianceCheckResource`,
 * `CheckResource`, `GateResource`, `VisionResource`.
 *
 * Eight methods: the P1.6 core (`create`, `get`, `list`, `addBundle`)
 * plus the P1.8 lifecycle/export ops (`sign`, `supersede`, `revoke`,
 * `export`). All are JSON request/response (`{success,data}` envelope
 * via `_request`) EXCEPT `export`, which returns a downloadable artifact
 * (json/pdf/zip) via the streaming transport `_streamRequest`.
 */
export class EvidencePackResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Create a new draft evidence pack for the authenticated organization.
   * Wraps `POST /api/v1/evidence-packs`.
   *
   * `orgId` and `userId` are derived server-side from the API key; they
   * are never accepted on the wire. The kernel applies defaults for
   * `frameworkBindings` (`[]`), `consumerHints` (`{}`), `metadata`
   * (`{}`), and `status` (`"draft"`) when fields are omitted.
   *
   * **Idempotency**: the kernel accepts `Idempotency-Key` on this
   * endpoint, but the SDK does NOT expose the header in P1.6 (see
   * resource header comment). Consumers needing safe retry today
   * should dedupe client-side.
   *
   * Errors — ordered by kernel firing precedence (rate-limit → auth →
   * body parse → Zod → DB):
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     (auto-retried by default — invariant #18).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *   - `AttestryAPIError` (status 403) — authenticated key lacks
   *     `WRITE_ASSESSMENTS` permission.
   *   - `AttestryAPIError` (status 400) — JSON parse failure on the
   *     body OR a malformed `Idempotency-Key` header (the kernel
   *     emits 400 for both transport-shape failures).
   *   - `AttestryAPIError` (status 409) — `Idempotency-Key` conflict
   *     (same key, different body hash; `details.code` ===
   *     `"evidence_pack.idempotency_key_conflict"`). Not reachable
   *     from P1.6's SDK directly.
   *   - `AttestryAPIError` (status 422) — Zod validation failed
   *     (`details.code` === `"evidence_pack.validation_failed"`;
   *     `details.issues` carries the field paths).
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired (pre-aborted or mid-flight).
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (not an object, wrong type on any
   *     field).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard, before body
   *     parsing).
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation (null/array/non-object input; missing
   *     `packType`; bad `packType` enum; bad `systemId` UUID; bad
   *     `frameworkBindings` array shape; bad `metadata` shape).
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch issued):
   *   - `input`: required; non-null, non-array object.
   *   - `input.packType`: required own-property; member of `PACK_TYPES`.
   *   - `input.systemId` (when own-present, value not undefined): non-
   *     empty string matching `UUID_REGEX`.
   *   - `input.frameworkBindings` (when own-present, value not
   *     undefined): array of length ≤50 (kernel cap); per-entry shape
   *     is open-spec and forwarded to the kernel as-is.
   *   - `input.metadata` (when own-present, value not undefined):
   *     non-null, non-array object.
   *
   * **Response-shape validation** (P2 hardening; symmetric defense on
   * response side via the `objectHasOwn` snapshot): every documented
   * `EvidencePack` field is type-checked. Rejects with `AttestryError`
   * on shape violation.
   *
   * @example Minimum viable pack (org-level, no system, no bindings)
   * ```ts
   * const pack = await client.evidencePack.create({
   *   packType: "underwriting_evidence",
   * });
   * console.log("created:", pack.id, "status:", pack.status); // "draft"
   * ```
   *
   * @example Annex IV pack scoped to a specific AI system
   * ```ts
   * const pack = await client.evidencePack.create({
   *   packType: "annex_iv",
   *   systemId: "11111111-1111-1111-1111-111111111111",
   *   frameworkBindings: [
   *     { framework: "eu_ai_act", identifier: "Annex.IV.1" },
   *     { framework: "iso_42001", identifier: "8.2" },
   *   ],
   *   metadata: { author: "compliance-bot", version: 1 },
   * });
   * ```
   */
  create(
    input: CreateEvidencePackInput,
    options?: RequestOptions,
  ): Promise<EvidencePack> {
    // Top-level shape — input is REQUIRED. typeof null === "object" and
    // typeof [] === "object", so guard both explicitly.
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "evidencePack.create: `input` must be a non-null object with `packType`",
      );
    }

    // Snapshot each field's value EXACTLY ONCE up front via the own-
    // property indexer. Three motivations (carry-forward from gate.ts /
    // vision.ts):
    //   1. Prototype-pollution defense (generalization of invariant #48):
    //      `Object.prototype.packType = "..."` cannot trick the SDK into
    //      silently sending the polluted value when `{}` is passed.
    //   2. TOCTOU defense: a Proxy / getter-defining input could yield
    //      different values across multiple reads.
    //   3. Explicit `{}` is treated as those-fields-omitted —
    //      `objectHasOwn` returns false on missing keys.
    //   4. Throwing-getter defense — each read goes through
    //      `readInputField`, converting a throwing accessor's exception
    //      into the documented synchronous `TypeError` input contract
    //      (session-22 hostile MEDIUM-1).
    const hasPackType = objectHasOwn(input, "packType");
    const packTypeRaw: unknown = hasPackType
      ? readInputField(input, "packType", "evidencePack.create")
      : undefined;
    const hasSystemId = objectHasOwn(input, "systemId");
    const systemIdRaw: unknown = hasSystemId
      ? readInputField(input, "systemId", "evidencePack.create")
      : undefined;
    const hasFrameworkBindings = objectHasOwn(input, "frameworkBindings");
    const frameworkBindingsRaw: unknown = hasFrameworkBindings
      ? readInputField(input, "frameworkBindings", "evidencePack.create")
      : undefined;
    const hasMetadata = objectHasOwn(input, "metadata");
    const metadataRaw: unknown = hasMetadata
      ? readInputField(input, "metadata", "evidencePack.create")
      : undefined;

    // packType REQUIRED + closed-enum membership.
    if (!hasPackType || packTypeRaw === undefined) {
      throw new TypeError(
        "evidencePack.create: `packType` is required",
      );
    }
    if (typeof packTypeRaw !== "string") {
      throw new TypeError(
        `evidencePack.create: \`packType\` must be a string ` +
          `(got ${describeType(packTypeRaw)})`,
      );
    }
    if (!(PACK_TYPES as readonly string[]).includes(packTypeRaw)) {
      throw new TypeError(
        `evidencePack.create: \`packType\` must be one of ` +
          `${JSON.stringify(PACK_TYPES)} (got ${JSON.stringify(packTypeRaw)})`,
      );
    }
    const validatedPackType = packTypeRaw as PackType;

    // Optional systemId — UUID pre-validation when own-present.
    let validatedSystemId: string | undefined;
    if (hasSystemId && systemIdRaw !== undefined) {
      if (typeof systemIdRaw !== "string") {
        throw new TypeError(
          `evidencePack.create: \`systemId\` must be a string when provided ` +
            `(got ${describeType(systemIdRaw)})`,
        );
      }
      if (!UUID_REGEX.test(systemIdRaw)) {
        throw new TypeError(
          "evidencePack.create: `systemId` must be an RFC 4122 hyphenated UUID",
        );
      }
      validatedSystemId = systemIdRaw;
    }

    // Optional frameworkBindings — array + length cap. Per-entry shape
    // is open-spec (kernel `frameworkBindingSchema` is the deep
    // validator with `.strict()` rejection of unknown keys).
    let validatedFrameworkBindings: unknown[] | undefined;
    if (hasFrameworkBindings && frameworkBindingsRaw !== undefined) {
      if (!Array.isArray(frameworkBindingsRaw)) {
        throw new TypeError(
          `evidencePack.create: \`frameworkBindings\` must be an array when ` +
            `provided (got ${describeType(frameworkBindingsRaw)})`,
        );
      }
      // Snapshot via Array.from so a Proxy whose `.length` or `[i]`
      // changes between reads can't slip past validation. Per-entry
      // shape is forwarded as-is to the kernel.
      const snapshot = Array.from(frameworkBindingsRaw as ArrayLike<unknown>);
      if (snapshot.length > MAX_FRAMEWORK_BINDINGS_LENGTH) {
        throw new TypeError(
          `evidencePack.create: \`frameworkBindings\` array exceeds the ` +
            `kernel's max length of ${MAX_FRAMEWORK_BINDINGS_LENGTH} (got ` +
            `${snapshot.length})`,
        );
      }
      validatedFrameworkBindings = snapshot;
    }

    // Optional metadata — non-null non-array object when present.
    let validatedMetadata: Record<string, unknown> | undefined;
    if (hasMetadata && metadataRaw !== undefined) {
      if (
        metadataRaw === null ||
        typeof metadataRaw !== "object" ||
        Array.isArray(metadataRaw)
      ) {
        throw new TypeError(
          `evidencePack.create: \`metadata\` must be a non-null object when ` +
            `provided (got ${describeType(metadataRaw)})`,
        );
      }
      validatedMetadata = metadataRaw as Record<string, unknown>;
    }

    // Build the body from explicitly-named fields. Omit optional fields
    // the consumer omitted so the kernel applies its `.default(...)`.
    const body: {
      packType: PackType;
      systemId?: string;
      frameworkBindings?: unknown[];
      metadata?: Record<string, unknown>;
    } = {
      packType: validatedPackType,
    };
    if (validatedSystemId !== undefined) body.systemId = validatedSystemId;
    if (validatedFrameworkBindings !== undefined) {
      body.frameworkBindings = validatedFrameworkBindings;
    }
    if (validatedMetadata !== undefined) body.metadata = validatedMetadata;

    return this.client
      ._request<EvidencePack>({
        method: "POST",
        path: "/api/v1/evidence-packs",
        body,
        options,
      })
      .then((result) => {
        validatePack(result, "evidencePack.create", "response");
        return result;
      });
  }

  /**
   * Retrieve a single evidence pack's metadata together with its full
   * reperformance-bundle list. Wraps `GET /api/v1/evidence-packs/{id}`.
   *
   * **Anti-enumeration 404**: a pack that doesn't exist OR exists in a
   * different org surfaces as `AttestryAPIError` with `status === 404`
   * and a generic "pack not found" message (faithful courier — the
   * kernel `getEvidencePack` query intentionally collapses cross-org
   * and missing to the same response).
   *
   * Errors — ordered by kernel firing precedence. The kernel route at
   * `src/app/api/v1/evidence-packs/[id]/route.ts` validates the URL-path
   * UUID BEFORE the auth check, so a malformed path UUID surfaces as 400
   * BEFORE 401/403 (same ordering as `addBundle`):
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried).
   *   - `AttestryAPIError` (status 400 — path UUID) — malformed UUID in
   *     the path (kernel `packPathParamsSchema` Zod rejection).
   *     **Fires BEFORE auth.** The SDK pre-validates the UUID format so
   *     this surface is only reachable via SDK rule changes.
   *   - `AttestryAPIError` (status 401 / 403) — auth missing / wrong
   *     permission (`READ_ASSESSMENTS`).
   *   - `AttestryAPIError` (status 404) — pack missing OR cross-org.
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — abort.
   *   - `AttestryError` (P2 hardening) — kernel response shape
   *     violation.
   *   - `AttestryAPIError` (P3 hardening) — non-JSON response.
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **SDK-side validation**:
   *   - `input`: required; non-null, non-array object.
   *   - `input.packId`: required own-property; non-empty string;
   *     matching `UUID_REGEX`.
   *
   * **Response-shape validation** (P2 hardening): `pack` field is a
   * full `EvidencePack`; `bundles` field is an array of
   * `ReperformanceBundle` (per-element shape validated).
   *
   * @example
   * ```ts
   * const { pack, bundles } = await client.evidencePack.get({
   *   packId: "11111111-1111-1111-1111-111111111111",
   * });
   * console.log(`${pack.packType} pack, status: ${pack.status}`);
   * console.log(`${bundles.length} bundles attached`);
   * ```
   */
  get(
    input: GetEvidencePackInput,
    options?: RequestOptions,
  ): Promise<GetEvidencePackResponse> {
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "evidencePack.get: `input` must be a non-null object with `packId`",
      );
    }

    const hasPackId = objectHasOwn(input, "packId");
    const packIdRaw: unknown = hasPackId
      ? readInputField(input, "packId", "evidencePack.get")
      : undefined;

    if (!hasPackId || packIdRaw === undefined) {
      throw new TypeError(
        "evidencePack.get: `packId` is required",
      );
    }
    if (typeof packIdRaw !== "string" || packIdRaw.length === 0) {
      throw new TypeError(
        "evidencePack.get: `packId` must be a non-empty string",
      );
    }
    if (!UUID_REGEX.test(packIdRaw)) {
      throw new TypeError(
        "evidencePack.get: `packId` must be an RFC 4122 hyphenated UUID",
      );
    }

    // `packId` is regex-validated to hex+hyphens only — no `/` / `.` /
    // `..` / NUL can reach the encoder. `encodeURIComponent` is belt-
    // and-suspenders.
    const path = `/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}`;

    return this.client
      ._request<GetEvidencePackResponse>({
        method: "GET",
        path,
        options,
      })
      .then((result) => {
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `evidencePack.get: expected an object response from the kernel ` +
              `(got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;

        const packRaw = objectHasOwn(obj, "pack") ? obj.pack : undefined;
        validatePack(packRaw, "evidencePack.get", "response.pack");

        const bundlesRaw = objectHasOwn(obj, "bundles")
          ? obj.bundles
          : undefined;
        if (!Array.isArray(bundlesRaw)) {
          throw new AttestryError(
            `evidencePack.get: expected response.bundles to be an array ` +
              `(got ${describeType(bundlesRaw)})`,
          );
        }
        for (let i = 0; i < bundlesRaw.length; i++) {
          validateBundle(
            bundlesRaw[i],
            "evidencePack.get",
            `response.bundles[${i}]`,
          );
        }
        return result;
      });
  }

  /**
   * List the authenticated organization's evidence packs, newest first.
   * Wraps `GET /api/v1/evidence-packs`.
   *
   * **Single page per call** (DEV-63). Pass `response.nextCursor` back
   * as `cursor` to fetch the next page; `nextCursor: null` means no
   * more pages. The kernel pages by tuple comparison over
   * `(created_at DESC, id DESC)` so same-microsecond timestamps do
   * not skip rows.
   *
   * **Filters are AND-combined kernel-side**. Omitting all filters
   * lists the entire org's packs (newest first). Empty `cursor` (`""`)
   * is rejected by the SDK; pass `undefined` (or omit the field) for
   * the first page.
   *
   * Errors — ordered by kernel firing precedence:
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried).
   *   - `AttestryAPIError` (status 401 / 403) — auth missing / wrong
   *     permission (`READ_ASSESSMENTS`).
   *   - `AttestryAPIError` (status 400) — a length-valid but
   *     UNDECODABLE `cursor` (`details.code` ===
   *     `"evidence_pack.invalid_cursor"`). NOTE: a `cursor` that fails
   *     the kernel's Zod length cap (>500 chars) fires EARLIER as 422
   *     (below), not 400 — the 400 path is reached only after the query
   *     schema accepts the cursor's shape. Since the SDK treats `cursor`
   *     as opaque (caller passes back `nextCursor` verbatim), neither is
   *     reachable with a kernel-issued cursor.
   *   - `AttestryAPIError` (status 422) — Zod query-param validation
   *     failed, INCLUDING an over-long (>500-char) `cursor`
   *     (`details.code` === `"evidence_pack.validation_failed"`).
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — abort.
   *   - `AttestryError` (P2 hardening) — response-shape violation.
   *   - `AttestryAPIError` (P3 hardening) — non-JSON response.
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **SDK-side validation**:
   *   - `input` (optional): if provided, non-null, non-array object.
   *   - `input.systemId` (when own-present): UUID format.
   *   - `input.packType` (when own-present): member of `PACK_TYPES`.
   *   - `input.status` (when own-present): member of `PACK_STATUSES`.
   *   - `input.limit` (when own-present): `Number.isInteger`, range
   *     [1, 200] inclusive. Mirrors kernel `.int().min(1).max(200)`.
   *   - `input.cursor` (when own-present): non-empty string.
   *
   * @example First page, all filters omitted
   * ```ts
   * const { items, nextCursor } = await client.evidencePack.list();
   * for (const pack of items) {
   *   console.log(pack.id, pack.packType, pack.status);
   * }
   * if (nextCursor) {
   *   const next = await client.evidencePack.list({ cursor: nextCursor });
   * }
   * ```
   *
   * @example Filter by system + status + cap to 25
   * ```ts
   * const draft = await client.evidencePack.list({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   *   status: "draft",
   *   limit: 25,
   * });
   * ```
   */
  list(
    input?: ListEvidencePacksInput,
    options?: RequestOptions,
  ): Promise<ListEvidencePacksResponse> {
    // `input` is optional. Reject explicit `null` and non-object
    // explicit values to match the input-shape discipline.
    if (input !== undefined) {
      if (
        input === null ||
        typeof input !== "object" ||
        Array.isArray(input)
      ) {
        throw new TypeError(
          "evidencePack.list: `input` must be a non-null object when provided",
        );
      }
    }
    // From here on `input` is `undefined` OR a non-null non-array
    // object. The own-property snapshots below tolerate either. Each
    // read goes through `readInputField` so a throwing accessor surfaces
    // as the documented synchronous `TypeError` (session-22 hostile
    // MEDIUM-1).
    const safeInput = (input ?? {}) as Record<string, unknown>;

    const hasSystemId = objectHasOwn(safeInput, "systemId");
    const systemIdRaw: unknown = hasSystemId
      ? readInputField(safeInput, "systemId", "evidencePack.list")
      : undefined;
    const hasPackType = objectHasOwn(safeInput, "packType");
    const packTypeRaw: unknown = hasPackType
      ? readInputField(safeInput, "packType", "evidencePack.list")
      : undefined;
    const hasStatus = objectHasOwn(safeInput, "status");
    const statusRaw: unknown = hasStatus
      ? readInputField(safeInput, "status", "evidencePack.list")
      : undefined;
    const hasLimit = objectHasOwn(safeInput, "limit");
    const limitRaw: unknown = hasLimit
      ? readInputField(safeInput, "limit", "evidencePack.list")
      : undefined;
    const hasCursor = objectHasOwn(safeInput, "cursor");
    const cursorRaw: unknown = hasCursor
      ? readInputField(safeInput, "cursor", "evidencePack.list")
      : undefined;

    let validatedSystemId: string | undefined;
    if (hasSystemId && systemIdRaw !== undefined) {
      if (typeof systemIdRaw !== "string") {
        throw new TypeError(
          `evidencePack.list: \`systemId\` must be a string when provided ` +
            `(got ${describeType(systemIdRaw)})`,
        );
      }
      if (!UUID_REGEX.test(systemIdRaw)) {
        throw new TypeError(
          "evidencePack.list: `systemId` must be an RFC 4122 hyphenated UUID",
        );
      }
      validatedSystemId = systemIdRaw;
    }

    let validatedPackType: PackType | undefined;
    if (hasPackType && packTypeRaw !== undefined) {
      if (typeof packTypeRaw !== "string") {
        throw new TypeError(
          `evidencePack.list: \`packType\` must be a string when provided ` +
            `(got ${describeType(packTypeRaw)})`,
        );
      }
      if (!(PACK_TYPES as readonly string[]).includes(packTypeRaw)) {
        throw new TypeError(
          `evidencePack.list: \`packType\` must be one of ` +
            `${JSON.stringify(PACK_TYPES)} (got ${JSON.stringify(packTypeRaw)})`,
        );
      }
      validatedPackType = packTypeRaw as PackType;
    }

    let validatedStatus: PackStatus | undefined;
    if (hasStatus && statusRaw !== undefined) {
      if (typeof statusRaw !== "string") {
        throw new TypeError(
          `evidencePack.list: \`status\` must be a string when provided ` +
            `(got ${describeType(statusRaw)})`,
        );
      }
      if (!(PACK_STATUSES as readonly string[]).includes(statusRaw)) {
        throw new TypeError(
          `evidencePack.list: \`status\` must be one of ` +
            `${JSON.stringify(PACK_STATUSES)} (got ${JSON.stringify(statusRaw)})`,
        );
      }
      validatedStatus = statusRaw as PackStatus;
    }

    let validatedLimit: number | undefined;
    if (hasLimit && limitRaw !== undefined) {
      if (typeof limitRaw !== "number") {
        throw new TypeError(
          `evidencePack.list: \`limit\` must be a number when provided ` +
            `(got ${describeType(limitRaw)})`,
        );
      }
      if (!Number.isInteger(limitRaw)) {
        throw new TypeError(
          `evidencePack.list: \`limit\` must be a finite integer ` +
            `(got ${limitRaw})`,
        );
      }
      if (limitRaw < 1 || limitRaw > MAX_LIST_LIMIT) {
        throw new TypeError(
          `evidencePack.list: \`limit\` must be in the range [1, ` +
            `${MAX_LIST_LIMIT}] (got ${limitRaw})`,
        );
      }
      validatedLimit = limitRaw;
    }

    let validatedCursor: string | undefined;
    if (hasCursor && cursorRaw !== undefined) {
      if (typeof cursorRaw !== "string") {
        throw new TypeError(
          `evidencePack.list: \`cursor\` must be a string when provided ` +
            `(got ${describeType(cursorRaw)})`,
        );
      }
      if (cursorRaw.length === 0) {
        throw new TypeError(
          "evidencePack.list: `cursor` must be a non-empty string when provided",
        );
      }
      validatedCursor = cursorRaw;
    }

    // Build the query record. The transport's `encodeQuery` drops
    // undefined values, so an omitted filter is never emitted — the
    // kernel then applies its own `.default(50)` on `limit` etc.
    // (closed-default invariant carry-forward).
    const query: Record<
      string,
      string | number | boolean | undefined | null
    > = {
      systemId: validatedSystemId,
      packType: validatedPackType,
      status: validatedStatus,
      limit: validatedLimit,
      cursor: validatedCursor,
    };

    return this.client
      ._request<ListEvidencePacksResponse>({
        method: "GET",
        path: "/api/v1/evidence-packs",
        query,
        options,
      })
      .then((result) => {
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `evidencePack.list: expected an object response from the kernel ` +
              `(got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;

        const itemsRaw = objectHasOwn(obj, "items") ? obj.items : undefined;
        if (!Array.isArray(itemsRaw)) {
          throw new AttestryError(
            `evidencePack.list: expected response.items to be an array ` +
              `(got ${describeType(itemsRaw)})`,
          );
        }
        for (let i = 0; i < itemsRaw.length; i++) {
          validatePack(
            itemsRaw[i],
            "evidencePack.list",
            `response.items[${i}]`,
          );
        }

        const nextCursorRaw = objectHasOwn(obj, "nextCursor")
          ? obj.nextCursor
          : undefined;
        if (nextCursorRaw !== null && typeof nextCursorRaw !== "string") {
          throw new AttestryError(
            `evidencePack.list: expected response.nextCursor to be a string ` +
              `or null (got ${describeType(nextCursorRaw)})`,
          );
        }
        return result;
      });
  }

  /**
   * Append a reperformance bundle to an existing **draft** evidence
   * pack. Wraps `POST /api/v1/evidence-packs/{id}/bundles`.
   *
   * The kernel recomputes the pack's `content_hash` after the append
   * and returns the updated pack alongside the new bundle. A
   * `hashCollision` flag is set when the new `(inputs_hash,
   * outputs_hash)` tuple matches any existing bundle on the SAME pack
   * — flagged but NOT blocked (P1.2 DEV-17, faithful courier).
   *
   * **State invariant**: the pack must be in `draft` status. A
   * non-draft pack (`signed`, `superseded`, `revoked`, `expired`)
   * rejects with `AttestryAPIError` status 409 (`details.code` ===
   * `"evidence_pack.invalid_state"`; `details.currentStatus` carries
   * the pack's current state).
   *
   * **Method name `addBundle`** — see resource header for the
   * `addBundle` vs `appendBundle` decision.
   *
   * **Idempotency**: same carry-forward as `create` — the kernel
   * accepts `Idempotency-Key` but the SDK doesn't expose the header
   * in P1.6.
   *
   * Errors — ordered by kernel firing precedence. The kernel route at
   * `src/app/api/v1/evidence-packs/[id]/bundles/route.ts` validates the
   * URL-path UUID BEFORE the auth check, so a malformed path UUID
   * surfaces as 400 BEFORE 401/403. Body-parse 400s and idempotency-
   * key 400s fire AFTER auth (matches the `get` JSDoc shape):
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried).
   *   - `AttestryAPIError` (status 400 — path UUID) — malformed
   *     URL-path packId. **Fires BEFORE auth** (the kernel
   *     `packPathParamsSchema.safeParse` runs first). The SDK
   *     pre-validates the path UUID so this surface is only reachable
   *     via SDK rule changes.
   *   - `AttestryAPIError` (status 401 / 403) — auth missing / wrong
   *     permission (`WRITE_ASSESSMENTS`).
   *   - `AttestryAPIError` (status 400 — JSON parse / idempotency-key
   *     format) — malformed JSON body OR malformed `Idempotency-Key`
   *     header. **Fires AFTER auth** (the kernel parses these after
   *     `requireSessionOrApiKey` resolves).
   *   - `AttestryAPIError` (status 404) — pack missing OR cross-org.
   *   - `AttestryAPIError` (status 409) — invalid state (carries
   *     `details.currentStatus`) OR idempotency conflict.
   *   - `AttestryAPIError` (status 413) — canonical bundle list >
   *     256 KiB (kernel `PayloadTooLargeError`).
   *   - `AttestryAPIError` (status 422) — Zod validation failed.
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — abort.
   *   - `AttestryError` (P2 hardening) — response-shape violation.
   *   - `AttestryAPIError` (P3 hardening) — non-JSON response.
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **SDK-side validation**:
   *   - `input`: required; non-null, non-array object.
   *   - `input.packId`: required own-property; non-empty UUID string.
   *   - `input.traceContent`: required own-property; array of length
   *     ≤1000. Per-entry shape is open-spec (kernel deep-validates).
   *   - `input.inputsHash`: required own-property; non-empty string;
   *     length ≤500.
   *   - `input.outputsHash`: required own-property; non-empty string;
   *     length ≤500.
   *   - `input.modelBehaviorLog` (when own-present): non-null,
   *     non-array object. Inner shape open-spec.
   *   - `input.corroborationResults` (when own-present): non-null,
   *     non-array object. Inner shape open-spec.
   *   - `input.storageUri` (when own-present): non-empty string;
   *     length ≤2000. Scheme validation kernel-authoritative.
   *   - `input.metadata` (when own-present): non-null, non-array
   *     object.
   *
   * **Response-shape validation** (P2 hardening): `bundle` is a
   * `ReperformanceBundle`; `pack` is an `EvidencePack`; `hashCollision`
   * is the 3-field `HashCollision` block.
   *
   * @example Append a bundle to a draft pack
   * ```ts
   * const { bundle, pack, hashCollision } = await client.evidencePack.addBundle({
   *   packId: "11111111-1111-1111-1111-111111111111",
   *   traceContent: [
   *     { action: "ingest", timestamp: "2026-05-18T12:00:00Z" },
   *     { action: "extract", timestamp: "2026-05-18T12:00:01Z" },
   *   ],
   *   inputsHash:  "sha256:0000000000000000000000000000000000000000000000000000000000000000",
   *   outputsHash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
   * });
   * console.log(`appended bundle ${bundle.id}; pack hash now ${pack.contentHash}`);
   * if (hashCollision.detected) {
   *   console.warn(`duplicate bundle — ${hashCollision.count} prior matches`);
   * }
   * ```
   */
  addBundle(
    input: AddBundleInput,
    options?: RequestOptions,
  ): Promise<AddBundleResponse> {
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "evidencePack.addBundle: `input` must be a non-null object with " +
          "`packId`, `traceContent`, `inputsHash`, `outputsHash`",
      );
    }

    // Snapshot each field via `readInputField` so a throwing accessor
    // surfaces as the documented synchronous `TypeError` input contract
    // (session-22 hostile MEDIUM-1); the `objectHasOwn` presence check
    // is a separate prototype-pollution defense.
    const hasPackId = objectHasOwn(input, "packId");
    const packIdRaw: unknown = hasPackId
      ? readInputField(input, "packId", "evidencePack.addBundle")
      : undefined;
    const hasTraceContent = objectHasOwn(input, "traceContent");
    const traceContentRaw: unknown = hasTraceContent
      ? readInputField(input, "traceContent", "evidencePack.addBundle")
      : undefined;
    const hasInputsHash = objectHasOwn(input, "inputsHash");
    const inputsHashRaw: unknown = hasInputsHash
      ? readInputField(input, "inputsHash", "evidencePack.addBundle")
      : undefined;
    const hasOutputsHash = objectHasOwn(input, "outputsHash");
    const outputsHashRaw: unknown = hasOutputsHash
      ? readInputField(input, "outputsHash", "evidencePack.addBundle")
      : undefined;
    const hasModelBehaviorLog = objectHasOwn(input, "modelBehaviorLog");
    const modelBehaviorLogRaw: unknown = hasModelBehaviorLog
      ? readInputField(input, "modelBehaviorLog", "evidencePack.addBundle")
      : undefined;
    const hasCorroborationResults = objectHasOwn(input, "corroborationResults");
    const corroborationResultsRaw: unknown = hasCorroborationResults
      ? readInputField(input, "corroborationResults", "evidencePack.addBundle")
      : undefined;
    const hasStorageUri = objectHasOwn(input, "storageUri");
    const storageUriRaw: unknown = hasStorageUri
      ? readInputField(input, "storageUri", "evidencePack.addBundle")
      : undefined;
    const hasMetadata = objectHasOwn(input, "metadata");
    const metadataRaw: unknown = hasMetadata
      ? readInputField(input, "metadata", "evidencePack.addBundle")
      : undefined;

    // packId REQUIRED.
    if (!hasPackId || packIdRaw === undefined) {
      throw new TypeError(
        "evidencePack.addBundle: `packId` is required",
      );
    }
    if (typeof packIdRaw !== "string" || packIdRaw.length === 0) {
      throw new TypeError(
        "evidencePack.addBundle: `packId` must be a non-empty string",
      );
    }
    if (!UUID_REGEX.test(packIdRaw)) {
      throw new TypeError(
        "evidencePack.addBundle: `packId` must be an RFC 4122 hyphenated UUID",
      );
    }

    // traceContent REQUIRED + array + length cap. Snapshot via Array.from.
    if (!hasTraceContent || traceContentRaw === undefined) {
      throw new TypeError(
        "evidencePack.addBundle: `traceContent` is required",
      );
    }
    if (!Array.isArray(traceContentRaw)) {
      throw new TypeError(
        `evidencePack.addBundle: \`traceContent\` must be an array ` +
          `(got ${describeType(traceContentRaw)})`,
      );
    }
    const validatedTraceContent = Array.from(
      traceContentRaw as ArrayLike<unknown>,
    );
    if (validatedTraceContent.length > MAX_TRACE_CONTENT_LENGTH) {
      throw new TypeError(
        `evidencePack.addBundle: \`traceContent\` array exceeds the ` +
          `kernel's max length of ${MAX_TRACE_CONTENT_LENGTH} (got ` +
          `${validatedTraceContent.length})`,
      );
    }

    // inputsHash REQUIRED + non-empty + length cap.
    if (!hasInputsHash || inputsHashRaw === undefined) {
      throw new TypeError(
        "evidencePack.addBundle: `inputsHash` is required",
      );
    }
    if (typeof inputsHashRaw !== "string") {
      throw new TypeError(
        `evidencePack.addBundle: \`inputsHash\` must be a string ` +
          `(got ${describeType(inputsHashRaw)})`,
      );
    }
    if (inputsHashRaw.length === 0) {
      throw new TypeError(
        "evidencePack.addBundle: `inputsHash` must be a non-empty string",
      );
    }
    if (inputsHashRaw.length > MAX_HASH_LENGTH) {
      throw new TypeError(
        `evidencePack.addBundle: \`inputsHash\` exceeds the maximum length ` +
          `of ${MAX_HASH_LENGTH} characters (got ${inputsHashRaw.length})`,
      );
    }
    // Capture the validated value into a typed local (matches the
    // `validated*` discipline used for every other field) so the body is
    // built ONLY from validated locals — a future refactor that moved
    // the read or changed `inputsHashRaw`'s type cannot silently ship an
    // unvalidated value (hostile-review F-CR-1).
    const validatedInputsHash: string = inputsHashRaw;

    // outputsHash REQUIRED + non-empty + length cap.
    if (!hasOutputsHash || outputsHashRaw === undefined) {
      throw new TypeError(
        "evidencePack.addBundle: `outputsHash` is required",
      );
    }
    if (typeof outputsHashRaw !== "string") {
      throw new TypeError(
        `evidencePack.addBundle: \`outputsHash\` must be a string ` +
          `(got ${describeType(outputsHashRaw)})`,
      );
    }
    if (outputsHashRaw.length === 0) {
      throw new TypeError(
        "evidencePack.addBundle: `outputsHash` must be a non-empty string",
      );
    }
    if (outputsHashRaw.length > MAX_HASH_LENGTH) {
      throw new TypeError(
        `evidencePack.addBundle: \`outputsHash\` exceeds the maximum length ` +
          `of ${MAX_HASH_LENGTH} characters (got ${outputsHashRaw.length})`,
      );
    }
    // Capture the validated value into a typed local (F-CR-1 — same
    // rationale as `validatedInputsHash`).
    const validatedOutputsHash: string = outputsHashRaw;

    // Optional modelBehaviorLog — non-null non-array object.
    let validatedModelBehaviorLog: Record<string, unknown> | undefined;
    if (hasModelBehaviorLog && modelBehaviorLogRaw !== undefined) {
      if (
        modelBehaviorLogRaw === null ||
        typeof modelBehaviorLogRaw !== "object" ||
        Array.isArray(modelBehaviorLogRaw)
      ) {
        throw new TypeError(
          `evidencePack.addBundle: \`modelBehaviorLog\` must be a non-null ` +
            `object when provided (got ${describeType(modelBehaviorLogRaw)})`,
        );
      }
      validatedModelBehaviorLog = modelBehaviorLogRaw as Record<
        string,
        unknown
      >;
    }

    // Optional corroborationResults — non-null non-array object.
    let validatedCorroborationResults: Record<string, unknown> | undefined;
    if (hasCorroborationResults && corroborationResultsRaw !== undefined) {
      if (
        corroborationResultsRaw === null ||
        typeof corroborationResultsRaw !== "object" ||
        Array.isArray(corroborationResultsRaw)
      ) {
        throw new TypeError(
          `evidencePack.addBundle: \`corroborationResults\` must be a non-` +
            `null object when provided (got ` +
            `${describeType(corroborationResultsRaw)})`,
        );
      }
      validatedCorroborationResults =
        corroborationResultsRaw as Record<string, unknown>;
    }

    // Optional storageUri — non-empty string + length cap. Scheme is
    // kernel-authoritative (faithful courier — same as vision.ts
    // imageUri).
    let validatedStorageUri: string | undefined;
    if (hasStorageUri && storageUriRaw !== undefined) {
      if (typeof storageUriRaw !== "string") {
        throw new TypeError(
          `evidencePack.addBundle: \`storageUri\` must be a string when ` +
            `provided (got ${describeType(storageUriRaw)})`,
        );
      }
      if (storageUriRaw.length === 0) {
        throw new TypeError(
          "evidencePack.addBundle: `storageUri` must be a non-empty string " +
            "when provided",
        );
      }
      if (storageUriRaw.length > MAX_STORAGE_URI_LENGTH) {
        throw new TypeError(
          `evidencePack.addBundle: \`storageUri\` exceeds the maximum ` +
            `length of ${MAX_STORAGE_URI_LENGTH} characters (got ` +
            `${storageUriRaw.length})`,
        );
      }
      validatedStorageUri = storageUriRaw;
    }

    // Optional metadata — non-null non-array object.
    let validatedMetadata: Record<string, unknown> | undefined;
    if (hasMetadata && metadataRaw !== undefined) {
      if (
        metadataRaw === null ||
        typeof metadataRaw !== "object" ||
        Array.isArray(metadataRaw)
      ) {
        throw new TypeError(
          `evidencePack.addBundle: \`metadata\` must be a non-null object ` +
            `when provided (got ${describeType(metadataRaw)})`,
        );
      }
      validatedMetadata = metadataRaw as Record<string, unknown>;
    }

    // Build the body. `packId` rides the URL path, NOT the body.
    const body: {
      traceContent: unknown[];
      inputsHash: string;
      outputsHash: string;
      modelBehaviorLog?: Record<string, unknown>;
      corroborationResults?: Record<string, unknown>;
      storageUri?: string;
      metadata?: Record<string, unknown>;
    } = {
      traceContent: validatedTraceContent,
      inputsHash: validatedInputsHash,
      outputsHash: validatedOutputsHash,
    };
    if (validatedModelBehaviorLog !== undefined) {
      body.modelBehaviorLog = validatedModelBehaviorLog;
    }
    if (validatedCorroborationResults !== undefined) {
      body.corroborationResults = validatedCorroborationResults;
    }
    if (validatedStorageUri !== undefined) {
      body.storageUri = validatedStorageUri;
    }
    if (validatedMetadata !== undefined) {
      body.metadata = validatedMetadata;
    }

    const path = `/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/bundles`;

    return this.client
      ._request<AddBundleResponse>({
        method: "POST",
        path,
        body,
        options,
      })
      .then((result) => {
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `evidencePack.addBundle: expected an object response from the ` +
              `kernel (got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;

        const bundleRaw = objectHasOwn(obj, "bundle") ? obj.bundle : undefined;
        validateBundle(bundleRaw, "evidencePack.addBundle", "response.bundle");

        const packRaw = objectHasOwn(obj, "pack") ? obj.pack : undefined;
        validatePack(packRaw, "evidencePack.addBundle", "response.pack");

        const hashCollisionRaw = objectHasOwn(obj, "hashCollision")
          ? obj.hashCollision
          : undefined;
        validateHashCollision(
          hashCollisionRaw,
          "evidencePack.addBundle",
          "response.hashCollision",
        );

        return result;
      });
  }

  /**
   * Sign a draft evidence pack, transitioning it `draft → signed` and
   * finalizing it into an auditor-visible compliance artifact. Wraps
   * `POST /api/v1/evidence-packs/{id}/sign`.
   *
   * The kernel recomputes the pack's `content_hash` over its current
   * bundle list on sign (never trusting the stored column), writes
   * `signed_at` + `signed_by_user_id` + (when provided)
   * `attestation_certificate_id`, and appends an `evidence_pack.signed`
   * audit-log entry — all atomic inside one per-org-locked transaction.
   *
   * **Auth: ADMIN-only** — the kernel gates `sessionRoles:['admin']` +
   * `apiKeyPermissions:[ADMIN]`. A non-admin key → 403.
   *
   * **Empty-pack guard**: signing a pack with no bundles → 409 with
   * `details.code === "evidence_pack.empty"` (a dedicated `EmptyPackError`,
   * NOT `InvalidStateError` — so it carries NO `currentStatus`; the pack
   * IS in the right `draft` pre-sign state, it just has nothing to sign).
   *
   * **Idempotency**: the kernel does NOT honor `Idempotency-Key` on sign
   * (a replay 409s with `currentStatus='signed'`); the SDK sends none.
   *
   * Errors — ordered by kernel firing precedence. The route validates the
   * URL-path UUID via `packPathParamsSchema.safeParse` BEFORE
   * `requireSessionOrApiKey`, so a malformed path UUID surfaces as 400
   * BEFORE 401/403:
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried).
   *   - `AttestryAPIError` (status 400 — path UUID) — malformed URL-path
   *     packId. **Fires BEFORE auth.** The SDK pre-validates the UUID, so
   *     this surface is only reachable via SDK rule changes.
   *   - `AttestryAPIError` (status 401 / 403) — auth missing / key is not
   *     ADMIN.
   *   - `AttestryAPIError` (status 400 — JSON parse) — malformed body.
   *     **Fires AFTER auth.**
   *   - `AttestryAPIError` (status 422) — Zod validation failed
   *     (`details.code === "evidence_pack.validation_failed"`).
   *   - `AttestryAPIError` (status 404) — pack missing OR cross-org OR
   *     (when an `attestationCertificateId` is supplied) the cert is
   *     missing / cross-org / cross-system (anti-enumeration — same
   *     "pack not found" message).
   *   - `AttestryAPIError` (status 409) — `InvalidStateError` (pack not in
   *     `draft`; `details.currentStatus` carries the state) OR
   *     `EmptyPackError` (`details.code === "evidence_pack.empty"`).
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — abort.
   *   - `AttestryError` (P2 hardening) — response-shape violation.
   *   - `AttestryAPIError` (P3 hardening) — non-JSON response.
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **SDK-side validation**:
   *   - `input`: required; non-null, non-array object.
   *   - `input.packId`: required own-property; non-empty UUID string.
   *   - `input.attestationCertificateId` (when own-present): UUID format.
   *
   * **Response-shape validation** (P2 hardening): the signed `EvidencePack`.
   *
   * @example
   * ```ts
   * const signed = await client.evidencePack.sign({
   *   packId: "11111111-1111-1111-1111-111111111111",
   * });
   * console.log(signed.status, signed.contentHash); // "signed", "sha256:..."
   * ```
   */
  sign(
    input: SignEvidencePackInput,
    options?: RequestOptions,
  ): Promise<EvidencePack> {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError(
        "evidencePack.sign: `input` must be a non-null object with `packId`",
      );
    }

    const hasPackId = objectHasOwn(input, "packId");
    const packIdRaw: unknown = hasPackId
      ? readInputField(input, "packId", "evidencePack.sign")
      : undefined;
    const hasAttestationCertificateId = objectHasOwn(
      input,
      "attestationCertificateId",
    );
    const attestationCertificateIdRaw: unknown = hasAttestationCertificateId
      ? readInputField(input, "attestationCertificateId", "evidencePack.sign")
      : undefined;

    if (!hasPackId || packIdRaw === undefined) {
      throw new TypeError("evidencePack.sign: `packId` is required");
    }
    if (typeof packIdRaw !== "string" || packIdRaw.length === 0) {
      throw new TypeError(
        "evidencePack.sign: `packId` must be a non-empty string",
      );
    }
    if (!UUID_REGEX.test(packIdRaw)) {
      throw new TypeError(
        "evidencePack.sign: `packId` must be an RFC 4122 hyphenated UUID",
      );
    }

    let validatedAttestationCertificateId: string | undefined;
    if (
      hasAttestationCertificateId &&
      attestationCertificateIdRaw !== undefined
    ) {
      if (typeof attestationCertificateIdRaw !== "string") {
        throw new TypeError(
          `evidencePack.sign: \`attestationCertificateId\` must be a string ` +
            `when provided (got ${describeType(attestationCertificateIdRaw)})`,
        );
      }
      if (!UUID_REGEX.test(attestationCertificateIdRaw)) {
        throw new TypeError(
          "evidencePack.sign: `attestationCertificateId` must be an RFC 4122 " +
            "hyphenated UUID",
        );
      }
      validatedAttestationCertificateId = attestationCertificateIdRaw;
    }

    // Body from validated locals only (F-CR-1). Always an object (never
    // undefined) so the transport sets Content-Type and the kernel route's
    // `parseBody` gets valid JSON; `{}` when no cert (mirrors the MCP tool).
    const body: { attestationCertificateId?: string } = {};
    if (validatedAttestationCertificateId !== undefined) {
      body.attestationCertificateId = validatedAttestationCertificateId;
    }

    const path = `/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/sign`;

    return this.client
      ._request<EvidencePack>({
        method: "POST",
        path,
        body,
        options,
      })
      .then((result) => {
        validatePack(result, "evidencePack.sign", "response");
        return result;
      });
  }

  /**
   * Supersede a signed evidence pack: transitions the old pack
   * `signed → superseded` and creates a NEW draft pack linked to it
   * (`parent_pack_id = oldPackId`). Wraps
   * `POST /api/v1/evidence-packs/{id}/supersede`.
   *
   * Both packs are returned (`{newPack, oldPack}`, HTTP 201). The two
   * operations + the audit-log entry commit atomically inside one
   * per-org-locked transaction.
   *
   * **Auth**: WRITE_ASSESSMENTS (NOT admin — supersede is a normal write).
   *
   * **`newPack` includes `consumerHints`** (unlike `create`, which omits
   * it) — mirroring the kernel `supersedeNewPackPayloadSchema` and the
   * P1.7 MCP supersede tool.
   *
   * **Idempotency**: the kernel route honors `Idempotency-Key` on
   * supersede, but the SDK does NOT send it (R-2 carry-forward — same as
   * `create` / `addBundle`). Consumers needing safe retry today should
   * dedupe client-side.
   *
   * Errors — ordered by kernel firing precedence (path-uuid 400 BEFORE
   * auth). The SDK does not send `Idempotency-Key`, so the idempotency-
   * format-400 / idempotency-conflict-409 surfaces are unreachable from
   * the SDK:
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried).
   *   - `AttestryAPIError` (status 400 — path UUID) — malformed URL-path
   *     packId. **Fires BEFORE auth.** Reachable only via SDK rule changes.
   *   - `AttestryAPIError` (status 401 / 403) — auth missing / lacks
   *     WRITE_ASSESSMENTS.
   *   - `AttestryAPIError` (status 400 — JSON parse) — malformed body.
   *   - `AttestryAPIError` (status 422) — Zod validation failed on
   *     `newPack` (`details.code === "evidence_pack.validation_failed"`).
   *   - `AttestryAPIError` (status 404) — old pack missing OR cross-org.
   *   - `AttestryAPIError` (status 409) — `InvalidStateError` (old pack not
   *     in `signed` state; `details.currentStatus` carries the state).
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — abort.
   *   - `AttestryError` (P2 hardening) — response-shape violation.
   *   - `AttestryAPIError` (P3 hardening) — non-JSON response.
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **SDK-side validation**:
   *   - `input`: required; non-null, non-array object.
   *   - `input.packId`: required own-property; non-empty UUID string.
   *   - `input.newPack`: required own-property; non-null, non-array object.
   *   - `input.newPack.packType`: required; member of `PACK_TYPES`.
   *   - `input.newPack.systemId` (when own-present): UUID format.
   *   - `input.newPack.frameworkBindings` (when own-present): array of
   *     length ≤50. Per-entry shape is open-spec (kernel deep-validates).
   *   - `input.newPack.consumerHints` (when own-present): non-null,
   *     non-array object. Inner shape open-spec (kernel deep-validates).
   *   - `input.newPack.metadata` (when own-present): non-null, non-array
   *     object.
   *
   * **Response-shape validation** (P2 hardening): `newPack` and `oldPack`
   * are each a full `EvidencePack`.
   *
   * @example
   * ```ts
   * const { newPack, oldPack } = await client.evidencePack.supersede({
   *   packId: "11111111-1111-1111-1111-111111111111", // the signed pack
   *   newPack: {
   *     packType: "annex_iv",
   *     frameworkBindings: [{ framework: "eu_ai_act", identifier: "Annex.IV.1" }],
   *   },
   * });
   * console.log(oldPack.status, newPack.status); // "superseded", "draft"
   * console.log(newPack.parentPackId === oldPack.id); // true
   * ```
   */
  supersede(
    input: SupersedeEvidencePackInput,
    options?: RequestOptions,
  ): Promise<SupersedeEvidencePackResponse> {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError(
        "evidencePack.supersede: `input` must be a non-null object with " +
          "`packId` and `newPack`",
      );
    }

    const hasPackId = objectHasOwn(input, "packId");
    const packIdRaw: unknown = hasPackId
      ? readInputField(input, "packId", "evidencePack.supersede")
      : undefined;
    const hasNewPack = objectHasOwn(input, "newPack");
    const newPackRaw: unknown = hasNewPack
      ? readInputField(input, "newPack", "evidencePack.supersede")
      : undefined;

    // packId REQUIRED + UUID.
    if (!hasPackId || packIdRaw === undefined) {
      throw new TypeError("evidencePack.supersede: `packId` is required");
    }
    if (typeof packIdRaw !== "string" || packIdRaw.length === 0) {
      throw new TypeError(
        "evidencePack.supersede: `packId` must be a non-empty string",
      );
    }
    if (!UUID_REGEX.test(packIdRaw)) {
      throw new TypeError(
        "evidencePack.supersede: `packId` must be an RFC 4122 hyphenated UUID",
      );
    }

    // newPack REQUIRED + non-null non-array object.
    if (!hasNewPack || newPackRaw === undefined) {
      throw new TypeError("evidencePack.supersede: `newPack` is required");
    }
    if (
      newPackRaw === null ||
      typeof newPackRaw !== "object" ||
      Array.isArray(newPackRaw)
    ) {
      throw new TypeError(
        `evidencePack.supersede: \`newPack\` must be a non-null object ` +
          `(got ${describeType(newPackRaw)})`,
      );
    }

    // newPack inner fields — snapshot each value EXACTLY ONCE, via
    // `readInputField` so a throwing accessor on the consumer-supplied
    // nested `newPack` object surfaces as the documented synchronous
    // `TypeError` input contract (session-22 hostile MEDIUM-1).
    const hasPackType = objectHasOwn(newPackRaw, "packType");
    const packTypeRaw: unknown = hasPackType
      ? readInputField(newPackRaw, "packType", "evidencePack.supersede")
      : undefined;
    const hasSystemId = objectHasOwn(newPackRaw, "systemId");
    const systemIdRaw: unknown = hasSystemId
      ? readInputField(newPackRaw, "systemId", "evidencePack.supersede")
      : undefined;
    const hasFrameworkBindings = objectHasOwn(newPackRaw, "frameworkBindings");
    const frameworkBindingsRaw: unknown = hasFrameworkBindings
      ? readInputField(newPackRaw, "frameworkBindings", "evidencePack.supersede")
      : undefined;
    const hasConsumerHints = objectHasOwn(newPackRaw, "consumerHints");
    const consumerHintsRaw: unknown = hasConsumerHints
      ? readInputField(newPackRaw, "consumerHints", "evidencePack.supersede")
      : undefined;
    const hasMetadata = objectHasOwn(newPackRaw, "metadata");
    const metadataRaw: unknown = hasMetadata
      ? readInputField(newPackRaw, "metadata", "evidencePack.supersede")
      : undefined;

    // newPack.packType REQUIRED + closed-enum membership.
    if (!hasPackType || packTypeRaw === undefined) {
      throw new TypeError(
        "evidencePack.supersede: `newPack.packType` is required",
      );
    }
    if (typeof packTypeRaw !== "string") {
      throw new TypeError(
        `evidencePack.supersede: \`newPack.packType\` must be a string ` +
          `(got ${describeType(packTypeRaw)})`,
      );
    }
    if (!(PACK_TYPES as readonly string[]).includes(packTypeRaw)) {
      throw new TypeError(
        `evidencePack.supersede: \`newPack.packType\` must be one of ` +
          `${JSON.stringify(PACK_TYPES)} (got ${JSON.stringify(packTypeRaw)})`,
      );
    }
    const validatedPackType = packTypeRaw as PackType;

    // newPack.systemId optional UUID.
    let validatedSystemId: string | undefined;
    if (hasSystemId && systemIdRaw !== undefined) {
      if (typeof systemIdRaw !== "string") {
        throw new TypeError(
          `evidencePack.supersede: \`newPack.systemId\` must be a string when ` +
            `provided (got ${describeType(systemIdRaw)})`,
        );
      }
      if (!UUID_REGEX.test(systemIdRaw)) {
        throw new TypeError(
          "evidencePack.supersede: `newPack.systemId` must be an RFC 4122 " +
            "hyphenated UUID",
        );
      }
      validatedSystemId = systemIdRaw;
    }

    // newPack.frameworkBindings optional array + length cap (Array.from
    // snapshot for TOCTOU defense; per-entry shape open-spec).
    let validatedFrameworkBindings: unknown[] | undefined;
    if (hasFrameworkBindings && frameworkBindingsRaw !== undefined) {
      if (!Array.isArray(frameworkBindingsRaw)) {
        throw new TypeError(
          `evidencePack.supersede: \`newPack.frameworkBindings\` must be an ` +
            `array when provided (got ${describeType(frameworkBindingsRaw)})`,
        );
      }
      const snapshot = Array.from(frameworkBindingsRaw as ArrayLike<unknown>);
      if (snapshot.length > MAX_FRAMEWORK_BINDINGS_LENGTH) {
        throw new TypeError(
          `evidencePack.supersede: \`newPack.frameworkBindings\` array ` +
            `exceeds the kernel's max length of ` +
            `${MAX_FRAMEWORK_BINDINGS_LENGTH} (got ${snapshot.length})`,
        );
      }
      validatedFrameworkBindings = snapshot;
    }

    // newPack.consumerHints optional non-null non-array object (DEV-74).
    let validatedConsumerHints: Record<string, unknown> | undefined;
    if (hasConsumerHints && consumerHintsRaw !== undefined) {
      if (
        consumerHintsRaw === null ||
        typeof consumerHintsRaw !== "object" ||
        Array.isArray(consumerHintsRaw)
      ) {
        throw new TypeError(
          `evidencePack.supersede: \`newPack.consumerHints\` must be a ` +
            `non-null object when provided (got ` +
            `${describeType(consumerHintsRaw)})`,
        );
      }
      validatedConsumerHints = consumerHintsRaw as Record<string, unknown>;
    }

    // newPack.metadata optional non-null non-array object.
    let validatedMetadata: Record<string, unknown> | undefined;
    if (hasMetadata && metadataRaw !== undefined) {
      if (
        metadataRaw === null ||
        typeof metadataRaw !== "object" ||
        Array.isArray(metadataRaw)
      ) {
        throw new TypeError(
          `evidencePack.supersede: \`newPack.metadata\` must be a non-null ` +
            `object when provided (got ${describeType(metadataRaw)})`,
        );
      }
      validatedMetadata = metadataRaw as Record<string, unknown>;
    }

    // Build newPack from validated locals only (F-CR-1). Omit the optional
    // fields the consumer omitted so the kernel applies its defaults.
    const newPack: {
      packType: PackType;
      systemId?: string;
      frameworkBindings?: unknown[];
      consumerHints?: Record<string, unknown>;
      metadata?: Record<string, unknown>;
    } = { packType: validatedPackType };
    if (validatedSystemId !== undefined) newPack.systemId = validatedSystemId;
    if (validatedFrameworkBindings !== undefined) {
      newPack.frameworkBindings = validatedFrameworkBindings;
    }
    if (validatedConsumerHints !== undefined) {
      newPack.consumerHints = validatedConsumerHints;
    }
    if (validatedMetadata !== undefined) newPack.metadata = validatedMetadata;

    const path = `/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/supersede`;

    return this.client
      ._request<SupersedeEvidencePackResponse>({
        method: "POST",
        path,
        body: { newPack },
        options,
      })
      .then((result) => {
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `evidencePack.supersede: expected an object response from the ` +
              `kernel (got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;

        const newPackRawResp = objectHasOwn(obj, "newPack")
          ? obj.newPack
          : undefined;
        validatePack(
          newPackRawResp,
          "evidencePack.supersede",
          "response.newPack",
        );

        const oldPackRawResp = objectHasOwn(obj, "oldPack")
          ? obj.oldPack
          : undefined;
        validatePack(
          oldPackRawResp,
          "evidencePack.supersede",
          "response.oldPack",
        );

        return result;
      });
  }

  /**
   * Revoke a signed evidence pack, transitioning it `signed → revoked`
   * and blocking future verification. Wraps
   * `POST /api/v1/evidence-packs/{id}/revoke`.
   *
   * **No cascade** — revoking a pack does NOT touch its children or the
   * supersession-chain neighbour. Revocation is intentionally NOT
   * idempotent: a second revoke 409s (auditors care about the difference
   * between "revoked once" and "revoked again"; the first is canonical).
   *
   * **Auth: ADMIN-only** — the kernel gates `sessionRoles:['admin']` +
   * `apiKeyPermissions:[ADMIN]`. A non-admin key → 403.
   *
   * Optional `reason` (≤500 chars) is recorded verbatim in the pack's
   * audit-log entry for compliance investigators.
   *
   * Errors — ordered by kernel firing precedence (path-uuid 400 BEFORE
   * auth):
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried).
   *   - `AttestryAPIError` (status 400 — path UUID) — malformed URL-path
   *     packId. **Fires BEFORE auth.** Reachable only via SDK rule changes.
   *   - `AttestryAPIError` (status 401 / 403) — auth missing / not ADMIN.
   *   - `AttestryAPIError` (status 400 — JSON parse) — malformed body.
   *   - `AttestryAPIError` (status 422) — Zod validation failed
   *     (`details.code === "evidence_pack.validation_failed"`).
   *   - `AttestryAPIError` (status 404) — pack missing OR cross-org.
   *   - `AttestryAPIError` (status 409) — `InvalidStateError` (pack not in
   *     `signed` state, e.g. already revoked / still draft / superseded;
   *     `details.currentStatus` carries the state).
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — abort.
   *   - `AttestryError` (P2 hardening) — response-shape violation.
   *   - `AttestryAPIError` (P3 hardening) — non-JSON response.
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **SDK-side validation**:
   *   - `input`: required; non-null, non-array object.
   *   - `input.packId`: required own-property; non-empty UUID string.
   *   - `input.reason` (when own-present): non-empty string; length ≤500.
   *
   * **Response-shape validation** (P2 hardening): the revoked `EvidencePack`.
   *
   * @example
   * ```ts
   * const revoked = await client.evidencePack.revoke({
   *   packId: "11111111-1111-1111-1111-111111111111",
   *   reason: "superseding control framework updated; pack no longer valid",
   * });
   * console.log(revoked.status); // "revoked"
   * ```
   */
  revoke(
    input: RevokeEvidencePackInput,
    options?: RequestOptions,
  ): Promise<EvidencePack> {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError(
        "evidencePack.revoke: `input` must be a non-null object with `packId`",
      );
    }

    const hasPackId = objectHasOwn(input, "packId");
    const packIdRaw: unknown = hasPackId
      ? readInputField(input, "packId", "evidencePack.revoke")
      : undefined;
    const hasReason = objectHasOwn(input, "reason");
    const reasonRaw: unknown = hasReason
      ? readInputField(input, "reason", "evidencePack.revoke")
      : undefined;

    if (!hasPackId || packIdRaw === undefined) {
      throw new TypeError("evidencePack.revoke: `packId` is required");
    }
    if (typeof packIdRaw !== "string" || packIdRaw.length === 0) {
      throw new TypeError(
        "evidencePack.revoke: `packId` must be a non-empty string",
      );
    }
    if (!UUID_REGEX.test(packIdRaw)) {
      throw new TypeError(
        "evidencePack.revoke: `packId` must be an RFC 4122 hyphenated UUID",
      );
    }

    // reason optional non-empty string + length cap.
    let validatedReason: string | undefined;
    if (hasReason && reasonRaw !== undefined) {
      if (typeof reasonRaw !== "string") {
        throw new TypeError(
          `evidencePack.revoke: \`reason\` must be a string when provided ` +
            `(got ${describeType(reasonRaw)})`,
        );
      }
      if (reasonRaw.length === 0) {
        throw new TypeError(
          "evidencePack.revoke: `reason` must be a non-empty string when " +
            "provided",
        );
      }
      if (reasonRaw.length > MAX_REASON_LENGTH) {
        throw new TypeError(
          `evidencePack.revoke: \`reason\` exceeds the maximum length of ` +
            `${MAX_REASON_LENGTH} characters (got ${reasonRaw.length})`,
        );
      }
      validatedReason = reasonRaw;
    }

    // Body from validated locals only (F-CR-1). Always an object; `{}`
    // when no reason (mirrors the MCP tool; route `parseBody` gets valid
    // JSON).
    const body: { reason?: string } = {};
    if (validatedReason !== undefined) body.reason = validatedReason;

    const path = `/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/revoke`;

    return this.client
      ._request<EvidencePack>({
        method: "POST",
        path,
        body,
        options,
      })
      .then((result) => {
        validatePack(result, "evidencePack.revoke", "response");
        return result;
      });
  }

  /**
   * Export an evidence pack as a downloadable artifact. Wraps
   * `GET /api/v1/evidence-packs/{id}/export?format={json|pdf|zip}`.
   *
   * **Returns a non-JSON artifact** (P1.8 DEV-73). Unlike every other
   * method, the kernel export route returns the RAW artifact on success
   * (NOT the `{success,data}` envelope) with a download
   * `Content-Disposition` header. This method therefore routes through the
   * streaming transport and returns an {@link EvidencePackExportResult}
   * wrapping the **un-consumed** `Response`:
   *
   *   - `json` → `await result.response.json()` yields the artifact
   *     `{export:{format,generatedAt,schemaVersion:"evidence-pack-export.v1"},
   *     pack, bundles}`.
   *   - `pdf`  → `await result.response.arrayBuffer()` yields the PDF bytes.
   *   - `zip`  → `result.response.body` is a `ReadableStream<Uint8Array>`
   *     (stream it to disk for large packs), or `await result.response.blob()`.
   *
   * The transport has already verified the HTTP status (a non-2xx threw
   * `AttestryAPIError` — NOT a stream/parse crash) and that the response's
   * `Content-Type` MIME matches the requested format. The SDK does NOT
   * consume or `validatePack` the artifact body — faithful courier (same
   * discipline as `decisions.export` / `auditLog.export`).
   *
   * **Auth**: READ_ASSESSMENTS. **Revoked packs are exportable** (the
   * artifact carries `status:'revoked'` verbatim — no filtering).
   *
   * **No internal timeout** — the streaming transport does not arm the
   * 30s default (a large zip can take longer). Pass `options.signal` from
   * your own `AbortController` to bound the duration.
   *
   * Errors — ordered by kernel firing precedence. **The query-schema parse
   * runs BEFORE auth** in this route, so an absent/unknown `format` 422s
   * BEFORE 401/403:
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried).
   *   - `AttestryAPIError` (status 400 — path UUID) — malformed URL-path
   *     packId. **Fires BEFORE auth.** Reachable only via SDK rule changes.
   *   - `AttestryAPIError` (status 422) — absent / unknown `format`
   *     (`details.code === "evidence_pack.validation_failed"`). **Fires
   *     BEFORE auth.** The SDK pre-validates `format`, so reachable only
   *     via SDK rule changes.
   *   - `AttestryAPIError` (status 401 / 403) — auth missing / lacks
   *     READ_ASSESSMENTS.
   *   - `AttestryAPIError` (status 404) — pack missing OR cross-org.
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — abort.
   *   - `AttestryAPIError` (transport guard) — a 2xx with the wrong
   *     `Content-Type` for the requested format.
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **SDK-side validation**:
   *   - `input`: required; non-null, non-array object.
   *   - `input.packId`: required own-property; non-empty UUID string.
   *   - `input.format`: required own-property; member of `EXPORT_FORMATS`.
   *
   * @example Stream a zip export to disk (Node)
   * ```ts
   * import { Writable } from "node:stream";
   * const { response } = await client.evidencePack.export({
   *   packId: "11111111-1111-1111-1111-111111111111",
   *   format: "zip",
   * });
   * await response.body!.pipeTo(Writable.toWeb(fs.createWriteStream("pack.zip")));
   * ```
   *
   * @example Read the JSON artifact for offline content-hash re-verification
   * ```ts
   * const { response } = await client.evidencePack.export({
   *   packId: "11111111-1111-1111-1111-111111111111",
   *   format: "json",
   * });
   * const artifact = await response.json(); // {export, pack, bundles}
   * ```
   */
  export(
    input: ExportEvidencePackInput,
    options?: RequestOptions,
  ): Promise<EvidencePackExportResult> {
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError(
        "evidencePack.export: `input` must be a non-null object with " +
          "`packId` and `format`",
      );
    }

    const hasPackId = objectHasOwn(input, "packId");
    const packIdRaw: unknown = hasPackId
      ? readInputField(input, "packId", "evidencePack.export")
      : undefined;
    const hasFormat = objectHasOwn(input, "format");
    const formatRaw: unknown = hasFormat
      ? readInputField(input, "format", "evidencePack.export")
      : undefined;

    if (!hasPackId || packIdRaw === undefined) {
      throw new TypeError("evidencePack.export: `packId` is required");
    }
    if (typeof packIdRaw !== "string" || packIdRaw.length === 0) {
      throw new TypeError(
        "evidencePack.export: `packId` must be a non-empty string",
      );
    }
    if (!UUID_REGEX.test(packIdRaw)) {
      throw new TypeError(
        "evidencePack.export: `packId` must be an RFC 4122 hyphenated UUID",
      );
    }

    // format REQUIRED + closed-enum membership (synchronous TypeError).
    if (!hasFormat || formatRaw === undefined) {
      throw new TypeError("evidencePack.export: `format` is required");
    }
    if (typeof formatRaw !== "string") {
      throw new TypeError(
        `evidencePack.export: \`format\` must be a string ` +
          `(got ${describeType(formatRaw)})`,
      );
    }
    if (!(EXPORT_FORMATS as readonly string[]).includes(formatRaw)) {
      throw new TypeError(
        `evidencePack.export: \`format\` must be one of ` +
          `${JSON.stringify(EXPORT_FORMATS)} (got ${JSON.stringify(formatRaw)})`,
      );
    }
    const validatedFormat = formatRaw as ExportFormat;

    const path = `/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/export`;
    const expectedContentType = EXPORT_CONTENT_TYPES[validatedFormat];

    // `export` returns a downloadable artifact, NOT the {success,data}
    // envelope — route through the streaming transport `_streamRequest`
    // (returns the un-consumed Response; sets Accept + the per-format
    // content-type guard from `expectedContentType`; on non-2xx drains the
    // body and throws AttestryAPIError BEFORE the guard runs). The SDK
    // does NOT consume/validate the body (faithful courier; DEV-73). The
    // canonical `contentType` is surfaced from EXPORT_CONTENT_TYPES — the
    // guard guarantees the response MIME equals it.
    return this.client
      ._streamRequest({
        path,
        query: { format: validatedFormat },
        expectedContentType,
        options,
      })
      .then((response) => ({
        format: validatedFormat,
        contentType: expectedContentType,
        contentDisposition: response.headers.get("content-disposition"),
        response,
      }));
  }
}

// ─── Shared validation helpers ──────────────────────────────────────────────

/**
 * Validate an `EvidencePack` response shape (P2 hardening). Throws
 * `AttestryError` on any violation. Used by `create` (the response
 * IS a pack), `get` (the `pack` field), `list` (each item in `items`),
 * and `addBundle` (the `pack` field).
 *
 * Every field read goes through the module-load `objectHasOwn`
 * snapshot — a hostile npm dep that pollutes
 * `Object.prototype.<field>` cannot mask a kernel regression where
 * the field is missing (symmetric prototype-pollution defense, carry-
 * forward of session-16 second-hostile-review MEDIUM #3).
 *
 * Closed-enum fields (`packType`, `status`) are checked as `typeof
 * === "string"` only at runtime — the typed-closed / runtime-open
 * faithful-courier discipline (carry-forward from `vision.ts`
 * `packIntegration.status` / `gate.ts` `gate`). The drift pin is the
 * trip-wire for actual enum drift.
 */
function validatePack(
  value: unknown,
  methodName: string,
  location: string,
): asserts value is EvidencePack {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AttestryError(
      `${methodName}: expected ${location} to be an object ` +
        `(got ${describeType(value)})`,
    );
  }
  const obj = value as Record<string, unknown>;

  // Always-present string fields.
  for (const key of ["id", "packType", "orgId", "status", "createdAt"] as const) {
    const v = objectHasOwn(obj, key) ? obj[key] : undefined;
    if (typeof v !== "string") {
      throw new AttestryError(
        `${methodName}: expected ${location}.${key} to be a string ` +
          `(got ${describeType(v)})`,
      );
    }
  }

  // Nullable string fields (string | null).
  for (const key of [
    "systemId",
    "parentPackId",
    "supersededById",
    "attestationCertificateId",
    "contentHash",
    "signedAt",
    "signedByUserId",
  ] as const) {
    const v = objectHasOwn(obj, key) ? obj[key] : undefined;
    if (v !== null && typeof v !== "string") {
      throw new AttestryError(
        `${methodName}: expected ${location}.${key} to be a string or null ` +
          `(got ${describeType(v)})`,
      );
    }
  }

  // frameworkBindings: array (kernel `notNull` jsonb default `[]`).
  const frameworkBindings = objectHasOwn(obj, "frameworkBindings")
    ? obj.frameworkBindings
    : undefined;
  if (!Array.isArray(frameworkBindings)) {
    throw new AttestryError(
      `${methodName}: expected ${location}.frameworkBindings to be an array ` +
        `(got ${describeType(frameworkBindings)})`,
    );
  }

  // consumerHints, metadata: non-null non-array object (kernel
  // `notNull` jsonb default `{}`).
  for (const key of ["consumerHints", "metadata"] as const) {
    const v = objectHasOwn(obj, key) ? obj[key] : undefined;
    if (v === null || typeof v !== "object" || Array.isArray(v)) {
      throw new AttestryError(
        `${methodName}: expected ${location}.${key} to be a non-null object ` +
          `(got ${describeType(v)})`,
      );
    }
  }
}

/**
 * Validate a `ReperformanceBundle` response shape (P2 hardening).
 * Used by `get` (`bundles[i]`) and `addBundle` (`bundle`).
 */
function validateBundle(
  value: unknown,
  methodName: string,
  location: string,
): asserts value is ReperformanceBundle {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AttestryError(
      `${methodName}: expected ${location} to be an object ` +
        `(got ${describeType(value)})`,
    );
  }
  const obj = value as Record<string, unknown>;

  // Always-present string fields.
  for (const key of [
    "id",
    "evidencePackId",
    "inputsHash",
    "outputsHash",
    "createdAt",
  ] as const) {
    const v = objectHasOwn(obj, key) ? obj[key] : undefined;
    if (typeof v !== "string") {
      throw new AttestryError(
        `${methodName}: expected ${location}.${key} to be a string ` +
          `(got ${describeType(v)})`,
      );
    }
  }

  // storageUri: string | null.
  const storageUri = objectHasOwn(obj, "storageUri")
    ? obj.storageUri
    : undefined;
  if (storageUri !== null && typeof storageUri !== "string") {
    throw new AttestryError(
      `${methodName}: expected ${location}.storageUri to be a string or null ` +
        `(got ${describeType(storageUri)})`,
    );
  }

  // traceContent: array (kernel `notNull` jsonb; runtime is an array).
  const traceContent = objectHasOwn(obj, "traceContent")
    ? obj.traceContent
    : undefined;
  if (!Array.isArray(traceContent)) {
    throw new AttestryError(
      `${methodName}: expected ${location}.traceContent to be an array ` +
        `(got ${describeType(traceContent)})`,
    );
  }

  // modelBehaviorLog, corroborationResults: object | null (both nullable).
  for (const key of ["modelBehaviorLog", "corroborationResults"] as const) {
    const v = objectHasOwn(obj, key) ? obj[key] : undefined;
    if (
      v !== null &&
      (typeof v !== "object" || Array.isArray(v))
    ) {
      throw new AttestryError(
        `${methodName}: expected ${location}.${key} to be an object or null ` +
          `(got ${describeType(v)})`,
      );
    }
  }

  // metadata: non-null non-array object (kernel `notNull` default `{}`).
  const metadata = objectHasOwn(obj, "metadata") ? obj.metadata : undefined;
  if (metadata === null || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new AttestryError(
      `${methodName}: expected ${location}.metadata to be a non-null object ` +
        `(got ${describeType(metadata)})`,
    );
  }
}

/**
 * Validate the `hashCollision` block on the `addBundle` response.
 */
function validateHashCollision(
  value: unknown,
  methodName: string,
  location: string,
): asserts value is HashCollision {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AttestryError(
      `${methodName}: expected ${location} to be an object ` +
        `(got ${describeType(value)})`,
    );
  }
  const obj = value as Record<string, unknown>;

  const detected = objectHasOwn(obj, "detected") ? obj.detected : undefined;
  if (typeof detected !== "boolean") {
    throw new AttestryError(
      `${methodName}: expected ${location}.detected to be a boolean ` +
        `(got ${describeType(detected)})`,
    );
  }

  const count = objectHasOwn(obj, "count") ? obj.count : undefined;
  if (typeof count !== "number") {
    throw new AttestryError(
      `${methodName}: expected ${location}.count to be a number ` +
        `(got ${describeType(count)})`,
    );
  }

  const collidingBundleIds = objectHasOwn(obj, "collidingBundleIds")
    ? obj.collidingBundleIds
    : undefined;
  if (!Array.isArray(collidingBundleIds)) {
    throw new AttestryError(
      `${methodName}: expected ${location}.collidingBundleIds to be an ` +
        `array (got ${describeType(collidingBundleIds)})`,
    );
  }
  for (let i = 0; i < collidingBundleIds.length; i++) {
    if (typeof collidingBundleIds[i] !== "string") {
      throw new AttestryError(
        `${methodName}: expected ${location}.collidingBundleIds[${i}] to ` +
          `be a string (got ${describeType(collidingBundleIds[i])})`,
      );
    }
  }
}

/**
 * Human-readable type description for error messages. Distinguishes
 * `null` and `array` from generic `object`. Duplicated across SDK
 * resource modules per project pattern (small helper, leaf-resource
 * modules, no shared module yet).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
