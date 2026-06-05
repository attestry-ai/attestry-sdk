// ─── Vision resource ────────────────────────────────────────────────────────
//
// Wraps the KE2 P5 vision extraction surface (P5.1–P5.5):
//
//   - POST /api/v1/vision/extract           sync single-document extraction
//   - POST /api/v1/vision/extract/batch     async multi-document submission
//   - GET  /api/v1/vision/extract/jobs/:id  poll an async job
//
// Ninth resource on `@attestry/sdk`. Sibling to `IncidentsResource`,
// `DecisionsResource`, `ChatResource`, `AuditLogResource`,
// `RegulatoryChangesResource`, `ComplianceCheckResource`, `CheckResource`,
// `GateResource`.
//
// Resource-class-per-kernel-resource convention (carry-forward invariant
// #43). Three methods today (`extract`, `extractBatch`, `getJobStatus`).
// All three are JSON request/response; the sync `extract` runs ~25s p50
// (Opus 4.7 vision tail) so the SDK does NOT lower the default 30s
// timeout — consumers extending it pass `{timeoutMs: 60_000}` via
// `RequestOptions` per call.
//
// **`mediaType` is REQUIRED** on both `extract` and `extractBatch` (P5.4
// DEV-10; REQ-04 spec-amendment open in COORDINATION_REQUESTS.md). The
// kernel route's Zod schema requires it; the SDK pre-validates against
// the local frozen `SUPPORTED_MEDIA_TYPES` tuple so a wrong value fails
// synchronously with a `TypeError` rather than a billed 422.
//
// **`base64` XOR `imageUri`** — exactly one of the two image-source
// fields must be supplied on each request (and each batch document).
// The kernel's `.refine` would 422 either way; the SDK pre-validates so
// the request fails BEFORE the network round-trip.
//
// **`packId` is the P5.5 evidence-pack wrap target** — optional UUID on
// `extract`. When supplied, the response carries an additive
// `packIntegration` field describing the wrap outcome. When omitted, the
// response is byte-identical to P5.4 (no `packIntegration` own-property).
// Drift-pinned in the spec-diff round.
//
// **Idempotency-Key header is NOT exposed** in P5.6 (carry-forward).
// The kernel accepts `Idempotency-Key` on `POST /extract/batch`; the
// SDK's `RequestOptions` does not currently surface extra headers for
// JSON POSTs (only `streamRequest` accepts a `headers` parameter).
// Adding it is a clean 5-line forward-compat — see the P5.6 audit doc
// carry-forward section. Consumers who need batch idempotency today
// should retry with their own client-side dedupe.
//
// **Symmetric prototype-pollution defense** — module-load snapshot of
// `Object.hasOwn` applied to BOTH input AND response sides (carry-
// forward of session-16 second-hostile-review MEDIUM #3 generalization;
// freshest implementation in `gate.ts`). Without the snapshot, a late-
// loading hostile/buggy npm dep that overrides the global (e.g.
// `Object.hasOwn = () => true`) would defeat the defense.
//
// **No URIError defense on body fields** — both POSTs use
// `JSON.stringify` (not `encodeURIComponent`), which handles lone UTF-16
// surrogates by emitting them as literal `\uDxxx` escapes. The URIError
// defect class (carry-forward invariant #32) applies only to query-
// string paths. `getJobStatus`'s path segment IS encoded via
// `encodeURIComponent`, but the SDK pre-validates `jobId` as a hyphen-
// only RFC 4122 UUID first, so a malformed input rejects with
// `TypeError` BEFORE the encoder runs.
//
// **P3 content-type guard** — already present in the SDK transport
// (`packages/attestry-sdk/src/transport.ts:271-291` + `readBody` at
// `:543-561`). A non-JSON 200 response (LB HTML error page, plain-text
// proxy body) surfaces as `AttestryAPIError`, NOT an opaque
// `SyntaxError`. P5.6 confirms this; HR-4(b) carry-forward applies to
// `mcp-server/src/client.ts`, NOT to the SDK transport.

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

// Module-load snapshot of `Object.hasOwn`. Mirror of `gate.ts`'s
// pattern. Used symmetrically on input AND response sides — defense on
// both boundaries.
const objectHasOwn = Object.hasOwn;

// RFC 4122 hyphenated UUID (8-4-4-4-12 hex, case-insensitive). Matches
// Zod's `z.string().uuid()` regex effectively. Mirror of `gate.ts`'s
// `UUID_REGEX`; drift-pinned in `sdk-drift.test.ts` (Round 2) so a
// kernel-side switch to a different UUID flavor (ULID, KSUID) fires
// before consumer regressions.
const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Maximum length of an `imageUri` string (kernel `z.string().url().max(2048)`).
 * Mirrored locally as the closed-spec rule the SDK pre-validates.
 */
const MAX_IMAGE_URI_LENGTH = 2048;

/**
 * Maximum length of a base64-encoded image (kernel `ANTHROPIC_IMAGE_MAX_BASE64`
 * in `src/lib/vision/types.ts` — `ceil((5 * 1024 * 1024 * 4) / 3) = 6_990_507`).
 * The kernel rejects oversize with 422; the SDK fails synchronously to save the
 * billed network round-trip. Drift-pinned in `sdk-drift.test.ts` so a kernel-
 * side adjustment surfaces before consumer regressions.
 */
const ANTHROPIC_IMAGE_MAX_BASE64 = 6_990_507;

// ─── Closed-enum frozen tuples (drift-pinned in Round 2) ────────────────────

/**
 * The four image MIME types the kernel accepts via `mediaType`. Mirrors
 * `src/lib/vision/types.ts:23-28` (kernel side). Frozen so consumer code can
 * safely use `SUPPORTED_MEDIA_TYPES.includes(...)` without mutation risk.
 *
 * Drift-pinned in the spec-diff round (`sdk-drift.test.ts`) by text-comparing
 * this declaration with the kernel's. An addition/removal on either side trips
 * the test.
 */
export const SUPPORTED_MEDIA_TYPES = Object.freeze([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif",
] as const);
export type VisionSupportedMediaType = (typeof SUPPORTED_MEDIA_TYPES)[number];

/**
 * The five document-type keys registered in the kernel schema library. Mirrors
 * `src/lib/vision/schemas/index.ts:140-146` (kernel side). Frozen; drift-
 * pinned identically to `SUPPORTED_MEDIA_TYPES`.
 *
 * Schema additions (e.g. a new Annex IV section schema) bump the kernel tuple
 * AND require a new `chore(sdk): bump` to keep the SDK in sync — the drift pin
 * is the trip-wire.
 */
export const SUPPORTED_DOCUMENT_TYPES = Object.freeze([
  "model-card",
  "validation-report",
  "certification-label",
  "schematic-extraction",
  "generic-tabular",
] as const);
export type VisionSupportedDocumentType =
  (typeof SUPPORTED_DOCUMENT_TYPES)[number];

/**
 * Closed enum for the optional `model` field. Mirrors kernel
 * `z.enum(["opus", "sonnet"])` in `src/app/api/v1/vision/extract/route.ts`.
 */
export const VISION_MODELS = Object.freeze(["opus", "sonnet"] as const);
export type VisionModelTier = (typeof VISION_MODELS)[number];

/**
 * `packIntegration.status` closed enum. Mirrors `PackIntegrationResult.status`
 * in kernel `src/lib/vision/pack-integration.ts:315`.
 *
 * Typed as a closed union at compile time; runtime check is `typeof ===
 * "string"` only (faithful courier — same convention as
 * `BulkFailedSummary.code` / `DecisionStreamEvent.eventType`). A future
 * kernel-side `"partial"` would round-trip via the type system; consumers
 * doing exhaustive narrowing should update the SDK type then.
 */
export const PACK_INTEGRATION_STATUSES = Object.freeze([
  "wrapped",
  "failed",
] as const);
export type VisionPackIntegrationStatus =
  (typeof PACK_INTEGRATION_STATUSES)[number];

// ─── Input shapes ────────────────────────────────────────────────────────────

/**
 * Input for `vision.extract`. Mirrors the request body of
 * `POST /api/v1/vision/extract` (kernel `src/app/api/v1/vision/extract/route.ts`
 * `extractBodySchema`).
 *
 * **`base64` XOR `imageUri`** — exactly one MUST be supplied (kernel
 * `.refine` enforces this with 422; the SDK pre-validates synchronously).
 *
 * **`mediaType` is REQUIRED** (P5.4 DEV-10; REQ-04 spec amendment).
 *
 * **`packId` is OPTIONAL** (P5.5). When supplied, the response carries an
 * additive `packIntegration` field. When omitted, the response is byte-
 * identical to P5.4.
 */
export interface VisionExtractInput {
  /**
   * Base64-encoded image bytes. Length-capped at `ANTHROPIC_IMAGE_MAX_BASE64`
   * (~6.99M chars ≈ 5 MB decoded). Mutually exclusive with `imageUri`.
   */
  base64?: string;
  /**
   * HTTPS URL the kernel fetches with SSRF defense (5-second timeout,
   * private-IP block, magic-byte MIME-spoof check). Length-capped at 2048.
   * Mutually exclusive with `base64`.
   */
  imageUri?: string;
  /**
   * Image MIME type. REQUIRED. Must be one of `SUPPORTED_MEDIA_TYPES`.
   */
  mediaType: VisionSupportedMediaType;
  /**
   * Schema-registry key. REQUIRED. Must be one of `SUPPORTED_DOCUMENT_TYPES`.
   */
  documentType: VisionSupportedDocumentType;
  /**
   * Schema-registry key override. When supplied, it (not `documentType`)
   * determines which Zod validator the kernel applies to the extraction.
   * Must be one of `SUPPORTED_DOCUMENT_TYPES`.
   */
  extractionSchema?: VisionSupportedDocumentType;
  /**
   * Model tier preference. Defaults kernel-side to `"opus"` when omitted.
   */
  model?: VisionModelTier;
  /**
   * P5.5 — optional evidence-pack wrap target. RFC 4122 hyphenated UUID. When
   * supplied, the response carries `packIntegration` describing the wrap
   * outcome (success or failure mode).
   */
  packId?: string;
}

/**
 * One document in a `vision.extractBatch` submission. Mirrors
 * `batchDocumentSchema` in `src/lib/vision/batch-submit.ts`.
 *
 * Same `base64` XOR `imageUri` rule as `vision.extract`. `mediaType` is
 * REQUIRED. `sourceImageUri` (optional) is recorded on the per-document call
 * row but NOT used to fetch — it's an audit-pointer URI for downstream
 * reperformance.
 */
export interface VisionBatchDocument {
  base64?: string;
  imageUri?: string;
  mediaType: VisionSupportedMediaType;
  documentType: VisionSupportedDocumentType;
  extractionSchema?: VisionSupportedDocumentType;
  /**
   * Audit-pointer URI persisted on the `vision_extraction_calls` row. Length-
   * capped at 2048.
   */
  sourceImageUri?: string;
}

/**
 * Input for `vision.extractBatch`. Wraps the body of
 * `POST /api/v1/vision/extract/batch` (kernel `batchExtractBodySchema`).
 *
 * **`documents.length >= 1`** — empty arrays reject SDK-side. The kernel
 * upper-bound (`MAX_DOCS_PER_JOB`, currently 10) is NOT duplicated in the
 * SDK (it lives in `src/lib/vision/cron-worker.ts` and is not part of the
 * SDK's public API surface); an oversized batch surfaces as a kernel 422
 * AFTER the full request payload is transmitted. For very large batches
 * (1,000+ base64 documents in a single submission, multi-MB each) this
 * is a bandwidth footgun — consumers should chunk client-side before
 * submitting. (P5.6 R3 hostile note.)
 */
export interface VisionBatchExtractInput {
  documents: VisionBatchDocument[];
  model?: VisionModelTier;
}

// ─── Response shapes ────────────────────────────────────────────────────────

/**
 * `packIntegration.schemaCompatibility` — advisory only; the kernel never
 * gates on it. Mirrors `SchemaCompatibility` in kernel
 * `src/lib/vision/pack-integration.ts:198-207`.
 */
export interface VisionSchemaCompatibility {
  /** `false` when the pack declares no `framework_bindings` (nothing to assess). */
  assessable: boolean;
  /** The vision extraction's effective `documentType`. */
  visionDocumentType: string;
  /** The pack's declared framework bindings (`framework` + `identifier` echo). */
  packFrameworkBindings: Array<{ framework: string; identifier: string }>;
  /** Human-readable advisory string. Open-spec; consumers SHOULD NOT pattern-match. */
  advisory: string;
}

/**
 * `packIntegration.hashCollision` — present when `addBundleToPack` detected
 * one or more prior bundles in the pack with the same `(inputs_hash,
 * outputs_hash)` tuple. The kernel caps the colliding-bundle-id list at 10;
 * the SDK exposes only `{detected, count}` (the count is the kernel-capped
 * value).
 */
export interface VisionPackIntegrationHashCollision {
  detected: boolean;
  count: number;
}

/**
 * `extract` response's optional `packIntegration` field. Mirrors
 * `PackIntegrationResult` in kernel `src/lib/vision/pack-integration.ts:315`.
 *
 * Present ONLY when the request supplied `packId`; the no-`packId` response
 * has no `packIntegration` own-property at all (drift-pinned).
 */
export interface VisionPackIntegrationResult {
  status: VisionPackIntegrationStatus;
  /** The pack the extraction was wrapped into. UUID. */
  packId: string;
  /**
   * The new bundle's UUID. PRESENT when `status === "wrapped"`; absent on
   * failure (a race or a transient DB fault).
   */
  bundleId?: string;
  /**
   * The pack's `content_hash` AFTER the bundle was appended. PRESENT when
   * `status === "wrapped"`. `null` is permitted (the kernel emits `null`
   * when the recomputation hadn't landed at the moment of the response).
   */
  packContentHash?: string | null;
  /** `sha256:` hash of the image input (decoded bytes OR uri string). */
  inputsHash?: string;
  /** `sha256:` hash of the canonical-JSON extraction-output projection. */
  outputsHash?: string;
  hashCollision?: VisionPackIntegrationHashCollision;
  /**
   * Advisory schema-compatibility echo. Always present (regardless of
   * status).
   */
  schemaCompatibility: VisionSchemaCompatibility;
  /**
   * Present when `status === "failed"`. Open-spec `code`; consumers can
   * branch on known values (`"vision.pack_wrap_failed"`,
   * `"evidence_pack.not_found"`, `"evidence_pack.invalid_state"`, ...) but
   * the SDK does NOT close-enum on it (faithful courier — same convention
   * as `BulkFailedSummary.code`).
   */
  error?: { code: string; message: string };
}

/**
 * Token-usage breakdown returned by the `extract` response. Mirrors
 * `TokensUsed` in kernel `src/lib/vision/types.ts:50-55`.
 */
export interface VisionTokensUsed {
  input: number;
  output: number;
  cacheCreation: number;
  cacheRead: number;
}

/**
 * Response for `vision.extract`. Mirrors the `successResponse(...)` body of
 * `src/app/api/v1/vision/extract/route.ts` (lines 185-194).
 *
 * `structuredExtraction` is `null` when the Anthropic response did not parse
 * to JSON (`parseError: 'parse_failed'` in the underlying call row). The
 * extraction was still billed and persisted; consumers detect this by
 * `result.structuredExtraction === null`.
 */
export interface VisionExtractResponse {
  /** UUID of the persisted `vision_extraction_calls` row. */
  callId: string;
  /**
   * The parsed JSON extraction OR `null` on a parse failure. Open-spec shape
   * — varies per `documentType` (model-card, validation-report, etc.).
   */
  structuredExtraction: Record<string, unknown> | null;
  /** Per-field confidence scores from the extraction (0..1 floats). */
  confidencePerField: Record<string, number>;
  /** Per-field source-region descriptions (free-text). */
  sourceRegions: Record<string, string>;
  tokensUsed: VisionTokensUsed;
  /** Cost in USD cents (integer). */
  costUsdCents: number;
  /** Wall-clock latency of the underlying Anthropic call, milliseconds. */
  latencyMs: number;
  /**
   * Additive P5.5 surface. PRESENT only when the request supplied `packId`;
   * the no-`packId` response has no `packIntegration` own-property.
   */
  packIntegration?: VisionPackIntegrationResult;
}

/**
 * Response for `vision.extractBatch`. The route returns HTTP 202 with this
 * body wrapped in `successResponse`. `status` is always literal `"queued"`
 * at submission time; consumers poll `vision.getJobStatus(jobId)` to observe
 * status transitions.
 */
export interface VisionBatchExtractResponse {
  jobId: string;
  status: "queued";
}

/**
 * Response for `vision.getJobStatus`. Mirrors the projection in
 * `src/app/api/v1/vision/extract/jobs/[jobId]/route.ts:67-83`.
 *
 * `errorLog`, `resultPackId`, `startedAt`, `completedAt` are nullable (the
 * job's terminal state determines which are non-null). `status` is the
 * kernel enum `'queued' | 'processing' | 'completed' | 'failed' | 'partial'`
 * but typed as `string` for forward-compat (a future kernel value would
 * round-trip without an SDK bump — same forward-compat convention as
 * `humanOversightState`).
 *
 * `costTokensInput` / `costTokensOutput` come from `bigint` Postgres columns;
 * Drizzle may serialize them as `number` (in-range) or `string` (out-of-
 * range Number.MAX_SAFE_INTEGER). The SDK accepts either at runtime.
 *
 * `config` (the raw batch request, which can hold base64 image payloads)
 * is INTENTIONALLY NOT echoed back by the kernel (P5.4 audit concern #21
 * + DEV-2) — payload-size privacy + anti-replay. The SDK type reflects
 * this faithfully (no `config` field).
 */
export interface VisionJobStatus {
  jobId: string;
  /** `'queued' | 'processing' | 'completed' | 'failed' | 'partial'`. */
  status: string;
  documentCount: number;
  documentsProcessed: number;
  /** Echoed from the request's `model` (`"opus"` / `"sonnet"`). */
  modelTier: string;
  costUsdCents: number;
  /** bigint column — `number` (in-range) or `string` (out-of-range). */
  costTokensInput: number | string;
  costTokensOutput: number | string;
  /**
   * jsonb column. Open-spec — entries are
   * `{docIndex: number, error: string}` (P5.3 partial-failure schema), but
   * the SDK does NOT enforce inner shape (faithful courier).
   */
  errorLog: unknown[] | null;
  /** UUID of the result evidence pack, IF the job's config wired one. */
  resultPackId: string | null;
  /** ISO-8601 timestamp. */
  createdAt: string;
  /** ISO-8601 timestamp; null when status === 'queued'. */
  startedAt: string | null;
  /** ISO-8601 timestamp; null until status is a terminal value. */
  completedAt: string | null;
}

// ─── Resource class ─────────────────────────────────────────────────────────

/**
 * `vision` resource — sibling to `IncidentsResource`, `DecisionsResource`,
 * `ChatResource`, `AuditLogResource`, `RegulatoryChangesResource`,
 * `ComplianceCheckResource`, `CheckResource`, `GateResource`.
 *
 * Three methods today (`extract`, `extractBatch`, `getJobStatus`). All three
 * are JSON request/response (no SSE / NDJSON). The class is also the landing
 * pad for future vision methods (e.g. a `listSupportedSchemas` once a kernel
 * route surfaces it — currently exposed only as an MCP tool).
 */
export class VisionResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Synchronously extract structured data from a single regulatory document
   * image. Wraps `POST /api/v1/vision/extract`.
   *
   * **Latency**: ~25.5s p50 with Opus 4.7 (`KE2-P5-VISION.md` §"Empirical
   * findings"); tail latency approaches the kernel `maxDuration: 60s`. The
   * SDK does NOT lower the default `timeoutMs: 30_000` for this method
   * (resource methods do not override per-method timeouts in `@attestry/sdk`).
   * Latency-sensitive consumers MAY raise it via `{timeoutMs: 60_000}` per
   * call.
   *
   * **Cost**: ~$0.22 per Opus 4.7 call; Sonnet 4 is ~5–6× cheaper. The cost
   * is returned in `response.costUsdCents` (integer).
   *
   * **`mediaType` is REQUIRED** (P5.4 DEV-10). The SDK rejects requests
   * without it synchronously (`TypeError`), saving the network round-trip
   * the kernel would otherwise 422.
   *
   * **`packId` is the P5.5 evidence-pack wrap target** — optional UUID.
   * When supplied, the response carries `packIntegration` describing the
   * wrap outcome:
   *   - success → `{status: "wrapped", packId, bundleId, packContentHash,
   *     inputsHash, outputsHash, hashCollision?, schemaCompatibility}`
   *   - post-extraction wrap failure (race / transient DB fault) →
   *     `{status: "failed", packId, schemaCompatibility, error}` —
   *     the extraction itself succeeded and is returned in the same response.
   *   - caller-error wrap target (unknown / cross-org / non-draft pack) →
   *     fails as `AttestryAPIError` BEFORE the billed extraction (the
   *     kernel's pre-flight catches these and returns 4xx; nothing is
   *     billed). The SDK does NOT pre-validate pack state; the kernel is
   *     the authority.
   *
   * Errors — ordered by kernel firing precedence (rate-limit → auth → body
   * parse → pre-flight pack → vision extraction → wrap). A request with
   * multiple problems surfaces ONLY the highest-precedence one.
   *
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST (auto-
   *     retried by default — invariant #18; per-IP rate-limit key
   *     `vision-extract:${ip}`).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *   - `AttestryAPIError` (status 403) — authenticated key lacks
   *     `WRITE_ASSESSMENTS` permission.
   *   - `AttestryAPIError` (status 400) — JSON parse failure on the body
   *     OR a kernel-side vision-validation rejection (`vision.<code>`).
   *   - `AttestryAPIError` (status 422) — Zod validation failed (`details.code`
   *     === `"vision.validation_failed"`; `details.issues` carries the
   *     field paths).
   *   - `AttestryAPIError` (status 404) — `packId` does not exist OR
   *     belongs to another org (anti-enumeration collapse; per
   *     `mapEvidencePackError`).
   *   - `AttestryAPIError` (status 409) — `packId` is not in `draft`
   *     state (signed / superseded / revoked / expired).
   *   - `AttestryAPIError` (status 502) — upstream Anthropic / DNS /
   *     gateway fault (`vision.<code>`).
   *   - `AttestryAPIError` (status 503) — extraction completed but the
   *     call row failed to persist (`vision.persist_failed`).
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` ("request aborted by caller") — caller-supplied
   *     `options.signal` fired (pre-aborted or mid-flight).
   *   - `AttestryError` (P2 hardening) — kernel response failed SDK-side
   *     shape validation (not an object, wrong type on any field).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a wrong
   *     `Content-Type` (transport-level guard at `transport.ts:271-291`,
   *     before body parsing).
   *   - `TypeError` (synchronous, no fetch issued) — input failed SDK-side
   *     validation (null / array / non-object input; missing or bad
   *     `mediaType` / `documentType`; bad `base64` / `imageUri` XOR;
   *     oversized `imageUri` / `base64`; bad `model` / `extractionSchema`
   *     enum; bad `packId` UUID).
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch issued):
   *   - `input` itself: required; must be a non-null, non-array object.
   *   - `input.mediaType`: required own-property; must be a member of
   *     `SUPPORTED_MEDIA_TYPES`.
   *   - `input.documentType`: required own-property; must be a member of
   *     `SUPPORTED_DOCUMENT_TYPES`.
   *   - `input.base64` XOR `input.imageUri`: exactly one own-property must
   *     be present with a non-empty string value.
   *   - `input.base64` (when present): non-empty string, length ≤
   *     ANTHROPIC_IMAGE_MAX_BASE64.
   *   - `input.imageUri` (when present): non-empty string, length ≤
   *     2048.
   *   - `input.extractionSchema` (when own-present, value not undefined):
   *     must be a member of `SUPPORTED_DOCUMENT_TYPES`.
   *   - `input.model` (when own-present, value not undefined): must be a
   *     member of `VISION_MODELS`.
   *   - `input.packId` (when own-present, value not undefined): must be a
   *     non-empty string matching `UUID_REGEX`.
   *
   * **Response-shape validation** (P2 hardening; symmetric to input-side
   * prototype-pollution defense): every documented response field is
   * type-checked via the `objectHasOwn` snapshot. A hostile npm dep that
   * pollutes `Object.prototype.<field>` cannot mask a kernel regression
   * where the field is missing.
   *
   * @example Basic single-image extraction
   * ```ts
   * const result = await client.vision.extract({
   *   base64: "iVBORw0KGgoAAAANSUhEUgAA...",
   *   mediaType: "image/png",
   *   documentType: "model-card",
   * });
   * console.log(result.structuredExtraction);
   * console.log(`cost: ${result.costUsdCents / 100} USD`);
   * ```
   *
   * @example Extraction wrapped into an evidence pack (P5.5)
   * ```ts
   * const result = await client.vision.extract({
   *   imageUri: "https://example.com/cert.png",
   *   mediaType: "image/png",
   *   documentType: "certification-label",
   *   model: "sonnet",                          // cheaper tier for high-volume
   *   packId: "11111111-1111-1111-1111-111111111111",
   * });
   * if (result.packIntegration?.status === "wrapped") {
   *   console.log("bundle:", result.packIntegration.bundleId);
   * }
   * ```
   */
  extract(
    input: VisionExtractInput,
    options?: RequestOptions,
  ): Promise<VisionExtractResponse> {
    // Top-level shape — input is REQUIRED. typeof null === "object" and
    // typeof [] === "object", so guard both explicitly.
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "vision.extract: `input` must be a non-null object",
      );
    }

    // Snapshot each field's value EXACTLY ONCE up front via the own-property
    // indexer. Three motivations (same as `gate.ts`):
    //   1. Prototype-pollution defense (generalization of invariant #48): a
    //      late-set `Object.prototype.documentType` cannot trick the SDK
    //      into silently sending a polluted value when the caller passes
    //      `{}`. The module-load `objectHasOwn` snapshot defends against a
    //      late-loading hostile dep too.
    //   2. TOCTOU defense: a Proxy / getter-defining input could yield
    //      different values across multiple reads. Snapshotting once
    //      collapses validate-then-send to a single read per field.
    //   3. Explicit `{}` (no other fields) is treated as those-fields-omitted
    //      — `objectHasOwn` correctly returns false on missing keys.
    //   4. Throwing-getter defense — each read goes through
    //      `readInputField`, converting a throwing accessor's exception
    //      into the documented synchronous `TypeError` input contract
    //      (session-22 hostile MEDIUM-1).
    const hasBase64 = objectHasOwn(input, "base64");
    const base64Raw: unknown = hasBase64
      ? readInputField(input, "base64", "vision.extract")
      : undefined;
    const hasImageUri = objectHasOwn(input, "imageUri");
    const imageUriRaw: unknown = hasImageUri
      ? readInputField(input, "imageUri", "vision.extract")
      : undefined;
    const hasMediaType = objectHasOwn(input, "mediaType");
    const mediaTypeRaw: unknown = hasMediaType
      ? readInputField(input, "mediaType", "vision.extract")
      : undefined;
    const hasDocumentType = objectHasOwn(input, "documentType");
    const documentTypeRaw: unknown = hasDocumentType
      ? readInputField(input, "documentType", "vision.extract")
      : undefined;
    const hasExtractionSchema = objectHasOwn(input, "extractionSchema");
    const extractionSchemaRaw: unknown = hasExtractionSchema
      ? readInputField(input, "extractionSchema", "vision.extract")
      : undefined;
    const hasModel = objectHasOwn(input, "model");
    const modelRaw: unknown = hasModel
      ? readInputField(input, "model", "vision.extract")
      : undefined;
    const hasPackId = objectHasOwn(input, "packId");
    const packIdRaw: unknown = hasPackId
      ? readInputField(input, "packId", "vision.extract")
      : undefined;

    // mediaType REQUIRED + closed-enum membership.
    if (!hasMediaType || mediaTypeRaw === undefined) {
      throw new TypeError(
        "vision.extract: `mediaType` is required",
      );
    }
    if (typeof mediaTypeRaw !== "string") {
      throw new TypeError(
        `vision.extract: \`mediaType\` must be a string ` +
          `(got ${describeType(mediaTypeRaw)})`,
      );
    }
    if (
      !(SUPPORTED_MEDIA_TYPES as readonly string[]).includes(mediaTypeRaw)
    ) {
      throw new TypeError(
        `vision.extract: \`mediaType\` must be one of ` +
          `${JSON.stringify(SUPPORTED_MEDIA_TYPES)} (got ` +
          `${JSON.stringify(mediaTypeRaw)})`,
      );
    }
    const validatedMediaType = mediaTypeRaw as VisionSupportedMediaType;

    // documentType REQUIRED + closed-enum membership.
    if (!hasDocumentType || documentTypeRaw === undefined) {
      throw new TypeError(
        "vision.extract: `documentType` is required",
      );
    }
    if (typeof documentTypeRaw !== "string") {
      throw new TypeError(
        `vision.extract: \`documentType\` must be a string ` +
          `(got ${describeType(documentTypeRaw)})`,
      );
    }
    if (
      !(SUPPORTED_DOCUMENT_TYPES as readonly string[]).includes(
        documentTypeRaw,
      )
    ) {
      throw new TypeError(
        `vision.extract: \`documentType\` must be one of ` +
          `${JSON.stringify(SUPPORTED_DOCUMENT_TYPES)} (got ` +
          `${JSON.stringify(documentTypeRaw)})`,
      );
    }
    const validatedDocumentType =
      documentTypeRaw as VisionSupportedDocumentType;

    // base64 XOR imageUri — exactly one own-present + non-empty string.
    // Empty strings reject in the per-field branches below; the XOR test
    // operates on "has-and-non-undefined" so {base64: undefined, imageUri:
    // "..."} is still treated as imageUri-only.
    const presentBase64 = hasBase64 && base64Raw !== undefined;
    const presentImageUri = hasImageUri && imageUriRaw !== undefined;
    if (presentBase64 && presentImageUri) {
      throw new TypeError(
        "vision.extract: `base64` and `imageUri` are mutually exclusive — " +
          "supply exactly one",
      );
    }
    if (!presentBase64 && !presentImageUri) {
      throw new TypeError(
        "vision.extract: exactly one of `base64` or `imageUri` is required",
      );
    }

    let validatedBase64: string | undefined;
    if (presentBase64) {
      if (typeof base64Raw !== "string") {
        throw new TypeError(
          `vision.extract: \`base64\` must be a string ` +
            `(got ${describeType(base64Raw)})`,
        );
      }
      if (base64Raw.length === 0) {
        throw new TypeError(
          "vision.extract: `base64` must be a non-empty string",
        );
      }
      if (base64Raw.length > ANTHROPIC_IMAGE_MAX_BASE64) {
        throw new TypeError(
          `vision.extract: \`base64\` exceeds the maximum length of ` +
            `${ANTHROPIC_IMAGE_MAX_BASE64} characters (got ${base64Raw.length})`,
        );
      }
      validatedBase64 = base64Raw;
    }

    let validatedImageUri: string | undefined;
    if (presentImageUri) {
      if (typeof imageUriRaw !== "string") {
        throw new TypeError(
          `vision.extract: \`imageUri\` must be a string ` +
            `(got ${describeType(imageUriRaw)})`,
        );
      }
      if (imageUriRaw.length === 0) {
        throw new TypeError(
          "vision.extract: `imageUri` must be a non-empty string",
        );
      }
      if (imageUriRaw.length > MAX_IMAGE_URI_LENGTH) {
        throw new TypeError(
          `vision.extract: \`imageUri\` exceeds the maximum length of ` +
            `${MAX_IMAGE_URI_LENGTH} characters (got ${imageUriRaw.length})`,
        );
      }
      validatedImageUri = imageUriRaw;
    }

    // Optional extractionSchema — closed-enum membership when own-present.
    let validatedExtractionSchema: VisionSupportedDocumentType | undefined;
    if (hasExtractionSchema && extractionSchemaRaw !== undefined) {
      if (typeof extractionSchemaRaw !== "string") {
        throw new TypeError(
          `vision.extract: \`extractionSchema\` must be a string when provided ` +
            `(got ${describeType(extractionSchemaRaw)})`,
        );
      }
      if (
        !(SUPPORTED_DOCUMENT_TYPES as readonly string[]).includes(
          extractionSchemaRaw,
        )
      ) {
        throw new TypeError(
          `vision.extract: \`extractionSchema\` must be one of ` +
            `${JSON.stringify(SUPPORTED_DOCUMENT_TYPES)} (got ` +
            `${JSON.stringify(extractionSchemaRaw)})`,
        );
      }
      validatedExtractionSchema =
        extractionSchemaRaw as VisionSupportedDocumentType;
    }

    // Optional model — closed-enum membership when own-present.
    let validatedModel: VisionModelTier | undefined;
    if (hasModel && modelRaw !== undefined) {
      if (typeof modelRaw !== "string") {
        throw new TypeError(
          `vision.extract: \`model\` must be a string when provided ` +
            `(got ${describeType(modelRaw)})`,
        );
      }
      if (!(VISION_MODELS as readonly string[]).includes(modelRaw)) {
        throw new TypeError(
          `vision.extract: \`model\` must be one of ` +
            `${JSON.stringify(VISION_MODELS)} (got ` +
            `${JSON.stringify(modelRaw)})`,
        );
      }
      validatedModel = modelRaw as VisionModelTier;
    }

    // Optional packId — UUID pre-validation when own-present.
    let validatedPackId: string | undefined;
    if (hasPackId && packIdRaw !== undefined) {
      if (typeof packIdRaw !== "string") {
        throw new TypeError(
          `vision.extract: \`packId\` must be a string when provided ` +
            `(got ${describeType(packIdRaw)})`,
        );
      }
      if (packIdRaw.length === 0) {
        throw new TypeError(
          "vision.extract: `packId` must be a non-empty string when provided",
        );
      }
      if (!UUID_REGEX.test(packIdRaw)) {
        throw new TypeError(
          "vision.extract: `packId` must be an RFC 4122 hyphenated UUID " +
            "(matched regex: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" +
            "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/)",
        );
      }
      validatedPackId = packIdRaw;
    }

    // Construct the body. Omit any optional field the consumer omitted —
    // the kernel `z.optional()` is the schema authority on the kernel side.
    const body: {
      base64?: string;
      imageUri?: string;
      mediaType: VisionSupportedMediaType;
      documentType: VisionSupportedDocumentType;
      extractionSchema?: VisionSupportedDocumentType;
      model?: VisionModelTier;
      packId?: string;
    } = {
      mediaType: validatedMediaType,
      documentType: validatedDocumentType,
    };
    if (validatedBase64 !== undefined) body.base64 = validatedBase64;
    if (validatedImageUri !== undefined) body.imageUri = validatedImageUri;
    if (validatedExtractionSchema !== undefined) {
      body.extractionSchema = validatedExtractionSchema;
    }
    if (validatedModel !== undefined) body.model = validatedModel;
    if (validatedPackId !== undefined) body.packId = validatedPackId;

    return this.client
      ._request<VisionExtractResponse>({
        method: "POST",
        path: "/api/v1/vision/extract",
        body,
        options,
      })
      .then((result) => {
        // P2 hardening: validate every documented field type. Symmetric
        // prototype-pollution defense — read each field via `objectHasOwn`
        // so a hostile npm dep polluting `Object.prototype.<field>` cannot
        // mask a kernel regression that drops the field.
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `vision.extract: expected an object response from the kernel ` +
              `(got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;

        const callId = objectHasOwn(obj, "callId") ? obj.callId : undefined;
        if (typeof callId !== "string") {
          throw new AttestryError(
            `vision.extract: expected response.callId to be a string ` +
              `(got ${describeType(callId)})`,
          );
        }

        // structuredExtraction: object | null (parse_failed = null).
        const structuredExtraction = objectHasOwn(obj, "structuredExtraction")
          ? obj.structuredExtraction
          : undefined;
        if (
          structuredExtraction !== null &&
          (typeof structuredExtraction !== "object" ||
            Array.isArray(structuredExtraction))
        ) {
          throw new AttestryError(
            `vision.extract: expected response.structuredExtraction to be ` +
              `an object or null (got ` +
              `${describeType(structuredExtraction)})`,
          );
        }

        const confidencePerField = objectHasOwn(obj, "confidencePerField")
          ? obj.confidencePerField
          : undefined;
        if (
          confidencePerField === null ||
          typeof confidencePerField !== "object" ||
          Array.isArray(confidencePerField)
        ) {
          throw new AttestryError(
            `vision.extract: expected response.confidencePerField to be ` +
              `an object (got ${describeType(confidencePerField)})`,
          );
        }

        const sourceRegions = objectHasOwn(obj, "sourceRegions")
          ? obj.sourceRegions
          : undefined;
        if (
          sourceRegions === null ||
          typeof sourceRegions !== "object" ||
          Array.isArray(sourceRegions)
        ) {
          throw new AttestryError(
            `vision.extract: expected response.sourceRegions to be ` +
              `an object (got ${describeType(sourceRegions)})`,
          );
        }

        const tokensUsed = objectHasOwn(obj, "tokensUsed")
          ? obj.tokensUsed
          : undefined;
        if (
          tokensUsed === null ||
          typeof tokensUsed !== "object" ||
          Array.isArray(tokensUsed)
        ) {
          throw new AttestryError(
            `vision.extract: expected response.tokensUsed to be ` +
              `an object (got ${describeType(tokensUsed)})`,
          );
        }
        // `tokensUsed` is a FIXED, always-present, closed 4-number shape
        // (kernel `TokensUsed` in src/lib/vision/types.ts:50-55 — input,
        // output, cacheCreation, cacheRead all `number`). Unlike the
        // optional / conditional / open-spec `packIntegration` sub-fields
        // (faithful courier) and the open-spec `confidencePerField` /
        // `sourceRegions` map VALUES, this shape is fully determined, so
        // the P2 validator enforces each inner field is a number — a kernel
        // regression that mistyped one (e.g. `input: "lots"`) would
        // otherwise round-trip a string typed as `number` to the consumer.
        // (Founder hostile-review F3.) Per-field own-property reads via the
        // module-load `objectHasOwn` snapshot — symmetric with the rest of
        // the response-side prototype-pollution defense.
        const tokensUsedObj = tokensUsed as Record<string, unknown>;
        for (const tf of [
          "input",
          "output",
          "cacheCreation",
          "cacheRead",
        ] as const) {
          const tv = objectHasOwn(tokensUsedObj, tf)
            ? tokensUsedObj[tf]
            : undefined;
          if (typeof tv !== "number") {
            throw new AttestryError(
              `vision.extract: expected response.tokensUsed.${tf} to be a ` +
                `number (got ${describeType(tv)})`,
            );
          }
        }

        const costUsdCents = objectHasOwn(obj, "costUsdCents")
          ? obj.costUsdCents
          : undefined;
        if (typeof costUsdCents !== "number") {
          throw new AttestryError(
            `vision.extract: expected response.costUsdCents to be a number ` +
              `(got ${describeType(costUsdCents)})`,
          );
        }

        const latencyMs = objectHasOwn(obj, "latencyMs")
          ? obj.latencyMs
          : undefined;
        if (typeof latencyMs !== "number") {
          throw new AttestryError(
            `vision.extract: expected response.latencyMs to be a number ` +
              `(got ${describeType(latencyMs)})`,
          );
        }

        // packIntegration — present ONLY when the request supplied packId.
        // The no-packId response has NO own-property here.
        if (objectHasOwn(obj, "packIntegration")) {
          const pi = obj.packIntegration;
          if (pi === null || typeof pi !== "object" || Array.isArray(pi)) {
            throw new AttestryError(
              `vision.extract: expected response.packIntegration to be ` +
                `an object when present (got ${describeType(pi)})`,
            );
          }
          const piObj = pi as Record<string, unknown>;
          const piStatus = objectHasOwn(piObj, "status")
            ? piObj.status
            : undefined;
          if (typeof piStatus !== "string") {
            throw new AttestryError(
              `vision.extract: expected response.packIntegration.status ` +
                `to be a string (got ${describeType(piStatus)})`,
            );
          }
          const piPackId = objectHasOwn(piObj, "packId")
            ? piObj.packId
            : undefined;
          if (typeof piPackId !== "string") {
            throw new AttestryError(
              `vision.extract: expected response.packIntegration.packId ` +
                `to be a string (got ${describeType(piPackId)})`,
            );
          }
          const piSchemaCompat = objectHasOwn(piObj, "schemaCompatibility")
            ? piObj.schemaCompatibility
            : undefined;
          if (
            piSchemaCompat === null ||
            typeof piSchemaCompat !== "object" ||
            Array.isArray(piSchemaCompat)
          ) {
            throw new AttestryError(
              `vision.extract: expected response.packIntegration.` +
                `schemaCompatibility to be an object ` +
                `(got ${describeType(piSchemaCompat)})`,
            );
          }
        }

        return result;
      });
  }

  /**
   * Submit a multi-document batch for asynchronous extraction. Wraps
   * `POST /api/v1/vision/extract/batch`.
   *
   * Returns immediately with the new `jobId` and `status: "queued"`. The
   * Vercel cron `vision-process-batch` (P5.3) drains the job over multiple
   * 5-minute ticks; consumers poll progress via `vision.getJobStatus(jobId)`.
   *
   * **Enterprise plan-gate** — the kernel `requirePlan(org, 'hasBatchVision')`
   * returns 403 with `details.code === "vision.batch.plan_required"` for
   * non-entitled orgs. The SDK forwards the error faithfully.
   *
   * **Per-org active-job ceiling** — the kernel rejects with 429 + `details.
   * code === "vision.batch.queue_limit"` when the org already has 5 jobs in
   * `queued` or `processing` state. The SDK forwards (no client-side count).
   *
   * **`Idempotency-Key` HTTP header is NOT exposed in P5.6** (concern #9 in
   * the audit doc; carry-forward documented). The kernel accepts the header
   * for safe replay, but the SDK transport does not currently surface a
   * way to thread arbitrary headers through JSON POSTs. A future small
   * `chore(sdk):` will add `headers?: Record<string, string>` to
   * `RequestOptions` and a corresponding method-arg here. Consumers needing
   * idempotency today should retry with their own client-side dedupe.
   *
   * Errors — ordered by kernel firing precedence:
   *   - `AttestryAPIError` (status 429) — rate limit OR queue-limit
   *     (`details.code === "vision.batch.queue_limit"`). The rate-limit
   *     variant is auto-retried; the queue-limit variant is NOT (it
   *     indicates persistent backpressure).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *   - `AttestryAPIError` (status 403) — plan-gate denial
   *     (`details.code === "vision.batch.plan_required"`).
   *   - `AttestryAPIError` (status 400) — JSON parse failure on body.
   *   - `AttestryAPIError` (status 422) — Zod validation failed
   *     (`details.code === "vision.validation_failed"`); OR custom
   *     `BatchValidationError` (`details.code === "vision.batch.invalid"`).
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (e.g. `vision_extraction_jobs` INSERT returned no id).
   *   - `AttestryError` — request abort / response shape failure / P3 guard.
   *   - `TypeError` (synchronous, no fetch issued) — input failed SDK-side
   *     validation.
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch issued):
   *   - `input` itself: required; non-null, non-array object.
   *   - `input.documents`: required; non-empty array (SDK enforces
   *     `length >= 1`; kernel's upper bound is NOT duplicated).
   *   - Each document mirrors `extract` validation: required `mediaType`
   *     (enum) + `documentType` (enum); `base64` XOR `imageUri`;
   *     `extractionSchema` / `sourceImageUri` optional with the same caps.
   *   - `input.model` (when own-present, value not undefined): must be a
   *     member of `VISION_MODELS`.
   *
   * @example
   * ```ts
   * const { jobId } = await client.vision.extractBatch({
   *   documents: [
   *     {
   *       imageUri: "https://example.com/cert1.png",
   *       mediaType: "image/png",
   *       documentType: "certification-label",
   *     },
   *     {
   *       imageUri: "https://example.com/cert2.png",
   *       mediaType: "image/png",
   *       documentType: "certification-label",
   *     },
   *   ],
   *   model: "sonnet",
   * });
   * // Poll: while (status !== "completed") { status = (await client.vision
   * //   .getJobStatus(jobId)).status; await new Promise(r => setTimeout(r, 5000)); }
   * ```
   */
  extractBatch(
    input: VisionBatchExtractInput,
    options?: RequestOptions,
  ): Promise<VisionBatchExtractResponse> {
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "vision.extractBatch: `input` must be a non-null object",
      );
    }

    // Snapshot via `readInputField` so a throwing accessor on the
    // consumer-supplied input surfaces as the documented synchronous
    // `TypeError` input contract (session-22 hostile MEDIUM-1); the
    // `objectHasOwn` presence check is a separate pollution defense.
    const hasDocuments = objectHasOwn(input, "documents");
    const documentsRaw: unknown = hasDocuments
      ? readInputField(input, "documents", "vision.extractBatch")
      : undefined;
    const hasModel = objectHasOwn(input, "model");
    const modelRaw: unknown = hasModel
      ? readInputField(input, "model", "vision.extractBatch")
      : undefined;

    if (!hasDocuments || documentsRaw === undefined) {
      throw new TypeError(
        "vision.extractBatch: `documents` is required",
      );
    }
    if (!Array.isArray(documentsRaw)) {
      throw new TypeError(
        `vision.extractBatch: \`documents\` must be an array ` +
          `(got ${describeType(documentsRaw)})`,
      );
    }
    // Snapshot via Array.from up front so a Proxy whose `.length` or `[i]`
    // changes between reads can't slip past validation.
    const docsSnapshot = Array.from(documentsRaw as ArrayLike<unknown>);
    if (docsSnapshot.length === 0) {
      throw new TypeError(
        "vision.extractBatch: `documents` must contain at least one entry",
      );
    }

    // Validate each document; collect a parallel array of validated payloads
    // to forward.
    const validatedDocuments: Array<{
      base64?: string;
      imageUri?: string;
      mediaType: VisionSupportedMediaType;
      documentType: VisionSupportedDocumentType;
      extractionSchema?: VisionSupportedDocumentType;
      sourceImageUri?: string;
    }> = [];
    for (let i = 0; i < docsSnapshot.length; i++) {
      const doc = docsSnapshot[i];
      if (doc === null || typeof doc !== "object" || Array.isArray(doc)) {
        throw new TypeError(
          `vision.extractBatch: \`documents[${i}]\` must be a non-null object ` +
            `(got ${describeType(doc)})`,
        );
      }
      validatedDocuments.push(validateBatchDocument(doc, i));
    }

    let validatedModel: VisionModelTier | undefined;
    if (hasModel && modelRaw !== undefined) {
      if (typeof modelRaw !== "string") {
        throw new TypeError(
          `vision.extractBatch: \`model\` must be a string when provided ` +
            `(got ${describeType(modelRaw)})`,
        );
      }
      if (!(VISION_MODELS as readonly string[]).includes(modelRaw)) {
        throw new TypeError(
          `vision.extractBatch: \`model\` must be one of ` +
            `${JSON.stringify(VISION_MODELS)} (got ` +
            `${JSON.stringify(modelRaw)})`,
        );
      }
      validatedModel = modelRaw as VisionModelTier;
    }

    const body: {
      documents: typeof validatedDocuments;
      model?: VisionModelTier;
    } = { documents: validatedDocuments };
    if (validatedModel !== undefined) body.model = validatedModel;

    return this.client
      ._request<VisionBatchExtractResponse>({
        method: "POST",
        path: "/api/v1/vision/extract/batch",
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
            `vision.extractBatch: expected an object response from the kernel ` +
              `(got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;
        const jobId = objectHasOwn(obj, "jobId") ? obj.jobId : undefined;
        if (typeof jobId !== "string") {
          throw new AttestryError(
            `vision.extractBatch: expected response.jobId to be a string ` +
              `(got ${describeType(jobId)})`,
          );
        }
        const status = objectHasOwn(obj, "status") ? obj.status : undefined;
        if (typeof status !== "string") {
          throw new AttestryError(
            `vision.extractBatch: expected response.status to be a string ` +
              `(got ${describeType(status)})`,
          );
        }
        return result;
      });
  }

  /**
   * Poll the status + cost rollup of an async batch job. Wraps
   * `GET /api/v1/vision/extract/jobs/{jobId}`.
   *
   * **Anti-enumeration 404 collapse** — a job belonging to another org
   * returns 404, identical to an unknown id. Consumers writing defensive
   * error-handling logic must NOT use a 404 to infer "this job ID never
   * existed". The raw `config` jsonb (which can hold base64 image
   * payloads) is INTENTIONALLY NOT echoed back; only status/cost/error
   * columns are projected.
   *
   * Errors:
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *   - `AttestryAPIError` (status 403) — authenticated key lacks
   *     `READ_ASSESSMENTS`.
   *   - `AttestryAPIError` (status 400) — kernel-side malformed UUID
   *     ("Invalid job id."). Pre-validated by the SDK first, so reaches
   *     consumers only via UUID regex drift.
   *   - `AttestryAPIError` (status 404) — not found OR cross-org
   *     (deliberate conflation).
   *   - `AttestryAPIError` (status 500) — internal kernel error.
   *   - `AttestryError` — request abort / response shape failure / P3.
   *   - `TypeError` (synchronous, no fetch issued) — `jobId` empty,
   *     non-string, or not an RFC 4122 hyphenated UUID.
   */
  getJobStatus(
    jobId: string,
    options?: RequestOptions,
  ): Promise<VisionJobStatus> {
    if (typeof jobId !== "string") {
      throw new TypeError(
        `vision.getJobStatus: \`jobId\` must be a string ` +
          `(got ${describeType(jobId)})`,
      );
    }
    if (jobId.length === 0) {
      throw new TypeError(
        "vision.getJobStatus: `jobId` must be a non-empty string",
      );
    }
    // UUID regex pre-validation. Hyphen-only characters: a UUID cannot
    // contain `.`/`..`/NUL/slashes/UTF-16 surrogates, so the path-traversal
    // and encodeURIComponent-URIError guards inherent to other resources
    // are automatically satisfied here.
    if (!UUID_REGEX.test(jobId)) {
      throw new TypeError(
        "vision.getJobStatus: `jobId` must be an RFC 4122 hyphenated UUID " +
          "(matched regex: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" +
          "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/)",
      );
    }
    const encoded = encodeURIComponent(jobId);
    return this.client
      ._request<VisionJobStatus>({
        method: "GET",
        path: `/api/v1/vision/extract/jobs/${encoded}`,
        options,
      })
      .then((result) => {
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `vision.getJobStatus: expected an object response from the kernel ` +
              `(got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;

        // String fields.
        const stringFields = ["jobId", "status", "modelTier", "createdAt"] as const;
        for (const field of stringFields) {
          const v = objectHasOwn(obj, field) ? obj[field] : undefined;
          if (typeof v !== "string") {
            throw new AttestryError(
              `vision.getJobStatus: expected response.${field} to be a string ` +
                `(got ${describeType(v)})`,
            );
          }
        }

        // Number fields (always present).
        const numberFields = [
          "documentCount",
          "documentsProcessed",
          "costUsdCents",
        ] as const;
        for (const field of numberFields) {
          const v = objectHasOwn(obj, field) ? obj[field] : undefined;
          if (typeof v !== "number") {
            throw new AttestryError(
              `vision.getJobStatus: expected response.${field} to be a number ` +
                `(got ${describeType(v)})`,
            );
          }
        }

        // bigint columns: number OR string.
        const bigintFields = ["costTokensInput", "costTokensOutput"] as const;
        for (const field of bigintFields) {
          const v = objectHasOwn(obj, field) ? obj[field] : undefined;
          if (typeof v !== "number" && typeof v !== "string") {
            throw new AttestryError(
              `vision.getJobStatus: expected response.${field} to be a number ` +
                `or string (got ${describeType(v)})`,
            );
          }
        }

        // Nullable fields: errorLog (array | null); resultPackId, startedAt,
        // completedAt (string | null).
        const errorLog = objectHasOwn(obj, "errorLog") ? obj.errorLog : undefined;
        if (errorLog !== null && !Array.isArray(errorLog)) {
          throw new AttestryError(
            `vision.getJobStatus: expected response.errorLog to be an array ` +
              `or null (got ${describeType(errorLog)})`,
          );
        }
        const nullableStringFields = [
          "resultPackId",
          "startedAt",
          "completedAt",
        ] as const;
        for (const field of nullableStringFields) {
          const v = objectHasOwn(obj, field) ? obj[field] : undefined;
          if (v !== null && typeof v !== "string") {
            throw new AttestryError(
              `vision.getJobStatus: expected response.${field} to be a string ` +
                `or null (got ${describeType(v)})`,
            );
          }
        }

        return result;
      });
  }
}

// ─── Internal helpers ───────────────────────────────────────────────────────

/**
 * Validate one batch-document object. Used by `extractBatch`. Returns a
 * frozen payload object with only the validated fields populated (mirrors
 * the per-document body kernel `batchDocumentSchema` accepts).
 *
 * Throws `TypeError` on any rule violation — same contract as `extract`'s
 * top-level validation.
 */
function validateBatchDocument(
  doc: unknown,
  index: number,
): {
  base64?: string;
  imageUri?: string;
  mediaType: VisionSupportedMediaType;
  documentType: VisionSupportedDocumentType;
  extractionSchema?: VisionSupportedDocumentType;
  sourceImageUri?: string;
} {
  const prefix = `vision.extractBatch: \`documents[${index}]\``;
  const d = doc as Record<string, unknown>;

  // Each per-document field read goes through `readInputField` so a
  // throwing accessor on a consumer-supplied `documents[i]` object
  // surfaces as the documented synchronous `TypeError` input contract
  // (session-22 hostile MEDIUM-1); the `objectHasOwn` presence check is
  // a separate pollution defense.
  const hasBase64 = objectHasOwn(d, "base64");
  const base64Raw = hasBase64
    ? readInputField(d, "base64", "vision.extractBatch")
    : undefined;
  const hasImageUri = objectHasOwn(d, "imageUri");
  const imageUriRaw = hasImageUri
    ? readInputField(d, "imageUri", "vision.extractBatch")
    : undefined;
  const hasMediaType = objectHasOwn(d, "mediaType");
  const mediaTypeRaw = hasMediaType
    ? readInputField(d, "mediaType", "vision.extractBatch")
    : undefined;
  const hasDocumentType = objectHasOwn(d, "documentType");
  const documentTypeRaw = hasDocumentType
    ? readInputField(d, "documentType", "vision.extractBatch")
    : undefined;
  const hasExtractionSchema = objectHasOwn(d, "extractionSchema");
  const extractionSchemaRaw = hasExtractionSchema
    ? readInputField(d, "extractionSchema", "vision.extractBatch")
    : undefined;
  const hasSourceImageUri = objectHasOwn(d, "sourceImageUri");
  const sourceImageUriRaw = hasSourceImageUri
    ? readInputField(d, "sourceImageUri", "vision.extractBatch")
    : undefined;

  if (!hasMediaType || mediaTypeRaw === undefined) {
    throw new TypeError(`${prefix}.mediaType is required`);
  }
  if (typeof mediaTypeRaw !== "string") {
    throw new TypeError(
      `${prefix}.mediaType must be a string (got ${describeType(mediaTypeRaw)})`,
    );
  }
  if (!(SUPPORTED_MEDIA_TYPES as readonly string[]).includes(mediaTypeRaw)) {
    throw new TypeError(
      `${prefix}.mediaType must be one of ${JSON.stringify(SUPPORTED_MEDIA_TYPES)} ` +
        `(got ${JSON.stringify(mediaTypeRaw)})`,
    );
  }

  if (!hasDocumentType || documentTypeRaw === undefined) {
    throw new TypeError(`${prefix}.documentType is required`);
  }
  if (typeof documentTypeRaw !== "string") {
    throw new TypeError(
      `${prefix}.documentType must be a string ` +
        `(got ${describeType(documentTypeRaw)})`,
    );
  }
  if (
    !(SUPPORTED_DOCUMENT_TYPES as readonly string[]).includes(documentTypeRaw)
  ) {
    throw new TypeError(
      `${prefix}.documentType must be one of ` +
        `${JSON.stringify(SUPPORTED_DOCUMENT_TYPES)} ` +
        `(got ${JSON.stringify(documentTypeRaw)})`,
    );
  }

  // base64 XOR imageUri.
  const presentBase64 = hasBase64 && base64Raw !== undefined;
  const presentImageUri = hasImageUri && imageUriRaw !== undefined;
  if (presentBase64 && presentImageUri) {
    throw new TypeError(
      `${prefix}: \`base64\` and \`imageUri\` are mutually exclusive — supply exactly one`,
    );
  }
  if (!presentBase64 && !presentImageUri) {
    throw new TypeError(
      `${prefix}: exactly one of \`base64\` or \`imageUri\` is required`,
    );
  }

  let validatedBase64: string | undefined;
  if (presentBase64) {
    if (typeof base64Raw !== "string") {
      throw new TypeError(
        `${prefix}.base64 must be a string (got ${describeType(base64Raw)})`,
      );
    }
    if (base64Raw.length === 0) {
      throw new TypeError(`${prefix}.base64 must be a non-empty string`);
    }
    if (base64Raw.length > ANTHROPIC_IMAGE_MAX_BASE64) {
      throw new TypeError(
        `${prefix}.base64 exceeds the maximum length of ` +
          `${ANTHROPIC_IMAGE_MAX_BASE64} characters (got ${base64Raw.length})`,
      );
    }
    validatedBase64 = base64Raw;
  }

  let validatedImageUri: string | undefined;
  if (presentImageUri) {
    if (typeof imageUriRaw !== "string") {
      throw new TypeError(
        `${prefix}.imageUri must be a string (got ${describeType(imageUriRaw)})`,
      );
    }
    if (imageUriRaw.length === 0) {
      throw new TypeError(`${prefix}.imageUri must be a non-empty string`);
    }
    if (imageUriRaw.length > MAX_IMAGE_URI_LENGTH) {
      throw new TypeError(
        `${prefix}.imageUri exceeds the maximum length of ` +
          `${MAX_IMAGE_URI_LENGTH} characters (got ${imageUriRaw.length})`,
      );
    }
    validatedImageUri = imageUriRaw;
  }

  let validatedExtractionSchema: VisionSupportedDocumentType | undefined;
  if (hasExtractionSchema && extractionSchemaRaw !== undefined) {
    if (typeof extractionSchemaRaw !== "string") {
      throw new TypeError(
        `${prefix}.extractionSchema must be a string when provided ` +
          `(got ${describeType(extractionSchemaRaw)})`,
      );
    }
    if (
      !(SUPPORTED_DOCUMENT_TYPES as readonly string[]).includes(
        extractionSchemaRaw,
      )
    ) {
      throw new TypeError(
        `${prefix}.extractionSchema must be one of ` +
          `${JSON.stringify(SUPPORTED_DOCUMENT_TYPES)} ` +
          `(got ${JSON.stringify(extractionSchemaRaw)})`,
      );
    }
    validatedExtractionSchema =
      extractionSchemaRaw as VisionSupportedDocumentType;
  }

  let validatedSourceImageUri: string | undefined;
  if (hasSourceImageUri && sourceImageUriRaw !== undefined) {
    if (typeof sourceImageUriRaw !== "string") {
      throw new TypeError(
        `${prefix}.sourceImageUri must be a string when provided ` +
          `(got ${describeType(sourceImageUriRaw)})`,
      );
    }
    if (sourceImageUriRaw.length === 0) {
      throw new TypeError(
        `${prefix}.sourceImageUri must be a non-empty string when provided`,
      );
    }
    if (sourceImageUriRaw.length > MAX_IMAGE_URI_LENGTH) {
      throw new TypeError(
        `${prefix}.sourceImageUri exceeds the maximum length of ` +
          `${MAX_IMAGE_URI_LENGTH} characters (got ${sourceImageUriRaw.length})`,
      );
    }
    validatedSourceImageUri = sourceImageUriRaw;
  }

  const out: {
    base64?: string;
    imageUri?: string;
    mediaType: VisionSupportedMediaType;
    documentType: VisionSupportedDocumentType;
    extractionSchema?: VisionSupportedDocumentType;
    sourceImageUri?: string;
  } = {
    mediaType: mediaTypeRaw as VisionSupportedMediaType,
    documentType: documentTypeRaw as VisionSupportedDocumentType,
  };
  if (validatedBase64 !== undefined) out.base64 = validatedBase64;
  if (validatedImageUri !== undefined) out.imageUri = validatedImageUri;
  if (validatedExtractionSchema !== undefined) {
    out.extractionSchema = validatedExtractionSchema;
  }
  if (validatedSourceImageUri !== undefined) {
    out.sourceImageUri = validatedSourceImageUri;
  }
  return out;
}

/**
 * Human-readable type description for error messages. Distinguishes `null`
 * and `array` from generic `object`. Duplicated per project pattern in
 * `decisions.ts` / `incidents.ts` / `gate.ts` / `check.ts` /
 * `compliance-check.ts` / `regulatory-changes.ts` (small helper, leaf-
 * resource modules, no shared module yet).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
