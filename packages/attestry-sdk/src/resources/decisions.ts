// ─── Decisions resource ─────────────────────────────────────────────────────
//
// Wraps the immutable decision-record surface (Prompt 4 / Prompt 8 / Prompt 11):
//
//   - POST /api/v1/decisions           ingest a record (append to the chain)
//   - POST /api/v1/decisions/bulk      append 1-500 records (partial-success envelope)
//   - GET  /api/v1/decisions/:id       retrieve one record
//   - GET  /api/v1/decisions           list (cursor-paginated) — Prompt 8 § 8.2
//   - GET  /api/v1/decisions/stream    SSE feed of records as they're appended
//   - GET  /api/v1/decisions/export    NDJSON export of a system's chain + Merkle trailer
//
// Decision records form an append-only hash-chained log per system; the
// `recordHash` of row N includes `prevRecordHash` of row N-1, so any
// tampering is detectable downstream by `verify-chain`. The kernel
// route deliberately omits `canonicalPayload` from the response (it's
// large BYTEA and only needed by the verifier endpoint).
//
// Cross-org isolation: the retrieve route returns 404 (not 403) when the
// caller does not own the record. The SDK surfaces that as
// `AttestryAPIError` with `status === 404` — the same shape as a genuine
// miss. Existence cannot be enumerated across orgs. The stream + export
// routes apply the same isolation at the WHERE-clause level — a caller
// never receives events / records from another org, regardless of
// cursor or systemId. (Export of a cross-org or nonexistent systemId
// returns 200 with zero records and a trailer with `recordCount: 0`.)

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import { parseNDJSONResponse } from "../ndjson-parser.js";
import { parseSSEData, parseSSEResponse } from "../sse-parser.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

/**
 * Public wire shape for a decision record returned by
 * `GET /api/v1/decisions/:id`. Mirrors the kernel's `successResponse`
 * column projection (canonicalPayload deliberately excluded).
 *
 * jsonb arrays (`frameworkClaims`, `toolInvocations`, `delegationChain`)
 * are typed as `unknown[]` — the SDK does not enforce inner shape; the
 * server already validated them at write time and the SDK is meant to
 * be forward-compatible with kernel-side schema growth.
 */
export interface DecisionRecord {
  id: string;
  orgId: string;
  systemId: string;
  manifestVersionId: string;
  /** Null when no attestation is bound to this record. */
  attestationId: string | null;
  /** Per-system monotonic sequence (notNull on the kernel side). */
  sequenceNumber: number;
  /** sha256:[a-f0-9]{64} format — server CHECK constraint. */
  inputDigest: string;
  /** sha256:[a-f0-9]{64} OR null when output isn't recorded. */
  outputDigest: string | null;
  frameworkClaims: unknown[];
  toolInvocations: unknown[];
  delegationChain: unknown[];
  humanOversightState: string | null;
  policyOutcome: string | null;
  /** Null on the first record in the chain; otherwise the previous record's hash. */
  prevRecordHash: string | null;
  /** Hash of (prev_record_hash || canonical_payload). */
  recordHash: string;
  clientSignature: string | null;
  clientKeyId: string | null;
  idempotencyKey: string | null;
  zkProof: Record<string, unknown> | null;
  tombstoned: boolean;
  /** ISO-8601 timestamp; non-null iff `tombstoned === true`. */
  tombstonedAt: string | null;
  tombstonedReason: string | null;
  /** ISO-8601 timestamp. */
  createdAt: string;
}

// ─── Public sub-shapes — input building blocks for `decisions.ingest` ──────
//
// Exported as named types so consumers can build a typed record in
// pieces (e.g., assemble a `FrameworkClaim[]` from a Drizzle query
// result) before passing it to `ingest()`. Same naming convention as
// `IncidentCluster` / `ChatContextGap`. Decision D2 in
// `IMPLEMENTATION/audit-prompt-F.1-decisions-ingest.md`.
//
// Field bounds (kernel `decisionCreateSchema`):
//   - `framework`: 1-100 chars
//   - `article`: 1-100 chars
//   - `claim`: 1-2000 chars
// SDK does NOT enforce caps — server's Zod is the schema authority (D5).

/**
 * One framework-compliance claim asserted by the decision (e.g.
 * `{framework: "eu_ai_act", article: "Art.13", claim: "human oversight provided"}`).
 * Up to 50 entries per record. The server validates each item's shape
 * via `.strict()`; the SDK forwards faithfully without per-item
 * validation.
 */
export interface FrameworkClaim {
  /** Framework code (1-100 chars). E.g., `"eu_ai_act"`, `"nist_ai_rmf"`. */
  framework: string;
  /** Article / section identifier (1-100 chars). E.g., `"Art.13"`, `"GV-1.1"`. */
  article: string;
  /** Claim text (1-2000 chars). */
  claim: string;
}

/**
 * One tool / model / external-API invocation that participated in the
 * decision (e.g. `{name: "vector-store-query", inputHash: "sha256:..."}`).
 * Up to 50 entries per record. Hash fields are optional; when present,
 * must match `sha256:[a-f0-9]{64}` server-side.
 */
export interface ToolInvocation {
  /** Tool / model identifier (1-200 chars). */
  name: string;
  /** Hash of the tool's input payload (sha256:[a-f0-9]{64}). */
  inputHash?: string;
  /** Hash of the tool's output payload (sha256:[a-f0-9]{64}). */
  outputHash?: string;
}

/**
 * One step in the agent-delegation chain that produced this decision.
 * Up to 20 entries per record. `agentId` identifies the agent
 * (caller-defined; could be a UUID, a slug, or an external system's
 * identifier); `delegationToken` is an optional opaque proof-of-
 * delegation (max 2000 chars).
 */
export interface DelegationEntry {
  /** Agent identifier (1-500 chars). Caller-defined format. */
  agentId: string;
  /** Opaque delegation token (max 2000 chars). Optional. */
  delegationToken?: string;
}

/**
 * Optional zero-knowledge proof attached to the decision.
 *
 * Field caps (kernel-side):
 *   - `type`: 1-100 chars (e.g., `"groth16"`, `"plonk"`, `"stark"`)
 *   - `proof`: 1-100_000 chars — generous for real ZK schemes
 *     (Groth16 ~200 bytes, PLONK ~5KB, STARKs can exceed 100KB)
 *   - `publicSignals`: array of strings, each ≤500 chars, max 100 entries
 *
 * SDK forwards the object faithfully; server validates the inner shape.
 */
export interface ZkProof {
  /** ZK scheme identifier (1-100 chars). */
  type: string;
  /** Proof data — opaque to the SDK (1-100_000 chars). */
  proof: string;
  /** Public signals — opaque strings (each ≤500 chars, max 100 entries). */
  publicSignals: string[];
}

/**
 * Input shape for `decisions.ingest()`. Mirrors the kernel's
 * `decisionCreateSchema` (`src/lib/validation/decision-schemas.ts:17-93`)
 * field-for-field. Strict at the server side (`.strict()`) — extra keys
 * cause a 422 response, which is load-bearing for hash-chain
 * non-malleability (every field that participates in the canonical hash
 * must come through this shape; silent extras would weaken the chain).
 *
 * SDK validates field TYPES synchronously (throws `TypeError` BEFORE
 * issuing any request). Format checks (UUID, hash regex, base64, enum
 * membership, length caps, refine clause) are deferred to the server —
 * decision D5 in the build-round audit.
 *
 * **Idempotency**: when `idempotencyKey` is provided AND a prior record
 * with the same `(orgId, idempotencyKey)` exists, the server compares
 * canonical bytes. Match → returns the persisted record (HTTP 200,
 * `decision.idempotency_replay`). Mismatch → 409
 * `IdempotencyConflictError` ("Idempotency key already used with
 * different payload"). The SDK does NOT surface the 200/201 distinction
 * (both resolve as `Promise<DecisionRecord>`); consumers can check
 * `record.idempotencyKey === input.idempotencyKey` if they need to know.
 *
 * **Pairing constraint**: `clientSignature` and `clientKeyId` must
 * EITHER both be provided OR both be absent. The server's `.refine()`
 * rejects asymmetric input with a 422; the SDK forwards faithfully (D4).
 */
export interface DecisionIngestInput {
  /** Required — UUID. The system this decision belongs to. */
  systemId: string;
  /** Required — `sha256:[a-f0-9]{64}`. Hash of the decision input. */
  inputDigest: string;
  /** Optional — `sha256:[a-f0-9]{64}`. Hash of the decision output. */
  outputDigest?: string;
  /** Optional — UUID. Bind this record to an existing attestation. */
  attestationId?: string;
  /** Optional — up to 50 framework-compliance claims. Defaults `[]`. */
  frameworkClaims?: FrameworkClaim[];
  /** Optional — up to 50 tool invocations. Defaults `[]`. */
  toolInvocations?: ToolInvocation[];
  /** Optional — up to 20 delegation steps. Defaults `[]`. */
  delegationChain?: DelegationEntry[];
  /** Optional — human-oversight gate state for this decision. */
  humanOversightState?: "approved" | "bypassed" | "not_required";
  /** Optional — final policy verdict for this decision. */
  policyOutcome?: "permitted" | "denied" | "escalated";
  /**
   * Optional — base64-encoded signature over the canonical payload.
   * Must be paired with `clientKeyId` (server `.refine()` rejects one
   * without the other).
   */
  clientSignature?: string;
  /**
   * Optional — identifier for the key used to produce `clientSignature`.
   * Must be paired with `clientSignature`.
   */
  clientKeyId?: string;
  /**
   * Optional — caller-supplied dedupe key (1-200 chars). Same
   * `(orgId, idempotencyKey)` + same canonical payload → idempotent
   * replay (returns the prior record). Different payload → 409.
   *
   * **For at-least-once delivery semantics across network failures,
   * pass an `idempotencyKey` so retries dedupe server-side.** Without
   * one, a 429-retry that succeeds-but-loses-the-response could create
   * a duplicate record.
   */
  idempotencyKey?: string;
  /** Optional — zero-knowledge proof attached to this decision. */
  zkProof?: ZkProof;
}

// ─── Bulk-ingest input + result shapes ──────────────────────────────────────
//
// `decisions.bulk` is the first SDK encounter with a partial-success
// envelope: the kernel returns 200 even when some records failed; the
// envelope describes which. The SDK does NOT throw on `totalFailed > 0`
// — that's the entire point of the endpoint. The transport unwraps the
// `{success:true, data}` envelope as usual; the caller branches on
// `result.failed.length > 0` if they care.
//
// Wire-shape source: kernel `src/lib/decisions/bulk-ingest.ts:57-84`
// (BulkInsertedSummary / BulkFailedSummary / BulkIngestResult).

/**
 * Input shape for `decisions.bulk()`. Mirrors the kernel's
 * `decisionBulkCreateSchema` (`src/lib/validation/decision-schemas.ts:105-114`)
 * — a single-field wrapper around an items array. The wrapper (rather
 * than a bare array) matches the kernel wire literal `{items}` and
 * leaves room for future top-level additions (e.g.,
 * `mode: "atomic" | "best-effort"`) without a breaking change.
 *
 * The SDK validates that `input` is an object and `input.items` is an
 * array (synchronously, before any fetch). It does NOT pre-cap the
 * length client-side — the kernel's `.min(1).max(500)` is the schema
 * authority — and it does NOT recursively validate `items[i]` shapes
 * (symmetric to ingest's `frameworkClaims` / `toolInvocations` policy
 * — `.strict()` Zod is the kernel-side authority).
 */
export interface DecisionBulkInput {
  /**
   * 1-500 entries. Each item is the same shape as `decisions.ingest`
   * input. Bulk does NOT recover from idempotency races — failed items
   * with `code === "idempotency_unique_violation"` should be retried
   * individually via `decisions.ingest` to invoke the per-record race
   * recovery path.
   */
  items: DecisionIngestInput[];
}

/**
 * One inserted-record summary in `BulkIngestResult.inserted[]`. Slim by
 * design — matches the kernel's bulk-ingest summary (no heavy fields
 * like `frameworkClaims` / `canonicalPayload`). Call
 * `decisions.retrieve(id)` if the caller needs the full record.
 *
 * Sorted by original input `index` server-side so the caller can map
 * each entry back to the position in the submitted `items[]` array.
 */
export interface BulkInsertedSummary {
  /** Position in the submitted `items[]` array (zero-based). */
  index: number;
  /** UUID of the persisted decision record. */
  id: string;
  systemId: string;
  /** Per-system monotonic sequence assigned at insert time. */
  sequenceNumber: number;
  /** sha256:[a-f0-9]{64} format. */
  recordHash: string;
  /**
   * ISO-8601 timestamp string. (Kernel emits a `Date`; `JSON.stringify`
   * converts it to the wire string.)
   */
  createdAt: string;
}

/**
 * One failed-record summary in `BulkIngestResult.failed[]`. The whole
 * chunk a record belonged to fails together (kernel groups records into
 * fixed-size chunks under one `chain_heads` lock; a chunk is all-or-
 * nothing), but other chunks for the same system OR other systems
 * continue. Sorted by original input `index` server-side.
 */
export interface BulkFailedSummary {
  /** Position in the submitted `items[]` array (zero-based). */
  index: number;
  systemId: string;
  /** Human-readable per-record error message. */
  error: string;
  /**
   * Machine-readable per-record code. Source of truth: kernel
   * `classifyChunkError` in `src/lib/decisions/bulk-ingest.ts:114-156`.
   * Today's possible values:
   *
   *   - `"idempotency_conflict"` — same idempotencyKey, different
   *     canonical bytes (within a chunk).
   *   - `"payload_too_large"` — one record's canonical bytes exceed
   *     the 256KB per-record cap.
   *   - `"chain_head_missing"` — internal invariant violation (should
   *     never fire in practice).
   *   - `"system_not_found"` — cross-org system OR cross-system
   *     `attestationId`. Collapsed deliberately for enumeration safety
   *     (matches single-record ingest behavior).
   *   - `"ijson_validation_failed"` — per-record canonicalize tripped
   *     on NaN/Infinity/BigInt/undefined/Symbol.
   *   - `"idempotency_unique_violation"` — race condition. Bulk does
   *     NOT recover; retry via `decisions.ingest` (single-record
   *     endpoint) to invoke the per-record race-recovery path.
   *   - `"chunk_failed"` — catch-all for unclassified chunk-tx
   *     failures.
   *
   * Typed as `string` (NOT a literal-union) for forward-compat — same
   * convention as `DecisionRecord.humanOversightState` and
   * `DecisionStreamEvent.eventType`. Future kernel additions slot in
   * cleanly without an SDK bump.
   */
  code: string;
}

/**
 * Result envelope returned by `decisions.bulk()`. The transport
 * unwraps the kernel's `{success:true, data}` JSON envelope — the
 * caller receives this shape directly.
 *
 * **Critical contract**: `decisions.bulk()` resolves successfully (no
 * throw) even when every record failed. Inspect `totalFailed` and
 * `failed[]` to detect per-record errors. Top-level failures (auth,
 * rate limit, plan limit, oversize batch) DO throw `AttestryAPIError`
 * with the corresponding HTTP status.
 */
export interface BulkIngestResult {
  /** Number of items in the submitted `items[]` array. */
  totalSubmitted: number;
  /** Number of records persisted to the chain. Equals `inserted.length`. */
  totalInserted: number;
  /** Number of records that failed. Equals `failed.length`. */
  totalFailed: number;
  /** Sorted by original input `index`. */
  inserted: BulkInsertedSummary[];
  /** Sorted by original input `index`. */
  failed: BulkFailedSummary[];
}

/**
 * Slim row returned by the list endpoint. Mirrors the kernel's
 * `DecisionListItem` (in `src/lib/decisions/list-query.ts`) — a subset
 * of the full `DecisionRecord`, deliberately excluding heavy fields
 * (`canonicalPayload` BYTEA, `manifestVersionId`, `attestationId`,
 * `clientSignature`, `clientKeyId`, `idempotencyKey`, `zkProof`,
 * `tombstonedAt`, `tombstonedReason`, `orgId`).
 *
 * jsonb arrays are typed as `unknown[]` for forward-compat — same
 * convention as `DecisionRecord`. `createdAt` is the wire-shape ISO
 * string (kernel `Date` → JSON.stringify → string).
 *
 * Use `decisions.retrieve(id)` if you need the full record (e.g.,
 * verifying a signature with `clientSignature` / `clientKeyId`).
 */
export interface DecisionListItem {
  id: string;
  systemId: string;
  /** Per-system monotonic sequence (notNull on the kernel side). */
  sequenceNumber: number;
  /** sha256:[a-f0-9]{64} format. */
  inputDigest: string;
  /** sha256:[a-f0-9]{64} OR null when output isn't recorded. */
  outputDigest: string | null;
  frameworkClaims: unknown[];
  toolInvocations: unknown[];
  delegationChain: unknown[];
  humanOversightState: string | null;
  policyOutcome: string | null;
  /** Hash of (prev_record_hash || canonical_payload). */
  recordHash: string;
  /** Null on the first record in the chain. */
  prevRecordHash: string | null;
  /** ISO-8601 timestamp string. */
  createdAt: string;
  tombstoned: boolean;
}

/**
 * Filter / pagination inputs for `decisions.list()`. All fields optional;
 * a bare `decisions.list()` call returns the most-recent page (default
 * 50) of the org's records.
 *
 * Pagination is keyset-based: pass back `response.nextCursor` as
 * `input.cursor` to fetch the next page. The cursor format is opaque
 * to the SDK — kernel encodes/decodes it.
 *
 * Filters:
 *   - `systemId`: limit to one system's records
 *   - `from` / `to`: ISO datetime range filters on `createdAt`
 *   - `framework` / `article`: jsonb-contains filters on `frameworkClaims`
 *   - `tool`: jsonb-contains filter on `toolInvocations`
 *   - `includeTombstoned`: include soft-deleted records (default false)
 *   - `limit`: page size, 1-200, default 50
 */
export interface DecisionsListInput {
  systemId?: string;
  /** ISO datetime — `createdAt >= from`. */
  from?: string;
  /** ISO datetime — `createdAt <= to`. */
  to?: string;
  /** Filter by `frameworkClaims[].framework`. 1-100 chars. */
  framework?: string;
  /** Filter by `frameworkClaims[].article`. 1-100 chars. */
  article?: string;
  /** Filter by `toolInvocations[].name`. 1-200 chars. */
  tool?: string;
  /** Opaque cursor from a prior response's `nextCursor`. */
  cursor?: string;
  /** Page size, 1-200, default 50. */
  limit?: number;
  /** Include soft-deleted records. Default false. */
  includeTombstoned?: boolean;
}

export interface DecisionsListResponse {
  items: DecisionListItem[];
  /**
   * Cursor for the next page. `null` (NOT undefined) when no more pages
   * exist — matches the kernel wire shape exactly. Pass as
   * `input.cursor` on the next call to fetch the following page.
   */
  nextCursor: string | null;
}

/**
 * Public stream event types. Today the kernel emits exactly one
 * (`decision.appended`) — extracted as `as const` so consumers can
 * iterate, narrow, and so the drift-detection pin in
 * `src/lib/incidents/__tests__/sdk-drift.test.ts` can compare
 * structurally against the kernel's `formatSSEFrame` default. When the
 * kernel adds a new event type (e.g. `decision.tombstoned`), update
 * BOTH this array AND the kernel emitter, and bump the SDK minor.
 */
export const DECISION_STREAM_EVENT_TYPES = Object.freeze([
  "decision.appended",
] as const);

export type DecisionStreamEventType = (typeof DECISION_STREAM_EVENT_TYPES)[number];

/**
 * One event yielded by `decisions.stream()`. Mirrors the kernel's
 * `DecisionStreamEvent` (in `src/lib/decisions/stream-cursor.ts`) but
 * `createdAt` is an ISO-8601 string (the wire shape — kernel emits
 * `event.createdAt.toISOString()` in `formatSSEFrame`), and two
 * SSE-level fields are surfaced for reconnection:
 *
 *   - `eventId`: the value from the SSE `id:` line. Pass this back as
 *     `input.lastEventId` on a subsequent `stream()` call to resume.
 *     The kernel's cursor format is opaque to the SDK (today it's a
 *     base64url-encoded `{c, i}` JSON, but the SDK does not parse it).
 *   - `eventType`: the value from the SSE `event:` line. Currently
 *     always `"decision.appended"`; surfaced for forward-compat with
 *     future event types (e.g. `"decision.tombstoned"`).
 *
 * Slim by design — clients call `decisions.retrieve(id)` for the full
 * record (including `frameworkClaims`, `delegationChain`, etc., which
 * the stream endpoint omits to keep frames small).
 */
export interface DecisionStreamEvent {
  /** Decision record id (UUID). */
  id: string;
  /** System the decision was made for (UUID). */
  systemId: string;
  /** Per-system monotonic sequence number. */
  sequenceNumber: number;
  /** sha256:[a-f0-9]{64} format. */
  recordHash: string;
  /** Null on the first record in the chain. */
  prevRecordHash: string | null;
  /** True if the record has been tombstoned. */
  tombstoned: boolean;
  /** ISO-8601 timestamp string. */
  createdAt: string;
  /**
   * SSE `id:` field — pass back as `input.lastEventId` to resume.
   * Always a non-empty string (the SDK validates the frame had a
   * non-empty `id:` line; throws `AttestryError` if not).
   */
  eventId: string;
  /**
   * SSE `event:` field. Today always `"decision.appended"` (the only
   * type emitted by the kernel — see `DECISION_STREAM_EVENT_TYPES`).
   * Typed as `string` rather than the literal-union for forward-compat:
   * a future kernel patch can add a new event type and consumer code
   * that does `if (event.eventType === 'decision.tombstoned')` keeps
   * compiling without an SDK bump (the consumer just needs to know
   * about the new type).
   */
  eventType: string;
}

/**
 * Filters / resume cursor for `decisions.stream()`. All fields optional:
 * a fresh `stream()` call with no args subscribes to the entire org's
 * stream from "now" forward.
 *
 * Lifecycle:
 *   1. First call with `lastEventId` undefined → start at "now", no
 *      historical replay. Server only emits events created AFTER the
 *      connection opens.
 *   2. Server emits events. Each event carries `eventId` (the resume
 *      cursor) — store the latest.
 *   3. On disconnect (network drop, server timeout, deliberate abort),
 *      call `stream({ lastEventId: lastSeen.eventId, ... })` to resume —
 *      server backfills every event after the cursor before resuming
 *      live polling.
 *
 * Validation: the SDK validates that `systemId` and `lastEventId` are
 * non-empty strings if provided (catches `null`/empty programming
 * errors). Format validation (UUID for systemId, base64url cursor for
 * lastEventId) is the server's job — the server returns 400 on
 * malformed input.
 */
export interface DecisionsStreamInput {
  /** Filter to a single system's events. UUID format. */
  systemId?: string;
  /** Resume cursor — typically the `eventId` of the last seen event. */
  lastEventId?: string;
}

// ─── Export input + frame shapes ────────────────────────────────────────────
//
// `decisions.export` is the first NDJSON streaming resource on the SDK
// and the first endpoint with a TRAILER pattern: every successful 200
// stream ends with one final line of shape
// `{"type":"ExportTrailer", systemId, recordCount, ..., merkleRoot,
// signing, generatedAt}`. The trailer commits the export to a single
// Merkle root over the per-record `recordHash` leaves; future Prompt 1
// will add an Ed25519 signature to that commitment.
//
// Wire-shape source:
//   - Records: kernel `src/lib/decisions/export-stream.ts:24-39`
//     (ExportRecord — IDENTICAL field-for-field to DecisionListItem)
//   - Trailer: kernel `src/lib/decisions/export-stream.ts:42-56`
//
// Critical mid-stream contract: the kernel commits to a 200 BEFORE
// knowing whether the stream will complete. Mid-stream errors (DB
// connection lost during pagination, malformed leaf hash) surface as
// `controller.error(err)` AFTER headers + initial bytes are sent — the
// HTTP response is already 200. The SDK detects this as a missing
// trailer at iterator end and throws `AttestryError`.

/**
 * Filter inputs for `decisions.export()`. `systemId` is REQUIRED — the
 * kernel scopes export to a single system's chain (no cross-system
 * exports). Date filters optional. No pagination — the response streams.
 *
 * Validation: SDK validates field TYPES synchronously (throws
 * `TypeError` BEFORE issuing any request). Format checks (UUID, ISO
 * datetime) deferred to the server's Zod schema (`decisionExportQuerySchema`).
 */
export interface DecisionsExportInput {
  /** REQUIRED — UUID. The system whose chain to export. */
  systemId: string;
  /** Optional — ISO datetime, `createdAt >= from`. */
  from?: string;
  /** Optional — ISO datetime, `createdAt <= to`. */
  to?: string;
  /** Optional — include soft-deleted records. Default false. */
  includeTombstoned?: boolean;
}

/**
 * Per-record frame yielded by `decisions.export()`. Structurally
 * IDENTICAL to `DecisionListItem` — same field names, same types, same
 * null-vs-undefined semantics. Reusing the existing exported type
 * (rather than redefining) signals to consumers that `decisions.list`
 * and `decisions.export` emit interchangeable rows. Kernel-side, the
 * `ExportRecord` shape was deliberately aligned with the list-row
 * projection to enable this type identity.
 *
 * Build-round D2.
 */
export type DecisionExportRecord = DecisionListItem;

/**
 * Final frame in a `decisions.export()` stream. Distinguishes itself
 * from records via the `type: "ExportTrailer"` discriminator. The
 * kernel emits exactly one trailer at the end of every successful
 * stream — including empty exports (recordCount === 0).
 *
 * The trailer commits the export to a single Merkle root over the
 * per-record `recordHash` leaves (Bitcoin-style binary Merkle, with
 * empty-export sentinel `sha256("ATTESTRY-EMPTY-EXPORT")`). Verifying
 * the commitment is the consumer's responsibility — the SDK exposes
 * the trailer raw without recomputation.
 */
export interface DecisionExportTrailer {
  /** Discriminator — distinguishes the trailer from records. */
  type: "ExportTrailer";
  /** UUID — the systemId from the export filter. */
  systemId: string;
  /** Number of records that streamed before the trailer. >= 0. */
  recordCount: number;
  /** First record's `sequenceNumber`. `null` on empty export. */
  sequenceFrom: number | null;
  /** Last record's `sequenceNumber`. `null` on empty export. */
  sequenceTo: number | null;
  /**
   * `sha256:[a-f0-9]{64}` format. Bitcoin-style binary Merkle root over
   * the per-record `recordHash` leaves (in `sequenceNumber` ascending
   * order). Empty-export sentinel: `sha256:` + hex of
   * `sha256("ATTESTRY-EMPTY-EXPORT")`. SDK does NOT recompute — the
   * caller (post-Prompt-1) verifies independently.
   */
  merkleRoot: string;
  /**
   * Today: literal string `"unsigned-prompt-1-blocked"`. Once Prompt 1
   * (Ed25519 signing) ships, the kernel will replace this field with
   * a structured `proof` value carrying an `eddsa-jcs-2022` signature
   * over the canonical trailer bytes. Typing as `string` (rather than
   * a literal-union) accommodates that transition without an SDK bump
   * — same forward-compat convention as `BulkFailedSummary.code`,
   * `humanOversightState`, and `eventType`. Build-round D1.
   *
   * SDK does NOT attempt signature verification — caller is
   * responsible (post-Prompt-1).
   */
  signing: string;
  /** ISO-8601 timestamp string. */
  generatedAt: string;
}

/**
 * Discriminated union of frames in the export stream. Records arrive
 * first (in `sequenceNumber` ascending order), then exactly one trailer.
 * Caller branches on the trailer:
 *
 * @example
 * ```ts
 * for await (const frame of client.decisions.export({ systemId })) {
 *   if ("type" in frame && frame.type === "ExportTrailer") {
 *     // Final frame — record count + Merkle root commit + signing field.
 *     console.log(`exported ${frame.recordCount} records, root=${frame.merkleRoot}`);
 *   } else {
 *     // Per-record frame — DecisionListItem shape.
 *     console.log(frame.id, frame.sequenceNumber, frame.recordHash);
 *   }
 * }
 * ```
 *
 * Build-round D3 (Option A: yield typed frames, vs Option B: two-phase
 * records + trailer-Promise API). Mirrors wire shape; symmetric to
 * `decisions.stream`.
 */
export type DecisionExportFrame =
  | DecisionExportRecord
  | DecisionExportTrailer;

/**
 * Result of `client.decisions.verifyChain(systemId)`. Source-of-truth
 * lives kernel-side at `src/lib/decisions/chain-verification.ts:20-49`.
 *
 * **Critical contract**: this shape is returned for BOTH valid and
 * invalid chains. `chainValid: false` is NOT an error — the kernel
 * answered the customer's question (is this chain tampered?) and the
 * SDK resolves the Promise with the verdict body. Top-level structural
 * failures (auth, rate limit, system-not-found, ChainTooLong) throw
 * `AttestryAPIError`. Carry-forward invariant #12.
 *
 * The two ID arrays distinguish two failure modes:
 *   - `tamperedRecordIds`: stored `recordHash` doesn't match the
 *     recomputed hash of `canonicalPayload` — direct content tampering
 *     (security signal, fires `chain.tampered` webhook).
 *   - `brokenRecordIds`: `prevRecordHash` doesn't match the running
 *     watermark — gap in the sequence (ops signal: record deleted /
 *     missing; fires `chain.broken` webhook). Both can be non-empty
 *     simultaneously; `chain.tampered` takes precedence at webhook
 *     dispatch but BOTH arrays appear in this response.
 */
export interface ChainVerificationResult {
  /** UUID of the system whose chain was verified. */
  systemId: string;
  /** Total rows replayed (active + tombstoned). */
  recordCount: number;
  /** Records with `tombstoned: false`. */
  activeRecordCount: number;
  /** Records with `tombstoned: true`. */
  tombstonedRecordCount: number;
  /**
   * `true` iff every record's `recordHash` matches the recomputed hash
   * AND every record's `prevRecordHash` matches the running watermark.
   * Empty chains verify as `true` (vacuous truth).
   */
  chainValid: boolean;
  /**
   * Sequence number of the last record before tampering was first
   * detected. Equals the highest sequence on a valid chain; one less
   * than the first tampered/broken record's sequence on an invalid
   * chain (so callers can show "verified up to sequence N"). `0` on
   * empty chains AND when the very first record fails verification.
   */
  lastVerifiedSequence: number;
  /**
   * ISO-8601 string captured by the kernel at the end of verification
   * (`new Date().toISOString()`). Wire is a STRING, not a `Date`
   * instance. Parse via `new Date(value)` if needed.
   */
  lastVerifiedAt: string;
  /**
   * Record IDs whose stored `recordHash` doesn't match the recomputed
   * hash of their `canonicalPayload` — direct content tampering
   * (security signal). Empty array on a valid chain. Triggers the
   * `chain.tampered` webhook server-side.
   */
  tamperedRecordIds: string[];
  /**
   * Record IDs whose `prevRecordHash` doesn't match the running
   * watermark — gap in the sequence (ops signal: record deleted /
   * missing). Empty array on a valid chain. Triggers the
   * `chain.broken` webhook server-side. Distinct from
   * `tamperedRecordIds` — both can be non-empty (tampered takes
   * precedence in webhook event selection but both arrays appear in
   * the webhook payload AND in this response).
   */
  brokenRecordIds: string[];
  /**
   * Server-side observability counters. Authoritative — the SDK does
   * NOT add its own timer.
   */
  performanceMetrics: {
    /** Wall-clock duration of the replay loop, milliseconds. */
    verificationDurationMs: number;
    /**
     * Rounded throughput. `0` on empty chains AND on sub-millisecond
     * verifications (kernel guards divide-by-zero). The SDK preserves
     * the kernel's value verbatim — does NOT recompute.
     */
    recordsPerSecond: number;
  };
}

export class DecisionsResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Retrieve one decision record by id.
   *
   * Server returns 400 for malformed UUIDs and 404 for not-found OR
   * cross-org records (deliberate conflation — see route docstring).
   * Both surface as `AttestryAPIError` with the corresponding status.
   *
   * Throws `TypeError` synchronously for invalid `id` BEFORE issuing
   * a request — empty string, non-string, lone-surrogate UTF-16, or
   * path-traversal segments (`"."` / `".."` / strings containing
   * `\0`) all reject. The path-traversal guard exists because
   * `encodeURIComponent` does NOT encode `.` or `..`, and `fetch`'s
   * URL normalization would collapse `retrieve("..")` to the LIST
   * endpoint at `/api/v1/decisions/` — silently redirecting to a
   * different resource. Hostile-review F1 (cross-resource fix
   * symmetric to `decisions.verifyChain`); validation centralized in
   * the shared `encodePathSegment` helper.
   *
   * Rejects with `AttestryError` (P2 hardening) if the kernel emits
   * a non-object response shape (`null`, scalar, or array). Rejects
   * with `AttestryAPIError` (P3 hardening) if the kernel responds
   * with a non-`application/json` Content-Type — protects against
   * proxy-injected HTML 200 pages parsing into junk consumer state.
   */
  retrieve(
    id: string,
    options?: RequestOptions,
  ): Promise<DecisionRecord> {
    const encoded = encodePathSegment(id, "id", "decisions.retrieve");
    return this.client
      ._request<DecisionRecord>({
        method: "GET",
        path: `/api/v1/decisions/${encoded}`,
        options,
      })
      .then((result) => {
        // P2 hardening (extended F1 sweep — sync GET completeness):
        // validate the kernel returned an object. A regression to
        // null/scalar/array would let TypeScript-typed access crash
        // consumers with a cryptic error. Throw AttestryError at the
        // SDK boundary instead. Per-field shape (id is UUID, etc.)
        // is faithful-courier — NOT validated here (P4 candidate).
        assertNonNullObjectResponse(result, "decisions.retrieve");
        return result;
      });
  }

  /**
   * Append a decision record to the org's append-only hash chain.
   *
   * Wraps `POST /api/v1/decisions`. Returns the persisted record (with
   * `canonicalPayload` BYTEA omitted — the kernel's `toResponseShape()`
   * helper drops it from the wire response since the client already has
   * the input digest for verification).
   *
   * **Idempotency replay**: subsequent calls with the same
   * `idempotencyKey` AND identical canonical payload return the SAME
   * record (server returns HTTP 200 `decision.idempotency_replay`; SDK
   * resolves the same `Promise<DecisionRecord>` as a fresh insert,
   * which returns 201). Different payload with the same key throws
   * `AttestryAPIError` with `status === 409`
   * `decision.idempotency_conflict`. Status-code distinction is NOT
   * surfaced in the SDK return type — both 2xx resolve identically.
   *
   * **At-least-once delivery**: pass an `idempotencyKey` to make
   * 429-retries safe under network failure. Without one, a retry that
   * succeeds-but-loses-the-response could create a duplicate record.
   * Body is re-stringified per attempt (carry-forward invariant #4).
   *
   * **Plan limits (402)**: when the org has exhausted its
   * `decisionsPerMonth` quota, the kernel throws `PlanLimitError`
   * (mapped to HTTP 402). The SDK surfaces it as `AttestryAPIError`
   * with `status === 402` and `details: {feature, currentPlan,
   * upgradeRequired}` — the structured body lets dashboards route the
   * user straight to the upgrade flow (B.1 carry-forward).
   *
   * Errors:
   *   - `AttestryAPIError` (status 401) — auth required
   *   - `AttestryAPIError` (status 402) — plan limit (with
   *     `details.feature` / `details.currentPlan` /
   *     `details.upgradeRequired`)
   *   - `AttestryAPIError` (status 404) — system not found OR cross-org
   *     attestation (collapsed deliberately to prevent enumeration)
   *   - `AttestryAPIError` (status 409) — idempotency conflict (same
   *     key, different payload)
   *   - `AttestryAPIError` (status 413) — canonical payload exceeds 256KB
   *   - `AttestryAPIError` (status 422) — Zod validation failed (field
   *     errors in `details`) OR I-JSON validation failed (NaN /
   *     Infinity / BigInt / undefined / Symbol — `details.path` names
   *     the offending field) OR refine-clause failed
   *     (clientSignature/clientKeyId pairing)
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried by
   *     default — invariant #18)
   *   - `AttestryAPIError` (status 500) — internal invariant violation
   *     (chain head missing — should never fire in practice)
   *   - `AttestryError` ("invalid request body: ...") — body
   *     serialization failed (BigInt, circular reference) BEFORE fetch
   *     (carry-forward invariant #4)
   *   - `AttestryError` ("request aborted by caller") — caller-supplied
   *     `options.signal` fired (pre-aborted or mid-flight)
   *   - `TypeError` (synchronous, no fetch issued) — input failed SDK-
   *     side type validation (see below)
   *
   * SDK-side validation (synchronous `TypeError`, no fetch issued):
   *   - `input` itself: must be a non-null, non-array object
   *   - `systemId` / `inputDigest`: required non-empty strings
   *   - Optional string fields: when provided, must be non-empty strings
   *     (outputDigest, attestationId, clientSignature, clientKeyId,
   *     idempotencyKey, humanOversightState, policyOutcome)
   *   - Optional array fields: when provided, must be `Array.isArray`
   *     (frameworkClaims, toolInvocations, delegationChain). Empty
   *     arrays pass through.
   *   - Optional `zkProof`: when provided, must be a non-null,
   *     non-array object.
   *
   * **Format validation deferred to server** (UUID, hash regex,
   * base64, enum membership, length caps, refine pairing,
   * inner-array shape, inner-zkProof shape). Decision D5 in the
   * build-round audit.
   *
   * @example
   * ```ts
   * const record = await client.decisions.ingest({
   *   systemId: "550e8400-e29b-41d4-a716-446655440000",
   *   inputDigest: "sha256:abc123...",
   *   frameworkClaims: [
   *     { framework: "eu_ai_act", article: "Art.13", claim: "human oversight provided" },
   *   ],
   *   humanOversightState: "approved",
   *   policyOutcome: "permitted",
   *   idempotencyKey: "ingest-2026-05-06-trace-789",  // safe retries
   * });
   * console.log(record.id, record.sequenceNumber, record.recordHash);
   * ```
   */
  ingest(
    input: DecisionIngestInput,
    options?: RequestOptions,
  ): Promise<DecisionRecord> {
    // Top-level input shape — must be a non-null, non-array object.
    // typeof null === "object" and typeof [] === "object", so guard
    // both explicitly.
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError(
        "decisions.ingest: `input` must be an object",
      );
    }
    // Defensive field snapshot — read each input field EXACTLY ONCE
    // via `readInputField`, which converts a throwing accessor's
    // exception into the documented synchronous `TypeError` input
    // contract (session-22 hostile review #1 — the SDK-wide MEDIUM-1
    // getter-throws fix). All validation below operates on the locals;
    // the request body still sends the original `input` (a throwing
    // getter is caught here first, so the transport is never reached).
    const systemId = readInputField(input, "systemId", "decisions.ingest");
    const inputDigest = readInputField(
      input,
      "inputDigest",
      "decisions.ingest",
    );
    const outputDigest = readInputField(
      input,
      "outputDigest",
      "decisions.ingest",
    );
    const attestationId = readInputField(
      input,
      "attestationId",
      "decisions.ingest",
    );
    const humanOversightState = readInputField(
      input,
      "humanOversightState",
      "decisions.ingest",
    );
    const policyOutcome = readInputField(
      input,
      "policyOutcome",
      "decisions.ingest",
    );
    const clientSignature = readInputField(
      input,
      "clientSignature",
      "decisions.ingest",
    );
    const clientKeyId = readInputField(
      input,
      "clientKeyId",
      "decisions.ingest",
    );
    const idempotencyKey = readInputField(
      input,
      "idempotencyKey",
      "decisions.ingest",
    );
    const frameworkClaims = readInputField(
      input,
      "frameworkClaims",
      "decisions.ingest",
    );
    const toolInvocations = readInputField(
      input,
      "toolInvocations",
      "decisions.ingest",
    );
    const delegationChain = readInputField(
      input,
      "delegationChain",
      "decisions.ingest",
    );
    const zkProof = readInputField(input, "zkProof", "decisions.ingest");

    // Required: systemId (UUID server-side; SDK only enforces non-empty
    // string). Failing here throws synchronously with no fetch — invariant.
    if (typeof systemId !== "string" || systemId.length === 0) {
      throw new TypeError(
        "decisions.ingest: `systemId` is required and must be a non-empty string",
      );
    }
    // Required: inputDigest (hash regex server-side; SDK only enforces
    // non-empty string).
    if (typeof inputDigest !== "string" || inputDigest.length === 0) {
      throw new TypeError(
        "decisions.ingest: `inputDigest` is required and must be a non-empty string",
      );
    }
    // Optional string fields — non-empty when provided. Format checks
    // (hash regex, UUID, base64, enum membership) deferred to server.
    validateOptionalNonEmptyString(
      outputDigest,
      "outputDigest",
      "decisions.ingest",
    );
    validateOptionalNonEmptyString(
      attestationId,
      "attestationId",
      "decisions.ingest",
    );
    validateOptionalNonEmptyString(
      humanOversightState,
      "humanOversightState",
      "decisions.ingest",
    );
    validateOptionalNonEmptyString(
      policyOutcome,
      "policyOutcome",
      "decisions.ingest",
    );
    validateOptionalNonEmptyString(
      clientSignature,
      "clientSignature",
      "decisions.ingest",
    );
    validateOptionalNonEmptyString(
      clientKeyId,
      "clientKeyId",
      "decisions.ingest",
    );
    validateOptionalNonEmptyString(
      idempotencyKey,
      "idempotencyKey",
      "decisions.ingest",
    );
    // Optional arrays — empty arrays pass through faithfully (server's
    // `.default([])` would produce the same persisted shape). The
    // SDK does NOT validate inner items — kernel `.strict()` does that;
    // duplicating here would risk drift.
    validateOptionalArray(
      frameworkClaims,
      "frameworkClaims",
      "decisions.ingest",
    );
    validateOptionalArray(
      toolInvocations,
      "toolInvocations",
      "decisions.ingest",
    );
    validateOptionalArray(
      delegationChain,
      "delegationChain",
      "decisions.ingest",
    );
    // Optional zkProof object — non-null, non-array. Inner shape
    // (type / proof / publicSignals) validated by server.
    if (zkProof !== undefined) {
      if (
        zkProof === null ||
        typeof zkProof !== "object" ||
        Array.isArray(zkProof)
      ) {
        throw new TypeError(
          "decisions.ingest: `zkProof` must be an object when provided",
        );
      }
    }
    return this.client._request<DecisionRecord>({
      method: "POST",
      path: "/api/v1/decisions",
      body: input,
      options,
    });
  }

  /**
   * Append up to 500 decision records in a single request, with a
   * partial-success envelope.
   *
   * Wraps `POST /api/v1/decisions/bulk`. Returns a `BulkIngestResult`
   * describing which records persisted and which failed — the call
   * **resolves successfully even when every record failed**. Partial
   * success is the entire point of the endpoint; the caller branches on
   * `result.totalFailed` (or `result.failed.length`) if they care about
   * per-record errors. Top-level failures (auth, rate limit, plan limit,
   * oversize batch) DO throw `AttestryAPIError` with the corresponding
   * HTTP status.
   *
   * **Per-record codes** — see `BulkFailedSummary.code` JSDoc for the
   * full list. Most relevant for retries:
   *   - `"idempotency_unique_violation"`: race condition. Bulk does NOT
   *     auto-recover — retry the failed record individually via
   *     `decisions.ingest()` to invoke per-record race recovery.
   *   - `"system_not_found"`: cross-org system OR cross-system
   *     attestationId. Collapsed for enumeration safety.
   *
   * **At-least-once delivery**: pass an `idempotencyKey` on every item.
   * A 429-retry of the same batch then returns duplicates as
   * `failed[i].code === "idempotency_unique_violation"`; other items
   * insert normally. Without per-item keys, a retry that succeeds-but-
   * loses-the-response can create duplicate records.
   *
   * **Plan limits (402)**: the kernel checks the FULL batch size against
   * the org's `decisionsPerMonth` quota. A 100-record batch with 50
   * quota remaining is rejected wholesale (none persisted) — partial
   * quota fills are a reconciliation hazard. The 402 carries the same
   * `details: {feature, currentPlan, upgradeRequired}` shape as
   * `decisions.ingest` (B.1 carry-forward).
   *
   * Errors:
   *   - `AttestryAPIError` (status 401) — auth required
   *   - `AttestryAPIError` (status 402) — plan limit (with
   *     `details.feature` / `details.currentPlan` /
   *     `details.upgradeRequired`)
   *   - `AttestryAPIError` (status 413) — defensive top-level batch
   *     size guard (>500 items). Verbatim message: `"Bulk ingest
   *     limited to 500 records per request"`. In practice the kernel's
   *     Zod `.max(500)` fires first with a 422; this 413 only surfaces
   *     if the schema is bypassed.
   *   - `AttestryAPIError` (status 422) — Zod validation failed (one or
   *     more `items` malformed; OR top-level Zod fails for >500 items
   *     OR empty array — server's `.min(1).max(500)`).
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried by
   *     default — invariant #18). Body re-stringified per attempt.
   *   - `AttestryError` ("invalid request body: ...") — body
   *     serialization failed (BigInt, circular reference) BEFORE fetch
   *     (carry-forward invariant #4)
   *   - `AttestryError` ("request aborted by caller") — caller-supplied
   *     `options.signal` fired (pre-aborted or mid-flight)
   *   - `TypeError` (synchronous, no fetch issued) — input failed SDK-
   *     side type validation (see below)
   *
   * Notably ABSENT from the top-level error chain (vs `decisions.ingest`):
   *   - 404 (system not found) → per-record `failed[i].code === "system_not_found"`
   *   - 409 (idempotency conflict) → per-record `code === "idempotency_conflict"`
   *   - 500 (chain head missing) → per-record `code === "chain_head_missing"`
   *
   * SDK-side validation (synchronous `TypeError`, no fetch issued):
   *   - `input` itself: must be a non-null, non-array object
   *   - `input.items`: required, must be `Array.isArray`
   *
   * **Format and per-item validation deferred to server**. The SDK does
   * NOT pre-cap `items.length` at 500 (kernel's `.max(500)` is the
   * authority — a future cap raise would otherwise require an SDK
   * change). It does NOT recurse into `items[i]` to validate per-record
   * shape (symmetric to ingest's `frameworkClaims` / `toolInvocations`
   * policy — server's `.strict()` Zod is the schema authority).
   *
   * @example
   * ```ts
   * const result = await client.decisions.bulk({
   *   items: [
   *     { systemId, inputDigest, idempotencyKey: "trace-001" },
   *     { systemId, inputDigest, idempotencyKey: "trace-002" },
   *   ],
   * });
   * console.log(`${result.totalInserted}/${result.totalSubmitted} succeeded`);
   * for (const failure of result.failed) {
   *   if (failure.code === "idempotency_unique_violation") {
   *     // retry via single-record endpoint to invoke race recovery
   *     await client.decisions.ingest(originalItems[failure.index]);
   *   }
   * }
   * ```
   */
  bulk(
    input: DecisionBulkInput,
    options?: RequestOptions,
  ): Promise<BulkIngestResult> {
    // Top-level input shape — must be a non-null, non-array object.
    // Symmetric to `decisions.ingest` validation. typeof null === "object"
    // and typeof [] === "object", so guard both explicitly.
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError("decisions.bulk: `input` must be an object");
    }
    // Required: `items` must be an array (Array.isArray rejects null,
    // strings, numbers, plain objects). Empty array is allowed at SDK
    // level — server's `.min(1)` rejects with 422; per-item shape and
    // upper bound (500) are also server's authority.
    //
    // Read via `readInputField` — a throwing `items` accessor surfaces
    // as the documented synchronous `TypeError`, not the getter's raw
    // exception (session-22 hostile review #1 — the SDK-wide MEDIUM-1
    // getter-throws fix).
    const items = readInputField(input, "items", "decisions.bulk");
    if (!Array.isArray(items)) {
      throw new TypeError(
        "decisions.bulk: `items` is required and must be an array",
      );
    }
    return this.client._request<BulkIngestResult>({
      method: "POST",
      path: "/api/v1/decisions/bulk",
      body: input,
      options,
    });
  }

  /**
   * List decision records the caller can see, cursor-paginated.
   *
   * Pagination is keyset-based over `(createdAt DESC, id DESC)` —
   * identical-microsecond timestamps don't cause skipped rows. Pass
   * back `response.nextCursor` as `input.cursor` to fetch the next page.
   *
   * Returns a slim per-row shape (`DecisionListItem`) — subset of
   * `DecisionRecord`, deliberately omitting heavy fields. Call
   * `decisions.retrieve(id)` for the full record.
   *
   * Errors:
   *   - `AttestryAPIError` (status 400) — malformed cursor (server-side)
   *   - `AttestryAPIError` (status 401) — auth required
   *   - `AttestryAPIError` (status 403) — api-key missing `read:assessments`
   *   - `AttestryAPIError` (status 422) — invalid query parameters
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried by default)
   *
   * SDK-side validation (throws `TypeError` synchronously):
   *   - Each optional string field (systemId, from, to, framework,
   *     article, tool, cursor) must be a non-empty string when provided.
   *     Format validation (UUID, ISO date) is deferred to the server.
   *   - `limit` must be a number when provided.
   *   - `includeTombstoned` must be a boolean when provided.
   *
   * Response-shape validation (P2 hardening):
   *   - Rejects with `AttestryError` if the kernel response isn't a
   *     non-null object, lacks an `items` array, or has a `nextCursor`
   *     that isn't a string-or-null. Per-row shape is faithful-courier
   *     (NOT validated — P4 candidate).
   *
   * Transport-shape validation (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with a
   *     non-`application/json` Content-Type — protects against
   *     proxy-injected HTML 200 pages parsing into junk consumer state.
   *
   * @example
   * ```ts
   * let cursor: string | undefined;
   * for (let page = 0; page < 100; page++) {
   *   const { items, nextCursor } = await client.decisions.list({
   *     systemId,
   *     limit: 50,
   *     cursor,
   *   });
   *   for (const item of items) console.log(item.id, item.sequenceNumber);
   *   if (nextCursor === null) break;
   *   cursor = nextCursor;
   * }
   * ```
   */
  list(
    input: DecisionsListInput = {},
    options?: RequestOptions,
  ): Promise<DecisionsListResponse> {
    // Snapshot each query field via `readInputField` — a throwing
    // accessor surfaces as the documented synchronous `TypeError`
    // rather than the getter's raw exception (session-22 hostile
    // review #3 — completes the SDK-wide MEDIUM-1 getter-throws fix;
    // reviews #1-#2 converted decisions.ingest / .bulk but missed the
    // decisions query methods). The `as` cast restores each field's
    // declared `DecisionsListInput` type for the typed query below.
    const systemId = readInputField(input, "systemId", "decisions.list") as
      DecisionsListInput["systemId"];
    const from = readInputField(input, "from", "decisions.list") as
      DecisionsListInput["from"];
    const to = readInputField(input, "to", "decisions.list") as
      DecisionsListInput["to"];
    const framework = readInputField(input, "framework", "decisions.list") as
      DecisionsListInput["framework"];
    const article = readInputField(input, "article", "decisions.list") as
      DecisionsListInput["article"];
    const tool = readInputField(input, "tool", "decisions.list") as
      DecisionsListInput["tool"];
    const cursor = readInputField(input, "cursor", "decisions.list") as
      DecisionsListInput["cursor"];
    const limit = readInputField(input, "limit", "decisions.list") as
      DecisionsListInput["limit"];
    const includeTombstoned = readInputField(
      input,
      "includeTombstoned",
      "decisions.list",
    ) as DecisionsListInput["includeTombstoned"];
    validateOptionalNonEmptyString(systemId, "systemId");
    validateOptionalNonEmptyString(from, "from");
    validateOptionalNonEmptyString(to, "to");
    validateOptionalNonEmptyString(framework, "framework");
    validateOptionalNonEmptyString(article, "article");
    validateOptionalNonEmptyString(tool, "tool");
    validateOptionalNonEmptyString(cursor, "cursor");
    if (limit !== undefined && typeof limit !== "number") {
      throw new TypeError(
        "decisions.list: `limit` must be a number when provided",
      );
    }
    if (
      includeTombstoned !== undefined &&
      typeof includeTombstoned !== "boolean"
    ) {
      throw new TypeError(
        "decisions.list: `includeTombstoned` must be a boolean when provided",
      );
    }
    // Synchronous lone-surrogate guard: encodeQuery → encodeURIComponent
    // throws raw URIError for malformed UTF-16. Cross-phase follow-up
    // to the decisions.export hostile-review fix (commit 0428777).
    if (systemId !== undefined) {
      assertEncodableQueryString(systemId, "systemId", "decisions.list");
    }
    if (from !== undefined) {
      assertEncodableQueryString(from, "from", "decisions.list");
    }
    if (to !== undefined) {
      assertEncodableQueryString(to, "to", "decisions.list");
    }
    if (framework !== undefined) {
      assertEncodableQueryString(framework, "framework", "decisions.list");
    }
    if (article !== undefined) {
      assertEncodableQueryString(article, "article", "decisions.list");
    }
    if (tool !== undefined) {
      assertEncodableQueryString(tool, "tool", "decisions.list");
    }
    if (cursor !== undefined) {
      assertEncodableQueryString(cursor, "cursor", "decisions.list");
    }
    return this.client
      ._request<DecisionsListResponse>({
        method: "GET",
        path: "/api/v1/decisions",
        query: {
          systemId,
          from,
          to,
          framework,
          article,
          tool,
          cursor,
          limit,
          // Hostile-round H1: kernel uses `z.coerce.boolean()` which calls
          // `Boolean(value)` — `Boolean("false") === true`. So a literal
          // `?includeTombstoned=false` would silently RETURN TOMBSTONED
          // records (server interprets the string as truthy). Workaround:
          // when the caller explicitly passes `false`, OMIT the param so
          // the server's `default(false)` applies — same behavior the
          // user intended. Only emit the param when `true`. When kernel
          // upgrades to a string-aware boolean schema (.preprocess or
          // similar), this workaround becomes a no-op (passes "true"
          // through; "false"/omit difference vanishes).
          includeTombstoned: includeTombstoned === true ? true : undefined,
        },
        options,
      })
      .then((result) => {
        // P2 hardening: validate response shape. The kernel emits
        // `{success:true, data:{items, nextCursor}}` and the transport
        // unwraps `data` to give us `{items, nextCursor}`. A kernel-
        // side regression (e.g., emitting `data: null` or `data: {
        // items: "scalar" }`) would let TypeScript-typed access
        // produce undefined / crash consumers. Throw AttestryError at
        // the SDK boundary for a clear message.
        assertDecisionsListResponse(result);
        return result;
      });
  }

  /**
   * Subscribe to decision-record events as they're appended.
   *
   * Returns an `AsyncIterable<DecisionStreamEvent>` — consume with
   * `for await (const event of stream)`. Errors THROW (the iterator
   * surfaces them via the for-await loop's natural error path), in
   * contrast to `chat.stream()` which yields error chunks. Reason:
   *
   *   - `chat.stream()` is a request/response (one POST → one iterator).
   *     Yielding errors inline lets consumers render them in the same UI
   *     stream as the assistant's text.
   *   - `decisions.stream()` is a long-lived subscription. An error
   *     means the connection is gone — yielding inline would force every
   *     consumer to write `if (chunk.type === 'error') break;`. Throwing
   *     gives clean `try/catch` semantics with typed error classes
   *     (`AttestryAPIError` for 4xx/5xx, `AttestryError` for network /
   *     abort).
   *
   * Errors surface as:
   *   - `AttestryAPIError` (status 401) — auth failed
   *   - `AttestryAPIError` (status 403) — insufficient permissions
   *     (api keys need `read:assessments` scope)
   *   - `AttestryAPIError` (status 400) — malformed `systemId` or
   *     `lastEventId` (server-side validation)
   *   - `AttestryAPIError` (status 429) — rate limited
   *   - `AttestryError` ("request aborted by caller") — caller-provided
   *     `options.signal` fired (pre-abort or mid-iteration)
   *   - `AttestryError` ("network error: ...") — fetch-level failure
   *     before any frame; OR mid-stream connection drop (surfaces from
   *     the underlying reader, wrapped during iteration)
   *   - `AttestryError` ("SSE frame data was not valid JSON: ...") —
   *     defensive; the kernel always emits valid JSON in `data:` lines.
   *
   * Reconnection: the iterator does NOT auto-reconnect. On any error or
   * clean termination (server-side 5min timeout closes the connection),
   * the for-await loop ends. The caller then decides whether to call
   * `stream({lastEventId: lastSeen.eventId})` to resume.
   *
   * Lazy: the request is NOT issued until the first iteration. Pass
   * `options.signal` for cancellation — pre-aborted causes the first
   * iteration to throw `AttestryError` with no fetch issued; mid-flight
   * abort surfaces as `AttestryError` from the iterator.
   *
   * Heartbeat frames (`: heartbeat\n\n`) are silently consumed by the
   * SSE parser and never yielded to the consumer.
   *
   * @example
   * ```ts
   * try {
   *   for await (const event of client.decisions.stream({ systemId })) {
   *     console.log(event.id, event.sequenceNumber);
   *     lastEventId = event.eventId; // for reconnection
   *   }
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 401) {
   *     // re-auth
   *   } else if (err instanceof AttestryError) {
   *     // network drop — wait + retry with lastEventId
   *   }
   * }
   * ```
   */
  stream(
    input?: DecisionsStreamInput,
    options?: RequestOptions,
  ): AsyncIterable<DecisionStreamEvent> {
    // Snapshot input fields via `readInputField` — a throwing accessor
    // surfaces as the documented synchronous `TypeError` rather than
    // the getter's raw exception (session-22 hostile review #3 —
    // completes the SDK-wide MEDIUM-1 getter-throws fix; reviews #1-#2
    // missed the decisions query methods). `input` is optional; the
    // locals are read only inside the guard. The `as` cast restores
    // the declared `DecisionsStreamInput` field types. `runDecisionsStream`
    // still receives the original `input` — a throwing getter is
    // caught here first, so the helper is never reached on one.
    if (input !== undefined) {
      const systemId = readInputField(
        input,
        "systemId",
        "decisions.stream",
      ) as DecisionsStreamInput["systemId"];
      const lastEventId = readInputField(
        input,
        "lastEventId",
        "decisions.stream",
      ) as DecisionsStreamInput["lastEventId"];
      if (systemId !== undefined) {
        if (typeof systemId !== "string" || systemId.length === 0) {
          throw new TypeError(
            "decisions.stream: `systemId` must be a non-empty string when provided",
          );
        }
      }
      if (lastEventId !== undefined) {
        if (typeof lastEventId !== "string" || lastEventId.length === 0) {
          throw new TypeError(
            "decisions.stream: `lastEventId` must be a non-empty string when provided",
          );
        }
      }
      // Synchronous lone-surrogate guard for the systemId query string.
      // Cross-phase follow-up to decisions.export hostile-review fix
      // (commit 0428777). lastEventId rides on the Last-Event-ID header
      // — Headers.set throws TypeError on its own for invalid values
      // (CR/LF), no URIError concern, so no guard needed there.
      if (systemId !== undefined) {
        assertEncodableQueryString(systemId, "systemId", "decisions.stream");
      }
    }
    return runDecisionsStream(this.client, input, options);
  }

  /**
   * Export a system's decision chain as a streaming NDJSON response.
   *
   * Wraps `GET /api/v1/decisions/export`. Returns an
   * `AsyncIterable<DecisionExportFrame>` — records arrive first (in
   * `sequenceNumber` ascending order), then exactly one trailer that
   * commits the batch to a Merkle root over per-record `recordHash`
   * leaves.
   *
   * Errors **throw** from the iterator (long-lived stream semantics —
   * symmetric with `decisions.stream`). Use `try / catch` around the
   * for-await loop:
   *
   * @example
   * ```ts
   * try {
   *   for await (const frame of client.decisions.export({ systemId })) {
   *     if ("type" in frame && frame.type === "ExportTrailer") {
   *       // Final commit — verify Merkle root client-side post-Prompt-1.
   *       console.log(`${frame.recordCount} records, root=${frame.merkleRoot}`);
   *     } else {
   *       // Per-record line — DecisionListItem shape.
   *       process(frame);
   *     }
   *   }
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 422) {
   *     // bad systemId / unknown query / malformed datetime
   *   } else if (err instanceof AttestryError) {
   *     // network drop, parser error, missing trailer
   *   }
   * }
   * ```
   *
   * **Empty export** — when the systemId has zero records (or doesn't
   * exist / belongs to another org), the iterator yields a SINGLE
   * frame: a trailer with `recordCount: 0`, `sequenceFrom: null`,
   * `sequenceTo: null`, and the deterministic empty-export merkleRoot
   * (`sha256:` + hex of `sha256("ATTESTRY-EMPTY-EXPORT")`). The SDK
   * does NOT throw — the empty trailer is the kernel's success signal
   * for "no data".
   *
   * **Missing trailer** — every successful 200 stream ends with a
   * trailer. If the iterator exhausts without seeing one (mid-stream
   * connection drop, kernel error after headers committed), the SDK
   * throws `AttestryError("decisions.export: stream ended without
   * trailer — connection dropped or server failed mid-stream")`. This
   * surfaces a class of failures that the kernel can't return as 4xx
   * (the response was already 200 by the time the error arose).
   *
   * **Trailer signing field** — today the trailer's `signing` field is
   * the literal string `"unsigned-prompt-1-blocked"`. Once Prompt 1
   * ships Ed25519 signing, the field is replaced by a structured proof.
   * The SDK does NOT verify the signature — caller is responsible
   * (post-Prompt-1).
   *
   * Errors:
   *   - `AttestryAPIError` (status 401) — auth required
   *   - `AttestryAPIError` (status 422) — invalid query (missing
   *     systemId / unknown key / non-UUID systemId / malformed datetime)
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried by
   *     default — invariant #18; initial fetch only — invariant #20)
   *   - `AttestryAPIError` — wrong content-type at 200 (proxy / LB
   *     error page wrapped at 200)
   *   - `AttestryError` ("decisions.export: stream ended without
   *     trailer ...") — mid-stream failure detected at iterator end
   *   - `AttestryError` ("network error during stream: ...") — TCP
   *     drop / proxy hang-up mid-stream
   *   - `AttestryError` ("request aborted by caller") — caller-supplied
   *     `options.signal` fired (pre-aborted or mid-flight)
   *   - `AttestryError` ("NDJSON line was not valid JSON: ...") —
   *     defensive; the kernel always emits valid JSON
   *   - `AttestryError` ("NDJSON line exceeded maximum buffer size ...") —
   *     defensive; the kernel's per-record line is well below 1 MiB
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side type validation (see below)
   *
   * Notably ABSENT from the error surface:
   *   - **No 402 plan-limit** — export is a READ, doesn't count against
   *     the org's `decisionsPerMonth` quota.
   *   - **No 404 system-not-found** — a non-existent or cross-org
   *     systemId returns 200 with zero records and a trailer with
   *     `recordCount: 0`. Consumers detect via the trailer.
   *
   * SDK-side validation (synchronous `TypeError`, no fetch issued):
   *   - `input` itself: must be a non-null, non-array object
   *   - `input.systemId`: required, non-empty string
   *   - `input.from` / `input.to`: optional; non-empty string when provided
   *   - `input.includeTombstoned`: optional; boolean when provided
   *
   * Format validation deferred to server (UUID, ISO datetime). The
   * `includeTombstoned: false` boolean is forwarded LITERALLY (no
   * workaround) — the kernel session-6 fix to `stringBoolean` accepts
   * `"false"` correctly. Asymmetry from `decisions.list` (which still
   * omits `false` as defense-in-depth) is deliberate — build-round D7.
   *
   * Lazy: the request is NOT issued until the first iteration. Pass
   * `options.signal` for cancellation — pre-aborted causes the first
   * iteration to throw `AttestryError` with no fetch issued; mid-flight
   * abort surfaces as `AttestryError` from the iterator.
   */
  export(
    input: DecisionsExportInput,
    options?: RequestOptions,
  ): AsyncIterable<DecisionExportFrame> {
    // Top-level shape — must be a non-null, non-array object.
    // Symmetric to ingest / bulk validation. typeof null === "object"
    // and typeof [] === "object", so guard both explicitly.
    if (input === null || typeof input !== "object" || Array.isArray(input)) {
      throw new TypeError("decisions.export: `input` must be an object");
    }
    // Snapshot each query field via `readInputField` — a throwing
    // accessor surfaces as the documented synchronous `TypeError`
    // rather than the getter's raw exception (session-22 hostile
    // review #3 — completes the SDK-wide MEDIUM-1 getter-throws fix;
    // reviews #1-#2 converted decisions.ingest / .bulk but missed the
    // decisions query methods). The `as` cast restores each field's
    // declared `DecisionsExportInput` type. `runDecisionsExport` still
    // receives the original `input` — a throwing getter is caught here
    // first, so the helper's own field reads are never reached on one.
    const systemId = readInputField(input, "systemId", "decisions.export") as
      DecisionsExportInput["systemId"];
    const from = readInputField(input, "from", "decisions.export") as
      DecisionsExportInput["from"];
    const to = readInputField(input, "to", "decisions.export") as
      DecisionsExportInput["to"];
    const includeTombstoned = readInputField(
      input,
      "includeTombstoned",
      "decisions.export",
    ) as DecisionsExportInput["includeTombstoned"];
    // Required: systemId. Failing here throws synchronously with no
    // fetch — invariant. Format check (UUID) deferred to server's Zod.
    if (typeof systemId !== "string" || systemId.length === 0) {
      throw new TypeError(
        "decisions.export: `systemId` is required and must be a non-empty string",
      );
    }
    // Optional date filters — non-empty strings when provided. ISO
    // datetime format check is the server's job.
    validateOptionalNonEmptyString(from, "from", "decisions.export");
    validateOptionalNonEmptyString(to, "to", "decisions.export");
    // Optional includeTombstoned — strict boolean when provided.
    if (
      includeTombstoned !== undefined &&
      typeof includeTombstoned !== "boolean"
    ) {
      throw new TypeError(
        "decisions.export: `includeTombstoned` must be a boolean when provided",
      );
    }
    // Synchronous lone-surrogate guard: the underlying transport runs
    // `encodeURIComponent` over each query value, which throws a raw
    // `URIError` for malformed UTF-16 (lone surrogates like `\uD800`).
    // Without this catch the URIError leaks into the consumer's
    // for-await loop as a non-AttestryError class — inconsistent with
    // `decisions.retrieve` (which already converts URIError → TypeError
    // for the path segment). Hostile-review: validate the strings
    // up-front so the failure is synchronous + named.
    assertEncodableQueryString(systemId, "systemId", "decisions.export");
    if (from !== undefined) {
      assertEncodableQueryString(from, "from", "decisions.export");
    }
    if (to !== undefined) {
      assertEncodableQueryString(to, "to", "decisions.export");
    }
    return runDecisionsExport(this.client, input, options);
  }

  /**
   * Replay a system's hash chain and report integrity verdict.
   *
   * Wraps `GET /api/v1/decisions/verify-chain/{systemId}`. Returns a
   * `ChainVerificationResult` describing whether tampering was detected
   * and which records (if any) failed which check.
   *
   * **Critical contract — partial-success envelope**: the kernel returns
   * **HTTP 200 with `chainValid: false`** when tampering is detected.
   * The SDK resolves the Promise with the verdict body — it does **NOT**
   * throw on `chainValid: false`. The customer asked the chain-integrity
   * question and the kernel answered; the SDK is a faithful courier.
   * Top-level structural failures (auth, rate limit, system-not-found,
   * `ChainTooLong`) DO throw `AttestryAPIError`. Carry-forward invariant
   * #12; same family as `decisions.bulk` (200 with `totalFailed > 0`
   * resolves rather than throws).
   *
   * **Failure-mode discrimination**: the two ID arrays are surfaced
   * separately so consumers can route on the SECURITY-vs-OPS distinction
   * at the call site (the kernel uses the same distinction to fire the
   * `chain.tampered` vs `chain.broken` webhook):
   *   - `tamperedRecordIds`: direct content tampering (security signal).
   *   - `brokenRecordIds`: gap in the chain (ops signal — missing record).
   * Both arrays can be non-empty simultaneously.
   *
   * **Side effect (out-of-band)**: the kernel dispatches one of three
   * fire-and-forget webhooks AFTER the response body is built but BEFORE
   * returning — `chain.verified` (when valid), `chain.tampered` (when
   * `tamperedRecordIds.length > 0`), or `chain.broken` (when only
   * `brokenRecordIds.length > 0`). The SDK does NOT see / verify these;
   * they're surfaced through the webhooks resource (a different SDK
   * surface). Consumers who want webhook-based observability subscribe
   * via the kernel's webhook endpoints.
   *
   * **413 with export hint**: when the chain length exceeds
   * `MAX_SYNC_CHAIN_LENGTH` (50,000 records), the kernel returns 413
   * with the export-endpoint hint. The transport stores the entire
   * parsed error body under `AttestryAPIError.details`, and the kernel's
   * own structured `details` object nests inside — so the consumer-side
   * access path is `err.details?.details?.hint` (double-`details`).
   * Consumers detect this case via
   * `error.details?.details?.hint?.includes("decisions/export")` and
   * fall back to streaming the chain through `decisions.export()` for
   * offline verification. The `ChainTooLongError` kernel class is
   * internal; its 413 surface is what the SDK exposes.
   *
   * Errors:
   *   - `AttestryAPIError` (status 400) — `systemId` failed server-side
   *     UUID format check (`isValidUuid` rejects, NOT a Zod 422).
   *   - `AttestryAPIError` (status 401) — auth required (no session
   *     and no api-key).
   *   - `AttestryAPIError` (status 403) — propagates if upstream
   *     `AuthError` was thrown with a custom 403 statusCode (rare; the
   *     route's default for cross-org systems is 404).
   *   - `AttestryAPIError` (status 404) — system not found OR cross-org
   *     system (deliberate enumeration-safety collapse, same shape as
   *     retrieve / ingest).
   *   - `AttestryAPIError` (status 413) — `ChainTooLong` (>50,000 records)
   *     with `err.details?.details?.hint` referencing `/api/v1/decisions/export`.
   *     (Double-`details`: transport stores the whole parsed body under
   *     `.details`; the kernel's own `details` object nests inside.)
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried by
   *     default — invariant #18; per-IP `assessmentLimiter`).
   *   - `AttestryAPIError` (status 500) — internal error with a SCRUBBED
   *     message (no leak of the underlying kernel error). Surfaces e.g.
   *     when the DB connection drops mid-verification.
   *   - `AttestryError` ("request aborted by caller") — caller-supplied
   *     `options.signal` fired (pre-aborted or mid-flight).
   *   - `TypeError` (synchronous, no fetch issued) — `systemId` failed
   *     SDK-side validation (empty / non-string / lone-surrogate /
   *     path-traversal segment).
   *
   * Notably ABSENT from the error chain:
   *   - **No 402 plan-limit** — verifyChain is a READ; doesn't count
   *     against `decisionsPerMonth` quota.
   *   - **No 422** — the only input is a path segment, validated as a
   *     UUID via `isValidUuid` (which returns 400, not 422). No query
   *     schema, no body schema, no Zod.
   *
   * SDK-side validation (synchronous `TypeError`, no fetch issued):
   *   - `systemId`: must be a non-empty string.
   *   - `systemId`: must NOT be the exact string `"."` or `".."` — these
   *     survive `encodeURIComponent` but get collapsed by `fetch`'s
   *     URL normalization into the parent endpoint, silently redirecting
   *     the request to a different resource. NUL bytes (`\0`) also
   *     rejected. Hostile-review F1.
   *   - `systemId`: must be encodable via `encodeURIComponent` — lone
   *     surrogates throw a synchronous `TypeError` with `cause: err`
   *     wrapping the original `URIError`. Mirror of `decisions.retrieve`'s
   *     L1 pattern (carry-forward invariant #32).
   *
   * **Format validation deferred to server** (UUID format check happens
   * server-side via `isValidUuid`, returns 400).
   *
   * Response-shape validation (P2 hardening):
   *   - Rejects with `AttestryError` if the kernel response isn't a
   *     non-null object (`null`, scalar, or array). Per-field shape
   *     (e.g. `chainValid: boolean`) is faithful-courier — NOT
   *     validated.
   *
   * Transport-shape validation (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with a
   *     non-`application/json` Content-Type. NOTE: `chainValid: false`
   *     is a normal 200 response and resolves the promise (carry-forward
   *     invariant #12); only structural failures throw.
   *
   * @example
   * ```ts
   * const verdict = await client.decisions.verifyChain(systemId);
   * if (!verdict.chainValid) {
   *   if (verdict.tamperedRecordIds.length > 0) {
   *     // SECURITY signal: someone edited stored bytes / hashes.
   *     await notifySecurity({ systemId, ids: verdict.tamperedRecordIds });
   *   } else if (verdict.brokenRecordIds.length > 0) {
   *     // OPS signal: a record went missing.
   *     await notifyOps({ systemId, ids: verdict.brokenRecordIds });
   *   }
   * }
   * console.log(`verified up to sequence ${verdict.lastVerifiedSequence}`);
   *
   * // 413 → fall back to export + offline verification:
   * try {
   *   await client.decisions.verifyChain(largeSystemId);
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 413) {
   *     // err.details?.details?.hint references /api/v1/decisions/export
   *     // (double-details: transport's wrap + kernel's structured detail)
   *     for await (const frame of client.decisions.export({ systemId: largeSystemId })) {
   *       // verify chain offline ...
   *     }
   *   }
   * }
   * ```
   */
  verifyChain(
    systemId: string,
    options?: RequestOptions,
  ): Promise<ChainVerificationResult> {
    // Validation + URL-segment encoding centralized in the shared
    // `encodePathSegment` helper. Throws TypeError synchronously for
    // empty/non-string/path-traversal/lone-surrogate inputs (mirror
    // of `decisions.retrieve`'s validation; carry-forward invariants
    // #32 + hostile-review F1).
    const encoded = encodePathSegment(
      systemId,
      "systemId",
      "decisions.verifyChain",
    );
    return this.client
      ._request<ChainVerificationResult>({
        method: "GET",
        path: `/api/v1/decisions/verify-chain/${encoded}`,
        options,
      })
      .then((result) => {
        // P2 hardening (extended F1 sweep — sync GET completeness):
        // validate the kernel returned an object. The kernel returns
        // 200 with `chainValid: false` on tampering (carry-forward
        // invariant #12 — the SDK does NOT throw on chainValid:false),
        // so the response is ALWAYS an object on the success path.
        // Null/scalar/array would be a kernel-side regression. Per-
        // field shape (chainValid is boolean, etc.) is faithful-courier
        // — NOT validated here.
        assertNonNullObjectResponse(result, "decisions.verifyChain");
        return result;
      });
  }
}

/**
 * Validate an optional input field is a non-empty string when provided.
 * Shared by `decisions.list` and `decisions.ingest`; symmetric to the
 * `decisions.stream` inline-validation pattern. Throws `TypeError` (not
 * `AttestryError`) so consumer code can branch on `instanceof TypeError`
 * uniformly across resources for input-validation errors.
 *
 * `methodName` defaults to `"decisions.list"` to preserve the original
 * call sites' message format. New callers (e.g., `decisions.ingest`)
 * pass their method name explicitly so the surfaced TypeError names
 * the right method.
 *
 * Format validation (UUID, ISO date, etc.) is deferred to the server —
 * the kernel's Zod gate is the schema authority (build-round D5).
 */
function validateOptionalNonEmptyString(
  value: unknown,
  fieldName: string,
  methodName: string = "decisions.list",
): void {
  if (value === undefined) return;
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(
      `${methodName}: \`${fieldName}\` must be a non-empty string when provided`,
    );
  }
}

/**
 * Synchronously verify a query-string value is encodable via
 * `encodeURIComponent`. The platform throws `URIError` for malformed
 * UTF-16 (lone surrogates such as `\uD800` / `\uDFFF`); the transport's
 * `encodeQuery` does NOT catch it, so without this guard the failure
 * leaks into the lazy iterator as a raw `URIError` — inconsistent with
 * `decisions.retrieve` (which already converts URIError → TypeError on
 * the path-segment encoding). Hostile-review: bring the export resource
 * in line so callers see a synchronous, named TypeError.
 *
 * Cause-chained for debugging.
 */
function assertEncodableQueryString(
  value: string,
  fieldName: string,
  methodName: string,
): void {
  try {
    encodeURIComponent(value);
  } catch (err) {
    throw new TypeError(
      `${methodName}: \`${fieldName}\` contains invalid UTF-16 sequences (${
        // encodeURIComponent always throws URIError (an Error subclass),
        // so the String(err) branch is unreachable. Defense-in-depth
        // marker for the v8 coverage tool.
        /* v8 ignore next */
        err instanceof Error ? err.message : String(err)
      })`,
      { cause: err },
    );
  }
}

/**
 * Validate + encode a single path-segment input. Returns the
 * `encodeURIComponent`-encoded form, or throws `TypeError`
 * synchronously for any of:
 *
 *   - non-string / empty string → `${methodName}: \`${fieldName}\` is required`
 *   - exact `"."` or `".."` or strings containing `\0` →
 *     `${methodName}: \`${fieldName}\` contains invalid path-segment characters`
 *   - lone UTF-16 surrogates (encodeURIComponent throws URIError) →
 *     `${methodName}: \`${fieldName}\` contains invalid UTF-16 sequences (...)`
 *     with `cause: err` wrapping the original `URIError`
 *
 * **Hostile-review F1 origin (cross-resource fix)**: `encodeURIComponent`
 * does NOT encode `.` or `..`, and WHATWG-spec `fetch` normalizes URL
 * paths — so a literal `verifyChain("..")` (or `retrieve("..")`) would
 * produce `/api/v1/decisions/verify-chain/..`, which the URL parser
 * collapses to `/api/v1/decisions/` (the LIST endpoint). The kernel
 * returns 200 with a list-shaped body, the SDK unwraps the envelope,
 * and the consumer's `result.chainValid` (or `result.id`) reads
 * `undefined`. Reject exact-match traversal segments AT the SDK
 * boundary so the failure is loud and synchronous instead of silent
 * cross-endpoint shadowing.
 *
 * Embedded `..` in a longer segment (e.g., `"foo/../bar"`) is safe —
 * `encodeURIComponent` encodes `/` as `%2F`, so the path stays a
 * single segment and the URL parser doesn't normalize.
 *
 * Carry-forward invariant #32 (URIError defect-class is uniformly
 * handled) — the URIError → TypeError wrap with `{cause: err}` and
 * the v8-ignore directive on the unreachable `String(err)` branch
 * are centralized here for all path-segment methods.
 *
 * Used by:
 *   - `decisions.retrieve(id)` — fieldName: "id"
 *   - `decisions.verifyChain(systemId)` — fieldName: "systemId"
 *   - Future `webhooks.delete(id)` / `webhooks.test(id)` — fieldName: "id"
 */
function encodePathSegment(
  value: unknown,
  fieldName: string,
  methodName: string,
): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${methodName}: \`${fieldName}\` is required`);
  }
  if (value === "." || value === ".." || value.includes("\0")) {
    throw new TypeError(
      `${methodName}: \`${fieldName}\` contains invalid path-segment characters`,
    );
  }
  try {
    return encodeURIComponent(value);
  } catch (err) {
    throw new TypeError(
      `${methodName}: \`${fieldName}\` contains invalid UTF-16 sequences (${
        // encodeURIComponent always throws URIError (an Error subclass),
        // so the String(err) branch is unreachable. Defense-in-depth
        // marker for the v8 coverage tool.
        /* v8 ignore next */
        err instanceof Error ? err.message : String(err)
      })`,
      { cause: err },
    );
  }
}

/**
 * Validate an optional input field is an array (any contents) when
 * provided. Used by `decisions.ingest` for nested array fields
 * (`frameworkClaims`, `toolInvocations`, `delegationChain`). Empty
 * arrays pass through faithfully — the server's `.default([])`
 * produces the same persisted shape.
 *
 * Inner-item validation (per-element shape, field caps) is deferred to
 * the server — duplicating it SDK-side would risk drift from the
 * kernel's `.strict()` Zod schema.
 */
function validateOptionalArray(
  value: unknown,
  fieldName: string,
  methodName: string,
): void {
  if (value === undefined) return;
  if (!Array.isArray(value)) {
    throw new TypeError(
      `${methodName}: \`${fieldName}\` must be an array when provided`,
    );
  }
}

/**
 * Human-readable type description for response-shape error messages.
 * Distinguishes `null` and `array` from generic `object`.
 *
 * Duplicated in `regulatory-changes.ts` and `incidents.ts` per project
 * pattern (small helper, leaf-resource modules, no shared module yet).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

/**
 * P2 hardening (F1 sweep — sync GET completeness): validate that a
 * sync GET response is a non-null, non-array object. Used by
 * `decisions.retrieve` and `decisions.verifyChain`, both of which
 * return single-object responses (`DecisionRecord` and
 * `ChainVerificationResult`) where the only legitimate kernel
 * shape is an object.
 *
 * Asserts only:
 *   - `raw` is non-null
 *   - `raw` is `typeof "object"` (catches scalars: string/number/etc.)
 *   - `raw` is NOT an array
 *
 * Per-field validation is faithful-courier — left to the consumer.
 * The transport's envelope unwrap is also unguarded against missing
 * `data` field (kernel emitting `{success:true}` without `data`
 * would let `{success:true}` reach this function, which passes
 * because it's a non-null object — that's a separate transport-
 * layer concern, P5 candidate).
 */
function assertNonNullObjectResponse(
  raw: unknown,
  methodName: string,
): void {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new AttestryError(
      `${methodName}: expected an object response from the kernel (got ${describeType(raw)})`,
    );
  }
}

/**
 * P2 hardening: validate the kernel's `decisions.list` response shape.
 *
 * The kernel emits `{success:true, data:{items: DecisionListItem[],
 * nextCursor: string|null}}`. The transport unwraps `data`, so we
 * receive `{items, nextCursor}` here. A kernel-side regression
 * (e.g., `data: null`, missing `items`, or `nextCursor` of wrong
 * type) would let TypeScript-typed access reach consumers
 * unchecked.
 *
 * Asserts:
 *   - `result` is a non-null, non-array object.
 *   - `result.items` is an array.
 *   - `result.nextCursor` is a string OR null (NOT undefined, NOT
 *     other types).
 *
 * Per-row item shape is NOT validated (faithful-courier; consumers
 * parse via their own per-row validators). Pinning per-row would
 * require a separate hardening initiative (P4 candidate).
 */
function assertDecisionsListResponse(
  raw: unknown,
): asserts raw is DecisionsListResponse {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new AttestryError(
      `decisions.list: expected an object response from the kernel (got ${describeType(raw)})`,
    );
  }
  const obj = raw as Record<string, unknown>;
  if (!Array.isArray(obj.items)) {
    throw new AttestryError(
      `decisions.list: kernel response missing or invalid \`items\` array (got ${describeType(obj.items)})`,
    );
  }
  if (obj.nextCursor !== null && typeof obj.nextCursor !== "string") {
    throw new AttestryError(
      `decisions.list: kernel response \`nextCursor\` must be string or null (got ${describeType(obj.nextCursor)})`,
    );
  }
}

/**
 * Internal — async generator backing `decisions.stream`. Lazy: the
 * request is NOT issued until the first iteration. The SSE parser
 * (`parseSSEResponse`) handles connection cleanup in its own `finally`
 * block — including the early-break case where a consumer exits the
 * for-await loop before the stream ends naturally.
 */
async function* runDecisionsStream(
  client: AttestryClient,
  input: DecisionsStreamInput | undefined,
  options: RequestOptions | undefined,
): AsyncGenerator<DecisionStreamEvent, void, unknown> {
  const headers: Record<string, string> = {};
  if (input?.lastEventId !== undefined) {
    headers["Last-Event-ID"] = input.lastEventId;
  }
  const query: Record<string, string> = {};
  if (input?.systemId !== undefined) {
    query.systemId = input.systemId;
  }

  const response = await client._streamRequest({
    path: "/api/v1/decisions/stream",
    query,
    headers,
    options,
  });

  // Wrap mid-iteration errors in SDK error classes for symmetry with
  // pre-iteration errors (which `streamRequest` already wraps in its
  // catch block). Without this wrap:
  //   - Mid-flight signal-abort would surface as DOMException
  //     `AbortError`, NOT as `AttestryError("request aborted by caller")`
  //     — inconsistent with the pre-aborted path. Hostile-review H1.
  //   - Mid-stream network failures (TCP RST, server crash, proxy
  //     hang-up) would surface as raw TypeError / AbortError, NOT as
  //     `AttestryError("network error during stream: ...")` — consumers
  //     can't branch on `instanceof AttestryError` uniformly.
  //     Hostile-review H2.
  // SDK errors raised inside the loop (parser validation, JSON parse,
  // missing fields) are already AttestryError — pass-through.
  try {
    for await (const frame of parseSSEResponse(response)) {
      // Skip metadata-only frames (no `data:` payload). The kernel never
      // emits these today — defensive.
      if (frame.data.length === 0) continue;
      // Validate the SSE-level `id:` line is present and non-empty. The
      // kernel ALWAYS emits `id: <cursor>` in `formatSSEFrame` — a frame
      // missing it is either a parser bug or a server-side regression.
      // Without this check, the SDK would silently set `eventId: ""`,
      // which the consumer would pass back as `Last-Event-ID: ` and the
      // server would 400 — better to fail-fast at the SDK boundary.
      if (typeof frame.id !== "string" || frame.id.length === 0) {
        throw new AttestryError(
          "decisions.stream: SSE frame missing required `id:` field — server emitted a frame without a resume cursor",
        );
      }
      const payload = parseSSEData<{
        id: unknown;
        systemId: unknown;
        sequenceNumber: unknown;
        recordHash: unknown;
        prevRecordHash: unknown;
        tombstoned: unknown;
        createdAt: unknown;
      }>(frame.data);
      // Validate the wire shape. The SDK is the typed boundary — if the
      // server emits a malformed payload (schema bug, version skew), we
      // throw a clear error rather than yielding `undefined as string`.
      if (
        payload === null ||
        typeof payload !== "object" ||
        typeof payload.id !== "string" ||
        typeof payload.systemId !== "string" ||
        typeof payload.sequenceNumber !== "number" ||
        typeof payload.recordHash !== "string" ||
        (payload.prevRecordHash !== null &&
          typeof payload.prevRecordHash !== "string") ||
        typeof payload.tombstoned !== "boolean" ||
        typeof payload.createdAt !== "string"
      ) {
        throw new AttestryError(
          "decisions.stream: SSE frame payload missing required fields or wrong type",
        );
      }
      yield {
        id: payload.id,
        systemId: payload.systemId,
        sequenceNumber: payload.sequenceNumber,
        recordHash: payload.recordHash,
        prevRecordHash: payload.prevRecordHash as string | null,
        tombstoned: payload.tombstoned,
        createdAt: payload.createdAt,
        eventId: frame.id,
        // `?? ""` defends against a frame with no `event:` line — the
        // kernel always emits it, so the empty-string fallback is
        // unreachable in tests. Defense-in-depth marker for v8.
        /* v8 ignore next */
        eventType: frame.event ?? "",
      };
    }
  } catch (err) {
    if (err instanceof AttestryError) throw err;
    if (isAbortError(err)) {
      throw new AttestryError("request aborted by caller", { cause: err });
    }
    throw new AttestryError(
      `network error during stream: ${
        // parseSSE doesn't wrap reader errors (unlike parseNDJSON
        // post hostile-fix), so the err can be a TypeError (Error
        // subclass — covered) or in principle any platform-thrown
        // value. Real fetch implementations always throw Error
        // subclasses; the String(err) branch is defense-in-depth
        // for non-Error throws.
        /* v8 ignore next */
        err instanceof Error ? err.message : String(err)
      }`,
      { cause: err },
    );
  }
}

/**
 * True if `err` is an AbortError-shaped exception. Both browsers and
 * Node 18+ throw `DOMException { name: "AbortError" }` when fetch /
 * stream-read is aborted — but type-narrowing on DOMException alone is
 * too broad (it includes other DOM errors). Check by name instead.
 */
function isAbortError(err: unknown): boolean {
  return (
    err !== null &&
    typeof err === "object" &&
    "name" in err &&
    (err as { name: unknown }).name === "AbortError"
  );
}

/**
 * Internal — async generator backing `decisions.export`. Lazy: the
 * request is NOT issued until the first iteration. The NDJSON parser
 * (`parseNDJSONResponse`) handles connection cleanup in its own
 * `finally` block — including the early-break case where a consumer
 * exits the for-await loop before the stream ends naturally.
 *
 * Mid-stream contract: throws `AttestryError("...stream ended without
 * trailer...")` if the iterator exhausts without seeing a frame with
 * `type: "ExportTrailer"`. The kernel commits to a 200 BEFORE knowing
 * the stream will succeed; mid-stream errors after that point can't
 * surface as 4xx, only as truncation. The SDK detects truncation
 * via the missing trailer and surfaces a clear error class.
 *
 * Defensive frame ordering: per build-round hostile #11 / #12, the SDK
 * accepts trailer-then-records and multi-trailer streams in wire order
 * (the kernel always emits exactly one trailer last). Once any trailer
 * has been seen, the missing-trailer check passes — extra frames
 * yielded after a trailer are still validated and emitted.
 */
async function* runDecisionsExport(
  client: AttestryClient,
  input: DecisionsExportInput,
  options: RequestOptions | undefined,
): AsyncGenerator<DecisionExportFrame, void, unknown> {
  // Build query — emit `false` literally per build-round D7 (kernel
  // session-6 stringBoolean fix means this works server-side).
  // `decisions.list`'s defense-in-depth workaround (omit when false)
  // is NOT applied here — asymmetry is deliberate.
  const query: Record<string, string | boolean | undefined> = {
    systemId: input.systemId,
    from: input.from,
    to: input.to,
    includeTombstoned: input.includeTombstoned,
  };

  const response = await client._streamRequest({
    path: "/api/v1/decisions/export",
    query,
    options,
    expectedContentType: "application/x-ndjson",
  });

  let sawTrailer = false;
  // No try/catch around the for-await: post the hostile-review fix at
  // commit 0428777, parseNDJSON wraps every reader rejection as
  // AttestryError (AbortError → "request aborted by caller"; everything
  // else → "network error during stream: ..."). Frame-validation throws
  // in this loop are also AttestryError. So errors propagate naturally
  // with the right type. Asymmetry vs `runDecisionsStream` (which still
  // wraps at the resource layer) is intentional — parseSSE doesn't wrap
  // and live in another phase.
  for await (const raw of parseNDJSONResponse(response)) {
      // Every NDJSON line must be a JSON object — neither records nor
      // trailer can be a primitive, array, or null. Defensive: kernel
      // always emits objects, but a parser yielding e.g. a bare number
      // would otherwise pass through as `frame` of type `unknown`.
      if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
        throw new AttestryError(
          "decisions.export: NDJSON line was not a JSON object",
        );
      }
      const obj = raw as Record<string, unknown>;
      // Discriminator: trailer carries `type: "ExportTrailer"`.
      if (obj.type === "ExportTrailer") {
        // Validate trailer wire shape. The SDK is the typed boundary —
        // a malformed trailer (schema bug, version skew) throws here
        // rather than yielding `undefined as string` to the caller.
        if (
          typeof obj.systemId !== "string" ||
          typeof obj.recordCount !== "number" ||
          (obj.sequenceFrom !== null &&
            typeof obj.sequenceFrom !== "number") ||
          (obj.sequenceTo !== null && typeof obj.sequenceTo !== "number") ||
          typeof obj.merkleRoot !== "string" ||
          typeof obj.signing !== "string" ||
          typeof obj.generatedAt !== "string"
        ) {
          throw new AttestryError(
            "decisions.export: ExportTrailer missing required fields or wrong type",
          );
        }
        sawTrailer = true;
        yield {
          type: "ExportTrailer",
          systemId: obj.systemId,
          recordCount: obj.recordCount,
          sequenceFrom: obj.sequenceFrom as number | null,
          sequenceTo: obj.sequenceTo as number | null,
          merkleRoot: obj.merkleRoot,
          signing: obj.signing,
          generatedAt: obj.generatedAt,
        };
      } else {
        // Per-record frame — must match the DecisionListItem shape.
        // Validate field-by-field; jsonb arrays accept any contents.
        if (
          typeof obj.id !== "string" ||
          typeof obj.systemId !== "string" ||
          typeof obj.sequenceNumber !== "number" ||
          typeof obj.inputDigest !== "string" ||
          (obj.outputDigest !== null && typeof obj.outputDigest !== "string") ||
          !Array.isArray(obj.frameworkClaims) ||
          !Array.isArray(obj.toolInvocations) ||
          !Array.isArray(obj.delegationChain) ||
          (obj.humanOversightState !== null &&
            typeof obj.humanOversightState !== "string") ||
          (obj.policyOutcome !== null &&
            typeof obj.policyOutcome !== "string") ||
          (obj.prevRecordHash !== null &&
            typeof obj.prevRecordHash !== "string") ||
          typeof obj.recordHash !== "string" ||
          typeof obj.createdAt !== "string" ||
          typeof obj.tombstoned !== "boolean"
        ) {
          throw new AttestryError(
            "decisions.export: NDJSON record missing required fields or wrong type",
          );
        }
        yield {
          id: obj.id,
          systemId: obj.systemId,
          sequenceNumber: obj.sequenceNumber,
          inputDigest: obj.inputDigest,
          outputDigest: obj.outputDigest as string | null,
          frameworkClaims: obj.frameworkClaims as unknown[],
          toolInvocations: obj.toolInvocations as unknown[],
          delegationChain: obj.delegationChain as unknown[],
          humanOversightState: obj.humanOversightState as string | null,
          policyOutcome: obj.policyOutcome as string | null,
          prevRecordHash: obj.prevRecordHash as string | null,
          recordHash: obj.recordHash,
          createdAt: obj.createdAt,
          tombstoned: obj.tombstoned,
        };
      }
    }
    // No catch needed: post the hostile-review fix at commit 0428777,
    // parseNDJSON wraps every reader rejection as AttestryError
    // (AbortError → "request aborted by caller"; everything else →
    // "network error during stream: ..."). Frame-validation throws in
    // the for-await body above are also AttestryError. So errors from
    // the loop are already typed and propagate naturally. (If a future
    // refactor un-wraps in parseNDJSON, the resulting raw exception
    // will surface to the consumer — that's the right behavior to
    // expose the regression early, not paper over it.)

  // Mid-stream contract: every successful 200 ends with a trailer. If
  // we exhausted the iterator without seeing one, the kernel committed
  // to 200 and then errored after the headers were sent — the response
  // can't be a 4xx by then. Surface as a clear AttestryError so the
  // caller can branch on it. Build-round D8 / hostile #10.
  if (!sawTrailer) {
    throw new AttestryError(
      "decisions.export: stream ended without trailer — connection dropped or server failed mid-stream",
    );
  }
}
