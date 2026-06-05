// ─── Batch resource ─────────────────────────────────────────────────────────
//
// Wraps the bulk classification + assessment surface (session 18):
//
//   - POST /api/v1/batch          Body: {jobType, systemIds, config?}
//   - GET  /api/v1/batch/<UUID>   Retrieve batch-job status + results
//
// Sixth non-decisions resource on `@attestry/sdk`. Sibling to
// `IncidentsResource`, `DecisionsResource`, `ChatResource`,
// `AuditLogResource`, `RegulatoryChangesResource`,
// `ComplianceCheckResource`, `CheckResource`, `GateResource`.
//
// **First SDK resource with asymmetric auth between methods on the
// same resource** (carry-forward invariant candidate #54). The two
// methods use DIFFERENT permission requirements:
//   - `submit()` (POST): kernel uses
//     `requireApiKeyWithPermission(req, CLASSIFY, WRITE_ASSESSMENTS)`
//     — UNION/OR semantics (`Array.some()` at permissions.ts:53-55).
//     **First SDK route to use a WRITE-side union pair**; every prior
//     SDK route's union has been READ-side
//     (`READ_ASSESSMENTS or READ_SYSTEMS`).
//   - `get()` (GET): kernel uses
//     `requireApiKeyWithPermission(req, READ_ASSESSMENTS)` — single-
//     permission auth, NOT a union. Status reads only need READ.
// Pin BOTH 401 (no/invalid key) AND 403 (key has NONE of the required
// permissions) branches separately per invariant #45 / #54.
//
// **NEW plan-guard 403 surface on `submit()`** (carry-forward
// invariant candidate #55). The kernel calls
// `requirePlan(org, "hasBatchProcessing")` at route.ts:67 BEFORE Zod
// body parsing. A free-tier org submitting a batch hits the plan
// gate FIRST (independently of permissions). The kernel emits
// `PlanLimitError` → **403 with a DIFFERENT recovery path than the
// permission-403**. Wording difference (verify against
// `src/lib/middleware/plan-guard.ts:requirePlan` — the throw is at
// lines 106-111 of that file at the time of writing; the surrounding
// function spans lines 96-112):
//   - Permission 403:
//     `"API key lacks required permission. Required: classify or
//     write:assessments. Key has: <perms>."`
//   - Plan 403:
//     `"The \"hasBatchProcessing\" feature is not available on your
//     current plan (<plan>). Please upgrade to access this feature."`
// The SDK surfaces both uniformly as `AttestryAPIError(403)`;
// consumers regex-match `apiErr.message` if they need to distinguish
// (the wording difference is documented; no SDK-side discriminator
// helper today — invariant candidate #55 option A). A future kernel
// version adding structured error metadata would unlock a clean
// discriminator field on `apiErr.details`.
//
// **THIRD SDK route to PRE-VALIDATE every Zod closed-spec rule
// synchronously** (after `check.run` and `gate.evaluate`). The
// kernel uses `parseBody(request, batchSubmitSchema)` where
// `batchSubmitSchema = z.object({jobType: z.enum([...]), systemIds:
// z.array(z.string().uuid()).min(1).max(50), config:
// z.object({frameworks: z.array(z.string().min(1).max(100))
// .max(20).optional()}).optional()})`. The SDK pre-validates EVERY
// closed-spec rule synchronously:
//   - `jobType` membership in the 3-string enum (#41 carry-forward).
//   - `systemIds` array length [1, 50] inclusive + per-element UUID
//     format (#49 carry-forward; **the `.min(1)` is new** —
//     gate/check's frameworks was `.max(20)` with empty allowed).
//   - `config.frameworks` carry-forward from gate/check exactly:
//     array length ≤20 + per-element string length [1, 100].
// The SDK's runtime checks always run regardless of TypeScript types
// — `as any` casts do NOT bypass them. So 422 from this route
// reaches consumers ONLY via kernel-side rule changes the SDK
// hasn't synced to.
//
// **Asymmetric cross-org / not-found error code on `submit()`** —
// the kernel verifies every requested system belongs to the caller's
// org (route.ts:71-85) and collapses any cross-org OR missing system
// to **404 with offending IDs EMBEDDED in the message string**:
// `"Systems not found or not in your organization: <id1>, <id2>, ..."`.
// **NEW shape vs gate's literal 404** — the message embeds variable
// data (the comma-joined invalid UUIDs). The SDK documents but does
// NOT parse the embedded IDs (faithful courier — consumers can regex-
// match if they want the IDs).
//
// **400 surface on `get()`** — the kernel's `isValidUuid(id)` check
// at route.ts:36 returns false → `errorResponse("Invalid batch job
// ID format", 400)`. **First 400 on a non-XOR SDK route** —
// `complianceCheck.check`'s 400 fires when consumer provides BOTH
// `systemId` AND `orgName`; batch's 400 is a path-param format
// failure. The SDK pre-validates the UUID format synchronously (D7
// — same regex as `systemId` in `submit()`), so the kernel 400 is
// reachable only via `as any` casts or a kernel-side switch to a
// different UUID flavor.
//
// **TWO silent kernel-side truncations** (faithful courier;
// invariant candidate #50):
//   1. `orgSystems` row-population on `submit()` — `.limit(500)` at
//      route.ts:76. The kernel reads up to 500 systems from the
//      caller's org to verify each `systemIds[i]` belongs to the org.
//      If the org has >500 systems, the 501st+ are absent from
//      `systemMap`; a `systemIds[i]` referencing one of those would
//      surface as a 404 with the ID in the message (`"Systems not
//      found..."`) EVEN THOUGH the system exists and the consumer
//      owns it. **Documented as a kernel surface gap** — orgs with
//      >500 systems may see spurious 404s on batch submissions; the
//      SDK does NOT mask. Spec-diff drift pin anchors to
//      `.from(schema.aiSystems)[\s\S]*?.limit(500)`.
//   2. `batchJobs` row-population on `get()` — `.limit(1)` at
//      route.ts:49. Defensive only — the `where` clause already
//      narrows to one row by primary-key UUID. A kernel-side
//      schema change (e.g., a composite primary key or a soft-
//      deleted-rows union) is the only way `.limit(1)` becomes load-
//      bearing. Pin separately as belt-and-suspenders.
//
// **CLOSED ENUM on input `jobType`** — `BATCH_JOB_TYPES` is exported
// frozen so consumers can iterate (`for (const t of
// BATCH_JOB_TYPES)`) and the SDK pre-rejects unknown values
// (invariant #41). The 3 valid values are:
//   - `"classify"` — run the rule-based classifier on each system.
//   - `"assess"` — return each system's CURRENT risk classification
//     state (read-only; no classifier re-run).
//   - `"classify_and_assess"` — classify each system AND return the
//     fresh classification (the `"classify"` write-path + a richer
//     response). **Note**: despite the name, no separate "assess" run
//     happens; the kernel only branches between (a)
//     classify-then-emit and (b) emit-current-state. Verify against
//     `route.ts:108-149` if rebuilding the semantics from the wire.
// Drift-pin the enum string array against the kernel's `z.enum` in
// the spec-diff round.
//
// **TWO DISTINCT STATUS ENUMS on the response** (invariant candidate
// #56 — partial-success in inline-async jobs). The wire field
// `status` lives in TWO places with DIFFERENT closed enums:
//   - **Batch-job status** (top-level `response.status`): on POST,
//     `"completed" | "failed"` only (kernel-computed at handler end —
//     `failed === total ? "failed" : "completed"` at route.ts:170).
//     On GET, the WIDER `"pending" | "processing" | "completed" |
//     "failed"` enum (DB column straight pass-through). The closed
//     enum is STRICTLY WIDER on GET than POST — a GET on a job
//     submitted through THIS SDK never observes `"pending"`
//     (already-processed inline), but a GET on a job submitted via a
//     future async path (or by a non-SDK caller mid-flight) could.
//     Type contract is closed at each call site; runtime is open
//     (faithful courier — the P2 validator checks `typeof status ===
//     "string"` only, mirroring gate's `gate: "pass" | "fail"`
//     pattern).
//   - **Per-row result status** (`response.results[i].status`):
//     `"success" | "error"` only, in BOTH POST and GET responses.
//     Discriminator for `classifications` vs `errorMessage` — use
//     `row.status === "success"` (closed-enum string match), NOT
//     `row.errorMessage === undefined` (prototype-pollution-unsafe
//     under `Object.prototype.errorMessage` pollution; the equality
//     check walks the prototype and would return false even when the
//     own-property is genuinely absent).
// **Document the distinction prominently** — consumers reading
// `if (response.status === "completed")` are checking a different
// thing than `if (response.results[0].status === "success")`. Both
// drift-pinned in the spec-diff round.
//
// **`writeAuditLog` side effect on `submit()`** — every successful
// POST writes one `batch.submitted` audit log entry (route.ts:182-195;
// SAME pattern as `gate.evaluate` per invariant candidate #53). Use
// the session-17-corrected wording on the side effect's timing:
// **TIME-BLOCKING but error-tolerant** — the kernel uses `await
// writeAuditLog(...)` which awaits two DB ops inside the function
// (SELECT previous-hash + INSERT new entry, at
// `src/lib/api.ts:130-159`). The submit-call response latency
// INCLUDES the audit-log write time. Error semantics ARE
// non-blocking: `writeAuditLog` wraps its body in a try/catch that
// swallows errors and logs them, so a write FAILURE does NOT fail
// the batch submission. Audit log writes are NOT counted against
// `decisionsPerMonth` quota. **`get()` does NOT write an audit log**
// — status reads are quiet.
//
// **Symmetric prototype-pollution defense** (carry-forward of
// session-16 second-hostile-review MEDIUM #3 + session-17 build-
// round baked-in pattern) — module-load snapshot of `Object.hasOwn`
// applied to BOTH input AND response sides on BOTH methods. Without
// the response-side defense, a kernel regression that drops a
// response field combined with a hostile npm dep polluting
// `Object.prototype.<field>` would let the polluted value pass
// typeof-check via prototype walk. With the defense, missing own-
// property → describeType(undefined) → AttestryError. See build-
// round audit doc D7.
//
// **NO URIError defense on body / path** — `submit()` body uses
// `JSON.stringify`, which handles lone UTF-16 surrogates by emitting
// them as literal `\uDxxx` escapes (per JSON spec); the URIError
// defect class (invariant #32) applies only to query-string paths
// (`encodeURIComponent`). `get()`'s path segment is a UUID — the
// SDK pre-validates the format before constructing the URL, so a
// lone-surrogate or non-hex `id` is rejected synchronously
// (TypeError) before reaching `encodeURIComponent`. The kernel-side
// `isValidUuid` would also reject in the 400 fallback path if the
// SDK's pre-validation were ever bypassed (`as any`).
//
// Sync JSON request/response on BOTH methods: reuses
// `client._request` and the existing `{success:true, data}`
// envelope-unwrap (carry-forward invariant #9). NO new SDK
// primitive needed. Returns `Promise<BatchSubmitResponse>` /
// `Promise<BatchJobStatus>`.

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

// Module-load snapshot of `Object.hasOwn` — defends against a
// late-loading hostile/buggy npm dependency that overrides the global
// (e.g., `Object.hasOwn = () => true`). Without the snapshot, the
// prototype-pollution defenses below would use whatever Object.hasOwn
// the dependency replaced it with at request time. Snapshotting at
// module load captures the original implementation BEFORE most
// consumer code has a chance to monkey-patch.
//
// Caveat: this is partial. If the hostile dependency is imported
// BEFORE @attestry/sdk in the consumer's load graph, the snapshot
// captures the bad version. Consumers ordering imports
// SDK-then-untrusted-deps benefit; the reverse ordering does not.
// Combined with `Object.hasOwn` itself being immune to
// `obj.hasOwnProperty = ...` overrides (per MDN), this gives a
// layered defense.
//
// Mirror of `gate.evaluate` / `check.run` / `complianceCheck.check`'s
// pattern. Used symmetrically on input AND response sides (session-16
// second-hostile-review MEDIUM #3 carry-forward — defense on both
// boundaries).
const objectHasOwn = Object.hasOwn;

// UUID format regex — RFC 4122 hyphenated form (8-4-4-4-12 hex,
// case-insensitive). Matches Zod's `z.string().uuid()` regex
// effectively. Mirror of `gate.evaluate` / `check.run`'s UUID_REGEX.
// Drift-pinned in `sdk-drift.test.ts` spec-diff round so a kernel-
// side switch to a different UUID flavor (ULID, KSUID, etc.) fires
// before consumer regressions.
const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Closed enum for `BatchSubmitInput.jobType`. Mirrors the kernel's
 * `batchSubmitSchema.jobType` at `src/app/api/v1/batch/route.ts:30`:
 * `z.enum(["classify", "assess", "classify_and_assess"])`.
 *
 * Frozen at module load to prevent runtime mutation by hostile /
 * buggy dependencies (P1 hardening — mirrors the freeze on
 * `AUDIT_LOG_EXPORT_FORMATS` / `CHAT_MESSAGE_ROLES` etc.). Iterating
 * `for (const t of BATCH_JOB_TYPES)` lists the 3 valid values; the
 * SDK's `submit()` pre-rejects any unknown string with `TypeError`
 * (invariant #41 — closed-enum SDK pre-rejection-eligible surface).
 *
 * Drift-pinned in `sdk-drift.test.ts` spec-diff round against the
 * kernel's Zod enum to catch a kernel-side widening (e.g., adding
 * `"generate_docs"` — the stale db/schema.ts:1030 comment mentions
 * this value but the route's Zod schema does NOT include it; the
 * comment is stale, the Zod is authoritative).
 *
 * **Semantics of each value**:
 *   - `"classify"` — run the rule-based classifier on each system
 *     and PERSIST the new `riskClassifications` to the system row
 *     (write-side effect). Per-row `classifications` contains the
 *     fresh classification.
 *   - `"assess"` — emit each system's CURRENT `riskClassifications`
 *     state from the DB (read-only; no write side effect, despite
 *     `WRITE_ASSESSMENTS` being a valid auth permission). Per-row
 *     `classifications` contains whatever was already on the row
 *     (may be `null` if no prior classification).
 *   - `"classify_and_assess"` — same as `"classify"` (the kernel
 *     branches `classify || classify_and_assess` together at
 *     route.ts:112). The two-name distinction is purely semantic
 *     for the consumer — both write the new classification and
 *     emit it.
 */
export const BATCH_JOB_TYPES = Object.freeze([
  "classify",
  "assess",
  "classify_and_assess",
] as const);

export type BatchJobType = (typeof BATCH_JOB_TYPES)[number];

/**
 * Closed enum for `BatchJobStatus.status` (the GET response's wider
 * batch-job-level status). Mirrors the kernel's
 * `schema.batchJobs.status` DB column comment at
 * `src/lib/db/schema.ts:1031`: `'pending' | 'processing' | 'completed' |
 * 'failed'`.
 *
 * **Wider than the POST response's `status`** — `submit()` returns
 * `status: "completed" | "failed"` only (computed at handler end from
 * `failed === total`). A `get()` call against a job submitted by the
 * SDK observes only `"completed" | "failed"` in practice (the job
 * processed inline before the row was committed), but a `get()`
 * against a job submitted via a future async path OR an out-of-band
 * caller mid-flight could observe `"pending"` / `"processing"`.
 *
 * Frozen at module load (P1 hardening — same rationale as
 * `BATCH_JOB_TYPES`). Iterating `for (const s of BATCH_JOB_STATUSES)`
 * lists all 4 values. **The DB column has no kernel-side enum
 * constraint** — the SDK exposes the closed union at the type level
 * but the runtime validator checks `typeof status === "string"` only
 * (faithful courier — same asymmetry as gate's `gate: "pass" |
 * "fail"` pattern).
 *
 * Drift-pinned in the spec-diff round (sdk-drift.test.ts —
 * "BATCH_JOB_STATUSES in SDK matches the kernel db/schema.ts
 * comment + .default() literal") via TWO assertions inside the
 * same `it()`:
 *   - **Assertion 1**: the schema's `.default("pending")` literal
 *     at `src/lib/db/schema.ts:1031` (machine-checkable). Fires
 *     on a default-change (e.g., from `"pending"` to `"queued"`).
 *   - **Assertion 2**: the schema column COMMENT listing all 4
 *     values (documentation source-of-truth). Fires on a
 *     widening (e.g., a new `"cancelled"` status added to the
 *     comment) OR a comment removal.
 * The pin's failure message distinguishes which assertion fires.
 */
export const BATCH_JOB_STATUSES = Object.freeze([
  "pending",
  "processing",
  "completed",
  "failed",
] as const);

export type BatchJobStatusValue = (typeof BATCH_JOB_STATUSES)[number];

/**
 * One per-system result row in `BatchSubmitResponse.results` /
 * `BatchJobStatus.results`. Source-of-truth at kernel
 * `src/app/api/v1/batch/route.ts:42-48` (`BatchSystemResult`
 * interface).
 *
 * **Discriminator pattern**: branch on `status: "success" | "error"`
 * (closed-enum string match). The kernel guarantees `classifications`
 * is present on `"success"` rows and `errorMessage` is present on
 * `"error"` rows — but **do NOT use `row.errorMessage === undefined`
 * or `row.classifications === undefined` as the discriminator**.
 * Under `Object.prototype.errorMessage = <value>` pollution, the
 * `=== undefined` equality walks the prototype and reads the polluted
 * value — returning false even when the own-property is genuinely
 * absent, silently misclassifying an `"error"` row as `"success"`.
 * The `status` field is the pollution-safe discriminator (the SDK's
 * own-property check would reject a missing `status` field anyway).
 *
 * **`classifications` is `unknown`** because the kernel emits the
 * full `classifySystem()` output OR the system's
 * `riskClassifications` jsonb cell — both open-spec objects whose
 * exact shape lives in `src/lib/classification.ts`. Consumers
 * casting to a specific shape should align with that module.
 *
 * **`errorMessage` is `string`** — the kernel scrubs at
 * route.ts:153-157 in this order: (1) take first line via
 * `.split("\n")[0]`, (2) **TRUNCATE** to 500 chars via
 * `.slice(0, 500)`, THEN (3) **REDACT** matches of:
 *   - alternation `(?:password|secret|token|key)` (literal,
 *     case-insensitive),
 *   - followed by `=`,
 *   - followed by **zero-or-more** characters that are NOT
 *     whitespace and NOT `&` (so `password=` with empty value
 *     IS matched; the actual kernel regex flags are `g` + `i`).
 *
 * **Order matters**: truncation happens BEFORE redaction, so a
 * credential straddling the 500-char boundary may be partially
 * sliced (the regex's zero-or-more arm matches the truncated
 * prefix, redacting whatever survived the slice — but the
 * sliced-off suffix is gone before redaction; whatever made it
 * past the slice gets redacted to `[REDACTED]`). The regex only
 * catches `<keyword>=<value>` shapes — Bearer tokens,
 * JSON-quoted secrets like `"token":"abc"`, or other formats
 * are NOT scrubbed. The SDK does NOT add a second scrubbing
 * pass — faithful courier.
 *
 * Note: per-row shape is NOT P2-validated by the SDK (`Array.isArray`
 * only on the `results` array — same faithful-courier pattern as
 * `gate.evaluate`'s `gaps: GateGap[]`). The kernel emits well-formed
 * rows reliably; consumers who paranoid-validate should do so post-
 * hoc.
 */
export interface BatchSystemResult {
  /**
   * UUID of the system this row describes. Always echoes the
   * corresponding entry in `BatchSubmitInput.systemIds`.
   */
  systemId: string;
  /**
   * Human-readable system name from `schema.aiSystems.name`. The
   * kernel uses `systemMap.get(systemId)?.name ?? "Unknown"` at
   * route.ts:161 — a defensive fallback that is **dead code today**.
   * Verified: (a) the prior membership check at route.ts:79-85
   * guarantees every `systemId` is present in `systemMap`, so
   * `systemMap.get(...)?.name` cannot return undefined via the `?.`
   * arm; (b) `schema.aiSystems.name` is `text("name").notNull()` at
   * `src/lib/db/schema.ts:156` — the column cannot be null, so the
   * `?? "Unknown"` arm cannot fire either. Both arms are unreachable
   * under the current schema; the fallback exists for defense-in-
   * depth if a future migration relaxes the `notNull()` constraint.
   * The SDK passes the literal string `"Unknown"` through faithfully
   * in that hypothetical future.
   */
  systemName: string;
  /**
   * Closed enum — discriminator for `classifications` vs
   * `errorMessage`. Use `row.status === "success"` (closed-enum
   * string match) to branch — NOT `row.errorMessage === undefined`
   * (prototype-pollution-unsafe).
   */
  status: "success" | "error";
  /**
   * Present only when `status === "success"`. The system's
   * classification output (the kernel's `classifySystem()` result
   * for `"classify"` / `"classify_and_assess"` job types, OR the
   * system's CURRENT `riskClassifications` for the `"assess"` job
   * type). Open-spec — typed `unknown` because the underlying
   * `classifySystem` return shape lives outside the kernel route
   * (`src/lib/classification.ts`).
   */
  classifications?: unknown;
  /**
   * Present only when `status === "error"`. Human-readable error
   * message. **Kernel-scrubbed** at `route.ts:153-157` in this
   * order: (1) first line only via `.split("\n")[0]`, (2)
   * **TRUNCATE** to 500 chars via `.slice(0, 500)`, then (3)
   * **REDACT** matches of `(?:password|secret|token|key)`
   * followed by `=` followed by **zero-or-more** characters
   * that are NOT whitespace and NOT `&` (case-insensitive,
   * global). **`password=` with empty value IS matched and
   * redacted**; the regex's quantifier is zero-or-more, not
   * one-or-more. **Order matters**: truncation BEFORE redaction
   * means a credential straddling the 500-char boundary is
   * sliced before the regex sees it — whatever survived the
   * slice gets redacted; whatever was sliced off is gone. The
   * regex only catches `<keyword>=<value>` shapes — Bearer
   * tokens, JSON-quoted secrets (`"token":"abc"`), or other
   * formats are NOT scrubbed. The SDK does NOT add a second
   * scrubbing pass — faithful courier.
   */
  errorMessage?: string;
}

/**
 * Optional config object on `BatchSubmitInput.config`. Mirrors the
 * kernel's `batchSubmitSchema.config` at
 * `src/app/api/v1/batch/route.ts:35-39` — a single-field wrapper
 * around `frameworks?`. The wrapper (rather than top-level fields)
 * matches the kernel wire literal `{config: {frameworks}}` and
 * leaves room for future top-level additions without breaking the
 * surface.
 *
 * Round-tripped on `get()` (the kernel persists `config` to the
 * `batch_jobs.config` jsonb column and emits it back on GET — see
 * `BatchJobStatus.config`).
 *
 * **`config.frameworks` carry-forward from gate / check exactly** —
 * array length ≤20 + per-element string length [1, 100]. The kernel
 * does NOT pin `frameworks` to a closed enum of values; any string
 * within the length bounds is accepted. Today the kernel does NOT
 * use `config.frameworks` in the inline classification path
 * (`classifySystem` doesn't take a frameworks filter) — the field is
 * persisted for forward-compat with future job types but has NO
 * visible effect on the current `classify` / `assess` paths.
 * Documented as a kernel surface gap; consumers passing
 * `config.frameworks` today get round-trip-only behavior.
 */
export interface BatchConfig {
  /**
   * Optional array of framework identifiers. Up to 20 entries; each
   * string of length 1-100. Round-tripped to `BatchJobStatus.config
   * .frameworks` on `get()`; no visible effect on the current
   * inline classification paths.
   */
  frameworks?: string[];
}

/**
 * Input shape for `batch.submit()`. Source-of-truth at kernel
 * `src/app/api/v1/batch/route.ts:29-40` (`batchSubmitSchema`).
 *
 * **`jobType`** — REQUIRED, closed enum of 3 strings (`BatchJobType`).
 * The SDK pre-validates membership in `BATCH_JOB_TYPES`
 * synchronously (invariant #41 — closed-enum SDK pre-rejection-
 * eligible). `TypeError` for an unknown value lists the valid set.
 *
 * **`systemIds`** — REQUIRED array of 1-50 UUIDs. The SDK pre-
 * validates: `Array.isArray`, length [1, 50] inclusive, each
 * element a non-empty string matching the RFC 4122 UUID regex (D4
 * — SDK pre-validates closed-spec rule per invariant #49). Snapshot
 * via `Array.from` up front for TOCTOU defense (a Proxy whose
 * `.length` or `[i]` changes between reads can't slip past
 * validation). **The `.min(1)` is new** — gate/check's `frameworks`
 * allowed empty arrays via `.optional().max(20)`; batch's
 * `systemIds` rejects empty at the Zod level, so the SDK also
 * pre-rejects empty.
 *
 * **`config`** — OPTIONAL. When provided, must be a non-null
 * non-array object. `config.frameworks` (when provided) is an
 * array of 1-100-char strings, length ≤20 (carry-forward from
 * gate / check). Today the kernel persists `config` to the row but
 * does NOT use it in the inline classification path — the field is
 * forward-compat. Documented as a kernel surface gap; consumers get
 * round-trip-only behavior.
 *
 * **No defaults** — `batchSubmitSchema` has NO `.default()` clauses
 * (carry-forward invariant #52 N/A here, asymmetric with gate's two
 * defaults). All fields without explicit values are simply absent
 * from the body when the consumer omits them.
 */
export interface BatchSubmitInput {
  /**
   * Closed enum: `"classify"` | `"assess"` | `"classify_and_assess"`.
   * See `BATCH_JOB_TYPES` for semantics.
   */
  jobType: BatchJobType;
  /**
   * 1-50 UUIDs (RFC 4122 hyphenated form, case-insensitive). The
   * `.min(1)` is enforced kernel-side AND SDK-side (empty arrays
   * rejected synchronously).
   */
  systemIds: string[];
  /**
   * Optional. Round-tripped to `BatchJobStatus.config` on `get()`;
   * no visible effect on the current inline classification paths.
   */
  config?: BatchConfig;
}

/**
 * Response shape returned by `batch.submit()`. 10 fields, ALL always
 * present (no emit-only optionality — distinct from `gate.evaluate`).
 *
 * Source-of-truth at kernel `src/app/api/v1/batch/route.ts:197-208`
 * (the `successResponse({...})` literal).
 *
 * **`status: "completed" | "failed"`** — kernel-computed at handler
 * end (route.ts:170): `failed === body.systemIds.length ? "failed" :
 * "completed"`. **STRICTLY NARROWER than `BatchJobStatus.status`**
 * (the GET response uses the wider 4-value enum). A POST-submitted
 * job is always fully-processed by the time the response is built,
 * so `"pending"` / `"processing"` are never observed on this method.
 * **Two distinct status enums on the same wire-shape family** —
 * invariant candidate #56. Type contract is closed at the call site;
 * runtime is open (faithful courier — P2 validator checks `typeof
 * === "string"` only).
 *
 * **`results: BatchSystemResult[]`** — partial-success envelope.
 * Each row describes one system's outcome with
 * `status: "success" | "error"` plus either `classifications` or
 * `errorMessage`. The call resolves successfully (no throw) even
 * when every row failed — top-level failures (auth, rate limit, plan
 * limit, Zod rejection, cross-org systemId, internal) DO throw
 * `AttestryAPIError`. Mirror of `decisions.bulk`'s contract — the
 * canonical SDK partial-success pattern.
 *
 * **`startedAt: string | null`** — the kernel sets `startedAt: new
 * Date()` at insert time (route.ts:99) so in practice this is
 * always a non-null ISO-8601 string. The `?? null` fallback at
 * route.ts:206 is defensive against a schema migration making the
 * column nullable; the SDK's wire-shape type follows the defensive
 * shape (`string | null`).
 *
 * **`completedAt: string`** — ALWAYS a string in the POST response
 * (route.ts:207 emits `new Date().toISOString()` unconditionally).
 * Asymmetric with `BatchJobStatus.completedAt` which is nullable
 * (DB column allows null for non-completed jobs).
 */
export interface BatchSubmitResponse {
  /** UUID of the newly-created batch job row. */
  id: string;
  /**
   * Echoes the input — one of the 3 `BatchJobType` values. Open at
   * runtime (P2 validates `typeof === "string"` only).
   */
  jobType: BatchJobType;
  /**
   * **Batch-job-level** status — closed to `"completed" | "failed"`
   * on POST (kernel-computed). Open at runtime (P2 validates
   * `typeof === "string"` only). Distinct from
   * `results[i].status` (per-row `"success" | "error"`).
   */
  status: "completed" | "failed";
  /** Echoes `systemIds.length` from the input (1-50). */
  totalSystems: number;
  /**
   * Count of rows whose `status === "success"`. May be less than
   * `totalSystems` when some systems failed; the call still
   * resolves successfully.
   */
  processedSystems: number;
  /**
   * Count of rows whose `status === "error"`. Equals
   * `totalSystems - processedSystems`. Both counts are kernel-
   * authoritative (NOT derived client-side).
   */
  failedSystems: number;
  /**
   * One entry per input `systemIds[i]`, in input order. Always
   * present, always an array (the kernel processes every input row
   * inline before emitting the response).
   */
  results: BatchSystemResult[];
  /** ISO-8601, from the row's `createdAt` column. */
  createdAt: string;
  /**
   * ISO-8601 OR null. In practice always a string on POST (the
   * kernel sets `startedAt: new Date()` at insert time); the null
   * fallback is defensive against future schema changes.
   */
  startedAt: string | null;
  /**
   * ISO-8601 — ALWAYS present on POST (kernel emits
   * `new Date().toISOString()` unconditionally at route.ts:207).
   * Asymmetric with `BatchJobStatus.completedAt` which is nullable.
   */
  completedAt: string;
}

/**
 * Response shape returned by `batch.get(id)`. 11 fields — includes
 * `config` (POST omits config from its response because it's already
 * in the request body, but GET re-emits for callers who didn't
 * submit and want the full picture).
 *
 * Source-of-truth at kernel `src/app/api/v1/batch/[id]/route.ts:57-69`.
 *
 * **`status: BatchJobStatusValue`** — the WIDER 4-value enum
 * (`"pending" | "processing" | "completed" | "failed"`). DB column
 * pass-through; the runtime value MAY observe any of the four for
 * non-SDK-submitted jobs. Type contract is closed at the call site;
 * runtime is open (faithful courier).
 *
 * **`results: BatchSystemResult[] | null`** — nullable on GET (DB
 * jsonb column allows null for `"pending"` jobs that haven't been
 * processed yet). SDK-submitted jobs always have non-null `results`
 * by the time their row is committed.
 *
 * **`config: BatchConfig | null`** — round-trips whatever was
 * submitted (`null` when consumer omitted `config`, or the
 * submitted shape when provided). Per-field shape is open-spec
 * (faithful courier — P2 validates `config === null` OR
 * `typeof === "object"` only).
 *
 * **`startedAt: string | null`** + **`completedAt: string | null`**
 * — both nullable on GET. `"pending"` jobs have both null;
 * `"processing"` has startedAt set but completedAt null;
 * `"completed"` / `"failed"` have both set.
 */
export interface BatchJobStatus {
  /** UUID of the batch job (echoes the `id` arg passed to `get()`). */
  id: string;
  /**
   * One of the 3 `BatchJobType` values. Open at runtime (P2
   * validates `typeof === "string"` only). DB column has no closed-
   * enum constraint, but rows can only reach the table via POST
   * which Zod-validates.
   */
  jobType: BatchJobType;
  /**
   * **Batch-job-level** status — closed to the 4-value
   * `BatchJobStatusValue` enum on GET (DB column pass-through).
   * Open at runtime (P2 validates `typeof === "string"` only).
   * Distinct from `results[i].status` (per-row `"success" |
   * "error"`).
   */
  status: BatchJobStatusValue;
  /** Echoes the original input `systemIds.length`. */
  totalSystems: number;
  /** Count of rows whose `status === "success"`. */
  processedSystems: number;
  /** Count of rows whose `status === "error"`. */
  failedSystems: number;
  /**
   * Array of per-system results OR `null`. **Nullable on GET** —
   * `"pending"` jobs have not yet been processed and their
   * `results` column is null. SDK-submitted jobs always have
   * non-null `results` by the time the row is committed.
   */
  results: BatchSystemResult[] | null;
  /**
   * The config object the submission used, OR `null`. **Three
   * distinct round-trip cases**:
   *   - `null` when the caller OMITTED `config` from the submit
   *     body (kernel writes `body.config ?? null` to the column —
   *     omission becomes literal `null`).
   *   - `{}` (empty object) when the caller passed an explicit
   *     empty `config: {}` — kernel writes the empty object
   *     verbatim.
   *   - `{frameworks: [...]}` (or any other valid shape) when the
   *     caller passed an explicit config.
   * **You CANNOT distinguish "consumer omitted" from "kernel wrote
   * null" via this field on GET** — both surface as `null`. To
   * detect explicit-empty-object, check `config !== null` after a
   * known submission. Round-trip only — the kernel does NOT use
   * `config.frameworks` in the current inline classification path.
   */
  config: BatchConfig | null;
  /** ISO-8601, from the row's `createdAt` column. */
  createdAt: string;
  /**
   * ISO-8601 OR null. `"pending"` jobs have null; jobs that have
   * been picked up by an inline or async worker have it set.
   */
  startedAt: string | null;
  /**
   * ISO-8601 OR null. `"pending"` and `"processing"` jobs have
   * null; `"completed"` / `"failed"` have it set.
   */
  completedAt: string | null;
}

/**
 * `batch` resource — sibling to `IncidentsResource`,
 * `DecisionsResource`, `ChatResource`, `AuditLogResource`,
 * `RegulatoryChangesResource`, `ComplianceCheckResource`,
 * `CheckResource`, `GateResource`.
 *
 * Multi-method resource (mirror of `ChatResource`'s `send` +
 * `stream`). Wraps TWO kernel routes:
 *   - `POST /api/v1/batch` via `submit(input, options?)`
 *   - `GET  /api/v1/batch/<UUID>` via `get(id, options?)`
 *
 * **First SDK resource with asymmetric auth between methods on the
 * same resource** (invariant candidate #54). `submit()` requires a
 * key with `CLASSIFY` or `WRITE_ASSESSMENTS` AND enterprise plan;
 * `get()` requires only `READ_ASSESSMENTS`. See per-method JSDoc.
 */
export class BatchResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Submit a batch job — classify and/or read the current
   * classification state for 1-50 systems in one call. Returns a
   * `BatchSubmitResponse` with a per-row `results` envelope
   * describing each system's outcome.
   *
   * **Partial-success contract**: the call resolves successfully
   * (no throw) even when every row failed. Inspect
   * `response.failedSystems` (or iterate `response.results` filtering
   * `row.status === "error"`) to detect per-row errors. Top-level
   * failures (auth, plan, rate limit, Zod, cross-org systemId,
   * internal) DO throw `AttestryAPIError`. Mirror of
   * `decisions.bulk`'s contract.
   *
   * **Multi-permission UNION auth scope (WRITE-side)**: kernel uses
   * `requireApiKeyWithPermission(req, CLASSIFY, WRITE_ASSESSMENTS)`
   * — OR semantics (`Array.some()` at `permissions.ts:53-55`).
   * **First SDK route to use a WRITE-side union pair** (every prior
   * SDK union has been READ-side). A key with EITHER permission
   * (or `ADMIN`, or null/empty permissions for backwards-compat)
   * succeeds. **HTTP 401** for no/invalid API key; **HTTP 403** for
   * an authenticated key that has NEITHER required permission. Pin
   * BOTH branches separately. Invariant #45 / #54.
   *
   * **NEW plan-guard 403 surface** (invariant candidate #55).
   * **BEFORE Zod body parsing**, the kernel calls
   * `requirePlan(org, "hasBatchProcessing")` at route.ts:67. A
   * free-tier (or trial-expired non-enterprise) org hits the plan
   * gate FIRST, regardless of body validity or systemIds. The
   * kernel emits `PlanLimitError` which the route catches at line
   * 216 and surfaces as **403** with a literal message of the form
   * `'The "hasBatchProcessing" feature is not available on your
   * current plan (<plan>). Please upgrade to access this feature.'`
   * Distinct from the permission-403 message
   * `'API key lacks required permission. Required: ... Key has: ...'`
   * — consumers regex-match the message contents if they need to
   * distinguish "upgrade your plan" from "grant more permissions to
   * your key". Both surface uniformly as `AttestryAPIError(403)`
   * (no SDK-side discriminator helper today).
   *
   * **Asymmetric cross-org / not-found error code (404 with
   * EMBEDDED IDs)**: the kernel verifies every requested system
   * belongs to the caller's org and collapses cross-org OR missing
   * to 404. **NEW shape vs gate's literal 404** — the message
   * embeds the comma-joined invalid UUIDs:
   * `'Systems not found or not in your organization: <id1>, <id2>, ...'`.
   * The SDK does NOT parse the embedded IDs — faithful courier;
   * consumers can regex-match if they want to surface specific IDs
   * to users.
   *
   * **TWO silent kernel-side truncations** (invariant candidate
   * #50):
   *   1. `orgSystems` row-population — `.limit(500)` at route.ts:76.
   *      The kernel reads up to 500 systems from the caller's org
   *      to verify membership. Orgs with >500 systems may see
   *      spurious 404s on batch submissions referencing systems
   *      outside the first 500 rows. **Documented kernel surface
   *      gap**; the SDK does NOT mask. Pin anchored to
   *      `.from(schema.aiSystems)[\s\S]*?.limit(500)` in the spec-
   *      diff round.
   *   2. (GET-side `.limit(1)` is documented under `get()` below.)
   *
   * **`writeAuditLog` side effect** — every successful `submit()`
   * call writes one `batch.submitted` entry to the org's audit log
   * (route.ts:182-195). Properties of the write:
   *   - Org-scoped, hash-chained (per `writeAuditLog` at
   *     `src/lib/api.ts:125-`).
   *   - **Time-blocking** but error-tolerant: the kernel uses
   *     `await writeAuditLog(...)`, which awaits two DB ops (SELECT
   *     previous-hash + INSERT new entry). The submit-call response
   *     latency INCLUDES the audit-log write time. Error semantics
   *     ARE non-blocking: `writeAuditLog` wraps its body in a
   *     try/catch that swallows errors and logs them, so a write
   *     FAILURE does NOT fail the submit request.
   *   - NOT counted against `decisionsPerMonth` quota.
   *
   * **Closed-enum input `jobType`** — pre-rejected SDK-side if not
   * one of `BATCH_JOB_TYPES`. Use `BATCH_JOB_TYPES` to iterate or
   * narrow at call sites.
   *
   * **Per-row discriminator** — use `row.status === "success"` (NOT
   * `row.errorMessage === undefined`, which is prototype-pollution
   * unsafe). See `BatchSystemResult` JSDoc for the full rationale.
   *
   * Errors — ordered by kernel firing precedence (rate-limit →
   * auth → org-load (404 if missing) → plan-guard → Zod body
   * validation → DB membership check → inline processing →
   * internal). A request with multiple problems surfaces ONLY the
   * highest-precedence one. For example: a request with bad auth
   * AND a free-tier org surfaces 401, not 403 (plan-guard fires
   * AFTER auth). A request whose org row was deleted between key
   * issuance and request time surfaces a 404 BEFORE the plan-
   * guard 403 fires (rare in practice). A request with valid auth
   * + valid org + free-tier + a malformed body surfaces 403
   * (plan-guard fires BEFORE Zod body validation).
   *
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     (auto-retried by default — invariant #18; per-IP rate-limit
   *     key `v1-batch:${ip}`; tighter limiter than apiLimiter —
   *     `assessmentLimiter` at 30 req/min vs apiLimiter's 60).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *   - `AttestryAPIError` (status 403, permission branch) — key
   *     has NEITHER `CLASSIFY` nor `WRITE_ASSESSMENTS`.
   *   - `AttestryAPIError` (status 404, org-not-found branch) — the
   *     caller's org row was deleted (route.ts:66: `if (!org)
   *     return errorResponse("Organization not found", 404)`).
   *     **Distinct from the systems-not-found 404 below** — same
   *     status code, different message. Rare in practice (orgs
   *     aren't deleted while keys are active).
   *   - `AttestryAPIError` (status 403, plan-gate branch) — the
   *     org's effective plan doesn't have `hasBatchProcessing`.
   *     Distinct wording from the permission-403 (above) — consumers
   *     regex-match to distinguish.
   *   - `AttestryAPIError` (status 422) — Zod schema rejection
   *     (kernel's `BodyParseError` surface — `parseBody(request,
   *     batchSubmitSchema)` failed). `apiErr.details` carries the
   *     full kernel error body verbatim (the transport does NOT
   *     strip the `{success:false, ...}` envelope on error
   *     responses — only the `{success:true, data}` envelope on
   *     success). The wire shape is: `{success: false, error:
   *     "Validation failed.", details: Array<{path: string;
   *     message: string}>}` — `error` is the literal string
   *     "Validation failed." (with trailing period), `details` is
   *     an array (NOT a keyed map) of `{path, message}` pairs
   *     derived from Zod's `result.error.errors`. Consumers reading
   *     field-by-field errors should iterate `apiErr.details.details`
   *     (the kernel's `details` array nested under the SDK's parsed-
   *     body wrapper). **The SDK pre-validates all closed-spec
   *     rules** (jobType enum membership, systemIds array length
   *     [1, 50] + per-element UUID format, frameworks array length
   *     ≤20 + per-element string length [1, 100]) AND the runtime
   *     checks always run regardless of TypeScript types — `as any`
   *     casts do NOT bypass them. So 422 reaches consumers ONLY
   *     via kernel rule changes the SDK hasn't synced to. Invariant
   *     #51.
   *   - `AttestryAPIError` (status 404, systems-not-found branch) —
   *     one or more `systemIds[i]` are not in the caller's org (or
   *     don't exist). The kernel collapses cross-org and genuine-
   *     missing to 404 with the literal message
   *     `"Systems not found or not in your organization: <id1>, <id2>, ..."`.
   *     **Embedded IDs** — the SDK does NOT parse the offending UUIDs
   *     out of the message; consumers can regex-match if needed.
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`).
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired (pre-aborted or mid-flight).
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (not an object, wrong type on
   *     any of the 10 response fields).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard before body
   *     parsing).
   *   - `TypeError` — input failed SDK-side validation (null /
   *     array / non-object input, missing jobType, unknown
   *     jobType, missing systemIds, non-array systemIds, empty
   *     systemIds, oversize systemIds, non-string systemIds
   *     element, non-UUID systemIds element, non-object config,
   *     non-array config.frameworks, oversize config.frameworks,
   *     non-string config.frameworks element, oversize/empty
   *     config.frameworks element). **THROWN SYNCHRONOUSLY** (no
   *     fetch issued; the function does NOT return a promise in
   *     this case). Distinct from `AttestryAPIError` /
   *     `AttestryError` above, which reject through the returned
   *     promise. Consumers using `await client.batch.submit(...)`
   *     see both surfaces uniformly; consumers wrapping the call
   *     in a non-awaiting context (e.g., `client.batch.submit(...)
   *     .then(...)`) must catch the synchronous throw with a
   *     surrounding try/catch — the `.then()` chain alone does
   *     NOT catch synchronous TypeErrors.
   *
   * **Notably ABSENT**:
   *   - **No 400** on POST — all input validation is Zod (422).
   *     The GET method DOES have a 400 (malformed `id` path
   *     parameter).
   *   - **No 413** — body size limit not explicit.
   *   - **No 402** — read-shaped from a quota perspective (despite
   *     writing per-system classifications, doesn't count against
   *     `decisionsPerMonth`).
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch
   * issued):
   *   - `input` itself: required; must be a non-null, non-array
   *     object.
   *   - `input.jobType`: required own-property; must be a string;
   *     must be one of `BATCH_JOB_TYPES`.
   *   - `input.systemIds`: required own-property; must be an Array;
   *     length [1, 50] inclusive; each element a non-empty string
   *     matching `UUID_REGEX`. Snapshot via `Array.from` for TOCTOU
   *     defense.
   *   - `input.config` (when own-property present, value not
   *     undefined): must be a non-null non-array object.
   *   - `input.config.frameworks` (when own-property present, value
   *     not undefined): must be an array of ≤20 strings, each of
   *     length 1-100. Snapshot via `Array.from` for TOCTOU defense.
   *
   * **Response-shape validation** (P2 hardening — symmetric defense
   * on response side, mirror of session-16 second-hostile-review
   * MEDIUM #3 carry-forward):
   *   - Rejects with `AttestryError` if the kernel response isn't a
   *     non-null, non-array object.
   *   - Rejects if `id` / `jobType` / `status` / `createdAt` /
   *     `completedAt` aren't strings.
   *   - Rejects if `startedAt` isn't a string or null.
   *   - Rejects if `totalSystems` / `processedSystems` /
   *     `failedSystems` aren't numbers.
   *   - Rejects if `results` isn't an array.
   *   - Per-row shape (open-spec — `BatchSystemResult`) is faithful-
   *     courier — NOT validated.
   *   - Each response field read goes through the module-load
   *     `objectHasOwn` snapshot (symmetric to input-side defense).
   *
   * **Transport-shape validation** (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with
   *     a non-`application/json` Content-Type.
   *
   * @example Submit a classify job for 3 systems
   * ```ts
   * const result = await client.batch.submit({
   *   jobType: "classify",
   *   systemIds: [
   *     "11111111-1111-1111-1111-111111111111",
   *     "22222222-2222-2222-2222-222222222222",
   *     "33333333-3333-3333-3333-333333333333",
   *   ],
   * });
   * console.log(`Processed ${result.processedSystems}/${result.totalSystems}`);
   * for (const row of result.results) {
   *   if (row.status === "success") {
   *     console.log(`OK ${row.systemId}:`, row.classifications);
   *   } else {
   *     // CRITICAL: branch on `row.status === "error"` — NOT
   *     // `row.errorMessage === undefined` (prototype-pollution
   *     // unsafe).
   *     console.error(`FAIL ${row.systemId}: ${row.errorMessage}`);
   *   }
   * }
   * ```
   *
   * @example Submit with framework filter (round-trip only today)
   * ```ts
   * const job = await client.batch.submit({
   *   jobType: "classify_and_assess",
   *   systemIds: ["11111111-1111-1111-1111-111111111111"],
   *   config: { frameworks: ["EU_AI_ACT", "ISO_42001"] },
   * });
   * // config.frameworks is persisted on the row but has no effect on
   * // the current inline classification path.
   * ```
   */
  submit(
    input: BatchSubmitInput,
    options?: RequestOptions,
  ): Promise<BatchSubmitResponse> {
    // Top-level shape — input is REQUIRED. typeof null === "object"
    // and typeof [] === "object", so guard both explicitly.
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "batch.submit: `input` must be a non-null object with `jobType` + `systemIds`",
      );
    }

    // Snapshot each field's value EXACTLY ONCE up front via the
    // own-property indexer. Three motivations (same as gate.evaluate):
    //   1. Prototype-pollution defense (generalization of #48).
    //      Pollution of `Object.prototype.<field>` does NOT trick
    //      the SDK into silently sending the polluted value when
    //      the user passes an object without that own property.
    //      Uses the module-load `objectHasOwn` snapshot so a late-
    //      loading dep overriding `Object.hasOwn` doesn't defeat
    //      the defense.
    //   2. TOCTOU defense: a Proxy or getter-defining input could
    //      yield DIFFERENT values across multiple reads. Snapshot-
    //      then-validate collapses validate-then-send to a single
    //      read per field; the validated value is provably the
    //      value sent.
    //   3. Explicit empty / missing fields are treated as omission
    //      — `objectHasOwn` correctly returns false on missing keys.
    const hasJobType = objectHasOwn(input, "jobType");
    const jobTypeRaw: unknown = hasJobType
      ? readInputField(input, "jobType", "batch.submit")
      : undefined;
    const hasSystemIds = objectHasOwn(input, "systemIds");
    const systemIdsRaw: unknown = hasSystemIds
      ? readInputField(input, "systemIds", "batch.submit")
      : undefined;
    const hasConfig = objectHasOwn(input, "config");
    const configRaw: unknown = hasConfig
      ? readInputField(input, "config", "batch.submit")
      : undefined;

    // jobType — REQUIRED, closed-enum string membership.
    if (!hasJobType || jobTypeRaw === undefined) {
      throw new TypeError("batch.submit: `jobType` is required");
    }
    if (typeof jobTypeRaw !== "string") {
      throw new TypeError(
        `batch.submit: \`jobType\` must be a string ` +
          `(got ${describeType(jobTypeRaw)})`,
      );
    }
    // Closed-enum SDK pre-rejection (invariant #41). The kernel's
    // Zod `z.enum([...])` enforces the same; the SDK pre-rejects
    // synchronously to fail fast and surface a clear error.
    if (
      !(BATCH_JOB_TYPES as readonly string[]).includes(jobTypeRaw)
    ) {
      throw new TypeError(
        `batch.submit: \`jobType\` must be one of ` +
          `${JSON.stringify(BATCH_JOB_TYPES)} (got ${JSON.stringify(jobTypeRaw)})`,
      );
    }
    const validatedJobType: BatchJobType = jobTypeRaw as BatchJobType;

    // systemIds — REQUIRED array of 1-50 UUIDs. Snapshot via
    // Array.from up front so a Proxy whose `.length` or `[i]`
    // changes between reads can't slip past validation. Per-element
    // pre-validation matches Zod's `.array(z.string().uuid())
    // .min(1).max(50)` exactly.
    if (!hasSystemIds || systemIdsRaw === undefined) {
      throw new TypeError("batch.submit: `systemIds` is required");
    }
    if (!Array.isArray(systemIdsRaw)) {
      throw new TypeError(
        `batch.submit: \`systemIds\` must be an array ` +
          `(got ${describeType(systemIdsRaw)})`,
      );
    }
    const systemIdsSnapshot = Array.from(
      systemIdsRaw as ArrayLike<unknown>,
    );
    // .min(1) — distinct from gate/check's frameworks (which allowed
    // empty). Empty batches are rejected at the Zod level; SDK pre-
    // rejects for symmetry.
    if (systemIdsSnapshot.length < 1) {
      throw new TypeError(
        "batch.submit: `systemIds` must contain at least 1 entry " +
          "(empty arrays rejected — Zod `.min(1, \"At least one system ID is required\")`)",
      );
    }
    if (systemIdsSnapshot.length > 50) {
      throw new TypeError(
        `batch.submit: \`systemIds\` array exceeds the kernel's max ` +
          `length of 50 (got ${systemIdsSnapshot.length})`,
      );
    }
    for (let i = 0; i < systemIdsSnapshot.length; i++) {
      const elem = systemIdsSnapshot[i];
      if (typeof elem !== "string") {
        throw new TypeError(
          `batch.submit: \`systemIds[${i}]\` must be a string ` +
            `(got ${describeType(elem)})`,
        );
      }
      if (elem.length === 0) {
        throw new TypeError(
          `batch.submit: \`systemIds[${i}]\` must be a non-empty string`,
        );
      }
      if (!UUID_REGEX.test(elem)) {
        throw new TypeError(
          `batch.submit: \`systemIds[${i}]\` must be an RFC 4122 hyphenated UUID ` +
            `(matched regex: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-` +
            `[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, got ${JSON.stringify(elem)})`,
        );
      }
    }
    const validatedSystemIds = systemIdsSnapshot as string[];

    // config — OPTIONAL. When provided, must be a non-null non-
    // array object with optional `frameworks` matching gate/check's
    // exact shape.
    let validatedConfig: BatchConfig | undefined;
    if (hasConfig && configRaw !== undefined) {
      if (
        configRaw === null ||
        typeof configRaw !== "object" ||
        Array.isArray(configRaw)
      ) {
        throw new TypeError(
          `batch.submit: \`config\` must be a non-null object when provided ` +
            `(got ${describeType(configRaw)})`,
        );
      }
      const hasFrameworks = objectHasOwn(configRaw, "frameworks");
      const frameworksRaw: unknown = hasFrameworks
        ? (configRaw as { frameworks?: unknown }).frameworks
        : undefined;
      let validatedFrameworks: string[] | undefined;
      if (hasFrameworks && frameworksRaw !== undefined) {
        if (!Array.isArray(frameworksRaw)) {
          throw new TypeError(
            `batch.submit: \`config.frameworks\` must be an array when provided ` +
              `(got ${describeType(frameworksRaw)})`,
          );
        }
        const fwSnapshot = Array.from(
          frameworksRaw as ArrayLike<unknown>,
        );
        if (fwSnapshot.length > 20) {
          throw new TypeError(
            `batch.submit: \`config.frameworks\` array exceeds the kernel's max ` +
              `length of 20 (got ${fwSnapshot.length})`,
          );
        }
        for (let i = 0; i < fwSnapshot.length; i++) {
          const elem = fwSnapshot[i];
          if (typeof elem !== "string") {
            throw new TypeError(
              `batch.submit: \`config.frameworks[${i}]\` must be a string ` +
                `(got ${describeType(elem)})`,
            );
          }
          if (elem.length === 0) {
            throw new TypeError(
              `batch.submit: \`config.frameworks[${i}]\` must be a non-empty string`,
            );
          }
          if (elem.length > 100) {
            throw new TypeError(
              `batch.submit: \`config.frameworks[${i}]\` exceeds the kernel's max ` +
                `length of 100 chars (got ${elem.length})`,
            );
          }
        }
        validatedFrameworks = fwSnapshot as string[];
      }
      validatedConfig = {};
      if (validatedFrameworks !== undefined) {
        validatedConfig.frameworks = validatedFrameworks;
      }
    }

    // Construct the body. Omit `config` if the consumer didn't
    // provide it (kernel applies its own default — none today;
    // `config` is `.optional()` with no `.default()`). Omitting an
    // optional field is preferred over emitting `null` so the
    // kernel sees the field as absent.
    const body: {
      jobType: BatchJobType;
      systemIds: string[];
      config?: BatchConfig;
    } = {
      jobType: validatedJobType,
      systemIds: validatedSystemIds,
    };
    if (validatedConfig !== undefined) {
      body.config = validatedConfig;
    }

    return this.client
      ._request<BatchSubmitResponse>({
        method: "POST",
        path: "/api/v1/batch",
        body,
        options,
      })
      .then((result) => validateBatchSubmitResponse(result));
  }

  /**
   * Retrieve a batch job's status and results by UUID. Returns a
   * `BatchJobStatus` with the wider 4-value `status` enum (NOT the
   * narrower `"completed" | "failed"` of POST) plus the original
   * `config` (round-tripped from submission).
   *
   * **Single-permission auth scope (DIFFERENT from `submit()`)** —
   * kernel uses `requireApiKeyWithPermission(req, READ_ASSESSMENTS)`
   * with ONLY ONE required permission, NOT a union. Status reads
   * don't need `CLASSIFY` or `WRITE_ASSESSMENTS`. **First SDK
   * resource with asymmetric auth between methods on the same
   * resource** (invariant candidate #54). Pin BOTH 401 (no/invalid
   * key) AND 403 (key lacks `READ_ASSESSMENTS`) branches.
   *
   * **NO plan-guard surface on `get()`** — `requirePlan` is invoked
   * only in `submit()`. A free-tier org can `get()` a job that was
   * previously submitted (e.g., on a higher plan that has since
   * downgraded). The submission would have been gated; the read
   * isn't.
   *
   * **400 surface on malformed UUID path parameter** — the kernel's
   * `isValidUuid(id)` check at route.ts:36 returns false →
   * `errorResponse("Invalid batch job ID format", 400)`. The SDK
   * pre-validates the UUID format synchronously (`TypeError`) — so
   * the 400 reaches consumers only via `as any` casts or a kernel-
   * side switch to a different UUID flavor (ULID, KSUID, etc.).
   *
   * **404 surface (literal string)** — the kernel's `where(id +
   * orgId)` query returns zero rows → `errorResponse("Batch job not
   * found", 404)`. **NEW shape** vs `submit()`'s 404 with embedded
   * IDs — the `get()` 404 is a LITERAL string with no variable
   * data. Cross-org `id` collapses to the same 404 (the `eq(orgId,
   * apiKeyUser.orgId)` clause silently filters out matching IDs in
   * other orgs).
   *
   * **No `writeAuditLog` side effect on `get()`** — status reads
   * are quiet. Asymmetric with `submit()`'s `batch.submitted`
   * write.
   *
   * **Defensive `.limit(1)` on the batchJobs query** (route.ts:49)
   * — the `where` clause already narrows to one row by primary-key
   * UUID, so this cap is belt-and-suspenders against a hypothetical
   * future schema change (composite primary key, soft-deleted-rows
   * union). Pin separately as a kernel surface gap. Invariant
   * candidate #50.
   *
   * Errors — ordered by kernel firing precedence (rate-limit →
   * auth → UUID format → DB lookup → internal):
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried;
   *     per-IP key `v1-batch-status:${ip}`; uses the standard
   *     `apiLimiter` at 60 req/min — looser than `submit()`'s 30/
   *     min `assessmentLimiter`).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *   - `AttestryAPIError` (status 403) — authenticated key lacks
   *     `READ_ASSESSMENTS` permission (single-permission check,
   *     NOT a union). Pin separately from `submit()`'s 403.
   *   - `AttestryAPIError` (status 400) — kernel's `isValidUuid(id)`
   *     returned false. **The SDK pre-validates UUID format**, so
   *     this 400 reaches consumers ONLY via `as any` casts or
   *     kernel-side UUID flavor changes.
   *   - `AttestryAPIError` (status 404) — batch job not found OR
   *     cross-org `id` (kernel collapses to "Batch job not found";
   *     literal string with NO embedded variable data — distinct
   *     from `submit()`'s 404 shape).
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message).
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired.
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (11 fields).
   *   - `AttestryAPIError` (P3 hardening) — wrong Content-Type.
   *   - `TypeError` — input failed SDK-side validation (missing
   *     `id`, non-string `id`, empty `id`, malformed UUID `id`).
   *     **THROWN SYNCHRONOUSLY** (no fetch issued; not via the
   *     returned promise). Consumers using `.then(...)` without
   *     a surrounding try/catch see this surface as an uncaught
   *     synchronous throw — same caveat as `submit()`.
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch
   * issued):
   *   - `id`: required; must be a non-empty string matching
   *     `UUID_REGEX` (RFC 4122 hyphenated, case-insensitive).
   *
   * **Response-shape validation** (P2 hardening — 11 fields, all
   * always-present; symmetric defense on response side via the
   * module-load `objectHasOwn` snapshot):
   *   - Rejects with `AttestryError` if the response isn't a non-
   *     null, non-array object.
   *   - Rejects if `id` / `jobType` / `status` / `createdAt` aren't
   *     strings.
   *   - Rejects if `totalSystems` / `processedSystems` /
   *     `failedSystems` aren't numbers.
   *   - Rejects if `results` isn't `null` OR an array.
   *   - Rejects if `config` isn't `null` OR a non-array object.
   *   - Rejects if `startedAt` / `completedAt` aren't `null` OR
   *     a string.
   *   - Per-row shape (open-spec `BatchSystemResult`) is faithful-
   *     courier — NOT validated.
   *   - `config.frameworks` shape is faithful-courier — NOT
   *     validated.
   *
   * **NO URIError defense on the `id` path segment** — the SDK
   * pre-validates the UUID format (synchronous `TypeError`) BEFORE
   * constructing the URL. A lone-surrogate or non-hex `id` is
   * rejected before any `encodeURIComponent`-style call could fire.
   * Hex-only UUIDs are guaranteed-safe for path concatenation.
   *
   * @example Poll a job's status
   * ```ts
   * const job = await client.batch.get("11111111-1111-1111-1111-111111111111");
   * if (job.status === "completed") {
   *   console.log(`Processed ${job.processedSystems}/${job.totalSystems}`);
   * } else if (job.status === "failed") {
   *   console.error("Batch failed entirely");
   * } else {
   *   // "pending" / "processing" — still in flight
   *   console.log(`Job is ${job.status}`);
   * }
   * ```
   */
  get(id: string, options?: RequestOptions): Promise<BatchJobStatus> {
    if (typeof id !== "string" || id.length === 0) {
      throw new TypeError(
        "batch.get: `id` must be a non-empty string",
      );
    }
    // UUID format pre-validation (D7 — SDK matches kernel's
    // `isValidUuid` check at route.ts:36). Mirror of gate /
    // check's UUID_REGEX. The kernel's 400 ("Invalid batch job ID
    // format") is reachable only via `as any` cast or future
    // kernel-side UUID flavor changes.
    if (!UUID_REGEX.test(id)) {
      throw new TypeError(
        "batch.get: `id` must be an RFC 4122 hyphenated UUID " +
          "(matched regex: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-" +
          "[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, got " +
          JSON.stringify(id) +
          ")",
      );
    }

    return this.client
      ._request<BatchJobStatus>({
        method: "GET",
        path: `/api/v1/batch/${id}`,
        options,
      })
      .then((result) => validateBatchJobStatusResponse(result));
  }
}

/**
 * P2 hardening: validate the POST response's 10 always-present
 * fields. Symmetric prototype-pollution defense — read EACH field
 * via the module-load `objectHasOwn` snapshot so a hostile npm dep
 * polluting `Object.prototype.<field>` cannot mask a kernel
 * regression that drops the field (per session-16 second-hostile-
 * review MEDIUM #3 carry-forward — defense applied on both input
 * AND response boundaries).
 *
 * Returns the validated `result` (typed `BatchSubmitResponse`) on
 * success; throws `AttestryError` on any shape violation. Extracted
 * as a free function so the resource method body stays focused on
 * input validation + request construction.
 */
function validateBatchSubmitResponse(
  result: unknown,
): BatchSubmitResponse {
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result)
  ) {
    throw new AttestryError(
      `batch.submit: expected an object response from the kernel ` +
        `(got ${describeType(result)})`,
    );
  }
  const obj = result as Record<string, unknown>;

  const id = objectHasOwn(obj, "id") ? obj.id : undefined;
  if (typeof id !== "string") {
    throw new AttestryError(
      `batch.submit: expected response.id to be a string ` +
        `(got ${describeType(id)})`,
    );
  }
  const jobType = objectHasOwn(obj, "jobType") ? obj.jobType : undefined;
  if (typeof jobType !== "string") {
    throw new AttestryError(
      `batch.submit: expected response.jobType to be a string ` +
        `(got ${describeType(jobType)})`,
    );
  }
  const status = objectHasOwn(obj, "status") ? obj.status : undefined;
  if (typeof status !== "string") {
    throw new AttestryError(
      `batch.submit: expected response.status to be a string ` +
        `(got ${describeType(status)})`,
    );
  }
  const totalSystems = objectHasOwn(obj, "totalSystems")
    ? obj.totalSystems
    : undefined;
  if (typeof totalSystems !== "number") {
    throw new AttestryError(
      `batch.submit: expected response.totalSystems to be a number ` +
        `(got ${describeType(totalSystems)})`,
    );
  }
  const processedSystems = objectHasOwn(obj, "processedSystems")
    ? obj.processedSystems
    : undefined;
  if (typeof processedSystems !== "number") {
    throw new AttestryError(
      `batch.submit: expected response.processedSystems to be a number ` +
        `(got ${describeType(processedSystems)})`,
    );
  }
  const failedSystems = objectHasOwn(obj, "failedSystems")
    ? obj.failedSystems
    : undefined;
  if (typeof failedSystems !== "number") {
    throw new AttestryError(
      `batch.submit: expected response.failedSystems to be a number ` +
        `(got ${describeType(failedSystems)})`,
    );
  }
  const results = objectHasOwn(obj, "results") ? obj.results : undefined;
  if (!Array.isArray(results)) {
    throw new AttestryError(
      `batch.submit: expected response.results to be an array ` +
        `(got ${describeType(results)})`,
    );
  }
  const createdAt = objectHasOwn(obj, "createdAt")
    ? obj.createdAt
    : undefined;
  if (typeof createdAt !== "string") {
    throw new AttestryError(
      `batch.submit: expected response.createdAt to be a string ` +
        `(got ${describeType(createdAt)})`,
    );
  }
  const startedAt = objectHasOwn(obj, "startedAt")
    ? obj.startedAt
    : undefined;
  if (startedAt !== null && typeof startedAt !== "string") {
    throw new AttestryError(
      `batch.submit: expected response.startedAt to be a string or null ` +
        `(got ${describeType(startedAt)})`,
    );
  }
  const completedAt = objectHasOwn(obj, "completedAt")
    ? obj.completedAt
    : undefined;
  if (typeof completedAt !== "string") {
    throw new AttestryError(
      `batch.submit: expected response.completedAt to be a string ` +
        `(got ${describeType(completedAt)})`,
    );
  }
  return result as BatchSubmitResponse;
}

/**
 * P2 hardening: validate the GET response's 11 always-present
 * fields. Same symmetric defense as `validateBatchSubmitResponse`.
 *
 * `results` and `config` are NULLABLE (DB jsonb columns); the
 * validator accepts `null` OR the typed shape. `startedAt` and
 * `completedAt` are BOTH nullable on GET (in contrast to POST where
 * `completedAt` is always a string).
 */
function validateBatchJobStatusResponse(
  result: unknown,
): BatchJobStatus {
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result)
  ) {
    throw new AttestryError(
      `batch.get: expected an object response from the kernel ` +
        `(got ${describeType(result)})`,
    );
  }
  const obj = result as Record<string, unknown>;

  const id = objectHasOwn(obj, "id") ? obj.id : undefined;
  if (typeof id !== "string") {
    throw new AttestryError(
      `batch.get: expected response.id to be a string ` +
        `(got ${describeType(id)})`,
    );
  }
  const jobType = objectHasOwn(obj, "jobType") ? obj.jobType : undefined;
  if (typeof jobType !== "string") {
    throw new AttestryError(
      `batch.get: expected response.jobType to be a string ` +
        `(got ${describeType(jobType)})`,
    );
  }
  const status = objectHasOwn(obj, "status") ? obj.status : undefined;
  if (typeof status !== "string") {
    throw new AttestryError(
      `batch.get: expected response.status to be a string ` +
        `(got ${describeType(status)})`,
    );
  }
  const totalSystems = objectHasOwn(obj, "totalSystems")
    ? obj.totalSystems
    : undefined;
  if (typeof totalSystems !== "number") {
    throw new AttestryError(
      `batch.get: expected response.totalSystems to be a number ` +
        `(got ${describeType(totalSystems)})`,
    );
  }
  const processedSystems = objectHasOwn(obj, "processedSystems")
    ? obj.processedSystems
    : undefined;
  if (typeof processedSystems !== "number") {
    throw new AttestryError(
      `batch.get: expected response.processedSystems to be a number ` +
        `(got ${describeType(processedSystems)})`,
    );
  }
  const failedSystems = objectHasOwn(obj, "failedSystems")
    ? obj.failedSystems
    : undefined;
  if (typeof failedSystems !== "number") {
    throw new AttestryError(
      `batch.get: expected response.failedSystems to be a number ` +
        `(got ${describeType(failedSystems)})`,
    );
  }
  const results = objectHasOwn(obj, "results") ? obj.results : undefined;
  if (results !== null && !Array.isArray(results)) {
    throw new AttestryError(
      `batch.get: expected response.results to be an array or null ` +
        `(got ${describeType(results)})`,
    );
  }
  const config = objectHasOwn(obj, "config") ? obj.config : undefined;
  if (
    config !== null &&
    (typeof config !== "object" || Array.isArray(config))
  ) {
    throw new AttestryError(
      `batch.get: expected response.config to be an object or null ` +
        `(got ${describeType(config)})`,
    );
  }
  const createdAt = objectHasOwn(obj, "createdAt")
    ? obj.createdAt
    : undefined;
  if (typeof createdAt !== "string") {
    throw new AttestryError(
      `batch.get: expected response.createdAt to be a string ` +
        `(got ${describeType(createdAt)})`,
    );
  }
  const startedAt = objectHasOwn(obj, "startedAt")
    ? obj.startedAt
    : undefined;
  if (startedAt !== null && typeof startedAt !== "string") {
    throw new AttestryError(
      `batch.get: expected response.startedAt to be a string or null ` +
        `(got ${describeType(startedAt)})`,
    );
  }
  const completedAt = objectHasOwn(obj, "completedAt")
    ? obj.completedAt
    : undefined;
  if (completedAt !== null && typeof completedAt !== "string") {
    throw new AttestryError(
      `batch.get: expected response.completedAt to be a string or null ` +
        `(got ${describeType(completedAt)})`,
    );
  }
  return result as BatchJobStatus;
}

/**
 * Human-readable type description for error messages. Distinguishes
 * `null` and `array` from generic `object`. Duplicated in
 * `decisions.ts`, `incidents.ts`, `regulatory-changes.ts`,
 * `compliance-check.ts`, `check.ts`, `gate.ts` per project pattern
 * (small helper, leaf-resource modules, no shared module yet).
 *
 * Every branch is reachable in this file through the multiple call
 * sites (top-level shape, each field type guard, systemIds element
 * non-string, frameworks element non-string, config non-object).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
