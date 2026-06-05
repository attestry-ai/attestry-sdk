// ─── Check resource ─────────────────────────────────────────────────────────
//
// Wraps the CI/CD compliance-check surface (session 16):
//
//   - POST /api/v1/check  Body: {systemId: <UUID>, frameworks?: string[]}
//
// Fourth non-decisions resource on `@attestry/sdk`. Sibling to
// `IncidentsResource`, `DecisionsResource`, `ChatResource`,
// `AuditLogResource`, `RegulatoryChangesResource`,
// `ComplianceCheckResource`. Single public method today (`run`); the
// resource class exists as the landing pad for future check methods
// if/when the kernel adds them (resource-class-per-kernel-resource
// convention, carry-forward invariant #43).
//
// Method name `run` rather than `check` — `client.check.check(...)`
// would be awkward; `run` mirrors the verb pattern of `chat.send`,
// `decisions.ingest`, `auditLog.export`. User-confirmed at session
// start.
//
// **Multi-permission UNION auth scope**: the kernel route gates on
// `requireApiKeyWithPermission(request, READ_ASSESSMENTS, READ_SYSTEMS)`
// which is OR semantics — `permissions.ts:53-55` uses `Array.some()`,
// NOT `.every()`. A key with EITHER permission (or `ADMIN`, or empty
// permissions for backwards-compat) succeeds. **HTTP 401** for
// no/invalid API key; **HTTP 403** for an authenticated key that has
// NEITHER required permission. Pin BOTH branches separately.
// Carry-forward invariant #45 (no re-discovery this round — same shape
// as `complianceCheck.check`).
//
// **First SDK route to PRE-VALIDATE every Zod closed-spec rule
// synchronously**. Other Zod-bodied SDK routes (e.g.,
// `incidents.create`) pass input through without SDK-side validation,
// so a 422 from Zod has been a consumer-visible surface there since
// v0.1. In `check.run` the kernel uses `parseBody(request,
// checkSchema)` where `checkSchema` is `z.object({systemId:
// z.string().uuid(), frameworks: z.array(z.string().min(1).max(100))
// .max(20).optional()})`. The SDK pre-validates EVERY closed-spec
// rule synchronously (UUID format, string length 1-100, array length
// cap 20). The SDK's runtime checks always run regardless of
// TypeScript types — `as any` casts do NOT bypass them. So 422 from
// this route reaches consumers ONLY via kernel-side rule changes the
// SDK hasn't synced to. Codifies new invariant candidate #49
// (pre-validate Zod closed-spec rules SDK-side) and #51 (POST + Zod
// body — pre-rejected TypeError is the primary path, kernel 422 is
// the fallback for rules the SDK hasn't synced to).
//
// **Asymmetric cross-org error code**: cross-org `systemId` returns
// **404** (kernel's `and(eq id, eq orgId)` at route.ts:42-51 followed
// by "System not found" — mirror of `decisions.retrieve` +
// `complianceCheck.check`'s systemId branch). Partial carry-forward
// of #47 (no orgName twin here, so only the 404 half applies).
//
// **Three silent kernel-side truncations** (faithful courier — SDK
// does NOT mask):
//   1. `issues` capped at 20 (`gaps.slice(0, 20)` at route.ts:90).
//   2. `assessments` capped at 100 (`.limit(100)` at route.ts:62).
//   3. `attestations` capped at 50 (`.limit(50)` at route.ts:100).
// Each documented in JSDoc + README + drift-pinned. New invariant
// candidate #50 (multi-silent-truncation enumeration).
//
// **`score` defaults to 0 (NOT null) when no completed assessment
// exists** (route.ts:84 — `typeof scores?.overallScore === "number"
// ? scores.overallScore : 0`). Asymmetric with
// `complianceCheck.check` which used `null` for "no data".
// Consumers cannot distinguish "scored zero" from "no completed
// assessment" via `score` alone — must check `lastAssessedAt ===
// null` to differentiate. Kernel surface gap, documented prominently.
//
// **`compliant` threshold stricter than `complianceCheck.check`**:
// here `compliant === activeAttestations > 0 && overallScore >= 70 &&
// issues.length === 0` (three conjuncts). Because `score` defaults
// to 0 (not null), a system with no completed assessment automatically
// has `compliant: false` here, even when active attestations exist.
//
// **NO URIError defense on body fields** — POST body uses
// `JSON.stringify`, which handles lone UTF-16 surrogates by emitting
// them as literal `\uDxxx` escapes. The URIError defect class
// (carry-forward invariant #32) applies only to query-string paths
// (`encodeURIComponent`); this route has no query string and a fixed
// path. `assertEncodableQueryString` is NOT invoked here — explicit
// asymmetry vs `complianceCheck.check` / decisions / incidents /
// audit-log / regulatory-changes. Documented as D4.
//
// Sync JSON request/response: reuses `client._request` and the
// existing `{success:true, data}` envelope-unwrap (carry-forward
// invariant #9). NO new SDK primitive needed. Returns
// `Promise<CheckResponse>`.

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

// Module-load snapshot of `Object.hasOwn` — defends against a
// late-loading hostile/buggy npm dependency that overrides the global
// (e.g., `Object.hasOwn = () => true`). Without the snapshot, the
// prototype-pollution defense below uses whatever Object.hasOwn the
// dependency replaced it with at request time. Snapshotting at module
// load captures the original implementation BEFORE most consumer
// code has a chance to monkey-patch.
//
// Caveat: this is partial. If the hostile dependency is imported
// BEFORE @attestry/sdk in the consumer's load graph, the snapshot
// captures the bad version. Consumers ordering imports
// SDK-then-untrusted-deps benefit; the reverse ordering does not.
// Combined with `Object.hasOwn` itself being immune to
// `obj.hasOwnProperty = ...` overrides (per MDN), this gives a
// layered defense.
//
// Mirror of `complianceCheck.check`'s pattern (hostile review session
// 15 LOW #2). Generalizes #48 beyond XOR branching: prototype
// pollution can lie about presence of ANY field where presence affects
// SDK control flow (here: `systemId` required-vs-missing, `frameworks`
// provided-vs-not). See build-round audit doc D5.
const objectHasOwn = Object.hasOwn;

// UUID format regex — RFC 4122 hyphenated form (8-4-4-4-12 hex,
// case-insensitive). Matches Zod's `z.string().uuid()` regex
// effectively (the `\b` word-boundaries in Zod's version are
// redundant between hex chars and hyphens). Drift-pinned in
// `sdk-drift.test.ts` spec-diff-round Pin so a kernel-side switch to
// a different UUID flavor (ULID, KSUID, etc.) fires before consumer
// regressions.
//
// Pre-validation here gives consumers a synchronous `TypeError` for
// malformed UUID input — faster + clearer than waiting for the
// kernel's 422 with `fieldErrors`. D2 deviation from
// `complianceCheck.check` (which deferred to kernel's `isValidUuid`
// returning 400). Codifies new invariant #49 (Zod-schema-validated
// input — pre-validate closed-spec rules SDK-side).
const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Input shape for `check.run`. Source-of-truth at kernel
 * `src/app/api/v1/check/route.ts:21-24` (Zod schema).
 *
 * **`systemId`** — REQUIRED RFC 4122 hyphenated UUID. The SDK
 * pre-validates the format synchronously (`TypeError` for malformed
 * input — D2 deviation from `complianceCheck.check`'s defer-to-kernel
 * stance). The SDK's runtime check always runs regardless of
 * TypeScript types — `as any` casts do NOT bypass it. The kernel-side
 * Zod validation (422 fallback) only fires for kernel rule changes
 * the SDK hasn't synced to.
 *
 * **`frameworks`** — OPTIONAL array of up to 20 framework
 * identifiers; each string of length 1-100. The kernel filters
 * assessments to those whose `assessment.frameworks: string[]`
 * intersects this list (OR-overlap semantics, NOT all-required —
 * consumers expecting AND will be surprised). When omitted, the
 * kernel considers all assessments. Empty array `[]` is accepted and
 * SDK-side passes through (matches Zod's `.array(...).max(20)` which
 * accepts empty arrays).
 *
 * Open-spec field — kernel does NOT enforce a closed enum of valid
 * framework names; any string within the length bounds is accepted.
 * Consumers should align their filter values with the framework
 * identifiers they used when creating assessments.
 */
export interface CheckInput {
  /**
   * UUID of the system to check. RFC 4122 hyphenated form
   * (8-4-4-4-12 hex, case-insensitive). Required.
   */
  systemId: string;
  /**
   * Optional framework filter. Each element must be a non-empty
   * string of length ≤100; the array length must be ≤20. SDK
   * pre-validates all three rules.
   *
   * **OR-overlap semantics** (kernel filters with `aFrameworks.some`
   * at route.ts:67-71) — an assessment matches if its frameworks
   * intersect this list, not if it covers ALL of them. Consumers
   * wanting AND-all-required semantics must apply that filter
   * post-hoc by inspecting individual assessments.
   */
  frameworks?: string[];
}

/**
 * Response shape returned by `check.run`. Source-of-truth at kernel
 * `src/app/api/v1/check/route.ts:109-116` (the route's only
 * `successResponse({...})` call). FLAT — no `systems[]` wrapper
 * (unlike `complianceCheck.check`'s `{systems, checkedAt}` shape).
 *
 * Synthesized at handler-time, NOT a Drizzle row. The kernel
 * iterates assessments + attestations for the system and emits
 * these 6 fields inline. The drift pin in `sdk-drift.test.ts` reads
 * the route source and asserts the literal property names match this
 * interface.
 */
export interface CheckResponse {
  /**
   * **Stricter-than-compliance-check threshold**: the kernel
   * computes `activeAttestations.length > 0 && overallScore >= 70
   * && issues.length === 0` against its internal filtered DB
   * arrays (route.ts:107), then emits the count as
   * `response.activeAttestations` and the score as
   * `response.score`. From the consumer's perspective this is
   * equivalent to `response.activeAttestations > 0 &&
   * response.score >= 70 && response.issues.length === 0` (three
   * conjuncts). The transcription difference is cosmetic — the
   * `activeAttestations` array's `.length` IS what gets emitted as
   * the response field.
   *
   * Because `score` defaults to 0 (NOT null) when no completed
   * assessment exists, a system with no completed assessment AND
   * active attestations still has `compliant: false` here —
   * different from `complianceCheck.check` which treated null-score
   * as "not failing". Consumers wanting different semantics should
   * inspect `score`, `lastAssessedAt`, and `activeAttestations`
   * directly.
   */
  compliant: boolean;
  /**
   * Overall score from the latest completed assessment's
   * `scores.overallScore` jsonb field, IF that field is a `number`.
   *
   * **DEFAULTS TO 0 — NOT NULL** (route.ts:84 — `typeof
   * scores?.overallScore === "number" ? scores.overallScore : 0`).
   * Consumers CANNOT distinguish "scored zero / fails compliance"
   * from "no completed assessment yet" via `score` alone — they
   * MUST check `lastAssessedAt === null` to differentiate.
   *
   * **Asymmetric with `complianceCheck.check`** which used `null`
   * for "no data" (preserving the distinction). Kernel surface gap;
   * the SDK does NOT mask (faithful courier).
   *
   * Range is unbounded — kernel does not clamp 0..100.
   */
  score: number;
  /**
   * Up to 20 issue strings derived from
   * `latestCompleted.gaps[].title ?? gap.description ?? "Compliance
   * gap detected"` (route.ts:90-93).
   *
   * **SILENTLY TRUNCATED at 20** (`.slice(0, 20)` at route.ts:90).
   * If the latest completed assessment has >20 gaps, the 21st+ are
   * invisible — no `total` field, no `hasMore` cursor, no
   * truncation indicator. Faithful courier; documented in JSDoc +
   * README. New invariant candidate #50 (multi-silent-truncation
   * enumeration).
   *
   * Each string is the gap's `title` (falling back to `description`,
   * then to the literal `"Compliance gap detected"` if both are
   * missing).
   */
  issues: string[];
  /**
   * Count of currently-active attestation rows — defined as
   * `attestations.status === "active"` AND
   * (`attestations.expiresAt === null` OR `attestations.expiresAt
   * > now`). Non-negative integer.
   *
   * **SILENTLY CAPPED AT 50 ROWS-CONSIDERED** — the kernel reads up
   * to 50 attestations (`.limit(50)` at route.ts:100) and counts
   * active ones from that subset. A system with >50 attestations
   * (rare but possible for long-lived production systems) may have
   * an UNDERCOUNTED active total. Faithful courier; documented.
   * Part of invariant candidate #50.
   */
  activeAttestations: number;
  /**
   * ISO-8601 from the latest completed assessment's `completedAt`,
   * OR `null` if no completed assessment exists.
   *
   * **Use this field — NOT `score === 0` — to detect "no completed
   * assessment yet"**. The kernel sorts completed assessments DESC
   * by `completedAt` (in JS, not SQL) and takes the first; the
   * pre-sort population is silently capped at 100 (see
   * `assessments` silent-cap note below).
   */
  lastAssessedAt: string | null;
  /**
   * ISO-8601, server-generated at handler end via
   * `new Date().toISOString()` (route.ts:115). Uniquely identifies
   * this check's snapshot — consumers may use it as a freshness
   * marker.
   */
  checkedAt: string;
}

/**
 * `check` resource — sibling to `IncidentsResource`,
 * `DecisionsResource`, `ChatResource`, `AuditLogResource`,
 * `RegulatoryChangesResource`, `ComplianceCheckResource`. Today
 * wraps a single endpoint (`run`); the class is the landing pad for
 * future check methods if the kernel adds them
 * (resource-class-per-kernel-resource convention, invariant #43).
 */
export class CheckResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Run a CI/CD compliance check for a single system. Returns a flat
   * 6-field summary: `{compliant, score, issues, activeAttestations,
   * lastAssessedAt, checkedAt}`. Sync JSON request/response — no
   * pagination, no streaming.
   *
   * **Multi-permission UNION auth scope**: kernel uses
   * `requireApiKeyWithPermission(req, READ_ASSESSMENTS, READ_SYSTEMS)`
   * which is OR semantics (`Array.some()` at
   * `permissions.ts:53-55`). A key with EITHER permission (or
   * `ADMIN`, or null/empty permissions for backwards-compat)
   * succeeds. **HTTP 401** for no/invalid API key, **HTTP 403** for
   * an authenticated key that has NEITHER required permission. Pin
   * BOTH branches separately. Carry-forward invariant #45 (same
   * shape as `complianceCheck.check`).
   *
   * **Asymmetric cross-org error code** (carry-forward #47, partial):
   * cross-org `systemId` returns **404** — the kernel's
   * `and(eq id, eq orgId)` at route.ts:42-51 collapses
   * cross-org to "System not found" (mirror of
   * `decisions.retrieve`). Consumers writing defensive error-handling
   * logic must recognize: a 404 may be "not your org" OR "genuine
   * missing UUID". No 403-via-orgName twin here (no orgName input
   * mode).
   *
   * **THREE silent kernel-side truncations** (faithful courier;
   * documented as kernel surface gaps — JSDoc + README + drift
   * pinned). New invariant candidate #50:
   *   1. `issues` — `.slice(0, 20)` at route.ts:90. If the latest
   *      completed assessment has >20 gaps, the 21st+ are invisible.
   *   2. `assessments` row-population — `.limit(100)` at route.ts:62.
   *      If the system has >100 assessments, the kernel's JS-side
   *      `.sort()` operates on the first 100 only; the "latest
   *      completed" may be missed.
   *   3. `attestations` row-population — `.limit(50)` at
   *      route.ts:100. If the system has >50 attestation rows,
   *      `activeAttestations` may be undercounted.
   *
   * **`score` defaults to 0 (NOT null) — kernel surface gap**:
   * route.ts:84 — `typeof scores?.overallScore === "number" ?
   * scores.overallScore : 0`. Consumers MUST check `lastAssessedAt
   * === null` to distinguish "no completed assessment yet" from
   * "scored zero / fails compliance". Asymmetric with
   * `complianceCheck.check`'s null-on-no-data.
   *
   * **`frameworks` filter is OR-overlap, NOT AND-all-required** —
   * route.ts:67-71 uses `aFrameworks.some((fw) =>
   * body.frameworks!.some(...))`. An assessment matches if its
   * `frameworks` array intersects the filter (at least one in
   * common), not if it covers ALL of them. Consumers wanting AND
   * semantics must filter post-hoc.
   *
   * Errors — ordered by kernel firing precedence (rate-limit → auth
   * → Zod body validation → DB lookup → internal). A request with
   * multiple problems surfaces ONLY the highest-precedence one. For
   * example: a request with bad auth AND a malformed body surfaces
   * 401, not 422; a request with valid auth + bad body AND a cross-
   * org systemId surfaces 422, not 404.
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     (auto-retried by default — invariant #18; per-IP rate-limit
   *     key `v1-check:${ip}`).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *     Fires AFTER rate-limit but BEFORE input validation.
   *   - `AttestryAPIError` (status 403) — authenticated key has
   *     NEITHER `READ_ASSESSMENTS` nor `READ_SYSTEMS` (the
   *     permission-check branch). Single test case — the union-auth
   *     pattern collapses three intuition-suggesting cases to one.
   *   - `AttestryAPIError` (status 422) — Zod schema rejection
   *     (kernel's `BodyParseError` surface — `parseBody(request,
   *     checkSchema)` failed). **Fires BEFORE the systemId/cross-
   *     org 404 lookup**, so a request with bad UUID format AND
   *     cross-org-correct UUID surfaces 422 (the kernel's Zod
   *     `.uuid()` reject), not 404. `apiErr.details` carries the
   *     full kernel error body verbatim (the transport does NOT
   *     strip the `{success:false, ...}` envelope on error responses
   *     — only the `{success:true, data}` envelope on success). The
   *     wire shape is: `{success: false, error: "Validation failed.",
   *     details: Array<{path: string; message: string}>}` — `error`
   *     is the literal string
   *     "Validation failed." (with trailing period), `details` is
   *     an array (NOT a keyed map) of `{path, message}` pairs
   *     derived from Zod's `result.error.errors`. Consumers
   *     reading field-by-field errors should iterate
   *     `apiErr.details.details` (the kernel's `details` array
   *     nested under the SDK's parsed-body wrapper). **The SDK
   *     pre-validates all closed-spec rules** (UUID format,
   *     framework element length 1-100, array length ≤20) AND the
   *     runtime checks always run regardless of TypeScript types —
   *     `as any` casts do NOT bypass them. So 422 reaches consumers
   *     ONLY via kernel rule changes the SDK hasn't synced to (e.g.,
   *     a future kernel tightening that adds a new Zod rule the SDK
   *     hasn't yet learned to pre-validate). New invariant candidate
   *     #51.
   *   - `AttestryAPIError` (status 404) — system not found OR
   *     cross-org systemId (kernel collapses to "System not found",
   *     route.ts:53-54). Fires AFTER Zod validation (422).
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`).
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired (pre-aborted or mid-flight).
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (not an object, wrong type on any
   *     of the 6 documented fields).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard before body
   *     parsing).
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation (null / array / non-object input,
   *     missing systemId, invalid UUID format, frameworks array too
   *     long, frameworks element wrong type or length).
   *
   * **Notably ABSENT**:
   *   - **No 400** — all input validation is Zod (422). The "missing
   *     required field" 400 from compliance-check is irrelevant
   *     (single required field; SDK pre-rejects as TypeError).
   *   - **No 413** — body size limit not explicit; the kernel's
   *     `parseBody` may have one but it isn't documented and the
   *     SDK doesn't pin it.
   *   - **No 402** — read-only, doesn't count against
   *     decisionsPerMonth quota.
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch
   * issued):
   *   - `input` itself: required; must be a non-null, non-array
   *     object.
   *   - `input.systemId`: required own-property (Object.hasOwn
   *     defends against prototype pollution lying about presence —
   *     generalization of invariant #48); must be a non-empty
   *     string; must match the RFC 4122 hyphenated UUID format
   *     (D2 — SDK pre-validates closed-spec rule). No
   *     lone-surrogate URIError defense (D4 — POST body uses
   *     JSON.stringify, not encodeURIComponent).
   *   - `input.frameworks` (when provided): must be an array of
   *     ≤20 strings, each of length 1-100. SDK pre-validates each
   *     rule (D3 — closed-spec rules mirror Zod). Array is
   *     snapshotted via `Array.from` for TOCTOU defense (Proxy /
   *     getter inputs can't yield different values across
   *     validate-vs-send).
   *
   * **Response-shape validation** (P2 hardening — D6, stricter than
   * `complianceCheck.check`'s 3-field top-level):
   *   - Rejects with `AttestryError` if the kernel response isn't a
   *     non-null, non-array object.
   *   - Rejects if `compliant` isn't a boolean.
   *   - Rejects if `score` isn't a number.
   *   - Rejects if `issues` isn't an array.
   *   - Rejects if `activeAttestations` isn't a number.
   *   - Rejects if `lastAssessedAt` isn't a string OR null.
   *   - Rejects if `checkedAt` isn't a string.
   *   - Each response field read goes through the module-load
   *     `objectHasOwn` snapshot (symmetric to the input-side
   *     prototype-pollution defense — D5 generalized to the response
   *     boundary). A hostile npm dep that pollutes
   *     `Object.prototype.<field>` cannot mask a kernel regression
   *     where the field is missing — the SDK requires the field to
   *     be a kernel-emitted own property.
   *   - Per-issue-string shape (open string) is faithful-courier —
   *     NOT validated.
   *
   * **Transport-shape validation** (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with
   *     a non-`application/json` Content-Type.
   *
   * @example Basic check
   * ```ts
   * const result = await client.check.run({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   * });
   * if (result.compliant) {
   *   console.log("OK to deploy — score:", result.score);
   * } else if (result.lastAssessedAt === null) {
   *   console.warn("No completed assessment yet — score=0 is the default, not a failing grade");
   * } else {
   *   console.warn("Compliance gaps:", result.issues);
   * }
   * ```
   *
   * @example Filtered by frameworks (OR-overlap)
   * ```ts
   * const euOnly = await client.check.run({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   *   frameworks: ["EU_AI_ACT", "ISO_42001"],
   * });
   * ```
   */
  run(
    input: CheckInput,
    options?: RequestOptions,
  ): Promise<CheckResponse> {
    // Top-level shape — input is REQUIRED. typeof null === "object"
    // and typeof [] === "object", so guard both explicitly.
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "check.run: `input` must be a non-null object with `systemId`",
      );
    }

    // Snapshot each field's value EXACTLY ONCE up front via the
    // own-property indexer, then operate only on the locals
    // downstream. Three motivations:
    //   1. **Prototype-pollution defense (generalization of #48)**:
    //      `Object.prototype.systemId = "<some-uuid>"` (set somewhere
    //      else in the consumer's process) DOES NOT trick the SDK
    //      into silently sending the polluted value when the user
    //      passes `{}`. `Object.hasOwn` only checks own properties
    //      (ES2022, Node 16.9+ — below the SDK's Node 18 floor). Use
    //      the module-load snapshot (`objectHasOwn`) so a
    //      late-loading dep that overrides the global doesn't defeat
    //      the defense (mirror of `complianceCheck.check`'s hostile-
    //      review LOW #2 fix).
    //   2. **TOCTOU defense**: a Proxy or getter-defining input could
    //      yield DIFFERENT values across multiple reads of the same
    //      field. Snapshotting once collapses validate-then-send to a
    //      single read per field; the validated value is provably the
    //      value sent.
    //   3. An explicit `{systemId: "..."}` (no `frameworks`) is
    //      treated as frameworks-omitted — `objectHasOwn` correctly
    //      returns false on the missing key.
    const hasSystemId = objectHasOwn(input, "systemId");
    const systemIdRaw: unknown = hasSystemId
      ? readInputField(input, "systemId", "check.run")
      : undefined;
    const hasFrameworks = objectHasOwn(input, "frameworks");
    const frameworksRaw: unknown = hasFrameworks
      ? readInputField(input, "frameworks", "check.run")
      : undefined;

    // systemId is REQUIRED. Reject missing-or-undefined first with a
    // clear "required" message; subsequent checks assume present.
    if (!hasSystemId || systemIdRaw === undefined) {
      throw new TypeError(
        "check.run: `systemId` is required",
      );
    }
    if (typeof systemIdRaw !== "string" || systemIdRaw.length === 0) {
      throw new TypeError(
        "check.run: `systemId` must be a non-empty string",
      );
    }
    // UUID format pre-validation (D2 — SDK matches kernel's Zod
    // `z.string().uuid()` closed-spec rule). Faster + clearer than
    // waiting for kernel 422 + fieldErrors decoding. Drift-pinned so
    // a future Zod regex change (e.g., adding v7 ULID support) trips
    // the suite.
    if (!UUID_REGEX.test(systemIdRaw)) {
      throw new TypeError(
        "check.run: `systemId` must be an RFC 4122 hyphenated UUID " +
          "(matched regex: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" +
          "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/)",
      );
    }

    // frameworks — optional. When provided, MUST mirror Zod:
    //   - Array (not other iterable).
    //   - Length ≤20.
    //   - Each element a string of length 1-100.
    // Snapshot via Array.from up front so a Proxy whose `.length` or
    // `[i]` changes between reads can't slip past validation. The
    // snapshot is then sent verbatim as the body field — no
    // re-read.
    let validatedFrameworks: string[] | undefined;
    if (hasFrameworks && frameworksRaw !== undefined) {
      if (!Array.isArray(frameworksRaw)) {
        throw new TypeError(
          `check.run: \`frameworks\` must be an array when provided ` +
            `(got ${describeType(frameworksRaw)})`,
        );
      }
      const snapshot = Array.from(frameworksRaw as ArrayLike<unknown>);
      if (snapshot.length > 20) {
        throw new TypeError(
          `check.run: \`frameworks\` array exceeds the kernel's max ` +
            `length of 20 (got ${snapshot.length})`,
        );
      }
      for (let i = 0; i < snapshot.length; i++) {
        const elem = snapshot[i];
        if (typeof elem !== "string") {
          throw new TypeError(
            `check.run: \`frameworks[${i}]\` must be a string ` +
              `(got ${describeType(elem)})`,
          );
        }
        if (elem.length === 0) {
          throw new TypeError(
            `check.run: \`frameworks[${i}]\` must be a non-empty string`,
          );
        }
        if (elem.length > 100) {
          throw new TypeError(
            `check.run: \`frameworks[${i}]\` exceeds the kernel's max ` +
              `length of 100 chars (got ${elem.length})`,
          );
        }
      }
      // Cast: we've validated every element is a string.
      validatedFrameworks = snapshot as string[];
    }

    // Construct the body. Omit `frameworks` entirely when not
    // provided — the kernel's Zod schema marks it `.optional()` and a
    // missing key is the cleanest representation. (JSON.stringify
    // would also drop `undefined`-valued keys, but explicit
    // construction is clearer.)
    const body: { systemId: string; frameworks?: string[] } = {
      systemId: systemIdRaw,
    };
    if (validatedFrameworks !== undefined) {
      body.frameworks = validatedFrameworks;
    }

    return this.client
      ._request<CheckResponse>({
        method: "POST",
        path: "/api/v1/check",
        body,
        options,
      })
      .then((result) => {
        // P2 hardening: validate every documented field type. The
        // check response is FLAT — all 6 fields are top-level (no
        // nested wrapper like `complianceCheck.check`'s `systems[]`).
        // A kernel-side regression that emits the wrong type on any
        // field would let a malformed shape reach consumers, who
        // crash downstream with a confusing TypeError. Catch at the
        // SDK boundary with a clear AttestryError naming the
        // specific field.
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `check.run: expected an object response from the kernel ` +
              `(got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;
        // **Prototype-pollution defense on the RESPONSE side**
        // (symmetric to the input-side D5 generalization of #48).
        // Snapshot each response field via `objectHasOwn` so a hostile
        // npm dep that pollutes `Object.prototype.<field> = <value>`
        // (e.g., `Object.prototype.compliant = true`) cannot mask a
        // kernel regression where the field is missing from the
        // response. Without this defense: kernel-regression-drops-field
        // + prototype-pollution-supplies-default → SDK accepts the
        // polluted value via prototype walk; consumer silently gets a
        // wrong response. With this defense: missing own-property →
        // describeType(undefined) → AttestryError thrown.
        //
        // Found by session-16 SECOND independent hostile review as
        // MEDIUM #3 — symmetric attack to the input-side defense,
        // previously unguarded on the response path.
        const compliant = objectHasOwn(obj, "compliant")
          ? obj.compliant
          : undefined;
        if (typeof compliant !== "boolean") {
          throw new AttestryError(
            `check.run: expected response.compliant to be a boolean ` +
              `(got ${describeType(compliant)})`,
          );
        }
        const score = objectHasOwn(obj, "score") ? obj.score : undefined;
        if (typeof score !== "number") {
          throw new AttestryError(
            `check.run: expected response.score to be a number ` +
              `(got ${describeType(score)})`,
          );
        }
        const issues = objectHasOwn(obj, "issues") ? obj.issues : undefined;
        if (!Array.isArray(issues)) {
          throw new AttestryError(
            `check.run: expected response.issues to be an array ` +
              `(got ${describeType(issues)})`,
          );
        }
        const activeAttestations = objectHasOwn(obj, "activeAttestations")
          ? obj.activeAttestations
          : undefined;
        if (typeof activeAttestations !== "number") {
          throw new AttestryError(
            `check.run: expected response.activeAttestations to be a number ` +
              `(got ${describeType(activeAttestations)})`,
          );
        }
        const lastAssessedAt = objectHasOwn(obj, "lastAssessedAt")
          ? obj.lastAssessedAt
          : undefined;
        if (lastAssessedAt !== null && typeof lastAssessedAt !== "string") {
          throw new AttestryError(
            `check.run: expected response.lastAssessedAt to be a string or null ` +
              `(got ${describeType(lastAssessedAt)})`,
          );
        }
        const checkedAt = objectHasOwn(obj, "checkedAt")
          ? obj.checkedAt
          : undefined;
        if (typeof checkedAt !== "string") {
          throw new AttestryError(
            `check.run: expected response.checkedAt to be a string ` +
              `(got ${describeType(checkedAt)})`,
          );
        }
        return result;
      });
  }
}

/**
 * Human-readable type description for error messages. Distinguishes
 * `null` and `array` from generic `object`. Duplicated in
 * `decisions.ts`, `incidents.ts`, `regulatory-changes.ts`,
 * `compliance-check.ts` per project pattern (small helper, leaf-
 * resource modules, no shared module yet).
 *
 * Every branch is reachable in this file:
 *   1. The top-level "expected object" path can see null OR scalar
 *      OR array (the negation of "non-null non-array object").
 *   2. The `compliant` / `score` / `activeAttestations` / `checkedAt`
 *      type guards can see any non-matching type (including null and
 *      array).
 *   3. The `lastAssessedAt` guard can see any type except string OR
 *      null (so the null branch is structurally unreachable from
 *      THAT call site — null would be filtered by the `!== null`
 *      check upstream).
 *   4. The `issues` guard can see any type except array (so the
 *      array branch is structurally unreachable from THAT call
 *      site).
 *   5. The `frameworks` non-array case can see any non-array type
 *      (so the array branch is structurally unreachable from THAT
 *      call site).
 *   6. The `frameworks[i]` non-string guard can see any
 *      non-string type.
 *
 * Multiple call sites means every branch IS reachable across the
 * module's invocations — no v8-ignore markers needed.
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
