// ─── Gate resource ──────────────────────────────────────────────────────────
//
// Wraps the CI/CD compliance gate surface (session 17):
//
//   - POST /api/v1/gate  Body: {systemId: <UUID>, minScore?: int 0-100,
//                              frameworks?: string[], failOnMissingAssessment?: boolean}
//
// Fifth non-decisions resource on `@attestry/sdk`. Sibling to
// `IncidentsResource`, `DecisionsResource`, `ChatResource`,
// `AuditLogResource`, `RegulatoryChangesResource`,
// `ComplianceCheckResource`, `CheckResource`. Single public method today
// (`evaluate`); the resource class exists as the landing pad for future
// gate methods if/when the kernel adds them (resource-class-per-kernel-
// resource convention, carry-forward invariant #43).
//
// Method name `evaluate` — matches the verb-method convention of
// `decisions.ingest`, `chat.send`, `auditLog.export`, `check.run`,
// `complianceCheck.check`. Pass/fail evaluation reads naturally as
// "evaluate the gate"; alternatives `run` / `check` / `execute` were
// considered and rejected (the first two clash naming-wise with sibling
// resources, the third is less idiomatic in the SDK). User-confirmed at
// session start.
//
// **Multi-permission UNION auth scope**: the kernel route gates on
// `requireApiKeyWithPermission(request, READ_ASSESSMENTS, READ_SYSTEMS)`
// which is OR semantics — `permissions.ts:53-55` uses `Array.some()`,
// NOT `.every()`. A key with EITHER permission (or `ADMIN`, or empty
// permissions for backwards-compat) succeeds. **HTTP 401** for
// no/invalid API key; **HTTP 403** for an authenticated key that has
// NEITHER required permission. Pin BOTH branches separately.
// Carry-forward invariant #45 (same shape as `check.run` —
// `READ_ASSESSMENTS` listed first in BOTH routes; `Array.some()` is
// order-insensitive but the kernel error message would echo the order
// declared).
//
// **Second SDK route to PRE-VALIDATE every Zod closed-spec rule
// synchronously** (first was `check.run`). The kernel uses
// `parseBody(request, gateSchema)` where `gateSchema` is
// `z.object({systemId: z.string().uuid(), minScore: z.number().int()
// .min(0).max(100).default(70), frameworks: z.array(z.string().min(1)
// .max(100)).max(20).optional(), failOnMissingAssessment: z.boolean()
// .default(true)})`. The SDK pre-validates EVERY closed-spec rule
// synchronously (UUID format on systemId, integer + range [0, 100] on
// minScore, boolean type on failOnMissingAssessment, array length cap
// + per-element string length on frameworks). The SDK's runtime
// checks always run regardless of TypeScript types — `as any` casts
// do NOT bypass them. So 422 from this route reaches consumers ONLY
// via kernel-side rule changes the SDK hasn't synced to. Codifies
// invariant #49 (carry-forward) and new invariant candidate #52
// (closed-default field pre-validation — when the schema has
// `.default(<value>)`, pre-validate AND omit the field from the body
// when the consumer omits it so the kernel applies its default).
//
// **Asymmetric cross-org error code**: cross-org `systemId` returns
// **404** (kernel's `and(eq id, eq orgId)` at route.ts:62-75 followed
// by "System not found or access denied" — mirror of `check.run`,
// `decisions.retrieve`, and `complianceCheck.check`'s systemId
// branch). Partial carry-forward of #47 (no orgName twin here, so
// only the 404 half applies). Note kernel emits the literal string
// `"System not found or access denied"` (longer than `check.run`'s
// `"System not found"`) — pin the exact string in the spec-diff drift
// suite.
//
// **Two silent kernel-side truncations** (faithful courier — SDK does
// NOT mask, new invariant candidate #50 carry-forward):
//   1. `assessments` row-population capped at 10 (`.limit(10)` at
//      route.ts:85). If the system has >10 assessment rows, the kernel
//      considers only the 10 most recent by `completedAt` DESC. A
//      system with the most-recent completed assessment in position
//      11+ would be misclassified as "no assessment found". **Tighter
//      cap than `check.run`'s `.limit(100)`** — gate is strictly less
//      defensive against many-assessment systems.
//   2. `remediationTasks` row-population capped at 100 (`.limit(100)`
//      at route.ts:154). If the assessment has >100 unresolved
//      remediation tasks, the 101st+ are invisible (cap is on
//      row-population BEFORE the filter-to-unresolved step). No
//      `total` field, no `hasMore` cursor.
// Each documented in JSDoc + README + drift-pinned with ANCHORED
// regex per session-16 second-review MEDIUM #4 (`.from(schema.X)
// [\s\S]*?.limit(N)`).
//
// **`score` defaults to `null` (NOT 0) when no completed assessment
// exists** (route.ts:118 + 131 — both no-assessment emit paths emit
// `score: null`). **Asymmetric with `check.run`** which used `0` as
// the default for "no completed assessment". Gate's `null` preserves
// the distinction at the type level and is more consumer-friendly
// for the CI/CD pipeline use case. Consumers should use `score ===
// null` (NOT `score === 0`) to detect the no-assessment branch.
//
// **`gate` is a STRING ENUM ("pass" | "fail"), NOT a boolean**
// (route.ts:114, 127, 181). The kernel uses string-enum form; the
// pre-build session-17 handoff predicted `passed: boolean` but route
// source contradicts that. The SDK contract uses the string-enum
// form to match the kernel emit.
//
// **`frameworks` filter is substring + case-insensitive
// (`.toLowerCase().includes()`), NOT exact-equality, NOT OR-overlap**
// (route.ts:94-96). **Asymmetric with `check.run`'s OR-overlap exact-
// equality** (route.ts:67-71 there). Consumer passing `["GDPR"]`
// matches an assessment with frameworks `["EU_GDPR_2024"]`,
// `["gdpr_compliance_v2"]`, etc. Documented as a kernel surface
// behavior; faithful courier.
//
// **`writeAuditLog` side effect** — gate WRITES one `gate.checked`
// audit log entry per call (route.ts:104-111 for the no-assessment
// emit + route.ts:165-178 for the normal emit). **NEW for a read-
// shaped SDK route**; new invariant candidate #53. Consumers should
// know each `gate.evaluate(...)` call leaves an auditable trail.
// Properties of the write: org-scoped, hash-chained (per
// `src/lib/api.ts:writeAuditLog`); **time-blocking but error-tolerant
// (NOT fire-and-forget)** — the kernel uses `await writeAuditLog(...)`
// (route.ts:104, 165) which awaits TWO DB ops inside the function
// (a SELECT to fetch the previous hash + an INSERT for the new entry,
// at `src/lib/api.ts:130-159`). The gate request's response latency
// includes the audit-log write time. **Error semantics are
// non-blocking**: `writeAuditLog` wraps its body in a try/catch that
// swallows errors and logs them, so a write FAILURE does NOT fail
// the gate request. Audit log writes are NOT counted against
// `decisionsPerMonth` (read-shaped from a quota perspective).
//
// **NO URIError defense on body fields** — POST body uses
// `JSON.stringify`, which handles lone UTF-16 surrogates by emitting
// them as literal `\uDxxx` escapes. The URIError defect class
// (carry-forward invariant #32) applies only to query-string paths
// (`encodeURIComponent`); this route has no query string and a fixed
// path. `assertEncodableQueryString` is NOT invoked here — explicit
// asymmetry vs `complianceCheck.check` / decisions / incidents /
// audit-log / regulatory-changes. Same asymmetry as `check.run`.
// Documented as D6.
//
// **Symmetric prototype-pollution defense** — module-load snapshot of
// `Object.hasOwn` applied to BOTH input AND response sides
// (carry-forward of session 16's second-hostile-review MEDIUM #3
// generalization). Without the response-side defense, a kernel
// regression that drops a response field combined with a hostile npm
// dep polluting `Object.prototype.<field>` would let the polluted
// value pass typeof-check via prototype walk. With the defense,
// missing own-property → describeType(undefined) → AttestryError. See
// build-round audit doc D7.
//
// Sync JSON request/response: reuses `client._request` and the
// existing `{success:true, data}` envelope-unwrap (carry-forward
// invariant #9). NO new SDK primitive needed. Returns
// `Promise<GateResponse>`.

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

// Module-load snapshot of `Object.hasOwn` — defends against a
// late-loading hostile/buggy npm dependency that overrides the global
// (e.g., `Object.hasOwn = () => true`). Without the snapshot, the
// prototype-pollution defenses below use whatever Object.hasOwn the
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
// Mirror of `check.run` / `complianceCheck.check`'s pattern. Used
// symmetrically on input AND response sides (session-16 second-
// hostile-review MEDIUM #3 carry-forward — defense on both
// boundaries).
const objectHasOwn = Object.hasOwn;

// UUID format regex — RFC 4122 hyphenated form (8-4-4-4-12 hex,
// case-insensitive). Matches Zod's `z.string().uuid()` regex
// effectively. Mirror of `check.run`'s UUID_REGEX. Drift-pinned in
// `sdk-drift.test.ts` spec-diff round so a kernel-side switch to a
// different UUID flavor (ULID, KSUID, etc.) fires before consumer
// regressions.
const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Input shape for `gate.evaluate`. Source-of-truth at kernel
 * `src/app/api/v1/gate/route.ts:31-36` (Zod schema).
 *
 * **`systemId`** — REQUIRED RFC 4122 hyphenated UUID. The SDK
 * pre-validates the format synchronously (`TypeError` for malformed
 * input — D2). The SDK's runtime check always runs regardless of
 * TypeScript types — `as any` casts do NOT bypass it. The kernel-side
 * Zod validation (422 fallback) only fires for kernel rule changes
 * the SDK hasn't synced to.
 *
 * **`minScore`** — OPTIONAL integer in `[0, 100]`. **Defaults to 70
 * kernel-side** (Zod `.default(70)`) when the SDK omits the field
 * from the body. Consumers who omit this get the implicit threshold
 * of 70 — a non-obvious default (carry-forward #44). Pre-validated
 * by the SDK: `typeof === "number"`, `Number.isInteger`, bounds
 * `[0, 100]` inclusive (`Number.isInteger` already rejects NaN /
 * Infinity, so no separate Number.isFinite check needed).
 *
 * **`frameworks`** — OPTIONAL array of up to 20 framework identifiers;
 * each string of length 1-100. **Substring + case-insensitive
 * matching** (kernel uses `aFrameworks.some((af) =>
 * af.toLowerCase().includes(f.toLowerCase()))` at route.ts:94-96).
 * **Asymmetric with `check.run`'s OR-overlap exact-equality** —
 * gate's looser substring match means `["GDPR"]` matches an
 * assessment with frameworks `["EU_GDPR_2024"]`, `["gdpr_compliance_v2"]`,
 * etc. When omitted (or empty), the kernel considers all completed
 * assessments. Empty array `[]` is accepted (Zod `.max(20)` permits
 * length 0; the kernel's `length > 0` guard at route.ts:90 short-
 * circuits the filter to "no filter").
 *
 * Open-spec field — the kernel does NOT enforce a closed enum of
 * valid framework names; any string within the length bounds is
 * accepted. Consumers should align their filter values with the
 * framework identifiers they used when creating assessments
 * (substring matching is forgiving but not magical).
 *
 * **`failOnMissingAssessment`** — OPTIONAL boolean. **Defaults to
 * `true` kernel-side** (Zod `.default(true)`) when the SDK omits the
 * field from the body. Consumers who omit this get strict behavior
 * (no assessment = fail). Pre-validated by the SDK: `typeof ===
 * "boolean"` (rejects truthy/falsy non-booleans like `1` / `"true"` /
 * `null`). Both defaults documented prominently per carry-forward
 * #44.
 */
export interface GateInput {
  /**
   * UUID of the system to evaluate. RFC 4122 hyphenated form
   * (8-4-4-4-12 hex, case-insensitive). Required.
   */
  systemId: string;
  /**
   * Pass/fail threshold (integer 0-100). **Defaults to 70 kernel-
   * side** when omitted.
   */
  minScore?: number;
  /**
   * Optional framework filter. Each element must be a non-empty
   * string of length ≤100; the array length must be ≤20.
   *
   * **Substring + case-insensitive matching** (kernel uses
   * `.toLowerCase().includes()` — asymmetric with `check.run`'s exact
   * equality). An assessment matches if any of its frameworks
   * contains any filter string as a substring (after lowercasing).
   */
  frameworks?: string[];
  /**
   * When `true` (the kernel default), a missing/incomplete
   * assessment causes the gate to return `gate: "fail"`. When
   * `false`, the gate returns `gate: "pass"` with `score: null` and
   * a `reason` indicating the relaxed mode.
   *
   * **Defaults to `true` kernel-side** when omitted (strict mode).
   */
  failOnMissingAssessment?: boolean;
}

/**
 * Structured gap entry returned in the `gaps` array for the normal
 * pass/fail emit path. Source-of-truth at kernel
 * `src/app/api/v1/gate/route.ts:38-43` (`GateGap` interface) +
 * route.ts:156-163 (the emit-site mapping).
 *
 * Built from `schema.remediationTasks` rows for the relevant
 * assessment, filtered to `status !== "resolved" && status !==
 * "wont_fix"` (route.ts:157).
 *
 * **`priority` is OPEN-SPEC** — the kernel does NOT enforce a closed
 * enum on `remediationTasks.priority`; it's a free-text string column.
 * The SDK exposes it as `string` (NOT `"critical" | "high" | "medium"
 * | "low"` enum) to preserve faithful-courier semantics. Consumers
 * needing closed-enum branching should filter post-hoc. **Note**: the
 * kernel uses the literal strings `"critical"` and `"high"` to compute
 * `criticalGaps` / `highGaps` counts (route.ts:193-194), so consumers
 * can safely match those two values; other values (`"medium"`,
 * `"low"`, custom) are not aggregated kernel-side.
 *
 * **`status` is also OPEN-SPEC** — the kernel filters out `"resolved"`
 * and `"wont_fix"` before emitting, so `status` will be neither of
 * those, but the kernel doesn't pin a closed enum on the remaining
 * values (e.g., `"open"`, `"in_progress"`, custom).
 */
export interface GateGap {
  /**
   * Stable requirement key the gap addresses (e.g., a framework
   * control identifier). Foreign key to `schema.remediationTasks
   * .requirementKey`.
   */
  requirementKey: string;
  /**
   * Human-readable title for the gap (the remediation task's title).
   */
  title: string;
  /**
   * Open-spec priority string. Kernel-aggregated values are
   * `"critical"` and `"high"` (counted into `criticalGaps` /
   * `highGaps` response fields); other values pass through verbatim.
   */
  priority: string;
  /**
   * Open-spec status string. Filtered kernel-side to NOT include
   * `"resolved"` or `"wont_fix"`; remaining values pass through.
   */
  status: string;
}

/**
 * Response shape returned by `gate.evaluate`. **UNION of 3 emit
 * paths** keyed by whether a `relevantAssessment` was found
 * (kernel route.ts:88-98) and the value of `failOnMissingAssessment`.
 *
 * Source-of-truth at kernel `src/app/api/v1/gate/route.ts`:
 *   - Path 1 — normal pass/fail (route.ts:180-199, 14 fields):
 *     `relevantAssessment` found; `score: number`; all 5 emit-only
 *     fields (`assessmentId`, `assessmentDate`, `gapCount`,
 *     `criticalGaps`, `highGaps`) are present.
 *   - Path 2 — fail-on-missing (route.ts:113-123, 9 fields):
 *     `failOnMissingAssessment=true` AND `relevantAssessment` is
 *     falsy; `gate: "fail"`; `score: null`; `gaps: []`; emit-only
 *     fields are ABSENT (not just `undefined` — own-property false).
 *   - Path 3 — pass-on-missing (route.ts:126-136, 9 fields):
 *     `failOnMissingAssessment=false` AND `relevantAssessment` is
 *     falsy; `gate: "pass"`; `score: null`; `gaps: []`; emit-only
 *     fields are ABSENT.
 *
 * **`relevantAssessment` is falsy in TWO distinct cases** (kernel
 * route.ts:88-98): (a) NO completed assessment exists within the 10
 * most-recent assessment rows (silent `.limit(10)` truncation), OR
 * (b) — with `frameworks` specified — no completed assessment within
 * those 10 rows matches ANY framework via substring + case-insensitive
 * comparison. A consumer setting `frameworks: ["UNMATCHED_FRAMEWORK"]`
 * on a system with multiple completed assessments would fall into
 * Paths 2/3 and see the literal `reason` string "No completed
 * assessment found for this system." — even though completed
 * assessments DO exist (they just don't match the filter). Consumers
 * should NOT use Paths 2/3 alone to conclude "this system has never
 * had a completed assessment".
 *
 * **Discriminator pattern** (mirrors `check.run`'s `lastAssessedAt ===
 * null`): use `response.score === null` to detect Paths 2 or 3.
 * `Object.hasOwn(response, "assessmentId") === false` is an
 * equivalent own-property-only alternative that is ALSO safe under
 * `Object.prototype.assessmentId` pollution. **Do NOT use
 * `response.assessmentId === undefined`** as the discriminator —
 * a hostile dep polluting `Object.prototype.assessmentId` makes the
 * `=== undefined` check return false (reads the polluted value via
 * prototype walk) even in Paths 2 + 3, silently misclassifying them
 * as Path 1. `score === null` is the canonical safe discriminator
 * (the SDK's P2 validator type-checks `score` as an own property
 * with `objectHasOwn`).
 */
export interface GateResponse {
  /**
   * Pass/fail verdict. **String enum, NOT a boolean** — kernel
   * emits the literal strings `"pass"` and `"fail"` (route.ts:114,
   * 127, 181). Consumers should NOT compare against `true`/`false`.
   *
   * **Type contract is closed (`"pass" | "fail"`); runtime is open
   * (faithful courier).** The SDK's P2 validator checks `typeof gate
   * === "string"` only — it does NOT reject unknown string values.
   * If a future kernel emits `gate: "warn"` / `gate: "skip"` / etc.
   * before the SDK is bumped, the value round-trips at runtime
   * (typed as the closed union at compile time, but holding the new
   * string at runtime). Consumers using exhaustive type-narrowing
   * (`if (gate === "pass") ... else /* TS: 'fail' *‍/`) would
   * misclassify an unknown value as the `"fail"` branch. The
   * kernel-side `gate` emit-sites are drift-pinned via the wire-
   * shape build-round pin so a kernel extension surfaces in the
   * drift suite before consumer regressions.
   */
  gate: "pass" | "fail";
  /**
   * The system's UUID (echoes the input — kernel route.ts:115, 128,
   * 182).
   */
  systemId: string;
  /**
   * The system's display name (`schema.aiSystems.name`,
   * route.ts:116, 129, 183). Open-spec string.
   */
  systemName: string;
  /**
   * Overall compliance score from the relevant completed
   * assessment's `scores.overall` jsonb field, IF that field is a
   * `number` (route.ts:141: `typeof scoresObj?.overall === "number"
   * ? scoresObj.overall : 0`).
   *
   * **`null` in the no-assessment paths** (Paths 2 + 3, route.ts:118
   * + 131). **Asymmetric with `check.run` which defaulted to 0**;
   * gate's `null` preserves the distinction at the type level.
   * Consumers should use `score === null` (NOT `score === 0`) to
   * detect the no-assessment branch.
   *
   * **In Path 1, `score: 0` is AMBIGUOUS** between (a) the assessment
   * legitimately scored zero, AND (b) the assessment row had a
   * missing or non-numeric `scores.overall` (e.g., `undefined`, a
   * string, or the literal jsonb string `"NaN"` — anything where
   * `typeof !== "number"`). The kernel collapses (b) to 0 via
   * `typeof === "number" ? value : 0` at `route.ts:141`. Consumers
   * CANNOT distinguish (a) from (b) from the wire response alone —
   * both cases emit `score: 0` with all 14 Path-1 fields present. A
   * CI/CD pipeline treating `gate: "fail" && score === 0` as a
   * "broken assessment data" signal would silently miss case (a).
   * Faithful courier; the SDK does NOT mask the kernel's collapse.
   *
   * **Note on IEEE-754 NaN in jsonb**: an exotic edge case — if the
   * jsonb stores IEEE-754 NaN as a number (NOT the string `"NaN"`),
   * `typeof === "number"` returns true, the kernel passes NaN
   * through, and `JSON.stringify(NaN)` emits `null` on the wire. The
   * SDK's P2 validator accepts `score: null` in Path 1 (`score`
   * typed `number | null`). Consumers would see `gate: "fail" &&
   * score: null` with the OTHER 12 Path-1 fields present (NOT the
   * 9-field Path-2/3 shape). This combination is the disambiguator
   * for NaN-in-jsonb specifically vs the no-assessment branch.
   *
   * In Path 1 the value is a `number` (typically 0..100 but
   * unbounded — the kernel does not clamp the jsonb value).
   *
   * Note: kernel internally uses `scoresObj?.overall` (NOT
   * `overallScore` like `check.run`) but the SDK contract is just
   * `score: number | null`; the jsonb key difference is invisible.
   */
  score: number | null;
  /**
   * Pass/fail threshold applied (number). Echoes the consumer's
   * input OR the kernel default (70) when omitted. ALWAYS present
   * in all 3 emit paths.
   */
  minScore: number;
  /**
   * In Paths 2 + 3 (no assessment): echoes the consumer's
   * `frameworks` input (or `[]` if omitted) — route.ts:120 + 133.
   * In Path 1: the **assessment's** frameworks (NOT the consumer's
   * filter) — route.ts:186-188. Type contract is the same
   * (`string[]`) but the SEMANTIC source differs by path.
   * Documented for completeness; consumers should treat this field
   * as "the frameworks relevant to this evaluation" without assuming
   * input echo.
   */
  frameworks: string[];
  /**
   * Structured gap list (kernel emit-site: route.ts:191 in Path 1;
   * empty array in Paths 2 + 3). Each gap is a `GateGap` row from
   * `schema.remediationTasks` filtered to `status !== "resolved" &&
   * status !== "wont_fix"`.
   *
   * **SILENTLY CAPPED AT 100 ROWS-CONSIDERED** — the kernel reads up
   * to 100 remediation tasks (`.limit(100)` at route.ts:154) and
   * filters within that subset. If the assessment has >100
   * unresolved gaps, the 101st+ are invisible. No `total`, no
   * `hasMore`. Faithful courier; documented in JSDoc + README.
   * Invariant candidate #50.
   */
  gaps: GateGap[];
  /**
   * Human-readable reason string. Path-specific contents:
   *   - Path 1: `"Score N meets minimum threshold of M."` or
   *     `"Score N is below minimum threshold of M. K unresolved
   *     gaps."` (route.ts:195-197).
   *   - Path 2: `"No completed assessment found for this system."`
   *     (route.ts:117).
   *   - Path 3: `"No assessment found but failOnMissingAssessment is
   *     false."` (route.ts:130).
   * Open-spec string; consumers should NOT pattern-match these for
   * branching (kernel may reword). Use `gate` + `score === null` for
   * programmatic decisions.
   */
  reason: string;
  /**
   * ISO-8601, server-generated at handler end via `new
   * Date().toISOString()` (route.ts:122, 135, 198). Uniquely
   * identifies this evaluation's snapshot — consumers may use it as
   * a freshness marker.
   */
  timestamp: string;
  /**
   * UUID of the assessment used (`schema.assessments.id`,
   * route.ts:189). **PRESENT ONLY in Path 1** — absent (own-property
   * false) in Paths 2 + 3. **Use `score === null` (or
   * `Object.hasOwn(response, "assessmentId") === false`) to detect
   * the no-assessment branch — NOT `response.assessmentId ===
   * undefined`** which reads via prototype walk and is unsafe under
   * `Object.prototype.assessmentId` pollution. See the top-level
   * GateResponse JSDoc's "Discriminator pattern" section for the full
   * rationale.
   */
  assessmentId?: string;
  /**
   * ISO-8601 of the assessment's `completedAt`, OR `null` if the
   * assessment row's `completedAt` column is null (rare — completed
   * assessments usually have a non-null timestamp, but the column
   * is nullable). **PRESENT ONLY in Path 1** — absent in Paths 2 + 3.
   */
  assessmentDate?: string | null;
  /**
   * Count of unresolved gaps after kernel filtering (NOT the raw
   * row count — `blockingGaps.length` at route.ts:192).
   * **PRESENT ONLY in Path 1**. Equivalent to `gaps.length` at the
   * call site; the kernel emits it as a convenience.
   */
  gapCount?: number;
  /**
   * Count of gaps with `priority === "critical"` (route.ts:193).
   * **PRESENT ONLY in Path 1**. Open-spec priority — the kernel
   * matches the literal string `"critical"`; consumers using custom
   * priority taxonomies won't see those aggregated here.
   */
  criticalGaps?: number;
  /**
   * Count of gaps with `priority === "high"` (route.ts:194).
   * **PRESENT ONLY in Path 1**. Same priority-string caveat as
   * `criticalGaps`.
   */
  highGaps?: number;
}

/**
 * `gate` resource — sibling to `IncidentsResource`,
 * `DecisionsResource`, `ChatResource`, `AuditLogResource`,
 * `RegulatoryChangesResource`, `ComplianceCheckResource`,
 * `CheckResource`. Today wraps a single endpoint (`evaluate`); the
 * class is the landing pad for future gate methods if the kernel
 * adds them (resource-class-per-kernel-resource convention, invariant
 * #43).
 */
export class GateResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Evaluate a CI/CD compliance gate for a single system. Returns a
   * structured pass/fail verdict (string enum `"pass"`/`"fail"`),
   * the score, the threshold, and a list of unresolved compliance
   * gaps. Designed for pipeline integration (CI build logs / GitHub
   * Actions / GitLab CI).
   *
   * **Three emit paths** — the response shape varies by whether a
   * completed assessment was found and the value of
   * `failOnMissingAssessment`:
   *   - **Path 1 (normal pass/fail)**: assessment found; `score: number`;
   *     all 14 fields present (including `assessmentId`,
   *     `assessmentDate`, `gapCount`, `criticalGaps`, `highGaps`).
   *   - **Path 2 (fail-on-missing)**: `failOnMissingAssessment=true`
   *     (the default) AND no completed assessment; `gate: "fail"`;
   *     `score: null`; `gaps: []`; emit-only fields ABSENT.
   *   - **Path 3 (pass-on-missing)**: `failOnMissingAssessment=false`
   *     AND no completed assessment; `gate: "pass"`; `score: null`;
   *     `gaps: []`; emit-only fields ABSENT.
   *
   * **Multi-permission UNION auth scope**: kernel uses
   * `requireApiKeyWithPermission(req, READ_ASSESSMENTS, READ_SYSTEMS)`
   * which is OR semantics (`Array.some()` at
   * `permissions.ts:53-55`). A key with EITHER permission (or
   * `ADMIN`, or null/empty permissions for backwards-compat)
   * succeeds. **HTTP 401** for no/invalid API key, **HTTP 403** for
   * an authenticated key that has NEITHER required permission. Pin
   * BOTH branches separately. Carry-forward invariant #45 (same
   * shape as `check.run`).
   *
   * **Asymmetric cross-org error code** (carry-forward #47, partial):
   * cross-org `systemId` returns **404** — the kernel's
   * `and(eq id, eq orgId)` at route.ts:62-75 collapses cross-org
   * to "System not found or access denied" (mirror of
   * `check.run`'s 404 surface; note kernel emits a LONGER literal
   * string than `check.run`'s `"System not found"`). Consumers
   * writing defensive error-handling logic must recognize: a 404
   * may be "not your org" OR "genuine missing UUID". No 403-via-
   * orgName twin here (no orgName input mode).
   *
   * **Two silent kernel-side truncations** (faithful courier;
   * documented as kernel surface gaps — JSDoc + README + drift
   * pinned with ANCHORED regex per session-16 second-review
   * MEDIUM #4). Invariant candidate #50:
   *   1. `assessments` row-population — `.limit(10)` at route.ts:85.
   *      If the system has >10 assessment rows, the kernel only
   *      considers the 10 most recent by `completedAt` DESC. The
   *      "relevant" completed assessment is found by `.find()` over
   *      those 10 — a system with the most-recent completed
   *      assessment in position 11+ would be misclassified as "no
   *      assessment found" (falling into Paths 2 or 3). **Tighter
   *      cap than `check.run`'s `.limit(100)`** — gate is strictly
   *      less defensive against many-assessment systems.
   *   2. `remediationTasks` row-population — `.limit(100)` at
   *      route.ts:154. If the assessment has >100 unresolved
   *      remediation tasks, the 101st+ are invisible. The cap
   *      applies BEFORE the filter-to-unresolved step
   *      (`status !== "resolved" && status !== "wont_fix"`), so the
   *      final `gaps.length` may be less than 100 even at the cap.
   *
   * **`score` defaults to `null` in the no-assessment paths**
   * (route.ts:118 + 131). **Asymmetric with `check.run` which used
   * `0`** — gate's `null` preserves the distinction at the type
   * level. Consumers should use `score === null` (NOT `score === 0`)
   * to detect Paths 2 or 3.
   *
   * **`gate` is a STRING ENUM, NOT a boolean** — kernel emits the
   * literal strings `"pass"` and `"fail"` (route.ts:114, 127, 181).
   * Type-narrowing via equality check: `if (result.gate === "pass")`.
   *
   * **`frameworks` filter is substring + case-insensitive** — kernel
   * uses `.toLowerCase().includes()` at route.ts:94-96. **Asymmetric
   * with `check.run`'s exact-equality OR-overlap**. Consumer passing
   * `["GDPR"]` matches an assessment with `["EU_GDPR_2024"]`,
   * `["gdpr_compliance_v2"]`, etc. Looser semantics may surprise.
   *
   * **`writeAuditLog` side effect** — every `gate.evaluate(...)`
   * call writes one `gate.checked` entry to the org's audit log
   * (route.ts:104-111 for the no-assessment paths, route.ts:165-178
   * for the normal path). Properties of the write:
   *   - Org-scoped, hash-chained (per `writeAuditLog` at
   *     `src/lib/api.ts:125-`).
   *   - **Time-blocking** but error-tolerant: the kernel uses
   *     `await writeAuditLog(...)`, which awaits two DB ops (SELECT
   *     previous-hash + INSERT new entry). The gate response latency
   *     INCLUDES the audit-log write time — a slow audit-log DB will
   *     delay every gate.evaluate() response. Error semantics ARE
   *     non-blocking: `writeAuditLog` wraps its body in a try/catch
   *     that swallows errors and logs them, so a write FAILURE does
   *     NOT fail the gate request.
   *   - NOT counted against `decisionsPerMonth` quota (gate is read-
   *     shaped from a quota perspective).
   *
   * **Defaults applied by the kernel when fields are omitted**
   * (carry-forward #44, non-obvious-default-filter pattern):
   *   - `minScore` defaults to **70** (Zod `.default(70)` at
   *     route.ts:33). Consumers who omit this field get the implicit
   *     threshold of 70.
   *   - `failOnMissingAssessment` defaults to **true** (Zod
   *     `.default(true)` at route.ts:35). Consumers who omit this
   *     get strict behavior.
   * The SDK omits these fields from the request body when the
   * consumer omits them, so the kernel applies its defaults
   * (invariant candidate #52).
   *
   * Errors — ordered by kernel firing precedence (rate-limit → auth
   * → Zod body validation → DB lookup → internal). A request with
   * multiple problems surfaces ONLY the highest-precedence one. For
   * example: a request with bad auth AND a malformed body surfaces
   * 401, not 422; a request with valid auth + bad body AND a cross-
   * org systemId surfaces 422, not 404.
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     (auto-retried by default — invariant #18; per-IP rate-limit
   *     key `v1-gate:${ip}`).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *     Fires AFTER rate-limit but BEFORE input validation.
   *   - `AttestryAPIError` (status 403) — authenticated key has
   *     NEITHER `READ_ASSESSMENTS` nor `READ_SYSTEMS` (the
   *     permission-check branch). Single test case — the union-auth
   *     pattern collapses three intuition-suggesting cases to one.
   *   - `AttestryAPIError` (status 422) — Zod schema rejection
   *     (kernel's `BodyParseError` surface — `parseBody(request,
   *     gateSchema)` failed). **Fires BEFORE the systemId/cross-
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
   *     minScore int + range, failOnMissingAssessment boolean,
   *     framework element length 1-100, array length ≤20) AND the
   *     runtime checks always run regardless of TypeScript types —
   *     `as any` casts do NOT bypass them. So 422 reaches consumers
   *     ONLY via kernel rule changes the SDK hasn't synced to.
   *     Invariant candidate #51.
   *   - `AttestryAPIError` (status 404) — system not found OR
   *     cross-org systemId (kernel collapses to "System not found
   *     or access denied", route.ts:74). Fires AFTER Zod validation
   *     (422).
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`).
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired (pre-aborted or mid-flight).
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (not an object, wrong type on any
   *     field).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard before body
   *     parsing).
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation (null / array / non-object input,
   *     missing systemId, invalid UUID format, non-integer minScore,
   *     out-of-range minScore, non-boolean failOnMissingAssessment,
   *     frameworks array too long, frameworks element wrong type or
   *     length).
   *
   * **Notably ABSENT**:
   *   - **No 400** — all input validation is Zod (422).
   *   - **No 413** — body size limit not explicit.
   *   - **No 402** — read-shaped, doesn't count against
   *     decisionsPerMonth quota (despite the audit-log side effect).
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
   *     lone-surrogate URIError defense (D6 — POST body uses
   *     JSON.stringify).
   *   - `input.minScore` (when own-property present, value not
   *     undefined): must be a `number`, an integer (`Number.isInteger`,
   *     which excludes NaN / ±Infinity automatically), and within
   *     `[0, 100]` inclusive. Mirrors Zod's
   *     `z.number().int().min(0).max(100)` exactly (D3).
   *   - `input.failOnMissingAssessment` (when own-property present,
   *     value not undefined): must be a `boolean` (`typeof ===
   *     "boolean"`). Mirrors Zod's `z.boolean()` exactly (D4).
   *   - `input.frameworks` (when own-property present, value not
   *     undefined): must be an array of ≤20 strings, each of length
   *     1-100. SDK pre-validates each rule (D5). Array is
   *     snapshotted via `Array.from` for TOCTOU defense.
   *
   * **Response-shape validation** (P2 hardening — D8, symmetric
   * defense on response side per D7):
   *   - Rejects with `AttestryError` if the kernel response isn't a
   *     non-null, non-array object.
   *   - Rejects if `gate` isn't a string.
   *   - Rejects if `systemId` / `systemName` / `reason` / `timestamp`
   *     aren't strings.
   *   - Rejects if `score` isn't a number OR null.
   *   - Rejects if `minScore` isn't a number.
   *   - Rejects if `frameworks` / `gaps` aren't arrays.
   *   - Rejects if `assessmentId` (when own-present) isn't a string.
   *   - Rejects if `assessmentDate` (when own-present) isn't a
   *     string or null.
   *   - Rejects if `gapCount` / `criticalGaps` / `highGaps` (when
   *     own-present) aren't numbers.
   *   - Each response field read goes through the module-load
   *     `objectHasOwn` snapshot (symmetric to the input-side
   *     prototype-pollution defense — D7 generalized to the response
   *     boundary). A hostile npm dep that pollutes
   *     `Object.prototype.<field>` cannot mask a kernel regression
   *     where the field is missing — the SDK requires the field to
   *     be a kernel-emitted own property.
   *   - Per-gap-element shape (open-spec strings) is faithful-
   *     courier — NOT validated.
   *
   * **Transport-shape validation** (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with
   *     a non-`application/json` Content-Type.
   *
   * @example Basic gate evaluation (defaults: minScore=70, failOnMissingAssessment=true)
   * ```ts
   * const result = await client.gate.evaluate({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   * });
   * if (result.gate === "pass") {
   *   console.log("OK to deploy — score:", result.score);
   * } else if (result.score === null) {
   *   console.warn("No completed assessment — failing strict-mode gate");
   * } else {
   *   // Path 1 fail: emit-only fields are present at runtime, but
   *   // typed as optional. Use `??` (or a Path-1 narrowing check on
   *   // `assessmentId`) so the example compiles without `!` or `as`.
   *   console.warn(
   *     `Score ${result.score} below threshold ${result.minScore};`,
   *     `${result.gapCount ?? 0} unresolved gaps (${result.criticalGaps ?? 0} critical)`
   *   );
   * }
   * ```
   *
   * @example Strict threshold + framework filter
   * ```ts
   * const euOnly = await client.gate.evaluate({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   *   minScore: 85,
   *   frameworks: ["EU_AI_ACT", "ISO_42001"],
   * });
   * ```
   *
   * @example Pre-launch / staging — allow missing assessments
   * ```ts
   * const lenient = await client.gate.evaluate({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   *   failOnMissingAssessment: false,
   * });
   * // `lenient.gate === "pass"` even without a completed assessment.
   * ```
   */
  evaluate(
    input: GateInput,
    options?: RequestOptions,
  ): Promise<GateResponse> {
    // Top-level shape — input is REQUIRED. typeof null === "object"
    // and typeof [] === "object", so guard both explicitly.
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "gate.evaluate: `input` must be a non-null object with `systemId`",
      );
    }

    // Snapshot each field's value EXACTLY ONCE up front via the
    // own-property indexer, then operate only on the locals
    // downstream. Three motivations:
    //   1. **Prototype-pollution defense (generalization of #48)**:
    //      `Object.prototype.systemId = "<some-uuid>"` (set somewhere
    //      else in the consumer's process) does NOT trick the SDK
    //      into silently sending the polluted value when the user
    //      passes `{}`. Use the module-load snapshot (`objectHasOwn`)
    //      so a late-loading dep that overrides the global doesn't
    //      defeat the defense.
    //   2. **TOCTOU defense**: a Proxy or getter-defining input could
    //      yield DIFFERENT values across multiple reads. Snapshotting
    //      once collapses validate-then-send to a single read per
    //      field; the validated value is provably the value sent.
    //   3. An explicit `{systemId: "..."}` (no other fields) is
    //      treated as those-fields-omitted — `objectHasOwn` correctly
    //      returns false on missing keys.
    const hasSystemId = objectHasOwn(input, "systemId");
    const systemIdRaw: unknown = hasSystemId
      ? readInputField(input, "systemId", "gate.evaluate")
      : undefined;
    const hasMinScore = objectHasOwn(input, "minScore");
    const minScoreRaw: unknown = hasMinScore
      ? readInputField(input, "minScore", "gate.evaluate")
      : undefined;
    const hasFrameworks = objectHasOwn(input, "frameworks");
    const frameworksRaw: unknown = hasFrameworks
      ? readInputField(input, "frameworks", "gate.evaluate")
      : undefined;
    const hasFailOnMissing = objectHasOwn(input, "failOnMissingAssessment");
    const failOnMissingRaw: unknown = hasFailOnMissing
      ? readInputField(input, "failOnMissingAssessment", "gate.evaluate")
      : undefined;

    // systemId is REQUIRED. Reject missing-or-undefined first with a
    // clear "required" message; subsequent checks assume present.
    if (!hasSystemId || systemIdRaw === undefined) {
      throw new TypeError(
        "gate.evaluate: `systemId` is required",
      );
    }
    if (typeof systemIdRaw !== "string" || systemIdRaw.length === 0) {
      throw new TypeError(
        "gate.evaluate: `systemId` must be a non-empty string",
      );
    }
    // UUID format pre-validation (D2 — SDK matches kernel's Zod
    // `z.string().uuid()` closed-spec rule). Mirror of `check.run`.
    // Drift-pinned in spec-diff round.
    if (!UUID_REGEX.test(systemIdRaw)) {
      throw new TypeError(
        "gate.evaluate: `systemId` must be an RFC 4122 hyphenated UUID " +
          "(matched regex: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" +
          "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/)",
      );
    }

    // minScore — optional. When provided, MUST mirror Zod's
    // `z.number().int().min(0).max(100)` exactly:
    //   - typeof === "number"
    //   - Number.isInteger (which already rejects NaN / ±Infinity,
    //     since neither is an integer per ECMA-262 spec)
    //   - within [0, 100] inclusive
    // (D3 — SDK pre-validates closed-spec rule + closed-default
    // candidate #52.)
    let validatedMinScore: number | undefined;
    if (hasMinScore && minScoreRaw !== undefined) {
      if (typeof minScoreRaw !== "number") {
        throw new TypeError(
          `gate.evaluate: \`minScore\` must be a number when provided ` +
            `(got ${describeType(minScoreRaw)})`,
        );
      }
      if (!Number.isInteger(minScoreRaw)) {
        throw new TypeError(
          `gate.evaluate: \`minScore\` must be a finite integer ` +
            `(got ${minScoreRaw})`,
        );
      }
      if (minScoreRaw < 0 || minScoreRaw > 100) {
        throw new TypeError(
          `gate.evaluate: \`minScore\` must be in the range [0, 100] ` +
            `(got ${minScoreRaw})`,
        );
      }
      validatedMinScore = minScoreRaw;
    }

    // failOnMissingAssessment — optional boolean. When provided, MUST
    // mirror Zod's `z.boolean()` exactly:
    //   - typeof === "boolean"
    // (D4 — SDK pre-validates closed-spec rule + closed-default
    // candidate #52. Truthy/falsy non-booleans like 0 / 1 / "true" /
    // null are rejected.)
    let validatedFailOnMissing: boolean | undefined;
    if (hasFailOnMissing && failOnMissingRaw !== undefined) {
      if (typeof failOnMissingRaw !== "boolean") {
        throw new TypeError(
          `gate.evaluate: \`failOnMissingAssessment\` must be a boolean ` +
            `when provided (got ${describeType(failOnMissingRaw)})`,
        );
      }
      validatedFailOnMissing = failOnMissingRaw;
    }

    // frameworks — optional. Carry-forward from check.run exactly:
    //   - Array (not other iterable).
    //   - Length ≤20.
    //   - Each element a string of length 1-100.
    // Snapshot via Array.from up front so a Proxy whose `.length` or
    // `[i]` changes between reads can't slip past validation.
    let validatedFrameworks: string[] | undefined;
    if (hasFrameworks && frameworksRaw !== undefined) {
      if (!Array.isArray(frameworksRaw)) {
        throw new TypeError(
          `gate.evaluate: \`frameworks\` must be an array when provided ` +
            `(got ${describeType(frameworksRaw)})`,
        );
      }
      const snapshot = Array.from(frameworksRaw as ArrayLike<unknown>);
      if (snapshot.length > 20) {
        throw new TypeError(
          `gate.evaluate: \`frameworks\` array exceeds the kernel's max ` +
            `length of 20 (got ${snapshot.length})`,
        );
      }
      for (let i = 0; i < snapshot.length; i++) {
        const elem = snapshot[i];
        if (typeof elem !== "string") {
          throw new TypeError(
            `gate.evaluate: \`frameworks[${i}]\` must be a string ` +
              `(got ${describeType(elem)})`,
          );
        }
        if (elem.length === 0) {
          throw new TypeError(
            `gate.evaluate: \`frameworks[${i}]\` must be a non-empty string`,
          );
        }
        if (elem.length > 100) {
          throw new TypeError(
            `gate.evaluate: \`frameworks[${i}]\` exceeds the kernel's max ` +
              `length of 100 chars (got ${elem.length})`,
          );
        }
      }
      validatedFrameworks = snapshot as string[];
    }

    // Construct the body. Omit any optional field the consumer
    // omitted — the kernel's Zod schema applies defaults
    // (minScore=70, failOnMissingAssessment=true) when fields are
    // absent. Closed-default invariant candidate #52: consumer
    // omission → kernel default applied.
    const body: {
      systemId: string;
      minScore?: number;
      frameworks?: string[];
      failOnMissingAssessment?: boolean;
    } = {
      systemId: systemIdRaw,
    };
    if (validatedMinScore !== undefined) {
      body.minScore = validatedMinScore;
    }
    if (validatedFrameworks !== undefined) {
      body.frameworks = validatedFrameworks;
    }
    if (validatedFailOnMissing !== undefined) {
      body.failOnMissingAssessment = validatedFailOnMissing;
    }

    return this.client
      ._request<GateResponse>({
        method: "POST",
        path: "/api/v1/gate",
        body,
        options,
      })
      .then((result) => {
        // P2 hardening: validate every documented field type.
        // Symmetric prototype-pollution defense — read EACH field
        // via `objectHasOwn` so a hostile npm dep polluting
        // `Object.prototype.<field>` cannot mask a kernel regression
        // that drops the field (per session-16 second-hostile-review
        // MEDIUM #3 carry-forward — defense applied on both input AND
        // response boundaries).
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `gate.evaluate: expected an object response from the kernel ` +
              `(got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;

        // Always-present fields (9 in all 3 emit paths).
        const gate = objectHasOwn(obj, "gate") ? obj.gate : undefined;
        if (typeof gate !== "string") {
          throw new AttestryError(
            `gate.evaluate: expected response.gate to be a string ` +
              `(got ${describeType(gate)})`,
          );
        }
        const systemId = objectHasOwn(obj, "systemId")
          ? obj.systemId
          : undefined;
        if (typeof systemId !== "string") {
          throw new AttestryError(
            `gate.evaluate: expected response.systemId to be a string ` +
              `(got ${describeType(systemId)})`,
          );
        }
        const systemName = objectHasOwn(obj, "systemName")
          ? obj.systemName
          : undefined;
        if (typeof systemName !== "string") {
          throw new AttestryError(
            `gate.evaluate: expected response.systemName to be a string ` +
              `(got ${describeType(systemName)})`,
          );
        }
        const score = objectHasOwn(obj, "score") ? obj.score : undefined;
        if (score !== null && typeof score !== "number") {
          throw new AttestryError(
            `gate.evaluate: expected response.score to be a number or null ` +
              `(got ${describeType(score)})`,
          );
        }
        const minScore = objectHasOwn(obj, "minScore")
          ? obj.minScore
          : undefined;
        if (typeof minScore !== "number") {
          throw new AttestryError(
            `gate.evaluate: expected response.minScore to be a number ` +
              `(got ${describeType(minScore)})`,
          );
        }
        const frameworks = objectHasOwn(obj, "frameworks")
          ? obj.frameworks
          : undefined;
        if (!Array.isArray(frameworks)) {
          throw new AttestryError(
            `gate.evaluate: expected response.frameworks to be an array ` +
              `(got ${describeType(frameworks)})`,
          );
        }
        const gaps = objectHasOwn(obj, "gaps") ? obj.gaps : undefined;
        if (!Array.isArray(gaps)) {
          throw new AttestryError(
            `gate.evaluate: expected response.gaps to be an array ` +
              `(got ${describeType(gaps)})`,
          );
        }
        const reason = objectHasOwn(obj, "reason") ? obj.reason : undefined;
        if (typeof reason !== "string") {
          throw new AttestryError(
            `gate.evaluate: expected response.reason to be a string ` +
              `(got ${describeType(reason)})`,
          );
        }
        const timestamp = objectHasOwn(obj, "timestamp")
          ? obj.timestamp
          : undefined;
        if (typeof timestamp !== "string") {
          throw new AttestryError(
            `gate.evaluate: expected response.timestamp to be a string ` +
              `(got ${describeType(timestamp)})`,
          );
        }

        // Emit-only fields (5 in Path 1 only). Validate ONLY when
        // own-present; absence is the correct "no assessment" shape
        // (Paths 2 + 3), not an error. Per-field own-property check
        // mirrors the always-present fields' defense pattern.
        if (objectHasOwn(obj, "assessmentId")) {
          const assessmentId = obj.assessmentId;
          if (typeof assessmentId !== "string") {
            throw new AttestryError(
              `gate.evaluate: expected response.assessmentId to be a string ` +
                `when present (got ${describeType(assessmentId)})`,
            );
          }
        }
        if (objectHasOwn(obj, "assessmentDate")) {
          const assessmentDate = obj.assessmentDate;
          if (
            assessmentDate !== null &&
            typeof assessmentDate !== "string"
          ) {
            throw new AttestryError(
              `gate.evaluate: expected response.assessmentDate to be a string or null ` +
                `when present (got ${describeType(assessmentDate)})`,
            );
          }
        }
        if (objectHasOwn(obj, "gapCount")) {
          const gapCount = obj.gapCount;
          if (typeof gapCount !== "number") {
            throw new AttestryError(
              `gate.evaluate: expected response.gapCount to be a number ` +
                `when present (got ${describeType(gapCount)})`,
            );
          }
        }
        if (objectHasOwn(obj, "criticalGaps")) {
          const criticalGaps = obj.criticalGaps;
          if (typeof criticalGaps !== "number") {
            throw new AttestryError(
              `gate.evaluate: expected response.criticalGaps to be a number ` +
                `when present (got ${describeType(criticalGaps)})`,
            );
          }
        }
        if (objectHasOwn(obj, "highGaps")) {
          const highGaps = obj.highGaps;
          if (typeof highGaps !== "number") {
            throw new AttestryError(
              `gate.evaluate: expected response.highGaps to be a number ` +
                `when present (got ${describeType(highGaps)})`,
            );
          }
        }
        return result;
      });
  }
}

/**
 * Human-readable type description for error messages. Distinguishes
 * `null` and `array` from generic `object`. Duplicated in
 * `decisions.ts`, `incidents.ts`, `regulatory-changes.ts`,
 * `compliance-check.ts`, `check.ts` per project pattern (small
 * helper, leaf-resource modules, no shared module yet).
 *
 * Every branch is reachable in this file through the multiple call
 * sites (top-level shape, each field type guard, frameworks
 * non-array, frameworks element non-string).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
