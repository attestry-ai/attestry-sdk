// ─── ShipGate resource ──────────────────────────────────────────────────────
//
// Wraps the CI/CD ship-gate check surface (Prompt E.2 — session 20):
//
//   - POST /api/v1/ship-gate/check  Body: {systemId: <UUID>, attestationId: <string 1-256>}
//
// Seventh non-decisions resource on `@attestry/sdk`. Sibling to
// `IncidentsResource`, `DecisionsResource`, `ChatResource`,
// `AuditLogResource`, `RegulatoryChangesResource`,
// `ComplianceCheckResource`, `CheckResource`, `GateResource`,
// `BatchResource`. Single public method today (`check`); the resource
// class is the landing pad for future ship-gate methods if/when the
// kernel adds them (resource-class-per-kernel-resource convention,
// invariant #43).
//
// Method name `check` — matches the kernel endpoint name (POST
// /api/v1/ship-gate/check). Alternative `run` was considered for
// symmetry with `check.run` and rejected because the kernel endpoint
// is named `/check` and the existing `check.run` already occupies the
// `.run` verb at the SDK level. User-confirmed at session 20 start.
//
// **Distinct from `gate.evaluate`** — `gate.evaluate` is a synchronous
// compliance-score gate (pass/fail on assessment scores); `shipGate.check`
// is a multi-approver workflow gate that asks "is an in-flight approval
// chain blocking THIS build?". Different lifecycle (gate.evaluate has
// no state; shipGate has the gated → released/rejected/timed_out
// state machine bound to an approval chain execution). Different
// kernel routes and different consumer audience (gate.evaluate for
// CI score gates; shipGate.check for human-approver gates).
//
// **Multi-permission UNION auth scope**: the kernel route gates on
// `requireApiKeyWithPermission(request, READ_SYSTEMS, READ_ASSESSMENTS)`
// which is OR semantics — `permissions.ts:53-55` uses `Array.some()`.
// A key with EITHER permission (or `ADMIN`, or empty permissions for
// backwards-compat) succeeds. **HTTP 401** for no/invalid API key;
// **HTTP 403** for an authenticated key that has NEITHER required
// permission. Pin BOTH branches separately. Carry-forward invariant
// #45. **NOTE — argument order is READ_SYSTEMS FIRST** (asymmetric
// with `check.run` and `gate.evaluate` which list READ_ASSESSMENTS
// first); `Array.some()` is order-insensitive, but the kernel error
// message would echo the order declared. Drift-pinned exact-arglist
// in the spec-diff round.
//
// **Fourth SDK route to PRE-VALIDATE every Zod closed-spec rule
// synchronously** (after `check.run`, `gate.evaluate`, and
// `batch.submit`). The kernel
// uses `parseBody(request, checkSchema)` where `checkSchema` is
// `z.object({systemId: z.string().uuid(), attestationId: z.string()
// .min(1).max(MAX_ATTESTATION_ID_LENGTH)})`. The SDK pre-validates BOTH
// closed-spec rules synchronously (UUID format on systemId, string
// length bounds [1, 256] on attestationId). The SDK's runtime checks
// always run regardless of TypeScript types — `as any` casts do NOT
// bypass them. So 422 from this route reaches consumers ONLY via
// kernel-side rule changes the SDK hasn't synced to. Codifies
// invariants #49 + #51.
//
// **Variadic four-shape response** — SDK exposes a single
// `ShipGateCheckResponse` type with `gated: boolean` as the ALWAYS-
// present anchor field and 5 OPTIONAL own-property fields. The 4
// emit shapes (kernel `formatShipGateCheckResult` at
// `ship-gates.ts:249-312` + the default-permissive `{ gated: false }`
// short-circuit at `ship-gates.ts:544`):
//   - Shape A (no gate exists): `{ gated: false }` — 1 field
//     (default-permissive — the gate is opt-in; missing
//     `(system_id, attestation_id)` row → SDK returns this shape).
//   - Shape B (released): `{ gated: false, state: "released",
//     executionId, chainId }` — 4 fields. The approval chain approved
//     the deployment; the build proceeds.
//   - Shape C (rejected/timed_out): `{ gated: true, reason: "rejected"
//     | "timed_out", approvers_pending: [], state: "rejected" |
//     "timed_out", executionId, chainId }` — 6 fields. The approval
//     chain went terminal in a build-blocking state. `approvers_pending`
//     is always `[]` (nobody is pending on a closed chain).
//   - Shape D (gated): `{ gated: true, reason: "awaiting_approvers",
//     approvers_pending: [<UUIDs>], state: "gated", executionId,
//     chainId }` — 6 fields. The approval chain is in-flight;
//     `approvers_pending` lists the userIds still owed a decision
//     (pool-order, post-decided filtering — see kernel
//     `computeApproversPending` for the full algorithm).
// Discriminate via `gated === true` (closed-enum boolean), NOT
// `reason === undefined` (prototype-pollution-unsafe — see D7).
//
// **`approvers_pending` is SNAKE_CASE on the wire** — the kernel emits
// the literal field name `approvers_pending` (NOT `approversPending`),
// asymmetric with the rest of the SDK's camelCase response surface.
// This matches the master-plan spec contract (line 5369) verbatim and
// is preserved here as-is. Consumers must use the snake_case spelling
// to read the field. Drift-pinned in the spec-diff round.
//
// **`reason` is a closed-string-enum** (`"awaiting_approvers" |
// "rejected" | "timed_out"`) at the TYPE level; the P2 runtime
// validator checks `typeof === "string"` only (faithful courier —
// mirror of gate.evaluate's `gate: "pass" | "fail"` pattern). If a
// future kernel emits a new reason code (e.g., `"escalated"`) before
// the SDK is bumped, the value round-trips at runtime. Consumers
// using exhaustive type-narrowing would misclassify the new value.
// The kernel emit sites are drift-pinned via the wire-shape build-
// round pin so a kernel extension surfaces in the drift suite before
// consumer regressions.
//
// **`state` is also a closed-string-enum** (`"gated" | "released" |
// "rejected" | "timed_out"`) — 4 values. Same faithful-courier
// treatment as `reason`. Drift-pinned in build-round wire pin.
//
// **Reconciliation-on-read inside transaction** — when the linked
// `approval_chain_executions` row has gone terminal (approved /
// rejected / timed_out) but the ship_gate row still says `gated`,
// the kernel's `checkShipGate` advances the gate to the corresponding
// terminal state inside `SELECT … FOR UPDATE` (see
// `ship-gates.ts:567-584`). The SDK does NOT observe the
// reconciliation step — only the post-reconciliation shape. A
// consumer calling `check()` twice in quick succession on a chain
// that just completed sees the gated-state shape on call 1 (if
// reconciliation hadn't fired yet) and the terminal shape on call 2.
// **Documented kernel surface behavior, faithful courier**.
//
// **`writeAuditLog` side effect** — every `shipGate.check(...)` call
// writes one `ship_gate.checked` entry to the org's audit log
// (route.ts:73-87). Properties of the write:
//   - Org-scoped, hash-chained (per `writeAuditLog`).
//   - **Time-blocking** but error-tolerant: the kernel uses
//     `await writeAuditLog(...)`, which awaits two DB ops (SELECT
//     previous-hash + INSERT new entry, at `src/lib/api.ts:130-159`).
//     The check response latency INCLUDES the audit-log write time —
//     a slow audit-log DB will delay every shipGate.check() response.
//     Error semantics ARE non-blocking: `writeAuditLog` wraps its
//     body in a try/catch that swallows + logs errors, so a write
//     FAILURE does NOT fail the check request.
//   - NOT counted against `decisionsPerMonth` quota (read-shaped from
//     a quota perspective). Invariant candidate #53 carry-forward
//     (matches `gate.evaluate`'s pattern).
//
// **Kernel-side 15-second timeout** (`maxDuration = 15` at
// `route.ts:24`). **Same as `gate.evaluate`'s 15s; tighter than
// `auditLog.verifyChain`'s 30s.** Ship-gate's transaction has a
// SELECT FOR UPDATE + up to 4 follow-up reads + an optional UPDATE
// on the reconcile path, and the kernel team budgeted 15s as
// sufficient for the worst case. The SDK does NOT enforce a client-
// side timeout (consumers manage via `options.signal`), but the
// kernel's function-runtime cap bounds the request latency on the
// server side. A future kernel raise (e.g., 15 → 30s) would relax
// this; CI pipeline timeout settings should be revisited. Drift-
// pinned in build-round Pin 7.
//
// **Documented kernel-side cascade-gap surfaces — TWO distinct paths**:
//   1. **Execution-missing → HTTP 404** (named-error path). The kernel
//      route maps `ShipGateExecutionNotFoundError` to 404 at
//      route.ts:97-99. This error is thrown by `checkShipGate` ONLY
//      when the inner `executionRows.length === 0` defensive branch
//      fires (`ship-gates.ts:559-564`) — i.e., when a `ship_gates`
//      row references an `executionId` whose row is missing in
//      `approval_chain_executions`.
//   2. **Chain-missing → HTTP 500 (scrubbed)** (plain-Error path).
//      A SEPARATE defensive branch in `checkShipGate` at
//      `ship-gates.ts:610-617` throws a PLAIN `Error` (NOT a named
//      ship-gate error class) when a `ship_gates` row → execution
//      → chain reference is broken on the LAST hop (execution row
//      exists but its `chainId` doesn't resolve to an
//      `approval_chains` row in the same org). The route's catch
//      block has only three `instanceof` arms (`AuthError`,
//      `BodyParseError`, `ShipGateExecutionNotFoundError`); a plain
//      `Error` falls through to `internalErrorResponse → 500` with
//      the scrubbed message "An internal error occurred. Please
//      try again later." Defense-in-depth refusal posture per the
//      kernel comment; the caller can't observe the chain-missing
//      condition distinctly from any other internal error.
// Both branches should be unreachable via the RESTRICT FK + filter-
// by-orgId pattern in normal operation; both are documented as
// "only reachable via direct DB intervention or a cascade-behavior
// gap." Faithful courier: the SDK surfaces whichever status the
// kernel chose (404 vs 500), but consumers running SIEM /
// observability filters on cascade-gap-404 events should know the
// second branch hides as 500 (NOT 404).
//
// **No path-segment URIError defense** — POST body uses
// `JSON.stringify`, which handles lone UTF-16 surrogates by emitting
// them as literal `\uDxxx` escapes. The URIError defect class
// (carry-forward invariant #32) applies only to query-string paths
// (`encodeURIComponent`); this route has no query string and a fixed
// path. `assertEncodableQueryString` is NOT invoked here — explicit
// asymmetry vs `complianceCheck.check` / decisions / incidents /
// audit-log / regulatory-changes. Same asymmetry as `check.run` /
// `gate.evaluate`.
//
// **Symmetric prototype-pollution defense** — module-load snapshot of
// `Object.hasOwn` applied to BOTH input AND response sides. Mirror of
// `gate.ts` / `audit-log.ts` / `check.ts` / `batch.ts` pattern.
// Without the response-side defense, a kernel regression that drops
// a response field combined with a hostile npm dep polluting
// `Object.prototype.<field>` would let the polluted value pass
// typeof-check via prototype walk. With the defense, missing own-
// property → describeType(undefined) → AttestryError.
//
// Sync JSON request/response: reuses `client._request` and the
// existing `{success:true, data}` envelope-unwrap (carry-forward
// invariant #9). NO new SDK primitive needed. Returns
// `Promise<ShipGateCheckResponse>`.

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
// Mirror of `audit-log.ts` / `batch.ts` / `gate.ts` / `check.ts` /
// `compliance-check.ts` pattern. Used symmetrically on input AND
// response sides (input boundary is non-empty here — 2 fields:
// systemId + attestationId).
const objectHasOwn = Object.hasOwn;

// UUID format regex — RFC 4122 hyphenated form (8-4-4-4-12 hex,
// case-insensitive). Matches Zod's `z.string().uuid()` regex
// effectively. Mirror of `check.ts` / `gate.ts` UUID_REGEX. Drift-
// pinned in `sdk-drift.test.ts` spec-diff round so a kernel-side
// switch to a different UUID flavor (ULID, KSUID, etc.) fires before
// consumer regressions.
const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// Max attestation-id length — mirrors the kernel constant
// `MAX_ATTESTATION_ID_LENGTH = 256` at `src/lib/workflow/ship-gates.ts:106`.
// Pre-validated SDK-side (D4); drift-pinned in spec-diff round so a
// kernel-side relax/tighten surfaces before consumer regressions.
const MAX_ATTESTATION_ID_LENGTH = 256;

/**
 * Stable enum-like reason codes returned in the `reason` field. CI
 * clients key off these strings to render PR comments / build logs.
 * Mirror of the kernel's `ShipGateReasonCode` at
 * `src/lib/workflow/ship-gates.ts:65-68`. **Closed-enum at the type
 * level; runtime validation is `typeof === "string"` only** (faithful
 * courier — gate.evaluate carry-forward). If a future kernel emits
 * a new reason code before the SDK is bumped, the value round-trips
 * at runtime. Drift-pinned via the wire-shape build-round pin.
 */
export type ShipGateReasonCode =
  | "awaiting_approvers"
  | "rejected"
  | "timed_out";

/**
 * State of the ship-gate row. Mirror of the kernel's `ShipGateState`
 * at `src/lib/workflow/ship-gates.ts:59`. **Closed-enum at the type
 * level; runtime validation is `typeof === "string"` only** (faithful
 * courier).
 */
export type ShipGateState = "gated" | "released" | "rejected" | "timed_out";

/**
 * Input shape for `shipGate.check`. Source-of-truth at kernel
 * `src/app/api/v1/ship-gate/check/route.ts:41-44` (Zod schema).
 *
 * **`systemId`** — REQUIRED RFC 4122 hyphenated UUID. The SDK
 * pre-validates the format synchronously (`TypeError` for malformed
 * input — D2). The SDK's runtime check always runs regardless of
 * TypeScript types — `as any` casts do NOT bypass it. The kernel-side
 * Zod validation (422 fallback) only fires for kernel rule changes
 * the SDK hasn't synced to.
 *
 * **`attestationId`** — REQUIRED non-empty string of length 1-256.
 * Identifies the specific build / attestation under consideration
 * (e.g., a git SHA, a CI build number, an attestation hash). The
 * kernel uses this together with `systemId` as the lookup key for
 * the `ship_gates` table's UNIQUE `(org_id, system_id, attestation_id)`
 * constraint — calling `check()` with the same tuple repeatedly is
 * idempotent in the no-gate / released cases (no side effect beyond
 * the audit-log entry) and reads the same gated/terminal verdict in
 * the gated case (post-reconciliation). The SDK pre-validates length
 * bounds against `MAX_ATTESTATION_ID_LENGTH = 256` (the kernel
 * constant at `src/lib/workflow/ship-gates.ts:106`).
 */
export interface ShipGateInput {
  /**
   * UUID of the system to check. RFC 4122 hyphenated form
   * (8-4-4-4-12 hex, case-insensitive). Required.
   */
  systemId: string;
  /**
   * Build / attestation identifier (free-text 1-256 chars). Required.
   * Forms a unique tuple with `systemId` for the `ship_gates` lookup
   * — repeated calls on the same `(systemId, attestationId)` pair
   * are idempotent (no side effect beyond the audit-log entry).
   */
  attestationId: string;
}

/**
 * Response shape returned by `shipGate.check`. **UNION of 4 emit
 * shapes** keyed by the gate's existence + state:
 *
 *   - **Shape A — no gate exists** (`gated: false` ONLY, 1 field):
 *     The default-permissive short-circuit — no `ship_gates` row
 *     for this `(systemId, attestationId)` tuple. The gate is
 *     opt-in; consumers who never create a gate never block a build.
 *     `state`, `executionId`, `chainId`, `reason`, and
 *     `approvers_pending` are ALL absent (own-property false).
 *     Source: kernel `ship-gates.ts:543-545`.
 *   - **Shape B — released** (4 fields): `{ gated: false, state:
 *     "released", executionId, chainId }`. The approval chain
 *     approved the deployment. `reason` and `approvers_pending` are
 *     absent. Source: kernel `ship-gates.ts:275-282`.
 *   - **Shape C — rejected or timed_out** (6 fields): `{ gated: true,
 *     reason: "rejected" | "timed_out", approvers_pending: [], state:
 *     "rejected" | "timed_out", executionId, chainId }`. The approval
 *     chain went terminal in a build-blocking state. `approvers_pending`
 *     is always `[]` (nobody is pending on a closed chain). Source:
 *     kernel `ship-gates.ts:283-302`.
 *   - **Shape D — gated awaiting approvers** (6 fields): `{ gated:
 *     true, reason: "awaiting_approvers", approvers_pending: [<UUIDs>],
 *     state: "gated", executionId, chainId }`. The approval chain is
 *     in-flight; `approvers_pending` lists the userIds still owed a
 *     decision (pool-order, post-decided filtering — see kernel
 *     `computeApproversPending` at `ship-gates.ts:169-205`). Source:
 *     kernel `ship-gates.ts:303-311`.
 *
 * **Discriminator pattern**: use `result.gated === true` (closed-enum
 * boolean) to detect "build must block". Use `result.state` (when
 * own-property present) to differentiate Shapes B / C / D. **Do NOT
 * use `result.reason === undefined`** as a discriminator — a hostile
 * dep polluting `Object.prototype.reason` makes the `=== undefined`
 * check return false (reads the polluted value via prototype walk),
 * silently misclassifying Shape A / B as Shape C / D. `gated` has
 * an UNCONDITIONAL own-property check in the validator (every code
 * path reads `obj.gated` first); branching on it is pollution-safe.
 *
 * **`approvers_pending` is SNAKE_CASE on the wire** — asymmetric with
 * the rest of the SDK's camelCase response surface. The kernel
 * emits the literal field name `approvers_pending` (mirror of master
 * plan spec contract). Consumers must use the snake_case spelling.
 */
export interface ShipGateCheckResponse {
  /**
   * `true` iff CI/CD must block the build. ALWAYS-PRESENT anchor
   * field. Closed-enum boolean — pollution-safe discriminator for
   * "build must block" decisions.
   */
  gated: boolean;
  /**
   * Stable reason code. **PRESENT ONLY when `gated: true`** (Shapes
   * C + D). Closed-enum at the type level (`"awaiting_approvers" |
   * "rejected" | "timed_out"`); runtime is open (faithful courier —
   * validator checks `typeof === "string"` only). Drift-pinned via
   * the wire-shape build-round pin.
   *
   * **Discriminator safety**: do NOT use `result.reason === undefined`
   * for Shape A/B vs C/D detection (prototype walk reads polluted
   * values under `Object.prototype.reason` pollution). Branch on
   * `result.gated === true` (the only pollution-safe consumer-side
   * discriminator).
   */
  reason?: ShipGateReasonCode;
  /**
   * UserIds still owed a decision (pool-order). **PRESENT ONLY when
   * `gated: true`** (Shapes C + D). On Shape C (rejected /
   * timed_out): always `[]` (nobody is pending on a closed chain).
   * On Shape D (awaiting_approvers): the list of pending userIds
   * computed by `computeApproversPending` (serial-mode preserves
   * pool order from currentStep onward; parallel-mode returns ALL
   * non-decided pool members; escalation user appended IFF
   * `lastEscalatedAt` is set).
   *
   * **SNAKE_CASE wire field name** — asymmetric with the rest of
   * the SDK's camelCase response surface. The kernel emits the
   * literal field name `approvers_pending` (master plan spec
   * contract). Consumers must use the snake_case spelling to read
   * the field.
   *
   * **Discriminator safety**: do NOT use
   * `result.approvers_pending === undefined` (prototype walk under
   * `Object.prototype.approvers_pending` pollution returns the
   * polluted value). Branch on `result.gated === true` first.
   */
  approvers_pending?: string[];
  /**
   * Diagnostic — gate's resolved state after reconciliation.
   * **PRESENT in Shapes B + C + D, ABSENT in Shape A** (no gate
   * exists). Closed-enum at the type level (`"gated" | "released" |
   * "rejected" | "timed_out"`); runtime is open (faithful courier).
   *
   * **Discriminator safety**: do NOT use `result.state === undefined`
   * for Shape A vs B detection (prototype walk under
   * `Object.prototype.state` pollution returns the polluted value).
   * Branch on `result.gated === true` first; for Shape A vs B
   * specifically, neither `result.state === undefined` NOR
   * `Object.hasOwn(result, "state")` is fully pollution-safe on the
   * CONSUMER side (the live `Object.hasOwn` can itself be overridden;
   * only the SDK's module-load snapshot guards its internal
   * validator). For consumer-side defense, prefer
   * `result.gated === false` (anchor field is always own-present and
   * pollution-safe) AND treat the no-state branch as Shape A.
   */
  state?: ShipGateState;
  /**
   * Diagnostic — UUID of the approval-chain execution backing the
   * gate. **PRESENT in Shapes B + C + D, ABSENT in Shape A**. The
   * kernel column is `uuid` (PostgreSQL `uuid` type, source of truth);
   * the SDK does not re-validate UUID format at runtime — faithful
   * courier for the kernel's column constraint.
   *
   * **Discriminator safety**: same as `state` — branch on
   * `result.gated` first; `executionId === undefined` is NOT a
   * pollution-safe discriminator.
   */
  executionId?: string;
  /**
   * Diagnostic — UUID of the approval-chain template backing the
   * execution. **PRESENT in Shapes B + C + D, ABSENT in Shape A**.
   * Same `uuid`-column source-of-truth posture as `executionId`.
   *
   * **Discriminator safety**: same as `state` — branch on
   * `result.gated` first; `chainId === undefined` is NOT a
   * pollution-safe discriminator.
   */
  chainId?: string;
}

/**
 * `shipGate` resource — sibling to `IncidentsResource`,
 * `DecisionsResource`, `ChatResource`, `AuditLogResource`,
 * `RegulatoryChangesResource`, `ComplianceCheckResource`,
 * `CheckResource`, `GateResource`, `BatchResource`. Today wraps a
 * single endpoint (`check`); the class is the landing pad for future
 * ship-gate methods if the kernel adds them (resource-class-per-
 * kernel-resource convention, invariant #43).
 */
export class ShipGateResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Check whether a CI/CD build is gated by an in-flight approval
   * chain. Returns a four-shape verdict keyed by the gate's
   * existence + state. Designed for pipeline integration (GitHub
   * Actions / GitLab CI / Buildkite).
   *
   * **Four emit shapes** — the response shape varies by the gate's
   * existence + state:
   *   - **Shape A — no gate exists**: `{ gated: false }` (1 field —
   *     default-permissive, opt-in gate semantics).
   *   - **Shape B — released**: `{ gated: false, state: "released",
   *     executionId, chainId }` (4 fields).
   *   - **Shape C — rejected / timed_out**: `{ gated: true, reason:
   *     "rejected" | "timed_out", approvers_pending: [], state, ... }`
   *     (6 fields; `approvers_pending` always `[]` on closed chain).
   *   - **Shape D — gated awaiting approvers**: `{ gated: true,
   *     reason: "awaiting_approvers", approvers_pending: [<UUIDs>],
   *     state: "gated", ... }` (6 fields; `approvers_pending` lists
   *     pending userIds).
   *
   * **`approvers_pending` is SNAKE_CASE on the wire** — the kernel
   * emits the literal field name `approvers_pending` (asymmetric
   * with the rest of the SDK's camelCase response surface). The SDK
   * preserves this verbatim; consumers must use the snake_case
   * spelling.
   *
   * **Multi-permission UNION auth scope**: kernel uses
   * `requireApiKeyWithPermission(req, READ_SYSTEMS, READ_ASSESSMENTS)`
   * which is OR semantics (`Array.some()` at
   * `permissions.ts:53-55`). A key with EITHER permission (or
   * `ADMIN`, or null/empty permissions for backwards-compat)
   * succeeds. **HTTP 401** for no/invalid API key, **HTTP 403** for
   * an authenticated key that has NEITHER required permission. Pin
   * BOTH branches separately. Carry-forward invariant #45.
   * **NOTE — argument order is READ_SYSTEMS FIRST** (asymmetric
   * with `check.run` and `gate.evaluate` which list READ_ASSESSMENTS
   * first); `Array.some()` is order-insensitive, but drift-pinned
   * exact-arglist in the spec-diff round catches a kernel-side
   * rename or reordering.
   *
   * **Discriminator pattern**: branch on `result.gated === true`
   * (closed-enum boolean) to detect "build must block". The SDK's
   * P2 validator guarantees `gated` is ALWAYS an own-property of
   * the returned object — that's the only consumer-side discriminator
   * that is genuinely pollution-safe (no prototype-walk hazard).
   *
   * **Do NOT use `result.reason === undefined`** as a discriminator
   * — a hostile dep polluting `Object.prototype.reason` makes the
   * `=== undefined` check return false (reads via prototype walk),
   * silently misclassifying Shape A / B as Shape C / D.
   *
   * **Consumer-side `Object.hasOwn(result, "state")` is NOT a fully
   * safe alternative** — it relies on the LIVE global `Object.hasOwn`,
   * which is itself subject to override by a hostile dep
   * (`Object.hasOwn = () => true`). The SDK's own response-side
   * validator uses a module-load snapshot of `Object.hasOwn` (taken
   * at SDK import time, before consumer-graph deps load) so the
   * SDK-internal validation is hardened; consumer code calling the
   * live `Object.hasOwn` after the SDK resolves is not. For
   * consumer-side defense-in-depth, branch on `result.gated` first
   * (the safe boolean), and only inspect `result.state` after.
   *
   * **Reconciliation-on-read inside transaction** — when the linked
   * `approval_chain_executions` row has gone terminal but the
   * `ship_gates` row still says `gated`, the kernel's `checkShipGate`
   * advances the gate to the corresponding terminal state inside
   * `SELECT … FOR UPDATE` (`ship-gates.ts:567-584`). The SDK does
   * NOT observe the reconciliation step — only the post-reconciliation
   * shape. A consumer calling `check()` twice in quick succession
   * on a chain that just completed sees the gated-state shape on
   * call 1 (if reconciliation hadn't fired yet) and the terminal
   * shape on call 2. Faithful courier; documented kernel behavior.
   *
   * **`writeAuditLog` side effect** — every `shipGate.check(...)`
   * call writes one audit-log entry with `action: "ship_gate.checked"`
   * and `resourceType: "ship_gate"` (route.ts:73-87; both strings
   * drift-pinned). SIEM / observability consumers keying off either
   * field for filter setup should depend on both staying stable.
   * Properties of the write:
   *   - Org-scoped, hash-chained (per `writeAuditLog`).
   *   - **Time-blocking** but error-tolerant: the kernel uses
   *     `await writeAuditLog(...)`, which awaits two DB ops (SELECT
   *     previous-hash + INSERT new entry). The check response
   *     latency INCLUDES the audit-log write time — a slow audit-log
   *     DB will delay every `shipGate.check()` response. Error
   *     semantics ARE non-blocking: `writeAuditLog` wraps its body
   *     in a try/catch that swallows + logs errors, so a write
   *     FAILURE does NOT fail the check request.
   *   - NOT counted against `decisionsPerMonth` quota (read-shaped).
   * Invariant #53 carry-forward (matches `gate.evaluate`'s pattern).
   *
   * **Kernel-side 15-second timeout** (`maxDuration = 15` at
   * `route.ts:24`). **Same as `gate.evaluate`'s 15s; tighter than
   * `auditLog.verifyChain`'s 30s.** The SDK does NOT enforce a
   * client-side timeout (consumers manage via `options.signal`),
   * but the kernel's function-runtime cap bounds the request
   * latency on the server side. CI pipeline timeouts should budget
   * relative to this cap.
   *
   * **Documented kernel-side cascade-gap surfaces — TWO distinct
   * paths**:
   *   1. **Execution-missing → HTTP 404** (named-error path). The
   *      kernel maps `ShipGateExecutionNotFoundError` to 404 at
   *      route.ts:97-99. Thrown by `checkShipGate` only when the
   *      inner `executionRows.length === 0` defensive branch fires
   *      (`ship-gates.ts:559-564`).
   *   2. **Chain-missing → HTTP 500 (scrubbed)** (plain-Error path).
   *      A SEPARATE defensive branch at `ship-gates.ts:610-617`
   *      throws a PLAIN `Error` (NOT a named class) when a
   *      ship_gate → execution → chain reference is broken on the
   *      LAST hop. The route's catch block has only three
   *      `instanceof` arms (`AuthError`, `BodyParseError`,
   *      `ShipGateExecutionNotFoundError`); a plain `Error` falls
   *      through to `internalErrorResponse → 500` with the scrubbed
   *      message "An internal error occurred. Please try again
   *      later." The caller cannot distinguish this cascade-gap
   *      from any other internal error via the HTTP status alone.
   * Both branches are unreachable in normal operation (RESTRICT FK
   * + filter-by-orgId); both documented as "only reachable via
   * direct DB intervention or a cascade-behavior gap." Faithful
   * courier: the SDK surfaces whichever status the kernel chose
   * (404 vs 500), but SIEM consumers running cascade-gap-404
   * filters should know the second branch hides as 500.
   *
   * Errors — **happy-path precedence ordering** is rate-limit → auth
   * → Zod body validation → DB lookup → successResponse. A request
   * with multiple happy-path problems surfaces ONLY the highest-
   * precedence one. **The 500-catchall is a SEPARATE DIMENSION** —
   * any throwable not matched by the named `instanceof` arms (see
   * the 500 bullet below) falls to 500, regardless of where in the
   * happy-path it fired. So e.g. a Zod-library crash during body
   * parsing surfaces as 500 (NOT 422).
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     (auto-retried by default — invariant #18; per-IP rate-limit
   *     key `v1-ship-gate-check:${ip}` against the standard
   *     `apiLimiter`).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *     Fires AFTER rate-limit but BEFORE input validation.
   *   - `AttestryAPIError` (status 403) — authenticated key has
   *     NEITHER `READ_SYSTEMS` nor `READ_ASSESSMENTS`. Single test
   *     case — the union-auth pattern collapses three intuition-
   *     suggesting cases to one.
   *   - `AttestryAPIError` (status 422) — Zod schema rejection
   *     (kernel's `BodyParseError` surface — `parseBody(request,
   *     checkSchema)` failed). **Fires BEFORE the cascade-gap 404
   *     lookup**. `apiErr.details` carries the full kernel error
   *     body verbatim (the transport does NOT strip the
   *     `{success:false, ...}` envelope on error responses — only
   *     the `{success:true, data}` envelope on success). The wire
   *     shape is: `{success: false, error: "Validation failed.",
   *     details: Array<{path: string; message: string}>}` — `error`
   *     is the literal string "Validation failed." (with trailing
   *     period), `details` is an array (NOT a keyed map) of `{path,
   *     message}` pairs derived from Zod's `result.error.errors`.
   *     **The SDK pre-validates both closed-spec rules** (UUID
   *     format on systemId, length 1-256 on attestationId) AND the
   *     runtime checks always run regardless of TypeScript types —
   *     `as any` casts do NOT bypass them. So 422 reaches consumers
   *     ONLY via kernel rule changes the SDK hasn't synced to.
   *     Invariant #51.
   *   - `AttestryAPIError` (status 404) — cascade-gap rare path:
   *     kernel threw `ShipGateExecutionNotFoundError` because a
   *     `ship_gates` row references an `executionId` whose row is
   *     missing in `approval_chain_executions`. Documented as "only
   *     reachable via direct DB intervention".
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`). **The 500
   *     surface is orthogonal to the precedence list above**: ANY
   *     throwable not matched by the three named `instanceof` arms
   *     (`AuthError` 401/403, `BodyParseError` 422,
   *     `ShipGateExecutionNotFoundError` 404) — INCLUDING throwables
   *     that fire DURING any of the happy-path steps — falls to
   *     500. **Includes the chain-missing cascade-gap** (the second
   *     defensive branch in `checkShipGate` at `ship-gates.ts:
   *     610-617` throws a plain `Error` that hides as 500, NOT as a
   *     named 404 surface).
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired (pre-aborted or mid-flight).
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (not an object, wrong type on
   *     `gated`, wrong type on any optional own-property field).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard before body
   *     parsing).
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation (null / array / non-object input,
   *     missing systemId, invalid UUID format, missing attestationId,
   *     non-string attestationId, attestationId length out of
   *     range [1, 256]).
   *
   * **Notably ABSENT**:
   *   - **No 400** — all input validation is Zod (422).
   *   - **No 402** — read-shaped, doesn't count against
   *     decisionsPerMonth quota (despite the audit-log side effect).
   *   - **No 413** — body size limit not explicit.
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
   *     lone-surrogate URIError defense (POST body uses
   *     JSON.stringify).
   *   - `input.attestationId`: required own-property; must be a
   *     non-empty string; length 1-256 (matches kernel constant
   *     `MAX_ATTESTATION_ID_LENGTH = 256` at
   *     `src/lib/workflow/ship-gates.ts:106`).
   *
   * **Response-shape validation** (P2 hardening — symmetric defense
   * on response side per the module-load `objectHasOwn` snapshot;
   * mirror of `gate.ts` / `audit-log.ts` patterns):
   *   - Rejects with `AttestryError` if the kernel response isn't
   *     a non-null, non-array object.
   *   - Rejects if `gated` isn't a boolean (ALWAYS-present anchor
   *     field — the validator's `gated` branch is UNCONDITIONAL).
   *   - Rejects if `reason` (when own-present) isn't a string.
   *   - Rejects if `approvers_pending` (when own-present) isn't an
   *     array.
   *   - Rejects if `state` (when own-present) isn't a string.
   *   - Rejects if `executionId` / `chainId` (when own-present)
   *     aren't strings.
   *   - Each response field read goes through the module-load
   *     `objectHasOwn` snapshot — defends against
   *     `Object.prototype.<field>` pollution masking a missing field.
   *   - Per-element shape on `approvers_pending` (each element must
   *     be a string) is validated when the field is own-present.
   *
   * **Transport-shape validation** (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with
   *     a non-`application/json` Content-Type.
   *
   * @example Basic ship-gate check (typical CI usage)
   * ```ts
   * const verdict = await client.shipGate.check({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   *   attestationId: "build-1234",
   * });
   * if (verdict.gated) {
   *   // Shape C or D — build must block.
   *   if (verdict.reason === "awaiting_approvers") {
   *     // Shape D — list pending approvers in PR comment.
   *     console.error(
   *       `Awaiting approval from ${verdict.approvers_pending?.join(", ")}`,
   *     );
   *   } else {
   *     // Shape C — rejected or timed_out.
   *     console.error(`Build blocked: ${verdict.reason}`);
   *   }
   *   process.exit(1);
   * }
   * // Shape A (no gate) or Shape B (released) — build proceeds.
   * console.log("OK to deploy.");
   * ```
   *
   * @example Discriminate Shape A vs Shape B (no-gate vs released)
   * ```ts
   * const verdict = await client.shipGate.check({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   *   attestationId: "build-1234",
   * });
   * if (!verdict.gated) {
   *   if (verdict.state === "released") {
   *     console.log(`Approved (execution: ${verdict.executionId})`);
   *   } else {
   *     // No state field → Shape A (no gate exists).
   *     console.log("No gate configured for this build.");
   *   }
   * }
   * ```
   */
  check(
    input: ShipGateInput,
    options?: RequestOptions,
  ): Promise<ShipGateCheckResponse> {
    // Top-level shape — input is REQUIRED. typeof null === "object"
    // and typeof [] === "object", so guard both explicitly.
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "shipGate.check: `input` must be a non-null object with `systemId` and `attestationId`",
      );
    }

    // Snapshot each field's value EXACTLY ONCE up front via the
    // own-property indexer, then operate only on the locals
    // downstream. Three motivations (mirror of gate.ts / check.ts):
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
    //   3. An explicit `{systemId: "..."}` (no attestationId) is
    //      treated as attestationId-omitted — `objectHasOwn` correctly
    //      returns false on missing keys.
    const hasSystemId = objectHasOwn(input, "systemId");
    const systemIdRaw: unknown = hasSystemId
      ? readInputField(input, "systemId", "shipGate.check")
      : undefined;
    const hasAttestationId = objectHasOwn(input, "attestationId");
    const attestationIdRaw: unknown = hasAttestationId
      ? readInputField(input, "attestationId", "shipGate.check")
      : undefined;

    // systemId is REQUIRED. Reject missing-or-undefined first with a
    // clear "required" message; subsequent checks assume present.
    if (!hasSystemId || systemIdRaw === undefined) {
      throw new TypeError("shipGate.check: `systemId` is required");
    }
    if (typeof systemIdRaw !== "string" || systemIdRaw.length === 0) {
      throw new TypeError(
        "shipGate.check: `systemId` must be a non-empty string",
      );
    }
    // UUID format pre-validation (D2 — SDK matches kernel's Zod
    // `z.string().uuid()` closed-spec rule). Mirror of `check.run` /
    // `gate.evaluate`. Drift-pinned in spec-diff round.
    if (!UUID_REGEX.test(systemIdRaw)) {
      throw new TypeError(
        "shipGate.check: `systemId` must be an RFC 4122 hyphenated UUID " +
          "(matched regex: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" +
          "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/)",
      );
    }

    // attestationId is REQUIRED. Length 1-256 inclusive (matches
    // kernel constant MAX_ATTESTATION_ID_LENGTH at
    // src/lib/workflow/ship-gates.ts:106). Drift-pinned in spec-diff.
    if (!hasAttestationId || attestationIdRaw === undefined) {
      throw new TypeError("shipGate.check: `attestationId` is required");
    }
    if (typeof attestationIdRaw !== "string") {
      throw new TypeError(
        `shipGate.check: \`attestationId\` must be a string ` +
          `(got ${describeType(attestationIdRaw)})`,
      );
    }
    if (attestationIdRaw.length === 0) {
      throw new TypeError(
        "shipGate.check: `attestationId` must be a non-empty string",
      );
    }
    if (attestationIdRaw.length > MAX_ATTESTATION_ID_LENGTH) {
      throw new TypeError(
        `shipGate.check: \`attestationId\` exceeds the kernel's max ` +
          `length of ${MAX_ATTESTATION_ID_LENGTH} chars ` +
          `(got ${attestationIdRaw.length})`,
      );
    }

    const body = {
      systemId: systemIdRaw,
      attestationId: attestationIdRaw,
    };

    return this.client
      ._request<ShipGateCheckResponse>({
        method: "POST",
        path: "/api/v1/ship-gate/check",
        body,
        options,
      })
      .then((result) => validateShipGateCheckResponse(result));
  }
}

/**
 * P2 hardening: validate the `check()` response's anchor field
 * (`gated`) + each of the 5 optional own-property fields (`reason`,
 * `approvers_pending`, `state`, `executionId`, `chainId`). Symmetric
 * prototype-pollution defense — read EACH field via the module-load
 * `objectHasOwn` snapshot so a hostile npm dep polluting
 * `Object.prototype.<field>` cannot mask a kernel regression that
 * drops the field OR silently inject a polluted value through a
 * present-but-missing-own-property read path.
 *
 * Returns the validated `result` (typed `ShipGateCheckResponse`) on
 * success; throws `AttestryError` on any shape violation. Extracted
 * as a free function so the resource method body stays focused on
 * request construction.
 *
 * **`gated` is the ALWAYS-PRESENT anchor field** — UNCONDITIONAL
 * own-property check. Every response code path (Shapes A, B, C, D)
 * emits `gated`. A missing `gated` is a hard regression signal.
 *
 * **The other 5 fields are OPTIONAL own-properties** — kernel omits
 * them entirely in Shape A (`{gated: false}` 1-field); kernel omits
 * `reason` + `approvers_pending` in Shape B (4 fields); kernel
 * includes all 5 in Shapes C + D (6 fields). Validator checks
 * `objectHasOwn` BEFORE type-checking, so absent-and-untyped is
 * forward-compatible — present-but-wrong-type is the actual
 * regression signal.
 *
 * **Number-field validation is N/A here** — this resource has NO
 * numeric response fields; the validator's footprint is smaller
 * than `audit-log.ts` / `gate.ts`. If a future field is added
 * (e.g., a `slaHoursRemaining: number`), revisit the
 * faithful-courier-on-numbers asymmetry documented in
 * `audit-log.ts:920-940` (typeof === "number" accepts NaN /
 * Infinity, which JSON.parse never produces for JSON wire formats).
 *
 * **Single-field rejection semantics** (carry-forward from
 * audit-log.ts L1 / session-19 review-3 M1 — project convention).
 * The validator checks fields SEQUENTIALLY in declaration order
 * (gated → reason → approvers_pending → state → executionId →
 * chainId) and throws on the FIRST failing field. If a kernel
 * regression drops MULTIPLE fields at once, the consumer sees ONLY
 * the first failing field's diagnostic — they must fix the fixture
 * and re-run to surface the next failure. This matches batch.ts /
 * gate.ts / check.ts / audit-log.ts patterns (project convention
 * for response-shape validators); accumulating into a multi-field
 * message would diverge from the rest of the SDK. Trade-off
 * accepted: consistency-with-project-pattern wins over single-cycle
 * full-diagnostic.
 */
function validateShipGateCheckResponse(
  result: unknown,
): ShipGateCheckResponse {
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result)
  ) {
    throw new AttestryError(
      `shipGate.check: expected an object response from the kernel ` +
        `(got ${describeType(result)})`,
    );
  }
  const obj = result as Record<string, unknown>;

  // gated — ALWAYS-PRESENT anchor. UNCONDITIONAL own-property check.
  const gated = objectHasOwn(obj, "gated") ? obj.gated : undefined;
  if (typeof gated !== "boolean") {
    throw new AttestryError(
      `shipGate.check: expected response.gated to be a boolean ` +
        `(got ${describeType(gated)})`,
    );
  }

  // reason — OPTIONAL own-property. PRESENT only in Shapes C + D.
  if (objectHasOwn(obj, "reason")) {
    const reason = obj.reason;
    if (typeof reason !== "string") {
      throw new AttestryError(
        `shipGate.check: expected response.reason to be a string ` +
          `when present (got ${describeType(reason)})`,
      );
    }
  }

  // approvers_pending — OPTIONAL own-property (SNAKE_CASE wire name).
  // PRESENT only in Shapes C + D. Each element must be a string.
  if (objectHasOwn(obj, "approvers_pending")) {
    const approversPending = obj.approvers_pending;
    if (!Array.isArray(approversPending)) {
      throw new AttestryError(
        `shipGate.check: expected response.approvers_pending to be an array ` +
          `when present (got ${describeType(approversPending)})`,
      );
    }
    for (let i = 0; i < approversPending.length; i++) {
      const elem = approversPending[i];
      if (typeof elem !== "string") {
        throw new AttestryError(
          `shipGate.check: expected response.approvers_pending[${i}] to be a string ` +
            `(got ${describeType(elem)})`,
        );
      }
    }
  }

  // state — OPTIONAL own-property. PRESENT in Shapes B + C + D.
  if (objectHasOwn(obj, "state")) {
    const state = obj.state;
    if (typeof state !== "string") {
      throw new AttestryError(
        `shipGate.check: expected response.state to be a string ` +
          `when present (got ${describeType(state)})`,
      );
    }
  }

  // executionId — OPTIONAL own-property. PRESENT in Shapes B + C + D.
  if (objectHasOwn(obj, "executionId")) {
    const executionId = obj.executionId;
    if (typeof executionId !== "string") {
      throw new AttestryError(
        `shipGate.check: expected response.executionId to be a string ` +
          `when present (got ${describeType(executionId)})`,
      );
    }
  }

  // chainId — OPTIONAL own-property. PRESENT in Shapes B + C + D.
  if (objectHasOwn(obj, "chainId")) {
    const chainId = obj.chainId;
    if (typeof chainId !== "string") {
      throw new AttestryError(
        `shipGate.check: expected response.chainId to be a string ` +
          `when present (got ${describeType(chainId)})`,
      );
    }
  }

  return result as ShipGateCheckResponse;
}

/**
 * Human-readable type description for error messages. Distinguishes
 * `null` and `array` from generic `object`. Duplicated in
 * `decisions.ts`, `incidents.ts`, `regulatory-changes.ts`,
 * `compliance-check.ts`, `check.ts`, `gate.ts`, `batch.ts`,
 * `audit-log.ts` per project pattern (small helper, leaf-resource
 * modules, no shared module yet).
 *
 * All branches are reachable through this file's call sites: top-
 * level shape check (null + array + non-object scalar), per-field
 * type guards (each field's `describeType(<wrong type>)` exercised
 * by tests in the build round).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
