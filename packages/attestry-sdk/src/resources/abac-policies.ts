// ─── AbacPolicies resource ──────────────────────────────────────────────────
//
// Wraps the ABAC (Attribute-Based Access Control) policies surface
// (Prompt C.3 — session 21):
//
//   - GET    /api/v1/abac-policies                list       (session 21)
//   - POST   /api/v1/abac-policies                create     (session 21)
//   - GET    /api/v1/abac-policies/[id]           retrieve   (session 22)
//   - PATCH  /api/v1/abac-policies/[id]           update     (session 22)
//   - DELETE /api/v1/abac-policies/[id]           delete     (session 22)
//
// Eighth non-decisions resource on `@attestry/sdk` (after `auditLog`,
// `regulatoryChanges`, `complianceCheck`, `check`, `gate`, `batch`,
// `shipGate`). Sibling to all 10 existing resource classes on the SDK.
// FIRST 5-method CRUD cluster on the SDK — prior multi-method clusters
// either grew an existing class (`decisions` reached 7 methods over
// many sessions; `auditLog` reached 2; `batch` shipped with 2) OR
// shipped a smaller surface. `.list()` and `.create()` shipped in
// session 21; `.retrieve()`, `.update()`, and `.delete()` complete
// the cluster in session 22.
//
// **Dual-auth admin scope** — the kernel route gates on
// `requireSessionOrApiKey(request, { sessionRoles: ["admin"],
// apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })`. The dual-auth
// helper routes by request header presence: an `x-api-key` header
// (even empty-string) takes the api-key path; absent header takes
// the session path. The SDK's transport ALWAYS sends `x-api-key`
// (constructed at `transport.ts:headers.set("x-api-key", apiKey)`),
// so the api-key path is the ONLY one reachable from SDK consumers.
// The session path is exercised by the dashboard, not by the SDK.
//
// **NOT the first SDK use of dual-auth** — `auditLog.export`
// (session 12) and `decisions.verifyChain` (session 19) already use
// `requireSessionOrApiKey` middleware on the kernel side. The novelty
// for `abacPolicies` is that it's the first SDK CRUD cluster (5
// methods) under dual-auth admin, not the first dual-auth use.
//
// **Status-code surface — 401 vs 403 distinguished** (asymmetric with
// the ADMIN-only-route convention from carry-forward invariant #42).
// The kernel returns:
//   - **HTTP 401** for: no `x-api-key` header (when session is also
//     absent — SDK path is api-key-only, so this is the "no key"
//     case); empty `x-api-key` header (`""`); invalid key (no matching
//     keyHash row in the `apiKeys` table); expired key (`expiresAt <
//     now`).
//   - **HTTP 403** for: a VALID api-key in the org whose `permissions`
//     column does NOT include `ADMIN`. Error message:
//     `"API key lacks required permission. Required: admin. Key has:
//     ..."`. Source: `src/lib/middleware/permissions.ts:57-62`.
// Pin BOTH branches separately. **`auditLog.export` is the SAME
// dual-auth surface** — its kernel route uses the identical
// `requireSessionOrApiKey(request, { sessionRoles: ["admin"],
// apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })` gate (verified at
// `src/app/api/v1/audit-log/export/route.ts:66-68`), so it too
// returns 401 for no/invalid/expired key and 403 for a valid key
// lacking `ADMIN`. The `audit-log.ts` JSDoc previously claimed "HTTP
// 401 for both" — a mis-read of the kernel test, which MOCKS
// `AuthError(401)` and never exercises the real middleware;
// `audit-log.ts` was corrected in session-22 hostile review #2.
// Carry-forward invariant #42's "auditLog.export collapses both to
// 401" premise is corrected by the same review.
// Established invariant: **dual-auth admin routes surface BOTH 401 AND
// 403** (verified by reading `requireRole` at `auth.ts:96-110` +
// `requireApiKeyWithPermission` at `permissions.ts:35-66`).
//
// **No pagination on `.list()`** — the response is `{items: AbacPolicy[],
// count: number}` with NO cursor / nextCursor field. Server-side
// `listAbacPolicies` caps at `MAX_POLICIES_PER_ORG_FETCH = 200` rows
// (`src/lib/auth/abac-policies.ts:113`). Consumers calling `.list()`
// get up to 200 rows verbatim. If an org has >200 policies (rare —
// the policy table is intended for ~tens of rules), only the lowest
// 200 by `priority` ASC are returned. Documented kernel surface gap
// — invariant #50 (silent kernel-side truncation enumeration; the
// 200 cap is the ONLY truncation on this method).
//
// **Audit log side effect — NONE on `.list()`** — read-shaped routes
// without `writeAuditLog` calls (asymmetric with `gate.evaluate`,
// `batch.submit`, `shipGate.check` which all write). `.create()` /
// `.update()` / `.delete()` will write entries (`abac_policy.create`
// / `.update` / `.delete`) but `.list()` is quiet. The `.retrieve()`
// method (session 22) will also be quiet.
//
// **Symmetric prototype-pollution defense — RESPONSE side only on
// `.list()`** — module-load snapshot of `Object.hasOwn` applied to
// the response shape. The input side is N/A (`.list()` takes no
// input — only `options?: RequestOptions`).
//
// Sync JSON request/response: reuses `client._request` and the
// existing `{success:true, data}` envelope-unwrap (carry-forward
// invariant #9). NO new SDK primitive needed.

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

// ─── Public closed-enum runtime arrays ──────────────────────────────────────
//
// Mirrored from kernel `src/lib/auth.ts` (RESOURCES + ACTIONS) and the
// kernel's Effect type alias. **Object.freeze**'d (P1 hardening — mirror
// of constants.ts pattern) so a hostile/buggy npm dep cannot mutate the
// validation arrays at runtime, bypassing the `.includes()` checks in
// `.create()` pre-validation.
//
// Drift-pinned in `src/lib/incidents/__tests__/sdk-drift.test.ts` so any
// kernel-side addition / rename / reorder lands at the SDK before
// consumer regressions.
//
// Used by `.create()` pre-validation to reject unknown resource /
// action / effect values synchronously (closed-enum SDK fields always
// pre-reject — carry-forward invariant #41).

/**
 * Closed-enum of resources an ABAC policy can target. Runtime mirror
 * of the kernel's `RESOURCES` const at `src/lib/auth.ts:29-40`.
 * Object.freeze'd to prevent runtime mutation.
 */
export const ABAC_POLICY_RESOURCES = Object.freeze([
  "systems",
  "assessments",
  "documents",
  "attestations",
  "evidence",
  "users",
  "api_keys",
  "audit_log",
  "organization",
  "regulations",
] as const);

/**
 * Closed-enum of actions an ABAC policy can gate. Runtime mirror of
 * the kernel's `ACTIONS` const at `src/lib/auth.ts:42-48`.
 */
export const ABAC_POLICY_ACTIONS = Object.freeze([
  "create",
  "read",
  "update",
  "delete",
  "manage",
] as const);

/**
 * Closed-enum of effects. Runtime mirror of the kernel's `Effect` type
 * alias at `src/lib/auth/abac-policies.ts:77` + the Zod
 * `z.enum(["allow", "deny"]).default("allow")` at
 * `src/lib/auth/abac-policies.ts:756`.
 */
export const ABAC_POLICY_EFFECTS = Object.freeze(["allow", "deny"] as const);

// ─── Public closed-spec bounds (mirror kernel constants) ────────────────────
//
// Drift-pinned in `sdk-drift.test.ts` so kernel-side changes surface
// before consumer regressions. Used by `.create()` for synchronous
// pre-validation per invariant #49.

/** Mirror of kernel `MAX_POLICY_NAME_LENGTH = 128` at `abac-policies.ts:115`. */
const MAX_POLICY_NAME_LENGTH = 128;
/** Mirror of kernel `description.max(2000)` at `abac-policies.ts:753`. */
const MAX_POLICY_DESCRIPTION_LENGTH = 2000;
/** Mirror of kernel `MIN_PRIORITY = 0` at `abac-policies.ts:117`. */
const MIN_POLICY_PRIORITY = 0;
/** Mirror of kernel `MAX_PRIORITY = 1000` at `abac-policies.ts:118`. */
const MAX_POLICY_PRIORITY = 1000;

// ─── UUID path-segment validation (mirror kernel `badId`) ───────────────────
//
// RFC 4122 hyphenated form (8-4-4-4-12 hex, case-insensitive). Mirror
// of `batch.get` / `gate.evaluate` / `check.run` / `shipGate.check`'s
// `UUID_REGEX`, AND a runtime mirror of the kernel's `UUID_RE` at
// `src/app/api/v1/abac-policies/[id]/route.ts:32-33`. The kernel's
// `badId` helper rejects a malformed id with HTTP 400 "Invalid policy
// id." BEFORE rate-limit + auth. The SDK pre-validates `id` for
// `.retrieve()` / `.update()` / `.delete()` (the three id-path
// methods) so that 400 is reachable only via an `as any` cast or a
// kernel-side id-flavor change (ULID, KSUID, etc.).
//
// **No `encodeURIComponent` on the path segment** — a string matching
// this regex is ASCII hex digits + hyphens only: every code point is
// URL-safe AND none can form a lone UTF-16 surrogate, so
// `encodeURIComponent` could neither throw a `URIError` nor alter the
// string. The validated `id` is interpolated into the request path
// raw. Mirror of `batch.get` (asymmetric with `decisions.retrieve`,
// whose free-form `id` needs `encodePathSegment` + path-traversal +
// URIError defenses — carry-forward invariant #32 applies only where
// a segment can actually reach `encodeURIComponent`; a pre-validated
// UUID cannot). Drift-pinned in `sdk-drift.test.ts`.
const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// Module-load snapshot of `Object.hasOwn` — defends against a
// late-loading hostile/buggy npm dependency that overrides the global
// (e.g., `Object.hasOwn = () => true`). Without the snapshot, the
// response-side prototype-pollution defense below would use whatever
// `Object.hasOwn` the dependency replaced at request time.
//
// Mirror of `audit-log.ts` / `batch.ts` / `gate.ts` / `check.ts` /
// `compliance-check.ts` / `ship-gate.ts` pattern. Used on the response
// side; the input side is N/A for `.list()` (no input fields).
const objectHasOwn = Object.hasOwn;

// ─── Public closed-string-enum types ────────────────────────────────────────

/**
 * Stable enum of ABAC effects. Mirror of the kernel's `Effect` type
 * alias at `src/lib/auth/abac-policies.ts:77`. **Closed-enum at the
 * type level; runtime validation is `typeof === "string"` only**
 * (faithful courier — mirror of `gate.evaluate`'s `gate: "pass" | "fail"`
 * pattern). If a future kernel emits a new effect (unlikely — the
 * NIST SP 800-162 decision algorithm is fundamentally allow/deny),
 * the value round-trips at runtime.
 */
export type AbacPolicyEffect = "allow" | "deny";

/**
 * Stable enum of resources an ABAC policy can target. Mirror of the
 * kernel's `Resource` type alias at `src/lib/auth.ts:5-15` AND the
 * runtime `RESOURCES` const at `src/lib/auth.ts:29-40`. The SDK's
 * mirrored runtime array (`ABAC_POLICY_RESOURCES`) ships in the
 * `.create()` build round (session 22) when input pre-validation
 * needs it; for `.list()` only the type alias is used.
 *
 * **Closed-enum at the type level; runtime is faithful-courier**
 * (P2 validator checks `typeof === "string"` only). A kernel-side
 * RESOURCES addition would surface in the drift suite (spec-diff
 * round) before consumer regressions.
 */
export type AbacPolicyResource =
  | "systems"
  | "assessments"
  | "documents"
  | "attestations"
  | "evidence"
  | "users"
  | "api_keys"
  | "audit_log"
  | "organization"
  | "regulations";

/**
 * Stable enum of actions an ABAC policy can gate. Mirror of the
 * kernel's `Action` type alias at `src/lib/auth.ts:17` AND the runtime
 * `ACTIONS` const at `src/lib/auth.ts:42-48`.
 */
export type AbacPolicyAction =
  | "create"
  | "read"
  | "update"
  | "delete"
  | "manage";

// ─── AST condition types ────────────────────────────────────────────────────
//
// Mirror of the kernel's condition AST at `src/lib/auth/abac-policies.ts:56-75`.
// The grammar is a small bounded predicate language with operators
// `eq | ne | in | notIn | exists | notExists | attrEq | attrNe | and | or | not`.
// Attributes are addressed by dotted path rooted at `principal.` or
// `resource.` only (the `SAFE_PATH_RE` regex enforces this server-side;
// the SDK does NOT pre-validate path safety — `.create()` defers to
// the canonical validator. See `.create()` JSDoc — session 22).
//
// **Recursive type** — `and` / `or` / `not` clauses nest recursively.
// TypeScript's recursive types are compile-cheap enough for this
// grammar (~10 ops, max depth 8) that we mirror the full AST. Drift-
// pinned via the spec-diff round (kernel AST type alias body).

/**
 * Root for attribute paths in a condition leaf. The kernel rejects
 * paths not rooted at `principal.<...>` or `resource.<...>` via the
 * `SAFE_PATH_RE` regex at `src/lib/auth/abac-policies.ts:143`.
 */
export type AbacAttrRoot = "principal" | "resource";

/**
 * Dotted attribute path like `principal.id` or `resource.ownerId`. The
 * kernel's `SAFE_PATH_RE` requires `\.[A-Za-z_][A-Za-z0-9_]*` segments
 * after the root and rejects `__proto__` / `constructor` / `prototype`
 * via a separate `FORBIDDEN_KEYS` check. The SDK's TypeScript template-
 * literal type only encodes the root prefix — segment-level shape is
 * documented but not type-enforced (TS template-literal recursion
 * costs aren't worth the small ergonomic win here).
 */
export type AbacAttrPath = `${AbacAttrRoot}.${string}`;

/**
 * A primitive value an attribute can equal / be-in. Strings, numbers,
 * and booleans only. Mirror of the kernel's `AttrValue` at
 * `src/lib/auth/abac-policies.ts:63`. `null` / `undefined` are NOT in
 * the union — the evaluator treats missing attributes specially (see
 * `evaluateCondition` at `src/lib/auth/abac-policies.ts:486-578`).
 */
export type AbacAttrValue = string | number | boolean;

/**
 * Leaf condition — one of 8 operator shapes. Mirror of the kernel's
 * `LeafCondition` at `src/lib/auth/abac-policies.ts:65-69`. The
 * canonical validator enforces per-op allowed-key sets server-side
 * (`src/lib/auth/abac-policies.ts:220-232`) — admin typos like
 * `valuee:` get rejected, not silently dropped.
 */
export type AbacLeafCondition =
  | { op: "eq" | "ne"; attr: AbacAttrPath; value: AbacAttrValue }
  | { op: "in" | "notIn"; attr: AbacAttrPath; values: AbacAttrValue[] }
  | { op: "exists" | "notExists"; attr: AbacAttrPath }
  | { op: "attrEq" | "attrNe"; left: AbacAttrPath; right: AbacAttrPath };

/**
 * Compound condition — `and` / `or` / `not`. Mirror of the kernel's
 * `CompoundCondition` at `src/lib/auth/abac-policies.ts:71-73`. The
 * canonical validator enforces depth + clause budgets server-side
 * (`MAX_DEPTH = 8`, `MAX_CLAUSES_PER_COMPOUND = 32`,
 * `MAX_NODES_PER_EVALUATION = 1000`).
 */
export type AbacCompoundCondition =
  | { op: "and" | "or"; clauses: AbacCondition[] }
  | { op: "not"; clause: AbacCondition };

/**
 * Full condition AST — discriminated union of leaf + compound.
 * Mirror of the kernel's `AbacCondition` at
 * `src/lib/auth/abac-policies.ts:75`.
 */
export type AbacCondition = AbacLeafCondition | AbacCompoundCondition;

// ─── Public row shape ───────────────────────────────────────────────────────

/**
 * An ABAC policy row as returned by `.list()` / `.retrieve()` /
 * `.create()` / `.update()` / `.delete()`. Mirror of the kernel's
 * `AbacPolicyRow` at `src/lib/auth/abac-policies.ts:88-98`.
 *
 * **Wire-shape note — Dates are ISO strings, not Date objects.** The
 * kernel's TypeScript type declares `createdAt: Date` / `updatedAt:
 * Date` (it's a Drizzle `timestamp` column inferred as `Date` post-
 * fetch), but the response goes through `NextResponse.json(...)` which
 * serializes Dates via `JSON.stringify(new Date(...))` → ISO-8601
 * string. The SDK type reflects the wire reality (`string`), not the
 * kernel's TypeScript intermediate.
 *
 * **`description`, `createdByUserId` — `string | null`** (NOT
 * `string | undefined`). The kernel uses `null` for unset values via
 * the `?? null` coalesce at `src/lib/auth/abac-policies.ts:706, 713`;
 * the field is ALWAYS present on the wire, with value `null` when
 * unset. Consumers comparing should use `policy.description !== null`
 * (or truthy coercion, since null is falsy).
 *
 * **`condition` — recursive AST** mirroring the kernel grammar (8 leaf
 * ops + 3 compound ops). Consumers can branch on `condition.op` to
 * destructure. Server-side validation enforces depth / clause / value-
 * list / total-node budgets; the SDK does NOT re-validate the AST
 * after the kernel returns it (faithful courier).
 */
export interface AbacPolicy {
  /** UUID of the policy row. */
  id: string;
  /** UUID of the owning org. Always equals the auth caller's `orgId`. */
  orgId: string;
  /** Short identifier (1-128 chars). UNIQUE per `(orgId, name)` — */
  /* duplicate names trip the kernel's `AbacPolicyNameConflictError`. */
  name: string;
  /**
   * Optional human-readable description (max 2000 chars on the kernel's
   * Zod schema). `null` when unset. **NOT `undefined`** — the kernel
   * uses `?? null` coalesce server-side, so `description` is always an
   * own-property on the wire.
   */
  description: string | null;
  /** Resource the policy targets (closed-enum). */
  resource: AbacPolicyResource;
  /** Action the policy gates (closed-enum). */
  action: AbacPolicyAction;
  /** Effect — `allow` grants access, `deny` denies (NIST SP 800-162 §5.2). */
  effect: AbacPolicyEffect;
  /** Recursive condition AST evaluated against `{principal, resource}`. */
  condition: AbacCondition;
  /**
   * Priority [0, 1000] used to order policies before evaluation (ASC
   * — lower-priority policies are evaluated first, but `deny` short-
   * circuits regardless of order). Default 100 server-side.
   */
  priority: number;
  /** When `false`, the policy is excluded from the per-request fetch. */
  enabled: boolean;
  /**
   * UUID of the user who created the policy. `null` when the policy
   * was inserted directly via DB (e.g., migrations / fixtures), or
   * when the creator's user row was deleted (ON DELETE SET NULL).
   */
  createdByUserId: string | null;
  /** ISO-8601 timestamp of the insert. */
  createdAt: string;
  /** ISO-8601 timestamp of the most recent update (or insert if never updated). */
  updatedAt: string;
}

/**
 * Response shape returned by `.list()`. The kernel emits
 * `{success: true, data: {items: AbacPolicy[], count: number}}`; the
 * transport unwraps `data`, so consumers receive `{items, count}`.
 *
 * **No pagination** — `count` is `items.length` (NOT a total org
 * count beyond the materialized page). Server-side cap is
 * `MAX_POLICIES_PER_ORG_FETCH = 200`. Orgs with >200 policies see
 * only the LOWEST 200 by priority ASC. Documented kernel surface
 * gap — invariant #50.
 */
export interface AbacPoliciesListResponse {
  /** Up to 200 policies ordered by `priority` ASC, server-truncated. */
  items: AbacPolicy[];
  /** `items.length` — same as `items.length`; NOT a total org count. */
  count: number;
}

// ─── Create input shape ─────────────────────────────────────────────────────

/**
 * Input shape for `.create()`. Mirror of the kernel's
 * `createAbacPolicySchema` Zod at
 * `src/lib/auth/abac-policies.ts:750-761`. The kernel applies
 * **`.strict()`** — any extra fields are rejected with 422.
 *
 * **Required fields**: `name`, `resource`, `action`, `condition`.
 *
 * **Closed-spec defaults** (kernel applies if SDK omits):
 *   - `effect` defaults to `"allow"`.
 *   - `priority` defaults to `100`.
 *   - `enabled` defaults to `true`.
 * Per invariant #52, the SDK OMITS the field from the body when the
 * consumer omits it (so the kernel applies its default). Documenting
 * each default prominently below.
 *
 * **`condition` is the recursive AST** (`AbacCondition`). The SDK
 * does NOT pre-validate the AST grammar — the kernel's canonical
 * validator runs server-side and rejects invalid shapes (depth >8,
 * clauses >32 per compound, values >64 per list, total nodes >1000,
 * unknown ops, malformed attr paths). **First SDK route with
 * partial Zod pre-validation**: closed-spec fields are pre-validated
 * SDK-side (UUID-style closed-enum + length bounds), but the
 * recursive AST field defers entirely to server. Consumers see
 * `AbacPolicyValidationError` as 422 with `details: { errors:
 * string[] }` for AST violations; closed-spec rule violations
 * surface as `BodyParseError` 422 with `details:
 * Array<{path, message}>`.
 *
 * **Fifth SDK route to PRE-VALIDATE every Zod closed-spec rule
 * synchronously** (after `check.run`, `gate.evaluate`,
 * `batch.submit`, `shipGate.check`). **FIRST SDK route with PARTIAL
 * pre-validation** — the `condition` field is an OPEN-spec rule
 * (`z.record(z.string(), z.unknown())`) so AST grammar validation
 * defers entirely to the server's canonical validator. Calibration:
 * pre-validatable closed-spec rules are `name.min(1).max(128)`,
 * `description.max(2000).optional().nullable()`,
 * `resource`/`action`/`effect` closed-enums,
 * `priority.int().min(0).max(1000)`, `enabled.boolean()`. The
 * `condition` field is the only non-closed-spec rule on the schema.
 */
export interface AbacPolicyCreateInput {
  /**
   * Short identifier (1-128 chars). UNIQUE per `(orgId, name)` on the
   * `abac_policies` table — duplicates trip `AbacPolicyNameConflictError`
   * which surfaces as HTTP 409.
   */
  name: string;
  /**
   * Optional description (max 2000 chars). Accepts `string`, `null`,
   * or `undefined` (omitted). When omitted, the kernel persists `null`.
   */
  description?: string | null;
  /** Resource the policy targets (closed-enum). */
  resource: AbacPolicyResource;
  /** Action the policy gates (closed-enum). */
  action: AbacPolicyAction;
  /**
   * `"allow"` grants access, `"deny"` denies. Default `"allow"` —
   * the SDK OMITS this field when consumer omits it; kernel applies
   * `"allow"`. Per invariant #52.
   */
  effect?: AbacPolicyEffect;
  /**
   * Recursive condition AST evaluated against `{principal, resource}`.
   * The SDK does NOT pre-validate the AST grammar — the kernel's
   * canonical validator at `src/lib/auth/abac-policies.ts:161-174`
   * handles depth / clause / value-list / total-node budgets +
   * per-operator allowed keys. SDK-side check is only "is this an
   * object" (rejects `null`, arrays, primitives).
   */
  condition: AbacCondition;
  /**
   * Integer [0, 1000]. Default `100` — the SDK OMITS this field when
   * consumer omits it; kernel applies `100`. Per invariant #52.
   * Lower values are evaluated FIRST (asc), but the deny-wins
   * algorithm short-circuits regardless of order.
   */
  priority?: number;
  /**
   * Per-policy enable flag. Default `true` — the SDK OMITS this field
   * when consumer omits it; kernel applies `true`. When `false`, the
   * policy is excluded from the per-request fetch.
   */
  enabled?: boolean;
}

// ─── Update input shape ─────────────────────────────────────────────────────

/**
 * Input shape for `.update()`. Mirror of the kernel's
 * `updateAbacPolicySchema` Zod at
 * `src/lib/auth/abac-policies.ts:763-795`. The kernel applies
 * **`.strict()`** — any extra fields are rejected with 422.
 *
 * **EVERY field is optional** — `.update()` is a PARTIAL update
 * (PATCH semantics). Asymmetric with `AbacPolicyCreateInput`, whose
 * `name` / `resource` / `action` / `condition` are required: the
 * kernel's `updateAbacPolicySchema` carries `.optional()` on all 8
 * fields. A consumer patches only the fields they want to change.
 *
 * **Empty-patch rejection** — the kernel schema ends in a `.refine()`
 * rejecting a body with NO updatable field (`"PATCH body must
 * include at least one updatable field"`). The SDK pre-rejects an
 * empty patch — `update(id, {})`, an all-`undefined` patch, or a
 * patch carrying ONLY unknown keys — synchronously with a
 * `TypeError` BEFORE any fetch is issued.
 *
 * **`description` accepts `null`** — passing `description: null`
 * CLEARS an existing description. `null` is a present field for the
 * kernel's `.refine()` (`description !== undefined` is `true` when
 * `description` is `null`), so `update(id, { description: null })`
 * is a valid non-empty patch. An explicit `description: undefined`
 * is treated as omission (symmetric with `.create()`).
 *
 * **`condition` is the recursive AST** (`AbacCondition`) — same as
 * `.create()`. The SDK does NOT pre-validate the AST grammar; a
 * present `condition` is pre-validated only as "is this a non-null
 * object", and the recursive grammar defers to the kernel's
 * canonical validator. The fields reuse `AbacPolicyResource` /
 * `AbacPolicyAction` / `AbacPolicyEffect` / `AbacCondition` verbatim.
 */
export interface AbacPolicyUpdateInput {
  /**
   * New short identifier (1-128 chars). UNIQUE per `(orgId, name)` on
   * the `abac_policies` table — a collision trips
   * `AbacPolicyNameConflictError` (HTTP 409).
   */
  name?: string;
  /**
   * New description (max 2000 chars). Accepts `string`, `null`, or
   * `undefined` (omitted). Pass `null` to CLEAR an existing
   * description — `null` counts as a present field (a non-empty
   * patch); `undefined` is treated as omission.
   */
  description?: string | null;
  /** New resource the policy targets (closed-enum). */
  resource?: AbacPolicyResource;
  /** New action the policy gates (closed-enum). */
  action?: AbacPolicyAction;
  /** New effect — `"allow"` grants access, `"deny"` denies (closed-enum). */
  effect?: AbacPolicyEffect;
  /**
   * New recursive condition AST evaluated against `{principal,
   * resource}`. The SDK pre-validates only that a present `condition`
   * is a non-null object; the recursive AST grammar (depth / clause /
   * value-list / total-node budgets, per-operator allowed keys) is
   * validated server-side by the kernel's canonical validator.
   */
  condition?: AbacCondition;
  /** New priority — integer [0, 1000]. Lower values are evaluated FIRST. */
  priority?: number;
  /** New per-policy enable flag. When `false`, the policy is excluded from the per-request fetch. */
  enabled?: boolean;
}

// ─── Resource class ─────────────────────────────────────────────────────────

/**
 * `abacPolicies` resource — sibling to all 10 existing resource classes
 * on the SDK. The class is the landing pad for the 5-method CRUD
 * cluster; `.list()` is the first method to ship (session 21), with
 * `.create()` / `.retrieve()` / `.update()` / `.delete()` arriving in
 * session 22. Resource-class-per-kernel-resource convention,
 * invariant #43.
 */
export class AbacPoliciesResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * List ABAC policies for the caller's org. Returns up to 200 rows
   * ordered by `priority` ASC. No pagination; the cap is a documented
   * kernel surface gap.
   *
   * **Dual-auth admin scope** — the kernel route gates on
   * `requireSessionOrApiKey(request, { sessionRoles: ["admin"],
   * apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })`. The SDK's
   * transport always sends `x-api-key`, so the api-key path is the
   * only one reachable from SDK consumers. An api-key without the
   * `ADMIN` permission returns 403 (NOT 401 — see status code
   * surface below).
   *
   * **Status-code surface — 401 AND 403 distinguished** (verified
   * by reading `src/lib/middleware/auth.ts:96-110` and
   * `src/lib/middleware/permissions.ts:35-66`):
   *   - **HTTP 401**: no `x-api-key` header, empty `x-api-key`
   *     header (`""`), invalid key (no matching row), expired key.
   *   - **HTTP 403**: valid api-key in the org whose `permissions`
   *     column does NOT include `ADMIN`. Error message: `"API key
   *     lacks required permission. Required: admin. Key has: ..."`.
   * `auditLog.export` shares this EXACT dual-auth surface — its
   * kernel route uses the identical `requireSessionOrApiKey(...
   * sessionRoles:["admin"], apiKeyPermissions:[ADMIN] ...)` gate, so
   * it too returns 401 vs 403 distinctly. (The `audit-log.ts` JSDoc's
   * prior "HTTP 401 for both" claim was a mis-read of the kernel
   * test's mocked `AuthError(401)` — corrected in session-22 hostile
   * review #2.)
   *
   * **No pagination** — `count` is `items.length`, NOT a total org
   * count. Server-side cap is 200 rows by priority ASC. Orgs with
   * >200 policies are silently truncated (documented invariant #50
   * gap; the SDK does NOT auto-paginate this method because the
   * kernel emits no cursor — there's no next-page anchor to follow).
   *
   * **No `writeAuditLog` side effect** — `.list()` is quiet
   * (asymmetric with `gate.evaluate` / `batch.submit` /
   * `shipGate.check` which all write entries).
   *
   * **Symmetric prototype-pollution defense — RESPONSE side only**:
   * the P2 validator uses the module-load `objectHasOwn` snapshot on
   * each response field read. Input side is N/A (`.list()` has no
   * input fields). Mirror of `audit-log.verifyChain` /
   * `regulatoryChanges.list` pattern.
   *
   * Errors — **happy-path precedence ordering** is rate-limit → auth
   * → DB lookup → successResponse. **The 500-catchall is a SEPARATE
   * DIMENSION** — any throwable not matched by the named `instanceof`
   * arms (only `AuthError` here) falls to 500, regardless of where
   * in the happy-path it fired.
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     (auto-retried by default — invariant #18; per-IP rate-limit
   *     key `abac-policies-list:${ip}` against the
   *     `assessmentLimiter` — 30 req / 1-min sliding window).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key
   *     OR expired key. Fires AFTER rate-limit.
   *   - `AttestryAPIError` (status 403) — valid api-key in the org
   *     whose permissions do NOT include `ADMIN`. Distinct branch
   *     from 401 — pin BOTH separately per the dual-auth status-
   *     code surface.
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`). **The 500
   *     surface is orthogonal to the precedence list above**: ANY
   *     throwable not matched by the route's single `instanceof
   *     AuthError` arm falls to 500.
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired.
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (not an object, `items` not an
   *     array, `count` not a number).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard before body
   *     parsing).
   *
   * **Notably ABSENT**:
   *   - **No 400** — no input → nothing to validate.
   *   - **No 404** — `.list()` returns `{items: [], count: 0}` on
   *     empty result (NOT 404). 404 is only on `.retrieve()` /
   *     `.update()` / `.delete()` (session 22).
   *
   * **Response-shape validation** (P2 hardening — symmetric defense
   * on response side per the module-load `objectHasOwn` snapshot;
   * mirror of `regulatoryChanges.list` / `incidents.list` patterns):
   *   - Rejects with `AttestryError` if the kernel response isn't
   *     a non-null, non-array object.
   *   - Rejects if `items` isn't an array.
   *   - Rejects if `count` isn't a number.
   *   - Per-row item shape NOT validated (faithful courier — P4
   *     candidate; matches incidents.list / regulatoryChanges.list).
   *
   * **Transport-shape validation** (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with
   *     a non-`application/json` Content-Type.
   *
   * @example List all ABAC policies for the caller's org
   * ```ts
   * const { items, count } = await client.abacPolicies.list();
   * console.log(`${count} policies in this org:`);
   * for (const policy of items) {
   *   console.log(`  ${policy.priority} ${policy.effect} ${policy.action} ${policy.resource}: ${policy.name}`);
   * }
   * ```
   *
   * @example Inspect a policy's condition AST
   * ```ts
   * const { items } = await client.abacPolicies.list();
   * const ownerOnly = items.find((p) => p.name === "owner-only");
   * if (ownerOnly && ownerOnly.condition.op === "attrEq") {
   *   console.log(`Compares ${ownerOnly.condition.left} === ${ownerOnly.condition.right}`);
   * }
   * ```
   */
  list(
    options?: RequestOptions,
  ): Promise<AbacPoliciesListResponse> {
    return this.client
      ._request<AbacPoliciesListResponse>({
        method: "GET",
        path: "/api/v1/abac-policies",
        options,
      })
      .then((result) => validateAbacPoliciesListResponse(result));
  }

  /**
   * Create a new ABAC policy in the caller's org. Returns the
   * inserted row on success (HTTP 201).
   *
   * **Dual-auth admin scope** — same as `.list()`: kernel uses
   * `requireSessionOrApiKey(request, { sessionRoles: ["admin"],
   * apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })`. The SDK's
   * transport always sends `x-api-key`, so the api-key path is the
   * only one reachable from SDK consumers. **HTTP 401** for no/
   * invalid/expired key, **HTTP 403** for valid-key-without-ADMIN
   * permission. Pin BOTH branches separately.
   *
   * **FIRST SDK route to return HTTP 201 on success** (NOT 200).
   * The transport unwraps the `{success:true, data}` envelope and
   * returns the body on any 2xx status — consumers receive the
   * created row directly. To inspect the literal HTTP status,
   * consumers must inspect via fetch-instrumented middleware
   * (not exposed by the SDK today; P4 candidate).
   *
   * **FIRST SDK route with HTTP 409 Conflict surface**. The
   * `(org_id, name)` unique constraint trips `AbacPolicyNameConflictError`
   * at the DB layer; the kernel maps to 409 with error message
   * `An ABAC policy named "<name>" already exists in this organization.`.
   * Consumers should branch on `err.status === 409` to render a
   * specific "name taken" UX.
   *
   * **Three-way 422 fan-out — distinct wire shapes per error class**:
   * The kernel's POST handler catch block has THREE 422-mapping arms:
   *
   *   1. **`BodyParseError`** (most common — from `parseBody(request,
   *      schema)`) → `{ success: false, error: "Validation failed.",
   *      details: Array<{ path: string, message: string }> }`. Raised
   *      when Zod's `.strict()` schema rejects (e.g., extra field,
   *      wrong type, out-of-range value).
   *   2. **`ZodError`** (DEFENSIVE — DEAD on happy path; `parseBody`
   *      catches Zod and converts to `BodyParseError`. The catch arm
   *      exists as defense-in-depth if some other code path throws
   *      raw `ZodError`) → `{ success: false, error: "Validation
   *      failed.", details: ZodIssue[] }` (richer than BodyParseError's
   *      mapped form — includes `code`, `expected`, `received`).
   *   3. **`AbacPolicyValidationError`** (REACHABLE — from server-side
   *      canonical AST validation in `createAbacPolicy`) → `{ success:
   *      false, error: "ABAC policy validation failed: <messages>",
   *      details: { errors: string[] } }`. Raised when the condition
   *      AST violates depth / clause / value-list / total-node budgets,
   *      or has unknown ops / malformed attr paths.
   *
   * SDK surfaces all three uniformly as `AttestryAPIError(422)` —
   * consumers inspect `err.details` to discriminate:
   * - `Array.isArray(err.details)` → BodyParseError OR ZodError
   *   (per-field validation failure; iterate for `{path, message}`).
   * - `err.details && Array.isArray(err.details.errors)` →
   *   AbacPolicyValidationError (AST violation; iterate `details.errors`
   *   for descriptive strings).
   *
   * Drift-pinned in spec-diff round (both wire shapes + the DEAD
   * ZodError catch arm).
   *
   * **Fifth SDK route to PRE-VALIDATE every Zod closed-spec rule
   * synchronously** (after `check.run`, `gate.evaluate`,
   * `batch.submit`, `shipGate.check`). **FIRST SDK route with
   * PARTIAL pre-validation** — the SDK pre-validates all 7 closed-
   * spec fields synchronously (name length, description length-or-
   * null, resource/action/effect closed-enums, priority int +
   * bounds, enabled boolean) AND defers the recursive AST validation
   * on `condition` to the server canonical validator. The condition
   * field is `z.record(z.string(), z.unknown())` at the schema level
   * (OPEN-spec, not pre-validatable without shipping the full
   * recursive validator). Invariant #49 calibration: closed-spec
   * rules ARE pre-validatable; recursive grammar rules are NOT
   * (too expensive to mirror).
   *
   * **`writeAuditLog` side effect — every successful `.create()` call
   * writes one audit entry** with `action: "abac_policy.create"` and
   * `resourceType: "abac_policy"` (kernel route.ts:105-120; both
   * strings drift-pinned). Properties:
   *   - Org-scoped, hash-chained.
   *   - **Time-blocking** but error-tolerant: kernel uses
   *     `await writeAuditLog(...)`; check response latency INCLUDES
   *     the audit-log write time.
   *   - Write FAILURE does NOT fail the request (try/catch swallows).
   *   - NOT counted against `decisionsPerMonth` quota.
   *   - **Audit log is NOT written on failed create** (Zod / canonical
   *     validation / name conflict all surface BEFORE writeAuditLog).
   *
   * **Kernel-side 30-second timeout** (`maxDuration = 30`). Same as
   * `.list()` and `auditLog.export`; looser than `gate.evaluate` /
   * `shipGate.check`'s 15s. ABAC policy creation does NO heavy
   * computation — the 30s budget is for DB I/O headroom.
   *
   * **Default-applied fields**: `effect` defaults to `"allow"`,
   * `priority` defaults to `100`, `enabled` defaults to `true`. The
   * SDK OMITS these fields from the request body when the consumer
   * omits them (so the kernel applies its default). Per invariant #52.
   *
   * Errors:
   *   - `AttestryAPIError` (429) — rate limit (auto-retried; per-IP
   *     key `abac-policies-create:${ip}` against `assessmentLimiter`).
   *   - `AttestryAPIError` (401) — no/invalid/expired api-key.
   *   - `AttestryAPIError` (403) — valid api-key without ADMIN permission.
   *   - `AttestryAPIError` (422) — Zod-schema validation OR canonical-
   *     validator AST failure. Discriminate via `err.details` shape
   *     (see "Three-way 422 fan-out" above).
   *   - `AttestryAPIError` (409) — `(org_id, name)` uniqueness
   *     conflict.
   *   - `AttestryAPIError` (500) — internal kernel error (scrubbed).
   *   - `AttestryError` ("request aborted by caller") — `options.signal`
   *     fired.
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation. Pre-validated per-row shape:
   *     non-null object + all 13 fields present and correctly typed.
   *   - `AttestryAPIError` (P3 hardening) — wrong Content-Type on
   *     response.
   *   - `TypeError` (synchronous, no fetch issued) — SDK-side input
   *     validation: missing required field, wrong type, out-of-range
   *     value, unknown closed-enum value, malformed input.
   *
   * @example Create a simple "owner can edit own assessments" policy
   * ```ts
   * const policy = await client.abacPolicies.create({
   *   name: "owner-can-edit-own",
   *   description: "Owners can edit their own assessments.",
   *   resource: "assessments",
   *   action: "update",
   *   effect: "allow",
   *   condition: {
   *     op: "attrEq",
   *     left: "principal.id",
   *     right: "resource.ownerId",
   *   },
   *   priority: 100,
   *   enabled: true,
   * });
   * console.log(`Created policy ${policy.id}`);
   * ```
   *
   * @example Catch name-conflict (HTTP 409)
   * ```ts
   * try {
   *   await client.abacPolicies.create({...});
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 409) {
   *     // Show "name taken" UX
   *   }
   * }
   * ```
   *
   * @example Discriminate 422 wire-shape (Zod vs canonical-validator)
   * ```ts
   * try {
   *   await client.abacPolicies.create({...});
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 422) {
   *     const details = err.details as unknown;
   *     if (Array.isArray(details)) {
   *       // Zod field-level failures: [{path, message}, ...]
   *     } else if (details && typeof details === "object" &&
   *                Array.isArray((details as {errors?: unknown}).errors)) {
   *       // Canonical-validator AST failures: {errors: string[]}
   *     }
   *   }
   * }
   * ```
   */
  create(
    input: AbacPolicyCreateInput,
    options?: RequestOptions,
  ): Promise<AbacPolicy> {
    // Top-level shape — input is REQUIRED.
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "abacPolicies.create: `input` must be a non-null object with " +
          "`name`, `resource`, `action`, `condition` (and optional " +
          "`description`, `effect`, `priority`, `enabled`)",
      );
    }

    // Snapshot each field's value EXACTLY ONCE up front via the
    // own-property indexer, then operate only on the locals
    // downstream. Four motivations (mirror of ship-gate.ts):
    //   1. Prototype-pollution defense (generalization of #48).
    //   2. TOCTOU defense — Proxy / getter inputs read once.
    //   3. Missing-key shape: objectHasOwn correctly returns false.
    //   4. Throwing-getter defense — `readInputField` converts a
    //      throwing accessor's exception into the documented
    //      synchronous `TypeError` input contract (session-22
    //      hostile review #1; the SDK-wide MEDIUM-1 fix).
    const hasName = objectHasOwn(input, "name");
    const nameRaw: unknown = hasName
      ? readInputField(input, "name", "abacPolicies.create")
      : undefined;
    const hasDescription = objectHasOwn(input, "description");
    const descriptionRaw: unknown = hasDescription
      ? readInputField(input, "description", "abacPolicies.create")
      : undefined;
    const hasResource = objectHasOwn(input, "resource");
    const resourceRaw: unknown = hasResource
      ? readInputField(input, "resource", "abacPolicies.create")
      : undefined;
    const hasAction = objectHasOwn(input, "action");
    const actionRaw: unknown = hasAction
      ? readInputField(input, "action", "abacPolicies.create")
      : undefined;
    const hasEffect = objectHasOwn(input, "effect");
    const effectRaw: unknown = hasEffect
      ? readInputField(input, "effect", "abacPolicies.create")
      : undefined;
    const hasCondition = objectHasOwn(input, "condition");
    const conditionRaw: unknown = hasCondition
      ? readInputField(input, "condition", "abacPolicies.create")
      : undefined;
    const hasPriority = objectHasOwn(input, "priority");
    const priorityRaw: unknown = hasPriority
      ? readInputField(input, "priority", "abacPolicies.create")
      : undefined;
    const hasEnabled = objectHasOwn(input, "enabled");
    const enabledRaw: unknown = hasEnabled
      ? readInputField(input, "enabled", "abacPolicies.create")
      : undefined;

    // ─── Required field validation ──────────────────────────────────────────

    // name — REQUIRED non-empty string, length 1-128.
    if (!hasName || nameRaw === undefined) {
      throw new TypeError("abacPolicies.create: `name` is required");
    }
    if (typeof nameRaw !== "string") {
      throw new TypeError(
        `abacPolicies.create: \`name\` must be a string ` +
          `(got ${describeType(nameRaw)})`,
      );
    }
    if (nameRaw.length === 0) {
      throw new TypeError(
        "abacPolicies.create: `name` must be a non-empty string",
      );
    }
    if (nameRaw.length > MAX_POLICY_NAME_LENGTH) {
      throw new TypeError(
        `abacPolicies.create: \`name\` exceeds the kernel's max length of ` +
          `${MAX_POLICY_NAME_LENGTH} chars (got ${nameRaw.length})`,
      );
    }

    // resource — REQUIRED closed-enum.
    if (!hasResource || resourceRaw === undefined) {
      throw new TypeError("abacPolicies.create: `resource` is required");
    }
    if (typeof resourceRaw !== "string") {
      throw new TypeError(
        `abacPolicies.create: \`resource\` must be a string ` +
          `(got ${describeType(resourceRaw)})`,
      );
    }
    if (
      !(ABAC_POLICY_RESOURCES as readonly string[]).includes(resourceRaw)
    ) {
      throw new TypeError(
        `abacPolicies.create: \`resource\` must be one of ` +
          `[${ABAC_POLICY_RESOURCES.join(", ")}] (got "${resourceRaw}")`,
      );
    }

    // action — REQUIRED closed-enum.
    if (!hasAction || actionRaw === undefined) {
      throw new TypeError("abacPolicies.create: `action` is required");
    }
    if (typeof actionRaw !== "string") {
      throw new TypeError(
        `abacPolicies.create: \`action\` must be a string ` +
          `(got ${describeType(actionRaw)})`,
      );
    }
    if (!(ABAC_POLICY_ACTIONS as readonly string[]).includes(actionRaw)) {
      throw new TypeError(
        `abacPolicies.create: \`action\` must be one of ` +
          `[${ABAC_POLICY_ACTIONS.join(", ")}] (got "${actionRaw}")`,
      );
    }

    // condition — REQUIRED non-null object (AST validation defers to server).
    if (!hasCondition || conditionRaw === undefined) {
      throw new TypeError("abacPolicies.create: `condition` is required");
    }
    if (
      conditionRaw === null ||
      typeof conditionRaw !== "object" ||
      Array.isArray(conditionRaw)
    ) {
      throw new TypeError(
        `abacPolicies.create: \`condition\` must be a non-null object ` +
          `(got ${describeType(conditionRaw)}). The recursive AST grammar ` +
          `is validated server-side by the canonical validator.`,
      );
    }

    // ─── Optional field validation (per invariant #52 — omit when missing) ─

    // description — OPTIONAL string OR null. An explicit `undefined`
    // own-property is treated as omission (consistent with the JSDoc
    // claim "Accepts `string`, `null`, or `undefined` (omitted)" AND
    // with the symmetric pattern used by `effect` / `priority` /
    // `enabled` below). The kernel's Zod is `.optional().nullable()`
    // so `undefined` AND missing-key are both accepted server-side;
    // JSON.stringify drops undefined fields anyway. Pre-rejecting
    // undefined here was a HIGH false-positive: a consumer doing
    // `{...form, description: form.maybeStr}` where `maybeStr: string |
    // undefined` would hit a TypeError despite the JSDoc claim
    // (hostile-review HIGH-1).
    if (hasDescription && descriptionRaw !== undefined) {
      if (descriptionRaw !== null && typeof descriptionRaw !== "string") {
        throw new TypeError(
          `abacPolicies.create: \`description\` must be a string or null ` +
            `when present (got ${describeType(descriptionRaw)})`,
        );
      }
      if (
        typeof descriptionRaw === "string" &&
        descriptionRaw.length > MAX_POLICY_DESCRIPTION_LENGTH
      ) {
        throw new TypeError(
          `abacPolicies.create: \`description\` exceeds the kernel's max ` +
            `length of ${MAX_POLICY_DESCRIPTION_LENGTH} chars ` +
            `(got ${descriptionRaw.length})`,
        );
      }
    }

    // effect — OPTIONAL closed-enum. Default "allow" applied server-side.
    if (hasEffect && effectRaw !== undefined) {
      if (typeof effectRaw !== "string") {
        throw new TypeError(
          `abacPolicies.create: \`effect\` must be a string when present ` +
            `(got ${describeType(effectRaw)})`,
        );
      }
      if (!(ABAC_POLICY_EFFECTS as readonly string[]).includes(effectRaw)) {
        throw new TypeError(
          `abacPolicies.create: \`effect\` must be one of ` +
            `[${ABAC_POLICY_EFFECTS.join(", ")}] (got "${effectRaw}")`,
        );
      }
    }

    // priority — OPTIONAL int [0, 1000]. Default 100 applied server-side.
    if (hasPriority && priorityRaw !== undefined) {
      if (typeof priorityRaw !== "number" || !Number.isFinite(priorityRaw)) {
        throw new TypeError(
          `abacPolicies.create: \`priority\` must be a finite number when ` +
            `present (got ${describeType(priorityRaw)})`,
        );
      }
      if (!Number.isInteger(priorityRaw)) {
        throw new TypeError(
          `abacPolicies.create: \`priority\` must be an integer when ` +
            `present (got ${priorityRaw})`,
        );
      }
      if (
        priorityRaw < MIN_POLICY_PRIORITY ||
        priorityRaw > MAX_POLICY_PRIORITY
      ) {
        throw new TypeError(
          `abacPolicies.create: \`priority\` must be in range ` +
            `[${MIN_POLICY_PRIORITY}, ${MAX_POLICY_PRIORITY}] ` +
            `(got ${priorityRaw})`,
        );
      }
    }

    // enabled — OPTIONAL boolean. Default true applied server-side.
    if (hasEnabled && enabledRaw !== undefined) {
      if (typeof enabledRaw !== "boolean") {
        throw new TypeError(
          `abacPolicies.create: \`enabled\` must be a boolean when present ` +
            `(got ${describeType(enabledRaw)})`,
        );
      }
    }

    // ─── Body construction (omit defaults so kernel applies them — #52) ────
    const body: Record<string, unknown> = {
      name: nameRaw,
      resource: resourceRaw,
      action: actionRaw,
      condition: conditionRaw,
    };
    if (hasDescription && descriptionRaw !== undefined) {
      // Pass through both string and null verbatim (caller's intent).
      // Explicit `undefined` is treated as omission per the JSDoc
      // contract — JSON.stringify would drop the key anyway, but the
      // symmetric guard with effect/priority/enabled keeps the body
      // construction predictable (hostile-review HIGH-1).
      body.description = descriptionRaw;
    }
    if (hasEffect && effectRaw !== undefined) {
      body.effect = effectRaw;
    }
    if (hasPriority && priorityRaw !== undefined) {
      body.priority = priorityRaw;
    }
    if (hasEnabled && enabledRaw !== undefined) {
      body.enabled = enabledRaw;
    }

    return this.client
      ._request<AbacPolicy>({
        method: "POST",
        path: "/api/v1/abac-policies",
        body,
        options,
      })
      .then((result) => validateAbacPolicy(result, "abacPolicies.create"));
  }

  /**
   * Retrieve one ABAC policy by id. Returns the policy row.
   *
   * **FIRST `abacPolicies` method with a UUID path segment** — `id`
   * is interpolated into the request path
   * (`/api/v1/abac-policies/<id>`). `.list()` / `.create()` hit the
   * collection path with no segment; `.update()` / `.delete()` share
   * this id-path shape.
   *
   * **Dual-auth admin scope** — same as `.list()` / `.create()`: the
   * kernel route gates on `requireSessionOrApiKey(request, {
   * sessionRoles: ["admin"], apiKeyPermissions:
   * [API_KEY_PERMISSIONS.ADMIN] })`. The SDK transport always sends
   * `x-api-key`, so the api-key path is the only one reachable from
   * SDK consumers. **HTTP 401** for no/invalid/expired key, **HTTP
   * 403** for a valid key whose permissions do NOT include `ADMIN`.
   * Pin BOTH branches separately (asymmetric with carry-forward
   * invariant #42's ADMIN-only 401-collapse).
   *
   * **UUID pre-validation** — the SDK pre-validates `id` against
   * `UUID_REGEX` synchronously (`TypeError`, NO fetch issued) before
   * constructing the URL. The kernel's own `badId` check would
   * return HTTP 400 "Invalid policy id." on a malformed id, but the
   * SDK pre-empts it — that 400 is reachable only via an `as any`
   * cast or a kernel-side id-flavor change. Mirror of `batch.get`.
   *
   * **No `encodeURIComponent` / URIError defense on the path
   * segment** — a string matching `UUID_REGEX` is ASCII hex digits +
   * hyphens, so it is URL-safe verbatim and cannot trigger a
   * `URIError`. The validated `id` is interpolated raw. Asymmetric
   * with `decisions.retrieve` (free-form id → `encodePathSegment`
   * with path-traversal + URIError defenses).
   *
   * **404 surface** — the kernel's `getAbacPolicyById(orgId, id)`
   * returns `null` for a missing id OR a cross-org id (the
   * `eq(orgId)` clause silently filters policies in other orgs), and
   * the GET handler maps that to `errorResponse("ABAC policy not
   * found.", 404)`. **Inline literal message** — distinct from
   * `.update()` / `.delete()`'s 404, which is raised by
   * `AbacPolicyNotFoundError` with the id-embedded message `"ABAC
   * policy <id> not found in this organization."`.
   *
   * **No `writeAuditLog` side effect** — `.retrieve()` is a quiet
   * read (same as `.list()`; asymmetric with `.create()` /
   * `.update()` / `.delete()`, which each write an `abac_policy.*`
   * audit-log entry).
   *
   * **Kernel-side 30-second timeout** (`maxDuration = 30`). Same as
   * `.list()` / `.create()` / `auditLog.export`; looser than
   * `gate.evaluate` / `shipGate.check`'s 15s.
   *
   * Errors — **happy-path precedence ordering**: UUID format (kernel
   * `badId` — SDK-pre-empted) → rate-limit → auth → DB lookup →
   * successResponse. **The 500-catchall is a SEPARATE DIMENSION** —
   * any throwable not matched by the GET handler's single
   * `instanceof AuthError` arm falls to 500.
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     among the network surfaces (auto-retried by default —
   *     invariant #18; per-IP key `abac-policies-get:${ip}` against
   *     `assessmentLimiter` — 30 req / 1-min sliding window).
   *   - `AttestryAPIError` (status 401) — no/invalid/expired api-key.
   *   - `AttestryAPIError` (status 403) — valid api-key whose
   *     permissions do NOT include `ADMIN`. Distinct branch from
   *     401 — pin BOTH separately.
   *   - `AttestryAPIError` (status 404) — policy not found OR a
   *     cross-org id (kernel collapses both to "ABAC policy not
   *     found.").
   *   - `AttestryAPIError` (status 400) — kernel `badId` rejected
   *     the id. **SDK-pre-empted** — reachable from a consumer only
   *     via an `as any` cast or a kernel-side id-flavor change.
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`). **Orthogonal
   *     to the precedence list** — ANY throwable not matched by the
   *     route's single `instanceof AuthError` arm falls here.
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired.
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (non-object, or any of the 13
   *     `AbacPolicy` fields missing / wrong-typed).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard before body
   *     parsing).
   *   - `TypeError` (synchronous, NO fetch issued) — `id` is missing,
   *     a non-string, an empty string, or not an RFC 4122 UUID.
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch
   * issued):
   *   - `id`: required; must be a non-empty string matching
   *     `UUID_REGEX` (RFC 4122 hyphenated, case-insensitive).
   *
   * **Response-shape validation** (P2 hardening) — the shared
   * `validateAbacPolicy` validator checks all 13 `AbacPolicy` fields
   * via the module-load `objectHasOwn` snapshot (symmetric
   * prototype-pollution defense). `condition` is validated as a
   * non-null object only — the recursive AST is faithful-courier.
   *
   * **Transport-shape validation** (P3 hardening) — rejects with
   * `AttestryAPIError` if the kernel responds with a
   * non-`application/json` Content-Type.
   *
   * @example Retrieve a policy by id
   * ```ts
   * const policy = await client.abacPolicies.retrieve(
   *   "550e8400-e29b-41d4-a716-446655440000",
   * );
   * console.log(`${policy.effect} ${policy.action} ${policy.resource}`);
   * ```
   *
   * @example Handle not-found (HTTP 404)
   * ```ts
   * try {
   *   return await client.abacPolicies.retrieve(id);
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 404) {
   *     return null; // policy doesn't exist (or belongs to another org)
   *   }
   *   throw err;
   * }
   * ```
   */
  retrieve(id: string, options?: RequestOptions): Promise<AbacPolicy> {
    assertValidPolicyId(id, "abacPolicies.retrieve");
    return this.client
      ._request<AbacPolicy>({
        method: "GET",
        path: `/api/v1/abac-policies/${id}`,
        options,
      })
      .then((result) => validateAbacPolicy(result, "abacPolicies.retrieve"));
  }

  /**
   * Update one ABAC policy by id (PARTIAL update). Returns the
   * **updated row** — the policy as it exists AFTER the patch is
   * applied — on HTTP 200.
   *
   * **SECOND SDK method using the HTTP `PATCH` verb** (`incidents.update`
   * is the first). The kernel route is `PATCH /api/v1/abac-policies/[id]`.
   *
   * **Partial update — every input field is optional.** A consumer
   * patches only the fields they want to change; omitted fields keep
   * their current value. The SDK builds the request body from the
   * present-and-not-`undefined` fields only — an omitted field (or an
   * explicit `field: undefined`) is left out of the body so the kernel
   * leaves that column untouched.
   *
   * **Empty-patch pre-validation.** The kernel's `updateAbacPolicySchema`
   * ends in a `.refine()` rejecting a body with NO updatable field
   * (`"PATCH body must include at least one updatable field"`). The
   * SDK pre-rejects an empty patch — `update(id, {})`, an
   * all-`undefined` patch, or a patch carrying ONLY unknown keys —
   * synchronously with a `TypeError` (NO fetch issued) so the consumer
   * never burns a round-trip on a guaranteed 422.
   *
   * **Dual-auth admin scope** — same as `.list()` / `.create()` /
   * `.retrieve()` / `.delete()`: `requireSessionOrApiKey(request, {
   * sessionRoles: ["admin"], apiKeyPermissions:
   * [API_KEY_PERMISSIONS.ADMIN] })`. **HTTP 401** for no/invalid/
   * expired key, **HTTP 403** for a valid key whose permissions do NOT
   * include `ADMIN`. Pin BOTH branches separately.
   *
   * **UUID pre-validation** — `id` is pre-validated against
   * `UUID_REGEX` synchronously via the shared `assertValidPolicyId`
   * helper (`TypeError`, NO fetch issued). The kernel `badId` 400
   * ("Invalid policy id.") is SDK-pre-empted. **No `encodeURIComponent`
   * / URIError defense** — a validated UUID is ASCII hex + hyphens and
   * is interpolated into the path raw (mirror of `batch.get`).
   *
   * **Partial Zod pre-validation** — the closed-spec fields that ARE
   * present are pre-validated synchronously (name length, description
   * length-or-null, resource/action/effect closed-enums, priority
   * int+bounds, enabled boolean); a present `condition` is checked
   * only as a non-null object, deferring the recursive AST grammar to
   * the kernel's canonical validator. Mirror of `.create()`'s partial
   * pre-validation — but here EVERY field is optional.
   *
   * **`description: null` CLEARS the description.** Passing
   * `description: null` is a valid non-empty patch — the kernel
   * persists `null`. An explicit `description: undefined` is treated
   * as omission (symmetric with `.create()`).
   *
   * **Three-way 422 fan-out — same distinct wire shapes as `.create()`:**
   *   1. **`BodyParseError`** (Zod `.strict()` rejection via
   *      `parseBody`) → `details: Array<{ path, message }>`.
   *   2. **`ZodError`** (DEFENSIVE — DEAD on the happy path;
   *      `parseBody` catches Zod and converts to `BodyParseError`) →
   *      `details: ZodIssue[]`.
   *   3. **`AbacPolicyValidationError`** (server-side canonical AST
   *      validation) → `details: { errors: string[] }`.
   * SDK surfaces all three uniformly as `AttestryAPIError(422)` —
   * discriminate via `err.details` (see the `.create()` examples).
   *
   * **HTTP 409 Conflict** — patching `name` to a value already used
   * by a sibling policy in the org trips the `(orgId, name)` unique
   * constraint → `AbacPolicyNameConflictError` → 409.
   *
   * **HTTP 404** — the kernel's `updateAbacPolicy` throws
   * `AbacPolicyNotFoundError` when the `(id, orgId)`-scoped lookup
   * misses (a missing id OR a cross-org id). **The message is
   * id-embedded** — `"ABAC policy <id> not found in this
   * organization."` — same shape as `.delete()`'s 404 (distinct from
   * `.retrieve()`'s INLINE `"ABAC policy not found."`).
   *
   * **6 named-error catch arms — the LARGEST on the SDK**, in order:
   * `AuthError`, `BodyParseError`, `ZodError`,
   * `AbacPolicyValidationError`, `AbacPolicyNameConflictError`,
   * `AbacPolicyNotFoundError`. Everything else falls to the 500
   * `internalErrorResponse` catchall.
   *
   * **`writeAuditLog` side effect** — every successful `.update()`
   * writes one audit-log entry with `action: "abac_policy.update"`
   * and `resourceType: "abac_policy"`; the entry's `details` records
   * the changed field names plus a structured `before`/`after` diff.
   * The write is org-scoped + hash-chained, `await`-ed (so `.update()`
   * latency includes the audit write) but error-tolerant (a write
   * failure does NOT fail the request) and is NOT counted against any
   * quota. The audit log is NOT written on a failed update — 404 /
   * 409 / 422 all surface BEFORE the `writeAuditLog` call.
   *
   * **Kernel-side 30-second timeout** (`maxDuration = 30`). Same as
   * `.list()` / `.create()` / `.retrieve()` / `.delete()`.
   *
   * Errors — **happy-path precedence ordering**: UUID format (kernel
   * `badId` — SDK-pre-empted) → rate-limit → auth → body parse → DB
   * lookup/update → audit write → successResponse.
   *   - `AttestryAPIError` (429) — rate limit FIRES FIRST among the
   *     network surfaces (auto-retried; per-IP key
   *     `abac-policies-patch:${ip}` against `assessmentLimiter`).
   *   - `AttestryAPIError` (401) — no/invalid/expired api-key.
   *   - `AttestryAPIError` (403) — valid api-key without `ADMIN`.
   *     Distinct branch from 401 — pin BOTH separately.
   *   - `AttestryAPIError` (422) — Zod-schema validation OR canonical-
   *     validator AST failure. Discriminate via `err.details` shape.
   *   - `AttestryAPIError` (409) — `(orgId, name)` uniqueness conflict.
   *   - `AttestryAPIError` (404) — policy not found OR a cross-org id
   *     (`AbacPolicyNotFoundError`; id-embedded message).
   *   - `AttestryAPIError` (400) — kernel `badId` rejected the id.
   *     **SDK-pre-empted**.
   *   - `AttestryAPIError` (500) — internal kernel error (scrubbed).
   *   - `AttestryError` ("request aborted by caller") — `options.signal`
   *     fired.
   *   - `AttestryError` (P2 hardening) — the updated row failed
   *     SDK-side shape validation (non-object, or any of the 13
   *     `AbacPolicy` fields missing / wrong-typed).
   *   - `AttestryAPIError` (P3 hardening) — wrong Content-Type on the
   *     response.
   *   - `TypeError` (synchronous, NO fetch issued) — invalid `id`;
   *     `input` not a non-null object; a present field is the wrong
   *     type / out of range / an unknown closed-enum value; OR the
   *     patch is empty (no updatable field).
   *
   * @example Patch a single field (the rest of the policy is unchanged)
   * ```ts
   * const updated = await client.abacPolicies.update(
   *   "550e8400-e29b-41d4-a716-446655440000",
   *   { enabled: false },
   * );
   * console.log(`Policy "${updated.name}" is now ${updated.enabled ? "on" : "off"}`);
   * ```
   *
   * @example Clear a description (pass null) and re-prioritize
   * ```ts
   * await client.abacPolicies.update(id, { description: null, priority: 10 });
   * ```
   *
   * @example Catch a name-conflict (HTTP 409)
   * ```ts
   * try {
   *   await client.abacPolicies.update(id, { name: "taken-name" });
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 409) {
   *     // another policy in the org already uses that name
   *   }
   * }
   * ```
   */
  update(
    id: string,
    input: AbacPolicyUpdateInput,
    options?: RequestOptions,
  ): Promise<AbacPolicy> {
    // `id` first — the path segment is validated before the body,
    // mirror of the kernel PATCH handler (`badId` runs before
    // `parseBody`).
    assertValidPolicyId(id, "abacPolicies.update");

    // Top-level shape — `input` is REQUIRED (a non-null, non-array
    // object). `update(id)` with no second argument lands here too
    // (`undefined` is not an object).
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "abacPolicies.update: `input` must be a non-null object with at " +
          "least one updatable field (`name`, `description`, `resource`, " +
          "`action`, `effect`, `condition`, `priority`, `enabled`)",
      );
    }

    // Snapshot each field's value EXACTLY ONCE up front via the
    // own-property indexer, then operate only on the locals downstream
    // (mirror of `.create()`): prototype-pollution defense, TOCTOU
    // defense (Proxy / getter inputs read once), a correct missing-key
    // shape (objectHasOwn returns false), and the throwing-getter
    // defense (`readInputField` converts a throwing accessor into the
    // documented synchronous `TypeError` — session-22 hostile review
    // #1, the SDK-wide MEDIUM-1 fix).
    const hasName = objectHasOwn(input, "name");
    const nameRaw: unknown = hasName
      ? readInputField(input, "name", "abacPolicies.update")
      : undefined;
    const hasDescription = objectHasOwn(input, "description");
    const descriptionRaw: unknown = hasDescription
      ? readInputField(input, "description", "abacPolicies.update")
      : undefined;
    const hasResource = objectHasOwn(input, "resource");
    const resourceRaw: unknown = hasResource
      ? readInputField(input, "resource", "abacPolicies.update")
      : undefined;
    const hasAction = objectHasOwn(input, "action");
    const actionRaw: unknown = hasAction
      ? readInputField(input, "action", "abacPolicies.update")
      : undefined;
    const hasEffect = objectHasOwn(input, "effect");
    const effectRaw: unknown = hasEffect
      ? readInputField(input, "effect", "abacPolicies.update")
      : undefined;
    const hasCondition = objectHasOwn(input, "condition");
    const conditionRaw: unknown = hasCondition
      ? readInputField(input, "condition", "abacPolicies.update")
      : undefined;
    const hasPriority = objectHasOwn(input, "priority");
    const priorityRaw: unknown = hasPriority
      ? readInputField(input, "priority", "abacPolicies.update")
      : undefined;
    const hasEnabled = objectHasOwn(input, "enabled");
    const enabledRaw: unknown = hasEnabled
      ? readInputField(input, "enabled", "abacPolicies.update")
      : undefined;

    // ─── Per-field validation (EVERY field optional — PATCH semantics) ─────
    // Each block fires only when the field is present AND not
    // `undefined` — an explicit `undefined` own-property is treated as
    // omission, the same convention `.create()` applies to its optional
    // fields.

    // name — when present: non-empty string, length 1-128.
    if (hasName && nameRaw !== undefined) {
      if (typeof nameRaw !== "string") {
        throw new TypeError(
          `abacPolicies.update: \`name\` must be a string when present ` +
            `(got ${describeType(nameRaw)})`,
        );
      }
      if (nameRaw.length === 0) {
        throw new TypeError(
          "abacPolicies.update: `name` must be a non-empty string when present",
        );
      }
      if (nameRaw.length > MAX_POLICY_NAME_LENGTH) {
        throw new TypeError(
          `abacPolicies.update: \`name\` exceeds the kernel's max length ` +
            `of ${MAX_POLICY_NAME_LENGTH} chars (got ${nameRaw.length})`,
        );
      }
    }

    // description — when present: string OR null. An explicit
    // `undefined` is treated as omission; `null` CLEARS the field.
    if (hasDescription && descriptionRaw !== undefined) {
      if (descriptionRaw !== null && typeof descriptionRaw !== "string") {
        throw new TypeError(
          `abacPolicies.update: \`description\` must be a string or null ` +
            `when present (got ${describeType(descriptionRaw)})`,
        );
      }
      if (
        typeof descriptionRaw === "string" &&
        descriptionRaw.length > MAX_POLICY_DESCRIPTION_LENGTH
      ) {
        throw new TypeError(
          `abacPolicies.update: \`description\` exceeds the kernel's max ` +
            `length of ${MAX_POLICY_DESCRIPTION_LENGTH} chars ` +
            `(got ${descriptionRaw.length})`,
        );
      }
    }

    // resource — when present: closed-enum.
    if (hasResource && resourceRaw !== undefined) {
      if (typeof resourceRaw !== "string") {
        throw new TypeError(
          `abacPolicies.update: \`resource\` must be a string when present ` +
            `(got ${describeType(resourceRaw)})`,
        );
      }
      if (
        !(ABAC_POLICY_RESOURCES as readonly string[]).includes(resourceRaw)
      ) {
        throw new TypeError(
          `abacPolicies.update: \`resource\` must be one of ` +
            `[${ABAC_POLICY_RESOURCES.join(", ")}] (got "${resourceRaw}")`,
        );
      }
    }

    // action — when present: closed-enum.
    if (hasAction && actionRaw !== undefined) {
      if (typeof actionRaw !== "string") {
        throw new TypeError(
          `abacPolicies.update: \`action\` must be a string when present ` +
            `(got ${describeType(actionRaw)})`,
        );
      }
      if (!(ABAC_POLICY_ACTIONS as readonly string[]).includes(actionRaw)) {
        throw new TypeError(
          `abacPolicies.update: \`action\` must be one of ` +
            `[${ABAC_POLICY_ACTIONS.join(", ")}] (got "${actionRaw}")`,
        );
      }
    }

    // effect — when present: closed-enum.
    if (hasEffect && effectRaw !== undefined) {
      if (typeof effectRaw !== "string") {
        throw new TypeError(
          `abacPolicies.update: \`effect\` must be a string when present ` +
            `(got ${describeType(effectRaw)})`,
        );
      }
      if (!(ABAC_POLICY_EFFECTS as readonly string[]).includes(effectRaw)) {
        throw new TypeError(
          `abacPolicies.update: \`effect\` must be one of ` +
            `[${ABAC_POLICY_EFFECTS.join(", ")}] (got "${effectRaw}")`,
        );
      }
    }

    // condition — when present: non-null object (AST defers to server).
    if (hasCondition && conditionRaw !== undefined) {
      if (
        conditionRaw === null ||
        typeof conditionRaw !== "object" ||
        Array.isArray(conditionRaw)
      ) {
        throw new TypeError(
          `abacPolicies.update: \`condition\` must be a non-null object ` +
            `when present (got ${describeType(conditionRaw)}). The ` +
            `recursive AST grammar is validated server-side by the ` +
            `canonical validator.`,
        );
      }
    }

    // priority — when present: integer [0, 1000].
    if (hasPriority && priorityRaw !== undefined) {
      if (typeof priorityRaw !== "number" || !Number.isFinite(priorityRaw)) {
        throw new TypeError(
          `abacPolicies.update: \`priority\` must be a finite number when ` +
            `present (got ${describeType(priorityRaw)})`,
        );
      }
      if (!Number.isInteger(priorityRaw)) {
        throw new TypeError(
          `abacPolicies.update: \`priority\` must be an integer when ` +
            `present (got ${priorityRaw})`,
        );
      }
      if (
        priorityRaw < MIN_POLICY_PRIORITY ||
        priorityRaw > MAX_POLICY_PRIORITY
      ) {
        throw new TypeError(
          `abacPolicies.update: \`priority\` must be in range ` +
            `[${MIN_POLICY_PRIORITY}, ${MAX_POLICY_PRIORITY}] ` +
            `(got ${priorityRaw})`,
        );
      }
    }

    // enabled — when present: boolean.
    if (hasEnabled && enabledRaw !== undefined) {
      if (typeof enabledRaw !== "boolean") {
        throw new TypeError(
          `abacPolicies.update: \`enabled\` must be a boolean when present ` +
            `(got ${describeType(enabledRaw)})`,
        );
      }
    }

    // ─── Body construction (only present-and-not-undefined fields) ─────────
    const body: Record<string, unknown> = {};
    if (hasName && nameRaw !== undefined) {
      body.name = nameRaw;
    }
    if (hasDescription && descriptionRaw !== undefined) {
      // `null` rides through verbatim — it CLEARS the description.
      body.description = descriptionRaw;
    }
    if (hasResource && resourceRaw !== undefined) {
      body.resource = resourceRaw;
    }
    if (hasAction && actionRaw !== undefined) {
      body.action = actionRaw;
    }
    if (hasEffect && effectRaw !== undefined) {
      body.effect = effectRaw;
    }
    if (hasCondition && conditionRaw !== undefined) {
      body.condition = conditionRaw;
    }
    if (hasPriority && priorityRaw !== undefined) {
      body.priority = priorityRaw;
    }
    if (hasEnabled && enabledRaw !== undefined) {
      body.enabled = enabledRaw;
    }

    // ─── Empty-patch pre-validation ────────────────────────────────────────
    // The kernel `updateAbacPolicySchema` ends in a `.refine()` that
    // rejects a body carrying no updatable field. Pre-reject the empty
    // patch synchronously so the consumer gets a `TypeError` (NO fetch
    // issued) instead of burning a round-trip on a guaranteed 422. An
    // input of `{}`, an all-`undefined` patch, or a patch carrying only
    // unknown keys all produce a zero-key `body`.
    if (Object.keys(body).length === 0) {
      throw new TypeError(
        "abacPolicies.update: `input` must include at least one updatable " +
          "field (`name`, `description`, `resource`, `action`, `effect`, " +
          "`condition`, `priority`, `enabled`) — the kernel rejects an " +
          "empty patch",
      );
    }

    return this.client
      ._request<AbacPolicy>({
        method: "PATCH",
        path: `/api/v1/abac-policies/${id}`,
        body,
        options,
      })
      .then((result) => validateAbacPolicy(result, "abacPolicies.update"));
  }

  /**
   * Delete one ABAC policy by id. Returns the **deleted row** — the
   * policy as it existed immediately before deletion — on HTTP 200.
   *
   * **Returns the deleted row, NOT `void`.** The kernel's DELETE
   * handler emits `successResponse(row, 200)` carrying the
   * just-deleted `AbacPolicy`, so a caller can log / audit / render
   * an undo affordance with the full prior state. Consumers MUST NOT
   * expect `Promise<void>` or a `{ deleted: true }` envelope — the
   * resolved value is a complete `AbacPolicy`.
   *
   * **FIRST SDK method using the HTTP `DELETE` verb.** Every prior
   * SDK route is GET / POST / PATCH. The transport's
   * `InternalRequestArgs.method` union already includes `"DELETE"`,
   * so no new transport primitive is needed.
   *
   * **Dual-auth admin scope** — same as `.list()` / `.create()` /
   * `.retrieve()`: `requireSessionOrApiKey(request, { sessionRoles:
   * ["admin"], apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })`.
   * **HTTP 401** for no/invalid/expired key, **HTTP 403** for a valid
   * key whose permissions do NOT include `ADMIN`. Pin BOTH branches.
   *
   * **UUID pre-validation** — `id` is pre-validated against
   * `UUID_REGEX` synchronously (`TypeError`, NO fetch issued) via the
   * shared `assertValidPolicyId` helper. The kernel `badId` 400
   * ("Invalid policy id.") is SDK-pre-empted. **No `encodeURIComponent`
   * / URIError defense** — a validated UUID is ASCII hex + hyphens and
   * is interpolated into the path raw (see `UUID_REGEX`; mirror of
   * `batch.get`).
   *
   * **404 surface** — the kernel's `deleteAbacPolicy(orgId, id)`
   * throws `AbacPolicyNotFoundError` when the `(id, orgId)`-scoped
   * delete matches zero rows (a missing id OR a cross-org id — the
   * `eq(orgId)` clause scopes the delete). The DELETE handler maps it
   * to `errorResponse(error.message, 404)`. **The message is
   * id-embedded** — `"ABAC policy <id> not found in this
   * organization."` — distinct from `.retrieve()`'s INLINE
   * `"ABAC policy not found."`. (`.retrieve()` uses an inline string;
   * `.update()` / `.delete()` raise `AbacPolicyNotFoundError`.)
   *
   * **`writeAuditLog` side effect — every successful `.delete()` call
   * writes one audit-log entry** with `action: "abac_policy.delete"`
   * and `resourceType: "abac_policy"`. The entry's `details` records
   * the deleted policy's `name` / `resource` / `action` / `effect`
   * for forensics. The write is org-scoped + hash-chained; it is
   * `await`-ed (so `.delete()` latency includes the audit write) but
   * error-tolerant (a write failure does NOT fail the request); it is
   * NOT counted against any quota. The audit log is NOT written on a
   * failed delete — a 404 surfaces BEFORE the `writeAuditLog` call.
   *
   * **Kernel-side 30-second timeout** (`maxDuration = 30`). Same as
   * `.list()` / `.create()` / `.retrieve()`.
   *
   * Errors — **happy-path precedence ordering**: UUID format (kernel
   * `badId` — SDK-pre-empted) → rate-limit → auth → DB delete → audit
   * write → successResponse. **The 500-catchall is a SEPARATE
   * DIMENSION** — any throwable not matched by the DELETE handler's 2
   * `instanceof` arms (`AuthError`, `AbacPolicyNotFoundError`) falls
   * to 500.
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     among the network surfaces (auto-retried by default —
   *     invariant #18; per-IP key `abac-policies-delete:${ip}`
   *     against `assessmentLimiter` — 30 req / 1-min sliding window).
   *   - `AttestryAPIError` (status 401) — no/invalid/expired api-key.
   *   - `AttestryAPIError` (status 403) — valid api-key without
   *     `ADMIN`. Distinct branch from 401 — pin BOTH separately.
   *   - `AttestryAPIError` (status 404) — policy not found OR a
   *     cross-org id (`AbacPolicyNotFoundError`; id-embedded message).
   *   - `AttestryAPIError` (status 400) — kernel `badId` rejected the
   *     id. **SDK-pre-empted** — reachable from a consumer only via
   *     an `as any` cast or a kernel-side id-flavor change.
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`). **Orthogonal
   *     to the precedence list** — ANY throwable not matched by the
   *     route's 2 `instanceof` arms falls here.
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired.
   *   - `AttestryError` (P2 hardening) — the deleted row failed
   *     SDK-side shape validation (non-object, or any of the 13
   *     `AbacPolicy` fields missing / wrong-typed).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard before body
   *     parsing).
   *   - `TypeError` (synchronous, NO fetch issued) — `id` is missing,
   *     a non-string, an empty string, or not an RFC 4122 UUID.
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch
   * issued):
   *   - `id`: required; must be a non-empty string matching
   *     `UUID_REGEX` (RFC 4122 hyphenated, case-insensitive).
   *
   * **Response-shape validation** (P2 hardening) — the shared
   * `validateAbacPolicy` validator checks all 13 `AbacPolicy` fields
   * of the deleted row via the module-load `objectHasOwn` snapshot.
   * `condition` is validated as a non-null object only — the
   * recursive AST is faithful-courier.
   *
   * **Transport-shape validation** (P3 hardening) — rejects with
   * `AttestryAPIError` if the kernel responds with a
   * non-`application/json` Content-Type.
   *
   * @example Delete a policy and log the prior state
   * ```ts
   * const deleted = await client.abacPolicies.delete(
   *   "550e8400-e29b-41d4-a716-446655440000",
   * );
   * console.log(`Deleted "${deleted.name}" (${deleted.effect} ${deleted.action})`);
   * ```
   *
   * @example Treat a not-found delete as idempotent success
   * ```ts
   * try {
   *   await client.abacPolicies.delete(id);
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 404) {
   *     // already gone — fine for an idempotent caller
   *   } else {
   *     throw err;
   *   }
   * }
   * ```
   */
  delete(id: string, options?: RequestOptions): Promise<AbacPolicy> {
    assertValidPolicyId(id, "abacPolicies.delete");
    return this.client
      ._request<AbacPolicy>({
        method: "DELETE",
        path: `/api/v1/abac-policies/${id}`,
        options,
      })
      .then((result) => validateAbacPolicy(result, "abacPolicies.delete"));
  }
}

// ─── UUID path-segment pre-validation ───────────────────────────────────────

/**
 * Pre-validate an ABAC policy `id` path segment. Shared by
 * `.retrieve()` / `.update()` / `.delete()` — the three methods that
 * interpolate `id` into the request path `/api/v1/abac-policies/<id>`.
 *
 * The kernel validates `id` with a strict RFC 4122 UUID regex
 * (`badId` at `src/app/api/v1/abac-policies/[id]/route.ts:35-37`) and
 * returns HTTP 400 "Invalid policy id." on a mismatch — BEFORE
 * rate-limit + auth. The SDK pre-validates synchronously (mirror of
 * `batch.get`) so that 400 is reachable from a consumer only via an
 * `as any` cast or a kernel-side id-flavor change (ULID, KSUID, ...).
 *
 * **No `encodeURIComponent` / URIError defense** — see `UUID_REGEX`
 * above: a validated UUID is ASCII hex + hyphens, so the caller
 * interpolates it into the path raw. Carry-forward invariant #32
 * (URIError → TypeError conversion) applies only where a path segment
 * can actually reach `encodeURIComponent` with potentially-malformed
 * input (`decisions.retrieve`'s free-form id); a pre-validated UUID
 * cannot, so there is no `URIError` surface to convert.
 *
 * Throws `TypeError` synchronously (NO fetch issued) when `id` is a
 * non-string, an empty string, or not an RFC 4122 hyphenated UUID.
 */
function assertValidPolicyId(id: unknown, methodName: string): void {
  if (typeof id !== "string" || id.length === 0) {
    throw new TypeError(`${methodName}: \`id\` must be a non-empty string`);
  }
  if (!UUID_REGEX.test(id)) {
    throw new TypeError(
      `${methodName}: \`id\` must be an RFC 4122 hyphenated UUID ` +
        `(matched regex: /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-` +
        `[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, got ${JSON.stringify(id)})`,
    );
  }
}

// ─── Response-shape validation (P2 hardening) ───────────────────────────────

/**
 * P2 hardening: validate the `.list()` response shape. Mirror of
 * `assertIncidentsListResponse` in `incidents.ts` and the
 * `regulatoryChanges.list` validator pattern.
 *
 * The kernel emits
 * `{success: true, data: {items: AbacPolicy[], count: number}}`. After
 * the transport's envelope-unwrap, this validator sees `{items,
 * count}`. Asserts:
 *   - non-null, non-array object
 *   - `items` is an array
 *   - `count` is a number
 *
 * **Per-row item shape NOT validated** (faithful courier — P4
 * candidate; consistent with `incidents.list` /
 * `regulatoryChanges.list`).
 *
 * **`objectHasOwn` is the module-load snapshot** (set at module-load
 * via `const objectHasOwn = Object.hasOwn`). A hostile dep that
 * monkey-patches `Object.hasOwn` AFTER SDK import time does NOT
 * affect this validator. Symmetric prototype-pollution defense on
 * the response side; input side is N/A for `.list()`.
 */
function validateAbacPoliciesListResponse(
  result: unknown,
): AbacPoliciesListResponse {
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result)
  ) {
    throw new AttestryError(
      `abacPolicies.list: expected an object response from the kernel ` +
        `(got ${describeType(result)})`,
    );
  }
  const obj = result as Record<string, unknown>;

  // items — ALWAYS-PRESENT array (empty when org has no policies).
  // UNCONDITIONAL own-property check (the validator's items branch
  // is unconditional).
  const items = objectHasOwn(obj, "items") ? obj.items : undefined;
  if (!Array.isArray(items)) {
    throw new AttestryError(
      `abacPolicies.list: expected response.items to be an array ` +
        `(got ${describeType(items)})`,
    );
  }

  // count — ALWAYS-PRESENT number.
  const count = objectHasOwn(obj, "count") ? obj.count : undefined;
  if (typeof count !== "number") {
    throw new AttestryError(
      `abacPolicies.list: expected response.count to be a number ` +
        `(got ${describeType(count)})`,
    );
  }

  return result as AbacPoliciesListResponse;
}

/**
 * P2 hardening: validate a single `AbacPolicy` row response. **Shared
 * by `.create()` / `.retrieve()` / `.update()` / `.delete()`** — all
 * four kernel handlers emit `{success: true, data: <row>}` (HTTP 201
 * for `.create()`, 200 for the other three) and the transport
 * unwraps `data`, so this validator sees the row directly. The
 * `methodName` argument (`"abacPolicies.create"` / `".retrieve"` /
 * `".update"` / `".delete"`) prefixes every thrown `AttestryError`
 * message so a malformed response names the method the consumer
 * actually called — mirror of the shared `encodePathSegment` /
 * `assertNonNullObjectResponse` `methodName`-parameter convention.
 *
 * Symmetric prototype-pollution defense — read EACH field via the
 * module-load `objectHasOwn` snapshot so a hostile npm dep polluting
 * `Object.prototype.<field>` cannot mask a kernel regression that
 * drops a field. Mirror of `ship-gate.ts` / `gate.ts` patterns.
 *
 * All 13 fields are ALWAYS-PRESENT on the wire (`description` and
 * `createdByUserId` are `string | null`, NOT optional; kernel uses
 * `?? null` coalesce at `rowToPolicy`). Validator's branches for
 * each field are UNCONDITIONAL.
 *
 * **`condition` is validated as `non-null object`** only — the
 * recursive AST grammar is the kernel's source of truth. SDK
 * passes the AST through verbatim once it's confirmed to be an
 * object (faithful courier on the recursive structure).
 *
 * **Single-field rejection semantics** (mirror of ship-gate.ts /
 * gate.ts / batch.ts / audit-log.ts) — validator checks fields in
 * declaration order and throws on the FIRST failing field. Project
 * convention.
 */
function validateAbacPolicy(
  result: unknown,
  methodName: string,
): AbacPolicy {
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result)
  ) {
    throw new AttestryError(
      `${methodName}: expected an object response from the kernel ` +
        `(got ${describeType(result)})`,
    );
  }
  const obj = result as Record<string, unknown>;

  // id — string (UUID).
  const id = objectHasOwn(obj, "id") ? obj.id : undefined;
  if (typeof id !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.id to be a string ` +
        `(got ${describeType(id)})`,
    );
  }

  // orgId — string (UUID).
  const orgId = objectHasOwn(obj, "orgId") ? obj.orgId : undefined;
  if (typeof orgId !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.orgId to be a string ` +
        `(got ${describeType(orgId)})`,
    );
  }

  // name — string.
  const name = objectHasOwn(obj, "name") ? obj.name : undefined;
  if (typeof name !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.name to be a string ` +
        `(got ${describeType(name)})`,
    );
  }

  // description — string OR null (ALWAYS-PRESENT — kernel uses ?? null).
  const description = objectHasOwn(obj, "description")
    ? obj.description
    : undefined;
  if (description !== null && typeof description !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.description to be a string ` +
        `or null (got ${describeType(description)})`,
    );
  }

  // resource — string (closed-enum, but P2 is faithful courier).
  const resource = objectHasOwn(obj, "resource") ? obj.resource : undefined;
  if (typeof resource !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.resource to be a string ` +
        `(got ${describeType(resource)})`,
    );
  }

  // action — string (closed-enum, faithful courier).
  const action = objectHasOwn(obj, "action") ? obj.action : undefined;
  if (typeof action !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.action to be a string ` +
        `(got ${describeType(action)})`,
    );
  }

  // effect — string (closed-enum, faithful courier).
  const effect = objectHasOwn(obj, "effect") ? obj.effect : undefined;
  if (typeof effect !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.effect to be a string ` +
        `(got ${describeType(effect)})`,
    );
  }

  // condition — non-null object (AST recursive shape NOT validated;
  // faithful courier on the recursive grammar).
  const condition = objectHasOwn(obj, "condition") ? obj.condition : undefined;
  if (
    condition === null ||
    typeof condition !== "object" ||
    Array.isArray(condition)
  ) {
    throw new AttestryError(
      `${methodName}: expected response.condition to be a non-null ` +
        `object (got ${describeType(condition)})`,
    );
  }

  // priority — number.
  const priority = objectHasOwn(obj, "priority") ? obj.priority : undefined;
  if (typeof priority !== "number") {
    throw new AttestryError(
      `${methodName}: expected response.priority to be a number ` +
        `(got ${describeType(priority)})`,
    );
  }

  // enabled — boolean.
  const enabled = objectHasOwn(obj, "enabled") ? obj.enabled : undefined;
  if (typeof enabled !== "boolean") {
    throw new AttestryError(
      `${methodName}: expected response.enabled to be a boolean ` +
        `(got ${describeType(enabled)})`,
    );
  }

  // createdByUserId — string OR null.
  const createdByUserId = objectHasOwn(obj, "createdByUserId")
    ? obj.createdByUserId
    : undefined;
  if (createdByUserId !== null && typeof createdByUserId !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.createdByUserId to be a ` +
        `string or null (got ${describeType(createdByUserId)})`,
    );
  }

  // createdAt — string (ISO-8601; NOT Date — wire shape).
  const createdAt = objectHasOwn(obj, "createdAt") ? obj.createdAt : undefined;
  if (typeof createdAt !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.createdAt to be a string ` +
        `(got ${describeType(createdAt)})`,
    );
  }

  // updatedAt — string (ISO-8601).
  const updatedAt = objectHasOwn(obj, "updatedAt") ? obj.updatedAt : undefined;
  if (typeof updatedAt !== "string") {
    throw new AttestryError(
      `${methodName}: expected response.updatedAt to be a string ` +
        `(got ${describeType(updatedAt)})`,
    );
  }

  return result as AbacPolicy;
}

/**
 * Human-readable type description for error messages. Distinguishes
 * `null` and `array` from generic `object`. Duplicated in
 * `decisions.ts` / `incidents.ts` / `regulatory-changes.ts` /
 * `compliance-check.ts` / `check.ts` / `gate.ts` / `batch.ts` /
 * `audit-log.ts` / `ship-gate.ts` per project pattern (small helper,
 * leaf-resource modules, no shared module yet).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
