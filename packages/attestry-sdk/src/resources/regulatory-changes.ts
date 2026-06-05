// ─── RegulatoryChanges resource ─────────────────────────────────────────────
//
// Wraps the regulatory-changes feed surface (Prompt R12):
//
//   - GET /api/v1/regulatory-changes    sync JSON list of regulatory updates
//
// Second non-decisions resource on `@attestry/sdk`. Sibling to
// `IncidentsResource`, `DecisionsResource`, `ChatResource`,
// `AuditLogResource`. Single public method today (`list`); the resource
// class exists as the landing pad for future regulatory-changes methods
// if/when the kernel adds them.
//
// READ_SYSTEMS auth scope: the kernel route gates on
// `apiKeyPermissions:[READ_SYSTEMS]`. Returns **HTTP 401** for no/invalid
// API key (via `requireApiKey` first), and **HTTP 403** for an authenticated
// key that lacks the READ_SYSTEMS permission. `auditLog.export` (ADMIN-only
// dual-auth) surfaces the SAME 401-vs-403 split — the auth MODELS differ
// (single READ_SYSTEMS permission vs ADMIN-only dual-auth) but the status
// surface does not (corrected session-22 hostile review #2; the prior
// "auditLog.export returns 401 for both" framing of invariant #42 was
// wrong). Consumers must pin both 401 and 403 branches separately.
//
// Sync JSON list response: reuses `client._request` and the existing
// `{success:true, data}` envelope-unwrap (carry-forward invariant #9).
// NO new SDK primitive needed — smaller blast radius than `auditLog.export`.
// Returns `Promise<RegulatoryChange[]>`.
//
// **Default-excludes-dismissed semantics** (the non-obvious gotcha):
//   - `status` omitted     → kernel filters dismissed rows OUT
//                            (`WHERE status != 'dismissed'`)
//   - `status: "dismissed"` → only dismissed rows
//   - `status: "new"|"reviewed"|"actioned"` → only that exact status
// There is currently NO way to retrieve "everything including dismissed"
// via this endpoint. Documented prominently in JSDoc on `list()` and
// `RegulatoryChangesListInput.status`. Pinned via URL test
// (omitted-status URL omits the param entirely; explicit-`"dismissed"`
// URL contains `status=dismissed`).

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

/**
 * Public closed-enum of supported severity values. Mirrors the kernel's
 * route-local `validSeverities` const at
 * `src/app/api/v1/regulatory-changes/route.ts:39`. Drift-pinned in
 * `src/lib/incidents/__tests__/sdk-drift.test.ts`.
 *
 * Forward-compat: when a future severity value is added kernel-side,
 * bump the SDK minor version and extend this array. The kernel returns
 * 400 for any value outside this set; the SDK pre-rejects invalid
 * values synchronously as `TypeError` (build-round D5 — closed-enum
 * input validates at the SDK boundary so the failure is faster +
 * clearer than waiting for the server's 400).
 */
export const REGULATORY_CHANGE_SEVERITIES = Object.freeze([
  "critical",
  "high",
  "medium",
  "low",
] as const);

export type RegulatoryChangeSeverity =
  (typeof REGULATORY_CHANGE_SEVERITIES)[number];

/**
 * Public closed-enum of supported status values. Mirrors the kernel's
 * route-local `VALID_STATUSES` const at
 * `src/app/api/v1/regulatory-changes/route.ts:62`. Drift-pinned in
 * `src/lib/incidents/__tests__/sdk-drift.test.ts`.
 *
 * Same forward-compat trade-off as `REGULATORY_CHANGE_SEVERITIES`
 * (build-round D5).
 */
export const REGULATORY_CHANGE_STATUSES = Object.freeze([
  "new",
  "reviewed",
  "actioned",
  "dismissed",
] as const);

export type RegulatoryChangeStatus =
  (typeof REGULATORY_CHANGE_STATUSES)[number];

/**
 * Wire shape for a single regulatory-change row. Source-of-truth at
 * kernel `src/lib/db/schema.ts:1082-1111` (`regulatoryChanges` pgTable).
 *
 * The route returns raw Drizzle rows (no `rowToWireJson` mapper today —
 * unlike `auditLog.export`'s stable wire shape). Drizzle serializes
 * timestamp columns as ISO-8601 strings via `JSON.stringify(Date)`.
 * jsonb columns (`affectedRequirements`, `aiAnalysis`,
 * `statusTransitions`) are typed as `unknown` — the schema comment hints
 * at concrete shapes (`string[]`, Reggie analysis, `[{status, date,
 * source}]`) but they're not enforced server-side. Consumers parse via
 * their own validators (build-round D3).
 *
 * `severity` and `status` are typed as `string` (NOT typed unions) —
 * forward-compat for kernel-side enum additions that haven't landed in
 * the SDK yet. The write-side `RegulatoryChangesListInput.severity` /
 * `.status` use the literal-union for IDE auto-completion. Same
 * asymmetry as `humanOversightState`/`policyOutcome` on
 * `decisions.ingest` (build-round D2).
 *
 * **Field stability**: this wire shape IS the Drizzle row shape today.
 * A future row-to-wire mapper (parallel to `rowToWireJson`) would
 * stabilize it; until then a kernel-side column rename ripples directly
 * to the SDK. The drift pin in `sdk-drift.test.ts` trip-wires that
 * change at the kernel-source level.
 */
export interface RegulatoryChange {
  /** UUID. */
  id: string;
  /** Framework code: `"EU_AI_ACT"` / `"COLORADO_AI_ACT"` / etc. — open string. */
  framework: string;
  title: string;
  description: string | null;
  /**
   * `'amendment' | 'clarification' | 'enforcement' | 'guidance'` per
   * the schema comment. Not enforced server-side — typed as `string`
   * for forward-compat.
   */
  changeType: string;
  /**
   * `'critical' | 'high' | 'medium' | 'low'` (closed enum, see
   * `REGULATORY_CHANGE_SEVERITIES`). Typed as `string` for forward-compat
   * (build-round D2).
   */
  severity: string;
  /** ISO-8601, nullable. */
  effectiveDate: string | null;
  /**
   * jsonb — typed as `string[]` in the schema comment, but defensively
   * `unknown` at the SDK boundary (build-round D3).
   */
  affectedRequirements: unknown;
  sourceUrl: string | null;
  /** ISO-8601, nullable; kernel sorts the response DESC by this column. */
  publishedAt: string | null;
  /**
   * `'eur_lex' | 'federal_register' | 'uk_legislation' | 'colorado_leg'
   * | 'nist_gov' | 'rss_custom'` per schema comment. Open string —
   * source pipeline IDs.
   */
  sourceId: string | null;
  /** External document ID from the source system. */
  sourceReferenceId: string | null;
  /** ISO-8601, nullable; kernel records when the row was scraped. */
  ingestedAt: string | null;
  /** E.g., `"European Commission"`, `"US Congress"`. */
  authorityPublisher: string | null;
  /**
   * jsonb — Reggie's cached analysis result. Defensively `unknown`
   * (build-round D3).
   */
  aiAnalysis: unknown;
  /** ISO-8601, nullable; kernel records when alerts were sent. */
  notifiedAt: string | null;
  /**
   * `'draft' | 'introduced' | 'committee' | 'passed_one_chamber' |
   * 'passed_both' | 'signed' | 'enacted' | 'vetoed' | 'withdrawn'` per
   * schema comment. Open string — bill lifecycle state.
   */
  billStatus: string | null;
  /**
   * jsonb — array of `{status, date, source}` per schema comment.
   * Defensively `unknown` (build-round D3).
   */
  statusTransitions: unknown;
  /**
   * `'new' | 'reviewed' | 'actioned' | 'dismissed'` (closed enum, see
   * `REGULATORY_CHANGE_STATUSES`). Defaults `"new"` server-side. Typed
   * as `string` for forward-compat (build-round D2).
   */
  status: string;
  /** `'high' | 'medium' | 'low'` per schema comment; defaults `"medium"` server-side. */
  relevance: string | null;
  /** ISO-8601, NOT NULL (server `defaultNow()`). */
  createdAt: string;
}

/**
 * Input shape for `regulatoryChanges.list(input?)`. All fields
 * optional; a bare `regulatoryChanges.list()` call returns the most
 * recent 200 non-dismissed regulatory-change rows (kernel default —
 * see "Default-excludes-dismissed" in JSDoc on `list()`).
 *
 * Filters are AND-combined server-side. Date range filters apply to
 * `publishedAt` (kernel `gte` / `lte`).
 */
export interface RegulatoryChangesListInput {
  /**
   * Open string — kernel forwards verbatim to a DB filter
   * (`WHERE framework = ?`). The SDK does NOT pre-validate (forward-
   * compat: new framework codes added kernel-side don't require an
   * SDK bump). URIError defense via `assertEncodableQueryString`
   * (carry-forward invariant #32).
   */
  framework?: string;
  /**
   * Closed enum. Pre-validated against
   * `REGULATORY_CHANGE_SEVERITIES`; SDK throws `TypeError`
   * synchronously for unknown values (build-round D5; carry-forward
   * invariant #41). Drift-pinned.
   */
  severity?: RegulatoryChangeSeverity;
  /**
   * Closed enum. Pre-validated against
   * `REGULATORY_CHANGE_STATUSES`; SDK throws `TypeError` synchronously
   * for unknown values (build-round D5).
   *
   * **Default-excludes-dismissed**: when omitted, the kernel filters
   * dismissed rows OUT (`WHERE status != 'dismissed'`). To include
   * dismissed rows, pass `status: "dismissed"` (returns ONLY
   * dismissed) or one of `"new"` / `"reviewed"` / `"actioned"` for an
   * exact match. There is currently NO way to retrieve "everything
   * including dismissed" via this endpoint.
   */
  status?: RegulatoryChangeStatus;
  /**
   * Date-string lower bound on `publishedAt`. Kernel parses via
   * `new Date(value)` and returns 400 with
   * `error: "Invalid 'from' date format"` if `isNaN(parsed.getTime())`.
   * The SDK does NOT pre-validate ISO-8601 format (build-round D6 —
   * kernel's `new Date(...)` is lenient: `"May 7 2026"`, `"2026/05/07"`,
   * and `"2026-05-07T00:00:00Z"` all parse; pre-validating to strict
   * ISO would reject valid kernel inputs).
   */
  from?: string;
  /** Same semantics as `from`. */
  to?: string;
  /**
   * Page size, 1..200; default 200 server-side. SDK pre-rejects
   * `NaN` / `Infinity` / `<= 0` / non-integer as `TypeError`
   * synchronously. Values > 200 are forwarded verbatim — server
   * returns 400 (`"Invalid limit. Must be between 1 and 200."`).
   * Build-round D4: kernel's MAX_LIMIT is the authority; pre-capping
   * SDK-side would silently mask future kernel raises.
   */
  limit?: number;
}

/**
 * RegulatoryChanges resource — sibling to `IncidentsResource`,
 * `DecisionsResource`, `ChatResource`, `AuditLogResource`. Today wraps
 * a single endpoint (`list`); the class is the landing pad for future
 * regulatory-changes methods (mark-as-read, mark-as-actioned,
 * subscribe-to-framework, etc.).
 */
export class RegulatoryChangesResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * List regulatory-change rows filtered by framework / severity /
   * status / date range. Returns all matching rows up to `limit`
   * (default 200 server-side, max 200). Rows arrive DESC by
   * `publishedAt`.
   *
   * **Default-excludes-dismissed** (the non-obvious gotcha — read
   * carefully): when `status` is OMITTED from the input, the kernel
   * filters dismissed rows OUT (`WHERE status != 'dismissed'`). To
   * retrieve dismissed rows, pass `status: "dismissed"` (returns ONLY
   * dismissed). There is currently NO way to retrieve "everything
   * including dismissed" via this endpoint — the kernel route hardcodes
   * the exclusion at `route.ts:78-79`.
   *
   * **READ_SYSTEMS auth scope**: returns HTTP 401 for no/invalid API
   * key, HTTP **403** for an authenticated key that lacks the
   * READ_SYSTEMS permission. `auditLog.export` (ADMIN-only dual-auth)
   * surfaces the SAME 401-vs-403 split — the auth models differ, the
   * status surface does not (corrected session-22 hostile review #2).
   * Consumers must distinguish 401 (re-authenticate) from 403 (request
   * a different API key) at the call site.
   *
   * **Sync JSON list**: returns `Promise<RegulatoryChange[]>`. No
   * pagination cursor — caller adjusts `limit` or filters to narrow the
   * result set. An empty match returns `[]` (no 404).
   *
   * Errors:
   *   - `AttestryAPIError` (status 400) — invalid `from`/`to` date
   *     format (kernel's `new Date(...)` returned `NaN`), or
   *     `limit > 200` / `limit < 1` (server-side range check). Closed-
   *     enum 400s (`severity` / `status` not in enum) are
   *     UNREACHABLE through the SDK — pre-rejected as `TypeError`.
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key
   *     (the `requireApiKey` branch).
   *   - `AttestryAPIError` (status 403) — authenticated key lacks
   *     `READ_SYSTEMS` permission (the `requireApiKeyWithPermission`
   *     branch).
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried by
   *     default — invariant #18; per-IP rate-limit key
   *     `v1-reg-changes:${ip}`).
   *   - `AttestryAPIError` (status 500) — internal kernel error (scrubbed
   *     message via `internalErrorResponse`).
   *   - `AttestryError` ("request aborted by caller") — caller-supplied
   *     `options.signal` fired (pre-aborted or mid-flight).
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **Notably ABSENT**:
   *   - **No 404** — empty filter set returns 200 with `data: []`. Do
   *     NOT special-case 404 in error handling.
   *   - **No 422** — closed enums return 400 (kernel uses inline
   *     string-includes parsing, not Zod for these query params).
   *   - **No 413** — limit is enforced by `parseInt` + range check.
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch
   * issued):
   *   - `input` itself: optional; when provided, must be a non-null,
   *     non-array object.
   *   - `input.framework`: optional; non-empty string when provided.
   *     Lone-surrogate guard via `assertEncodableQueryString`
   *     (carry-forward invariant #32). NOT pre-validated as a known
   *     framework code (forward-compat).
   *   - `input.severity`: optional; one of `"critical"`/`"high"`/
   *     `"medium"`/`"low"` when provided. Pre-validated against the
   *     closed enum (`REGULATORY_CHANGE_SEVERITIES`).
   *   - `input.status`: optional; one of `"new"`/`"reviewed"`/
   *     `"actioned"`/`"dismissed"` when provided. Pre-validated against
   *     the closed enum (`REGULATORY_CHANGE_STATUSES`).
   *   - `input.from` / `input.to`: optional; non-empty string when
   *     provided. Lone-surrogate guard. **NOT pre-validated as ISO-8601**
   *     (build-round D6 — kernel's `new Date(...)` is lenient).
   *   - `input.limit`: optional; positive finite integer when provided.
   *     `NaN` / `Infinity` / `<= 0` / non-integer rejected. Values
   *     `> 200` forwarded verbatim (build-round D4).
   *
   * **Response-shape validation** (P2 hardening):
   *   - Rejects with `AttestryError` if the kernel response isn't an
   *     array. Per-row shape (the 21-field `RegulatoryChange`) is
   *     faithful-courier — NOT validated (P4 candidate).
   *
   * **Transport-shape validation** (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with a
   *     non-`application/json` Content-Type — protects against
   *     proxy-injected HTML 200 pages parsing into junk consumer state.
   *
   * @example List the most recent 200 non-dismissed regulatory updates
   * ```ts
   * const changes = await client.regulatoryChanges.list();
   * for (const change of changes) {
   *   console.log(change.framework, change.severity, change.title);
   * }
   * ```
   *
   * @example Filter to critical EU AI Act updates from last week
   * ```ts
   * const changes = await client.regulatoryChanges.list({
   *   framework: "EU_AI_ACT",
   *   severity: "critical",
   *   from: "2026-04-30T00:00:00Z",
   *   limit: 50,
   * });
   * ```
   *
   * @example Retrieve only dismissed rows (default omits them)
   * ```ts
   * const dismissed = await client.regulatoryChanges.list({
   *   status: "dismissed",
   * });
   * ```
   */
  list(
    input?: RegulatoryChangesListInput,
    options?: RequestOptions,
  ): Promise<RegulatoryChange[]> {
    // Top-level shape — when provided, must be a non-null, non-array
    // object. typeof null === "object" and typeof [] === "object", so
    // guard both explicitly. Like auditLog.export, input is OPTIONAL —
    // `()` and `(undefined)` are both valid.
    //
    // The six query fields are snapshotted into locals (declared here
    // so they stay visible for the query construction below — `input`
    // is optional, and when omitted the locals stay `undefined`). Each
    // read goes through `readInputField`, which converts a throwing
    // accessor's exception into the documented synchronous `TypeError`
    // input contract (session-22 hostile review #1 — the SDK-wide
    // MEDIUM-1 getter-throws fix). The `as` cast re-asserts only what
    // the consumer's own `RegulatoryChangesListInput` type claims.
    let framework: RegulatoryChangesListInput["framework"];
    let severity: RegulatoryChangesListInput["severity"];
    let status: RegulatoryChangesListInput["status"];
    let from: RegulatoryChangesListInput["from"];
    let to: RegulatoryChangesListInput["to"];
    let limit: RegulatoryChangesListInput["limit"];
    if (input !== undefined) {
      if (
        input === null ||
        typeof input !== "object" ||
        Array.isArray(input)
      ) {
        throw new TypeError(
          "regulatoryChanges.list: `input` must be an object when provided",
        );
      }
      framework = readInputField(
        input,
        "framework",
        "regulatoryChanges.list",
      ) as RegulatoryChangesListInput["framework"];
      severity = readInputField(
        input,
        "severity",
        "regulatoryChanges.list",
      ) as RegulatoryChangesListInput["severity"];
      status = readInputField(
        input,
        "status",
        "regulatoryChanges.list",
      ) as RegulatoryChangesListInput["status"];
      from = readInputField(
        input,
        "from",
        "regulatoryChanges.list",
      ) as RegulatoryChangesListInput["from"];
      to = readInputField(
        input,
        "to",
        "regulatoryChanges.list",
      ) as RegulatoryChangesListInput["to"];
      limit = readInputField(
        input,
        "limit",
        "regulatoryChanges.list",
      ) as RegulatoryChangesListInput["limit"];
      // framework: open string. Non-empty when provided. Lone-surrogate
      // guard (#32). NOT pre-validated as a known code.
      if (framework !== undefined) {
        if (typeof framework !== "string" || framework.length === 0) {
          throw new TypeError(
            "regulatoryChanges.list: `framework` must be a non-empty string when provided",
          );
        }
        assertEncodableQueryString(
          framework,
          "framework",
          "regulatoryChanges.list",
        );
      }
      // severity: closed enum. Pre-reject invalid values synchronously
      // (#41 / build-round D5).
      if (severity !== undefined) {
        if (
          typeof severity !== "string" ||
          !(REGULATORY_CHANGE_SEVERITIES as readonly string[]).includes(
            severity,
          )
        ) {
          throw new TypeError(
            `regulatoryChanges.list: \`severity\` must be one of ${REGULATORY_CHANGE_SEVERITIES.join(", ")} when provided`,
          );
        }
      }
      // status: closed enum. Same treatment as severity.
      if (status !== undefined) {
        if (
          typeof status !== "string" ||
          !(REGULATORY_CHANGE_STATUSES as readonly string[]).includes(status)
        ) {
          throw new TypeError(
            `regulatoryChanges.list: \`status\` must be one of ${REGULATORY_CHANGE_STATUSES.join(", ")} when provided`,
          );
        }
      }
      // from / to: open date strings. Non-empty when provided. NOT
      // pre-validated as ISO-8601 (build-round D6 — kernel's
      // `new Date(...)` is lenient). Lone-surrogate guard (#32).
      if (from !== undefined) {
        if (typeof from !== "string" || from.length === 0) {
          throw new TypeError(
            "regulatoryChanges.list: `from` must be a non-empty string when provided",
          );
        }
        assertEncodableQueryString(from, "from", "regulatoryChanges.list");
      }
      if (to !== undefined) {
        if (typeof to !== "string" || to.length === 0) {
          throw new TypeError(
            "regulatoryChanges.list: `to` must be a non-empty string when provided",
          );
        }
        assertEncodableQueryString(to, "to", "regulatoryChanges.list");
      }
      // limit: positive finite integer. NaN / Infinity / fractional /
      // <= 0 rejected. Stricter than kernel's 400 (build-round D4 —
      // fail-loud-and-synchronous; mirrors auditLog.export's limit
      // policy).
      if (limit !== undefined) {
        if (
          typeof limit !== "number" ||
          !Number.isInteger(limit) ||
          limit <= 0
        ) {
          throw new TypeError(
            "regulatoryChanges.list: `limit` must be a positive integer when provided",
          );
        }
      }
    }
    return this.client
      ._request<RegulatoryChange[]>({
        method: "GET",
        path: "/api/v1/regulatory-changes",
        query: {
          framework,
          severity,
          status,
          from,
          to,
          limit,
        },
        options,
      })
      .then((result) => {
        // P2 hardening: validate the kernel returned an array. The
        // route emits `successResponse(changes)` where `changes` comes
        // from Drizzle's `db.select()...limit(N)` which always returns
        // Array — but a kernel-side regression to scalar/null/undefined
        // would let `null as RegulatoryChange[]` reach consumers, who
        // would crash on `out.length` with a confusing TypeError.
        // Catch it at the SDK boundary with a clear AttestryError.
        // NOTE: G6 documented behavior (wrong content-type with
        // unparseable body resolves to null) is changed in P3 — see
        // the P3 audit-prompt for the transport-level content-type
        // guard that subsumes this null-case.
        if (!Array.isArray(result)) {
          throw new AttestryError(
            `regulatoryChanges.list: expected an array response from the kernel (got ${describeType(result)})`,
          );
        }
        return result;
      });
  }
}

/**
 * Synchronously verify a query-string value is encodable via
 * `encodeURIComponent`. Mirrors the helper in `decisions.ts` and
 * `audit-log.ts` (carry-forward invariant #32 — URIError defect-class
 * is uniformly handled).
 *
 * Duplicated rather than shared because cross-resource imports between
 * `regulatory-changes.ts`, `audit-log.ts`, and `decisions.ts` would
 * create graph-cycle hazards — all three want to remain leaf-resource
 * modules. A future SDK refactor may extract validation helpers to a
 * shared module (e.g., `src/validate.ts`) when a fourth caller shows
 * up; for now the duplication is intentional and documented.
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
 * Human-readable type description for response-shape error messages.
 * Distinguishes `null` and `array` from generic `object`.
 *
 * Duplicated in `decisions.ts` and `incidents.ts` per project pattern
 * (small helper, leaf-resource modules, no shared module yet).
 *
 * In regulatoryChanges.list, the validator's outer check is
 * `!Array.isArray(result)` — describeType is only invoked when the
 * result is NOT an array. The Array.isArray branch below is therefore
 * structurally unreachable in this file's call site (kept for helper
 * symmetry with the sibling files where the branch IS reachable —
 * decisions.ts and incidents.ts both call describeType from
 * "expected object, got X" contexts where X may be an array).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  // The validator above guarantees `value` is not an array when this
  // helper is invoked from regulatoryChanges.list. Branch retained
  // for helper symmetry with decisions.ts / incidents.ts (where it
  // IS reachable) and as defense-in-depth if the validator's outer
  // check is ever changed. Coverage marker:
  /* v8 ignore next */
  if (Array.isArray(value)) return "array";
  return typeof value;
}
