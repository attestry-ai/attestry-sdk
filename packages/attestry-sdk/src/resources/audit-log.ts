// ─── AuditLog resource ──────────────────────────────────────────────────────
//
// Wraps the audit-log SIEM export surface (Prompt C.4) + the org-wide
// audit-log hash-chain verifier (session 19):
//
//   - GET /api/v1/audit-log/export         NDJSON / ECS / CEF stream of audit_log rows
//   - GET /api/v1/audit-chain/verify       Org-wide hash-chain integrity verdict
//
// First non-decisions resource on `@attestry/sdk`. Sibling to
// `IncidentsResource`, `DecisionsResource`, `ChatResource`. Two
// public methods today (`export` + `verifyChain`); the resource class
// is the landing pad for future audit-log methods if/when the kernel
// adds them.
//
// **`verifyChain()` vs `decisions.verifyChain()`** — DISTINCT surfaces:
//   - `decisions.verifyChain(systemId)` — verifies a SINGLE system's
//     decision chain (per-system hash-chain integrity). Takes a UUID
//     path parameter; emits `ChainVerificationResult` with per-record
//     tampered/broken arrays. Used for security/ops signals on a
//     specific system.
//   - `auditLog.verifyChain()` — verifies the entire ORG's audit log
//     chain (org-wide tamper-evidence). Takes NO arguments; emits
//     `AuditChainVerificationResult` with one `brokenAt` UUID (if any).
//     Used by compliance auditors for end-to-end audit-log integrity.
// Different responsibility, different kernel route, different consumer
// audience. The two methods complement each other.
//
// Dual-auth admin scope: the kernel route gates on
// `requireSessionOrApiKey(request, { sessionRoles: ["admin"],
// apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })` (verified at
// `src/app/api/v1/audit-log/export/route.ts:66-68`) — the identical
// dual-auth pattern the abacPolicies cluster uses. The SDK's transport
// always sends `x-api-key`, so the api-key path is the only one
// reachable from SDK consumers: **HTTP 401** for no / invalid /
// expired api-key, **HTTP 403** for a VALID api-key whose permissions
// do NOT include `ADMIN`. The two are DISTINCT.
//
// (Corrected — session-22 hostile review #2. The prior comment claimed
// "HTTP 401 for both no-auth AND insufficient-permission"; that
// mis-read the kernel TEST at `audit-log/export/__tests__/route.test.ts`,
// which MOCKS `AuthError(401)` and never exercises the real
// `requireSessionOrApiKey` middleware. The middleware's
// `requireApiKeyWithPermission` path returns 403 for the
// insufficient-permission case — same surface as every abacPolicies
// method.)
//
// Three wire formats:
//   - `jsonl` (default): one JSON object per line, structured
//     `AuditLogRecord` shape. SDK validates wire shape strictly and
//     yields parsed objects.
//   - `ecs`: one Elastic Common Schema 8.x event per line (JSON-encoded).
//     Rides the same `application/x-ndjson` content-type as `jsonl` —
//     consumers parse the ECS shape themselves; SDK yields `unknown`.
//   - `cef`: one ArcSight CEF v0 line per row. Plain text, NOT JSON.
//     Content-Type: `text/plain`. SDK yields raw `string`.
//
// Cursor pagination via response HEADER (`x-attestry-next-cursor`) —
// NOT a body trailer (asymmetric with `decisions.export`). The SDK
// auto-paginates by default: the iterator transparently fetches the
// next page whenever the current page exhausts and the kernel emitted
// a next-cursor header. Single-page behavior is opt-in via
// `autoPaginate: false`.
//
// Compound cursor format: `<ISO-8601-UTC>:<UUID>`. Bare ISO is a legacy
// fallback (may skip same-microsecond rows; documented kernel behavior).

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import { parseLinesResponse } from "../lines-parser.js";
import { parseNDJSONResponse } from "../ndjson-parser.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

// Module-load snapshot of `Object.hasOwn` — defends against a
// late-loading hostile/buggy npm dependency that overrides the global
// (e.g., `Object.hasOwn = () => true`). Without the snapshot, the
// prototype-pollution defenses in `validateAuditChainVerificationResponse`
// would use whatever Object.hasOwn the dependency replaced it with at
// request time. Snapshotting at module load captures the original
// implementation BEFORE most consumer code has a chance to monkey-
// patch.
//
// Mirror of `batch.ts` / `gate.ts` / `check.ts` / `compliance-check.ts`
// pattern. Used on the response side of `verifyChain()` (this method
// has no input; the input-side defense is N/A — no fields to guard).
// Carry-forward of session-16 second-hostile-review MEDIUM #3 +
// session-17 build-round baked-in pattern.
const objectHasOwn = Object.hasOwn;

/**
 * Public closed-enum of supported wire formats. Mirrors the kernel's
 * `VALID_FORMATS` const at `src/lib/audit-log/export-helpers.ts:15-19`.
 * Drift-pinned in `src/lib/incidents/__tests__/sdk-drift.test.ts`.
 *
 * Forward-compat: when a future format is added (e.g., `csv`), bump the
 * SDK minor version and extend this array. The kernel's parseFormat
 * function returns 400 for any value outside this set; the SDK
 * pre-rejects invalid values synchronously as `TypeError` (build-round
 * D5 — closed-enum input validates at the SDK boundary so the failure
 * is faster + clearer than waiting for the server's 400).
 */
export const AUDIT_LOG_EXPORT_FORMATS = Object.freeze([
  "jsonl",
  "ecs",
  "cef",
] as const);

export type AuditLogExportFormat = (typeof AUDIT_LOG_EXPORT_FORMATS)[number];

/**
 * Wire shape for `format=jsonl`. Source-of-truth at kernel
 * `src/lib/audit-log/export-helpers.ts:115-150` (`rowToWireJson`).
 *
 * Stable wire format — distinct from the raw Drizzle row, so a column
 * rename in the DB doesn't churn the wire. The SDK mirrors this verbatim;
 * a kernel-side rename surfaces via the drift pin in `sdk-drift.test.ts`.
 *
 * `details` is `unknown` (jsonb) — the kernel emits whatever the row's
 * `details` column contains (any JSON value, OR null when the column
 * was null). Consumers parse based on the row's `action` (e.g.,
 * `"login"` → `{userAgent, ip}` shape; `"settings_updated"` →
 * `{key, oldValue, newValue}`). Forward-compatible with future kernel
 * action additions — the SDK does NOT enforce a per-action shape.
 *
 * `entryHash` / `previousEntryHash` form the audit-log's tamper-evidence
 * chain: `entryHash` is `sha256:<hex64>` over the row's canonical
 * payload; `previousEntryHash` is the prior row's `entryHash` (or null
 * for the very first row OR for rows ingested before chaining was
 * enabled). Consumers verify the chain by replaying — same conceptual
 * shape as decisions.verifyChain, but for audit events.
 */
export interface AuditLogRecord {
  /** UUID. */
  id: string;
  /** ISO-8601 UTC, microsecond precision (`YYYY-MM-DDTHH:MM:SS.sssZ`). */
  timestamp: string;
  /** UUID — the org that owns the row. Same as the caller's auth org. */
  orgId: string;
  /** UUID; null for cron / system actions where no user is involved. */
  userId: string | null;
  /** E.g. `"login"`, `"decision.created"`, `"webhook_endpoint_created"`. */
  action: string;
  /** E.g. `"session"`, `"decision_record"`, `"webhook_endpoint"`. */
  resourceType: string | null;
  /** ID of the affected resource (UUID for db rows; key for opaque ids). */
  resourceId: string | null;
  /** jsonb — any JSON value OR null. Per-action shape varies. */
  details: unknown;
  /** Source IP (INET → string). Null for non-network actions. */
  ipAddress: string | null;
  /** UA string. Null for non-browser actors. */
  userAgent: string | null;
  /** Session id (opaque). Null for non-session actors (api-key, cron). */
  sessionId: string | null;
  /**
   * `sha256:<hex64>` — hash of canonical row payload. NULL for rows
   * ingested before tamper-evidence chaining was enabled.
   */
  entryHash: string | null;
  /**
   * Previous row's `entryHash`. NULL for the very first row in the
   * chain OR for rows ingested before chaining.
   */
  previousEntryHash: string | null;
}

/**
 * Input shape for `auditLog.export(input?)`. All fields optional.
 *
 * Defaults applied server-side AND mirrored in the SDK's input
 * validation:
 *   - `format`: defaults to `"jsonl"` (kernel's `parseFormat` default)
 *   - `cursor`: defaults to none (start from the most-recent row)
 *   - `limit`: defaults to 1000 (kernel's `DEFAULT_LIMIT`)
 *   - `autoPaginate`: defaults to `true` (SDK-side; kernel has no opinion)
 *
 * `cursor` flow: the SDK reads `x-attestry-next-cursor` from each
 * page's response headers and passes it as `?cursor=<value>` on the
 * next page. Auto-pagination consumers don't need to manage cursors
 * themselves; explicit-cursor consumers call `export()` with
 * `autoPaginate: false` and inspect... actually, the SDK CANNOT expose
 * the response header through the async-iterator protocol cleanly.
 * For explicit-cursor mode today, consumers call `export()` with
 * `autoPaginate: false`, drain the iterator (one page worth of rows),
 * and call again with the previously-returned next-cursor. (Returning
 * the cursor through the iterator's protocol would require a
 * non-standard hybrid shape; documented as build-round D3.)
 */
export interface AuditLogExportInput {
  /**
   * Wire format. Defaults to `"jsonl"` if omitted. The SDK pre-validates
   * against `AUDIT_LOG_EXPORT_FORMATS` and throws `TypeError` synchronously
   * for any value outside the closed enum (build-round D5).
   */
  format?: AuditLogExportFormat;
  /**
   * Cursor. Compound `<ISO-8601-UTC>:<UUID>` (preferred — strict tuple
   * ordering across same-timestamp rows) OR bare ISO-8601 UTC (legacy
   * fallback — may skip same-microsecond rows; the kernel emits this
   * shape only on requests-from-old-clients but accepts both forms).
   * The SDK forwards verbatim — kernel's regex is the format authority.
   */
  cursor?: string;
  /**
   * Page size. 1-5000; kernel clamps to 5000 silently. SDK rejects
   * `NaN` / `Infinity` / `<= 0` / non-integer as TypeError (more
   * strict than kernel's silent coerce-to-1000 — fail-loud-and-
   * synchronous; build-round D4).
   */
  limit?: number;
  /**
   * When `true` (the default), the iterator transparently walks all
   * pages until the kernel stops emitting `x-attestry-next-cursor`.
   * When `false`, the iterator yields only the first page's rows and
   * stops; consumers fetch the next page by calling `export()` again
   * with the next cursor. (Caller-managed-cursor mode is documented
   * but cumbersome — see JSDoc on the input field.)
   */
  autoPaginate?: boolean;
}

/**
 * Result of `client.auditLog.verifyChain()`. Source-of-truth lives at
 * the kernel route `src/app/api/v1/audit-chain/verify/route.ts:66-73`
 * (the `successResponse({...})` literal) and `src/lib/crypto/audit-chain.ts:50-55`
 * (the `verifyAuditChain` return-type literal that the route uses).
 *
 * **Critical contract**: this shape is returned for BOTH valid and
 * invalid chains. `valid: false` is NOT an error — the kernel answered
 * the customer's question (is this audit log tampered?) and the SDK
 * resolves the Promise with the verdict body. Top-level structural
 * failures (auth, rate limit, internal) throw `AttestryAPIError`.
 * **Mirror of `decisions.verifyChain`'s contract** (carry-forward
 * invariant #12 — chainValid:false / valid:false is a verdict, not
 * an error).
 *
 * **Field semantics**:
 *   - `valid`: `true` iff every audit-log entry's `entryHash`
 *     matches the recomputed hash AND every entry's
 *     `previousEntryHash` matches the prior entry's `entryHash`.
 *     Empty audit logs verify as `true` (vacuous truth).
 *   - `entriesVerified`: count of entries verified successfully
 *     BEFORE the first broken link (or all entries on a valid
 *     chain). On a tampered chain, equals the broken entry's index
 *     in the ordered list; consumers can show "verified up to N
 *     entries". `0` on empty logs AND when the very first entry
 *     fails verification.
 *   - `totalEntries`: total count of audit-log entries fetched
 *     (post-truncation — the kernel caps at 5000 entries via the
 *     `.limit(5000)` clause at `route.ts:51`; orgs with more than
 *     5000 entries see only the oldest 5000 verified).
 *   - `firstEntry`: ISO-8601 UTC timestamp of the OLDEST entry in
 *     the fetched window. `null` if `totalEntries === 0`. Always
 *     present in the body (kernel emits it unconditionally with
 *     null fallback at `route.ts:63`); ALWAYS-PRESENT field on the
 *     wire even though its value may be null.
 *   - `lastEntry`: ISO-8601 UTC timestamp of the NEWEST entry in
 *     the fetched window. `null` if `totalEntries === 0`. Same
 *     emission semantics as `firstEntry`.
 *   - `brokenAt`: UUID of the entry where the chain broke, OR
 *     **OMITTED ENTIRELY from the wire when the chain is intact**.
 *     The kernel uses a conditional spread:
 *     `...(result.brokenAtId ? { brokenAt: result.brokenAtId } : {})`
 *     so the field is an own-property only on broken chains. The
 *     SDK preserves this faithfully — consumers detect "broken
 *     chain" via `result.valid === false` (closed-enum boolean),
 *     NOT via `result.brokenAt === undefined` (which is
 *     prototype-pollution-unsafe — see the JSDoc on `verifyChain()`
 *     for the full rationale).
 *
 * **Silent kernel-side truncation** (invariant #50): the kernel's
 * audit-log fetch is capped at 5000 entries (`route.ts:51`). For an
 * org with >5000 audit-log entries, the verifier sees only the
 * oldest 5000; the newest entries are NOT verified by this call.
 * The kernel does NOT emit a "truncated" flag — `totalEntries`
 * equals the number of rows fetched, NOT the org's full audit-log
 * row count. **Documented kernel surface gap**; the SDK does NOT
 * mask. A future kernel raise to a higher limit or pagination would
 * be additive (the SDK forwards `totalEntries` verbatim).
 *
 * **Mirror of `decisions.verifyChain`'s `ChainVerificationResult`
 * but with different field names** — the org-wide audit-log
 * verifier is a separate kernel function with separate vocabulary:
 *   - `valid` vs decisions' `chainValid`
 *   - `entriesVerified` vs decisions' `lastVerifiedSequence`
 *   - `totalEntries` vs decisions' `recordCount`
 *   - `brokenAt` (single UUID, optional own-property) vs decisions'
 *     `tamperedRecordIds: string[]` + `brokenRecordIds: string[]`
 *     (always-present arrays, distinguish security vs ops)
 * Drift-pinned kernel-side in `sdk-drift.test.ts` (build round).
 */
export interface AuditChainVerificationResult {
  /**
   * `true` iff the org's audit-log hash chain is intact. Empty logs
   * verify as `true` (vacuous truth). On `false`, inspect `brokenAt`
   * for the offending entry's UUID.
   */
  valid: boolean;
  /**
   * Count of entries verified successfully BEFORE the first broken
   * link. Equals `totalEntries` on a valid chain; less than
   * `totalEntries` on a broken chain (consumers show "verified up
   * to N entries").
   */
  entriesVerified: number;
  /**
   * Total entries fetched by the kernel. **Capped at 5000 per call**
   * by the kernel's `.limit(5000)` at `route.ts:51`. For orgs with
   * more than 5000 audit-log entries, this is the number of rows
   * verified, NOT the org's full audit-log row count. Documented
   * kernel surface gap.
   */
  totalEntries: number;
  /**
   * ISO-8601 UTC timestamp of the OLDEST entry in the fetched
   * window. `null` if `totalEntries === 0`. Always present on the
   * wire (kernel emits the field unconditionally with null
   * fallback at `route.ts:63`).
   */
  firstEntry: string | null;
  /**
   * ISO-8601 UTC timestamp of the NEWEST entry in the fetched
   * window. `null` if `totalEntries === 0`. Same emission semantics
   * as `firstEntry`.
   */
  lastEntry: string | null;
  /**
   * UUID of the entry where the chain broke. **OMITTED from the
   * wire when the chain is intact** — the kernel uses a conditional
   * spread `...(result.brokenAtId ? { brokenAt: result.brokenAtId } : {})`
   * at `route.ts:72`. On a valid chain, the field is NOT an
   * own-property of the response. Consumers detect "broken chain"
   * via `result.valid === false` (the closed-enum boolean is the
   * pollution-safe discriminator); reading `result.brokenAt`
   * yields `undefined` on a valid chain.
   */
  brokenAt?: string;
}

/**
 * AuditLog resource — sibling to `IncidentsResource`, `DecisionsResource`,
 * `ChatResource`. Today wraps two endpoints (`export` + `verifyChain`);
 * the class is the landing pad for future audit-log methods.
 */
export class AuditLogResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Stream audit-log rows in the requested format. Returns an
   * async-iterable that yields per-row frames.
   *
   * **Format-discriminated yield types** (TypeScript narrows via the
   * overload signatures):
   *   - `format: "jsonl"` (default) → `AsyncIterable<AuditLogRecord>`
   *   - `format: "ecs"` → `AsyncIterable<unknown>` (consumer parses ECS event)
   *   - `format: "cef"` → `AsyncIterable<string>` (raw CEF lines)
   *
   * **Auto-pagination** (default — `autoPaginate !== false`): the
   * iterator transparently walks back through history, fetching the
   * next page whenever the current page exhausts and the kernel emits
   * `x-attestry-next-cursor`. Stops when the kernel's response omits
   * the header (last page).
   *
   * **Single-page mode** (`autoPaginate: false`): the iterator yields
   * only the first page's rows then stops. The next-cursor IS NOT
   * exposed through the iterator protocol — consumers either pass
   * `autoPaginate` (default) and trust the SDK to walk, OR pass an
   * explicit `cursor` they tracked from a previous response (rare;
   * the response header isn't surfaced through the iterator today —
   * build-round D3).
   *
   * **Dual-auth admin scope**: the kernel route gates on
   * `requireSessionOrApiKey(request, { sessionRoles: ["admin"],
   * apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })` — the identical
   * dual-auth pattern the abacPolicies cluster uses. The SDK's
   * transport always sends `x-api-key`, so the api-key path is the
   * only one reachable from SDK consumers: **HTTP 401** for no /
   * invalid / expired api-key, **HTTP 403** for a valid api-key whose
   * permissions do NOT include `ADMIN`. Pin BOTH branches separately.
   * (Corrected — session-22 hostile review #2: the prior "401 for
   * both" claim mis-read the kernel test, which MOCKS the auth error;
   * the real dual-auth middleware returns 403 for insufficient
   * permission, same as the abacPolicies cluster.)
   *
   * **Order**: rows arrive DESC by `(timestamp, id)` — newest first.
   * Auto-pagination preserves this order across page boundaries.
   *
   * **Errors thrown FROM the iterator** (long-lived stream semantics —
   * symmetric with `decisions.stream` / `decisions.export`):
   *   - `AttestryAPIError` (status 400) — invalid `format` (server-side;
   *     SDK pre-rejects via TypeError), or invalid `cursor` (malformed
   *     ISO/UUID).
   *   - `AttestryAPIError` (status 401) — no / invalid / expired
   *     api-key.
   *   - `AttestryAPIError` (status 403) — a valid api-key whose
   *     permissions do NOT include `ADMIN`. Distinct from 401 — pin
   *     both branches separately.
   *   - `AttestryAPIError` (status 429) — rate limit (auto-retried by
   *     default; initial fetch only — invariant #20 — but each page's
   *     INITIAL fetch is independent so 429-on-page-2 retries cleanly).
   *   - `AttestryAPIError` (status 500) — internal error during streaming;
   *     scrubbed message.
   *   - `AttestryAPIError` — wrong content-type for the requested format
   *     (proxy / LB error page wrapped at 200; the transport's
   *     `expectedContentType` guard fails fast).
   *   - `AttestryError("auditLog.export: NDJSON line was not a JSON object")` —
   *     defensive; the kernel always emits objects in `jsonl` / `ecs`.
   *   - `AttestryError("auditLog.export: NDJSON record missing required
   *     fields or wrong type")` — defensive; jsonl-mode shape validation
   *     fails. Server emits the rowToWireJson shape verbatim.
   *   - `AttestryError("network error during stream: ...")` — TCP drop /
   *     proxy hang-up mid-stream. Wrapped by the parser primitives.
   *   - `AttestryError("request aborted by caller")` — `options.signal`
   *     fired (pre-aborted or mid-flight).
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation.
   *
   * **Notably ABSENT from the error surface**:
   *   - **No 402 plan-limit** — admin-only; no per-org quota gate.
   *   - **No 422** — the route uses inline string parsing, not Zod, for
   *     query params. Format validation returns 400 (not 422 like
   *     decisions.list).
   *   - **No 404** — orgId is implicit from auth; cross-org access is
   *     impossible (rows filtered by `auth.orgId`).
   *   - **No 413** — kernel's `MAX_LIMIT = 5000` is enforced by silent
   *     clamp, not 413. A request with `limit=10000` succeeds with
   *     5000 rows.
   *   - **No "stream ended without trailer" error** — different from
   *     `decisions.export`. The audit-log/export route does NOT emit a
   *     body trailer; the cursor lives in headers, the empty page is
   *     a valid stop signal. (Build-round D8.)
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch issued):
   *   - `input` itself: optional; when provided, must be a non-null,
   *     non-array object.
   *   - `input.format`: optional; one of `"jsonl"` / `"ecs"` / `"cef"`
   *     when provided. Pre-validated against the closed enum
   *     (`AUDIT_LOG_EXPORT_FORMATS`).
   *   - `input.cursor`: optional; non-empty string when provided.
   *     Lone-surrogate guard via `assertEncodableQueryString`
   *     (carry-forward invariant #32). Format check (compound
   *     `<ISO>:<UUID>` regex) deferred to server's `parseCursor`.
   *   - `input.limit`: optional; positive finite integer when provided.
   *     `NaN` / `Infinity` / `<= 0` / non-integer rejected. (Kernel's
   *     silent coerce-to-1000 is more permissive — SDK rejects loudly;
   *     build-round D4.)
   *   - `input.autoPaginate`: optional; boolean when provided.
   *
   * **Lazy**: the request is NOT issued until the first iteration.
   * Pass `options.signal` for cancellation — pre-aborted causes the
   * first iteration to throw `AttestryError` with no fetch issued;
   * mid-flight abort surfaces as `AttestryError` from the iterator.
   *
   * @example Walk all admin events, newest first
   * ```ts
   * for await (const row of client.auditLog.export()) {
   *   // row: AuditLogRecord
   *   if (row.action === "api_key_created") notify(row);
   * }
   * ```
   *
   * @example ECS for SIEM ingest
   * ```ts
   * for await (const event of client.auditLog.export({ format: "ecs" })) {
   *   // event: unknown — consumer parses as ECS 8.x
   *   await elasticIngest(event);
   * }
   * ```
   *
   * @example CEF for ArcSight
   * ```ts
   * for await (const line of client.auditLog.export({ format: "cef" })) {
   *   // line: string starting with "CEF:0|Attestry|..."
   *   await arcsightForward(line);
   * }
   * ```
   *
   * @example One page at a time (manual cursor — rare)
   * ```ts
   * const firstPage = client.auditLog.export({ autoPaginate: false, limit: 100 });
   * for await (const row of firstPage) { process(row); }
   * // The next-cursor is NOT exposed through the iterator. To paginate
   * // manually, the caller must track the last-seen `(timestamp, id)`
   * // and supply it as `cursor` on the next call. Most consumers want
   * // auto-paginate (the default) instead.
   * ```
   */
  export(): AsyncIterable<AuditLogRecord>;
  export(
    input: { format: "ecs" } & Omit<AuditLogExportInput, "format">,
    options?: RequestOptions,
  ): AsyncIterable<unknown>;
  export(
    input: { format: "cef" } & Omit<AuditLogExportInput, "format">,
    options?: RequestOptions,
  ): AsyncIterable<string>;
  export(
    input?: AuditLogExportInput,
    options?: RequestOptions,
  ): AsyncIterable<AuditLogRecord>;
  export(
    input?: AuditLogExportInput,
    options?: RequestOptions,
  ): AsyncIterable<AuditLogRecord | unknown | string> {
    // Top-level shape — when provided, must be a non-null, non-array
    // object. typeof null === "object" and typeof [] === "object", so
    // guard both explicitly. Unlike decisions.export (which requires
    // `input.systemId`), auditLog.export's input is OPTIONAL — `()`
    // and `(undefined)` are both valid.
    if (input !== undefined) {
      if (input === null || typeof input !== "object" || Array.isArray(input)) {
        throw new TypeError("auditLog.export: `input` must be an object when provided");
      }
      // Snapshot each input field via `readInputField` — a throwing
      // accessor surfaces as the documented synchronous `TypeError`
      // rather than the getter's raw exception (session-22 hostile
      // review #1 — the SDK-wide MEDIUM-1 getter-throws fix). The
      // export helper below still receives the original `input` (a
      // throwing getter is caught here first, so it is never reached).
      const format = readInputField(input, "format", "auditLog.export");
      const cursor = readInputField(input, "cursor", "auditLog.export");
      const limit = readInputField(input, "limit", "auditLog.export");
      const autoPaginate = readInputField(
        input,
        "autoPaginate",
        "auditLog.export",
      );
      // format: closed enum. Pre-reject invalid values synchronously
      // (faster + clearer than waiting for server's 400). Build-round D5.
      if (format !== undefined) {
        if (
          typeof format !== "string" ||
          !(AUDIT_LOG_EXPORT_FORMATS as readonly string[]).includes(format)
        ) {
          throw new TypeError(
            `auditLog.export: \`format\` must be one of ${AUDIT_LOG_EXPORT_FORMATS.join(", ")} when provided`,
          );
        }
      }
      // cursor: non-empty string + lone-surrogate guard.
      if (cursor !== undefined) {
        if (typeof cursor !== "string" || cursor.length === 0) {
          throw new TypeError(
            "auditLog.export: `cursor` must be a non-empty string when provided",
          );
        }
        assertEncodableQueryString(cursor, "cursor", "auditLog.export");
      }
      // limit: positive finite integer. NaN / Infinity / fractional /
      // <= 0 rejected. Stricter than kernel's silent coerce-to-1000
      // (build-round D4).
      if (limit !== undefined) {
        if (
          typeof limit !== "number" ||
          !Number.isInteger(limit) ||
          limit <= 0
        ) {
          throw new TypeError(
            "auditLog.export: `limit` must be a positive integer when provided",
          );
        }
      }
      // autoPaginate: strict boolean.
      if (autoPaginate !== undefined && typeof autoPaginate !== "boolean") {
        throw new TypeError(
          "auditLog.export: `autoPaginate` must be a boolean when provided",
        );
      }
    }
    return runAuditLogExport(this.client, input, options);
  }

  /**
   * Verify the integrity of the org's audit-log hash chain. Returns
   * an `AuditChainVerificationResult` describing whether the chain is
   * intact, and (when broken) the UUID of the entry where verification
   * failed.
   *
   * Wraps `GET /api/v1/audit-chain/verify` — no input, no query
   * parameters, no body. The caller's org is implicit from auth; the
   * kernel fetches up to 5000 audit-log entries ordered ascending by
   * timestamp and runs `verifyAuditChain()` on them.
   *
   * **API-key auth scope** (uses `requireApiKey` DIRECT — distinct
   * from BOTH siblings): the kernel route calls `requireApiKey(request)`
   * at `route.ts:31` with NO permission scoping AND NO subsequent
   * role check. Any valid API key for the org can verify the chain.
   * Returns **HTTP 401** for no/invalid API key; the `requireApiKey`
   * branch does NOT distinguish "no key" from "invalid key". **Note**:
   * `auditLog.export` ALSO calls `requireApiKey(request)` directly at
   * its route but then performs a separate role/permission check
   * (ADMIN-only — see audit-log/export route). `verifyChain()` is
   * distinct: NO role check, NO permission filter. The 403 path is
   * unreachable for this route, and ALL valid api-keys in the org
   * succeed (in contrast to `auditLog.export` where only ADMIN keys
   * succeed).
   *
   * **Kernel-side invariant (session-19 review-3 L2 carry-forward)**:
   * the route at `route.ts:32` reads `apiKeyUser.orgId` and passes
   * it directly to the Drizzle `eq(schema.auditLog.orgId, orgId)`
   * filter without a null-guard. The SDK assumes the kernel's
   * `requireApiKey` returns an `ApiKeyUser` with a non-null `orgId`
   * (i.e., the `apiKeys` table's `orgId` column is NOT NULL). If
   * a future schema migration relaxes that constraint, the route
   * could match zero rows on a malformed key and return a vacuous-
   * truth `valid: true` verdict, masking actual chain tampering.
   * This is a kernel-side hardening concern (SDK cannot detect
   * it from the wire); flagged here so a future kernel-hardening
   * audit knows to add a runtime guard in `requireApiKey`.
   *
   * **CRITICAL contract — does NOT throw on `valid: false`** (carry-
   * forward invariant #12). The kernel returns HTTP 200 with
   * `valid: false` on a tampered chain; the SDK MUST resolve the
   * Promise with the verdict body. Top-level structural failures
   * (auth, rate limit, internal) throw `AttestryAPIError`. Mirror of
   * `decisions.verifyChain`'s same contract.
   *
   * **NO `writeAuditLog` side effect** — the verifier is quiet
   * (asymmetric with `gate.evaluate` / `batch.submit` which both write
   * audit-log entries). Writing to the audit log while verifying it
   * would be ironic; the kernel team avoided this. `auditLog.verifyChain`
   * is a pure read.
   *
   * **Silent kernel-side truncation at 5000 entries** (invariant #50).
   * The kernel's audit-log fetch is capped at 5000 entries
   * (`route.ts:51`: `.limit(5000)`). For an org with more than 5000
   * audit-log entries, only the OLDEST 5000 are verified by this call.
   * The kernel does NOT emit a "truncated" flag — `totalEntries`
   * equals the number of rows fetched, NOT the org's full audit-log
   * row count. **Documented kernel surface gap**; the SDK does NOT
   * mask. Consumers with high-volume audit logs should be aware that
   * the kernel's verifier sees a stale window of the chain. A future
   * kernel pagination or higher limit would be additive (the SDK
   * forwards `totalEntries` verbatim).
   *
   * **Kernel-side 30-second timeout** (`maxDuration = 30` at
   * `route.ts:14`). The SDK does NOT enforce a client-side timeout
   * (consumers manage via `options.signal`), but the kernel's
   * function-runtime cap bounds the verification latency on the
   * server side. Cron-job consumers should budget call latency
   * relative to this cap — a near-5000-entry verification can take
   * tens of seconds under high SHA-256 load. A future kernel raise
   * (e.g., 30 → 60s) would relax this cap; downstream cron-job
   * sizing assumptions should be revisited.
   *
   * **Pollution-safe discriminator pattern** — branch on
   * `result.valid` (closed-enum boolean) to detect a broken chain,
   * NOT on `result.brokenAt === undefined`. The kernel emits
   * `brokenAt` as an OWN-PROPERTY of the response only when the
   * chain is broken; on a valid chain it's omitted entirely (kernel
   * uses a conditional spread at `route.ts:72`). Under
   * `Object.prototype.brokenAt = <value>` pollution, the equality
   * check walks the prototype and reads the polluted value —
   * returning false (i.e., "field is present") even when the
   * own-property is genuinely absent. The SDK's response-side
   * validator uses `Object.hasOwn` (snapshotted at module load) to
   * defend against this; consumers should use `result.valid`
   * directly. Carry-forward of session-17 first-hostile-review
   * MEDIUM #3 + session-18 build-round baked-in pattern.
   *
   * **Errors** — ordered by kernel firing precedence (rate-limit →
   * auth-pass-or-401 → DB fetch → verifier → 500-catchall):
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     (auto-retried by default — invariant #18; per-IP rate-limit
   *     key `audit-chain-verify:${ip}` against the standard
   *     `apiLimiter`).
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key.
   *     Single 401 surface (NO 403 — the route has no permission
   *     filter). Surfaces only when `requireApiKey` throws an
   *     `AuthError`; the route's catch (route.ts:74-77) propagates
   *     `error.statusCode` (401 for `AuthError`).
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`). Surfaces
   *     when the DB connection drops mid-fetch, the verifier
   *     throws, OR `requireApiKey`'s INFRASTRUCTURE fails (e.g., a
   *     DB error during the API-key lookup, not an auth-rejection;
   *     non-`AuthError` errors fall through to the route's
   *     `internalErrorResponse` catchall at route.ts:78).
   *   - `AttestryError` ("request aborted by caller") — caller-
   *     supplied `options.signal` fired (pre-aborted or mid-flight).
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation. See "Response-shape validation"
   *     below.
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard).
   *
   * **Notably ABSENT from the error surface**:
   *   - **No 400** — this method has no input; nothing to reject for
   *     malformed input. The route doesn't parse query params or
   *     body.
   *   - **No 402 plan-limit** — verifyChain is a READ; no quota.
   *   - **No 403** — no permission filter on the route (any key with
   *     a valid org binding succeeds). Asymmetric with
   *     `auditLog.export` (which gates on ADMIN role).
   *   - **No 404** — orgId is implicit from auth; no path/query
   *     parameters that could mismatch.
   *   - **No 413** — the kernel's `.limit(5000)` silently caps the
   *     fetch; oversize orgs see a truncated verification (NOT a
   *     413). Documented kernel surface gap.
   *   - **No 422** — no Zod schema (no body, no query).
   *   - **No TypeError from SDK** — this method has no input to
   *     validate.
   *
   * **Response-shape validation** (P2 hardening — symmetric defense
   * on response side via the module-load `objectHasOwn` snapshot;
   * mirror of `batch.ts` / `gate.ts` patterns):
   *   - Rejects with `AttestryError` if the response isn't a non-null,
   *     non-array object.
   *   - Rejects if `valid` isn't a boolean.
   *   - Rejects if `entriesVerified` / `totalEntries` aren't numbers.
   *   - Rejects if `firstEntry` / `lastEntry` aren't `null` OR a
   *     string.
   *   - Rejects if `brokenAt` is OWN-PROPERTY present but NOT a
   *     string. (When absent, the field is forward-compatibly
   *     undefined — kernel omits it on valid chains.)
   *   - Each response field read goes through the module-load
   *     `objectHasOwn` snapshot — defends against
   *     `Object.prototype.<field>` pollution masking a missing field.
   *
   * **Transport-shape validation** (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with
   *     a non-`application/json` Content-Type. NOTE: `valid: false`
   *     is a normal 200 response and resolves the promise (carry-
   *     forward invariant #12); only structural failures throw.
   *
   * @example Detect a tampered audit log
   * ```ts
   * const verdict = await client.auditLog.verifyChain();
   * if (!verdict.valid) {
   *   // brokenAt is an OWN-PROPERTY only on broken chains.
   *   await notifySecurity({
   *     entryId: verdict.brokenAt,
   *     verifiedUpTo: verdict.entriesVerified,
   *     totalEntries: verdict.totalEntries,
   *   });
   * }
   * console.log(`Verified ${verdict.entriesVerified}/${verdict.totalEntries} entries`);
   * ```
   *
   * @example Schedule periodic verification (cron job)
   * ```ts
   * // Run hourly from a cron — surfaces tampering within an hour
   * // of occurrence (high-frequency monitoring for compliance-
   * // critical orgs).
   * try {
   *   const verdict = await client.auditLog.verifyChain();
   *   if (!verdict.valid) {
   *     await pageOncall({ brokenAt: verdict.brokenAt });
   *   }
   * } catch (err) {
   *   if (err instanceof AttestryAPIError && err.status === 429) {
   *     // Back off — verifier is rate-limited per IP.
   *     return;
   *   }
   *   throw err;
   * }
   * ```
   */
  verifyChain(
    options?: RequestOptions,
  ): Promise<AuditChainVerificationResult> {
    // No input → no SDK-side input validation. Mirror of decisions'
    // `verifyChain(systemId)` minus the path-segment validation.
    return this.client
      ._request<AuditChainVerificationResult>({
        method: "GET",
        path: "/api/v1/audit-chain/verify",
        options,
      })
      .then((result) => validateAuditChainVerificationResponse(result));
  }
}

/**
 * Synchronously verify a query-string value is encodable via
 * `encodeURIComponent`. Mirrors the helper at `decisions.ts` (carry-
 * forward invariant #32 — URIError defect-class is uniformly handled).
 *
 * Duplicated rather than shared because cross-resource imports between
 * `audit-log.ts` and `decisions.ts` would create a graph cycle hazard
 * — both files want to remain leaf-resource modules. A future SDK
 * refactor may extract validation helpers to a shared module
 * (e.g., `src/validate.ts`) when a third caller shows up; for now the
 * duplication is intentional and documented.
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
 * Internal — async generator backing `auditLog.export`. Lazy: the
 * request is NOT issued until the first iteration.
 *
 * Auto-pagination loop: each iteration fetches one page; in
 * `autoPaginate: true` (the default), continues until the kernel stops
 * emitting `x-attestry-next-cursor`. Each page's INITIAL fetch goes
 * through the retry middleware (429 + Retry-After). Mid-stream errors
 * bubble per invariant #20.
 *
 * Format dispatch:
 *   - `cef` → `parseLinesResponse` (raw line splitter; yields strings)
 *   - `jsonl` → `parseNDJSONResponse` + per-row shape validation; yields
 *     `AuditLogRecord`. The SDK is the typed boundary — a malformed row
 *     (schema bug, version skew) throws `AttestryError` rather than
 *     yielding `undefined as string`.
 *   - `ecs` → `parseNDJSONResponse`; yields `unknown` (consumer parses
 *     ECS event shape themselves).
 */
async function* runAuditLogExport(
  client: AttestryClient,
  input: AuditLogExportInput | undefined,
  options: RequestOptions | undefined,
): AsyncGenerator<AuditLogRecord | unknown | string, void, unknown> {
  const format: AuditLogExportFormat = input?.format ?? "jsonl";
  const autoPaginate = input?.autoPaginate ?? true;

  // The transport's `expectedContentType` guard runs per-request;
  // jsonl/ecs ride `application/x-ndjson`, cef rides `text/plain`.
  // Drives both the `Accept:` request header AND the response
  // content-type fail-fast guard (single source of truth).
  const expectedContentType =
    format === "cef" ? "text/plain" : "application/x-ndjson";

  let cursor: string | undefined = input?.cursor;

  while (true) {
    // Build query — `format` always, `cursor` and `limit` only when
    // provided. `encodeQuery` skips `undefined` values.
    const query: Record<string, string | number | undefined> = {
      format,
      cursor,
      limit: input?.limit,
    };

    const response = await client._streamRequest({
      path: "/api/v1/audit-log/export",
      query,
      options,
      expectedContentType,
    });

    if (format === "cef") {
      // Raw line splitter — yields strings.
      for await (const line of parseLinesResponse(response)) {
        yield line;
      }
    } else if (format === "ecs") {
      // ECS rides NDJSON; SDK doesn't enforce ECS shape — consumers
      // parse via their own ECS schema. Forward-compatible with
      // future ECS-version additions.
      for await (const raw of parseNDJSONResponse(response)) {
        yield raw;
      }
    } else {
      // jsonl — validate AuditLogRecord shape per row.
      for await (const raw of parseNDJSONResponse(response)) {
        // Every NDJSON line must be a JSON object — neither primitives
        // nor arrays nor nulls are valid rows. Defensive: kernel always
        // emits objects, but a parser yielding e.g. a bare number would
        // otherwise pass through as `frame` of type `unknown`.
        if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
          throw new AttestryError(
            "auditLog.export: NDJSON line was not a JSON object",
          );
        }
        const obj = raw as Record<string, unknown>;
        // Validate per-row shape. The SDK is the typed boundary — a
        // malformed row (schema bug, version skew) throws here rather
        // than yielding `undefined as string` to the caller. Same
        // invariant as decisions.export's per-record validation.
        if (
          typeof obj.id !== "string" ||
          typeof obj.timestamp !== "string" ||
          typeof obj.orgId !== "string" ||
          (obj.userId !== null && typeof obj.userId !== "string") ||
          typeof obj.action !== "string" ||
          (obj.resourceType !== null && typeof obj.resourceType !== "string") ||
          (obj.resourceId !== null && typeof obj.resourceId !== "string") ||
          // `details` is `unknown` (jsonb) — pass through as-is.
          (obj.ipAddress !== null && typeof obj.ipAddress !== "string") ||
          (obj.userAgent !== null && typeof obj.userAgent !== "string") ||
          (obj.sessionId !== null && typeof obj.sessionId !== "string") ||
          (obj.entryHash !== null && typeof obj.entryHash !== "string") ||
          (obj.previousEntryHash !== null &&
            typeof obj.previousEntryHash !== "string")
        ) {
          throw new AttestryError(
            "auditLog.export: NDJSON record missing required fields or wrong type",
          );
        }
        yield {
          id: obj.id,
          timestamp: obj.timestamp,
          orgId: obj.orgId,
          userId: obj.userId as string | null,
          action: obj.action,
          resourceType: obj.resourceType as string | null,
          resourceId: obj.resourceId as string | null,
          details: obj.details,
          ipAddress: obj.ipAddress as string | null,
          userAgent: obj.userAgent as string | null,
          sessionId: obj.sessionId as string | null,
          entryHash: obj.entryHash as string | null,
          previousEntryHash: obj.previousEntryHash as string | null,
        };
      }
    }

    // Pagination decision. The cursor lives in the response HEADER
    // (NOT a body trailer — asymmetric with decisions.export, build-
    // round D8). After draining the body, read the header. If absent
    // OR autoPaginate is false, exit. Otherwise feed the cursor back
    // into the next page's query.
    const nextCursor = response.headers.get("x-attestry-next-cursor");
    if (!autoPaginate || nextCursor === null) {
      return;
    }
    cursor = nextCursor;
  }
}

/**
 * P2 hardening: validate the `verifyChain()` response's 5 always-
 * present fields plus the optional `brokenAt` field. Symmetric
 * prototype-pollution defense — read EACH field via the module-load
 * `objectHasOwn` snapshot so a hostile npm dep polluting
 * `Object.prototype.<field>` cannot mask a kernel regression that
 * drops the field (per session-16 second-hostile-review MEDIUM #3
 * carry-forward — defense applied on the response boundary even when
 * the input boundary is empty).
 *
 * Returns the validated `result` (typed `AuditChainVerificationResult`)
 * on success; throws `AttestryError` on any shape violation. Extracted
 * as a free function so the resource method body stays focused on
 * request construction.
 *
 * **`brokenAt` is INTENTIONALLY omitted from the wire on valid chains**
 * — the kernel uses a conditional spread
 * `...(result.brokenAtId ? { brokenAt: result.brokenAtId } : {})` at
 * `route.ts:72`. When `valid: true`, the field is NOT an own-property
 * of the response. The validator checks `objectHasOwn` BEFORE
 * type-checking, so absent-and-untyped is forward-compatible —
 * present-but-non-string is the actual regression signal.
 *
 * **Number-field validation is `typeof X === "number"` ONLY**
 * (session-19 review-2 LOW-2 carry-forward — faithful-courier
 * documented asymmetry). The check accepts `NaN`, `Infinity`,
 * `-Infinity`, `-0`, and `MAX_SAFE_INTEGER+1` (which loses
 * precision) — these would all pass `typeof === "number"`. This
 * is INTENTIONAL: JSON.parse on a kernel-emitted JSON string can
 * NEVER produce NaN / Infinity (JSON spec doesn't represent them);
 * `-0` and large numbers round-trip with whatever precision the
 * JSON gave. Tightening to `Number.isFinite` / `Number.isInteger`
 * would be a stricter contract than the kernel emits — the SDK
 * stays faithful-courier on numbers (symmetric with batch /
 * decisions / gate's response validators). **If a future wire
 * format (msgpack, CBOR) is added, this asymmetry must be
 * revisited** — the new wire could carry NaN literally, and the
 * faithful-courier semantic would leak NaN to consumers.
 *
 * **Single-field rejection semantics** (session-19 review-3 M1
 * carry-forward — UX/diagnostic clarification). The validator
 * checks fields SEQUENTIALLY in declaration order (valid →
 * entriesVerified → totalEntries → firstEntry → lastEntry →
 * brokenAt) and throws on the FIRST failing field. If a kernel
 * regression drops MULTIPLE fields at once, the consumer sees
 * ONLY the first failing field's diagnostic — they must fix
 * the fixture and re-run to surface the next failure. This
 * matches batch.ts / gate.ts / check.ts patterns (project
 * convention for response-shape validators); accumulating into
 * a multi-field message would diverge from the rest of the SDK.
 * Trade-off accepted: consistency-with-project-pattern wins
 * over single-cycle full-diagnostic.
 */
function validateAuditChainVerificationResponse(
  result: unknown,
): AuditChainVerificationResult {
  if (
    result === null ||
    typeof result !== "object" ||
    Array.isArray(result)
  ) {
    throw new AttestryError(
      `auditLog.verifyChain: expected an object response from the kernel ` +
        `(got ${describeType(result)})`,
    );
  }
  const obj = result as Record<string, unknown>;

  const valid = objectHasOwn(obj, "valid") ? obj.valid : undefined;
  if (typeof valid !== "boolean") {
    throw new AttestryError(
      `auditLog.verifyChain: expected response.valid to be a boolean ` +
        `(got ${describeType(valid)})`,
    );
  }
  const entriesVerified = objectHasOwn(obj, "entriesVerified")
    ? obj.entriesVerified
    : undefined;
  if (typeof entriesVerified !== "number") {
    throw new AttestryError(
      `auditLog.verifyChain: expected response.entriesVerified to be a number ` +
        `(got ${describeType(entriesVerified)})`,
    );
  }
  const totalEntries = objectHasOwn(obj, "totalEntries")
    ? obj.totalEntries
    : undefined;
  if (typeof totalEntries !== "number") {
    throw new AttestryError(
      `auditLog.verifyChain: expected response.totalEntries to be a number ` +
        `(got ${describeType(totalEntries)})`,
    );
  }
  const firstEntry = objectHasOwn(obj, "firstEntry")
    ? obj.firstEntry
    : undefined;
  if (firstEntry !== null && typeof firstEntry !== "string") {
    throw new AttestryError(
      `auditLog.verifyChain: expected response.firstEntry to be a string or null ` +
        `(got ${describeType(firstEntry)})`,
    );
  }
  const lastEntry = objectHasOwn(obj, "lastEntry")
    ? obj.lastEntry
    : undefined;
  if (lastEntry !== null && typeof lastEntry !== "string") {
    throw new AttestryError(
      `auditLog.verifyChain: expected response.lastEntry to be a string or null ` +
        `(got ${describeType(lastEntry)})`,
    );
  }
  // `brokenAt` is OPTIONAL — kernel omits it entirely on valid chains.
  // Only enforce the type guard when the field is an own-property of
  // the response. Absent-AND-untyped is the valid-chain shape.
  if (objectHasOwn(obj, "brokenAt")) {
    const brokenAt = obj.brokenAt;
    if (typeof brokenAt !== "string") {
      throw new AttestryError(
        `auditLog.verifyChain: expected response.brokenAt to be a string when present ` +
          `(got ${describeType(brokenAt)})`,
      );
    }
  }
  return result as AuditChainVerificationResult;
}

/**
 * Human-readable type description for error messages. Distinguishes
 * `null` and `array` from generic `object`. Duplicated in
 * `decisions.ts`, `incidents.ts`, `regulatory-changes.ts`,
 * `compliance-check.ts`, `check.ts`, `gate.ts`, `batch.ts` per
 * project pattern (small helper, leaf-resource modules, no shared
 * module yet).
 *
 * All four branches are reachable through `validateAuditChainVerificationResponse`'s
 * call sites: top-level shape check (null + array + non-object scalar),
 * per-field type guards (each field's `describeType(<wrong type>)`
 * exercised by tests).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
