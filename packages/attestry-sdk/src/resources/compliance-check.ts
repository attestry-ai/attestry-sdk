// ─── ComplianceCheck resource ───────────────────────────────────────────────
//
// Wraps the compliance-check surface (session 15):
//
//   - GET /api/v1/compliance-check?systemId=<UUID>
//   - GET /api/v1/compliance-check?orgName=<string>
//
// Third non-decisions resource on `@attestry/sdk`. Sibling to
// `IncidentsResource`, `DecisionsResource`, `ChatResource`,
// `AuditLogResource`, `RegulatoryChangesResource`. Single public
// method today (`check`); the resource class exists as the landing
// pad for future compliance-check methods if/when the kernel adds
// them (resource-class-per-kernel-resource convention, carry-forward
// invariant candidate #43).
//
// Multi-permission UNION auth scope: the kernel route gates on
// `requireApiKeyWithPermission(request, READ_SYSTEMS, READ_ASSESSMENTS)`
// which is OR semantics — `permissions.ts:53-55` uses `Array.some()`,
// NOT `.every()`. A key with EITHER permission (or `ADMIN`, or empty
// permissions for backwards-compat) succeeds. **HTTP 401** for
// no/invalid API key (the `requireApiKey` branch fires first inside
// `requireApiKeyWithPermission`); **HTTP 403** for an authenticated
// key that has NEITHER required permission. Pin BOTH branches
// separately. **Different from `auditLog.export`** which returns 401
// for both unauth and insufficient-permission (ADMIN-only convention;
// carry-forward invariant #42 governs ADMIN routes specifically).
// First SDK route to exercise the multi-arg form of
// `requireApiKeyWithPermission` — invariant candidate #45.
//
// XOR input mode (the **first** non-obvious gotcha): exactly one of
// `systemId` OR `orgName` must be provided. The kernel is NOT strictly
// XOR — when both are provided, kernel uses `systemId` and silently
// ignores `orgName` (route.ts:80-87). The SDK is **stricter** than the
// kernel — synchronously rejects "both provided" with a clear
// `TypeError`. This protects consumers from silent shadow-of-orgName
// bugs that the kernel quietly enables. Invariant candidate #46.
//
// Asymmetric cross-org error codes (the **second** non-obvious
// gotcha): cross-org systemId returns **404** (kernel collapses to
// "System not found", route.ts:76 — mirror of decisions.retrieve),
// while cross-org orgName returns **403** ("Access denied",
// route.ts:95). Pin BOTH branches and document the asymmetry in
// JSDoc + README. Invariant candidate #47.
//
// Silent `.limit(100)` on orgName path (the **third** non-obvious
// gotcha): route.ts:107 hardcodes `.limit(100)` on the org-systems
// query. Orgs with more than 100 systems see a truncated set with NO
// indicator — no `total` field, no `hasMore` cursor. The SDK does NOT
// mask this — JSDoc + README call it out as a kernel surface gap.
// Faithful-courier policy.
//
// Sync JSON request/response: reuses `client._request` and the
// existing `{success:true, data}` envelope-unwrap (carry-forward
// invariant #9). NO new SDK primitive needed — smaller blast radius
// than `auditLog.export`. Returns
// `Promise<ComplianceCheckResponse>`.

import type { AttestryClient } from "../client.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

// Module-load snapshot of `Object.hasOwn` — defends against a
// late-loading hostile/buggy npm dependency that overrides the global
// (e.g., `Object.hasOwn = () => true`). Without the snapshot, the H4
// prototype-pollution defense uses whatever Object.hasOwn the
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
// layered defense — perfect protection isn't possible at the SDK
// layer.
//
// Hostile review session 15 finding (LOW #2).
const objectHasOwn = Object.hasOwn;

/**
 * Per-system framework-coverage breakdown. Source-of-truth at
 * kernel `src/app/api/v1/compliance-check/route.ts:155-161`.
 *
 * Computed at handler-time, NOT a Drizzle column. The route iterates
 * target systems, reads each system's `riskClassifications` jsonb
 * (`applicableFrameworks: string[]`), aggregates assessed frameworks
 * across that system's assessment rows, and emits these three fields.
 *
 * `coveragePct` is `Math.round((assessed.size / applicable.length) * 100)`
 * when `applicable.length > 0`, else `0`. Defensively-typed
 * `coveragePct: number` (NOT clamped 0-100 in the type — `assessed`
 * can in theory exceed `applicable` if a system was assessed against
 * frameworks NOT in its applicable list; the kernel doesn't filter,
 * so the percentage could exceed 100). Consumers may want to apply
 * their own clamping.
 */
export interface ComplianceCheckFrameworkCoverage {
  /**
   * Frameworks the system is required to comply with — read from
   * the system's `riskClassifications.applicableFrameworks` jsonb
   * field. Open string array — kernel does not enforce a closed
   * enum. Order is preserved from the source array (kernel does
   * NOT re-sort).
   */
  applicable: string[];
  /**
   * Distinct frameworks the system has been assessed against —
   * computed as the deduped union of `assessment.frameworks: string[]`
   * across all assessment rows (NOT just completed assessments;
   * kernel includes every status). Order is the iteration order of
   * the deduplication `Set` — JS spec preserves insertion order.
   * Open string array (no closed enum).
   */
  assessed: string[];
  /**
   * Integer percentage 0..100 (typically — see note below).
   * `Math.round((assessed.size / applicable.length) * 100)` when
   * `applicable.length > 0`, else `0`.
   *
   * Edge cases consumers should be aware of:
   *   - `applicable: []` always yields `coveragePct: 0` regardless
   *     of how many `assessed` frameworks exist.
   *   - If `assessed.size > applicable.length` (a system assessed
   *     against frameworks outside its applicable list), the
   *     percentage exceeds 100. Kernel does NOT filter
   *     `assessed` to `applicable`-only — faithful courier.
   */
  coveragePct: number;
}

/**
 * Wire shape for a single per-system compliance result. Source-of-truth
 * at kernel `src/app/api/v1/compliance-check/route.ts:150-164`.
 *
 * Synthesized at handler-time, NOT a Drizzle row. The route iterates
 * target systems, queries assessments + attestations + risk
 * classifications, and emits these 7 fields. There is no row-to-wire
 * mapper module (unlike `auditLog.export`'s `rowToWireJson`); the
 * literal object shape lives inline in the route's `results.push({...})`
 * call. The drift pin in `sdk-drift.test.ts` reads the route source
 * and asserts the literal property names match this interface.
 *
 * **`compliant` field — implicit threshold of 70**:
 * `compliant === activeAttestations > 0 && (overallScore === null || overallScore >= 70)`.
 * Two qualifying clauses:
 *   1. `activeAttestations > 0` — must have at least one currently
 *      active (non-expired) attestation.
 *   2. `overallScore === null` (no scored assessment yet — counts as
 *      NOT-FAILING) **OR** `overallScore >= 70`.
 *
 * The 70 threshold is a kernel-side business policy. The SDK does NOT
 * re-derive — faithful courier. Consumers wanting a different bar can
 * apply it post-hoc via the `score` field.
 */
export interface ComplianceCheckResult {
  /** UUID. */
  systemId: string;
  /** From `aiSystems.name`. */
  systemName: string;
  /**
   * Compound boolean — see "implicit threshold of 70" note above.
   * `false` when `activeAttestations === 0`, OR when there's a
   * scored assessment with `overallScore < 70`. `true` otherwise.
   */
  compliant: boolean;
  /**
   * Numeric overall score from the LATEST `completed` assessment's
   * `scores.overallScore` jsonb field, IF that field is a `number`.
   * `null` when:
   *   - No completed assessment exists for this system, OR
   *   - The latest completed assessment's `scores.overallScore` is
   *     missing or non-numeric (kernel typeguards `typeof === "number"`).
   * Range is unbounded — kernel does not clamp 0..100.
   */
  score: number | null;
  /** See `ComplianceCheckFrameworkCoverage`. */
  frameworkCoverage: ComplianceCheckFrameworkCoverage;
  /**
   * Count of currently-active attestation rows — defined as
   * `attestations.status === "active"` AND
   * (`attestations.expiresAt === null` OR `attestations.expiresAt > now`).
   * Non-negative integer.
   */
  activeAttestations: number;
  /**
   * ISO-8601 from the LATEST `completed` assessment's `completedAt`,
   * or `null` if no completed assessment exists. The kernel sorts
   * completed assessments DESC by `completedAt` and takes the first.
   */
  lastAssessedAt: string | null;
}

/**
 * Top-level wire shape returned by `complianceCheck.check()`.
 * Source-of-truth at kernel `src/app/api/v1/compliance-check/route.ts:167-170`.
 *
 * `systems` cardinality:
 *   - **systemId path**: exactly 1 system on 200 (kernel returns 404
 *     if not found). Never empty.
 *   - **orgName path**: 0..100 systems (kernel hardcodes `.limit(100)`
 *     at route.ts:107). Empty array is a valid 200 response (org has
 *     no systems). **Truncation past 100 is silent** — see JSDoc on
 *     `check()`.
 *
 * `checkedAt` is server-generated at handler end via
 * `new Date().toISOString()` — uniquely identifies the snapshot.
 * Consumers may use it as a freshness marker.
 */
export interface ComplianceCheckResponse {
  systems: ComplianceCheckResult[];
  /** ISO-8601, server-generated at handler end. */
  checkedAt: string;
}

/**
 * Mutually-exclusive input shapes — modeled as a TypeScript
 * discriminated union so TS-typed callers cannot pass both at compile
 * time (the `?: never` exclusion on each branch makes "both" a type
 * error). Runtime guard rejects "both" too, for JS callers and
 * `as any` casts.
 *
 * **The kernel is NOT strict XOR** — when both are provided, kernel
 * silently uses `systemId` and ignores `orgName` (route.ts:80-87).
 * The SDK is **stricter** than the kernel — rejects "both" with a
 * clear `TypeError`. This protects consumers from silent
 * shadow-of-orgName bugs (D3 / invariant candidate #46).
 *
 * **Input properties must be enumerable** (faithful courier). The
 * runtime XOR check uses `Object.hasOwn` which returns `true` for
 * non-enumerable own properties as well as enumerable ones. So an
 * input constructed via `Object.defineProperty(obj, "orgName", {
 * value: "x", enumerable: false })` would be runtime-rejected as
 * "both provided" even when TS treats it as the systemId-only
 * branch. This is contrived (typical literal-object input is always
 * enumerable; class field initializers emit enumerable own
 * properties); the SDK does not defend against it. Hostile-review
 * LOW #6.
 */
export type ComplianceCheckInput =
  | {
      /** UUID of the system to check (kernel validates format). */
      systemId: string;
      /** TS-only exclusion — must be undefined when systemId is set. */
      orgName?: never;
    }
  | {
      /** TS-only exclusion — must be undefined when orgName is set. */
      systemId?: never;
      /**
       * Open-string org name to look up. Kernel resolves to an org
       * row by exact name match. The org MUST be the same as the API
       * key's org — cross-org returns 403. Returns up to 100 systems
       * (kernel hardcodes `.limit(100)`).
       */
      orgName: string;
    };

/**
 * ComplianceCheck resource — sibling to `IncidentsResource`,
 * `DecisionsResource`, `ChatResource`, `AuditLogResource`,
 * `RegulatoryChangesResource`. Today wraps a single endpoint
 * (`check`); the class is the landing pad for future compliance-check
 * methods if the kernel adds them (resource-class-per-kernel-resource
 * convention, invariant candidate #43).
 */
export class ComplianceCheckResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Return a per-system compliance summary for either a single system
   * (by UUID) or every system in an org (by org name, capped at 100).
   * Returns `Promise<ComplianceCheckResponse>` — sync JSON, no
   * pagination, no streaming.
   *
   * **Input mode — XOR with kernel quirk** (read carefully): exactly
   * one of `systemId` OR `orgName` must be provided. The kernel is
   * NOT strictly XOR — when both are provided, kernel silently picks
   * `systemId` and ignores `orgName`. The SDK is **stricter** than
   * the kernel and synchronously throws `TypeError` when both are
   * provided. This is a deliberate D3 deviation: the kernel's
   * silent-pick is a quirk that future maintenance could change at
   * any time, and surfacing the conflict at the SDK boundary makes
   * consumer code stable across kernel revisions.
   *
   * **Multi-permission UNION auth scope**: kernel uses
   * `requireApiKeyWithPermission(req, READ_SYSTEMS, READ_ASSESSMENTS)`
   * which is OR semantics (`Array.some()` at
   * `permissions.ts:53-55`). A key with EITHER permission (or `ADMIN`,
   * or null/empty permissions for backwards-compat) succeeds.
   * **HTTP 401** for no/invalid API key, **HTTP 403** for an
   * authenticated key that has NEITHER required permission. Pin
   * BOTH branches separately. **Distinct from `auditLog.export`** in
   * the auth MODEL — that route is ADMIN-only dual-auth — but NOT in
   * the status surface: `auditLog.export` also returns 401 vs 403
   * distinctly (corrected session-22 hostile review #2; the prior
   * "ADMIN-only 401-for-both" framing of invariant #42 was wrong).
   * First SDK route to exercise multi-arg
   * `requireApiKeyWithPermission` — invariant candidate #45.
   *
   * **Asymmetric cross-org error codes** (read carefully):
   * cross-org `systemId` returns **404** (kernel collapses to
   * "System not found" at route.ts:76 — mirror of
   * `decisions.retrieve`); cross-org `orgName` returns **403**
   * ("Access denied" at route.ts:95). Consumers writing defensive
   * error-handling logic must distinguish: a 404 on systemId path
   * may be "not your org" OR "genuine missing UUID"; a 403 on
   * orgName path is unambiguously "the org exists but you don't
   * own it". Invariant candidate #47.
   *
   * **Silent `.limit(100)` on orgName path** (read carefully): if
   * the org has more than 100 systems, the response is silently
   * truncated to the first 100 — NO `total` field, NO `hasMore`
   * cursor, NO warning. The SDK does NOT mask this (faithful
   * courier — kernel decided 100 is enough). Consumers managing
   * >100-system orgs should switch to systemId-per-row.
   *
   * **`compliant` field — implicit threshold of 70**:
   * `compliant === activeAttestations > 0 && (overallScore === null || overallScore >= 70)`.
   * Documented in detail on `ComplianceCheckResult.compliant` —
   * consumers wanting a different bar can apply it post-hoc via
   * the `score` field.
   *
   * Errors (kernel firing precedence: rate-limit → auth → input
   * validation, so a request with multiple problems surfaces only the
   * highest-precedence one. Hostile-review LOW #8):
   *   - `AttestryAPIError` (status 429) — rate limit FIRES FIRST
   *     (auto-retried by default — invariant #18; per-IP rate-limit
   *     key `v1-compliance-check:${ip}`). A flooded IP gets 429 even
   *     for unauthenticated or malformed requests.
   *   - `AttestryAPIError` (status 401) — no API key OR invalid key
   *     (the `requireApiKey` branch). Fires AFTER rate-limit but
   *     BEFORE input validation.
   *   - `AttestryAPIError` (status 403) — authenticated key has
   *     NEITHER `READ_SYSTEMS` nor `READ_ASSESSMENTS` (the
   *     permission-check branch); OR cross-org orgName ("Access
   *     denied"). Distinguish via the response body's `error`
   *     message.
   *   - `AttestryAPIError` (status 400) — invalid systemId UUID
   *     format (kernel's `isValidUuid` rejection). Fires AFTER auth.
   *     The SDK does NOT pre-validate UUID format (D2: kernel is the
   *     authority). The "neither systemId nor orgName" 400 is
   *     UNREACHABLE through the SDK — pre-rejected as `TypeError`.
   *   - `AttestryAPIError` (status 404) — systemId not found OR
   *     systemId belongs to a different org (kernel collapses
   *     cross-org systemId to 404); OR orgName not found.
   *   - `AttestryAPIError` (status 500) — internal kernel error
   *     (scrubbed message via `internalErrorResponse`).
   *   - `AttestryError` ("request aborted by caller") — caller-supplied
   *     `options.signal` fired (pre-aborted or mid-flight).
   *   - `AttestryError` (P2 hardening) — kernel response failed
   *     SDK-side shape validation (not an object, missing `systems`
   *     array, missing `checkedAt` string).
   *   - `AttestryAPIError` (P3 hardening) — kernel response had a
   *     wrong Content-Type (transport-level guard before body parsing).
   *   - `TypeError` (synchronous, no fetch issued) — input failed
   *     SDK-side validation (null / array / non-object input,
   *     neither systemId nor orgName provided, both provided, empty
   *     string, non-string, lone surrogates).
   *
   * **Notably ABSENT**:
   *   - **No 422** — no Zod schema; no closed enums in input.
   *   - **No 413** — no body size limit (no body — GET).
   *   - **No 402** — read-only, doesn't count against decisionsPerMonth quota.
   *
   * **SDK-side validation** (synchronous `TypeError`, no fetch
   * issued):
   *   - `input` itself: required; must be a non-null, non-array
   *     object.
   *   - `input.systemId` XOR `input.orgName`: exactly one must be
   *     provided. Both = `TypeError` (stricter than kernel — D3).
   *     Neither = `TypeError`.
   *   - `input.systemId` (when provided): non-empty string.
   *     Lone-surrogate guard via `assertEncodableQueryString`
   *     (carry-forward invariant #32). UUID format NOT pre-validated
   *     (D2 — kernel is the authority).
   *   - `input.orgName` (when provided): non-empty string.
   *     Lone-surrogate guard.
   *
   * **Response-shape validation** (P2 hardening):
   *   - Rejects with `AttestryError` if the kernel response isn't a
   *     non-null, non-array object.
   *   - Rejects if `response.systems` isn't an array.
   *   - Rejects if `response.checkedAt` isn't a string.
   *   - Per-row shape (the 7-field `ComplianceCheckResult`) is
   *     faithful-courier — NOT validated (P4 candidate).
   *
   * **Transport-shape validation** (P3 hardening):
   *   - Rejects with `AttestryAPIError` if the kernel responds with
   *     a non-`application/json` Content-Type — protects against
   *     proxy-injected HTML 200 pages parsing into junk consumer
   *     state.
   *
   * @example Compliance check by system UUID
   * ```ts
   * const result = await client.complianceCheck.check({
   *   systemId: "11111111-1111-1111-1111-111111111111",
   * });
   * for (const system of result.systems) {
   *   console.log(system.systemName, system.compliant, system.score);
   * }
   * ```
   *
   * @example Compliance check by org name (capped at 100 systems)
   * ```ts
   * const result = await client.complianceCheck.check({
   *   orgName: "Acme Corp",
   * });
   * console.log(`${result.systems.length} systems checked at ${result.checkedAt}`);
   * ```
   */
  check(
    input: ComplianceCheckInput,
    options?: RequestOptions,
  ): Promise<ComplianceCheckResponse> {
    // Top-level shape — input is REQUIRED (unlike auditLog.export /
    // regulatoryChanges.list which accept undefined). typeof null ===
    // "object" and typeof [] === "object", so guard both explicitly.
    if (
      input === null ||
      typeof input !== "object" ||
      Array.isArray(input)
    ) {
      throw new TypeError(
        "complianceCheck.check: `input` must be a non-null object with `systemId` or `orgName`",
      );
    }

    // XOR check — snapshot each field's value EXACTLY ONCE up front,
    // then operate only on the locals downstream. Three motivations:
    //   1. **Prototype-pollution defense (hostile round H4)**:
    //      `Object.prototype.systemId = "evil-uuid"` (set somewhere
    //      else in the consumer's process) DOES NOT trick the SDK
    //      into thinking systemId was provided when the user passed
    //      `{orgName: "Acme"}`. `Object.hasOwn` only checks own
    //      properties (ES2022, Node 16.9+ — well below the SDK's
    //      Node 18 floor). Use the module-load snapshot
    //      (`objectHasOwn`) so a late-loading dep that overrides the
    //      global doesn't defeat the defense. Hostile-review LOW #2.
    //   2. **TOCTOU defense (hostile-review LOW #1)**: a Proxy or
    //      getter-defining input could yield DIFFERENT values across
    //      multiple reads of the same field — the SDK would validate
    //      one value and send another to the wire. Snapshotting once
    //      collapses validate-then-send to a single read per field;
    //      the validated value is provably the value sent.
    //   3. An explicit `{systemId: "uuid", orgName: undefined}` (which
    //      TS permits via the `orgName?: never` branch) is treated as
    //      systemId-only — `objectHasOwn` says "yes, orgName is an
    //      own property" but the value is `undefined`, so the
    //      undefined-check filters it out.
    //
    // Each input field is read exactly once via the indexer below;
    // every subsequent operation uses the local snapshot.
    const systemIdRaw: unknown = objectHasOwn(input, "systemId")
      ? readInputField(input, "systemId", "complianceCheck.check")
      : undefined;
    const orgNameRaw: unknown = objectHasOwn(input, "orgName")
      ? readInputField(input, "orgName", "complianceCheck.check")
      : undefined;
    const hasSystemId = systemIdRaw !== undefined;
    const hasOrgName = orgNameRaw !== undefined;

    if (!hasSystemId && !hasOrgName) {
      throw new TypeError(
        "complianceCheck.check: must provide exactly one of `systemId` or `orgName`",
      );
    }
    if (hasSystemId && hasOrgName) {
      // **SDK is STRICTER than the kernel**. The kernel silently
      // picks systemId when both are provided (route.ts:80-87).
      // The SDK rejects to prevent shadow-of-orgName bugs that
      // could otherwise pass kernel-side and produce confusing
      // results (consumer expects orgName to take effect; gets
      // systemId-shaped response). D3 / invariant candidate #46.
      throw new TypeError(
        "complianceCheck.check: provide either `systemId` or `orgName`, not both " +
          "(kernel silently ignores `orgName` when both are present; SDK rejects " +
          "synchronously to prevent shadow-of-orgName bugs)",
      );
    }

    let validatedSystemId: string | undefined;
    let validatedOrgName: string | undefined;

    if (hasSystemId) {
      if (typeof systemIdRaw !== "string" || systemIdRaw.length === 0) {
        throw new TypeError(
          "complianceCheck.check: `systemId` must be a non-empty string when provided",
        );
      }
      // UUID format NOT pre-validated (D2 — kernel's `isValidUuid`
      // is the authority). Lone-surrogate guard (#32) catches the
      // URIError defect class.
      assertEncodableQueryString(systemIdRaw, "systemId", "complianceCheck.check");
      validatedSystemId = systemIdRaw;
    } else {
      if (typeof orgNameRaw !== "string" || orgNameRaw.length === 0) {
        throw new TypeError(
          "complianceCheck.check: `orgName` must be a non-empty string when provided",
        );
      }
      assertEncodableQueryString(orgNameRaw, "orgName", "complianceCheck.check");
      validatedOrgName = orgNameRaw;
    }

    return this.client
      ._request<ComplianceCheckResponse>({
        method: "GET",
        path: "/api/v1/compliance-check",
        query: {
          systemId: validatedSystemId,
          orgName: validatedOrgName,
        },
        options,
      })
      .then((result) => {
        // P2 hardening: validate the kernel returned an object with
        // the expected top-level shape. The route emits
        // `successResponse({systems, checkedAt})` where systems is
        // always an array (initialized as `[]` and populated via
        // `.push`) and checkedAt is always a string
        // (`new Date().toISOString()`). A kernel-side regression that
        // breaks any of these invariants would let a malformed shape
        // reach consumers, who would crash on `result.systems.length`
        // or similar with a confusing TypeError. Catch at the SDK
        // boundary with a clear AttestryError.
        if (
          result === null ||
          typeof result !== "object" ||
          Array.isArray(result)
        ) {
          throw new AttestryError(
            `complianceCheck.check: expected an object response from the kernel (got ${describeType(result)})`,
          );
        }
        const obj = result as unknown as Record<string, unknown>;
        if (!Array.isArray(obj.systems)) {
          throw new AttestryError(
            `complianceCheck.check: expected response.systems to be an array (got ${describeType(obj.systems)})`,
          );
        }
        if (typeof obj.checkedAt !== "string") {
          throw new AttestryError(
            `complianceCheck.check: expected response.checkedAt to be a string (got ${describeType(obj.checkedAt)})`,
          );
        }
        return result;
      });
  }
}

/**
 * Synchronously verify a query-string value is encodable via
 * `encodeURIComponent`. Mirrors the helper in `decisions.ts`,
 * `audit-log.ts`, and `regulatory-changes.ts` (carry-forward invariant
 * #32 — URIError defect-class is uniformly handled).
 *
 * Duplicated rather than shared because cross-resource imports between
 * leaf-resource modules would create graph-cycle hazards. A future
 * SDK refactor may extract validation helpers to a shared module
 * (e.g., `src/validate.ts`) when a fifth caller shows up; for now the
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
        // encodeURIComponent always throws URIError (an Error
        // subclass), so the String(err) branch is unreachable.
        // Defense-in-depth marker for the v8 coverage tool.
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
 * Duplicated in `decisions.ts`, `incidents.ts`, and
 * `regulatory-changes.ts` per project pattern (small helper,
 * leaf-resource modules, no shared module yet).
 *
 * In complianceCheck.check, `describeType` is invoked from THREE
 * call sites:
 *   1. Top-level "expected an object" error — value is null OR a
 *      non-object scalar OR an array (the negation of "non-null
 *      non-array object"). All three branches are reachable here.
 *   2. "expected response.systems to be an array" — value is the
 *      `systems` field, which can be anything but `Array`. All
 *      branches reachable.
 *   3. "expected response.checkedAt to be a string" — value is the
 *      `checkedAt` field, which can be anything but `string`. All
 *      branches reachable.
 *
 * Unlike regulatoryChanges.list (which only invokes describeType
 * from the "not an array" path, making the array branch
 * structurally unreachable in that call site), every branch here
 * IS reachable. No v8-ignore-next marker needed on any branch.
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}
