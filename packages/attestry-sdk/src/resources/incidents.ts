// ─── Incidents resource ─────────────────────────────────────────────────────
//
// Wraps the AI Incident Database surface (Prompt 16.5 + B.5):
//
//   - POST   /api/v1/incidents              create
//   - GET    /api/v1/incidents              list (cursor + filters)
//   - PATCH  /api/v1/incidents/:id          update (optInShare / resolved)
//   - POST   /api/ai/incidents/search       cluster search
//
// The SDK's public input/output types are decoupled from the kernel's
// internal Zod schemas. Drift detection lives in a follow-on pin (kernel
// reads packages/attestry-sdk/src/constants.ts and asserts the enum
// arrays match). Adding a new field to the kernel surface = explicit SDK
// release; we don't proxy unknown fields.

import type { AttestryClient } from "../client.js";
import type {
  FrameworkCode,
  IncidentType,
  Severity,
} from "../constants.js";
import { AttestryError } from "../errors.js";
import type { RequestOptions } from "../types.js";
import { readInputField } from "./safe-input-read.js";

export interface IncidentReportInput {
  incidentType: IncidentType;
  severity: Severity;
  /** Defaults to `[]` when omitted. */
  frameworksAffected?: FrameworkCode[];
  /** 1-10_000 chars. RAW caller text — server runs anonymizer at write time. */
  description: string;
  context?: Record<string, unknown>;
  /**
   * System / agent / model names to be hashed (not redacted) so cross-row
   * correlation is preserved. ≤50 entries, each ≤200 chars.
   */
  systemNames?: string[];
  /** Default false — explicit opt-in to share into the cross-tenant corpus. */
  optInShare?: boolean;
  /** Default false. */
  resolved?: boolean;
}

export interface Incident {
  id: string;
  incidentType: IncidentType;
  severity: Severity;
  frameworksAffected: FrameworkCode[];
  /**
   * Anonymized description AFTER the server's PII scrub. SDK callers see
   * this; raw input is never returned.
   */
  anonymizedDescription: string;
  patternHash: string;
  resolved: boolean;
  optInShare: boolean;
  createdAt: string;
}

export interface IncidentListInput {
  /**
   * `mine` returns the auth org's incidents (any opt-in state). `shared`
   * (default) returns the cross-tenant corpus filtered to opt-in rows.
   */
  scope?: "mine" | "shared";
  incidentType?: IncidentType;
  severity?: Severity;
  framework?: FrameworkCode;
  resolved?: boolean;
  /** ISO timestamp lower bound (inclusive). */
  from?: string;
  /** ISO timestamp upper bound (exclusive). */
  to?: string;
  cursor?: string;
  /** 1-200, default 50. */
  limit?: number;
}

export interface IncidentListResponse {
  items: Incident[];
  /**
   * Cursor for the next page. `null` (NOT undefined) when no more pages
   * — matches the kernel wire shape exactly. The kernel emits the field
   * even on the last page (with value `null`), so the SDK type reflects
   * that contract literally. Pass as `input.cursor` on the next call to
   * fetch the following page.
   *
   * Note: this is `string | null` not `string | undefined`; consumers
   * comparing should use `nextCursor !== null` rather than truthy
   * coercion. (Truthy works too — null is falsy — but the explicit
   * comparison documents intent better.)
   */
  nextCursor: string | null;
}

export interface IncidentPatchInput {
  optInShare?: boolean;
  resolved?: boolean;
}

export interface IncidentSearchInput {
  query?: string;
  patternHashes?: string[];
  incidentTypes?: IncidentType[];
  frameworks?: FrameworkCode[];
  /** 1-50, default 20. */
  limit?: number;
}

export interface IncidentClusterSeverityCounts {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface IncidentCluster {
  patternHash: string;
  incidentType: IncidentType;
  frameworksAffected: FrameworkCode[];
  count: number;
  resolvedCount: number;
  unresolvedCount: number;
  earliestAt: string;
  latestAt: string;
  representativeDescription: string;
  severityCounts: IncidentClusterSeverityCounts;
}

export interface IncidentSearchResponse {
  clusters: IncidentCluster[];
  count: number;
  /** True when the underlying corpus was bigger than the search cap pulled. */
  truncated: boolean;
}

export class IncidentsResource {
  constructor(private readonly client: AttestryClient) {}

  /** Submit a new incident. Server-side PII scrub runs before insert. */
  create(
    input: IncidentReportInput,
    options?: RequestOptions,
  ): Promise<Incident> {
    return this.client._request<Incident>({
      method: "POST",
      path: "/api/v1/incidents",
      body: input,
      options,
    });
  }

  /**
   * Cursor-paginated list of incidents the caller can see.
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
   */
  list(
    input: IncidentListInput = {},
    options?: RequestOptions,
  ): Promise<IncidentListResponse> {
    // Snapshot each query field via `readInputField` — a throwing
    // accessor surfaces as the documented synchronous `TypeError`
    // rather than the getter's raw exception (session-22 hostile
    // review #1 — the SDK-wide MEDIUM-1 getter-throws fix). The `as`
    // cast restores each field's declared `IncidentListInput` type for
    // the typed query construction below; it re-asserts only what the
    // consumer's own TypeScript type already claims.
    const scope = readInputField(input, "scope", "incidents.list") as
      IncidentListInput["scope"];
    const incidentType = readInputField(
      input,
      "incidentType",
      "incidents.list",
    ) as IncidentListInput["incidentType"];
    const severity = readInputField(input, "severity", "incidents.list") as
      IncidentListInput["severity"];
    const framework = readInputField(input, "framework", "incidents.list") as
      IncidentListInput["framework"];
    const resolved = readInputField(input, "resolved", "incidents.list") as
      IncidentListInput["resolved"];
    const from = readInputField(input, "from", "incidents.list") as
      IncidentListInput["from"];
    const to = readInputField(input, "to", "incidents.list") as
      IncidentListInput["to"];
    const cursor = readInputField(input, "cursor", "incidents.list") as
      IncidentListInput["cursor"];
    const limit = readInputField(input, "limit", "incidents.list") as
      IncidentListInput["limit"];

    // Synchronous lone-surrogate guard: the underlying transport runs
    // encodeURIComponent over each query value, which throws raw
    // URIError for malformed UTF-16. Without this check the URIError
    // leaks into the consumer (inconsistent with `incidents.update`'s
    // path-segment guard above and with the decisions.* resources
    // hardened in commits 0428777 / 85064c0). Same defect-class
    // sweep — close incidents.list now to keep the URIError surface
    // uniform across the SDK.
    if (scope !== undefined) {
      assertEncodableIncidentQueryString(scope, "scope");
    }
    if (incidentType !== undefined) {
      assertEncodableIncidentQueryString(incidentType, "incidentType");
    }
    if (severity !== undefined) {
      assertEncodableIncidentQueryString(severity, "severity");
    }
    if (framework !== undefined) {
      assertEncodableIncidentQueryString(framework, "framework");
    }
    if (from !== undefined) {
      assertEncodableIncidentQueryString(from, "from");
    }
    if (to !== undefined) {
      assertEncodableIncidentQueryString(to, "to");
    }
    if (cursor !== undefined) {
      assertEncodableIncidentQueryString(cursor, "cursor");
    }
    return this.client
      ._request<IncidentListResponse>({
        method: "GET",
        path: "/api/v1/incidents",
        query: {
          scope,
          incidentType,
          severity,
          framework,
          resolved,
          from,
          to,
          cursor,
          limit,
        },
        options,
      })
      .then((result) => {
        // P2 hardening: validate response shape (mirrors decisions.list
        // and regulatoryChanges.list). The kernel emits
        // `{success:true, data:{items: Incident[], nextCursor: string|null}}`
        // and the transport unwraps `data`. A regression to scalar/null
        // would let consumers crash; throw AttestryError at the SDK
        // boundary instead.
        assertIncidentsListResponse(result);
        return result;
      });
  }

  /** Toggle the customer-controlled flags. Anonymized payload is immutable. */
  update(
    id: string,
    input: IncidentPatchInput,
    options?: RequestOptions,
  ): Promise<Incident> {
    if (typeof id !== "string" || id.length === 0) {
      throw new TypeError("incidents.update: `id` is required");
    }
    let encoded: string;
    try {
      encoded = encodeURIComponent(id);
    } catch (err) {
      // encodeURIComponent throws URIError on lone surrogates (malformed
      // UTF-16). Surface that as the same TypeError shape consumers
      // already expect from id-validation, instead of leaking the raw
      // platform error class. Hostile round L1 (decisions resource) —
      // symmetric carry-forward.
      throw new TypeError(
        `incidents.update: \`id\` contains invalid UTF-16 sequences (${
          // `encodeURIComponent` always throws URIError (an Error
          // subclass), so the String(err) branch is unreachable.
          // Defense-in-depth marker for the v8 coverage tool.
          /* v8 ignore next */
          err instanceof Error ? err.message : String(err)
        })`,
        { cause: err },
      );
    }
    return this.client._request<Incident>({
      method: "PATCH",
      path: `/api/v1/incidents/${encoded}`,
      body: input,
      options,
    });
  }

  /**
   * Cross-tenant pattern search. Returns CLUSTERS — never raw rows. Wraps
   * `POST /api/ai/incidents/search`. At least one of `query`,
   * `patternHashes`, `incidentTypes`, `frameworks` must be present.
   */
  search(
    input: IncidentSearchInput,
    options?: RequestOptions,
  ): Promise<IncidentSearchResponse> {
    return this.client._request<IncidentSearchResponse>({
      method: "POST",
      path: "/api/ai/incidents/search",
      body: input,
      options,
    });
  }
}

/**
 * Synchronously verify a query-string value is encodable via
 * `encodeURIComponent`. The platform throws `URIError` for malformed
 * UTF-16 (lone surrogates such as `\uD800` / `\uDFFF`); the transport's
 * `encodeQuery` does NOT catch it, so without this guard the failure
 * leaks into `incidents.list` as a raw `URIError` — inconsistent with
 * `incidents.update` (which already converts URIError → TypeError on
 * the path-segment encoding) and with the decisions.* resources hardened
 * in commits 0428777 / 85064c0.
 *
 * Cause-chained for debugging. Mirrors `assertEncodableQueryString` in
 * resources/decisions.ts (deliberately duplicated rather than shared
 * via a new helpers module — small function, two call sites today,
 * extracting on a third).
 */
function assertEncodableIncidentQueryString(
  value: string,
  fieldName: string,
): void {
  try {
    encodeURIComponent(value);
  } catch (err) {
    throw new TypeError(
      `incidents.list: \`${fieldName}\` contains invalid UTF-16 sequences (${
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
 * Duplicated in `decisions.ts` and `regulatory-changes.ts` per
 * project pattern (small helper, leaf-resource modules).
 */
function describeType(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

/**
 * P2 hardening: validate the kernel's `incidents.list` response
 * shape. Mirrors `assertDecisionsListResponse` in `decisions.ts`.
 *
 * The kernel emits `{success:true, data:{items: Incident[],
 * nextCursor: string|null}}`. After transport envelope-unwrap, we
 * receive `{items, nextCursor}`. Asserts:
 *   - non-null, non-array object
 *   - `items` is an array
 *   - `nextCursor` is string OR null
 *
 * Per-row item shape NOT validated (faithful-courier).
 */
function assertIncidentsListResponse(
  raw: unknown,
): asserts raw is IncidentListResponse {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new AttestryError(
      `incidents.list: expected an object response from the kernel (got ${describeType(raw)})`,
    );
  }
  const obj = raw as Record<string, unknown>;
  if (!Array.isArray(obj.items)) {
    throw new AttestryError(
      `incidents.list: kernel response missing or invalid \`items\` array (got ${describeType(obj.items)})`,
    );
  }
  if (obj.nextCursor !== null && typeof obj.nextCursor !== "string") {
    throw new AttestryError(
      `incidents.list: kernel response \`nextCursor\` must be string or null (got ${describeType(obj.nextCursor)})`,
    );
  }
}
