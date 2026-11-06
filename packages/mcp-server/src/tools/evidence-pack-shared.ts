import { z } from "zod";
import { apiGet, apiPost, type ApiResponse } from "../client.js";

/**
 * KE2 P1.5 — Shared surface for the four evidence-pack MCP tools
 * (`attestry_evidence_pack_create` / `_get` / `_list` / `_append_bundle`).
 *
 * Holds the closed-enum mirrors, the UUID input primitive, the REST
 * envelope types, and the REST-call + result-mapping helpers that the
 * four tool files reuse. Kept in one module so the drift pins and the
 * coverage gate have a single shared surface to target.
 */

// ─── Closed-enum mirrors (drift-pinned against the kernel) ──────────────────
//
// These MUST stay byte-identical to `PACK_TYPES` / `PACK_STATUSES` in the
// kernel's `src/lib/evidence-pack/types.ts`. The MCP layer mirrors them so
// a bad `packType` / `status` is rejected at the SDK boundary (spec P1.5
// hostile concern #3) instead of round-tripping to a REST 422.
//
// Drift defense: `__tests__/drift-evidence-pack.test.ts` source-reads the
// kernel file and asserts tuple equality. If either side adds/removes a
// value without the other, that pin fails.

export const PACK_TYPES = [
  "annex_iv",
  "agentic_reperformance",
  "red_team_cycle",
  "pccp_evidence",
  "underwriting_evidence",
] as const;

export type PackType = (typeof PACK_TYPES)[number];

export const PACK_STATUSES = [
  "draft",
  "signed",
  "superseded",
  "revoked",
  "expired",
] as const;

export type PackStatus = (typeof PACK_STATUSES)[number];

// ─── UUID input + lowercase normalization ───────────────────────────────────
//
// Spec P1.5 hostile concern #2: UUID format pre-check at the SDK boundary.
// Mirrors the kernel's `uuidLc()` (`src/lib/evidence-pack/types.ts`):
//   z.string().uuid().transform((v) => v.toLowerCase())
// Postgres `uuid` columns canonicalize to lowercase, and the kernel
// lowercases every UUID at its own Zod boundary; the MCP layer applies the
// identical transform so an uppercase UUID from a caller normalizes the
// same way on both sides (no case-sensitivity surprises in URLs / filters).
//
// zod 4 note (1.1.0): the kernel is on zod 3, whose `.uuid()` accepts any
// 8-4-4-4-12 hex string. zod 4's `.uuid()` is RFC 9562-strict (version
// nibble 1-8, variant 8/9/a/b) and would reject ids the kernel accepts.
// zod 4's `.guid()` is the exact zod-3 `.uuid()` check, so every UUID
// field in this package uses `.guid()` to keep MCP-side validation
// identical to 1.0.0 and to the kernel. Do not "fix" these to `.uuid()`.

export const uuidLc = () =>
  z
    .string()
    .guid()
    .transform((v) => v.toLowerCase());

// ─── MCP tool result ────────────────────────────────────────────────────────
//
// DEV-41: the four P1.5 tools return a structured result carrying the
// JSON-string `text` AND an `isError` flag. `src/index.ts` maps `isError`
// onto the MCP `CallToolResult` so a REST failure surfaces as a
// protocol-level tool error (spec P1.5 hostile concern #4) instead of a
// success-shaped payload the caller has to introspect.

export interface EvidencePackToolResult {
  /** Pretty-printed JSON string — the tool's `content[0].text`. */
  text: string;
  /** True when the call did not succeed; mapped to `CallToolResult.isError`. */
  isError: boolean;
}

// ─── REST envelope types ─────────────────────────────────────────────────────
//
// The kernel evidence-pack routes answer with:
//   success → {success: true, data: <T>}
//   error   → {success: false, error: <message>, details?: {code, ...}}
// (`src/lib/api.ts` `successResponse` / `errorResponse`).
//
// `ApiResponse<T>` (client.ts) models {success, data?, error?, fieldErrors?}
// — it has no `details`. `RestEnvelope<T>` widens it with the optional
// `details` field. Because every field is optional, an `ApiResponse<T>`
// value is assignable to `RestEnvelope<T>` with no cast.

export interface RestErrorDetails {
  /** Machine-readable error identifier, e.g. `evidence_pack.not_found`. */
  code?: string;
  /** Zod issue list on a 422 (`{path, message}` entries). */
  issues?: unknown;
  /** Current pack status on a 409 `evidence_pack.invalid_state`. */
  currentStatus?: string;
  [key: string]: unknown;
}

export interface RestEnvelope<T> {
  success?: boolean;
  data?: T;
  error?: string;
  details?: RestErrorDetails;
  fieldErrors?: Record<string, unknown>;
}

// ─── REST call wrapper ───────────────────────────────────────────────────────
//
// DEV-47: `apiGet` / `apiPost` can throw before producing an envelope —
// a missing `ATTESTRY_API_KEY` (`getConfig`), a network failure (`fetch`),
// or a non-JSON / malformed response body (`response.json()`). `callRest`
// catches all three transport-layer throws and converts them to a
// `RestOutcome` the caller maps to a clean tool result.
//
// The result builders below stay exception-free by construction (F-HR-2):
// they only ever `JSON.stringify` values that originated from
// `response.json()` — finite plain-JSON trees, so no cycles and no BigInt
// that could make `JSON.stringify` itself throw.

export type RestOutcome<T> =
  | { ok: true; env: RestEnvelope<T> }
  | { ok: false; transportError: string };

export async function callRest<T = unknown>(
  call: () => Promise<ApiResponse<T>>,
): Promise<RestOutcome<T>> {
  try {
    const env: RestEnvelope<T> = await call();
    return { ok: true, env };
  } catch (e) {
    return {
      ok: false,
      transportError: e instanceof Error ? e.message : String(e),
    };
  }
}

/** Re-export the raw HTTP helpers so tool files import from one module. */
export { apiGet, apiPost };

// ─── Result builders ─────────────────────────────────────────────────────────

const JSON_INDENT = 2;

/**
 * Build a success tool result. The REST `data` payload is passed through
 * verbatim (DEV-3) — evidence-pack records are compliance artifacts, so
 * the tools never reshape or summarize them (DEV-42).
 */
export function successResult(data: unknown): EvidencePackToolResult {
  return {
    text: JSON.stringify(data ?? null, null, JSON_INDENT),
    isError: false,
  };
}

/**
 * Build an error tool result (`isError: true`) with a structured body:
 * `{error, code?, details?}`. `code` is hoisted from `details.code` so a
 * consumer can branch on the machine-readable identifier without digging
 * (spec P1.5 hostile concern #4); `details` carries the full structured
 * object (`issues` / `currentStatus`) when present.
 */
export function errorResult(fields: {
  error: string;
  code?: string;
  details?: RestErrorDetails;
}): EvidencePackToolResult {
  const body: Record<string, unknown> = { error: fields.error };
  if (fields.code !== undefined) {
    body.code = fields.code;
  }
  if (fields.details !== undefined) {
    body.details = fields.details;
  }
  return { text: JSON.stringify(body, null, JSON_INDENT), isError: true };
}

/**
 * Map a `RestOutcome` to an `EvidencePackToolResult`:
 *  - transport failure       → isError, "request failed: …" message
 *  - non-object / null body  → isError, the supplied fallback message
 *  - {success: true}         → success, `data` passed through
 *  - {success: false, …}     → isError, REST `error` + `details.code`
 *
 * The null / non-object guards cover a kernel response that is not the
 * expected envelope at all (spec P1.5 hostile concern #1 residual).
 */
export function outcomeToResult<T>(
  outcome: RestOutcome<T>,
  fallbackError: string,
): EvidencePackToolResult {
  if (!outcome.ok) {
    return errorResult({
      error: `Attestry API request failed: ${outcome.transportError}`,
    });
  }

  const env = outcome.env as RestEnvelope<T> | null | undefined;
  if (env == null || typeof env !== "object") {
    return errorResult({ error: fallbackError });
  }

  if (env.success === true) {
    return successResult(env.data);
  }

  return errorResult({
    error: typeof env.error === "string" ? env.error : fallbackError,
    code:
      typeof env.details?.code === "string" ? env.details.code : undefined,
    details: env.details,
  });
}
