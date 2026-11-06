import {
  uuidLc,
  apiGet,
  callRest,
  successResult,
  errorResult,
  type EvidencePackToolResult,
  type RestEnvelope,
  type RestOutcome,
} from "./evidence-pack-shared.js";

/**
 * MCP tool: evidence_pack.export (registered `attestry_evidence_pack_export`).
 * Wraps GET /api/v1/evidence-packs/{id}/export?format=json — returns the
 * canonical JSON export artifact for a pack (an `export` marker block plus
 * the full pack record and its reperformance bundle list), org-scoped by
 * the API key.
 *
 * Authority (P1.7 DQ-1): like every P1.7 tool, this tool's authority is the
 * MCP server's configured `ATTESTRY_API_KEY`; `export` is a read operation,
 * so it needs a key with read access. `export` carries no `confirm` gate
 * (DQ-1 — only `sign` / `revoke` do).
 *
 * Format (P1.7 DQ-3): the MCP tool is JSON-only — it always requests
 * `?format=json` and exposes no `format` argument. The kernel's `pdf` /
 * `zip` exports are binary artifacts and remain REST-only; a structured-JSON
 * artifact is what an AI consumer wants anyway.
 *
 * Wire contract (P1.7 DEV-53): unlike every other evidence-pack route, the
 * export route returns the RAW JSON artifact on success — NOT the standard
 * `{success, data}` envelope — and a `{success: false, ...}` envelope on
 * error. So `export` cannot use the shared `outcomeToResult` (which keys
 * success off `success === true`); it uses `exportOutcomeToResult` below,
 * which discriminates on `success === false`. The export artifact's
 * top-level keys are `export` / `pack` / `bundles` with no `success` field,
 * so the discriminator is unambiguous (drift-pinned).
 */

export const evidencePackExportSchema = {
  packId: uuidLc().describe("UUID of the evidence pack to export."),
};

export const evidencePackExportDescription =
  "Export an evidence pack as a structured JSON artifact. Returns the " +
  "canonical JSON export — an 'export' marker block plus the full pack " +
  "record and its reperformance bundle list — suitable for offline " +
  "content-hash re-verification. A tool's authority is the permission set " +
  "of the MCP server's configured ATTESTRY_API_KEY; this read-only export " +
  "needs a key with read access. This tool always exports JSON; PDF and ZIP " +
  "exports are available only via the REST API (a binary artifact is a poor " +
  "fit for a text tool result, and an AI consumer wants the structured " +
  "JSON).";

/**
 * Map a REST outcome to a tool result for the export endpoint.
 *
 * The export route does not answer with the standard `{success, data}`
 * envelope on success — it returns the raw JSON export artifact. Errors DO
 * use the standard `{success: false, error, details?}` envelope. So:
 *   - transport failure       → isError, "request failed: ..." message
 *   - null / non-object body  → isError, fallback message
 *   - `success === false`     → isError, the REST error + `details.code`
 *   - anything else           → success: the raw export artifact, verbatim
 */
function exportOutcomeToResult(
  outcome: RestOutcome<unknown>,
): EvidencePackToolResult {
  if (!outcome.ok) {
    return errorResult({
      error: `Attestry API request failed: ${outcome.transportError}`,
    });
  }

  const env = outcome.env as RestEnvelope<unknown> | null | undefined;
  if (env == null || typeof env !== "object") {
    return errorResult({ error: "Failed to export evidence pack." });
  }

  if (env.success === false) {
    return errorResult({
      error:
        typeof env.error === "string"
          ? env.error
          : "Failed to export evidence pack.",
      code:
        typeof env.details?.code === "string" ? env.details.code : undefined,
      details: env.details,
    });
  }

  // Not an error envelope → the JSON export artifact. Passed through
  // verbatim (DEV-53) — the artifact is a compliance document, never
  // reshaped or summarized.
  return successResult(env);
}

export async function evidencePackExport(args: {
  packId: string;
}): Promise<EvidencePackToolResult> {
  // DQ-3: always request `format=json`; no `format` argument is exposed.
  // `packId` is UUID-validated + lowercased by the schema;
  // `encodeURIComponent` is belt-and-suspenders against URL-path injection.
  const outcome = await callRest(() =>
    apiGet(
      `/api/v1/evidence-packs/${encodeURIComponent(args.packId)}/export`,
      { format: "json" },
    ),
  );
  return exportOutcomeToResult(outcome);
}
