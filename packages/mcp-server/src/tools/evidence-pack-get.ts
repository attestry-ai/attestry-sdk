import {
  uuidLc,
  apiGet,
  callRest,
  outcomeToResult,
  type EvidencePackToolResult,
} from "./evidence-pack-shared.js";

/**
 * MCP tool: evidence_pack.get (registered `attestry_evidence_pack_get`).
 * Wraps GET /api/v1/evidence-packs/{id} — retrieves a single pack's
 * metadata together with its full bundle list, org-scoped by the API key.
 */

export const evidencePackGetSchema = {
  packId: uuidLc().describe("UUID of the evidence pack to retrieve."),
};

export const evidencePackGetDescription =
  "Retrieve a single evidence pack's metadata and its full reperformance " +
  "bundle list. Returns {pack, bundles}. A pack that does not exist or " +
  "belongs to another organization returns a not-found error.";

export async function evidencePackGet(args: {
  packId: string;
}): Promise<EvidencePackToolResult> {
  // `packId` is UUID-validated + lowercased by the schema before the
  // handler runs; `encodeURIComponent` is belt-and-suspenders against
  // URL-path injection (spec P1.5 hostile concern #2 cross-ref).
  const outcome = await callRest(() =>
    apiGet(`/api/v1/evidence-packs/${encodeURIComponent(args.packId)}`),
  );
  return outcomeToResult(outcome, "Failed to retrieve evidence pack.");
}
