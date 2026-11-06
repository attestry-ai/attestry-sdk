import { z } from "zod";
import {
  uuidLc,
  apiPost,
  callRest,
  outcomeToResult,
  type EvidencePackToolResult,
} from "./evidence-pack-shared.js";

/**
 * MCP tool: evidence_pack.revoke (registered `attestry_evidence_pack_revoke`).
 * Wraps POST /api/v1/evidence-packs/{id}/revoke — transitions a signed
 * evidence pack to `revoked`, invalidating it and blocking future
 * verification.
 *
 * Authority (P1.7 DQ-1): this tool's authority IS the MCP server's
 * configured `ATTESTRY_API_KEY`. The kernel revoke route is admin-only — a
 * read-scoped key (the documented default) makes this tool inert: the REST
 * route answers 403. A read-scoped key is recommended for autonomous /
 * untrusted AI deployments.
 *
 * `confirm` (DQ-1) is a required intentionality speed-bump enforced at the
 * MCP SDK schema boundary (`z.literal(true)`). It is consumed at the MCP
 * layer and NEVER forwarded in the REST body. `orgId` / `userId` are
 * auth-derived server-side.
 */

export const evidencePackRevokeSchema = {
  packId: uuidLc().describe("UUID of the signed evidence pack to revoke."),
  reason: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional human-readable revocation reason. Recorded verbatim in the " +
        "pack's audit-log entry for compliance investigators.",
    ),
  confirm: z
    .literal(true)
    .describe(
      "Required confirmation flag — must be exactly true. Revoking " +
        "invalidates a signed pack and blocks all future verification; this " +
        "gate ensures the transition is deliberate and not triggered by " +
        "loose inference.",
    ),
};

export const evidencePackRevokeDescription =
  "Revoke a signed evidence pack: transitions it from 'signed' to " +
  "'revoked', invalidating it and blocking all future verification. ADMIN " +
  "authority required — a tool's authority is the permission set of the MCP " +
  "server's configured ATTESTRY_API_KEY, and a read-scoped key (the " +
  "documented default) makes this tool inert (HTTP 403). A read-scoped key " +
  "is recommended for autonomous or untrusted AI deployments. Requires " +
  "confirm: true. Returns the revoked pack record.";

export async function evidencePackRevoke(args: {
  packId: string;
  reason?: string;
  /**
   * Validated by the MCP SDK schema (`z.literal(true)`) before this handler
   * runs — a DQ-1 intentionality gate only. Intentionally not referenced
   * here and never placed in the REST body.
   */
  confirm: true;
}): Promise<EvidencePackToolResult> {
  // Body from explicitly-named fields only — never spread `args` — so
  // `confirm` (an MCP-layer-only gate) and any unknown key cannot reach the
  // kernel route's `.strict()` body schema.
  const body: Record<string, unknown> = {};
  if (args.reason !== undefined) {
    body.reason = args.reason;
  }

  // `packId` is UUID-validated + lowercased by the schema;
  // `encodeURIComponent` is belt-and-suspenders against URL-path injection.
  const outcome = await callRest(() =>
    apiPost(
      `/api/v1/evidence-packs/${encodeURIComponent(args.packId)}/revoke`,
      body,
    ),
  );
  return outcomeToResult(outcome, "Failed to revoke evidence pack.");
}
