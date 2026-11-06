import { z } from "zod";
import {
  uuidLc,
  apiPost,
  callRest,
  outcomeToResult,
  type EvidencePackToolResult,
} from "./evidence-pack-shared.js";

/**
 * MCP tool: evidence_pack.sign (registered `attestry_evidence_pack_sign`).
 * Wraps POST /api/v1/evidence-packs/{id}/sign — transitions a draft evidence
 * pack to `signed`, finalizing it into an auditor-visible compliance
 * artifact (the kernel recomputes its content hash on sign).
 *
 * Authority (P1.7 DQ-1): this tool's authority IS the MCP server's
 * configured `ATTESTRY_API_KEY`. The kernel sign route is admin-only — a
 * read-scoped key (the documented default) makes this tool inert: the REST
 * route answers 403 and the tool surfaces a clean error. A read-scoped key
 * is recommended for autonomous / untrusted AI deployments.
 *
 * `confirm` (DQ-1) is a required intentionality speed-bump enforced at the
 * MCP SDK schema boundary (`z.literal(true)`). It is consumed at the MCP
 * layer and NEVER forwarded in the REST body. `orgId` / `userId` are
 * auth-derived server-side from the API key.
 */

export const evidencePackSignSchema = {
  packId: uuidLc().describe("UUID of the draft evidence pack to sign."),
  attestationCertificateId: uuidLc()
    .optional()
    .describe(
      "Optional UUID of an attestation certificate to bind to the signed " +
        "pack. When provided, it must belong to the caller's organization.",
    ),
  confirm: z
    .literal(true)
    .describe(
      "Required confirmation flag — must be exactly true. Signing finalizes " +
        "a draft pack into an immutable, auditor-visible compliance " +
        "artifact; this gate ensures the transition is deliberate and not " +
        "triggered by loose inference.",
    ),
};

export const evidencePackSignDescription =
  "Sign a draft evidence pack: transitions it from 'draft' to 'signed', " +
  "finalizing it into an auditor-visible compliance artifact and recomputing " +
  "its content hash. ADMIN authority required — a tool's authority is the " +
  "permission set of the MCP server's configured ATTESTRY_API_KEY, and a " +
  "read-scoped key (the documented default) makes this tool inert (HTTP " +
  "403). A read-scoped key is recommended for autonomous or untrusted AI " +
  "deployments. Requires confirm: true. Returns the signed pack record.";

export async function evidencePackSign(args: {
  packId: string;
  attestationCertificateId?: string;
  /**
   * Validated by the MCP SDK schema (`z.literal(true)`) before this handler
   * runs — a DQ-1 intentionality gate only. Intentionally not referenced
   * here and never placed in the REST body.
   */
  confirm: true;
}): Promise<EvidencePackToolResult> {
  // Build the REST body from explicitly-named fields only — never spread
  // `args` — so `confirm` (an MCP-layer-only gate) and any unknown key
  // cannot reach the kernel route's `.strict()` body schema.
  const body: Record<string, unknown> = {};
  if (args.attestationCertificateId !== undefined) {
    body.attestationCertificateId = args.attestationCertificateId;
  }

  // `packId` is UUID-validated + lowercased by the schema before the handler
  // runs; `encodeURIComponent` is belt-and-suspenders against URL-path
  // injection (matches the P1.5 get / append_bundle tools).
  const outcome = await callRest(() =>
    apiPost(
      `/api/v1/evidence-packs/${encodeURIComponent(args.packId)}/sign`,
      body,
    ),
  );
  return outcomeToResult(outcome, "Failed to sign evidence pack.");
}
