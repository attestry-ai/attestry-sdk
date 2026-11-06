import { z } from "zod";
import {
  PACK_TYPES,
  PACK_STATUSES,
  uuidLc,
  apiGet,
  callRest,
  outcomeToResult,
  type EvidencePackToolResult,
} from "./evidence-pack-shared.js";

/**
 * MCP tool: evidence_pack.list (registered `attestry_evidence_pack_list`).
 * Wraps GET /api/v1/evidence-packs — lists evidence packs for the
 * authenticated organization, newest first.
 *
 * Single page per call (DEV-45 / spec P1.5 hostile concern #5): this tool
 * does NOT auto-paginate. The kernel's keyset cursor is passed through in
 * the response as `nextCursor`; a caller pages by passing that value back
 * as the `cursor` argument on a subsequent call.
 */

export const evidencePackListSchema = {
  systemId: uuidLc()
    .optional()
    .describe("Optional: filter to packs scoped to this AI system UUID."),
  packType: z
    .enum(PACK_TYPES)
    .optional()
    .describe(
      "Optional: filter by pack type (annex_iv, agentic_reperformance, " +
        "red_team_cycle, pccp_evidence, underwriting_evidence).",
    ),
  status: z
    .enum(PACK_STATUSES)
    .optional()
    .describe(
      "Optional: filter by status (draft, signed, superseded, revoked, " +
        "expired).",
    ),
  limit: z
    .number()
    .int()
    .min(1)
    .max(200)
    .optional()
    .describe(
      "Optional: maximum packs to return (1-200). When omitted the API " +
        "applies its default page size of 50.",
    ),
  cursor: z
    .string()
    .optional()
    .describe(
      "Optional: opaque pagination cursor. Pass the `nextCursor` value " +
        "from a previous call's result to fetch the next page.",
    ),
};

export const evidencePackListDescription =
  "List evidence packs for the authenticated organization, newest first. " +
  "Returns {items, nextCursor}. Supports filtering by system, pack type, " +
  "and status. Returns a single page per call — pass `nextCursor` back as " +
  "`cursor` to page through results.";

export async function evidencePackList(args: {
  systemId?: string;
  packType?: string;
  status?: string;
  limit?: number;
  cursor?: string;
}): Promise<EvidencePackToolResult> {
  // `apiGet` drops `undefined` params, so an omitted filter is never sent
  // as a bare empty query value (which the kernel list route treats as
  // absent anyway — but not emitting it is cleaner).
  const params: Record<string, string | undefined> = {
    systemId: args.systemId,
    packType: args.packType,
    status: args.status,
    limit: args.limit !== undefined ? String(args.limit) : undefined,
    cursor: args.cursor,
  };

  const outcome = await callRest(() =>
    apiGet("/api/v1/evidence-packs", params),
  );
  return outcomeToResult(outcome, "Failed to list evidence packs.");
}
