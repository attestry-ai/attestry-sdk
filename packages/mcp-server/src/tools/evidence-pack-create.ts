import { z } from "zod";
import {
  PACK_TYPES,
  uuidLc,
  apiPost,
  callRest,
  outcomeToResult,
  type EvidencePackToolResult,
} from "./evidence-pack-shared.js";

/**
 * MCP tool: evidence_pack.create (registered `attestry_evidence_pack_create`).
 * Wraps POST /api/v1/evidence-packs — creates a draft evidence pack for the
 * authenticated organization. `orgId` / `userId` are derived server-side
 * from the API key; they are never accepted on the wire.
 */

/**
 * Framework-binding item shape. Descriptive mirror of the kernel's
 * `frameworkBindingSchema` (DEV-43) — field names + optionality, so the
 * MCP client knows how to populate it; the kernel route remains the
 * authoritative validator for length bounds and `.strict()` rejection.
 */
const frameworkBindingSchema = z
  .object({
    framework: z
      .string()
      .describe("Framework key, e.g. 'eu_ai_act' or 'colorado_ai_act'."),
    identifier: z
      .string()
      .describe("Framework-specific identifier (article / clause / control)."),
    jurisdiction: z
      .string()
      .optional()
      .describe("Optional jurisdiction, e.g. 'EU' or 'US-CO'."),
    effective_date: z
      .string()
      .optional()
      .describe("Optional ISO-8601 date the binding takes effect."),
  })
  .describe("A single regulatory framework binding.");

export const evidencePackCreateSchema = {
  packType: z
    .enum(PACK_TYPES)
    .describe(
      "Evidence pack type. One of: annex_iv, agentic_reperformance, " +
        "red_team_cycle, pccp_evidence, underwriting_evidence.",
    ),
  systemId: uuidLc()
    .optional()
    .describe(
      "Optional UUID of the AI system the pack is scoped to. Omit for an " +
        "org-level pack.",
    ),
  frameworkBindings: z
    .array(frameworkBindingSchema)
    .optional()
    .describe("Optional list of regulatory framework bindings for the pack."),
  metadata: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Optional free-form metadata object (string-keyed)."),
};

export const evidencePackCreateDescription =
  "Create a new draft evidence pack for the authenticated organization. " +
  "Returns the created pack record (id, pack type, status 'draft', " +
  "framework bindings, timestamps).";

export async function evidencePackCreate(args: {
  packType: string;
  systemId?: string;
  frameworkBindings?: unknown[];
  metadata?: Record<string, unknown>;
}): Promise<EvidencePackToolResult> {
  // Build the REST body from explicitly-named fields only — never spread
  // `args` — so unknown keys can never reach the route's `.strict()`
  // schema (DEV-43, spec P1.5 hostile concern #1).
  const body: Record<string, unknown> = { packType: args.packType };
  if (args.systemId !== undefined) {
    body.systemId = args.systemId;
  }
  if (args.frameworkBindings !== undefined) {
    body.frameworkBindings = args.frameworkBindings;
  }
  if (args.metadata !== undefined) {
    body.metadata = args.metadata;
  }

  const outcome = await callRest(() =>
    apiPost("/api/v1/evidence-packs", body),
  );
  return outcomeToResult(outcome, "Failed to create evidence pack.");
}
