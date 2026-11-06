import { z } from "zod";
import {
  uuidLc,
  apiPost,
  callRest,
  outcomeToResult,
  type EvidencePackToolResult,
} from "./evidence-pack-shared.js";

/**
 * MCP tool: evidence_pack.append_bundle
 * (registered `attestry_evidence_pack_append_bundle`).
 * Wraps POST /api/v1/evidence-packs/{id}/bundles — appends a reperformance
 * bundle to an existing draft evidence pack. The pack's content hash is
 * recomputed server-side. `orgId` / `userId` are derived from the API key.
 */

/**
 * Trace-entry item shape. Descriptive mirror of the kernel's
 * `traceEntrySchema` (DEV-43) — the kernel route remains the authoritative
 * validator for length bounds, the datetime format, and `.strict()`.
 */
const traceEntrySchema = z
  .object({
    action: z.string().describe("Action name for this trace step."),
    timestamp: z.string().describe("ISO-8601 timestamp of the step."),
    refs: z
      .array(z.string())
      .optional()
      .describe("Optional list of reference identifiers for the step."),
  })
  .describe("A single reperformance trace entry.");

/**
 * Model-behavior-log shape. Descriptive mirror of the kernel's
 * `modelBehaviorLogSchema` (DEV-43).
 */
const modelBehaviorLogSchema = z
  .object({
    model: z.string().describe("Model identifier."),
    version: z.string().describe("Model version string."),
    sampling_params: z
      .record(z.string(), z.unknown())
      .optional()
      .describe("Optional sampling-parameter object."),
    response_hash: z
      .string()
      .optional()
      .describe("Optional 'sha256:<hex>' hash of the model response."),
  })
  .describe("Optional model-behavior log for the bundle.");

export const evidencePackAppendBundleSchema = {
  packId: uuidLc().describe(
    "UUID of the draft evidence pack to append the bundle to.",
  ),
  traceContent: z
    .array(traceEntrySchema)
    .describe("Ordered list of reperformance trace entries for the bundle."),
  // `.min(1)` mirrors the kernel's required-non-empty invariant for these
  // hashes (F-HR-1) — a top-level required scalar, the same class as the
  // drift-pinned enum/UUID mirrors. The kernel's `.max(500)` is left
  // REST-authoritative (DEV-43 — an arbitrary numeric bound, not mirrored).
  inputsHash: z
    .string()
    .min(1)
    .describe("Hash of the bundle's inputs (caller-computed); non-empty."),
  outputsHash: z
    .string()
    .min(1)
    .describe("Hash of the bundle's outputs (caller-computed); non-empty."),
  modelBehaviorLog: modelBehaviorLogSchema.optional(),
  corroborationResults: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Optional corroboration-results object."),
  storageUri: z
    .string()
    .url()
    .optional()
    .describe("Optional HTTPS URI of binary bundle content in storage."),
  metadata: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Optional free-form metadata object (string-keyed)."),
};

export const evidencePackAppendBundleDescription =
  "Append a reperformance bundle to an existing draft evidence pack. The " +
  "pack's content hash is recomputed server-side. Returns " +
  "{bundle, pack, hashCollision}.";

export async function evidencePackAppendBundle(args: {
  packId: string;
  traceContent: unknown[];
  inputsHash: string;
  outputsHash: string;
  modelBehaviorLog?: Record<string, unknown>;
  corroborationResults?: Record<string, unknown>;
  storageUri?: string;
  metadata?: Record<string, unknown>;
}): Promise<EvidencePackToolResult> {
  // Body from explicitly-named fields only (DEV-43): `packId` rides the URL
  // path; `orgId` / `userId` are auth-derived and never sent.
  const body: Record<string, unknown> = {
    traceContent: args.traceContent,
    inputsHash: args.inputsHash,
    outputsHash: args.outputsHash,
  };
  if (args.modelBehaviorLog !== undefined) {
    body.modelBehaviorLog = args.modelBehaviorLog;
  }
  if (args.corroborationResults !== undefined) {
    body.corroborationResults = args.corroborationResults;
  }
  if (args.storageUri !== undefined) {
    body.storageUri = args.storageUri;
  }
  if (args.metadata !== undefined) {
    body.metadata = args.metadata;
  }

  // `packId` is UUID-validated + lowercased by the schema; `encodeURIComponent`
  // is belt-and-suspenders against URL-path injection.
  const outcome = await callRest(() =>
    apiPost(
      `/api/v1/evidence-packs/${encodeURIComponent(args.packId)}/bundles`,
      body,
    ),
  );
  return outcomeToResult(outcome, "Failed to append bundle to evidence pack.");
}
