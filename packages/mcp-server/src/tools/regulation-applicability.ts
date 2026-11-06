import { z } from "zod";
import {
  apiGet,
  callRest,
  outcomeToResult,
  FRAMEWORK_PARAM_MAX_LEN,
  type RegulationToolResult,
} from "./regulation-shared.js";

/**
 * MCP tool: regulation.applicability (registered
 * `attestry_regulation_applicability`). Wraps GET
 * /api/regulations/applicability — returns the regulation frameworks applicable
 * to a geography, optionally narrowed by system type.
 *
 * DEV-86: the spec's input shape was {system_description, sector, jurisdiction,
 * modality}; the kernel's `getApplicableFrameworks` consumes only
 * (geography, systemType?), so this tool exposes those two directly
 * (jurisdiction -> geography; modality / sector -> systemType). The richer
 * fields are not consumed today; pinned for R2 / a future lib extension.
 */

export const regulationApplicabilitySchema = {
  geography: z
    .string()
    .min(1)
    .max(FRAMEWORK_PARAM_MAX_LEN)
    .describe(
      'Country, region, or jurisdiction, e.g. "Germany", "EU", "Colorado", "United States".',
    ),
  systemType: z
    .string()
    .min(1)
    .max(FRAMEWORK_PARAM_MAX_LEN)
    .optional()
    .describe('Optional system-type filter, e.g. "high-risk", "gpai".'),
};

export const regulationApplicabilityDescription =
  "Determine which regulation frameworks apply to an AI system given its " +
  "geography (country, region, or jurisdiction) and, optionally, its system " +
  'type (e.g. "high-risk", "gpai", or a modality). Returns the applicable ' +
  "frameworks with version and jurisdiction metadata. An unrecognized " +
  "geography still returns the universally-applicable frameworks (e.g. " +
  "international standards such as ISO/IEC 42001).";

export async function regulationApplicability(args: {
  geography: string;
  systemType?: string;
}): Promise<RegulationToolResult> {
  const outcome = await callRest(() =>
    apiGet("/api/regulations/applicability", {
      geography: args.geography,
      systemType: args.systemType,
    }),
  );
  return outcomeToResult(outcome, "Failed to determine applicable frameworks.");
}
