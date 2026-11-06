import {
  apiGet,
  callRest,
  outcomeToResult,
  frameworkNameArg,
  type RegulationToolResult,
} from "./regulation-shared.js";

/**
 * MCP tool: regulation.crosswalk (registered `attestry_regulation_crosswalk`).
 * Wraps GET /api/regulations/crosswalk — returns the crosswalk mappings from a
 * source framework, optionally narrowed to a single target framework.
 *
 * DEV-87: the spec's input shape was {source, targets} (a plural target array).
 * The existing GET endpoint takes a single optional `target` and returns the
 * mappings between the pair (or all mappings from the source). This tool wraps
 * the endpoint's actual single-target shape so its output matches the REST
 * response (acceptance line 235); the plural-target form is pinned for R2.
 */

export const regulationCrosswalkSchema = {
  source: frameworkNameArg().describe(
    'Source framework name or alias, e.g. "EU AI Act", "GDPR".',
  ),
  target: frameworkNameArg()
    .optional()
    .describe(
      "Optional target framework name or alias. Omit to return all mappings from the source framework.",
    ),
};

export const regulationCrosswalkDescription =
  "Look up crosswalk mappings between regulation frameworks: given a source " +
  "framework (and optionally a single target framework), returns the mapped " +
  "provisions with their relationship strength and authoritative references. " +
  "An unknown source or target framework returns an error.";

export async function regulationCrosswalk(args: {
  source: string;
  target?: string;
}): Promise<RegulationToolResult> {
  const outcome = await callRest(() =>
    apiGet("/api/regulations/crosswalk", {
      source: args.source,
      target: args.target,
    }),
  );
  return outcomeToResult(outcome, "Failed to retrieve crosswalk mappings.");
}
