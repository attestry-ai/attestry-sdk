import { z } from "zod";
import {
  apiGet,
  callRest,
  outcomeToResult,
  frameworkNameArg,
  FRAMEWORK_PARAM_MAX_LEN,
  type RegulationToolResult,
} from "./regulation-shared.js";

/**
 * MCP tool: regulation.cite (registered `attestry_regulation_cite`).
 * Wraps GET /api/regulations/cite — resolves a specific regulation provision to
 * its canonical citation, the provision content, and a tamper-evident sha256
 * content hash (computed server-side, so it is authoritative and identical for
 * every consumer).
 *
 * DEV-83: `identifier` is the framework's `getRequirements` section selector
 * (per-framework conventions vary — GDPR accepts "Art.5"; EU AI Act uses named
 * sections like "prohibitedPractices"), not a universal article-number scheme.
 */

export const regulationCiteSchema = {
  framework: frameworkNameArg().describe(
    'Framework name or registered alias, e.g. "EU AI Act", "GDPR", "NIST AI RMF", "ISO/IEC 42001:2023".',
  ),
  identifier: z
    .string()
    .min(1)
    .max(FRAMEWORK_PARAM_MAX_LEN)
    .describe(
      'Provision / section selector within the framework. Conventions vary per framework: e.g. GDPR "Art.5" or "articles"; EU AI Act "prohibitedPractices"; NIST AI RMF "govern".',
    ),
};

export const regulationCiteDescription =
  "Resolve a specific regulation provision to its canonical citation, the " +
  "provision content, and a tamper-evident sha256 content hash. Takes a " +
  "framework name (or alias) and a provision/section identifier. An unknown " +
  "framework returns an error; an identifier that matches no provision in the " +
  "framework returns a not-found error.";

export async function regulationCite(args: {
  framework: string;
  identifier: string;
}): Promise<RegulationToolResult> {
  const outcome = await callRest(() =>
    apiGet("/api/regulations/cite", {
      framework: args.framework,
      identifier: args.identifier,
    }),
  );
  return outcomeToResult(outcome, "Failed to resolve regulation citation.");
}
