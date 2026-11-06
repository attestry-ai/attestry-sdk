import { z } from "zod";
import {
  apiGet,
  callRest,
  outcomeToResult,
  FRAMEWORK_PARAM_MAX_LEN,
  type RegulationToolResult,
} from "./regulation-shared.js";

/**
 * MCP tool: schedule.deadline (registered `attestry_schedule_deadline`).
 * Wraps GET /api/regulatory-calendar — returns regulatory compliance deadlines
 * (built-in + custom), optionally filtered by jurisdiction, framework, status,
 * and a date window.
 *
 * DEV-89: the spec's input shape was {system_class, jurisdictions, frameworks}
 * (plural arrays). The existing /api/regulatory-calendar endpoint filters by a
 * SINGLE jurisdiction (exact, case-insensitive), a SINGLE framework
 * (case-insensitive substring), status, and a from/to window. This tool wraps
 * the endpoint's actual query params so its output matches the REST response
 * (acceptance line 235); the plural arrays / system_class / horizon_days form
 * is pinned for R2.
 */

export const scheduleDeadlineSchema = {
  jurisdiction: z
    .string()
    .min(1)
    .max(FRAMEWORK_PARAM_MAX_LEN)
    .optional()
    .describe('Optional jurisdiction filter (exact, case-insensitive), e.g. "EU", "US".'),
  framework: z
    .string()
    .min(1)
    .max(FRAMEWORK_PARAM_MAX_LEN)
    .optional()
    .describe('Optional framework filter (case-insensitive substring), e.g. "EU AI Act".'),
  status: z
    .string()
    .min(1)
    .max(FRAMEWORK_PARAM_MAX_LEN)
    .optional()
    .describe(
      'Optional status filter (case-insensitive exact match), e.g. "upcoming" or "passed".',
    ),
  from: z
    .string()
    .min(1)
    .max(FRAMEWORK_PARAM_MAX_LEN)
    .optional()
    .describe("Optional start of the deadline window, ISO 8601 (YYYY-MM-DD)."),
  to: z
    .string()
    .min(1)
    .max(FRAMEWORK_PARAM_MAX_LEN)
    .optional()
    .describe("Optional end of the deadline window, ISO 8601 (YYYY-MM-DD)."),
};

export const scheduleDeadlineDescription =
  "List regulatory compliance deadlines (effective dates, compliance " +
  "deadlines, reporting, enforcement) across frameworks. Optionally filter by " +
  "jurisdiction, framework, status (upcoming / passed), and a from/to date " +
  "window. Results are sorted by deadline ascending.";

export async function scheduleDeadline(args: {
  jurisdiction?: string;
  framework?: string;
  status?: string;
  from?: string;
  to?: string;
}): Promise<RegulationToolResult> {
  const outcome = await callRest(() =>
    apiGet("/api/regulatory-calendar", {
      jurisdiction: args.jurisdiction,
      framework: args.framework,
      status: args.status,
      from: args.from,
      to: args.to,
    }),
  );
  return outcomeToResult(outcome, "Failed to retrieve regulatory deadlines.");
}
