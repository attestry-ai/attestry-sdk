import { z } from "zod";
import { apiGet } from "../client.js";

export const listChangesSchema = {
  severity: z
    .enum(["critical", "high", "medium", "low"])
    .optional()
    .describe("Filter by severity level"),
  framework: z
    .string()
    .optional()
    .describe("Filter by framework (e.g. 'eu_ai_act', 'colorado_ai_act')"),
  limit: z
    .number()
    .min(1)
    .max(50)
    .optional()
    .default(10)
    .describe("Number of changes to return (default: 10, max: 50)"),
};

export const listChangesDescription =
  "Get recent regulatory changes and updates affecting AI compliance. " +
  "Returns changes with titles, severity, effective dates, and affected frameworks. " +
  "Useful for staying current on EU AI Act, Colorado AI Act, NIST AI RMF, and ISO 42001 developments.";

interface RegulatoryChange {
  id: string;
  title: string;
  summary: string | null;
  framework: string;
  severity: string;
  status: string;
  sourceUrl: string | null;
  publishedAt: string;
  effectiveDate: string | null;
}

export async function listChanges(args: {
  severity?: string;
  framework?: string;
  limit?: number;
}): Promise<string> {
  const result = await apiGet<RegulatoryChange[]>("/api/regulatory-changes", {
    severity: args.severity,
    framework: args.framework,
  });

  if (!result.success) {
    return JSON.stringify({
      error: result.error || "Failed to fetch regulatory changes",
    });
  }

  const changes = (result.data ?? []).slice(0, args.limit ?? 10);

  return JSON.stringify(
    {
      totalReturned: changes.length,
      changes: changes.map((c) => ({
        id: c.id,
        title: c.title,
        summary: c.summary,
        framework: c.framework,
        severity: c.severity,
        status: c.status,
        publishedAt: c.publishedAt,
        effectiveDate: c.effectiveDate,
        sourceUrl: c.sourceUrl,
      })),
    },
    null,
    2
  );
}
