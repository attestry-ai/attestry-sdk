import { z } from "zod";
import { apiGet } from "../client.js";

export const getAssessmentSchema = {
  systemId: z
    .string()
    .guid()
    .describe("The UUID of the AI system to get assessment details for"),
};

export const getAssessmentDescription =
  "Get the latest compliance assessment summary for an AI system. " +
  "Returns the compliance status, score, framework coverage, active attestations, and recommendations.";

interface Assessment {
  id: string;
  systemId: string;
  frameworks: string[];
  status: string;
  scores: Record<string, unknown> | null;
  gaps: Array<{ title?: string; description?: string; severity?: string }> | null;
  responses: Record<string, unknown> | null;
  completedAt: string | null;
  integrityHash: string | null;
  createdAt: string;
}

export async function getAssessment(args: {
  systemId: string;
}): Promise<string> {
  // Use the compliance-check endpoint which gives assessment data per system
  const result = await apiGet<{
    systems: Array<{
      systemId: string;
      systemName: string;
      compliant: boolean;
      score: number | null;
      frameworkCoverage: {
        applicable: string[];
        assessed: string[];
        coveragePct: number;
      };
      activeAttestations: number;
      lastAssessedAt: string | null;
    }>;
  }>("/api/v1/compliance-check", { systemId: args.systemId });

  if (!result.success) {
    return JSON.stringify({
      error: result.error || "Failed to get assessment",
    });
  }

  const systems = result.data?.systems ?? [];
  if (systems.length === 0) {
    return JSON.stringify({
      error: "No assessment data found for this system",
    });
  }

  const system = systems[0];

  return JSON.stringify(
    {
      systemId: system.systemId,
      systemName: system.systemName,
      compliant: system.compliant,
      score: system.score,
      frameworkCoverage: system.frameworkCoverage,
      activeAttestations: system.activeAttestations,
      lastAssessedAt: system.lastAssessedAt,
      recommendations:
        system.frameworkCoverage.coveragePct < 100
          ? [
              `Only ${system.frameworkCoverage.coveragePct}% of applicable frameworks have been assessed`,
              `Missing assessments for: ${system.frameworkCoverage.applicable
                .filter((f) => !system.frameworkCoverage.assessed.includes(f))
                .join(", ")}`,
            ]
          : ["All applicable frameworks have been assessed"],
    },
    null,
    2
  );
}
