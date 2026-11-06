import { z } from "zod";
import { apiPost } from "../client.js";

export const classifySystemSchema = {
  systemId: z.string().guid().describe("The UUID of the AI system to classify"),
};

export const classifySystemDescription =
  "Classify an AI system's risk level (EU AI Act tiers + Colorado consequential-decision domains, with NIST applicability flags; ISO 42001 via assessment). " +
  "Triggers the classification engine and returns risk levels, applicable frameworks, and classification details.";

interface ClassificationResult {
  overallRiskLevel: string;
  frameworkClassifications: Record<
    string,
    { riskLevel: string; rationale: string }
  >;
  applicableFrameworks: string[];
  coloradoAffirmativeDefense?: {
    eligible: boolean;
    score: number;
    factors: Record<string, unknown>;
  };
}

export async function classifySystem(args: {
  systemId: string;
}): Promise<string> {
  const result = await apiPost<ClassificationResult>(
    `/api/systems/${args.systemId}/classify`,
    {}
  );

  if (!result.success) {
    return JSON.stringify({
      error: result.error || "Classification failed",
    });
  }

  const data = result.data!;
  return JSON.stringify(
    {
      overallRiskLevel: data.overallRiskLevel,
      applicableFrameworks: data.applicableFrameworks,
      frameworkClassifications: data.frameworkClassifications,
      coloradoAffirmativeDefense: data.coloradoAffirmativeDefense ?? null,
    },
    null,
    2
  );
}
