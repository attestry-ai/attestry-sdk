import { z } from "zod";
import { apiPost } from "../client.js";

export const checkComplianceSchema = {
  systemId: z.string().guid().describe("The UUID of the AI system to check"),
  frameworks: z
    .array(z.string())
    .optional()
    .describe(
      "Optional list of frameworks to check against (e.g. ['eu_ai_act', 'colorado_ai_act', 'nist_ai_rmf', 'iso_42001'])"
    ),
};

export const checkComplianceDescription =
  "Check an AI system's compliance status against regulatory frameworks. " +
  "Returns pass/fail status, overall score, compliance issues, and active attestation count.";

interface ComplianceCheckResult {
  compliant: boolean;
  score: number;
  issues: string[];
  activeAttestations: number;
  lastAssessedAt: string | null;
  checkedAt: string;
}

export async function checkCompliance(args: {
  systemId: string;
  frameworks?: string[];
}): Promise<string> {
  const result = await apiPost<ComplianceCheckResult>("/api/v1/check", {
    systemId: args.systemId,
    ...(args.frameworks && { frameworks: args.frameworks }),
  });

  if (!result.success) {
    return JSON.stringify({ error: result.error || "Compliance check failed" });
  }

  const data = result.data!;
  return JSON.stringify(
    {
      status: data.compliant ? "PASS" : "FAIL",
      score: data.score,
      issues: data.issues,
      activeAttestations: data.activeAttestations,
      lastAssessedAt: data.lastAssessedAt,
      checkedAt: data.checkedAt,
      recommendations:
        data.issues.length > 0
          ? [
              "Address the listed compliance gaps",
              "Run a new assessment after remediation",
              data.score < 70
                ? "Score is below 70 — significant remediation needed"
                : "Score is adequate but gaps should be addressed",
            ]
          : ["System is currently compliant. Continue monitoring for regulatory changes."],
    },
    null,
    2
  );
}
