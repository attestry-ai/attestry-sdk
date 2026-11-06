import { apiGet } from "../client.js";

export const listSystemsDescription =
  "List all registered AI systems for the authenticated organization. " +
  "Returns system names, IDs, risk classifications, and statuses.";

interface AiSystem {
  id: string;
  name: string;
  status: string;
  riskClassifications: Record<string, unknown> | null;
  intendedUse: string | null;
  decisionType: string | null;
  deploymentGeography: string | string[] | null;
  createdAt: string;
  updatedAt: string;
}

export async function listSystems(): Promise<string> {
  const result = await apiGet<AiSystem[]>("/api/systems");

  if (!result.success) {
    return JSON.stringify({
      error: result.error || "Failed to list systems",
    });
  }

  const systems = result.data ?? [];

  const summary = systems.map((s) => {
    const classifications = s.riskClassifications as Record<string, unknown> | null;
    return {
      id: s.id,
      name: s.name,
      status: s.status,
      overallRiskLevel: classifications?.overallRiskLevel ?? "unclassified",
      applicableFrameworks: classifications?.applicableFrameworks ?? [],
      intendedUse: s.intendedUse,
      deploymentGeography: s.deploymentGeography,
      updatedAt: s.updatedAt,
    };
  });

  return JSON.stringify(
    {
      totalSystems: summary.length,
      systems: summary,
    },
    null,
    2
  );
}
