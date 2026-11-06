import { apiGet } from "../client.js";

/**
 * MCP tool: vision.list_supported_schemas (registered
 * `attestry_vision_list_supported_schemas`). Wraps GET /api/v1/vision/schemas.
 */
export const visionListSupportedSchemasDescription =
  "List the vision extraction schemas available — the document types the " +
  "vision extract tools can target — with their versions, model-tier " +
  "preferences, and confidence thresholds.";

interface SchemaSummary {
  documentType: string;
  description: string;
  version: string;
  modelTierPreference: string;
  confidenceThreshold: number;
  fieldCount: number;
  requiredFieldCount: number;
  fingerprint: string;
}

export async function visionListSupportedSchemas(): Promise<string> {
  const result = await apiGet<{ schemas: SchemaSummary[] }>(
    "/api/v1/vision/schemas",
  );
  if (!result.success) {
    return JSON.stringify({
      error: result.error || "Failed to list vision schemas",
    });
  }
  return JSON.stringify(result.data ?? null, null, 2);
}
