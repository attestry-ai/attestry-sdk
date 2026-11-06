import { z } from "zod";
import { apiPost } from "../client.js";

/**
 * MCP tool: vision.compliance_extract (registered `attestry_vision_compliance_extract`).
 * Wraps POST /api/v1/vision/extract — synchronous single-document extraction.
 */
export const visionComplianceExtractSchema = {
  documentType: z
    .string()
    .describe(
      "Document type / extraction schema. One of: model-card, " +
        "validation-report, certification-label, schematic-extraction, " +
        "generic-tabular.",
    ),
  mediaType: z
    .string()
    .describe(
      "Image media type: image/jpeg, image/png, image/webp, or image/gif.",
    ),
  base64: z
    .string()
    .optional()
    .describe(
      "Base64-encoded image bytes. Provide exactly one of base64 or imageUri.",
    ),
  imageUri: z
    .string()
    .optional()
    .describe(
      "HTTPS URL of the image. Provide exactly one of base64 or imageUri.",
    ),
  extractionSchema: z
    .string()
    .optional()
    .describe(
      "Optional explicit schema key; overrides documentType for the extraction.",
    ),
  model: z
    .string()
    .optional()
    .describe(
      "Model tier: 'opus' (quality-critical, the default) or 'sonnet' (high-volume).",
    ),
};

export const visionComplianceExtractDescription =
  "Extract structured, schema-validated compliance data from a single " +
  "document image (synchronous). Returns per-field values with confidence " +
  "scores, source-region descriptions, token usage, and cost.";

interface VisionExtractResult {
  callId: string;
  structuredExtraction: unknown;
  confidencePerField: Record<string, number>;
  sourceRegions: Record<string, string>;
  tokensUsed: {
    input: number;
    output: number;
    cacheCreation: number;
    cacheRead: number;
  };
  costUsdCents: number;
  latencyMs: number;
}

export async function visionComplianceExtract(args: {
  documentType: string;
  mediaType: string;
  base64?: string;
  imageUri?: string;
  extractionSchema?: string;
  model?: string;
}): Promise<string> {
  const result = await apiPost<VisionExtractResult>("/api/v1/vision/extract", {
    documentType: args.documentType,
    mediaType: args.mediaType,
    base64: args.base64,
    imageUri: args.imageUri,
    extractionSchema: args.extractionSchema,
    model: args.model,
  });

  if (!result.success) {
    return JSON.stringify({
      error: result.error || "Vision extraction failed",
      fieldErrors: result.fieldErrors,
    });
  }
  return JSON.stringify(result.data ?? null, null, 2);
}
