import { z } from "zod";
import { apiPost, getConfig } from "../client.js";

export const generateDocumentSchema = {
  systemId: z
    .string()
    .guid()
    .describe("The UUID of the AI system to generate the document for"),
  docType: z
    .enum([
      "eu_technical_documentation",
      "colorado_impact_assessment",
      "risk_management_plan",
      "model_card",
      "post_market_monitoring_plan",
      "consumer_disclosure",
      "nist_ai_rmf_profile",
      "custom_framework_report",
    ])
    .describe(
      "The type of compliance document to generate. Options: " +
        "eu_technical_documentation (EU AI Act Art. 11), " +
        "colorado_impact_assessment (optional governance artifact; SB 26-189), " +
        "risk_management_plan (NIST AI RMF), " +
        "model_card (transparency), " +
        "post_market_monitoring_plan (EU AI Act Art. 72), " +
        "consumer_disclosure (Colorado consumer notice), " +
        "nist_ai_rmf_profile (NIST framework profile), " +
        "custom_framework_report (custom framework)"
    ),
  assessmentId: z
    .string()
    .guid()
    .optional()
    .describe("Optional assessment ID to include assessment data in the document"),
  useAI: z
    .boolean()
    .optional()
    .default(false)
    .describe("Use AI to generate narrative sections (requires AI credits)"),
};

export const generateDocumentDescription =
  "Generate a compliance document for an AI system. " +
  "Supports EU Technical Documentation, Colorado Impact Assessment, Risk Management Plan, " +
  "Model Card, Post-Market Monitoring Plan, Consumer Disclosure, and NIST AI RMF Profile. " +
  "Returns the generated document metadata.";

interface GeneratedDocument {
  id: string;
  systemId: string;
  docType: string;
  framework: string | null;
  generatedAt: string;
  // Returned by POST /api/documents — the signed-link bundle the assistant
  // needs to point a user at the rendered PDF/DOCX without requiring a
  // dashboard session.
  downloadToken?: string;
  downloadUrl?: string;
  downloadExpiresInHours?: number;
}

export async function generateDocument(args: {
  systemId: string;
  docType: string;
  assessmentId?: string;
  useAI?: boolean;
}): Promise<string> {
  const result = await apiPost<GeneratedDocument>("/api/documents", {
    systemId: args.systemId,
    docType: args.docType,
    ...(args.assessmentId && { assessmentId: args.assessmentId }),
    useAI: args.useAI ?? false,
  });

  if (!result.success) {
    return JSON.stringify({
      error: result.error || "Document generation failed",
      fieldErrors: result.fieldErrors,
    });
  }

  const doc = result.data!;

  // The backend returns a relative downloadUrl. Build the absolute form using
  // the same API base the tool authenticated against, so the assistant can
  // hand the full link to a user without needing to know the host.
  const apiBase = getConfig().apiUrl;
  const absoluteDownloadUrl = doc.downloadUrl
    ? `${apiBase}${doc.downloadUrl}`
    : null;

  return JSON.stringify(
    {
      documentId: doc.id,
      systemId: doc.systemId,
      docType: doc.docType,
      framework: doc.framework,
      generatedAt: doc.generatedAt,
      downloadToken: doc.downloadToken ?? null,
      downloadUrl: absoluteDownloadUrl,
      downloadExpiresInHours: doc.downloadExpiresInHours ?? null,
      message: absoluteDownloadUrl
        ? `Document generated. The signed download link expires in ${doc.downloadExpiresInHours ?? 72} hours: ${absoluteDownloadUrl}`
        : `Document generated successfully (id ${doc.id}).`,
    },
    null,
    2
  );
}
