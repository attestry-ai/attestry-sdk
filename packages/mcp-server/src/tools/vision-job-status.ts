import { z } from "zod";
import { apiGet } from "../client.js";

/**
 * MCP tool: vision.get_job_status (registered `attestry_vision_get_job_status`).
 * Wraps GET /api/v1/vision/extract/jobs/{jobId}.
 */
export const visionGetJobStatusSchema = {
  jobId: z
    .string()
    .guid()
    .describe("The UUID of the vision batch extraction job to poll."),
};

export const visionGetJobStatusDescription =
  "Get the status and results of an asynchronous vision batch extraction " +
  "job submitted via the batch endpoint. Reports progress, cost, and any " +
  "per-document errors.";

interface VisionJobStatus {
  jobId: string;
  status: string;
  documentCount: number;
  documentsProcessed: number;
  modelTier: string;
  costUsdCents: number;
  costTokensInput: number;
  costTokensOutput: number;
  errorLog: unknown;
  resultPackId: string | null;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
}

export async function visionGetJobStatus(args: {
  jobId: string;
}): Promise<string> {
  const result = await apiGet<VisionJobStatus>(
    `/api/v1/vision/extract/jobs/${args.jobId}`,
  );
  if (!result.success) {
    return JSON.stringify({
      error: result.error || "Failed to get vision job status",
    });
  }
  return JSON.stringify(result.data ?? null, null, 2);
}
