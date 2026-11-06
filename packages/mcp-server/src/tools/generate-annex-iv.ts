import { z } from "zod";
import { apiPost } from "../client.js";

export const generateAnnexIvSchema = {
  technicalFileId: z
    .string()
    .guid()
    .describe(
      "The UUID of the signed technical file to generate, cryptobind, and persist the Annex IV PDF for",
    ),
};

export const generateAnnexIvDescription =
  "Generate the EU AI Act Annex IV technical documentation PDF for a signed technical file. " +
  "Composes all nine Annex IV sections, cryptobinds (tamper-evidently seals) the rendered PDF, " +
  "persists it to content-addressed storage, meters the document, and returns the artifact " +
  "references: the PDF byte hash, signing key id, status-list index, the detached bind sidecar (JWS), " +
  "and absolute download URLs for the PDF and the bind sidecar.";

interface AnnexIvGenerateResult {
  technicalFileId: string;
  pdfByteSha256: string;
  signingKeyId: string;
  statusListRef: string;
  statusListIndex: number;
  sidecarJws: string;
  pdfUrl: string;
  bindUrl: string;
}

export async function generateAnnexIv(args: {
  technicalFileId: string;
}): Promise<string> {
  const result = await apiPost<AnnexIvGenerateResult>(
    `/api/v1/technical-files/${args.technicalFileId}/annex-iv`,
    {},
  );

  if (!result.success) {
    // Surface the kernel envelope's machine-readable leg (details.code is what
    // callers branch on — e.g. annex_iv.already_bound / annex_iv.file_not_signed;
    // a 422 annex_iv.validation_failed adds details.issues). The envelope never
    // carries top-level fieldErrors — the evidence-pack tools' idiom
    // (evidence-pack-shared.ts) is the surface's gold standard (③ H fix).
    return JSON.stringify({
      error: result.error || "Annex IV generation failed",
      code: typeof result.details?.code === "string" ? result.details.code : undefined,
      details: result.details,
    });
  }

  const d = result.data!;

  // pdfUrl / bindUrl are returned ALREADY ABSOLUTE by the route (off the app's
  // own base URL). Forward them VERBATIM — do NOT prefix `getConfig().apiUrl`
  // (the generate-document idiom): that is the SaaS API host, a separate surface
  // from the route host, so prefixing would point at the wrong URL.
  return JSON.stringify(
    {
      technicalFileId: d.technicalFileId,
      pdfByteSha256: d.pdfByteSha256,
      signingKeyId: d.signingKeyId,
      statusListRef: d.statusListRef,
      statusListIndex: d.statusListIndex,
      sidecarJws: d.sidecarJws,
      pdfUrl: d.pdfUrl,
      bindUrl: d.bindUrl,
      message:
        `Annex IV technical file generated and cryptobound (status-list index ${d.statusListIndex}). ` +
        `Download the PDF at ${d.pdfUrl} and the bind sidecar at ${d.bindUrl}.`,
    },
    null,
    2,
  );
}
