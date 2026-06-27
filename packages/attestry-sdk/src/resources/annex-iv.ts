// ─── AnnexIvResource ────────────────────────────────────────────────────────
//
// The published-SDK courier for the Annex IV technical-file bind path
// (work-item C). Three methods mirror the three kernel routes VERBATIM
// (the shapes are kernel-pinned; this file is a faithful courier — it never
// invents fields the route's strict schema would 422):
//
//   - `generate`     POST /api/v1/technical-files/{id}/annex-iv
//                    → the 8-field 201 body. Sends an EMPTY body (the route
//                      is `z.object({}).strict()` — ANY field 422s).
//   - `downloadPdf`  GET  /api/v1/technical-files/{id}/annex-iv/pdf
//                    → raw `application/pdf` bytes (NOT a JSON envelope);
//                      returns the un-consumed `Response` (faithful courier,
//                      mirroring `evidencePack.export`).
//   - `getBind`      GET  /api/v1/technical-files/{id}/annex-iv/bind
//                    → the 5-field bind body (4 nullable). DISTINCT from
//                      `generate`'s shape — do not conflate (the wire column
//                      `bind_artifact` is renamed to `sidecarJws`).
//
// The OFFLINE verifier `verifyAnnexIvBindOffline` is a TOP-LEVEL pure export
// (it has no apiKey/transport/network), NOT a method on this resource — see
// `../annex-iv-verify/index.ts`. The intended flow:
//   const g = await client.annexIv.generate({ technicalFileId });
//   const pdf = new Uint8Array(
//     await (await client.annexIv.downloadPdf({ technicalFileId })).response.arrayBuffer(),
//   );
//   const r = verifyAnnexIvBindOffline({ sidecarJws: g.sidecarJws, pdfBytes: pdf, jwks });

import { readInputField } from "./safe-input-read.js";
import type { AttestryClient } from "../client.js";
import type { RequestOptions } from "../types.js";

// ─── Wire shapes (kernel-mirrored — the route is the source of truth) ─────────

/**
 * The 201 body of `POST /api/v1/technical-files/{id}/annex-iv`
 * (mirror of `src/app/api/v1/technical-files/[id]/annex-iv/route.ts:246-258`).
 * Eight fields; `sidecarJws` is the wire name of the persisted `bind_artifact`
 * column. `pdfUrl`/`bindUrl` are the self-relative locators of the two GETs.
 */
export interface AnnexIvGenerateResult {
  technicalFileId: string;
  pdfByteSha256: string;
  signingKeyId: string;
  statusListRef: string;
  statusListIndex: number;
  sidecarJws: string;
  pdfUrl: string;
  bindUrl: string;
}

/**
 * The 200 body of `GET /api/v1/technical-files/{id}/annex-iv/bind`
 * (mirror of `…/annex-iv/bind/route.ts:71-79`). Five fields; four are nullable
 * (the bind columns are nullable until the first successful bind). DISTINCT
 * from {@link AnnexIvGenerateResult} — no URLs, four nullable.
 */
export interface AnnexIvBindResult {
  sidecarJws: string;
  pdfByteSha256: string | null;
  signingKeyId: string | null;
  statusListRef: string | null;
  statusListIndex: number | null;
}

/**
 * The result of {@link AnnexIvResource.downloadPdf}. A faithful-courier
 * wrapper around the un-consumed `Response` (mirroring `EvidencePackExportResult`):
 * the SDK does NOT read the body — feed it to the offline verifier via
 * `new Uint8Array(await result.response.arrayBuffer())`.
 */
export interface AnnexIvDownloadPdfResult {
  /** Always `"application/pdf"` — the route's content-type, guarded by the transport. */
  contentType: string;
  /** The `Content-Disposition` header (e.g. `attachment; filename="…"`), or `null`. */
  contentDisposition: string | null;
  /** The un-consumed `Response`. Read the bytes with `new Uint8Array(await response.arrayBuffer())`. */
  response: Response;
}

export interface GenerateAnnexIvInput {
  technicalFileId: string;
}
export interface GetAnnexIvBindInput {
  technicalFileId: string;
}
export interface DownloadAnnexIvPdfInput {
  technicalFileId: string;
}

// ─── Internals ────────────────────────────────────────────────────────────--

const objectHasOwn = Object.hasOwn;

/** RFC 4122 hyphenated UUID — the `evidence-pack.ts` `safe-input-read` idiom. */
const UUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** The shared `application/pdf` content-type literal (drift-pinned). */
const PDF_CONTENT_TYPE = "application/pdf";

/**
 * Validate the consumer-supplied `{ technicalFileId }` input synchronously,
 * returning the validated UUID. Throws a documented `TypeError` (the
 * `safe-input-read` idiom) on a non-object input, an absent/non-string
 * `technicalFileId`, or a non-UUID — NO request is issued on bad input.
 */
function validateTechnicalFileId(input: unknown, context: string): string {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError(
      `${context}: \`input\` must be a non-null object with \`technicalFileId\``,
    );
  }
  const has = objectHasOwn(input, "technicalFileId");
  const raw: unknown = has
    ? readInputField(input, "technicalFileId", context)
    : undefined;
  if (!has || raw === undefined) {
    throw new TypeError(`${context}: \`technicalFileId\` is required`);
  }
  if (typeof raw !== "string" || raw.length === 0) {
    throw new TypeError(
      `${context}: \`technicalFileId\` must be a non-empty string`,
    );
  }
  if (!UUID_REGEX.test(raw)) {
    throw new TypeError(
      `${context}: \`technicalFileId\` must be an RFC 4122 hyphenated UUID`,
    );
  }
  return raw;
}

export class AnnexIvResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Generate the Annex IV bind for a signed technical file — FIRST-BIND-ONLY:
   * an already-bound file is rejected with a 422 `annex_iv.already_bound`
   * (the route never returns the existing bind; fetch it via
   * {@link AnnexIvResource.getBind}). Wraps
   * `POST /api/v1/technical-files/{id}/annex-iv`.
   *
   * **Empty body**: the route body schema is `z.object({}).strict()` — this
   * method sends `{}` and adds NO fields (any stray field would 422). The
   * transport adds `x-api-key` + `Content-Type: application/json`.
   *
   * **SLOW route** (`maxDuration: 300` — up to 9 serial composer narratives).
   * The SDK does NOT add a per-method timeout (resource methods do not
   * override per-call timeouts in `@attestry/sdk`). The default
   * `timeoutMs: 30_000` WILL abort this route. Latency-tolerant callers MUST
   * construct `new AttestryClient({ timeoutMs: 0 })` (`0` DISABLES the abort
   * timer) or `{ timeoutMs: >= 300_000 }` (NOT `60_000` — still under the
   * 300s route ceiling), and/or pass a long-lived `options.signal`. Thread
   * `options` so `signal`/`retry` compose.
   *
   * @throws {TypeError}          synchronously, on a malformed `input` (no request issued).
   * @throws {AttestryAPIError}   on a non-2xx response (401/403/404/422/429-auto-retried/500); `details` carries the parsed `{success:false,error,details?}` body (the 422 `details` carries the `annex_iv.*` `{code}` — incl. `annex_iv.already_bound` on a re-call for an already-bound file — or `{code:"annex_iv.validation_failed",issues}`).
   * @throws {AttestryError}      on a network failure / timeout (request never reached the API).
   */
  generate(
    input: GenerateAnnexIvInput,
    options?: RequestOptions,
  ): Promise<AnnexIvGenerateResult> {
    const id = validateTechnicalFileId(input, "annexIv.generate");
    return this.client._request<AnnexIvGenerateResult>({
      method: "POST",
      path: `/api/v1/technical-files/${encodeURIComponent(id)}/annex-iv`,
      // The route is strict-empty — send `{}`, add NO fields.
      body: {},
      options,
    });
  }

  /**
   * Download the persisted Annex IV PDF bytes. Wraps
   * `GET /api/v1/technical-files/{id}/annex-iv/pdf`.
   *
   * Returns the un-consumed `Response` (faithful courier — the SDK does NOT
   * read the body). Read the bytes with
   * `new Uint8Array(await result.response.arrayBuffer())` to feed the offline
   * verifier.
   *
   * @throws {TypeError}          synchronously, on a malformed `input`.
   * @throws {AttestryAPIError}   on a non-2xx (404 not generated / 502 object missing / 500 integrity mismatch) — drained + thrown BEFORE the content-type guard; a wrong-content-type 2xx → `AttestryAPIError(status, null)`.
   * @throws {AttestryError}      on a network failure.
   */
  downloadPdf(
    input: DownloadAnnexIvPdfInput,
    options?: RequestOptions,
  ): Promise<AnnexIvDownloadPdfResult> {
    const id = validateTechnicalFileId(input, "annexIv.downloadPdf");
    return this.client
      ._streamRequest({
        path: `/api/v1/technical-files/${encodeURIComponent(id)}/annex-iv/pdf`,
        expectedContentType: PDF_CONTENT_TYPE,
        options,
      })
      .then((response) => ({
        contentType: PDF_CONTENT_TYPE,
        contentDisposition: response.headers.get("content-disposition"),
        response,
      }));
  }

  /**
   * Fetch the persisted Annex IV bind columns for a technical file. Wraps
   * `GET /api/v1/technical-files/{id}/annex-iv/bind`.
   *
   * Returns the 5-field {@link AnnexIvBindResult} (four nullable). DISTINCT
   * from {@link generate}'s 8-field shape.
   *
   * @throws {TypeError}          synchronously, on a malformed `input`.
   * @throws {AttestryAPIError}   on a non-2xx response; `details` carries the parsed body.
   * @throws {AttestryError}      on a network failure / timeout.
   */
  getBind(
    input: GetAnnexIvBindInput,
    options?: RequestOptions,
  ): Promise<AnnexIvBindResult> {
    const id = validateTechnicalFileId(input, "annexIv.getBind");
    return this.client._request<AnnexIvBindResult>({
      method: "GET",
      path: `/api/v1/technical-files/${encodeURIComponent(id)}/annex-iv/bind`,
      options,
    });
  }
}
