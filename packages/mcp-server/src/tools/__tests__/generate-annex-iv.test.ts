import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiPost } from "../../client.js";
import { generateAnnexIv } from "../generate-annex-iv.js";

// W3-B §10.5 — `../../client.js` is mocked so `apiPost` never performs real
// HTTP; the tool's forward-the-route-fields logic runs for real.
vi.mock("../../client.js", () => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}));

const mockApiPost = vi.mocked(apiPost);

beforeEach(() => {
  vi.clearAllMocks();
});

const TF_ID = "11111111-1111-4111-8111-111111111111";
const ROUTE_DATA = {
  technicalFileId: TF_ID,
  pdfByteSha256: `sha256:${"a".repeat(64)}`,
  signingKeyId: "kid-2026",
  statusListRef: "https://attestry.ai/.well-known/status-list",
  statusListIndex: 5,
  sidecarJws: "jws-compact-detached",
  pdfUrl: `https://attestry.ai/api/v1/technical-files/${TF_ID}/annex-iv/pdf`,
  bindUrl: `https://attestry.ai/api/v1/technical-files/${TF_ID}/annex-iv/bind`,
};

describe("attestry_generate_annex_iv — MCP1 happy", () => {
  it("posts to the annex-iv route with an empty body and forwards the URLs VERBATIM", async () => {
    mockApiPost.mockResolvedValue({ success: true, data: ROUTE_DATA });

    const result = await generateAnnexIv({ technicalFileId: TF_ID });

    expect(mockApiPost).toHaveBeenCalledWith(
      `/api/v1/technical-files/${TF_ID}/annex-iv`,
      {},
    );

    const parsed = JSON.parse(result);
    // 9-key tool JSON = the 8 route-body fields forwarded + a tool-side message.
    expect(Object.keys(parsed).sort()).toEqual(
      [
        "bindUrl",
        "message",
        "pdfByteSha256",
        "pdfUrl",
        "sidecarJws",
        "signingKeyId",
        "statusListIndex",
        "statusListRef",
        "technicalFileId",
      ].sort(),
    );
    // The tool did NOT mutate / double-prefix the already-absolute URLs.
    expect(parsed.pdfUrl).toBe(ROUTE_DATA.pdfUrl);
    expect(parsed.bindUrl).toBe(ROUTE_DATA.bindUrl);
    expect(parsed.technicalFileId).toBe(TF_ID);
    expect(parsed.statusListIndex).toBe(5);
  });
});

describe("attestry_generate_annex_iv — MCP2 failure", () => {
  // The REAL kernel error envelope is {success:false, error, details:{code,…}}
  // (route-errors.ts:20-27; api.ts errorResponse) — it never carries top-level
  // fieldErrors. The pre-③ test mocked a phantom fieldErrors shape, so the tool
  // silently dropped every typed annex_iv.* code with the suite green (③ H fix
  // SEAM3-MCP-ERRCODE-DROP, 2026-06-10).
  it("surfaces details.code + details from the kernel envelope on !success", async () => {
    mockApiPost.mockResolvedValue({
      success: false,
      error: "Technical file must be signed before generating its Annex IV bind.",
      details: { code: "annex_iv.file_not_signed" },
    });

    const result = await generateAnnexIv({ technicalFileId: TF_ID });
    const parsed = JSON.parse(result);
    expect(parsed.error).toBe(
      "Technical file must be signed before generating its Annex IV bind.",
    );
    expect(parsed.code).toBe("annex_iv.file_not_signed");
    expect(parsed.details).toEqual({ code: "annex_iv.file_not_signed" });
  });

  it("surfaces the 422 validation issues leg", async () => {
    mockApiPost.mockResolvedValue({
      success: false,
      error: "Annex IV composition failed validation.",
      details: {
        code: "annex_iv.validation_failed",
        issues: [{ path: ["sections", 0], message: "missing field" }],
      },
    });

    const parsed = JSON.parse(await generateAnnexIv({ technicalFileId: TF_ID }));
    expect(parsed.code).toBe("annex_iv.validation_failed");
    expect(parsed.details.issues).toEqual([
      { path: ["sections", 0], message: "missing field" },
    ]);
  });

  it("omits code (no crash) when the envelope carries no details", async () => {
    mockApiPost.mockResolvedValue({ success: false, error: "boom" });
    const parsed = JSON.parse(await generateAnnexIv({ technicalFileId: TF_ID }));
    expect(parsed.error).toBe("boom");
    expect(parsed.code).toBeUndefined();
  });
});
