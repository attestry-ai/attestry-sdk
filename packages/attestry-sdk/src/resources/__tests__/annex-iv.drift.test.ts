// ─── SDK ⇄ kernel drift-detection — annexIv resource (work-item C) ──────────
//
// `packages/attestry-sdk/src/resources/annex-iv.ts` mirrors three kernel
// routes' wire shapes + literals. The two copies are textually independent,
// so a kernel-side change can drift unnoticed. This is the trip-wire.
//
// Same convention as `evidence-pack.drift.test.ts`: read both files as TEXT +
// match anchored regexes (NOT `import` — the SDK is Node16 ESM, the kernel
// runs through Vitest/Next.js `@/`-alias; a cross-module import is fragile).
// Guarded by `existsSync` so the published mirror's `npm test` (no kernel
// source) skips rather than fails (test files are not in the npm artifact).

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "fs";
import { resolve } from "path";

// From __dirname (`__tests__/`): SDK source is one level up; kernel routes are
// five levels up (→ resources/ → src/ → attestry-sdk/ → packages/ → repo root).
const SDK_ANNEX_IV_PATH = resolve(__dirname, "../annex-iv.ts");
const KERNEL_PDF_ROUTE_PATH = resolve(
  __dirname,
  "../../../../../src/app/api/v1/technical-files/[id]/annex-iv/pdf/route.ts",
);

const KERNEL_SOURCES_PRESENT = existsSync(KERNEL_PDF_ROUTE_PATH);
const describeDrift = KERNEL_SOURCES_PRESENT ? describe : describe.skip;
const read = (path: string): string =>
  KERNEL_SOURCES_PRESENT ? readFileSync(path, "utf-8") : "";

describeDrift("annexIv ⇄ kernel drift", () => {
  const sdkSrc = read(SDK_ANNEX_IV_PATH);
  const pdfRouteSrc = read(KERNEL_PDF_ROUTE_PATH);

  it("the application/pdf content-type literal matches the kernel pdf route", () => {
    // SDK declares it as the PDF_CONTENT_TYPE const.
    expect(sdkSrc).toMatch(/PDF_CONTENT_TYPE\s*=\s*"application\/pdf"/);
    // The kernel pdf route serves application/pdf.
    expect(pdfRouteSrc).toMatch(/["']application\/pdf["']/);
  });

  it("the SDK uses the three kernel route path templates", () => {
    // POST generate + GET bind + GET pdf — all under .../annex-iv.
    expect(sdkSrc).toMatch(
      /\/api\/v1\/technical-files\/\$\{encodeURIComponent\(id\)\}\/annex-iv`/,
    );
    expect(sdkSrc).toMatch(
      /\/api\/v1\/technical-files\/\$\{encodeURIComponent\(id\)\}\/annex-iv\/pdf`/,
    );
    expect(sdkSrc).toMatch(
      /\/api\/v1\/technical-files\/\$\{encodeURIComponent\(id\)\}\/annex-iv\/bind`/,
    );
  });

  it("the kernel pdf route is a raw-bytes route (NextResponse, not successResponse envelope)", () => {
    // The pdf route returns raw bytes via NextResponse(Uint8Array) — the SDK
    // courier routes it through _streamRequest, NOT the envelope-unwrap path.
    expect(pdfRouteSrc).toMatch(/NextResponse/);
  });
});
