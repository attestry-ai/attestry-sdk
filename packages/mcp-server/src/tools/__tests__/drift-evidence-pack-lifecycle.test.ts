import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as path from "node:path";
import { evidencePackSignSchema } from "../evidence-pack-sign.js";
import { evidencePackSupersedeSchema } from "../evidence-pack-supersede.js";
import { evidencePackRevokeSchema } from "../evidence-pack-revoke.js";
import { evidencePackExportSchema } from "../evidence-pack-export.js";
import { itKernel, readKernelSource } from "./_kernel-sources.js";

/**
 * KE2 P1.7 — Spec-diff round: drift pins for the four lifecycle + export
 * MCP tools. Sibling to P1.5's `drift-evidence-pack.test.ts` (which is left
 * byte-untouched); the `PACK_TYPES` closed-enum byte-equality is already
 * pinned there and is reused via `evidence-pack-shared.ts`.
 *
 * Pins: REST URL paths each tool wraps; tool input-schema shapes vs the
 * prompt §"Tool input shapes"; the `newPack` mirror vs the kernel
 * `supersedeNewPackPayloadSchema`; the sibling-registrar + `index.ts`
 * wiring; and the two load-bearing DEV decisions — the DEV-53 export-artifact
 * discriminator and the DEV-54 supersede header contract.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const toolDir = path.resolve(here, "..");

function readTool(file: string): string {
  return readFileSync(path.join(toolDir, file), "utf8");
}

const indexSource = readFileSync(
  path.resolve(here, "../../index.ts"),
  "utf8",
);
// Kernel-reading pins use `itKernel` (see `_kernel-sources.ts`): they skip
// in a standalone copy (the publish mirror) and stay strict in-monorepo.
const kernelTypesSource = readKernelSource("src/lib/evidence-pack/types.ts");
const kernelExportSource = readKernelSource("src/lib/evidence-pack/export.ts");
const kernelSupersedeRouteSource = readKernelSource(
  "src/app/api/v1/evidence-packs/[id]/supersede/route.ts",
);
const kernelExportRouteSource = readKernelSource(
  "src/app/api/v1/evidence-packs/[id]/export/route.ts",
);

// ─── REST URL paths each tool wraps ─────────────────────────────────────────

describe("drift — P1.7 REST URL paths each tool wraps", () => {
  it("sign POSTs /api/v1/evidence-packs/{id}/sign", () => {
    const src = readTool("evidence-pack-sign.ts");
    expect(src).toContain("apiPost(");
    expect(src).toContain("`/api/v1/evidence-packs/");
    expect(src).toContain("/sign`");
  });

  it("supersede POSTs /api/v1/evidence-packs/{id}/supersede", () => {
    const src = readTool("evidence-pack-supersede.ts");
    expect(src).toContain("postWithIdempotencyKey(");
    expect(src).toContain("`/api/v1/evidence-packs/");
    expect(src).toContain("/supersede`");
  });

  it("revoke POSTs /api/v1/evidence-packs/{id}/revoke", () => {
    const src = readTool("evidence-pack-revoke.ts");
    expect(src).toContain("apiPost(");
    expect(src).toContain("`/api/v1/evidence-packs/");
    expect(src).toContain("/revoke`");
  });

  it("export GETs /api/v1/evidence-packs/{id}/export and always sends format=json", () => {
    const src = readTool("evidence-pack-export.ts");
    expect(src).toContain("apiGet(");
    expect(src).toContain("`/api/v1/evidence-packs/");
    expect(src).toContain("/export`");
    expect(src).toContain('{ format: "json" }');
  });
});

// ─── Tool input-schema shapes vs the prompt §"Tool input shapes" ────────────

describe("drift — P1.7 tool input-schema shapes", () => {
  it("sign schema = {packId, attestationCertificateId, confirm}", () => {
    expect(Object.keys(evidencePackSignSchema).sort()).toEqual(
      ["attestationCertificateId", "confirm", "packId"],
    );
  });

  it("supersede schema = {oldPackId, newPack, idempotencyKey}", () => {
    expect(Object.keys(evidencePackSupersedeSchema).sort()).toEqual(
      ["idempotencyKey", "newPack", "oldPackId"],
    );
  });

  it("revoke schema = {packId, reason, confirm}", () => {
    expect(Object.keys(evidencePackRevokeSchema).sort()).toEqual(
      ["confirm", "packId", "reason"],
    );
  });

  it("export schema = {packId} only — no `format` argument (DQ-3)", () => {
    expect(Object.keys(evidencePackExportSchema)).toEqual(["packId"]);
  });

  it("only sign and revoke carry a `confirm` gate (DQ-1)", () => {
    expect("confirm" in evidencePackSignSchema).toBe(true);
    expect("confirm" in evidencePackRevokeSchema).toBe(true);
    expect("confirm" in evidencePackSupersedeSchema).toBe(false);
    expect("confirm" in evidencePackExportSchema).toBe(false);
  });
});

// ─── supersede `newPack` mirror vs kernel supersedeNewPackPayloadSchema ──────

describe("drift — supersede newPack mirror vs kernel supersedeNewPackPayloadSchema", () => {
  const mirrorKeys = Object.keys(
    evidencePackSupersedeSchema.newPack.shape,
  ).sort();

  it("the MCP newPack mirror has the five documented fields", () => {
    expect(mirrorKeys).toEqual([
      "consumerHints",
      "frameworkBindings",
      "metadata",
      "packType",
      "systemId",
    ]);
  });

  itKernel("the kernel supersedeNewPackPayloadSchema declares each mirrored field", () => {
    const m = kernelTypesSource.match(
      /supersedeNewPackPayloadSchema = z\s*\.object\(\{([\s\S]*?)\}\)\s*\.strict\(\)/,
    );
    expect(m).not.toBeNull();
    const block = m![1];
    for (const key of mirrorKeys) {
      expect(block).toContain(`${key}:`);
    }
  });
});

// ─── Sibling-registrar + index.ts wiring ────────────────────────────────────

describe("drift — P1.7 lifecycle-tool registration wiring", () => {
  const TOOL_NAMES = [
    "attestry_evidence_pack_sign",
    "attestry_evidence_pack_supersede",
    "attestry_evidence_pack_revoke",
    "attestry_evidence_pack_export",
  ];
  const registerSource = readTool("evidence-pack-lifecycle-register.ts");

  it("src/index.ts imports and calls registerEvidencePackLifecycleTools", () => {
    expect(indexSource).toContain(
      'from "./tools/evidence-pack-lifecycle-register.js"',
    );
    expect(indexSource).toContain("registerEvidencePackLifecycleTools(server)");
  });

  it("the registrar registers all four lifecycle tools by their wire names", () => {
    for (const name of TOOL_NAMES) {
      expect(registerSource).toContain(`"${name}"`);
    }
  });

  it("the registrar registers them in sign → supersede → revoke → export order", () => {
    const positions = TOOL_NAMES.map((n) => registerSource.indexOf(`"${n}"`));
    expect(positions.every((p) => p >= 0)).toBe(true);
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it("the registrar imports all four lifecycle tool modules", () => {
    for (const mod of [
      "evidence-pack-sign",
      "evidence-pack-supersede",
      "evidence-pack-revoke",
      "evidence-pack-export",
    ]) {
      expect(registerSource).toContain(`from "./${mod}.js"`);
    }
  });
});

// ─── DEV-53 — export-artifact shape validates the success-discriminator ─────

describe("drift — export-artifact shape (DEV-53 discriminator)", () => {
  itKernel("kernel encodeJsonExport envelopes export/pack/bundles with no top-level `success` key", () => {
    const m = kernelExportSource.match(
      /export function encodeJsonExport\([\s\S]*?\n\}/,
    );
    expect(m).not.toBeNull();
    const fn = m![0];
    expect(fn).toContain("export:");
    expect(fn).toContain("pack: data.pack");
    expect(fn).toContain("bundles: data.bundles");
    // The export artifact must carry NO top-level `success` key, or the
    // `success === false` error discriminator in evidence-pack-export.ts
    // would mis-classify a successful export as an error.
    expect(fn).not.toContain("success:");
  });

  itKernel("the kernel export route returns the raw artifact via NextResponse, not the {success,data} envelope", () => {
    // DEV-53's discriminator (`success === false` → error) holds only while
    // the export route returns the artifact RAW. If a future kernel change
    // wrapped it in successResponse(), a successful export would gain a
    // top-level `success:true` and the export tool would pass the whole
    // envelope through as the artifact (hostile-redux F-HR-2). Pin the
    // assumption where it lives — the export route itself.
    expect(kernelExportRouteSource).toContain("new NextResponse(");
    expect(kernelExportRouteSource).not.toContain("successResponse");
  });
});

// ─── DEV-54 — supersede header contract ─────────────────────────────────────

describe("drift — supersede header contract (DEV-54)", () => {
  const supersedeSource = readTool("evidence-pack-supersede.ts");

  it("the supersede tool sends an Idempotency-Key header and reuses getConfig + apiPost headers", () => {
    expect(supersedeSource).toContain('"Idempotency-Key"');
    expect(supersedeSource).toContain("getConfig");
    expect(supersedeSource).toContain('"x-api-key"');
    expect(supersedeSource).toContain('"Content-Type"');
  });

  itKernel("the kernel supersede route reads the idempotency-key request header", () => {
    expect(kernelSupersedeRouteSource).toContain(
      'headers.get("idempotency-key")',
    );
  });
});
