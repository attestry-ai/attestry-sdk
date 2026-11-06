import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as path from "node:path";
import { PACK_TYPES, PACK_STATUSES } from "../evidence-pack-shared.js";
import { evidencePackCreateSchema } from "../evidence-pack-create.js";
import { evidencePackGetSchema } from "../evidence-pack-get.js";
import { evidencePackListSchema } from "../evidence-pack-list.js";
import { evidencePackAppendBundleSchema } from "../evidence-pack-append-bundle.js";
import { describeKernel, readKernelSource } from "./_kernel-sources.js";

/**
 * KE2 P1.5 — drift pins for the evidence-pack MCP tools.
 *
 *  Build round    — closed-enum mirrors (`PACK_TYPES` / `PACK_STATUSES`)
 *                   byte-identical to the kernel's `types.ts`.
 *  Spec-diff round — REST URL paths each tool calls; tool input-schema
 *                   shapes vs the spec signatures; the four `server.tool`
 *                   registrations in `src/index.ts` (DEV-49).
 *
 * Spec P1.5 hostile concern #3 + handoff §"Conventions you MUST keep
 * consistent" + §"MCP test discipline".
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const toolDir = path.resolve(here, "..");
// Kernel-reading pins use `describeKernel` (see `_kernel-sources.ts`): they
// skip in a standalone copy (the publish mirror) and stay strict in-monorepo.
const kernelSource = readKernelSource("src/lib/evidence-pack/types.ts");
const indexSource = readFileSync(path.resolve(here, "../../index.ts"), "utf8");

/** Extract a kernel `export const NAME = [ "..." , ... ] as const;` tuple. */
function extractKernelTuple(source: string, name: string): string[] {
  const m = source.match(
    new RegExp(`export const ${name} = \\[([\\s\\S]*?)\\] as const;`),
  );
  if (!m) {
    throw new Error(`drift: could not locate '${name}' in kernel types.ts`);
  }
  return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
}

function readTool(file: string): string {
  return readFileSync(path.join(toolDir, file), "utf8");
}

// ─── Build round — closed-enum mirrors vs kernel ────────────────────────────

describeKernel("drift — PACK_TYPES mirror vs kernel", () => {
  const kernelPackTypes = extractKernelTuple(kernelSource, "PACK_TYPES");

  it("kernel PACK_TYPES has exactly five values", () => {
    expect(kernelPackTypes).toHaveLength(5);
  });

  it("MCP mirror is byte-equal (value + order) to kernel PACK_TYPES", () => {
    expect([...PACK_TYPES]).toEqual(kernelPackTypes);
  });
});

describeKernel("drift — PACK_STATUSES mirror vs kernel", () => {
  const kernelPackStatuses = extractKernelTuple(kernelSource, "PACK_STATUSES");

  it("kernel PACK_STATUSES has exactly five values", () => {
    expect(kernelPackStatuses).toHaveLength(5);
  });

  it("MCP mirror is byte-equal (value + order) to kernel PACK_STATUSES", () => {
    expect([...PACK_STATUSES]).toEqual(kernelPackStatuses);
  });
});

// ─── Spec-diff round — REST URL paths each tool calls ───────────────────────

describe("drift — REST URL paths each tool wraps", () => {
  it("create POSTs /api/v1/evidence-packs", () => {
    expect(readTool("evidence-pack-create.ts")).toContain(
      'apiPost("/api/v1/evidence-packs"',
    );
  });

  it("list GETs /api/v1/evidence-packs", () => {
    expect(readTool("evidence-pack-list.ts")).toContain(
      'apiGet("/api/v1/evidence-packs"',
    );
  });

  it("get GETs /api/v1/evidence-packs/{id}", () => {
    expect(readTool("evidence-pack-get.ts")).toContain(
      "apiGet(`/api/v1/evidence-packs/",
    );
  });

  it("append_bundle POSTs /api/v1/evidence-packs/{id}/bundles", () => {
    const src = readTool("evidence-pack-append-bundle.ts");
    expect(src).toContain("`/api/v1/evidence-packs/");
    expect(src).toContain("/bundles`");
  });
});

// ─── Spec-diff round — tool input-schema shapes vs spec signatures ──────────

describe("drift — tool input-schema shapes vs spec P1.5 signatures", () => {
  it("create schema = {packType, systemId, frameworkBindings, metadata}", () => {
    expect(Object.keys(evidencePackCreateSchema).sort()).toEqual(
      ["frameworkBindings", "metadata", "packType", "systemId"].sort(),
    );
  });

  it("get schema = {packId}", () => {
    expect(Object.keys(evidencePackGetSchema)).toEqual(["packId"]);
  });

  it("list schema = {systemId, packType, status, limit, cursor}", () => {
    expect(Object.keys(evidencePackListSchema).sort()).toEqual(
      ["cursor", "limit", "packType", "status", "systemId"].sort(),
    );
  });

  it("append_bundle schema = required + optional bundle fields", () => {
    expect(Object.keys(evidencePackAppendBundleSchema).sort()).toEqual(
      [
        "corroborationResults",
        "inputsHash",
        "metadata",
        "modelBehaviorLog",
        "outputsHash",
        "packId",
        "storageUri",
        "traceContent",
      ].sort(),
    );
  });
});

// ─── src/index.ts + registrar wiring (DEV-49) ───────────────────────────────
//
// The four `server.tool(...)` registrations + their `isError` adapters live
// in `evidence-pack-register.ts` (execution-tested by
// `evidence-pack-register.test.ts`). These source-read pins are the drift
// backstop: `index.ts` itself is an entry-point module and is not executed
// under coverage, so a source-read confirms it actually calls the registrar.

describe("drift — evidence-pack tool registration wiring", () => {
  const TOOL_NAMES = [
    "attestry_evidence_pack_create",
    "attestry_evidence_pack_get",
    "attestry_evidence_pack_list",
    "attestry_evidence_pack_append_bundle",
  ];
  const registerSource = readTool("evidence-pack-register.ts");

  it("src/index.ts imports and calls registerEvidencePackTools", () => {
    expect(indexSource).toContain('from "./tools/evidence-pack-register.js"');
    expect(indexSource).toContain("registerEvidencePackTools(server)");
  });

  it("the registrar registers all four tools by their wire names", () => {
    for (const name of TOOL_NAMES) {
      expect(registerSource).toContain(`"${name}"`);
    }
  });

  it("the registrar registers them in create → get → list → append_bundle order", () => {
    const positions = TOOL_NAMES.map((n) => registerSource.indexOf(`"${n}"`));
    expect(positions.every((p) => p >= 0)).toBe(true);
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it("the registrar imports all four tool modules", () => {
    for (const mod of [
      "evidence-pack-create",
      "evidence-pack-get",
      "evidence-pack-list",
      "evidence-pack-append-bundle",
    ]) {
      expect(registerSource).toContain(`from "./${mod}.js"`);
    }
  });
});
