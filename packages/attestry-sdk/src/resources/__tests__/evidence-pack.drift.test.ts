// ─── SDK ⇄ kernel constant drift-detection — evidence-pack (P1.6 / AC7) ─────
//
// `packages/attestry-sdk/src/resources/evidence-pack.ts` deliberately
// DUPLICATES the kernel-side `PACK_TYPES` / `PACK_STATUSES` arrays
// declared in `src/lib/evidence-pack/types.ts`. The SDK is a published
// artifact and must not depend on kernel internals — same rationale as
// the kernel-side `src/lib/incidents/__tests__/sdk-drift.test.ts`.
//
// Because the two copies are textually independent, an enum addition on
// either side can drift unnoticed. This test is the drift trip-wire,
// **satisfying P1 checkpoint AC7** ("SDK drift pin: `pack_type` enum in
// SDK matches kernel; if either side adds a value without the other,
// drift test fails").
//
// **Why SDK-local, not in `sdk-drift.test.ts`?** (DEV-65 / handoff
// Open Question #2.) The kernel-side `sdk-drift.test.ts` is ~146 KB and
// is actively co-edited by parallel sessions — P5.6 just added 6 vision
// drift pins and `git status` showed the file still modified at P1.6
// kickoff (a sibling has further pending edits). Committing into it
// carries the shared-file hazard the P1.5 audit doc documented twice.
// An SDK-local drift test under
// `packages/attestry-sdk/src/resources/__tests__/` avoids the kernel-
// side co-edit window entirely and establishes a clean precedent for
// future SDK drift pins.
//
// **Why `readFileSync` + regex, not `import`?** Same rationale as the
// kernel-side helper:
//
// > We deliberately AVOID `import`-ing the SDK module here. The SDK is
// > ESM with Node16 module resolution; the kernel runs through Vitest /
// > Next.js with `@/`-alias paths and a different module graph. A
// > cross-module import works some days and breaks others as toolchain
// > versions move underneath us. Reading text + parsing is robust to
// > both compile targets and survives a future SDK move to a sibling
// > repo (the test would just need a different file path).
//
// Inverted here: the SDK test does NOT import the kernel module. It
// reads both files as text + extracts the array literals via regex +
// `deep.equal` byte-comparison.
//
// Test files are NOT part of the published npm artifact (SDK
// `package.json` `files: ["dist", "README.md", "LICENSE"]`), so reading
// a kernel source path at test time does not break the SDK's
// standalone use.

import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { resolve } from "path";

// ─── Path resolution ────────────────────────────────────────────────────────
//
// This test file lives at
//   packages/attestry-sdk/src/resources/__tests__/evidence-pack.drift.test.ts
// SDK source side:
//   packages/attestry-sdk/src/resources/evidence-pack.ts
// Kernel source side:
//   src/lib/evidence-pack/types.ts
//
// From __dirname (`__tests__/`):
//   - SDK source: `../evidence-pack.ts` (one level up)
//   - Kernel source: `../../../../../src/lib/evidence-pack/types.ts`
//     (five levels up: __tests__/ → resources/ → src/ → attestry-sdk/
//     → packages/ → repo root, then down to src/lib/...)

const SDK_EVIDENCE_PACK_PATH = resolve(__dirname, "../evidence-pack.ts");
const KERNEL_EVIDENCE_PACK_TYPES_PATH = resolve(
  __dirname,
  "../../../../../src/lib/evidence-pack/types.ts",
);
const KERNEL_DB_SCHEMA_PATH = resolve(
  __dirname,
  "../../../../../src/lib/db/schema.ts",
);
const KERNEL_EVIDENCE_PACK_QUERIES_PATH = resolve(
  __dirname,
  "../../../../../src/lib/evidence-pack/queries.ts",
);
const KERNEL_EVIDENCE_PACK_CREATE_ROUTE_PATH = resolve(
  __dirname,
  "../../../../../src/app/api/v1/evidence-packs/route.ts",
);
const KERNEL_EVIDENCE_PACK_ID_ROUTE_PATH = resolve(
  __dirname,
  "../../../../../src/app/api/v1/evidence-packs/[id]/route.ts",
);
const KERNEL_EVIDENCE_PACK_BUNDLES_ROUTE_PATH = resolve(
  __dirname,
  "../../../../../src/app/api/v1/evidence-packs/[id]/bundles/route.ts",
);
// ─── P1.8 lifecycle/export kernel sources ───────────────────────────────────
const KERNEL_EVIDENCE_PACK_TRANSITIONS_PATH = resolve(
  __dirname,
  "../../../../../src/lib/evidence-pack/transitions.ts",
);
const KERNEL_EVIDENCE_PACK_EXPORT_PATH = resolve(
  __dirname,
  "../../../../../src/lib/evidence-pack/export.ts",
);
const KERNEL_EVIDENCE_PACK_SIGN_ROUTE_PATH = resolve(
  __dirname,
  "../../../../../src/app/api/v1/evidence-packs/[id]/sign/route.ts",
);
const KERNEL_EVIDENCE_PACK_SUPERSEDE_ROUTE_PATH = resolve(
  __dirname,
  "../../../../../src/app/api/v1/evidence-packs/[id]/supersede/route.ts",
);
const KERNEL_EVIDENCE_PACK_REVOKE_ROUTE_PATH = resolve(
  __dirname,
  "../../../../../src/app/api/v1/evidence-packs/[id]/revoke/route.ts",
);
const KERNEL_EVIDENCE_PACK_EXPORT_ROUTE_PATH = resolve(
  __dirname,
  "../../../../../src/app/api/v1/evidence-packs/[id]/export/route.ts",
);

const sdkEvidencePackSource = readFileSync(SDK_EVIDENCE_PACK_PATH, "utf-8");
const kernelEvidencePackTypesSource = readFileSync(
  KERNEL_EVIDENCE_PACK_TYPES_PATH,
  "utf-8",
);
const kernelDbSchemaSource = readFileSync(KERNEL_DB_SCHEMA_PATH, "utf-8");
const kernelEvidencePackQueriesSource = readFileSync(
  KERNEL_EVIDENCE_PACK_QUERIES_PATH,
  "utf-8",
);
const kernelEvidencePackCreateRouteSource = readFileSync(
  KERNEL_EVIDENCE_PACK_CREATE_ROUTE_PATH,
  "utf-8",
);
const kernelEvidencePackIdRouteSource = readFileSync(
  KERNEL_EVIDENCE_PACK_ID_ROUTE_PATH,
  "utf-8",
);
const kernelEvidencePackBundlesRouteSource = readFileSync(
  KERNEL_EVIDENCE_PACK_BUNDLES_ROUTE_PATH,
  "utf-8",
);
const kernelEvidencePackTransitionsSource = readFileSync(
  KERNEL_EVIDENCE_PACK_TRANSITIONS_PATH,
  "utf-8",
);
const kernelEvidencePackExportSource = readFileSync(
  KERNEL_EVIDENCE_PACK_EXPORT_PATH,
  "utf-8",
);
const kernelEvidencePackSignRouteSource = readFileSync(
  KERNEL_EVIDENCE_PACK_SIGN_ROUTE_PATH,
  "utf-8",
);
const kernelEvidencePackSupersedeRouteSource = readFileSync(
  KERNEL_EVIDENCE_PACK_SUPERSEDE_ROUTE_PATH,
  "utf-8",
);
const kernelEvidencePackRevokeRouteSource = readFileSync(
  KERNEL_EVIDENCE_PACK_REVOKE_ROUTE_PATH,
  "utf-8",
);
const kernelEvidencePackExportRouteSource = readFileSync(
  KERNEL_EVIDENCE_PACK_EXPORT_ROUTE_PATH,
  "utf-8",
);

// ─── Regex extraction helpers (mirror of kernel-side sdk-drift.test.ts) ─────

/**
 * Escape regex metacharacters in `s` so it can be safely embedded into
 * a `new RegExp(...)` source. Defensive — today all callers pass static
 * identifier names, but if a future caller passes anything containing
 * `.`, `*`, `(`, `)`, etc., the un-escaped form would silently change
 * the pattern's meaning or throw `SyntaxError` on unbalanced
 * metacharacters.
 */
function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Strip `//` line comments through end-of-line. Avoids matching
 * commented-out declarations.
 */
function stripLineComments(source: string): string {
  return source.replace(/\/\/[^\n]*$/gm, "");
}

/**
 * Extract a string array from a TypeScript `as const` literal.
 *
 * Matches BOTH the bare `as const` form (kernel route-local consts) AND
 * the `Object.freeze([...] as const)` form (SDK closed-enum exports are
 * runtime-frozen for P1 hardening). Same algorithm as the kernel-side
 * `extractAsConstArray` helper in `src/lib/incidents/__tests__/sdk-drift.test.ts`.
 *
 * Returns the parsed string entries in source order. Throws if the
 * declaration is missing or malformed — failure here means the source
 * has been restructured and this test needs to be updated, not that
 * the constants drifted.
 */
function extractAsConstArray(
  rawSource: string,
  name: string,
  sourceLabel: string,
): string[] {
  const source = stripLineComments(rawSource);
  const declRe = new RegExp(
    `export\\s+const\\s+${escapeRegex(name)}\\s*=\\s*` +
      `(?:Object\\s*\\.\\s*freeze\\s*\\(\\s*)?` +
      `\\[([\\s\\S]*?)\\]\\s*as\\s+const\\s*\\)?\\s*;`,
    "m",
  );
  const m = source.match(declRe);
  if (!m) {
    throw new Error(
      `${sourceLabel}: could not find \`export const ${name} = [...] as const\` ` +
        `declaration. Source restructured?`,
    );
  }
  const body = m[1];
  // Strip per-element trailing commas + whitespace; parse each
  // double-quoted (or single-quoted) string literal.
  const literalRe = /(["'])([^"'\n]*)\1/g;
  const out: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = literalRe.exec(body)) !== null) {
    out.push(match[2]);
  }
  if (out.length === 0) {
    throw new Error(
      `${sourceLabel}: \`${name}\` array literal contains no string entries`,
    );
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════
// P1.6 / AC7 — SDK ↔ kernel drift detection for evidence-pack closed enums
// ═══════════════════════════════════════════════════════════════════════════

describe("evidence-pack SDK ⇄ kernel drift detection (P1.6 / AC7)", () => {
  it("PACK_TYPES: SDK array byte-equals kernel `PACK_TYPES`", () => {
    const sdkValues = extractAsConstArray(
      sdkEvidencePackSource,
      "PACK_TYPES",
      "SDK packages/attestry-sdk/src/resources/evidence-pack.ts",
    );
    const kernelValues = extractAsConstArray(
      kernelEvidencePackTypesSource,
      "PACK_TYPES",
      "kernel src/lib/evidence-pack/types.ts",
    );
    expect(sdkValues).toEqual(kernelValues);
    // Belt-and-suspenders: explicit length + content + order pins so a
    // future restructure doesn't accidentally produce a `[]`-vs-`[]`
    // false positive.
    expect(sdkValues.length).toBe(5);
    expect(sdkValues).toEqual([
      "annex_iv",
      "agentic_reperformance",
      "red_team_cycle",
      "pccp_evidence",
      "underwriting_evidence",
    ]);
  });

  it("PACK_STATUSES: SDK array byte-equals kernel `PACK_STATUSES`", () => {
    const sdkValues = extractAsConstArray(
      sdkEvidencePackSource,
      "PACK_STATUSES",
      "SDK packages/attestry-sdk/src/resources/evidence-pack.ts",
    );
    const kernelValues = extractAsConstArray(
      kernelEvidencePackTypesSource,
      "PACK_STATUSES",
      "kernel src/lib/evidence-pack/types.ts",
    );
    expect(sdkValues).toEqual(kernelValues);
    expect(sdkValues.length).toBe(5);
    expect(sdkValues).toEqual([
      "draft",
      "signed",
      "superseded",
      "revoked",
      "expired",
    ]);
  });

  it("kernel `PACK_TYPES` declaration is reachable from the SDK package", () => {
    // Sanity guard — if the relative path resolution breaks (e.g., the
    // monorepo layout shifts), the readFileSync at module load already
    // threw. This test just confirms the file content looks like the
    // expected kernel module (smoke-check before drift extraction).
    expect(kernelEvidencePackTypesSource).toMatch(/export const PACK_TYPES/);
    expect(kernelEvidencePackTypesSource).toMatch(
      /export const PACK_STATUSES/,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Round 2 (spec-diff) — structural drift pins beyond closed enums
// ═══════════════════════════════════════════════════════════════════════════
//
// Each pin asserts a field name appears in BOTH the kernel-side source
// (Zod schema, Drizzle table, route handler, query helper, or result
// type) AND the SDK-side declaration. A rename or removal on either
// side trips the test before consumer regressions.
//
// The `.toContain(...)` approach is intentionally loose vs deep-equal:
// it pins the FIELD NAME, not the full surrounding shape (e.g. a kernel
// `.optional()` becoming `.optional().nullable()` will not trip). The
// tighter check would require full TypeScript / Zod AST parsing —
// out-of-scope for a regex-based drift test. The closed-enum byte-
// equality pin (above) is the strict check; these `.toContain` pins
// are the wide trip-wire.

describe("evidence-pack SDK ⇄ kernel structural drift (P1.6 R2)", () => {
  // ─── `create` (POST /api/v1/evidence-packs) request-body shape ─────────────
  describe("POST /api/v1/evidence-packs — request body field names", () => {
    // Kernel-side schema is the omit-derived `createPackBodySchema` in
    // the route, sourced from `createEvidencePackInputSchema` in types.ts
    // MINUS the auth-derived `orgId` / `userId`. P1.6 surface mirrors
    // the MCP P1.5 surface — 4 fields (no consumerHints, no
    // parentPackId). DEV-67.
    const P16_CREATE_FIELDS = [
      "packType",
      "systemId",
      "frameworkBindings",
      "metadata",
    ] as const;

    for (const field of P16_CREATE_FIELDS) {
      it(`field \`${field}\` appears in kernel createEvidencePackInputSchema AND SDK CreateEvidencePackInput`, () => {
        // Kernel side: types.ts has `packType: z.enum(...)`,
        // `systemId: uuidLc().optional()`, etc.
        expect(kernelEvidencePackTypesSource).toContain(`${field}:`);
        // SDK side: evidence-pack.ts has the same field in
        // CreateEvidencePackInput interface.
        expect(sdkEvidencePackSource).toContain(`${field}:`);
      });
    }
  });

  // ─── `addBundle` (POST /{id}/bundles) request-body shape ───────────────────
  describe("POST /api/v1/evidence-packs/{id}/bundles — request body field names", () => {
    // Kernel-side schema is `appendBundleBodySchema` in [id]/bundles/route.ts
    // (derived from `addBundleToPackInputSchema` minus packId/orgId/userId).
    // The SDK matches P1.5 MCP parity at 7 body fields (packId rides
    // URL path, NOT in body). DEV-67.
    const P16_ADD_BUNDLE_BODY_FIELDS = [
      "traceContent",
      "inputsHash",
      "outputsHash",
      "modelBehaviorLog",
      "corroborationResults",
      "storageUri",
      "metadata",
    ] as const;

    for (const field of P16_ADD_BUNDLE_BODY_FIELDS) {
      it(`field \`${field}\` appears in kernel addBundleToPackInputSchema AND SDK AddBundleInput`, () => {
        expect(kernelEvidencePackTypesSource).toContain(`${field}:`);
        expect(sdkEvidencePackSource).toContain(`${field}:`);
      });
    }

    it("`packId` is in SDK AddBundleInput AND the kernel URL path interpolation (NOT in body)", () => {
      // SDK side: packId IS a field on AddBundleInput.
      expect(sdkEvidencePackSource).toContain("packId:");
      // Kernel side: `packId` lives in `addBundleToPackInputSchema` (the
      // generator-input shape) AND in the route's `params.id` →
      // `parsedParams.data.packId` URL-path resolution.
      expect(kernelEvidencePackTypesSource).toContain("packId:");
      expect(kernelEvidencePackBundlesRouteSource).toContain("packId");
      // The SDK builds the URL path with `${packId}/bundles` (this
      // assertion locks the URL shape so a kernel-side path rename
      // surfaces here).
      expect(sdkEvidencePackSource).toContain("/bundles");
      expect(kernelEvidencePackBundlesRouteSource).toContain("bundles");
    });
  });

  // ─── `list` (GET /) query-string shape ─────────────────────────────────────
  describe("GET /api/v1/evidence-packs — query-string field names", () => {
    // SDK list surface mirrors MCP P1.5 — 5 fields (no parentPackId
    // filter, even though kernel listEvidencePacksQuerySchema accepts
    // it). DEV-67.
    const P16_LIST_QUERY_FIELDS = [
      "systemId",
      "packType",
      "status",
      "limit",
      "cursor",
    ] as const;

    for (const field of P16_LIST_QUERY_FIELDS) {
      it(`field \`${field}\` appears in kernel listEvidencePacksQuerySchema AND SDK ListEvidencePacksInput`, () => {
        expect(kernelEvidencePackTypesSource).toContain(`${field}:`);
        expect(sdkEvidencePackSource).toContain(`${field}:`);
      });
    }
  });

  // ─── `list` (GET /) response shape ─────────────────────────────────────────
  describe("GET /api/v1/evidence-packs — response shape", () => {
    it("`items` + `nextCursor` are in kernel ListEvidencePacksResult AND SDK ListEvidencePacksResponse", () => {
      expect(kernelEvidencePackQueriesSource).toContain("items:");
      expect(kernelEvidencePackQueriesSource).toContain("nextCursor:");
      expect(sdkEvidencePackSource).toContain("items:");
      expect(sdkEvidencePackSource).toContain("nextCursor:");
    });
  });

  // ─── `get` (GET /{id}) response shape ──────────────────────────────────────
  describe("GET /api/v1/evidence-packs/{id} — response shape", () => {
    it("`pack` + `bundles` are in kernel GetEvidencePackResult AND SDK GetEvidencePackResponse", () => {
      expect(kernelEvidencePackQueriesSource).toContain("pack:");
      expect(kernelEvidencePackQueriesSource).toContain("bundles:");
      expect(sdkEvidencePackSource).toContain("pack:");
      expect(sdkEvidencePackSource).toContain("bundles:");
    });
  });

  // ─── `addBundle` (POST /{id}/bundles) response shape ───────────────────────
  describe("POST /api/v1/evidence-packs/{id}/bundles — response shape", () => {
    it("`bundle` + `pack` + `hashCollision` are in kernel AddBundleToPackResult AND SDK AddBundleResponse", () => {
      // Kernel side: AddBundleToPackResult lives in types.ts.
      expect(kernelEvidencePackTypesSource).toContain("bundle:");
      expect(kernelEvidencePackTypesSource).toContain("pack:");
      expect(kernelEvidencePackTypesSource).toContain("hashCollision:");
      // SDK side: AddBundleResponse interface.
      expect(sdkEvidencePackSource).toContain("bundle:");
      expect(sdkEvidencePackSource).toContain("pack:");
      expect(sdkEvidencePackSource).toContain("hashCollision:");
    });

    it("hashCollision shape — `detected` + `count` + `collidingBundleIds`", () => {
      expect(kernelEvidencePackTypesSource).toContain("detected:");
      expect(kernelEvidencePackTypesSource).toContain("count:");
      expect(kernelEvidencePackTypesSource).toContain("collidingBundleIds:");
      expect(sdkEvidencePackSource).toContain("detected:");
      expect(sdkEvidencePackSource).toContain("count:");
      expect(sdkEvidencePackSource).toContain("collidingBundleIds:");
    });
  });

  // ─── EvidencePack wire shape (Drizzle column names) ────────────────────────
  describe("EvidencePack wire shape — Drizzle column names ↔ SDK interface", () => {
    // Drizzle column declarations in schema.ts use camelCase property
    // names like `packType: packTypeEnum("pack_type").notNull()`. The
    // Next.js JSON response serializes the Drizzle row to camelCase
    // (Drizzle's `select()` returns camelCase). The SDK's EvidencePack
    // interface uses the same camelCase keys.
    const EVIDENCE_PACK_COLUMNS = [
      "id",
      "packType",
      "orgId",
      "systemId",
      "status",
      "frameworkBindings",
      "parentPackId",
      "supersededById",
      "consumerHints",
      "attestationCertificateId",
      "contentHash",
      "signedAt",
      "signedByUserId",
      "metadata",
      "createdAt",
    ] as const;

    for (const column of EVIDENCE_PACK_COLUMNS) {
      it(`column \`${column}\` appears in kernel evidencePacks Drizzle table AND SDK EvidencePack`, () => {
        // Kernel side: schema.ts has `<col>: uuid("<snake>")...` /
        // `<col>: text(...)` / `<col>: jsonb(...)` etc.
        expect(kernelDbSchemaSource).toContain(`${column}:`);
        // SDK side: EvidencePack interface field.
        expect(sdkEvidencePackSource).toContain(`${column}:`);
      });
    }
  });

  // ─── ReperformanceBundle wire shape (Drizzle column names) ─────────────────
  describe("ReperformanceBundle wire shape — Drizzle column names ↔ SDK interface", () => {
    const REPERFORMANCE_BUNDLE_COLUMNS = [
      "id",
      "evidencePackId",
      "traceContent",
      "inputsHash",
      "outputsHash",
      "modelBehaviorLog",
      "corroborationResults",
      "storageUri",
      "metadata",
      "createdAt",
    ] as const;

    for (const column of REPERFORMANCE_BUNDLE_COLUMNS) {
      it(`column \`${column}\` appears in kernel reperformanceBundles Drizzle table AND SDK ReperformanceBundle`, () => {
        expect(kernelDbSchemaSource).toContain(`${column}:`);
        expect(sdkEvidencePackSource).toContain(`${column}:`);
      });
    }
  });

  // ─── URL path conventions ──────────────────────────────────────────────────
  describe("Kernel REST URL paths ↔ SDK request paths", () => {
    it("`/api/v1/evidence-packs` base path appears in BOTH kernel route AND SDK source", () => {
      // The kernel POST + GET route file exists at the canonical path;
      // its source matches. The SDK calls the same path.
      expect(kernelEvidencePackCreateRouteSource).toContain(
        "evidence-pack",
      );
      expect(sdkEvidencePackSource).toContain("/api/v1/evidence-packs");
    });

    it("`/{id}` single-pack route is referenced by SDK get()", () => {
      // The kernel [id]/route.ts exists; the SDK constructs the URL via
      // `${encodeURIComponent(packIdRaw)}` path interpolation.
      expect(kernelEvidencePackIdRouteSource).toContain("getEvidencePack");
      expect(sdkEvidencePackSource).toContain(
        "/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}",
      );
    });

    it("`/{id}/bundles` append-bundle route is referenced by SDK addBundle()", () => {
      expect(kernelEvidencePackBundlesRouteSource).toContain("addBundleToPack");
      expect(sdkEvidencePackSource).toContain(
        "/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/bundles",
      );
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// P1.8 (spec-diff DEV-77) — SDK ⇄ kernel drift for the lifecycle/export surface
// ═══════════════════════════════════════════════════════════════════════════
//
// Same discipline as the P1.6 R2 pins: EXPORT_FORMATS gets a strict byte-
// equality check (it is a load-bearing closed enum, mirror of PACK_TYPES);
// the request-body / response / artifact / path pins are wide `.toContain`
// trip-wires for renames or removals on either side.

describe("evidence-pack SDK ⇄ kernel P1.8 lifecycle/export drift (DEV-77)", () => {
  // ─── EXPORT_FORMATS closed enum (strict byte-equality) ─────────────────────
  describe("EXPORT_FORMATS closed enum", () => {
    it("SDK array byte-equals kernel `EXPORT_FORMATS`", () => {
      const sdkValues = extractAsConstArray(
        sdkEvidencePackSource,
        "EXPORT_FORMATS",
        "SDK packages/attestry-sdk/src/resources/evidence-pack.ts",
      );
      const kernelValues = extractAsConstArray(
        kernelEvidencePackTypesSource,
        "EXPORT_FORMATS",
        "kernel src/lib/evidence-pack/types.ts",
      );
      expect(sdkValues).toEqual(kernelValues);
      expect(sdkValues.length).toBe(3);
      expect(sdkValues).toEqual(["json", "pdf", "zip"]);
    });

    it("kernel `EXPORT_FORMATS` declaration is reachable from the SDK package", () => {
      expect(kernelEvidencePackTypesSource).toMatch(/export const EXPORT_FORMATS/);
    });
  });

  // ─── EXPORT_CONTENT_TYPES mapping (format → MIME pairs) ─────────────────────
  describe("EXPORT_CONTENT_TYPES mapping ↔ kernel export.ts", () => {
    const EXPORT_CONTENT_TYPE_PAIRS = [
      'json: "application/json"',
      'pdf: "application/pdf"',
      'zip: "application/zip"',
    ] as const;

    for (const pair of EXPORT_CONTENT_TYPE_PAIRS) {
      it(`mapping \`${pair}\` appears in kernel export.ts AND SDK evidence-pack.ts`, () => {
        expect(kernelEvidencePackExportSource).toContain(pair);
        expect(sdkEvidencePackSource).toContain(pair);
      });
    }

    it("both sources name the mapping `EXPORT_CONTENT_TYPES`", () => {
      expect(kernelEvidencePackExportSource).toContain("EXPORT_CONTENT_TYPES");
      expect(sdkEvidencePackSource).toContain("EXPORT_CONTENT_TYPES");
    });
  });

  // ─── sign (POST /{id}/sign) request body + response + path ─────────────────
  describe("POST /{id}/sign — body field + response + path", () => {
    it("`attestationCertificateId` is in kernel signPackInputSchema AND SDK SignEvidencePackInput", () => {
      expect(kernelEvidencePackTypesSource).toContain("attestationCertificateId:");
      expect(sdkEvidencePackSource).toContain("attestationCertificateId:");
    });

    it("response type linkage — kernel signPack returns a bare `EvidencePack` AND the SDK validates the response as a pack", () => {
      // Founder-fed re-audit F-RA-1: the DoD enumerates a `sign` RESPONSE
      // drift pin. sign returns a plain EvidencePack (whose 15-column wire
      // shape is already pinned above); this pin locks the RETURN-TYPE
      // linkage so a kernel change that wraps the response (e.g.
      // `{pack, signature}`) trips here, and so the SDK keeps validating it.
      expect(kernelEvidencePackTransitionsSource).toContain(
        "signPack(input: SignPackInput): Promise<EvidencePack>",
      );
      expect(sdkEvidencePackSource).toContain(
        'validatePack(result, "evidencePack.sign", "response")',
      );
    });

    it("the `/sign` URL path is in BOTH the SDK source AND the kernel sign route", () => {
      expect(sdkEvidencePackSource).toContain(
        "/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/sign",
      );
      expect(kernelEvidencePackSignRouteSource).toContain("signPack");
    });
  });

  // ─── supersede (POST /{id}/supersede) newPack body + response + path ───────
  describe("POST /{id}/supersede — newPack body, response, path", () => {
    // The supersede newPack payload mirrors kernel supersedeNewPackPayloadSchema
    // — INCLUDING consumerHints (DEV-74), the one field create deliberately
    // omits. This pin is the OQ#2 drift trip-wire.
    const SUPERSEDE_NEW_PACK_FIELDS = [
      "packType",
      "systemId",
      "frameworkBindings",
      "consumerHints",
      "metadata",
    ] as const;

    for (const field of SUPERSEDE_NEW_PACK_FIELDS) {
      it(`newPack field \`${field}\` is in kernel supersedeNewPackPayloadSchema AND SDK SupersedeEvidencePackNewPack`, () => {
        expect(kernelEvidencePackTypesSource).toContain(`${field}:`);
        expect(sdkEvidencePackSource).toContain(`${field}:`);
      });
    }

    it("`newPack` wrapper is in kernel supersedePackInputSchema AND SDK SupersedeEvidencePackInput", () => {
      expect(kernelEvidencePackTypesSource).toContain("newPack:");
      expect(sdkEvidencePackSource).toContain("newPack:");
    });

    it("response shape `{newPack, oldPack}` is in kernel transitions.ts AND SDK SupersedeEvidencePackResponse", () => {
      // Kernel supersedePack returns `{ newPack, oldPack }`.
      expect(kernelEvidencePackTransitionsSource).toContain("newPack");
      expect(kernelEvidencePackTransitionsSource).toContain("oldPack");
      expect(sdkEvidencePackSource).toContain("newPack:");
      expect(sdkEvidencePackSource).toContain("oldPack:");
    });

    it("the `/supersede` URL path is in BOTH the SDK source AND the kernel supersede route", () => {
      expect(sdkEvidencePackSource).toContain(
        "/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/supersede",
      );
      expect(kernelEvidencePackSupersedeRouteSource).toContain("supersedePack");
    });
  });

  // ─── revoke (POST /{id}/revoke) request body + response + path ─────────────
  describe("POST /{id}/revoke — body field + response + path", () => {
    it("`reason` is in kernel revokePackInputSchema AND SDK RevokeEvidencePackInput", () => {
      expect(kernelEvidencePackTypesSource).toContain("reason:");
      expect(sdkEvidencePackSource).toContain("reason:");
    });

    it("response type linkage — kernel revokePack returns a bare `EvidencePack` AND the SDK validates the response as a pack", () => {
      // Founder-fed re-audit F-RA-1: the DoD enumerates a `revoke` RESPONSE
      // drift pin (the EvidencePack wire shape is pinned above; this locks
      // the return-type linkage so a kernel response-wrapping change trips).
      expect(kernelEvidencePackTransitionsSource).toContain(
        "revokePack(input: RevokePackInput): Promise<EvidencePack>",
      );
      expect(sdkEvidencePackSource).toContain(
        'validatePack(result, "evidencePack.revoke", "response")',
      );
    });

    it("the `/revoke` URL path is in BOTH the SDK source AND the kernel revoke route", () => {
      expect(sdkEvidencePackSource).toContain(
        "/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/revoke",
      );
      expect(kernelEvidencePackRevokeRouteSource).toContain("revokePack");
    });
  });

  // ─── export (GET /{id}/export) artifact + query + path ─────────────────────
  describe("GET /{id}/export — artifact shape, query, path", () => {
    it("the JSON artifact top-level keys (export / pack / bundles) are in kernel export.ts encodeJsonExport", () => {
      // Kernel encodeJsonExport returns `{export:{...}, pack, bundles}`.
      expect(kernelEvidencePackExportSource).toContain("export:");
      expect(kernelEvidencePackExportSource).toContain("pack:");
      expect(kernelEvidencePackExportSource).toContain("bundles:");
    });

    it("the artifact `schemaVersion` string matches between kernel export.ts and the SDK consumer contract", () => {
      // The SDK is a faithful courier (no type for the artifact) — the
      // schemaVersion literal documents the consumer contract in JSDoc.
      // A kernel schemaVersion bump trips this pin so the SDK docs stay
      // in sync.
      expect(kernelEvidencePackExportSource).toContain("evidence-pack-export.v1");
      expect(sdkEvidencePackSource).toContain("evidence-pack-export.v1");
    });

    it("`format` is in kernel exportQuerySchema AND the SDK ExportEvidencePackInput", () => {
      expect(kernelEvidencePackTypesSource).toContain("format:");
      expect(sdkEvidencePackSource).toContain("format:");
    });

    it("the `/export` URL path is in BOTH the SDK source AND the kernel export route", () => {
      expect(sdkEvidencePackSource).toContain(
        "/api/v1/evidence-packs/${encodeURIComponent(packIdRaw)}/export",
      );
      expect(kernelEvidencePackExportRouteSource).toContain("exportEvidencePack");
    });
  });
});
