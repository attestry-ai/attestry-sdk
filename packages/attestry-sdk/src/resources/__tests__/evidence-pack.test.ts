import { describe, it, expect, vi, afterEach } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import {
  PACK_TYPES,
  PACK_STATUSES,
  EXPORT_FORMATS,
  type CreateEvidencePackInput,
  type GetEvidencePackInput,
  type ListEvidencePacksInput,
  type AddBundleInput,
  type SignEvidencePackInput,
  type SupersedeEvidencePackInput,
  type RevokeEvidencePackInput,
  type ExportEvidencePackInput,
  type EvidencePack,
  type ReperformanceBundle,
  type AddBundleResponse,
  type SupersedeEvidencePackResponse,
} from "../evidence-pack.js";
import type { FetchLike } from "../../types.js";

// ─── evidencePack resource — POST create / GET get / GET list / POST addBundle
//
// Wire shapes (from src/app/api/v1/evidence-packs/{route,[id]/route,[id]/bundles/route}.ts):
//
//   - POST /api/v1/evidence-packs
//       Body:   {packType: enum, systemId?: UUID, frameworkBindings?: array, metadata?: object}
//       Resp:   EvidencePack
//
//   - GET /api/v1/evidence-packs/{id}
//       Resp:   {pack: EvidencePack, bundles: ReperformanceBundle[]}
//
//   - GET /api/v1/evidence-packs?...
//       Query:  {systemId?: UUID, packType?: enum, status?: enum, limit?: int, cursor?: string}
//       Resp:   {items: EvidencePack[], nextCursor: string | null}
//
//   - POST /api/v1/evidence-packs/{id}/bundles
//       Body:   {traceContent: array, inputsHash: string, outputsHash: string,
//                modelBehaviorLog?, corroborationResults?, storageUri?, metadata?}
//       Resp:   {bundle: ReperformanceBundle, pack: EvidencePack, hashCollision}
//
// Tenth resource on the SDK. P1.6-scope: exactly 4 methods (sign /
// supersede / revoke / export deferred to a future P1.8).

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

function makeMockedClient(
  responses: Array<{
    status?: number;
    body?: unknown;
    bodyText?: string;
    // P1.8 export extensions (backward-compatible — all optional):
    //   - rawBody: a non-JSON body (binary Uint8Array / ReadableStream)
    //     for the `export` pdf/zip paths. Takes precedence over body/bodyText.
    //   - contentType: overrides the default "application/json" (export
    //     pdf → "application/pdf", zip → "application/zip").
    //   - contentDisposition: sets the download header the export route emits.
    //   - omitContentType: drop the Content-Type header entirely (proxy-
    //     stripped-header probe).
    rawBody?: BodyInit;
    contentType?: string;
    contentDisposition?: string;
    omitContentType?: boolean;
  }>,
) {
  const calls: MockedRequest[] = [];
  let i = 0;
  const mockFetch: FetchLike = async (url, init) => {
    calls.push({
      url: String(url),
      method: (init?.method as string) ?? "GET",
      headers: init?.headers as Headers,
      body: init?.body as string | undefined,
    });
    const r = responses[i++] ?? {};
    const status = r.status ?? 200;
    const respBody: BodyInit =
      r.rawBody !== undefined
        ? r.rawBody
        : r.bodyText !== undefined
          ? r.bodyText
          : JSON.stringify(r.body ?? {});
    const headers: Record<string, string> = {};
    if (!r.omitContentType) {
      headers["Content-Type"] = r.contentType ?? "application/json";
    }
    if (r.contentDisposition !== undefined) {
      headers["Content-Disposition"] = r.contentDisposition;
    }
    return new Response(respBody, { status, headers });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const VALID_UUID = "11111111-1111-1111-1111-111111111111";
const VALID_PACK_ID = "22222222-2222-2222-2222-222222222222";
const VALID_BUNDLE_ID = "33333333-3333-3333-3333-333333333333";
const VALID_ORG_ID = "44444444-4444-4444-4444-444444444444";
const VALID_USER_ID = "55555555-5555-5555-5555-555555555555";

// ─── Mock fixtures ──────────────────────────────────────────────────────────

const MOCK_PACK: EvidencePack = {
  id: VALID_PACK_ID,
  packType: "annex_iv",
  orgId: VALID_ORG_ID,
  systemId: VALID_UUID,
  status: "draft",
  frameworkBindings: [
    { framework: "eu_ai_act", identifier: "Annex.IV.1" },
  ],
  parentPackId: null,
  supersededById: null,
  consumerHints: {},
  attestationCertificateId: null,
  contentHash: null,
  signedAt: null,
  signedByUserId: null,
  metadata: {},
  createdAt: "2026-05-18T12:00:00.000Z",
};

const MOCK_PACK_SIGNED: EvidencePack = {
  ...MOCK_PACK,
  status: "signed",
  contentHash:
    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  signedAt: "2026-05-18T13:00:00.000Z",
  signedByUserId: VALID_USER_ID,
  attestationCertificateId: VALID_UUID,
};

const MOCK_BUNDLE: ReperformanceBundle = {
  id: VALID_BUNDLE_ID,
  evidencePackId: VALID_PACK_ID,
  traceContent: [
    { action: "ingest", timestamp: "2026-05-18T12:00:00.000Z" },
  ],
  inputsHash:
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  outputsHash:
    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  modelBehaviorLog: null,
  corroborationResults: null,
  storageUri: null,
  metadata: {},
  createdAt: "2026-05-18T12:00:01.000Z",
};

const MOCK_ADD_BUNDLE_RESPONSE: AddBundleResponse = {
  bundle: MOCK_BUNDLE,
  pack: { ...MOCK_PACK, contentHash: "sha256:" + "f".repeat(64) },
  hashCollision: { detected: false, count: 0, collidingBundleIds: [] },
};

// ─── P1.8 lifecycle/export fixtures ─────────────────────────────────────────

const VALID_NEW_PACK_ID = "66666666-6666-6666-6666-666666666666";

// supersede: the old pack transitioned `signed → superseded`.
const MOCK_PACK_OLD_SUPERSEDED: EvidencePack = {
  ...MOCK_PACK_SIGNED,
  status: "superseded",
  supersededById: VALID_NEW_PACK_ID,
};

// supersede: the new draft pack referencing the old as parent.
const MOCK_PACK_NEW_DRAFT: EvidencePack = {
  ...MOCK_PACK,
  id: VALID_NEW_PACK_ID,
  status: "draft",
  parentPackId: VALID_PACK_ID,
  contentHash: null,
  signedAt: null,
  signedByUserId: null,
  attestationCertificateId: null,
};

const MOCK_SUPERSEDE_RESPONSE: SupersedeEvidencePackResponse = {
  newPack: MOCK_PACK_NEW_DRAFT,
  oldPack: MOCK_PACK_OLD_SUPERSEDED,
};

// revoke: the pack transitioned `signed → revoked`.
const MOCK_PACK_REVOKED: EvidencePack = {
  ...MOCK_PACK_SIGNED,
  status: "revoked",
};

// export json artifact — the RAW shape the kernel emits on success (NO
// `{success, data}` envelope). Mirrors `encodeJsonExport` in
// src/lib/evidence-pack/export.ts.
const MOCK_EXPORT_JSON_ARTIFACT = {
  export: {
    format: "json" as const,
    generatedAt: "2026-05-23T12:00:00.000Z",
    schemaVersion: "evidence-pack-export.v1",
  },
  pack: MOCK_PACK_SIGNED,
  bundles: [MOCK_BUNDLE],
};

const EXPORT_CONTENT_DISPOSITION = `attachment; filename="evidence-pack-${VALID_PACK_ID}.json"`;

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.create — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.create — happy path", () => {
  it("POSTs /api/v1/evidence-packs with a minimal JSON body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK } },
    ]);
    const out = await client.evidencePack.create({
      packType: "annex_iv",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/evidence-packs");
    expect(url.search).toBe("");
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({ packType: "annex_iv" });
    expect(out).toEqual(MOCK_PACK);
  });

  it("POSTs with all fields when fully provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK } },
    ]);
    await client.evidencePack.create({
      packType: "agentic_reperformance",
      systemId: VALID_UUID,
      frameworkBindings: [{ framework: "iso_42001", identifier: "8.2" }],
      metadata: { author: "bot", version: 1 },
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      packType: "agentic_reperformance",
      systemId: VALID_UUID,
      frameworkBindings: [{ framework: "iso_42001", identifier: "8.2" }],
      metadata: { author: "bot", version: 1 },
    });
  });

  it("forwards x-api-key + Accept + Content-Type headers", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK } },
    ]);
    await client.evidencePack.create({ packType: "annex_iv" });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("round-trips all 5 packType values", async () => {
    for (const pt of PACK_TYPES) {
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: { ...MOCK_PACK, packType: pt } } },
      ]);
      await client.evidencePack.create({ packType: pt });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed.packType).toBe(pt);
    }
  });

  it("omits optional fields from the body when consumer omits them", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK } },
    ]);
    await client.evidencePack.create({ packType: "annex_iv" });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.keys(parsed).sort()).toEqual(["packType"]);
  });

  it("treats own-present-but-undefined optional fields as omitted", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK } },
    ]);
    await client.evidencePack.create({
      packType: "annex_iv",
      systemId: undefined,
      frameworkBindings: undefined,
      metadata: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({ packType: "annex_iv" });
  });

  it("sends an explicit empty frameworkBindings array", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK } },
    ]);
    await client.evidencePack.create({
      packType: "annex_iv",
      frameworkBindings: [],
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.frameworkBindings).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.create — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.create — input validation (pre-fetch)", () => {
  it("throws TypeError for null input — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create(null as unknown as CreateEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create(
        undefined as unknown as CreateEvidencePackInput,
      ),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create("bad" as unknown as CreateEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create([] as unknown as CreateEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packType is missing", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({} as unknown as CreateEvidencePackInput),
    ).toThrowError(/`packType` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packType is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: undefined as unknown as "annex_iv",
      }),
    ).toThrowError(/`packType` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string packType (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: 42 as unknown as "annex_iv",
      }),
    ).toThrowError(/`packType` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown packType value (closed-enum violation)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: "unknown_pack_type" as unknown as "annex_iv",
      }),
    ).toThrowError(/`packType` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: "annex_iv",
        systemId: 42 as unknown as string,
      }),
    ).toThrowError(/`systemId` must be a string when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for malformed systemId UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: "annex_iv",
        systemId: "not-a-uuid",
      }),
    ).toThrowError(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-array frameworkBindings", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: "annex_iv",
        frameworkBindings: { 0: "x" } as unknown as unknown[],
      }),
    ).toThrowError(/`frameworkBindings` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when frameworkBindings exceeds 50 entries", () => {
    const { client, calls } = makeMockedClient([]);
    const big = Array.from({ length: 51 }, () => ({ framework: "x", identifier: "y" }));
    expect(() =>
      client.evidencePack.create({
        packType: "annex_iv",
        frameworkBindings: big,
      }),
    ).toThrowError(/exceeds the kernel's max length of 50/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for null metadata", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: "annex_iv",
        metadata: null as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`metadata` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array metadata", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: "annex_iv",
        metadata: [] as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`metadata` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object metadata (string)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.create({
        packType: "annex_iv",
        metadata: "bad" as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`metadata` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.create — response validation (P2)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.create — response validation (P2)", () => {
  async function callWithBadResponse(data: unknown) {
    const { client } = makeMockedClient([
      { body: { success: true, data } },
    ]);
    return client.evidencePack.create({ packType: "annex_iv" });
  }

  it("rejects when response is null", async () => {
    await expect(callWithBadResponse(null)).rejects.toBeInstanceOf(
      AttestryError,
    );
  });

  it("rejects when response is an array", async () => {
    await expect(callWithBadResponse([])).rejects.toThrow(
      /expected response to be an object/,
    );
  });

  it("rejects when response is a primitive (number)", async () => {
    await expect(callWithBadResponse(42)).rejects.toThrow(
      /expected response to be an object/,
    );
  });

  it("rejects when id is missing", async () => {
    const { id: _id, ...rest } = MOCK_PACK;
    await expect(callWithBadResponse(rest)).rejects.toThrow(
      /response\.id to be a string/,
    );
  });

  it("rejects when id is the wrong type", async () => {
    await expect(callWithBadResponse({ ...MOCK_PACK, id: 42 })).rejects.toThrow(
      /response\.id to be a string/,
    );
  });

  it("rejects when packType is missing", async () => {
    const { packType: _t, ...rest } = MOCK_PACK;
    await expect(callWithBadResponse(rest)).rejects.toThrow(
      /response\.packType to be a string/,
    );
  });

  it("rejects when orgId is missing", async () => {
    const { orgId: _o, ...rest } = MOCK_PACK;
    await expect(callWithBadResponse(rest)).rejects.toThrow(
      /response\.orgId to be a string/,
    );
  });

  it("rejects when status is the wrong type", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, status: 42 }),
    ).rejects.toThrow(/response\.status to be a string/);
  });

  it("rejects when createdAt is the wrong type", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, createdAt: 42 }),
    ).rejects.toThrow(/response\.createdAt to be a string/);
  });

  it("rejects when systemId is a number (not string-or-null)", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, systemId: 42 }),
    ).rejects.toThrow(/response\.systemId to be a string or null/);
  });

  it("accepts systemId = null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_PACK, systemId: null } } },
    ]);
    const out = await client.evidencePack.create({ packType: "annex_iv" });
    expect(out.systemId).toBeNull();
  });

  it("rejects when parentPackId is a number", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, parentPackId: 42 }),
    ).rejects.toThrow(/response\.parentPackId to be a string or null/);
  });

  it("rejects when supersededById is a number", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, supersededById: 42 }),
    ).rejects.toThrow(/response\.supersededById to be a string or null/);
  });

  it("rejects when attestationCertificateId is a number", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, attestationCertificateId: 42 }),
    ).rejects.toThrow(
      /response\.attestationCertificateId to be a string or null/,
    );
  });

  it("rejects when contentHash is a number", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, contentHash: 42 }),
    ).rejects.toThrow(/response\.contentHash to be a string or null/);
  });

  it("rejects when signedAt is a number", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, signedAt: 42 }),
    ).rejects.toThrow(/response\.signedAt to be a string or null/);
  });

  it("rejects when signedByUserId is a number", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, signedByUserId: 42 }),
    ).rejects.toThrow(/response\.signedByUserId to be a string or null/);
  });

  it("rejects when a nullable-string field is missing entirely (own-property false on the loop ternary)", async () => {
    // Round 4 coverage pin: exercises the `: undefined` else-branch of
    // the `for (const key of ["systemId", "parentPackId", ...])` loop
    // ternary at line ~1501 of evidence-pack.ts. The systemId iteration
    // takes the truthy branch (present in rest); the parentPackId
    // iteration takes the falsy branch (absent from rest). The first
    // absent-and-then-rejecting iteration short-circuits — but because
    // the loop iterates over multiple keys and BOTH branches are
    // exercised across iterations, line 1501's ternary hits both
    // branches for v8 branch coverage.
    const { parentPackId: _p, ...rest } = MOCK_PACK;
    await expect(callWithBadResponse(rest)).rejects.toThrow(
      /response\.parentPackId to be a string or null/,
    );
  });

  it("accepts signed-pack shape (every nullable populated)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_SIGNED } },
    ]);
    const out = await client.evidencePack.create({ packType: "annex_iv" });
    expect(out).toEqual(MOCK_PACK_SIGNED);
  });

  it("rejects when frameworkBindings is not an array (object)", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, frameworkBindings: {} }),
    ).rejects.toThrow(/response\.frameworkBindings to be an array/);
  });

  it("rejects when frameworkBindings is null", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, frameworkBindings: null }),
    ).rejects.toThrow(/response\.frameworkBindings to be an array/);
  });

  it("rejects when frameworkBindings is missing entirely (own-property false)", async () => {
    // Round 4 coverage pin: exercises the `: undefined` else-branch of
    // `objectHasOwn(obj, "frameworkBindings") ? obj.frameworkBindings : undefined`.
    // P5.6 R4 documented the same defect class: wrong-type tests only
    // exercise the truthy branch (own-property present with non-array
    // value); missing-field tests exercise the falsy branch.
    const { frameworkBindings: _f, ...rest } = MOCK_PACK;
    await expect(callWithBadResponse(rest)).rejects.toThrow(
      /response\.frameworkBindings to be an array/,
    );
  });

  it("rejects when consumerHints is an array", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, consumerHints: [] }),
    ).rejects.toThrow(/response\.consumerHints to be a non-null object/);
  });

  it("rejects when consumerHints is null", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, consumerHints: null }),
    ).rejects.toThrow(/response\.consumerHints to be a non-null object/);
  });

  it("rejects when consumerHints is a string", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, consumerHints: "x" }),
    ).rejects.toThrow(/response\.consumerHints to be a non-null object/);
  });

  it("rejects when metadata is an array", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, metadata: [] }),
    ).rejects.toThrow(/response\.metadata to be a non-null object/);
  });

  it("rejects when metadata is null", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_PACK, metadata: null }),
    ).rejects.toThrow(/response\.metadata to be a non-null object/);
  });

  it("rejects when pack.metadata is missing (own-property false)", async () => {
    // Round 4 coverage pin: exercises the `: undefined` else-branch of
    // the `for (const key of ["consumerHints", "metadata"])` loop
    // ternary inside validatePack. The consumerHints iteration takes
    // the truthy branch (present in rest); the metadata iteration
    // takes the falsy branch (absent from rest).
    const { metadata: _m, ...rest } = MOCK_PACK;
    await expect(callWithBadResponse(rest)).rejects.toThrow(
      /response\.metadata to be a non-null object/,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.create — error mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.create — error mapping", () => {
  it("surfaces 401 as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      { status: 401, body: { success: false, error: "Unauthorized." } },
    ]);
    await expect(
      client.evidencePack.create({ packType: "annex_iv" }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 403 as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      { status: 403, body: { success: false, error: "Forbidden." } },
    ]);
    try {
      await client.evidencePack.create({ packType: "annex_iv" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
    }
  });

  it("surfaces 422 (validation_failed) as AttestryAPIError with details.code", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: {
            code: "evidence_pack.validation_failed",
            issues: [{ path: "frameworkBindings.0.framework", message: "Required" }],
          },
        },
      },
    ]);
    try {
      await client.evidencePack.create({ packType: "annex_iv" });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      const detail = apiErr.details as { details?: { code?: string } };
      expect(detail.details?.code).toBe("evidence_pack.validation_failed");
    }
  });

  it("surfaces 500 as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      { status: 500, body: { success: false, error: "Internal error." } },
    ]);
    await expect(
      client.evidencePack.create({ packType: "annex_iv" }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("HR-4(b) confirmation: non-JSON 200 surfaces as AttestryAPIError (NOT SyntaxError)", async () => {
    const mockFetch: FetchLike = async () =>
      new Response("<html>502 Bad Gateway</html>", {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    let caught: unknown;
    try {
      await client.evidencePack.create({ packType: "annex_iv" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect(caught).not.toBeInstanceOf(SyntaxError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.create — abort signal
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.create — abort signal", () => {
  it("rejects synchronously when caller's AbortSignal is pre-aborted", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.evidencePack.create(
        { packType: "annex_iv" },
        { signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(AttestryError);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.get — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.get — happy path", () => {
  it("GETs /api/v1/evidence-packs/{id} with the validated UUID", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { pack: MOCK_PACK, bundles: [MOCK_BUNDLE] },
        },
      },
    ]);
    const out = await client.evidencePack.get({ packId: VALID_PACK_ID });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe(`/api/v1/evidence-packs/${VALID_PACK_ID}`);
    expect(url.search).toBe("");
    expect(out.pack).toEqual(MOCK_PACK);
    expect(out.bundles).toEqual([MOCK_BUNDLE]);
  });

  it("returns empty bundles array when pack has no bundles", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { pack: MOCK_PACK, bundles: [] } } },
    ]);
    const out = await client.evidencePack.get({ packId: VALID_PACK_ID });
    expect(out.bundles).toEqual([]);
  });

  it("forwards x-api-key + Accept headers (GET, no body)", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: {
          success: true,
          data: { pack: MOCK_PACK, bundles: [] },
        },
      },
    ]);
    await client.evidencePack.get({ packId: VALID_PACK_ID });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.get — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.get — input validation (pre-fetch)", () => {
  it("throws TypeError for null input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.get(null as unknown as GetEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.get(undefined as unknown as GetEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.get(42 as unknown as GetEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.get([] as unknown as GetEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is missing", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.get({} as unknown as GetEvidencePackInput),
    ).toThrowError(/`packId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.get({
        packId: undefined as unknown as string,
      }),
    ).toThrowError(/`packId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string packId (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.get({
        packId: 42 as unknown as string,
      }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty string packId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.evidencePack.get({ packId: "" })).toThrowError(
      /`packId` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for malformed packId UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.get({ packId: "not-a-uuid" }),
    ).toThrowError(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.get — response validation (P2)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.get — response validation (P2)", () => {
  async function callWithBadResponse(data: unknown) {
    const { client } = makeMockedClient([
      { body: { success: true, data } },
    ]);
    return client.evidencePack.get({ packId: VALID_PACK_ID });
  }

  it("rejects when response is null", async () => {
    await expect(callWithBadResponse(null)).rejects.toBeInstanceOf(
      AttestryError,
    );
  });

  it("rejects when response is an array", async () => {
    await expect(callWithBadResponse([])).rejects.toThrow(
      /expected an object response from the kernel/,
    );
  });

  it("rejects when response is a primitive", async () => {
    await expect(callWithBadResponse("nope")).rejects.toThrow(
      /expected an object response from the kernel/,
    );
  });

  it("rejects when pack is missing", async () => {
    await expect(
      callWithBadResponse({ bundles: [] }),
    ).rejects.toThrow(/response\.pack to be an object/);
  });

  it("rejects when pack is not an object", async () => {
    await expect(
      callWithBadResponse({ pack: "nope", bundles: [] }),
    ).rejects.toThrow(/response\.pack to be an object/);
  });

  it("rejects when pack has a wrong field type", async () => {
    await expect(
      callWithBadResponse({
        pack: { ...MOCK_PACK, id: 42 },
        bundles: [],
      }),
    ).rejects.toThrow(/response\.pack\.id to be a string/);
  });

  it("rejects when bundles is missing", async () => {
    await expect(callWithBadResponse({ pack: MOCK_PACK })).rejects.toThrow(
      /response\.bundles to be an array/,
    );
  });

  it("rejects when bundles is not an array", async () => {
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: "no" }),
    ).rejects.toThrow(/response\.bundles to be an array/);
  });

  it("rejects when bundles is null", async () => {
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: null }),
    ).rejects.toThrow(/response\.bundles to be an array/);
  });

  it("rejects when bundles[i] is null", async () => {
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: [null] }),
    ).rejects.toThrow(/response\.bundles\[0\] to be an object/);
  });

  it("rejects when bundles[i] is an array", async () => {
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: [[]] }),
    ).rejects.toThrow(/response\.bundles\[0\] to be an object/);
  });

  it("rejects when bundles[i] is missing id", async () => {
    const { id: _id, ...rest } = MOCK_BUNDLE;
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: [rest] }),
    ).rejects.toThrow(/response\.bundles\[0\]\.id to be a string/);
  });

  it("rejects when bundles[i].evidencePackId is wrong type", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, evidencePackId: 42 }],
      }),
    ).rejects.toThrow(/response\.bundles\[0\]\.evidencePackId to be a string/);
  });

  it("rejects when bundles[i].inputsHash is wrong type", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, inputsHash: 42 }],
      }),
    ).rejects.toThrow(/response\.bundles\[0\]\.inputsHash to be a string/);
  });

  it("rejects when bundles[i].outputsHash is wrong type", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, outputsHash: 42 }],
      }),
    ).rejects.toThrow(/response\.bundles\[0\]\.outputsHash to be a string/);
  });

  it("rejects when bundles[i].createdAt is wrong type", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, createdAt: 42 }],
      }),
    ).rejects.toThrow(/response\.bundles\[0\]\.createdAt to be a string/);
  });

  it("rejects when bundles[i].storageUri is a number (not string-or-null)", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, storageUri: 42 }],
      }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.storageUri to be a string or null/,
    );
  });

  it("rejects when bundles[i].storageUri is missing (own-property false)", async () => {
    // Round 4 coverage pin: exercises the `: undefined` else-branch of
    // `objectHasOwn(obj, "storageUri") ? obj.storageUri : undefined`.
    const { storageUri: _s, ...rest } = MOCK_BUNDLE;
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: [rest] }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.storageUri to be a string or null/,
    );
  });

  it("accepts bundles[i].storageUri = string", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            pack: MOCK_PACK,
            bundles: [{ ...MOCK_BUNDLE, storageUri: "https://example.com/x" }],
          },
        },
      },
    ]);
    const out = await client.evidencePack.get({ packId: VALID_PACK_ID });
    expect(out.bundles[0].storageUri).toBe("https://example.com/x");
  });

  it("rejects when bundles[i].traceContent is not an array", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, traceContent: {} }],
      }),
    ).rejects.toThrow(/response\.bundles\[0\]\.traceContent to be an array/);
  });

  it("rejects when bundles[i].traceContent is missing (own-property false)", async () => {
    // Round 4 coverage pin: exercises the `: undefined` else-branch of
    // `objectHasOwn(obj, "traceContent") ? obj.traceContent : undefined`.
    const { traceContent: _t, ...rest } = MOCK_BUNDLE;
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: [rest] }),
    ).rejects.toThrow(/response\.bundles\[0\]\.traceContent to be an array/);
  });

  it("rejects when bundles[i].modelBehaviorLog is an array", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, modelBehaviorLog: [] }],
      }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.modelBehaviorLog to be an object or null/,
    );
  });

  it("rejects when bundles[i].modelBehaviorLog is a string", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, modelBehaviorLog: "x" }],
      }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.modelBehaviorLog to be an object or null/,
    );
  });

  it("accepts bundles[i].modelBehaviorLog = populated object", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            pack: MOCK_PACK,
            bundles: [
              {
                ...MOCK_BUNDLE,
                modelBehaviorLog: { model: "opus", version: "4.7" },
                corroborationResults: { fooScore: 0.9 },
              },
            ],
          },
        },
      },
    ]);
    const out = await client.evidencePack.get({ packId: VALID_PACK_ID });
    expect(out.bundles[0].modelBehaviorLog).toEqual({
      model: "opus",
      version: "4.7",
    });
    expect(out.bundles[0].corroborationResults).toEqual({ fooScore: 0.9 });
  });

  it("rejects when bundles[i].corroborationResults is an array", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, corroborationResults: [] }],
      }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.corroborationResults to be an object or null/,
    );
  });

  it("accepts bundles[i] with both modelBehaviorLog AND corroborationResults missing (own-property false on both loop iterations)", async () => {
    // Round 4 coverage pin: exercises the `: undefined` else-branch of
    // the `for (const key of ["modelBehaviorLog", "corroborationResults"])`
    // loop ternary. Both fields are nullable (object | null), so the
    // undefined fallthrough lands on the `v !== null && (typeof v !==
    // "object" || ...)` check — since undefined !== null AND typeof
    // undefined !== "object", the check throws.
    const { modelBehaviorLog: _m, corroborationResults: _c, ...rest } =
      MOCK_BUNDLE;
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: [rest] }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.modelBehaviorLog to be an object or null/,
    );
  });

  it("rejects when bundles[i].metadata is null", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, metadata: null }],
      }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.metadata to be a non-null object/,
    );
  });

  it("rejects when bundles[i].metadata is an array", async () => {
    await expect(
      callWithBadResponse({
        pack: MOCK_PACK,
        bundles: [{ ...MOCK_BUNDLE, metadata: [] }],
      }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.metadata to be a non-null object/,
    );
  });

  it("rejects when bundles[i].metadata is missing (own-property false)", async () => {
    // Round 4 coverage pin: exercises the `: undefined` else-branch of
    // the single `objectHasOwn(obj, "metadata") ? obj.metadata : undefined`
    // ternary in validateBundle (the bundle's metadata is non-loop,
    // distinct from the pack's metadata loop iteration).
    const { metadata: _m, ...rest } = MOCK_BUNDLE;
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, bundles: [rest] }),
    ).rejects.toThrow(
      /response\.bundles\[0\]\.metadata to be a non-null object/,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.get — error mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.get — error mapping", () => {
  it("surfaces 404 (pack not found OR cross-org) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: {
          success: false,
          error: "pack not found",
          details: { code: "evidence_pack.not_found" },
        },
      },
    ]);
    try {
      await client.evidencePack.get({ packId: VALID_PACK_ID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
    }
  });

  it("surfaces 400 (invalid path UUID) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      { status: 400, body: { success: false, error: "Invalid pack id." } },
    ]);
    await expect(
      client.evidencePack.get({ packId: VALID_PACK_ID }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 401 / 403 / 500 as AttestryAPIError", async () => {
    for (const status of [401, 403, 500]) {
      const { client } = makeMockedClient([
        { status, body: { success: false, error: "x" } },
      ]);
      await expect(
        client.evidencePack.get({ packId: VALID_PACK_ID }),
      ).rejects.toBeInstanceOf(AttestryAPIError);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.list — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.list — happy path", () => {
  it("GETs /api/v1/evidence-packs with no args (no query string)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [MOCK_PACK], nextCursor: null } } },
    ]);
    const out = await client.evidencePack.list();
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/evidence-packs");
    expect(url.search).toBe("");
    expect(out.items).toEqual([MOCK_PACK]);
    expect(out.nextCursor).toBeNull();
  });

  it("GETs with all 5 filters serialized into query string", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.evidencePack.list({
      systemId: VALID_UUID,
      packType: "red_team_cycle",
      status: "signed",
      limit: 25,
      cursor: "opaque-cursor-abc",
    });
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/evidence-packs");
    expect(url.searchParams.get("systemId")).toBe(VALID_UUID);
    expect(url.searchParams.get("packType")).toBe("red_team_cycle");
    expect(url.searchParams.get("status")).toBe("signed");
    expect(url.searchParams.get("limit")).toBe("25");
    expect(url.searchParams.get("cursor")).toBe("opaque-cursor-abc");
  });

  it("returns nextCursor when more pages remain", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { items: [MOCK_PACK], nextCursor: "next-page-cursor" },
        },
      },
    ]);
    const out = await client.evidencePack.list();
    expect(out.nextCursor).toBe("next-page-cursor");
  });

  it("returns an empty items array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    const out = await client.evidencePack.list({ systemId: VALID_UUID });
    expect(out.items).toEqual([]);
  });

  it("treats own-present-but-undefined fields as omitted (no query value emitted)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.evidencePack.list({
      systemId: undefined,
      packType: undefined,
      status: undefined,
      limit: undefined,
      cursor: undefined,
    });
    const url = new URL(calls[0].url);
    expect(url.search).toBe("");
  });

  it("round-trips all 5 packType filter values", async () => {
    for (const pt of PACK_TYPES) {
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: { items: [], nextCursor: null } } },
      ]);
      await client.evidencePack.list({ packType: pt });
      const url = new URL(calls[0].url);
      expect(url.searchParams.get("packType")).toBe(pt);
    }
  });

  it("round-trips all 5 status filter values", async () => {
    for (const s of PACK_STATUSES) {
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: { items: [], nextCursor: null } } },
      ]);
      await client.evidencePack.list({ status: s });
      const url = new URL(calls[0].url);
      expect(url.searchParams.get("status")).toBe(s);
    }
  });

  it("accepts limit = 1 (minimum)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.evidencePack.list({ limit: 1 });
    const url = new URL(calls[0].url);
    expect(url.searchParams.get("limit")).toBe("1");
  });

  it("accepts limit = 200 (maximum)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.evidencePack.list({ limit: 200 });
    const url = new URL(calls[0].url);
    expect(url.searchParams.get("limit")).toBe("200");
  });

  it("forwards x-api-key + Accept headers (GET, no body)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    await client.evidencePack.list();
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.list — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.list — input validation (pre-fetch)", () => {
  it("throws TypeError for null input (explicit)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list(null as unknown as ListEvidencePacksInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list(42 as unknown as ListEvidencePacksInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list([] as unknown as ListEvidencePacksInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string systemId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({
        systemId: 42 as unknown as string,
      }),
    ).toThrowError(/`systemId` must be a string when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for malformed systemId UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({ systemId: "not-a-uuid" }),
    ).toThrowError(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string packType filter", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({
        packType: 42 as unknown as "annex_iv",
      }),
    ).toThrowError(/`packType` must be a string when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown packType value (closed-enum)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({
        packType: "bogus" as unknown as "annex_iv",
      }),
    ).toThrowError(/`packType` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string status filter", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({
        status: 42 as unknown as "draft",
      }),
    ).toThrowError(/`status` must be a string when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown status value (closed-enum)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({
        status: "bogus" as unknown as "draft",
      }),
    ).toThrowError(/`status` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-number limit", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({ limit: "50" as unknown as number }),
    ).toThrowError(/`limit` must be a number when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-integer limit (1.5)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({ limit: 1.5 }),
    ).toThrowError(/`limit` must be a finite integer/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for NaN limit", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({ limit: Number.NaN }),
    ).toThrowError(/`limit` must be a finite integer/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for limit = 0 (below min)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.evidencePack.list({ limit: 0 })).toThrowError(
      /`limit` must be in the range \[1, 200\]/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for limit = -1", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.evidencePack.list({ limit: -1 })).toThrowError(
      /`limit` must be in the range \[1, 200\]/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for limit = 201 (above max)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.evidencePack.list({ limit: 201 })).toThrowError(
      /`limit` must be in the range \[1, 200\]/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string cursor", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.list({ cursor: 42 as unknown as string }),
    ).toThrowError(/`cursor` must be a string when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty-string cursor", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.evidencePack.list({ cursor: "" })).toThrowError(
      /`cursor` must be a non-empty string when provided/,
    );
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.list — response validation (P2)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.list — response validation (P2)", () => {
  async function callWithBadResponse(data: unknown) {
    const { client } = makeMockedClient([
      { body: { success: true, data } },
    ]);
    return client.evidencePack.list();
  }

  it("rejects when response is null", async () => {
    await expect(callWithBadResponse(null)).rejects.toBeInstanceOf(
      AttestryError,
    );
  });

  it("rejects when response is an array", async () => {
    await expect(callWithBadResponse([])).rejects.toThrow(
      /expected an object response from the kernel/,
    );
  });

  it("rejects when response is a primitive", async () => {
    await expect(callWithBadResponse("x")).rejects.toThrow(
      /expected an object response from the kernel/,
    );
  });

  it("rejects when items is missing", async () => {
    await expect(
      callWithBadResponse({ nextCursor: null }),
    ).rejects.toThrow(/response\.items to be an array/);
  });

  it("rejects when items is not an array", async () => {
    await expect(
      callWithBadResponse({ items: "no", nextCursor: null }),
    ).rejects.toThrow(/response\.items to be an array/);
  });

  it("rejects when items[i] is not an object", async () => {
    await expect(
      callWithBadResponse({ items: ["not-an-object"], nextCursor: null }),
    ).rejects.toThrow(/response\.items\[0\] to be an object/);
  });

  it("rejects when items[i] is missing a required field", async () => {
    const { id: _id, ...rest } = MOCK_PACK;
    await expect(
      callWithBadResponse({ items: [rest], nextCursor: null }),
    ).rejects.toThrow(/response\.items\[0\]\.id to be a string/);
  });

  it("rejects when nextCursor is a number (not string-or-null)", async () => {
    await expect(
      callWithBadResponse({ items: [], nextCursor: 42 }),
    ).rejects.toThrow(/response\.nextCursor to be a string or null/);
  });

  it("rejects when nextCursor is missing", async () => {
    await expect(callWithBadResponse({ items: [] })).rejects.toThrow(
      /response\.nextCursor to be a string or null/,
    );
  });

  it("accepts nextCursor = null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { items: [], nextCursor: null } } },
    ]);
    const out = await client.evidencePack.list();
    expect(out.nextCursor).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.list — error mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.list — error mapping", () => {
  it("surfaces 400 (invalid_cursor) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 400,
        body: {
          success: false,
          error: "Invalid cursor.",
          details: { code: "evidence_pack.invalid_cursor" },
        },
      },
    ]);
    await expect(client.evidencePack.list()).rejects.toBeInstanceOf(
      AttestryAPIError,
    );
  });

  it("surfaces 422 (validation_failed) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Invalid query parameters.",
          details: { code: "evidence_pack.validation_failed" },
        },
      },
    ]);
    await expect(client.evidencePack.list()).rejects.toBeInstanceOf(
      AttestryAPIError,
    );
  });

  it("surfaces 401 / 403 / 500 as AttestryAPIError", async () => {
    for (const status of [401, 403, 500]) {
      const { client } = makeMockedClient([
        { status, body: { success: false, error: "x" } },
      ]);
      await expect(client.evidencePack.list()).rejects.toBeInstanceOf(
        AttestryAPIError,
      );
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.addBundle — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.addBundle — happy path", () => {
  it("POSTs /api/v1/evidence-packs/{id}/bundles with a minimal body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
    ]);
    const out = await client.evidencePack.addBundle({
      packId: VALID_PACK_ID,
      traceContent: [{ action: "ingest", timestamp: "2026-05-18T12:00:00Z" }],
      inputsHash: "sha256:" + "0".repeat(64),
      outputsHash: "sha256:" + "1".repeat(64),
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe(
      `/api/v1/evidence-packs/${VALID_PACK_ID}/bundles`,
    );
    expect(url.search).toBe("");
    const parsed = JSON.parse(calls[0].body!);
    // packId rides the URL path, NOT the body.
    expect(parsed).not.toHaveProperty("packId");
    expect(parsed.traceContent).toHaveLength(1);
    expect(parsed.inputsHash).toBe("sha256:" + "0".repeat(64));
    expect(parsed.outputsHash).toBe("sha256:" + "1".repeat(64));
    expect(out).toEqual(MOCK_ADD_BUNDLE_RESPONSE);
  });

  it("POSTs with all 4 optional fields when fully provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
    ]);
    await client.evidencePack.addBundle({
      packId: VALID_PACK_ID,
      traceContent: [],
      inputsHash: "h1",
      outputsHash: "h2",
      modelBehaviorLog: { model: "opus", version: "4.7" },
      corroborationResults: { fooScore: 0.9 },
      storageUri: "https://example.com/blob",
      metadata: { run: 1 },
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.modelBehaviorLog).toEqual({ model: "opus", version: "4.7" });
    expect(parsed.corroborationResults).toEqual({ fooScore: 0.9 });
    expect(parsed.storageUri).toBe("https://example.com/blob");
    expect(parsed.metadata).toEqual({ run: 1 });
  });

  it("omits optional fields from the body when consumer omits them", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
    ]);
    await client.evidencePack.addBundle({
      packId: VALID_PACK_ID,
      traceContent: [],
      inputsHash: "h1",
      outputsHash: "h2",
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.keys(parsed).sort()).toEqual(
      ["traceContent", "inputsHash", "outputsHash"].sort(),
    );
  });

  it("treats own-present-but-undefined optionals as omitted", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
    ]);
    await client.evidencePack.addBundle({
      packId: VALID_PACK_ID,
      traceContent: [],
      inputsHash: "h1",
      outputsHash: "h2",
      modelBehaviorLog: undefined,
      corroborationResults: undefined,
      storageUri: undefined,
      metadata: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.keys(parsed).sort()).toEqual(
      ["traceContent", "inputsHash", "outputsHash"].sort(),
    );
  });

  it("forwards x-api-key + Accept + Content-Type headers (POST with body)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
    ]);
    await client.evidencePack.addBundle({
      packId: VALID_PACK_ID,
      traceContent: [],
      inputsHash: "h1",
      outputsHash: "h2",
    });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("surfaces hashCollision shape (detected: true, count > 0)", async () => {
    const colliding: AddBundleResponse = {
      ...MOCK_ADD_BUNDLE_RESPONSE,
      hashCollision: {
        detected: true,
        count: 3,
        collidingBundleIds: [VALID_BUNDLE_ID, VALID_UUID],
      },
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: colliding } },
    ]);
    const out = await client.evidencePack.addBundle({
      packId: VALID_PACK_ID,
      traceContent: [],
      inputsHash: "h1",
      outputsHash: "h2",
    });
    expect(out.hashCollision.detected).toBe(true);
    expect(out.hashCollision.count).toBe(3);
    expect(out.hashCollision.collidingBundleIds).toHaveLength(2);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.addBundle — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.addBundle — input validation (pre-fetch)", () => {
  const MIN_VALID: AddBundleInput = {
    packId: VALID_PACK_ID,
    traceContent: [],
    inputsHash: "h1",
    outputsHash: "h2",
  };

  it("throws TypeError for null input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle(null as unknown as AddBundleInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle("nope" as unknown as AddBundleInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle([] as unknown as AddBundleInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is missing", () => {
    const { client, calls } = makeMockedClient([]);
    const { packId: _p, ...rest } = MIN_VALID;
    expect(() =>
      client.evidencePack.addBundle(rest as unknown as AddBundleInput),
    ).toThrowError(/`packId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        packId: undefined as unknown as string,
      }),
    ).toThrowError(/`packId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string packId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        packId: 42 as unknown as string,
      }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty packId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, packId: "" }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for malformed packId UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, packId: "bad" }),
    ).toThrowError(/must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when traceContent is missing", () => {
    const { client, calls } = makeMockedClient([]);
    const { traceContent: _t, ...rest } = MIN_VALID;
    expect(() =>
      client.evidencePack.addBundle(rest as unknown as AddBundleInput),
    ).toThrowError(/`traceContent` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when traceContent is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        traceContent: undefined as unknown as unknown[],
      }),
    ).toThrowError(/`traceContent` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-array traceContent", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        traceContent: { 0: "x" } as unknown as unknown[],
      }),
    ).toThrowError(/`traceContent` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when traceContent exceeds 1000 entries", () => {
    const { client, calls } = makeMockedClient([]);
    const big = Array.from({ length: 1001 }, () => ({}));
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, traceContent: big }),
    ).toThrowError(/exceeds the kernel's max length of 1000/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when inputsHash is missing", () => {
    const { client, calls } = makeMockedClient([]);
    const { inputsHash: _i, ...rest } = MIN_VALID;
    expect(() =>
      client.evidencePack.addBundle(rest as unknown as AddBundleInput),
    ).toThrowError(/`inputsHash` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when inputsHash is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        inputsHash: undefined as unknown as string,
      }),
    ).toThrowError(/`inputsHash` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string inputsHash", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        inputsHash: 42 as unknown as string,
      }),
    ).toThrowError(/`inputsHash` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty inputsHash", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, inputsHash: "" }),
    ).toThrowError(/`inputsHash` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when inputsHash exceeds 500 chars", () => {
    const { client, calls } = makeMockedClient([]);
    const big = "a".repeat(501);
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, inputsHash: big }),
    ).toThrowError(/`inputsHash` exceeds the maximum length of 500/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when outputsHash is missing", () => {
    const { client, calls } = makeMockedClient([]);
    const { outputsHash: _o, ...rest } = MIN_VALID;
    expect(() =>
      client.evidencePack.addBundle(rest as unknown as AddBundleInput),
    ).toThrowError(/`outputsHash` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when outputsHash is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        outputsHash: undefined as unknown as string,
      }),
    ).toThrowError(/`outputsHash` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string outputsHash", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        outputsHash: 42 as unknown as string,
      }),
    ).toThrowError(/`outputsHash` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty outputsHash", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, outputsHash: "" }),
    ).toThrowError(/`outputsHash` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when outputsHash exceeds 500 chars", () => {
    const { client, calls } = makeMockedClient([]);
    const big = "b".repeat(501);
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, outputsHash: big }),
    ).toThrowError(/`outputsHash` exceeds the maximum length of 500/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for null modelBehaviorLog", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        modelBehaviorLog: null as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`modelBehaviorLog` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array modelBehaviorLog", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        modelBehaviorLog: [] as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`modelBehaviorLog` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object modelBehaviorLog (string)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        modelBehaviorLog: "bad" as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`modelBehaviorLog` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for null corroborationResults", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        corroborationResults: null as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`corroborationResults` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array corroborationResults", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        corroborationResults: [] as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`corroborationResults` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object corroborationResults (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        corroborationResults: 42 as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`corroborationResults` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string storageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        storageUri: 42 as unknown as string,
      }),
    ).toThrowError(/`storageUri` must be a string when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty storageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, storageUri: "" }),
    ).toThrowError(/`storageUri` must be a non-empty string when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when storageUri exceeds 2000 chars", () => {
    const { client, calls } = makeMockedClient([]);
    const big = "https://example.com/" + "a".repeat(2000);
    expect(() =>
      client.evidencePack.addBundle({ ...MIN_VALID, storageUri: big }),
    ).toThrowError(/`storageUri` exceeds the maximum length of 2000/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for null metadata", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        metadata: null as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`metadata` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array metadata", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        metadata: [] as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`metadata` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object metadata (boolean)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.addBundle({
        ...MIN_VALID,
        metadata: true as unknown as Record<string, unknown>,
      }),
    ).toThrowError(/`metadata` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.addBundle — response validation (P2)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.addBundle — response validation (P2)", () => {
  async function callWithBadResponse(data: unknown) {
    const { client } = makeMockedClient([
      { body: { success: true, data } },
    ]);
    return client.evidencePack.addBundle({
      packId: VALID_PACK_ID,
      traceContent: [],
      inputsHash: "h1",
      outputsHash: "h2",
    });
  }

  it("rejects when response is null", async () => {
    await expect(callWithBadResponse(null)).rejects.toBeInstanceOf(
      AttestryError,
    );
  });

  it("rejects when response is an array", async () => {
    await expect(callWithBadResponse([])).rejects.toThrow(
      /expected an object response from the kernel/,
    );
  });

  it("rejects when response is a primitive", async () => {
    await expect(callWithBadResponse(42)).rejects.toThrow(
      /expected an object response from the kernel/,
    );
  });

  it("rejects when bundle is missing", async () => {
    await expect(
      callWithBadResponse({ pack: MOCK_PACK, hashCollision: { detected: false, count: 0, collidingBundleIds: [] } }),
    ).rejects.toThrow(/response\.bundle to be an object/);
  });

  it("rejects when bundle has wrong field type", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        bundle: { ...MOCK_BUNDLE, id: 42 },
      }),
    ).rejects.toThrow(/response\.bundle\.id to be a string/);
  });

  it("rejects when pack is missing", async () => {
    await expect(
      callWithBadResponse({
        bundle: MOCK_BUNDLE,
        hashCollision: { detected: false, count: 0, collidingBundleIds: [] },
      }),
    ).rejects.toThrow(/response\.pack to be an object/);
  });

  it("rejects when pack has wrong field type", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        pack: { ...MOCK_PACK, id: 42 },
      }),
    ).rejects.toThrow(/response\.pack\.id to be a string/);
  });

  it("rejects when hashCollision is missing", async () => {
    await expect(
      callWithBadResponse({ bundle: MOCK_BUNDLE, pack: MOCK_PACK }),
    ).rejects.toThrow(/response\.hashCollision to be an object/);
  });

  it("rejects when hashCollision is not an object (string)", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        hashCollision: "no",
      }),
    ).rejects.toThrow(/response\.hashCollision to be an object/);
  });

  it("rejects when hashCollision is null", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_ADD_BUNDLE_RESPONSE, hashCollision: null }),
    ).rejects.toThrow(/response\.hashCollision to be an object/);
  });

  it("rejects when hashCollision is an array", async () => {
    await expect(
      callWithBadResponse({ ...MOCK_ADD_BUNDLE_RESPONSE, hashCollision: [] }),
    ).rejects.toThrow(/response\.hashCollision to be an object/);
  });

  it("rejects when hashCollision.detected is not a boolean", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        hashCollision: { detected: "no", count: 0, collidingBundleIds: [] },
      }),
    ).rejects.toThrow(/response\.hashCollision\.detected to be a boolean/);
  });

  it("rejects when hashCollision.detected is missing", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        hashCollision: { count: 0, collidingBundleIds: [] },
      }),
    ).rejects.toThrow(/response\.hashCollision\.detected to be a boolean/);
  });

  it("rejects when hashCollision.count is not a number", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        hashCollision: { detected: false, count: "0", collidingBundleIds: [] },
      }),
    ).rejects.toThrow(/response\.hashCollision\.count to be a number/);
  });

  it("rejects when hashCollision.count is missing", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        hashCollision: { detected: false, collidingBundleIds: [] },
      }),
    ).rejects.toThrow(/response\.hashCollision\.count to be a number/);
  });

  it("rejects when hashCollision.collidingBundleIds is not an array", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        hashCollision: { detected: false, count: 0, collidingBundleIds: {} },
      }),
    ).rejects.toThrow(
      /response\.hashCollision\.collidingBundleIds to be an array/,
    );
  });

  it("rejects when hashCollision.collidingBundleIds is missing", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        hashCollision: { detected: false, count: 0 },
      }),
    ).rejects.toThrow(
      /response\.hashCollision\.collidingBundleIds to be an array/,
    );
  });

  it("rejects when hashCollision.collidingBundleIds[i] is not a string", async () => {
    await expect(
      callWithBadResponse({
        ...MOCK_ADD_BUNDLE_RESPONSE,
        hashCollision: {
          detected: true,
          count: 1,
          collidingBundleIds: [42],
        },
      }),
    ).rejects.toThrow(
      /response\.hashCollision\.collidingBundleIds\[0\] to be a string/,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.addBundle — error mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.addBundle — error mapping", () => {
  it("surfaces 404 (pack not found / cross-org) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: {
          success: false,
          error: "pack not found",
          details: { code: "evidence_pack.not_found" },
        },
      },
    ]);
    await expect(
      client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: [],
        inputsHash: "h1",
        outputsHash: "h2",
      }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 409 (invalid_state) as AttestryAPIError with details.currentStatus", async () => {
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: "Pack is signed; cannot append bundles.",
          details: {
            code: "evidence_pack.invalid_state",
            currentStatus: "signed",
          },
        },
      },
    ]);
    try {
      await client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: [],
        inputsHash: "h1",
        outputsHash: "h2",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(409);
      const detail = apiErr.details as {
        details?: { code?: string; currentStatus?: string };
      };
      expect(detail.details?.code).toBe("evidence_pack.invalid_state");
      expect(detail.details?.currentStatus).toBe("signed");
    }
  });

  it("surfaces 413 (payload_too_large) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 413,
        body: {
          success: false,
          error: "Canonical bundle list exceeds size limit.",
          details: { code: "evidence_pack.payload_too_large" },
        },
      },
    ]);
    await expect(
      client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: [],
        inputsHash: "h1",
        outputsHash: "h2",
      }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 422 (validation_failed) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: {
            code: "evidence_pack.validation_failed",
            issues: [{ path: "traceContent.0.action", message: "Required" }],
          },
        },
      },
    ]);
    await expect(
      client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: [],
        inputsHash: "h1",
        outputsHash: "h2",
      }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 400 / 401 / 403 / 500 as AttestryAPIError", async () => {
    for (const status of [400, 401, 403, 500]) {
      const { client } = makeMockedClient([
        { status, body: { success: false, error: "x" } },
      ]);
      await expect(
        client.evidencePack.addBundle({
          packId: VALID_PACK_ID,
          traceContent: [],
          inputsHash: "h1",
          outputsHash: "h2",
        }),
      ).rejects.toBeInstanceOf(AttestryAPIError);
    }
  });

  it("HR-4(b) confirmation: non-JSON 200 surfaces as AttestryAPIError", async () => {
    const mockFetch: FetchLike = async () =>
      new Response("plain-text-body", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    await expect(
      client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: [],
        inputsHash: "h1",
        outputsHash: "h2",
      }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.addBundle — abort signal
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.addBundle — abort signal", () => {
  it("rejects synchronously when caller's AbortSignal is pre-aborted", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("cancelled"));
    await expect(
      client.evidencePack.addBundle(
        {
          packId: VALID_PACK_ID,
          traceContent: [],
          inputsHash: "h1",
          outputsHash: "h2",
        },
        { signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(AttestryError);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Round 3 — Hostile probes (defense confirmation; no source change expected)
// ═══════════════════════════════════════════════════════════════════════════
//
// Each probe exercises a hostile-input defense documented in the
// `evidence-pack.ts` header comment AND confirms it holds against a
// directly-adversarial input. Probes follow the categorization the
// P1.4 / P1.5 hostile rounds established (H-P16-1 .. H-P16-8); a probe
// failing here is a load-bearing defense gap requiring a source change.

describe("evidencePack — Round 3 hostile probes (H-P16-1..8)", () => {
  // ─── H-P16-1: prototype-pollution defense via objectHasOwn snapshot ────────
  describe("H-P16-1: Object.prototype pollution does not bypass own-property checks", () => {
    afterEach(() => {
      // Always clean up any prototype pollution from these probes —
      // otherwise it leaks into sibling tests.
      delete (Object.prototype as Record<string, unknown>).packType;
      delete (Object.prototype as Record<string, unknown>).systemId;
      delete (Object.prototype as Record<string, unknown>).packId;
      delete (Object.prototype as Record<string, unknown>).traceContent;
      delete (Object.prototype as Record<string, unknown>).inputsHash;
      delete (Object.prototype as Record<string, unknown>).outputsHash;
    });

    it("`Object.prototype.packType` does not trick create({}) into sending the polluted value", () => {
      (Object.prototype as Record<string, unknown>).packType = "annex_iv";
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.create({} as unknown as CreateEvidencePackInput),
      ).toThrowError(/`packType` is required/);
      expect(calls).toHaveLength(0);
    });

    it("`Object.prototype.packId` does not trick get({}) into sending the polluted value", () => {
      (Object.prototype as Record<string, unknown>).packId = VALID_PACK_ID;
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.get({} as unknown as GetEvidencePackInput),
      ).toThrowError(/`packId` is required/);
      expect(calls).toHaveLength(0);
    });

    it("`Object.prototype.traceContent` does not trick addBundle into omitting traceContent validation", () => {
      (Object.prototype as Record<string, unknown>).traceContent = [];
      (Object.prototype as Record<string, unknown>).inputsHash = "h1";
      (Object.prototype as Record<string, unknown>).outputsHash = "h2";
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.addBundle({
          packId: VALID_PACK_ID,
        } as unknown as AddBundleInput),
      ).toThrowError(/`traceContent` is required/);
      expect(calls).toHaveLength(0);
    });
  });

  // ─── H-P16-2: late Object.hasOwn override doesn't defeat module-load snapshot
  describe("H-P16-2: monkey-patched Object.hasOwn does not defeat the module-load snapshot", () => {
    // Capture the ORIGINAL Object.hasOwn ONCE at describe-block entry
    // (BEFORE any test in this block patches it). Sub-agent hostile
    // redux F-HR1-2: an earlier draft did
    //   `Object.hasOwn = Object.getPrototypeOf({}).constructor.hasOwn;`
    // which evaluates to `Object.hasOwn = Object.hasOwn` (the polluted
    // value back onto itself — a no-op). The pollution would leak
    // across test files in the same Vitest run; cross-test isolation
    // would silently break.
    const ORIGINAL_OBJECT_HAS_OWN = Object.hasOwn;
    afterEach(() => {
      Object.hasOwn = ORIGINAL_OBJECT_HAS_OWN;
    });

    it("a hostile dep overriding Object.hasOwn = () => false does NOT make the SDK think own-properties are absent", async () => {
      // The SDK's `objectHasOwn = Object.hasOwn` snapshot is captured
      // at module load. If we replace globalThis.Object.hasOwn AFTER
      // the SDK is loaded, the snapshot is unaffected — the SDK
      // continues to read own-properties via the original
      // implementation.
      (Object as { hasOwn: typeof Object.hasOwn }).hasOwn = (() =>
        false) as typeof Object.hasOwn;
      const { client } = makeMockedClient([
        { body: { success: true, data: MOCK_PACK } },
      ]);
      // If the SDK were using the polluted Object.hasOwn, every
      // hasField check would return false; packType would be treated
      // as missing and the call would throw "packType is required".
      // The fact that the call succeeds confirms the snapshot defense.
      const out = await client.evidencePack.create({ packType: "annex_iv" });
      expect(out).toEqual(MOCK_PACK);
    });

    it("a hostile dep overriding Object.hasOwn = () => true does NOT make the SDK accept missing own-properties", () => {
      (Object as { hasOwn: typeof Object.hasOwn }).hasOwn = (() =>
        true) as typeof Object.hasOwn;
      const { client, calls } = makeMockedClient([]);
      // Sub-agent hostile redux F-HR1-3: this test passes whether the
      // SDK uses the module-load snapshot (returns false for
      // `objectHasOwn({}, "packType")` → throws on
      // `!hasPackType`) OR uses the polluted Object.hasOwn (returns
      // true → falls through to `packTypeRaw === undefined` →
      // throws on the second condition). Both defenses cause the
      // rejection; the test verifies that the rejection holds under
      // hostile override regardless of which defense fires.
      expect(() =>
        client.evidencePack.create({} as unknown as CreateEvidencePackInput),
      ).toThrowError(/`packType` is required/);
      expect(calls).toHaveLength(0);
    });

    it("packType own-present-but-undefined cleanly exercises the second-layer `=== undefined` defense (under hostile Object.hasOwn = () => true)", () => {
      // Sub-agent hostile redux F-HR1-3 — distinguishes the two
      // defenses. With `packType: undefined` (own-property PRESENT but
      // value undefined): the module-load snapshot returns true for
      // `objectHasOwn(input, "packType")`. The polluted runtime
      // Object.hasOwn would also return true. So `hasPackType = true`
      // either way. The throw fires on `packTypeRaw === undefined`
      // (the second-layer defense). This pin exercises specifically
      // the second-layer check, distinct from the snapshot defense.
      (Object as { hasOwn: typeof Object.hasOwn }).hasOwn = (() =>
        true) as typeof Object.hasOwn;
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.create({
          packType: undefined as unknown as "annex_iv",
        }),
      ).toThrowError(/`packType` is required/);
      expect(calls).toHaveLength(0);
    });
  });

  // ─── H-P16-3: closed-enum case sensitivity ─────────────────────────────────
  describe("H-P16-3: closed-enum values are case-sensitive (no normalization)", () => {
    it("packType `ANNEX_IV` (uppercase) is rejected — closed-enum check is case-sensitive", () => {
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.create({
          packType: "ANNEX_IV" as unknown as "annex_iv",
        }),
      ).toThrowError(/`packType` must be one of/);
      expect(calls).toHaveLength(0);
    });

    it("packType `Annex_IV` (mixed case) is rejected", () => {
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.create({
          packType: "Annex_IV" as unknown as "annex_iv",
        }),
      ).toThrowError(/`packType` must be one of/);
      expect(calls).toHaveLength(0);
    });

    it("status filter `DRAFT` (uppercase) is rejected on list", () => {
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.list({
          status: "DRAFT" as unknown as "draft",
        }),
      ).toThrowError(/`status` must be one of/);
      expect(calls).toHaveLength(0);
    });
  });

  // ─── H-P16-4: path-traversal defense ───────────────────────────────────────
  describe("H-P16-4: packId path-traversal candidates rejected at UUID regex", () => {
    it("rejects packId containing `/` (path injection attempt)", () => {
      const { client, calls } = makeMockedClient([]);
      const evil =
        "11111111-1111-1111-1111-111111111111/etc/passwd" as unknown as string;
      expect(() => client.evidencePack.get({ packId: evil })).toThrowError(
        /must be an RFC 4122/,
      );
      expect(calls).toHaveLength(0);
    });

    it("rejects packId containing `..` (path-traversal)", () => {
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.get({
          packId: "11111111-1111-1111-1111-111111111111..",
        }),
      ).toThrowError(/must be an RFC 4122/);
      expect(calls).toHaveLength(0);
    });

    it("rejects packId containing NUL byte", () => {
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.get({
          packId: "11111111-1111-1111-1111-111111111111\x00",
        }),
      ).toThrowError(/must be an RFC 4122/);
      expect(calls).toHaveLength(0);
    });

    it("rejects packId containing whitespace / newlines", () => {
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.get({
          packId: "11111111-1111-1111-1111-111111111111\n",
        }),
      ).toThrowError(/must be an RFC 4122/);
      expect(calls).toHaveLength(0);
    });

    it("rejects packId containing query-string injection (`?`)", () => {
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.addBundle({
          packId: "11111111-1111-1111-1111-111111111111?evil=1",
          traceContent: [],
          inputsHash: "h1",
          outputsHash: "h2",
        }),
      ).toThrowError(/must be an RFC 4122/);
      expect(calls).toHaveLength(0);
    });
  });

  // ─── H-P16-5: boundary values on length caps ───────────────────────────────
  describe("H-P16-5: boundary values on length / count caps", () => {
    it("traceContent length = 1000 (exactly at cap) accepted", async () => {
      const at_cap = Array.from({ length: 1000 }, () => ({}));
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
      ]);
      await client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: at_cap,
        inputsHash: "h1",
        outputsHash: "h2",
      });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed.traceContent).toHaveLength(1000);
    });

    it("inputsHash length = 500 (exactly at cap) accepted", async () => {
      const at_cap = "x".repeat(500);
      const { client } = makeMockedClient([
        { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
      ]);
      await client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: [],
        inputsHash: at_cap,
        outputsHash: "h2",
      });
      // No throw — accepted.
    });

    it("outputsHash length = 500 (exactly at cap) accepted", async () => {
      const at_cap = "y".repeat(500);
      const { client } = makeMockedClient([
        { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
      ]);
      await client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: [],
        inputsHash: "h1",
        outputsHash: at_cap,
      });
    });

    it("storageUri length = 2000 (exactly at cap) accepted", async () => {
      const at_cap = "https://" + "a".repeat(2000 - "https://".length);
      const { client } = makeMockedClient([
        { body: { success: true, data: MOCK_ADD_BUNDLE_RESPONSE } },
      ]);
      await client.evidencePack.addBundle({
        packId: VALID_PACK_ID,
        traceContent: [],
        inputsHash: "h1",
        outputsHash: "h2",
        storageUri: at_cap,
      });
    });

    it("frameworkBindings length = 50 (exactly at cap) accepted", async () => {
      const at_cap = Array.from({ length: 50 }, () => ({
        framework: "x",
        identifier: "y",
      }));
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: MOCK_PACK } },
      ]);
      await client.evidencePack.create({
        packType: "annex_iv",
        frameworkBindings: at_cap,
      });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed.frameworkBindings).toHaveLength(50);
    });

    it("limit = ±Infinity / NaN rejected via Number.isInteger", () => {
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.evidencePack.list({ limit: Number.POSITIVE_INFINITY }),
      ).toThrowError(/`limit` must be a finite integer/);
      expect(() =>
        client.evidencePack.list({ limit: Number.NEGATIVE_INFINITY }),
      ).toThrowError(/`limit` must be a finite integer/);
      expect(calls).toHaveLength(0);
    });
  });

  // ─── H-P16-6: forward-compat (typed-closed, runtime-open) ──────────────────
  describe("H-P16-6: kernel-emitted future enum values round-trip at runtime", () => {
    it("response packType = `future_pack_type` round-trips (typed-closed, runtime-open faithful courier)", async () => {
      const futurePack = {
        ...MOCK_PACK,
        packType: "future_pack_type",
      };
      const { client } = makeMockedClient([
        { body: { success: true, data: futurePack } },
      ]);
      const out = await client.evidencePack.create({ packType: "annex_iv" });
      // Runtime accepts the new value (typeof === "string"); the drift
      // pin would fire in CI BEFORE this regression reaches production.
      expect(out.packType).toBe("future_pack_type");
    });

    it("response status = `archived` (future kernel value) round-trips", async () => {
      const futurePack = {
        ...MOCK_PACK,
        status: "archived",
      };
      const { client } = makeMockedClient([
        { body: { success: true, data: futurePack } },
      ]);
      const out = await client.evidencePack.create({ packType: "annex_iv" });
      expect(out.status).toBe("archived");
    });
  });

  // ─── H-P16-7: TOCTOU defense via own-property snapshot ─────────────────────
  describe("H-P16-7: Proxy with shifting values does not bypass validation", () => {
    it("input.packType getter that flips values across reads is snapshotted ONCE", async () => {
      let readCount = 0;
      const input = new Proxy(
        {},
        {
          get(_target, prop) {
            if (prop === "packType") {
              readCount++;
              // First read: valid; second read: hostile.
              return readCount === 1 ? "annex_iv" : "EVIL";
            }
            return undefined;
          },
          has(_target, prop) {
            return prop === "packType";
          },
          getOwnPropertyDescriptor(_target, prop) {
            if (prop === "packType") {
              return {
                value: readCount === 0 ? "annex_iv" : "EVIL",
                writable: true,
                enumerable: true,
                configurable: true,
              };
            }
            return undefined;
          },
        },
      ) as unknown as CreateEvidencePackInput;
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: MOCK_PACK } },
      ]);
      await client.evidencePack.create(input);
      // The SDK reads input.packType EXACTLY ONCE (the snapshot to
      // `packTypeRaw`). Validation + body construction both use the
      // snapshot. A buggy SDK with a TOCTOU re-read would have:
      //   1st read (validation) → "annex_iv" (passes PACK_TYPES check)
      //   2nd read (body) → "EVIL" (sent over the wire)
      // — letting a hostile Proxy bypass validation. Pinning the
      // body's packType === "annex_iv" exactly confirms the snapshot
      // discipline holds. If the assertion were relaxed to
      // `expect(["annex_iv", "EVIL"]).toContain(...)`, this defect
      // class could regress silently.
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed.packType).toBe("annex_iv");
      // readCount === 1 means the Proxy's `get` trap fired ONCE
      // (the snapshot). A re-read would set readCount === 2.
      expect(readCount).toBe(1);
    });
  });

  // ─── H-P16-8: hostile transport — sibling-error pass-through ───────────────
  describe("H-P16-8: transport-layer abuse surfaces as AttestryError, not opaque", () => {
    it("a 502 with non-JSON HTML body surfaces as AttestryAPIError with details containing the raw text", async () => {
      // The SDK transport (transport.ts) already falls back to raw
      // text when the error body isn't JSON (hostile-review H1
      // carry-forward). Confirm the SDK propagates this cleanly.
      const mockFetch: FetchLike = async () =>
        new Response("<html>502 Bad Gateway</html>", {
          status: 502,
          headers: { "Content-Type": "text/html" },
        });
      const client = new AttestryClient({
        apiKey: "k",
        fetch: vi.fn(mockFetch) as unknown as FetchLike,
        baseUrl: "https://test.attestry.local",
        retry: { maxRetries: 0 },
      });
      let caught: unknown;
      try {
        await client.evidencePack.create({ packType: "annex_iv" });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(AttestryAPIError);
      expect((caught as AttestryAPIError).status).toBe(502);
      // The raw HTML body should be in details.
      const details = (caught as AttestryAPIError).details;
      expect(typeof details).toBe("string");
      expect(details).toContain("502 Bad Gateway");
    });

    it("a malformed JSON success body (200 + content-type JSON + broken JSON) surfaces cleanly", async () => {
      const mockFetch: FetchLike = async () =>
        new Response("{not-valid-json", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      const client = new AttestryClient({
        apiKey: "k",
        fetch: vi.fn(mockFetch) as unknown as FetchLike,
        baseUrl: "https://test.attestry.local",
        retry: { maxRetries: 0 },
      });
      // The transport reads the body via `readBody` which catches
      // JSON.parse failures and returns `parsed: null`. The transport's
      // 2xx unwrap then returns `null` (the envelope unwrap only fires
      // when parsed is a `{success: true, data}` object). The SDK's
      // P2 validator then rejects `result === null`.
      let caught: unknown;
      try {
        await client.evidencePack.create({ packType: "annex_iv" });
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(AttestryError);
      // Confirm it's NOT an unhandled SyntaxError leaking from JSON.parse.
      expect(caught).not.toBeInstanceOf(SyntaxError);
    });
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ═══ P1.8 — lifecycle/export methods (sign / supersede / revoke / export) ═══
// ═══════════════════════════════════════════════════════════════════════════

// ─── EXPORT_FORMATS closed-enum tuple ───────────────────────────────────────

describe("EXPORT_FORMATS — frozen closed-enum tuple", () => {
  it("is exactly [json, pdf, zip] in order", () => {
    expect([...EXPORT_FORMATS]).toEqual(["json", "pdf", "zip"]);
  });

  it("is frozen (Object.isFrozen) — blocks hostile/buggy mutation", () => {
    expect(Object.isFrozen(EXPORT_FORMATS)).toBe(true);
  });

  it("rejects a push mutation with TypeError (strict-mode frozen array)", () => {
    expect(() => {
      (EXPORT_FORMATS as unknown as string[]).push("evil");
    }).toThrowError(TypeError);
    expect([...EXPORT_FORMATS]).toEqual(["json", "pdf", "zip"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.sign — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.sign — happy path", () => {
  it("POSTs /{id}/sign with an empty JSON body when no cert is given", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_SIGNED } },
    ]);
    const out = await client.evidencePack.sign({ packId: VALID_PACK_ID });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe(`/api/v1/evidence-packs/${VALID_PACK_ID}/sign`);
    expect(url.search).toBe("");
    expect(JSON.parse(calls[0].body!)).toEqual({});
    expect(out).toEqual(MOCK_PACK_SIGNED);
  });

  it("POSTs with attestationCertificateId when provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_SIGNED } },
    ]);
    await client.evidencePack.sign({
      packId: VALID_PACK_ID,
      attestationCertificateId: VALID_UUID,
    });
    expect(JSON.parse(calls[0].body!)).toEqual({
      attestationCertificateId: VALID_UUID,
    });
  });

  it("treats own-present-but-undefined attestationCertificateId as omitted", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_SIGNED } },
    ]);
    await client.evidencePack.sign({
      packId: VALID_PACK_ID,
      attestationCertificateId: undefined,
    });
    expect(JSON.parse(calls[0].body!)).toEqual({});
  });

  it("forwards x-api-key + Accept + Content-Type headers", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_SIGNED } },
    ]);
    await client.evidencePack.sign({ packId: VALID_PACK_ID });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("encodeURIComponent-encodes the packId in the path", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_SIGNED } },
    ]);
    await client.evidencePack.sign({ packId: VALID_PACK_ID });
    expect(calls[0].url).toContain(
      `/api/v1/evidence-packs/${encodeURIComponent(VALID_PACK_ID)}/sign`,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.sign — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.sign — input validation (pre-fetch)", () => {
  it("throws TypeError for null input — no request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign(null as unknown as SignEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign(undefined as unknown as SignEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign("x" as unknown as SignEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign([] as unknown as SignEvidencePackInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is missing", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign({} as unknown as SignEvidencePackInput),
    ).toThrowError(/`packId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign({
        packId: undefined as unknown as string,
      }),
    ).toThrowError(/`packId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is not a string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign({ packId: 123 as unknown as string }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign({ packId: "" }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is not a UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign({ packId: "not-a-uuid" }),
    ).toThrowError(/`packId` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when attestationCertificateId is not a string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign({
        packId: VALID_PACK_ID,
        attestationCertificateId: 5 as unknown as string,
      }),
    ).toThrowError(/`attestationCertificateId` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when attestationCertificateId is not a UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign({
        packId: VALID_PACK_ID,
        attestationCertificateId: "bad",
      }),
    ).toThrowError(/`attestationCertificateId` must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.sign — response validation (P2)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.sign — response validation (P2)", () => {
  it("throws AttestryError when the response is not an object", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: "nope" } },
    ]);
    await expect(
      client.evidencePack.sign({ packId: VALID_PACK_ID }),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("throws AttestryError when a required pack field is missing", async () => {
    const { id: _id, ...packNoId } = MOCK_PACK_SIGNED;
    const { client } = makeMockedClient([
      { body: { success: true, data: packNoId } },
    ]);
    await expect(
      client.evidencePack.sign({ packId: VALID_PACK_ID }),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.sign — error mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.sign — error mapping", () => {
  it("surfaces 401 as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      { status: 401, body: { success: false, error: "Unauthorized." } },
    ]);
    await expect(
      client.evidencePack.sign({ packId: VALID_PACK_ID }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 403 (non-admin) as AttestryAPIError with status 403", async () => {
    const { client } = makeMockedClient([
      { status: 403, body: { success: false, error: "Forbidden." } },
    ]);
    try {
      await client.evidencePack.sign({ packId: VALID_PACK_ID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
    }
  });

  it("surfaces 409 InvalidStateError with details.currentStatus", async () => {
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: "pack is in 'signed' state; only draft packs can be signed",
          details: {
            code: "evidence_pack.invalid_state",
            currentStatus: "signed",
          },
        },
      },
    ]);
    try {
      await client.evidencePack.sign({ packId: VALID_PACK_ID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(409);
      const detail = apiErr.details as {
        details?: { code?: string; currentStatus?: string };
      };
      expect(detail.details?.code).toBe("evidence_pack.invalid_state");
      expect(detail.details?.currentStatus).toBe("signed");
    }
  });

  it("surfaces 409 EmptyPackError with details.code evidence_pack.empty (no currentStatus)", async () => {
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: "cannot sign an empty pack (no bundles attached)",
          details: { code: "evidence_pack.empty" },
        },
      },
    ]);
    try {
      await client.evidencePack.sign({ packId: VALID_PACK_ID });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(409);
      const detail = apiErr.details as {
        details?: { code?: string; currentStatus?: string };
      };
      expect(detail.details?.code).toBe("evidence_pack.empty");
      expect(detail.details?.currentStatus).toBeUndefined();
    }
  });

  it("surfaces 404 (missing/cross-org) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: {
          success: false,
          error: "pack not found",
          details: { code: "evidence_pack.not_found" },
        },
      },
    ]);
    await expect(
      client.evidencePack.sign({ packId: VALID_PACK_ID }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 500 as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      { status: 500, body: { success: false, error: "Internal error." } },
    ]);
    await expect(
      client.evidencePack.sign({ packId: VALID_PACK_ID }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("HR-4(b): non-JSON 200 surfaces as AttestryAPIError (NOT SyntaxError)", async () => {
    const { client } = makeMockedClient([
      {
        status: 200,
        bodyText: "<html>oops</html>",
        contentType: "text/html",
      },
    ]);
    let caught: unknown;
    try {
      await client.evidencePack.sign({ packId: VALID_PACK_ID });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect(caught).not.toBeInstanceOf(SyntaxError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.sign — abort signal
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.sign — abort signal", () => {
  it("rejects with AttestryError when the signal is pre-aborted; no fetch", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.evidencePack.sign(
        { packId: VALID_PACK_ID },
        { signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(AttestryError);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.supersede — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.supersede — happy path", () => {
  it("POSTs /{id}/supersede with the newPack body (minimal newPack)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_SUPERSEDE_RESPONSE } },
    ]);
    const out = await client.evidencePack.supersede({
      packId: VALID_PACK_ID,
      newPack: { packType: "annex_iv" },
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(new URL(calls[0].url).pathname).toBe(
      `/api/v1/evidence-packs/${VALID_PACK_ID}/supersede`,
    );
    expect(JSON.parse(calls[0].body!)).toEqual({
      newPack: { packType: "annex_iv" },
    });
    expect(out).toEqual(MOCK_SUPERSEDE_RESPONSE);
    expect(out.oldPack.status).toBe("superseded");
    expect(out.newPack.status).toBe("draft");
    expect(out.newPack.parentPackId).toBe(out.oldPack.id);
  });

  it("forwards all newPack fields including consumerHints (DEV-74)", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_SUPERSEDE_RESPONSE } },
    ]);
    await client.evidencePack.supersede({
      packId: VALID_PACK_ID,
      newPack: {
        packType: "agentic_reperformance",
        systemId: VALID_UUID,
        frameworkBindings: [{ framework: "iso_42001", identifier: "8.2" }],
        consumerHints: { allowPublicRetrieval: true },
        metadata: { author: "bot" },
      },
    });
    expect(JSON.parse(calls[0].body!)).toEqual({
      newPack: {
        packType: "agentic_reperformance",
        systemId: VALID_UUID,
        frameworkBindings: [{ framework: "iso_42001", identifier: "8.2" }],
        consumerHints: { allowPublicRetrieval: true },
        metadata: { author: "bot" },
      },
    });
  });

  it("omits own-present-but-undefined newPack optional fields", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_SUPERSEDE_RESPONSE } },
    ]);
    await client.evidencePack.supersede({
      packId: VALID_PACK_ID,
      newPack: {
        packType: "annex_iv",
        systemId: undefined,
        frameworkBindings: undefined,
        consumerHints: undefined,
        metadata: undefined,
      },
    });
    expect(JSON.parse(calls[0].body!)).toEqual({
      newPack: { packType: "annex_iv" },
    });
  });

  it("sends an explicit empty frameworkBindings array", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_SUPERSEDE_RESPONSE } },
    ]);
    await client.evidencePack.supersede({
      packId: VALID_PACK_ID,
      newPack: { packType: "annex_iv", frameworkBindings: [] },
    });
    expect(JSON.parse(calls[0].body!).newPack.frameworkBindings).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.supersede — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.supersede — input validation (pre-fetch)", () => {
  it("throws TypeError for null/array/non-object input", () => {
    const { client, calls } = makeMockedClient([]);
    for (const bad of [null, undefined, "x", []]) {
      expect(() =>
        client.evidencePack.supersede(
          bad as unknown as SupersedeEvidencePackInput,
        ),
      ).toThrowError(TypeError);
    }
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is missing / not a UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        newPack: { packType: "annex_iv" },
      } as unknown as SupersedeEvidencePackInput),
    ).toThrowError(/`packId` is required/);
    expect(() =>
      client.evidencePack.supersede({
        packId: "bad",
        newPack: { packType: "annex_iv" },
      }),
    ).toThrowError(/`packId` must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack is missing", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
      } as unknown as SupersedeEvidencePackInput),
    ).toThrowError(/`newPack` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: undefined as unknown as { packType: "annex_iv" },
      }),
    ).toThrowError(/`newPack` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack is not an object (array/null/string)", () => {
    const { client, calls } = makeMockedClient([]);
    for (const bad of [[], null, "x"]) {
      expect(() =>
        client.evidencePack.supersede({
          packId: VALID_PACK_ID,
          newPack: bad as unknown as { packType: "annex_iv" },
        }),
      ).toThrowError(/`newPack` must be a non-null object/);
    }
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack.packType is missing / undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: {} as unknown as { packType: "annex_iv" },
      }),
    ).toThrowError(/`newPack.packType` is required/);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: undefined as unknown as "annex_iv" },
      }),
    ).toThrowError(/`newPack.packType` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack.packType is not a string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: 7 as unknown as "annex_iv" },
      }),
    ).toThrowError(/`newPack.packType` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack.packType is not a valid enum value", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "nope" as unknown as "annex_iv" },
      }),
    ).toThrowError(/`newPack.packType` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack.systemId is not a string / not a UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv", systemId: 1 as unknown as string },
      }),
    ).toThrowError(/`newPack.systemId` must be a string/);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv", systemId: "bad" },
      }),
    ).toThrowError(/`newPack.systemId` must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack.frameworkBindings is not an array", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: {
          packType: "annex_iv",
          frameworkBindings: {} as unknown as unknown[],
        },
      }),
    ).toThrowError(/`newPack.frameworkBindings` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack.frameworkBindings exceeds 50", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: {
          packType: "annex_iv",
          frameworkBindings: new Array(51).fill({ framework: "x", identifier: "y" }),
        },
      }),
    ).toThrowError(/exceeds the kernel's max length of 50/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack.consumerHints is not a non-null object", () => {
    const { client, calls } = makeMockedClient([]);
    for (const bad of [null, [], "x", 3]) {
      expect(() =>
        client.evidencePack.supersede({
          packId: VALID_PACK_ID,
          newPack: {
            packType: "annex_iv",
            consumerHints: bad as unknown as Record<string, unknown>,
          },
        }),
      ).toThrowError(/`newPack.consumerHints` must be a non-null object/);
    }
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when newPack.metadata is not a non-null object", () => {
    const { client, calls } = makeMockedClient([]);
    for (const bad of [null, [], "x"]) {
      expect(() =>
        client.evidencePack.supersede({
          packId: VALID_PACK_ID,
          newPack: {
            packType: "annex_iv",
            metadata: bad as unknown as Record<string, unknown>,
          },
        }),
      ).toThrowError(/`newPack.metadata` must be a non-null object/);
    }
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.supersede — response validation (P2)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.supersede — response validation (P2)", () => {
  it("throws AttestryError when the response is not an object", async () => {
    const { client } = makeMockedClient([
      { status: 201, body: { success: true, data: "nope" } },
    ]);
    await expect(
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv" },
      }),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("throws AttestryError when response.newPack is missing", async () => {
    const { client } = makeMockedClient([
      {
        status: 201,
        body: { success: true, data: { oldPack: MOCK_PACK_OLD_SUPERSEDED } },
      },
    ]);
    await expect(
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv" },
      }),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("throws AttestryError when response.oldPack is malformed", async () => {
    const { client } = makeMockedClient([
      {
        status: 201,
        body: {
          success: true,
          data: { newPack: MOCK_PACK_NEW_DRAFT, oldPack: "nope" },
        },
      },
    ]);
    await expect(
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv" },
      }),
    ).rejects.toBeInstanceOf(AttestryError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.supersede — error mapping + abort
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.supersede — error mapping + abort", () => {
  it("surfaces 403 (lacks WRITE_ASSESSMENTS) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      { status: 403, body: { success: false, error: "Forbidden." } },
    ]);
    await expect(
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv" },
      }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 409 InvalidStateError (old pack not signed) with currentStatus", async () => {
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: "pack is in 'draft' state; only signed packs can be superseded",
          details: {
            code: "evidence_pack.invalid_state",
            currentStatus: "draft",
          },
        },
      },
    ]);
    try {
      await client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv" },
      });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as AttestryAPIError).status).toBe(409);
      const detail = (err as AttestryAPIError).details as {
        details?: { currentStatus?: string };
      };
      expect(detail.details?.currentStatus).toBe("draft");
    }
  });

  it("surfaces 422 (newPack validation) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: { code: "evidence_pack.validation_failed" },
        },
      },
    ]);
    await expect(
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv" },
      }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("rejects with AttestryError when the signal is pre-aborted; no fetch", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("cancelled"));
    await expect(
      client.evidencePack.supersede(
        { packId: VALID_PACK_ID, newPack: { packType: "annex_iv" } },
        { signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(AttestryError);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.revoke — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.revoke — happy path", () => {
  it("POSTs /{id}/revoke with an empty body when no reason is given", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_REVOKED } },
    ]);
    const out = await client.evidencePack.revoke({ packId: VALID_PACK_ID });
    expect(calls[0].method).toBe("POST");
    expect(new URL(calls[0].url).pathname).toBe(
      `/api/v1/evidence-packs/${VALID_PACK_ID}/revoke`,
    );
    expect(JSON.parse(calls[0].body!)).toEqual({});
    expect(out.status).toBe("revoked");
  });

  it("POSTs with the reason when provided", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_REVOKED } },
    ]);
    await client.evidencePack.revoke({
      packId: VALID_PACK_ID,
      reason: "control framework superseded",
    });
    expect(JSON.parse(calls[0].body!)).toEqual({
      reason: "control framework superseded",
    });
  });

  it("treats own-present-but-undefined reason as omitted", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_REVOKED } },
    ]);
    await client.evidencePack.revoke({
      packId: VALID_PACK_ID,
      reason: undefined,
    });
    expect(JSON.parse(calls[0].body!)).toEqual({});
  });

  it("accepts a reason at the 500-char boundary", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_REVOKED } },
    ]);
    const reason = "a".repeat(500);
    await client.evidencePack.revoke({ packId: VALID_PACK_ID, reason });
    expect(JSON.parse(calls[0].body!).reason.length).toBe(500);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.revoke — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.revoke — input validation (pre-fetch)", () => {
  it("throws TypeError for null/array/non-object input", () => {
    const { client, calls } = makeMockedClient([]);
    for (const bad of [null, undefined, "x", []]) {
      expect(() =>
        client.evidencePack.revoke(bad as unknown as RevokeEvidencePackInput),
      ).toThrowError(TypeError);
    }
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is missing / not a UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.revoke({} as unknown as RevokeEvidencePackInput),
    ).toThrowError(/`packId` is required/);
    expect(() =>
      client.evidencePack.revoke({ packId: "bad" }),
    ).toThrowError(/`packId` must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when reason is not a string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.revoke({
        packId: VALID_PACK_ID,
        reason: 5 as unknown as string,
      }),
    ).toThrowError(/`reason` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when reason is an empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.revoke({ packId: VALID_PACK_ID, reason: "" }),
    ).toThrowError(/`reason` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when reason exceeds 500 chars", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.revoke({
        packId: VALID_PACK_ID,
        reason: "a".repeat(501),
      }),
    ).toThrowError(/exceeds the maximum length of 500/);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.revoke — response validation (P2) + error mapping + abort
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.revoke — response / error / abort", () => {
  it("throws AttestryError when the response pack is malformed", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { id: 123 } } },
    ]);
    await expect(
      client.evidencePack.revoke({ packId: VALID_PACK_ID }),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("surfaces 403 (non-admin) as AttestryAPIError with status 403", async () => {
    const { client } = makeMockedClient([
      { status: 403, body: { success: false, error: "Forbidden." } },
    ]);
    try {
      await client.evidencePack.revoke({ packId: VALID_PACK_ID });
      throw new Error("expected throw");
    } catch (err) {
      expect((err as AttestryAPIError).status).toBe(403);
    }
  });

  it("surfaces 409 InvalidStateError (already revoked) with currentStatus", async () => {
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: "pack is in 'revoked' state; only signed packs can be revoked",
          details: {
            code: "evidence_pack.invalid_state",
            currentStatus: "revoked",
          },
        },
      },
    ]);
    try {
      await client.evidencePack.revoke({ packId: VALID_PACK_ID });
      throw new Error("expected throw");
    } catch (err) {
      const detail = (err as AttestryAPIError).details as {
        details?: { currentStatus?: string };
      };
      expect(detail.details?.currentStatus).toBe("revoked");
    }
  });

  it("rejects with AttestryError when the signal is pre-aborted; no fetch", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("cancelled"));
    await expect(
      client.evidencePack.revoke(
        { packId: VALID_PACK_ID },
        { signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(AttestryError);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.export — happy path (json / pdf / zip)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.export — happy path", () => {
  it("GETs /{id}/export?format=json and returns the raw artifact via .response.json()", async () => {
    const { client, calls } = makeMockedClient([
      {
        body: MOCK_EXPORT_JSON_ARTIFACT,
        contentType: "application/json",
        contentDisposition: EXPORT_CONTENT_DISPOSITION,
      },
    ]);
    const result = await client.evidencePack.export({
      packId: VALID_PACK_ID,
      format: "json",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe(`/api/v1/evidence-packs/${VALID_PACK_ID}/export`);
    expect(url.searchParams.get("format")).toBe("json");
    expect(result.format).toBe("json");
    expect(result.contentType).toBe("application/json");
    expect(result.contentDisposition).toBe(EXPORT_CONTENT_DISPOSITION);
    // The SDK does NOT consume the body — the consumer reads it.
    const artifact = await result.response.json();
    expect(artifact).toEqual(MOCK_EXPORT_JSON_ARTIFACT);
    // The raw artifact has NO `success` envelope.
    expect((artifact as Record<string, unknown>).success).toBeUndefined();
    expect((artifact as Record<string, unknown>).export).toBeDefined();
  });

  it("GETs format=pdf, returns binary bytes via .response.arrayBuffer()", async () => {
    const pdfBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // %PDF
    const { client, calls } = makeMockedClient([
      {
        rawBody: pdfBytes,
        contentType: "application/pdf",
        contentDisposition: `attachment; filename="evidence-pack-${VALID_PACK_ID}.pdf"`,
      },
    ]);
    const result = await client.evidencePack.export({
      packId: VALID_PACK_ID,
      format: "pdf",
    });
    expect(new URL(calls[0].url).searchParams.get("format")).toBe("pdf");
    expect(result.format).toBe("pdf");
    expect(result.contentType).toBe("application/pdf");
    const bytes = new Uint8Array(await result.response.arrayBuffer());
    expect(Array.from(bytes)).toEqual([0x25, 0x50, 0x44, 0x46]);
  });

  it("GETs format=zip, exposes a readable .response.body stream", async () => {
    const zipBytes = new Uint8Array([0x50, 0x4b, 0x03, 0x04]); // PK..
    const { client, calls } = makeMockedClient([
      {
        rawBody: zipBytes,
        contentType: "application/zip",
        contentDisposition: `attachment; filename="evidence-pack-${VALID_PACK_ID}.zip"`,
      },
    ]);
    const result = await client.evidencePack.export({
      packId: VALID_PACK_ID,
      format: "zip",
    });
    expect(new URL(calls[0].url).searchParams.get("format")).toBe("zip");
    expect(result.format).toBe("zip");
    expect(result.contentType).toBe("application/zip");
    expect(result.response.body).not.toBeNull();
    const bytes = new Uint8Array(await result.response.arrayBuffer());
    expect(Array.from(bytes)).toEqual([0x50, 0x4b, 0x03, 0x04]);
  });

  it("sets the Accept header to the per-format content type", async () => {
    const { client, calls } = makeMockedClient([
      { body: MOCK_EXPORT_JSON_ARTIFACT, contentType: "application/json" },
    ]);
    await client.evidencePack.export({ packId: VALID_PACK_ID, format: "json" });
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("x-api-key")).toBe("k");
  });

  it("surfaces contentDisposition as null when the header is absent", async () => {
    const { client } = makeMockedClient([
      { body: MOCK_EXPORT_JSON_ARTIFACT, contentType: "application/json" },
    ]);
    const result = await client.evidencePack.export({
      packId: VALID_PACK_ID,
      format: "json",
    });
    expect(result.contentDisposition).toBeNull();
  });

  it("encodeURIComponent-encodes the packId in the path", async () => {
    const { client, calls } = makeMockedClient([
      { body: MOCK_EXPORT_JSON_ARTIFACT, contentType: "application/json" },
    ]);
    await client.evidencePack.export({ packId: VALID_PACK_ID, format: "json" });
    expect(calls[0].url).toContain(
      `/api/v1/evidence-packs/${encodeURIComponent(VALID_PACK_ID)}/export`,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.export — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.export — input validation (pre-fetch)", () => {
  it("throws TypeError for null/array/non-object input", () => {
    const { client, calls } = makeMockedClient([]);
    for (const bad of [null, undefined, "x", []]) {
      expect(() =>
        client.evidencePack.export(bad as unknown as ExportEvidencePackInput),
      ).toThrowError(TypeError);
    }
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when packId is missing / not a UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.export({
        format: "json",
      } as unknown as ExportEvidencePackInput),
    ).toThrowError(/`packId` is required/);
    expect(() =>
      client.evidencePack.export({ packId: "bad", format: "json" }),
    ).toThrowError(/`packId` must be an RFC 4122/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when format is missing / undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.export({
        packId: VALID_PACK_ID,
      } as unknown as ExportEvidencePackInput),
    ).toThrowError(/`format` is required/);
    expect(() =>
      client.evidencePack.export({
        packId: VALID_PACK_ID,
        format: undefined as unknown as "json",
      }),
    ).toThrowError(/`format` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when format is not a string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.export({
        packId: VALID_PACK_ID,
        format: 7 as unknown as "json",
      }),
    ).toThrowError(/`format` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for an unknown format", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.export({
        packId: VALID_PACK_ID,
        format: "xml" as unknown as "json",
      }),
    ).toThrowError(/`format` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("rejects a wrong-case format (closed-enum is case-sensitive)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.export({
        packId: VALID_PACK_ID,
        format: "JSON" as unknown as "json",
      }),
    ).toThrowError(/`format` must be one of/);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack.export — transport / content-type / error mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("evidencePack.export — transport / error mapping", () => {
  it("surfaces a 404 during export as AttestryAPIError (NOT a stream/parse crash)", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: {
          success: false,
          error: "pack not found",
          details: { code: "evidence_pack.not_found" },
        },
      },
    ]);
    let caught: unknown;
    try {
      await client.evidencePack.export({ packId: VALID_PACK_ID, format: "pdf" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(404);
  });

  it("surfaces a 422 (format) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Invalid query parameters.",
          details: { code: "evidence_pack.validation_failed" },
        },
      },
    ]);
    // The SDK pre-validates format, so this 422 is only reachable when the
    // mock returns it directly — the SDK still surfaces it as AttestryAPIError.
    await expect(
      client.evidencePack.export({ packId: VALID_PACK_ID, format: "json" }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("surfaces 401 / 403 / 500 as AttestryAPIError", async () => {
    for (const status of [401, 403, 500]) {
      const { client } = makeMockedClient([
        { status, body: { success: false, error: "err" } },
      ]);
      await expect(
        client.evidencePack.export({ packId: VALID_PACK_ID, format: "json" }),
      ).rejects.toBeInstanceOf(AttestryAPIError);
    }
  });

  it("throws AttestryAPIError on a 2xx with the WRONG content type for the format", async () => {
    // format=json (expects application/json) but the server returns pdf.
    const { client } = makeMockedClient([
      {
        rawBody: new Uint8Array([1, 2, 3]),
        contentType: "application/pdf",
      },
    ]);
    await expect(
      client.evidencePack.export({ packId: VALID_PACK_ID, format: "json" }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("throws AttestryAPIError on a 2xx with an HTML body (proxy error page)", async () => {
    const { client } = makeMockedClient([
      { status: 200, bodyText: "<html>502</html>", contentType: "text/html" },
    ]);
    await expect(
      client.evidencePack.export({ packId: VALID_PACK_ID, format: "zip" }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("throws AttestryAPIError on a 2xx with the Content-Type header stripped (proxy)", async () => {
    // A proxy that drops the Content-Type entirely: the streaming transport's
    // guard treats an absent header as "" and rejects the format mismatch
    // (rather than soft-failing). A Uint8Array body is required — the Response
    // constructor auto-sets "text/plain" for a string body, but leaves a
    // binary body with NO Content-Type, faithfully simulating the stripped
    // header. (Exercises the `makeMockedClient` `omitContentType` affordance.)
    const { client } = makeMockedClient([
      { rawBody: new Uint8Array([1, 2, 3]), omitContentType: true },
    ]);
    await expect(
      client.evidencePack.export({ packId: VALID_PACK_ID, format: "json" }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("rejects with AttestryError when the signal is pre-aborted; no fetch", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("cancelled"));
    await expect(
      client.evidencePack.export(
        { packId: VALID_PACK_ID, format: "json" },
        { signal: controller.signal },
      ),
    ).rejects.toBeInstanceOf(AttestryError);
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack — P1.8 Round 3 hostile probes (H-P18-1..8)
// ═══════════════════════════════════════════════════════════════════════════
//
// Adversarial probes confirming the build-round defenses hold on the 4 new
// methods. Distinct from the build-round input-validation tests (happy
// validate-then-reject) — these target prototype pollution, late
// Object.hasOwn override, TOCTOU single-read, path-traversal candidates,
// at-cap boundaries, and the export faithful-courier (no body consumption).

describe("evidencePack — P1.8 Round 3 hostile probes (H-P18-1..8)", () => {
  // Capture the original BEFORE any test patches it (P1.6 hostile-redux
  // F-HR1-2 — a no-op restore leaks pollution across files).
  const ORIGINAL_OBJECT_HAS_OWN = Object.hasOwn;

  afterEach(() => {
    Object.hasOwn = ORIGINAL_OBJECT_HAS_OWN;
    // Delete every Object.prototype key the probes might have polluted.
    for (const key of [
      "packId",
      "attestationCertificateId",
      "format",
      "reason",
      "newPack",
      "packType",
      "systemId",
      "consumerHints",
      "frameworkBindings",
      "metadata",
    ]) {
      delete (Object.prototype as unknown as Record<string, unknown>)[key];
    }
  });

  // ─── H-P18-1: Object.prototype pollution does NOT satisfy required fields ──
  it("H-P18-1: polluted Object.prototype.packId does not satisfy sign required packId", () => {
    (Object.prototype as unknown as Record<string, unknown>).packId =
      VALID_PACK_ID;
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.sign({} as unknown as SignEvidencePackInput),
    ).toThrowError(/`packId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("H-P18-1: polluted Object.prototype.format does not satisfy export required format", () => {
    (Object.prototype as unknown as Record<string, unknown>).format = "json";
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.export({
        packId: VALID_PACK_ID,
      } as unknown as ExportEvidencePackInput),
    ).toThrowError(/`format` is required/);
    expect(calls).toHaveLength(0);
  });

  it("H-P18-1: polluted Object.prototype.newPack does not satisfy supersede required newPack", () => {
    (Object.prototype as unknown as Record<string, unknown>).newPack = {
      packType: "annex_iv",
    };
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
      } as unknown as SupersedeEvidencePackInput),
    ).toThrowError(/`newPack` is required/);
    expect(calls).toHaveLength(0);
  });

  it("H-P18-1: polluted Object.prototype.packType does not satisfy supersede newPack.packType", () => {
    (Object.prototype as unknown as Record<string, unknown>).packType =
      "annex_iv";
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: {} as unknown as { packType: "annex_iv" },
      }),
    ).toThrowError(/`newPack.packType` is required/);
    expect(calls).toHaveLength(0);
  });

  // ─── H-P18-2: polluted optional field is NOT sent on the wire ──────────────
  it("H-P18-2: polluted Object.prototype.attestationCertificateId is NOT sent by sign", async () => {
    (Object.prototype as unknown as Record<string, unknown>).attestationCertificateId =
      "evil";
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_SIGNED } },
    ]);
    await client.evidencePack.sign({ packId: VALID_PACK_ID });
    expect(JSON.parse(calls[0].body!)).toEqual({});
  });

  it("H-P18-2: polluted Object.prototype.reason is NOT sent by revoke", async () => {
    (Object.prototype as unknown as Record<string, unknown>).reason = "evil";
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_REVOKED } },
    ]);
    await client.evidencePack.revoke({ packId: VALID_PACK_ID });
    expect(JSON.parse(calls[0].body!)).toEqual({});
  });

  it("H-P18-2: polluted Object.prototype.consumerHints is NOT sent in supersede newPack", async () => {
    (Object.prototype as unknown as Record<string, unknown>).consumerHints = {
      allowPublicRetrieval: true,
    };
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_SUPERSEDE_RESPONSE } },
    ]);
    await client.evidencePack.supersede({
      packId: VALID_PACK_ID,
      newPack: { packType: "annex_iv" },
    });
    expect(JSON.parse(calls[0].body!)).toEqual({
      newPack: { packType: "annex_iv" },
    });
  });

  // ─── H-P18-3: late Object.hasOwn override doesn't defeat the snapshot ──────
  it("H-P18-3: late Object.hasOwn = () => false doesn't make sign drop a valid packId", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_SIGNED } },
    ]);
    Object.hasOwn = () => false;
    // The module-load snapshot is unaffected; sign still reads packId and
    // succeeds. (Were the SDK using the live global, hasPackId would be
    // false -> a spurious "packId is required" throw.)
    await client.evidencePack.sign({ packId: VALID_PACK_ID });
    expect(calls).toHaveLength(1);
    expect(new URL(calls[0].url).pathname).toBe(
      `/api/v1/evidence-packs/${VALID_PACK_ID}/sign`,
    );
  });

  it("H-P18-3: late Object.hasOwn = () => true doesn't make export send a phantom field", async () => {
    const { client, calls } = makeMockedClient([
      { body: MOCK_EXPORT_JSON_ARTIFACT, contentType: "application/json" },
    ]);
    Object.hasOwn = () => true;
    // The snapshot is unaffected; export still validates format against the
    // real own-property value and issues the request.
    await client.evidencePack.export({ packId: VALID_PACK_ID, format: "json" });
    expect(new URL(calls[0].url).searchParams.get("format")).toBe("json");
  });

  // ─── H-P18-4: closed-enum case sensitivity ────────────────────────────────
  it("H-P18-4: export rejects every wrong-case format variant", () => {
    const { client, calls } = makeMockedClient([]);
    for (const bad of ["JSON", "Json", "PDF", "Zip", "ZIP"]) {
      expect(() =>
        client.evidencePack.export({
          packId: VALID_PACK_ID,
          format: bad as unknown as "json",
        }),
      ).toThrowError(/`format` must be one of/);
    }
    expect(calls).toHaveLength(0);
  });

  it("H-P18-4: supersede rejects a wrong-case newPack.packType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "ANNEX_IV" as unknown as "annex_iv" },
      }),
    ).toThrowError(/`newPack.packType` must be one of/);
    expect(calls).toHaveLength(0);
  });

  // ─── H-P18-5: path-traversal candidates rejected at the UUID regex ─────────
  it("H-P18-5: packId with path-traversal/control chars is rejected before any fetch (all 4 methods)", () => {
    const { client, calls } = makeMockedClient([]);
    const newline = String.fromCharCode(10);
    const hostilePackIds = [
      "../../etc/passwd",
      "11111111-1111-1111-1111-111111111111/../../x",
      "11111111-1111-1111-1111-111111111111%2F..",
      `11111111${newline}1111-1111-1111-111111111111`,
      "11111111-1111-1111-1111-111111111111 ",
      "11111111-1111-1111-1111-111111111111?evil=1",
    ];
    for (const bad of hostilePackIds) {
      expect(() => client.evidencePack.sign({ packId: bad })).toThrowError(
        /`packId` must be an RFC 4122 hyphenated UUID/,
      );
      expect(() => client.evidencePack.revoke({ packId: bad })).toThrowError(
        /`packId` must be an RFC 4122 hyphenated UUID/,
      );
      expect(() =>
        client.evidencePack.export({ packId: bad, format: "json" }),
      ).toThrowError(/`packId` must be an RFC 4122 hyphenated UUID/);
      expect(() =>
        client.evidencePack.supersede({
          packId: bad,
          newPack: { packType: "annex_iv" },
        }),
      ).toThrowError(/`packId` must be an RFC 4122 hyphenated UUID/);
    }
    expect(calls).toHaveLength(0);
  });

  // ─── H-P18-6: at-cap boundary values accepted ─────────────────────────────
  it("H-P18-6: supersede accepts newPack.frameworkBindings at the 50-element cap", async () => {
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_SUPERSEDE_RESPONSE } },
    ]);
    const fb = new Array(50).fill({ framework: "x", identifier: "y" });
    await client.evidencePack.supersede({
      packId: VALID_PACK_ID,
      newPack: { packType: "annex_iv", frameworkBindings: fb },
    });
    expect(JSON.parse(calls[0].body!).newPack.frameworkBindings).toHaveLength(50);
  });

  it("H-P18-6: revoke accepts a reason at the 500-char cap but rejects 501", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_PACK_REVOKED } },
    ]);
    await client.evidencePack.revoke({
      packId: VALID_PACK_ID,
      reason: "z".repeat(500),
    });
    expect(JSON.parse(calls[0].body!).reason).toHaveLength(500);
    expect(() =>
      client.evidencePack.revoke({
        packId: VALID_PACK_ID,
        reason: "z".repeat(501),
      }),
    ).toThrowError(/exceeds the maximum length of 500/);
  });

  // ─── H-P18-7: TOCTOU — input fields are read EXACTLY ONCE ──────────────────
  it("H-P18-7: export reads `format` exactly once (Proxy flip cannot bypass validation)", async () => {
    let readCount = 0;
    const hostileInput = new Proxy(
      { packId: VALID_PACK_ID, format: "json" },
      {
        get(target, prop, receiver) {
          if (prop === "format") {
            readCount++;
            // First read returns valid; a TOCTOU re-read would return "evil".
            return readCount === 1 ? "json" : "evil";
          }
          return Reflect.get(target, prop, receiver);
        },
        has(target, prop) {
          return Reflect.has(target, prop);
        },
      },
    ) as unknown as ExportEvidencePackInput;
    const { client, calls } = makeMockedClient([
      { body: MOCK_EXPORT_JSON_ARTIFACT, contentType: "application/json" },
    ]);
    await client.evidencePack.export(hostileInput);
    // The snapshot value ("json") is what reached the wire — NOT "evil".
    expect(new URL(calls[0].url).searchParams.get("format")).toBe("json");
    expect(readCount).toBe(1);
  });

  it("H-P18-7: supersede reads `newPack.packType` exactly once", async () => {
    let readCount = 0;
    const hostileNewPack = new Proxy(
      { packType: "annex_iv" },
      {
        get(target, prop, receiver) {
          if (prop === "packType") {
            readCount++;
            return readCount === 1 ? "annex_iv" : "evil";
          }
          return Reflect.get(target, prop, receiver);
        },
        has(target, prop) {
          return Reflect.has(target, prop);
        },
      },
    ) as unknown as { packType: "annex_iv" };
    const { client, calls } = makeMockedClient([
      { status: 201, body: { success: true, data: MOCK_SUPERSEDE_RESPONSE } },
    ]);
    await client.evidencePack.supersede({
      packId: VALID_PACK_ID,
      newPack: hostileNewPack,
    });
    expect(JSON.parse(calls[0].body!).newPack.packType).toBe("annex_iv");
    expect(readCount).toBe(1);
  });

  // ─── H-P18-8: export faithful-courier — SDK never consumes the body ────────
  it("H-P18-8: export hands back an UN-consumed body (response.bodyUsed === false)", async () => {
    const { client } = makeMockedClient([
      { body: MOCK_EXPORT_JSON_ARTIFACT, contentType: "application/json" },
    ]);
    const result = await client.evidencePack.export({
      packId: VALID_PACK_ID,
      format: "json",
    });
    // The SDK did NOT read the body — the consumer owns it.
    expect(result.response.bodyUsed).toBe(false);
  });

  it("H-P18-8: a 4xx export with a non-JSON HTML error body surfaces as AttestryAPIError with the raw text in details", async () => {
    const { client } = makeMockedClient([
      {
        status: 502,
        bodyText: "<html>502 Bad Gateway</html>",
        contentType: "text/html",
      },
    ]);
    let caught: unknown;
    try {
      await client.evidencePack.export({ packId: VALID_PACK_ID, format: "zip" });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryAPIError).status).toBe(502);
    expect(String((caught as AttestryAPIError).details)).toContain(
      "502 Bad Gateway",
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// evidencePack — P1.8 Round 4 coverage closure (DEV-78)
// ═══════════════════════════════════════════════════════════════════════════
//
// Closes the four branches the build/hostile rounds left uncovered, all of
// the same shape the build round covered for `sign` but not for the other
// three methods:
//   - supersede / revoke / export `packId` non-string / empty-string branch
//     (the build round's combined "missing / not a UUID" tests skipped the
//     `typeof !== "string" || length === 0` arm);
//   - supersede response `oldPack` own-property-absent branch (the build
//     round's response tests covered newPack-absent + oldPack-malformed, but
//     not oldPack-entirely-absent).

describe("evidencePack — P1.8 Round 4 coverage closure", () => {
  it("supersede throws TypeError when packId is a non-empty NON-string (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: 123 as unknown as string,
        newPack: { packType: "annex_iv" },
      }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("supersede throws TypeError when packId is an empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.supersede({
        packId: "",
        newPack: { packType: "annex_iv" },
      }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("supersede throws AttestryError when response.oldPack is entirely absent", async () => {
    const { client } = makeMockedClient([
      {
        status: 201,
        body: { success: true, data: { newPack: MOCK_PACK_NEW_DRAFT } },
      },
    ]);
    await expect(
      client.evidencePack.supersede({
        packId: VALID_PACK_ID,
        newPack: { packType: "annex_iv" },
      }),
    ).rejects.toBeInstanceOf(AttestryError);
  });

  it("revoke throws TypeError when packId is a non-empty NON-string (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.revoke({ packId: 5 as unknown as string }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("revoke throws TypeError when packId is an empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.revoke({ packId: "" }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("export throws TypeError when packId is a non-empty NON-string (number)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.export({
        packId: 7 as unknown as string,
        format: "json",
      }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("export throws TypeError when packId is an empty string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.evidencePack.export({ packId: "", format: "json" }),
    ).toThrowError(/`packId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });
});
