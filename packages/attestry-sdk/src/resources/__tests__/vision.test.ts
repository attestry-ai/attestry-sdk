import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  VisionExtractInput,
  VisionExtractResponse,
  VisionBatchExtractInput,
  VisionBatchExtractResponse,
  VisionJobStatus,
  VisionPackIntegrationResult,
} from "../vision.js";
import type { FetchLike } from "../../types.js";

// ─── vision resource — POST extract / POST extractBatch / GET getJobStatus ──
//
// Wire shapes (from src/app/api/v1/vision/extract{,/batch,/jobs/[jobId]}/route.ts):
//
//   - POST /api/v1/vision/extract
//       Body: {base64?: string, imageUri?: string, mediaType: enum,
//              documentType: enum, extractionSchema?: enum, model?: enum,
//              packId?: UUID}
//       Response: {callId, structuredExtraction, confidencePerField,
//                  sourceRegions, tokensUsed, costUsdCents, latencyMs,
//                  packIntegration?}
//
//   - POST /api/v1/vision/extract/batch
//       Body: {documents: BatchDocument[], model?: enum}
//       Response: {jobId, status: "queued"} (HTTP 202)
//
//   - GET /api/v1/vision/extract/jobs/{jobId}
//       Response: {jobId, status, documentCount, documentsProcessed,
//                  modelTier, costUsdCents, costTokensInput, costTokensOutput,
//                  errorLog, resultPackId, createdAt, startedAt, completedAt}
//
// Ninth resource on the SDK. The vision surface is the largest yet —
// 3 methods, the P5.5 `packId`/`packIntegration` surface, 2 frozen
// closed-enum tuples (SUPPORTED_MEDIA_TYPES, SUPPORTED_DOCUMENT_TYPES).
//
// `mediaType` REQUIRED on extract + each batch document (P5.4 DEV-10).
// `base64` XOR `imageUri` per request / per document — exactly one must
// be supplied.
// `packId` (extract only) is optional UUID; when present, response
// carries an additive `packIntegration` field; when absent, the response
// is byte-identical to P5.4 (no `packIntegration` own-property —
// drift-pinned).

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

function makeMockedClient(
  responses: Array<{ status?: number; body?: unknown; bodyText?: string }>,
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
    const body =
      r.bodyText !== undefined ? r.bodyText : JSON.stringify(r.body ?? {});
    return new Response(body, {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    // Resource tests disable retry so a 429 mock doesn't hang on
    // backoff and accidentally consume the next mock response.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const VALID_UUID = "11111111-1111-1111-1111-111111111111";
const VALID_PACK_ID = "22222222-2222-2222-2222-222222222222";
const SAMPLE_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAA==";

// ─── Mock fixtures ──────────────────────────────────────────────────────────

const MOCK_EXTRACT_RESPONSE_NO_PACK: VisionExtractResponse = {
  callId: "33333333-3333-3333-3333-333333333333",
  structuredExtraction: { name: "Sample Model", version: "1.0" },
  confidencePerField: { name: 0.99, version: 0.95 },
  sourceRegions: { name: "top-left header", version: "footer" },
  tokensUsed: { input: 1500, output: 500, cacheCreation: 0, cacheRead: 0 },
  costUsdCents: 22,
  latencyMs: 25_500,
};

const MOCK_PACK_INTEGRATION: VisionPackIntegrationResult = {
  status: "wrapped",
  packId: VALID_PACK_ID,
  bundleId: "44444444-4444-4444-4444-444444444444",
  packContentHash:
    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  inputsHash:
    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  outputsHash:
    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  hashCollision: { detected: false, count: 0 },
  schemaCompatibility: {
    assessable: true,
    visionDocumentType: "model-card",
    packFrameworkBindings: [{ framework: "EU_AI_ACT", identifier: "Art.13" }],
    advisory:
      "Advisory only: confirm the vision documentType 'model-card' aligns with the pack's declared framework_bindings.",
  },
};

const MOCK_EXTRACT_RESPONSE_WITH_PACK: VisionExtractResponse = {
  ...MOCK_EXTRACT_RESPONSE_NO_PACK,
  packIntegration: MOCK_PACK_INTEGRATION,
};

const MOCK_BATCH_RESPONSE: VisionBatchExtractResponse = {
  jobId: "55555555-5555-5555-5555-555555555555",
  status: "queued",
};

const MOCK_JOB_STATUS: VisionJobStatus = {
  jobId: VALID_UUID,
  status: "processing",
  documentCount: 3,
  documentsProcessed: 1,
  modelTier: "opus",
  costUsdCents: 44,
  costTokensInput: 4533,
  costTokensOutput: 1024,
  errorLog: null,
  resultPackId: null,
  createdAt: "2026-05-18T13:55:51.000Z",
  startedAt: "2026-05-18T13:55:52.000Z",
  completedAt: null,
};

// ═══════════════════════════════════════════════════════════════════════════
// vision.extract — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extract — happy path", () => {
  it("POSTs /api/v1/vision/extract with a JSON body (base64 input)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
    ]);
    const out = await client.vision.extract({
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/vision/extract");
    expect(url.search).toBe("");
    expect(calls[0].body).toBeDefined();
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
    });
    // Envelope unwrapped — top-level is the data object.
    expect(out).toEqual(MOCK_EXTRACT_RESPONSE_NO_PACK);
  });

  it("POSTs body with all fields when fully provided (imageUri + packId)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_WITH_PACK } },
    ]);
    await client.vision.extract({
      imageUri: "https://example.com/cert.png",
      mediaType: "image/png",
      documentType: "certification-label",
      extractionSchema: "certification-label",
      model: "sonnet",
      packId: VALID_PACK_ID,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      imageUri: "https://example.com/cert.png",
      mediaType: "image/png",
      documentType: "certification-label",
      extractionSchema: "certification-label",
      model: "sonnet",
      packId: VALID_PACK_ID,
    });
  });

  it("forwards x-api-key + Accept + Content-Type headers (POST with body)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
    ]);
    await client.vision.extract({
      base64: SAMPLE_BASE64,
      mediaType: "image/jpeg",
      documentType: "validation-report",
    });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("returns the response shape unchanged when no packId was sent (no packIntegration own-property)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
    ]);
    const out = await client.vision.extract({
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
    });
    // Critical drift-pinned property: the no-packId response has NO
    // packIntegration own-property (byte-identical to P5.4).
    expect(Object.hasOwn(out, "packIntegration")).toBe(false);
    expect(Object.keys(out).sort()).toEqual(
      [
        "callId",
        "structuredExtraction",
        "confidencePerField",
        "sourceRegions",
        "tokensUsed",
        "costUsdCents",
        "latencyMs",
      ].sort(),
    );
  });

  it("returns packIntegration when packId was sent and the wrap succeeded", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_WITH_PACK } },
    ]);
    const out = await client.vision.extract({
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
      packId: VALID_PACK_ID,
    });
    expect(Object.hasOwn(out, "packIntegration")).toBe(true);
    expect(out.packIntegration?.status).toBe("wrapped");
    expect(out.packIntegration?.packId).toBe(VALID_PACK_ID);
    expect(out.packIntegration?.bundleId).toBe(
      "44444444-4444-4444-4444-444444444444",
    );
    expect(out.packIntegration?.schemaCompatibility.assessable).toBe(true);
  });

  it("supports all 4 mediaType values without round-trip drift", async () => {
    for (const mt of [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif",
    ] as const) {
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
      ]);
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: mt,
        documentType: "model-card",
      });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed.mediaType).toBe(mt);
    }
  });

  it("supports all 5 documentType values without round-trip drift", async () => {
    for (const dt of [
      "model-card",
      "validation-report",
      "certification-label",
      "schematic-extraction",
      "generic-tabular",
    ] as const) {
      const { client, calls } = makeMockedClient([
        { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
      ]);
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: dt,
      });
      const parsed = JSON.parse(calls[0].body!);
      expect(parsed.documentType).toBe(dt);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.extract — input validation (pre-fetch)
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extract — input validation (pre-fetch)", () => {
  it("throws TypeError for null input — does NOT issue a request", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract(null as unknown as VisionExtractInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract(undefined as unknown as VisionExtractInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-object input (string)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract("not an object" as unknown as VisionExtractInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract([] as unknown as VisionExtractInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when mediaType is missing", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        documentType: "model-card",
      } as unknown as VisionExtractInput),
    ).toThrowError(/`mediaType` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when mediaType is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: undefined as unknown as "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/`mediaType` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string mediaType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: 42 as unknown as "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/`mediaType` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown mediaType (closed-enum violation)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/bmp" as unknown as "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/`mediaType` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when documentType is missing", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
      } as unknown as VisionExtractInput),
    ).toThrowError(/`documentType` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string documentType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: null as unknown as "model-card",
      }),
    ).toThrowError(/`documentType` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown documentType (closed-enum violation)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "annex-iv-section-1" as unknown as "model-card",
      }),
    ).toThrowError(/`documentType` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when both base64 and imageUri are supplied (XOR)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        imageUri: "https://example.com/img.png",
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/mutually exclusive/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when neither base64 nor imageUri is supplied (XOR)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/exactly one of `base64` or `imageUri` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string base64", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: 42 as unknown as string,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/`base64` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty base64 string", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: "",
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/`base64` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for oversized base64 (>ANTHROPIC_IMAGE_MAX_BASE64)", () => {
    const { client, calls } = makeMockedClient([]);
    const oversized = "A".repeat(6_990_508);
    expect(() =>
      client.vision.extract({
        base64: oversized,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/exceeds the maximum length of 6990507 characters/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string imageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        imageUri: 42 as unknown as string,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/`imageUri` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty imageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        imageUri: "",
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/`imageUri` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for oversized imageUri (>2048)", () => {
    const { client, calls } = makeMockedClient([]);
    const oversized = "https://example.com/" + "a".repeat(2050);
    expect(() =>
      client.vision.extract({
        imageUri: oversized,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).toThrowError(/exceeds the maximum length of 2048 characters/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for non-string extractionSchema", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        extractionSchema: 42 as unknown as "model-card",
      }),
    ).toThrowError(/`extractionSchema` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown extractionSchema (closed-enum)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        extractionSchema: "not-a-real-schema" as unknown as "model-card",
      }),
    ).toThrowError(/`extractionSchema` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("accepts extractionSchema explicitly undefined (own-present, value undefined → skip)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
    ]);
    await client.vision.extract({
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
      extractionSchema: undefined,
    });
    // extractionSchema should NOT appear in the serialized body.
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.extractionSchema).toBeUndefined();
    expect(Object.hasOwn(parsed, "extractionSchema")).toBe(false);
  });

  it("throws TypeError for non-string model", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        model: 42 as unknown as "opus",
      }),
    ).toThrowError(/`model` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown model (closed-enum)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        model: "haiku" as unknown as "opus",
      }),
    ).toThrowError(/`model` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("accepts model own-present but undefined (skip path)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
    ]);
    await client.vision.extract({
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
      model: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.model).toBeUndefined();
  });

  it("throws TypeError for non-string packId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: 42 as unknown as string,
      }),
    ).toThrowError(/`packId` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty packId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: "",
      }),
    ).toThrowError(/`packId` must be a non-empty string when provided/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for malformed packId UUID", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: "not-a-uuid",
      }),
    ).toThrowError(/`packId` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("accepts packId own-present but undefined (skip path)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
    ]);
    await client.vision.extract({
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
      packId: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.hasOwn(parsed, "packId")).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.extract — response P2 validation
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extract — P2 response-shape hardening", () => {
  it("throws AttestryError when kernel response is null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    let caught: unknown;
    try {
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /expected an object response from the kernel \(got null\)/,
    );
  });

  it("throws AttestryError when kernel response is an array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_EXTRACT_RESPONSE_NO_PACK] } },
    ]);
    let caught: unknown;
    try {
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect((caught as AttestryError).message).toMatch(/\(got array\)/);
  });

  it("throws AttestryError when callId is missing", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, callId: undefined },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.callId to be a string/);
  });

  it("accepts structuredExtraction: null (parse_failed path)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, structuredExtraction: null },
        },
      },
    ]);
    const out = await client.vision.extract({
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
    });
    expect(out.structuredExtraction).toBeNull();
  });

  it("throws AttestryError when structuredExtraction is an array", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_EXTRACT_RESPONSE_NO_PACK,
            structuredExtraction: ["array", "not", "object"],
          },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.structuredExtraction.*\(got array\)/);
  });

  it("throws AttestryError when confidencePerField is not an object", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, confidencePerField: null },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.confidencePerField to be an object/);
  });

  it("throws AttestryError when sourceRegions is not an object", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, sourceRegions: "string" },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.sourceRegions to be an object/);
  });

  it("throws AttestryError when tokensUsed is not an object", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, tokensUsed: 42 },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.tokensUsed to be an object/);
  });

  // Founder hostile-review F3 — tokensUsed inner-field round-trip
  // validation. tokensUsed is a fixed, always-present, closed 4-number
  // shape (input/output/cacheCreation/cacheRead). The P2 validator now
  // enforces each inner field is a number so a kernel regression that
  // mistyped one cannot round-trip a non-number typed as `number`.
  it("throws AttestryError when a tokensUsed inner field is a non-number (round-trip integrity)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_EXTRACT_RESPONSE_NO_PACK,
            tokensUsed: {
              input: "lots", // non-number — must be rejected
              output: 500,
              cacheCreation: 0,
              cacheRead: 0,
            },
          },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.tokensUsed.input to be a number/);
  });

  it("throws AttestryError when a tokensUsed inner field is MISSING (own-property false branch)", async () => {
    // Omit `cacheRead` entirely — JSON.stringify drops undefined, so the
    // wire body has no `cacheRead` key; `objectHasOwn` is false → the
    // `: undefined` branch fires → typeof undefined !== "number" → throw.
    const tokensDict: Record<string, unknown> = {
      input: 1500,
      output: 500,
      cacheCreation: 0,
      cacheRead: 0,
    };
    delete tokensDict.cacheRead;
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, tokensUsed: tokensDict },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.tokensUsed.cacheRead to be a number/);
  });

  it("throws AttestryError when costUsdCents is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, costUsdCents: "22" },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.costUsdCents to be a number/);
  });

  it("throws AttestryError when latencyMs is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, latencyMs: null },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.latencyMs to be a number/);
  });

  // R4 coverage round — exercise the `: undefined` branch of every
  // own-property-snapshot ternary in `extract`'s P2 response validation.
  // The existing wrong-type tests above pass the field with a non-string/
  // non-object value, hitting the `? obj.X` branch. These tests OMIT the
  // field entirely from the wire body (via the `bodyText` raw-JSON
  // option) so `objectHasOwn(obj, "X") === false` and the `: undefined`
  // branch fires. P2 hardening must reject missing-field responses
  // identically to wrong-type responses (symmetric defense against
  // kernel-side regressions that drop a field).
  it("throws AttestryError when structuredExtraction is MISSING (own-property false → undefined branch)", async () => {
    // Construct a body where structuredExtraction is genuinely absent.
    // JSON.stringify drops `undefined` values from objects, so passing
    // `structuredExtraction: undefined` in the spread produces a body
    // with no `structuredExtraction` key.
    const bodyDict = { ...MOCK_EXTRACT_RESPONSE_NO_PACK } as Record<
      string,
      unknown
    >;
    delete bodyDict.structuredExtraction;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.structuredExtraction to be an object or null/);
  });

  it("throws AttestryError when confidencePerField is MISSING (own-property false branch)", async () => {
    const bodyDict = { ...MOCK_EXTRACT_RESPONSE_NO_PACK } as Record<
      string,
      unknown
    >;
    delete bodyDict.confidencePerField;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.confidencePerField to be an object/);
  });

  it("throws AttestryError when sourceRegions is MISSING (own-property false branch)", async () => {
    const bodyDict = { ...MOCK_EXTRACT_RESPONSE_NO_PACK } as Record<
      string,
      unknown
    >;
    delete bodyDict.sourceRegions;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.sourceRegions to be an object/);
  });

  it("throws AttestryError when tokensUsed is MISSING (own-property false branch)", async () => {
    const bodyDict = { ...MOCK_EXTRACT_RESPONSE_NO_PACK } as Record<
      string,
      unknown
    >;
    delete bodyDict.tokensUsed;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.tokensUsed to be an object/);
  });

  it("throws AttestryError when costUsdCents is MISSING (own-property false branch)", async () => {
    const bodyDict = { ...MOCK_EXTRACT_RESPONSE_NO_PACK } as Record<
      string,
      unknown
    >;
    delete bodyDict.costUsdCents;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.costUsdCents to be a number/);
  });

  it("throws AttestryError when latencyMs is MISSING (own-property false branch)", async () => {
    const bodyDict = { ...MOCK_EXTRACT_RESPONSE_NO_PACK } as Record<
      string,
      unknown
    >;
    delete bodyDict.latencyMs;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toThrow(/response.latencyMs to be a number/);
  });

  it("throws AttestryError when packIntegration is present but not an object", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_EXTRACT_RESPONSE_NO_PACK, packIntegration: "string" },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: VALID_PACK_ID,
      }),
    ).rejects.toThrow(/response.packIntegration to be an object/);
  });

  it("throws AttestryError when packIntegration.status is missing", async () => {
    const piMissingStatus = {
      packId: VALID_PACK_ID,
      schemaCompatibility: MOCK_PACK_INTEGRATION.schemaCompatibility,
    };
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_EXTRACT_RESPONSE_NO_PACK,
            packIntegration: piMissingStatus,
          },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: VALID_PACK_ID,
      }),
    ).rejects.toThrow(/packIntegration.status to be a string/);
  });

  it("throws AttestryError when packIntegration.packId is missing", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_EXTRACT_RESPONSE_NO_PACK,
            packIntegration: {
              status: "wrapped",
              schemaCompatibility: MOCK_PACK_INTEGRATION.schemaCompatibility,
            },
          },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: VALID_PACK_ID,
      }),
    ).rejects.toThrow(/packIntegration.packId to be a string/);
  });

  it("throws AttestryError when packIntegration.schemaCompatibility is missing", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_EXTRACT_RESPONSE_NO_PACK,
            packIntegration: { status: "wrapped", packId: VALID_PACK_ID },
          },
        },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: VALID_PACK_ID,
      }),
    ).rejects.toThrow(/packIntegration.schemaCompatibility to be an object/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.extract — error mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extract — error mapping", () => {
  it("surfaces 401 as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      { status: 401, body: { success: false, error: "Unauthorized." } },
    ]);
    try {
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("surfaces 422 with vision.validation_failed code in details", async () => {
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          code: "vision.validation_failed",
          issues: [{ path: "documentType", message: "Required" }],
        },
      },
    ]);
    try {
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      const details = apiErr.details as { code?: string };
      expect(details?.code).toBe("vision.validation_failed");
    }
  });

  it("surfaces 404 (pack not found) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 404,
        body: {
          success: false,
          error: "evidence pack not found",
          code: "evidence_pack.not_found",
        },
      },
    ]);
    try {
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: VALID_PACK_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
    }
  });

  it("surfaces 409 (non-draft pack) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 409,
        body: {
          success: false,
          error: "pack is in 'signed' state",
          code: "evidence_pack.invalid_state",
        },
      },
    ]);
    try {
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
        packId: VALID_PACK_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(409);
    }
  });

  it("surfaces 502 (upstream Anthropic) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 502,
        body: { success: false, error: "Upstream gateway fault." },
      },
    ]);
    await expect(
      client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      }),
    ).rejects.toBeInstanceOf(AttestryAPIError);
  });

  it("HR-4(b) confirmation: non-JSON 200 surfaces as AttestryAPIError (NOT SyntaxError)", async () => {
    // The transport's P3 content-type guard (transport.ts:271-291) catches
    // non-JSON 200 responses before parsing. Confirms the HR-4(b) defect
    // class does NOT apply to the SDK transport.
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
      await client.vision.extract({
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect(caught).not.toBeInstanceOf(SyntaxError);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.extract — abort signal
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extract — abort signal", () => {
  it("rejects synchronously when caller's AbortSignal is pre-aborted", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.vision.extract(
        {
          base64: SAMPLE_BASE64,
          mediaType: "image/png",
          documentType: "model-card",
        },
        { signal: controller.signal },
      ),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted AbortSignal and completes normally", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_EXTRACT_RESPONSE_NO_PACK } },
    ]);
    const controller = new AbortController();
    const out = await client.vision.extract(
      {
        base64: SAMPLE_BASE64,
        mediaType: "image/png",
        documentType: "model-card",
      },
      { signal: controller.signal },
    );
    expect(out).toEqual(MOCK_EXTRACT_RESPONSE_NO_PACK);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.extractBatch — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extractBatch — happy path", () => {
  it("POSTs /api/v1/vision/extract/batch with a single document", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_BATCH_RESPONSE } },
    ]);
    const out = await client.vision.extractBatch({
      documents: [
        {
          base64: SAMPLE_BASE64,
          mediaType: "image/png",
          documentType: "model-card",
        },
      ],
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    const url = new URL(calls[0].url);
    expect(url.pathname).toBe("/api/v1/vision/extract/batch");
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed).toEqual({
      documents: [
        {
          base64: SAMPLE_BASE64,
          mediaType: "image/png",
          documentType: "model-card",
        },
      ],
    });
    expect(out).toEqual(MOCK_BATCH_RESPONSE);
  });

  it("POSTs with multiple documents + model + per-doc extractionSchema + sourceImageUri", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_BATCH_RESPONSE } },
    ]);
    await client.vision.extractBatch({
      documents: [
        {
          imageUri: "https://example.com/cert1.png",
          mediaType: "image/png",
          documentType: "certification-label",
          extractionSchema: "certification-label",
          sourceImageUri: "https://internal.example/audit-pointer-1",
        },
        {
          base64: SAMPLE_BASE64,
          mediaType: "image/jpeg",
          documentType: "validation-report",
        },
      ],
      model: "sonnet",
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.documents).toHaveLength(2);
    expect(parsed.model).toBe("sonnet");
    expect(parsed.documents[0].extractionSchema).toBe("certification-label");
    expect(parsed.documents[0].sourceImageUri).toBe(
      "https://internal.example/audit-pointer-1",
    );
  });

  it("forwards x-api-key + Accept + Content-Type headers", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_BATCH_RESPONSE } },
    ]);
    await client.vision.extractBatch({
      documents: [
        {
          base64: SAMPLE_BASE64,
          mediaType: "image/png",
          documentType: "model-card",
        },
      ],
    });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.extractBatch — input validation
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extractBatch — input validation", () => {
  it("throws TypeError for null input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch(null as unknown as VisionBatchExtractInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for array input", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch([] as unknown as VisionBatchExtractInput),
    ).toThrowError(TypeError);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when documents is missing", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({} as unknown as VisionBatchExtractInput),
    ).toThrowError(/`documents` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when documents is own-present but undefined", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: undefined as unknown as VisionBatchExtractInput["documents"],
      }),
    ).toThrowError(/`documents` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when documents is not an array", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: "not-array" as unknown as VisionBatchExtractInput["documents"],
      }),
    ).toThrowError(/`documents` must be an array/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when documents is an empty array", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({ documents: [] }),
    ).toThrowError(/`documents` must contain at least one entry/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document is null", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [null] as unknown as VisionBatchExtractInput["documents"],
      }),
    ).toThrowError(/`documents\[0\]` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document is an array", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          [] as unknown,
        ] as unknown as VisionBatchExtractInput["documents"],
      }),
    ).toThrowError(/`documents\[0\]` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document is missing mediaType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            documentType: "model-card",
          } as unknown as VisionBatchExtractInput["documents"][number],
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+mediaType is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document has bad mediaType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType:
              "image/bmp" as unknown as VisionBatchExtractInput["documents"][number]["mediaType"],
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+mediaType must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document has non-string mediaType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType:
              42 as unknown as VisionBatchExtractInput["documents"][number]["mediaType"],
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+mediaType must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document is missing documentType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
          } as unknown as VisionBatchExtractInput["documents"][number],
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+documentType is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document has non-string documentType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType:
              42 as unknown as VisionBatchExtractInput["documents"][number]["documentType"],
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+documentType must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document has bad documentType", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType:
              "not-a-real-doc" as unknown as VisionBatchExtractInput["documents"][number]["documentType"],
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+documentType must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document has both base64 and imageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            imageUri: "https://example.com/img.png",
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/mutually exclusive/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError when a document has neither base64 nor imageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/exactly one of `base64` or `imageUri` is required/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document non-string base64", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: 42 as unknown as string,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+base64 must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document empty base64", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: "",
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+base64 must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document oversized base64", () => {
    const { client, calls } = makeMockedClient([]);
    const oversized = "A".repeat(6_990_508);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: oversized,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/exceeds the maximum length of 6990507 characters/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document non-string imageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            imageUri: 42 as unknown as string,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+imageUri must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document empty imageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            imageUri: "",
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+imageUri must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document oversized imageUri", () => {
    const { client, calls } = makeMockedClient([]);
    const oversized = "https://example.com/" + "a".repeat(2050);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            imageUri: oversized,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+imageUri exceeds the maximum length of 2048 characters/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document non-string extractionSchema", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
            extractionSchema:
              42 as unknown as VisionBatchExtractInput["documents"][number]["extractionSchema"],
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+extractionSchema must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document bad extractionSchema", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
            extractionSchema:
              "not-real" as unknown as VisionBatchExtractInput["documents"][number]["extractionSchema"],
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+extractionSchema must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("accepts document with own-present-but-undefined extractionSchema (skip path)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_BATCH_RESPONSE } },
    ]);
    await client.vision.extractBatch({
      documents: [
        {
          base64: SAMPLE_BASE64,
          mediaType: "image/png",
          documentType: "model-card",
          extractionSchema: undefined,
        },
      ],
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.hasOwn(parsed.documents[0], "extractionSchema")).toBe(false);
  });

  it("throws TypeError for document non-string sourceImageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
            sourceImageUri: 42 as unknown as string,
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+sourceImageUri must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document empty sourceImageUri", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
            sourceImageUri: "",
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+sourceImageUri must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for document oversized sourceImageUri", () => {
    const { client, calls } = makeMockedClient([]);
    const oversized = "https://example.com/" + "a".repeat(2050);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
            sourceImageUri: oversized,
          },
        ],
      }),
    ).toThrowError(/documents\[0\][^A-Za-z]+sourceImageUri exceeds the maximum length of 2048/);
    expect(calls).toHaveLength(0);
  });

  it("accepts document with own-present-but-undefined sourceImageUri (skip path)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_BATCH_RESPONSE } },
    ]);
    await client.vision.extractBatch({
      documents: [
        {
          base64: SAMPLE_BASE64,
          mediaType: "image/png",
          documentType: "model-card",
          sourceImageUri: undefined,
        },
      ],
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(Object.hasOwn(parsed.documents[0], "sourceImageUri")).toBe(false);
  });

  it("throws TypeError for non-string model", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
        model: 42 as unknown as "opus",
      }),
    ).toThrowError(/`model` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for unknown model", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
        model: "haiku" as unknown as "opus",
      }),
    ).toThrowError(/`model` must be one of/);
    expect(calls).toHaveLength(0);
  });

  it("accepts batch with own-present-but-undefined model (skip path)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_BATCH_RESPONSE } },
    ]);
    await client.vision.extractBatch({
      documents: [
        {
          base64: SAMPLE_BASE64,
          mediaType: "image/png",
          documentType: "model-card",
        },
      ],
      model: undefined,
    });
    const parsed = JSON.parse(calls[0].body!);
    expect(parsed.model).toBeUndefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.extractBatch — response P2 validation
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extractBatch — P2 response-shape hardening", () => {
  it("throws AttestryError when response is null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).rejects.toThrow(/expected an object response from the kernel \(got null\)/);
  });

  it("throws AttestryError when response is an array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_BATCH_RESPONSE] } },
    ]);
    await expect(
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).rejects.toThrow(/\(got array\)/);
  });

  it("throws AttestryError when jobId is missing", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { status: "queued" } } },
    ]);
    await expect(
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).rejects.toThrow(/response.jobId to be a string/);
  });

  it("throws AttestryError when status is missing", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { jobId: "55555555-5555-5555-5555-555555555555" },
        },
      },
    ]);
    await expect(
      client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      }),
    ).rejects.toThrow(/response.status to be a string/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.extractBatch — error mapping
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.extractBatch — error mapping", () => {
  it("surfaces 403 (plan_required) with code in details", async () => {
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error: "This feature is not available on your current plan.",
          code: "vision.batch.plan_required",
          feature: "hasBatchVision",
          currentPlan: "growth",
        },
      },
    ]);
    try {
      await client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      expect((apiErr.details as { code?: string })?.code).toBe(
        "vision.batch.plan_required",
      );
    }
  });

  it("surfaces 429 (queue_limit) with code in details", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: {
          success: false,
          error: "Organization already has 5 active vision batch jobs",
          code: "vision.batch.queue_limit",
        },
      },
    ]);
    try {
      await client.vision.extractBatch({
        documents: [
          {
            base64: SAMPLE_BASE64,
            mediaType: "image/png",
            documentType: "model-card",
          },
        ],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.getJobStatus — happy path
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.getJobStatus — happy path", () => {
  it("GETs /api/v1/vision/extract/jobs/{jobId} with no body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_JOB_STATUS } },
    ]);
    const out = await client.vision.getJobStatus(VALID_UUID);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("GET");
    expect(calls[0].url).toBe(
      `https://test.attestry.local/api/v1/vision/extract/jobs/${VALID_UUID}`,
    );
    expect(calls[0].body).toBeUndefined();
    expect(calls[0].headers.get("Content-Type")).toBeNull();
    expect(out).toEqual(MOCK_JOB_STATUS);
  });

  it("forwards x-api-key + Accept headers (GET, no Content-Type)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: MOCK_JOB_STATUS } },
    ]);
    await client.vision.getJobStatus(VALID_UUID);
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.getJobStatus — input validation
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.getJobStatus — input validation", () => {
  it("throws TypeError for non-string jobId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.getJobStatus(42 as unknown as string),
    ).toThrowError(/`jobId` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for null jobId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.getJobStatus(null as unknown as string),
    ).toThrowError(/`jobId` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for undefined jobId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.vision.getJobStatus(undefined as unknown as string),
    ).toThrowError(/`jobId` must be a string/);
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for empty jobId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.vision.getJobStatus("")).toThrowError(
      /`jobId` must be a non-empty string/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for malformed UUID jobId", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.vision.getJobStatus("not-a-uuid")).toThrowError(
      /`jobId` must be an RFC 4122 hyphenated UUID/,
    );
    expect(calls).toHaveLength(0);
  });

  it("throws TypeError for jobId with path-traversal characters (regex blocks)", () => {
    const { client, calls } = makeMockedClient([]);
    expect(() => client.vision.getJobStatus("..")).toThrowError(TypeError);
    expect(() => client.vision.getJobStatus("./..")).toThrowError(TypeError);
    expect(() => client.vision.getJobStatus("foo\0bar")).toThrowError(
      TypeError,
    );
    expect(calls).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.getJobStatus — response P2 validation
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.getJobStatus — P2 response-shape hardening", () => {
  it("throws AttestryError when response is null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: null } },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /expected an object response from the kernel \(got null\)/,
    );
  });

  it("throws AttestryError when response is an array", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: [MOCK_JOB_STATUS] } },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /\(got array\)/,
    );
  });

  it("throws AttestryError when jobId field is not a string", async () => {
    const { client } = makeMockedClient([
      {
        body: { success: true, data: { ...MOCK_JOB_STATUS, jobId: 42 } },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.jobId to be a string/,
    );
  });

  it("throws AttestryError when status is missing", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, status: undefined },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.status to be a string/,
    );
  });

  it("throws AttestryError when modelTier is missing", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, modelTier: undefined },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.modelTier to be a string/,
    );
  });

  it("throws AttestryError when createdAt is missing", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, createdAt: undefined },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.createdAt to be a string/,
    );
  });

  it("throws AttestryError when documentCount is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, documentCount: "3" },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.documentCount to be a number/,
    );
  });

  it("throws AttestryError when documentsProcessed is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, documentsProcessed: null },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.documentsProcessed to be a number/,
    );
  });

  it("throws AttestryError when costUsdCents is not a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, costUsdCents: "44" },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.costUsdCents to be a number/,
    );
  });

  it("accepts costTokensInput as number (in-range)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, costTokensInput: 1500 },
        },
      },
    ]);
    const out = await client.vision.getJobStatus(VALID_UUID);
    expect(out.costTokensInput).toBe(1500);
  });

  it("accepts costTokensInput as string (bigint out-of-range)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_JOB_STATUS,
            costTokensInput: "999999999999999999999",
          },
        },
      },
    ]);
    const out = await client.vision.getJobStatus(VALID_UUID);
    expect(out.costTokensInput).toBe("999999999999999999999");
  });

  it("throws AttestryError when costTokensInput is null (neither number nor string)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, costTokensInput: null },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.costTokensInput to be a number or string/,
    );
  });

  it("throws AttestryError when costTokensOutput is an array", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, costTokensOutput: [42] },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.costTokensOutput to be a number or string/,
    );
  });

  it("accepts errorLog as null (no errors)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, errorLog: null },
        },
      },
    ]);
    const out = await client.vision.getJobStatus(VALID_UUID);
    expect(out.errorLog).toBeNull();
  });

  it("accepts errorLog as array", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_JOB_STATUS,
            errorLog: [{ docIndex: 2, error: "Parse failed" }],
          },
        },
      },
    ]);
    const out = await client.vision.getJobStatus(VALID_UUID);
    expect(out.errorLog).toEqual([{ docIndex: 2, error: "Parse failed" }]);
  });

  it("throws AttestryError when errorLog is an object (not array)", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, errorLog: { error: "wrong" } },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.errorLog to be an array or null/,
    );
  });

  it("accepts resultPackId as null", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_JOB_STATUS, resultPackId: null } } },
    ]);
    const out = await client.vision.getJobStatus(VALID_UUID);
    expect(out.resultPackId).toBeNull();
  });

  it("accepts resultPackId as string UUID", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, resultPackId: VALID_PACK_ID },
        },
      },
    ]);
    const out = await client.vision.getJobStatus(VALID_UUID);
    expect(out.resultPackId).toBe(VALID_PACK_ID);
  });

  it("throws AttestryError when resultPackId is a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, resultPackId: 42 },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.resultPackId to be a string or null/,
    );
  });

  it("accepts startedAt as null AND as string", async () => {
    const { client: c1 } = makeMockedClient([
      { body: { success: true, data: { ...MOCK_JOB_STATUS, startedAt: null } } },
    ]);
    const out1 = await c1.vision.getJobStatus(VALID_UUID);
    expect(out1.startedAt).toBeNull();

    const { client: c2 } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, startedAt: "2026-05-18T13:55:52.000Z" },
        },
      },
    ]);
    const out2 = await c2.vision.getJobStatus(VALID_UUID);
    expect(out2.startedAt).toBe("2026-05-18T13:55:52.000Z");
  });

  it("throws AttestryError when startedAt is a number", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, startedAt: 1234567890 },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.startedAt to be a string or null/,
    );
  });

  it("accepts completedAt as null AND as string", async () => {
    const { client: c1 } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, completedAt: null },
        },
      },
    ]);
    const out1 = await c1.vision.getJobStatus(VALID_UUID);
    expect(out1.completedAt).toBeNull();

    const { client: c2 } = makeMockedClient([
      {
        body: {
          success: true,
          data: {
            ...MOCK_JOB_STATUS,
            completedAt: "2026-05-18T13:56:00.000Z",
          },
        },
      },
    ]);
    const out2 = await c2.vision.getJobStatus(VALID_UUID);
    expect(out2.completedAt).toBe("2026-05-18T13:56:00.000Z");
  });

  it("throws AttestryError when completedAt is a boolean", async () => {
    const { client } = makeMockedClient([
      {
        body: {
          success: true,
          data: { ...MOCK_JOB_STATUS, completedAt: false },
        },
      },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.completedAt to be a string or null/,
    );
  });

  // R4 coverage round — exercise the `: undefined` branch of every
  // ternary inside `getJobStatus`'s P2 validation loops. The wrong-type
  // tests above pass values (own-property true → `? obj[field]` branch).
  // These tests OMIT one field per loop so `objectHasOwn(obj, field)
  // === false` and the `: undefined` else-branch fires.
  it("throws AttestryError when documentCount is MISSING (numberFields loop undefined branch)", async () => {
    const bodyDict = { ...MOCK_JOB_STATUS } as Record<string, unknown>;
    delete bodyDict.documentCount;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.documentCount to be a number/,
    );
  });

  it("throws AttestryError when costTokensInput is MISSING (bigintFields loop undefined branch)", async () => {
    const bodyDict = { ...MOCK_JOB_STATUS } as Record<string, unknown>;
    delete bodyDict.costTokensInput;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.costTokensInput to be a number or string/,
    );
  });

  it("throws AttestryError when errorLog is MISSING (single-line ternary undefined branch)", async () => {
    // errorLog accepts `null | array`. When MISSING, objectHasOwn is
    // false → v = undefined. `undefined !== null && !Array.isArray
    // (undefined)` is true, so the throw fires.
    const bodyDict = { ...MOCK_JOB_STATUS } as Record<string, unknown>;
    delete bodyDict.errorLog;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.errorLog to be an array or null/,
    );
  });

  it("throws AttestryError when resultPackId is MISSING (nullableStringFields loop undefined branch)", async () => {
    // nullableStringFields accept `null | string`. MISSING ⇒
    // undefined ⇒ NOT null AND NOT string ⇒ throw.
    const bodyDict = { ...MOCK_JOB_STATUS } as Record<string, unknown>;
    delete bodyDict.resultPackId;
    const { client } = makeMockedClient([
      { body: { success: true, data: bodyDict } },
    ]);
    await expect(client.vision.getJobStatus(VALID_UUID)).rejects.toThrow(
      /response.resultPackId to be a string or null/,
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// vision.getJobStatus — error mapping + abort
// ═══════════════════════════════════════════════════════════════════════════

describe("vision.getJobStatus — error mapping + abort", () => {
  it("surfaces 404 (anti-enumeration: unknown id OR cross-org)", async () => {
    const { client } = makeMockedClient([
      { status: 404, body: { success: false, error: "Job not found." } },
    ]);
    try {
      await client.vision.getJobStatus(VALID_UUID);
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
      expect((err as AttestryAPIError).message).toBe("Job not found.");
    }
  });

  it("rejects synchronously when caller's AbortSignal is pre-aborted", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.vision.getJobStatus(VALID_UUID, { signal: controller.signal }),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });
});
