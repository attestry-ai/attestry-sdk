import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import {
  EvidencePackResource,
  type CreateEvidencePackInput,
  type GetEvidencePackInput,
  type ListEvidencePacksInput,
  type AddBundleInput,
  type SignEvidencePackInput,
  type SupersedeEvidencePackInput,
  type RevokeEvidencePackInput,
  type ExportEvidencePackInput,
} from "../evidence-pack.js";
import {
  VisionResource,
  type VisionExtractInput,
  type VisionBatchExtractInput,
} from "../vision.js";
import type { FetchLike } from "../../types.js";

// ─── Throwing-getter retrofit — evidence-pack + vision ──────────────────────
//
// Session-22 hostile review #1 (the SDK-wide MEDIUM-1 getter-throws
// contract gap), retrofit onto the 2.0 resources that predated the
// shared `readInputField` helper. Each public method that reads a
// consumer-supplied input object now snapshots every field through
// `readInputField`, which converts a throwing accessor's exception into
// the documented synchronous `TypeError` input contract (with the
// original error preserved on `.cause`).
//
// These integration pins mirror the 1.0 pattern in
// `abac-policies-create.test.ts` ("hostile review #1: throwing-getter
// MEDIUM-1 fix"): for every retrofitted method, a throwing own-getter on
// a representative field must surface as a `TypeError` (NOT the getter's
// raw error / a non-`TypeError` class), name the method + field, and
// issue NO request. The shared-helper unit tests live in
// `safe-input-read.test.ts`.

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

// A mock client whose fetch records every call. A throwing-getter input
// must reject synchronously BEFORE any request, so a 0-length `calls`
// array is part of the contract these tests assert.
function makeMockedClient(
  responses: Array<{ status?: number; body?: unknown }>,
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
    return new Response(JSON.stringify(r.body ?? {}), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    retry: { maxRetries: 0 },
  });
  // Instantiate the resources directly off the client. This decouples
  // these pins from how `AttestryClient` wires `client.evidencePack` /
  // `client.vision` (resource wiring is owned elsewhere); the
  // throwing-getter contract lives entirely in the resource methods.
  const evidencePack = new EvidencePackResource(client);
  const vision = new VisionResource(client);
  return { client, calls, evidencePack, vision };
}

const VALID_PACK_ID = "22222222-2222-2222-2222-222222222222";
const SAMPLE_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAA==";

// A reusable assertion: the thrown value is the SDK's `TypeError` input
// contract (cause-chained to the getter's original error), names the
// method + field, does NOT splice the getter's own message, and the call
// issued no request.
function expectThrowingGetterContract(
  run: () => unknown,
  calls: MockedRequest[],
  method: string,
  field: string,
): void {
  let caught: unknown;
  try {
    run();
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(TypeError);
  const msg = (caught as Error).message;
  expect(msg).toContain(method);
  expect(msg).toContain(field);
  // The getter's OWN message is NOT the SDK's contract message...
  expect(msg).not.toContain("getter boom");
  // ...but the original error is preserved on `.cause`.
  expect((caught as Error & { cause?: unknown }).cause).toBeInstanceOf(Error);
  // No request was issued — the throw is synchronous, pre-request.
  expect(calls).toHaveLength(0);
}

// ─── evidencePack ───────────────────────────────────────────────────────────

describe("evidencePack — throwing-getter retrofit (session-22 MEDIUM-1)", () => {
  it("create: a throwing `packType` getter surfaces as a TypeError (not the raw error)", () => {
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      get packType(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as CreateEvidencePackInput;
    expectThrowingGetterContract(
      () => evidencePack.create(evil),
      calls,
      "evidencePack.create",
      "packType",
    );
  });

  it("create: a throwing getter on a LATER field (`metadata`) is also converted", () => {
    // Proves the fix is not first-field-only — every snapshot read is
    // wrapped, not just the first.
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      packType: "annex_iv",
      get metadata(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as CreateEvidencePackInput;
    expectThrowingGetterContract(
      () => evidencePack.create(evil),
      calls,
      "evidencePack.create",
      "metadata",
    );
  });

  it("get: a throwing `packId` getter surfaces as a TypeError", () => {
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      get packId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as GetEvidencePackInput;
    expectThrowingGetterContract(
      () => evidencePack.get(evil),
      calls,
      "evidencePack.get",
      "packId",
    );
  });

  it("list: a throwing `systemId` getter (own-property on input) surfaces as a TypeError", () => {
    // `list` reads off `input ?? {}`; an own getter on the supplied
    // `input` passes `objectHasOwn` and reaches `readInputField`.
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      get systemId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as ListEvidencePacksInput;
    expectThrowingGetterContract(
      () => evidencePack.list(evil),
      calls,
      "evidencePack.list",
      "systemId",
    );
  });

  it("addBundle: a throwing `packId` getter surfaces as a TypeError", () => {
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      get packId(): unknown {
        throw new Error("getter boom");
      },
      traceContent: [],
      inputsHash: "sha256:" + "0".repeat(64),
      outputsHash: "sha256:" + "1".repeat(64),
    } as unknown as AddBundleInput;
    expectThrowingGetterContract(
      () => evidencePack.addBundle(evil),
      calls,
      "evidencePack.addBundle",
      "packId",
    );
  });

  it("addBundle: a throwing getter on a LATER field (`outputsHash`) is also converted", () => {
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      packId: VALID_PACK_ID,
      traceContent: [],
      inputsHash: "sha256:" + "0".repeat(64),
      get outputsHash(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as AddBundleInput;
    expectThrowingGetterContract(
      () => evidencePack.addBundle(evil),
      calls,
      "evidencePack.addBundle",
      "outputsHash",
    );
  });

  it("sign: a throwing `packId` getter surfaces as a TypeError", () => {
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      get packId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as SignEvidencePackInput;
    expectThrowingGetterContract(
      () => evidencePack.sign(evil),
      calls,
      "evidencePack.sign",
      "packId",
    );
  });

  it("supersede: a throwing `packId` getter surfaces as a TypeError", () => {
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      get packId(): unknown {
        throw new Error("getter boom");
      },
      newPack: { packType: "annex_iv" },
    } as unknown as SupersedeEvidencePackInput;
    expectThrowingGetterContract(
      () => evidencePack.supersede(evil),
      calls,
      "evidencePack.supersede",
      "packId",
    );
  });

  it("supersede: a throwing getter on a NESTED `newPack` field (`packType`) is also converted", () => {
    // The nested `newPack` object is consumer-supplied; its inner-field
    // reads go through `readInputField` too.
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      packId: VALID_PACK_ID,
      newPack: {
        get packType(): unknown {
          throw new Error("getter boom");
        },
      },
    } as unknown as SupersedeEvidencePackInput;
    expectThrowingGetterContract(
      () => evidencePack.supersede(evil),
      calls,
      "evidencePack.supersede",
      "packType",
    );
  });

  it("revoke: a throwing `packId` getter surfaces as a TypeError", () => {
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      get packId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as RevokeEvidencePackInput;
    expectThrowingGetterContract(
      () => evidencePack.revoke(evil),
      calls,
      "evidencePack.revoke",
      "packId",
    );
  });

  it("export: a throwing `packId` getter surfaces as a TypeError", () => {
    const { evidencePack, calls } = makeMockedClient([]);
    const evil = {
      get packId(): unknown {
        throw new Error("getter boom");
      },
      format: "json",
    } as unknown as ExportEvidencePackInput;
    expectThrowingGetterContract(
      () => evidencePack.export(evil),
      calls,
      "evidencePack.export",
      "packId",
    );
  });

  it("a throwing getter does NOT leak as a non-TypeError exception class (RangeError)", () => {
    // The getter throws a RangeError; the SDK still surfaces a
    // TypeError (the documented input-contract class), not RangeError.
    const { evidencePack } = makeMockedClient([]);
    const evil = {
      get packType(): unknown {
        throw new RangeError("range boom");
      },
    } as unknown as CreateEvidencePackInput;
    let caught: unknown;
    try {
      evidencePack.create(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught).not.toBeInstanceOf(RangeError);
  });
});

// ─── vision ─────────────────────────────────────────────────────────────────

describe("vision — throwing-getter retrofit (session-22 MEDIUM-1)", () => {
  it("extract: a throwing `mediaType` getter surfaces as a TypeError", () => {
    const { vision, calls } = makeMockedClient([]);
    const evil = {
      base64: SAMPLE_BASE64,
      get mediaType(): unknown {
        throw new Error("getter boom");
      },
      documentType: "model-card",
    } as unknown as VisionExtractInput;
    expectThrowingGetterContract(
      () => vision.extract(evil),
      calls,
      "vision.extract",
      "mediaType",
    );
  });

  it("extract: a throwing getter on a LATER field (`packId`) is also converted", () => {
    const { vision, calls } = makeMockedClient([]);
    const evil = {
      base64: SAMPLE_BASE64,
      mediaType: "image/png",
      documentType: "model-card",
      get packId(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as VisionExtractInput;
    expectThrowingGetterContract(
      () => vision.extract(evil),
      calls,
      "vision.extract",
      "packId",
    );
  });

  it("extractBatch: a throwing `documents` getter surfaces as a TypeError", () => {
    const { vision, calls } = makeMockedClient([]);
    const evil = {
      get documents(): unknown {
        throw new Error("getter boom");
      },
    } as unknown as VisionBatchExtractInput;
    expectThrowingGetterContract(
      () => vision.extractBatch(evil),
      calls,
      "vision.extractBatch",
      "documents",
    );
  });

  it("extractBatch: a throwing getter on a per-document field (`documents[0].mediaType`) is converted", () => {
    // The per-document objects are consumer-supplied; each
    // `documents[i]` field read goes through `readInputField` inside
    // `validateBatchDocument`.
    const { vision, calls } = makeMockedClient([]);
    const evil = {
      documents: [
        {
          base64: SAMPLE_BASE64,
          get mediaType(): unknown {
            throw new Error("getter boom");
          },
          documentType: "model-card",
        },
      ],
    } as unknown as VisionBatchExtractInput;
    expectThrowingGetterContract(
      () => vision.extractBatch(evil),
      calls,
      "vision.extractBatch",
      "mediaType",
    );
  });

  it("a throwing getter does NOT leak as a non-TypeError exception class (RangeError)", () => {
    const { vision } = makeMockedClient([]);
    const evil = {
      base64: SAMPLE_BASE64,
      get mediaType(): unknown {
        throw new RangeError("range boom");
      },
      documentType: "model-card",
    } as unknown as VisionExtractInput;
    let caught: unknown;
    try {
      vision.extract(evil);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect(caught).not.toBeInstanceOf(RangeError);
  });
});
