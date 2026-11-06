import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { z } from "zod";
import {
  evidencePackSupersede,
  evidencePackSupersedeSchema,
  deriveIdempotencyKey,
} from "../evidence-pack-supersede.js";

/**
 * KE2 P1.7 — Build round: unit tests for `evidence_pack.supersede`.
 *
 * Unlike the sign / revoke / export unit tests (which `vi.mock` the client
 * module), these tests stub `globalThis.fetch` and exercise the REAL
 * `getConfig` plus the tool's own `postWithIdempotencyKey` helper — because
 * the supersede tool issues its own header-bearing POST rather than routing
 * through the mockable `apiPost` (DEV-54 / DEV-58).
 */

const OLD_PACK_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const ORIG_KEY = process.env.ATTESTRY_API_KEY;
const ORIG_URL = process.env.ATTESTRY_API_URL;
const NEW_PACK = { packType: "annex_iv" };

beforeEach(() => {
  process.env.ATTESTRY_API_KEY = "test-key-p17-supersede";
  process.env.ATTESTRY_API_URL = "https://attestry.test";
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (ORIG_KEY === undefined) delete process.env.ATTESTRY_API_KEY;
  else process.env.ATTESTRY_API_KEY = ORIG_KEY;
  if (ORIG_URL === undefined) delete process.env.ATTESTRY_API_URL;
  else process.env.ATTESTRY_API_URL = ORIG_URL;
});

/** Stub `globalThis.fetch`; return the mock so calls can be inspected. */
function stubFetch(impl: (...args: unknown[]) => unknown) {
  const mock = vi.fn(impl);
  vi.stubGlobal("fetch", mock);
  return mock;
}

/** A `fetch` stub that resolves a JSON body. */
function jsonResponse(body: unknown) {
  return () => ({ json: async () => body });
}

interface DecodedFetchCall {
  url: string;
  method?: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

/** Decode a recorded `fetch` call into its url / method / headers / body. */
function fetchCallAt(
  mock: ReturnType<typeof stubFetch>,
  i: number,
): DecodedFetchCall {
  const [url, opts] = mock.mock.calls[i] as [
    string,
    { method?: string; headers: Record<string, string>; body: string },
  ];
  return {
    url,
    method: opts.method,
    headers: opts.headers,
    body: JSON.parse(opts.body) as Record<string, unknown>,
  };
}

describe("evidence_pack.supersede — happy path", () => {
  it("POSTs to /{id}/supersede with {newPack} and returns {newPack, oldPack}", async () => {
    const fetchMock = stubFetch(
      jsonResponse({
        success: true,
        data: { newPack: { id: "new-1" }, oldPack: { id: OLD_PACK_ID } },
      }),
    );

    const result = await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: NEW_PACK,
    });

    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text).newPack.id).toBe("new-1");

    const call = fetchCallAt(fetchMock, 0);
    expect(call.url).toBe(
      `https://attestry.test/api/v1/evidence-packs/${OLD_PACK_ID}/supersede`,
    );
    expect(call.method).toBe("POST");
    expect(call.body).toEqual({ newPack: NEW_PACK });
  });

  it("sends the x-api-key and a derived Idempotency-Key header", async () => {
    const fetchMock = stubFetch(jsonResponse({ success: true, data: {} }));

    await evidencePackSupersede({ oldPackId: OLD_PACK_ID, newPack: NEW_PACK });

    const { headers } = fetchCallAt(fetchMock, 0);
    expect(headers["x-api-key"]).toBe("test-key-p17-supersede");
    expect(headers["Content-Type"]).toBe("application/json");
    expect(headers["Idempotency-Key"]).toBe(
      deriveIdempotencyKey(OLD_PACK_ID, NEW_PACK),
    );
  });

  it("never places idempotencyKey or oldPackId in the REST body", async () => {
    const fetchMock = stubFetch(jsonResponse({ success: true, data: {} }));

    await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: NEW_PACK,
      idempotencyKey: "caller-supplied-key",
    });

    expect(Object.keys(fetchCallAt(fetchMock, 0).body)).toEqual(["newPack"]);
  });
});

describe("evidence_pack.supersede — idempotency key (DQ-2)", () => {
  it("two identical supersede calls send the identical derived key", async () => {
    const fetchMock = stubFetch(jsonResponse({ success: true, data: {} }));

    await evidencePackSupersede({ oldPackId: OLD_PACK_ID, newPack: NEW_PACK });
    await evidencePackSupersede({ oldPackId: OLD_PACK_ID, newPack: NEW_PACK });

    expect(fetchCallAt(fetchMock, 0).headers["Idempotency-Key"]).toBe(
      fetchCallAt(fetchMock, 1).headers["Idempotency-Key"],
    );
  });

  it("a differing newPack produces a differing key", async () => {
    const fetchMock = stubFetch(jsonResponse({ success: true, data: {} }));

    await evidencePackSupersede({ oldPackId: OLD_PACK_ID, newPack: NEW_PACK });
    await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: { packType: "red_team_cycle" },
    });

    expect(fetchCallAt(fetchMock, 0).headers["Idempotency-Key"]).not.toBe(
      fetchCallAt(fetchMock, 1).headers["Idempotency-Key"],
    );
  });

  it("an explicit idempotencyKey overrides the derived key", async () => {
    const fetchMock = stubFetch(jsonResponse({ success: true, data: {} }));

    await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: NEW_PACK,
      idempotencyKey: "caller-supplied-key",
    });

    expect(fetchCallAt(fetchMock, 0).headers["Idempotency-Key"]).toBe(
      "caller-supplied-key",
    );
  });
});

describe("deriveIdempotencyKey — determinism + canonicalization (DQ-2)", () => {
  it("is a stable 64-char hex sha256 digest", () => {
    expect(deriveIdempotencyKey(OLD_PACK_ID, NEW_PACK)).toMatch(
      /^[a-f0-9]{64}$/,
    );
  });

  it("is independent of object key insertion order (canonicalization)", () => {
    const a = deriveIdempotencyKey(OLD_PACK_ID, {
      packType: "annex_iv",
      metadata: { a: 1, b: 2 },
    });
    const b = deriveIdempotencyKey(OLD_PACK_ID, {
      metadata: { b: 2, a: 1 },
      packType: "annex_iv",
    });
    expect(a).toBe(b);
  });

  it("preserves array order (array order is semantic)", () => {
    const a = deriveIdempotencyKey(OLD_PACK_ID, {
      frameworkBindings: [{ framework: "x" }, { framework: "y" }],
    });
    const b = deriveIdempotencyKey(OLD_PACK_ID, {
      frameworkBindings: [{ framework: "y" }, { framework: "x" }],
    });
    expect(a).not.toBe(b);
  });

  it("walks nested objects, arrays, primitives and null without error", () => {
    expect(
      deriveIdempotencyKey(OLD_PACK_ID, {
        packType: "annex_iv",
        frameworkBindings: [{ framework: "f", identifier: "i" }],
        metadata: { nested: { z: null, a: 1 }, flag: true },
      }),
    ).toMatch(/^[a-f0-9]{64}$/);
  });

  it("a differing oldPackId produces a differing key", () => {
    expect(deriveIdempotencyKey(OLD_PACK_ID, NEW_PACK)).not.toBe(
      deriveIdempotencyKey("ffffffff-e5f6-4a7b-8c9d-0e1f2a3b4c5d", NEW_PACK),
    );
  });

  it("distinguishes a payload with an own `__proto__` key (hostile-redux F-HR-1)", () => {
    // MCP arguments arrive via JSON.parse, which — unlike an object literal —
    // produces an own enumerable `__proto__` property. canonicalize must
    // preserve it (not let the Object.prototype setter swallow it), or two
    // structurally-different newPacks would derive the same key.
    const withProto = JSON.parse(
      '{"packType":"annex_iv","metadata":{"__proto__":{"x":1},"real":2}}',
    );
    const withoutProto = JSON.parse(
      '{"packType":"annex_iv","metadata":{"real":2}}',
    );
    expect(deriveIdempotencyKey(OLD_PACK_ID, withProto)).not.toBe(
      deriveIdempotencyKey(OLD_PACK_ID, withoutProto),
    );
  });
});

describe("evidence_pack.supersede — error mapping", () => {
  it("maps a 409 invalid-state error (old pack not signed), surfacing currentStatus", async () => {
    stubFetch(
      jsonResponse({
        success: false,
        error: "pack is in 'draft' state; only signed packs can be superseded",
        details: {
          code: "evidence_pack.invalid_state",
          currentStatus: "draft",
        },
      }),
    );

    const result = await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: NEW_PACK,
    });

    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.code).toBe("evidence_pack.invalid_state");
    expect(body.details.currentStatus).toBe("draft");
  });

  it("maps a 409 idempotency-key conflict, surfacing details.code", async () => {
    // Fixture mirrors the real kernel `IdempotencyKeyConflictError`
    // (idempotency.ts) — code `idempotency.key_conflict`, verbatim message
    // (hostile-redux HR2-1: the prior fixture pinned a fictional code).
    stubFetch(
      jsonResponse({
        success: false,
        error:
          "Idempotency-Key was previously used with a different request body",
        details: { code: "idempotency.key_conflict" },
      }),
    );

    const result = await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: NEW_PACK,
      idempotencyKey: "reused-key",
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).code).toBe("idempotency.key_conflict");
  });

  it("maps a cyclic newPack to a clean isError, not a raw exception (HR2-2)", async () => {
    // A cyclic object cannot arrive via the MCP protocol (`JSON.parse`
    // cannot build one), but a direct in-process caller could. The DQ-2 key
    // derivation runs inside the `callRest` closure, so the `canonicalize`
    // stack-overflow on a cycle surfaces as a clean transport `isError`
    // rather than escaping `evidencePackSupersede` as a raw exception.
    stubFetch(jsonResponse({ success: true, data: {} }));
    const cyclic: Record<string, unknown> = { packType: "annex_iv" };
    cyclic.self = cyclic;

    const result = await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: cyclic,
    });

    expect(result.isError).toBe(true);
  });

  it("maps a 403 auth error to a clean isError", async () => {
    stubFetch(
      jsonResponse({
        success: false,
        error: "Forbidden: write scope required",
      }),
    );

    const result = await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: NEW_PACK,
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("Forbidden");
  });

  it("maps a network failure to isError", async () => {
    stubFetch(() => Promise.reject(new TypeError("fetch failed")));

    const result = await evidencePackSupersede({
      oldPackId: OLD_PACK_ID,
      newPack: NEW_PACK,
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("fetch failed");
  });
});

describe("evidence_pack.supersede — schema validation", () => {
  const schema = z.object(evidencePackSupersedeSchema);

  it("accepts a minimal valid input", () => {
    expect(
      schema.safeParse({
        oldPackId: OLD_PACK_ID,
        newPack: { packType: "annex_iv" },
      }).success,
    ).toBe(true);
  });

  it("rejects a non-UUID oldPackId", () => {
    expect(
      schema.safeParse({
        oldPackId: "not-a-uuid",
        newPack: { packType: "annex_iv" },
      }).success,
    ).toBe(false);
  });

  it("rejects a missing newPack", () => {
    expect(schema.safeParse({ oldPackId: OLD_PACK_ID }).success).toBe(false);
  });

  it("rejects an out-of-enum newPack.packType", () => {
    expect(
      schema.safeParse({
        oldPackId: OLD_PACK_ID,
        newPack: { packType: "not_a_type" },
      }).success,
    ).toBe(false);
  });

  it("rejects an empty-string idempotencyKey", () => {
    expect(
      schema.safeParse({
        oldPackId: OLD_PACK_ID,
        newPack: { packType: "annex_iv" },
        idempotencyKey: "",
      }).success,
    ).toBe(false);
  });

  it("lowercases an uppercase oldPackId at the SDK boundary", () => {
    const parsed = schema.safeParse({
      oldPackId: "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D",
      newPack: { packType: "annex_iv" },
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data.oldPackId).toBe(OLD_PACK_ID);
    }
  });
});
