import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { evidencePackCreate } from "../evidence-pack-create.js";
import { evidencePackGet } from "../evidence-pack-get.js";
import { evidencePackList } from "../evidence-pack-list.js";
import { evidencePackAppendBundle } from "../evidence-pack-append-bundle.js";

/**
 * KE2 P1.5 — Round 3 (Hostile): residual-gap probes.
 *
 * Unlike the build-round unit tests, these probes do NOT mock
 * `../../client.js` — they exercise the REAL `apiGet` / `apiPost` /
 * `getConfig` and stub `globalThis.fetch`, so the actual transport-error
 * paths (`getConfig` throw, `fetch` rejection, `response.json()` throw)
 * and the actual `URL` construction run end-to-end.
 *
 * Audit-chain side-effect probe: N/A. The four MCP tools are pure HTTP
 * clients — they never touch the database or `audit_log`; the wrapped
 * P1.3 REST routes perform all audit emission server-side.
 */

const PACK_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const ORIG_KEY = process.env.ATTESTRY_API_KEY;
const ORIG_URL = process.env.ATTESTRY_API_URL;

beforeEach(() => {
  process.env.ATTESTRY_API_KEY = "test-key-p15-hostile";
  process.env.ATTESTRY_API_URL = "https://attestry.test";
});

afterEach(() => {
  vi.unstubAllGlobals();
  if (ORIG_KEY === undefined) delete process.env.ATTESTRY_API_KEY;
  else process.env.ATTESTRY_API_KEY = ORIG_KEY;
  if (ORIG_URL === undefined) delete process.env.ATTESTRY_API_URL;
  else process.env.ATTESTRY_API_URL = ORIG_URL;
});

/** Stub `globalThis.fetch` with an arbitrary implementation. */
function stubFetch(impl: (...args: unknown[]) => unknown) {
  const mock = vi.fn(impl);
  vi.stubGlobal("fetch", mock);
  return mock;
}

// ─── H-P15-1 — malformed / non-JSON response body ───────────────────────────

describe("H-P15-1 — non-JSON response body", () => {
  it("create: a body that fails response.json() → clean isError", async () => {
    stubFetch(() => ({
      json: async () => {
        throw new SyntaxError("Unexpected token < in JSON at position 0");
      },
    }));
    const result = await evidencePackCreate({ packType: "annex_iv" });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("request failed");
  });

  it("get: a body that fails response.json() → clean isError", async () => {
    stubFetch(() => ({
      json: async () => {
        throw new SyntaxError("Unexpected end of JSON input");
      },
    }));
    const result = await evidencePackGet({ packId: PACK_ID });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("request failed");
  });
});

// ─── H-P15-2 — missing ATTESTRY_API_KEY ─────────────────────────────────────

describe("H-P15-2 — missing API key (getConfig throws)", () => {
  it("get: an unset ATTESTRY_API_KEY → clean isError, no raw exception", async () => {
    delete process.env.ATTESTRY_API_KEY;
    const result = await evidencePackGet({ packId: PACK_ID });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("request failed");
  });
});

// ─── H-P15-3 — network failure ──────────────────────────────────────────────

describe("H-P15-3 — fetch network rejection", () => {
  it("list: a rejected fetch → clean isError", async () => {
    stubFetch(() => Promise.reject(new TypeError("fetch failed")));
    const result = await evidencePackList({});
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("fetch failed");
  });
});

// ─── H-P15-4 — HTTP 4xx with a valid JSON error envelope ────────────────────

describe("H-P15-4 — HTTP 404 with a JSON error envelope", () => {
  it("get: a 404 status is NOT a transport error — envelope flows through", async () => {
    // `apiGet` calls response.json() regardless of status; a 404 with a
    // valid error envelope must surface as isError + details.code, not as
    // a transport failure.
    stubFetch(() => ({
      status: 404,
      json: async () => ({
        success: false,
        error: "pack not found",
        details: { code: "evidence_pack.not_found" },
      }),
    }));
    const result = await evidencePackGet({ packId: PACK_ID });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.error).toBe("pack not found");
    expect(body.code).toBe("evidence_pack.not_found");
  });
});

// ─── H-P15-5 — valid-JSON non-envelope response body ────────────────────────

describe("H-P15-5 — valid JSON that is not the expected envelope", () => {
  it("list: a literal-null body → clean isError", async () => {
    stubFetch(() => ({ json: async () => null }));
    const result = await evidencePackList({});
    expect(result.isError).toBe(true);
  });

  it("get: an array body → clean isError", async () => {
    stubFetch(() => ({ json: async () => [] }));
    const result = await evidencePackGet({ packId: PACK_ID });
    expect(result.isError).toBe(true);
  });

  it("create: an envelope with no success field → clean isError", async () => {
    stubFetch(() => ({ json: async () => ({ unexpected: true }) }));
    const result = await evidencePackCreate({ packType: "annex_iv" });
    expect(result.isError).toBe(true);
  });
});

// ─── H-P15-6 / H-P15-7 — URL-path injection defense (encodeURIComponent) ────

describe("H-P15-6 — get: URL-path injection is neutralized", () => {
  it("a non-UUID packId with slashes is percent-encoded — no traversal", async () => {
    // `packId` is UUID-validated at the SDK boundary; this probes the
    // function-level `encodeURIComponent` defense-in-depth for a caller
    // that bypasses the schema.
    const fetchMock = stubFetch(() => ({
      json: async () => ({ success: true, data: {} }),
    }));
    await evidencePackGet({ packId: "../../../admin" });
    const calledUrl = String(fetchMock.mock.calls[0]?.[0]);
    expect(calledUrl).toContain("%2F");
    expect(calledUrl).not.toContain("/evidence-packs/../");
  });
});

describe("H-P15-7 — append_bundle: URL-path injection is neutralized", () => {
  it("a non-UUID packId with slashes is percent-encoded — /bundles intact", async () => {
    const fetchMock = stubFetch(() => ({
      json: async () => ({ success: true, data: {} }),
    }));
    await evidencePackAppendBundle({
      packId: "../../admin",
      traceContent: [],
      inputsHash: "h",
      outputsHash: "h",
    });
    const calledUrl = String(fetchMock.mock.calls[0]?.[0]);
    expect(calledUrl).toContain("%2F");
    expect(calledUrl).toContain("/bundles");
    expect(calledUrl).not.toContain("/evidence-packs/../");
  });
});
