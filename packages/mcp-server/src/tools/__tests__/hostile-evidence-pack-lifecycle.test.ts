import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { evidencePackSign } from "../evidence-pack-sign.js";
import {
  evidencePackSupersede,
  deriveIdempotencyKey,
} from "../evidence-pack-supersede.js";
import { evidencePackRevoke } from "../evidence-pack-revoke.js";
import { evidencePackExport } from "../evidence-pack-export.js";

/**
 * KE2 P1.7 — Round 3 (Hostile): residual-gap probes for the four lifecycle +
 * export MCP tools.
 *
 * Unlike the build-round sign / revoke / export unit tests (which mock
 * `../../client.js`), these probes exercise the REAL `apiGet` / `apiPost` /
 * `getConfig` and the supersede tool's REAL `postWithIdempotencyKey`, and
 * stub `globalThis.fetch` — so the actual transport-error paths
 * (`getConfig` throw, `fetch` rejection, `response.json()` throw) and the
 * actual `URL` construction run end-to-end.
 *
 * The `status` field on the `fetch` stubs below is illustrative — it
 * documents the HTTP status each fixture models. The tools read only
 * `response.json()`, never `.status` / `.ok` / `.headers`, so the response
 * body alone drives result classification; the numeric HTTP status is
 * intentionally not surfaced (residual R-1). (hostile-redux HR2-3.)
 *
 * Audit-chain side-effect probe: N/A. The four MCP tools are pure HTTP
 * clients — they never touch the database or `audit_log`. The kernel
 * `sign` / `revoke` / `supersede` routes emit `audit_log` entries
 * server-side under the configured API key's identity (the basis of the
 * provenance residual R-7); the MCP layer's only side effect is the
 * outbound HTTP request, which the probes below exercise.
 */

const PACK_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const NEW_PACK = { packType: "annex_iv" };
const ORIG_KEY = process.env.ATTESTRY_API_KEY;
const ORIG_URL = process.env.ATTESTRY_API_URL;

beforeEach(() => {
  process.env.ATTESTRY_API_KEY = "test-key-p17-hostile";
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

/** The recorded request URL for a given `fetch` call. */
function urlOf(mock: ReturnType<typeof stubFetch>, i: number): string {
  return String(mock.mock.calls[i]?.[0]);
}

/** The recorded request headers for a given `fetch` call. */
function headersOf(
  mock: ReturnType<typeof stubFetch>,
  i: number,
): Record<string, string> {
  return (mock.mock.calls[i]?.[1] as { headers: Record<string, string> })
    .headers;
}

// ─── H-P17-1 — non-JSON / malformed response body ───────────────────────────

describe("H-P17-1 — non-JSON response body → clean isError (real transport)", () => {
  it("sign: a body that fails response.json() → clean isError", async () => {
    stubFetch(() => ({
      json: async () => {
        throw new SyntaxError("Unexpected token < in JSON at position 0");
      },
    }));
    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("request failed");
  });

  it("export: a body that fails response.json() → clean isError", async () => {
    stubFetch(() => ({
      json: async () => {
        throw new SyntaxError("Unexpected end of JSON input");
      },
    }));
    const result = await evidencePackExport({ packId: PACK_ID });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("request failed");
  });

  it("supersede: a body that fails response.json() → clean isError", async () => {
    stubFetch(() => ({
      json: async () => {
        throw new SyntaxError("malformed body");
      },
    }));
    const result = await evidencePackSupersede({
      oldPackId: PACK_ID,
      newPack: NEW_PACK,
    });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("request failed");
  });
});

// ─── H-P17-2 — missing ATTESTRY_API_KEY (getConfig throws) ──────────────────

describe("H-P17-2 — missing API key (getConfig throws) → clean isError", () => {
  it("revoke: an unset ATTESTRY_API_KEY → clean isError, no raw exception", async () => {
    delete process.env.ATTESTRY_API_KEY;
    const result = await evidencePackRevoke({ packId: PACK_ID, confirm: true });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("request failed");
  });

  it("supersede: an unset key → clean isError (getConfig throws in the POST helper)", async () => {
    delete process.env.ATTESTRY_API_KEY;
    const result = await evidencePackSupersede({
      oldPackId: PACK_ID,
      newPack: NEW_PACK,
    });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("request failed");
  });
});

// ─── H-P17-3 — fetch network rejection ──────────────────────────────────────

describe("H-P17-3 — fetch network rejection → clean isError", () => {
  it("sign: a rejected fetch → clean isError, message preserved", async () => {
    stubFetch(() => Promise.reject(new TypeError("fetch failed")));
    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("fetch failed");
  });

  it("export: a rejected fetch → clean isError, message preserved", async () => {
    stubFetch(() => Promise.reject(new TypeError("fetch failed")));
    const result = await evidencePackExport({ packId: PACK_ID });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).error).toContain("fetch failed");
  });
});

// ─── H-P17-4 — DQ-1 authority: a 403 with no details.code ───────────────────

describe("H-P17-4 — DQ-1 authority: a 403 (no details.code) surfaces cleanly", () => {
  it("sign: HTTP 403 {success:false,error} → isError, message preserved, code undefined", async () => {
    stubFetch(() => ({
      status: 403,
      json: async () => ({ success: false, error: "Forbidden" }),
    }));
    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.error).toBe("Forbidden");
    expect(body.code).toBeUndefined();
  });
});

// ─── H-P17-5 — EmptyPackError on sign ───────────────────────────────────────

describe("H-P17-5 — EmptyPackError: sign on a bundle-less pack → 409 evidence_pack.empty", () => {
  it("sign: HTTP 409 evidence_pack.empty → isError + details.code surfaces", async () => {
    stubFetch(() => ({
      status: 409,
      json: async () => ({
        success: false,
        error: "pack has no bundles; cannot sign an empty pack",
        details: { code: "evidence_pack.empty" },
      }),
    }));
    const result = await evidencePackSign({ packId: PACK_ID, confirm: true });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).code).toBe("evidence_pack.empty");
  });
});

// ─── H-P17-6 — terminal-state transitions ───────────────────────────────────

describe("H-P17-6 — terminal-state: revoke/supersede on a non-signed pack → 409 + currentStatus", () => {
  it("revoke: HTTP 409 invalid_state → currentStatus surfaces", async () => {
    stubFetch(() => ({
      status: 409,
      json: async () => ({
        success: false,
        error: "pack is in 'draft' state",
        details: {
          code: "evidence_pack.invalid_state",
          currentStatus: "draft",
        },
      }),
    }));
    const result = await evidencePackRevoke({ packId: PACK_ID, confirm: true });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).details.currentStatus).toBe("draft");
  });

  it("supersede: HTTP 409 invalid_state → currentStatus surfaces", async () => {
    stubFetch(() => ({
      status: 409,
      json: async () => ({
        success: false,
        error: "pack is in 'revoked' state",
        details: {
          code: "evidence_pack.invalid_state",
          currentStatus: "revoked",
        },
      }),
    }));
    const result = await evidencePackSupersede({
      oldPackId: PACK_ID,
      newPack: NEW_PACK,
    });
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.text).details.currentStatus).toBe("revoked");
  });
});

// ─── H-P17-7 — export success/error discrimination (DEV-53) ──────────────────

describe("H-P17-7 — export: the raw-artifact discriminator over the real transport", () => {
  it("a 404 {success:false} envelope → isError + code, NOT a transport failure", async () => {
    stubFetch(() => ({
      status: 404,
      json: async () => ({
        success: false,
        error: "pack not found",
        details: { code: "evidence_pack.not_found" },
      }),
    }));
    const result = await evidencePackExport({ packId: PACK_ID });
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.text);
    expect(body.error).toBe("pack not found");
    expect(body.code).toBe("evidence_pack.not_found");
  });

  it("a raw {export,pack,bundles} artifact → success, passed through verbatim", async () => {
    const artifact = {
      export: { format: "json", schemaVersion: "evidence-pack-export.v1" },
      pack: { id: PACK_ID, status: "revoked" },
      bundles: [{ id: "bundle-1" }],
    };
    stubFetch(() => ({ status: 200, json: async () => artifact }));
    const result = await evidencePackExport({ packId: PACK_ID });
    expect(result.isError).toBe(false);
    expect(JSON.parse(result.text)).toEqual(artifact);
  });
});

// ─── H-P17-8 — DQ-2 idempotency key over the real transport ─────────────────

describe("H-P17-8 — DQ-2: supersede sends a deterministic Idempotency-Key (real transport)", () => {
  it("identical calls send the identical key; a differing newPack a differing key", async () => {
    const fetchMock = stubFetch(() => ({
      status: 200,
      json: async () => ({ success: true, data: {} }),
    }));

    await evidencePackSupersede({ oldPackId: PACK_ID, newPack: NEW_PACK });
    await evidencePackSupersede({ oldPackId: PACK_ID, newPack: NEW_PACK });
    await evidencePackSupersede({
      oldPackId: PACK_ID,
      newPack: { packType: "pccp_evidence" },
    });

    const key0 = headersOf(fetchMock, 0)["Idempotency-Key"];
    const key1 = headersOf(fetchMock, 1)["Idempotency-Key"];
    const key2 = headersOf(fetchMock, 2)["Idempotency-Key"];
    expect(key0).toBe(key1);
    expect(key0).not.toBe(key2);
    expect(key0).toBe(deriveIdempotencyKey(PACK_ID, NEW_PACK));
  });
});

// ─── H-P17-9 — DQ-3: export always sends format=json ────────────────────────

describe("H-P17-9 — DQ-3: export always sends ?format=json on the real fetched URL", () => {
  it("the fetched URL carries format=json", async () => {
    const fetchMock = stubFetch(() => ({
      status: 200,
      json: async () => ({ export: {}, pack: {}, bundles: [] }),
    }));
    await evidencePackExport({ packId: PACK_ID });
    expect(urlOf(fetchMock, 0)).toContain("format=json");
  });
});

// ─── H-P17-10 — URL-path injection defense (encodeURIComponent) ──────────────

describe("H-P17-10 — URL-path injection is neutralized by encodeURIComponent", () => {
  it("sign: a `../`-bearing packId is percent-encoded — no traversal", async () => {
    const fetchMock = stubFetch(() => ({
      status: 200,
      json: async () => ({ success: true, data: {} }),
    }));
    await evidencePackSign({ packId: "../../../admin", confirm: true });
    const url = urlOf(fetchMock, 0);
    expect(url).toContain("%2F");
    expect(url).not.toContain("/evidence-packs/../");
    expect(url).toContain("/sign");
  });

  it("supersede: a `../`-bearing oldPackId is percent-encoded — /supersede intact", async () => {
    const fetchMock = stubFetch(() => ({
      status: 200,
      json: async () => ({ success: true, data: {} }),
    }));
    await evidencePackSupersede({
      oldPackId: "../../admin",
      newPack: NEW_PACK,
    });
    const url = urlOf(fetchMock, 0);
    expect(url).toContain("%2F");
    expect(url).not.toContain("/evidence-packs/../");
    expect(url).toContain("/supersede");
  });

  it("export: a `../`-bearing packId is percent-encoded — /export intact", async () => {
    const fetchMock = stubFetch(() => ({
      status: 200,
      json: async () => ({ export: {}, pack: {}, bundles: [] }),
    }));
    await evidencePackExport({ packId: "../etc/passwd" });
    const url = urlOf(fetchMock, 0);
    expect(url).toContain("%2F");
    expect(url).not.toContain("/evidence-packs/../");
    expect(url).toContain("/export");
  });
});
