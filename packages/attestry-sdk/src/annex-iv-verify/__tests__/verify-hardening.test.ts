// ─── The bundled verifier — revocation / header hardening (0.8.0 work) ────────
//
// SDK-side pins for the hardening that the golden vectors (V12–V22) and the
// hostile tables exercise against the kernel oracle, plus the SDK-only surface:
//   - JWS protected header: `alg` pinned to EdDSA, `crit` rejected (any value),
//     over a VALID Ed25519 signature (so only the header guard can reject);
//   - P2-12 status-list validity window: the half-open `validFrom <= now <
//     validUntil` bounds, the clock-skew tolerance, `maxStatusListAgeMs`, `now`
//     as a number or a Date;
//   - P2-11 `trustworthy` / `requireRevocationCheck` on the documented paths;
//   - option usage errors → typed `AttestryError` BEFORE any verification step;
//   - the `#annex-iv-verify/zlib` split: the portable binding never needs a
//     static `node:zlib`, and no module on the root import graph imports one
//     (other than the "node"-condition binding).

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { AttestryError } from "../../errors.js";
import * as root from "../../index.js";
import * as subpath from "../index.js";
import { verifyAnnexIvBindOffline } from "../verify.js";
import { ed25519GetPublicKey, ed25519Sign, generateEd25519SecretKey } from "../ed25519.js";
import { bytesToBase64url } from "../jwk.js";
import { decodeBitstring, encodeBitstring, createBitstring, setBit, getBit } from "../status-list.js";
import {
  GZIP_CODEC_UNAVAILABLE_MESSAGE,
  resolveBuiltinZlib,
  gunzipSync as portableGunzip,
  gzipSync as portableGzip,
} from "../zlib-portable.js";
import type { Ed25519PublicJwk } from "../jwk.js";
import goldenVectors from "./golden-vectors.json" with { type: "json" };
import hostileFixtures from "./hostile-fixtures.json" with { type: "json" };

interface Vector {
  id: string;
  sidecarJws: string;
  pdfBytesB64: string;
  publicKeyJwk: Ed25519PublicJwk;
  cachedStatusListCredential?: unknown;
}
const VECTORS = goldenVectors as unknown as Vector[];
const FX = hostileFixtures as unknown as { base: { sidecarJws: string; pdfBytesB64: string; publicKeyJwk: Ed25519PublicJwk } };

const bytes = (b64: string): Uint8Array => new Uint8Array(Buffer.from(b64, "base64"));
const byId = (id: string): Vector => VECTORS.find((v) => v.id === id)!;

// V16: a compact bind + a WINDOWED list (validFrom 2026-05-30T12:00:00Z,
// validUntil 2026-05-31T12:00:00Z), bit clear — the documented happy path.
const V16 = byId("V16");
const VALID_FROM_MS = Date.parse("2026-05-30T12:00:00Z");
const VALID_UNTIL_MS = Date.parse("2026-05-31T12:00:00Z");
const v16 = (extra: Record<string, unknown> = {}) =>
  verifyAnnexIvBindOffline({
    sidecarJws: V16.sidecarJws,
    pdfBytes: bytes(V16.pdfBytesB64),
    cachedStatusListCredential: V16.cachedStatusListCredential,
    jwks: [V16.publicKeyJwk],
    ...extra,
  });

// ─── JWS protected-header hardening ─────────────────────────────────────────--

describe("JWS header — alg pinned to EdDSA, crit rejected (over a VALID Ed25519 signature)", () => {
  const sk = generateEd25519SecretKey();
  const pk = ed25519GetPublicKey(sk);
  const [protectedB64, payloadB64] = FX.base.sidecarJws.split(".");
  const baseHeader = JSON.parse(Buffer.from(protectedB64, "base64url").toString("utf8")) as Record<string, unknown>;
  const pdf = bytes(FX.base.pdfBytesB64);

  /** Re-sign the base payload under `header` with a fresh key the resolver returns. */
  const mint = (header: unknown): string => {
    const h = bytesToBase64url(new TextEncoder().encode(JSON.stringify(header)));
    const sig = ed25519Sign(new TextEncoder().encode(`${h}.${payloadB64}`), sk);
    return `${h}.${payloadB64}.${bytesToBase64url(sig)}`;
  };
  const verify = (header: unknown) =>
    verifyAnnexIvBindOffline({ sidecarJws: mint(header), pdfBytes: pdf, resolvePublicKey: () => pk });

  it("control: the production header (alg EdDSA, no crit) re-signed → valid:true", () => {
    expect(baseHeader.alg).toBe("EdDSA");
    const r = verify(baseHeader);
    expect(r.signatureOk).toBe(true);
    expect(r.valid).toBe(true);
  });

  for (const alg of ["none", "HS256", "RS256", "ES256", "Ed25519", "eddsa", "", null, 0]) {
    it(`alg ${JSON.stringify(alg)} → valid:false at step 0 (never reaches the signature)`, () => {
      const r = verify({ ...baseHeader, alg });
      expect(r.valid).toBe(false);
      expect(r.tagOk).toBe(false);
      expect(r.signatureOk).toBe(false);
      expect(r.reason).toBe(
        `domain tag / parse: unexpected JWS alg: ${JSON.stringify(alg)} (only "EdDSA" is accepted)`,
      );
    });
  }

  it("an ABSENT alg → valid:false", () => {
    const { alg: _alg, ...noAlg } = baseHeader;
    const r = verify(noAlg);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('domain tag / parse: unexpected JWS alg: undefined (only "EdDSA" is accepted)');
  });

  for (const crit of [["b64"], ["exp"], [], "b64", null]) {
    it(`crit ${JSON.stringify(crit)} → valid:false (no extension is understood)`, () => {
      const r = verify({ ...baseHeader, crit, b64: false });
      expect(r.valid).toBe(false);
      expect(r.tagOk).toBe(false);
      expect(r.reason).toBe(`domain tag / parse: unsupported JWS crit header: ${JSON.stringify(crit)}`);
    });
  }

  for (const header of [null, [baseHeader], "EdDSA", 7]) {
    it(`a protected header that is not a JSON object (${JSON.stringify(header)?.slice(0, 20)}) → valid:false, no throw`, () => {
      const r = verify(header);
      expect(r.valid).toBe(false);
      expect(r.reason).toBe("domain tag / parse: malformed JWS protected header: not a JSON object");
    });
  }
});

// ─── P2-12 — the status-list validity window ────────────────────────────────--

describe("P2-12 — status-list validity window (validFrom <= now < validUntil, skew-tolerant)", () => {
  it("inside the window → checked, and the window is surfaced on `revocation`", () => {
    const r = v16({ now: VALID_FROM_MS + 60 * 60 * 1000 });
    expect(r.revocation).toEqual({
      checked: true,
      revoked: false,
      statusPurpose: "revocation",
      validFrom: "2026-05-30T12:00:00Z",
      validUntil: "2026-05-31T12:00:00Z",
    });
    expect(r.trustworthy).toBe(true);
  });

  it("`now` as a Date ≡ `now` as epoch ms", () => {
    const t = VALID_FROM_MS + 1234;
    expect(v16({ now: new Date(t) })).toEqual(v16({ now: t }));
  });

  it("validFrom is INCLUSIVE; a list 30 s in the future is accepted under the default 60 s tolerance, rejected at tolerance 0", () => {
    expect(v16({ now: VALID_FROM_MS, clockToleranceMs: 0 }).revocation.checked).toBe(true);
    expect(v16({ now: VALID_FROM_MS - 30_000 }).revocation.checked).toBe(true);
    const strict = v16({ now: VALID_FROM_MS - 30_000, clockToleranceMs: 0 });
    expect(strict.revocation.checked).toBe(false);
    expect(strict.revocation.reason).toBe("status list not yet valid (validFrom 2026-05-30T12:00:00Z)");
    expect(strict.valid).toBe(true); // unchecked never flips valid by default
    expect(strict.trustworthy).toBe(false);
  });

  it("validUntil is EXCLUSIVE (half-open); the tolerance extends it symmetrically", () => {
    expect(v16({ now: VALID_UNTIL_MS - 1, clockToleranceMs: 0 }).revocation.checked).toBe(true);
    expect(v16({ now: VALID_UNTIL_MS, clockToleranceMs: 0 }).revocation.reason).toBe(
      "status list expired (validUntil 2026-05-31T12:00:00Z)",
    );
    expect(v16({ now: VALID_UNTIL_MS + 59_999 }).revocation.checked).toBe(true);
    expect(v16({ now: VALID_UNTIL_MS + 60_000 }).revocation.checked).toBe(false);
  });

  it("maxStatusListAgeMs: an age of exactly the bound is fresh, 1 ms more is stale", () => {
    const maxStatusListAgeMs = 2 * 60 * 60 * 1000;
    expect(v16({ now: VALID_FROM_MS + maxStatusListAgeMs, maxStatusListAgeMs }).revocation.checked).toBe(true);
    const stale = v16({ now: VALID_FROM_MS + maxStatusListAgeMs + 1, maxStatusListAgeMs });
    expect(stale.revocation.checked).toBe(false);
    expect(stale.revocation.reason).toMatch(/^status list is stale/);
  });

  it("DEFAULT clock (no `now`): the 2026-05 list is long expired → unchecked, valid stands (backward compatible), NOT trustworthy", () => {
    const r = v16();
    expect(r.valid).toBe(true);
    expect(r.trustworthy).toBe(false);
    expect(r.revocation.reason).toBe("status list expired (validUntil 2026-05-31T12:00:00Z)");
  });

  it("a revoked bind (V12's list) stays revoked at EVERY evaluation instant — before, inside and long after the window", () => {
    const v12 = byId("V12");
    for (const now of [VALID_FROM_MS - 86_400_000, VALID_FROM_MS + 1000, VALID_UNTIL_MS, VALID_UNTIL_MS + 10 * 365 * 86_400_000]) {
      for (const maxStatusListAgeMs of [undefined, 1]) {
        const r = verifyAnnexIvBindOffline({
          sidecarJws: v12.sidecarJws,
          pdfBytes: bytes(v12.pdfBytesB64),
          cachedStatusListCredential: v12.cachedStatusListCredential,
          jwks: [v12.publicKeyJwk],
          now,
          ...(maxStatusListAgeMs !== undefined ? { maxStatusListAgeMs } : {}),
        });
        expect(r.valid).toBe(false);
        expect(r.reason).toBe("revoked");
        expect(r.revocation).toMatchObject({ checked: true, revoked: true });
      }
    }
  });

  it("an expired list cannot vouch for not-revoked even when replayed under requireRevocationCheck", () => {
    const r = v16({ now: VALID_UNTIL_MS + 24 * 60 * 60 * 1000, requireRevocationCheck: true });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("revocation not checked: status list expired (validUntil 2026-05-31T12:00:00Z)");
  });

  it("a list WITHOUT validUntil (V2) keeps verifying on the wall clock — the window is enforced only when present", () => {
    const v2 = byId("V2");
    const r = verifyAnnexIvBindOffline({
      sidecarJws: v2.sidecarJws,
      pdfBytes: bytes(v2.pdfBytesB64),
      cachedStatusListCredential: v2.cachedStatusListCredential,
      jwks: [v2.publicKeyJwk],
    });
    expect(r.revocation.checked).toBe(true);
    expect(r.trustworthy).toBe(true);
  });
});

// ─── P2-11 — trustworthy / requireRevocationCheck ───────────────────────────--

describe("P2-11 — `trustworthy` and `requireRevocationCheck`", () => {
  it("no list: valid:true but trustworthy:false; under requireRevocationCheck → valid:false", () => {
    const base = { sidecarJws: V16.sidecarJws, pdfBytes: bytes(V16.pdfBytesB64), jwks: [V16.publicKeyJwk] };
    const lax = verifyAnnexIvBindOffline(base);
    expect(lax.valid).toBe(true);
    expect(lax.trustworthy).toBe(false);
    const strict = verifyAnnexIvBindOffline({ ...base, requireRevocationCheck: true });
    expect(strict.valid).toBe(false);
    expect(strict.reason).toBe("revocation not checked: status list not provided (offline)");
  });

  it("requireRevocationCheck:false is the default behaviour", () => {
    const now = VALID_FROM_MS + 1000;
    expect(v16({ now, requireRevocationCheck: false })).toEqual(v16({ now }));
  });

  it("a revoked bind stays reason 'revoked' under requireRevocationCheck (the revocation wins over the policy)", () => {
    const v3 = byId("V3");
    const r = verifyAnnexIvBindOffline({
      sidecarJws: v3.sidecarJws,
      pdfBytes: bytes(v3.pdfBytesB64),
      cachedStatusListCredential: v3.cachedStatusListCredential,
      jwks: [v3.publicKeyJwk],
      requireRevocationCheck: true,
    });
    expect(r.valid).toBe(false);
    expect(r.reason).toBe("revoked");
    expect(r.trustworthy).toBe(false);
  });

  it("an INVALID artifact is never trustworthy, whatever the list says", () => {
    const v4 = byId("V4"); // 1-byte PDF mutation
    const r = verifyAnnexIvBindOffline({
      sidecarJws: v4.sidecarJws,
      pdfBytes: bytes(v4.pdfBytesB64),
      jwks: [v4.publicKeyJwk],
    });
    expect(r.valid).toBe(false);
    expect(r.trustworthy).toBe(false);
  });
});

// ─── Usage errors → typed AttestryError, BEFORE any verification step ────────

describe("option usage errors → AttestryError (a precondition, never a verdict)", () => {
  // A NON-JWS sidecar: proves the throw happens before step 0, not as a verdict.
  const garbage = { sidecarJws: "not-a-jws", pdfBytes: new Uint8Array(), jwks: [V16.publicKeyJwk] };
  const cases: Array<[string, Record<string, unknown>, RegExp]> = [
    ["requireRevocationCheck: 'true' (a string)", { requireRevocationCheck: "true" }, /requireRevocationCheck` must be a boolean/],
    ["now: NaN", { now: Number.NaN }, /`now` must be a finite/],
    ["now: an invalid Date", { now: new Date("not a date") }, /`now` must be a finite/],
    ["now: an ISO string", { now: "2026-05-30T12:00:00Z" }, /`now` must be an epoch-ms number or a Date/],
    ["maxStatusListAgeMs: -1", { maxStatusListAgeMs: -1 }, /maxStatusListAgeMs/],
    ["maxStatusListAgeMs: Infinity", { maxStatusListAgeMs: Number.POSITIVE_INFINITY }, /maxStatusListAgeMs/],
    ["maxStatusListAgeMs: '3600000'", { maxStatusListAgeMs: "3600000" }, /maxStatusListAgeMs/],
    ["clockToleranceMs: -5", { clockToleranceMs: -5 }, /clockToleranceMs/],
  ];
  for (const [name, opts, msg] of cases) {
    it(`${name} → throws AttestryError`, () => {
      let thrown: unknown;
      try {
        verifyAnnexIvBindOffline({ ...garbage, ...opts } as never);
      } catch (e) {
        thrown = e;
      }
      expect(thrown).toBeInstanceOf(AttestryError);
      expect((thrown as Error).message).toMatch(/^verifyAnnexIvBindOffline: /);
      expect((thrown as Error).message).toMatch(msg);
    });
  }

  it("missing key material is still reported first", () => {
    expect(() =>
      verifyAnnexIvBindOffline({ sidecarJws: "x", pdfBytes: new Uint8Array(), now: Number.NaN } as never),
    ).toThrow(/requires key material/);
  });
});

// ─── The `#annex-iv-verify/zlib` split (non-Node import safety) ──────────────

describe("gzip codec split — the root import graph has no static node:zlib outside Node", () => {
  it("the portable binding resolves node:zlib lazily via process.getBuiltinModule, else null (never throws)", () => {
    expect(resolveBuiltinZlib(undefined)).toBeNull();
    expect(resolveBuiltinZlib({})).toBeNull();
    expect(resolveBuiltinZlib({ getBuiltinModule: () => undefined })).toBeNull();
    expect(
      resolveBuiltinZlib({
        getBuiltinModule: () => {
          throw new Error("no builtins here");
        },
      }),
    ).toBeNull();
    expect(resolveBuiltinZlib({ getBuiltinModule: () => ({ gzipSync: 1 }) })).toBeNull();
    const fake = { gzipSync: (d: Uint8Array) => d, gunzipSync: (d: Uint8Array) => d };
    expect(resolveBuiltinZlib({ getBuiltinModule: (id) => (id === "node:zlib" ? fake : undefined) })).toBe(fake);
    expect(GZIP_CODEC_UNAVAILABLE_MESSAGE).toMatch(/node:zlib/);
  });

  it("on a host WITH getBuiltinModule (this Node), the portable codec round-trips a status list like node:zlib", () => {
    const hasBuiltin = typeof (process as { getBuiltinModule?: unknown }).getBuiltinModule === "function";
    if (!hasBuiltin) return; // Node < 20.16 — covered by the resolver cases above
    const bs = createBitstring();
    setBit(bs, 4242, true);
    const encoded = encodeBitstring(bs); // node binding
    const viaPortable = portableGunzip(Buffer.from(encoded.slice(1), "base64url"), { maxOutputLength: 1 << 20 });
    expect(Buffer.compare(Buffer.from(viaPortable), Buffer.from(bs))).toBe(0);
    expect(getBit(decodeBitstring("u" + Buffer.from(portableGzip(bs)).toString("base64url")), 4242)).toBe(true);
  });

  it("no non-test source module statically imports a `node:` builtin except the node-condition zlib binding", () => {
    const srcRoot = resolve(__dirname, "../..");
    const offenders: string[] = [];
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        if (statSync(p).isDirectory()) {
          if (name !== "__tests__") walk(p);
          continue;
        }
        if (!name.endsWith(".ts")) continue;
        const rel = relative(srcRoot, p).split("\\").join("/");
        if (rel === "annex-iv-verify/zlib-node.ts") continue;
        const text = readFileSync(p, "utf8");
        // Real import/export statements only (a `node:` mention inside a JSDoc
        // example starts with `*`, not `import`).
        if (/^\s*(?:import|export)\b[^;]*?\bfrom\s*["']node:/m.test(text) || /\brequire\(\s*["']node:/.test(text)) {
          offenders.push(rel);
        }
      }
    };
    walk(srcRoot);
    expect(offenders).toEqual([]);
  });

  it("the root and the `@attestry/sdk/annex-iv-verify` subpath export the SAME verifier", () => {
    expect(root.verifyAnnexIvBindOffline).toBe(subpath.verifyAnnexIvBindOffline);
    expect(root.makeJwksResolver).toBe(subpath.makeJwksResolver);
    expect(root.STATUS_LIST_VALIDITY_MS).toBe(24 * 60 * 60 * 1000);
    expect(subpath.DEFAULT_STATUS_LIST_CLOCK_TOLERANCE_MS).toBe(60_000);
  });

  it("package.json exposes the subpath export (+ dist/* back-compat) and maps the codec by condition (node → static, default → portable)", () => {
    const pkg = JSON.parse(readFileSync(resolve(__dirname, "../../../package.json"), "utf8")) as {
      exports: Record<string, unknown>;
      imports: Record<string, Record<string, string>>;
    };
    expect(Object.keys(pkg.exports)).toEqual([".", "./annex-iv-verify", "./dist/*.js", "./dist/*", "./package.json"]);
    expect(pkg.exports["./annex-iv-verify"]).toEqual({
      types: "./dist/annex-iv-verify/index.d.ts",
      default: "./dist/annex-iv-verify/index.js",
    });
    // Back-compat (0.7.x deep imports): `@attestry/sdk/dist/<path>.js` keeps
    // resolving, with its sibling `.d.ts` as the types; any other dist file maps 1:1.
    expect(pkg.exports["./dist/*.js"]).toEqual({ types: "./dist/*.d.ts", default: "./dist/*.js" });
    expect(pkg.exports["./dist/*"]).toBe("./dist/*");
    const zlib = pkg.imports["#annex-iv-verify/zlib"];
    expect(Object.keys(zlib)).toEqual(["types", "node", "default"]);
    expect(zlib.node).toBe("./dist/annex-iv-verify/zlib-node.js");
    expect(zlib.default).toBe("./dist/annex-iv-verify/zlib-portable.js");
  });
});
