// ─── Golden cross-vectors — SDK verdict-identity gate (V1–V25) ──────────────-
//
// The DECISIVE defense against a kernel↔SDK divergence. Loads the local
// `golden-vectors.json` (byte-identical to the kernel copy — gated kernel-side
// by `golden-vectors.identity.test.ts`) and runs each vector through the bundled
// `verifyAnnexIvBindOffline`, asserting the FULL result deep-equals the kernel
// oracle's `expected`. The loop branches on the `resolverKind` discriminator
// (CR-2) to reconstruct byte-for-byte the resolver the kernel oracle used:
//   "jwks"     → jwks: [publicKeyJwk]
//   "wrongKey" → resolvePublicKey: () => <pk from wrongKeyJwk>
//   "null"     → resolvePublicKey: () => null
// and passes the vector's `options` (V12+: a pinned `now`, `maxStatusListAgeMs`,
// `clockToleranceMs`, `requireRevocationCheck`) exactly as the kernel's
// `vectorOptionsToInput` does — `now` is ISO-8601 in the JSON, `Date.parse`d here.
//
// The kernel generator (`src/lib/annex-iv/__tests__/golden-vectors.gen.ts`) is
// the ORACLE; these vectors break first on any divergence. Do NOT hand-edit the
// JSON — regenerate via the kernel gen test.

import { describe, it, expect } from "vitest";
import { verifyAnnexIvBindOffline } from "../verify.js";
import { jwkToEd25519PublicKey, type Ed25519PublicJwk } from "../jwk.js";
import type { VerifyAnnexIvBindOfflineInput, VerifyAnnexIvBindResult } from "../verify.js";
import vectors from "./golden-vectors.json" with { type: "json" };

interface GoldenVectorOptions {
  now?: string;
  maxStatusListAgeMs?: number;
  clockToleranceMs?: number;
  requireRevocationCheck?: boolean;
}

interface GoldenVector {
  id: string;
  label: string;
  resolverKind: "jwks" | "wrongKey" | "null";
  sidecarJws: string;
  pdfBytesB64: string;
  publicKeyJwk: Ed25519PublicJwk;
  wrongKeyJwk?: Ed25519PublicJwk;
  cachedStatusListCredential?: unknown;
  options?: GoldenVectorOptions;
  expected: VerifyAnnexIvBindResult;
}

const VECTORS = vectors as unknown as GoldenVector[];

/** Mirror of the kernel generator's `vectorOptionsToInput`. */
function vectorOptionsToInput(
  options: GoldenVectorOptions | undefined,
): Pick<VerifyAnnexIvBindOfflineInput, "now" | "maxStatusListAgeMs" | "clockToleranceMs" | "requireRevocationCheck"> {
  if (!options) return {};
  return {
    ...(options.now !== undefined ? { now: Date.parse(options.now) } : {}),
    ...(options.maxStatusListAgeMs !== undefined ? { maxStatusListAgeMs: options.maxStatusListAgeMs } : {}),
    ...(options.clockToleranceMs !== undefined ? { clockToleranceMs: options.clockToleranceMs } : {}),
    ...(options.requireRevocationCheck !== undefined
      ? { requireRevocationCheck: options.requireRevocationCheck }
      : {}),
  };
}

function pdfBytes(v: GoldenVector): Uint8Array {
  return new Uint8Array(Buffer.from(v.pdfBytesB64, "base64"));
}

describe("golden cross-vectors — SDK verdict-identity (V1–V25)", () => {
  it("loads exactly V1–V25", () => {
    expect(VECTORS.map((v) => v.id)).toEqual(Array.from({ length: 25 }, (_, i) => `V${i + 1}`));
  });

  for (const v of VECTORS) {
    it(`${v.id} — ${v.label} → SDK verdict == kernel oracle (full-result deep-equal)`, () => {
      const base = {
        sidecarJws: v.sidecarJws,
        pdfBytes: pdfBytes(v),
        cachedStatusListCredential: v.cachedStatusListCredential,
        ...vectorOptionsToInput(v.options),
      };

      let result: VerifyAnnexIvBindResult;
      switch (v.resolverKind) {
        case "jwks":
          result = verifyAnnexIvBindOffline({ ...base, jwks: [v.publicKeyJwk] });
          break;
        case "wrongKey": {
          const wrongPk = jwkToEd25519PublicKey(v.wrongKeyJwk);
          result = verifyAnnexIvBindOffline({
            ...base,
            resolvePublicKey: () => wrongPk,
          });
          break;
        }
        case "null":
          result = verifyAnnexIvBindOffline({ ...base, resolvePublicKey: () => null });
          break;
      }

      // The verdict-identity gate: the WHOLE structured result equals the oracle.
      expect(result).toEqual(v.expected);
      // …and the P2-11 invariant holds on every vector.
      expect(result.trustworthy).toBe(result.valid && result.revocation.checked && !result.revocation.revoked);
    });
  }
});
