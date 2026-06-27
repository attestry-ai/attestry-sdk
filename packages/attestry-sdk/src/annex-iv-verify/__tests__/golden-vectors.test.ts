// ─── Golden cross-vectors — SDK verdict-identity gate (V1–V11) ──────────────-
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
//
// The kernel generator (`src/lib/annex-iv/__tests__/golden-vectors.gen.ts`) is
// the ORACLE; these vectors break first on any divergence. Do NOT hand-edit the
// JSON — regenerate via the kernel gen test.

import { describe, it, expect } from "vitest";
import { verifyAnnexIvBindOffline } from "../verify.js";
import { jwkToEd25519PublicKey, type Ed25519PublicJwk } from "../jwk.js";
import type { VerifyAnnexIvBindResult } from "../verify.js";
import vectors from "./golden-vectors.json" with { type: "json" };

interface GoldenVector {
  id: string;
  label: string;
  resolverKind: "jwks" | "wrongKey" | "null";
  sidecarJws: string;
  pdfBytesB64: string;
  publicKeyJwk: Ed25519PublicJwk;
  wrongKeyJwk?: Ed25519PublicJwk;
  cachedStatusListCredential?: unknown;
  expected: VerifyAnnexIvBindResult;
}

const VECTORS = vectors as unknown as GoldenVector[];

function pdfBytes(v: GoldenVector): Uint8Array {
  return new Uint8Array(Buffer.from(v.pdfBytesB64, "base64"));
}

describe("golden cross-vectors — SDK verdict-identity (V1–V11)", () => {
  it("loads exactly V1–V11", () => {
    expect(VECTORS.map((v) => v.id)).toEqual([
      "V1",
      "V2",
      "V3",
      "V4",
      "V5",
      "V6",
      "V7",
      "V8",
      "V9",
      "V10",
      "V11",
    ]);
  });

  for (const v of VECTORS) {
    it(`${v.id} — ${v.label} → SDK verdict == kernel oracle (full-result deep-equal)`, () => {
      const base = {
        sidecarJws: v.sidecarJws,
        pdfBytes: pdfBytes(v),
        cachedStatusListCredential: v.cachedStatusListCredential,
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
    });
  }
});
