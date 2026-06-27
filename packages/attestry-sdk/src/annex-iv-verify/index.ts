// ─── The bundled OFFLINE Annex IV bind verifier (work-item C) ───────────────
//
// A DB-free, network-free, pure verifier — a faithful VERIFY-only port of the
// kernel's `verifyAnnexIvBind` (the kernel is the source of truth; the golden
// cross-vectors break first on any divergence). The caller supplies key material
// (a `resolvePublicKey` or a `jwks`); the SDK never reads a DB or the network.
//
// Barrel imports take the explicit `.js` extension (the SDK is `module:"Node16"`).

export {
  verifyAnnexIvBindOffline,
  type VerifyAnnexIvBindOfflineInput,
  type VerifyAnnexIvBindResult,
  type AnnexIvBindPayload,
} from "./verify.js";

export {
  makeJwksResolver,
  type Ed25519PublicJwk,
} from "./resolver.js";

export type { PublicKeyResolver } from "./data-integrity.js";
