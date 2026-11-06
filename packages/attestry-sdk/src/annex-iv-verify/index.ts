// ─── The bundled OFFLINE Annex IV bind verifier (work-item C) ───────────────
//
// A DB-free, network-free, pure verifier — a faithful VERIFY-only port of the
// kernel's `verifyAnnexIvBind` (the kernel is the source of truth; the golden
// cross-vectors break first on any divergence). The caller supplies key material
// (a `resolvePublicKey` or a `jwks`); the SDK never reads a DB or the network.
//
// Barrel imports take the explicit `.js` extension (the SDK is `module:"Node16"`).
//
// This barrel IS the `@attestry/sdk/annex-iv-verify` subpath export (package.json
// "exports") — the recommended import. The root `@attestry/sdk` keeps re-exporting
// the same symbols for compatibility. Neither entry point imports `node:zlib` at
// load time outside Node (see `zlib-portable.ts`).

export {
  verifyAnnexIvBindOffline,
  type VerifyAnnexIvBindOfflineInput,
  type VerifyAnnexIvBindResult,
  type AnnexIvBindPayload,
  type RevocationCheck,
} from "./verify.js";

export {
  STATUS_LIST_VALIDITY_MS,
  DEFAULT_STATUS_LIST_CLOCK_TOLERANCE_MS,
} from "./status-list.js";

export {
  makeJwksResolver,
  type Ed25519PublicJwk,
} from "./resolver.js";

export type { PublicKeyResolver } from "./data-integrity.js";
