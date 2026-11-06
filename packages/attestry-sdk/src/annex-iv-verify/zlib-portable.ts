// The NON-Node binding of the status-list gzip codec — what the package.json
// subpath import `#annex-iv-verify/zlib` resolves to under every condition
// EXCEPT "node" (browser / worker / edge bundles). SDK-only; not a kernel port.
//
// Why it exists: `status-list.ts` needs `gzipSync`/`gunzipSync`. A static
// `import ... from "node:zlib"` there made the ROOT `import "@attestry/sdk"`
// fail to bundle/load outside Node (0.7.0), even for callers that never touch the
// verifier. This module never imports `node:zlib` at load time. It resolves the
// codec LAZILY, on first use, through `process.getBuiltinModule("node:zlib")`
// (Node >= 20.16 / 22.3, Deno, Bun, Cloudflare Workers with `nodejs_compat`) —
// the SAME node:zlib implementation, so a decoded list is byte-identical with the
// kernel's. Where no such builtin exists the call throws; the status-list leg
// catches it and reports `checked:false` (never a fabricated "not revoked"), and
// `requireRevocationCheck` turns that into `valid:false`.
//
// Under Node the "node" condition selects `zlib-node.ts` (a plain static
// re-export), so Node 18+ behaviour is unchanged.

/** The two gzip primitives the status-list codec needs (a structural subset of `node:zlib`). */
export interface GzipCodec {
  gzipSync(data: Uint8Array): Uint8Array;
  gunzipSync(data: Uint8Array, options: { maxOutputLength: number }): Uint8Array;
}

/** The minimal `process` surface the lazy loader reads (injectable for tests). */
export interface BuiltinModuleHost {
  getBuiltinModule?: (id: string) => unknown;
}

/**
 * Resolve `node:zlib` from a `process`-like host via `getBuiltinModule`, or
 * `null` when the host has no such builtin. Never throws.
 */
export function resolveBuiltinZlib(host: BuiltinModuleHost | undefined): GzipCodec | null {
  try {
    const mod = typeof host?.getBuiltinModule === "function" ? host.getBuiltinModule("node:zlib") : undefined;
    const codec = mod as Partial<GzipCodec> | undefined;
    return codec && typeof codec.gzipSync === "function" && typeof codec.gunzipSync === "function"
      ? (codec as GzipCodec)
      : null;
  } catch {
    return null;
  }
}

/** The error thrown when the codec is used in a runtime that has no `node:zlib`. */
export const GZIP_CODEC_UNAVAILABLE_MESSAGE =
  "gzip codec unavailable: this runtime exposes no node:zlib (needs Node >= 18, or process.getBuiltinModule)";

let cached: GzipCodec | null | undefined;

function codec(): GzipCodec {
  if (cached === undefined) {
    cached = resolveBuiltinZlib((globalThis as { process?: BuiltinModuleHost }).process);
  }
  if (cached === null) throw new Error(GZIP_CODEC_UNAVAILABLE_MESSAGE);
  return cached;
}

export const gzipSync: GzipCodec["gzipSync"] = (data) => codec().gzipSync(data);
export const gunzipSync: GzipCodec["gunzipSync"] = (data, options) => codec().gunzipSync(data, options);
