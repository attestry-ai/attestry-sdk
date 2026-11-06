// The Node binding of the status-list gzip codec — what the package.json subpath
// import `#annex-iv-verify/zlib` resolves to under the "node" condition (and for
// the SDK's own type-check). A plain static binding to `node:zlib`: exactly the
// kernel's codec, so Node 18+ behaviour (incl. the gzip-bomb `maxOutputLength`
// cap) is unchanged. Non-Node runtimes get `zlib-portable.ts` instead.
import { gzipSync as nodeGzipSync, gunzipSync as nodeGunzipSync } from "node:zlib";
import type { GzipCodec } from "./zlib-portable.js";

export const gzipSync: GzipCodec["gzipSync"] = nodeGzipSync;
export const gunzipSync: GzipCodec["gunzipSync"] = nodeGunzipSync;
