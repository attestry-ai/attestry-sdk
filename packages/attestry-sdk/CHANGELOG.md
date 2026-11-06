# Changelog — `@attestry/sdk`

Release notes for 0.7.0 and earlier are in the README's status notes.

## 0.8.0 (unreleased)

A minor release. It folds in the planned 0.7.1 patch (never published) and hardens the bundled Annex IV offline verifier. No API is removed. Behaviour changes are flagged below. From the transport fixes: redirects now fail instead of being followed, and Node 20.19+ is required. From the verifier: a malformed status list now makes a bind invalid; status lists are checked against their validity window; only `EdDSA` JWS headers are accepted; and the package now has an `exports` map.

### Added (offline verifier)

- **`trustworthy`** on the `verifyAnnexIvBindOffline` result: `valid && revocation.checked && !revocation.revoked`. This is the one boolean to gate on. By default, `valid: true` only means *intact as issued*. It does **not** mean *not revoked*. With no status list, or one the verifier could not use, `valid` stays `true` and `revocation.checked` is `false`.
- **`requireRevocationCheck`** option. When `true`, a revocation status that could not be checked makes the result `valid: false`, with `reason: "revocation not checked: …"`.
- **Status-list validity window options:**
  - `now` (epoch ms or `Date`; default `Date.now()`);
  - `maxStatusListAgeMs` (rejects lists whose `validFrom` is older than this);
  - `clockToleranceMs` (default 60 000; `0` for the exact window).

  Invalid values throw `AttestryError` before anything is verified.
- **New `revocation` fields:**
  - `validFrom` / `validUntil`: the window of the list the verdict rests on;
  - `malformed`: set when the value you passed is not a parsed status list.
- **`@attestry/sdk/annex-iv-verify` subpath export** carrying the verifier. The root export still re-exports it.
- **New exports:** `RevocationCheck`, `STATUS_LIST_VALIDITY_MS` (24 h, the issuer's list lifetime), `DEFAULT_STATUS_LIST_CLOCK_TOLERANCE_MS`.
- **README:** new "Verifying Annex IV binds offline" section.

### Changed (offline verifier — behaviour changes)

- **A malformed `cachedStatusListCredential` is now invalid.** Examples: the response *text* instead of the parsed object, `{}`, an API envelope, an array, a number, `""`, `false`. These now give `valid: false` with `revocation.malformed: true` and a reason naming the problem. In 0.7.0 they gave `valid: true` with the revocation status unchecked (the empty and falsy values were treated as "not provided"). Pass `undefined` or `null` when you have no list.
- **Status lists are checked against their validity window.** The rule is `validFrom <= now < validUntil` whenever those fields are present, using strict date parsing (a value without a timezone is rejected).
  - A list that is expired, not yet valid, or older than `maxStatusListAgeMs` can no longer confirm *not revoked*. It gives `revocation.checked: false`, which becomes `valid: false` under `requireRevocationCheck`.
  - A **revocation** bit set in such an authentic list still counts as revoked, because revocation is irreversible. A **suspension** bit can be lifted, so an out-of-window suspension stays unchecked.
  - Lists without `validUntil` are unaffected; that is every list issued before this change. Lists the issuer serves now carry `validUntil = validFrom + 24 h`.
- **JWS protected header is pinned.** `alg` must be `"EdDSA"`. Headers with `alg: "none"`, `"HS256"`, a missing `alg`, any `crit` parameter, or a protected header that is not an object are rejected, even when the Ed25519 signature is valid. The issuer has only ever emitted `EdDSA`.
- **The package now has an `exports` map.** Entries:
  - `"."` and `"./annex-iv-verify"`;
  - `"./dist/*.js"` (with the matching `.d.ts` types) and `"./dist/*"`, so existing `@attestry/sdk/dist/…` deep imports keep resolving;
  - `"./package.json"`.

  Paths outside the map (e.g. `src/`) no longer resolve. Neither do extensionless deep imports such as `@attestry/sdk/dist/index`.
- **Importing the root no longer loads `node:zlib` outside Node.** A conditional subpath import selects the codec (`#annex-iv-verify/zlib`), so `import "@attestry/sdk"` now bundles for browser, edge and worker targets. In 0.7.0 these failed with `Could not resolve "node:zlib"`. Running the verifier still needs Node, or a runtime that provides `Buffer` and `node:zlib` through `process.getBuiltinModule`.

### Fixed

- **`decisions.stream()` merged or dropped SSE frames, and could hang after an early `break`.** Affected 0.6.0 through 0.7.0. The frame-boundary regex was a module-level `/g` regex. `exec` resumed at a stale `lastIndex` on a buffer the parser re-slices after every frame. Two failures followed. First, several frames delivered in one network chunk were merged, so the stream threw `SSE frame data was not valid JSON`. Second, a stream abandoned mid-chunk left state behind that made the next stream in the same process miss its first frame and hang. The regex is now stateless (`src/sse-parser.ts`). The NDJSON and line parsers split on `indexOf` and were never affected. The test suite only passed because of file order; a new `npm run test:shuffle` script runs it in random order.
- **`timeoutMs` and `options.signal` stopped applying once the response headers arrived.** A server or proxy that stalled mid-body hung the call forever, and the caller's `AbortSignal` was ignored. Both now stay in force until the body has been fully read. A stalled body rejects with `AttestryError("request timed out")` (or `"request aborted by caller"`), and the body is canceled so the connection is released. The timer and listener are cleaned up afterwards (`src/transport.ts`).
- **`annexIv.generate` was aborted by the default 30 s timeout** on a route that may run for 300 s. A re-call then failed with 422 `annex_iv.already_bound`, and that call is metered. `generate` now defaults to 300 000 ms. A per-call `options.timeoutMs` or an explicitly configured client `timeoutMs` still takes precedence. The README has a new `client.annexIv` section: on a timeout, poll `getBind`, do not call `generate` again (`src/resources/annex-iv.ts`).
- **`annexIv.downloadPdf` had no timeout at all.** It now honours the client `timeoutMs` (or per-call `options.timeoutMs`) and `options.signal`, covering both the request and the caller's read of the returned body.
- **`evidencePack.export` had no timeout at all either.** A server or proxy that stalled, before the headers or mid-zip, hung the call and the consumer's body read forever. It now gets the same body-covering timeout as `downloadPdf`. The default is **120 000 ms**, twice the route's 60 s `maxDuration`, so a large zip the server streams within its own limit is never cut off. The client's 30 s default would have been shorter than the route allows. Precedence: per-call `options.timeoutMs`, then an explicitly configured client `timeoutMs`, then 120 000; `0` disables it (`src/resources/evidence-pack.ts`).
- **The timeout timer leaked when a request body failed to serialize** (e.g. a `BigInt`). It kept the process alive for `timeoutMs`, and the caller-signal listener stayed attached. The body is now serialized before either is set up.
- A connection that drops mid-body now rejects with `AttestryError("network error: …")` instead of a raw `TypeError`.

### Security

- **Redirects are no longer followed** (`redirect: "manual"` on every request). `fetch` strips only `Authorization` on a cross-origin redirect, not the custom `x-api-key` header, so 0.7.0 forwarded the org API key to any host a redirect named. **Behaviour change:** a 3xx now fails with an `AttestryAPIError`. Its `status` is the 3xx code, its `details` is `{ location }`, and its message names the URL and the redirect target and asks you to check `baseUrl`. A response that a custom `fetch` followed anyway (`response.redirected`) is rejected the same way.
- **`apiKey` must be a valid HTTP header value.** Leading and trailing whitespace is trimmed, the same normalization `Headers` applies, so a key read from a file with a trailing newline keeps working. Embedded CR/LF (header injection), spaces, control characters or non-ASCII characters (e.g. a pasted smart quote) now throw `AttestryError` when the client is constructed. Before, every request failed with a raw `TypeError`. The error names the offending code point and never echoes the key.

### Changed

- A 2xx with the wrong content type (e.g. an HTML login or access-gate page answering in place of the API) still throws `AttestryAPIError(status, null)`, and its message still starts with `expected application/json response, got "…"`. It now also names the request URL (query string omitted) and asks you to check `baseUrl`. The streaming paths (SSE, NDJSON, PDF) say the same.
- **`engines.node` is now `>=20.19.0`** (was `>=18.0.0`). The old range was never accurate: the runtime dependency `@noble/hashes` requires Node 20.19+. The README now states that the package is ESM-only (no CommonJS build).
- The default `baseUrl` is unchanged (`https://attestry.ai`).

### Added

- `RequestOptions.timeoutMs`: a per-call timeout override, where `0` disables the timeout. It applies to JSON requests and to the one-shot downloads `annexIv.downloadPdf` and `evidencePack.export`. Long-lived streams (`*.stream()`, `decisions.export()`, `auditLog.export()`) ignore it.

### Tooling (development only; not part of the published package)

- vitest `^3` → `^4.1.12` (clears the dev-only vitest/vite/esbuild/tinypool advisories; `npm audit`: 0 vulnerabilities). Lockfile refreshed.
- `tsconfig.json`: `"types": ["node"]`, so a TypeScript 6+ upgrade doesn't break the build. `"inlineSources": true`, so the shipped `.js.map` files carry their sources (`src/` is not published). Declaration maps (`.d.ts.map`) are no longer emitted: they pointed at the unpublished `src/` and could not resolve.
- `abac-policies-create.test.ts` imports the public API from `src/` instead of `dist/`, so the suite no longer depends on a prior build.
- `canonicalize` stays on `^3.0.0`: 4.x and 5.x change JCS output, so the kernel signer and the SDK verifier must upgrade together.
