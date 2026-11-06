# Changelog — @attestry/otel-agent-compliance

## 0.2.0 — 2026-11-05

Fixes for two ways 0.1.x could lose compliance records without logging anything, plus an install break on current OpenTelemetry JS. This release contains breaking packaging changes, listed under **Breaking**.

### Fixed

- **Per-record ingest failures were reported as success.** The client read `totalInserted` / `totalFailed` at the top level of the response, but `POST /api/v1/decisions/bulk` returns `{ success: true, data: { totalInserted, totalFailed, inserted[], failed[] } }`. A batch with rejected records came back as `{ ok: true, failed: 0 }`, and nothing was logged. The client now unwraps `data`. When `totalFailed > 0`, it logs a warning with the rejected indices and `failed[].code` values, and returns them as `failures` with `ok: false`.
- **Any 2xx counted as success, including HTML.** A `200 text/html` page (for example a gate or login page reached through a redirect), a `success: false` body, or an unrecognised body is now a logged failure.
- **Redirects were followed, and `x-api-key` went with them.** Requests now use `redirect: "manual"`. A 3xx is a logged, non-retried failure that reports the redacted `Location`, so the API key is never sent to another origin.
- **The retry policy now follows `RETRYABLE_STATUS`.** Only network errors, timeouts, and `408` / `429` / `500` / `502` / `503` / `504` are retried. 0.1.x did not retry `408`, and it did retry `501` / `505`.
- **`npm install` failed with `ERESOLVE` next to current `@opentelemetry/sdk-node`.** The cause was the optional peer `~0.214.0`. The package now declares no OTel dependency or peer at all (see **Breaking**). Strict installs succeed for every sdk-node row tested, from `0.200.0` through `0.301.0`, both one-shot and when added to an existing project.
- **Docs pointed at endpoints that do not exist.** The documented ingest URL is now `https://attestry.ai/api/v1/decisions/bulk`. Removed the `/api/otel/{orgSlug}/v1/traces/decisions` route, which never existed, and fixed a `/decisions/batch` reference to `/decisions/bulk`. The example no longer links to the nonexistent `/dashboard/decisions` page.
- **The lockfile pinned `@opentelemetry/core` 2.7.1** (GHSA-8988-4f7v-96qf). It now resolves `@opentelemetry/*` 3.1.0 (dev and test only; consumers resolve their own).

### Breaking

- **No dependencies or peer dependencies.**
  - `@opentelemetry/api` and the deprecated `@opentelemetry/sdk-trace-base` were never imported at runtime, so they are no longer dependencies.
  - The `@opentelemetry/sdk-node` peer was never used, so it is gone too.
  - The type-only import of `SpanProcessor` / `ReadableSpan` / `Span` is replaced by the local structural types `SpanProcessorLike`, `ReadableSpanLike` and `SpanLike`, which are exported. The exporter's `onStart` / `onEnd` parameters now use these types.

  An OTel peer of any range cannot work here, because npm resolves an absent optional peer at its newest version. `@opentelemetry/sdk-trace` 3.x needs `@opentelemetry/api >=1.10`, while sdk-node `0.200`–`0.219` pin `<1.10` and ship no sdk-trace at all. Supported SDKs are OTel JS 2.x (sdk-node `0.200`–`0.223`) and 3.x (sdk-node `0.300`+).
- **`engines.node` is now `>=20.19.0`** (was `>=18.0.0`). OpenTelemetry JS 3.x itself requires Node `>=22.15.0`, so on Node 20 use OTel 2.x. The package is ESM-only, which is now stated in the README.
- **`AttestryClient.recordDecisionsBatch()` returns `ok: false` for a partially rejected batch.** It now also returns `failures`. `BatchSendResult` and `BatchRecordFailure` are exported as types.
- **The log message for a dropped batch changed** from `Decision batch failed after retries` to `Decision batch failed — records dropped`. Its metadata now includes `retryable` and `attempts`. Partial rejections log `Decision batch partially rejected by server — rejected records were not recorded`.

### Documented

- **Digest semantics.** `inputDigest` / `outputDigest` are computed over the sanitizer's redacted output, never over the raw input, so the digest is not a reversible fingerprint of raw PII. This was already the behaviour and the spec, and is now documented and covered by regression tests. See README "Digest semantics" for how to reproduce a digest and how to tell inputs apart that differ only in redacted values.

### Tooling

- `npm run test:otel-compat` covers sdk-node `0.200.0`, `0.210.0`, `0.214.0`, `0.219.0`, `0.220.0`, `0.223.0`, `0.300.0` and `latest`. For each, it runs strict one-shot and add-to-existing installs of the packed tarball, `npm ls --all`, and a runtime smoke test (NodeSDK + span processor + local ingest stub). It also runs a consumer typecheck that assigns each SDK's real span and processor types to the structural types, with a negative control.
- `src/__tests__/otel-types.test.ts`: compile-time checks of the structural types against the `@opentelemetry/sdk-trace` 3.x devDependency.
- `npm run typecheck` now also typechecks the test files.
- vitest `^4.1.12` (was `^3.0.0`). This clears the dev-only vitest / vite / tinypool advisories.

## 0.1.1 — 2026-06-06

- Authenticate with `x-api-key` instead of `Authorization: Bearer`.

## 0.1.0 (never published to npm)

- Initial version: the `AttestryDecisionExporter` span processor, the PII sanitizer, the framework tagger, and the batch client.
