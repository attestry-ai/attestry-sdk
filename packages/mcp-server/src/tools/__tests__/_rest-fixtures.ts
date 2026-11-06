import type { ApiResponse } from "../../client.js";

/**
 * KE2 P1.5 — test fixture. Builds a mock REST body for the mocked
 * `apiGet` / `apiPost` to resolve with.
 *
 * The real client casts `response.json()` to `ApiResponse<T>`, whose type
 * has no `details` field — but an evidence-pack ERROR body does carry
 * `details: {code, issues?, currentStatus?}`. This fixture casts past the
 * (known-incomplete) `ApiResponse` type so tests can simulate the actual
 * runtime envelope, exactly as the production `RestEnvelope` widening in
 * `evidence-pack-shared.ts` expects it.
 *
 * Not a `*.test.ts` file, so vitest does not run it as a suite; the `_`
 * prefix marks it as test-support infrastructure.
 */
export function restBody(body: {
  success?: boolean;
  data?: unknown;
  error?: unknown;
  details?: Record<string, unknown>;
}): ApiResponse<unknown> {
  return body as unknown as ApiResponse<unknown>;
}
