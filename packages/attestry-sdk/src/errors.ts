// ─── SDK error hierarchy ────────────────────────────────────────────────────
//
// Two error classes:
//   - `AttestryError` — non-API errors (network failure, invalid client
//     configuration, request timeout). Always indicates the request did
//     not reach the API.
//   - `AttestryAPIError` — the API returned a non-2xx response. Carries
//     `status` (HTTP status code), normalized `code` from the response
//     body when present, and the raw response shape under `details`.
//
// Both extend the standard `Error` so consumer code can `instanceof` test
// each layer separately.

export class AttestryError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = "AttestryError";
    if (options?.cause !== undefined) {
      // Preserve native ES2022 cause chain when available.
      (this as Error & { cause?: unknown }).cause = options.cause;
    }
    // Restore prototype chain across compile targets that drop it.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the API returns a non-2xx HTTP response. Always carries the
 * `status` code; `details` holds the parsed response body (when JSON) or
 * `null` (when the body wasn't valid JSON or was empty).
 */
export class AttestryAPIError extends AttestryError {
  readonly status: number;
  readonly details: unknown;

  constructor(message: string, status: number, details: unknown = null) {
    super(message);
    this.name = "AttestryAPIError";
    this.status = status;
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
