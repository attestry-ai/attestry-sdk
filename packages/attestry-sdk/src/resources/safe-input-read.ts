// ─── Defensive input-field read ─────────────────────────────────────────────
//
// Shared by every SDK resource that validates a consumer-supplied
// input object by reading fields off it.
//
// **The gap this closes** (session-22 hostile review #1 — the SDK-wide
// MEDIUM-1 getter-throws contract gap, deferred from session 21):
// every resource's input validation reads fields with a bare property
// access — `(input as { name?: unknown }).name` or `input.systemId`.
// A consumer (or a hostile dependency that polluted a prototype) can
// install a THROWING accessor on the input object —
// `{ get name() { throw new Error("boom") } }` — and the bare read
// surfaces that arbitrary exception verbatim. Every resource's JSDoc
// promises a synchronous `TypeError` for malformed input; a throwing
// getter breaks that documented cross-SDK contract by leaking a
// non-`TypeError` (or a `TypeError` the SDK never authored) to the
// caller.
//
// `readInputField` wraps the read in a try/catch and re-throws a
// getter's exception as a `TypeError` — preserving the original error
// on `.cause` (the `errors.ts` cause-assignment pattern) — so the
// synchronous-`TypeError` input contract holds SDK-wide regardless of
// what the input object's accessors do.

/**
 * Read a single field off a consumer-supplied input object, converting
 * a throwing getter's exception into the SDK's documented `TypeError`
 * input contract.
 *
 * The caller MUST have already confirmed `obj` is a non-null object
 * (every resource does the top-level `typeof input === "object"` guard
 * first). The read is a plain index access, so it walks the prototype
 * chain identically to the bare `obj.key` it replaces — callers that
 * need own-property semantics still gate on `Object.hasOwn` (the
 * module-load snapshot) exactly as before; this helper only adds the
 * throwing-getter → `TypeError` conversion.
 *
 * @param obj     The consumer-supplied input object (already confirmed non-null).
 * @param key     The field name to read.
 * @param context The calling method (e.g. `"abacPolicies.create"`) — prefixes the thrown message.
 * @returns       The field value (`undefined` if absent — same as a bare read).
 * @throws {TypeError} If the field's getter throws — the getter's error is preserved on `.cause`.
 */
export function readInputField(
  obj: object,
  key: string,
  context: string,
): unknown {
  try {
    return (obj as Record<string, unknown>)[key];
  } catch (cause) {
    const err = new TypeError(
      `${context}: could not read input field \`${key}\` — its getter threw`,
    );
    // Preserve the native ES2022 cause chain — mirror of the
    // `AttestryError` cause-assignment pattern in `errors.ts` (assigned
    // post-construction rather than via the 2-arg `Error` constructor,
    // for compile-target portability).
    (err as Error & { cause?: unknown }).cause = cause;
    throw err;
  }
}
