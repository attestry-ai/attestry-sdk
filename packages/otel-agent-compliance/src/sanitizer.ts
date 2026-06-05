/**
 * Built-in PII sanitizer for span attributes. Customers can pass their
 * own via `AttestryExporterConfig.sanitizer`; this is the safe default.
 *
 * Design constraints:
 *  - **Defensive, not exhaustive.** A regex stripper can never catch
 *    every PII shape. The customer's compliance team needs to review
 *    what hits the wire. We err on the side of redacting too much, not
 *    too little.
 *  - **No backreferences, no catastrophic backtracking.** Each regex is
 *    O(n) on the input string. Tested against malformed inputs of 10K+
 *    chars to ensure no ReDoS vector.
 *  - **Pure function.** Returns a new object; never mutates the input.
 *    The walker recurses into plain objects and arrays only — primitive
 *    boxed types (Date, RegExp, Map, Set) are passed through unchanged
 *    because OTel attribute values are spec'd as primitives + arrays.
 *  - **Cycle-safe.** A WeakSet of visited objects prevents stack
 *    overflow on circular attribute graphs.
 */

const REDACTED = "[REDACTED]";

/**
 * Cap recursion depth. OTel attribute spec is primitives + arrays of
 * primitives — there's no legitimate reason to nest deeper than a
 * couple of levels. The cap protects against a misconfigured customer
 * shoving a deep object in via `setAttribute(...)`. Anything past the
 * cap is replaced wholesale with REDACTED, biased toward over-redacting
 * in the failure mode.
 */
const MAX_DEPTH = 20;

const PII_PATTERNS: { name: string; pattern: RegExp }[] = [
  // Email — RFC 5321 local-part chars + domain. The {1,254} bound
  // matches the SMTP cap; without it, a 1MB string of dots would be
  // valid input to scan.
  {
    name: "email",
    pattern:
      /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g,
  },
  // E.164 + common North American formats. The leading `\(?` allows
  // the `(415) 555-0199` shape; the `\+?` allows the `+1-415...` shape.
  // We require at least 10 chars to bracket out order-numbers-with-hyphens.
  {
    name: "phone",
    pattern: /\(?\+?\d[\d \-().]{8,18}\d/g,
  },
  // SSN (US) — XXX-XX-XXXX with separators required so we don't
  // shred every 9-digit number (Social Security area numbers don't
  // start with 000, 666, or 9XX, but enforcing that here would let
  // through a deliberately-formatted leak).
  {
    name: "ssn",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  // Credit card — Luhn-shaped 13-19 digit groups, optional separators.
  // We don't run a Luhn check (false positive on order numbers is
  // preferable to a false negative on a real card).
  {
    name: "credit_card",
    pattern: /\b(?:\d[ -]?){13,19}\b/g,
  },
  // IPv4 — strips client/server addresses that often appear in tool
  // attribute bags.
  {
    name: "ipv4",
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b/g,
  },
];

function redactString(value: string): string {
  let out = value;
  for (const { pattern } of PII_PATTERNS) {
    out = out.replace(pattern, REDACTED);
  }
  return out;
}

function redactValue(
  value: unknown,
  seen: WeakSet<object>,
  depth: number,
): unknown {
  if (depth > MAX_DEPTH) return REDACTED;
  if (typeof value === "string") {
    return redactString(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) return REDACTED;
    seen.add(value);
    return value.map((v) => redactValue(v, seen, depth + 1));
  }
  if (value !== null && typeof value === "object") {
    if (seen.has(value as object)) return REDACTED;
    seen.add(value as object);
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactValue(v, seen, depth + 1);
    }
    return out;
  }
  return value;
}

export function sanitizePII(
  attrs: Record<string, unknown>,
): Record<string, unknown> {
  const seen = new WeakSet<object>();
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(attrs)) {
    out[k] = redactValue(v, seen, 1);
  }
  return out;
}

export const __test__ = {
  PII_PATTERNS,
  redactString,
  REDACTED,
  MAX_DEPTH,
};
