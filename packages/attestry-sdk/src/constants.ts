// ─── Public enums mirrored from the kernel's incident schema ────────────────
//
// Duplicated here on purpose: the SDK is a public API and must not import
// from the kernel's internal `src/lib/incidents/schema.ts`. Drift is caught
// by a server-side test in the kernel that reads this file and asserts
// the arrays match.
//
// **Object.freeze (P1 hardening)**: each export is runtime-frozen so a
// hostile or buggy npm dependency cannot mutate the array between SDK
// import and method call. Without freeze, a `(SEVERITIES as
// any).push("evil")` from a misbehaving dependency would bypass the
// SDK's `.includes()` validation on closed-enum input fields. The
// drift extractor in `src/lib/incidents/__tests__/sdk-drift.test.ts`
// accepts both `as const` forms (bare and `Object.freeze`-wrapped) so
// kernel-side route-local consts continue to extract cleanly.

export const INCIDENT_TYPES = Object.freeze([
  "prompt_injection",
  "jailbreak",
  "tool_misuse",
  "compliance_violation",
  "data_leak",
  "hallucination",
  "bias_detected",
  "safety_bypass",
  "other",
] as const);

export type IncidentType = (typeof INCIDENT_TYPES)[number];

export const SEVERITIES = Object.freeze([
  "low",
  "medium",
  "high",
  "critical",
] as const);

export type Severity = (typeof SEVERITIES)[number];

export const FRAMEWORK_CODES = Object.freeze([
  "eu_ai_act",
  "colorado_ai_act",
  "nyc_local_law_144",
  "nist_ai_rmf",
  "iso_42001",
  "soc_2",
  "hipaa",
  "gdpr",
] as const);

export type FrameworkCode = (typeof FRAMEWORK_CODES)[number];
