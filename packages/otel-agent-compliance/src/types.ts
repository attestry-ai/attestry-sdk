/**
 * Public types for `@attestry/otel-agent-compliance`.
 *
 * Kept dependency-free (no `@opentelemetry/*` types in this file) so
 * customers who only want the type surface can import them without
 * pulling in the OTel runtime.
 */

/**
 * One canonical EU-AI-Act / NIST / ISO claim attached to a decision
 * record. Matches the wire format of `frameworkClaims[]` in
 * `decisionCreateSchema` (server-side validation enforces the same
 * field bounds).
 */
export interface FrameworkClaim {
  framework: string;
  article: string;
  claim: string;
}

export interface ToolInvocation {
  name: string;
  inputHash?: string;
  outputHash?: string;
}

/**
 * The shape we POST to `/api/v1/decisions/bulk` as one item. Mirrors
 * `DecisionCreateInput` on the server but kept structurally local — the
 * exporter never imports server code.
 *
 * Hash strings MUST already be in `sha256:[a-f0-9]{64}` form. The
 * exporter computes them; customers usually don't construct DecisionInput
 * by hand.
 */
export interface DecisionInput {
  systemId: string;
  inputDigest: string;
  outputDigest?: string;
  frameworkClaims: FrameworkClaim[];
  toolInvocations: ToolInvocation[];
  delegationChain: { agentId: string; delegationToken?: string }[];
  humanOversightState?: "approved" | "bypassed" | "not_required";
  policyOutcome?: "permitted" | "denied" | "escalated";
  idempotencyKey?: string;
}

/**
 * Configuration for AttestryDecisionExporter. The split between
 * `apiUrl` (full URL of the batch ingest endpoint) and `systemId` is
 * deliberate — one exporter instance ingests on behalf of one Attestry
 * system. Multi-system processes spin up multiple exporters.
 *
 * `sanitizer` overrides the built-in PII regex stripper. Customers with
 * stricter rules (HIPAA, EU GDPR special categories) supply their own.
 *
 * `frameworkTagger` overrides the heuristic mapping from span attrs to
 * framework articles. Customers with a curated taxonomy supply their
 * own.
 */
export interface AttestryExporterConfig {
  /**
   * Full URL of the bulk decision ingest endpoint (`POST
   * /api/v1/decisions/bulk`). For the hosted service this is
   * `https://attestry.ai/api/v1/decisions/bulk`.
   *
   * The exporter doesn't infer this from `apiKey`; the customer provides
   * the literal URL so that staging / on-prem deployments work without
   * an extra env var. It must be the FINAL URL: redirects are never
   * followed (so `x-api-key` is never forwarded to another origin), and
   * a 3xx is logged as a failed batch.
   */
  apiUrl: string;
  apiKey: string;
  systemId: string;
  /**
   * Optional override for the default PII sanitizer. Receives the
   * span's attribute bag, returns the redacted attribute bag. Pure
   * function — exporter doesn't expect side effects.
   *
   * The returned bag is ALSO what `inputDigest` / `outputDigest` are
   * computed over: digests fingerprint the redacted input, never the
   * raw one (see README "Digest semantics").
   */
  sanitizer?: (attrs: Record<string, unknown>) => Record<string, unknown>;
  /**
   * Optional override for the default framework tagger. Receives a
   * lightweight view of the span (name + attributes), returns claim
   * tuples to attach to the decision record.
   */
  frameworkTagger?: (input: SpanFrameworkContext) => FrameworkClaim[];
  /**
   * Optional decision-detection override. If supplied, replaces the
   * built-in heuristic. Returning `false` skips the span (it's never
   * queued).
   */
  shouldRecordAsDecision?: (input: SpanFrameworkContext) => boolean;
  /** Default 20. */
  batchSize?: number;
  /** Default 5000ms. */
  batchInterval?: number;
  /** Default 10_000ms. */
  fetchTimeoutMs?: number;
  /**
   * Optional logger. Defaults to a console-prefixed logger that writes
   * to stderr. Customers wiring through pino/winston pass their own.
   * The exporter calls `logger.warn` on flush failures and
   * `logger.error` on internal bugs — never throws.
   */
  logger?: ExporterLogger;
}

export interface SpanFrameworkContext {
  name: string;
  attributes: Record<string, unknown>;
}

export interface ExporterLogger {
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

// ─── Structural OpenTelemetry types ──────────────────────────────────

/*
 * The package depends on NO `@opentelemetry/*` package, not even for
 * types: these are the minimal shapes the exporter actually touches.
 * Spans and span processors from OpenTelemetry JS 2.x
 * (`@opentelemetry/sdk-trace-base` 2.0+, `@opentelemetry/sdk-trace` 2.9+)
 * and 3.x (`@opentelemetry/sdk-trace` 3.x) are structurally compatible
 * with them. `scripts/otel-compat.mjs` proves this with a consumer
 * typecheck against the real types of every sdk-node row in its matrix,
 * from 0.200.0 through the latest release.
 *
 * Why not import the real OTel types and declare an (optional) peer?
 * npm resolves an ABSENT optional peer at its newest version when it
 * checks for conflicts. No single OTel tracing package exists across
 * both lines with compatible `@opentelemetry/api` ranges:
 * `@opentelemetry/sdk-trace` starts at 2.9.0, and its 3.x needs
 * api >=1.10; `sdk-trace-base` is 2.x-only, with api <1.10. So any
 * such peer makes `npm install` ERESOLVE in an existing project on one
 * of the two lines.
 */

/** The part of a just-started span the exporter uses (`onStart`). */
export interface SpanLike {
  setAttribute(key: string, value: string): unknown;
}

/** The part of an ended span the exporter reads (`onEnd`). */
export interface ReadableSpanLike {
  readonly name: string;
  readonly attributes: Readonly<Record<string, unknown>>;
  spanContext(): { readonly spanId: string };
}

/**
 * Structural OpenTelemetry `SpanProcessor`. The 2.x and 3.x interfaces
 * share this shape; 3.x's optional `onEnding` is not implemented.
 */
export interface SpanProcessorLike {
  onStart(span: SpanLike, parentContext?: unknown): void;
  onEnd(span: ReadableSpanLike): void;
  forceFlush(): Promise<void>;
  shutdown(): Promise<void>;
}
