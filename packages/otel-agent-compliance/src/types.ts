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
 * The shape we POST to `/api/v1/decisions/batch` as one item. Mirrors
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
   * Full URL of the ingest endpoint. Customers pass either:
   *   - `https://attestry.app/api/v1/decisions/bulk` (default ingest), or
   *   - `https://attestry.app/api/otel/{orgSlug}/v1/traces/decisions`
   *     (OTel-native path that maps spans → decisions server-side).
   *
   * The exporter doesn't infer this from `apiKey`; the customer provides
   * the literal URL so that staging / on-prem deployments work without
   * an extra env var.
   */
  apiUrl: string;
  apiKey: string;
  systemId: string;
  /**
   * Optional override for the default PII sanitizer. Receives the
   * span's attribute bag, returns the redacted attribute bag. Pure
   * function — exporter doesn't expect side effects.
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
