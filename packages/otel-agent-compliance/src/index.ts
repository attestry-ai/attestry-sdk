/**
 * Public entry point for `@attestry/otel-agent-compliance`.
 *
 * Customers typically import only `AttestryDecisionExporter`:
 *
 * ```ts
 * import { NodeSDK } from "@opentelemetry/sdk-node";
 * import { AttestryDecisionExporter } from "@attestry/otel-agent-compliance";
 *
 * const sdk = new NodeSDK({
 *   spanProcessors: [
 *     new AttestryDecisionExporter({
 *       apiUrl: "https://attestry.app/api/v1/decisions/bulk",
 *       apiKey: process.env.ATTESTRY_API_KEY!,
 *       systemId: process.env.ATTESTRY_SYSTEM_ID!,
 *     }),
 *   ],
 * });
 * sdk.start();
 * ```
 *
 * Power users override the sanitizer / framework tagger / decision
 * heuristic; see the `AttestryExporterConfig` type for the full
 * surface.
 */

export { AttestryDecisionExporter } from "./exporter.js";
export { AttestryClient } from "./client.js";
export { sanitizePII } from "./sanitizer.js";
export { tagWithFrameworks } from "./framework-tagger.js";
export type {
  AttestryExporterConfig,
  DecisionInput,
  ExporterLogger,
  FrameworkClaim,
  SpanFrameworkContext,
  ToolInvocation,
} from "./types.js";
