/**
 * Compile-time proof (`npm run typecheck` checks this file) that the
 * local structural types are compatible with the REAL OpenTelemetry
 * types in this repo's devDependencies (`@opentelemetry/sdk-trace` 3.x).
 * For OTel 2.x (`sdk-trace-base` 2.0+ via sdk-node 0.200–0.219, and
 * `sdk-trace` 2.9+), `scripts/otel-compat.mjs` runs the same checks as a
 * consumer typecheck against each sdk-node release's own types.
 *
 * The runtime assertions are trivial; the value is that tsc rejects the
 * file if any assignment below stops type-checking.
 */
import type {
  ReadableSpan,
  Span,
  SpanProcessor,
} from "@opentelemetry/sdk-trace";
import { describe, expect, it } from "vitest";
import { AttestryDecisionExporter } from "../exporter.js";
import type {
  ReadableSpanLike,
  SpanLike,
  SpanProcessorLike,
} from "../types.js";

// The exporter is usable wherever OTel expects a SpanProcessor.
const asOtelProcessor = (e: AttestryDecisionExporter): SpanProcessor => e;
// Real OTel spans satisfy what the exporter reads / writes.
const asReadableLike = (s: ReadableSpan): ReadableSpanLike => s;
const asSpanLike = (s: Span): SpanLike => s;
// And the structural processor shape is itself an OTel SpanProcessor.
const likeAsOtel = (p: SpanProcessorLike): SpanProcessor => p;

describe("structural OTel types", () => {
  it("are assignable to/from @opentelemetry/sdk-trace types (checked by tsc)", () => {
    const exporter = new AttestryDecisionExporter({
      apiUrl: "https://example.com/api/v1/decisions/bulk",
      apiKey: "k",
      systemId: "s",
    });
    expect(asOtelProcessor(exporter)).toBe(exporter);
    expect(likeAsOtel(exporter)).toBe(exporter);
    expect(typeof asReadableLike).toBe("function");
    expect(typeof asSpanLike).toBe("function");
    return exporter.shutdown();
  });
});
