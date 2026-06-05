/**
 * Minimal ReadableSpan / Span fakes for tests. We intentionally don't
 * depend on a real `@opentelemetry/sdk-node` runtime in unit tests —
 * the SpanProcessor contract is small enough to fake, and a real SDK
 * pulls in tracer providers, resources, and exporters we don't need.
 *
 * The `integration.test.ts` file in this same directory does spin up a
 * real `BasicTracerProvider` to verify end-to-end wiring.
 */

import type {
  ReadableSpan,
  Span,
} from "@opentelemetry/sdk-trace-base";

export interface MakeSpanInput {
  name: string;
  attributes?: Record<string, unknown>;
  spanId?: string;
}

let nextSpanId = 1;

export function makeReadableSpan(input: MakeSpanInput): ReadableSpan {
  const spanId =
    input.spanId ?? `00000000${(nextSpanId++).toString(16).padStart(8, "0")}`;
  return {
    name: input.name,
    attributes: input.attributes ?? {},
    spanContext: () => ({
      traceId: "00000000000000000000000000000000",
      spanId,
      traceFlags: 1,
    }),
  } as unknown as ReadableSpan;
}

export function makeSpan(input: MakeSpanInput): Span {
  const attrs: Record<string, unknown> = { ...(input.attributes ?? {}) };
  return {
    setAttribute(key: string, value: unknown): Span {
      attrs[key] = value;
      return this as unknown as Span;
    },
    spanContext: () => ({
      traceId: "00000000000000000000000000000000",
      spanId: input.spanId ?? "00000000deadbeef",
      traceFlags: 1,
    }),
    _capturedAttributes: attrs,
  } as unknown as Span;
}
