/**
 * Minimal ReadableSpan / Span fakes for tests. We intentionally don't
 * depend on a real `@opentelemetry/sdk-node` runtime in unit tests —
 * the SpanProcessor contract is small enough to fake, and a real SDK
 * pulls in tracer providers, resources, and exporters we don't need.
 *
 * The `integration.test.ts` file in this same directory does spin up a
 * real `TracerProvider` (`@opentelemetry/sdk-trace`) to verify
 * end-to-end wiring.
 */

import type {
  ReadableSpan,
  Span,
} from "@opentelemetry/sdk-trace";

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

export interface KernelFailedRecord {
  index: number;
  code: string;
  error?: string;
}

/**
 * A `Response` shaped exactly like the kernel's real
 * `POST /api/v1/decisions/bulk` success: the route returns
 * `successResponse(result, 200)` (kernel
 * `src/app/api/v1/decisions/bulk/route.ts`), i.e.
 * `{ success: true, data: BulkIngestResult }` with
 * `Content-Type: application/json` (`NextResponse.json`, kernel
 * `src/lib/api.ts`). `BulkIngestResult` = `{ totalSubmitted,
 * totalInserted, totalFailed, inserted[], failed[{ index, systemId,
 * error, code }] }` (kernel `src/lib/decisions/bulk-ingest.ts`).
 *
 * 0.1.x tests mocked a bare `{ totalInserted }` body, which is why the
 * client's top-level read of the envelope was never caught.
 */
export function kernelBulkResponse(opts: {
  submitted: number;
  failed?: KernelFailedRecord[];
  systemId?: string;
}): Response {
  const systemId = opts.systemId ?? "00000000-0000-0000-0000-000000000001";
  const failed = (opts.failed ?? []).map((f) => ({
    index: f.index,
    systemId,
    error: f.error ?? `record ${f.index} rejected`,
    code: f.code,
  }));
  const failedIdx = new Set(failed.map((f) => f.index));
  const inserted = [];
  for (let index = 0; index < opts.submitted; index++) {
    if (failedIdx.has(index)) continue;
    inserted.push({
      index,
      id: `00000000-0000-0000-0000-${index.toString(16).padStart(12, "0")}`,
      systemId,
      sequenceNumber: index + 1,
      recordHash: "0".repeat(64),
      createdAt: "2026-11-05T00:00:00.000Z",
    });
  }
  return new Response(
    JSON.stringify({
      success: true,
      data: {
        totalSubmitted: opts.submitted,
        totalInserted: inserted.length,
        totalFailed: failed.length,
        inserted,
        failed,
      },
    }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
}

/** Kernel `errorResponse(message, status)` shape: `{ success: false, error }`. */
export function kernelErrorResponse(
  status: number,
  error: string,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify({ success: false, error }), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}
