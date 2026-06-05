/**
 * Integration test against a real `BasicTracerProvider` from
 * `@opentelemetry/sdk-trace-base`. Verifies the exporter actually
 * implements the SpanProcessor contract correctly — the unit tests
 * above use fakes that match our reading of the contract; this test
 * proves that reading is right by feeding spans from a real tracer.
 *
 * We skip this test if the OTel SDK isn't installed (the package may
 * be exercised in environments without the peer dep).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AttestryDecisionExporter } from "../exporter.js";

let SDK_AVAILABLE = false;
let BasicTracerProvider: typeof import("@opentelemetry/sdk-trace-base").BasicTracerProvider;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  ({ BasicTracerProvider } = await import(
    "@opentelemetry/sdk-trace-base"
  ));
  SDK_AVAILABLE = true;
} catch {
  SDK_AVAILABLE = false;
}

const VALID_CONFIG = {
  apiUrl: "https://example.com/api/v1/decisions/bulk",
  apiKey: "k",
  systemId: "00000000-0000-0000-0000-000000000001",
};

describe.skipIf(!SDK_AVAILABLE)("integration with BasicTracerProvider", () => {
  let captured: { url: string; init?: RequestInit }[] = [];

  beforeEach(() => {
    captured = [];
    globalThis.fetch = vi
      .fn()
      .mockImplementation(async (url: string, init?: RequestInit) => {
        captured.push({ url, init });
        return new Response(
          JSON.stringify({ totalInserted: 1, totalFailed: 0 }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("a span ended through a real tracer reaches the exporter and flushes", async () => {
    const exporter = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    const provider = new BasicTracerProvider({
      spanProcessors: [exporter],
    });
    const tracer = provider.getTracer("test");

    const span = tracer.startSpan("openai.llm.completion");
    span.setAttribute("ai.operation", "completion");
    span.setAttribute("input", "what is 2+2?");
    span.setAttribute("output", "4");
    span.end();

    await provider.forceFlush();

    expect(captured.length).toBeGreaterThanOrEqual(1);
    const body = JSON.parse(captured[0]?.init?.body as string);
    expect(body.items[0].systemId).toBe(VALID_CONFIG.systemId);
    expect(body.items[0].inputDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(body.items[0].outputDigest).toMatch(/^sha256:[a-f0-9]{64}$/);

    await provider.shutdown();
  });

  it("provider.shutdown drains the in-memory queue", async () => {
    const exporter = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 100, // never trip size-based flush
      batchInterval: 999_999,
    });
    const provider = new BasicTracerProvider({
      spanProcessors: [exporter],
    });
    const tracer = provider.getTracer("test");

    for (let i = 0; i < 3; i++) {
      const s = tracer.startSpan(`tool.call.${i}`);
      s.setAttribute("tool.name", `t${i}`);
      s.end();
    }
    expect(captured).toHaveLength(0); // no flush yet

    await provider.shutdown();

    expect(captured).toHaveLength(1);
    const body = JSON.parse(captured[0]?.init?.body as string);
    expect(body.items).toHaveLength(3);
  });
});
