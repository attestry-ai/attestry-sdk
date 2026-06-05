/**
 * LangChain → Attestry compliance integration example.
 *
 * Run:
 *   ATTESTRY_API_KEY=... \
 *   ATTESTRY_SYSTEM_ID=... \
 *   npx tsx examples/langchain-integration.ts
 *
 * Expected: each LangChain tool call / LLM completion in this script
 * surfaces as a decision record in Attestry. Run this against your
 * staging org first; the bulk endpoint counts toward your monthly
 * quota.
 *
 * What this example demonstrates:
 *  1. Initializing `NodeSDK` with `AttestryDecisionExporter` as the
 *     SpanProcessor. (`@opentelemetry/sdk-node` is the peer dep —
 *     install separately.)
 *  2. Manually creating spans that look like LangChain's
 *     OpenInference instrumentation — `gen_ai.operation.name`,
 *     `tool.name`, `input`/`output` attributes.
 *  3. Graceful shutdown via `sdk.shutdown()` so the in-memory queue
 *     drains before the process exits.
 *
 * The actual LangChain JS SDK ships its own OpenInference
 * instrumentation (`@arizeai/openinference-instrumentation-langchain`)
 * that emits these span shapes automatically. Once you've registered
 * that instrumentation in addition to the AttestryDecisionExporter
 * SpanProcessor, the example below is what every chain step looks like
 * to the exporter.
 */

import { trace } from "@opentelemetry/api";
// `@opentelemetry/sdk-node` is a peer dep. Customers install it
// alongside this package. We import lazily inside main() so this file
// type-checks even when the peer isn't installed in the dev tree.
import { AttestryDecisionExporter } from "../src/index.js";

async function main() {
  const apiKey = process.env.ATTESTRY_API_KEY;
  const systemId = process.env.ATTESTRY_SYSTEM_ID;
  const apiUrl =
    process.env.ATTESTRY_API_URL ??
    "https://attestry.app/api/v1/decisions/bulk";

  if (!apiKey || !systemId) {
    console.error(
      "[example] ATTESTRY_API_KEY and ATTESTRY_SYSTEM_ID env vars required.",
    );
    process.exit(2);
  }

  // Lazy import so type-checking doesn't require the peer dep to be
  // installed at compile time.
  const sdkNodeMod = (await import("@opentelemetry/sdk-node").catch(
    () => null,
  )) as typeof import("@opentelemetry/sdk-node") | null;

  if (!sdkNodeMod) {
    console.error(
      "[example] @opentelemetry/sdk-node is required. Install with:",
      "  npm install @opentelemetry/sdk-node",
    );
    process.exit(2);
  }

  const exporter = new AttestryDecisionExporter({
    apiUrl,
    apiKey,
    systemId,
    batchSize: 5,
    batchInterval: 2_000,
  });

  const sdk = new sdkNodeMod.NodeSDK({
    spanProcessors: [exporter],
  });
  sdk.start();

  // ── Simulated chain step 1: tool call ──────────────────────────
  const tracer = trace.getTracer("attestry-example");
  await tracer.startActiveSpan(
    "langchain.tool.call",
    async (span) => {
      span.setAttribute("tool.name", "fetch_user");
      span.setAttribute("input", JSON.stringify({ userId: "u-123" }));
      // Pretend the tool returned the user record.
      span.setAttribute("output", JSON.stringify({ id: "u-123", role: "ops" }));
      span.end();
    },
  );

  // ── Simulated chain step 2: LLM completion ─────────────────────
  await tracer.startActiveSpan("langchain.llm.completion", async (span) => {
    span.setAttribute("gen_ai.operation.name", "chat");
    span.setAttribute("ai.operation", "completion");
    span.setAttribute("input", "Summarize the user's recent activity.");
    span.setAttribute(
      "output",
      "User logged in twice today and triaged three incidents.",
    );
    span.end();
  });

  // ── Simulated chain step 3: policy gate ────────────────────────
  await tracer.startActiveSpan("policy.evaluate", async (span) => {
    span.setAttribute("policy.outcome", "permitted");
    span.setAttribute("input", JSON.stringify({ action: "summarize" }));
    span.end();
  });

  // Drain in-flight spans before exit.
  await sdk.shutdown();
  console.log(
    "[example] decisions submitted. Verify at " +
      "https://attestry.app/dashboard/decisions",
  );
}

main().catch((err) => {
  console.error("[example] failed:", err);
  process.exit(1);
});
