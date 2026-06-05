# @attestry/otel-agent-compliance

OpenTelemetry SpanProcessor that emits Attestry ABDR (Agent-Based Decision Record) entries for every AI tool call, LLM completion, retrieval, or policy evaluation that flows through your tracer. Every recorded decision becomes part of a hash-chained, cryptographically-verifiable compliance ledger you can replay against EU AI Act, NIST AI RMF, and ISO 42001 audits.

## Install

```bash
npm install @attestry/otel-agent-compliance @opentelemetry/sdk-node
```

`@opentelemetry/sdk-node` is a peer dependency. Install it alongside if you don't have it already.

## Quick start

```ts
import { NodeSDK } from "@opentelemetry/sdk-node";
import { AttestryDecisionExporter } from "@attestry/otel-agent-compliance";

const sdk = new NodeSDK({
  spanProcessors: [
    new AttestryDecisionExporter({
      apiUrl: "https://attestry.app/api/v1/decisions/bulk",
      apiKey: process.env.ATTESTRY_API_KEY!,
      systemId: process.env.ATTESTRY_SYSTEM_ID!,
    }),
  ],
});

sdk.start();

process.on("SIGTERM", async () => {
  await sdk.shutdown(); // flushes the in-memory queue
});
```

## What gets recorded

By default, the exporter records a span as a decision when ANY of the following is true:

| Signal | Source |
|---|---|
| `ai.operation` attribute set | OpenInference / OpenTelemetry semantic conventions |
| `gen_ai.operation.name` attribute set | OTel GenAI semantic conventions |
| `tool.name` attribute set | LangChain / LlamaIndex tool spans |
| `policy.outcome` or `decision.outcome` attribute set | Customer policy engines |
| Span name contains `tool`, `llm`, `completion`, or `policy` | Heuristic on framework span names |

Spans that don't match are dropped without making a network call. Override with `shouldRecordAsDecision`.

## What lands on the wire

Each decision posted to `/api/v1/decisions/bulk` contains:

- `systemId` — the Attestry system this exporter is attached to
- `inputDigest` — `sha256:` of the canonical-form span input (sorted keys)
- `outputDigest` — `sha256:` of the canonical-form span output, when present
- `frameworkClaims[]` — heuristic mappings to EU AI Act / NIST AI RMF / ISO 42001 articles
- `toolInvocations[]` — `tool.name` if set
- `policyOutcome` — `permitted` / `denied` / `escalated` if recognized
- `idempotencyKey` — the OTel span ID (replay-safe)

**The exporter never sends raw span input or output text.** Only digests cross the wire by default. Tools, prompts, and completions stay inside your process.

## PII sanitizer

The default sanitizer redacts emails, phone numbers, US SSNs, credit card numbers, and IPv4 addresses inside any string-valued span attribute. Override with `config.sanitizer` to plug in HIPAA / GDPR special-category rules:

```ts
new AttestryDecisionExporter({
  // ...
  sanitizer: (attrs) => {
    const out = { ...attrs };
    delete out["http.request.body"]; // never ship request bodies
    return out;
  },
});
```

## Framework tagger

Heuristic mapping from span context to `frameworkClaims[]`. Customers with curated taxonomies override it:

```ts
new AttestryDecisionExporter({
  // ...
  frameworkTagger: ({ name, attributes }) => {
    if (attributes["custom.tag"] === "loan-decision") {
      return [
        {
          framework: "EU AI Act",
          article: "Annex III §5(b)",
          claim: "Creditworthiness evaluation for natural persons.",
        },
      ];
    }
    return [];
  },
});
```

## Configuration reference

| Option | Default | Description |
|---|---|---|
| `apiUrl` | (required) | Full URL of the bulk ingest endpoint |
| `apiKey` | (required) | API key with `write:assessments` permission |
| `systemId` | (required) | Attestry system UUID |
| `batchSize` | `20` | Flush trigger — records per batch |
| `batchInterval` | `5000ms` | Flush trigger — max delay before partial flush |
| `fetchTimeoutMs` | `10_000` | Per-request abort timeout |
| `sanitizer` | regex stripper | Override PII sanitization |
| `frameworkTagger` | heuristic mapping | Override claim generation |
| `shouldRecordAsDecision` | heuristic | Override decision detection |
| `logger` | console (stderr) | Wire pino/winston/etc. via `warn`/`error` |

## Failure mode

The exporter never throws to your application. Network errors, 5xx responses, and timeouts go through three retries with capped exponential backoff (250ms → 750ms → 2_250ms + jitter), then log via the configured logger and drop the batch. 4xx responses (other than 429) are treated as permanent — no retry, log + drop.

## Integration examples

### LangChain

LangChain emits OTel spans automatically when `LANGCHAIN_TRACING_V2=true` and an OTel SDK is initialized in the process. Wire the exporter and every chain step shows up in Attestry.

### LlamaIndex

LlamaIndex's OpenInference instrumentation tags spans with `openinference.span.kind`. The default decider catches them via the `ai.operation` / `gen_ai.operation.name` keys.

### OpenAI / Anthropic SDK

Wrap the SDK call in a manual span and set `ai.operation` to "completion":

```ts
import { trace } from "@opentelemetry/api";

const tracer = trace.getTracer("my-app");
await tracer.startActiveSpan("openai.completion", async (span) => {
  span.setAttribute("ai.operation", "completion");
  span.setAttribute("input", prompt);
  const result = await openai.chat.completions.create({ ... });
  span.setAttribute("output", result.choices[0].message.content);
  span.end();
});
```

## License

Apache-2.0
