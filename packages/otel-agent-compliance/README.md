# @attestry/otel-agent-compliance

OpenTelemetry SpanProcessor that emits Attestry ABDR (Agent-Based Decision Record) entries for every AI tool call, LLM completion, retrieval, or policy evaluation that flows through your tracer. Every recorded decision becomes part of a hash-chained, cryptographically-verifiable compliance ledger you can replay against EU AI Act, NIST AI RMF, and ISO 42001 audits.

## Install

```bash
npm install @attestry/otel-agent-compliance @opentelemetry/sdk-node
```

The package has **no dependencies and no peer dependencies**. Bring your own OpenTelemetry SDK (usually `@opentelemetry/sdk-node`); see [Compatibility](#compatibility) for supported versions.

## Compatibility

| | Supported |
|---|---|
| Node.js | `>=20.19.0` |
| Module format | **ESM only** (`"type": "module"`, no CommonJS build). Use `import`. On the supported Node versions, `require()` from CommonJS also works through Node's built-in `require(esm)`. |
| OpenTelemetry JS 2.x | `@opentelemetry/sdk-node` `0.200.x`–`0.223.x` (`sdk-trace-base` 2.0+, `sdk-trace` 2.9+) |
| OpenTelemetry JS 3.x | `@opentelemetry/sdk-node` `0.300.x`+ (`sdk-trace` 3.x). **OTel JS 3.x itself requires Node `>=22.15.0`.** On Node 20, stay on OTel 2.x: `npm install @opentelemetry/sdk-node@"<0.300"`. |

The exporter doesn't import any `@opentelemetry/*` package, not even for types. It implements the span-processor interface structurally, through its own exported `SpanProcessorLike` / `ReadableSpanLike` / `SpanLike` types. These cover only the members it touches (`span.name`, `span.attributes`, `span.spanContext().spanId`, `span.setAttribute`). OTel JS 2.x and 3.x spans and processors are compatible with them. A consumer typecheck confirms this against sdk-node releases from `0.200.0` through the latest (see [Development](#development)). Because nothing is declared against OTel, `npm install` cannot conflict with whatever OTel version your app already uses, whether you add this package to an existing project or install both together.

## Quick start

```ts
import { NodeSDK } from "@opentelemetry/sdk-node";
import { AttestryDecisionExporter } from "@attestry/otel-agent-compliance";

const sdk = new NodeSDK({
  spanProcessors: [
    new AttestryDecisionExporter({
      apiUrl: "https://attestry.ai/api/v1/decisions/bulk",
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
- `inputDigest` — `sha256:` of the canonical form (sorted keys) of the span's `input` (or `ai.prompt`) attribute **after sanitization**. See [Digest semantics](#digest-semantics).
- `outputDigest` — the same for `output` (or `ai.completion`), when present
- `frameworkClaims[]` — heuristic mappings to EU AI Act / NIST AI RMF / ISO 42001 articles
- `toolInvocations[]` — `tool.name` if set
- `policyOutcome` — `permitted` / `denied` / `escalated` if recognized
- `idempotencyKey` — the OTel span ID (replay-safe)

**The exporter never sends raw span input or output text.** Only digests cross the wire by default. Tools, prompts, and completions stay inside your process.

### Digest semantics

The sanitizer runs first. `inputDigest` and `outputDigest` are computed over its **redacted** output, never over the raw attributes:

```
inputDigest = "sha256:" + hex(sha256(stableStringify(sanitized.input ?? sanitized["ai.prompt"] ?? {})))
```

Here `sanitized` is the sanitizer's output, and `stableStringify` is `JSON.stringify` with object keys sorted recursively.

This is deliberate. A sha256 of a short raw value (an email address, phone number, SSN, or card number) can be reversed by dictionary or brute force, so hashing the raw input would leak the PII that the sanitizer removes. This has two consequences:

- **To reproduce a digest**, run the same sanitizer (the default `sanitizePII` or your own) over the original input, then hash the result.
- **Inputs that differ only in redacted spans get the same digest.** For example, `refund alice@example.com` and `refund mallory@example.com` collide. The digest attests to the redacted content, not to which PII value was present. If you need digests that tell such inputs apart, supply a `sanitizer` that replaces each PII value with a stable token (for example, a keyed HMAC under a key you control) instead of `[REDACTED]`. The digest is always computed over whatever your sanitizer returns.

## PII sanitizer

The default sanitizer redacts emails, phone numbers, US SSNs, credit card numbers, and IPv4 addresses inside any string-valued span attribute. Its output is also what the digests are computed over (see [Digest semantics](#digest-semantics)). Override with `config.sanitizer` to plug in HIPAA / GDPR special-category rules:

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
| `apiUrl` | (required) | Full URL of the bulk ingest endpoint: `https://attestry.ai/api/v1/decisions/bulk` for the hosted service. It must be the final URL, because redirects are not followed. |
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

The exporter never throws to your application. Every failed or partially rejected batch is logged as a `warn` on the configured logger. Records are never dropped silently.

- **Retried (up to 3 attempts in total):** network errors, timeouts, and HTTP `408`, `429`, `500`, `502`, `503`, `504`. The backoff is capped exponential (250ms, then 750ms, plus jitter). A `Retry-After` header is honored, capped at 60s. If the last attempt fails, the batch is logged and dropped.
- **Permanent, logged and dropped after one attempt:** any other non-2xx (`400`, `401`, `402`, `403`, `404`, `413`, `422`, `501`, …).
- **Redirects (3xx) are never followed.** Following a cross-origin redirect would forward your `x-api-key` header to the redirect target, so a 3xx is logged as a failure, with the redacted `Location`. `apiUrl` must be the final ingest URL.
- **A 2xx counts only when it is `application/json` with `{ "success": true, "data": { … } }`.** An HTML page served with `200` (a login, gate, or captive-portal page), a body with `success: false`, or an unrecognised body is logged as a failure.
- **Partial batches:** the ingest route answers `200` even when some records are rejected, and lists them in `data.failed[]`. The exporter logs a warning with the rejected indices and their `code`s (for example `ijson_validation_failed` or `idempotency_unique_violation`). `AttestryClient.recordDecisionsBatch()` returns them as `failures`, with `ok: false`.

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

## Development

```bash
npm ci && npm run typecheck && npm test && npm run build
npm run test:otel-compat   # strict consumer installs next to OTel JS 2.x + 3.x
```

`test:otel-compat` packs the package. For each `@opentelemetry/sdk-node` row (`0.200.0`, `0.210.0`, `0.214.0`, `0.219.0`, `0.220.0`, `0.223.0`, `0.300.0`, `latest`) it runs:

- strict one-shot and add-to-existing `npm install`s, without `--legacy-peer-deps`, plus `npm ls --all`
- a NodeSDK runtime smoke test against a local stub
- a consumer `tsc` check: that SDK's real span and processor types are assigned to the structural types, with a negative control

OTel 3.x rows are skipped on Node < 22.15. In CI, run it on Node 20.19+ (2.x rows) and on Node 22.15+ (all rows).

## License

Apache-2.0
