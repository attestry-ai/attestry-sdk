/**
 * AttestryDecisionExporter — implements the OpenTelemetry SpanProcessor
 * interface from `@opentelemetry/sdk-trace-base`. Customers register
 * one instance with their TracerProvider; every ended span flows
 * through `onEnd`, gets queued if it looks like an AI decision, and
 * is flushed to the Attestry batch ingest endpoint in batches.
 *
 * Design constraints — every one of these is load-bearing:
 *
 *  - **`onEnd` MUST NOT throw.** SpanProcessor is on the OTel hot path;
 *    a throw here causes telemetry to drop silently for the whole
 *    process. We wrap every step in try/catch and log via the
 *    configured logger.
 *  - **Batch on size OR interval, whichever first.** A bursty workload
 *    fills the queue past the batch size and flushes immediately; a
 *    quiet workload flushes the partial queue every `batchInterval`
 *    so decisions arrive within a bounded delay of the span ending.
 *  - **`shutdown` flushes the remaining queue.** Otherwise a graceful
 *    Node.js exit (SIGTERM during a deploy, e.g.) loses the last
 *    in-memory batch. We await the final flush.
 *  - **Per-span work is bounded.** The exporter does NOT record raw
 *    span input/output text — it records a sha256 digest of each.
 *    A 100KB tool output becomes 64 hex chars in the wire payload.
 *  - **Decision detection runs synchronously in `onEnd`.** The async
 *    network call happens later in `flush`. We never block the OTel
 *    pipeline on I/O.
 *  - **Queue cap.** A misconfigured customer (no flush, slow server)
 *    must not OOM the process. We cap the queue at 10× batch size; on
 *    overflow, we drop the OLDEST records (FIFO) and log a warning.
 *    Newest records are more diagnostically valuable than 5-minute-old
 *    ones from a stalled flusher.
 *  - **`flush` is reentrant-safe.** Two concurrent flushes draining the
 *    same queue are guarded by `flushInFlight` — the second waits for
 *    the first to finish, then re-checks the queue.
 */

import type {
  ReadableSpan,
  Span,
  SpanProcessor,
} from "@opentelemetry/sdk-trace-base";
import { createHash } from "node:crypto";

import { AttestryClient, safeLog } from "./client.js";
import { sanitizePII } from "./sanitizer.js";
import { tagWithFrameworks } from "./framework-tagger.js";
import type {
  AttestryExporterConfig,
  DecisionInput,
  ExporterLogger,
  SpanFrameworkContext,
} from "./types.js";

const DEFAULT_BATCH_SIZE = 20;
const DEFAULT_BATCH_INTERVAL_MS = 5000;
const QUEUE_CAP_MULTIPLIER = 10;
/** Wire schema cap (`decisionCreateSchema.frameworkClaims.max(50)`).
 *  A custom tagger that exceeds this would get the entire decision
 *  rejected by the server; we slice defensively. */
const FRAMEWORK_CLAIMS_CAP = 50;

const DECISION_KEYWORDS = ["tool", "llm", "completion", "policy"];
const DECISION_ATTR_KEYS = [
  "ai.operation",
  "gen_ai.operation.name",
  "tool.name",
  "policy.outcome",
  "decision.outcome",
];

const consoleLogger: ExporterLogger = {
  warn(message, meta) {
    if (meta) {
      console.warn(`[attestry/otel] ${message}`, meta);
    } else {
      console.warn(`[attestry/otel] ${message}`);
    }
  },
  error(message, meta) {
    if (meta) {
      console.error(`[attestry/otel] ${message}`, meta);
    } else {
      console.error(`[attestry/otel] ${message}`);
    }
  },
};

export class AttestryDecisionExporter implements SpanProcessor {
  private readonly client: AttestryClient;
  private readonly logger: ExporterLogger;
  private readonly batchSize: number;
  private readonly batchInterval: number;
  private readonly queueCap: number;
  private readonly sanitizer: (
    attrs: Record<string, unknown>,
  ) => Record<string, unknown>;
  private readonly tagger: (
    ctx: SpanFrameworkContext,
  ) => ReturnType<typeof tagWithFrameworks>;
  private readonly decider: (ctx: SpanFrameworkContext) => boolean;

  private queue: ReadableSpan[] = [];
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private flushInFlight: Promise<void> | null = null;
  private shutdownCalled = false;

  constructor(private readonly config: AttestryExporterConfig) {
    if (!config.apiUrl) {
      throw new Error(
        "AttestryDecisionExporter: config.apiUrl is required",
      );
    }
    if (!config.apiKey) {
      throw new Error(
        "AttestryDecisionExporter: config.apiKey is required",
      );
    }
    if (!config.systemId) {
      throw new Error(
        "AttestryDecisionExporter: config.systemId is required",
      );
    }

    this.client = new AttestryClient(config);
    this.logger = config.logger ?? consoleLogger;
    this.batchSize = Math.max(1, config.batchSize ?? DEFAULT_BATCH_SIZE);
    this.batchInterval = Math.max(
      1,
      config.batchInterval ?? DEFAULT_BATCH_INTERVAL_MS,
    );
    this.queueCap = this.batchSize * QUEUE_CAP_MULTIPLIER;
    this.sanitizer = config.sanitizer ?? sanitizePII;
    this.tagger = config.frameworkTagger ?? tagWithFrameworks;
    this.decider = config.shouldRecordAsDecision ?? defaultDecider;

    this.scheduleFlush();
  }

  // ─── SpanProcessor API ───────────────────────────────────────────

  onStart(span: Span): void {
    try {
      span.setAttribute("attestry.system_id", this.config.systemId);
    } catch (err) {
      // Some Span impls (e.g. NoopSpan) reject attribute writes —
      // that's fine, we just skip the tag.
      safeLog(this.logger, "error", "onStart: setAttribute failed", {
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  onEnd(span: ReadableSpan): void {
    if (this.shutdownCalled) return;
    try {
      const ctx: SpanFrameworkContext = {
        name: span.name,
        attributes: { ...span.attributes },
      };
      if (!this.decider(ctx)) return;

      this.queue.push(span);

      if (this.queue.length > this.queueCap) {
        const dropped = this.queue.length - this.queueCap;
        this.queue.splice(0, dropped);
        safeLog(
          this.logger,
          "warn",
          "Queue cap hit — dropping oldest records",
          { dropped, queueCap: this.queueCap },
        );
      }

      if (this.queue.length >= this.batchSize) {
        // Fire-and-forget. flush() never rejects (every path is
        // try/wrapped + safeLog), but defense-in-depth catch keeps
        // a misbehaved logger from creating an UnhandledPromiseRejection
        // that would surface in the customer's Node process.
        this.flush().catch(() => {
          /* swallow — already logged inside flush */
        });
      }
    } catch (err) {
      safeLog(this.logger, "error", "onEnd failed", {
        error: err instanceof Error ? err.message : String(err),
        spanName: span.name,
      });
    }
  }

  async forceFlush(): Promise<void> {
    await this.flush();
  }

  async shutdown(): Promise<void> {
    this.shutdownCalled = true;
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  // ─── Internals ───────────────────────────────────────────────────

  private async flush(): Promise<void> {
    // Reentrancy guard: if a flush is already in flight, queue this
    // call to run after it completes, then re-check the queue.
    if (this.flushInFlight) {
      await this.flushInFlight;
      // After awaiting, fall through and try again — the prior flush
      // may have left newer records in the queue.
    }

    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.queue.length);
    const decisions: DecisionInput[] = [];
    for (const span of batch) {
      try {
        decisions.push(this.spanToDecision(span));
      } catch (err) {
        safeLog(this.logger, "error", "spanToDecision failed", {
          error: err instanceof Error ? err.message : String(err),
          spanName: span.name,
        });
      }
    }

    if (decisions.length === 0) return;

    this.flushInFlight = this.client
      .recordDecisionsBatch(decisions)
      .then(() => undefined)
      .catch((err) => {
        // recordDecisionsBatch already swallows errors, but defense
        // in depth — never let an unhandled rejection escape.
        safeLog(this.logger, "error", "flush: client unexpectedly threw", {
          error: err instanceof Error ? err.message : String(err),
        });
      })
      .finally(() => {
        this.flushInFlight = null;
      });

    // Defensive catch on the awaited promise: if the customer's logger
    // throws inside the .catch above, the resulting rejection would
    // propagate out of flush(). safeLog already wraps the customer
    // logger, but a second guard here is cheap insurance.
    try {
      await this.flushInFlight;
    } catch {
      /* already logged */
    }
  }

  private spanToDecision(span: ReadableSpan): DecisionInput {
    const rawAttrs: Record<string, unknown> = { ...span.attributes };
    const sanitized = this.sanitizer(rawAttrs);

    // Validate the sanitizer's contract — a misbehaved customer
    // sanitizer that returns null/undefined/string would otherwise
    // crash inside `Object.keys(...)` in the framework tagger or
    // `sanitized["tool.name"]` lookup with a confusing TypeError.
    if (sanitized === null || typeof sanitized !== "object") {
      throw new Error(
        "sanitizer must return an object (got " +
          (sanitized === null ? "null" : typeof sanitized) +
          ")",
      );
    }

    const ctx: SpanFrameworkContext = {
      name: span.name,
      attributes: sanitized,
    };
    // Cap claims to wire schema max(50). A custom tagger that exceeds
    // would have its decision rejected wholesale by the server; the
    // slice keeps the partial claim list (better than zero claims).
    const frameworkClaims = this.tagger(ctx).slice(0, FRAMEWORK_CLAIMS_CAP);

    const inputDigest = computeInputDigest(sanitized);
    const outputDigest = computeOutputDigest(sanitized);

    const toolName = sanitized["tool.name"];
    const toolInvocations =
      typeof toolName === "string" && toolName.length > 0
        ? [{ name: toolName.slice(0, 200) }]
        : [];

    const policyOutcome = normalizePolicyOutcome(
      sanitized["decision.outcome"] ?? sanitized["policy.outcome"],
    );

    return {
      systemId: this.config.systemId,
      inputDigest,
      outputDigest,
      frameworkClaims,
      toolInvocations,
      delegationChain: [],
      humanOversightState: "not_required",
      policyOutcome,
      idempotencyKey: span.spanContext().spanId,
    };
  }

  private scheduleFlush(): void {
    this.flushTimer = setInterval(() => {
      // Defensive catch on the fire-and-forget — flush() never rejects,
      // but a customer logger that throws inside safeLog's last-resort
      // console fallback could in theory bubble out. Never let the
      // interval timer create an UnhandledPromiseRejection.
      this.flush().catch(() => {
        /* swallow — already logged inside flush */
      });
    }, this.batchInterval);
    // .unref() so the timer doesn't keep Node alive after the
    // application's normal exit. Customers calling shutdown()
    // explicitly still flush deterministically.
    if (typeof (this.flushTimer as { unref?: () => void }).unref === "function") {
      (this.flushTimer as { unref?: () => void }).unref?.();
    }
  }
}

// ─── Helpers (exported for tests) ─────────────────────────────────

function defaultDecider(ctx: SpanFrameworkContext): boolean {
  const lowerName = ctx.name.toLowerCase();
  for (const kw of DECISION_KEYWORDS) {
    if (lowerName.includes(kw)) return true;
  }
  for (const key of DECISION_ATTR_KEYS) {
    if (ctx.attributes[key] !== undefined) return true;
  }
  return false;
}

function computeInputDigest(attrs: Record<string, unknown>): string {
  // Default to `{}` (empty object) on missing input — matches the
  // spec's `JSON.stringify(attrs['input'] ?? {})` behavior in
  // AGENT_COMPLIANCE_KERNEL_PLAN.md § 15.2. Means "no input" produces
  // a stable, well-known digest (sha256 of "{}") shared with any
  // future Python/Go exporter following the same spec.
  const input = attrs["input"] ?? attrs["ai.prompt"] ?? {};
  return `sha256:${sha256Hex(stableStringify(input))}`;
}

function computeOutputDigest(
  attrs: Record<string, unknown>,
): string | undefined {
  const output = attrs["output"] ?? attrs["ai.completion"];
  if (output === undefined || output === null || output === "") return undefined;
  return `sha256:${sha256Hex(stableStringify(output))}`;
}

function normalizePolicyOutcome(
  raw: unknown,
): "permitted" | "denied" | "escalated" | undefined {
  if (raw === "permitted" || raw === "denied" || raw === "escalated") {
    return raw;
  }
  return undefined;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Sort object keys recursively before serialization so the digest is
 * stable across runs. NOT a JCS implementation — it's a poor man's
 * canonical form sufficient for content addressing on the wire.
 * Customers who need true RFC 8785 supply a sanitizer that runs JCS.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(
    ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
  );
  return `{${entries
    .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`)
    .join(",")}}`;
}

export const __test__ = {
  defaultDecider,
  computeInputDigest,
  computeOutputDigest,
  normalizePolicyOutcome,
  sha256Hex,
  stableStringify,
  DEFAULT_BATCH_SIZE,
  DEFAULT_BATCH_INTERVAL_MS,
  QUEUE_CAP_MULTIPLIER,
  FRAMEWORK_CLAIMS_CAP,
};
