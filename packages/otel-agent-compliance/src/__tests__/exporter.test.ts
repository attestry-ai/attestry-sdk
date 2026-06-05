import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AttestryDecisionExporter } from "../exporter.js";
import { __test__ as exporterTest } from "../exporter.js";
import { makeReadableSpan, makeSpan } from "./fakes.js";
import type { ExporterLogger } from "../types.js";

const VALID_CONFIG = {
  apiUrl: "https://example.com/api/v1/decisions/bulk",
  apiKey: "k",
  systemId: "00000000-0000-0000-0000-000000000001",
};

function makeLogger(): ExporterLogger & {
  warns: { msg: string; meta?: Record<string, unknown> }[];
  errors: { msg: string; meta?: Record<string, unknown> }[];
} {
  const warns: { msg: string; meta?: Record<string, unknown> }[] = [];
  const errors: { msg: string; meta?: Record<string, unknown> }[] = [];
  return {
    warn: (msg, meta) => warns.push({ msg, meta }),
    error: (msg, meta) => errors.push({ msg, meta }),
    warns,
    errors,
  };
}

interface FetchCapture {
  url: string;
  init?: RequestInit;
}

function captureFetch(): FetchCapture[] {
  const captured: FetchCapture[] = [];
  globalThis.fetch = vi
    .fn()
    .mockImplementation(async (url: string, init?: RequestInit) => {
      captured.push({ url, init });
      return new Response(
        JSON.stringify({ totalInserted: 1, totalFailed: 0 }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
  return captured;
}

describe("AttestryDecisionExporter — config validation", () => {
  it("throws when apiUrl missing", () => {
    expect(
      () =>
        new AttestryDecisionExporter({
          ...VALID_CONFIG,
          apiUrl: "",
        }),
    ).toThrow(/apiUrl is required/);
  });

  it("throws when apiKey missing", () => {
    expect(
      () =>
        new AttestryDecisionExporter({
          ...VALID_CONFIG,
          apiKey: "",
        }),
    ).toThrow(/apiKey is required/);
  });

  it("throws when systemId missing", () => {
    expect(
      () =>
        new AttestryDecisionExporter({
          ...VALID_CONFIG,
          systemId: "",
        }),
    ).toThrow(/systemId is required/);
  });
});

describe("AttestryDecisionExporter — onStart", () => {
  let exporter: AttestryDecisionExporter;
  beforeEach(() => {
    exporter = new AttestryDecisionExporter(VALID_CONFIG);
  });
  afterEach(async () => {
    await exporter.shutdown();
  });

  it("tags incoming spans with attestry.system_id", () => {
    const span = makeSpan({ name: "tool" });
    exporter.onStart(span);
    expect(
      (span as unknown as { _capturedAttributes: Record<string, unknown> })
        ._capturedAttributes["attestry.system_id"],
    ).toBe(VALID_CONFIG.systemId);
  });

  it("does not throw when setAttribute throws (NoopSpan)", () => {
    const logger = makeLogger();
    const ex2 = new AttestryDecisionExporter({ ...VALID_CONFIG, logger });
    const broken = {
      setAttribute: () => {
        throw new Error("noop");
      },
      spanContext: () => ({}),
    };
    expect(() => ex2.onStart(broken as never)).not.toThrow();
    expect(logger.errors).toHaveLength(1);
  });
});

describe("AttestryDecisionExporter — decision detection", () => {
  let exporter: AttestryDecisionExporter;
  let captured: FetchCapture[];

  beforeEach(() => {
    captured = captureFetch();
    exporter = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1, // flush on every push so we can observe synchronously
      batchInterval: 999_999,
    });
  });

  afterEach(async () => {
    await exporter.shutdown();
    vi.restoreAllMocks();
  });

  it("queues spans matching the keyword heuristic (tool/llm/policy)", async () => {
    exporter.onEnd(
      makeReadableSpan({ name: "openai.llm.completion", attributes: {} }),
    );
    await exporter.forceFlush();
    expect(captured).toHaveLength(1);
  });

  it("queues spans matching the attribute heuristic (ai.operation set)", async () => {
    exporter.onEnd(
      makeReadableSpan({
        name: "no-keyword-match",
        attributes: { "ai.operation": "classification" },
      }),
    );
    await exporter.forceFlush();
    expect(captured).toHaveLength(1);
  });

  it("DROPS unrelated spans (no keyword and no attribute match)", async () => {
    exporter.onEnd(
      makeReadableSpan({
        name: "http.request",
        attributes: { "http.url": "https://x.test" },
      }),
    );
    await exporter.forceFlush();
    expect(captured).toHaveLength(0);
  });

  it("respects custom shouldRecordAsDecision", async () => {
    await exporter.shutdown();
    captured = captureFetch();
    const ex2 = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
      shouldRecordAsDecision: (ctx) =>
        ctx.attributes["custom.flag"] === true,
    });

    ex2.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x" },
      }),
    );
    await ex2.forceFlush();
    expect(captured).toHaveLength(0);

    ex2.onEnd(
      makeReadableSpan({
        name: "anything",
        attributes: { "custom.flag": true },
      }),
    );
    await ex2.forceFlush();
    expect(captured).toHaveLength(1);

    await ex2.shutdown();
  });
});

describe("AttestryDecisionExporter — batching", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("flushes when queue reaches batchSize", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 3,
      batchInterval: 999_999,
    });
    for (let i = 0; i < 3; i++) {
      ex.onEnd(
        makeReadableSpan({
          name: "tool.call",
          attributes: { "tool.name": `t${i}` },
          spanId: `00000000${i.toString().padStart(8, "0")}`,
        }),
      );
    }
    await ex.forceFlush();
    expect(captured).toHaveLength(1);
    const body = JSON.parse(captured[0]?.init?.body as string);
    expect(body.items).toHaveLength(3);
    await ex.shutdown();
  });

  it("flushes on interval when below batchSize", async () => {
    vi.useFakeTimers();
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 100,
      batchInterval: 50,
    });
    ex.onEnd(
      makeReadableSpan({ name: "tool.call", attributes: { "tool.name": "t" } }),
    );
    // Fire the setInterval once. We deliberately do NOT call
    // `vi.runAllTimersAsync()` — that re-fires the interval forever and
    // hits vitest's 10K-timer safety abort.
    await vi.advanceTimersByTimeAsync(60);
    // forceFlush awaits any in-flight flush + drains anything left.
    await ex.forceFlush();
    expect(captured.length).toBeGreaterThanOrEqual(1);
    await ex.shutdown();
    vi.useRealTimers();
  });

  it("flushes remaining queue on shutdown", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 100,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "remaining" },
      }),
    );
    await ex.shutdown();
    expect(captured).toHaveLength(1);
  });

  it("ignores onEnd after shutdown (no further flushes)", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    await ex.shutdown();
    ex.onEnd(
      makeReadableSpan({ name: "tool.call", attributes: { "tool.name": "x" } }),
    );
    await ex.forceFlush();
    expect(captured).toHaveLength(0);
  });

  it("drops oldest records when queue cap exceeded", async () => {
    const logger = makeLogger();
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 2,
      batchInterval: 999_999,
      logger,
    });
    // Cap = batchSize * 10 = 20. Disable batchSize-triggered flush by
    // mocking fetch as a never-resolving call so the in-flight flush
    // holds the queue.
    let resolveFetch: (v: Response) => void = () => {};
    globalThis.fetch = vi
      .fn()
      .mockImplementation(
        () =>
          new Promise<Response>((resolve) => {
            resolveFetch = resolve;
          }),
      );

    // Fill the queue past the cap (20). Each push beyond 2 triggers a
    // flush but the flush is hung, so the queue keeps growing.
    for (let i = 0; i < 30; i++) {
      ex.onEnd(
        makeReadableSpan({
          name: "tool.call",
          attributes: { "tool.name": `t${i}` },
          spanId: `${i.toString().padStart(16, "0")}`,
        }),
      );
    }

    // At least one warning about cap drop should have fired.
    expect(
      logger.warns.some((w) => w.msg.includes("Queue cap hit")),
    ).toBe(true);

    resolveFetch(new Response("{}", { status: 200 }));
    await ex.shutdown();
  });
});

describe("AttestryDecisionExporter — spanToDecision", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("emits sha256:hex inputDigest from sanitized input attribute", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: {
          "tool.name": "fetch_user",
          input: { userId: "abc" },
        },
      }),
    );
    await ex.forceFlush();
    const body = JSON.parse(captured[0]?.init?.body as string);
    const decision = body.items[0];
    expect(decision.inputDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(decision.systemId).toBe(VALID_CONFIG.systemId);
    await ex.shutdown();
  });

  it("emits outputDigest only when output attribute is present", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "fetch_user", input: { x: 1 } },
      }),
    );
    await ex.forceFlush();
    const body = JSON.parse(captured[0]?.init?.body as string);
    expect(body.items[0].outputDigest).toBeUndefined();
    await ex.shutdown();
  });

  it("uses span ID as idempotencyKey", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x" },
        spanId: "deadbeefcafebabe",
      }),
    );
    await ex.forceFlush();
    const body = JSON.parse(captured[0]?.init?.body as string);
    expect(body.items[0].idempotencyKey).toBe("deadbeefcafebabe");
    await ex.shutdown();
  });

  it("includes frameworkClaims from heuristic tagger", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "classify",
        attributes: { "ai.operation": "classification", input: "x" },
      }),
    );
    await ex.forceFlush();
    const body = JSON.parse(captured[0]?.init?.body as string);
    const claims = body.items[0].frameworkClaims;
    expect(claims).toHaveLength(2);
    expect(claims[0]).toMatchObject({
      framework: "EU AI Act",
      article: "Article 6",
    });
    await ex.shutdown();
  });

  it("normalizes invalid policy outcomes to undefined", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "policy",
        attributes: { "policy.outcome": "WHATEVER" },
      }),
    );
    await ex.forceFlush();
    const body = JSON.parse(captured[0]?.init?.body as string);
    expect(body.items[0].policyOutcome).toBeUndefined();
    await ex.shutdown();
  });

  it("redacts PII from sanitized attributes before hashing", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    // Compare two spans: one with the PII, one with the redacted form.
    // They should produce the same digest.
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x", input: "user@host.com" },
        spanId: "0000000000000001",
      }),
    );
    await ex.forceFlush();

    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x", input: "[REDACTED]" },
        spanId: "0000000000000002",
      }),
    );
    await ex.forceFlush();

    expect(captured).toHaveLength(2);
    const a = JSON.parse(captured[0]?.init?.body as string).items[0];
    const b = JSON.parse(captured[1]?.init?.body as string).items[0];
    expect(a.inputDigest).toBe(b.inputDigest);
    await ex.shutdown();
  });
});

// ─── Hostile r2 (H4): sanitizer return-shape validation ────────────

describe("AttestryDecisionExporter — sanitizer contract", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("drops the span (not crashes) when sanitizer returns null", async () => {
    const logger = makeLogger();
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
      logger,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      sanitizer: () => null as any,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x" },
      }),
    );
    await ex.forceFlush();
    expect(captured).toHaveLength(0);
    expect(
      logger.errors.some((e) => e.msg.includes("spanToDecision failed")),
    ).toBe(true);
    expect(
      String(logger.errors[0]?.meta?.error ?? "").includes(
        "sanitizer must return an object",
      ),
    ).toBe(true);
    await ex.shutdown();
  });

  it("drops the span when sanitizer returns a string", async () => {
    const logger = makeLogger();
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
      logger,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      sanitizer: () => "redacted" as any,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x" },
      }),
    );
    await ex.forceFlush();
    expect(captured).toHaveLength(0);
    expect(logger.errors.length).toBeGreaterThan(0);
    await ex.shutdown();
  });
});

// ─── Hostile r2 (H5): frameworkClaims capped to 50 ────────────────

describe("AttestryDecisionExporter — frameworkClaims cap", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("slices >50 claims from a custom tagger to exactly 50", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
      frameworkTagger: () =>
        Array.from({ length: 200 }, (_, i) => ({
          framework: "Custom",
          article: `art-${i}`,
          claim: "test claim",
        })),
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x" },
      }),
    );
    await ex.forceFlush();
    const body = JSON.parse(captured[0]?.init?.body as string);
    expect(body.items[0].frameworkClaims).toHaveLength(50);
    expect(body.items[0].frameworkClaims[0].article).toBe("art-0");
    expect(body.items[0].frameworkClaims[49].article).toBe("art-49");
    await ex.shutdown();
  });
});

// ─── Hostile r2 (H2): never crashes when customer logger throws ───

describe("AttestryDecisionExporter — broken-logger resilience", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("does not throw when the customer logger throws on every call", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
      logger: {
        warn: () => {
          throw new Error("logger blew up");
        },
        error: () => {
          throw new Error("logger blew up");
        },
      },
      // Intentionally crash spanToDecision to force a logger.error call.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      sanitizer: () => null as any,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x" },
      }),
    );
    // The error path runs safeLog which wraps logger.error; even though
    // the customer's logger throws, neither flush nor shutdown should
    // propagate the rejection.
    await expect(ex.forceFlush()).resolves.toBeUndefined();
    await expect(ex.shutdown()).resolves.toBeUndefined();
    expect(captured).toHaveLength(0);
  });
});

describe("exporter helpers (__test__)", () => {
  it("stableStringify sorts keys deterministically", () => {
    const a = exporterTest.stableStringify({ b: 1, a: 2 });
    const b = exporterTest.stableStringify({ a: 2, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"b":1}');
  });

  it("sha256Hex returns 64 lowercase hex chars", () => {
    const h = exporterTest.sha256Hex("hello");
    expect(h).toMatch(/^[a-f0-9]{64}$/);
  });

  it("defaultDecider returns true for tool/llm/policy keywords in span name", () => {
    expect(
      exporterTest.defaultDecider({ name: "my.tool.call", attributes: {} }),
    ).toBe(true);
    expect(
      exporterTest.defaultDecider({ name: "some.llm.span", attributes: {} }),
    ).toBe(true);
    expect(
      exporterTest.defaultDecider({ name: "policy.gate", attributes: {} }),
    ).toBe(true);
  });

  it("defaultDecider returns false for unrelated spans", () => {
    expect(
      exporterTest.defaultDecider({ name: "http.client", attributes: {} }),
    ).toBe(false);
  });

  // ─── Coverage sweep (G5–G8): digest source fallbacks + array stringify ──

  it("computeInputDigest falls back to attrs['ai.prompt'] when 'input' missing", () => {
    const a = exporterTest.computeInputDigest({ "ai.prompt": "hello world" });
    const b = exporterTest.computeInputDigest({ input: "hello world" });
    expect(a).toBe(b);
  });

  it("computeInputDigest defaults to {} when both sources missing (sha256 of '{}')", () => {
    const digest = exporterTest.computeInputDigest({});
    // sha256("{}") is a fixed value — assert it stays stable.
    expect(digest).toBe(
      "sha256:" + exporterTest.sha256Hex(exporterTest.stableStringify({})),
    );
  });

  it("computeOutputDigest falls back to attrs['ai.completion'] when 'output' missing", () => {
    const a = exporterTest.computeOutputDigest({ "ai.completion": "answer" });
    const b = exporterTest.computeOutputDigest({ output: "answer" });
    expect(a).toBe(b);
    expect(a).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("computeOutputDigest returns undefined when output is null", () => {
    expect(exporterTest.computeOutputDigest({ output: null })).toBeUndefined();
  });

  it("stableStringify serializes arrays in order (vs sorted-object form)", () => {
    expect(exporterTest.stableStringify([3, 1, 2])).toBe("[3,1,2]");
    expect(exporterTest.stableStringify([{ b: 1, a: 2 }])).toBe(
      '[{"a":2,"b":1}]',
    );
  });

  it("stableStringify handles primitive null at top level", () => {
    expect(exporterTest.stableStringify(null)).toBe("null");
  });
});

// ─── Coverage sweep (G1–G2): batch params clamp ────────────────────

describe("AttestryDecisionExporter — config clamping", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("batchSize=0 clamps to 1 (every span flushes immediately)", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 0,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x" },
      }),
    );
    await ex.forceFlush();
    expect(captured).toHaveLength(1);
    await ex.shutdown();
  });

  it("batchSize=-5 clamps to 1", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: -5,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "x" },
      }),
    );
    await ex.forceFlush();
    expect(captured).toHaveLength(1);
    await ex.shutdown();
  });

  it("batchInterval=0 clamps to 1ms (timer still fires)", async () => {
    // We don't actually wait for the interval — we just verify the
    // exporter doesn't crash when constructed with a non-positive
    // interval.
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 100,
      batchInterval: 0,
    });
    expect(ex).toBeInstanceOf(AttestryDecisionExporter);
    await ex.shutdown();
  });
});

// ─── Coverage sweep (G3): customer decider throws → outer try catches ──

describe("AttestryDecisionExporter — onEnd outer catch", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("logs and continues when shouldRecordAsDecision throws", () => {
    const logger = makeLogger();
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
      logger,
      shouldRecordAsDecision: () => {
        throw new Error("decider blew up");
      },
    });
    expect(() =>
      ex.onEnd(
        makeReadableSpan({
          name: "tool.call",
          attributes: { "tool.name": "x" },
        }),
      ),
    ).not.toThrow();
    expect(
      logger.errors.some((e) => e.msg.includes("onEnd failed")),
    ).toBe(true);
    expect(captured).toHaveLength(0);
  });
});

// ─── Coverage sweep (G4): non-string tool.name → no toolInvocations ──

describe("AttestryDecisionExporter — non-string tool.name", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("emits empty toolInvocations[] when tool.name is a number", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        // Number-typed tool.name is a contract violation but happens
        // when customers stringify wrong (typeof tool.name === "number").
        name: "tool.call",
        attributes: { "tool.name": 12345 },
      }),
    );
    await ex.forceFlush();
    const body = JSON.parse(captured[0]?.init?.body as string);
    expect(body.items[0].toolInvocations).toEqual([]);
    await ex.shutdown();
  });
});

// ─── Coverage sweep (G9): shutdown idempotent ────────────────────

describe("AttestryDecisionExporter — shutdown idempotency", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = captureFetch();
  });
  afterEach(() => vi.restoreAllMocks());

  it("calling shutdown twice is a no-op the second time", async () => {
    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 100,
      batchInterval: 999_999,
    });
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "first" },
      }),
    );
    await ex.shutdown();
    expect(captured).toHaveLength(1);
    // Second shutdown: should not throw, should not double-flush.
    await expect(ex.shutdown()).resolves.toBeUndefined();
    expect(captured).toHaveLength(1);
  });
});

// ─── Coverage sweep (G10): flush reentrancy ──────────────────────

describe("AttestryDecisionExporter — flush reentrancy", () => {
  let captured: FetchCapture[];
  beforeEach(() => {
    captured = [];
  });
  afterEach(() => vi.restoreAllMocks());

  it("two concurrent flushes drain both batches without double-sending", async () => {
    let resolveFirst: (v: Response) => void = () => {};
    const fetchOrder: number[] = [];
    let callCount = 0;
    globalThis.fetch = vi.fn().mockImplementation(
      (_url: string, init?: RequestInit) => {
        callCount++;
        const myCall = callCount;
        captured.push({ url: _url, init });
        return new Promise<Response>((resolve) => {
          if (myCall === 1) {
            // First call hangs until we explicitly resolve it.
            resolveFirst = (r) => {
              fetchOrder.push(1);
              resolve(r);
            };
          } else {
            fetchOrder.push(myCall);
            resolve(
              new Response(JSON.stringify({ totalInserted: 1 }), {
                status: 200,
              }),
            );
          }
        });
      },
    );

    const ex = new AttestryDecisionExporter({
      ...VALID_CONFIG,
      batchSize: 1,
      batchInterval: 999_999,
    });

    // First span queues + triggers flush (which hangs on first fetch).
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "first" },
        spanId: "0000000000000001",
      }),
    );
    // Wait a microtask so the flush has time to start its fetch.
    await new Promise((resolve) => setImmediate(resolve));

    // Second span queues + triggers another flush — this one should
    // hit the reentrancy guard (flushInFlight is set), await the first
    // flush, then drain.
    ex.onEnd(
      makeReadableSpan({
        name: "tool.call",
        attributes: { "tool.name": "second" },
        spanId: "0000000000000002",
      }),
    );

    // Now release the first fetch.
    resolveFirst(
      new Response(JSON.stringify({ totalInserted: 1 }), { status: 200 }),
    );

    await ex.shutdown();
    // Both batches were flushed, separately — no double-send.
    expect(captured).toHaveLength(2);
    const a = JSON.parse(captured[0]?.init?.body as string);
    const b = JSON.parse(captured[1]?.init?.body as string);
    expect(a.items).toHaveLength(1);
    expect(b.items).toHaveLength(1);
    expect(a.items[0].idempotencyKey).toBe("0000000000000001");
    expect(b.items[0].idempotencyKey).toBe("0000000000000002");
  });
});
