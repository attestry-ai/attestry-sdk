import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError } from "../../errors.js";
import type { ChatStreamChunk } from "../chat.js";
import type { FetchLike } from "../../types.js";

interface MockedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string;
}

function makeMockedClient(
  responses: Array<{ status?: number; body?: unknown; bodyText?: string }>,
) {
  const calls: MockedRequest[] = [];
  let i = 0;
  const mockFetch: FetchLike = async (url, init) => {
    calls.push({
      url: String(url),
      method: (init?.method as string) ?? "GET",
      headers: init?.headers as Headers,
      body: init?.body as string | undefined,
    });
    const r = responses[i++] ?? {};
    const status = r.status ?? 200;
    const body =
      r.bodyText !== undefined ? r.bodyText : JSON.stringify(r.body ?? {});
    return new Response(body, {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
  const client = new AttestryClient({
    apiKey: "k",
    fetch: vi.fn(mockFetch) as unknown as FetchLike,
    baseUrl: "https://test.attestry.local",
    // Retry tests live in src/__tests__/retry.test.ts. Resource tests
    // disable retry so a 429-mock test doesn't hang on backoff and then
    // accidentally consume the next mock response.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

describe("chat.send", () => {
  it("POSTs /api/ai/chat with the messages body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { message: "hi from Reggie", agent: "Reggie" } } },
    ]);
    const out = await client.chat.send({
      messages: [{ role: "user", content: "What does EU AI Act Article 9 say?" }],
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe("https://test.attestry.local/api/ai/chat");
    expect(JSON.parse(calls[0].body!)).toEqual({
      messages: [{ role: "user", content: "What does EU AI Act Article 9 say?" }],
    });
    expect(out).toEqual({ message: "hi from Reggie", agent: "Reggie" });
  });

  it("includes optional context when provided (forwards every documented field)", async () => {
    // Round-trips a saturated context object so a future refactor that
    // accidentally drops or renames a field is caught at pin time.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { message: "ack", agent: "Reggie" } } },
    ]);
    const fullContext = {
      systemName: "atlas-credit-scorer",
      systemDescription: "Consumer credit scoring",
      deploymentGeography: ["US-CA", "EU-DE"],
      riskLevel: "high",
      frameworks: ["eu-ai-act", "colorado-ai-act"],
      assessmentScores: { transparency: 78, fairness: 64 },
      gaps: [
        {
          requirementKey: "eu-ai-act:Art.13",
          priority: "P1",
          description: "Missing disclosure boilerplate",
        },
      ],
      jurisdictions: ["DE", "FR"],
      orgName: "Acme",
      systemCount: 2,
      systemNames: ["atlas-credit-scorer", "atlas-fraud-detector"],
      overallComplianceScore: 72,
      activeAttestationCount: 1,
      pendingRemediationTasks: 4,
      recentRegChangesCount: 3,
      currentPage: "/dashboard",
    };
    await client.chat.send({
      messages: [{ role: "user", content: "give me a status" }],
      context: fullContext,
    });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.context).toEqual(fullContext);
  });

  it("forwards x-api-key + Accept + Content-Type headers", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { message: "ok", agent: "Reggie" } } },
    ]);
    await client.chat.send({
      messages: [{ role: "user", content: "hi" }],
    });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
    // Content-Type is set on POSTs with a body — distinct from GET decisions.
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
  });

  it("preserves multi-turn message ordering on the wire", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { message: "ack", agent: "Reggie" } } },
    ]);
    await client.chat.send({
      messages: [
        { role: "user", content: "first" },
        { role: "assistant", content: "ack" },
        { role: "user", content: "follow-up" },
      ],
    });
    const sent = JSON.parse(calls[0].body!);
    expect(sent.messages.map((m: { role: string }) => m.role)).toEqual([
      "user",
      "assistant",
      "user",
    ]);
    expect(sent.messages[2].content).toBe("follow-up");
  });

  it("surfaces a 429 rate-limit response as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: {
          success: false,
          error: "Too many requests. Please try again later.",
        },
      },
    ]);
    try {
      await client.chat.send({
        messages: [{ role: "user", content: "hi" }],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(429);
      expect(apiErr.message).toContain("Too many requests");
    }
  });

  it("surfaces a 503 (Reggie not configured) as AttestryAPIError", async () => {
    const { client } = makeMockedClient([
      {
        status: 503,
        body: {
          success: false,
          error: "Reggie is not available. AI features require configuration.",
        },
      },
    ]);
    try {
      await client.chat.send({
        messages: [{ role: "user", content: "hi" }],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(503);
    }
  });

  it("preserves the wire-stable `hasAttestor` plan-limit details on a 403 (B.1 rebrand pin)", async () => {
    // Server-side B.1 hostile-review fix maps internal `hasReggie` flag
    // back to the public-wire `hasAttestor` for backwards compatibility.
    // The SDK must not strip or mutate `details` — pinning that
    // AttestryAPIError.details carries the exact server payload through.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: {
          success: false,
          error:
            'Reggie requires Builder plan (current: free). Upgrade for the "hasAttestor" feature.',
          details: {
            upgradeRequired: true,
            feature: "hasAttestor",
            currentPlan: "free",
          },
        },
      },
    ]);
    try {
      await client.chat.send({
        messages: [{ role: "user", content: "hi" }],
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(403);
      // The full body (success+error+details) is preserved as the parsed details.
      expect(apiErr.details).toMatchObject({
        details: {
          upgradeRequired: true,
          feature: "hasAttestor",
          currentPlan: "free",
        },
      });
    }
  });

  it("forwards the caller's AbortSignal through RequestOptions", async () => {
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.chat.send(
        { messages: [{ role: "user", content: "hi" }] },
        { signal: controller.signal },
      ),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("accepts a non-aborted AbortSignal and the request completes normally (coverage)", async () => {
    // Symmetric to the decisions coverage pin: closes the resource-level
    // happy path where `options.signal` is a live signal that the
    // transport attaches to and cleanly removes in `finally`.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { message: "ok", agent: "Reggie" } } },
    ]);
    const controller = new AbortController();
    const out = await client.chat.send(
      { messages: [{ role: "user", content: "ping" }] },
      { signal: controller.signal },
    );
    expect(out).toEqual({ message: "ok", agent: "Reggie" });
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("does not pre-validate input — passes empty messages array through to server (server rejects)", async () => {
    // The server's Zod schema rejects empty messages arrays with 400.
    // The SDK is intentionally NOT a re-implementation of server-side
    // validation; it forwards faithfully. Pinning so a future "be
    // helpful" refactor doesn't quietly add a client-side guard that
    // diverges from the server's actual contract.
    const { client, calls } = makeMockedClient([
      {
        status: 400,
        body: { success: false, error: "Validation failed." },
      },
    ]);
    try {
      await client.chat.send({ messages: [] });
    } catch {
      /* ignore — we want to verify the request was issued, not the result */
    }
    expect(calls).toHaveLength(1);
    expect(JSON.parse(calls[0].body!)).toEqual({ messages: [] });
  });
});

// ─── chat.stream — async-iterator API ──────────────────────────────────────
//
// The streaming-shaped API mandated by the F.1 handoff Action 3
// (KERNEL_AGENT_HANDOFF_2026-05-05.md lines 152-181). Today the kernel
// route is synchronous; the iterator yields one `text` chunk + `done` on
// success. Forward-compatible to true SSE: when the kernel adds streaming
// the iterator's body parses SSE chunks instead of buffering one POST
// response. Public contract — chunk shapes, ordering, terminators, abort
// semantics — stays.

describe("chat.stream", () => {
  it("yields one text chunk + done on a successful response", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { message: "Reggie says hello", agent: "Reggie" } } },
    ]);
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of client.chat.stream({
      messages: [{ role: "user", content: "ping" }],
    })) {
      chunks.push(chunk);
    }
    expect(chunks).toEqual([
      { type: "text", delta: "Reggie says hello" },
      { type: "done" },
    ]);
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe("https://test.attestry.local/api/ai/chat");
  });

  it("yields error chunk on a 4xx response and terminates iterator", async () => {
    const { client } = makeMockedClient([
      { status: 400, body: { success: false, error: "Validation failed." } },
    ]);
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of client.chat.stream({
      messages: [{ role: "user", content: "ping" }],
    })) {
      chunks.push(chunk);
    }
    expect(chunks).toHaveLength(1);
    expect(chunks[0].type).toBe("error");
    if (chunks[0].type === "error") {
      expect(chunks[0].message).toBe("Validation failed.");
    }
  });

  it("yields error chunk on a 5xx response and terminates iterator", async () => {
    const { client } = makeMockedClient([
      {
        status: 503,
        body: { success: false, error: "Reggie is not available." },
      },
    ]);
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of client.chat.stream({
      messages: [{ role: "user", content: "ping" }],
    })) {
      chunks.push(chunk);
    }
    expect(chunks).toEqual([
      { type: "error", message: "Reggie is not available." },
    ]);
  });

  it("yields error chunk on pre-aborted signal — does NOT issue a request", async () => {
    // The transport rejects synchronously on a pre-aborted signal; the
    // generator's catch block surfaces that as an `error` chunk and
    // ends the iterator. Pin: no fetch call, exactly one error chunk.
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of client.chat.stream(
      { messages: [{ role: "user", content: "ping" }] },
      { signal: controller.signal },
    )) {
      chunks.push(chunk);
    }
    expect(chunks).toHaveLength(1);
    expect(chunks[0].type).toBe("error");
    if (chunks[0].type === "error") {
      // The transport's pre-abort guard rejects with the message
      // "request aborted by caller" — pin that the iterator surfaces
      // it (not a generic timeout / network message).
      expect(chunks[0].message).toContain("aborted by caller");
    }
    expect(calls).toHaveLength(0);
  });

  it("yields error chunk on network failure (ECONNREFUSED, DNS fail, etc.)", async () => {
    let calls = 0;
    const failingClient = new AttestryClient({
      apiKey: "k",
      baseUrl: "https://test.attestry.local",
      fetch: vi.fn(async () => {
        calls++;
        throw new Error("ECONNREFUSED");
      }) as unknown as FetchLike,
    });
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of failingClient.chat.stream({
      messages: [{ role: "user", content: "ping" }],
    })) {
      chunks.push(chunk);
    }
    expect(chunks).toHaveLength(1);
    expect(chunks[0].type).toBe("error");
    if (chunks[0].type === "error") {
      // The transport wraps the network error as
      // `network error: <message>`; pin that the message survives.
      expect(chunks[0].message).toContain("ECONNREFUSED");
    }
    expect(calls).toBe(1);
  });

  it("does NOT issue the request until first iteration (lazy)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { message: "ok", agent: "Reggie" } } },
    ]);
    const stream = client.chat.stream({
      messages: [{ role: "user", content: "ping" }],
    });
    // Constructed but not iterated yet — no request.
    expect(calls).toHaveLength(0);
    // First iteration → request fires.
    const iterator = stream[Symbol.asyncIterator]();
    await iterator.next();
    expect(calls).toHaveLength(1);
  });

  it("iterator ends after the terminator chunk (next() returns done: true)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: { message: "ok", agent: "Reggie" } } },
    ]);
    const iterator = client.chat
      .stream({ messages: [{ role: "user", content: "ping" }] })
      [Symbol.asyncIterator]();
    const r1 = await iterator.next();
    expect(r1.done).toBe(false);
    expect((r1.value as ChatStreamChunk).type).toBe("text");
    const r2 = await iterator.next();
    expect(r2.done).toBe(false);
    expect((r2.value as ChatStreamChunk).type).toBe("done");
    const r3 = await iterator.next();
    expect(r3.done).toBe(true);
    // Subsequent calls remain done — generator is exhausted.
    const r4 = await iterator.next();
    expect(r4.done).toBe(true);
  });

  it("forwards optional context unchanged through the stream wrapper", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: { message: "ok", agent: "Reggie" } } },
    ]);
    const ctx = { systemName: "atlas", currentPage: "/dashboard" };
    for await (const _chunk of client.chat.stream({
      messages: [{ role: "user", content: "hi" }],
      context: ctx,
    })) {
      /* drain */
      void _chunk;
    }
    const sent = JSON.parse(calls[0].body!);
    expect(sent.context).toEqual(ctx);
    expect(sent.messages).toEqual([{ role: "user", content: "hi" }]);
  });

  it("omits empty assistant message text — yields only done on empty success body", async () => {
    // Defensive: server returning {message: "", agent: "Reggie"} should
    // skip the empty `text` chunk and go straight to `done`. Otherwise
    // a consumer treating "first text chunk arrived" as a heartbeat
    // would get confused by an empty delta.
    const { client } = makeMockedClient([
      { body: { success: true, data: { message: "", agent: "Reggie" } } },
    ]);
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of client.chat.stream({
      messages: [{ role: "user", content: "hi" }],
    })) {
      chunks.push(chunk);
    }
    expect(chunks).toEqual([{ type: "done" }]);
  });

  it("yields only done when the response message field is missing or non-string (defensive — coverage)", async () => {
    // Closes the branch where `typeof response.message === "string"` is
    // false (vs the empty-string case where length === 0). Today the
    // kernel route always returns {message: <string>, agent: <string>};
    // this pin defends against a future server bug that returns
    // {agent: "Reggie"} (no message field) — the iterator yields just
    // `done` rather than `{type:'text', delta: undefined}`.
    const { client } = makeMockedClient([
      { body: { success: true, data: { agent: "Reggie" } } },
    ]);
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of client.chat.stream({
      messages: [{ role: "user", content: "hi" }],
    })) {
      chunks.push(chunk);
    }
    expect(chunks).toEqual([{ type: "done" }]);
  });

  it("yields only done when the response body is empty (transport returns null — coverage)", async () => {
    // Closes the branch where `response` itself is falsy. Transport
    // returns `null as T` for 200-with-empty-body (and 204 — but
    // `new Response("", {status: 204})` throws per spec, so we exercise
    // the null path via 200 + empty body, which `readBody` short-circuits
    // identically). The iterator's outer `if (response && ...)`
    // short-circuits to false; no text yield, just `done`. Defensive —
    // current kernel route always emits a body, but a misconfigured
    // proxy could strip it.
    const { client } = makeMockedClient([
      { status: 200, bodyText: "" },
    ]);
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of client.chat.stream({
      messages: [{ role: "user", content: "hi" }],
    })) {
      chunks.push(chunk);
    }
    expect(chunks).toEqual([{ type: "done" }]);
  });

  it("yields error chunk with String-coerced message on non-Error throw (defensive — coverage)", async () => {
    // Defensive branch in runChatStream's catch: `err instanceof Error
    // ? err.message : String(err)`. The transport ALWAYS wraps fetch /
    // abort failures as AttestryError or AttestryAPIError (both Error
    // subclasses), so the `String(err)` branch is unreachable under
    // realistic conditions. This pin exercises it via a spy on
    // `client._request` that rejects with a non-Error value —
    // simulates a transport-internal bug where some code does
    // `throw "string"` instead of throwing an Error subclass. Closes
    // the only previously-uncovered branch in the SDK
    // (`chat.ts:155`'s `String(err)` falsy-ternary branch).
    //
    // The cast to `never` bypasses the type system; rejecting with a
    // non-Error is type-incorrect but exists only to exercise the
    // defensive coverage path. Spy is auto-restored when the local
    // `client` instance is GC'd at end of test (instance-only override
    // via vi.spyOn).
    const { client } = makeMockedClient([]);
    vi.spyOn(client, "_request").mockRejectedValue(
      "transport internal: not an Error instance" as never,
    );
    const chunks: ChatStreamChunk[] = [];
    for await (const chunk of client.chat.stream({
      messages: [{ role: "user", content: "ping" }],
    })) {
      chunks.push(chunk);
    }
    expect(chunks).toHaveLength(1);
    expect(chunks[0].type).toBe("error");
    if (chunks[0].type === "error") {
      // String("transport internal: not an Error instance") = verbatim.
      // Confirms the falsy-ternary branch fires and produces a
      // useful (non-"undefined", non-"[object Object]") message
      // when err is a string.
      expect(chunks[0].message).toBe(
        "transport internal: not an Error instance",
      );
    }
  });
});
