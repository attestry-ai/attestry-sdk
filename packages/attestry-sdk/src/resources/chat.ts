// ─── Chat resource ──────────────────────────────────────────────────────────
//
// Wraps `POST /api/ai/chat` (Reggie) — the org's compliance copilot.
// Despite earlier handoff text suggesting an SSE / async-iterator
// design, the actual kernel route is a *synchronous* JSON endpoint:
// caller POSTs messages + optional context, server runs `chatWithReggie`
// and returns one final assistant message via `successResponse({...})`.
// No streaming, no chunking. The build doc covers this deviation.
//
// Server-side context injection (Prompt B.4): Reggie's system prompt
// is enriched server-side with crosswalk-row matches and the top
// unresolved gap. The SDK does NOT mirror that — those fields are
// computed from the auth context and the supplied `messages`, not the
// caller-supplied context. SDK callers send their own UI / page
// context; the server appends to it.

import type { AttestryClient } from "../client.js";
import type { RequestOptions } from "../types.js";

/**
 * Public chat-message roles. Mirrors the kernel route's `z.enum(['user',
 * 'assistant'])` at `src/app/api/ai/chat/route.ts`. `system` is reserved
 * for the server-side prompt and is not a valid client role. Extracted
 * as `as const` so consumers can iterate (`for (const r of
 * CHAT_MESSAGE_ROLES)`) and so a future drift-detection pin can compare
 * structurally against the kernel source.
 */
export const CHAT_MESSAGE_ROLES = Object.freeze(["user", "assistant"] as const);

export type ChatMessageRole = (typeof CHAT_MESSAGE_ROLES)[number];

export interface ChatMessage {
  /** `system` role is reserved for the server; clients send 'user' / 'assistant'. */
  role: ChatMessageRole;
  /** 1-4000 chars; server-side Zod hard-rejects out-of-range. */
  content: string;
}

export interface ChatContextGap {
  requirementKey: string;
  priority: string;
  description?: string;
}

/**
 * Optional UI-side context that callers can attach to seed Reggie's
 * answer. Mirrors the kernel's `chatSchema.context` exactly. Every
 * field is optional — server validates each independently. Callers
 * with no useful context just pass `undefined`.
 *
 * The server REJECTS unknown context fields per the route's Zod
 * `.optional()` boundary; do not embed forward-compatible "extra"
 * keys. Coordinate with the kernel team and bump the SDK on schema
 * additions.
 */
export interface ChatContext {
  // ─── System-specific context ──────────────────────────────────────────────
  systemName?: string;
  systemDescription?: string;
  deploymentGeography?: string[];
  riskLevel?: string;
  frameworks?: string[];
  assessmentScores?: Record<string, number>;
  gaps?: ChatContextGap[];
  jurisdictions?: string[];

  // ─── Live user / org context (typically injected by the UI on panel open) ─
  orgName?: string;
  /** Non-negative integer; server enforces `int().nonnegative()`. */
  systemCount?: number;
  systemNames?: string[];
  /** 0-100 score; server enforces `min(0).max(100)`. */
  overallComplianceScore?: number;
  /** Non-negative integer. */
  activeAttestationCount?: number;
  /** Non-negative integer. */
  pendingRemediationTasks?: number;
  /** Non-negative integer. */
  recentRegChangesCount?: number;

  // ─── Page-aware context ───────────────────────────────────────────────────
  /** Up to 200 chars. */
  currentPage?: string;
}

export interface ChatSendInput {
  /** 1-50 entries; each content 1-4000 chars. Server rejects out-of-range. */
  messages: ChatMessage[];
  context?: ChatContext;
}

export interface ChatSendResponse {
  /** The final assistant message text. */
  message: string;
  /** Always `"Reggie"` today; surfaced in case a future agent is added. */
  agent: string;
}

/**
 * One chunk emitted by `chat.stream`'s async iterator.
 *
 * Iterator contract:
 *   - Zero or more `{type: 'text', delta}` chunks (today: exactly one,
 *     since the kernel route is sync; tomorrow: many, when SSE lands).
 *   - Followed by EXACTLY ONE terminator: either `{type: 'done'}` on
 *     success or `{type: 'error', message}` on any failure.
 *   - After the terminator, the iterator ends (`next()` returns
 *     `{value: undefined, done: true}`).
 *
 * Errors are surfaced as `error` chunks rather than thrown so consumers
 * have a uniform `for await` handling pattern — no per-iteration
 * try/catch required. The original error-classification info lives in
 * the message text plus, when relevant, the structured `AttestryAPIError`
 * available via the equivalent `chat.send` method.
 */
export type ChatStreamChunk =
  | { type: "text"; delta: string }
  | { type: "done" }
  | { type: "error"; message: string };

/**
 * Internal — async generator backing `chat.stream`. Today calls the
 * sync POST endpoint, buffers the single response, and emits one
 * `text` chunk + `done`. Forward-compatible: when the kernel migrates
 * `/api/ai/chat` to SSE (or a sibling streaming endpoint lands), swap
 * the body for a `Response.body!.getReader()` + `TextDecoder` SSE
 * parser per the F.1 handoff's option (a). The public `stream` API
 * contract — chunks, ordering, terminators, abort semantics — stays.
 *
 * Lazy: the request is NOT issued until the first iteration. Tested.
 */
async function* runChatStream(
  client: AttestryClient,
  input: ChatSendInput,
  options?: RequestOptions,
): AsyncGenerator<ChatStreamChunk, void, unknown> {
  try {
    const response = await client._request<ChatSendResponse>({
      method: "POST",
      path: "/api/ai/chat",
      body: input,
      options,
    });
    if (
      response &&
      typeof response.message === "string" &&
      response.message.length > 0
    ) {
      yield { type: "text", delta: response.message };
    }
    yield { type: "done" };
  } catch (err) {
    yield {
      type: "error",
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

export class ChatResource {
  constructor(private readonly client: AttestryClient) {}

  /**
   * Send messages to Reggie and receive a single response.
   *
   * Errors surface as `AttestryAPIError` with statuses:
   *   - 400 — schema rejection (e.g., too many messages, content too long)
   *   - 401 — auth missing / invalid (transport surfaces as AuthError on the
   *           kernel side; SDK consumers see AttestryAPIError 401)
   *   - 403 — plan limit (`details` carries `{upgradeRequired, feature,
   *           currentPlan}`; `feature` is the wire-stable `hasAttestor`
   *           rather than internal `hasReggie` per the B.1 rebrand pin)
   *   - 429 — rate limit (assessmentLimiter, 20/min/IP)
   *   - 503 — AI not configured server-side
   */
  send(
    input: ChatSendInput,
    options?: RequestOptions,
  ): Promise<ChatSendResponse> {
    return this.client._request<ChatSendResponse>({
      method: "POST",
      path: "/api/ai/chat",
      body: input,
      options,
    });
  }

  /**
   * Stream Reggie's response as an async iterable of `ChatStreamChunk`.
   *
   * Iterator yields zero-or-more `{type:'text', delta}` chunks, then
   * exactly one terminator: `{type:'done'}` on success OR
   * `{type:'error', message}` on any failure. After the terminator the
   * iterator ends.
   *
   * Today: backed by the sync POST endpoint (same as `send`). Yields
   * one `text` chunk + `done` on success. When `/api/ai/chat` migrates
   * to SSE — or when a sibling streaming endpoint lands — the underlying
   * implementation swaps to an SSE parser without changing this method's
   * public contract.
   *
   * Lazy: the request is NOT issued until the first iteration. Pass
   * `options.signal` for cancellation — pre-aborted causes the first
   * iteration to yield `error` and end with no fetch issued; mid-flight
   * abort fires the underlying `AbortController` and surfaces as an
   * `error` chunk.
   *
   * Errors NEVER throw from the iterator — they surface as `error`
   * chunks. Consumer code can use a single `for await` loop without
   * per-iteration try/catch.
   *
   * @example
   * ```ts
   * const stream = client.chat.stream({
   *   messages: [{ role: 'user', content: 'What changed in NIST AI RMF v2?' }],
   * });
   * let buffer = '';
   * for await (const chunk of stream) {
   *   if (chunk.type === 'text')  buffer += chunk.delta;
   *   if (chunk.type === 'error') console.error('chat failed:', chunk.message);
   * }
   * ```
   */
  stream(
    input: ChatSendInput,
    options?: RequestOptions,
  ): AsyncIterable<ChatStreamChunk> {
    return runChatStream(this.client, input, options);
  }
}
