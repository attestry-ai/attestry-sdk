# @attestry/sdk

Official TypeScript SDK for the [Attestry](https://attestry.ai) compliance kernel. Submit AI incidents, fetch decision records, subscribe to live decision streams, and chat with the Reggie compliance copilot from server-side TypeScript / JavaScript code.

> **Status — v0.5.7 (preview).** Eleven resources shipped: `incidents` (create / list / update / search), `decisions` (ingest / bulk / retrieve / list / SSE stream / NDJSON export / chain verify — **decisions surface complete**, 7 methods), `chat` (send + iterator), `auditLog` (export — multi-format SIEM streaming with auto-pagination; verifyChain — org-wide audit-log hash-chain integrity verdict; 2 methods today), `regulatoryChanges` (list — read-only feed of regulatory updates filtered by framework / severity / status / date-range), `complianceCheck` (check — per-system or per-org compliance summary with active-attestations + framework coverage), `check` (run — flat per-system CI/CD compliance check with framework filter, first SDK route to pre-validate every Zod closed-spec rule synchronously), `gate` (evaluate — pass/fail CI/CD deployment gate with structured gap output + score-threshold + missing-assessment policy), `batch` (submit + get — bulk classification/assessment for up to 50 systems with per-row partial-success envelope; **first SDK resource with asymmetric auth between methods**, **first SDK route with a plan-guard 403 surface distinct from the permission-403**), `shipGate` (check — CI/CD ship-gate verdict on whether a build is gated by an in-flight approval-chain execution; 4-shape variadic response with snake_case `approvers_pending` wire field), `abacPolicies` (list / create / retrieve / update / delete — attribute-based access-control (ABAC) policy management; the SDK's FIRST 5-method CRUD cluster, and the FIRST SDK method on the HTTP `DELETE` verb). API is stable inside its surface; new resources are additive. Automatic retry on 429 is on by default.
>
> **0.5.7 — `abacPolicies` CRUD cluster completed** (additive, no breaking changes). The `abacPolicies` resource — attribute-based access-control policy management — reaches its full 5-method surface: `list` / `create` (shipped 0.5.6) plus `retrieve` / `update` / `delete` (this release). **The SDK's FIRST 5-method CRUD cluster** — prior multi-method resources either grew an existing class over many sessions (`decisions` reached 7) or shipped a smaller surface. **FIRST SDK method on the HTTP `DELETE` verb** (`abacPolicies.delete`) and **SECOND on the HTTP `PATCH` verb** (`abacPolicies.update`; `incidents.update` is the first). **The three id-path methods** (`retrieve` / `update` / `delete`) pre-validate `id` against a strict RFC 4122 UUID regex and interpolate it into the request path RAW — mirror of `batch.get`, with **NO `encodeURIComponent` and NO `URIError` defense**: a string matching the UUID regex is ASCII hex + hyphens, URL-safe verbatim and incapable of forming a lone surrogate, so a malformed `id` is pre-rejected synchronously (`TypeError`) before any URL is built (asymmetric with `decisions.retrieve`, whose free-form id needs `encodePathSegment`). **`abacPolicies.update` is the richest method of the cluster** — a **6-arm `instanceof` catch block (the LARGEST on the SDK)**, the three-way 422 fan-out inherited from `.create` (`BodyParseError` → `Array<{path, message}>` / a defensive DEAD `ZodError` arm → `ZodIssue[]` / `AbacPolicyValidationError` → `{errors: string[]}`) PLUS HTTP 409 (name conflict) PLUS HTTP 404 (`AbacPolicyNotFoundError`, an id-embedded message). **Empty-patch pre-validation** — `.update` is a partial update with every field optional; the SDK pre-rejects an empty patch (`update(id, {})`, an all-`undefined` patch, or a patch carrying only unknown keys) synchronously with a `TypeError`, mirroring the kernel `updateAbacPolicySchema`'s `.refine()`. `.delete` returns the **deleted row** (the policy as it existed immediately before deletion — NOT `void` / NOT a `{deleted:true}` envelope); `.update` returns the **updated row** (the `after` state). All 5 methods are **dual-auth admin scope** — HTTP 401 for no/invalid/expired key, HTTP 403 for a valid key lacking `ADMIN` (both branches distinct — pin separately). `.create` / `.update` / `.delete` each write one `abac_policy.*` audit-log entry; `.list` / `.retrieve` are quiet reads. Symmetric prototype-pollution defense on input AND response sides (`Object.hasOwn` module-load snapshot).
>
> **0.5.6 — `shipGate` resource added** (additive, no breaking changes). Single-method resource wrapping `POST /api/v1/ship-gate/check` — multi-approver workflow gate that asks "is an in-flight approval chain blocking THIS build?". **Distinct from `gate.evaluate`** — that method is a synchronous compliance-score gate (pass/fail on assessment scores); `shipGate.check` has the `gated → released/rejected/timed_out` state machine bound to an approval-chain execution. **Variadic 4-shape response** with `gated: boolean` as ALWAYS-PRESENT anchor and 5 OPTIONAL own-property fields (`reason`, `approvers_pending`, `state`, `executionId`, `chainId`): Shape A `{gated: false}` 1-field (no gate exists — default-permissive opt-in); Shape B 4-field (released); Shape C 6-field (rejected/timed_out with empty `approvers_pending`); Shape D 6-field (gated awaiting approvers, populated `approvers_pending`). Discriminate via `result.gated === true` (closed-enum boolean, pollution-safe anchor), NOT `reason === undefined`. **First SDK wire field with SNAKE_CASE naming** — `approvers_pending` (asymmetric with the rest of the SDK's camelCase response surface; master plan spec contract line 5369). **Fourth SDK route to pre-validate every Zod closed-spec rule synchronously** (after `check.run`, `gate.evaluate`, and `batch.submit`) — UUID format on `systemId` + length 1-256 on `attestationId` (matches kernel `MAX_ATTESTATION_ID_LENGTH = 256`). **Multi-permission UNION auth** with **READ_SYSTEMS FIRST** (asymmetric with `check.run` and `gate.evaluate` which list `READ_ASSESSMENTS` first). **TWO distinct cascade-gap surfaces**: execution-missing → HTTP 404 (named `ShipGateExecutionNotFoundError`); chain-missing → HTTP 500 (plain `Error`, scrubbed by `internalErrorResponse`). `writeAuditLog` side effect — every call writes one `ship_gate.checked` entry. Kernel-side 15s `maxDuration` (same as `gate.evaluate`; tighter than `auditLog.verifyChain`'s 30s). Symmetric prototype-pollution defense on input AND response sides (`Object.hasOwn` snapshot).
>
> **0.5.5 — `auditLog.verifyChain` added** (additive, no breaking changes). Sibling method to `auditLog.export` on the same resource class — wraps `GET /api/v1/audit-chain/verify` for org-wide audit-log hash-chain integrity verification. **Distinct from `decisions.verifyChain` (per-system)** — this verifier operates on the entire org's audit log; different responsibility, different kernel route, different consumer audience (compliance auditors). **CRITICAL contract** (carry-forward invariant #12): does NOT throw on `valid: false` — the kernel returns 200 with `valid: false` on tampered chains; the SDK resolves the Promise with the verdict body. **First SDK route using `requireApiKey` DIRECT (no permission scoping)** — any valid api-key in the org succeeds; no 403 path. **Asymmetric with `auditLog.export`** (which gates on ADMIN role). **`brokenAt` is OPTIONAL** — the kernel uses a conditional spread, so the field is an OWN-PROPERTY only on broken chains; consumers detect broken-chain via `result.valid === false` (closed-enum boolean discriminator), NOT `result.brokenAt === undefined` (prototype-pollution-unsafe). **Silent kernel-side truncation at 5000 entries** — orgs with >5000 audit log entries see only the OLDEST 5000 verified per call (documented kernel surface gap). NO `writeAuditLog` side effect (the verifier is quiet — writing while verifying would be ironic). NO input → no `TypeError` from SDK boundary; the method takes only `options?: RequestOptions`. Symmetric prototype-pollution defense on the response side (input boundary is empty).
>
> **0.5.4 — `batch` resource added** (additive, no breaking changes). Multi-method resource wrapping `POST /api/v1/batch` (submit) and `GET /api/v1/batch/<UUID>` (get). **First SDK resource with asymmetric auth between methods on the same resource** — `submit()` requires `CLASSIFY` OR `WRITE_ASSESSMENTS` (UNION, the FIRST WRITE-side union pair on the SDK); `get()` requires only `READ_ASSESSMENTS` (single permission). **First SDK route exposing a plan-guard 403 surface** distinct from the permission-403 (`requirePlan(org, "hasBatchProcessing")` fires BEFORE Zod body parsing on `submit()`); the kernel's `PlanLimitError` wording is `'The "hasBatchProcessing" feature is not available on your current plan (<plan>). Please upgrade to access this feature.'` — distinct from the permission-403's `'API key lacks required permission. Required: classify or write:assessments. Key has: ...'`. SDK surfaces both uniformly as `AttestryAPIError(403)`; consumers regex-match `apiErr.message` to distinguish "upgrade your plan" from "grant more permissions to your key" (no SDK-side discriminator helper today). Pre-validates every Zod closed-spec rule synchronously across THREE fields (`jobType` closed-enum 3-string membership, `systemIds` array length [1, 50] + per-element UUID format, `config.frameworks` array length ≤20 + per-element string length [1, 100]) — third SDK route to pre-validate after `check.run` and `gate.evaluate`. Partial-success contract: `submit()` resolves successfully (no throw) even when every row failed; consumers branch on per-row `status === "success"` (closed-enum string match — NOT `errorMessage === undefined` which is pollution-unsafe). **TWO distinct status enums on response wire-shape family**: top-level batch-job `status` (`"completed" | "failed"` on POST, wider 4-enum `"pending" | "processing" | "completed" | "failed"` on GET) vs per-row `results[i].status` (`"success" | "error"` on both). Asymmetric 404 shapes: POST embeds invalid UUIDs in the message (`Systems not found or not in your organization: <id>, <id>...`); GET is a literal string (`Batch job not found`). 400 surface on GET for malformed UUID path param (SDK pre-validates synchronously — kernel 400 reachable only via `as any` casts). `writeAuditLog` side effect on `submit()` writes one `batch.submitted` entry per call (time-blocking but error-tolerant — kernel awaits two DB ops inside writeAuditLog; response latency INCLUDES the write time; error semantics ARE non-blocking — write failure does NOT fail the request). Symmetric prototype-pollution defense on input AND response sides (`Object.hasOwn` snapshot, mirrors session-16 second-hostile-review MEDIUM #3).
>
> **0.5.3 — `gate` resource added** (additive, no breaking changes). Wraps `POST /api/v1/gate` with a Zod-validated body (`systemId` UUID + optional `minScore` int 0-100 default 70 + optional `frameworks` filter + optional `failOnMissingAssessment` boolean default true), multi-permission union auth (READ_ASSESSMENTS or READ_SYSTEMS — same as `check.run`), cross-org systemId collapsed to 404 (LONGER kernel string than `check.run`: `"System not found or access denied"`), and TWO silent kernel-side truncations (assessments at 10 — TIGHTER than `check.run`'s 100 — and remediationTasks at 100). SDK pre-validates every Zod closed-spec rule synchronously across FOUR fields (UUID format, minScore int + range, failOnMissingAssessment boolean, frameworks string + array bounds) — most extensive pre-validation surface to date; 422 only reaches consumers via kernel-side rule changes the SDK hasn't synced to. Response is a STRING-ENUM `gate: "pass" | "fail"` (NOT a boolean) over THREE emit paths (normal pass/fail + fail-on-missing + pass-on-missing); `score` is `number | null` (NOT defaulted to 0 — **asymmetric with `check.run`** where score=0 was the no-assessment default; gate preserves the null distinction at the type level). Every call writes one `gate.checked` audit log entry (new invariant candidate #53 — SDK documents the side effect). Symmetric prototype-pollution defense on input AND response sides (`Object.hasOwn` snapshot, mirrors `check.run`'s session-16 second-hostile-review MEDIUM #3 defense).
>
> **0.5.2 — `check` resource added** (additive, no breaking changes). Wraps `POST /api/v1/check` with a Zod-validated body (`systemId` UUID + optional `frameworks` filter), multi-permission union auth (READ_ASSESSMENTS or READ_SYSTEMS), cross-org systemId collapsed to 404 ("System not found", mirror of `decisions.retrieve`), and THREE silent kernel-side truncations (issues at 20, assessments at 100, attestations at 50) — each documented in JSDoc + the resource section below as separate kernel surface gaps. SDK pre-validates every Zod closed-spec rule synchronously (UUID format, framework string length 1-100, array length cap 20) so 422 only reaches consumers via kernel-side rule changes the SDK hasn't synced to — the runtime checks always run regardless of TypeScript types (`as any` casts do NOT bypass them). `score` defaults to **0 (not null)** when no completed assessment exists — consumers MUST check `lastAssessedAt === null` to distinguish "scored zero" from "no completed assessment yet". Includes prototype-pollution defense on BOTH input field presence AND response field reads (`Object.hasOwn` snapshot — generalization of the XOR-only input-side defense added in 0.5.1, now also applied symmetrically to the P2 response validators per session-16 second-hostile-review MEDIUM #3).
>
> **0.5.1 — `complianceCheck` resource added** (additive, no breaking changes). Wraps `GET /api/v1/compliance-check` with XOR systemId-or-orgName input mode, multi-permission union auth (READ_SYSTEMS or READ_ASSESSMENTS), asymmetric cross-org error codes (404 systemId / 403 orgName), and silent kernel-side `.limit(100)` truncation on the orgName branch (documented in JSDoc + the resource section below — faithful courier, not auto-paginated). Includes a defense-in-depth fix against prototype pollution on the XOR check (`Object.hasOwn` instead of `in`).
>
> **0.5.0 hardening release** (P1+P2+P3): closed-enum exports are now `Object.freeze`-immutable (prevents hostile/buggy npm dependencies from mutating SDK validation arrays); list-shaped sync responses validate `Array.isArray` + `nextCursor` shape at the SDK boundary (kernel regressions to scalar/null surface as `AttestryError` instead of cryptic consumer crashes); sync `request<T>` enforces `Content-Type: application/json` on 2xx responses (proxy/LB-injected HTML error pages now throw `AttestryAPIError` instead of soft-failing). The content-type guard is the only consumer-visible behavior change — wrong-content-type responses that previously soft-failed now throw.

## Install

```bash
npm install @attestry/sdk
```

Requires Node 18+ (uses the global `fetch`). Browser support is intentionally NOT in v0 — server-side use only.

## Quick start

```ts
import { AttestryClient } from "@attestry/sdk";

const client = new AttestryClient({
  apiKey: process.env.ATTESTRY_API_KEY!,
});

// Submit an AI incident.
const incident = await client.incidents.create({
  incidentType: "prompt_injection",
  severity: "high",
  description: "Customer-facing chatbot leaked an internal system prompt.",
  frameworksAffected: ["eu_ai_act", "nist_ai_rmf"],
  optInShare: true,
});

// Append a decision record to the system's hash chain.
const record = await client.decisions.ingest({
  systemId,
  inputDigest: "sha256:abc...",
  frameworkClaims: [
    { framework: "eu_ai_act", article: "Art.13", claim: "human oversight provided" },
  ],
  humanOversightState: "approved",
  policyOutcome: "permitted",
  // Pass an idempotencyKey to make 429-retries safe under network failure.
  idempotencyKey: "decision-2026-05-06-trace-789",
});

// Append a batch of records (1-500). Partial-success envelope: the
// call resolves even when some records fail. Inspect `result.failed[]`
// for per-record errors; `code` distinguishes recovery paths
// (e.g., retry idempotency_unique_violation via decisions.ingest).
const result = await client.decisions.bulk({
  items: [
    { systemId, inputDigest: "sha256:abc...", idempotencyKey: "trace-001" },
    { systemId, inputDigest: "sha256:def...", idempotencyKey: "trace-002" },
  ],
});
console.log(`${result.totalInserted}/${result.totalSubmitted} succeeded`);

// Search the cross-tenant corpus for similar patterns.
const { clusters } = await client.incidents.search({
  query: "system prompt leak",
  limit: 10,
});

// Subscribe to live decision events as they're appended.
for await (const event of client.decisions.stream({ systemId })) {
  console.log(event.id, event.sequenceNumber, event.recordHash);
}

// Export the entire chain as NDJSON (records + a Merkle-root trailer).
// The trailer is the LAST frame and commits the export to a single
// hash over per-record `recordHash` leaves.
for await (const frame of client.decisions.export({ systemId })) {
  if ("type" in frame && frame.type === "ExportTrailer") {
    console.log(`exported ${frame.recordCount} records, root=${frame.merkleRoot}`);
  } else {
    process(frame); // DecisionListItem shape
  }
}

// Verify a system's hash chain integrity. Resolves with the verdict
// body even when chainValid:false — the kernel's answer to "is the
// chain tampered?" is itself a successful response. Branch on
// verdict.chainValid.
const verdict = await client.decisions.verifyChain(systemId);
if (!verdict.chainValid) {
  // Two arrays distinguish the failure mode:
  //   tamperedRecordIds = direct content tampering (security signal)
  //   brokenRecordIds   = sequence gap (ops signal — record missing)
  console.error("chain integrity failure", {
    tampered: verdict.tamperedRecordIds,
    broken: verdict.brokenRecordIds,
    verifiedUpTo: verdict.lastVerifiedSequence,
  });
}

// Stream the org's audit-log to your SIEM. Default jsonl format yields
// AuditLogRecord rows; `format: "ecs"` yields Elastic Common Schema
// events; `format: "cef"` yields ArcSight CEF v0 lines as raw strings.
// Auto-paginates by default (walks all history newest-first).
//
// Dual-auth admin — the api-key must carry the ADMIN permission;
// 401 for no/invalid/expired key, 403 for a valid key lacking ADMIN.
for await (const row of client.auditLog.export()) {
  if (row.action === "api_key_revoked") notifySecurity(row);
}

// List recent regulatory updates filtered by framework / severity.
// Returns a Promise<RegulatoryChange[]> sorted DESC by publishedAt.
// IMPORTANT: when `status` is omitted, the kernel filters dismissed
// rows OUT (default-excludes-dismissed). Pass status: "dismissed" to
// retrieve only dismissed rows.
const recentCritical = await client.regulatoryChanges.list({
  framework: "EU_AI_ACT",
  severity: "critical",
  from: "2026-04-01T00:00:00Z",
  limit: 50,
});
for (const change of recentCritical) {
  console.log(change.framework, change.severity, change.title);
}
```

## Configuration

```ts
new AttestryClient({
  apiKey: "sk_live_…",                        // required
  baseUrl: "https://app.attestry.ai",         // optional — defaults to prod
  timeoutMs: 30_000,                          // optional — defaults to 30s (NOT applied to streams)
  fetch: customFetch,                         // optional — defaults to globalThis.fetch
  retry: { maxRetries: 3 },                   // optional — see "Automatic retry" below
});
```

| Option | Default | Notes |
|---|---|---|
| `apiKey` | required | API key from the Attestry org settings page. Sent as `x-api-key`. |
| `baseUrl` | `https://app.attestry.ai` | Override for self-hosted, EU residency, or local dev. Trailing slashes are stripped. |
| `timeoutMs` | `30_000` | Per-request timeout for JSON requests (not streams). Set `0` to disable. |
| `fetch` | `globalThis.fetch` | Inject a custom fetch (testing, retries, observability). Must match the standard `fetch` signature. |
| `retry` | `{maxRetries: 3, initialDelayMs: 1000, maxDelayMs: 30_000, honorRetryAfter: true}` | Automatic retry on 429. See "Automatic retry" section below. Set `{maxRetries: 0}` to disable. |

Construction is fail-fast: a missing API key, missing fetch, or an invalid `timeoutMs` / `retry` config throws `AttestryError` synchronously.

## Errors

Two error classes:

```ts
import { AttestryClient, AttestryError, AttestryAPIError } from "@attestry/sdk";

try {
  await client.incidents.create({ /* … */ });
} catch (err) {
  if (err instanceof AttestryAPIError) {
    // The API returned a non-2xx response.
    console.error(`API ${err.status}: ${err.message}`, err.details);
  } else if (err instanceof AttestryError) {
    // Network failure, timeout, or aborted request — the call did NOT
    // reach the API.
    console.error("transport error:", err.message);
  } else {
    throw err;
  }
}
```

`AttestryAPIError extends AttestryError extends Error`, so a single `instanceof AttestryError` catches both layers.

## Cancellation

```ts
const ac = new AbortController();
setTimeout(() => ac.abort(), 5_000);

try {
  await client.incidents.search({ query: "long-running" }, { signal: ac.signal });
} catch (err) {
  if (err instanceof AttestryError && err.message === "request aborted by caller") {
    // user cancelled
  }
}
```

The caller's `AbortSignal` is composed with the SDK's internal timeout signal (for JSON requests); aborting either one cancels the request. For streams, `signal` is the only cancellation hook — there's no internal timeout.

`signal.abort()` mid-retry-backoff also interrupts the wait immediately — the SDK rejects with `AttestryError("request aborted by caller")` rather than completing the backoff and retrying.

## Automatic retry

The SDK automatically retries HTTP 429 (`Too Many Requests`) responses with exponential backoff and full jitter.

**Default config:** `{maxRetries: 3, initialDelayMs: 1_000, maxDelayMs: 30_000, honorRetryAfter: true}`.
That's up to 4 total attempts (1 initial + 3 retries), starting at ~1s and doubling each time, capped at 30s. The server-supplied `Retry-After` header (RFC 7231 — both delta-seconds and HTTP-date forms) takes precedence when present, also capped at `maxDelayMs`.

```ts
// Disable client-wide:
const client = new AttestryClient({
  apiKey,
  retry: { maxRetries: 0 },
});

// Tighten for a latency-sensitive call:
await client.incidents.search(query, {
  retry: { maxRetries: 1, initialDelayMs: 200, maxDelayMs: 1_000 },
});

// One-off "do not retry":
await client.incidents.create(input, { retry: { maxRetries: 0 } });
```

| Field | Default | Notes |
|---|---|---|
| `maxRetries` | `3` | 0 disables. Capped at 100 (config DoS guard). |
| `initialDelayMs` | `1_000` | Base for exponential schedule. |
| `maxDelayMs` | `30_000` | Cap on both exponential and `Retry-After`. |
| `honorRetryAfter` | `true` | When false, the SDK ignores the server hint and uses pure exponential. |

**Why only 429?** 429 means the server rejected the request before processing — by definition safe to retry. Other transient statuses (502/503/504) MAY be safe but require HTTP-level idempotency-key support (planned). The SDK does not retry network errors either — fetch failures (DNS, ECONNREFUSED) bubble as `AttestryError` for the caller to handle.

**Streams:** the initial fetch retries on 429. Once events have been delivered, mid-stream errors throw to the caller — auto-retrying mid-stream would risk lost or duplicated events. Caller resumes by passing the last seen `event.eventId` back as `lastEventId`.

## Resources

### `client.incidents`

| Method | Wraps | Returns |
|---|---|---|
| `create(input, options?)` | `POST /api/v1/incidents` | `Incident` |
| `list(input?, options?)` | `GET  /api/v1/incidents` | `{ items, nextCursor? }` |
| `update(id, input, options?)` | `PATCH /api/v1/incidents/:id` | `Incident` |
| `search(input, options?)` | `POST /api/ai/incidents/search` | `{ clusters, count, truncated }` |

See `src/resources/incidents.ts` for the full input/output type shapes.

### `client.decisions`

| Method | Wraps | Returns |
|---|---|---|
| `ingest(input, options?)` | `POST /api/v1/decisions` | `DecisionRecord` |
| `bulk(input, options?)` | `POST /api/v1/decisions/bulk` | `BulkIngestResult` (partial-success envelope) |
| `retrieve(id, options?)` | `GET /api/v1/decisions/:id` | `DecisionRecord` |
| `list(input?, options?)` | `GET /api/v1/decisions` | `{ items: DecisionListItem[], nextCursor: string \| null }` |
| `stream(input?, options?)` | `GET /api/v1/decisions/stream` (SSE) | `AsyncIterable<DecisionStreamEvent>` |
| `export(input, options?)` | `GET /api/v1/decisions/export` (NDJSON) | `AsyncIterable<DecisionExportFrame>` |
| `verifyChain(systemId, options?)` | `GET /api/v1/decisions/verify-chain/:systemId` | `ChainVerificationResult` (200 with chainValid:true OR chainValid:false) |

`ingest()` appends a record to the org's append-only hash chain. Pass an `idempotencyKey` for at-least-once delivery semantics — server dedupes on `(orgId, idempotencyKey)`. Different payload with the same key surfaces as `AttestryAPIError` with `status === 409`. When the org exhausts its `decisionsPerMonth` plan quota, the SDK throws `AttestryAPIError(402)` with structured `details: {feature, currentPlan, upgradeRequired}` so dashboards can route to the upgrade flow. Sub-shapes (`FrameworkClaim`, `ToolInvocation`, `DelegationEntry`, `ZkProof`) are exported for typed input building.

`bulk()` appends 1-500 records in a single request. **Critical contract:** the call resolves successfully even when every record failed — partial success is the entire point of the endpoint. Inspect `result.totalFailed` and `result.failed[]` for per-record errors; the `code` field distinguishes recovery paths (`idempotency_conflict`, `payload_too_large`, `chain_head_missing`, `system_not_found`, `ijson_validation_failed`, `idempotency_unique_violation`, `chunk_failed`). Top-level failures (auth, rate limit, plan limit, oversize batch) DO throw `AttestryAPIError`. The plan-limit (402) check counts the FULL batch wholesale against the `decisionsPerMonth` quota — partial quota fills are not allowed. For at-least-once retry semantics, give every item its own `idempotencyKey`; failed items with `code === "idempotency_unique_violation"` should be retried individually via `decisions.ingest` to invoke per-record race recovery.

`list()` is keyset-paginated. Pass `response.nextCursor` back as `input.cursor` to fetch the next page; iterate until `nextCursor === null`. The slim `DecisionListItem` type omits heavy fields (`canonicalPayload`, `clientSignature`, etc.) — call `decisions.retrieve(id)` for the full record. Filters: `systemId`, `from` / `to` (ISO datetimes), `framework` / `article` (jsonb-contains), `tool`, `includeTombstoned`, `limit` (1-200, default 50).


`stream()` is an async-iterator over Server-Sent Events. Errors **throw** from the iterator (long-lived subscription semantics); use `try / catch` around the for-await loop:

```ts
let lastEventId: string | undefined;
try {
  for await (const event of client.decisions.stream({ systemId, lastEventId })) {
    process(event);
    lastEventId = event.eventId; // keep for reconnection
  }
} catch (err) {
  if (err instanceof AttestryAPIError && err.status === 401) {
    // re-auth
  } else if (err instanceof AttestryError) {
    // network / abort / parser error — wait + reconnect with lastEventId
  }
}
```

The SDK does **not** auto-reconnect — caller controls reconnect timing using `lastEventId`. Heartbeat frames are silently consumed; consumers see only real events.

`export()` streams a system's entire decision chain as NDJSON (`application/x-ndjson` — one JSON line per record), then a final trailer frame committing the batch to a single Merkle root over the per-record `recordHash` leaves. Records first (in `sequenceNumber` ascending order), then exactly one trailer:

```ts
for await (const frame of client.decisions.export({ systemId })) {
  if ("type" in frame && frame.type === "ExportTrailer") {
    // Final commit — verify Merkle root client-side post-Prompt-1.
    console.log(frame.recordCount, frame.merkleRoot, frame.signing);
  } else {
    // Per-record line — DecisionListItem shape (interchangeable with `list()` rows).
    process(frame);
  }
}
```

The trailer's **`signing` field is today the literal string `"unsigned-prompt-1-blocked"`** — Prompt 1's Ed25519 signing isn't shipped yet, so the trailer is unsigned and the field carries that fact explicitly. Once Prompt 1 lands, the field will be replaced by a structured `eddsa-jcs-2022` proof. The SDK types the field as `string` (not a literal-union) for forward-compat with that transition; the runtime literal value is drift-pinned kernel-side. The SDK does **not** verify the Merkle root or signature — caller is responsible (off-the-shelf libraries: `ed25519-verify`, `merkle-tree`).

**Empty exports** still emit a trailer — when the systemId has zero records (or doesn't exist / belongs to another org), the iterator yields a single frame with `recordCount: 0`, `sequenceFrom: null`, `sequenceTo: null`, and the deterministic empty-export merkleRoot (`sha256:` + hex of `sha256("ATTESTRY-EMPTY-EXPORT")`). Consumers detect "no data" via the trailer rather than a zero-frame iterator.

**Missing trailer** is treated as a mid-stream failure. If the iterator exhausts without seeing a trailer (kernel committed to 200 then hit a DB error during pagination — can't return as 4xx), the SDK throws `AttestryError("decisions.export: stream ended without trailer — connection dropped or server failed mid-stream")`. Caller can branch on this to distinguish "kernel-completed export" from "kernel-aborted export".

The export endpoint runs up to 5 minutes server-side. The SDK does not arm an internal timeout for streams; cancel via `options.signal` if needed. `includeTombstoned: false` is forwarded literally — no kernel `z.coerce.boolean()` workaround required (the kernel session-6 `stringBoolean` fix accepts `"false"` correctly; this asymmetry from `decisions.list` — which still omits `false` as defense-in-depth — is deliberate).

`verifyChain()` replays a system's hash chain server-side and reports an integrity verdict. **Critical contract:** the kernel returns HTTP 200 with `chainValid: false` when tampering is detected — the SDK resolves the Promise with the verdict body, it does **NOT** throw. Mirror of `decisions.bulk`'s partial-success contract: the customer asked the chain-integrity question, the kernel answered, and the SDK is a faithful courier. Top-level structural failures (auth, rate limit, system-not-found, ChainTooLong) DO throw `AttestryAPIError`. The result distinguishes failure modes via two arrays — `tamperedRecordIds` (direct content tampering, security signal) and `brokenRecordIds` (sequence gap, ops signal); both can be non-empty simultaneously and the kernel fires `chain.tampered` / `chain.broken` / `chain.verified` webhooks fire-and-forget out-of-band (the SDK does NOT see them; subscribe via the `webhooks` resource for delivery). Chains over 50K records 413 with `err.details?.details?.hint` referencing `decisions.export` for offline verification — fall back to `decisions.export()` on that signal. (The double-`details` reflects the transport's error-body wrap: it stores the full parsed body under `AttestryAPIError.details`, and the kernel's own structured `details` payload nests inside.) `lastVerifiedAt` is a wire ISO-string (NOT a Date instance); parse via `new Date(value)` if needed.

### `client.chat`

| Method | Wraps | Returns |
|---|---|---|
| `send(input, options?)` | `POST /api/ai/chat` | `{ message, agent }` |
| `stream(input, options?)` | `POST /api/ai/chat` (sync, iterator-shaped) | `AsyncIterable<ChatStreamChunk>` |

`chat.stream()` yields zero-or-more `{type: 'text', delta}` chunks then exactly one terminator (`{type: 'done'}` on success or `{type: 'error', message}` on failure). Errors do NOT throw — request/response semantics. Forward-compat for true SSE if `/api/ai/chat` migrates.

### `client.auditLog`

| Method | Wraps | Returns |
|---|---|---|
| `export(input?, options?)` | `GET /api/v1/audit-log/export` (NDJSON or text/plain) | `AsyncIterable<AuditLogRecord \| unknown \| string>` (format-discriminated) |
| `verifyChain(options?)` | `GET /api/v1/audit-chain/verify` | `Promise<AuditChainVerificationResult>` |

`auditLog.export()` streams the org's audit-log rows as line-oriented frames in one of three wire formats — `jsonl` (default; structured `AuditLogRecord` shape), `ecs` (Elastic Common Schema 8.x events), or `cef` (ArcSight CEF v0 lines). The iterator's yield type is format-discriminated via overload signatures: `format: "jsonl"` → `AuditLogRecord`; `format: "ecs"` → `unknown` (consumers parse their own ECS schema); `format: "cef"` → `string` (raw CEF line, no JSON.parse).

**Dual-auth admin scope.** The kernel route gates on `requireSessionOrApiKey(request, { sessionRoles: ["admin"], apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })` — the identical dual-auth pattern the `abacPolicies` cluster uses. The SDK's transport always sends `x-api-key`, so the api-key path is the only one reachable from SDK consumers: **HTTP 401** for no / invalid / expired api-key, **HTTP 403** for a valid api-key whose permissions do NOT include `ADMIN`. Pin BOTH branches separately. (Corrected — session-22 hostile review #2: the prior "HTTP 401 for both" claim mis-read the kernel test, which MOCKS `AuthError(401)` and never exercises the real `requireSessionOrApiKey` middleware; the middleware returns 403 for the insufficient-permission case.)

**Auto-paginates by default.** The kernel emits `x-attestry-next-cursor` in the response headers when more pages exist; the iterator transparently fetches the next page. Pass `autoPaginate: false` to yield only the first page (rare — most consumers want the full history walked transparently). The next-cursor is NOT exposed through the iterator protocol; consumers needing manual cursor control track the last `(timestamp, id)` themselves and pass it as `cursor` on the next call.

Rows arrive DESC by `(timestamp, id)` — newest first. Order is preserved across page boundaries.

**Cursor format.** Compound `<ISO-8601-UTC>:<UUID>` (preferred — strict tuple ordering across same-timestamp rows) OR bare ISO-8601 UTC (legacy fallback — may skip same-microsecond rows). The SDK forwards `cursor` verbatim; the kernel's regex is the format authority.

**`limit` semantics.** Defaults to 1000 server-side. Max 5000; the kernel silently clamps. The SDK rejects `NaN` / `Infinity` / `<= 0` / non-integer as `TypeError` synchronously (more strict than the kernel's silent coerce-to-1000 — fail-loud-and-synchronous; build-round D4). Limits over 5000 are forwarded verbatim — the kernel's `MAX_LIMIT` is the authority, leaving room for future raises without an SDK bump.

**No body trailer.** Different from `decisions.export`: audit-log/export does NOT emit a Merkle-root trailer; the cursor lives in headers, the empty page is a valid stop signal. The SDK does NOT throw "stream ended without trailer" — that check is intentionally absent (asymmetric with `decisions.export` per build-round D8).

```ts
// Walk all admin events (auto-paginate)
for await (const row of client.auditLog.export()) {
  if (row.action === "api_key_revoked") audit(row);
}

// ECS for SIEM ingest (Elastic / Datadog / Logstash):
for await (const event of client.auditLog.export({ format: "ecs" })) {
  await elasticIngest(event); // event: unknown — parse via your own ECS schema
}

// CEF for ArcSight / QRadar:
for await (const line of client.auditLog.export({ format: "cef" })) {
  await arcsightForward(line); // line: string starting with "CEF:0|Attestry|..."
}
```

#### `auditLog.verifyChain(options?)` — org-wide audit-log hash-chain integrity

`auditLog.verifyChain()` verifies the integrity of the org's audit-log hash chain. Returns an `AuditChainVerificationResult` describing whether the chain is intact, and (when broken) the UUID of the entry where verification failed. Takes NO input — auth-derived org binding is the only scope.

**Distinct from `decisions.verifyChain` (per-system).** That method verifies a single system's decision chain; `auditLog.verifyChain` verifies the entire ORG's audit log. Different responsibility, different kernel route, different consumer audience (compliance auditors). The two complement each other.

**CRITICAL contract — does NOT throw on `valid: false`.** The kernel returns HTTP 200 with `valid: false` on a tampered chain; the SDK resolves the Promise with the verdict body. Top-level structural failures (auth, rate limit, internal) throw `AttestryAPIError`. Mirror of `decisions.verifyChain`'s same contract (carry-forward invariant #12 — the verdict is the answer, not an error).

**API-key auth scope — no permission filter.** The kernel route uses `requireApiKey(request)` directly — NO permission scoping. **Any valid api-key for the org succeeds; the 403 path is unreachable.** Asymmetric with `auditLog.export` (which gates on ADMIN role) and with `decisions.verifyChain` (which uses `requireSessionOrApiKey`). The route is open to ALL keys in the org.

**`brokenAt` is OPTIONAL.** The kernel uses a conditional spread `...(result.brokenAtId ? { brokenAt: result.brokenAtId } : {})`, so the field is an OWN-PROPERTY of the response ONLY on broken chains. On a valid chain it's omitted entirely. **Consumers MUST detect broken-chain via `result.valid === false`** (closed-enum boolean discriminator), NOT `result.brokenAt === undefined` (prototype-pollution-unsafe — under `Object.prototype.brokenAt = "fake-uuid"` pollution, the equality check walks the prototype and reads the polluted value).

**Silent kernel-side truncation at 5000 entries.** The kernel's audit-log fetch is capped at 5000 entries (`route.ts:51`: `.limit(5000)`). For orgs with more than 5000 audit-log entries, only the OLDEST 5000 are verified per call. The kernel does NOT emit a "truncated" flag — `totalEntries` equals the number of rows fetched, NOT the org's full audit-log row count. Documented kernel surface gap; the SDK does NOT mask. Consumers with high-volume audit logs should be aware that the verifier sees a stale window.

**NO `writeAuditLog` side effect.** The verifier is quiet — writing to the audit log while verifying it would be ironic; the kernel team avoided this. Asymmetric with `gate.evaluate` / `batch.submit` (both write audit entries).

**Response shape** (`AuditChainVerificationResult`): 5 always-present fields plus 1 optional own-property:

| Field | Type | Notes |
|---|---|---|
| `valid` | `boolean` | `true` iff chain intact. Empty logs verify as `true` (vacuous). |
| `entriesVerified` | `number` | Count verified before first broken link; equals `totalEntries` on valid chain. |
| `totalEntries` | `number` | Total entries fetched. Capped at 5000 by silent kernel truncation. |
| `firstEntry` | `string \| null` | ISO-8601 UTC of oldest entry. `null` on empty log. ALWAYS present on the wire. |
| `lastEntry` | `string \| null` | ISO-8601 UTC of newest entry. `null` on empty log. ALWAYS present on the wire. |
| `brokenAt` | `string` (optional own-property) | UUID of the broken entry. **Omitted from the wire on valid chains** — own-property ONLY on broken chains. TypeScript reads as `string \| undefined` due to the optional marker; the wire shape is absent-or-string (JSON has no `undefined`). |

**No 400 / 402 / 403 / 404 / 413 / 422 / `TypeError` surfaces.** This method has no input (no `TypeError`), no body (no 422), no permission filter (no 403), implicit org from auth (no 404), no quota (no 402), and silent truncation instead of 413. Only 401 (auth), 429 (rate limit), 500 (internal), `AttestryError` (abort / P2 response shape), and `AttestryAPIError` (P3 content-type) surface.

```ts
// Detect a tampered audit log
const verdict = await client.auditLog.verifyChain();
if (!verdict.valid) {
  // brokenAt is an OWN-PROPERTY only on broken chains. TypeScript
  // narrows it to `string | undefined`; check before forwarding.
  if (verdict.brokenAt) {
    await notifySecurity({
      entryId: verdict.brokenAt,
      verifiedUpTo: verdict.entriesVerified,
      totalEntries: verdict.totalEntries,
    });
  }
}
console.log(`Verified ${verdict.entriesVerified}/${verdict.totalEntries} entries`);

// Schedule periodic verification (cron job)
try {
  const verdict = await client.auditLog.verifyChain();
  if (!verdict.valid && verdict.brokenAt) {
    await pageOncall({ brokenAt: verdict.brokenAt });
  }
} catch (err) {
  if (err instanceof AttestryAPIError && err.status === 429) {
    // Back off — verifier is rate-limited per IP via `audit-chain-verify:${ip}`.
    return;
  }
  throw err;
}
```

### `client.regulatoryChanges`

| Method | Wraps | Returns |
|---|---|---|
| `list(input?, options?)` | `GET /api/v1/regulatory-changes` | `Promise<RegulatoryChange[]>` |

`regulatoryChanges.list()` returns the org's regulatory-change feed — a read-only list of regulatory updates ingested by the kernel (EU AI Act amendments, US federal-register notices, state legislative updates, etc.) filtered by `framework` / `severity` / `status` / `from` / `to` / `limit`. Rows arrive DESC by `publishedAt`. Sync JSON list response — no pagination cursor. Returns `Promise<RegulatoryChange[]>`.

**Default-excludes-dismissed (the non-obvious gotcha).** When `status` is **omitted** from the input, the kernel filters dismissed rows OUT (`WHERE status != 'dismissed'`). To retrieve dismissed rows, pass `status: "dismissed"` (returns ONLY dismissed rows). To retrieve `"new"` / `"reviewed"` / `"actioned"` rows, pass that exact status. There is currently NO way to retrieve "everything including dismissed" via this endpoint — the kernel route hardcodes the exclusion at the default branch.

**READ_SYSTEMS auth scope.** Returns HTTP **401** for no/invalid API key (the `requireApiKey` branch) and HTTP **403** for an authenticated key that lacks the `READ_SYSTEMS` permission (the `requireApiKeyWithPermission` branch). `auditLog.export` (ADMIN-only dual-auth) surfaces the SAME 401-vs-403 split — the auth models differ, the status surface does not (corrected session-22 hostile review #2). Consumers must distinguish 401 (re-authenticate) from 403 (request a different API key) at the call site.

**Closed enums.** `severity` (`"critical"` / `"high"` / `"medium"` / `"low"`) and `status` (`"new"` / `"reviewed"` / `"actioned"` / `"dismissed"`) are pre-validated SDK-side as `TypeError` synchronously — kernel additions require an SDK release. Both arrays are exported as `REGULATORY_CHANGE_SEVERITIES` and `REGULATORY_CHANGE_STATUSES` and drift-pinned kernel-side. `framework` is an open string (forward-compat for new framework codes added kernel-side without an SDK bump). `from` / `to` are date-strings passed verbatim to the kernel's `new Date(...)` parser; the SDK does NOT pre-validate ISO-8601 (kernel's parser is lenient).

**Limit semantics.** Defaults to 200 server-side (max 200 — the kernel returns 400 for out-of-range). The SDK rejects `NaN` / `Infinity` / `<= 0` / non-integer as `TypeError` synchronously; values `> 200` are forwarded verbatim — kernel's authority. (Kernel's `MAX_LIMIT` is 200 here, NOT 5000 like `auditLog.export` — read carefully.)

**Wire shape.** `RegulatoryChange` is a 21-field row mirroring the kernel's `regulatoryChanges` Drizzle table verbatim — the route returns raw rows (no `rowToWireJson` mapper). `severity` and `status` are typed as `string` for forward-compat with kernel-side enum additions; `affectedRequirements`, `aiAnalysis`, and `statusTransitions` are typed as `unknown` (jsonb fields with comment-only shape hints; consumers parse via their own validators). Nullable timestamp fields (`effectiveDate`, `publishedAt`, `ingestedAt`, `notifiedAt`) round-trip as `null`.

```ts
// Most recent 200 non-dismissed rows (kernel default).
const changes = await client.regulatoryChanges.list();

// Filter to critical EU AI Act updates from the last 30 days.
const critical = await client.regulatoryChanges.list({
  framework: "EU_AI_ACT",
  severity: "critical",
  from: "2026-04-07T00:00:00Z",
  limit: 50,
});

// Retrieve only dismissed rows (pass status explicitly — default omits them).
const dismissed = await client.regulatoryChanges.list({ status: "dismissed" });
```

### `client.complianceCheck`

| Method | Wraps | Returns |
|---|---|---|
| `check(input, options?)` | `GET /api/v1/compliance-check` | `Promise<ComplianceCheckResponse>` |

`complianceCheck.check()` returns a per-system compliance summary for either a single system (by UUID) or every system in an org (by org name, capped at 100). The response combines active-attestation counts, the latest completed assessment's `overallScore`, and a framework-coverage breakdown (applicable vs assessed). Sync JSON request/response — no pagination, no streaming. Returns `Promise<ComplianceCheckResponse>` shaped as `{systems: ComplianceCheckResult[], checkedAt: ISO-string}`.

**XOR input mode (read carefully).** Exactly one of `systemId` OR `orgName` must be provided. The kernel is **not** strict XOR — when both are provided, kernel silently picks `systemId` and ignores `orgName`. The SDK is **stricter** than the kernel and synchronously throws `TypeError` when both are provided. This is a deliberate design choice: kernel quirks are unstable across revisions; surfacing the conflict at the SDK boundary makes consumer code stable. The TypeScript type (`ComplianceCheckInput`) is a discriminated union that prevents typed callers from passing both at compile time.

**Multi-permission union auth scope.** The kernel uses `requireApiKeyWithPermission(req, READ_SYSTEMS, READ_ASSESSMENTS)` which is **OR** semantics — a key with EITHER permission (or `ADMIN`, or null/empty permissions for backwards-compat) succeeds. Returns HTTP **401** for no/invalid API key (the `requireApiKey` branch) and HTTP **403** only for an authenticated key that has NEITHER required permission (the `requireApiKeyWithPermission` branch). `auditLog.export` (ADMIN-only dual-auth) surfaces the SAME 401-vs-403 split — the auth models differ, the status surface does not (corrected session-22 hostile review #2).

**Asymmetric cross-org error codes (read carefully).** Cross-org `systemId` returns **404** ("System not found") — the kernel collapses cross-org to 404 to avoid leaking "this UUID exists but belongs to another org" (mirror of `decisions.retrieve`). Cross-org `orgName` returns **403** ("Access denied") — the kernel intentionally surfaces "the org exists but you can't see its systems". Consumers writing defensive error-handling logic must distinguish: a 404 on the systemId path may be "not your org" OR "genuine missing UUID"; a 403 on the orgName path is unambiguously "the org exists but you don't own it".

**Silent `.limit(100)` on the orgName path.** If the org has more than 100 systems, the response is silently truncated to the first 100 — NO `total` field, NO `hasMore` cursor, NO warning. The SDK does not mask this (faithful courier — the kernel decided 100 is enough). Consumers managing >100-system orgs should switch to `systemId`-per-row.

**Implicit threshold of 70 on `compliant`.** The `compliant` boolean is computed as `activeAttestations > 0 && (overallScore === null || overallScore >= 70)`. Two qualifying clauses: (1) at least one currently-active (non-expired) attestation exists; (2) either no scored assessment yet (counts as not-failing) OR the latest completed assessment's `overallScore >= 70`. Consumers wanting a different bar can apply it post-hoc via the `score` field.

**Wire shape.** `ComplianceCheckResult` has 7 fields (`systemId`, `systemName`, `compliant`, `score`, `frameworkCoverage`, `activeAttestations`, `lastAssessedAt`). `frameworkCoverage` is a 3-field nested object (`applicable: string[]`, `assessed: string[]`, `coveragePct: number`). `score` and `lastAssessedAt` are nullable. `coveragePct` is `Math.round((assessed.size / applicable.length) * 100)` when `applicable.length > 0`, else `0` — note the kernel does NOT clamp 0..100, so a system assessed against frameworks outside its applicable list can yield a `coveragePct > 100`.

```ts
// Compliance check by system UUID.
const single = await client.complianceCheck.check({
  systemId: "11111111-1111-1111-1111-111111111111",
});
console.log(single.systems[0].compliant, single.systems[0].score);

// Compliance check by org name (capped at 100 systems — silently).
const org = await client.complianceCheck.check({
  orgName: "Acme Corp",
});
console.log(`${org.systems.length} systems checked at ${org.checkedAt}`);
```

### `client.check`

| Method | Wraps | Returns |
|---|---|---|
| `run(input, options?)` | `POST /api/v1/check` | `Promise<CheckResponse>` |

`check.run()` returns a flat per-system CI/CD compliance summary suitable for blocking a deploy on missing attestations or low assessment scores. The response combines a `compliant` boolean (computed kernel-side at the implicit threshold of 70 — see below), the latest completed assessment's `overallScore`, an up-to-20 issues array derived from that assessment's gaps, an active-attestations count, and timestamp metadata. Sync JSON request/response — no pagination, no streaming. Returns `Promise<CheckResponse>` with 6 top-level fields: `compliant`, `score`, `issues`, `activeAttestations`, `lastAssessedAt`, `checkedAt`. Method name `run` (not `check`) avoids the awkward `client.check.check` collision.

**Method name — `client.check.run(input)`.** The resource is named `check` (matches the kernel route `/api/v1/check`); the method is `run`. Mirrors `chat.send` / `decisions.ingest` / `auditLog.export` verb-method convention.

**Multi-permission union auth scope.** The kernel uses `requireApiKeyWithPermission(req, READ_ASSESSMENTS, READ_SYSTEMS)` which is **OR** semantics — a key with EITHER permission (or `ADMIN`, or null/empty permissions for backwards-compat) succeeds. Returns HTTP **401** for no/invalid API key and HTTP **403** only for an authenticated key that has NEITHER required permission. Same shape as `complianceCheck.check` (arguments in the opposite order, but `Array.some()` doesn't care). `auditLog.export` (ADMIN-only dual-auth) surfaces the SAME 401-vs-403 split — the auth models differ, the status surface does not (corrected session-22 hostile review #2).

**Cross-org systemId collapses to 404.** The kernel's `and(eq id, eq orgId)` followed by `errorResponse("System not found", 404)` collapses cross-org systemId to 404 — mirror of `decisions.retrieve` and `complianceCheck.check`'s systemId branch. Consumers writing defensive error-handling logic must recognize: a 404 may be "not your org" OR "genuine missing UUID". No 403-via-orgName twin here (no orgName input mode).

**First SDK route to pre-validate every Zod closed-spec rule synchronously.** The kernel uses `parseBody(request, checkSchema)` where `checkSchema = z.object({systemId: z.string().uuid(), frameworks: z.array(z.string().min(1).max(100)).max(20).optional()})`. Other Zod-bodied SDK routes (e.g., `incidents.create`) pass input through without SDK-side validation, so a 422 from Zod is the consumer-visible surface there; in `check.run` the SDK pre-validates each Zod closed-spec rule (UUID format, string length 1-100, array length cap 20) so 422 only reaches consumers through a kernel-side rule change the SDK hasn't synced to (the SDK's runtime checks always run regardless of TypeScript types — `as any` casts do NOT bypass them). The SDK-side error is a synchronous `TypeError` with a specific message naming the violating field; the kernel-side 422 fallback body is `{success: false, error: "Validation failed.", details: Array<{path: string; message: string}>}` (the field errors live at the `details` ARRAY, NOT a `fieldErrors` keyed map; consumers reading field-by-field errors iterate `apiErr.details.details`). Consumers writing defensive error-handling code should expect the SDK-side TypeError as the normal path.

**THREE silent kernel-side truncations** (each separately load-bearing — the SDK does NOT mask any of them, faithful courier):
- `issues` — `gaps.slice(0, 20)` at `route.ts:90`. If the latest completed assessment has >20 gaps, the 21st+ are invisible (no `total`, no `hasMore`, no truncation flag).
- `assessments` row-population — `.limit(100)` at `route.ts:62`. The kernel reads up to 100 assessments and sorts in JS to find the latest completed. If a system has >100 assessment rows, the "latest completed" may be MISSED (positions 100+ are silently dropped pre-sort).
- `attestations` row-population — `.limit(50)` at `route.ts:100`. The kernel reads up to 50 attestation rows and counts active ones. If a system has >50 attestations, the `activeAttestations` count may be UNDERCOUNTED.

**`score` defaults to 0 (not null) — kernel surface gap.** Asymmetric with `complianceCheck.check` (which used `null` for "no data"). The kernel emits `score: 0` whenever no completed assessment exists OR the latest's `scores.overallScore` field is missing / non-numeric. **Consumers cannot distinguish "scored zero / fails compliance" from "no completed assessment yet" via `score` alone** — they MUST check `lastAssessedAt === null` to differentiate. The SDK does NOT mask this; documented prominently in JSDoc + this section.

**`compliant` threshold of 70 — stricter than `complianceCheck.check`.** Computed kernel-side as `activeAttestations > 0 && overallScore >= 70 && issues.length === 0` (three conjuncts). Because `score` defaults to 0 (not null), a system with no completed assessment and active attestations still has `compliant: false` here — different from `complianceCheck.check` which treated null-score as "not failing". Consumers wanting different semantics should inspect `score`, `lastAssessedAt`, and `activeAttestations` directly.

**`frameworks` filter is OR-overlap (NOT AND-all-required).** When `frameworks` is supplied, the kernel filters assessments to those whose `assessment.frameworks` array **intersects** the filter (at least one in common — `aFrameworks.some(...)` at `route.ts:67-71`). Consumers expecting "match systems covered by ALL these frameworks" will be surprised. Omitting `frameworks` (or passing an empty array) considers all assessments.

```ts
// Basic CI/CD check.
const result = await client.check.run({
  systemId: "11111111-1111-1111-1111-111111111111",
});
if (result.compliant) {
  console.log("OK to deploy — score:", result.score);
} else if (result.lastAssessedAt === null) {
  // CRITICAL: score=0 + lastAssessedAt=null means "no completed
  // assessment yet" — NOT "failed with score zero". Treat as
  // pre-launch, not as a failing grade.
  console.warn("No completed assessment yet — gate may need a baseline run");
} else {
  console.warn("Compliance gaps:", result.issues);
  console.warn("Score:", result.score, "(threshold = 70)");
}

// Filtered by frameworks (OR-overlap, not AND-all-required).
const euOnly = await client.check.run({
  systemId: "11111111-1111-1111-1111-111111111111",
  frameworks: ["EU_AI_ACT", "ISO_42001"],
});
```

### `client.gate`

| Method | Wraps | Returns |
|---|---|---|
| `evaluate(input, options?)` | `POST /api/v1/gate` | `Promise<GateResponse>` |

`gate.evaluate()` returns a pass/fail verdict for CI/CD deployment gates, with a structured list of unresolved compliance gaps suitable for build logs. Designed for pipeline integration (curl-from-CI / GitHub Actions / GitLab CI). Sync JSON request/response — no pagination, no streaming. Method name `evaluate` (not `run` / `check`) matches the verb-method convention AND the pass/fail evaluation semantics naturally; `check` would clash with `complianceCheck.check` and `check.run`.

**Three emit paths.** The response shape varies by whether a `relevantAssessment` was found (kernel route.ts:88-98) and the value of `failOnMissingAssessment`:
- **Path 1 — normal pass/fail (`relevantAssessment` found)**: 14 fields. `score: number`; emit-only fields (`assessmentId`, `assessmentDate`, `gapCount`, `criticalGaps`, `highGaps`) all present.
- **Path 2 — fail-on-missing**: `failOnMissingAssessment=true` (the default) AND `relevantAssessment` is falsy. 9 fields. `gate: "fail"`, `score: null`, `gaps: []`. Emit-only fields ABSENT (own-property false).
- **Path 3 — pass-on-missing**: `failOnMissingAssessment=false` AND `relevantAssessment` is falsy. 9 fields. `gate: "pass"`, `score: null`, `gaps: []`. Emit-only fields ABSENT.

**`relevantAssessment` is falsy in TWO distinct cases**: (a) NO completed assessment exists within the 10 most-recent assessment rows (silent `.limit(10)` truncation — see below), OR (b) — with `frameworks` specified — no completed assessment within those 10 rows matches ANY framework via substring + case-insensitive comparison. A consumer setting `frameworks: ["UNMATCHED_FRAMEWORK"]` on a system with multiple completed assessments would fall into Paths 2/3 and see the literal `reason` string "No completed assessment found for this system." — even though completed assessments DO exist (they just don't match the filter). Consumers should NOT use Paths 2/3 alone to conclude "this system has never had a completed assessment".

The SDK exposes a single `GateResponse` type with the 5 emit-only fields marked optional (`?:`). The recommended discriminator is `score === null` (Paths 2 + 3) — mirrors `check.run`'s `lastAssessedAt === null` disambiguation pattern. `Object.hasOwn(response, "assessmentId") === false` is an equivalent own-property-only alternative that is ALSO safe under prototype pollution. **Do NOT use `response.assessmentId === undefined`** — a hostile/buggy dep polluting `Object.prototype.assessmentId` makes the `=== undefined` check return false (reads via prototype walk) even in Paths 2 + 3, silently misclassifying them as Path 1.

**`gate` is a STRING ENUM, NOT a boolean.** The kernel emits the literal strings `"pass"` and `"fail"` (route.ts:114, 127, 181). Type-narrowing via equality check: `if (result.gate === "pass") { ... }`. Consumers comparing against `true`/`false` see `false` (string-vs-boolean comparison).

**Type contract is closed; runtime is open (faithful courier).** The SDK's TypeScript type is `gate: "pass" | "fail"` (closed union), but the P2 runtime validator checks `typeof gate === "string"` only — it does NOT reject unknown string values. If a future kernel emits `gate: "warn"` / `gate: "skip"` / etc. before the SDK is bumped, the value round-trips at runtime (typed as the closed union at compile time, but holding the new string at runtime). Consumers using exhaustive type-narrowing (`if (gate === "pass") ... else /* TS: "fail" */`) would misclassify an unknown value as the `"fail"` branch. Kernel-side `gate` emit-sites are drift-pinned via the wire-shape build-round pin, so a kernel extension surfaces in the drift suite before consumer regressions.

**Method name — `client.gate.evaluate(input)`.** The resource is named `gate` (matches the kernel route `/api/v1/gate`); the method is `evaluate`. Mirrors `chat.send` / `decisions.ingest` / `auditLog.export` / `check.run` verb-method convention.

**Multi-permission union auth scope.** The kernel uses `requireApiKeyWithPermission(req, READ_ASSESSMENTS, READ_SYSTEMS)` which is **OR** semantics — a key with EITHER permission (or `ADMIN`, or null/empty permissions for backwards-compat) succeeds. Returns HTTP **401** for no/invalid API key and HTTP **403** only for an authenticated key that has NEITHER required permission. **Same shape as `check.run`** (argument order identical — both list `READ_ASSESSMENTS` first).

**Cross-org systemId collapses to 404.** The kernel's `and(eq id, eq orgId)` followed by `errorResponse("System not found or access denied", 404)` collapses cross-org systemId to 404 — partial mirror of `check.run` (note: gate emits a **LONGER literal string** `"System not found or access denied"` vs check.run's `"System not found"`). Consumers writing defensive error-handling logic must recognize: a 404 may be "not your org" OR "genuine missing UUID".

**SECOND SDK route to pre-validate every Zod closed-spec rule synchronously** (after `check.run`). FOUR pre-validated fields — most extensive pre-validation surface in the SDK to date:
- `systemId`: RFC 4122 hyphenated UUID format (`/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-...-[0-9a-fA-F]{12}$/`, case-insensitive).
- `minScore`: integer in `[0, 100]` inclusive — `typeof === "number"` + `Number.isInteger` (already rejects NaN / ±Infinity) + bounds check.
- `failOnMissingAssessment`: `typeof === "boolean"` (rejects truthy/falsy non-booleans like `1` / `"true"` / `null`).
- `frameworks`: array, ≤20 elements, each string of length 1-100. Snapshotted via `Array.from` for TOCTOU defense.

The SDK's runtime checks always run regardless of TypeScript types — `as any` casts do NOT bypass them. So the kernel's 422 surface only reaches consumers via kernel-side rule changes the SDK hasn't synced to. SDK-side error is a synchronous `TypeError` naming the violating field; kernel-side 422 fallback body is `{success: false, error: "Validation failed.", details: Array<{path: string; message: string}>}` (the field errors live at the `details` ARRAY, NOT a `fieldErrors` keyed map; consumers reading field-by-field errors iterate `apiErr.details.details`).

**TWO silent kernel-side truncations** (each separately load-bearing — the SDK does NOT mask either, faithful courier):
- `assessments` row-population — `.limit(10)` at `route.ts:85`. **TIGHTER than `check.run`'s `.limit(100)`** — gate is strictly less defensive against many-assessment systems. The kernel reads up to 10 assessment rows by `completedAt` DESC and finds the "relevant" completed one via `.find()` over that subset. A system with the most-recent completed assessment in position 11+ would be misclassified as "no assessment found" (falling into Paths 2 or 3).
- `remediationTasks` row-population — `.limit(100)` at `route.ts:154`. If the relevant assessment has >100 unresolved remediation tasks, the 101st+ are invisible. The cap applies BEFORE the filter-to-unresolved step (`status !== "resolved" && status !== "wont_fix"`), so the final `gaps.length` may be less than 100 even at the cap.

**`score` is `null` in no-assessment paths (NOT 0)** — **asymmetric with `check.run`** which used `0` as the default. Gate's `null` preserves the distinction at the type level and is more consumer-friendly for the CI/CD pipeline use case. Consumers should use `score === null` (NOT `score === 0`) to detect Paths 2 + 3. In Path 1, a system that legitimately scored 0 has `score: 0` (NOT null) — distinct from the no-assessment branches.

**In Path 1, `score: 0` is AMBIGUOUS.** The value can mean either (a) the assessment legitimately scored zero, OR (b) the assessment row had a missing / non-numeric `scores.overall` (kernel collapses to 0 via `typeof === "number" ? value : 0` at `route.ts:141`). Consumers CANNOT distinguish these from the wire response alone — both cases emit `score: 0` with all 14 Path-1 fields present. A CI/CD pipeline treating `gate: "fail" && score === 0` as a "broken assessment data" signal would silently miss case (a). Faithful courier; the SDK does NOT mask the kernel's collapse.

**`frameworks` filter is substring + case-insensitive** (kernel uses `aFrameworks.some((af) => af.toLowerCase().includes(f.toLowerCase()))` at `route.ts:94-96`). **Asymmetric with `check.run`'s OR-overlap exact-equality.** Consumer passing `["GDPR"]` matches an assessment with frameworks `["EU_GDPR_2024"]`, `["gdpr_compliance_v2"]`, etc. — looser semantics than `check.run`. Omitting `frameworks` (or passing an empty array) considers all assessments.

**Side effect — `gate.evaluate()` writes one `gate.checked` audit log entry per call** (route.ts:104-111 for the no-assessment paths, route.ts:165-178 for the normal path). **NEW for a read-shaped SDK route** (invariant candidate #53). Properties of the write:
- Org-scoped, hash-chained (per `writeAuditLog`).
- **Time-blocking** but error-tolerant: the kernel uses `await writeAuditLog(...)` which awaits two DB ops (SELECT previous-hash + INSERT new entry). The gate response latency INCLUDES the audit-log write time — a slow audit-log DB will delay every `gate.evaluate()` response. Error semantics ARE non-blocking: `writeAuditLog` wraps its body in a try/catch that swallows + logs errors, so a write FAILURE does NOT fail the gate request.
- NOT counted against `decisionsPerMonth` quota.

Consumers should know each `gate.evaluate(...)` call leaves an auditable trail. Compliance use case, not a bug.

**Two non-obvious defaults applied kernel-side when fields are omitted** (carry-forward #44, non-obvious-default-filter pattern; invariant candidate #52 — closed-default field pre-validation):
- `minScore` defaults to **70** (Zod `.default(70)`). Consumers who omit this field get the implicit threshold of 70.
- `failOnMissingAssessment` defaults to **true** (Zod `.default(true)`). Consumers who omit this get strict behavior (no assessment = fail).

The SDK omits these fields from the request body when the consumer omits them, so the kernel applies its defaults.

**`GateGap` shape.** Path 1's `gaps` array contains `GateGap` rows from `schema.remediationTasks` filtered to `status !== "resolved" && status !== "wont_fix"`:

```ts
interface GateGap {
  requirementKey: string;  // foreign key to the framework requirement
  title: string;
  priority: string;        // open-spec; kernel aggregates "critical" and "high"
  status: string;          // open-spec; filtered to NOT "resolved" / "wont_fix"
}
```

`priority` and `status` are open-spec strings (kernel does NOT enforce closed enums on the underlying `remediationTasks` columns). The kernel's `criticalGaps` / `highGaps` count fields match the literal strings `"critical"` / `"high"` for aggregation; consumers using custom priority taxonomies won't see those aggregated.

```ts
// Basic gate evaluation (defaults: minScore=70, failOnMissingAssessment=true).
const result = await client.gate.evaluate({
  systemId: "11111111-1111-1111-1111-111111111111",
});
if (result.gate === "pass") {
  console.log("OK to deploy — score:", result.score);
} else if (result.score === null) {
  // CRITICAL: score=null means "no completed assessment yet" — NOT
  // "failed with score zero". Use score === null (not score === 0)
  // to detect Paths 2 + 3.
  console.warn("No completed assessment — failing strict-mode gate");
} else {
  // Path 1 fail: emit-only fields are present at runtime, but typed
  // as optional. Use `??` so the example compiles without `!` / `as`.
  console.warn(
    `Score ${result.score} below threshold ${result.minScore};`,
    `${result.gapCount ?? 0} unresolved gaps (${result.criticalGaps ?? 0} critical)`,
  );
  // gaps is a structured GateGap[] — iterate for build-log output.
  for (const gap of result.gaps) {
    console.warn(`  - [${gap.priority}] ${gap.title} (${gap.requirementKey})`);
  }
}

// Strict threshold + framework filter (substring + case-insensitive,
// NOT OR-overlap exact-equality like check.run).
const euOnly = await client.gate.evaluate({
  systemId: "11111111-1111-1111-1111-111111111111",
  minScore: 85,
  frameworks: ["EU_AI_ACT", "ISO_42001"],
});

// Pre-launch / staging — allow missing assessments.
const lenient = await client.gate.evaluate({
  systemId: "11111111-1111-1111-1111-111111111111",
  failOnMissingAssessment: false,
});
// `lenient.gate === "pass"` even without a completed assessment.
```

### `client.batch`

| Method | Endpoint | Returns |
|---|---|---|
| `submit(input, options?)` | `POST /api/v1/batch` | `Promise<BatchSubmitResponse>` |
| `get(id, options?)` | `GET /api/v1/batch/<UUID>` | `Promise<BatchJobStatus>` |

`batch.submit()` submits up to 50 systems for inline classification and/or current-state assessment, returning a per-system success/error envelope. `batch.get(id)` retrieves a batch job's status and results by UUID. **First SDK resource with asymmetric auth between methods on the same resource** — `submit()` requires a key with `CLASSIFY` or `WRITE_ASSESSMENTS` (UNION); `get()` requires only `READ_ASSESSMENTS` (single permission). Multi-method resource (sibling to `chat.send` + `chat.stream`).

**Multi-permission UNION auth on `submit()` — FIRST WRITE-side union pair on the SDK.** Kernel uses `requireApiKeyWithPermission(req, CLASSIFY, WRITE_ASSESSMENTS)` with `Array.some()` semantics (an API key with EITHER permission succeeds). Every prior SDK union has been READ-side — batch is the first WRITE-side union pair. HTTP **401** for no/invalid API key; HTTP **403** for an authenticated key that has NEITHER permission.

**NEW plan-guard 403 surface on `submit()` — distinct from the permission-403.** The kernel calls `requirePlan(org, "hasBatchProcessing")` BEFORE Zod body parsing — a free-tier (or trial-expired non-enterprise) org hits the plan gate FIRST, regardless of body validity. The kernel emits `PlanLimitError` → **403** with the literal wording:

```
The "hasBatchProcessing" feature is not available on your current plan (<plan>). Please upgrade to access this feature.
```

This is **distinct from the permission-403's wording**:

```
API key lacks required permission. Required: classify or write:assessments. Key has: <perms>.
```

The SDK surfaces both uniformly as `AttestryAPIError(403)`. Consumers who need to distinguish "upgrade your plan" from "grant more permissions to your key" should regex-match `apiErr.message`:

```ts
try {
  await client.batch.submit({ jobType: "classify", systemIds: [...] });
} catch (err) {
  if (err instanceof AttestryAPIError && err.status === 403) {
    // Prefer matching the TEMPLATE STEM (kernel-stable) over the
    // FEATURE KEY ("hasBatchProcessing" — internal kernel name that
    // the kernel team may rename). The stem is less likely to drift.
    if (/feature is not available on your current plan/.test(err.message)) {
      // Plan-gate — show "Upgrade to enterprise" CTA
    } else if (/API key lacks required permission/.test(err.message)) {
      // Permission denial — show "Generate a new API key with CLASSIFY" CTA
    }
  }
  throw err;
}
```

A future kernel version adding structured error metadata would unlock a clean discriminator field on `apiErr.details`.

**Single-permission auth on `get()` — DIFFERENT from `submit()`.** Kernel uses `requireApiKeyWithPermission(req, READ_ASSESSMENTS)` with ONLY ONE required permission, NOT a union. Status reads don't need `CLASSIFY` or `WRITE_ASSESSMENTS`. **No plan-guard surface** on `get()` — a free-tier org can `get()` a job submitted earlier on a higher plan that has since downgraded. The submission would have been gated; the read isn't.

**Closed-enum `jobType` — SDK pre-rejects unknown values.** Three valid values via the `BATCH_JOB_TYPES` frozen array:

- `"classify"` — run the rule-based classifier on each system and **persist** the new `riskClassifications` (write-side effect). Per-row `classifications` contains the fresh classification.
- `"assess"` — emit each system's CURRENT `riskClassifications` from the DB (read-only; no write side effect, despite `WRITE_ASSESSMENTS` being a valid auth permission). Per-row `classifications` contains whatever was already on the row (may be `null` if no prior classification).
- `"classify_and_assess"` — same as `"classify"` (the kernel branches `classify || classify_and_assess` together). The two-name distinction is purely semantic for the consumer — both write the new classification and emit it.

> **Forward-compat caveat**: closed-enum SDK pre-rejection (invariant #41) means a deployed SDK against a future kernel that has widened the enum (e.g., added `"verify"`) will reject the new value synchronously with `TypeError` listing the OLD set — even though the kernel would accept it. **To consume a new enum value, upgrade `@attestry/sdk` to a version that includes it.** The drift suite catches the kernel widening at SDK CI build time, so the SDK team is informed; consumers using the old SDK with a newer kernel are not.

**`systemIds` bounds — 1 to 50, each UUID.** The `.min(1)` is **new** vs `gate.evaluate`'s `frameworks` (which allowed empty). The SDK pre-validates empty arrays + oversize arrays + per-element UUID format synchronously. **`Array.from` snapshot** for TOCTOU defense.

**`config.frameworks` — round-trip-only today.** The kernel persists `config` to the row but does NOT use `config.frameworks` in the current inline classification path (`classifySystem()` doesn't take a frameworks filter). The field is forward-compat for future job types. Consumers passing `config.frameworks` today see it round-tripped on `get()` but with no visible effect.

**Partial-success contract — `submit()` resolves successfully even when every row failed.** Inspect `response.failedSystems` (or iterate `response.results` filtering `row.status === "error"`) to detect per-row errors. Top-level failures (auth, plan, rate limit, Zod, cross-org systemId, internal) DO throw `AttestryAPIError`. Mirror of `decisions.bulk`'s contract.

**Per-row discriminator: `row.status === "success"` (closed-enum string match).** Do **NOT** use `row.errorMessage === undefined` or `row.classifications === undefined` as the discriminator — under `Object.prototype.errorMessage = <value>` pollution, the equality check walks the prototype and reads the polluted value, returning false even when the own-property is genuinely absent. The `status` field is the pollution-safe discriminator.

**TWO DISTINCT STATUS ENUMS on the response wire-shape family.** Top-level `response.status` is the **batch-job** status:
- POST emits **`"completed" | "failed"` only** (kernel-computed at handler end — `failed === total ? "failed" : "completed"`).
- GET emits the **WIDER 4-value enum** `"pending" | "processing" | "completed" | "failed"` (DB column pass-through). SDK-submitted jobs always observe `"completed" | "failed"` in practice (already-processed inline), but a GET on a job submitted via a future async path could observe `"pending"` / `"processing"`.

Per-row `response.results[i].status` is the **per-system** status — `"success" | "error"` only, in BOTH POST and GET responses. **Consumers reading `if (response.status === "completed")` are checking a different thing than `if (response.results[0].status === "success")`.**

**Asymmetric 404 shapes between methods.** `submit()` emits 404 with **EMBEDDED variable data** — the comma-joined invalid UUIDs in the message string:

```
Systems not found or not in your organization: 22222222-2222-2222-2222-222222222222, 33333333-3333-3333-3333-333333333333
```

`get()` emits 404 as a **LITERAL string** with no embedded data:

```
Batch job not found
```

The SDK does NOT parse the embedded UUIDs out of `submit()`'s 404 (faithful courier); consumers can regex-match if needed.

**400 surface on `get()` only.** Kernel `isValidUuid(id)` returns false → 400 `"Invalid batch job ID format"`. The SDK pre-validates UUID format synchronously (`TypeError`) — so the 400 reaches consumers only via `as any` casts or a kernel-side switch to a different UUID flavor.

**Side effect — `batch.submit()` writes one `batch.submitted` audit log entry per call** (not counted against `decisionsPerMonth` quota). Org-scoped, hash-chained. **Time-blocking** but error-tolerant: the kernel uses `await writeAuditLog(...)`, which awaits two DB ops (SELECT previous-hash + INSERT new entry). The submit-call response latency **INCLUDES** the audit-log write time. **Error semantics ARE non-blocking**: `writeAuditLog` wraps its body in a try/catch that swallows and logs errors, so a write FAILURE does NOT fail the submit request. `batch.get()` has NO audit-log write — status reads are quiet.

**Two silent kernel-side truncations (faithful courier).** Documented as kernel surface gaps:
- `submit()` `.limit(500)` on the org-systems verification query — orgs with >500 systems may see spurious 404s on batch submissions referencing systems outside the first 500 rows.
- `get()` `.limit(1)` on the batchJobs query — defensive only; the `where` clause already narrows to one row by primary key UUID.

```ts
// Submit a classify job for 3 systems.
const result = await client.batch.submit({
  jobType: "classify",
  systemIds: [
    "11111111-1111-1111-1111-111111111111",
    "22222222-2222-2222-2222-222222222222",
    "33333333-3333-3333-3333-333333333333",
  ],
});
console.log(`Processed ${result.processedSystems}/${result.totalSystems} systems`);
for (const row of result.results) {
  if (row.status === "success") {
    // CRITICAL: branch on `row.status === "success"` (closed-enum
    // string match) — NOT `row.errorMessage === undefined` (which
    // is prototype-pollution unsafe).
    console.log(`OK ${row.systemId}:`, row.classifications);
  } else {
    console.error(`FAIL ${row.systemId}: ${row.errorMessage}`);
  }
}

// Retrieve a job's status.
const job = await client.batch.get(result.id);
if (job.status === "completed") {
  console.log(`Job complete — ${job.processedSystems}/${job.totalSystems}`);
} else if (job.status === "failed") {
  console.error("Batch failed entirely");
} else {
  // "pending" / "processing" — still in flight
  console.log(`Job is ${job.status}`);
}

// Submit with framework filter (round-trip only today — kernel does NOT
// use config.frameworks in the inline classification path).
const futureProofed = await client.batch.submit({
  jobType: "classify_and_assess",
  systemIds: ["11111111-1111-1111-1111-111111111111"],
  config: { frameworks: ["EU_AI_ACT", "ISO_42001"] },
});
// futureProofed.results contains the classifications;
// `futureProofed.config` is NOT in the response (POST omits it
// because it's already in the request body). On GET, `config` IS
// echoed back so callers retrieving by ID can see what was used.
```

### `client.shipGate`

| Method | Wraps | Returns |
|---|---|---|
| `check(input, options?)` | `POST /api/v1/ship-gate/check` | `Promise<ShipGateCheckResponse>` |

`shipGate.check()` returns a 4-shape verdict describing whether a CI/CD build is gated by an in-flight approval-chain execution. Designed for pipeline integration (GitHub Actions / GitLab CI / Buildkite). Sync JSON request/response — no pagination, no streaming.

**Distinct from `gate.evaluate`.** That method is a synchronous compliance-score gate (pass/fail on assessment scores). `shipGate.check()` is a multi-approver workflow gate that asks "is an in-flight approval chain blocking THIS build?". Different lifecycle (gate.evaluate has no state; shipGate has the `gated → released/rejected/timed_out` state machine bound to an approval-chain execution). Different consumer audience (gate.evaluate for CI score gates; shipGate.check for human-approver gates).

**Variadic four-shape response.** The response has `gated: boolean` as ALWAYS-PRESENT anchor and 5 OPTIONAL own-property fields. Discriminate via `gated === true` (closed-enum boolean — pollution-safe), NOT `reason === undefined` (prototype-pollution-unsafe — reads via prototype walk):

- **Shape A — no gate exists**: `{ gated: false }` (1 field). Default-permissive short-circuit — no `ship_gates` row for this `(systemId, attestationId)` tuple. The gate is opt-in; consumers who never create a gate never block a build.
- **Shape B — released**: `{ gated: false, state: "released", executionId, chainId }` (4 fields). The approval chain approved the deployment.
- **Shape C — rejected / timed_out**: `{ gated: true, reason: "rejected" | "timed_out", approvers_pending: [], state, executionId, chainId }` (6 fields). The approval chain went terminal in a build-blocking state. `approvers_pending` is always `[]` (nobody is pending on a closed chain).
- **Shape D — gated awaiting approvers**: `{ gated: true, reason: "awaiting_approvers", approvers_pending: [<UUIDs>], state: "gated", executionId, chainId }` (6 fields). The approval chain is in-flight; `approvers_pending` lists the userIds still owed a decision (pool-order, post-decided filtering).

**Wire-shape vs TypeScript-narrowed.** The optional own-property fields (`reason`, `approvers_pending`, `state`, `executionId`, `chainId`) are ABSENT from the JSON wire on shapes that don't emit them (JSON has no `undefined`); TypeScript reads them as `<type> | undefined` due to the `?:` marker. For own-property detection inside the SDK, the response validator uses a module-load `Object.hasOwn` snapshot (pollution-safe at the validator boundary). For CONSUMER-side detection, branch on `result.gated === true | false` first — that's the only ALWAYS-present pollution-safe boolean. `Object.hasOwn(result, "state")` on the CONSUMER side relies on the live global, which is itself subject to override by a hostile dep (only the SDK's internal snapshot is hardened).

**`approvers_pending` is SNAKE_CASE on the wire.** Asymmetric with the rest of the SDK's camelCase response surface — the kernel emits the literal field name `approvers_pending` (master plan spec contract line 5369). Consumers must use the snake_case spelling to read the field.

**Type contract is closed; runtime is open (faithful courier).** The SDK's TypeScript types are `ShipGateReasonCode = "awaiting_approvers" | "rejected" | "timed_out"` (3 values) and `ShipGateState = "gated" | "released" | "rejected" | "timed_out"` (4 values), but the P2 runtime validator checks `typeof === "string"` only — it does NOT reject unknown string values. If a future kernel emits a new reason / state value before the SDK is bumped, the value round-trips at runtime. Mirror of `gate.evaluate`'s `gate: "pass" | "fail"` pattern.

**Method name — `client.shipGate.check(input)`.** The resource is named `shipGate` (matches the kernel route `/api/v1/ship-gate/`); the method is `check` (matches the kernel endpoint `/check`). Chosen over `run` / `evaluate` because the kernel endpoint is named `/check` and `check.run` already occupies the `.run` verb at the SDK level.

**Multi-permission union auth scope.** The kernel uses `requireApiKeyWithPermission(req, READ_SYSTEMS, READ_ASSESSMENTS)` with `Array.some()` semantics (a key with EITHER permission succeeds). Returns HTTP **401** for no/invalid API key and HTTP **403** for an authenticated key that has NEITHER permission. **NOTE — argument order is READ_SYSTEMS FIRST** (asymmetric with `check.run` and `gate.evaluate` which list `READ_ASSESSMENTS` first). `Array.some()` is order-insensitive at runtime, but a kernel-side error message would echo the order declared.

**Fourth SDK route to pre-validate every Zod closed-spec rule synchronously** (after `check.run`, `gate.evaluate`, and `batch.submit`). Two pre-validated fields:
- `systemId`: RFC 4122 hyphenated UUID format (`/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-...-[0-9a-fA-F]{12}$/`, case-insensitive).
- `attestationId`: non-empty string of length 1-256 (matches kernel constant `MAX_ATTESTATION_ID_LENGTH = 256` at `src/lib/workflow/ship-gates.ts:106`; drift-pinned).

The SDK's runtime checks always run regardless of TypeScript types — `as any` casts do NOT bypass them. So the kernel's 422 surface only reaches consumers via kernel-side rule changes the SDK hasn't synced to. SDK-side error is a synchronous `TypeError` naming the violating field; kernel-side 422 fallback body is `{success: false, error: "Validation failed.", details: Array<{path: string; message: string}>}` (the field errors live at the `details` ARRAY, NOT a `fieldErrors` keyed map; consumers reading field-by-field errors iterate `apiErr.details.details`).

**Documented kernel-side cascade-gap surfaces — TWO distinct paths.**
1. **Execution-missing → HTTP 404** (named-error path). The kernel maps `ShipGateExecutionNotFoundError` to 404 at route.ts:97-99. Thrown only when a `ship_gates` row references an `executionId` whose row is missing in `approval_chain_executions`.
2. **Chain-missing → HTTP 500 (scrubbed)** (plain-Error path). A SEPARATE defensive branch in `checkShipGate` throws a plain `Error` (NOT a named ship-gate class) when a ship_gate → execution → chain reference is broken on the LAST hop. The route's catch block falls through to `internalErrorResponse → 500` with the scrubbed message "An internal error occurred. Please try again later." The caller cannot distinguish this cascade-gap from any other internal error via the HTTP status alone.

Both branches are unreachable in normal operation (RESTRICT FK + filter-by-orgId); both documented as "only reachable via direct DB intervention or a cascade-behavior gap". Faithful courier: the SDK surfaces whichever status the kernel chose. SIEM consumers running cascade-gap-404 filters should know the second branch hides as 500 (NOT 404).

**`writeAuditLog` side effect — every `shipGate.check()` call writes one audit-log entry** with `action: "ship_gate.checked"` and `resourceType: "ship_gate"` (route.ts:73-87; both strings drift-pinned). SIEM / observability consumers keying off either field for filter setup should depend on both staying stable. Properties of the write:
- Org-scoped, hash-chained.
- **Time-blocking** but error-tolerant: the kernel uses `await writeAuditLog(...)` which awaits two DB ops (SELECT previous-hash + INSERT new entry). The check response latency INCLUDES the audit-log write time — a slow audit-log DB will delay every `shipGate.check()` response. Error semantics ARE non-blocking: a write FAILURE does NOT fail the check request.
- NOT counted against `decisionsPerMonth` quota.

Invariant candidate #53 carry-forward (matches `gate.evaluate`'s pattern).

**Kernel-side 15-second timeout** (`maxDuration = 15`). **Same as `gate.evaluate`'s 15s; tighter than `auditLog.verifyChain`'s 30s.** Ship-gate's transaction has a SELECT FOR UPDATE + up to 4 follow-up reads + an optional UPDATE on the reconcile path, and the kernel team budgeted 15s as sufficient for the worst case. The SDK does NOT enforce a client-side timeout (consumers manage via `options.signal`); CI pipeline timeouts should budget relative to this cap.

**Reconciliation-on-read inside transaction.** When the linked `approval_chain_executions` row has gone terminal but the `ship_gates` row still says `gated`, the kernel advances the gate to the corresponding terminal state inside `SELECT … FOR UPDATE`. The SDK does NOT observe the reconciliation step — only the post-reconciliation shape. A consumer calling `check()` twice in quick succession on a chain that just completed sees the gated-state shape on call 1 (if reconciliation hadn't fired yet) and the terminal shape on call 2. Faithful courier; documented kernel behavior.

```ts
// Basic ship-gate check (typical CI usage)
const verdict = await client.shipGate.check({
  systemId: "11111111-1111-1111-1111-111111111111",
  attestationId: "build-1234",
});
if (verdict.gated) {
  // Shape C or D — build must block.
  if (verdict.reason === "awaiting_approvers") {
    // Shape D — list pending approvers in PR comment. Fall back
    // gracefully if the array is missing (forward-compat) or empty
    // (kernel emitted no UUIDs for some reason).
    const approvers = verdict.approvers_pending?.join(", ") || "(unknown)";
    console.error(`Awaiting approval from ${approvers}`);
  } else {
    // Shape C — rejected or timed_out.
    console.error(`Build blocked: ${verdict.reason}`);
  }
  process.exit(1);
}
// Shape A (no gate) or Shape B (released) — build proceeds.
console.log("OK to deploy.");

// Discriminate Shape A vs Shape B (no-gate vs released)
const verdict2 = await client.shipGate.check({
  systemId: "11111111-1111-1111-1111-111111111111",
  attestationId: "build-1234",
});
if (!verdict2.gated) {
  if (verdict2.state === "released") {
    console.log(`Approved (execution: ${verdict2.executionId})`);
  } else {
    // No state field → Shape A (no gate exists).
    console.log("No gate configured for this build.");
  }
}
```

### `client.abacPolicies`

| Method | Wraps | Returns |
|---|---|---|
| `list(options?)` | `GET /api/v1/abac-policies` | `Promise<AbacPoliciesListResponse>` |
| `create(input, options?)` | `POST /api/v1/abac-policies` | `Promise<AbacPolicy>` |
| `retrieve(id, options?)` | `GET /api/v1/abac-policies/[id]` | `Promise<AbacPolicy>` |
| `update(id, input, options?)` | `PATCH /api/v1/abac-policies/[id]` | `Promise<AbacPolicy>` |
| `delete(id, options?)` | `DELETE /api/v1/abac-policies/[id]` | `Promise<AbacPolicy>` |

`abacPolicies.list()` returns up to 200 ABAC policies for the caller's org, ordered by `priority` ASC. Eighth non-decisions resource on the SDK; the first method of the five-method `abacPolicies` CRUD cluster (`list` / `create` / `retrieve` / `update` / `delete`).

**Dual-auth admin scope.** The kernel route uses `requireSessionOrApiKey(request, { sessionRoles: ["admin"], apiKeyPermissions: [API_KEY_PERMISSIONS.ADMIN] })`. The dual-auth helper routes by request header presence: an `x-api-key` header (even empty-string) takes the api-key path; absent header takes the session path. The SDK's transport always sends `x-api-key`, so the api-key path is the only one reachable from SDK consumers. NOT the first SDK use of dual-auth — `auditLog.export` (session 12) and `decisions.verifyChain` (session 19) already use it. The novelty here is that this is the first SDK CRUD cluster under dual-auth admin.

**Status-code surface — 401 AND 403 distinguished.** The kernel returns HTTP **401** for: no `x-api-key` header, empty `x-api-key` header (`""`), invalid key (no matching `apiKeys` row), expired key. The kernel returns HTTP **403** for: a valid api-key in the org whose `permissions` column does NOT include `ADMIN` (error message: `"API key lacks required permission. Required: admin. Key has: ..."`). Pin BOTH branches separately. Verified by reading the dual-auth middleware end-to-end (`src/lib/middleware/auth.ts:96-110` + `src/lib/middleware/permissions.ts:35-66`). Established invariant: **dual-auth admin routes surface BOTH 401 AND 403** — `auditLog.export` shares this exact surface. (Corrected session-22 hostile review #2: the prior "`auditLog.export` returns 401 for both" framing of carry-forward invariant #42 mis-read the kernel test's mocked `AuthError(401)`; the real `requireSessionOrApiKey` middleware returns 403 for the insufficient-permission case.)

**No pagination.** `count` is `items.length` (NOT a total org count beyond the materialized page). Server-side `listAbacPolicies` caps at `MAX_POLICIES_PER_ORG_FETCH = 200` (`src/lib/auth/abac-policies.ts:113`). Orgs with >200 policies see only the LOWEST 200 by priority ASC. Documented kernel surface gap — invariant #50 (silent kernel-side truncation enumeration). The SDK does NOT auto-paginate (no cursor anchor exists to follow).

**No `writeAuditLog` side effect** — `.list()` is quiet (asymmetric with `gate.evaluate` / `batch.submit` / `shipGate.check` which all write entries). `.create()` writes an `abac_policy.create` entry; `.update()` / `.delete()` write `abac_policy.update` / `abac_policy.delete` entries; `.retrieve()` is also quiet.

**`condition` field is a recursive AST** mirroring the kernel grammar (8 leaf ops + 3 compound ops):
- Leaf ops: `eq` / `ne` / `in` / `notIn` / `exists` / `notExists` / `attrEq` / `attrNe`.
- Compound ops: `and` / `or` / `not`.
- Attribute paths are rooted at `principal.<...>` or `resource.<...>` only (server-side `SAFE_PATH_RE` rejects `__proto__` / `constructor` / `prototype`).
- Server-side validation enforces depth ≤ 8, clauses ≤ 32 per compound, values ≤ 64 per list, total nodes ≤ 1000 per tree. The SDK does NOT re-validate the AST after the kernel returns it (faithful courier on the response side; `.create()` defers condition validation to the server canonical validator).

**Wire-shape note — dates are ISO-8601 strings.** The kernel's TypeScript declares `createdAt: Date` / `updatedAt: Date` (Drizzle `timestamp` column), but `NextResponse.json` serializes Dates via `JSON.stringify` → ISO-8601 string. The SDK type is `string` to reflect the wire reality. Both sides drift-pinned independently.

**`description` and `createdByUserId` are `string | null`** (NOT `undefined`). The kernel uses `?? null` coalesce server-side; both fields are ALWAYS present on the wire with value `null` when unset.

**Response shape** (`AbacPoliciesListResponse`):

| Field | Type | Notes |
|---|---|---|
| `items` | `AbacPolicy[]` | Up to 200 policies; ordered by `priority` ASC. Empty array on no-policies. |
| `count` | `number` | Equals `items.length`; NOT a total org count. |

**Per-row shape** (`AbacPolicy`):

| Field | Type | Notes |
|---|---|---|
| `id` | `string` | UUID of the policy row. |
| `orgId` | `string` | Always the caller's `orgId`. |
| `name` | `string` | UNIQUE per `(orgId, name)` server-side. |
| `description` | `string \| null` | Always own-present; `null` when unset. |
| `resource` | `AbacPolicyResource` | Closed-enum (10 values). |
| `action` | `AbacPolicyAction` | Closed-enum (5 values). |
| `effect` | `AbacPolicyEffect` | `"allow"` or `"deny"`. |
| `condition` | `AbacCondition` | Recursive AST. |
| `priority` | `number` | Integer [0, 1000]. |
| `enabled` | `boolean` | Per-policy enable flag. |
| `createdByUserId` | `string \| null` | UUID; `null` for fixture rows or when creator was deleted. |
| `createdAt` | `string` | ISO-8601. |
| `updatedAt` | `string` | ISO-8601. |

```ts
// List all ABAC policies for the caller's org
const { items, count } = await client.abacPolicies.list();
console.log(`${count} policies in this org:`);
for (const policy of items) {
  console.log(`  ${policy.priority} ${policy.effect} ${policy.action} ${policy.resource}: ${policy.name}`);
}

// Inspect a policy's condition AST
const ownerOnly = items.find((p) => p.name === "owner-only");
if (ownerOnly && ownerOnly.condition.op === "attrEq") {
  console.log(`Compares ${ownerOnly.condition.left} === ${ownerOnly.condition.right}`);
}

// Branch on compound conditions
function describe(c: AbacCondition): string {
  switch (c.op) {
    case "and": return `(${c.clauses.map(describe).join(" AND ")})`;
    case "or": return `(${c.clauses.map(describe).join(" OR ")})`;
    case "not": return `NOT (${describe(c.clause)})`;
    case "eq": return `${c.attr} == ${JSON.stringify(c.value)}`;
    case "ne": return `${c.attr} != ${JSON.stringify(c.value)}`;
    case "in": return `${c.attr} IN [${c.values.join(", ")}]`;
    case "notIn": return `${c.attr} NOT IN [${c.values.join(", ")}]`;
    case "exists": return `${c.attr} EXISTS`;
    case "notExists": return `${c.attr} NOT EXISTS`;
    case "attrEq": return `${c.left} == ${c.right}`;
    case "attrNe": return `${c.left} != ${c.right}`;
  }
}
```

#### `abacPolicies.create(input, options?)` — create a new ABAC policy

`abacPolicies.create()` creates a new ABAC policy in the caller's org and returns the inserted row (HTTP 201).

**FIRST SDK route with HTTP 201 success status.** Distinct from the rest of the SDK's 200-OK pattern; the transport unwraps the `{success:true, data}` envelope on any 2xx response so consumers receive the created row directly.

**FIRST SDK route with HTTP 409 Conflict.** The `(orgId, name)` unique constraint trips `AbacPolicyNameConflictError` at the DB layer; the kernel maps to 409 with `An ABAC policy named "<name>" already exists in this organization.`. Branch on `err.status === 409` to render a specific "name taken" UX.

**FIRST SDK route with three-way 422 fan-out — distinct wire shapes per error class:**

1. **`BodyParseError`** (most common — Zod schema rejection via `parseBody`): `{ success: false, error: "Validation failed.", details: Array<{ path: string, message: string }> }`.
2. **`ZodError`** (DEFENSIVE — DEAD on happy path; `parseBody` catches Zod and converts to `BodyParseError`. Arm exists as defense-in-depth): `{ success: false, error: "Validation failed.", details: ZodIssue[] }` (richer — includes `code`, `expected`, `received`).
3. **`AbacPolicyValidationError`** (REACHABLE — server-side canonical AST validation): `{ success: false, error: "ABAC policy validation failed: <messages>", details: { errors: string[] } }`. Raised when the condition AST violates depth / clause / value-list / total-node budgets or has unknown ops / malformed attr paths.

SDK surfaces all three uniformly as `AttestryAPIError(422)`. Consumers inspect `err.details.details` to discriminate:

```ts
try {
  await client.abacPolicies.create({...});
} catch (err) {
  if (err instanceof AttestryAPIError && err.status === 422) {
    // err.details is the FULL parsed wire body; the kernel's inner
    // details field nests one level deep.
    const wireBody = err.details as { details: unknown };
    const inner = wireBody.details;
    if (Array.isArray(inner)) {
      // BodyParseError / ZodError — iterate {path, message} entries.
    } else if (inner && typeof inner === "object" &&
               Array.isArray((inner as {errors?: unknown}).errors)) {
      // AbacPolicyValidationError — iterate AST error strings.
    }
  }
}
```

**FIRST SDK route with PARTIAL Zod pre-validation.** The SDK pre-validates 7 closed-spec fields synchronously (name length, description length-or-null, resource/action/effect closed-enums, priority int+range, enabled boolean) but defers the recursive `condition` AST validation to the kernel's canonical validator. **Fifth SDK route to pre-validate Zod closed-spec rules** (after `check.run`, `gate.evaluate`, `batch.submit`, `shipGate.check`). 422 reaches consumers ONLY via (a) kernel-side rule changes the SDK hasn't synced to, OR (b) condition AST violations.

**Default-applied fields** (per invariant #52 — SDK OMITS from body when consumer omits; kernel applies its default):
- `effect` defaults to `"allow"`.
- `priority` defaults to `100`.
- `enabled` defaults to `true`.
- `description` defaults to `null`.

Pass these explicitly to override. Pass `null` for description to set it explicitly; the SDK preserves the difference between "omitted" and "explicitly null".

**`writeAuditLog` side effect — every successful `.create()` call writes one audit-log entry** with `action: "abac_policy.create"` and `resourceType: "abac_policy"`. Audit log is NOT written on failed create (Zod / canonical validation / name conflict all surface BEFORE writeAuditLog).

**Kernel-side 30-second timeout** (`maxDuration = 30`). Same as `.list()` and `auditLog.export`; looser than `gate.evaluate` / `shipGate.check`'s 15s.

**Status-code surface — 401 AND 403 distinguished** (same dual-auth admin surface as `.list()`). Pin BOTH branches.

**Input shape** (`AbacPolicyCreateInput`):

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | `string` | yes | 1-128 chars. UNIQUE per `(orgId, name)`. |
| `resource` | `AbacPolicyResource` | yes | Closed-enum (10 values). |
| `action` | `AbacPolicyAction` | yes | Closed-enum (5 values). |
| `condition` | `AbacCondition` | yes | Recursive AST (validated server-side). |
| `description` | `string \| null` | optional | Max 2000 chars. Pass `null` to set explicitly. |
| `effect` | `AbacPolicyEffect` | optional | `"allow"` or `"deny"`. Defaults to `"allow"`. |
| `priority` | `number` | optional | Integer [0, 1000]. Defaults to `100`. |
| `enabled` | `boolean` | optional | Defaults to `true`. |

```ts
// Create a simple "owner can edit own assessments" policy
const policy = await client.abacPolicies.create({
  name: "owner-can-edit-own",
  description: "Owners can edit their own assessments.",
  resource: "assessments",
  action: "update",
  effect: "allow",
  condition: {
    op: "attrEq",
    left: "principal.id",
    right: "resource.ownerId",
  },
  priority: 100,
  enabled: true,
});
console.log(`Created policy ${policy.id}`);

// Catch name-conflict (HTTP 409)
try {
  await client.abacPolicies.create({...});
} catch (err) {
  if (err instanceof AttestryAPIError && err.status === 409) {
    // Show "name taken" UX
  }
}

// Create with all defaults (kernel applies effect=allow, priority=100,
// enabled=true; SDK omits these fields from the body)
const minimal = await client.abacPolicies.create({
  name: "deny-archived-systems-delete",
  resource: "systems",
  action: "delete",
  condition: {
    op: "and",
    clauses: [
      { op: "eq", attr: "resource.archived", value: true },
      { op: "ne", attr: "principal.role", value: "admin" },
    ],
  },
});
```

#### `abacPolicies.retrieve(id, options?)` — retrieve one ABAC policy

`abacPolicies.retrieve()` fetches one ABAC policy by id from the caller's org and returns the policy row (HTTP 200). `id` is a path parameter — `GET /api/v1/abac-policies/<id>`.

**FIRST `abacPolicies` method with a UUID path segment.** `.list()` / `.create()` hit the collection path with no segment; `.retrieve()` / `.update()` / `.delete()` take an `id` path parameter.

**UUID pre-validation.** The SDK pre-validates `id` against `UUID_REGEX` (RFC 4122 hyphenated, case-insensitive) synchronously — a missing / non-string / empty / non-UUID `id` throws `TypeError` BEFORE any fetch is issued. The kernel's own `badId` check would return HTTP 400 `"Invalid policy id."`, but the SDK pre-empts it: that 400 is reachable only via an `as any` cast or a kernel-side id-flavor change. Mirror of `batch.get`.

**No `encodeURIComponent` / URIError defense on the path segment.** A string matching `UUID_REGEX` is ASCII hex digits + hyphens — URL-safe verbatim, and incapable of producing a lone UTF-16 surrogate — so the validated `id` is interpolated into the path raw. Asymmetric with `decisions.retrieve`, whose free-form `id` needs `encodePathSegment` (path-traversal + URIError defenses).

**404 surface.** The kernel's `getAbacPolicyById(orgId, id)` returns `null` for a missing id OR a cross-org id (the `eq(orgId)` clause silently filters policies in other orgs); the GET handler maps `null` to `errorResponse("ABAC policy not found.", 404)` — an **inline literal message**. Distinct from `.update()` / `.delete()`'s 404, which is raised by `AbacPolicyNotFoundError` with the id-embedded message `"ABAC policy <id> not found in this organization."`.

**No `writeAuditLog` side effect** — `.retrieve()` is a quiet read (same as `.list()`).

**Kernel-side 30-second timeout** (`maxDuration = 30`). Same as `.list()` and `.create()`.

**Status-code surface — 401 AND 403 distinguished** (same dual-auth admin surface as `.list()` / `.create()`). Pin BOTH branches.

Errors: `TypeError` (synchronous — invalid `id`; no fetch issued); `AttestryAPIError` with status 429 (rate limit, auto-retried; per-IP key `abac-policies-get:${ip}` against `assessmentLimiter`), 401, 403, 404, 400 (SDK-pre-empted), or 500; `AttestryError` (request aborted, or P2 response-shape failure); `AttestryAPIError` (P3 — wrong Content-Type). The response row is validated by the shared `validateAbacPolicy` (all 13 `AbacPolicy` fields, prototype-pollution-safe).

```ts
// Retrieve a policy by id
const policy = await client.abacPolicies.retrieve(
  "550e8400-e29b-41d4-a716-446655440000",
);
console.log(`${policy.effect} ${policy.action} ${policy.resource}: ${policy.name}`);

// Handle not-found (HTTP 404)
try {
  return await client.abacPolicies.retrieve(id);
} catch (err) {
  if (err instanceof AttestryAPIError && err.status === 404) {
    return null; // policy doesn't exist (or belongs to another org)
  }
  throw err;
}
```

#### `abacPolicies.update(id, input, options?)` — update one ABAC policy

`abacPolicies.update()` partial-updates one ABAC policy by id and returns the **updated row** — the policy as it exists AFTER the patch is applied (HTTP 200). `id` is a path parameter — `PATCH /api/v1/abac-policies/<id>`.

**SECOND SDK method using the HTTP `PATCH` verb** (`incidents.update` is the first). The richest method of the cluster — 6 catch arms, a three-way 422 fan-out, 409, 404, and empty-patch pre-validation.

**Partial update — every input field is optional.** Patch only the fields you want to change; omitted fields keep their current value. The SDK builds the request body from the present-and-not-`undefined` fields only, so an omitted field (or an explicit `field: undefined`) is left out of the body and the kernel leaves that column untouched.

**Empty-patch pre-validation.** The kernel's `updateAbacPolicySchema` ends in a `.refine()` rejecting a body with NO updatable field (`"PATCH body must include at least one updatable field"`). The SDK pre-rejects an empty patch — `update(id, {})`, an all-`undefined` patch, or a patch carrying ONLY unknown keys — synchronously with a `TypeError` (no fetch issued).

**`description: null` clears the description.** Passing `description: null` is a valid non-empty patch — the kernel persists `null`. An explicit `description: undefined` is treated as omission (the SDK preserves the "omitted" vs "explicitly null" distinction, same as `.create()`).

**UUID pre-validation.** Same as `.retrieve()` / `.delete()`: `id` is pre-validated against `UUID_REGEX` synchronously via the shared `assertValidPolicyId` helper — a missing / non-string / empty / non-UUID `id` throws `TypeError` before any fetch. The kernel `badId` 400 is SDK-pre-empted. No `encodeURIComponent` / URIError defense — a validated UUID is interpolated raw.

**Partial Zod pre-validation.** The closed-spec fields that ARE present are pre-validated synchronously (name length, description length-or-null, resource/action/effect closed-enums, priority int+bounds, enabled boolean); a present `condition` is checked only as a non-null object, deferring the recursive AST grammar to the kernel's canonical validator. Mirror of `.create()`'s partial pre-validation — but every field is optional.

**Three-way 422 fan-out — same distinct wire shapes as `.create()`:** `BodyParseError` (`details: Array<{path, message}>`), `ZodError` (DEFENSIVE — DEAD on the happy path; `details: ZodIssue[]`), `AbacPolicyValidationError` (canonical AST validation; `details: { errors: string[] }`). SDK surfaces all three uniformly as `AttestryAPIError(422)` — discriminate via `err.details` (see the `.create()` 422 example).

**HTTP 409 Conflict.** Patching `name` to a value already used by a sibling policy in the org trips the `(orgId, name)` unique constraint → `AbacPolicyNameConflictError` → 409.

**HTTP 404.** The kernel's `updateAbacPolicy` throws `AbacPolicyNotFoundError` when the `(id, orgId)`-scoped lookup misses (a missing id OR a cross-org id). **The message is id-embedded** — `"ABAC policy <id> not found in this organization."` — same shape as `.delete()`'s 404 (distinct from `.retrieve()`'s inline message).

**6 named-error catch arms — the LARGEST on the SDK**, in order: `AuthError`, `BodyParseError`, `ZodError`, `AbacPolicyValidationError`, `AbacPolicyNameConflictError`, `AbacPolicyNotFoundError`. Everything else falls to the 500 catchall.

**`writeAuditLog` side effect** — every successful `.update()` writes one `abac_policy.update` audit-log entry (`resourceType: "abac_policy"`); the entry records the changed field names plus a structured `before`/`after` diff. `await`-ed, error-tolerant, NOT counted against any quota. The audit log is NOT written on a failed update (404 / 409 / 422 surface before the write).

**Kernel-side 30-second timeout** (`maxDuration = 30`). Same as `.list()` / `.create()` / `.retrieve()` / `.delete()`.

**Status-code surface — 401 AND 403 distinguished** (same dual-auth admin surface as the other four cluster methods). Pin BOTH branches.

**Input shape** (`AbacPolicyUpdateInput`) — every field optional; at least one required (empty-patch pre-validation):

| Field | Type | Notes |
|---|---|---|
| `name` | `string` | 1-128 chars. UNIQUE per `(orgId, name)` — a collision is HTTP 409. |
| `description` | `string \| null` | Max 2000 chars. Pass `null` to CLEAR; `undefined` is omission. |
| `resource` | `AbacPolicyResource` | Closed-enum (10 values). |
| `action` | `AbacPolicyAction` | Closed-enum (5 values). |
| `effect` | `AbacPolicyEffect` | `"allow"` or `"deny"`. |
| `condition` | `AbacCondition` | Recursive AST (validated server-side). |
| `priority` | `number` | Integer [0, 1000]. |
| `enabled` | `boolean` | Per-policy enable flag. |

Errors: `TypeError` (synchronous — invalid `id`, `input` not a non-null object, a present field is the wrong type / out of range / an unknown closed-enum value, OR an empty patch; no fetch issued); `AttestryAPIError` with status 429 (rate limit, auto-retried; per-IP key `abac-policies-patch:${ip}` against `assessmentLimiter`), 401, 403, 404 (id-embedded message), 409, 422, 400 (SDK-pre-empted), or 500; `AttestryError` (request aborted, or P2 response-shape failure on the updated row); `AttestryAPIError` (P3 — wrong Content-Type). The updated row is validated by the shared `validateAbacPolicy` (all 13 `AbacPolicy` fields, prototype-pollution-safe).

```ts
// Patch a single field — the rest of the policy is unchanged
const updated = await client.abacPolicies.update(
  "550e8400-e29b-41d4-a716-446655440000",
  { enabled: false },
);
console.log(`Policy "${updated.name}" is now ${updated.enabled ? "on" : "off"}`);

// Clear a description (pass null) and re-prioritize in one patch
await client.abacPolicies.update(id, { description: null, priority: 10 });

// Catch a name-conflict (HTTP 409)
try {
  await client.abacPolicies.update(id, { name: "taken-name" });
} catch (err) {
  if (err instanceof AttestryAPIError && err.status === 409) {
    // another policy in the org already uses that name
  }
}
```

#### `abacPolicies.delete(id, options?)` — delete one ABAC policy

`abacPolicies.delete()` deletes one ABAC policy by id from the caller's org and returns the **deleted row** — the policy as it existed immediately before deletion (HTTP 200). `id` is a path parameter — `DELETE /api/v1/abac-policies/<id>`.

**Returns the deleted row, NOT `void`.** The kernel's DELETE handler emits `successResponse(row, 200)` carrying the just-deleted `AbacPolicy`, so a caller can log / audit / render an undo affordance with the full prior state. Do NOT expect `Promise<void>` or a `{ deleted: true }` envelope — the resolved value is a complete 13-field `AbacPolicy`.

**FIRST SDK method using the HTTP `DELETE` verb.** Every prior SDK route is GET / POST / PATCH. The transport's `method` union already includes `"DELETE"`, so no new primitive was needed.

**UUID pre-validation.** Same as `.retrieve()`: the SDK pre-validates `id` against `UUID_REGEX` (RFC 4122 hyphenated, case-insensitive) synchronously via the shared `assertValidPolicyId` helper — a missing / non-string / empty / non-UUID `id` throws `TypeError` BEFORE any fetch is issued. The kernel's `badId` 400 `"Invalid policy id."` is SDK-pre-empted. **No `encodeURIComponent` / URIError defense** — a validated UUID is ASCII hex + hyphens, interpolated into the path raw (mirror of `batch.get`).

**404 surface.** The kernel's `deleteAbacPolicy(orgId, id)` throws `AbacPolicyNotFoundError` when the `(id, orgId)`-scoped delete matches zero rows (a missing id OR a cross-org id — the `eq(orgId)` clause scopes the delete). The DELETE handler maps it to `errorResponse(error.message, 404)`. **The message is id-embedded** — `"ABAC policy <id> not found in this organization."` — distinct from `.retrieve()`'s INLINE `"ABAC policy not found."`.

**`writeAuditLog` side effect — every successful `.delete()` call writes one `abac_policy.delete` audit-log entry** (`resourceType: "abac_policy"`). The entry's `details` records the deleted policy's `name` / `resource` / `action` / `effect` for forensics. The write is org-scoped + hash-chained, `await`-ed (so `.delete()` latency includes the audit write) but error-tolerant (a write failure does NOT fail the request) and is NOT counted against any quota. The audit log is NOT written on a failed delete — a 404 surfaces BEFORE the `writeAuditLog` call.

**Kernel-side 30-second timeout** (`maxDuration = 30`). Same as `.list()` / `.create()` / `.retrieve()`.

**Status-code surface — 401 AND 403 distinguished** (same dual-auth admin surface as `.list()` / `.create()` / `.retrieve()`). Pin BOTH branches.

Errors: `TypeError` (synchronous — invalid `id`; no fetch issued); `AttestryAPIError` with status 429 (rate limit, auto-retried; per-IP key `abac-policies-delete:${ip}` against `assessmentLimiter`), 401, 403, 404 (id-embedded message), 400 (SDK-pre-empted), or 500; `AttestryError` (request aborted, or P2 response-shape failure on the deleted row); `AttestryAPIError` (P3 — wrong Content-Type). The deleted row is validated by the shared `validateAbacPolicy` (all 13 `AbacPolicy` fields, prototype-pollution-safe).

```ts
// Delete a policy and log the prior state
const deleted = await client.abacPolicies.delete(
  "550e8400-e29b-41d4-a716-446655440000",
);
console.log(`Deleted "${deleted.name}" (${deleted.effect} ${deleted.action} ${deleted.resource})`);

// Treat a not-found delete as idempotent success
try {
  await client.abacPolicies.delete(id);
} catch (err) {
  if (err instanceof AttestryAPIError && err.status === 404) {
    // already gone — fine for an idempotent caller
  } else {
    throw err;
  }
}
```

## Public enums

```ts
import {
  INCIDENT_TYPES,
  SEVERITIES,
  FRAMEWORK_CODES,
  CHAT_MESSAGE_ROLES,
  DECISION_STREAM_EVENT_TYPES,
  AUDIT_LOG_EXPORT_FORMATS,
  REGULATORY_CHANGE_SEVERITIES,
  REGULATORY_CHANGE_STATUSES,
  BATCH_JOB_TYPES,
  BATCH_JOB_STATUSES,
} from "@attestry/sdk";
import type {
  IncidentType,
  Severity,
  FrameworkCode,
  ChatMessageRole,
  DecisionStreamEventType,
  AuditLogExportFormat,
  RegulatoryChangeSeverity,
  RegulatoryChangeStatus,
  BatchJobType,
  BatchJobStatusValue,
} from "@attestry/sdk";

// Wire-shape types are also re-exported (e.g., for consumers
// writing typed helpers around the SDK output):
import type {
  BatchSubmitInput,
  BatchSubmitResponse,
  BatchJobStatus,
  BatchSystemResult,
  BatchConfig,
} from "@attestry/sdk";
```

These are duplicated from the kernel intentionally — the SDK's public contract must not depend on internal kernel modules. A drift-detection pin in the kernel asserts the arrays match (any divergence fails CI).

## Roadmap

Tracked for the next release:
- `bundles` resource (after evidence-bundle ships)
- `webhooks` resource — BLOCKED on a kernel-side prereq: webhook routes today live at `/api/webhooks/*` with `requireAuth` (Supabase-session-only); needs dual-auth + WEBHOOK_MANAGE permission to be SDK-callable.
- `apiKeys` resource
- Ed25519 signing of `decisions.export` trailers (Prompt 1 — kernel prereq; today the trailer's `signing` field is the literal string `"unsigned-prompt-1-blocked"`)
- HTTP-level idempotency-key support → retry on 5xx (kernel prereq)
- Browser support
- Python SDK port (Checkpoint H prereq)

## License

Apache-2.0
