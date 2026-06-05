import { afterEach, describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../../client.js";
import { AttestryAPIError, AttestryError } from "../../errors.js";
import type {
  // Result-shape type import — pinned at compile time. If
  // ShipGateCheckResponse is dropped from `index.ts` or the
  // resource's exports, this file fails to compile and the test run
  // aborts before any pin runs.
  ShipGateCheckResponse,
} from "../ship-gate.js";
import type { FetchLike } from "../../types.js";

// ─── shipGate.check — POST CI/CD ship-gate verdict (4-shape variadic response) ─
//
// Wire shape (kernel src/app/api/v1/ship-gate/check/route.ts):
//   POST /api/v1/ship-gate/check
//   Auth: x-api-key (requireApiKeyWithPermission, READ_SYSTEMS|READ_ASSESSMENTS UNION)
//   Body: {systemId: <UUID>, attestationId: <string 1-256>}
//   200 OK Shape A (no gate): {success:true, data: {gated: false}}                 — 1 field
//   200 OK Shape B (released): {gated: false, state:"released", executionId, chainId} — 4 fields
//   200 OK Shape C (rejected/timed_out): {gated: true, reason, approvers_pending:[], state, executionId, chainId} — 6 fields
//   200 OK Shape D (awaiting):  {gated: true, reason:"awaiting_approvers", approvers_pending:[<UUIDs>], state:"gated", executionId, chainId} — 6 fields
//   401 auth, 403 permission, 404 cascade-gap, 422 Zod, 429 rate-limit, 500 internal
//
// `gated` is the ALWAYS-PRESENT anchor; 5 OPTIONAL own-property fields.
// `approvers_pending` is SNAKE_CASE on the wire (asymmetric with the rest
// of the SDK's camelCase response surface — preserved verbatim).
//
// CRITICAL contract: the SDK PRE-VALIDATES every Zod closed-spec rule
// synchronously (UUID format on systemId, length 1-256 on attestationId).
// 422 only reaches consumers via kernel rule changes the SDK hasn't
// synced to. Invariant #51.
//
// 20th audit chain in the F.1 phase. Sibling test files:
//   - gate-evaluate.test.ts (the gate.evaluate compliance-score gate)
//   - audit-log-verify-chain.test.ts (the org-wide audit chain verifier — 5-always + 1-optional shape)
// Adapted for the 4-shape variadic response + snake_case wire field +
// 2-field pre-validated input shape.

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
    // Resource tests disable retry so a 429 mock doesn't hang on backoff
    // and accidentally consume the next mock response. The retry-semantics
    // describe block below opts back in via per-call options.
    retry: { maxRetries: 0 },
  });
  return { client, calls };
}

const VALID_SYSTEM_ID = "11111111-2222-3333-4444-555555555555";
const VALID_ATTESTATION_ID = "build-1234";
const EXECUTION_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const CHAIN_ID = "99999999-8888-7777-6666-555555555555";
const APPROVER_ID_1 = "user-1111-1111-1111-111111111111";
const APPROVER_ID_2 = "user-2222-2222-2222-222222222222";

// Shape A — default-permissive: no gate exists for this tuple.
const SHAPE_A_NO_GATE: ShipGateCheckResponse = {
  gated: false,
};

// Shape B — released: chain approved the deployment.
const SHAPE_B_RELEASED: ShipGateCheckResponse = {
  gated: false,
  state: "released",
  executionId: EXECUTION_ID,
  chainId: CHAIN_ID,
};

// Shape C — rejected: chain went terminal in build-blocking state.
const SHAPE_C_REJECTED: ShipGateCheckResponse = {
  gated: true,
  reason: "rejected",
  approvers_pending: [],
  state: "rejected",
  executionId: EXECUTION_ID,
  chainId: CHAIN_ID,
};

// Shape C variant — timed_out.
const SHAPE_C_TIMED_OUT: ShipGateCheckResponse = {
  gated: true,
  reason: "timed_out",
  approvers_pending: [],
  state: "timed_out",
  executionId: EXECUTION_ID,
  chainId: CHAIN_ID,
};

// Shape D — gated awaiting approvers.
const SHAPE_D_AWAITING: ShipGateCheckResponse = {
  gated: true,
  reason: "awaiting_approvers",
  approvers_pending: [APPROVER_ID_1, APPROVER_ID_2],
  state: "gated",
  executionId: EXECUTION_ID,
  chainId: CHAIN_ID,
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

// ─── Happy path ──────────────────────────────────────────────────────────────

describe("shipGate.check — happy path", () => {
  it("POSTs /api/v1/ship-gate/check with systemId + attestationId body", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/ship-gate/check",
    );
    expect(calls[0].body).toBe(
      JSON.stringify({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    );
    expect(calls[0].headers.get("Content-Type")).toBe("application/json");
    // Transport unwraps the {success:true, data} envelope — bare result.
    expect(out).toEqual(SHAPE_A_NO_GATE);
  });

  it("Shape A (no gate) → {gated: false}, all 5 optional fields ABSENT (own-property false)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(false);
    // Shape A default-permissive — no other own-properties.
    expect(Object.hasOwn(out, "reason")).toBe(false);
    expect(Object.hasOwn(out, "approvers_pending")).toBe(false);
    expect(Object.hasOwn(out, "state")).toBe(false);
    expect(Object.hasOwn(out, "executionId")).toBe(false);
    expect(Object.hasOwn(out, "chainId")).toBe(false);
  });

  it("Shape B (released) → gated:false + state:'released' + executionId + chainId (4 fields)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_B_RELEASED } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(false);
    expect(out.state).toBe("released");
    expect(out.executionId).toBe(EXECUTION_ID);
    expect(out.chainId).toBe(CHAIN_ID);
    // Shape B has no reason / approvers_pending.
    expect(Object.hasOwn(out, "reason")).toBe(false);
    expect(Object.hasOwn(out, "approvers_pending")).toBe(false);
  });

  it("Shape C (rejected) → gated:true + reason:'rejected' + approvers_pending:[] + state + executionId + chainId (6 fields)", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_C_REJECTED } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(true);
    expect(out.reason).toBe("rejected");
    expect(out.approvers_pending).toEqual([]);
    expect(out.state).toBe("rejected");
    expect(out.executionId).toBe(EXECUTION_ID);
    expect(out.chainId).toBe(CHAIN_ID);
  });

  it("Shape C (timed_out) → gated:true + reason:'timed_out' + approvers_pending:[] + state:'timed_out'", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_C_TIMED_OUT } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(true);
    expect(out.reason).toBe("timed_out");
    expect(out.approvers_pending).toEqual([]);
    expect(out.state).toBe("timed_out");
  });

  it("Shape D (awaiting) → gated:true + reason:'awaiting_approvers' + approvers_pending:[<UUIDs>] + state:'gated'", async () => {
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_D_AWAITING } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(true);
    expect(out.reason).toBe("awaiting_approvers");
    expect(out.approvers_pending).toEqual([APPROVER_ID_1, APPROVER_ID_2]);
    expect(out.state).toBe("gated");
    expect(out.executionId).toBe(EXECUTION_ID);
    expect(out.chainId).toBe(CHAIN_ID);
  });

  it("forwards x-api-key + Accept headers (transport-level smoke)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(calls[0].headers.get("x-api-key")).toBe("k");
    expect(calls[0].headers.get("Accept")).toBe("application/json");
  });

  it("sends NO query string (POST body — pure POST)", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(calls[0].url).not.toContain("?");
  });
});

// ─── Variadic-shape discriminator semantics ──────────────────────────────────

describe("shipGate.check — variadic-shape discriminator semantics", () => {
  it("`gated` is the pollution-safe boolean discriminator (closed-enum boolean — own-property anchor)", async () => {
    // The 4 emit shapes all share `gated` as ALWAYS-present anchor.
    // Pin: every shape has `gated` as an own-property, with a
    // closed-enum boolean value. Consumers branch on `gated === true`.
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
      { body: { success: true, data: SHAPE_B_RELEASED } },
      { body: { success: true, data: SHAPE_C_REJECTED } },
      { body: { success: true, data: SHAPE_D_AWAITING } },
    ]);
    for (let i = 0; i < 4; i++) {
      const out = await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      expect(Object.hasOwn(out, "gated")).toBe(true);
      expect(typeof out.gated).toBe("boolean");
    }
  });

  it("Shape A vs Shape B distinguishable by `state` own-property (NOT by gated alone)", async () => {
    // Shape A and Shape B BOTH have `gated: false` — the discriminator
    // for build-proceed-related cases is `state` own-property presence.
    // Pin: Shape A lacks `state` own-property; Shape B has it.
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
      { body: { success: true, data: SHAPE_B_RELEASED } },
    ]);
    const a = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(a.gated).toBe(false);
    expect(Object.hasOwn(a, "state")).toBe(false);
    const b = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(b.gated).toBe(false);
    expect(Object.hasOwn(b, "state")).toBe(true);
    expect(b.state).toBe("released");
  });

  it("Shape C (rejected) vs Shape D (awaiting) — `approvers_pending` is `[]` on closed chain, populated on awaiting", async () => {
    // The kernel always sets approvers_pending to `[]` on closed
    // chains (rejected/timed_out — nobody is pending) and the list
    // of pending userIds on awaiting. Pin the contract: empty array
    // on Shape C, populated on Shape D.
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_C_REJECTED } },
      { body: { success: true, data: SHAPE_D_AWAITING } },
    ]);
    const c = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(c.approvers_pending).toEqual([]);
    const d = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(d.approvers_pending).toHaveLength(2);
  });

  it("`approvers_pending` SNAKE_CASE wire field preserved verbatim (NOT camelCased to `approversPending`)", async () => {
    // Asymmetric with the rest of the SDK's camelCase response
    // surface. The kernel emits `approvers_pending`; the SDK does
    // NOT auto-rewrite to `approversPending`. Pin: snake_case key
    // is an own-property; camelCase key is NOT.
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_D_AWAITING } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(Object.hasOwn(out, "approvers_pending")).toBe(true);
    expect(
      Object.hasOwn(
        out as ShipGateCheckResponse & { approversPending?: unknown },
        "approversPending",
      ),
    ).toBe(false);
  });

  it("extra fields on the result (forward-compat) pass through opaquely", async () => {
    // The transport doesn't strict-check the response body. New
    // kernel fields (e.g., `slaHoursRemaining`, `escalationDueAt`)
    // flow through as extra properties on the returned object —
    // TypeScript-erased but observable at runtime. Pin: SDK still
    // resolves cleanly, documented fields still present.
    const withExtras = {
      ...SHAPE_D_AWAITING,
      slaHoursRemaining: 4.5,
      escalationDueAt: "2026-05-20T12:00:00.000Z",
    };
    const { client } = makeMockedClient([
      { body: { success: true, data: withExtras } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(true);
    const opaque = out as ShipGateCheckResponse & {
      slaHoursRemaining?: number;
      escalationDueAt?: string;
    };
    expect(opaque.slaHoursRemaining).toBe(4.5);
    expect(opaque.escalationDueAt).toBe("2026-05-20T12:00:00.000Z");
  });
});

// ─── SDK-side input validation (synchronous TypeError, no fetch issued) ─────

describe("shipGate.check — input validation (synchronous TypeError)", () => {
  it("rejects null input as TypeError", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check(null as unknown as { systemId: string; attestationId: string }),
    ).toThrow(/`input` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("rejects array input as TypeError", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check([] as unknown as { systemId: string; attestationId: string }),
    ).toThrow(/`input` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("rejects non-object scalar input as TypeError", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check("not-an-object" as unknown as { systemId: string; attestationId: string }),
    ).toThrow(/`input` must be a non-null object/);
    expect(calls).toHaveLength(0);
  });

  it("rejects missing systemId as TypeError (no fetch)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        attestationId: VALID_ATTESTATION_ID,
      } as unknown as { systemId: string; attestationId: string }),
    ).toThrow(/`systemId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("rejects explicit undefined systemId as TypeError", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: undefined as unknown as string,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).toThrow(/`systemId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("rejects non-string systemId as TypeError", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: 12345 as unknown as string,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).toThrow(/`systemId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("rejects empty-string systemId as TypeError", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: "",
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).toThrow(/`systemId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("rejects malformed-UUID systemId as TypeError (UUID format pre-validation — invariant #49)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: "not-a-uuid",
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).toThrow(/`systemId` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("rejects UUID-but-wrong-length systemId as TypeError", async () => {
    // 7-4-4-4-12 instead of 8-4-4-4-12 (missing one hex char in
    // first group). Confirms the regex pre-validation is exact.
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: "1111111-1111-1111-1111-111111111111",
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).toThrow(/`systemId` must be an RFC 4122 hyphenated UUID/);
    expect(calls).toHaveLength(0);
  });

  it("accepts upper-case-hex UUID systemId (case-insensitive regex)", async () => {
    // Confirms the regex `[0-9a-fA-F]` accepts upper-case hex.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    await client.shipGate.check({
      systemId: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(calls).toHaveLength(1);
  });

  it("rejects missing attestationId as TypeError (no fetch)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
      } as unknown as { systemId: string; attestationId: string }),
    ).toThrow(/`attestationId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("rejects explicit undefined attestationId as TypeError", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: undefined as unknown as string,
      }),
    ).toThrow(/`attestationId` is required/);
    expect(calls).toHaveLength(0);
  });

  it("rejects non-string attestationId as TypeError (number)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: 1234 as unknown as string,
      }),
    ).toThrow(/`attestationId` must be a string \(got number\)/);
    expect(calls).toHaveLength(0);
  });

  it("rejects non-string attestationId as TypeError (null)", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: null as unknown as string,
      }),
    ).toThrow(/`attestationId` must be a string \(got null\)/);
    expect(calls).toHaveLength(0);
  });

  it("rejects empty-string attestationId as TypeError", async () => {
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: "",
      }),
    ).toThrow(/`attestationId` must be a non-empty string/);
    expect(calls).toHaveLength(0);
  });

  it("rejects attestationId exceeding MAX_ATTESTATION_ID_LENGTH=256 as TypeError", async () => {
    // 257 chars — one over the kernel's
    // `MAX_ATTESTATION_ID_LENGTH` constant at
    // src/lib/workflow/ship-gates.ts:106. Drift-pinned in spec-diff.
    const oversized = "a".repeat(257);
    const { client, calls } = makeMockedClient([]);
    expect(() =>
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: oversized,
      }),
    ).toThrow(/`attestationId` exceeds the kernel's max length of 256 chars \(got 257\)/);
    expect(calls).toHaveLength(0);
  });

  it("accepts attestationId of exactly 256 chars (boundary, no fetch issued for bounds check)", async () => {
    // The boundary value 256 is INSIDE the kernel's allowed range
    // (z.string().min(1).max(MAX_ATTESTATION_ID_LENGTH) at
    // route.ts:43); 257 above is OUTSIDE. Pin both — defends
    // against off-by-one regressions.
    const max = "a".repeat(256);
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: max,
    });
    expect(calls).toHaveLength(1);
  });

  it("accepts attestationId of exactly 1 char (boundary minimum)", async () => {
    // Length 1 is INSIDE the range (.min(1) inclusive); length 0
    // (empty string) is rejected above. Defends against the lower
    // boundary.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: "x",
    });
    expect(calls).toHaveLength(1);
  });
});

// ─── Top-level error paths (these THROW AttestryAPIError) ───────────────────

describe("shipGate.check — top-level error paths", () => {
  it("401 (auth required) → AttestryAPIError(401)", async () => {
    // No API key OR invalid key. Fires AFTER rate-limit but BEFORE
    // permission check or body validation.
    const { client } = makeMockedClient([
      {
        status: 401,
        body: { success: false, error: "Authentication required." },
      },
    ]);
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(401);
    }
  });

  it("403 (permission denied — UNION-auth NEITHER permission) → AttestryAPIError(403)", async () => {
    // Multi-permission UNION auth: kernel uses
    // requireApiKeyWithPermission(req, READ_SYSTEMS, READ_ASSESSMENTS).
    // An authenticated key that has NEITHER permission surfaces as
    // 403 (NOT 401 — distinct from ADMIN-only routes per invariant #42).
    // Carry-forward invariant #45.
    const { client } = makeMockedClient([
      {
        status: 403,
        body: { success: false, error: "Insufficient permission." },
      },
    ]);
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(403);
    }
  });

  it("404 (cascade-gap — ShipGateExecutionNotFoundError) → AttestryAPIError(404)", async () => {
    // Documented kernel-side cascade-gap path. The kernel maps
    // ShipGateExecutionNotFoundError (thrown by checkShipGate when
    // the inner executionRows.length === 0 defensive branch fires)
    // to HTTP 404 at route.ts:97-99. The RESTRICT FK should
    // prevent this in normal operation; documented as "only
    // reachable via direct DB intervention or cascade-behavior gap".
    const { client } = makeMockedClient([
      {
        status: 404,
        body: {
          success: false,
          error:
            `Approval chain execution ${EXECUTION_ID} not found in this organization.`,
        },
      },
    ]);
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(404);
      expect((err as AttestryAPIError).message).toMatch(
        /Approval chain execution .* not found in this organization/,
      );
    }
  });

  it("422 via UUID-shaped systemId — surfaces kernel's actual Validation-failed body (details: Array)", async () => {
    // Pin the actual 422 wire shape from src/lib/api.ts:84-91:
    // {error: "Validation failed.", details: Array<{path, message}>}.
    // Use a UUID-shaped systemId that passes SDK pre-validation but
    // a kernel mock rejects (simulating a kernel-side rule change).
    const { client } = makeMockedClient([
      {
        status: 422,
        body: {
          success: false,
          error: "Validation failed.",
          details: [
            { path: "attestationId", message: "Must include build prefix" },
          ],
        },
      },
    ]);
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: "valid-but-kernel-rule-rejects",
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(422);
      // The transport does NOT strip the {success:false} envelope
      // on error responses — consumers reading field-level errors
      // iterate `apiErr.details.details` (the nested kernel array).
      expect(apiErr.message).toBe("Validation failed.");
      const errDetails = apiErr.details as {
        error: string;
        details: Array<{ path: string; message: string }>;
      };
      expect(errDetails.error).toBe("Validation failed.");
      expect(Array.isArray(errDetails.details)).toBe(true);
      expect(errDetails.details[0].path).toBe("attestationId");
      expect(errDetails.details[0].message).toBe(
        "Must include build prefix",
      );
    }
  });

  it("429 (rate limit) → AttestryAPIError(429) when retry disabled", async () => {
    const { client } = makeMockedClient([
      {
        status: 429,
        body: {
          success: false,
          error: "Too many requests.",
        },
      },
    ]);
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
  });

  it("non-application/json content-type → AttestryAPIError (P3 hardening — transport-level guard)", async () => {
    // P3 content-type fail-fast claim documented in JSDoc + README.
    // The transport's expectedContentType guard fails fast when the
    // kernel responds with text/html (e.g., a proxy / load-balancer
    // error page wrapped at 200). Mirror of audit-log.verifyChain's
    // P3 test (added in session-19 review-2 LOW-1).
    const mockFetch: FetchLike = async () =>
      new Response("<html><body>Proxy error</body></html>", {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      // Transport's content-type guard surfaces as AttestryAPIError
      // (NOT AttestryError); status is 200 (the proxy sent 200 OK
      // with wrong body); message names the expected-vs-actual
      // content-type mismatch.
      expect(apiErr.status).toBe(200);
      expect(apiErr.message).toMatch(/application\/json/i);
    }
  });

  it("500 (internal) → AttestryAPIError(500) with SCRUBBED message (no kernel error leak)", async () => {
    const { client } = makeMockedClient([
      {
        status: 500,
        body: {
          success: false,
          error: "An internal error occurred. Please try again later.",
        },
      },
    ]);
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      const apiErr = err as AttestryAPIError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.message).toBe(
        "An internal error occurred. Please try again later.",
      );
      // Negative pins — confirm raw kernel error text doesn't leak.
      expect(apiErr.message).not.toContain("ECONNREFUSED");
      expect(apiErr.message).not.toContain("postgres");
      expect(apiErr.message).not.toContain("checkShipGate");
    }
  });
});

// ─── Retry semantics (default-on for 429 only — invariant #18) ──────────────

describe("shipGate.check — retry semantics", () => {
  it("429 retried once by default (carry-forward invariant #18)", async () => {
    const calls: MockedRequest[] = [];
    let i = 0;
    const responses = [
      {
        status: 429 as const,
        body: { success: false, error: "Too many requests." },
      },
      {
        status: 200 as const,
        body: { success: true, data: SHAPE_A_NO_GATE },
      },
    ];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      const r = responses[i++];
      return new Response(JSON.stringify(r.body), {
        status: r.status,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { initialDelayMs: 1, maxDelayMs: 1, maxRetries: 1 },
    });
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(calls).toHaveLength(2);
    expect(out.gated).toBe(false);
  });

  it("429 NOT retried when options.retry: {maxRetries: 0}", async () => {
    const calls: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      return new Response(
        JSON.stringify({ success: false, error: "Too many requests." }),
        { status: 429, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
    });
    try {
      await client.shipGate.check(
        {
          systemId: VALID_SYSTEM_ID,
          attestationId: VALID_ATTESTATION_ID,
        },
        { retry: { maxRetries: 0 } },
      );
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(429);
    }
    expect(calls).toHaveLength(1);
  });

  it("5xx NOT retried (only 429 — invariant #18)", async () => {
    const calls: MockedRequest[] = [];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      return new Response(
        JSON.stringify({
          success: false,
          error: "An internal error occurred. Please try again later.",
        }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
    });
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryAPIError);
      expect((err as AttestryAPIError).status).toBe(500);
    }
    expect(calls).toHaveLength(1);
  });

  it("retry preserves variadic-shape contract (200 + Shape D survives a 429 retry)", async () => {
    // After a 429 + retry, the server's eventual Shape D response
    // is surfaced cleanly. Pin that the retry path doesn't lose
    // approvers_pending or any other optional own-property.
    const calls: MockedRequest[] = [];
    let i = 0;
    const responses = [
      {
        status: 429 as const,
        body: { success: false, error: "Too many requests." },
      },
      {
        status: 200 as const,
        body: { success: true, data: SHAPE_D_AWAITING },
      },
    ];
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      const r = responses[i++];
      return new Response(JSON.stringify(r.body), {
        status: r.status,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { initialDelayMs: 1, maxDelayMs: 1, maxRetries: 1 },
    });
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(calls).toHaveLength(2);
    expect(out.gated).toBe(true);
    expect(out.reason).toBe("awaiting_approvers");
    expect(out.approvers_pending).toEqual([APPROVER_ID_1, APPROVER_ID_2]);
  });
});

// ─── Abort semantics ────────────────────────────────────────────────────────

describe("shipGate.check — abort semantics", () => {
  it("pre-aborted signal → AttestryError synchronously (post-input-validation), no fetch", async () => {
    // Carry-forward invariant #3: pre-aborted signals reject in the
    // transport BEFORE any fetch is issued (but AFTER SDK input
    // validation — input validation runs first, synchronously).
    const { client, calls } = makeMockedClient([]);
    const controller = new AbortController();
    controller.abort(new Error("user cancelled"));
    await expect(
      client.shipGate.check(
        {
          systemId: VALID_SYSTEM_ID,
          attestationId: VALID_ATTESTATION_ID,
        },
        { signal: controller.signal },
      ),
    ).rejects.toThrow(/aborted by caller/);
    expect(calls).toHaveLength(0);
  });

  it("non-aborted signal → request completes normally", async () => {
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    const controller = new AbortController();
    const out = await client.shipGate.check(
      {
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      },
      { signal: controller.signal },
    );
    expect(out).toEqual(SHAPE_A_NO_GATE);
    expect(calls).toHaveLength(1);
    expect(controller.signal.aborted).toBe(false);
  });

  it("mid-flight abort → AttestryError with the abort cause (transport-level)", async () => {
    const calls: MockedRequest[] = [];
    const controller = new AbortController();
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      controller.abort(new Error("mid-flight cancellation"));
      const err = new DOMException("aborted", "AbortError");
      throw err;
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    try {
      await client.shipGate.check(
        {
          systemId: VALID_SYSTEM_ID,
          attestationId: VALID_ATTESTATION_ID,
        },
        { signal: controller.signal },
      );
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(AttestryError);
    }
    expect(calls).toHaveLength(1);
  });
});

// ─── Response-shape validation (P2 hardening) ───────────────────────────────

describe("shipGate.check — response shape (P2 hardening)", () => {
  it("throws AttestryError when kernel response is null", async () => {
    // P2 extension: extracted-data envelope with null payload.
    // Class identity is the contract — must be AttestryError (NOT
    // AttestryAPIError, which is for status-code-bearing errors).
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: null } },
    ]);
    let caught: unknown;
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /shipGate\.check: expected an object response from the kernel \(got null\)/,
    );
  });

  it("throws AttestryError when kernel response is an array (not object)", async () => {
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: [] } },
    ]);
    let caught: unknown;
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /shipGate\.check: expected an object response from the kernel \(got array\)/,
    );
  });

  it("throws AttestryError when kernel response is a scalar (string)", async () => {
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: "not-an-object" } },
    ]);
    let caught: unknown;
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toMatch(
      /shipGate\.check: expected an object response from the kernel \(got string\)/,
    );
  });

  it("throws AttestryError when response.gated is not a boolean", async () => {
    // gated is closed-enum boolean — closed-enum-at-type level.
    // A regression emitting number/string/null would silently let
    // consumer code mis-branch.
    const { client } = makeMockedClient([
      {
        status: 200,
        body: { success: true, data: { gated: "false" } },
      },
    ]);
    await expect(
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.gated to be a boolean \(got string\)/,
    );
  });

  it("throws AttestryError when response.reason is OWN-PROPERTY but not a string", async () => {
    // reason is OPTIONAL — kernel omits it in Shapes A + B. When
    // PRESENT as own-property, it MUST be a string. A regression
    // emitting number/boolean would let consumer code mis-branch.
    const { client } = makeMockedClient([
      {
        status: 200,
        body: { success: true, data: { ...SHAPE_C_REJECTED, reason: 42 } },
      },
    ]);
    await expect(
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.reason to be a string when present \(got number\)/,
    );
  });

  it("throws AttestryError when response.approvers_pending is OWN-PROPERTY but not an array", async () => {
    // approvers_pending is OPTIONAL — kernel omits in Shapes A + B.
    // When PRESENT, MUST be an array.
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...SHAPE_C_REJECTED, approvers_pending: "not-an-array" },
        },
      },
    ]);
    await expect(
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.approvers_pending to be an array when present \(got string\)/,
    );
  });

  it("throws AttestryError when response.approvers_pending[i] is not a string", async () => {
    // Per-element shape on approvers_pending — kernel emits an
    // array of UUIDs (string). A regression emitting numbers or
    // null would let consumer code crash when concatenating into
    // PR comments.
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: {
            ...SHAPE_D_AWAITING,
            approvers_pending: [APPROVER_ID_1, 12345, APPROVER_ID_2],
          },
        },
      },
    ]);
    await expect(
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.approvers_pending\[1\] to be a string \(got number\)/,
    );
  });

  it("throws AttestryError when response.state is OWN-PROPERTY but not a string", async () => {
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...SHAPE_B_RELEASED, state: true },
        },
      },
    ]);
    await expect(
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.state to be a string when present \(got boolean\)/,
    );
  });

  it("throws AttestryError when response.executionId is OWN-PROPERTY but not a string", async () => {
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...SHAPE_B_RELEASED, executionId: null },
        },
      },
    ]);
    await expect(
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.executionId to be a string when present \(got null\)/,
    );
  });

  it("throws AttestryError when response.chainId is OWN-PROPERTY but not a string", async () => {
    const { client } = makeMockedClient([
      {
        status: 200,
        body: {
          success: true,
          data: { ...SHAPE_B_RELEASED, chainId: 42 },
        },
      },
    ]);
    await expect(
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.chainId to be a string when present \(got number\)/,
    );
  });

  it("accepts all 5 optional fields absent on Shape A (forward-compat — no own-property)", async () => {
    // The Shape A default-permissive shape has ONLY `gated: false`.
    // Validator must NOT reject when reason/approvers_pending/state/
    // executionId/chainId are absent — pin the forward-compat
    // behavior.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(false);
    expect(out.reason).toBeUndefined();
    expect(out.approvers_pending).toBeUndefined();
    expect(out.state).toBeUndefined();
    expect(out.executionId).toBeUndefined();
    expect(out.chainId).toBeUndefined();
  });

  it("accepts empty approvers_pending:[] on Shape C (closed chain — no pending)", async () => {
    // Shape C always emits approvers_pending: []. Validator's
    // per-element loop must NOT throw on length=0.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: SHAPE_C_REJECTED } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.approvers_pending).toEqual([]);
  });
});

// ─── Missing own-property exercises :undefined ternary arm (D-pin) ──────────
//
// The validator's `gated` field uses a ternary
// `objectHasOwn(obj, "gated") ? obj.gated : undefined`. The `:undefined`
// arm needs explicit exercise via a response that omits `gated` as an
// own-property. Front-loaded per session-17 build-round carry-forward
// (D12 pattern). Only `gated` is ALWAYS-PRESENT — the other 5 fields
// use `if (objectHasOwn(...)) {...}` patterns (no ternary, no
// `:undefined` arm to exercise; their else branches are exercised by
// the Shape A test which has them all absent).

describe("shipGate.check — missing own-property exercises :undefined ternary arm (D-pin)", () => {
  it("throws AttestryError when response is missing own-property `gated` (exercises :undefined arm)", async () => {
    // Build a response WITHOUT `gated` as own-property. The
    // validator's `objectHasOwn(obj, "gated") ? obj.gated : undefined`
    // ternary lands on the `:undefined` arm; subsequent typeof check
    // fires AttestryError.
    const incomplete: Record<string, unknown> = { ...SHAPE_C_REJECTED };
    delete incomplete.gated;
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: incomplete } },
    ]);
    let caught: unknown;
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toContain(
      "shipGate.check: expected response.gated to be a boolean",
    );
    expect((caught as AttestryError).message).toContain("got undefined");
  });
});

// ─── Prototype-pollution defense (symmetric — input AND response sides) ─────

describe("shipGate.check — prototype-pollution defense (response side)", () => {
  // The validator uses module-load `objectHasOwn` snapshot to defend
  // against a hostile dep polluting `Object.prototype.<field>`.

  it("Object.prototype.reason pollution does NOT mask missing own-property on Shape A", async () => {
    // Hostile attack: malicious dep sets
    // `Object.prototype.reason = "fake-reason"` before the SDK
    // verifies the response. Without `Object.hasOwn`-based defense,
    // a consumer reading `result.reason` would see the polluted
    // value (via prototype walk) — silently misclassifying a Shape A
    // (no-gate) response as Shape C (rejected/timed_out).
    //
    // With the defense: validator uses
    // `objectHasOwn(obj, "reason")` which returns FALSE on a
    // Shape-A response (kernel omits the field). The polluted
    // prototype value is NOT picked up.
    const originalProto = Object.prototype as unknown as { reason?: string };
    try {
      (Object.prototype as unknown as { reason?: string }).reason =
        "polluted-reason";
      const { client } = makeMockedClient([
        { body: { success: true, data: SHAPE_A_NO_GATE } },
      ]);
      const out = await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      expect(out.gated).toBe(false);
      // The defense's load-bearing claim: response did NOT carry
      // reason as own-property.
      expect(Object.hasOwn(out, "reason")).toBe(false);
    } finally {
      delete originalProto.reason;
    }
  });

  it("Object.prototype.gated pollution does NOT mask missing own-property in the validator", async () => {
    // Combined attack: hostile dep pollutes
    // `Object.prototype.gated = true`, then the kernel response
    // accidentally drops `gated` from the wire (regression).
    // Without `Object.hasOwn` defense, `obj.gated` walks the
    // prototype and reads `true` — the validator's
    // `typeof gated !== "boolean"` check passes silently, and the
    // consumer sees a misleading "gated: true" verdict.
    //
    // With the defense: validator uses `objectHasOwn(obj, "gated")`
    // which returns false; ternary lands on `:undefined` arm; typeof
    // check fails; AttestryError thrown.
    const originalProto = Object.prototype as unknown as { gated?: boolean };
    try {
      (Object.prototype as unknown as { gated?: boolean }).gated = true;
      const incomplete = { ...SHAPE_C_REJECTED } as Partial<
        ShipGateCheckResponse
      >;
      delete incomplete.gated;
      const { client } = makeMockedClient([
        { status: 200, body: { success: true, data: incomplete } },
      ]);
      let caught: unknown;
      try {
        await client.shipGate.check({
          systemId: VALID_SYSTEM_ID,
          attestationId: VALID_ATTESTATION_ID,
        });
      } catch (err) {
        caught = err;
      }
      // The SDK rejected despite the prototype pollution — the
      // load-bearing claim of the symmetric-defense pattern.
      expect(caught).toBeInstanceOf(AttestryError);
      expect((caught as AttestryError).message).toContain(
        "shipGate.check: expected response.gated to be a boolean",
      );
      expect((caught as AttestryError).message).toContain("got undefined");
    } finally {
      delete originalProto.gated;
    }
  });

  it("Object.prototype.state pollution does NOT mask missing own-property on Shape A (SDK-internal validator uses module-load snapshot)", async () => {
    // Hostile attack: malicious dep sets
    // `Object.prototype.state = "released"` before the SDK verifies
    // the response. Without the SDK's module-load Object.hasOwn
    // snapshot, the validator would walk the prototype on
    // `obj.state` read (after a present-but-wrong-type check
    // passes) — but the validator's structure (`if
    // (objectHasOwn(obj, "state")) { ... }`) skips the whole block
    // when the snapshot returns false. So Shape A pollution-test:
    // pollute state with a valid string, send Shape A response,
    // verify validator does NOT consult the polluted prototype.
    //
    // Distinct from the `gated` test (which polluted the
    // UNCONDITIONAL anchor) — `state` is OPTIONAL, exercising the
    // CONDITIONAL skip branch.
    const originalProto = Object.prototype as unknown as { state?: string };
    try {
      (Object.prototype as unknown as { state?: string }).state =
        "released";
      const { client } = makeMockedClient([
        { body: { success: true, data: SHAPE_A_NO_GATE } },
      ]);
      const out = await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      expect(out.gated).toBe(false);
      // Defense load-bearing claim: SDK-internal validator did NOT
      // pick up the polluted state via prototype walk; response did
      // NOT carry state as own-property.
      expect(Object.hasOwn(out, "state")).toBe(false);
    } finally {
      delete originalProto.state;
    }
  });

  it("Object.prototype.approvers_pending pollution does NOT inject polluted values on Shape A", async () => {
    // Hostile attack: malicious dep sets
    // `Object.prototype.approvers_pending = ["fake-approver-uuid"]`
    // before the SDK verifies the response. Without
    // `Object.hasOwn`-based defense, consumer reading
    // `result.approvers_pending` walks the prototype and reads the
    // polluted array — silently injecting fake approvers into the
    // CI build comment.
    //
    // With the defense: validator's
    // `objectHasOwn(obj, "approvers_pending")` returns false on
    // Shape A; polluted prototype value is NOT picked up by the
    // validator (consumer's read CAN see it, but the SDK's contract
    // is that the field is own-property absent — Object.hasOwn check
    // is the load-bearing surface).
    const originalProto = Object.prototype as unknown as {
      approvers_pending?: string[];
    };
    try {
      (Object.prototype as unknown as {
        approvers_pending?: string[];
      }).approvers_pending = ["polluted-approver"];
      const { client } = makeMockedClient([
        { body: { success: true, data: SHAPE_A_NO_GATE } },
      ]);
      const out = await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
      // Defense load-bearing claim: response did NOT carry
      // approvers_pending as own-property; consumer detecting
      // "build blocked by approver list" should branch on
      // `gated === true`, NOT existence of approvers_pending.
      expect(Object.hasOwn(out, "approvers_pending")).toBe(false);
      expect(out.gated).toBe(false);
    } finally {
      delete originalProto.approvers_pending;
    }
  });
});

describe("shipGate.check — prototype-pollution defense (input side)", () => {
  it("Object.prototype.systemId pollution does NOT cause the SDK to send a polluted value when consumer passes input without systemId", async () => {
    // Hostile attack: malicious dep sets
    // `Object.prototype.systemId = "<some-uuid>"`. Without the
    // input-side defense, a consumer passing
    // `{attestationId: "build-x"}` (no systemId) would silently
    // send the polluted UUID — calling the kernel with a foreign
    // org's system ID.
    //
    // With the defense: input-side `objectHasOwn(input, "systemId")`
    // returns false; SDK rejects synchronously with `systemId is
    // required`; no fetch issued.
    const originalProto = Object.prototype as unknown as { systemId?: string };
    try {
      (Object.prototype as unknown as { systemId?: string }).systemId =
        "00000000-0000-0000-0000-000000000000";
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.shipGate.check({
          attestationId: VALID_ATTESTATION_ID,
        } as unknown as { systemId: string; attestationId: string }),
      ).toThrow(/`systemId` is required/);
      expect(calls).toHaveLength(0);
    } finally {
      delete originalProto.systemId;
    }
  });

  it("Object.prototype.attestationId pollution does NOT cause the SDK to send a polluted value when consumer passes input without attestationId", async () => {
    // Symmetric to systemId-pollution test above — defends against
    // pollution lying about attestationId presence.
    const originalProto = Object.prototype as unknown as {
      attestationId?: string;
    };
    try {
      (Object.prototype as unknown as {
        attestationId?: string;
      }).attestationId = "polluted-attestation-id";
      const { client, calls } = makeMockedClient([]);
      expect(() =>
        client.shipGate.check({
          systemId: VALID_SYSTEM_ID,
        } as unknown as { systemId: string; attestationId: string }),
      ).toThrow(/`attestationId` is required/);
      expect(calls).toHaveLength(0);
    } finally {
      delete originalProto.attestationId;
    }
  });
});

// ─── URL & request invariants ───────────────────────────────────────────────

describe("shipGate.check — URL & request invariants", () => {
  it("repeated check() calls produce byte-identical URL (no hidden cache)", async () => {
    // Idempotent at the URL-shape level. Catches a future
    // regression that adds a request-id query param, lowercases
    // the path, or memoizes state across calls.
    const { client, calls } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(calls).toHaveLength(2);
    expect(calls[0].url).toBe(calls[1].url);
    expect(calls[0].url).toBe(
      "https://test.attestry.local/api/v1/ship-gate/check",
    );
  });

  it("concurrent check() calls share no state — independent fetches", async () => {
    // Two concurrent calls should produce independent fetches with
    // independent results.
    const calls: MockedRequest[] = [];
    const responses = [SHAPE_A_NO_GATE, SHAPE_D_AWAITING];
    let i = 0;
    const mockFetch: FetchLike = async (url, init) => {
      calls.push({
        url: String(url),
        method: (init?.method as string) ?? "GET",
        headers: init?.headers as Headers,
        body: init?.body as string | undefined,
      });
      const r = responses[i++];
      return new Response(JSON.stringify({ success: true, data: r }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 0 },
    });
    const [outA, outB] = await Promise.all([
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
      client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ]);
    expect(calls).toHaveLength(2);
    // Each call got its own response.
    const gatedSorted = [outA.gated, outB.gated].sort();
    expect(gatedSorted).toEqual([false, true]);
  });

  it("does NOT mutate caller's input object", async () => {
    // The check method snapshots fields up front but does NOT
    // mutate the original input. Pin: frozen input survives
    // without mutation.
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    const input = Object.freeze({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    await client.shipGate.check(input);
    expect(Object.isFrozen(input)).toBe(true);
    expect(input.systemId).toBe(VALID_SYSTEM_ID);
    expect(input.attestationId).toBe(VALID_ATTESTATION_ID);
  });

  it("does NOT mutate caller's RequestOptions object", async () => {
    // Symmetric defensive pin. The check method passes `options`
    // straight through to `_request<T>`; nothing in the resource
    // layer touches the options object. Frozen options must survive
    // without mutation (deep — inner retry obj too).
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    const controller = new AbortController();
    const retry = Object.freeze({ maxRetries: 0 });
    const options = Object.freeze({
      signal: controller.signal,
      retry,
    });
    await client.shipGate.check(
      {
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      },
      options,
    );
    expect(Object.isFrozen(options)).toBe(true);
    expect(Object.isFrozen(options.retry)).toBe(true);
    expect(options.signal).toBe(controller.signal);
    expect(options.retry.maxRetries).toBe(0);
  });

  it("synchronous call signature: returns a Promise (not an iterator)", async () => {
    // Asymmetric with `auditLog.export` (returns AsyncIterable).
    // Pin that check() returns a Promise.
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    const result = client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(result).toBeInstanceOf(Promise);
    expect(
      (result as unknown as { [Symbol.asyncIterator]?: unknown })[
        Symbol.asyncIterator
      ],
    ).toBeUndefined();
    await result;
  });
});

// ─── Hostile round (residual gaps) ──────────────────────────────────────────
//
// These pins exercise the defense MECHANISM, not just any rejection
// path. Each H<N> targets a residual gap that build-round + spec-diff
// tests don't directly cover. Mirror of audit-log.verifyChain's
// hostile-round structure adapted for the 4-shape variadic response +
// snake_case approvers_pending wire field + 2-field pre-validated
// input + writeAuditLog side effect.

describe("shipGate.check — hostile round (residual gaps)", () => {
  it("H1: 429 exhausting all retries → final AttestryAPIError(429) (carry-forward from audit-log.verifyChain H1)", async () => {
    // Spec hostile #1: every retry returns 429; SDK exhausts the
    // retry budget; surfaces the final 429 as AttestryAPIError.
    // Fake timers + Math.random stub keep the test fast +
    // deterministic under coverage instrumentation.
    //
    // Math.random stubbed to 0.5 — retry.ts:sleepWithSignal early-
    // returns when ms<=0 BEFORE registering the abort listener; an
    // unstubbed Math.random producing < 0.001 (~0.1% probability
    // with initialDelayMs:1_000) would yield delay=0, listener
    // wouldn't register. Stubbing guarantees a non-zero delay.
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0.5);
    let fetchCount = 0;
    const mockFetch: FetchLike = async () => {
      fetchCount++;
      return new Response(
        JSON.stringify({ success: false, error: "Too many requests." }),
        { status: 429, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { maxRetries: 2, initialDelayMs: 1, maxDelayMs: 1 },
    });
    const promise = client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    const observer = promise.catch(() => undefined);
    await vi.advanceTimersByTimeAsync(1000);
    await observer;
    await expect(promise).rejects.toBeInstanceOf(AttestryAPIError);
    await expect(promise).rejects.toMatchObject({ status: 429 });
    // Loosened contract pin (session-19 review-1 LOW-3 carry-
    // forward): assert retry fired (count > 1) AND budget exhausted
    // (count <= 3 = 1 + maxRetries:2). Exact count would be
    // implementation-coupled.
    expect(fetchCount).toBeGreaterThan(1);
    expect(fetchCount).toBeLessThanOrEqual(3);
  });

  it("H2: mid-flight abort during retry backoff — cancels backoff, no second fetch (invariant #22)", async () => {
    // Carry-forward invariant #22 (`sleepWithSignal` cleans up
    // listener in BOTH paths — timer-fires AND abort-fires) is the
    // load-bearing transport behavior. Pin: a 429 → backoff sleep →
    // abort fires mid-sleep → AttestryError thrown synchronously,
    // NO second fetch was issued. Fake timers + Math.random stub
    // for determinism.
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0.5);
    let fetchCount = 0;
    const ac = new AbortController();
    const mockFetch: FetchLike = async () => {
      fetchCount++;
      return new Response(
        JSON.stringify({ success: false, error: "Too many requests." }),
        { status: 429, headers: { "Content-Type": "application/json" } },
      );
    };
    const client = new AttestryClient({
      apiKey: "k",
      fetch: vi.fn(mockFetch) as unknown as FetchLike,
      baseUrl: "https://test.attestry.local",
      retry: { initialDelayMs: 1_000, maxDelayMs: 10_000, maxRetries: 3 },
    });
    const promise = client.shipGate.check(
      {
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      },
      { signal: ac.signal },
    );
    const observer = promise.catch(() => undefined);
    // STRING reason (NOT Error) — vitest's fake-timer +
    // AbortController dispatch re-throws Error reasons; strings
    // don't trigger that path.
    setTimeout(() => ac.abort("user cancelled"), 0);
    await vi.advanceTimersByTimeAsync(10);
    await observer;
    await expect(promise).rejects.toThrow(/aborted/);
    expect(fetchCount).toBe(1);
  });

  it("H3: frozen RequestOptions object — SDK does NOT mutate options (deep)", async () => {
    // Symmetric defensive pin. The check method passes `options`
    // straight through to `_request<T>`; nothing in the resource
    // layer touches the options object. Pin BOTH outer freeze AND
    // inner retry freeze (deep — hostile-review F4 from
    // decisions.verifyChain).
    const { client } = makeMockedClient([
      { body: { success: true, data: SHAPE_A_NO_GATE } },
    ]);
    const controller = new AbortController();
    const retry = Object.freeze({ maxRetries: 0 });
    const options = Object.freeze({
      signal: controller.signal,
      retry,
    });
    await client.shipGate.check(
      {
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      },
      options,
    );
    expect(Object.isFrozen(options)).toBe(true);
    expect(Object.isFrozen(options.retry)).toBe(true);
    expect(options.signal).toBe(controller.signal);
    expect(options.retry.maxRetries).toBe(0);
  });

  it("H4: forward-compat synthetic — gated:true + NO reason own-property — validator is lenient on optional own-property absence", async () => {
    // **Forward-compat synthetic test**, not a defense against a
    // kernel regression: the kernel's `formatShipGateCheckResult`
    // (`ship-gates.ts:283-311`) currently produces every `gated:true`
    // shape with `reason` set unconditionally — a kernel regression
    // dropping `reason` population would also fail the wire-shape
    // drift pin (build-round Pin 1 in sdk-drift.test.ts) BEFORE this
    // H4 test fires. So the load-bearing defense is the drift pin;
    // H4's value is asserting the SDK validator is LENIENT on
    // forward-compat inputs that the wire shape MAY emit in the
    // future (e.g., a kernel evolution adding a fourth shape with
    // gated:true but no reason — say `reason: undefined` collapsing
    // to absence, or a new "stalled" diagnostic state).
    //
    // The SDK's validator allows this — the validator's `reason`
    // check only fires when the field IS own-present (validator at
    // ship-gate.ts). Pin: validator accepts; reason remains undefined;
    // other fields preserved verbatim.
    const inconsistent = { ...SHAPE_C_REJECTED } as Partial<
      ShipGateCheckResponse
    >;
    delete inconsistent.reason;
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: inconsistent } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(true);
    // reason is absent on the wire — SDK does NOT synthesize.
    expect(Object.hasOwn(out, "reason")).toBe(false);
    expect(out.reason).toBeUndefined();
    // Other fields preserved verbatim.
    expect(out.state).toBe("rejected");
    expect(out.executionId).toBe(EXECUTION_ID);
    expect(out.chainId).toBe(CHAIN_ID);
  });

  it("H5: field-coercion regression test — boolean gated as 1 / string reason as number rejected", async () => {
    // Faithful courier: SDK does NOT coerce 1 → true or 42 → "42".
    // The validator's strict `typeof` checks fire on type mismatch.
    // Pin BOTH paths — defends against a future "type-cleanup"
    // refactor that adds runtime coercion.
    const wrongType1 = { gated: 1 };
    const { client: client1 } = makeMockedClient([
      { status: 200, body: { success: true, data: wrongType1 } },
    ]);
    await expect(
      client1.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.gated to be a boolean \(got number\)/,
    );

    const wrongType2 = { ...SHAPE_C_REJECTED, reason: 42 };
    const { client: client2 } = makeMockedClient([
      { status: 200, body: { success: true, data: wrongType2 } },
    ]);
    await expect(
      client2.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      }),
    ).rejects.toThrow(
      /shipGate\.check: expected response\.reason to be a string when present \(got number\)/,
    );
  });

  it("H6: large approvers_pending (1000 UUIDs) preserved verbatim — kernel doesn't cap; SDK pass-through", async () => {
    // JSON.parse correctly decodes an array of 1000 strings. SDK
    // forwards verbatim — kernel `computeApproversPending` has no
    // upper bound, so the SDK does NOT cap either. Pin: extreme-
    // but-valid pending list survives round-trip with full length.
    // Defends against a future SDK-side truncation that would
    // silently hide approvers.
    const huge = {
      ...SHAPE_D_AWAITING,
      approvers_pending: Array.from(
        { length: 1000 },
        (_, i) => `${APPROVER_ID_1.slice(0, -4)}${(i + 1000).toString().padStart(4, "0")}`,
      ),
    };
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: huge } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.approvers_pending).toHaveLength(1000);
    // Confirm SDK validated every element (the per-element loop
    // exercises 1000 string checks; if any element were non-string
    // the validator would have thrown).
    expect(out.approvers_pending?.[0]).toBe(
      `${APPROVER_ID_1.slice(0, -4)}1000`,
    );
    expect(out.approvers_pending?.[999]).toBe(
      `${APPROVER_ID_1.slice(0, -4)}1999`,
    );
  });

  it("H7: 200 with empty body `{}` — AttestryError via missing `gated` (extreme-degenerate)", async () => {
    // Transport's unwrap-discrimination falls through:
    //   parsed.success !== true → return parsed as T directly.
    // With P2 hardening, the validator catches the empty {} at the
    // very first field check (`gated` must be boolean, got
    // undefined). Pin: rejection at the first-failing-field
    // boundary — a future SDK relaxation that returned consumer-
    // undefined-deref would regress here.
    const { client } = makeMockedClient([
      { status: 200, body: {} },
    ]);
    let caught: unknown;
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toContain(
      "shipGate.check: expected response.gated to be a boolean",
    );
  });

  it("H8: 200 with bare `{success:true}` (no data) — falls through to envelope shape; validator rejects on missing `gated`", async () => {
    // The transport's unwrap discrimination requires BOTH
    // `success === true` AND `"data" in parsed`. Without `data`,
    // it falls through to `return parsed as T` — consumer sees the
    // bare envelope `{success: true}`. With P2 hardening, the
    // validator sees `obj.gated === undefined` (envelope has no
    // `gated` field) and rejects.
    const { client } = makeMockedClient([
      { status: 200, body: { success: true } },
    ]);
    let caught: unknown;
    try {
      await client.shipGate.check({
        systemId: VALID_SYSTEM_ID,
        attestationId: VALID_ATTESTATION_ID,
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).not.toBeInstanceOf(AttestryAPIError);
    expect((caught as AttestryError).message).toContain(
      "shipGate.check: expected response.gated to be a boolean",
    );
  });

  it("H9: combined attack — Object.hasOwn global override + valid-typed Object.prototype.gated pollution + missing-own-property response; module-load snapshot defense fires", async () => {
    // CRITICAL hostile pin — exercises the LOAD-BEARING defense
    // mechanism, NOT just any rejection path.
    //
    // **Adversarial construction** (session-19 review-1 HIGH-1
    // lesson) — the polluted value MUST be type-valid (the
    // validator's `typeof gated !== "boolean"` would NOT reject
    // `true`), so the only way the test distinguishes "defense
    // active" from "defense broken" is via the `objectHasOwn`
    // branch:
    //   - WITH defense (validator uses module-load snapshot): the
    //     snapshot's hasOwn returns false on the missing field;
    //     ternary lands on `:undefined`; typeof check fails on
    //     undefined; AttestryError thrown. **Test passes via the
    //     thrown error.**
    //   - WITHOUT defense (validator uses overridden global): the
    //     overridden global's hasOwn returns true; ternary reads
    //     `obj.gated` which WALKS THE PROTOTYPE and reads the
    //     polluted `true`; typeof check passes; NO throw;
    //     consumer receives a bogus `gated: true` verdict for a
    //     response missing the field.
    //
    // Pollute `gated` (UNCONDITIONAL validator branch — every code
    // path reads `obj.gated` first) so the override-vs-snapshot
    // distinction is observable. Mirror of audit-log.verifyChain H9
    // with session-19 review-3 L4 carry-forward (eager spy restore
    // in finally + vi.spyOn over direct global assignment).
    const originalProto = Object.prototype as unknown as { gated?: boolean };
    let hasOwnSpy: ReturnType<typeof vi.spyOn> | undefined;
    try {
      // Step 1: pollute prototype with a VALID-TYPED value.
      (Object.prototype as unknown as { gated?: boolean }).gated = true;
      // Step 2: override the GLOBAL Object.hasOwn via vi.spyOn
      // (session-19 review-2 LOW-3 — direct assignment leaks on
      // test-kill; vi.spyOn is tracked + cleaned up by afterEach).
      hasOwnSpy = vi.spyOn(Object, "hasOwn").mockImplementation(
        () => true,
      );
      // Step 3: response WITHOUT `gated` own-property.
      const incomplete = { ...SHAPE_C_REJECTED } as Partial<
        ShipGateCheckResponse
      >;
      delete incomplete.gated;
      const { client } = makeMockedClient([
        { status: 200, body: { success: true, data: incomplete } },
      ]);
      let caught: unknown;
      try {
        await client.shipGate.check({
          systemId: VALID_SYSTEM_ID,
          attestationId: VALID_ATTESTATION_ID,
        });
      } catch (err) {
        caught = err;
      }
      // **Load-bearing assertion**: SDK rejected DESPITE both the
      // `Object.hasOwn` override AND the type-valid prototype
      // pollution. The module-load snapshot survived the override
      // — validator's `objectHasOwn` is the snapshot, NOT the
      // overridden global.
      expect(caught).toBeInstanceOf(AttestryError);
      expect(caught).not.toBeInstanceOf(AttestryAPIError);
      expect((caught as AttestryError).message).toContain(
        "shipGate.check: expected response.gated to be a boolean",
      );
      expect((caught as AttestryError).message).toContain("got undefined");
    } finally {
      // Session-19 review-3 L4: restore spy EAGERLY before
      // proto-cleanup. afterEach's vi.restoreAllMocks() is the
      // safety net.
      hasOwnSpy?.mockRestore();
      delete originalProto.gated;
    }
  });

  it("H10: forward-compat Shape A with extra `reason` own-property + gated:false — preserved verbatim, no normalization", async () => {
    // Asymmetric with H4 (which covers `gated:true + no reason` —
    // forward-compat synthetic, validator-leniency on a DROPPED
    // optional field). H10 covers the symmetric forward-compat
    // direction: a future kernel might emit `reason` as a non-empty
    // diagnostic on Shape A / B (e.g., `reason: "no_gate_configured"`
    // or `reason: "released_at_2026-05-13"`) — an ADDED optional
    // field where the current shapes have it absent. The SDK is a
    // faithful courier — preserves the value as-given. Pin: response
    // with `gated:false` + extra `reason` is accepted and forwarded.
    //
    // The validator's `typeof reason !== "string"` check passes (it's
    // a string); no rejection. The SDK does NOT enforce a cross-field
    // rule "reason should be absent when gated:false".
    // Cast via `Record<string, unknown>` instead of asserting the
    // future-string into the closed `ShipGateReasonCode` union —
    // the closed-union assertion would be a compile-time lie. The
    // test exercises RUNTIME laxness; the runtime type IS just a
    // string, but the closed union excludes "no_gate_configured" at
    // the type level. Cast via the unknown-record bypass to match
    // how this synthetic input arrives off the wire.
    const futureCompat = {
      gated: false,
      reason: "no_gate_configured",
    } as unknown as Record<string, unknown>;
    const { client } = makeMockedClient([
      { status: 200, body: { success: true, data: futureCompat } },
    ]);
    const out = await client.shipGate.check({
      systemId: VALID_SYSTEM_ID,
      attestationId: VALID_ATTESTATION_ID,
    });
    expect(out.gated).toBe(false);
    // Faithful-courier preservation — the SDK does NOT enforce a
    // cross-field consistency rule between gated and reason.
    expect(out.reason).toBe("no_gate_configured");
  });
});
