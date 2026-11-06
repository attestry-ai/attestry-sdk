import { describe, it, expect } from "vitest";
import {
  PACK_TYPES,
  PACK_STATUSES,
  uuidLc,
  callRest,
  successResult,
  errorResult,
  outcomeToResult,
  type RestEnvelope,
  type RestOutcome,
} from "../evidence-pack-shared.js";

/**
 * KE2 P1.5 — Build round: unit tests for the shared evidence-pack tool
 * surface (closed-enum mirrors, the UUID primitive, the REST-call wrapper,
 * and the result-mapping helpers).
 */

describe("evidence-pack-shared — closed-enum mirrors", () => {
  it("PACK_TYPES has the five kernel pack types", () => {
    expect([...PACK_TYPES]).toEqual([
      "annex_iv",
      "agentic_reperformance",
      "red_team_cycle",
      "pccp_evidence",
      "underwriting_evidence",
    ]);
  });

  it("PACK_STATUSES has the five kernel pack statuses", () => {
    expect([...PACK_STATUSES]).toEqual([
      "draft",
      "signed",
      "superseded",
      "revoked",
      "expired",
    ]);
  });
});

describe("evidence-pack-shared — uuidLc()", () => {
  it("accepts a valid UUID and lowercases it", () => {
    const parsed = uuidLc().safeParse("A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D");
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data).toBe("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    }
  });

  it("leaves an already-lowercase UUID unchanged", () => {
    const parsed = uuidLc().safeParse("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(parsed.data).toBe("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    }
  });

  it("rejects a non-UUID string", () => {
    expect(uuidLc().safeParse("not-a-uuid").success).toBe(false);
  });
});

describe("evidence-pack-shared — callRest()", () => {
  it("returns ok with the envelope when the call resolves", async () => {
    const outcome = await callRest(() =>
      Promise.resolve({ success: true, data: { x: 1 } }),
    );
    expect(outcome).toEqual({ ok: true, env: { success: true, data: { x: 1 } } });
  });

  it("catches an Error throw and reports its message", async () => {
    const outcome = await callRest(() =>
      Promise.reject(new Error("ECONNREFUSED")),
    );
    expect(outcome).toEqual({ ok: false, transportError: "ECONNREFUSED" });
  });

  it("catches a non-Error throw via String(e)", async () => {
    const outcome = await callRest(() => Promise.reject("plain string"));
    expect(outcome).toEqual({ ok: false, transportError: "plain string" });
  });
});

describe("evidence-pack-shared — successResult()", () => {
  it("pretty-prints the data payload", () => {
    const r = successResult({ id: "p1" });
    expect(r.isError).toBe(false);
    expect(JSON.parse(r.text)).toEqual({ id: "p1" });
    expect(r.text).toContain("\n");
  });

  it("renders undefined data as JSON null", () => {
    const r = successResult(undefined);
    expect(r.isError).toBe(false);
    expect(r.text).toBe("null");
  });
});

describe("evidence-pack-shared — errorResult()", () => {
  it("includes code and details when supplied", () => {
    const r = errorResult({
      error: "boom",
      code: "evidence_pack.not_found",
      details: { code: "evidence_pack.not_found" },
    });
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.text)).toEqual({
      error: "boom",
      code: "evidence_pack.not_found",
      details: { code: "evidence_pack.not_found" },
    });
  });

  it("omits code and details when not supplied", () => {
    const r = errorResult({ error: "boom" });
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.text)).toEqual({ error: "boom" });
  });
});

describe("evidence-pack-shared — outcomeToResult()", () => {
  it("maps a transport failure to an error result", () => {
    const r = outcomeToResult(
      { ok: false, transportError: "network down" },
      "fallback",
    );
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.text).error).toContain("network down");
  });

  it("maps a null envelope to the fallback error", () => {
    const outcome: RestOutcome<unknown> = {
      ok: true,
      env: null as unknown as RestEnvelope<unknown>,
    };
    const r = outcomeToResult(outcome, "fallback message");
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.text).error).toBe("fallback message");
  });

  it("maps a non-object envelope to the fallback error", () => {
    const outcome: RestOutcome<unknown> = {
      ok: true,
      env: 42 as unknown as RestEnvelope<unknown>,
    };
    const r = outcomeToResult(outcome, "fallback message");
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.text).error).toBe("fallback message");
  });

  it("maps {success:true, data} to a success result", () => {
    const r = outcomeToResult(
      { ok: true, env: { success: true, data: { id: "p1" } } },
      "fallback",
    );
    expect(r.isError).toBe(false);
    expect(JSON.parse(r.text)).toEqual({ id: "p1" });
  });

  it("maps {success:true} with no data to a success null result", () => {
    const r = outcomeToResult(
      { ok: true, env: { success: true } },
      "fallback",
    );
    expect(r.isError).toBe(false);
    expect(r.text).toBe("null");
  });

  it("maps a {success:false} envelope, surfacing error message + code", () => {
    const r = outcomeToResult(
      {
        ok: true,
        env: {
          success: false,
          error: "pack not found",
          details: { code: "evidence_pack.not_found" },
        },
      },
      "fallback",
    );
    expect(r.isError).toBe(true);
    const body = JSON.parse(r.text);
    expect(body.error).toBe("pack not found");
    expect(body.code).toBe("evidence_pack.not_found");
    expect(body.details).toEqual({ code: "evidence_pack.not_found" });
  });

  it("uses the fallback error when {success:false} carries no message", () => {
    const r = outcomeToResult(
      { ok: true, env: { success: false } },
      "fallback message",
    );
    expect(r.isError).toBe(true);
    const body = JSON.parse(r.text);
    expect(body.error).toBe("fallback message");
    expect(body.code).toBeUndefined();
  });

  it("surfaces details without a code (e.g. currentStatus only)", () => {
    const r = outcomeToResult(
      {
        ok: true,
        env: {
          success: false,
          error: "cannot append to a signed pack",
          details: { currentStatus: "signed" },
        },
      },
      "fallback",
    );
    expect(r.isError).toBe(true);
    const body = JSON.parse(r.text);
    expect(body.code).toBeUndefined();
    expect(body.details).toEqual({ currentStatus: "signed" });
  });

  it("uses the fallback when {success:false} error is not a string", () => {
    const r = outcomeToResult(
      {
        ok: true,
        env: { success: false, error: 123 as unknown as string },
      },
      "fallback message",
    );
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.text).error).toBe("fallback message");
  });
});
