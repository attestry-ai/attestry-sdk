import { describe, it, expect, vi } from "vitest";
import { AttestryClient } from "../client.js";
import { AttestryAPIError, AttestryError } from "../errors.js";
import type { FetchLike } from "../types.js";

const okFetch: FetchLike = async () =>
  new Response(JSON.stringify({ success: true, data: { ok: true } }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });

describe("AttestryClient", () => {
  it("constructs successfully with a valid apiKey", () => {
    const client = new AttestryClient({ apiKey: "k", fetch: okFetch });
    expect(client.incidents).toBeDefined();
  });

  it("propagates resolveClientConfig errors", () => {
    expect(
      () => new AttestryClient({ apiKey: "", fetch: okFetch }),
    ).toThrowError(AttestryError);
  });

  it("dispatches requests through `_request` to transport", async () => {
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify({ success: true, data: { a: 1 } }), {
        status: 200,
        // P3: transport now requires Content-Type: application/json
        // on 2xx success responses (sync content-type guard).
        headers: { "Content-Type": "application/json" },
      }),
    );
    const client = new AttestryClient({
      apiKey: "k",
      fetch: mockFetch as FetchLike,
    });
    const out = await client._request<{ a: number }>({
      method: "GET",
      path: "/x",
    });
    expect(out).toEqual({ a: 1 });
    expect(mockFetch).toHaveBeenCalledOnce();
  });
});

describe("AttestryError / AttestryAPIError", () => {
  it("AttestryError sets name and preserves cause", () => {
    const cause = new Error("upstream");
    const err = new AttestryError("network error: x", { cause });
    expect(err.name).toBe("AttestryError");
    expect(err.message).toBe("network error: x");
    expect((err as Error & { cause?: unknown }).cause).toBe(cause);
  });

  it("AttestryError without options does NOT set a cause field (coverage)", () => {
    // Branch: options?.cause === undefined → don't assign `cause`. This
    // matters because consumers checking `if (err.cause)` shouldn't see a
    // bogus undefined property when no cause was passed.
    const err = new AttestryError("standalone");
    expect((err as Error & { cause?: unknown }).cause).toBeUndefined();
  });

  it("AttestryAPIError extends AttestryError and carries status + details", () => {
    const err = new AttestryAPIError("bad", 422, { issues: [] });
    expect(err).toBeInstanceOf(AttestryError);
    expect(err).toBeInstanceOf(AttestryAPIError);
    expect(err.name).toBe("AttestryAPIError");
    expect(err.status).toBe(422);
    expect(err.details).toEqual({ issues: [] });
  });

  it("instanceof works through `try/catch` rethrow chains (prototype preserved)", () => {
    function reThrow() {
      try {
        throw new AttestryAPIError("x", 500);
      } catch (err) {
        throw err;
      }
    }
    let caught: unknown;
    try {
      reThrow();
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(AttestryAPIError);
    expect(caught).toBeInstanceOf(AttestryError);
    expect(caught).toBeInstanceOf(Error);
  });
});
