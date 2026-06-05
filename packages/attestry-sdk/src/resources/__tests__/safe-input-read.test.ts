import { describe, it, expect } from "vitest";
import { readInputField } from "../safe-input-read.js";

// ─── readInputField — defensive input-field read ────────────────────────────
//
// Session-22 hostile review #1: the SDK-wide MEDIUM-1 getter-throws
// contract gap. Every resource validates input by reading fields off a
// consumer-supplied object; a throwing accessor on that object would
// surface the getter's raw exception instead of the documented
// synchronous `TypeError` input contract. `readInputField` wraps the
// read and re-throws a getter's exception as a `TypeError` (cause-
// chained). These unit tests pin the helper directly; the per-resource
// regression pins (abac-policies / decisions / check test files) prove
// the integration.

describe("readInputField — happy path", () => {
  it("returns the value of a present own field", () => {
    expect(readInputField({ name: "x" }, "name", "ctx")).toBe("x");
  });

  it("returns undefined for an absent field (same as a bare read)", () => {
    expect(readInputField({}, "missing", "ctx")).toBeUndefined();
  });

  it("returns a falsy value verbatim (0 / false / null / empty string)", () => {
    expect(readInputField({ a: 0 }, "a", "ctx")).toBe(0);
    expect(readInputField({ a: false }, "a", "ctx")).toBe(false);
    expect(readInputField({ a: null }, "a", "ctx")).toBeNull();
    expect(readInputField({ a: "" }, "a", "ctx")).toBe("");
  });

  it("walks the prototype chain (reads an inherited property) — same as a bare `obj.key`", () => {
    const proto = { inherited: "from-proto" };
    const obj = Object.create(proto) as object;
    expect(readInputField(obj, "inherited", "ctx")).toBe("from-proto");
  });

  it("invokes a NON-throwing getter and returns its value", () => {
    let calls = 0;
    const obj = {
      get computed() {
        calls += 1;
        return "computed-value";
      },
    };
    expect(readInputField(obj, "computed", "ctx")).toBe("computed-value");
    expect(calls).toBe(1);
  });
});

describe("readInputField — throwing getter → TypeError contract", () => {
  it("converts a throwing getter's exception into a TypeError", () => {
    const obj = {
      get evil(): unknown {
        throw new Error("getter boom");
      },
    };
    expect(() => readInputField(obj, "evil", "ctx")).toThrow(TypeError);
  });

  it("the TypeError message names the context and the key", () => {
    const obj = {
      get evil(): unknown {
        throw new Error("getter boom");
      },
    };
    let caught: unknown;
    try {
      readInputField(obj, "evil", "abacPolicies.create");
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(TypeError);
    const msg = (caught as Error).message;
    expect(msg).toContain("abacPolicies.create");
    expect(msg).toContain("evil");
    expect(msg).toContain("getter threw");
    // The getter's OWN message is NOT spliced into the SDK message —
    // the SDK authors its own contract message.
    expect(msg).not.toContain("getter boom");
  });

  it("preserves the original error on `.cause` (ES2022 cause chain)", () => {
    const original = new Error("getter boom");
    const obj = {
      get evil(): unknown {
        throw original;
      },
    };
    let caught: unknown;
    try {
      readInputField(obj, "evil", "ctx");
    } catch (err) {
      caught = err;
    }
    expect((caught as Error & { cause?: unknown }).cause).toBe(original);
  });

  it("a getter throwing a NON-Error value still surfaces as a TypeError (cause is the raw value)", () => {
    // A getter may throw ANY value, not just an `Error`. The thrown
    // value is held in an `unknown`-typed local so the `throw`
    // expression stays lint-clean while still exercising the
    // non-Error `cause` path through `readInputField`'s catch.
    const notAnError: unknown = "a bare string, not an Error";
    const obj = {
      get evil(): unknown {
        throw notAnError;
      },
    };
    let caught: unknown;
    try {
      readInputField(obj, "evil", "ctx");
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(TypeError);
    expect((caught as Error & { cause?: unknown }).cause).toBe(
      "a bare string, not an Error",
    );
  });

  it("a getter installed on the PROTOTYPE that throws is also converted", () => {
    // A hostile dependency that polluted Object.prototype with a
    // throwing accessor — `readInputField` walks the chain, hits the
    // accessor, and converts the throw uniformly.
    const proto = {
      get polluted(): unknown {
        throw new Error("prototype getter boom");
      },
    };
    const obj = Object.create(proto) as object;
    expect(() => readInputField(obj, "polluted", "ctx")).toThrow(TypeError);
  });
});
