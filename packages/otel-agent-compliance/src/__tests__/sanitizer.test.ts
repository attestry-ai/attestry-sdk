import { describe, expect, it } from "vitest";
import { sanitizePII, __test__ } from "../sanitizer.js";

const { redactString, REDACTED } = __test__;

describe("sanitizePII", () => {
  describe("redactString — primitive PII patterns", () => {
    it("redacts plain emails", () => {
      expect(redactString("contact alice@example.com today")).toBe(
        `contact ${REDACTED} today`,
      );
    });

    it("redacts emails with subdomains and plus addressing", () => {
      expect(redactString("hi user+tag@mail.corp.example.co")).toBe(
        `hi ${REDACTED}`,
      );
    });

    it("redacts US-style and E.164 phone numbers", () => {
      expect(redactString("call (415) 555-0199 now")).toBe(
        `call ${REDACTED} now`,
      );
      expect(redactString("call +1-415-555-0199 now")).toBe(
        `call ${REDACTED} now`,
      );
    });

    it("redacts SSNs only when separator-formatted", () => {
      expect(redactString("ssn 123-45-6789 here")).toBe(
        `ssn ${REDACTED} here`,
      );
      // bare 9-digit numbers are NOT redacted as SSNs (avoid false
      // positives on order numbers); they MAY be caught by the
      // credit-card regex if they're long enough — but 9 digits is
      // below the 13-char cc minimum, so this stays intact.
      expect(redactString("ref 123456789 here")).toBe("ref 123456789 here");
    });

    it("redacts 13-19 digit credit-card-shaped numbers", () => {
      expect(redactString("card 4111-1111-1111-1111 ok")).toBe(
        `card ${REDACTED} ok`,
      );
      expect(redactString("card 4111 1111 1111 1111 ok")).toBe(
        `card ${REDACTED} ok`,
      );
    });

    it("redacts IPv4 addresses", () => {
      expect(redactString("from 192.168.1.42 connected")).toBe(
        `from ${REDACTED} connected`,
      );
    });

    it("returns clean strings unchanged", () => {
      expect(redactString("the quick brown fox")).toBe("the quick brown fox");
    });

    it("is O(n) on adversarial inputs (no ReDoS)", () => {
      const adversarial = "a".repeat(10_000) + "@";
      const start = Date.now();
      redactString(adversarial);
      const elapsed = Date.now() - start;
      // Generous budget — pathological backtracking would blow well past.
      expect(elapsed).toBeLessThan(500);
    });
  });

  describe("sanitizePII — recursive walk", () => {
    it("redacts strings inside nested objects", () => {
      const out = sanitizePII({
        user: { email: "x@y.com", name: "alice" },
        request: { headers: { from: "ops@example.com" } },
      });
      expect(out).toEqual({
        user: { email: REDACTED, name: "alice" },
        request: { headers: { from: REDACTED } },
      });
    });

    it("redacts strings inside arrays", () => {
      const out = sanitizePII({ recipients: ["a@b.com", "plain text"] });
      expect(out).toEqual({ recipients: [REDACTED, "plain text"] });
    });

    it("preserves non-string primitives (number, boolean, null)", () => {
      const out = sanitizePII({ n: 42, b: true, x: null });
      expect(out).toEqual({ n: 42, b: true, x: null });
    });

    it("does not mutate the input object", () => {
      const input = { email: "x@y.com" };
      sanitizePII(input);
      expect(input).toEqual({ email: "x@y.com" });
    });

    it("survives circular references without stack overflow", () => {
      const a: { self?: unknown; v: string } = { v: "u@v.com" };
      a.self = a;
      const out = sanitizePII({ a }) as { a: { self: unknown; v: string } };
      // First visit redacts the email; second visit hits the cycle
      // guard and returns REDACTED for the back-edge.
      expect(out.a.v).toBe(REDACTED);
      expect(out.a.self).toBe(REDACTED);
    });

    it("caps recursion at MAX_DEPTH (deep linear nesting)", () => {
      // Build a 50-deep linearly-nested object — past the 20-depth cap.
      // Anything past depth 20 is REDACTED wholesale; up to depth 20 is
      // walked normally.
      let nested: unknown = "leaf-value";
      for (let i = 0; i < 50; i++) {
        nested = { next: nested };
      }
      const out = sanitizePII({ nested });
      // Walk down to depth 20 — each level should still be a `{next: ...}`.
      // The sanitizer enters at depth=1, so out.nested is depth-1.
      // After 19 hops we're at depth-20 (still an object). One more
      // hop reaches depth-21, which is past the cap → REDACTED.
      let cursor: unknown = (out as { nested: unknown }).nested;
      for (let i = 0; i < 19; i++) {
        expect(typeof cursor).toBe("object");
        cursor = (cursor as { next: unknown }).next;
      }
      // cursor is at depth 20 (still an object). Its `.next` is REDACTED.
      expect(typeof cursor).toBe("object");
      expect((cursor as { next: unknown }).next).toBe(REDACTED);
    });
  });
});
