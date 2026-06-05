import { describe, expect, it } from "vitest";
import { tagWithFrameworks } from "../framework-tagger.js";

describe("tagWithFrameworks", () => {
  it("tags classification spans with EU AI Act Article 6 + NIST MAP-1.1", () => {
    const claims = tagWithFrameworks({
      name: "model.classify",
      attributes: { "ai.operation": "classification" },
    });
    expect(claims.map((c) => `${c.framework}/${c.article}`)).toEqual([
      "EU AI Act/Article 6",
      "NIST AI RMF/MAP-1.1",
    ]);
  });

  it("tags LLM completion spans with Article 50 + MEASURE-2.7", () => {
    const claims = tagWithFrameworks({
      name: "openai.chat.completion",
      attributes: { "gen_ai.operation.name": "chat" },
    });
    expect(claims).toContainEqual(
      expect.objectContaining({
        framework: "EU AI Act",
        article: "Article 50",
      }),
    );
    expect(claims).toContainEqual(
      expect.objectContaining({
        framework: "NIST AI RMF",
        article: "MEASURE-2.7",
      }),
    );
  });

  it("tags tool spans with Article 14 + ISO 42001 §8.4", () => {
    const claims = tagWithFrameworks({
      name: "my.tool.call",
      attributes: { "tool.name": "fetch_user" },
    });
    expect(claims.map((c) => c.article)).toEqual(["Article 14", "8.4"]);
  });

  it("tags policy spans with Article 9 + GOVERN-1.4", () => {
    const claims = tagWithFrameworks({
      name: "policy.evaluate",
      attributes: { "policy.outcome": "permitted" },
    });
    expect(claims.map((c) => c.article)).toEqual(["Article 9", "GOVERN-1.4"]);
  });

  it("tags retrieval spans via vector_db.* attributes", () => {
    const claims = tagWithFrameworks({
      name: "search",
      attributes: { "vector_db.collection": "docs" },
    });
    expect(claims.map((c) => `${c.framework}/${c.article}`)).toEqual([
      "ISO 42001/8.2",
      "NIST AI RMF/MEASURE-2.10",
    ]);
  });

  it("tags retrieval spans via name keyword 'rag'", () => {
    const claims = tagWithFrameworks({
      name: "rag.lookup",
      attributes: {},
    });
    expect(claims).toHaveLength(2);
    expect(claims[0]?.framework).toBe("ISO 42001");
  });

  it("first-match-wins — classification beats completion", () => {
    const claims = tagWithFrameworks({
      name: "classify-llm",
      attributes: {
        "ai.operation": "classification",
        "gen_ai.operation.name": "chat",
      },
    });
    expect(claims.map((c) => c.article)).toEqual(["Article 6", "MAP-1.1"]);
  });

  it("returns [] for spans that match no rule", () => {
    const claims = tagWithFrameworks({
      name: "http.request",
      attributes: { "http.url": "https://example.com" },
    });
    expect(claims).toEqual([]);
  });

  it("ignores empty-string truthy attrs (e.g. tool.name='')", () => {
    const claims = tagWithFrameworks({
      name: "no-match",
      attributes: { "tool.name": "" },
    });
    expect(claims).toEqual([]);
  });
});
