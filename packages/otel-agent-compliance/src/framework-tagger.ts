/**
 * Heuristic mapping from span context (name + attributes) to framework
 * article claims. Customers who care about precise tagging supply their
 * own tagger via `AttestryExporterConfig.frameworkTagger`; this
 * default is intentionally conservative.
 *
 * Conservative ⇒ when in doubt, return `[]` (no claim). Over-tagging
 * is worse than under-tagging because every claim becomes part of the
 * canonical hash and the customer's audit narrative.
 *
 * Mapping rules (in priority order — first match wins per category):
 *
 *  1. **Classification / risk-categorization**
 *     - `ai.operation === "classification"` OR span name contains
 *       "classify" → EU AI Act Article 6 (high-risk classification
 *       rules), NIST AI RMF MAP-1.1.
 *
 *  2. **LLM completion**
 *     - `ai.operation === "completion"`, `gen_ai.operation.name === "chat"`,
 *       OR span name contains "llm"/"completion" → EU AI Act Article 50
 *       (transparency obligations for general-purpose AI), NIST AI RMF
 *       MEASURE-2.7.
 *
 *  3. **Tool / function call**
 *     - `tool.name` set OR span name contains "tool" → EU AI Act
 *       Article 14 (human oversight — tool calls are oversight
 *       chokepoints), ISO 42001 § 8.4.
 *
 *  4. **Policy evaluation**
 *     - `policy.outcome` set OR span name contains "policy" → EU AI Act
 *       Article 9 (risk management system), NIST AI RMF GOVERN-1.4.
 *
 *  5. **Retrieval / RAG**
 *     - Span name contains "retrieval"/"rag" OR `vector_db.*` attrs
 *       set → ISO 42001 § 8.2 (data quality), NIST AI RMF MEASURE-2.10.
 *
 * Spans matching none of the above return `[]`. The exporter still
 * records them as decisions if `shouldRecordAsDecision` returned true —
 * the framework tags are advisory metadata, not the determining factor.
 */

import type { FrameworkClaim, SpanFrameworkContext } from "./types.js";

function attrIsTruthy(value: unknown): boolean {
  if (value === undefined || value === null) return false;
  if (typeof value === "string") return value.length > 0;
  return true;
}

function nameContains(name: string, needle: string): boolean {
  return name.toLowerCase().includes(needle);
}

export function tagWithFrameworks(
  ctx: SpanFrameworkContext,
): FrameworkClaim[] {
  const { name, attributes } = ctx;
  const claims: FrameworkClaim[] = [];

  // (1) Classification
  if (
    attributes["ai.operation"] === "classification" ||
    nameContains(name, "classify")
  ) {
    claims.push(
      {
        framework: "EU AI Act",
        article: "Article 6",
        claim:
          "Classification rules for high-risk AI systems — span recorded as evidence of automated risk categorization decision.",
      },
      {
        framework: "NIST AI RMF",
        article: "MAP-1.1",
        claim:
          "Context for AI system established at decision time; span captures input/output digests for traceability.",
      },
    );
    return claims;
  }

  // (2) LLM completion
  if (
    attributes["ai.operation"] === "completion" ||
    attributes["gen_ai.operation.name"] === "chat" ||
    nameContains(name, "llm") ||
    nameContains(name, "completion")
  ) {
    claims.push(
      {
        framework: "EU AI Act",
        article: "Article 50",
        claim:
          "General-purpose AI transparency — model output linked to a content-addressed input/output pair.",
      },
      {
        framework: "NIST AI RMF",
        article: "MEASURE-2.7",
        claim:
          "Output validity captured via cryptographic digest at the point of generation.",
      },
    );
    return claims;
  }

  // (3) Tool / function call
  if (attrIsTruthy(attributes["tool.name"]) || nameContains(name, "tool")) {
    claims.push(
      {
        framework: "EU AI Act",
        article: "Article 14",
        claim:
          "Human oversight checkpoint — tool invocation captured for after-the-fact review.",
      },
      {
        framework: "ISO 42001",
        article: "8.4",
        claim:
          "Operational control evidence — external tool call recorded with input/output digests.",
      },
    );
    return claims;
  }

  // (4) Policy evaluation
  if (
    attrIsTruthy(attributes["policy.outcome"]) ||
    attrIsTruthy(attributes["decision.outcome"]) ||
    nameContains(name, "policy")
  ) {
    claims.push(
      {
        framework: "EU AI Act",
        article: "Article 9",
        claim:
          "Risk management system — policy decision recorded with deterministic input.",
      },
      {
        framework: "NIST AI RMF",
        article: "GOVERN-1.4",
        claim: "Policy outcome recorded at the time of evaluation.",
      },
    );
    return claims;
  }

  // (5) Retrieval / RAG
  const hasVectorDbAttr = Object.keys(attributes).some((k) =>
    k.startsWith("vector_db.") || k.startsWith("db.vector."),
  );
  if (
    nameContains(name, "retrieval") ||
    nameContains(name, "rag") ||
    hasVectorDbAttr
  ) {
    claims.push(
      {
        framework: "ISO 42001",
        article: "8.2",
        claim:
          "Data quality — retrieval source content addressed by digest at the point of grounding.",
      },
      {
        framework: "NIST AI RMF",
        article: "MEASURE-2.10",
        claim: "Provenance recorded for retrieval-augmented generation context.",
      },
    );
    return claims;
  }

  return claims;
}
