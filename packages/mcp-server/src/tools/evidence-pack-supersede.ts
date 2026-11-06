import { z } from "zod";
import { createHash } from "node:crypto";
import { getConfig, type ApiResponse } from "../client.js";
import {
  PACK_TYPES,
  uuidLc,
  callRest,
  outcomeToResult,
  type EvidencePackToolResult,
} from "./evidence-pack-shared.js";

/**
 * MCP tool: evidence_pack.supersede
 * (registered `attestry_evidence_pack_supersede`).
 * Wraps POST /api/v1/evidence-packs/{id}/supersede — transitions a SIGNED
 * pack to `superseded` and creates a new draft pack linked to it.
 *
 * Authority (P1.7 DQ-1): this tool's authority IS the MCP server's
 * configured `ATTESTRY_API_KEY`; a read-scoped key (the documented default)
 * makes the tool inert (the REST route 403s). `supersede` does NOT carry a
 * `confirm` gate — only `sign` / `revoke` do (DQ-1).
 *
 * Idempotency (P1.7 DQ-2): the tool derives a deterministic
 * `Idempotency-Key = sha256(oldPackId + canonicalJSON(newPack))` and sends
 * it on the REST call, so an accidental retry of an identical supersede
 * replays the kernel's first result instead of creating a duplicate pack.
 * An optional `idempotencyKey` argument overrides the derived key.
 *
 * Transport (P1.7 DEV-54): the supersede call must carry an
 * `Idempotency-Key` request header. `client.ts`'s `apiPost` cannot send a
 * custom header and is shared by every existing tool (out of P1.7 scope —
 * not modified), so this tool uses a minimal local POST helper that mirrors
 * `apiPost`'s request shape and reuses `getConfig`.
 */

// ─── Nested mirror of the kernel `supersedeNewPackPayloadSchema` ─────────────
//
// Descriptive mirror (P1.5 DEV-43): `packType` mirrors the drift-pinned
// closed enum and `systemId` is rigorously UUID-mirrored; the nested
// `frameworkBindings` / `consumerHints` shapes are descriptive (field names
// + optionality + `.describe()`). The kernel route stays the authoritative
// validator for deep bounds + `.strict()` rejection.

const frameworkBindingSchema = z
  .object({
    framework: z
      .string()
      .describe("Framework key, e.g. 'eu_ai_act' or 'colorado_ai_act'."),
    identifier: z
      .string()
      .describe("Framework-specific identifier (article / clause / control)."),
    jurisdiction: z
      .string()
      .optional()
      .describe("Optional jurisdiction, e.g. 'EU' or 'US-CO'."),
    effective_date: z
      .string()
      .optional()
      .describe("Optional ISO-8601 date the binding takes effect."),
  })
  .describe("A single regulatory framework binding.");

const consumerHintsSchema = z
  .object({
    allowPublicRetrieval: z
      .boolean()
      .optional()
      .describe(
        "Whether the new pack may be retrieved via the public verify API.",
      ),
    suggestedVerifier: z
      .string()
      .optional()
      .describe("Optional hint URL for a suggested third-party verifier."),
    expectedQueryPatterns: z
      .array(z.string())
      .optional()
      .describe("Optional list of expected query patterns (cache hints)."),
  })
  .describe("Optional consumer-consumption hints for the new pack.");

const newPackSchema = z
  .object({
    packType: z
      .enum(PACK_TYPES)
      .describe(
        "Evidence pack type for the NEW pack. One of: annex_iv, " +
          "agentic_reperformance, red_team_cycle, pccp_evidence, " +
          "underwriting_evidence.",
      ),
    systemId: uuidLc()
      .optional()
      .describe(
        "Optional UUID of the AI system the new pack is scoped to. Omit " +
          "for an org-level pack.",
      ),
    frameworkBindings: z
      .array(frameworkBindingSchema)
      .optional()
      .describe("Optional list of regulatory framework bindings."),
    consumerHints: consumerHintsSchema.optional(),
    metadata: z
      .record(z.string(), z.unknown())
      .optional()
      .describe("Optional free-form metadata object (string-keyed)."),
  })
  .describe(
    "Inner payload for the NEW draft pack the supersede creates. Mirrors " +
      "the kernel `supersedeNewPackPayloadSchema`.",
  );

export const evidencePackSupersedeSchema = {
  oldPackId: uuidLc().describe(
    "UUID of the SIGNED evidence pack to supersede.",
  ),
  newPack: newPackSchema,
  idempotencyKey: z
    .string()
    .min(1)
    .optional()
    .describe(
      "Optional override for the request's Idempotency-Key. When omitted, " +
        "the tool derives a deterministic key from the request content so " +
        "an accidental identical retry does not create a duplicate pack.",
    ),
};

export const evidencePackSupersedeDescription =
  "Supersede a signed evidence pack: transitions the old pack from 'signed' " +
  "to 'superseded' and creates a new linked draft pack. A tool's authority " +
  "is the permission set of the MCP server's configured ATTESTRY_API_KEY; a " +
  "read-scoped key (the documented default) makes this tool inert (HTTP " +
  "403) — recommended for autonomous or untrusted AI deployments. The tool " +
  "derives a deterministic Idempotency-Key from the request content, so an " +
  "accidental identical retry replays the first result instead of creating " +
  "a duplicate pack. Returns {newPack, oldPack}.";

// ─── DQ-2 idempotency-key derivation ────────────────────────────────────────

/**
 * Recursively rebuild a JSON value with every object's keys sorted, so two
 * structurally-identical payloads serialize byte-identically regardless of
 * key insertion order. Array order is preserved (it is semantic). A small
 * local helper per DQ-2 — deliberately no kernel dependency.
 *
 * The rebuilt object uses `Object.create(null)` (no prototype). MCP
 * arguments arrive via `JSON.parse`, which — unlike an object literal — can
 * produce an own enumerable `__proto__` key; assigning that key to a normal
 * `{}` invokes the `Object.prototype` `__proto__` setter and silently drops
 * it, so two payloads differing only inside a `__proto__` key would derive
 * the same idempotency key (hostile-redux F-HR-1). A null-prototype object
 * has no such setter — every key, `__proto__` included, round-trips as a
 * plain own property.
 */
function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  const obj = value as Record<string, unknown>;
  const sorted: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = canonicalize(obj[key]);
  }
  return sorted;
}

/**
 * DQ-2: derive a deterministic Idempotency-Key from the supersede request
 * content — `sha256(oldPackId + canonicalJSON(newPack))`, hex-encoded. An
 * identical supersede (same old pack + structurally-identical new-pack
 * payload) always produces the same key, so the kernel replays its first
 * result instead of creating a duplicate pack; any difference in `oldPackId`
 * or `newPack` produces a different key.
 */
export function deriveIdempotencyKey(
  oldPackId: string,
  newPack: unknown,
): string {
  const canonicalNewPack = JSON.stringify(canonicalize(newPack));
  return createHash("sha256")
    .update(oldPackId + canonicalNewPack)
    .digest("hex");
}

// ─── Header-bearing POST helper (DEV-54) ────────────────────────────────────

/**
 * POST helper that carries an `Idempotency-Key` header.
 *
 * `client.ts`'s `apiPost` cannot send a custom header and is shared by every
 * existing MCP tool (out of P1.7 scope — must not be modified). This minimal
 * helper mirrors `apiPost`'s exact request shape — method, the `x-api-key` /
 * `Content-Type` / `Accept` / `User-Agent` headers, the `JSON.stringify`
 * body, the `response.json()` parse — and reuses `getConfig` so the API-key
 * and base-URL resolution stays single-sourced. The only addition is the
 * `Idempotency-Key` header DQ-2 requires.
 */
async function postWithIdempotencyKey<T = unknown>(
  path: string,
  body: Record<string, unknown>,
  idempotencyKey: string,
): Promise<ApiResponse<T>> {
  const config = getConfig();
  const url = new URL(path, config.apiUrl);
  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      // Attestry only accepts x-api-key for inbound API calls — never Bearer.
      "x-api-key": config.apiKey,
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "attestry-mcp-server/1.1.0",
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify(body),
  });
  return (await response.json()) as ApiResponse<T>;
}

export async function evidencePackSupersede(args: {
  oldPackId: string;
  newPack: unknown;
  idempotencyKey?: string;
}): Promise<EvidencePackToolResult> {
  // Body from explicitly-named fields only: `oldPackId` rides the URL path,
  // `idempotencyKey` becomes a request header (never a body field — the
  // kernel body schema is `.strict()`), `orgId` / `userId` are auth-derived.
  const body: Record<string, unknown> = { newPack: args.newPack };

  // `oldPackId` is UUID-validated + lowercased by the schema;
  // `encodeURIComponent` is belt-and-suspenders against URL-path injection.
  // The DQ-2 key derivation runs INSIDE the `callRest` closure (hostile-redux
  // HR2-2): any throw from it then surfaces as a clean `isError` transport
  // result rather than escaping as a raw exception — e.g. the
  // structurally-unreachable case of a cyclic `newPack` overflowing
  // `canonicalize`. Every protocol-reachable input is a `JSON.parse`d
  // (acyclic, JSON-typed) value, for which the derivation cannot throw.
  const outcome = await callRest(() => {
    // DQ-2: a caller-supplied override, else a deterministic content-derived
    // key so an accidental identical retry does not duplicate the pack.
    const idempotencyKey =
      args.idempotencyKey ?? deriveIdempotencyKey(args.oldPackId, args.newPack);
    return postWithIdempotencyKey(
      `/api/v1/evidence-packs/${encodeURIComponent(args.oldPackId)}/supersede`,
      body,
      idempotencyKey,
    );
  });
  return outcomeToResult(outcome, "Failed to supersede evidence pack.");
}
