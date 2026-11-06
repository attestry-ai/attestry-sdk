import { z } from "zod";
import type { EvidencePackToolResult } from "./evidence-pack-shared.js";

/**
 * KE2 P4.8 — shared surface for the four regulation / schedule MCP tools
 * (`attestry_regulation_cite` / `_crosswalk` / `_applicability` /
 * `attestry_schedule_deadline`).
 *
 * DEV-88: the generic REST-call + outcome-mapping machinery (`callRest`,
 * `outcomeToResult`, and the `apiGet` HTTP helper underneath) is re-used
 * verbatim from the closed P1.5 `evidence-pack-shared.ts`. Those helpers are
 * generic over `RestEnvelope<T>` with NO evidence-pack-specific logic, so the
 * regulation tools reuse them rather than duplicate ~60 lines that would then
 * drift. The `{text, isError}` result shape is generic; it is re-exported here
 * under a regulation-domain name (`RegulationToolResult`).
 */

export { apiGet, callRest, outcomeToResult } from "./evidence-pack-shared.js";

/**
 * The `{text, isError}` MCP tool result. Structurally identical to the
 * evidence-pack tools' result (re-exported under a regulation-domain name);
 * the registrar in `regulation-register.ts` maps `isError` onto the MCP
 * `CallToolResult`.
 */
export type RegulationToolResult = EvidencePackToolResult;

/**
 * Length cap on framework-name / free-text inputs, mirroring the REST routes'
 * `FRAMEWORK_PARAM_MAX_LEN` (crosswalk / applicability / cite). Bounds
 * pathological inputs at the MCP (SDK) boundary before they reach the wire.
 */
export const FRAMEWORK_PARAM_MAX_LEN = 200;

/**
 * Framework-name input primitive: a non-empty, length-capped string.
 *
 * Normalization + alias / canonical resolution happens SERVER-SIDE
 * (`resolveFrameworkName` in the REST route) — the MCP boundary only bounds the
 * raw shape, because the standalone mcp-server cannot import the kernel
 * resolver. Normalization is never re-implemented here.
 */
export const frameworkNameArg = () =>
  z.string().min(1).max(FRAMEWORK_PARAM_MAX_LEN);
