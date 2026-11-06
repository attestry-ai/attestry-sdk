import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  regulationCite,
  regulationCiteSchema,
  regulationCiteDescription,
} from "./regulation-cite.js";
import {
  regulationCrosswalk,
  regulationCrosswalkSchema,
  regulationCrosswalkDescription,
} from "./regulation-crosswalk.js";
import {
  regulationApplicability,
  regulationApplicabilitySchema,
  regulationApplicabilityDescription,
} from "./regulation-applicability.js";
import {
  scheduleDeadline,
  scheduleDeadlineSchema,
  scheduleDeadlineDescription,
} from "./schedule-deadline.js";

/**
 * KE2 P4.8 — register the four regulation / schedule MCP tools
 * (`attestry_regulation_cite` / `_crosswalk` / `_applicability` /
 * `attestry_schedule_deadline`) on an `McpServer`.
 *
 * Sibling to P1.5 / P1.7's evidence-pack registrars. Kept as a SEPARATE
 * registrar so this glue plus its four `isError`-propagating handler adapters
 * are unit-testable: `index.ts` is an entry-point module (importing it runs
 * `main()`, which connects a live stdio transport) and cannot be executed under
 * coverage. Each adapter maps the tool's `{text, isError}` result onto the MCP
 * `CallToolResult`, so a REST failure surfaces as a protocol-level tool error
 * (`isError: true`) rather than a success-shaped payload.
 */
export function registerRegulationTools(server: McpServer): void {
  server.tool(
    "attestry_regulation_cite",
    regulationCiteDescription,
    regulationCiteSchema,
    async (args) => {
      const result = await regulationCite(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_regulation_crosswalk",
    regulationCrosswalkDescription,
    regulationCrosswalkSchema,
    async (args) => {
      const result = await regulationCrosswalk(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_regulation_applicability",
    regulationApplicabilityDescription,
    regulationApplicabilitySchema,
    async (args) => {
      const result = await regulationApplicability(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_schedule_deadline",
    scheduleDeadlineDescription,
    scheduleDeadlineSchema,
    async (args) => {
      const result = await scheduleDeadline(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );
}
