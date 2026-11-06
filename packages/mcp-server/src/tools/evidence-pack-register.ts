import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  evidencePackCreate,
  evidencePackCreateSchema,
  evidencePackCreateDescription,
} from "./evidence-pack-create.js";
import {
  evidencePackGet,
  evidencePackGetSchema,
  evidencePackGetDescription,
} from "./evidence-pack-get.js";
import {
  evidencePackList,
  evidencePackListSchema,
  evidencePackListDescription,
} from "./evidence-pack-list.js";
import {
  evidencePackAppendBundle,
  evidencePackAppendBundleSchema,
  evidencePackAppendBundleDescription,
} from "./evidence-pack-append-bundle.js";

/**
 * KE2 P1.5 — register the four evidence-pack MCP tools on an `McpServer`.
 *
 * Extracted from `src/index.ts` so the registration glue AND the four
 * `isError`-propagating handler adapters are unit-testable: `index.ts`
 * is an entry-point module — importing it runs `main()`, which connects
 * a live stdio transport — so it cannot be executed under coverage.
 * Pulling the registrations into this function lets a test drive them
 * with a fake server and exercise every adapter (DEV-49).
 *
 * Each adapter maps the tool's `{text, isError}` result onto the MCP
 * `CallToolResult`, so a REST failure surfaces as a protocol-level tool
 * error (`isError: true`) rather than a success-shaped payload — spec
 * P1.5 hostile concern #4 / DEV-41.
 */
export function registerEvidencePackTools(server: McpServer): void {
  server.tool(
    "attestry_evidence_pack_create",
    evidencePackCreateDescription,
    evidencePackCreateSchema,
    async (args) => {
      const result = await evidencePackCreate(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_evidence_pack_get",
    evidencePackGetDescription,
    evidencePackGetSchema,
    async (args) => {
      const result = await evidencePackGet(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_evidence_pack_list",
    evidencePackListDescription,
    evidencePackListSchema,
    async (args) => {
      const result = await evidencePackList(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_evidence_pack_append_bundle",
    evidencePackAppendBundleDescription,
    evidencePackAppendBundleSchema,
    async (args) => {
      const result = await evidencePackAppendBundle(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );
}
