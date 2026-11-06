import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  evidencePackSign,
  evidencePackSignSchema,
  evidencePackSignDescription,
} from "./evidence-pack-sign.js";
import {
  evidencePackSupersede,
  evidencePackSupersedeSchema,
  evidencePackSupersedeDescription,
} from "./evidence-pack-supersede.js";
import {
  evidencePackRevoke,
  evidencePackRevokeSchema,
  evidencePackRevokeDescription,
} from "./evidence-pack-revoke.js";
import {
  evidencePackExport,
  evidencePackExportSchema,
  evidencePackExportDescription,
} from "./evidence-pack-export.js";

/**
 * KE2 P1.7 — register the four evidence-pack lifecycle + export MCP tools
 * (`attestry_evidence_pack_sign` / `_supersede` / `_revoke` / `_export`) on
 * an `McpServer`.
 *
 * Sibling to P1.5's `registerEvidencePackTools` (the read/create surface).
 * Kept as a SEPARATE registrar — rather than extending the P1.5 one — so
 * the P1.5 surface, which is verified and closed, is not modified, and so
 * this glue plus its four `isError`-propagating handler adapters are
 * unit-testable: `index.ts` is an entry-point module (importing it runs
 * `main()`, which connects a live stdio transport) and cannot be executed
 * under coverage.
 *
 * Each adapter maps the tool's `{text, isError}` result onto the MCP
 * `CallToolResult`, so a REST failure surfaces as a protocol-level tool
 * error (`isError: true`) rather than a success-shaped payload — P1.5
 * DEV-41 / P1.7 DEV-52.
 */
export function registerEvidencePackLifecycleTools(server: McpServer): void {
  server.tool(
    "attestry_evidence_pack_sign",
    evidencePackSignDescription,
    evidencePackSignSchema,
    async (args) => {
      const result = await evidencePackSign(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_evidence_pack_supersede",
    evidencePackSupersedeDescription,
    evidencePackSupersedeSchema,
    async (args) => {
      const result = await evidencePackSupersede(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_evidence_pack_revoke",
    evidencePackRevokeDescription,
    evidencePackRevokeSchema,
    async (args) => {
      const result = await evidencePackRevoke(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );

  server.tool(
    "attestry_evidence_pack_export",
    evidencePackExportDescription,
    evidencePackExportSchema,
    async (args) => {
      const result = await evidencePackExport(args);
      return {
        content: [{ type: "text", text: result.text }],
        isError: result.isError,
      };
    },
  );
}
