#!/usr/bin/env node

/**
 * Attestry MCP Server
 *
 * Provides AI assistants (Claude, Cursor, Windsurf) with direct access
 * to Attestry's AI compliance verification platform via the Model Context Protocol.
 *
 * Tools: 22 — 7 compliance operations, 3 vision-extraction tools,
 *         8 evidence-pack tools (create / get / list / append-bundle /
 *         sign / supersede / revoke / export), 4 regulation / schedule tools
 *         (regulation.cite / .crosswalk / .applicability / schedule.deadline)
 * Resources: 3 read-only data sources (systems, changes, status)
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import {
  checkCompliance,
  checkComplianceSchema,
  checkComplianceDescription,
} from "./tools/check-compliance.js";
import {
  classifySystem,
  classifySystemSchema,
  classifySystemDescription,
} from "./tools/classify-system.js";
import {
  listSystems,
  listSystemsDescription,
} from "./tools/list-systems.js";
import {
  getAssessment,
  getAssessmentSchema,
  getAssessmentDescription,
} from "./tools/get-assessment.js";
import {
  listChanges,
  listChangesSchema,
  listChangesDescription,
} from "./tools/list-changes.js";
import {
  generateDocument,
  generateDocumentSchema,
  generateDocumentDescription,
} from "./tools/generate-document.js";
import {
  generateAnnexIv,
  generateAnnexIvSchema,
  generateAnnexIvDescription,
} from "./tools/generate-annex-iv.js";
import {
  visionComplianceExtract,
  visionComplianceExtractSchema,
  visionComplianceExtractDescription,
} from "./tools/vision-extract.js";
import {
  visionListSupportedSchemas,
  visionListSupportedSchemasDescription,
} from "./tools/vision-list-schemas.js";
import {
  visionGetJobStatus,
  visionGetJobStatusSchema,
  visionGetJobStatusDescription,
} from "./tools/vision-job-status.js";
import { registerEvidencePackTools } from "./tools/evidence-pack-register.js";
import { registerEvidencePackLifecycleTools } from "./tools/evidence-pack-lifecycle-register.js";
import { registerRegulationTools } from "./tools/regulation-register.js";
import { apiGet } from "./client.js";

// ─── Server setup ────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "attestry",
  version: "1.1.0",
});

// ─── Tools ───────────────────────────────────────────────────────────────────

server.tool(
  "attestry_check_compliance",
  checkComplianceDescription,
  checkComplianceSchema,
  async (args) => ({
    content: [{ type: "text", text: await checkCompliance(args) }],
  })
);

server.tool(
  "attestry_classify_system",
  classifySystemDescription,
  classifySystemSchema,
  async (args) => ({
    content: [{ type: "text", text: await classifySystem(args) }],
  })
);

server.tool(
  "attestry_list_systems",
  listSystemsDescription,
  {},
  async () => ({
    content: [{ type: "text", text: await listSystems() }],
  })
);

server.tool(
  "attestry_get_assessment",
  getAssessmentDescription,
  getAssessmentSchema,
  async (args) => ({
    content: [{ type: "text", text: await getAssessment(args) }],
  })
);

server.tool(
  "attestry_list_changes",
  listChangesDescription,
  listChangesSchema,
  async (args) => ({
    content: [{ type: "text", text: await listChanges(args) }],
  })
);

server.tool(
  "attestry_generate_document",
  generateDocumentDescription,
  generateDocumentSchema,
  async (args) => ({
    content: [{ type: "text", text: await generateDocument(args) }],
  })
);

server.tool(
  "attestry_generate_annex_iv",
  generateAnnexIvDescription,
  generateAnnexIvSchema,
  async (args) => ({
    content: [{ type: "text", text: await generateAnnexIv(args) }],
  })
);

server.tool(
  "attestry_vision_compliance_extract",
  visionComplianceExtractDescription,
  visionComplianceExtractSchema,
  async (args) => ({
    content: [{ type: "text", text: await visionComplianceExtract(args) }],
  })
);

server.tool(
  "attestry_vision_list_supported_schemas",
  visionListSupportedSchemasDescription,
  {},
  async () => ({
    content: [{ type: "text", text: await visionListSupportedSchemas() }],
  })
);

server.tool(
  "attestry_vision_get_job_status",
  visionGetJobStatusDescription,
  visionGetJobStatusSchema,
  async (args) => ({
    content: [{ type: "text", text: await visionGetJobStatus(args) }],
  })
);

// KE2 P1.5 — evidence-pack tools (create / get / list / append_bundle),
// registered via a helper so the four isError-propagating handler adapters
// are unit-testable; index.ts is an entry-point module and is not executed
// under coverage.
registerEvidencePackTools(server);

// KE2 P1.7 — evidence-pack lifecycle + export tools (sign / supersede /
// revoke / export), registered via a sibling helper for the same reason.
registerEvidencePackLifecycleTools(server);

// KE2 P4.8 — regulation / schedule tools (regulation.cite / .crosswalk /
// .applicability / schedule.deadline) for the AACE pilot tier, registered via
// a sibling helper for the same coverage reason.
registerRegulationTools(server);

// ─── Resources ───────────────────────────────────────────────────────────────

server.resource(
  "systems",
  "attestry://systems",
  { description: "List of registered AI systems with risk classifications and statuses" },
  async () => ({
    contents: [
      {
        uri: "attestry://systems",
        mimeType: "application/json",
        text: await listSystems(),
      },
    ],
  })
);

server.resource(
  "changes",
  "attestry://changes",
  { description: "Recent regulatory changes affecting AI compliance frameworks" },
  async () => ({
    contents: [
      {
        uri: "attestry://changes",
        mimeType: "application/json",
        text: await listChanges({ limit: 20 }),
      },
    ],
  })
);

server.resource(
  "status",
  "attestry://status",
  { description: "Overall compliance dashboard summary across all registered AI systems" },
  async () => {
    // Fetch systems and build a summary
    const systemsRaw = await apiGet<
      Array<{
        id: string;
        name: string;
        status: string;
        riskClassifications: Record<string, unknown> | null;
      }>
    >("/api/systems");

    const systems = systemsRaw.data ?? [];
    const totalSystems = systems.length;

    const riskDistribution: Record<string, number> = {};
    const statusDistribution: Record<string, number> = {};
    let classifiedCount = 0;

    for (const s of systems) {
      // Count statuses
      statusDistribution[s.status] = (statusDistribution[s.status] ?? 0) + 1;

      // Count risk levels
      const classifications = s.riskClassifications;
      if (classifications?.overallRiskLevel) {
        const level = classifications.overallRiskLevel as string;
        riskDistribution[level] = (riskDistribution[level] ?? 0) + 1;
        classifiedCount++;
      }
    }

    const summary = {
      totalSystems,
      classifiedSystems: classifiedCount,
      unclassifiedSystems: totalSystems - classifiedCount,
      riskDistribution,
      statusDistribution,
      generatedAt: new Date().toISOString(),
    };

    return {
      contents: [
        {
          uri: "attestry://status",
          mimeType: "application/json",
          text: JSON.stringify(summary, null, 2),
        },
      ],
    };
  }
);

// ─── Start server ────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log to stderr (never stdout — that's for JSON-RPC messages)
  console.error("Attestry MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error starting Attestry MCP server:", error);
  process.exit(1);
});
