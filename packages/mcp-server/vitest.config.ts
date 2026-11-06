import { defineConfig } from "vitest/config";

/**
 * KE2 P1.5 — vitest config for the Attestry MCP server.
 *
 * Introduced with the P1.5 evidence-pack tools: the package previously had
 * no test harness. Coverage is scoped to the P1.5 surface
 * (`src/tools/evidence-pack-*.ts`) so the 100/100/100/100 gate measures the
 * four tool files plus the shared module without being diluted by the
 * pre-existing, untested legacy tools.
 */
export default defineConfig({
  test: {
    include: ["src/**/__tests__/**/*.test.ts"],
    coverage: {
      provider: "v8",
      all: true,
      include: [
        "src/tools/evidence-pack-*.ts",
        "src/tools/regulation-*.ts",
        "src/tools/schedule-deadline.ts",
      ],
      reporter: ["text", "text-summary"],
    },
  },
});
