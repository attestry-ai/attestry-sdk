import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      // package.json "imports" maps `#annex-iv-verify/zlib` to the BUILT
      // dist/ files (node → zlib-node.js). Tests run from source without a
      // build, so point the "node" binding at its source file here.
      "#annex-iv-verify/zlib": fileURLToPath(new URL("./src/annex-iv-verify/zlib-node.ts", import.meta.url)),
    },
  },
  test: {
    environment: "node",
    include: ["src/**/__tests__/**/*.test.ts"],
    globals: false,
    testTimeout: 10_000,
  },
});
