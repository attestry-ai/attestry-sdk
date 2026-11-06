import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PACKAGE_USER_AGENT, PACKAGE_VERSION } from "../version.js";

describe("version", () => {
  it("PACKAGE_VERSION matches package.json (User-Agent stays in sync)", () => {
    const pkg = JSON.parse(
      readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
    ) as { version: string };
    expect(PACKAGE_VERSION).toBe(pkg.version);
    expect(PACKAGE_USER_AGENT).toBe(
      `attestry-otel-agent-compliance/${pkg.version}`,
    );
  });
});
