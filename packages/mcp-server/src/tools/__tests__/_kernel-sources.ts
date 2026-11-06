import { describe, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as path from "node:path";

/**
 * Standalone / publish-mirror guard for the kernel drift pins.
 *
 * The drift tests compare this package against kernel sources four levels
 * up (`<kernel root>/src/...`). Those exist only while the package sits in
 * the kernel monorepo (`mcp-server/`). In a standalone copy, such as the
 * public provenance mirror (`attestry-ai/attestry-sdk`,
 * `packages/mcp-server/`), they do not, and `npm test` would fail at file
 * load with ENOENT.
 *
 * Detection is by the kernel ROOT (its package.json `name`), not by the
 * presence of any single kernel file. Inside the monorepo every kernel read
 * stays strict, so a moved or renamed kernel file still fails loudly
 * instead of silently skipping. Outside it, only the kernel-reading pins
 * skip; the self-contained pins (REST paths, schema shapes, registration
 * wiring) keep running. Same intent as the SDK's drift guard (mirror
 * 9f13fc2). Test-only: `files: ["dist"]` ships no tests.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const KERNEL_ROOT = path.resolve(here, "../../../..");
const KERNEL_PACKAGE_NAME = "attestry";

export const IN_KERNEL_MONOREPO: boolean = (() => {
  try {
    const pkg = JSON.parse(
      readFileSync(path.join(KERNEL_ROOT, "package.json"), "utf8"),
    ) as { name?: unknown };
    return pkg.name === KERNEL_PACKAGE_NAME;
  } catch {
    return false;
  }
})();

/** Read a kernel source file (path relative to the kernel root). Strict inside the monorepo; "" outside it. */
export function readKernelSource(relPath: string): string {
  return IN_KERNEL_MONOREPO
    ? readFileSync(path.join(KERNEL_ROOT, relPath), "utf8")
    : "";
}

const SKIP_REASON = "needs the kernel monorepo sources (standalone copy)";

/**
 * `describe` for suites whose factory body reads kernel sources. Outside
 * the monorepo the factory is NOT executed (vitest runs `describe.skip`
 * factories during collection, which would throw on the empty source).
 */
export const describeKernel: (name: string, factory: () => void) => void =
  IN_KERNEL_MONOREPO
    ? (name, factory) => {
        describe(name, factory);
      }
    : (name) => {
        describe.skip(name, () => {
          it(SKIP_REASON, () => {});
        });
      };

/** `it` for individual pins that read kernel sources. */
export const itKernel: (name: string, fn: () => void) => void =
  IN_KERNEL_MONOREPO
    ? (name, fn) => {
        it(name, fn);
      }
    : (name, fn) => {
        it.skip(name, fn);
      };
