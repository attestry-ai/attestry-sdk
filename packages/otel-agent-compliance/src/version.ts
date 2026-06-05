/**
 * Single source of truth for the package's outward-facing version
 * string. Bump when `package.json` `version` bumps — the User-Agent
 * header pulls from here.
 *
 * Why not read `package.json` at runtime? Doing so requires either a
 * JSON import (Node-version dependent assertion syntax differs between
 * 18/20/22) or a synchronous `require('./package.json')` call, which
 * doesn't work cleanly in ESM. The constant approach keeps the build
 * deterministic at the cost of a one-line manual sync.
 */

export const PACKAGE_VERSION = "0.1.1";
export const PACKAGE_USER_AGENT = `attestry-otel-agent-compliance/${PACKAGE_VERSION}`;
