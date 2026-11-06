#!/usr/bin/env node
/**
 * OpenTelemetry JS 2.x / 3.x consumer-install compatibility matrix.
 *
 *   npm run test:otel-compat                      # default matrix
 *   node scripts/otel-compat.mjs 0.223.0 latest   # chosen sdk-node versions
 *   node scripts/otel-compat.mjs '0.214.0+@opentelemetry/api@1.9.0'   # extra app deps
 *   node scripts/otel-compat.mjs --tarball ./attestry-otel-agent-compliance-0.2.0.tgz
 *
 * A row is `<sdk-node version>[+<extra package spec>...]`; extras are
 * installed next to sdk-node as part of "the user's app". For every row,
 * in fresh temp consumer projects, this script:
 *   1. one-shot:   `npm install @opentelemetry/sdk-node@<v> [extras] <tarball>`
 *   2. sequential: `npm install @opentelemetry/sdk-node@<v> [extras]` (the
 *      existing app), then `npm install <tarball>` (adding us to it).
 *      All installs are STRICT — no --legacy-peer-deps / --force — so a
 *      peer-range conflict (the 0.1.1 ERESOLVE) fails the row.
 *   3. `npm ls --all` must exit 0 in both projects (no invalid peers).
 *   4. Runtime smoke: NodeSDK({ spanProcessors: [AttestryDecisionExporter] }),
 *      end one decision span, `sdk.shutdown()`, and assert the exporter
 *      POSTed it to a local 127.0.0.1 kernel-shaped stub (no network
 *      beyond the npm registry).
 *   5. Type smoke: a consumer .ts file compiles with `tsc --noEmit`. It
 *      passes the exporter to NodeSDK's `spanProcessors`, and STRICTLY
 *      assigns that SDK's own `SpanProcessor.onStart`/`onEnd` span types
 *      to the package's structural `SpanLike` / `ReadableSpanLike`. It
 *      also has an `@ts-expect-error` negative control, so the check fails
 *      if the SDK's types ever resolve to `any`.
 *
 * Matrix entries whose OTel line needs a newer Node than the running one
 * (OTel JS 3.x requires Node >= 22.15.0) are SKIPPED, not failed, so the
 * script can run on every Node in CI: run it on Node 20.19+ for the 2.x
 * rows and on Node >= 22.15 for all rows.
 *
 * Exit code: 0 when every non-skipped row passes, 1 otherwise.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NPM = process.platform === "win32" ? "npm.cmd" : "npm";

/** sdk-node version → OTel JS line. 0.2xx = SDK 2.x, 0.3xx = SDK 3.x. */
const DEFAULT_MATRIX = [
  // OTel 2.x on `@opentelemetry/sdk-trace-base` only (no sdk-trace yet):
  // 2.0 GA, a middle release, the 0.1.x pin, and the last one.
  "0.200.0",
  "0.210.0",
  "0.214.0",
  "0.219.0",
  // OTel 2.x shipping `@opentelemetry/sdk-trace` 2.9+: first and last.
  "0.220.0",
  "0.223.0",
  // OTel 3.x: GA and current.
  "0.300.0",
  "latest",
];

const args = process.argv.slice(2);
let tarball = null;
let keep = false;
const versions = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--tarball") tarball = resolve(args[++i]);
  else if (args[i] === "--keep") keep = true;
  else versions.push(args[i]);
}
const matrix = versions.length > 0 ? versions : DEFAULT_MATRIX;

function run(cmd, cmdArgs, cwd) {
  const r = spawnSync(cmd, cmdArgs, { cwd, encoding: "utf8" });
  return { code: r.status ?? 1, out: `${r.stdout ?? ""}${r.stderr ?? ""}` };
}

function nodeAtLeast(spec) {
  const [a, b, c] = process.versions.node.split(".").map(Number);
  const [x, y, z] = spec.split(".").map(Number);
  return a !== x ? a > x : b !== y ? b > y : c >= z;
}

function resolveVersion(spec) {
  return execFileSync(
    NPM,
    ["view", `@opentelemetry/sdk-node@${spec}`, "version"],
    { encoding: "utf8" },
  )
    .trim()
    .split("\n")
    .pop()
    .replace(/^.*'(.+)'$/, "$1");
}

if (!tarball) {
  const packDir = mkdtempSync(join(tmpdir(), "otel-compat-pack-"));
  const out = execFileSync(
    NPM,
    ["pack", "--silent", "--pack-destination", packDir],
    { cwd: PKG_DIR, encoding: "utf8" },
  );
  tarball = join(packDir, out.trim().split("\n").pop());
}
console.log(`tarball: ${tarball}`);
console.log(`node:    ${process.version}`);

const SMOKE_MJS = `
import http from "node:http";
import { NodeSDK } from "@opentelemetry/sdk-node";
import { trace } from "@opentelemetry/api";
import { AttestryDecisionExporter } from "@attestry/otel-agent-compliance";

const received = [];
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const items = JSON.parse(body).items;
    received.push({ key: req.headers["x-api-key"], items });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, data: {
      totalSubmitted: items.length, totalInserted: items.length,
      totalFailed: 0, inserted: [], failed: [] } }));
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const logs = [];
const log = (m, meta) => logs.push(meta ? m + " " + JSON.stringify(meta) : m);
const exporter = new AttestryDecisionExporter({
  apiUrl: "http://127.0.0.1:" + server.address().port + "/api/v1/decisions/bulk",
  apiKey: "compat-key",
  systemId: "00000000-0000-0000-0000-000000000001",
  batchSize: 100,
  batchInterval: 60_000,
  logger: { warn: log, error: log },
});
const sdk = new NodeSDK({ spanProcessors: [exporter] });
sdk.start();
const span = trace.getTracer("otel-compat").startSpan("tool.call");
span.setAttribute("tool.name", "compat");
span.setAttribute("input", "contact bob@example.com");
span.end();
await sdk.shutdown();
server.close();
const item = received[0]?.items?.[0];
const ok = received.length === 1 && received[0].items.length === 1 &&
  received[0].key === "compat-key" && /^sha256:[a-f0-9]{64}$/.test(item?.inputDigest ?? "") &&
  logs.length === 0;
console.log(JSON.stringify({ ok, posts: received.length, items: received[0]?.items?.length ?? 0,
  toolInvocations: item?.toolInvocations, logs }));
process.exit(ok ? 0 : 1);
`;

const CHECK_TS = `
import { NodeSDK } from "@opentelemetry/sdk-node";
import {
  AttestryDecisionExporter,
  type BatchSendResult,
  type ReadableSpanLike,
  type SpanLike,
} from "@attestry/otel-agent-compliance";

const exporter = new AttestryDecisionExporter({
  apiUrl: "https://attestry.ai/api/v1/decisions/bulk",
  apiKey: "k",
  systemId: "s",
});
new NodeSDK({ spanProcessors: [exporter] });

// This SDK release's own SpanProcessor + span types, taken from NodeSDK's
// config so they come from whichever tracing package it uses
// (sdk-trace-base on 0.200-0.219, sdk-trace afterwards).
type SdkProcessor = NonNullable<
  NonNullable<ConstructorParameters<typeof NodeSDK>[0]>["spanProcessors"]
>[number];
type SdkStartedSpan = Parameters<SdkProcessor["onStart"]>[0];
type SdkEndedSpan = Parameters<SdkProcessor["onEnd"]>[0];
// Strict (non-bivariant) checks: real spans satisfy what we read/write.
export const ended = (s: SdkEndedSpan): ReadableSpanLike => s;
export const started = (s: SdkStartedSpan): SpanLike => s;
export const asProcessor = (e: AttestryDecisionExporter): SdkProcessor => e;

// Negative control: if the SDK types were 'any', this would NOT error and
// the directive itself would fail the build.
// @ts-expect-error - a bare object is not a SpanProcessor
new NodeSDK({ spanProcessors: [{}] });

export const r: BatchSendResult | null = null;
`;

const TSCONFIG = JSON.stringify({
  compilerOptions: {
    target: "ES2022",
    module: "NodeNext",
    moduleResolution: "NodeNext",
    strict: true,
    noEmit: true,
    skipLibCheck: true,
    types: [],
  },
  files: ["check.ts"],
});

const tscBin = join(PKG_DIR, "node_modules", "typescript", "bin", "tsc");
const results = [];

function consumerDir(label) {
  const dir = mkdtempSync(join(tmpdir(), `otel-compat-${label}-`));
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "otel-compat-consumer", private: true, type: "module" }),
  );
  return dir;
}

for (const spec of matrix) {
  const [sdkSpec, ...extras] = spec.split("+");
  const version = resolveVersion(sdkSpec);
  const line = version.startsWith("0.3") ? "3.x" : "2.x";
  const row = { sdkNode: version, line, extras };
  if (line === "3.x" && !nodeAtLeast("22.15.0")) {
    results.push({ ...row, status: "SKIP", reason: "OTel 3.x needs Node >= 22.15.0" });
    continue;
  }
  const app = [`@opentelemetry/sdk-node@${version}`, ...extras];
  const base = ["install", "--no-audit", "--no-fund"];
  const oneShot = consumerDir(`${version}-oneshot`);
  const dir = consumerDir(`${version}-seq`);
  try {
    let r = run(NPM, [...base, ...app, tarball], oneShot);
    if (r.code !== 0) throw new Error(`one-shot install failed (strict peers)\n${r.out}`);
    r = run(NPM, ["ls", "--all"], oneShot);
    if (r.code !== 0) throw new Error(`one-shot: npm ls --all reports problems\n${r.out}`);
    row.oneShot = "ok";

    r = run(NPM, [...base, ...app], dir);
    if (r.code !== 0) throw new Error(`app install failed\n${r.out}`);
    r = run(NPM, [...base, tarball], dir);
    if (r.code !== 0) throw new Error(`sequential install failed (strict peers)\n${r.out}`);
    const warnings = r.out.split("\n").filter((l) => /npm warn/i.test(l));
    r = run(NPM, ["ls", "--all"], dir);
    if (r.code !== 0) throw new Error(`sequential: npm ls --all reports problems\n${r.out}`);
    row.sequential = "ok";
    const installed = (name) => {
      try {
        return JSON.parse(readFileSync(join(dir, "node_modules", name, "package.json"), "utf8")).version;
      } catch {
        return null;
      }
    };
    row.installed = {
      "@opentelemetry/api": installed("@opentelemetry/api"),
      "@opentelemetry/sdk-trace": installed("@opentelemetry/sdk-trace"),
      "@opentelemetry/sdk-trace-base": installed("@opentelemetry/sdk-trace-base"),
      "@attestry/otel-agent-compliance": installed("@attestry/otel-agent-compliance"),
    };
    row.npmWarnings = warnings;

    writeFileSync(join(dir, "smoke.mjs"), SMOKE_MJS);
    r = run(process.execPath, ["smoke.mjs"], dir);
    row.smoke = r.out.trim().split("\n").pop();
    if (r.code !== 0) throw new Error(`runtime smoke failed\n${r.out}`);

    writeFileSync(join(dir, "check.ts"), CHECK_TS);
    writeFileSync(join(dir, "tsconfig.json"), TSCONFIG);
    r = run(process.execPath, [tscBin, "-p", "tsconfig.json"], dir);
    if (r.code !== 0) throw new Error(`consumer typecheck failed\n${r.out}`);
    row.typecheck = "ok";

    results.push({ ...row, status: "PASS" });
  } catch (err) {
    results.push({ ...row, status: "FAIL", error: String(err.message ?? err).slice(0, 4000) });
  } finally {
    if (!keep) {
      rmSync(dir, { recursive: true, force: true });
      rmSync(oneShot, { recursive: true, force: true });
    } else {
      row.dirs = [oneShot, dir];
    }
  }
}

for (const r of results) console.log(JSON.stringify(r));
const failed = results.filter((r) => r.status === "FAIL");
console.log(
  `otel-compat: ${results.filter((r) => r.status === "PASS").length} pass, ` +
    `${failed.length} fail, ${results.filter((r) => r.status === "SKIP").length} skip`,
);
process.exit(failed.length > 0 ? 1 : 0);
