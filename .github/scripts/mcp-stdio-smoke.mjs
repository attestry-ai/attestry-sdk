// Smoke test for an INSTALLED @attestry/mcp-server: start its `bin` and run
// an MCP handshake over stdio (initialize -> notifications/initialized ->
// tools/list). It checks that the bin exists and has a node shebang, that the
// server answers JSON-RPC, that the serverInfo version equals package.json,
// and that it registers tools. No network: the server makes no API calls for
// these requests (the API URL points at a closed local port anyway).
//
// usage: node mcp-stdio-smoke.mjs <installed package dir>
//   e.g. node mcp-stdio-smoke.mjs node_modules/@attestry/mcp-server
//
// AUTHORED in the private monorepo at
// scripts/publish/mirror-root/github/scripts/mcp-stdio-smoke.mjs and
// byte-mirrored to .github/scripts/mcp-stdio-smoke.mjs. Edit it there.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";

function die(message) {
  console.error(`mcp smoke FAILED: ${message}`);
  process.exit(1);
}

const pkgDir = process.argv[2];
if (!pkgDir) {
  console.error("usage: node mcp-stdio-smoke.mjs <installed package dir>");
  process.exit(2);
}
const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
const binRel = typeof pkg.bin === "string" ? pkg.bin : Object.values(pkg.bin ?? {})[0];
if (!binRel) die("package.json has no bin");
const bin = resolve(pkgDir, binRel);
const firstLine = readFileSync(bin, "utf8").split("\n", 1)[0];
if (!/^#!.*\bnode\b/.test(firstLine)) die(`bin ${binRel} has no node shebang (first line: ${JSON.stringify(firstLine)})`);

const child = spawn(process.execPath, [bin], {
  env: { ...process.env, ATTESTRY_API_KEY: "ci-smoke-key", ATTESTRY_API_URL: "http://127.0.0.1:9" },
  stdio: ["pipe", "pipe", "inherit"],
});
let finished = false;
const timer = setTimeout(() => fail("no tools/list response within 20 s"), 20_000);

function send(message) {
  child.stdin.write(JSON.stringify(message) + "\n");
}
function finish(code, message) {
  if (finished) return;
  finished = true;
  clearTimeout(timer);
  (code === 0 ? console.log : console.error)(message);
  child.kill();
  process.exit(code);
}
function fail(message) {
  finish(1, `mcp smoke FAILED: ${message}`);
}

createInterface({ input: child.stdout }).on("line", (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return fail(`non-JSON line on stdout: ${line.slice(0, 200)}`);
  }
  if (msg.error) return fail(`JSON-RPC error for id ${msg.id}: ${JSON.stringify(msg.error)}`);
  if (msg.id === 1) {
    const info = msg.result?.serverInfo ?? {};
    if (info.version !== pkg.version) {
      return fail(`serverInfo.version is ${JSON.stringify(info.version)} but package.json is ${pkg.version}; bump the McpServer version in src/index.ts`);
    }
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  } else if (msg.id === 2) {
    const tools = msg.result?.tools;
    if (!Array.isArray(tools) || tools.length === 0) return fail("tools/list returned no tools");
    const unnamed = tools.filter((t) => typeof t.name !== "string" || !t.inputSchema);
    if (unnamed.length > 0) return fail(`${unnamed.length} tool(s) lack a name or inputSchema`);
    finish(0, `mcp smoke OK: ${pkg.name}@${pkg.version} (${binRel}) lists ${tools.length} tools`);
  }
});
child.on("exit", (code, signal) => {
  if (!finished) fail(`server exited early (code ${code}, signal ${signal})`);
});

send({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "ci-smoke", version: "0.0.0" } },
});
