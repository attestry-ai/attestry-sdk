# Attestry SDKs

Official TypeScript packages for the [Attestry](https://attestry.app) compliance kernel —
verifiable AI-compliance evidence for the EU AI Act, NIST AI RMF, ISO/IEC 42001, and the
Colorado AI Act.

| Package | Install | What it does |
|---|---|---|
| [`@attestry/sdk`](packages/attestry-sdk) | `npm install @attestry/sdk` | Kernel API client — incidents, decisions, gate checks, evidence packs, vision extraction, batch, ship-gate, ABAC policies. |
| [`@attestry/otel-agent-compliance`](packages/otel-agent-compliance) | `npm install @attestry/otel-agent-compliance` | OpenTelemetry span processor that streams agent activity into the kernel's compliance evidence pipeline (`x-api-key` auth). |
| [`@attestry/mcp-server`](packages/mcp-server) | `npx -y @attestry/mcp-server` | MCP (Model Context Protocol) server, run over stdio, that lets AI assistants such as Claude, Cursor and Windsurf work with your Attestry compliance data. |

## Supply chain

Releases are published from this repository by the
[`publish-packages`](.github/workflows/publish-packages.yml) GitHub Actions workflow with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements) (Sigstore).
`@attestry/mcp-server` 1.0.0 predates this repository and has no provenance; later versions
are published from here.
Verify any install with:

```bash
npm audit signatures
```

Releases are tagged `sdk-v<version>` / `otel-v<version>` / `mcp-v<version>`. The workflow refuses any tag whose
version does not equal the package's `package.json` version, or whose commit is not on `main`.
It builds and tests in a job with read-only permissions and publishes the resulting tarball
from a separate job using npm Trusted Publishing (OIDC), with no long-lived npm token.

Every pull request and push to `main` runs the [CI](.github/workflows/ci.yml) workflow
on Node 20.19, 22, 24 and 26 (20.19 to 24 for the MCP server). It also tests the span processor
against OpenTelemetry JS 2.x and 3.x, and runs an MCP stdio handshake against the packed server.
CI never publishes.

## License

`@attestry/sdk` and `@attestry/otel-agent-compliance` are licensed under [Apache-2.0](LICENSE).
`@attestry/mcp-server` is licensed under [MIT](packages/mcp-server/LICENSE).
