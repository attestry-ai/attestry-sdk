# Attestry SDKs

Official TypeScript packages for the [Attestry](https://attestry.app) compliance kernel —
verifiable AI-compliance evidence for the EU AI Act, NIST AI RMF, ISO/IEC 42001, and the
Colorado AI Act.

| Package | Install | What it does |
|---|---|---|
| [`@attestry/sdk`](packages/attestry-sdk) | `npm install @attestry/sdk` | Kernel API client — incidents, decisions, gate checks, evidence packs, vision extraction, batch, ship-gate, ABAC policies. |
| [`@attestry/otel-agent-compliance`](packages/otel-agent-compliance) | `npm install @attestry/otel-agent-compliance` | OpenTelemetry span processor that streams agent activity into the kernel's compliance evidence pipeline (`x-api-key` auth). |

## Supply chain

Every release is published from this repository by the
[`publish-packages`](.github/workflows/publish-packages.yml) GitHub Actions workflow with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements) (Sigstore).
Verify any install with:

```bash
npm audit signatures
```

Releases are tagged `sdk-v<version>` / `otel-v<version>`; the workflow refuses any tag whose
version does not equal the package's `package.json` version.

## License

[Apache-2.0](LICENSE)
