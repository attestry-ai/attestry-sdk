# @attestry/mcp-server

MCP (Model Context Protocol) server for [Attestry](https://attestry.ai) — the cryptographically-verifiable AI compliance platform. Lets AI assistants (Claude, Cursor, Windsurf) interact directly with your Attestry compliance data.

## Setup

Requires Node.js 20.19 or later (`npx` runs the server with your local Node).

### 1. Get your API key

Create an API key in the Attestry app under **Settings → Integrations → API Keys**. The key has full access to the Attestry API — there are no scopes to configure.

### 2. Configure your AI assistant

No manual install is needed — the configs below launch the server on demand with `npx`. Just set your API key in the `env` block.

#### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "attestry": {
      "command": "npx",
      "args": ["-y", "@attestry/mcp-server"],
      "env": {
        "ATTESTRY_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

#### Claude Code

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "attestry": {
      "command": "npx",
      "args": ["-y", "@attestry/mcp-server"],
      "env": {
        "ATTESTRY_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

#### Cursor

Edit `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "attestry": {
      "command": "npx",
      "args": ["-y", "@attestry/mcp-server"],
      "env": {
        "ATTESTRY_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

#### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "attestry": {
      "command": "npx",
      "args": ["-y", "@attestry/mcp-server"],
      "env": {
        "ATTESTRY_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ATTESTRY_API_KEY` | Yes | — | Your Attestry API key (full access) |
| `ATTESTRY_API_URL` | No | `https://attestry.ai` | Attestry API base URL. The default is correct for the hosted product; override only for self-hosted/staging. |

## Tools

### `attestry_check_compliance`

Check an AI system's compliance status against regulatory frameworks.

**Input:**
- `systemId` (string, required) — UUID of the AI system
- `frameworks` (string[], optional) — Frameworks to check (e.g., `["eu_ai_act", "colorado_ai_act"]`)

**Output:** Pass/fail status, score, compliance issues, active attestation count, last-assessed + checked timestamps, and recommendations.

---

### `attestry_classify_system`

Classify an AI system's risk level (EU AI Act tiers + Colorado consequential-decision domains, with NIST applicability flags).

**Input:**
- `systemId` (string, required) — UUID of the AI system

**Output:** Overall risk level, per-framework classifications with rationale, applicable frameworks, Colorado affirmative defense status (legacy SB 24-205-era field — SB 26-189 carries no affirmative defense; see the frameworks note below).

---

### `attestry_list_systems`

List all registered AI systems for your organization.

**Input:** None

**Output:** Total count plus, for each system: ID, name, status, overall risk level, applicable frameworks, intended use, and deployment geography.

---

### `attestry_get_assessment`

Get the latest compliance assessment summary for an AI system.

**Input:**
- `systemId` (string, required) — UUID of the AI system

**Output:** Compliance status, score, framework coverage (applicable / assessed / percentage), active attestations, last-assessed timestamp, and recommendations.

---

### `attestry_list_changes`

Get recent regulatory changes affecting AI compliance.

**Input:**
- `severity` (string, optional) — Filter: `critical`, `high`, `medium`, `low`
- `framework` (string, optional) — Filter by framework
- `limit` (number, optional) — Number of results (default: 10, max: 50)

**Output:** Regulatory changes with titles, summaries, framework, severity, status, published + effective dates, and source URLs.

---

### `attestry_generate_document`

Generate a compliance document for an AI system.

**Input:**
- `systemId` (string, required) — UUID of the AI system
- `docType` (string, required) — One of:
  - `eu_technical_documentation` — EU AI Act Article 11
  - `colorado_impact_assessment` — optional governance artifact (SB 26-189 imposes no impact-assessment duty)
  - `risk_management_plan` — NIST AI RMF
  - `model_card` — Transparency documentation
  - `post_market_monitoring_plan` — EU AI Act Article 72
  - `consumer_disclosure` — Colorado consumer notice
  - `nist_ai_rmf_profile` — NIST framework profile
  - `custom_framework_report` — Custom framework
- `assessmentId` (string, optional) — Include assessment data
- `useAI` (boolean, optional) — Use AI for narrative generation (default `false`; consumes AI credits)

**Output:** Document ID, type, framework, generation timestamp, and a signed download URL + token (expires in ~72 hours).

## Resources

| URI | Description |
|-----|-------------|
| `attestry://systems` | List of AI systems with risk classifications |
| `attestry://changes` | Recent regulatory changes |
| `attestry://status` | Compliance dashboard summary |

## Example Prompts

Once configured, you can ask your AI assistant:

- "Check the compliance status of my AI system"
- "What's the risk classification for system X?"
- "Show me recent regulatory changes for the EU AI Act"
- "Generate a Colorado Impact Assessment for my hiring AI"
- "List all my registered AI systems"
- "What's my overall compliance status?"

## Supported Frameworks

- **EU AI Act** — Risk classification, technical documentation, post-market monitoring
- **Colorado AI Act (SB 26-189, formerly SB 24-205)** — Developer documentation, consumer notice/disclosure, 3-year recordkeeping (obligations from Jan 1, 2027)
- **NIST AI RMF** — Risk management profiles, governance documentation
- **ISO 42001** — AI management system certification readiness

## Development

Clone the repository, then from `mcp-server/`:

```bash
npm install
npm run dev    # Watch mode
npm run build  # Production build
npm start      # Run the server
```

---

### `attestry_generate_annex_iv`

Generate the EU AI Act Annex IV technical documentation PDF for a signed technical file. Composes all nine Annex IV sections, cryptobinds (tamper-evidently seals) the rendered PDF, persists it to content-addressed storage, meters the document, and returns the artifact references: the PDF byte hash, signing key id, status-list index, the detached bind sidecar (JWS), and absolute download URLs for the PDF and the bind sidecar.

**Input:**
- `technicalFileId` (string, required) — UUID of the **signed** technical file (first-bind-only: an already-bound file returns a typed `annex_iv.already_bound` error)

---

### `attestry_vision_compliance_extract`

Extract structured, schema-validated compliance data from a single document image (synchronous). Returns per-field values with confidence scores, source-region descriptions, token usage, and cost.

**Input:**
- `documentType` (string, required) — extraction schema: `model-card`, `validation-report`, `certification-label`, `schematic-extraction`, or `generic-tabular`
- `mediaType` (string, required) — `image/jpeg`, `image/png`, `image/webp`, or `image/gif`
- `base64` (string, optional) — base64-encoded image bytes (provide exactly one of `base64` or `imageUri`)
- `imageUri` (string, optional) — URI of the image (the alternative to `base64`)

---

### `attestry_vision_list_supported_schemas`

List the vision extraction schemas available — the document types the vision extract tools can target — with their versions, model-tier preferences, and confidence thresholds.

**Input:** none

---

### `attestry_vision_get_job_status`

Get the status and results of an asynchronous vision batch extraction job submitted via the batch endpoint. Reports progress, cost, and any per-document errors.

**Input:**
- `jobId` (string, required) — UUID of the vision batch extraction job to poll

## License

MIT © Attestry
