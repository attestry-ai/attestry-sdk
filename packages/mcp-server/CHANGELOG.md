# Changelog

All notable changes to `@attestry/mcp-server` are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] - Unreleased

### Added

1.0.0 shipped six tools. This release adds 16, bringing the total to 22.
They are additive, and the inputs of the six existing tools are unchanged.

- **Evidence packs** (auditor-facing compliance artifacts with a
  draft → signed → superseded / revoked lifecycle):
  - `attestry_evidence_pack_create`: create a draft pack, optionally scoped
    to an AI system.
  - `attestry_evidence_pack_get`: fetch a pack with its bundle list.
  - `attestry_evidence_pack_list`: list packs, newest first, with filters.
  - `attestry_evidence_pack_append_bundle`: append a reperformance bundle to
    a draft pack.
  - `attestry_evidence_pack_sign`: sign a draft pack (draft → signed).
  - `attestry_evidence_pack_supersede`: supersede a signed pack and create
    its linked replacement draft (sent with an `Idempotency-Key`).
  - `attestry_evidence_pack_revoke`: revoke a signed pack.
  - `attestry_evidence_pack_export`: export a pack as a structured JSON
    artifact.
- **Regulation and schedule**:
  - `attestry_regulation_cite`: resolve a provision to its canonical
    citation, its text and a sha256 content hash.
  - `attestry_regulation_crosswalk`: map provisions between frameworks.
  - `attestry_regulation_applicability`: list the frameworks that apply to a
    system, given its geography and system type.
  - `attestry_schedule_deadline`: list regulatory deadlines across
    frameworks.
- **EU AI Act Annex IV**: `attestry_generate_annex_iv` generates the
  Annex IV technical-documentation PDF for a signed technical file,
  cryptographically binds it, and returns the PDF and bind-sidecar
  references.
- **Vision extraction**:
  - `attestry_vision_compliance_extract`: extract schema-validated
    compliance data from one document image.
  - `attestry_vision_list_supported_schemas`: list the extraction schemas.
  - `attestry_vision_get_job_status`: poll an asynchronous batch-extraction
    job.

The descriptions of `attestry_classify_system` and
`attestry_generate_document` were also updated (classification scope and
Colorado SB 26-189 wording).

### Security

- Upgrade `zod` from `^3.24.2` to `^4.6.6` to fix
  [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)
  (memory exhaustion while validating oversized constrained collections;
  affects zod < 4.6.6, with no fix on 3.x). Tool arguments from the MCP
  client are zod-validated, so 1.0.0 was exposed to a local denial of
  service of its own stdio process.
- Upgrade `@modelcontextprotocol/sdk` from `^1.27.1` to `^1.32.2` (accepts
  zod 4) and refresh its transitive lockfile pins (`path-to-regexp`,
  `proxy-addr`, `qs`, `ip-address`, `hono`, `@hono/node-server`, among
  others). `npm audit --omit=dev` reports 0 vulnerabilities.

### Changed

- **The default API host is now `https://attestry.ai`** (previously
  `https://attestry.app`). This is the canonical Attestry API host and the
  `@attestry/sdk` default. Set `ATTESTRY_API_URL` to override it. The
  absolute download link returned by `attestry_generate_document` uses the
  same base.
- **Node.js 20.19.0 or later is required** (`engines.node`, previously
  `>=18.0.0`). Node 18 is end-of-life, and current releases of the MCP
  SDK's transitive dependencies (`@hono/node-server` 2.x) require Node 20.
- Package metadata: added `repository` (the public
  `attestry-ai/attestry-sdk` repo, `packages/mcp-server`), a `homepage`
  pointing at that README, and a `bugs.url`. npm provenance requires
  `repository.url` to match the repo that publishes the package.
- zod 4 migration, with validation behavior unchanged:
  - `z.record(value)` became `z.record(z.string(), value)`; zod 4 removed
    the single-argument form.
  - UUID fields use `z.string().guid()`. zod 4's `.uuid()` enforces RFC
    9562 version and variant bits and would reject ids that 1.0.0 and the
    Attestry API accept. `.guid()` is the exact zod 3 `.uuid()` check.
- Input-validation errors returned to the MCP client now use zod 4's
  wording (for example `Invalid GUID at systemId` instead of a JSON dump of
  zod 3 issues). Which inputs are accepted or rejected is unchanged.
- Advertised tool input JSON Schemas: `additionalProperties: false` is no
  longer emitted for objects. Unknown keys were always stripped at runtime,
  so the schema now matches the behavior. Record fields also gain
  `propertyNames: { "type": "string" }`.
- The server reports version `1.1.0` in MCP `serverInfo` and in its
  `User-Agent` header.

## [1.0.0] - 2026-05-30

### Added

- Initial release: six compliance tools (`attestry_check_compliance`,
  `attestry_classify_system`, `attestry_list_systems`,
  `attestry_get_assessment`, `attestry_list_changes`,
  `attestry_generate_document`) and three resources (`attestry://systems`,
  `attestry://changes`, `attestry://status`).
