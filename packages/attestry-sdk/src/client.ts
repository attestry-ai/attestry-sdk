// ─── AttestryClient ─────────────────────────────────────────────────────────
//
// The single entry point. Construct with `new AttestryClient({ apiKey })`,
// then access resource sub-clients on `client.<resource>` (Stripe-style).
//
// Resources call back into the client via `_request<T>(args)`. The
// underscore prefix signals "internal — don't call from consumer code";
// it's not literally private because TypeScript class-private fields
// would also hide it from the resource modules in this codebase.

import { AbacPoliciesResource } from "./resources/abac-policies.js";
import { AuditLogResource } from "./resources/audit-log.js";
import { BatchResource } from "./resources/batch.js";
import { ChatResource } from "./resources/chat.js";
import { CheckResource } from "./resources/check.js";
import { ComplianceCheckResource } from "./resources/compliance-check.js";
import { DecisionsResource } from "./resources/decisions.js";
import { EvidencePackResource } from "./resources/evidence-pack.js";
import { GateResource } from "./resources/gate.js";
import { IncidentsResource } from "./resources/incidents.js";
import { RegulatoryChangesResource } from "./resources/regulatory-changes.js";
import { ShipGateResource } from "./resources/ship-gate.js";
import { VisionResource } from "./resources/vision.js";
import {
  request as transportRequest,
  resolveClientConfig,
  streamRequest as transportStreamRequest,
} from "./transport.js";
import type { AttestryClientOptions, RequestOptions } from "./types.js";

interface InternalRequestArgs {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  options?: RequestOptions;
}

export class AttestryClient {
  readonly incidents: IncidentsResource;
  readonly decisions: DecisionsResource;
  readonly chat: ChatResource;
  readonly auditLog: AuditLogResource;
  readonly regulatoryChanges: RegulatoryChangesResource;
  readonly complianceCheck: ComplianceCheckResource;
  readonly check: CheckResource;
  readonly gate: GateResource;
  readonly batch: BatchResource;
  readonly shipGate: ShipGateResource;
  readonly abacPolicies: AbacPoliciesResource;
  // 2.0 flagship resources (the ≥0.6.0 union — W1 deliverable 5)
  readonly evidencePack: EvidencePackResource;
  readonly vision: VisionResource;

  // Frozen at construction time; resources read this through `_request`.
  private readonly _config: ReturnType<typeof resolveClientConfig>;

  constructor(options: AttestryClientOptions) {
    this._config = resolveClientConfig(options);
    this.incidents = new IncidentsResource(this);
    this.decisions = new DecisionsResource(this);
    this.chat = new ChatResource(this);
    this.auditLog = new AuditLogResource(this);
    this.regulatoryChanges = new RegulatoryChangesResource(this);
    this.complianceCheck = new ComplianceCheckResource(this);
    this.check = new CheckResource(this);
    this.gate = new GateResource(this);
    this.batch = new BatchResource(this);
    this.shipGate = new ShipGateResource(this);
    this.abacPolicies = new AbacPoliciesResource(this);
    this.evidencePack = new EvidencePackResource(this);
    this.vision = new VisionResource(this);
  }

  /** Internal — resources call this to dispatch HTTP requests. */
  _request<T>(args: InternalRequestArgs): Promise<T> {
    return transportRequest<T>({ config: this._config, ...args });
  }

  /**
   * Internal — resources call this to dispatch streaming requests (SSE
   * or NDJSON). Returns the un-consumed `Response` so the caller can
   * attach the appropriate parser to `response.body`. Non-2xx responses
   * throw `AttestryAPIError` exactly like `_request`. See `streamRequest`
   * in transport for the full contract — including the
   * `expectedContentType` parameter that drives both the `Accept:`
   * request header and the response content-type fail-fast guard.
   */
  _streamRequest(args: {
    path: string;
    query?: Record<string, string | number | boolean | undefined | null>;
    headers?: Record<string, string>;
    options?: RequestOptions;
    expectedContentType?: string;
  }): Promise<Response> {
    return transportStreamRequest({ config: this._config, ...args });
  }
}
