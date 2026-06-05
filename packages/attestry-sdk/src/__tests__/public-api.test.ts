// ─── Public API surface — imports through index.ts ──────────────────────────
//
// Every other test file imports from internal module paths (../client.js,
// ../transport.js, etc.), which means a typo or missing re-export in
// index.ts would let the suite pass while consumers see runtime errors.
// This file exists to pin the public entry point: any value or type that
// `@attestry/sdk` consumers are documented to import lands here.
//
// The test bodies don't have to exercise behavior — that's already covered
// in the unit tests. The pins assert the export exists and has the right
// runtime kind (function, class, value).

import { describe, it, expect } from "vitest";
import * as sdk from "../index.js";

describe("public API — index.ts re-exports", () => {
  it("exports AttestryClient (class)", () => {
    expect(typeof sdk.AttestryClient).toBe("function");
    // Class identity: prototype chain check is the cheapest "is a class"
    // smoke test that doesn't depend on emitted constructor format.
    expect(sdk.AttestryClient.prototype).toBeDefined();
  });

  it("exports the error classes (AttestryError, AttestryAPIError)", () => {
    expect(typeof sdk.AttestryError).toBe("function");
    expect(typeof sdk.AttestryAPIError).toBe("function");
    // Hierarchy must hold through the public surface, not just the
    // internal module path.
    const err = new sdk.AttestryAPIError("x", 500);
    expect(err).toBeInstanceOf(sdk.AttestryError);
  });

  it("exports the IncidentsResource class", () => {
    expect(typeof sdk.IncidentsResource).toBe("function");
    expect(sdk.IncidentsResource.prototype).toBeDefined();
  });

  it("exports the DecisionsResource class", () => {
    expect(typeof sdk.DecisionsResource).toBe("function");
    expect(sdk.DecisionsResource.prototype).toBeDefined();
  });

  it("exports the ChatResource class", () => {
    expect(typeof sdk.ChatResource).toBe("function");
    expect(sdk.ChatResource.prototype).toBeDefined();
  });

  it("exports the AuditLogResource class", () => {
    expect(typeof sdk.AuditLogResource).toBe("function");
    expect(sdk.AuditLogResource.prototype).toBeDefined();
  });

  it("exports the RegulatoryChangesResource class", () => {
    expect(typeof sdk.RegulatoryChangesResource).toBe("function");
    expect(sdk.RegulatoryChangesResource.prototype).toBeDefined();
  });

  it("exports the ComplianceCheckResource class", () => {
    expect(typeof sdk.ComplianceCheckResource).toBe("function");
    expect(sdk.ComplianceCheckResource.prototype).toBeDefined();
  });

  it("exports the CheckResource class", () => {
    expect(typeof sdk.CheckResource).toBe("function");
    expect(sdk.CheckResource.prototype).toBeDefined();
  });

  it("exports the GateResource class", () => {
    expect(typeof sdk.GateResource).toBe("function");
    expect(sdk.GateResource.prototype).toBeDefined();
  });

  it("exports the BatchResource class", () => {
    expect(typeof sdk.BatchResource).toBe("function");
    expect(sdk.BatchResource.prototype).toBeDefined();
  });

  it("exports the ShipGateResource class", () => {
    expect(typeof sdk.ShipGateResource).toBe("function");
    expect(sdk.ShipGateResource.prototype).toBeDefined();
  });

  it("exports the public enum constants", () => {
    expect(Array.isArray(sdk.INCIDENT_TYPES)).toBe(true);
    expect(sdk.INCIDENT_TYPES).toContain("prompt_injection");
    expect(Array.isArray(sdk.SEVERITIES)).toBe(true);
    expect(sdk.SEVERITIES).toContain("critical");
    expect(Array.isArray(sdk.FRAMEWORK_CODES)).toBe(true);
    expect(sdk.FRAMEWORK_CODES).toContain("eu_ai_act");
    expect(Array.isArray(sdk.CHAT_MESSAGE_ROLES)).toBe(true);
    expect(sdk.CHAT_MESSAGE_ROLES).toEqual(["user", "assistant"]);
    expect(Array.isArray(sdk.DECISION_STREAM_EVENT_TYPES)).toBe(true);
    expect(sdk.DECISION_STREAM_EVENT_TYPES).toEqual(["decision.appended"]);
    expect(Array.isArray(sdk.AUDIT_LOG_EXPORT_FORMATS)).toBe(true);
    expect(sdk.AUDIT_LOG_EXPORT_FORMATS).toEqual(["jsonl", "ecs", "cef"]);
    expect(Array.isArray(sdk.REGULATORY_CHANGE_SEVERITIES)).toBe(true);
    expect(sdk.REGULATORY_CHANGE_SEVERITIES).toEqual([
      "critical",
      "high",
      "medium",
      "low",
    ]);
    expect(Array.isArray(sdk.REGULATORY_CHANGE_STATUSES)).toBe(true);
    expect(sdk.REGULATORY_CHANGE_STATUSES).toEqual([
      "new",
      "reviewed",
      "actioned",
      "dismissed",
    ]);
    expect(Array.isArray(sdk.BATCH_JOB_TYPES)).toBe(true);
    expect(sdk.BATCH_JOB_TYPES).toEqual([
      "classify",
      "assess",
      "classify_and_assess",
    ]);
    expect(Array.isArray(sdk.BATCH_JOB_STATUSES)).toBe(true);
    expect(sdk.BATCH_JOB_STATUSES).toEqual([
      "pending",
      "processing",
      "completed",
      "failed",
    ]);
  });

  it("frozen enums block the full mutator family (push/pop/shift/unshift/splice/index/delete) — P1 hostile round H1", () => {
    // Defense-in-depth: the freeze pin asserts Object.isFrozen returns
    // true on every export, which is sufficient per JS spec to block
    // every mutator. This pin verifies the spec behavior holds for
    // each named mutator the SDK might worry about, in case a future
    // JS engine bug (or `new Proxy` shenanigan) lets one slip through.
    // Each push/pop/shift/unshift/splice/delete/index-set is rejected
    // in strict mode (TS-emitted modules). The frozen array's
    // contents remain unchanged across all attempts.
    const original = [...sdk.AUDIT_LOG_EXPORT_FORMATS];
    expect(() => {
      (sdk.AUDIT_LOG_EXPORT_FORMATS as unknown as string[]).push("evil");
    }).toThrowError(TypeError);
    expect(() => {
      (sdk.AUDIT_LOG_EXPORT_FORMATS as unknown as string[]).pop();
    }).toThrowError(TypeError);
    expect(() => {
      (sdk.AUDIT_LOG_EXPORT_FORMATS as unknown as string[]).shift();
    }).toThrowError(TypeError);
    expect(() => {
      (sdk.AUDIT_LOG_EXPORT_FORMATS as unknown as string[]).unshift("evil");
    }).toThrowError(TypeError);
    expect(() => {
      (sdk.AUDIT_LOG_EXPORT_FORMATS as unknown as string[]).splice(0, 1);
    }).toThrowError(TypeError);
    expect(() => {
      (sdk.AUDIT_LOG_EXPORT_FORMATS as unknown as string[])[0] = "evil";
    }).toThrowError(TypeError);
    expect(() => {
      delete (sdk.AUDIT_LOG_EXPORT_FORMATS as unknown as { 0: string })[0];
    }).toThrowError(TypeError);
    // Contents unchanged after every attempt.
    expect([...sdk.AUDIT_LOG_EXPORT_FORMATS]).toEqual(original);
  });

  it("frozen enums are non-extensible — `Array.prototype.push.call` and Object.defineProperty also blocked (H2)", () => {
    // Bypass attempt: calling Array.prototype.push directly with the
    // frozen array as `this`. Same TypeError. Object.defineProperty
    // adding a new index also rejected because Object.freeze makes
    // the array non-extensible.
    expect(() => {
      Array.prototype.push.call(
        sdk.SEVERITIES as unknown as string[],
        "evil",
      );
    }).toThrowError(TypeError);
    expect(() => {
      Object.defineProperty(sdk.SEVERITIES, 99, { value: "evil" });
    }).toThrowError(TypeError);
    expect(Object.isExtensible(sdk.SEVERITIES)).toBe(false);
  });

  it("spread `[...FROZEN]` returns a new mutable array (consumer escape hatch — H3)", () => {
    // Defensive: the frozen export is for VALIDATION at the SDK
    // boundary. Consumers who want a mutable copy (e.g., to add a
    // custom UI category) can spread into a fresh array. This pin
    // proves the escape hatch works — the spread copy is mutable and
    // mutating it does not affect the frozen original.
    const copy: string[] = [...sdk.SEVERITIES];
    expect(Object.isFrozen(copy)).toBe(false);
    copy.push("custom");
    expect(copy).toEqual(["low", "medium", "high", "critical", "custom"]);
    // Original unchanged.
    expect(sdk.SEVERITIES).toEqual(["low", "medium", "high", "critical"]);
  });

  it("frozen enums remain iterable + readable for legitimate consumers (H4)", () => {
    // Pin the read-only contract: every legitimate consumer operation
    // (for-of, .map, .filter, .indexOf, .join, .at) works identically
    // on the frozen array. Without this, a future "freeze too
    // aggressively" refactor that wraps in a Proxy with restricted
    // get-traps could break consumers — this pin would fire.
    const collected: string[] = [];
    for (const value of sdk.REGULATORY_CHANGE_SEVERITIES) {
      collected.push(value);
    }
    expect(collected).toEqual(["critical", "high", "medium", "low"]);
    expect(sdk.REGULATORY_CHANGE_SEVERITIES.map((v) => v.toUpperCase())).toEqual(
      ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    );
    expect(
      sdk.REGULATORY_CHANGE_SEVERITIES.filter((v) => v.length === 4),
    ).toEqual(["high"]);
    expect(sdk.REGULATORY_CHANGE_SEVERITIES.indexOf("medium")).toBe(2);
    expect(sdk.REGULATORY_CHANGE_SEVERITIES.join("|")).toBe(
      "critical|high|medium|low",
    );
    expect(sdk.REGULATORY_CHANGE_SEVERITIES.at(-1)).toBe("low");
  });

  it("public enum constants are frozen (P1 hardening — prevents hostile/buggy mutation)", () => {
    // P1: Object.freeze sweep on every closed-enum export. Without
    // this, a malicious or buggy npm dependency in the consumer's
    // node_modules could `(SEVERITIES as any).push("evil")` between
    // SDK import and method call — bypassing the SDK's `.includes()`
    // validation on closed-enum input fields (carry-forward invariant
    // #41). Object.freeze blocks the mutation: in strict mode (which
    // TypeScript-emitted ES modules use by default), the push throws
    // TypeError; in sloppy mode, the push silently fails. Either way,
    // the array is unchanged.
    //
    // This pin asserts the freeze contract at the public boundary.
    // If a future refactor accidentally drops the freeze on any
    // export, this test fires with a clear "expected true to be true
    // for <enum name>" message.
    expect(Object.isFrozen(sdk.INCIDENT_TYPES)).toBe(true);
    expect(Object.isFrozen(sdk.SEVERITIES)).toBe(true);
    expect(Object.isFrozen(sdk.FRAMEWORK_CODES)).toBe(true);
    expect(Object.isFrozen(sdk.CHAT_MESSAGE_ROLES)).toBe(true);
    expect(Object.isFrozen(sdk.DECISION_STREAM_EVENT_TYPES)).toBe(true);
    expect(Object.isFrozen(sdk.AUDIT_LOG_EXPORT_FORMATS)).toBe(true);
    expect(Object.isFrozen(sdk.REGULATORY_CHANGE_SEVERITIES)).toBe(true);
    expect(Object.isFrozen(sdk.REGULATORY_CHANGE_STATUSES)).toBe(true);

    // Defense-in-depth: explicitly confirm a mutation attempt is
    // rejected. In strict mode (TS-emitted modules), push throws
    // TypeError. The throw is the proof that the freeze is effective
    // at runtime, not just at the type level.
    expect(() => {
      (sdk.SEVERITIES as unknown as string[]).push("evil");
    }).toThrowError(TypeError);
    expect(sdk.SEVERITIES).toEqual(["low", "medium", "high", "critical"]);
  });

  it("AttestryClient construction works through the public surface", () => {
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    // Resource composition lands on the public type.
    expect(client.incidents).toBeInstanceOf(sdk.IncidentsResource);
    expect(client.decisions).toBeInstanceOf(sdk.DecisionsResource);
    expect(client.chat).toBeInstanceOf(sdk.ChatResource);
    expect(client.auditLog).toBeInstanceOf(sdk.AuditLogResource);
    expect(client.regulatoryChanges).toBeInstanceOf(
      sdk.RegulatoryChangesResource,
    );
    expect(client.complianceCheck).toBeInstanceOf(
      sdk.ComplianceCheckResource,
    );
    expect(client.check).toBeInstanceOf(sdk.CheckResource);
    expect(client.gate).toBeInstanceOf(sdk.GateResource);
    expect(client.batch).toBeInstanceOf(sdk.BatchResource);
    expect(client.shipGate).toBeInstanceOf(sdk.ShipGateResource);
    expect(client.abacPolicies).toBeInstanceOf(sdk.AbacPoliciesResource);
  });

  it("exports DEFAULT_RETRY_OPTIONS (retry middleware config)", () => {
    expect(typeof sdk.DEFAULT_RETRY_OPTIONS).toBe("object");
    expect(sdk.DEFAULT_RETRY_OPTIONS).toMatchObject({
      maxRetries: 3,
      initialDelayMs: 1_000,
      maxDelayMs: 30_000,
      honorRetryAfter: true,
    });
  });

  it("DecisionsResource exposes the list() method on the public surface", () => {
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.decisions.list).toBe("function");
  });

  it("DecisionsResource exposes the ingest() method on the public surface", () => {
    // Type-erased exports (DecisionIngestInput, FrameworkClaim,
    // ToolInvocation, DelegationEntry, ZkProof) can't be runtime-pinned,
    // but the resource METHOD is a runtime value — pin the
    // index.ts → client.ts → decisions.ts wiring surfaces ingest() to
    // consumers.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.decisions.ingest).toBe("function");
  });

  it("DecisionsResource exposes the bulk() method on the public surface", () => {
    // Type-erased exports (DecisionBulkInput, BulkInsertedSummary,
    // BulkFailedSummary, BulkIngestResult) can't be runtime-pinned,
    // but the resource METHOD is a runtime value — pin the
    // index.ts → client.ts → decisions.ts wiring surfaces bulk() to
    // consumers.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.decisions.bulk).toBe("function");
  });

  it("DecisionsResource exposes the stream() method on the public surface", () => {
    // Type-erased exports (DecisionStreamEvent, DecisionsStreamInput)
    // can't be runtime-pinned, but the resource METHOD is a runtime
    // value — pin that index.ts → client.ts → decisions.ts wiring
    // surfaces the new method to consumers.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.decisions.stream).toBe("function");
  });

  it("DecisionsResource exposes the export() method on the public surface", () => {
    // Type-erased exports (DecisionsExportInput, DecisionExportRecord,
    // DecisionExportTrailer, DecisionExportFrame) can't be runtime-
    // pinned, but the resource METHOD is a runtime value — pin that
    // index.ts → client.ts → decisions.ts wiring surfaces export() to
    // consumers (and so a typo in any of those layers would surface
    // here, not at install-time).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.decisions.export).toBe("function");
  });

  it("DecisionsResource exposes the verifyChain() method on the public surface", () => {
    // Type-erased exports (ChainVerificationResult) can't be runtime-
    // pinned, but the resource METHOD is a runtime value — pin that
    // index.ts → client.ts → decisions.ts wiring surfaces verifyChain()
    // to consumers (and so a typo in any of those layers would surface
    // here, not at install-time). Closes the decisions surface to 7
    // methods (ingest, bulk, retrieve, list, stream, export, verifyChain).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.decisions.verifyChain).toBe("function");
  });

  it("AuditLogResource exposes the export() method on the public surface", () => {
    // Type-erased exports (AuditLogRecord, AuditLogExportInput,
    // AuditLogExportFormat) can't be runtime-pinned, but the resource
    // METHOD is a runtime value — pin that index.ts → client.ts →
    // audit-log.ts wiring surfaces export() to consumers (and so a
    // typo in any of those layers would surface here, not at install-
    // time). First non-decisions resource on the SDK; sibling to
    // incidents / decisions / chat.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.auditLog.export).toBe("function");
  });

  it("AuditLogResource exposes the verifyChain() method on the public surface", () => {
    // Type-erased export (AuditChainVerificationResult) can't be
    // runtime-pinned, but the resource METHOD is a runtime value —
    // pin that index.ts → client.ts → audit-log.ts wiring surfaces
    // verifyChain() to consumers (and so a typo in any of those
    // layers would surface here, not at install-time). Session 19;
    // 19th audit chain in the F.1 phase. Closes the auditLog surface
    // to 2 methods (export, verifyChain). Distinct from
    // decisions.verifyChain (per-system) — auditLog.verifyChain is
    // org-wide audit-log hash-chain verification.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.auditLog.verifyChain).toBe("function");
  });

  it("RegulatoryChangesResource exposes the list() method on the public surface", () => {
    // Type-erased exports (RegulatoryChange, RegulatoryChangesListInput,
    // RegulatoryChangeSeverity, RegulatoryChangeStatus) can't be
    // runtime-pinned, but the resource METHOD is a runtime value — pin
    // that index.ts → client.ts → regulatory-changes.ts wiring surfaces
    // list() to consumers (and so a typo in any of those layers would
    // surface here, not at install-time). Second non-decisions resource
    // on the SDK; sibling to incidents / decisions / chat / auditLog.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.regulatoryChanges.list).toBe("function");
  });

  it("ComplianceCheckResource exposes the check() method on the public surface", () => {
    // Type-erased exports (ComplianceCheckInput, ComplianceCheckResult,
    // ComplianceCheckResponse, ComplianceCheckFrameworkCoverage) can't
    // be runtime-pinned, but the resource METHOD is a runtime value —
    // pin that index.ts → client.ts → compliance-check.ts wiring
    // surfaces check() to consumers (and so a typo in any of those
    // layers would surface here, not at install-time). Third
    // non-decisions resource on the SDK; sibling to incidents /
    // decisions / chat / auditLog / regulatoryChanges.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.complianceCheck.check).toBe("function");
  });

  it("CheckResource exposes the run() method on the public surface", () => {
    // Type-erased exports (CheckInput, CheckResponse) can't be runtime-
    // pinned, but the resource METHOD is a runtime value — pin that
    // index.ts → client.ts → check.ts wiring surfaces run() to consumers
    // (and so a typo in any of those layers would surface here, not at
    // install-time). Fourth non-decisions resource on the SDK; sibling
    // to incidents / decisions / chat / auditLog / regulatoryChanges /
    // complianceCheck. Method name `run` rather than `check` (the
    // resource is `check`, the verb is `run` — avoids `client.check.check`).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.check.run).toBe("function");
  });

  it("GateResource exposes the evaluate() method on the public surface", () => {
    // Type-erased exports (GateInput, GateGap, GateResponse) can't be
    // runtime-pinned, but the resource METHOD is a runtime value — pin
    // that index.ts → client.ts → gate.ts wiring surfaces evaluate() to
    // consumers (and so a typo in any of those layers would surface
    // here, not at install-time). Fifth non-decisions resource on the
    // SDK; sibling to incidents / decisions / chat / auditLog /
    // regulatoryChanges / complianceCheck / check. Method name
    // `evaluate` (verb-method convention matching pass/fail evaluation
    // semantics; chosen over `run` / `check` / `execute`).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.gate.evaluate).toBe("function");
  });

  it("BatchResource exposes the submit() method on the public surface", () => {
    // Type-erased exports (BatchSubmitInput, BatchSubmitResponse,
    // BatchSystemResult, BatchConfig, BatchJobType,
    // BatchJobStatusValue) can't be runtime-pinned, but the resource
    // METHOD is a runtime value — pin that index.ts → client.ts →
    // batch.ts wiring surfaces submit() to consumers. Sixth non-
    // decisions resource on the SDK; sibling to incidents /
    // decisions / chat / auditLog / regulatoryChanges /
    // complianceCheck / check / gate. **First SDK resource with
    // asymmetric auth between methods on the same resource**
    // (submit() needs CLASSIFY+WRITE_ASSESSMENTS union; get() needs
    // READ_ASSESSMENTS only). Method name `submit` (verb-method
    // convention matching the kernel POST action).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.batch.submit).toBe("function");
  });

  it("BatchResource exposes the get() method on the public surface", () => {
    // Type-erased exports (BatchJobStatus, BatchJobStatusValue) can't
    // be runtime-pinned, but the resource METHOD is a runtime value —
    // pin that index.ts → client.ts → batch.ts wiring surfaces get()
    // to consumers. Closes the batch surface to 2 methods (submit,
    // get). Method name `get` (canonical SDK retrieve verb; chosen
    // over `retrieve` / `status` / `bulk` to match the verb-method
    // convention and most SDK precedents).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.batch.get).toBe("function");
  });

  it("ShipGateResource exposes the check() method on the public surface", () => {
    // Type-erased exports (ShipGateInput, ShipGateCheckResponse,
    // ShipGateReasonCode, ShipGateState) can't be runtime-pinned, but
    // the resource METHOD is a runtime value — pin that index.ts →
    // client.ts → ship-gate.ts wiring surfaces check() to consumers.
    // Sixth non-decisions resource on the SDK; sibling to incidents /
    // decisions / chat / auditLog / regulatoryChanges /
    // complianceCheck / check / gate / batch. Method name `check`
    // (matches the kernel endpoint name POST /api/v1/ship-gate/check;
    // chosen over `run` / `evaluate` because the kernel endpoint is
    // named `/check` and `check.run` already occupies the `.run`
    // verb at the SDK level). Distinct from `gate.evaluate` — that
    // method is a synchronous compliance-score gate; `shipGate.check`
    // is a multi-approver workflow gate (different lifecycle).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () => new Response("{}", { status: 200 }),
    });
    expect(typeof client.shipGate.check).toBe("function");
  });

  it("AbacPoliciesResource exposes the list() method on the public surface", () => {
    // Type-erased exports (AbacPolicy, AbacPoliciesListResponse,
    // AbacCondition, etc.) can't be runtime-pinned, but the resource
    // METHOD is a runtime value — pin that index.ts → client.ts →
    // abac-policies.ts wiring surfaces list() to consumers. Eighth
    // non-decisions resource on the SDK; sibling to all 10 existing
    // resource classes. First method of the 5-method `abacPolicies`
    // CRUD cluster (`.create` shipped in session 21; `.retrieve` /
    // `.update` / `.delete` ship in session 22).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () =>
        new Response('{"success":true,"data":{"items":[],"count":0}}', {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });
    expect(typeof client.abacPolicies.list).toBe("function");
  });

  it("AbacPoliciesResource exposes the create() method on the public surface", () => {
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () =>
        new Response("{}", {
          status: 201,
          headers: { "Content-Type": "application/json" },
        }),
    });
    expect(typeof client.abacPolicies.create).toBe("function");
  });

  it("AbacPoliciesResource exposes the retrieve() method on the public surface", () => {
    // Third method of the 5-method `abacPolicies` CRUD cluster
    // (`.list` + `.create` shipped in session 21). `.retrieve()` is
    // the first method with a UUID path segment.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () =>
        new Response("{}", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });
    expect(typeof client.abacPolicies.retrieve).toBe("function");
  });

  it("AbacPoliciesResource exposes the delete() method on the public surface", () => {
    // Fourth method of the 5-method `abacPolicies` CRUD cluster.
    // FIRST SDK method using the HTTP DELETE verb.
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () =>
        new Response("{}", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });
    expect(typeof client.abacPolicies.delete).toBe("function");
  });

  it("AbacPoliciesResource exposes the update() method on the public surface", () => {
    // Fifth and final method of the 5-method `abacPolicies` CRUD
    // cluster — completes list / create / retrieve / update / delete.
    // SECOND SDK method using the HTTP PATCH verb (incidents.update
    // is the first).
    const client = new sdk.AttestryClient({
      apiKey: "k",
      fetch: async () =>
        new Response("{}", {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    });
    expect(typeof client.abacPolicies.update).toBe("function");
  });

  it("exports ABAC_POLICY_RESOURCES / ABAC_POLICY_ACTIONS / ABAC_POLICY_EFFECTS runtime arrays (frozen, mirror of kernel)", () => {
    // Closed-enum runtime arrays are runtime-pinned: pin the arrays
    // are exported, length matches expected, and Object.freeze'd so
    // a hostile dep can't mutate them at runtime (carry-forward
    // invariant #41).
    expect(Array.isArray(sdk.ABAC_POLICY_RESOURCES)).toBe(true);
    expect(sdk.ABAC_POLICY_RESOURCES.length).toBe(10);
    expect(sdk.ABAC_POLICY_RESOURCES).toContain("systems");
    expect(sdk.ABAC_POLICY_RESOURCES).toContain("audit_log");
    expect(Object.isFrozen(sdk.ABAC_POLICY_RESOURCES)).toBe(true);

    expect(Array.isArray(sdk.ABAC_POLICY_ACTIONS)).toBe(true);
    expect(sdk.ABAC_POLICY_ACTIONS.length).toBe(5);
    expect(sdk.ABAC_POLICY_ACTIONS).toContain("create");
    expect(sdk.ABAC_POLICY_ACTIONS).toContain("manage");
    expect(Object.isFrozen(sdk.ABAC_POLICY_ACTIONS)).toBe(true);

    expect(Array.isArray(sdk.ABAC_POLICY_EFFECTS)).toBe(true);
    expect(sdk.ABAC_POLICY_EFFECTS.length).toBe(2);
    expect(sdk.ABAC_POLICY_EFFECTS).toEqual(["allow", "deny"]);
    expect(Object.isFrozen(sdk.ABAC_POLICY_EFFECTS)).toBe(true);
  });
});
