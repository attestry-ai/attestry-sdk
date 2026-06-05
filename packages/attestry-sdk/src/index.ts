// ─── Public API ─────────────────────────────────────────────────────────────
//
// Entry point of `@attestry/sdk`. Anything not re-exported here is internal
// and not part of the public contract.

export { AttestryClient } from "./client.js";
export { AttestryError, AttestryAPIError } from "./errors.js";

export {
  INCIDENT_TYPES,
  SEVERITIES,
  FRAMEWORK_CODES,
  type IncidentType,
  type Severity,
  type FrameworkCode,
} from "./constants.js";

export type {
  AttestryClientOptions,
  FetchLike,
  RequestOptions,
} from "./types.js";

export {
  DEFAULT_RETRY_OPTIONS,
  type RetryOptions,
} from "./retry.js";

export {
  IncidentsResource,
  type Incident,
  type IncidentReportInput,
  type IncidentListInput,
  type IncidentListResponse,
  type IncidentPatchInput,
  type IncidentSearchInput,
  type IncidentSearchResponse,
  type IncidentCluster,
  type IncidentClusterSeverityCounts,
} from "./resources/incidents.js";

export {
  DecisionsResource,
  DECISION_STREAM_EVENT_TYPES,
  type DecisionRecord,
  type DecisionIngestInput,
  type FrameworkClaim,
  type ToolInvocation,
  type DelegationEntry,
  type ZkProof,
  type DecisionBulkInput,
  type BulkInsertedSummary,
  type BulkFailedSummary,
  type BulkIngestResult,
  type DecisionListItem,
  type DecisionsListInput,
  type DecisionsListResponse,
  type DecisionStreamEvent,
  type DecisionStreamEventType,
  type DecisionsStreamInput,
  type DecisionsExportInput,
  type DecisionExportRecord,
  type DecisionExportTrailer,
  type DecisionExportFrame,
  type ChainVerificationResult,
} from "./resources/decisions.js";

export {
  ChatResource,
  CHAT_MESSAGE_ROLES,
  type ChatMessage,
  type ChatMessageRole,
  type ChatContext,
  type ChatContextGap,
  type ChatSendInput,
  type ChatSendResponse,
  type ChatStreamChunk,
} from "./resources/chat.js";

export {
  AuditLogResource,
  AUDIT_LOG_EXPORT_FORMATS,
  type AuditLogExportFormat,
  type AuditLogRecord,
  type AuditLogExportInput,
  type AuditChainVerificationResult,
} from "./resources/audit-log.js";

export {
  RegulatoryChangesResource,
  REGULATORY_CHANGE_SEVERITIES,
  REGULATORY_CHANGE_STATUSES,
  type RegulatoryChangeSeverity,
  type RegulatoryChangeStatus,
  type RegulatoryChange,
  type RegulatoryChangesListInput,
} from "./resources/regulatory-changes.js";

export {
  ComplianceCheckResource,
  type ComplianceCheckInput,
  type ComplianceCheckResult,
  type ComplianceCheckResponse,
  type ComplianceCheckFrameworkCoverage,
} from "./resources/compliance-check.js";

export {
  CheckResource,
  type CheckInput,
  type CheckResponse,
} from "./resources/check.js";

export {
  GateResource,
  type GateInput,
  type GateGap,
  type GateResponse,
} from "./resources/gate.js";

export {
  BatchResource,
  BATCH_JOB_TYPES,
  BATCH_JOB_STATUSES,
  type BatchJobType,
  type BatchJobStatusValue,
  type BatchSystemResult,
  type BatchConfig,
  type BatchSubmitInput,
  type BatchSubmitResponse,
  type BatchJobStatus,
} from "./resources/batch.js";

export {
  ShipGateResource,
  type ShipGateInput,
  type ShipGateCheckResponse,
  type ShipGateReasonCode,
  type ShipGateState,
} from "./resources/ship-gate.js";

export {
  AbacPoliciesResource,
  ABAC_POLICY_RESOURCES,
  ABAC_POLICY_ACTIONS,
  ABAC_POLICY_EFFECTS,
  type AbacPolicy,
  type AbacPoliciesListResponse,
  type AbacPolicyCreateInput,
  type AbacPolicyUpdateInput,
  type AbacPolicyEffect,
  type AbacPolicyResource,
  type AbacPolicyAction,
  type AbacAttrRoot,
  type AbacAttrPath,
  type AbacAttrValue,
  type AbacLeafCondition,
  type AbacCompoundCondition,
  type AbacCondition,
} from "./resources/abac-policies.js";
