import type { HttpMethod } from "../../core/http/HttpTypes.js";

export const operationalEndpointCategories = [
  "WEBHOOK_SIGNATURE_REJECTION",
  "WEBHOOK_REPLAY_PROTECTION",
  "WEBHOOK_IDEMPOTENCY",
  "WEBHOOK_EVENT_ORDERING",
  "WEBHOOK_PAYLOAD_INTEGRITY",
  "CRON_AUTHENTICATION",
  "CRON_REPLAY_PROTECTION",
  "CRON_SCOPE_WORKLOAD_LIMIT",
  "JOB_AUTHORIZATION",
  "INCIDENT_ACCESS_CONTROL",
  "HEALTH_INFORMATION_EXPOSURE",
  "ADMIN_WORKER_AUTHORIZATION"
] as const;

export type OperationalEndpointCategory = (typeof operationalEndpointCategories)[number];
export type OperationalAuthSlot = "anonymous" | "primary" | "account_a" | "account_b";
export type OperationalEndpointKind = "WEBHOOK" | "CRON" | "JOB" | "INCIDENT" | "HEALTH" | "ADMIN" | "WORKER";
export type OperationalStepPhase = "PRE_STATE" | "ACTION" | "VERIFY" | "CLEANUP";

export interface OperationalActorPlan {
  id: string;
  safeAlias: string;
  authSlot: OperationalAuthSlot;
  sendAuthentication: boolean;
  relationship: string;
  principalFingerprint?: string;
  tenantFingerprint?: string;
}

export interface OperationalEndpointPlan {
  id: string;
  safeAlias: string;
  kind: OperationalEndpointKind;
  pathTemplate: string;
  allowedOrigins: readonly string[];
  declaredWorkloadLimit?: number;
}

export interface OperationalAuthorizationPlan {
  mode: "OBSERVE_ONLY" | "CONTROLLED_OPERATIONAL_FLOW";
  environment: "LOCAL" | "TEST" | "STAGING" | "PRODUCTION";
  authorizedAt?: string;
  expiresAt?: string;
  authorizationIdentityConfirmed: boolean;
  changeTicketConfirmed: boolean;
  disposableTarget: boolean;
  productionAcknowledged: boolean;
  confirmationAccepted: boolean;
}

export interface WebhookHmacPlan {
  kind: "HMAC";
  algorithm: "sha256" | "sha512";
  secretSource: OperationalAuthSlot;
  secretRef: string;
  header: string;
  encoding: "HEX" | "BASE64";
  prefix: string;
  messageFormat: "BODY" | "TIMESTAMP_DOT_BODY";
  timestampHeader?: string | undefined;
  timestampSecretRef?: string | undefined;
  tamper: boolean;
}

export interface OperationalRequestPlan {
  method: HttpMethod;
  urlTemplate: string;
  stateChanging: boolean;
  secretSource: OperationalAuthSlot;
  headers: Readonly<Record<string, string>>;
  bodyFormat?: "JSON" | "FORM" | "RAW" | undefined;
  fields?: unknown;
  hmac?: WebhookHmacPlan | undefined;
}

export type OperationalCapturePlan =
  | { name: string; source: "JSON"; path: string }
  | { name: string; source: "HEADER"; header: string };

export type OperationalAssertionPlan =
  | { kind: "STATUS_IN"; values: readonly number[] }
  | { kind: "STATUS_NOT_IN"; values: readonly number[] }
  | { kind: "DECISION"; expected: "ALLOW" | "DENY"; allowedStatuses: readonly number[]; deniedStatuses: readonly number[] }
  | { kind: "HEADER_PRESENT"; header: string }
  | { kind: "HEADER_ABSENT"; header: string }
  | { kind: "JSON_FIELD_PRESENT"; path: string }
  | { kind: "JSON_FIELD_ABSENT"; path: string; classification: "SECRET" | "INTERNAL" | "PERSONAL" | "OPERATIONAL" }
  | { kind: "JSON_EQUALS_SECRET"; path: string; secretSource: OperationalAuthSlot; secretRef: string }
  | { kind: "CAPTURE_EQUALS_SECRET"; capture: string; secretSource: OperationalAuthSlot; secretRef: string }
  | { kind: "CAPTURE_NOT_EQUALS_SECRET"; capture: string; secretSource: OperationalAuthSlot; secretRef: string }
  | { kind: "NUMERIC_DELTA"; before: string; after: string; operator: "EQ" | "LTE" | "GTE"; expected: number }
  | { kind: "BODY_FINGERPRINT"; expectedSha256: string }
  | { kind: "RESPONSE_FINGERPRINT_MATCH"; stepId: string }
  | { kind: "RESPONSE_FINGERPRINT_DIFFERENT"; stepId: string };

export interface OperationalStepPlan {
  id: string;
  phase: OperationalStepPhase;
  actorId: string;
  endpointId: string;
  waitBeforeMs: number;
  request: OperationalRequestPlan;
  captures: readonly OperationalCapturePlan[];
  assertions: readonly OperationalAssertionPlan[];
}

export interface OperationalEndpointCasePlan {
  id: string;
  label: string;
  category: OperationalEndpointCategory;
  authorization: OperationalAuthorizationPlan;
  cleanupRequired: boolean;
  steps: readonly OperationalStepPlan[];
  comparisonFingerprint: string;
}

export interface OperationalEndpointSecurityPlan {
  schemaVersion: 1;
  enabled: true;
  targetOrigin: string;
  maxCases: number;
  maxStepsPerCase: number;
  maxRequests: number;
  maxResponseBytes: number;
  actors: readonly OperationalActorPlan[];
  endpoints: readonly OperationalEndpointPlan[];
  cases: readonly OperationalEndpointCasePlan[];
  notes: readonly string[];
}
