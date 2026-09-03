import type { HttpMethod } from "../../core/http/HttpTypes.js";

export const apiGraphqlCheckKinds = [
  "OBJECT_AUTHORIZATION",
  "FUNCTION_AUTHORIZATION",
  "FIELD_AUTHORIZATION",
  "TENANT_ISOLATION",
  "METHOD_CONFUSION",
  "GRAPHQL_INTROSPECTION",
  "GRAPHQL_ALIAS_LIMIT",
  "GRAPHQL_BATCH_LIMIT",
  "VERSION_BOUNDARY"
] as const;

export type ApiGraphqlCheckKind = (typeof apiGraphqlCheckKinds)[number];
export type ApiGraphqlActorSlot = "anonymous" | "primary" | "account_a" | "account_b";
export type ApiGraphqlDecision = "ALLOW" | "DENY" | "OBSERVE";
export type ApiGraphqlOutcome = "PASS" | "FAIL" | "INCONCLUSIVE" | "BLOCKED";

export interface ApiGraphqlActorPlan {
  id: string;
  safeAlias: string;
  authSlot: ApiGraphqlActorSlot;
  relationship: string;
  principalFingerprint?: string;
  tenantFingerprint?: string;
  role?: string;
}

export interface ApiRouteSecurityPlan {
  id: string;
  safeAlias: string;
  protocol: "REST" | "GRAPHQL";
  kind: "OBJECT" | "COLLECTION" | "FUNCTION" | "SCHEMA" | "DOCUMENTATION";
  url: string;
  path: string;
  version?: string;
  objectType?: string;
  functionName?: string;
  documented: boolean;
  documentedMethods: readonly HttpMethod[];
  documentedResponseFields: readonly string[];
  schemaSourceId?: string;
  schemaPath?: string;
  inventoryActorId?: string;
  operatorConfirmedNonMutatingPost: boolean;
}

export interface ApiResponseFieldRulePlan {
  path: string;
  classification: "PUBLIC" | "INTERNAL" | "PERSONAL" | "FINANCIAL" | "SECRET" | "TENANT_BOUND" | "OBJECT_IDENTITY";
  expectation: "MUST_BE_PRESENT" | "MUST_BE_ABSENT" | "MUST_BE_REDACTED" | "OBSERVE";
}

export interface ApiRequestPlan {
  method: "GET" | "HEAD" | "OPTIONS" | "POST";
  headers: Readonly<Record<string, string>>;
  body?: unknown;
  graphql?: {
    operationName?: string;
    document: string;
    variables: Readonly<Record<string, unknown>>;
  };
}

export interface ApiResponseContractPlan {
  expectedDecision: ApiGraphqlDecision;
  allowedStatuses: readonly number[];
  deniedStatuses: readonly number[];
  fieldRules: readonly ApiResponseFieldRulePlan[];
  identity?: { path: string; expectedValue: unknown; expectedFingerprint: string };
  tenant?: { path: string; expectedValue?: unknown; expectedFingerprint?: string; forbiddenValueFingerprints: readonly string[]; forbiddenValues: readonly unknown[] };
  maxItems?: number;
}

export interface ApiAuthorizationCheckPlan {
  id: string;
  matrixId: string;
  label: string;
  kind: "OBJECT_AUTHORIZATION" | "FUNCTION_AUTHORIZATION" | "FIELD_AUTHORIZATION" | "TENANT_ISOLATION";
  routeId: string;
  actorId: string;
  requireVerifiedIdentity: boolean;
  request: ApiRequestPlan;
  response: ApiResponseContractPlan;
  comparisonFingerprint: string;
}

export interface MethodConfusionCheckPlan {
  id: string;
  label: string;
  kind: "METHOD_CONFUSION";
  routeId: string;
  actorId: string;
  requireVerifiedIdentity: boolean;
  canonicalMethod: "GET" | "HEAD" | "OPTIONS" | "POST";
  alternateMethods: readonly ("GET" | "HEAD" | "OPTIONS" | "POST")[];
  expectation: "MUST_MATCH_CANONICAL" | "ALTERNATES_MUST_DENY";
  request: Omit<ApiRequestPlan, "method">;
  allowedStatuses: readonly number[];
  deniedStatuses: readonly number[];
  comparisonFingerprint: string;
}

export interface GraphqlIntrospectionCheckPlan {
  id: string;
  label: string;
  kind: "GRAPHQL_INTROSPECTION";
  routeId: string;
  actorId: string;
  requireVerifiedIdentity: boolean;
  expectedClassification: "DISABLED" | "RESTRICTED" | "AVAILABLE" | "OBSERVE";
  comparisonFingerprint: string;
}

export interface GraphqlLimitCheckPlan {
  id: string;
  label: string;
  kind: "GRAPHQL_ALIAS_LIMIT" | "GRAPHQL_BATCH_LIMIT";
  routeId: string;
  actorId: string;
  requireVerifiedIdentity: boolean;
  operationCount: number;
  documents: readonly { operationName?: string; document: string; variables: Readonly<Record<string, unknown>> }[];
  expectation: "MUST_REJECT" | "MUST_ALLOW" | "OBSERVE";
  allowedStatuses: readonly number[];
  deniedStatuses: readonly number[];
  comparisonFingerprint: string;
}

export interface VersionBoundaryCheckPlan {
  id: string;
  label: string;
  kind: "VERSION_BOUNDARY";
  baselineRouteId: string;
  candidateRouteId: string;
  actorId: string;
  requireVerifiedIdentity: boolean;
  request: ApiRequestPlan;
  expectation: "MUST_MATCH_AUTHORIZATION" | "CANDIDATE_MUST_NOT_EXPOSE_MORE_FIELDS" | "MUST_MATCH_FIELD_SET";
  allowedStatuses: readonly number[];
  deniedStatuses: readonly number[];
  comparisonFingerprint: string;
}

export type ApiGraphqlCheckPlan = ApiAuthorizationCheckPlan | MethodConfusionCheckPlan | GraphqlIntrospectionCheckPlan | GraphqlLimitCheckPlan | VersionBoundaryCheckPlan;

export interface ApiGraphqlReviewPlan {
  schemaVersion: 1;
  enabled: true;
  targetOrigin: string;
  maxRequests: number;
  maxResponseBytes: number;
  maxJsonDepth: number;
  maxGraphqlDocumentBytes: number;
  maxGraphqlAliases: number;
  maxGraphqlBatchOperations: number;
  actors: readonly ApiGraphqlActorPlan[];
  routes: readonly ApiRouteSecurityPlan[];
  checks: readonly ApiGraphqlCheckPlan[];
  notes: readonly string[];
}
