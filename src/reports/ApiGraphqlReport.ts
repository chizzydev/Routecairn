import type { ApiGraphqlCheckKind, ApiGraphqlOutcome } from "../modules/apiGraphql/ApiGraphqlTypes.js";

export interface ApiRouteInventoryObservation {
  routeId: string;
  safeAlias: string;
  protocol: "REST" | "GRAPHQL";
  kind: string;
  path: string;
  version?: string;
  documented: boolean;
  documentedMethods: readonly string[];
  checksExecuted: number;
}

export interface ApiFieldExposureObservation {
  path: string;
  classification: string;
  expectation: string;
  observed: "PRESENT" | "ABSENT" | "REDACTED" | "UNAVAILABLE";
  outcome: ApiGraphqlOutcome;
}

export interface ApiRequestObservation {
  label: string;
  method: string;
  statusCode?: number;
  decision: "ALLOWED" | "DENIED" | "UNCLASSIFIED";
  bodyShapeFingerprint: string;
  fieldSetFingerprint: string;
  fieldCount: number;
  itemCount?: number;
  graphqlErrors: number;
  documentedFieldsPresent?: number;
  documentedFieldsMissing?: number;
  undocumentedFieldsObserved?: number;
}

export interface ApiGraphqlCheckObservation {
  checkId: string;
  label: string;
  kind: ApiGraphqlCheckKind;
  routeAliases: readonly string[];
  protocols: readonly ("REST" | "GRAPHQL")[];
  actorAlias: string;
  actorRelationship: string;
  outcome: ApiGraphqlOutcome;
  reasonCode: string;
  comparisonFingerprint: string;
  requests: readonly ApiRequestObservation[];
  fields: readonly ApiFieldExposureObservation[];
  objectIdentityConfirmed?: boolean;
  tenantBoundaryConfirmed?: boolean;
  introspectionClassification?: "DISABLED" | "RESTRICTED" | "AVAILABLE" | "INCONCLUSIVE";
  operationCount?: number;
  notes: readonly string[];
}

export interface ApiAuthorizationMatrixObservation {
  matrixId: string;
  dimension: "OBJECT" | "FUNCTION" | "FIELD" | "TENANT";
  routeAliases: readonly string[];
  cells: readonly { checkId: string; actorAlias: string; relationship: string; outcome: ApiGraphqlOutcome; observedDecision: string }[];
}

export interface ApiSchemaComparisonObservation {
  comparisonFingerprint?: string;
  routeId: string;
  routeAlias: string;
  schemaSourceAlias: string;
  schemaPath: string;
  pathDocumented: boolean;
  missingDocumentedMethods: readonly string[];
  undocumentedConfiguredMethods: readonly string[];
  outcome: ApiGraphqlOutcome;
  reasonCode: string;
}

export interface ApiGraphqlReviewReport {
  enabled: boolean;
  inventory: readonly ApiRouteInventoryObservation[];
  checks: readonly ApiGraphqlCheckObservation[];
  authorizationMatrices: readonly ApiAuthorizationMatrixObservation[];
  schemaComparisons: readonly ApiSchemaComparisonObservation[];
  plannedChecks: number;
  executedChecks: number;
  passedChecks: number;
  failedChecks: number;
  inconclusiveChecks: number;
  blockedChecks: number;
  restChecks: number;
  graphqlChecks: number;
  objectAuthorizationChecks: number;
  functionAuthorizationChecks: number;
  fieldAuthorizationChecks: number;
  tenantIsolationChecks: number;
  methodConfusionChecks: number;
  introspectionChecks: number;
  aliasLimitChecks: number;
  batchLimitChecks: number;
  versionBoundaryChecks: number;
  requestsTransmitted: number;
  requestBudget: number;
  notes: readonly string[];
}
