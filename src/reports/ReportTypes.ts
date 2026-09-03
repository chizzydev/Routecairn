import type { RouteCairnScope, ScanMode } from "../config/ConfigSchema.js";
import type { ScanProfileSummary } from "../config/ScanProfiles.js";
import type { ResolvedScanPlan } from "../core/planning/ScanPlan.js";
import type { HttpResponse, RequestAuditEntry } from "../core/http/HttpTypes.js";
import type { ScopeDecision } from "../core/scope/ScopeTypes.js";
import type { Finding } from "../core/findings/Finding.js";
import type { AuthProfileSummary } from "../core/auth/AuthProfile.js";
import type { AuthProfileSetSummary } from "../core/auth/AuthProfileSet.js";
import type { PrivilegeMutationReport } from "./PrivilegeMutationReport.js";
import type { SecretClassification } from "../modules/secretBoundary/SecretBoundaryTypes.js";

export type FalsePositiveStatus = "likely-valid" | "maybe-false-positive" | "likely-false-positive";

export interface BaselineProbe {
  url: string;
  statusCode?: number;
  title?: string;
  contentLength?: number;
  bodyHash?: string;
  error?: string;
}

export interface BaselineReport {
  probes: BaselineProbe[];
  wildcardStatusCode?: number;
  repeatedTitle?: string;
  repeatedBodyHash?: string;
  repeatedContentLength?: number;
  notes: string[];
}

export interface ResponseObservation {
  url: string;
  method: string;
  source: string;
  statusCode?: number;
  title?: string;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  responseHeaders?: Record<string, string | string[]>;
  bodyPreview?: string;
  responseTimeMs: number;
  falsePositiveStatus: FalsePositiveStatus;
  classificationReason: string;
}

export interface PathCandidate {
  path: string;
  source: string;
}

export type TechnologyCategory = "framework" | "platform" | "server" | "cdn" | "cms" | "commerce" | "storage" | "database" | "unknown";

export interface DetectedTechnology {
  name: string;
  category: TechnologyCategory;
  confidence: "Low" | "Medium" | "High";
  signals: string[];
}

export interface JsConfigValue {
  name: string;
  valuePreview: string;
  classification: "public-frontend-config" | "config-looking-value" | "redacted-sensitive-config";
  secretMaterialClass?: import("../modules/secretBoundary/SecretBoundaryTypes.js").SecretMaterialClass;
  secretImpact?: import("../modules/secretBoundary/SecretBoundaryTypes.js").SecretImpact;
}

export interface JsScriptAnalysis {
  scriptUrl: string;
  sameOrigin: boolean;
  downloaded: boolean;
  endpoints: string[];
  absoluteUrls: string[];
  websocketUrls: string[];
  cloudReferences: string[];
  configValues: JsConfigValue[];
  sourceMapUrls: string[];
  error?: string;
}

export interface JsIntelligenceReport {
  scripts: JsScriptAnalysis[];
  queuedEndpoints: PathCandidate[];
  sourceMaps: string[];
  notes: string[];
}

export interface ApiEndpointAnalysis {
  endpoint: string;
  method: string;
  routeType: string;
  riskTags: string[];
  likelyManualTests: string[];
  authRelevance: "low" | "medium" | "high";
  hasObjectId: boolean;
  privilegeSensitivity: "low" | "medium" | "high";
  dataExposureSensitivity: "low" | "medium" | "high";
  rateLimitSensitivity: "low" | "medium" | "high";
}

export interface ApiMapperReport {
  endpoints: ApiEndpointAnalysis[];
  graphQlEndpoints: string[];
  notes: string[];
}

export interface ApiProbeEndpointReview {
  endpoint: string;
  methodsTested: string[];
  statusByMethod: Record<string, number | "error">;
  contentTypes: string[];
  allowedMethods: string[];
  corsHints: string[];
  schemaHints: string[];
  graphQl: {
    attempted: boolean;
    available: boolean;
    evidence: string;
  };
  notes: string[];
}

export interface ApiProbeReport {
  safeMethods: string[];
  skippedMethods: string[];
  endpointsReviewed: ApiProbeEndpointReview[];
  schemaHints: string[];
  graphQlEndpoints: string[];
  notes: string[];
}

export interface AuthSurfaceAnalysis {
  endpoint: string;
  purpose: string;
  abuseCategories: string[];
  rateLimitSensitivity: "low" | "medium" | "high";
  accountEnumerationRelevance: "low" | "medium" | "high";
  suggestedTests: string[];
}

export interface AuthSurfaceReport {
  surfaces: AuthSurfaceAnalysis[];
  notes: string[];
}

export type AuthComparisonClassification = "auth-only" | "same-access" | "changed-content" | "auth-error" | "inconclusive";

export interface AuthResponseSummary {
  statusCode?: number;
  finalUrl?: string;
  title?: string;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  redirectChain?: Array<{ statusCode: number; location: string }>;
  error?: string;
}

export interface AuthComparisonResult {
  url: string;
  method: string;
  anonymous: AuthResponseSummary;
  authenticated: AuthResponseSummary;
  classification: AuthComparisonClassification;
  reason: string;
  proof: {
    anonymousCurlCommand: string;
    authenticatedCurlCommand: string;
    authMaterialRedacted: boolean;
  };
}

export interface AuthenticatedScanReport {
  profile: AuthProfileSummary;
  comparedUrls: number;
  authOnlySurfaces: AuthComparisonResult[];
  changedSurfaces: AuthComparisonResult[];
  results: AuthComparisonResult[];
  notes: string[];
}

export type RoleComparisonClassification =
  | "account-a-only"
  | "account-b-only"
  | "both-authenticated-access"
  | "only-authenticated-access"
  | "same-as-anonymous"
  | "role-error"
  | "inconclusive";

export interface RoleComparisonResult {
  url: string;
  method: string;
  anonymous: AuthResponseSummary;
  accountA: AuthResponseSummary;
  accountB: AuthResponseSummary;
  classification: RoleComparisonClassification;
  needsManualVerification: true;
  reason: string;
  proof: {
    anonymousCurlCommand: string;
    accountACurlCommand: string;
    accountBCurlCommand: string;
    authMaterialRedacted: boolean;
  };
}

export interface RoleComparisonReport {
  profileSet: AuthProfileSetSummary;
  comparedUrls: number;
  accountAOnly: RoleComparisonResult[];
  accountBOnly: RoleComparisonResult[];
  bothAuthenticatedAccess: RoleComparisonResult[];
  onlyAuthenticatedAccess: RoleComparisonResult[];
  results: RoleComparisonResult[];
  notes: string[];
}

export interface StateAwareApiMethodResult {
  method: string;
  safety: "safe" | "destructive-skipped" | "unknown-skipped";
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  allowHeader?: string;
  corsAllowMethods?: string;
  error?: string;
}

export interface StateAwareApiSkippedMethod {
  method: string;
  safety: "safe" | "destructive-skipped" | "unknown-skipped";
  reason: string;
}

export type StateAwareApiAccessSignal =
  | "account-a-only"
  | "account-b-only"
  | "only-authenticated-access"
  | "both-authenticated-different"
  | "auth-only"
  | "authenticated-different"
  | "publicly-accessible"
  | "inconclusive";

export interface StateAwareApiEndpointReview {
  endpoint: string;
  routeType: string;
  candidateReasons: string[];
  priority: "low" | "medium" | "high";
  safeMethodsTested: StateAwareApiMethodResult[];
  skippedMethods: StateAwareApiSkippedMethod[];
  accessComparison: {
    anonymous: AuthResponseSummary;
    authenticated?: AuthResponseSummary;
    accountA?: AuthResponseSummary;
    accountB?: AuthResponseSummary;
    signal: StateAwareApiAccessSignal;
    needsManualVerification: true;
  };
  evidenceNotes: string[];
}

export interface StateAwareApiReport {
  safeMethods: string[];
  skippedMethods: string[];
  candidateCount: number;
  reviewedEndpoints: StateAwareApiEndpointReview[];
  bolaIdorCandidates: StateAwareApiEndpointReview[];
  notes: string[];
}

export type IdentityVerificationCategory =
  | "VERIFIED"
  | "VERIFIED_WITH_PARTIAL_METADATA"
  | "DECLARED_ONLY"
  | "PRINCIPAL_MISMATCH"
  | "TENANT_MISMATCH"
  | "ROLE_MISMATCH"
  | "ACCOUNT_STATE_MISMATCH"
  | "IDENTITY_FIELD_MISSING"
  | "REQUIRED_METADATA_MISSING"
  | "AUTHENTICATION_FAILED"
  | "ANONYMOUS_RESPONSE"
  | "LOGIN_PAGE_RESPONSE"
  | "ACCESS_DENIED"
  | "UNSUPPORTED_CONTENT_TYPE"
  | "RESPONSE_TOO_LARGE"
  | "RATE_LIMITED"
  | "BUDGET_EXHAUSTED"
  | "OUT_OF_SCOPE"
  | "INCONCLUSIVE"
  | "EXECUTION_ERROR";

export interface IdentityVerificationResult {
  profileLabel: string;
  mode: "disabled" | "optional" | "required";
  endpoint?: string;
  method?: "GET" | "HEAD";
  category: IdentityVerificationCategory;
  verified: boolean;
  required: boolean;
  principalMatched: boolean;
  tenantMatched?: boolean;
  roleMatched?: boolean;
  accountStateMatched?: boolean;
  principalHash?: string;
  tenantHash?: string;
  roleHash?: string;
  accountStateHash?: string;
  safeAliasHash?: string;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  timestamp: string;
  notes: string[];
}

export interface IdentityVerificationReport {
  enabled: boolean;
  accountA?: IdentityVerificationResult;
  accountB?: IdentityVerificationResult;
  primary?: IdentityVerificationResult;
  distinctVerifiedPrincipals?: boolean;
  notes: string[];
}

export type ObjectPairResultCategory =
  | "AUTHORIZED_BASELINE_CONFIRMED"
  | "CROSS_ACCOUNT_ACCESS_CONFIRMED"
  | "CROSS_ACCOUNT_ACCESS_DENIED"
  | "PUBLIC_OBJECT_ACCESS"
  | "OBJECT_NOT_FOUND"
  | "AUTHENTICATION_FAILED"
  | "OWNERSHIP_NOT_CONFIRMED"
  | "RESPONSE_MISMATCH"
  | "RATE_LIMITED"
  | "TEST_BLOCKED_BY_SAFETY_POLICY"
  | "INCONCLUSIVE"
  | "EXECUTION_ERROR";

export type ObjectPairConfidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";
export type ObjectPairTechnicalAccessResult =
  | "OWNER_BASELINE_CONFIRMED"
  | "FOREIGN_PRIVATE_ACCESS_CONFIRMED"
  | "ACCESS_DENIED"
  | "PUBLIC_OR_SHARED_ACCESS"
  | "OBJECT_NOT_FOUND"
  | "AUTHENTICATION_FAILED"
  | "NOT_CONFIRMED"
  | "BLOCKED_BY_SAFETY_POLICY"
  | "EXECUTION_ERROR";
export type ObjectPairBusinessPolicyReviewStatus =
  | "DECLARED_PRIVATE_CONFIRMED"
  | "POLICY_REVIEW_REQUIRED"
  | "INTENDED_PUBLIC_OR_SHARED"
  | "NOT_APPLICABLE";
export type ObjectPairFinalClassification =
  | "CONFIRMED_VULNERABILITY"
  | "TECHNICAL_ACCESS_REQUIRES_POLICY_REVIEW"
  | "EXPECTED_ACCESS"
  | "PROTECTED"
  | "INCONCLUSIVE"
  | "BLOCKED"
  | "ERROR";

export interface ObjectPairResponseEvidence {
  statusCode?: number;
  finalUrl?: string;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  objectIdHash: string;
  containsExpectedObjectId: boolean;
  containsExpectedOwnerEvidence: boolean;
  containsPrivateFieldEvidence: boolean;
  denialMarker?: string;
  error?: string;
}

export interface ObjectPairRequestEvidence {
  matrixId: string;
  caseId: string;
  direction: "A_TO_A" | "B_TO_B" | "A_TO_B" | "B_TO_A";
  purpose: "owner-baseline" | "cross-account";
  requestingPrincipal: "account_a" | "account_b";
  targetOwner: "account_a" | "account_b";
  objectType: string;
  objectIdHash: string;
  method: "GET" | "HEAD";
  url: string;
  authMaterialRedacted: true;
  category: ObjectPairResultCategory;
  confidence: ObjectPairConfidence;
  technicalAccessResult: ObjectPairTechnicalAccessResult;
  businessPolicyReviewStatus: ObjectPairBusinessPolicyReviewStatus;
  finalClassification: ObjectPairFinalClassification;
  response: ObjectPairResponseEvidence;
  notes: string[];
}

export interface ObjectPairCaseResult {
  caseId: string;
  objectType: string;
  expectedVisibility: string;
  baselineA: ObjectPairRequestEvidence;
  baselineB: ObjectPairRequestEvidence;
  aToB: ObjectPairRequestEvidence;
  bToA: ObjectPairRequestEvidence;
  confirmedIssues: ObjectPairRequestEvidence[];
  inconclusive: boolean;
  notes: string[];
}

export interface ObjectPairTestingReport {
  enabled: boolean;
  plannedCases: number;
  plannedRequests: number;
  executedRequests: number;
  confirmedIssues: number;
  cases: ObjectPairCaseResult[];
  notes: string[];
}

export type FieldExposurePresenceState =
  | "PRESENT_VALUE"
  | "PRESENT_NULL"
  | "PRESENT_EMPTY_STRING"
  | "PRESENT_REDACTED"
  | "ABSENT"
  | "PATH_PARENT_MISSING"
  | "TYPE_MISMATCH"
  | "INDEX_OUT_OF_BOUNDS"
  | "RESPONSE_NOT_PARSEABLE"
  | "RESPONSE_TOO_LARGE"
  | "OBJECT_MISMATCH"
  | "NOT_EVALUATED";
export type FieldExposureClassification =
  | "FIELD_POLICY_SATISFIED"
  | "UNAUTHORIZED_FIELD_PRESENT"
  | "UNAUTHORIZED_PRIVATE_VALUE_EXPOSED"
  | "EXPECTED_REDACTION_MISSING"
  | "MASKING_POLICY_VIOLATION"
  | "PUBLIC_BASELINE_MISMATCH"
  | "SHARED_BASELINE_MISMATCH"
  | "FIELD_UNEXPECTEDLY_ABSENT"
  | "FIELD_TYPE_MISMATCH"
  | "OBJECT_CONFIRMED"
  | "OBJECT_IDENTITY_UNCONFIRMED"
  | "OBJECT_ACCESS_DENIED"
  | "OBJECT_MISMATCH"
  | "IDENTITY_REQUIREMENT_UNSATISFIED"
  | "PUBLIC_BASELINE_UNAVAILABLE"
  | "RESPONSE_NOT_COMPARABLE"
  | "RESPONSE_TOO_LARGE"
  | "RESPONSE_NOT_PARSEABLE"
  | "RATE_LIMITED"
  | "BUDGET_EXHAUSTED"
  | "TEST_BLOCKED_BY_SAFETY_POLICY"
  | "INCONCLUSIVE"
  | "EXECUTION_ERROR";
export type FieldExposureConfidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";

export interface FieldExposureObservation {
  fieldId: string;
  fieldLabel: string;
  fieldPathRef: string;
  actorId: string;
  actorType: string;
  presence: FieldExposurePresenceState;
  safeType: string;
  length?: number;
  valueFingerprint?: string;
  preview?: string;
  redactionMatched?: boolean;
  classification: FieldExposureClassification;
  confidence: FieldExposureConfidence;
  expectedPolicy: string;
}

export interface FieldExposureActorResult {
  actorId: string;
  actorType: string;
  requestId: string;
  method: "GET" | "HEAD";
  url: string;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  objectConfirmed: boolean;
  objectIdentity: "OBJECT_CONFIRMED" | "OBJECT_IDENTITY_UNCONFIRMED" | "OBJECT_MISMATCH" | "RESPONSE_NOT_COMPARABLE";
  category: FieldExposureClassification;
  observations: FieldExposureObservation[];
  error?: string;
  notes: string[];
}

export interface FieldExposureCaseResult {
  caseId: string;
  objectType: string;
  objectIdHash: string;
  expectedVisibility: string;
  plannedRequests: number;
  executedRequests: number;
  actors: FieldExposureActorResult[];
  confirmedIssues: FieldExposureObservation[];
  inconclusive: boolean;
  notes: string[];
}

export interface FieldExposureTestingReport {
  enabled: boolean;
  plannedCases: number;
  plannedRequests: number;
  executedRequests: number;
  confirmedIssues: number;
  cases: FieldExposureCaseResult[];
  notes: string[];
}

export type AuthorizationMatrixDecisionCategory =
  | "ACCESS_ALLOWED_CONFIRMED"
  | "ACCESS_DENIED_CONFIRMED"
  | "AUTHENTICATION_REQUIRED"
  | "OBJECT_NOT_FOUND"
  | "OBJECT_STATE_MISMATCH"
  | "OBJECT_IDENTITY_MISMATCH"
  | "SOFT_DENIAL"
  | "LOGIN_REDIRECT"
  | "PUBLIC_REPRESENTATION"
  | "RATE_LIMITED"
  | "BUDGET_EXHAUSTED"
  | "IDENTITY_REQUIREMENT_UNSATISFIED"
  | "RESPONSE_TOO_LARGE"
  | "RESPONSE_NOT_PARSEABLE"
  | "TEST_BLOCKED_BY_SAFETY_POLICY"
  | "INCONCLUSIVE"
  | "EXECUTION_ERROR";
export type AuthorizationMatrixExpectedDecision =
  | "MUST_ALLOW"
  | "MUST_DENY"
  | "MUST_REQUIRE_AUTHENTICATION"
  | "MUST_RETURN_NOT_FOUND"
  | "MUST_MATCH_REFERENCE_DECISION"
  | "MUST_NOT_EXCEED_REFERENCE_ACCESS"
  | "OBSERVE_ONLY";
export type AuthorizationMatrixFindingCategory =
  | "VERTICAL_AUTHORIZATION_BYPASS"
  | "CROSS_TENANT_ACCESS_CONFIRMED"
  | "ROLE_RESTRICTION_BYPASS"
  | "ACCOUNT_STATE_RESTRICTION_BYPASS"
  | "OBJECT_STATE_RESTRICTION_BYPASS"
  | "SUSPENDED_PRINCIPAL_ACCESS_CONFIRMED"
  | "DEACTIVATED_PRINCIPAL_ACCESS_CONFIRMED"
  | "UNPUBLISHED_OBJECT_ACCESS_CONFIRMED"
  | "ARCHIVED_OR_DELETED_OBJECT_ACCESS_CONFIRMED";
export type AuthorizationMatrixConfidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";

export interface AuthorizationMatrixCaseResult {
  matrixId: string;
  caseId: string;
  actorId: string;
  actorRelationship: string;
  authSlot?: "account_a" | "account_b";
  referenceCaseId?: string;
  objectType: string;
  objectIdHash: string;
  method: "GET";
  url: string;
  expectedDecision: AuthorizationMatrixExpectedDecision;
  observedDecision: AuthorizationMatrixDecisionCategory;
  matchedExpectation: boolean;
  objectIdentityConfirmed: boolean;
  objectStateConfirmed?: boolean;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  confidence: AuthorizationMatrixConfidence;
  findingCategory?: AuthorizationMatrixFindingCategory;
  error?: string;
  notes: string[];
}

export interface AuthorizationMatrixReport {
  enabled: boolean;
  plannedMatrices: number;
  plannedCases: number;
  plannedRequests: number;
  executedRequests: number;
  confirmedIssues: number;
  cases: AuthorizationMatrixCaseResult[];
  notes: string[];
}

export type EquivalentRouteDecisionCategory =
  | "ACCESS_ALLOWED_CONFIRMED"
  | "ACCESS_DENIED_CONFIRMED"
  | "AUTHENTICATION_REQUIRED"
  | "OBJECT_NOT_FOUND"
  | "PUBLIC_REPRESENTATION"
  | "SOFT_DENIAL"
  | "LOGIN_REDIRECT"
  | "OBJECT_IDENTITY_MISMATCH"
  | "OBJECT_STATE_MISMATCH"
  | "RESPONSE_NOT_PARSEABLE"
  | "RESPONSE_TOO_LARGE"
  | "RATE_LIMITED"
  | "BUDGET_EXHAUSTED"
  | "IDENTITY_REQUIREMENT_UNSATISFIED"
  | "TEST_BLOCKED_BY_SAFETY_POLICY"
  | "INCONCLUSIVE"
  | "EXECUTION_ERROR";
export type EquivalentRouteExpectedDecision =
  | "MUST_ALLOW"
  | "MUST_DENY"
  | "MUST_REQUIRE_AUTHENTICATION"
  | "MUST_RETURN_NOT_FOUND"
  | "MUST_MATCH_CANONICAL_DECISION"
  | "MUST_MATCH_REFERENCE_ROUTE"
  | "MUST_NOT_EXCEED_CANONICAL_ACCESS"
  | "MUST_NOT_EXCEED_PUBLIC_ACCESS"
  | "OBSERVE_ONLY";
export type EquivalentRouteFindingCategory =
  | "LEGACY_ROUTE_AUTHORIZATION_BYPASS"
  | "VERSIONED_ROUTE_AUTHORIZATION_BYPASS"
  | "NESTED_ROUTE_AUTHORIZATION_BYPASS"
  | "EXPORT_ROUTE_AUTHORIZATION_BYPASS"
  | "ALIAS_ROUTE_AUTHORIZATION_BYPASS"
  | "MOBILE_ROUTE_AUTHORIZATION_BYPASS"
  | "ALTERNATE_ROUTE_AUTHORIZATION_BYPASS"
  | "CROSS_TENANT_ROUTE_INCONSISTENCY"
  | "ROLE_BOUNDARY_ROUTE_INCONSISTENCY"
  | "ACCOUNT_STATE_ROUTE_INCONSISTENCY"
  | "OBJECT_STATE_ROUTE_INCONSISTENCY";
export type EquivalentRouteConfidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";

export interface EquivalentRouteObservation {
  routeSetId: string;
  cellId: string;
  actorId: string;
  actorRelationship: string;
  authSlot?: "account_a" | "account_b";
  routeId: string;
  routeLabel: string;
  routeCategory: string;
  isCanonical: boolean;
  canonicalRouteId: string;
  referenceRouteId?: string;
  objectType: string;
  objectIdHash: string;
  method: "GET";
  url: string;
  equivalencePolicy: string;
  expectedDecision: EquivalentRouteExpectedDecision;
  observedDecision: EquivalentRouteDecisionCategory;
  matchedExpectation: boolean;
  objectIdentityConfirmed: boolean;
  objectStateConfirmed?: boolean;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  confidence: EquivalentRouteConfidence;
  findingCategory?: EquivalentRouteFindingCategory;
  comparisonRouteId?: string;
  error?: string;
  notes: string[];
}

export interface EquivalentRouteReport {
  enabled: boolean;
  plannedRouteSets: number;
  plannedRoutes: number;
  plannedRequests: number;
  executedRequests: number;
  confirmedIssues: number;
  observations: EquivalentRouteObservation[];
  notes: string[];
}

export type CollectionMembershipCategory = "FOUND_ONCE" | "FOUND_MULTIPLE_TIMES" | "NOT_FOUND" | "METADATA_MISMATCH" | "NOT_EVALUATED";
export type CollectionAuthorizationDecisionCategory =
  | "MEMBERSHIP_EXPECTATION_SATISFIED"
  | "UNAUTHORIZED_OBJECT_LISTED"
  | "CROSS_TENANT_OBJECT_LISTED"
  | "ROLE_RESTRICTED_OBJECT_LISTED"
  | "ACCOUNT_STATE_RESTRICTED_OBJECT_LISTED"
  | "OBJECT_STATE_RESTRICTED_OBJECT_LISTED"
  | "PUBLIC_COLLECTION_OVEREXPOSURE"
  | "SEARCH_RESULT_OVEREXPOSURE"
  | "COUNT_DISCLOSURE_OBSERVED"
  | "SUMMARY_DISCLOSURE_OBSERVED"
  | "EXPECTED_OBJECT_MISSING"
  | "OBJECT_NOT_FOUND_IN_WINDOW"
  | "OBJECT_METADATA_MISMATCH"
  | "COLLECTION_RESPONSE_INCOMPLETE"
  | "IDENTITY_REQUIREMENT_UNSATISFIED"
  | "RESPONSE_TOO_LARGE"
  | "RESPONSE_NOT_PARSEABLE"
  | "RATE_LIMITED"
  | "BUDGET_EXHAUSTED"
  | "TEST_BLOCKED_BY_SAFETY_POLICY"
  | "INCONCLUSIVE"
  | "EXECUTION_ERROR";
export type CollectionAuthorizationFindingCategory =
  | "UNAUTHORIZED_COLLECTION_MEMBERSHIP"
  | "CROSS_TENANT_COLLECTION_EXPOSURE"
  | "ROLE_RESTRICTED_COLLECTION_EXPOSURE"
  | "SUSPENDED_PRINCIPAL_COLLECTION_ACCESS"
  | "DEACTIVATED_PRINCIPAL_COLLECTION_ACCESS"
  | "DRAFT_OBJECT_LISTING_EXPOSURE"
  | "ARCHIVED_OBJECT_LISTING_EXPOSURE"
  | "DELETED_OBJECT_LISTING_EXPOSURE"
  | "PRIVATE_OBJECT_PUBLIC_LISTING_EXPOSURE"
  | "SEARCH_RESULT_AUTHORIZATION_EXPOSURE"
  | "CONFIRMED_COUNT_DISCLOSURE"
  | "CONFIRMED_SUMMARY_DISCLOSURE";
export type CollectionAuthorizationConfidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";

export interface CollectionAuthorizationObservation {
  collectionId: string;
  collectionLabel: string;
  caseId: string;
  actorId: string;
  actorRelationship: string;
  authSlot?: "account_a" | "account_b";
  referenceCaseId?: string;
  category: string;
  completeness: string;
  objectType?: string;
  objectIdHash?: string;
  method: "GET";
  url: string;
  expectedMembership: string;
  observedMembership: CollectionMembershipCategory;
  observedDecision: CollectionAuthorizationDecisionCategory;
  matchedExpectation: boolean;
  matchedIndex?: number;
  duplicateCount?: number;
  objectMetadataConfirmed?: boolean;
  objectTenantConfirmed?: boolean;
  objectOwnerConfirmed?: boolean;
  objectStateConfirmed?: boolean;
  countObserved?: number;
  countObservedHash?: string;
  summaryObservedHash?: string;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  bodyHash?: string;
  matchedObjectPreview?: string;
  confidence: CollectionAuthorizationConfidence;
  findingCategory?: CollectionAuthorizationFindingCategory;
  error?: string;
  notes: string[];
}

export interface CollectionAuthorizationReport {
  enabled: boolean;
  plannedCollections: number;
  plannedCases: number;
  plannedRequests: number;
  executedRequests: number;
  confirmedIssues: number;
  observations: CollectionAuthorizationObservation[];
  notes: string[];
}

export type BulkAuthorizationDecisionCategory =
  | "BULK_POLICY_SATISFIED"
  | "BULK_ALLOWED_CONFIRMED"
  | "BULK_DENIED_CONFIRMED"
  | "ATOMIC_REJECTION_CONFIRMED"
  | "UNAUTHORIZED_OBJECT_FILTERED"
  | "PER_OBJECT_DECISIONS_CONFIRMED"
  | "UNAUTHORIZED_OBJECT_INCLUDED"
  | "UNAUTHORIZED_OBJECT_METADATA_EXPOSED"
  | "MIXED_OWNERSHIP_POLICY_BYPASS"
  | "CROSS_TENANT_BULK_ACCESS"
  | "ROLE_RESTRICTION_BYPASS"
  | "ACCOUNT_STATE_RESTRICTION_BYPASS"
  | "OBJECT_STATE_RESTRICTION_BYPASS"
  | "SINGLE_OBJECT_BULK_INCONSISTENCY"
  | "REFERENCE_CASE_MISMATCH"
  | "AUTHORIZED_OBJECT_UNEXPECTEDLY_DROPPED"
  | "BATCH_UNEXPECTEDLY_REJECTED"
  | "DRY_RUN_MARKER_MISSING"
  | "NON_MUTATING_CONTRACT_UNCONFIRMED"
  | "NON_MUTATING_CONTRACT_VIOLATED"
  | "ASYNCHRONOUS_OPERATION_DETECTED"
  | "DOWNLOAD_RESPONSE_BLOCKED"
  | "OBJECT_VERIFICATION_UNAVAILABLE"
  | "IDENTITY_REQUIREMENT_UNSATISFIED"
  | "RESPONSE_TOO_LARGE"
  | "RESPONSE_NOT_PARSEABLE"
  | "RATE_LIMITED"
  | "BUDGET_EXHAUSTED"
  | "TEST_BLOCKED_BY_SAFETY_POLICY"
  | "INCONCLUSIVE"
  | "EXECUTION_ERROR";
export type BulkAuthorizationFindingCategory =
  | "BULK_OBJECT_AUTHORIZATION_BYPASS"
  | "MIXED_OWNERSHIP_BULK_BYPASS"
  | "CROSS_TENANT_BULK_AUTHORIZATION_BYPASS"
  | "ROLE_RESTRICTED_BULK_ACCESS"
  | "ACCOUNT_STATE_BULK_RESTRICTION_BYPASS"
  | "OBJECT_STATE_BULK_RESTRICTION_BYPASS"
  | "BULK_SINGLE_OBJECT_AUTHORIZATION_INCONSISTENCY"
  | "BULK_PREVIEW_METADATA_EXPOSURE"
  | "SINGLE_VS_BULK_AUTHORIZATION_INCONSISTENCY"
  | "SENSITIVE_BULK_SUMMARY_EXPOSURE";
export type BulkAuthorizationConfidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";
export type BulkBaselineDecision = "ALLOWED_CONFIRMED" | "DENIED_CONFIRMED" | "AUTHENTICATION_REQUIRED" | "OBJECT_NOT_FOUND" | "OBJECT_IDENTITY_MISMATCH" | "OBJECT_STATE_MISMATCH" | "UNAVAILABLE" | "INCONCLUSIVE";
export type BulkPostconditionStatus = "NOT_APPLICABLE" | "OPERATOR_ATTESTED_NOT_INDEPENDENTLY_VERIFIED" | "VERIFIED_UNCHANGED" | "STATE_CHANGED" | "OBJECT_DISAPPEARED" | "OBJECT_IDENTITY_CHANGED" | "STATE_RESPONSE_UNAVAILABLE" | "STATE_RESPONSE_AMBIGUOUS" | "VERIFICATION_BLOCKED";

export interface BulkObjectObservation {
  objectAlias: string;
  objectIdHash: string;
  expectedDecision: string;
  included: boolean;
  duplicateCount: number;
  metadataExposed: boolean;
  observedDecision?: string;
  baselineDecision?: BulkBaselineDecision;
  baselineCompatible?: boolean;
  findingCategory?: BulkAuthorizationFindingCategory;
}

export interface BulkAuthorizationObservation {
  definitionId: string;
  caseId: string;
  actorId: string;
  actorRelationship: string;
  authSlot?: "account_a" | "account_b";
  operationType: string;
  requestStyle: string;
  method: "GET" | "POST";
  url: string;
  bodyHash?: string;
  expectedBatchPolicy: string;
  postSafetyMode: string;
  postconditionStatus: BulkPostconditionStatus;
  singleObjectComparison: "NOT_CONFIGURED" | "COMPATIBLE_DENIAL" | "COMPATIBLE_ALLOW" | "INCOMPATIBLE" | "UNAVAILABLE";
  observedDecision: BulkAuthorizationDecisionCategory;
  safetyContractSatisfied: boolean;
  matchedSuppliedObjects: number;
  unknownReturnedItemCount: number;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  responseHash?: string;
  confidence: BulkAuthorizationConfidence;
  findingCategory?: BulkAuthorizationFindingCategory;
  objects: BulkObjectObservation[];
  error?: string;
  notes: string[];
}

export interface BulkAuthorizationReport {
  enabled: boolean;
  plannedDefinitions: number;
  plannedCases: number;
  plannedRequests: number;
  executedRequests: number;
  confirmedIssues: number;
  observations: BulkAuthorizationObservation[];
  notes: string[];
}

export type FileAuthorizationDecisionCategory =
  | "METADATA_ACCESS_CONFIRMED"
  | "CONTENT_ACCESS_CONFIRMED"
  | "PREVIEW_ACCESS_CONFIRMED"
  | "SIGNED_URL_EXPOSED"
  | "SIGNED_URL_DOWNLOAD_ALLOWED"
  | "SIGNED_URL_DOWNLOAD_DENIED"
  | "SIGNED_URL_FILE_IDENTITY_MISMATCH"
  | "ACCESS_DENIED_CONFIRMED"
  | "AUTHENTICATION_REQUIRED"
  | "FILE_NOT_FOUND"
  | "FILE_IDENTITY_CONFIRMED"
  | "FILE_IDENTITY_UNCONFIRMED"
  | "FILE_STATE_MISMATCH"
  | "HEADERS_ONLY_OBSERVATION"
  | "CONTENT_LENGTH_EXCEEDS_LIMIT"
  | "STREAM_LIMIT_EXCEEDED"
  | "RANGE_IGNORED_STREAM_ABORTED"
  | "SIGNED_URL_ORIGIN_BLOCKED"
  | "SIGNED_URL_FOLLOW_NOT_CONFIGURED"
  | "SIGNED_URL_FOLLOW_INCONCLUSIVE"
  | "DECLARED_CONTENT_LENGTH_EXCEEDS_LIMIT"
  | "STREAM_TERMINATED_EARLY"
  | "UNKNOWN_LENGTH_BOUNDED"
  | "FULL_STREAM_COMPLETED"
  | "PARTIAL_STREAM_COMPLETED"
  | "INVALID_CONTENT_RANGE"
  | "RANGE_NOT_SATISFIABLE"
  | "RESPONSE_TOO_LARGE"
  | "RESPONSE_NOT_PARSEABLE"
  | "RATE_LIMITED"
  | "BUDGET_EXHAUSTED"
  | "TEST_BLOCKED_BY_SAFETY_POLICY"
  | "IDENTITY_REQUIREMENT_UNSATISFIED"
  | "INCONCLUSIVE"
  | "EXECUTION_ERROR";
export type FileAuthorizationFindingCategory =
  | "UNAUTHORIZED_FILE_METADATA_ACCESS"
  | "UNAUTHORIZED_FILE_CONTENT_ACCESS"
  | "PUBLIC_PRIVATE_FILE_ACCESS"
  | "CROSS_TENANT_FILE_ACCESS"
  | "ROLE_RESTRICTED_FILE_ACCESS"
  | "FILE_STATE_RESTRICTION_BYPASS"
  | "UNAUTHORIZED_SIGNED_URL_ISSUANCE"
  | "UNAUTHORIZED_SIGNED_URL_DOWNLOAD"
  | "PREVIEW_OR_THUMBNAIL_AUTHORIZATION_BYPASS";
export type FileAuthorizationConfidence = "CONFIRMED" | "HIGH" | "MEDIUM" | "LOW" | "INCONCLUSIVE";

export interface FileAuthorizationObservation {
  definitionId: string;
  caseId: string;
  label: string;
  category: string;
  actorId: string;
  actorRelationship: string;
  authSlot?: "account_a" | "account_b";
  fileAlias: string;
  fileRefHash: string;
  method: "GET" | "HEAD";
  url: string;
  expectedDecision: string;
  observedDecision: FileAuthorizationDecisionCategory;
  identityStrategy: string;
  identityConfirmed: boolean;
  contentProofMode: string;
  bytesObserved: number;
  streamTruncated: boolean;
  rangeIgnored: boolean;
  signedUrlObserved: boolean;
  signedUrlFollowed: boolean;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  contentDispositionClass?: string;
  bodyHash?: string;
  findingCategory?: FileAuthorizationFindingCategory;
  confidence: FileAuthorizationConfidence;
  error?: string;
  notes: string[];
}

export interface FileAuthorizationReport {
  enabled: boolean;
  plannedDefinitions: number;
  plannedCases: number;
  plannedRequests: number;
  executedRequests: number;
  confirmedIssues: number;
  observations: FileAuthorizationObservation[];
  notes: string[];
}

export type ParameterLocation = "query" | "path";
export type ParameterKind =
  | "object-id"
  | "uuid"
  | "numeric-id"
  | "slug"
  | "pagination"
  | "search"
  | "filter"
  | "sort"
  | "price"
  | "user-account"
  | "token"
  | "unknown";
export type ParameterRiskTag = "object-id" | "authorization-sensitive" | "business-logic" | "harmless-navigation";

export interface ParameterSignal {
  name: string;
  valuePreview: string;
  location: ParameterLocation;
  kind: ParameterKind;
  riskTags: ParameterRiskTag[];
  confidence: "Low" | "Medium" | "High";
  evidence: string;
}

export interface ParameterizedUrlAnalysis {
  url: string;
  path: string;
  parameters: ParameterSignal[];
  highRisk: boolean;
}

export interface ParameterWorkflowTarget {
  url: string;
  reasons: ParameterRiskTag[];
  suggestedWorkflow: string;
}

export interface ParameterAnalysisReport {
  analyzedUrls: ParameterizedUrlAnalysis[];
  totalParameters: number;
  highRiskParameters: ParameterSignal[];
  riskSummary: {
    objectId: number;
    authorizationSensitive: number;
    businessLogic: number;
    harmlessNavigation: number;
  };
  workflowTargets: ParameterWorkflowTarget[];
  notes: string[];
}

export type NextJsDetectionConfidence = "CONFIRMED" | "HIGH_CONFIDENCE" | "POSSIBLE" | "NOT_DETECTED";
export type NextJsRouterKind = "PAGES_ROUTER" | "APP_ROUTER" | "MIXED" | "UNKNOWN";
export type NextJsSurfaceType =
  | "HTML"
  | "NEXT_DATA"
  | "BUILD_MANIFEST"
  | "SSG_MANIFEST"
  | "ROUTE_MANIFEST"
  | "APP_MANIFEST"
  | "RSC"
  | "FLIGHT"
  | "JS_CHUNK"
  | "CSS_ASSET"
  | "SOURCE_MAP"
  | "RUNTIME_CONFIG"
  | "OTHER_NEXT_METADATA";
export type NextJsParseStatus = "PARSED" | "UNSUPPORTED_SHAPE" | "MALFORMED" | "TOO_LARGE" | "OUT_OF_SCOPE" | "BUDGET_EXHAUSTED" | "REQUEST_FAILED" | "CANCELLED";
export type NextJsObservationCategory =
  | "NEXTJS_DETECTED"
  | "NEXTJS_PAGES_ROUTER_OBSERVED"
  | "NEXTJS_APP_ROUTER_OBSERVED"
  | "NEXTJS_MIXED_ROUTER_OBSERVED"
  | "NEXTJS_BUILD_ID_OBSERVED"
  | "NEXTJS_BUILD_MANIFEST_OBSERVED"
  | "NEXTJS_SSG_MANIFEST_OBSERVED"
  | "NEXTJS_ROUTE_METADATA_OBSERVED"
  | "NEXTJS_DATA_SURFACE_OBSERVED"
  | "NEXTJS_RSC_SURFACE_OBSERVED"
  | "NEXTJS_SOURCE_MAP_OBSERVED"
  | "NEXTJS_SOURCE_MAP_WITH_SOURCES_CONTENT"
  | "NEXTJS_PUBLIC_RUNTIME_CONFIG_OBSERVED"
  | "NEXTJS_CACHE_SIGNAL_OBSERVED"
  | "NEXTJS_UNKNOWN_MANIFEST_SHAPE";

export interface NextJsCacheMetadata {
  cacheControl?: string;
  age?: number;
  etagFingerprint?: string;
  vary: string[];
  expires?: string;
  lastModified?: string;
  nextJsCacheState?: string;
  surrogateControl?: string;
  cdnIndicators: string[];
  actor: "PUBLIC" | "PRIMARY" | "ACCOUNT_A" | "ACCOUNT_B";
  bodyFingerprint?: string;
  dataSensitivity: "NONE" | "SIGNAL" | "SENSITIVE";
}

export interface NextJsSensitivitySignal {
  category: string;
  fieldPath: string;
  valueType: string;
  valueLength: number;
  confidence: "HIGH" | "MEDIUM";
  correlationFingerprint?: string;
}

export interface NextJsSurface {
  surfaceType: NextJsSurfaceType;
  sourceUrl: string;
  normalizedUrl: string;
  routerKind: NextJsRouterKind;
  routeTemplate?: string;
  concreteRoute?: string;
  buildIdFingerprint?: string;
  actor: "PUBLIC" | "PRIMARY" | "ACCOUNT_A" | "ACCOUNT_B";
  contentType?: string;
  status?: number;
  cacheMetadata?: NextJsCacheMetadata;
  source: string;
  retrievalMethod: "OBSERVED_RESPONSE" | "BROWSER_NETWORK" | "BROKER_GET" | "INLINE";
  sensitivitySignals: NextJsSensitivitySignal[];
  evidenceReferences: string[];
  parseStatus: NextJsParseStatus;
}

export interface NextJsObservation {
  category: NextJsObservationCategory;
  summary: string;
  sourceUrl?: string;
  provenance: string;
  parseStatus: NextJsParseStatus;
}

export interface NextJsManifestReview {
  url: string;
  kind: "BUILD_MANIFEST" | "SSG_MANIFEST" | "ROUTE_MANIFEST" | "APP_MANIFEST" | "UNKNOWN";
  parseStatus: NextJsParseStatus;
  routes: string[];
  assets: string[];
  processedEntries: number;
  totalEntries: number;
  truncated: boolean;
  notes: string[];
}

export interface NextJsDataRouteReview {
  url: string;
  statusCode?: number;
  contentType?: string;
  contentLength?: number;
  cacheControl?: string;
  cacheMetadata?: NextJsCacheMetadata;
  parseStatus?: NextJsParseStatus;
  propertyPaths?: string[];
  sensitivitySignals?: NextJsSensitivitySignal[];
  actor?: "PUBLIC" | "PRIMARY" | "ACCOUNT_A" | "ACCOUNT_B";
  routeTemplate?: string;
  concreteRoute?: string;
  responseFingerprint?: string;
  dataIndicators: string[];
  cacheRisk: "normal-public-cache" | "data-needs-review" | "possible-private-data-cache" | "not-reachable";
  notes: string[];
}

export interface NextJsSourceMapReview {
  url: string;
  classification: "nextjs-public-source-map-review" | "generic-source-map-review";
  severityHint: "low" | "medium";
  reason: string;
  parseStatus?: NextJsParseStatus;
  version?: number;
  file?: string;
  sourceCount?: number;
  sourcesContentCount?: number;
  namesCount?: number;
  mappingSize?: number;
  sourcePaths?: string[];
  sensitivitySignals?: NextJsSensitivitySignal[];
  inline?: boolean;
}

export interface NextJsReviewReport {
  detected: boolean;
  detectionConfidence?: NextJsDetectionConfidence;
  detectionEvidence?: string[];
  routerKind?: NextJsRouterKind;
  routerEvidence?: string[];
  buildIds: string[];
  surfaces?: NextJsSurface[];
  observations?: NextJsObservation[];
  manifests?: NextJsManifestReview[];
  dataRoutes: NextJsDataRouteReview[];
  sourceMaps: NextJsSourceMapReview[];
  cacheSignals: string[];
  securityFindingCounts?: Record<string, number>;
  coverage?: {
    moduleState: "EXECUTED" | "SKIPPED_NOT_DETECTED";
    sourceMapReview: "DISABLED" | "EXECUTED" | "BUDGET_EXHAUSTED" | "NO_REFERENCES";
    dataSurfaceReview: "EXECUTED" | "BUDGET_EXHAUSTED" | "NO_CONCRETE_ROUTES";
    cacheDifferential: "DISABLED" | "EXECUTED" | "NOT_CONFIGURED" | "BUDGET_EXHAUSTED";
    processedRoutes: number;
    availableRoutes: number;
    truncated: boolean;
    limitations: string[];
  };
  requestBudget?: {
    manifest: { used: number; limit: number };
    dataSurface: { used: number; limit: number };
    sourceMap: { used: number; limit: number };
    cacheDifferential: { used: number; limit: number };
    other: { used: number; limit: number };
    maximumAdditionalRequests: number;
  };
  notes: string[];
}

export interface BrowserNetworkRequest {
  url: string;
  method: string;
  resourceType: string;
  decision?: "allowed" | "blocked";
  reason?: string;
  depth?: number;
  transmitted?: boolean;
}

export interface BrowserPolicyEvent {
  url: string;
  method?: string;
  resourceType?: string;
  pageUrl?: string;
  depth?: number;
  reason: string;
  transmitted: boolean;
}

export interface BrowserConsoleError {
  type: string;
  text: string;
  location?: string;
}

export interface BrowserStorageObservation {
  origin: string;
  storage: "cookie" | "localStorage" | "sessionStorage";
  name: string;
  valueLength: number;
  valueDigest: string;
  classification: "authentication" | "csrf" | "preference" | "application";
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
  secretBoundary?: SecretClassification;
}

export interface BrowserFieldObservation {
  pageUrl: string;
  name: string;
  controlType: string;
  access: "writable" | "read-only" | "disabled";
}

export interface BrowserTrafficEntry {
  startedAt: string;
  pageUrl: string;
  url: string;
  method: string;
  resourceType: string;
  requestHeaderNames: string[];
  requestFieldNames: string[];
  requestBodyFormat?: "JSON" | "FORM";
  requestSecretBindings?: Record<string, string>;
  transmitted: boolean;
  authorizationContext: "EXPLICIT_LOGIN" | "READ_ONLY" | "BLOCKED_MUTATION_HYPOTHESIS";
  blockedReason?: string;
  responseStatus?: number;
  responseContentType?: string;
  responseHeaderNames?: string[];
  responseBodyBytes?: number;
  responseCookieNames?: string[];
  redactionApplied: true;
}

export interface BrowserLearnedTestCase {
  id: string;
  source: "browser-learned-traffic";
  method: string;
  endpoint: string;
  observedFieldNames: string[];
  requestBodyFormat?: "JSON" | "FORM";
  requestSecretBindings: Record<string, string>;
  observedStatusCodes: number[];
  responseCookieNames: string[];
  authorizationContext: BrowserTrafficEntry["authorizationContext"];
  transmitted: boolean;
  suggestedLifecycleCategories: string[];
  classification: "READ_ONLY_OBSERVATION" | "MUTATION_HYPOTHESIS";
  state: "DRAFT_REQUIRES_OPERATOR_CASE";
  executable: false;
  operatorApprovalRequired: boolean;
}

export interface BrowserLifecycleLearningBundleSummary {
  schemaVersion: 1;
  artifactPath: string;
  candidateCount: number;
  loginCandidateCount: number;
  mutationHypothesisCount: number;
  automaticallyCompilableCategories: string[];
  secretsStored: false;
}

export interface BrowserIdentityCorrelation {
  principal: "MATCHED" | "MISMATCH" | "NOT_CONFIGURED";
  tenant: "MATCHED" | "MISMATCH" | "NOT_CONFIGURED";
  role: "MATCHED" | "MISMATCH" | "NOT_CONFIGURED";
  rawIdentityStored: false;
}

export interface BrowserAuthenticationReport {
  mode: "header-cookie-bootstrap" | "learned-login-flow";
  bootstrapSucceeded: boolean;
  sessionIsolated: true;
  sessionSecretsPersisted: false;
  loginStepsExecuted: number;
  loginWriteRequestsAllowed: number;
  loginWriteRequestsBlocked: number;
  browserRestartCount: number;
  redactedHarPath?: string;
  storage: BrowserStorageObservation[];
  fields: BrowserFieldObservation[];
  adminRoutes: string[];
  learnedTestCases: BrowserLearnedTestCase[];
  lifecycleLearningBundle: BrowserLifecycleLearningBundleSummary;
  identityCorrelation: BrowserIdentityCorrelation;
  protectedActionProof: "REQUIRES_APPROVED_OPERATOR_CASE" | "BOUND_TO_APPROVED_CASE_ONLY";
  rollbackVerification: "REQUIRES_APPROVED_OPERATOR_CASE" | "BOUND_TO_APPROVED_CASE_ONLY";
}

export interface BrowserCrawlReport {
  startUrl: string;
  renderedLinks: PathCandidate[];
  networkRequests: BrowserNetworkRequest[];
  policyEvents?: BrowserPolicyEvent[];
  policyEventCount?: number;
  transmittedRequestCount?: number;
  blockedRequestCount?: number;
  visitedPages?: Array<{ url: string; depth: number }>;
  consoleErrors: BrowserConsoleError[];
  screenshotPath?: string;
  formsDetected: number;
  formsSubmitted: number;
  authentication?: BrowserAuthenticationReport;
  notes: string[];
}

export type VulnerabilityWorkflowCategory = "idor-bola" | "auth-session" | "rate-limit" | "graphql" | "nextjs-data";
export type WorkflowPriority = "low" | "medium" | "high";

export interface VulnerabilityWorkflow {
  category: VulnerabilityWorkflowCategory;
  title: string;
  target: string;
  priority: WorkflowPriority;
  confidence: "Low" | "Medium" | "High";
  evidence: string[];
  relatedEndpoints: string[];
  safeTestPlan: string[];
  avoidActions: string[];
}

export interface VulnerabilityWorkflowReport {
  workflows: VulnerabilityWorkflow[];
  notes: string[];
}

export type WorkflowEvidenceTemplateKind = "idor-bola" | "auth-bypass" | "rate-limit" | "graphql" | "export-download" | "price-filter";

export interface WorkflowEvidenceTemplate {
  kind: WorkflowEvidenceTemplateKind;
  title: string;
  priority: WorkflowPriority;
  target: string;
  relatedEndpoints: string[];
  preconditions: string[];
  steps: string[];
  expectedSecureBehavior: string[];
  evidenceToCapture: string[];
  avoidActions: string[];
  needsManualVerification: true;
}

export interface WorkflowValidationReport {
  templates: WorkflowEvidenceTemplate[];
  notes: string[];
}

export interface ProofModeResponseSummary {
  statusCode?: number;
  finalUrl: string;
  contentType?: string;
  contentLength?: number;
  title?: string;
  bodyHash?: string;
  responseTimeMs: number;
  redirectChain: Array<{ statusCode: number; location: string }>;
  error?: string;
}

export interface ProofModeComparison {
  label: "anonymous" | "authenticated" | "account-a" | "account-b";
  request: {
    method: "GET";
    url: string;
    curlCommand: string;
    authMaterialRedacted: boolean;
  };
  response: ProofModeResponseSummary;
}

export interface ProofModeBlock {
  id: string;
  source: "finding" | "endpoint";
  title: string;
  target: string;
  severity: string;
  severityReason: string;
  whySelected: string[];
  comparisons: ProofModeComparison[];
  stableEvidence: string[];
  bountySubmissionSummary: string;
  needsManualVerification: true;
}

export interface ProofModeReport {
  enabled: boolean;
  retestedTargets: number;
  blocks: ProofModeBlock[];
  notes: string[];
}

export interface ScanReportMetadata {
  startedAt: string;
  completedAt: string;
  durationMs: number;
  totalRequests: number;
  failedRequests: number;
}

export interface RouteCairnReport {
  execution?: {
    status: "RUNNING" | "COMPLETED" | "CANCELLED" | "FAILED" | "INTERRUPTED";
    partial: boolean;
    reason: string;
    checkpointAt: string;
    cleanup: {
      state: "CLEAR" | "REQUIRED" | "UNKNOWN";
      cases: Array<{ caseId: string; stage: string; recoveryBundleAvailable: boolean }>;
    };
  };
  assistedReview?: import("./AssistedReviewReport.js").AssistedReviewReport;
  routeCairnVersion: string;
  target: string;
  mode: ScanMode;
  profile?: ScanProfileSummary;
  scanPlan: ResolvedScanPlan;
  program: string;
  scope: Pick<
    RouteCairnScope,
    | "allowedDomains"
    | "disallowedPaths"
    | "allowedMethods"
    | "rateLimitPerSecond"
    | "concurrency"
    | "sameOriginOnly"
    | "includeSubdomains"
  >;
  metadata: ScanReportMetadata;
  requestBudget?: import("../core/http/ScanRequestLedger.js").ScanRequestLedgerSnapshot;
  baseline?: BaselineReport;
  scopeDecisions: ScopeDecision[];
  requestAudit: RequestAuditEntry[];
  responses: HttpResponse[];
  technologies: DetectedTechnology[];
  jsIntelligence?: JsIntelligenceReport;
  browserCrawl?: BrowserCrawlReport;
  apiMapper?: ApiMapperReport;
  apiProbe?: ApiProbeReport;
  authSurface?: AuthSurfaceReport;
  authenticatedScan?: AuthenticatedScanReport;
  roleComparison?: RoleComparisonReport;
  stateAwareApi?: StateAwareApiReport;
  identityVerification?: IdentityVerificationReport;
  objectPairTesting?: ObjectPairTestingReport;
  fieldExposureTesting?: FieldExposureTestingReport;
  authorizationMatrix?: AuthorizationMatrixReport;
  collectionAuthorization?: CollectionAuthorizationReport;
  bulkAuthorization?: BulkAuthorizationReport;
  fileAuthorization?: FileAuthorizationReport;
  equivalentRouteTesting?: EquivalentRouteReport;
  parameterAnalysis?: ParameterAnalysisReport;
  nextJsReview?: NextJsReviewReport;
  vulnerabilityWorkflows?: VulnerabilityWorkflowReport;
  workflowValidation?: WorkflowValidationReport;
  proofMode?: ProofModeReport;
  privilegeMutation?: PrivilegeMutationReport;
  supabaseAuthorization?: import("./SupabaseAuthorizationReport.js").SupabaseAuthorizationReport;
  authenticationLifecycle?: import("./AuthenticationLifecycleReport.js").AuthenticationLifecycleReport;
  businessInvariant?: import("./BusinessInvariantReport.js").BusinessInvariantReport;
  controlledRace?: import("./ControlledRaceReport.js").ControlledRaceReport;
  apiGraphql?: import("./ApiGraphqlReport.js").ApiGraphqlReviewReport;
  linkPortalSecurity?: import("./LinkPortalSecurityReport.js").LinkPortalSecurityReport;
  operationalEndpointSecurity?: import("./OperationalEndpointSecurityReport.js").OperationalEndpointSecurityReport;
  billingEntitlement?: import("./BillingEntitlementReport.js").BillingEntitlementReport;
  secretBoundary?: import("./SecretBoundaryReport.js").SecretBoundaryReport;
  discoveredUrls: ResponseObservation[];
  findings: Finding[];
}
