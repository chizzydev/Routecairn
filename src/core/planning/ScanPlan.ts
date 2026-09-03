import type { RouteCairnConfig, RouteCairnScope, ScanMode } from "../../config/ConfigSchema.js";
import type { ScanProfileName } from "../../config/ScanProfiles.js";
import type { AuthProfile } from "../auth/AuthProfile.js";
import type { AuthProfileSet } from "../auth/AuthProfileSet.js";
import type { HttpMethod, RetryPolicyOptions } from "../http/HttpTypes.js";
import type { PluginPhase } from "../plugins/Plugin.js";
import type { PathSource } from "../../modules/pathDiscovery/PathSources.js";

export const scanPlanSchemaVersion = 1;

export type ModuleId =
  | "baseline"
  | "tech-fingerprint"
  | "js-intelligence"
  | "browser-crawler"
  | "path-discovery"
  | "api-mapper"
  | "api-probe"
  | "auth-surface"
  | "parameter-analysis"
  | "nextjs-review"
  | "vulnerability-workflows"
  | "workflow-validation"
  | "authenticated-testing"
  | "role-comparison"
  | "state-aware-api"
  | "object-pair-testing"
  | "field-exposure-testing"
  | "authorization-matrix-testing"
  | "collection-authorization-testing"
  | "bulk-authorization-testing"
  | "file-authorization-testing"
  | "privilege-mutation-testing"
  | "supabase-authorization"
  | "authentication-lifecycle"
  | "business-invariant"
  | "controlled-race"
  | "api-graphql-authorization"
  | "link-portal-export-security"
  | "operational-endpoint-security"
  | "billing-entitlement-security"
  | "secret-boundary"
  | "assisted-review"
  | "equivalent-route-testing"
  | "header-review"
  | "cookie-review"
  | "cors-review"
  | "method-review"
  | "exposure-review"
  | "proof-mode";

export type ModuleCapability =
  | "assisted-review"
  | "baseline"
  | "fingerprint"
  | "javascript"
  | "browser"
  | "discovery"
  | "api"
  | "auth-surface"
  | "auth-comparison"
  | "role-comparison"
  | "state-aware-api"
  | "object-pair"
  | "field-exposure"
  | "authorization-matrix"
  | "collection-authorization"
  | "bulk-authorization"
  | "file-authorization"
  | "controlled-mutation"
  | "supabase-authorization"
  | "authentication-lifecycle"
  | "business-invariant"
  | "controlled-race"
  | "api-graphql-authorization"
  | "link-portal-export-security"
  | "operational-endpoint-security"
  | "billing-entitlement-security"
  | "secret-boundary"
  | "equivalent-route"
  | "headers"
  | "cookies"
  | "cors"
  | "methods"
  | "exposure"
  | "nextjs"
  | "workflow"
  | "proof";

export type ModuleCost = "low" | "medium" | "high";
export type ModuleReadiness = "production" | "experimental";
export type AuthenticationLevel = "none" | "single-profile" | "account-pair";
export type EvidenceLevel = "minimal" | "normal" | "strong";
export type FailurePolicy = "fail-fast" | "continue-on-module-error";
export type BrowserResourceType =
  | "document"
  | "stylesheet"
  | "image"
  | "media"
  | "font"
  | "script"
  | "texttrack"
  | "xhr"
  | "fetch"
  | "eventsource"
  | "websocket"
  | "manifest"
  | "other";

export interface ScanLimits {
  maxDepth: number;
  rateLimitPerSecond: number;
  concurrency: number;
  requestTimeoutMs: number;
  bodyPreviewBytes: number;
  maxResponseBytes: number;
  /** Total physical network transmissions across every broker, including cleanup. */
  maxRequests: number;
  /** Capacity withheld from ordinary scan traffic and available only to cleanup/restoration. */
  cleanupReservedRequests: number;
  maxScanDurationMs: number;
  retry: RetryPolicyOptions;
}

export interface AuthenticationRequirements {
  required: boolean;
  level: AuthenticationLevel;
  requireSingleProfile: boolean;
  requireAccountPair: boolean;
}

export interface AuthenticationAvailability {
  hasSingleProfile: boolean;
  hasAccountPair: boolean;
}

export interface EvidencePolicy {
  level: EvidenceLevel;
  collectRequestAudit: boolean;
  collectBodyPreview: boolean;
  requireReproducibleEvidence: boolean;
  retainProofBlocks: boolean;
}

export interface OutputExpectations {
  json: true;
  markdown: true;
  html: true;
  stableForDiff: boolean;
  includePlan: boolean;
  includeRequestAudit: boolean;
}

export type ObjectPairPrincipalLabel = "account_a" | "account_b";
export type ObjectPairMatrixPurpose = "owner-baseline" | "cross-account";
export type ObjectPairDirection = "A_TO_A" | "B_TO_B" | "A_TO_B" | "B_TO_A";
export type ObjectVisibilityExpectation = "PRIVATE_TO_OWNER" | "SHARED_WITH_SPECIFIC_PRINCIPALS" | "TENANT_VISIBLE" | "ROLE_VISIBLE" | "PUBLIC" | "UNKNOWN_REQUIRES_REVIEW";

export interface ObjectPairPrincipalPlan {
  label: ObjectPairPrincipalLabel;
  redactedLabel: string;
  principalIdHash: string;
  tenantIdHash?: string;
  expectedAccountId?: string;
  tenantId?: string;
  role?: string;
}

export interface ObjectOwnershipAssertionPlan {
  objectId: string;
  objectIdHash: string;
  objectType: string;
  owner: ObjectPairPrincipalLabel;
  expectedVisibility: ObjectVisibilityExpectation;
  confirmedSafeToTest: true;
  readOnly: true;
  source: string;
  expectedObjectIdField?: string;
  expectedOwnerField?: string;
  expectedOwnerValue?: string;
  expectedTenantField?: string;
  expectedTenantValue?: string;
  expectedObjectIdHeader?: string;
  expectedOwnerHeader?: string;
  expectedPrivateHeaders: readonly string[];
  expectedSafeMarkers: readonly string[];
  expectedPrivateFields: readonly string[];
}

export interface ObjectAccessTemplatePlan {
  id: string;
  method: "GET" | "HEAD";
  urlTemplate: string;
  headers: Readonly<Record<string, string>>;
}

export interface ObjectPairRequestPlan {
  id: string;
  caseId: string;
  direction: ObjectPairDirection;
  purpose: ObjectPairMatrixPurpose;
  requestingPrincipal: ObjectPairPrincipalLabel;
  targetOwner: ObjectPairPrincipalLabel;
  targetObjectId: string;
  targetObjectIdHash: string;
  objectType: string;
  expectedVisibility: ObjectVisibilityExpectation;
  method: "GET" | "HEAD";
  url: string;
}

export interface ObjectPairCasePlan {
  id: string;
  objectType: string;
  template: ObjectAccessTemplatePlan;
  accountAObject: ObjectOwnershipAssertionPlan;
  accountBObject: ObjectOwnershipAssertionPlan;
  requestMatrix: readonly ObjectPairRequestPlan[];
}

export interface ObjectPairTestingPlan {
  schemaVersion: 1;
  enabled: true;
  principals: readonly ObjectPairPrincipalPlan[];
  cases: readonly ObjectPairCasePlan[];
  requestMatrix: readonly ObjectPairRequestPlan[];
  maxPairs: number;
  maxRequests: number;
  notes: readonly string[];
}

export type FieldExposureActorType =
  | "OWNER"
  | "NON_OWNER"
  | "SECONDARY_NON_OWNER"
  | "SHARED_PRINCIPAL"
  | "LOWER_PRIVILEGED_ROLE"
  | "HIGHER_PRIVILEGED_ROLE"
  | "SAME_TENANT_MEMBER"
  | "CROSS_TENANT_MEMBER"
  | "PUBLIC";
export type FieldExposureAuthSlot = "account_a" | "account_b";
export type FieldExposureExpectationType =
  | "MUST_BE_ABSENT"
  | "MUST_BE_NULL"
  | "MUST_BE_REDACTED"
  | "MUST_DIFFER_FROM_OWNER"
  | "MUST_MATCH_PUBLIC_BASELINE"
  | "MUST_MATCH_SHARED_BASELINE"
  | "MAY_BE_PRESENT"
  | "MUST_BE_PRESENT"
  | "MASKED_VALUE"
  | "OWNER_ONLY_VALUE";
export type FieldExposureSensitivity = "PUBLIC" | "PRIVATE" | "OWNER_ONLY" | "TENANT" | "ROLE" | "INTERNAL";
export type FieldExposureVisibilityExpectation =
  | "OWNER_ONLY"
  | "PUBLIC_SUMMARY"
  | "PUBLIC_FULL"
  | "SHARED_WITH_SPECIFIC_PRINCIPALS"
  | "TENANT_VISIBLE"
  | "ROLE_VISIBLE"
  | "AUTHENTICATED_USERS"
  | "UNKNOWN_REQUIRES_REVIEW";

export interface FieldExposureActorPlan {
  id: string;
  type: FieldExposureActorType;
  redactedLabel: string;
  authSlot?: FieldExposureAuthSlot;
  principalIdHash?: string;
  tenantIdHash?: string;
  roleHash?: string;
}

export interface FieldExposureTemplatePlan {
  id: string;
  method: "GET" | "HEAD";
  urlTemplate: string;
  headers: Readonly<Record<string, string>>;
}

export interface FieldExposureObjectConfirmationPlan {
  expectedObjectIdField: string;
  expectedObjectIdHash: string;
  expectedOwnerField?: string;
  expectedOwnerHash?: string;
  expectedTenantField?: string;
  expectedTenantHash?: string;
}

export interface FieldExposureExpectationPlan {
  id: string;
  path: string;
  label: string;
  sensitivity: FieldExposureSensitivity;
  expectation: FieldExposureExpectationType;
  allowedActors: readonly string[];
  prohibitedActors: readonly string[];
  redactionPattern?: string;
  allowPreview: boolean;
  maxLength?: number;
}

export interface FieldExposureRequestPlan {
  id: string;
  caseId: string;
  actorId: string;
  actorType: FieldExposureActorType;
  authSlot?: FieldExposureAuthSlot;
  purpose: "owner-baseline" | "public-baseline" | "shared-baseline" | "actor-baseline";
  method: "GET" | "HEAD";
  url: string;
  objectIdHash: string;
}

export interface FieldExposureCasePlan {
  id: string;
  objectType: string;
  objectId: string;
  objectIdHash: string;
  ownerActorId: string;
  expectedVisibility: FieldExposureVisibilityExpectation;
  template: FieldExposureTemplatePlan;
  actors: readonly FieldExposureActorPlan[];
  objectConfirmation: FieldExposureObjectConfirmationPlan;
  fieldExpectations: readonly FieldExposureExpectationPlan[];
  requestMatrix: readonly FieldExposureRequestPlan[];
  requireVerifiedIdentity: boolean;
}

export interface FieldExposureTestingPlan {
  schemaVersion: 1;
  enabled: true;
  cases: readonly FieldExposureCasePlan[];
  requestMatrix: readonly FieldExposureRequestPlan[];
  maxCases: number;
  maxFieldsPerCase: number;
  maxRequests: number;
  maxResponseBytes: number;
  maxPreviewLength: number;
  notes: readonly string[];
}

export type AuthorizationMatrixAuthSlot = "account_a" | "account_b";
export type AuthorizationMatrixRelationship =
  | "OWNER"
  | "NON_OWNER"
  | "SAME_TENANT_MEMBER"
  | "SAME_TENANT_ADMIN"
  | "CROSS_TENANT_MEMBER"
  | "CROSS_TENANT_ADMIN"
  | "PLATFORM_ADMIN"
  | "MODERATOR"
  | "SHARED_PRINCIPAL"
  | "PUBLIC"
  | "CUSTOM_DECLARED_RELATIONSHIP";
export type ExpectedAuthorizationDecision =
  | "MUST_ALLOW"
  | "MUST_DENY"
  | "MUST_REQUIRE_AUTHENTICATION"
  | "MUST_RETURN_NOT_FOUND"
  | "MUST_MATCH_REFERENCE_DECISION"
  | "MUST_NOT_EXCEED_REFERENCE_ACCESS"
  | "OBSERVE_ONLY";

export interface AuthorizationMatrixActorPlan {
  id: string;
  relationship: AuthorizationMatrixRelationship;
  redactedLabel: string;
  authSlot?: AuthorizationMatrixAuthSlot;
  principalIdHash?: string;
  tenantIdHash?: string;
  roleHash?: string;
  accountStateHash?: string;
}

export interface AuthorizationMatrixTemplatePlan {
  id: string;
  method: "GET";
  urlTemplate: string;
  headers: Readonly<Record<string, string>>;
}

export interface AuthorizationMatrixCasePlan {
  id: string;
  matrixId: string;
  actorId: string;
  relationship: AuthorizationMatrixRelationship;
  authSlot?: AuthorizationMatrixAuthSlot;
  objectId: string;
  objectIdHash: string;
  expectedObjectState?: string;
  expectedObjectStateHash?: string;
  expectedDecision: ExpectedAuthorizationDecision;
  referenceCaseId?: string;
  requireVerifiedIdentity: boolean;
  expectedTenantHash?: string;
  expectedRoleHash?: string;
  expectedAccountStateHash?: string;
  url: string;
}

export interface AuthorizationMatrixPlan {
  id: string;
  name: string;
  objectType: string;
  template: AuthorizationMatrixTemplatePlan;
  objectIdentityField: string;
  objectStateField?: string;
  actors: readonly AuthorizationMatrixActorPlan[];
  cases: readonly AuthorizationMatrixCasePlan[];
}

export interface AuthorizationMatrixTestingPlan {
  schemaVersion: 1;
  enabled: true;
  matrices: readonly AuthorizationMatrixPlan[];
  requestMatrix: readonly AuthorizationMatrixCasePlan[];
  maxMatrices: number;
  maxCasesPerMatrix: number;
  maxRequests: number;
  maxResponseBytes: number;
  maxPreviewLength: number;
  notes: readonly string[];
}

export type EquivalentRouteAuthSlot = "account_a" | "account_b";
export type EquivalentRouteCategory =
  | "CANONICAL"
  | "LEGACY"
  | "VERSIONED"
  | "NESTED"
  | "TOP_LEVEL"
  | "EXPORT"
  | "SUMMARY"
  | "DETAIL"
  | "MOBILE"
  | "WEB"
  | "ALIAS"
  | "COMPATIBILITY"
  | "RELATIONSHIP"
  | "ALTERNATE_FORMAT"
  | "CUSTOM_DECLARED";
export type EquivalentRouteRelationship =
  | "OWNER"
  | "NON_OWNER"
  | "SAME_TENANT_MEMBER"
  | "SAME_TENANT_ADMIN"
  | "CROSS_TENANT_MEMBER"
  | "CROSS_TENANT_ADMIN"
  | "ADMINISTRATOR"
  | "MODERATOR"
  | "SUSPENDED"
  | "ACTIVE"
  | "SHARED_PRINCIPAL"
  | "PUBLIC"
  | "CUSTOM_DECLARED_RELATIONSHIP";
export type RouteEquivalencePolicy =
  | "AUTHORIZATION_ONLY"
  | "SAME_OBJECT"
  | "SAME_PUBLIC_BOUNDARY"
  | "SAME_OWNER_BOUNDARY"
  | "SAME_TENANT_BOUNDARY"
  | "SAME_ROLE_BOUNDARY"
  | "SAME_STATE_BOUNDARY"
  | "MUST_NOT_EXCEED_REFERENCE_ROUTE";
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

export interface EquivalentRouteActorPlan {
  id: string;
  relationship: EquivalentRouteRelationship;
  redactedLabel: string;
  authSlot?: EquivalentRouteAuthSlot;
  principalIdHash?: string;
  tenantIdHash?: string;
  roleHash?: string;
  accountStateHash?: string;
}

export interface EquivalentRouteTemplatePlan {
  id: string;
  method: "GET";
  urlTemplate: string;
  headers: Readonly<Record<string, string>>;
}

export interface EquivalentRouteDefinitionPlan {
  id: string;
  label: string;
  category: EquivalentRouteCategory;
  isCanonical: boolean;
  deprecated: boolean;
  expectedPublic: boolean;
  template: EquivalentRouteTemplatePlan;
  objectIdentityField?: string;
  responseEnvelopePath?: string;
  objectStateField?: string;
  expectedContentType: string;
  representationType: string;
  equivalencePolicy: RouteEquivalencePolicy;
  referenceRouteId?: string;
}

export interface EquivalentRouteCellPlan {
  id: string;
  routeSetId: string;
  actorId: string;
  actorRelationship: EquivalentRouteRelationship;
  authSlot?: EquivalentRouteAuthSlot;
  routeId: string;
  routeLabel: string;
  routeCategory: EquivalentRouteCategory;
  isCanonical: boolean;
  referenceRouteId?: string;
  canonicalRouteId: string;
  objectType: string;
  objectId: string;
  objectIdHash: string;
  expectedObjectState?: string;
  expectedObjectStateHash?: string;
  expectedDecision: EquivalentRouteExpectedDecision;
  equivalencePolicy: RouteEquivalencePolicy;
  requireVerifiedIdentity: boolean;
  expectedTenantHash?: string;
  expectedRoleHash?: string;
  expectedAccountStateHash?: string;
  objectIdentityField: string;
  responseEnvelopePath?: string;
  objectStateField?: string;
  expectedContentType: string;
  representationType: string;
  url: string;
}

export interface EquivalentRouteSetPlan {
  id: string;
  name: string;
  objectType: string;
  objectId: string;
  objectIdHash: string;
  canonicalRouteId: string;
  objectIdentityField: string;
  objectStateField?: string;
  expectedObjectState?: string;
  expectedObjectStateHash?: string;
  equivalencePolicy: RouteEquivalencePolicy;
  actors: readonly EquivalentRouteActorPlan[];
  routes: readonly EquivalentRouteDefinitionPlan[];
  cells: readonly EquivalentRouteCellPlan[];
}

export interface EquivalentRouteTestingPlan {
  schemaVersion: 1;
  enabled: true;
  routeSets: readonly EquivalentRouteSetPlan[];
  requestMatrix: readonly EquivalentRouteCellPlan[];
  maxRouteSets: number;
  maxRoutesPerSet: number;
  maxActorsPerSet: number;
  maxCells: number;
  maxRequests: number;
  maxResponseBytes: number;
  maxPreviewLength: number;
  notes: readonly string[];
}

export type CollectionAuthorizationAuthSlot = "account_a" | "account_b";
export type CollectionActorRelationship =
  | "OWNER"
  | "NON_OWNER"
  | "SAME_TENANT_MEMBER"
  | "SAME_TENANT_ADMIN"
  | "CROSS_TENANT_MEMBER"
  | "CROSS_TENANT_ADMIN"
  | "PLATFORM_ADMIN"
  | "MODERATOR"
  | "SHARED_PRINCIPAL"
  | "ACTIVE_ACCOUNT"
  | "SUSPENDED_ACCOUNT"
  | "DEACTIVATED_ACCOUNT"
  | "PUBLIC"
  | "CUSTOM_DECLARED_RELATIONSHIP";
export type CollectionEndpointCategory = "LIST" | "SEARCH" | "COUNT" | "SUMMARY" | "DASHBOARD" | "RECENT" | "ARCHIVE" | "ADMIN_LIST" | "TENANT_LIST" | "PUBLIC_LIST" | "CUSTOM_DECLARED";
export type CollectionCompletenessPolicy = "COMPLETE_COLLECTION" | "FIXED_RESULT_WINDOW" | "SEARCH_RESULT_SET" | "SUMMARY_ONLY" | "UNKNOWN_COMPLETENESS";
export type CollectionMembershipExpectation =
  | "MUST_CONTAIN"
  | "MUST_NOT_CONTAIN"
  | "MAY_CONTAIN"
  | "MUST_MATCH_PUBLIC_MEMBERSHIP"
  | "MUST_MATCH_REFERENCE_CASE"
  | "MUST_NOT_EXCEED_REFERENCE_MEMBERSHIP"
  | "OBSERVE_ONLY";
export type CollectionCountExpectationType = "MUST_EQUAL" | "MUST_MATCH_REFERENCE" | "MUST_NOT_EXCEED_REFERENCE" | "MUST_BE_ZERO" | "MAY_DIFFER" | "OBSERVE_ONLY";
export type CollectionSummaryExpectationType = "MUST_EQUAL" | "MUST_MATCH_REFERENCE" | "MUST_NOT_EXCEED_REFERENCE" | "MUST_BE_ZERO" | "MAY_DIFFER" | "OBSERVE_ONLY";

export interface CollectionActorPlan {
  id: string;
  relationship: CollectionActorRelationship;
  redactedLabel: string;
  authSlot?: CollectionAuthorizationAuthSlot;
  principalIdHash?: string;
  tenantIdHash?: string;
  roleHash?: string;
  accountStateHash?: string;
}

export interface KnownCollectionObjectPlan {
  id: string;
  objectId: string;
  objectIdHash: string;
  objectType: string;
  ownerActorId?: string;
  tenantIdHash?: string;
  state?: string;
  stateHash?: string;
  redactedLabel: string;
  expectedPublic: boolean;
  expectedShared: boolean;
  confirmedSafeToTest: true;
}

export interface CollectionCountExpectationPlan {
  path: string;
  expectation: CollectionCountExpectationType;
  expectedCount?: number;
  referenceCaseId?: string;
  securitySensitive: boolean;
  volatile: boolean;
}

export interface CollectionSummaryExpectationPlan {
  path: string;
  expectation: CollectionSummaryExpectationType;
  expectedValue?: string | number | boolean | null;
  referenceCaseId?: string;
  securitySensitive: boolean;
  volatile: boolean;
}

export interface CollectionAuthorizationCasePlan {
  id: string;
  collectionId: string;
  actorId: string;
  actorRelationship: CollectionActorRelationship;
  authSlot?: CollectionAuthorizationAuthSlot;
  knownObjectId?: string;
  objectId?: string;
  objectIdHash?: string;
  objectType?: string;
  expectedMembership: CollectionMembershipExpectation;
  requireVerifiedIdentity: boolean;
  referenceCaseId?: string;
  expectedTenantHash?: string;
  expectedRoleHash?: string;
  expectedAccountStateHash?: string;
  expectedObjectState?: string;
  expectedObjectStateHash?: string;
  countExpectation?: CollectionCountExpectationPlan;
  summaryExpectations: readonly CollectionSummaryExpectationPlan[];
  url: string;
}

export interface CollectionAuthorizationDefinitionPlan {
  id: string;
  label: string;
  category: CollectionEndpointCategory;
  method: "GET";
  url: string;
  headers: Readonly<Record<string, string>>;
  expectedContentType: string;
  completeness: CollectionCompletenessPolicy;
  resultArrayPath?: string;
  objectIdPath?: string;
  objectTenantPath?: string;
  objectOwnerPath?: string;
  objectStatePath?: string;
  objectTypePath?: string;
  maxInspectedEntries: number;
  maxResponseBytes: number;
  maxJsonDepth: number;
  actors: readonly CollectionActorPlan[];
  knownObjects: readonly KnownCollectionObjectPlan[];
  cases: readonly CollectionAuthorizationCasePlan[];
}

export interface CollectionAuthorizationTestingPlan {
  schemaVersion: 1;
  enabled: true;
  collections: readonly CollectionAuthorizationDefinitionPlan[];
  requestMatrix: readonly CollectionAuthorizationCasePlan[];
  maxCollections: number;
  maxCasesPerCollection: number;
  maxKnownObjects: number;
  maxRequests: number;
  maxRetainedObservations: number;
  maxPreviewLength: number;
  notes: readonly string[];
}

export type BulkAuthorizationAuthSlot = "account_a" | "account_b";
export type BulkActorRelationship = CollectionActorRelationship;
export type BulkOperationType = "PREVIEW" | "VALIDATE" | "DRY_RUN" | "EXPORT_SUMMARY" | "EXPORT_MANIFEST_PREVIEW" | "SELECTION_SUMMARY" | "ELIGIBILITY_CHECK" | "PERMISSION_CHECK" | "SIMULATION" | "OBSERVE_ONLY";
export type BulkEnvironment = "CONTROLLED_TEST" | "LOCAL_FIXTURE" | "AUTHORIZED_STAGING" | "AUTHORIZED_PRODUCTION_TEST_DATA";
export type BulkRequestStyle = "GET_REPEATED_QUERY" | "GET_COMMA_QUERY" | "JSON_POST";
export type BulkCaseType = "SINGLE_ALLOWED" | "SINGLE_DENIED" | "ALL_ALLOWED" | "ALL_DENIED" | "MIXED_OWNERSHIP" | "MIXED_TENANT" | "MIXED_ROLE_VISIBILITY" | "MIXED_OBJECT_STATE" | "PUBLIC_MIXED_VISIBILITY" | "REFERENCE_COMPARISON";
export type BulkObjectExpectedDecision = "ALLOW" | "DENY" | "FILTER_OUT" | "EXPLICIT_REJECTION" | "REDACTED_METADATA_ONLY" | "PUBLIC_SUMMARY_ONLY" | "MATCH_SINGLE_OBJECT_DECISION" | "OBSERVE_ONLY";
export type BulkBatchPolicy = "MUST_ALLOW_ENTIRE_BATCH" | "MUST_REJECT_ENTIRE_BATCH" | "MUST_FILTER_UNAUTHORIZED_OBJECTS" | "MUST_RETURN_PER_OBJECT_DECISIONS" | "MUST_NOT_EXPOSE_RESTRICTED_METADATA" | "MUST_MATCH_SINGLE_OBJECT_DECISIONS" | "MUST_MATCH_REFERENCE_CASE" | "OBSERVE_ONLY";
export type BulkResponseContractType = "ATOMIC_DECISION" | "FILTERED_OBJECT_LIST" | "PER_OBJECT_DECISIONS" | "PREVIEW_OBJECT_LIST" | "SUMMARY_ONLY" | "EXPORT_MANIFEST_PREVIEW" | "VALIDATION_RESULTS" | "REFERENCE_ONLY";
export type BulkPostSafetyMode = "GET_ONLY" | "OPERATOR_ATTESTED_DRY_RUN" | "POSTCONDITION_VERIFIED_DRY_RUN";
export type BulkBaselineExpectedDecision = "MUST_ALLOW" | "MUST_DENY" | "MUST_REQUIRE_AUTHENTICATION" | "MUST_RETURN_NOT_FOUND" | "OBSERVE_ONLY";
export type BulkBaselineSource = "SAFE_GET" | "REUSE_OBJECT_PAIR_RESULT" | "REUSE_AUTHORIZATION_MATRIX_RESULT";

export interface BulkActorPlan {
  id: string;
  relationship: BulkActorRelationship;
  redactedLabel: string;
  authSlot?: BulkAuthorizationAuthSlot;
  principalIdHash?: string;
  tenantIdHash?: string;
  roleHash?: string;
  accountStateHash?: string;
}

export interface BulkObjectPlan {
  id: string;
  objectId: string;
  objectIdHash: string;
  redactedAlias: string;
  objectType: string;
  expectedDecision: BulkObjectExpectedDecision;
  ownerActorId?: string;
  tenantIdHash?: string;
  state?: string;
  stateHash?: string;
  roleVisibilityHash?: string;
  verificationSource: "DECLARED_ONLY" | "REUSE_VERIFIED_OBJECT_RESULT" | "SAFE_DETAIL_BASELINE";
  baseline?: BulkSingleObjectBaselinePlan;
}

export interface BulkSingleObjectBaselinePlan {
  id: string;
  source: BulkBaselineSource;
  actorId: string;
  authSlot?: BulkAuthorizationAuthSlot;
  method: "GET";
  url: string;
  headers: Readonly<Record<string, string>>;
  expectedDecision: BulkBaselineExpectedDecision;
  requireVerifiedIdentity: boolean;
  objectIdentityField: string;
  objectStateField?: string;
  expectedObjectState?: string;
  expectedObjectStateHash?: string;
  expectedTenantHash?: string;
  expectedRoleHash?: string;
  maxResponseBytes: number;
  maxJsonDepth: number;
}

export interface BulkPostconditionFieldPlan {
  path: string;
  expectedValue?: string | number | boolean | null;
  expectedValueHash?: string;
}

export interface BulkPostconditionCheckPlan {
  id: string;
  actorId: string;
  authSlot?: BulkAuthorizationAuthSlot;
  objectId: string;
  objectIdHash: string;
  method: "GET";
  url: string;
  headers: Readonly<Record<string, string>>;
  objectIdentityField: string;
  objectStateField?: string;
  fields: readonly BulkPostconditionFieldPlan[];
  requireVerifiedIdentity: boolean;
  expectedTenantHash?: string;
  expectedRoleHash?: string;
  maxResponseBytes: number;
  maxJsonDepth: number;
}

export interface BulkSafetyContractPlan {
  operationType: BulkOperationType;
  operatorConfirmedNonMutating: true;
  environment: BulkEnvironment;
  requiredRequestMarkerPath?: string;
  requiredRequestMarkerValue?: string | number | boolean | null;
  requiredResponseMarkerPath?: string;
  requiredResponseMarkerValue?: string | number | boolean | null;
  disallowedResponsePaths: readonly string[];
  disallowedStatusCodes: readonly number[];
  prohibitAsync: boolean;
  prohibitDownloads: boolean;
}

export interface BulkResponseContractPlan {
  type: BulkResponseContractType;
  resultArrayPath?: string;
  resultObjectIdPath?: string;
  perObjectDecisionPath?: string;
  rejectedArrayPath?: string;
  rejectedObjectIdPath?: string;
  overallDecisionPath?: string;
  previewCountPath?: string;
  metadataPaths: readonly string[];
  maxItems: number;
}

export interface BulkAuthorizationCasePlan {
  id: string;
  definitionId: string;
  actorId: string;
  actorRelationship: BulkActorRelationship;
  authSlot?: BulkAuthorizationAuthSlot;
  caseType: BulkCaseType;
  requestStyle: BulkRequestStyle;
  method: "GET" | "POST";
  url: string;
  headers: Readonly<Record<string, string>>;
  body?: string;
  bodyHash?: string;
  objectOrderMatters: boolean;
  objects: readonly BulkObjectPlan[];
  expectedBatchPolicy: BulkBatchPolicy;
  requireVerifiedIdentity: boolean;
  expectedTenantHash?: string;
  expectedRoleHash?: string;
  expectedAccountStateHash?: string;
  safetyContract: BulkSafetyContractPlan;
  responseContract: BulkResponseContractPlan;
  postSafetyMode: BulkPostSafetyMode;
  postconditionChecks: readonly BulkPostconditionCheckPlan[];
  maxResponseBytes: number;
  maxJsonDepth: number;
  maxPreviewLength: number;
}

export interface BulkAuthorizationDefinitionPlan {
  id: string;
  label: string;
  cases: readonly BulkAuthorizationCasePlan[];
}

export interface BulkAuthorizationTestingPlan {
  schemaVersion: 1;
  enabled: true;
  definitions: readonly BulkAuthorizationDefinitionPlan[];
  requestMatrix: readonly BulkAuthorizationCasePlan[];
  maxDefinitions: number;
  maxCasesPerDefinition: number;
  maxObjectsPerCase: number;
  maxRequests: number;
  maxRetainedObservations: number;
  notes: readonly string[];
}

export type FileAuthorizationAuthSlot = "account_a" | "account_b";
export type FileAuthorizationActorRelationship = CollectionActorRelationship;
export type FileCategory =
  | "FILE_METADATA"
  | "INLINE_VIEW"
  | "DIRECT_DOWNLOAD"
  | "FILE_PREVIEW"
  | "THUMBNAIL"
  | "ATTACHMENT"
  | "EXPORT_ARTIFACT"
  | "EVIDENCE_FILE"
  | "PRIVATE_DOCUMENT"
  | "SIGNED_URL_ISSUANCE"
  | "SIGNED_URL_DOWNLOAD"
  | "DOWNLOAD_MANIFEST"
  | "OBSERVE_ONLY";
export type FileAccessExpectation =
  | "MUST_ALLOW_METADATA"
  | "MUST_DENY_METADATA"
  | "MUST_ALLOW_CONTENT"
  | "MUST_DENY_CONTENT"
  | "MUST_REQUIRE_AUTHENTICATION"
  | "MUST_RETURN_NOT_FOUND"
  | "MUST_ALLOW_PREVIEW_ONLY"
  | "MUST_NOT_RECEIVE_SIGNED_URL"
  | "MUST_MATCH_REFERENCE_CASE"
  | "OBSERVE_ONLY";
export type FileIdentityStrategy = "METADATA_FIELD_MATCH" | "OPERATOR_SUPPLIED_FINGERPRINT" | "SIGNED_URL_FIELD_MATCH" | "OBSERVE_ONLY";
export type FileContentProofMode = "HEADERS_ONLY" | "METADATA_ONLY" | "BOUNDED_PREFIX" | "FULL_STREAM_FINGERPRINT" | "SIGNED_URL_ONLY";

export interface FileAuthorizationActorPlan {
  id: string;
  relationship: FileAuthorizationActorRelationship;
  redactedLabel: string;
  authSlot?: FileAuthorizationAuthSlot;
  principalIdHash?: string;
  tenantIdHash?: string;
  roleHash?: string;
  accountStateHash?: string;
}

export interface FileReferencePlan {
  id: string;
  fileRef: string;
  fileRefHash: string;
  redactedAlias: string;
  fileType?: string;
  ownerActorId?: string;
  tenantIdHash?: string;
  state?: string;
  stateHash?: string;
  expectedPublic: boolean;
}

export interface FileAuthorizationCasePlan {
  id: string;
  definitionId: string;
  label: string;
  category: FileCategory;
  actorId: string;
  actorRelationship: FileAuthorizationActorRelationship;
  authSlot?: FileAuthorizationAuthSlot;
  method: "GET" | "HEAD";
  url: string;
  headers: Readonly<Record<string, string>>;
  fileRefId: string;
  fileRef: string;
  fileRefHash: string;
  fileAlias: string;
  expectedDecision: FileAccessExpectation;
  requireVerifiedIdentity: boolean;
  expectedTenantHash?: string;
  expectedRoleHash?: string;
  expectedAccountStateHash?: string;
  expectedFileState?: string;
  expectedFileStateHash?: string;
  identityStrategy: FileIdentityStrategy;
  identityField?: string;
  stateField?: string;
  signedUrlField?: string;
  expectedFingerprint?: string;
  contentProofMode: FileContentProofMode;
  rangeHeader?: string;
  maxMetadataBytes: number;
  maxProbeBytes: number;
  maxFullStreamBytes: number;
  allowedRedirectOrigins: readonly string[];
  followSignedUrl: boolean;
  allowedSignedUrlOrigins: readonly string[];
}

export interface FileAuthorizationDefinitionPlan {
  id: string;
  label: string;
  actors: readonly FileAuthorizationActorPlan[];
  files: readonly FileReferencePlan[];
  cases: readonly FileAuthorizationCasePlan[];
}

export interface FileAuthorizationTestingPlan {
  schemaVersion: 1;
  enabled: true;
  definitions: readonly FileAuthorizationDefinitionPlan[];
  requestMatrix: readonly FileAuthorizationCasePlan[];
  maxDefinitions: number;
  maxCasesPerDefinition: number;
  maxFilesPerDefinition: number;
  maxRequests: number;
  maxRetainedObservations: number;
  notes: readonly string[];
}

export interface ModuleSettings {
  pathSources?: readonly PathSource[];
  maxEndpoints?: number;
  maxComparisons?: number;
  maxEndpointReviews?: number;
  maxDataRoutes?: number;
  maxNextJsManifestRequests?: number;
  maxNextJsDataSurfaceRequests?: number;
  maxNextJsSourceMapRequests?: number;
  maxNextJsCacheDifferentialRequests?: number;
  maxNextJsAssetsInspected?: number;
  maxNextJsRoutesProcessed?: number;
  inspectNextJsSourceMaps?: boolean;
  inspectKnownNextJsDataSurfaces?: boolean;
  nextJsCacheReviewMode?: "PASSIVE_CACHE_REVIEW" | "CONTROLLED_CACHE_DIFFERENTIAL";
  maxProofTargets?: number;
  safeMethods?: readonly HttpMethod[];
  enabled?: boolean;
  browserMaxPages?: number;
  browserMaxLinksPerPage?: number;
  browserMaxPolicyEvents?: number;
  browserMaxRequestsPerPage?: number;
  browserBlockThirdParty?: boolean;
  browserAllowedResourceTypes?: readonly BrowserResourceType[];
  browserCaptureScreenshot?: boolean;
  browserAllowPopups?: boolean;
  browserAllowDownloads?: boolean;
  browserAllowUploads?: boolean;
  browserAllowServiceWorkers?: boolean;
  browserAllowWebSockets?: boolean;
  browserAllowPrivateNetwork?: boolean;
  browserAllowedPrivateOrigins?: readonly string[];
  browserAllowedThirdPartyOrigins?: readonly string[];
  maxObjectPairs?: number;
  maxFieldExposureCases?: number;
  maxFieldExposureFields?: number;
  maxAuthorizationMatrixCases?: number;
  maxEquivalentRouteSets?: number;
  maxEquivalentRouteCells?: number;
  maxCollectionAuthorizationCollections?: number;
  maxCollectionAuthorizationCases?: number;
  maxBulkAuthorizationCases?: number;
  maxFileAuthorizationCases?: number;
  maxSecretBoundaryObservedResponses?: number;
  maxSecretBoundaryAdditionalRequests?: number;
  maxSecretBoundarySourceMaps?: number;
  maxSecretBoundaryCandidatesPerSource?: number;
  maxSecretBoundaryCandidates?: number;
  maxSecretBoundaryAnalysisBytes?: number;
  inspectSecretBoundarySourceMaps?: boolean;
  secretBoundaryProbePaths?: readonly string[];
}

export interface ModulePlan {
  id: ModuleId;
  phase: PluginPhase;
  settings: Readonly<ModuleSettings>;
  limits: Readonly<Partial<ScanLimits>>;
  includedBecause: string[];
}

export interface ModuleSkip {
  id: ModuleId;
  reason: string;
}

export interface ScanPlanMetadata {
  requestedProfile: ScanProfileName;
  resolvedProfile: ScanProfileName;
  legacyMode?: ScanMode;
  legacyModeTranslation?: string;
  createdAt: string;
}

export interface ResolvedScanPlan {
  targetAuthorization?: import("../authorization/TargetAuthorization.js").TargetAuthorization;
  preHandover?: import("../../modules/preHandover/PreHandoverPlanner.js").PreHandoverPlan;
  assistedReview?: Readonly<import("../../modules/assistedReview/AssistedReviewTypes.js").AssistedReviewPlan>;
  schemaVersion: typeof scanPlanSchemaVersion;
  profile: ScanProfileName;
  displayName: string;
  description: string;
  metadata: ScanPlanMetadata;
  modules: readonly ModulePlan[];
  skippedModules: readonly ModuleSkip[];
  limits: Readonly<ScanLimits>;
  authentication: AuthenticationRequirements & AuthenticationAvailability;
  evidence: Readonly<EvidencePolicy>;
  output: Readonly<OutputExpectations>;
  failurePolicy: FailurePolicy;
  optionalModulesMayBeSkipped: boolean;
  reportFocus: readonly string[];
  objectPairTesting?: Readonly<ObjectPairTestingPlan>;
  fieldExposureTesting?: Readonly<FieldExposureTestingPlan>;
  authorizationMatrixTesting?: Readonly<AuthorizationMatrixTestingPlan>;
  collectionAuthorizationTesting?: Readonly<CollectionAuthorizationTestingPlan>;
  bulkAuthorizationTesting?: Readonly<BulkAuthorizationTestingPlan>;
  fileAuthorizationTesting?: Readonly<FileAuthorizationTestingPlan>;
  equivalentRouteTesting?: Readonly<EquivalentRouteTestingPlan>;
  privilegeMutationTesting?: Readonly<import("../../modules/privilegeMutation/PrivilegeMutationPlanner.js").PrivilegeMutationTestingPlan>;
  supabaseAuthorization?: Readonly<import("../../modules/supabaseAuthorization/SupabaseAuthorizationTypes.js").SupabaseAuthorizationPlan>;
  authenticationLifecycle?: Readonly<import("../../modules/authenticationLifecycle/AuthenticationLifecycleTypes.js").AuthenticationLifecyclePlan>;
  businessInvariant?: Readonly<import("../../modules/businessInvariant/BusinessInvariantTypes.js").BusinessInvariantPlan>;
  controlledRace?: Readonly<import("../../modules/controlledRace/ControlledRaceTypes.js").ControlledRacePlan>;
  apiGraphql?: Readonly<import("../../modules/apiGraphql/ApiGraphqlTypes.js").ApiGraphqlReviewPlan>;
  linkPortalSecurity?: Readonly<import("../../modules/linkPortalSecurity/LinkPortalSecurityTypes.js").LinkPortalSecurityPlan>;
  operationalEndpointSecurity?: Readonly<import("../../modules/operationalEndpointSecurity/OperationalEndpointSecurityTypes.js").OperationalEndpointSecurityPlan>;
  billingEntitlement?: Readonly<import("../../modules/billingEntitlement/BillingEntitlementTypes.js").BillingEntitlementPlan>;
}

export interface ModuleMetadata {
  id: ModuleId;
  displayName: string;
  description: string;
  phase: PluginPhase;
  capabilities: readonly ModuleCapability[];
  requiresAuthentication: AuthenticationLevel;
  monitoringCompatible: boolean;
  supportsEvidence: boolean;
  dependencies: readonly ModuleId[];
  orderAfter: readonly ModuleId[];
  cost: ModuleCost;
  readiness: ModuleReadiness;
  defaultSettings: Readonly<ModuleSettings>;
  supportedSettings: readonly (keyof ModuleSettings)[];
}

export interface ScanProfileDefinition {
  name: ScanProfileName;
  displayName: string;
  description: string;
  enabledModules: readonly ModuleId[];
  disabledModules: readonly ModuleId[];
  moduleSettings: Readonly<Partial<Record<ModuleId, ModuleSettings>>>;
  authentication: AuthenticationRequirements;
  limits: Readonly<Partial<ScanLimits>>;
  perModuleLimits: Readonly<Partial<Record<ModuleId, Partial<ScanLimits>>>>;
  evidence: Readonly<EvidencePolicy>;
  output: Readonly<OutputExpectations>;
  failurePolicy: FailurePolicy;
  optionalModulesMayBeSkipped: boolean;
  reportFocus: readonly string[];
}

export interface ScanPlannerInput {
  targetAuthorization?: import("../authorization/TargetAuthorization.js").TargetAuthorization;
  preHandover?: import("../../modules/preHandover/PreHandoverPlanner.js").PreHandoverPlan;
  assistedReview?: import("../../modules/assistedReview/AssistedReviewTypes.js").AssistedReviewPlan;
  requestedProfile: ScanProfileName;
  scope: RouteCairnScope;
  config: RouteCairnConfig;
  authProfile?: AuthProfile;
  authProfileSet?: AuthProfileSet;
  overrides?: {
    rateLimitPerSecond?: number;
    concurrency?: number;
    maxRequests?: number;
    cleanupReservedRequests?: number;
    includeModules?: ModuleId[];
    excludeModules?: ModuleId[];
    moduleSettings?: Partial<Record<ModuleId, ModuleSettings>>;
    evidenceLevel?: EvidenceLevel;
  };
  objectPairTesting?: ObjectPairTestingPlan;
  fieldExposureTesting?: FieldExposureTestingPlan;
  authorizationMatrixTesting?: AuthorizationMatrixTestingPlan;
  collectionAuthorizationTesting?: CollectionAuthorizationTestingPlan;
  bulkAuthorizationTesting?: BulkAuthorizationTestingPlan;
  fileAuthorizationTesting?: FileAuthorizationTestingPlan;
  equivalentRouteTesting?: EquivalentRouteTestingPlan;
  privilegeMutationTesting?: import("../../modules/privilegeMutation/PrivilegeMutationPlanner.js").PrivilegeMutationTestingPlan;
  supabaseAuthorization?: import("../../modules/supabaseAuthorization/SupabaseAuthorizationTypes.js").SupabaseAuthorizationPlan;
  authenticationLifecycle?: import("../../modules/authenticationLifecycle/AuthenticationLifecycleTypes.js").AuthenticationLifecyclePlan;
  businessInvariant?: import("../../modules/businessInvariant/BusinessInvariantTypes.js").BusinessInvariantPlan;
  controlledRace?: import("../../modules/controlledRace/ControlledRaceTypes.js").ControlledRacePlan;
  apiGraphql?: import("../../modules/apiGraphql/ApiGraphqlTypes.js").ApiGraphqlReviewPlan;
  linkPortalSecurity?: import("../../modules/linkPortalSecurity/LinkPortalSecurityTypes.js").LinkPortalSecurityPlan;
  operationalEndpointSecurity?: import("../../modules/operationalEndpointSecurity/OperationalEndpointSecurityTypes.js").OperationalEndpointSecurityPlan;
  billingEntitlement?: import("../../modules/billingEntitlement/BillingEntitlementTypes.js").BillingEntitlementPlan;
  legacyMode?: ScanMode;
  legacyModeTranslation?: string;
}
