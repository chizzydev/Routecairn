import { profileNames, profileSummary, resolveScanProfile, type ScanProfileName } from "../../config/ScanProfiles.js";
import { moduleCatalog } from "./ModuleCatalog.js";
import type { ModuleCapability, ModuleId } from "./ScanPlan.js";

export type DashboardParityStatus =
  | "FULL_DASHBOARD_PARITY"
  | "BACKEND_ONLY"
  | "ADVANCED_JSON_ONLY"
  | "FILE_REFERENCE_ONLY"
  | "PARTIAL_UI"
  | "PARTIAL_DASHBOARD_PARITY"
  | "MISSING"
  | "MISSING_DASHBOARD_PARITY"
  | "CLI_ONLY_JUSTIFIED"
  | "INTERNAL_ONLY"
  | "DEPRECATED";

export interface CapabilityParity {
  status: DashboardParityStatus;
  reason: string;
  backendChanges: readonly string[];
  frontendChanges: readonly string[];
  securityConcerns: readonly string[];
  testsRequired: readonly string[];
}

export interface ControlledWorkflowCapability {
  id: string;
  displayName: string;
  moduleId: ModuleId;
  capability: ModuleCapability;
  cliSupport: boolean;
  dashboardSupport: DashboardParityStatus;
  schemaSource: string;
  requiresAccountPair: boolean;
  safeMethods: readonly string[];
  description: string;
  schemaVersion: 1;
  guidedEditorSupport: true;
  advancedJsonSupport: true;
  caseCollection: "cases" | "matrices.cases" | "routeSets.routes" | "collections.cases" | "definitions.cases";
  supportedActors: readonly string[];
  expectationTypes: readonly string[];
  guidedOptions: Readonly<Record<string, readonly string[]>>;
  guidedFieldCoverage: readonly string[];
  advancedOnlyFields: readonly string[];
  limits: Readonly<Record<string, number>>;
  requiresVerifiedIdentity: boolean;
  safetyNotes: readonly string[];
  parity: CapabilityParity;
}

export interface RouteCairnCapabilityRegistry {
  schemaVersion: 1;
  generatedFrom: "scanner-core";
  profiles: ReturnType<typeof profileSummary>[];
  modules: Readonly<typeof moduleCatalog>;
  controlledWorkflows: readonly ControlledWorkflowCapability[];
  limits: {
    configurable: readonly string[];
    hardSafetyCeilings: Record<string, number>;
  };
  evidenceLevels: ReadonlyArray<{ id: "minimal" | "normal" | "strong"; retention: string; dashboardSupport: DashboardParityStatus }>;
  browserPolicyFields: readonly string[];
  parity: Record<string, CapabilityParity>;
}

const full: CapabilityParity = {
  status: "FULL_DASHBOARD_PARITY",
  reason: "Implemented through scanner-core metadata, validated dashboard API, persistence, and a usable dashboard workflow.",
  backendChanges: [],
  frontendChanges: [],
  securityConcerns: [],
  testsRequired: []
};

const commonActors = ["OWNER", "NON_OWNER", "SAME_TENANT_MEMBER", "SAME_TENANT_ADMIN", "CROSS_TENANT_MEMBER", "CROSS_TENANT_ADMIN", "PLATFORM_ADMIN", "MODERATOR", "SHARED_PRINCIPAL", "PUBLIC", "CUSTOM_DECLARED_RELATIONSHIP"] as const;
const decisionExpectations = ["MUST_ALLOW", "MUST_DENY", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "MUST_MATCH_REFERENCE_DECISION", "MUST_NOT_EXCEED_REFERENCE_ACCESS", "OBSERVE_ONLY"] as const;

const guidedFieldCoverage: Readonly<Partial<Record<ModuleCapability, readonly string[]>>> = {
  "object-pair": ["schemaVersion", "maxPairs", "principals.accountA.expectedAccountId", "principals.accountA.tenantId", "principals.accountA.role", "principals.accountB.expectedAccountId", "principals.accountB.tenantId", "principals.accountB.role", "cases[].id", "cases[].objectType", "cases[].expectedVisibility", "cases[].template.id", "cases[].template.method", "cases[].template.url", "cases[].template.headers", "cases[].accountAObject", "cases[].accountBObject"],
  "field-exposure": ["schemaVersion", "maxCases", "maxResponseBytes", "maxPreviewLength", "cases[].id", "cases[].objectType", "cases[].objectId", "cases[].declaredOwnerActor", "cases[].expectedVisibility", "cases[].requireVerifiedIdentity", "cases[].template", "cases[].objectConfirmation", "cases[].actors[]", "cases[].fieldExpectations[].id", "cases[].fieldExpectations[].path", "cases[].fieldExpectations[].label", "cases[].fieldExpectations[].sensitivity", "cases[].fieldExpectations[].expectation", "cases[].fieldExpectations[].allowedActors", "cases[].fieldExpectations[].prohibitedActors", "cases[].fieldExpectations[].allowPreview"],
  "authorization-matrix": ["schemaVersion", "maxMatrices", "maxCasesPerMatrix", "maxResponseBytes", "maxPreviewLength", "matrices[].id", "matrices[].name", "matrices[].objectType", "matrices[].template", "matrices[].objectIdentityField", "matrices[].objectStateField", "matrices[].actors[]", "matrices[].cases[].id", "matrices[].cases[].actorId", "matrices[].cases[].objectId", "matrices[].cases[].expectedObjectState", "matrices[].cases[].expectedDecision", "matrices[].cases[].referenceCaseId", "matrices[].cases[].requireVerifiedIdentity", "matrices[].cases[].expectedTenantId", "matrices[].cases[].expectedRole", "matrices[].cases[].expectedAccountState"],
  "equivalent-route": ["schemaVersion", "maxRouteSets", "maxRoutesPerSet", "maxActorsPerSet", "maxCells", "maxResponseBytes", "maxPreviewLength", "routeSets[].id", "routeSets[].name", "routeSets[].objectType", "routeSets[].objectId", "routeSets[].canonicalRouteId", "routeSets[].equivalencePolicy", "routeSets[].objectIdentityField", "routeSets[].objectStateField", "routeSets[].expectedObjectState", "routeSets[].requireVerifiedIdentity", "routeSets[].actors[]", "routeSets[].routes[].id", "routeSets[].routes[].label", "routeSets[].routes[].category", "routeSets[].routes[].isCanonical", "routeSets[].routes[].deprecated", "routeSets[].routes[].expectedPublic", "routeSets[].routes[].template", "routeSets[].routes[].objectIdentityField", "routeSets[].routes[].responseEnvelopePath", "routeSets[].routes[].objectStateField", "routeSets[].routes[].expectedContentType", "routeSets[].routes[].representationType", "routeSets[].routes[].equivalencePolicy", "routeSets[].routes[].referenceRouteId", "routeSets[].routes[].expectations"],
  "collection-authorization": ["schemaVersion", "maxCollections", "maxCasesPerCollection", "maxKnownObjects", "maxRequests", "maxRetainedObservations", "maxPreviewLength", "collections[].id", "collections[].label", "collections[].category", "collections[].method", "collections[].url", "collections[].headers", "collections[].expectedContentType", "collections[].completeness", "collections[].resultArrayPath", "collections[].objectIdPath", "collections[].objectTenantPath", "collections[].objectOwnerPath", "collections[].objectStatePath", "collections[].objectTypePath", "collections[].maxInspectedEntries", "collections[].maxResponseBytes", "collections[].maxJsonDepth", "collections[].actors[]", "collections[].knownObjects[]", "collections[].cases[].id", "collections[].cases[].actorId", "collections[].cases[].knownObjectId", "collections[].cases[].expectedMembership", "collections[].cases[].expectedActorRelationship", "collections[].cases[].expectedTenantId", "collections[].cases[].expectedRole", "collections[].cases[].expectedAccountState", "collections[].cases[].expectedObjectState", "collections[].cases[].requireVerifiedIdentity", "collections[].cases[].referenceCaseId", "collections[].cases[].countExpectation", "collections[].cases[].summaryExpectations[]"],
  "bulk-authorization": ["schemaVersion", "maxDefinitions", "maxCasesPerDefinition", "maxObjectsPerCase", "maxRequests", "maxRetainedObservations", "definitions[].id", "definitions[].label", "definitions[].actors[]", "definitions[].cases[].id", "definitions[].cases[].actorId", "definitions[].cases[].caseType", "definitions[].cases[].requestStyle", "definitions[].cases[].method", "definitions[].cases[].url", "definitions[].cases[].headers", "definitions[].cases[].bodyTemplate", "definitions[].cases[].objectOrderMatters", "definitions[].cases[].objects[]", "definitions[].cases[].expectedBatchPolicy", "definitions[].cases[].requireVerifiedIdentity", "definitions[].cases[].expectedTenantId", "definitions[].cases[].expectedRole", "definitions[].cases[].expectedAccountState", "definitions[].cases[].safetyContract", "definitions[].cases[].responseContract", "definitions[].cases[].postSafetyMode", "definitions[].cases[].postconditionChecks[]", "definitions[].cases[].maxResponseBytes", "definitions[].cases[].maxJsonDepth", "definitions[].cases[].maxPreviewLength"],
  "file-authorization": ["schemaVersion", "maxDefinitions", "maxCasesPerDefinition", "maxFilesPerDefinition", "maxRequests", "maxRetainedObservations", "definitions[].id", "definitions[].label", "definitions[].actors[]", "definitions[].files[]", "definitions[].cases[].id", "definitions[].cases[].label", "definitions[].cases[].category", "definitions[].cases[].actorId", "definitions[].cases[].fileRefId", "definitions[].cases[].method", "definitions[].cases[].url", "definitions[].cases[].placeholder", "definitions[].cases[].headers", "definitions[].cases[].expectedDecision", "definitions[].cases[].requireVerifiedIdentity", "definitions[].cases[].expectedTenantId", "definitions[].cases[].expectedRole", "definitions[].cases[].expectedAccountState", "definitions[].cases[].expectedFileState", "definitions[].cases[].identityStrategy", "definitions[].cases[].identityField", "definitions[].cases[].stateField", "definitions[].cases[].signedUrlField", "definitions[].cases[].expectedFingerprint", "definitions[].cases[].contentProofMode", "definitions[].cases[].rangeStart", "definitions[].cases[].rangeLength", "definitions[].cases[].maxMetadataBytes", "definitions[].cases[].maxProbeBytes", "definitions[].cases[].maxFullStreamBytes", "definitions[].cases[].allowedRedirectOrigins", "definitions[].cases[].followSignedUrl", "definitions[].cases[].allowedSignedUrlOrigins"],
};

const controlledWorkflows: readonly ControlledWorkflowCapability[] = [
  workflow("object-pair", "Object Pair Authorization", "object-pair-testing", "Compare exact Account A and Account B owned objects using a fixed four-request matrix.", "cases", ["account_a", "account_b"], ["PRIVATE_TO_OWNER", "SHARED_WITH_SPECIFIC_PRINCIPALS", "TENANT_VISIBLE", "ROLE_VISIBLE", "PUBLIC", "UNKNOWN_REQUIRES_REVIEW"], { maxCases: 20, requestsPerCase: 4 }, ["GET", "HEAD"], { expectedVisibility: ["PRIVATE_TO_OWNER", "SHARED_WITH_SPECIFIC_PRINCIPALS", "TENANT_VISIBLE", "ROLE_VISIBLE", "PUBLIC", "UNKNOWN_REQUIRES_REVIEW"] }),
  workflow("field-exposure", "Field Exposure Authorization", "field-exposure-testing", "Compare exact configured JSON fields across explicit owner, non-owner, shared, and public actors.", "cases", ["OWNER", "NON_OWNER", "SECONDARY_NON_OWNER", "SHARED_PRINCIPAL", "LOWER_PRIVILEGED_ROLE", "HIGHER_PRIVILEGED_ROLE", "SAME_TENANT_MEMBER", "CROSS_TENANT_MEMBER", "PUBLIC"], ["MUST_BE_ABSENT", "MUST_BE_NULL", "MUST_BE_REDACTED", "MUST_DIFFER_FROM_OWNER", "MUST_MATCH_PUBLIC_BASELINE", "MUST_MATCH_SHARED_BASELINE", "MAY_BE_PRESENT", "MUST_BE_PRESENT", "MASKED_VALUE", "OWNER_ONLY_VALUE"], { maxCases: 20, maxFieldsPerCase: 40 }, ["GET"], { actorType: ["OWNER", "NON_OWNER", "SECONDARY_NON_OWNER", "SHARED_PRINCIPAL", "LOWER_PRIVILEGED_ROLE", "HIGHER_PRIVILEGED_ROLE", "SAME_TENANT_MEMBER", "CROSS_TENANT_MEMBER", "PUBLIC"], visibility: ["OWNER_ONLY", "PUBLIC_SUMMARY", "PUBLIC_FULL", "SHARED_WITH_SPECIFIC_PRINCIPALS", "TENANT_VISIBLE", "ROLE_VISIBLE", "AUTHENTICATED_USERS", "UNKNOWN_REQUIRES_REVIEW"], sensitivity: ["PUBLIC", "PRIVATE", "OWNER_ONLY", "TENANT", "ROLE", "INTERNAL"] }),
  workflow("authorization-matrix", "Role and State Authorization Matrix", "authorization-matrix-testing", "Test explicit actor, role, tenant, account-state, and object-state rows without generating permutations.", "matrices.cases", commonActors, decisionExpectations, { maxMatrices: 5, maxCasesPerMatrix: 40 }, ["GET"], { relationship: commonActors, expectedDecision: decisionExpectations }),
  workflow("equivalent-route", "Equivalent Route Authorization", "equivalent-route-testing", "Compare exact operator-supplied route equivalents for the same supplied object.", "routeSets.routes", commonActors, ["MUST_ALLOW", "MUST_DENY", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "MUST_MATCH_CANONICAL_DECISION", "MUST_MATCH_REFERENCE_ROUTE", "MUST_NOT_EXCEED_CANONICAL_ACCESS", "MUST_NOT_EXCEED_PUBLIC_ACCESS", "OBSERVE_ONLY"], { maxRouteSets: 5, maxRoutesPerSet: 8, maxCells: 80 }, ["GET"], { routeCategory: ["CANONICAL", "LEGACY", "VERSIONED", "NESTED", "TOP_LEVEL", "EXPORT", "SUMMARY", "DETAIL", "MOBILE", "WEB", "ALIAS", "COMPATIBILITY", "RELATIONSHIP", "ALTERNATE_FORMAT", "CUSTOM_DECLARED"], relationship: ["OWNER", "NON_OWNER", "SAME_TENANT_MEMBER", "SAME_TENANT_ADMIN", "CROSS_TENANT_MEMBER", "CROSS_TENANT_ADMIN", "ADMINISTRATOR", "MODERATOR", "SUSPENDED", "ACTIVE", "SHARED_PRINCIPAL", "PUBLIC", "CUSTOM_DECLARED_RELATIONSHIP"], equivalencePolicy: ["AUTHORIZATION_ONLY", "SAME_OBJECT", "SAME_PUBLIC_BOUNDARY", "SAME_OWNER_BOUNDARY", "SAME_TENANT_BOUNDARY", "SAME_ROLE_BOUNDARY", "SAME_STATE_BOUNDARY", "MUST_NOT_EXCEED_REFERENCE_ROUTE"] }),
  workflow("collection-authorization", "Collection and Listing Authorization", "collection-authorization-testing", "Check exact known-object membership in bounded collection, search, count, or summary responses.", "collections.cases", commonActors, ["MUST_CONTAIN", "MUST_NOT_CONTAIN", "MAY_CONTAIN", "MUST_MATCH_PUBLIC_MEMBERSHIP", "MUST_MATCH_REFERENCE_CASE", "MUST_NOT_EXCEED_REFERENCE_MEMBERSHIP", "OBSERVE_ONLY"], { maxCollections: 5, maxCasesPerCollection: 40, maxKnownObjects: 40 }, ["GET"], { relationship: ["OWNER", "NON_OWNER", "SAME_TENANT_MEMBER", "SAME_TENANT_ADMIN", "CROSS_TENANT_MEMBER", "CROSS_TENANT_ADMIN", "PLATFORM_ADMIN", "MODERATOR", "SHARED_PRINCIPAL", "ACTIVE_ACCOUNT", "SUSPENDED_ACCOUNT", "DEACTIVATED_ACCOUNT", "PUBLIC", "CUSTOM_DECLARED_RELATIONSHIP"], category: ["LIST", "SEARCH", "COUNT", "SUMMARY", "DASHBOARD", "RECENT", "ARCHIVE", "ADMIN_LIST", "TENANT_LIST", "PUBLIC_LIST", "CUSTOM_DECLARED"], completeness: ["COMPLETE_COLLECTION", "FIXED_RESULT_WINDOW", "SEARCH_RESULT_SET", "SUMMARY_ONLY", "UNKNOWN_COMPLETENESS"], countExpectation: ["MUST_EQUAL", "MUST_MATCH_REFERENCE", "MUST_NOT_EXCEED_REFERENCE", "MUST_BE_ZERO", "MAY_DIFFER", "OBSERVE_ONLY"], summaryExpectation: ["MUST_EQUAL", "MUST_MATCH_REFERENCE", "MUST_NOT_EXCEED_REFERENCE", "MUST_BE_ZERO", "MAY_DIFFER", "OBSERVE_ONLY"] }),
  workflow("bulk-authorization", "Bulk Authorization", "bulk-authorization-testing", "Exercise exact supplied object sets through safe GET or explicitly attested non-mutating dry-run POST contracts.", "definitions.cases", commonActors, ["MUST_ALLOW_ENTIRE_BATCH", "MUST_REJECT_ENTIRE_BATCH", "MUST_FILTER_UNAUTHORIZED_OBJECTS", "MUST_RETURN_PER_OBJECT_DECISIONS", "MUST_NOT_EXPOSE_RESTRICTED_METADATA", "MUST_MATCH_SINGLE_OBJECT_DECISIONS", "MUST_MATCH_REFERENCE_CASE", "OBSERVE_ONLY"], { maxDefinitions: 5, maxCasesPerDefinition: 40, maxObjectsPerCase: 40 }, ["GET", "POST"], { relationship: ["OWNER", "NON_OWNER", "SAME_TENANT_MEMBER", "SAME_TENANT_ADMIN", "CROSS_TENANT_MEMBER", "CROSS_TENANT_ADMIN", "PLATFORM_ADMIN", "MODERATOR", "SHARED_PRINCIPAL", "ACTIVE_ACCOUNT", "SUSPENDED_ACCOUNT", "DEACTIVATED_ACCOUNT", "PUBLIC", "CUSTOM_DECLARED_RELATIONSHIP"], operation: ["PREVIEW", "VALIDATE", "DRY_RUN", "EXPORT_SUMMARY", "EXPORT_MANIFEST_PREVIEW", "SELECTION_SUMMARY", "ELIGIBILITY_CHECK", "PERMISSION_CHECK", "SIMULATION", "OBSERVE_ONLY"], environment: ["CONTROLLED_TEST", "LOCAL_FIXTURE", "AUTHORIZED_STAGING", "AUTHORIZED_PRODUCTION_TEST_DATA"], requestStyle: ["GET_REPEATED_QUERY", "GET_COMMA_QUERY", "JSON_POST"], caseType: ["SINGLE_ALLOWED", "SINGLE_DENIED", "ALL_ALLOWED", "ALL_DENIED", "MIXED_OWNERSHIP", "MIXED_TENANT", "MIXED_ROLE_VISIBILITY", "MIXED_OBJECT_STATE", "PUBLIC_MIXED_VISIBILITY", "REFERENCE_COMPARISON"], objectDecision: ["ALLOW", "DENY", "FILTER_OUT", "EXPLICIT_REJECTION", "REDACTED_METADATA_ONLY", "PUBLIC_SUMMARY_ONLY", "MATCH_SINGLE_OBJECT_DECISION", "OBSERVE_ONLY"], responseContract: ["ATOMIC_DECISION", "FILTERED_OBJECT_LIST", "PER_OBJECT_DECISIONS", "PREVIEW_OBJECT_LIST", "SUMMARY_ONLY", "EXPORT_MANIFEST_PREVIEW", "VALIDATION_RESULTS", "REFERENCE_ONLY"], postSafetyMode: ["GET_ONLY", "OPERATOR_ATTESTED_DRY_RUN", "POSTCONDITION_VERIFIED_DRY_RUN"], baselineSource: ["SAFE_GET", "REUSE_OBJECT_PAIR_RESULT", "REUSE_AUTHORIZATION_MATRIX_RESULT"], baselineDecision: ["MUST_ALLOW", "MUST_DENY", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "OBSERVE_ONLY"], verificationSource: ["DECLARED_ONLY", "REUSE_VERIFIED_OBJECT_RESULT", "SAFE_DETAIL_BASELINE"] }),
  workflow("file-authorization", "File and Download Authorization", "file-authorization-testing", "Test exact file references with bounded metadata, prefix, fingerprint, or explicitly approved signed-URL evidence.", "definitions.cases", commonActors, ["MUST_ALLOW_METADATA", "MUST_DENY_METADATA", "MUST_ALLOW_CONTENT", "MUST_DENY_CONTENT", "MUST_REQUIRE_AUTHENTICATION", "MUST_RETURN_NOT_FOUND", "MUST_ALLOW_PREVIEW_ONLY", "MUST_NOT_RECEIVE_SIGNED_URL", "MUST_MATCH_REFERENCE_CASE", "OBSERVE_ONLY"], { maxDefinitions: 5, maxCasesPerDefinition: 40, maxFilesPerDefinition: 40 }, ["GET", "HEAD"], { relationship: commonActors, category: ["FILE_METADATA", "INLINE_VIEW", "DIRECT_DOWNLOAD", "FILE_PREVIEW", "THUMBNAIL", "ATTACHMENT", "EXPORT_ARTIFACT", "EVIDENCE_FILE", "PRIVATE_DOCUMENT", "SIGNED_URL_ISSUANCE", "SIGNED_URL_DOWNLOAD", "DOWNLOAD_MANIFEST", "OBSERVE_ONLY"], identityStrategy: ["METADATA_FIELD_MATCH", "OPERATOR_SUPPLIED_FINGERPRINT", "SIGNED_URL_FIELD_MATCH", "OBSERVE_ONLY"], proofMode: ["HEADERS_ONLY", "METADATA_ONLY", "BOUNDED_PREFIX", "FULL_STREAM_FINGERPRINT", "SIGNED_URL_ONLY"], placeholder: ["FILE_ID", "FILE_KEY"] })
];

export function routeCairnCapabilityRegistry(): RouteCairnCapabilityRegistry {
  return {
    schemaVersion: 1,
    generatedFrom: "scanner-core",
    profiles: profileNames().map((name: ScanProfileName) => profileSummary(resolveScanProfile(name))),
    modules: moduleCatalog,
    controlledWorkflows,
    limits: {
      configurable: ["maxDepth", "rateLimitPerSecond", "concurrency", "requestTimeoutMs", "bodyPreviewBytes", "maxResponseBytes", "maxRequests", "maxScanDurationMs", "retry"],
      hardSafetyCeilings: {
        rateLimitPerSecond: 50,
        concurrency: 50,
        maxJsonBodyBytes: 1024 * 1024
      }
    },
    evidenceLevels: [
      { id: "minimal", retention: "Status, lengths, hashes, redacted metadata, and detection indicators only.", dashboardSupport: "FULL_DASHBOARD_PARITY" },
      { id: "normal", retention: "Bounded redacted previews and structured evidence summaries.", dashboardSupport: "FULL_DASHBOARD_PARITY" },
      { id: "strong", retention: "Bounded redacted reproducibility metadata and proof blocks where modules support it.", dashboardSupport: "FULL_DASHBOARD_PARITY" }
    ],
    browserPolicyFields: [...moduleCatalog["browser-crawler"].supportedSettings],
    parity: {
      profiles: full,
      modules: full,
      "projects-targets": full,
      "scan-builder": full,
      "controlled-workflow-editors": full,
      "credential-vault": full,
      "server-mode-rbac": full,
      "isolated-workers": full,
      "browser-network-isolation": full,
      "audit": full
    }
  };
}

function workflow(
  capability: ModuleCapability,
  displayName: string,
  moduleId: ModuleId,
  description: string,
  caseCollection: ControlledWorkflowCapability["caseCollection"],
  supportedActors: readonly string[],
  expectationTypes: readonly string[],
  limits: Readonly<Record<string, number>>,
  safeMethods: readonly string[] = ["GET", "HEAD"],
  guidedOptions: Readonly<Record<string, readonly string[]>> = {}
): ControlledWorkflowCapability {
  return {
    id: capability,
    displayName,
    moduleId,
    capability,
    cliSupport: true,
    dashboardSupport: "FULL_DASHBOARD_PARITY",
    schemaSource: "ScanPlanner controlled workflow input schemas",
    requiresAccountPair: true,
    safeMethods,
    description,
    schemaVersion: 1,
    guidedEditorSupport: true,
    advancedJsonSupport: true,
    caseCollection,
    supportedActors,
    expectationTypes,
    guidedOptions,
    guidedFieldCoverage: guidedFieldCoverage[capability] ?? [],
    advancedOnlyFields: [],
    limits,
    requiresVerifiedIdentity: true,
    safetyNotes: ["Only exact operator-supplied cases execute.", "Runtime responses never expand identifiers, actors, routes, fields, or files.", "Planner validation remains authoritative."],
    parity: full
  };
}
