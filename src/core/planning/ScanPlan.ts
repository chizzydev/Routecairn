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
  | "header-review"
  | "cookie-review"
  | "cors-review"
  | "method-review"
  | "exposure-review"
  | "proof-mode";

export type ModuleCapability =
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
  maxRequests: number;
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

export interface ModuleSettings {
  pathSources?: readonly PathSource[];
  maxEndpoints?: number;
  maxComparisons?: number;
  maxEndpointReviews?: number;
  maxDataRoutes?: number;
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
  requestedProfile: ScanProfileName;
  scope: RouteCairnScope;
  config: RouteCairnConfig;
  authProfile?: AuthProfile;
  authProfileSet?: AuthProfileSet;
  overrides?: {
    rateLimitPerSecond?: number;
    concurrency?: number;
    includeModules?: ModuleId[];
    excludeModules?: ModuleId[];
    moduleSettings?: Partial<Record<ModuleId, ModuleSettings>>;
  };
  objectPairTesting?: ObjectPairTestingPlan;
  fieldExposureTesting?: FieldExposureTestingPlan;
  legacyMode?: ScanMode;
  legacyModeTranslation?: string;
}
