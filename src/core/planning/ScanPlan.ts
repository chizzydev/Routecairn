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
  legacyMode?: ScanMode;
  legacyModeTranslation?: string;
}
