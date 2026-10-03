
import { type PlanPreview } from "./api";
import { type WorkflowCapability, type WorkflowDraft } from "./AuthorizationWorkflowStudio";

import type { RetestDraft } from "./FindingsCommandCenter";
import { type AdvancedEngineDraft } from "./AdvancedEngineStudio";



export type AuthSource = "ephemeral" | "saved";

export type AuthMode = "public" | "primary" | "account-pair";

export type HeaderRow = { id: string; name: string; value: string };

export type CookieRow = { id: string; name: string; value: string };

export type IdentityState = {
  mode: "disabled" | "optional" | "required";
  endpoint: string;
  method: "GET" | "HEAD";
  principalIdField: string;
  tenantIdField: string;
  roleField: string;
  accountStateField: string;
  expectedPrincipal: string;
  expectedTenant: string;
  expectedRole: string;
  expectedState: string;
  maxResponseBytes: number;
};

export type ActorState = {
  source: AuthSource;
  savedId: string;
  safeAlias: string;
  bearerToken: string;
  headers: HeaderRow[];
  cookies: CookieRow[];
  identity: IdentityState;
};

export type ScopeState = {
  program: string;
  allowedDomains: string[];
  disallowedPaths: string[];
  allowedMethods: Array<"GET" | "HEAD" | "OPTIONS" | "POST" | "PATCH" | "PUT" | "DELETE" | "CONNECT">;
  rateLimitPerSecond: number;
  concurrency: number;
  maxDepth: number;
  sameOriginOnly: boolean;
  includeSubdomains: boolean;
  respectRobotsTxt: boolean;
  userAgent: string;
};

export type NextJsReviewSettings = {
  inspectNextJsSourceMaps: boolean;
  inspectKnownNextJsDataSurfaces: boolean;
  nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW" | "CONTROLLED_CACHE_DIFFERENTIAL";
  maxNextJsManifestRequests: number;
  maxNextJsDataSurfaceRequests: number;
  maxNextJsSourceMapRequests: number;
  maxNextJsCacheDifferentialRequests: number;
  maxNextJsAssetsInspected: number;
  maxNextJsRoutesProcessed: number;
};

export type TransportState = {
  poolingEnabled: boolean;
  http2Enabled: boolean;
  maxOrigins: number;
  maxConnectionsPerOrigin: number;
  maxConcurrentHttp2Streams: number;
  maxHeaderSizeBytes: number;
  keepAliveTimeoutMs: number;
  keepAliveMaxTimeoutMs: number;
  maxConnectionLifetimeMs: number;
  maxRequestsPerConnection: number;
  dnsCacheTtlMs: number;
};

export type StudioState = {
  currentStep: number;
  scanName: string;
  operatorNote: string;
  projectId: string;
  targetId: string;
  target: string;
  authorizationCategory:
    | "OWNED"
    | "CLIENT_AUTHORIZED"
    | "BUG_BOUNTY"
    | "CONTROLLED_LAB"
    | "OTHER_AUTHORIZED";
  authorizationConfirmed: boolean;
  authorizationNote: string;
  scope: ScopeState;
  profile: string;
  selectedModules: string[];
  nextJsReview: NextJsReviewSettings;
  transport: TransportState;
  authMode: AuthMode;
  primary: ActorState;
  accountA: ActorState;
  accountB: ActorState;
  evidenceLevel: "minimal" | "normal" | "strong";
  maxRequestsOverride: string;
  cleanupReservedRequestsOverride: string;
  outputs: { json: boolean; markdown: boolean; html: boolean };
  workflows: WorkflowDraft[];
  advancedEngines: AdvancedEngineDraft[];
  providerAdapterBinding?: { profileId: string; versionId: string; adapterDigest: string };
  adaptiveExecutionBinding?: { recommendationId: string; sourceFingerprint: string; executionFingerprint: string; compilerVersion: 1 | 2; graphFingerprint?: string; graphPathIds?: string[] };
  authenticationLifecycleFile: string;
  authenticationLifecycleAutoFile: string;
  businessInvariantFile: string;
  controlledRaceFile: string;
  apiGraphqlFile: string;
  linkPortalSecurityFile: string;
  operationalEndpointSecurityFile: string;
  billingEntitlementFile: string;
  assistedReviewFile: string;
  preHandoverFile: string;
  targetAuthorizationFile: string;
  retestContext?: RetestDraft["context"];
  preview: PlanPreview | undefined;
};

export type CapabilityRegistry = {
  profiles: Array<{
    name: string;
    displayName: string;
    description: string;
    modules: string[];
    limits: Record<string, unknown>;
    browserUse: string;
    authComparisonDepth: string;
    proofMode: boolean;
    reportFocus: string[];
  }>;
  modules: Array<{
    id: string;
    displayName: string;
    description: string;
    phase: string;
    capabilities: string[];
    requiresAuthentication: string;
    dependencies: string[];
    cost: string;
    supportedSettings: string[];
  }>;
  controlledWorkflows: WorkflowCapability[];
  evidenceLevels: Array<{
    id: "minimal" | "normal" | "strong";
    retention: string;
  }>;
  transport?: { defaults: TransportState; http2: string; dnsRevalidation: string; diagnostics: string[] };
};

export const steps = [
  "Target",
  "Scope",
  "Profile & Modules",
  "Authentication",
  "Verified Identity",
  "Browser & Limits",
  "Evidence & Outputs",
  "Controlled Workflows",
  "Plan Review",
  "Launch",
];

export const headerNamePattern = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;

export const forbiddenHeaders = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "upgrade",
  "expect",
  "te",
  "trailer",
]);

export const fieldPathPattern =
  /^[A-Za-z_$][A-Za-z0-9_$]*(?:\[(?:0|[1-9][0-9]{0,2})\]|\.[A-Za-z_$][A-Za-z0-9_$]*){0,8}$/;

export const emptyIdentity = (): IdentityState => ({
  mode: "disabled",
  endpoint: "",
  method: "GET",
  principalIdField: "id",
  tenantIdField: "",
  roleField: "",
  accountStateField: "",
  expectedPrincipal: "",
  expectedTenant: "",
  expectedRole: "",
  expectedState: "",
  maxResponseBytes: 8192,
});

export const emptyActor = (alias: string): ActorState => ({
  source: "ephemeral",
  savedId: "",
  safeAlias: alias,
  bearerToken: "",
  headers: [],
  cookies: [],
  identity: emptyIdentity(),
});

export type ValidationError = { step: number; message: string };
