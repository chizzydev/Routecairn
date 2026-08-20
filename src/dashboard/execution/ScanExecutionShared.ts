import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { defaultConfig } from "../../config/defaults.js";
import { routeCairnConfigSchema, scopeSchema } from "../../config/ConfigSchema.js";
import { loadRouteCairnConfig, loadScope } from "../../config/loadConfig.js";
import { authHeadersForProfile, loadAuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfile } from "../../core/auth/AuthProfile.js";
import { loadAuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import type { ResolvedScanPlan, ScanPlannerInput } from "../../core/planning/ScanPlan.js";
import type { ModuleId } from "../../core/planning/ScanPlan.js";
import { ScanPlanner } from "../../core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../core/engine/ScanOrchestrator.js";
import { redactDashboardValue } from "../security/Redaction.js";
import type { CredentialProfileSecret, CredentialProfileSummary, CredentialVault } from "../credentials/CredentialVault.js";
import type { ScanStudioAuthActor } from "../contracts/ScanStudioSchemas.js";
import { planObjectPairTesting } from "../../modules/objectPairTesting/ObjectPairPlanner.js";
import { planFieldExposureTesting } from "../../modules/fieldExposureTesting/FieldExposurePlanner.js";
import { planAuthorizationMatrixTesting } from "../../modules/authorizationMatrix/AuthorizationMatrixPlanner.js";
import { planEquivalentRouteTesting } from "../../modules/equivalentRouteTesting/EquivalentRoutePlanner.js";
import { planCollectionAuthorizationTesting } from "../../modules/collectionAuthorization/CollectionAuthorizationPlanner.js";
import { planBulkAuthorizationTesting } from "../../modules/bulkAuthorization/BulkAuthorizationPlanner.js";
import { planFileAuthorizationTesting } from "../../modules/fileAuthorization/FileAuthorizationPlanner.js";

export interface DashboardResolvedAuth {
  authProfile?: AuthProfile | undefined;
  authProfileSet?: AuthProfileSet | undefined;
  safeSummary: Record<string, unknown>;
}

export async function resolveDashboardScanPlan(request: DashboardScanCreateRequest, resolvedAuth?: DashboardResolvedAuth): Promise<ResolvedPlanInputs> {
  if ((request.authAFile && !request.authBFile) || (!request.authAFile && request.authBFile)) {
    throw new Error("Account-pair authentication requires both authAFile and authBFile.");
  }
  if ((request.credentialProfileAId && !request.credentialProfileBId) || (!request.credentialProfileAId && request.credentialProfileBId)) {
    throw new Error("Account-pair credential profiles require both Account A and Account B.");
  }
  const config = request.configFile ? await loadRouteCairnConfig(resolve(request.configFile)) : routeCairnConfigSchema.parse(defaultConfig);
  const scope = request.studio?.scope ? scopeSchema.parse(request.studio.scope) : await loadScope(resolve(requiredScopeFile(request)));
  const studioEphemeralAuth = authFromStudioEphemeral(request);
  const authProfile = resolvedAuth?.authProfile ?? studioEphemeralAuth?.authProfile ?? (request.authFile ? await loadAuthProfile(resolve(request.authFile)) : undefined);
  const authProfileSet = resolvedAuth?.authProfileSet ?? studioEphemeralAuth?.authProfileSet ?? (request.authAFile && request.authBFile ? await loadAuthProfileSet(resolve(request.authAFile), resolve(request.authBFile)) : undefined);
  const workflowPlans = resolveStudioWorkflowPlans(request, { target: request.target, scope, ...(authProfileSet ? { authProfileSet } : {}) });
  const input: ScanPlannerInput = {
    requestedProfile: request.profile,
    scope,
    config,
    ...(authProfile ? { authProfile } : {}),
    ...(authProfileSet ? { authProfileSet } : {}),
    ...workflowPlans,
    overrides: {
      ...(request.rateLimitPerSecond ? { rateLimitPerSecond: request.rateLimitPerSecond } : {}),
      ...(request.concurrency ? { concurrency: request.concurrency } : {}),
      ...(request.studio?.evidenceLevel ? { evidenceLevel: request.studio.evidenceLevel } : {}),
      ...(request.includeModules && request.includeModules.length > 0 ? { includeModules: request.includeModules as ModuleId[] } : {})
    }
  };
  const planner = new ScanPlanner(createDefaultPluginRegistry());
  return { plan: planner.resolve(input), config, scope, ...(authProfile ? { authProfile } : {}), ...(authProfileSet ? { authProfileSet } : {}) };
}

export function resolveCredentialAuthForDashboardScan(vault: CredentialVault, request: DashboardScanCreateRequest): DashboardResolvedAuth {
  if (request.studio?.authentication.mode && request.studio.authentication.mode !== "public") {
    return resolveStudioAuth(vault, request);
  }
  if (!request.credentialProfileId && !request.credentialProfileAId && !request.credentialProfileBId) {
    return { safeSummary: { savedCredentialAuth: false } };
  }
  if (request.authFile || request.authAFile || request.authBFile) {
    throw new Error("Use either auth files or saved credential profiles for a dashboard scan, not both.");
  }
  if (request.credentialProfileId) {
    const authProfile = profileFromVault(vault, request.credentialProfileId, request, "single");
    return { authProfile, safeSummary: { savedCredentialAuth: true, single: safeCredentialReference(vault.getSummary(request.credentialProfileId), "single") } };
  }
  if (!request.credentialProfileAId || !request.credentialProfileBId) {
    throw new Error("Account-pair credential profiles require both Account A and Account B.");
  }
  if (request.credentialProfileAId === request.credentialProfileBId) {
    throw new Error("Account A and Account B must use different credential profiles.");
  }
  const authProfileSet = {
    accountA: profileFromVault(vault, request.credentialProfileAId, request, "accountA"),
    accountB: profileFromVault(vault, request.credentialProfileBId, request, "accountB")
  };
  return {
    authProfile: authProfileSet.accountA,
    authProfileSet,
    safeSummary: {
      savedCredentialAuth: true,
      accountA: safeCredentialReference(vault.getSummary(request.credentialProfileAId), "accountA"),
      accountB: safeCredentialReference(vault.getSummary(request.credentialProfileBId), "accountB")
    }
  };
}

export function safeConfigurationSummary(request: DashboardScanCreateRequest): Record<string, unknown> {
  return {
    target: request.target,
    targetOrigin: new URL(request.target).origin,
    profile: request.profile,
    projectId: request.projectId,
    targetId: request.targetId,
    authorizationDeclaration: request.authorizationDeclaration,
    scope: request.studio?.scope,
    scopeFile: request.scopeFile ? resolve(request.scopeFile) : undefined,
    configFile: request.configFile ? resolve(request.configFile) : undefined,
    scopeFileLabel: request.scopeFile ? safePathLabel(request.scopeFile) : "inline-scope",
    configFileLabel: request.configFile ? safePathLabel(request.configFile) : "default",
    auth: Boolean(request.authFile),
    accountPair: Boolean(request.authAFile && request.authBFile),
    savedCredentialAuth: Boolean(request.credentialProfileId || request.credentialProfileAId || request.credentialProfileBId),
    credentialProfile: request.credentialProfileId ? safeCredentialReferenceForId(request.credentialProfileId, "single") : undefined,
    credentialProfileA: request.credentialProfileAId ? safeCredentialReferenceForId(request.credentialProfileAId, "accountA") : undefined,
    credentialProfileB: request.credentialProfileBId ? safeCredentialReferenceForId(request.credentialProfileBId, "accountB") : undefined,
    rateLimitPerSecond: request.rateLimitPerSecond,
    concurrency: request.concurrency,
    includeModules: request.includeModules ?? [],
    studio: request.studio ? safeStudioSummary(request) : undefined
  };
}

export function safePlanIdentity(request: DashboardScanCreateRequest, plan: ResolvedScanPlan): string {
  const stablePlan = redactDashboardValue({ ...plan, metadata: { ...plan.metadata, createdAt: "<volatile>" } });
  return createHash("sha256").update(JSON.stringify({ request: safeConfigurationSummary(request), plan: stablePlan })).digest("hex");
}

export function planSnapshot(plan: ResolvedScanPlan, scope: Awaited<ReturnType<typeof loadScope>>) {
  const redactedPlan = redactDashboardValue({
    ...plan,
    objectPairTesting: workflowPlanSummary(plan.objectPairTesting),
    fieldExposureTesting: workflowPlanSummary(plan.fieldExposureTesting),
    authorizationMatrixTesting: workflowPlanSummary(plan.authorizationMatrixTesting),
    collectionAuthorizationTesting: workflowPlanSummary(plan.collectionAuthorizationTesting),
    bulkAuthorizationTesting: workflowPlanSummary(plan.bulkAuthorizationTesting),
    fileAuthorizationTesting: workflowPlanSummary(plan.fileAuthorizationTesting),
    equivalentRouteTesting: workflowPlanSummary(plan.equivalentRouteTesting)
  });
  return {
    plannerVersion: String(plan.schemaVersion),
    profile: plan.profile,
    modules: plan.modules.map((modulePlan) => ({ id: modulePlan.id, phase: modulePlan.phase, settings: modulePlan.settings })),
    limits: plan.limits,
    evidencePolicy: plan.evidence,
    browserPolicySummary: plan.modules.find((modulePlan) => modulePlan.id === "browser-crawler")?.settings ?? {},
    scopeSummary: { allowedDomains: scope.allowedDomains, sameOriginOnly: scope.sameOriginOnly, includeSubdomains: scope.includeSubdomains },
    authenticationSummary: plan.authentication,
    controlledWorkflowSummary: {
      objectPairTesting: Boolean(plan.objectPairTesting),
      fieldExposureTesting: Boolean(plan.fieldExposureTesting),
      authorizationMatrixTesting: Boolean(plan.authorizationMatrixTesting),
      collectionAuthorizationTesting: Boolean(plan.collectionAuthorizationTesting),
      bulkAuthorizationTesting: Boolean(plan.bulkAuthorizationTesting),
      fileAuthorizationTesting: Boolean(plan.fileAuthorizationTesting),
      equivalentRouteTesting: Boolean(plan.equivalentRouteTesting)
    },
    redactedPlan
  };
}

export function reportDirectoryFor(baseReportsDir: string, scanId: string): string {
  return resolve(baseReportsDir, scanId);
}

export function outputDirFromReport(reportPath: string): string {
  return dirname(reportPath);
}

export interface ResolvedPlanInputs {
  plan: ResolvedScanPlan;
  config: Awaited<ReturnType<typeof loadRouteCairnConfig>>;
  scope: Awaited<ReturnType<typeof loadScope>>;
  authProfile?: Awaited<ReturnType<typeof loadAuthProfile>>;
  authProfileSet?: Awaited<ReturnType<typeof loadAuthProfileSet>>;
}

function authFromStudioEphemeral(request: DashboardScanCreateRequest): DashboardResolvedAuth | undefined {
  const auth = request.studio?.authentication;
  if (!auth || auth.mode === "public") return undefined;
  if (auth.mode === "primary" && auth.primary.source === "ephemeral") {
    validateStudioProfile(auth.primary.profile);
    return { authProfile: auth.primary.profile, safeSummary: studioAuthSafeSummary(request) };
  }
  if (auth.mode === "account-pair" && auth.accountA.source === "ephemeral" && auth.accountB.source === "ephemeral") {
    validateStudioProfile(auth.accountA.profile);
    validateStudioProfile(auth.accountB.profile);
    return { authProfile: auth.accountA.profile, authProfileSet: { accountA: auth.accountA.profile, accountB: auth.accountB.profile }, safeSummary: studioAuthSafeSummary(request) };
  }
  return undefined;
}

function resolveStudioAuth(vault: CredentialVault, request: DashboardScanCreateRequest): DashboardResolvedAuth {
  const auth = request.studio?.authentication;
  if (!auth || auth.mode === "public") return { safeSummary: { mode: "public" } };
  const actor = (value: ScanStudioAuthActor, role: "single" | "accountA" | "accountB") =>
    value.source === "saved" ? profileFromVault(vault, value.credentialProfileId, request, role) : validatedStudioProfile(value.profile);
  if (auth.mode === "primary") {
    return { authProfile: actor(auth.primary, "single"), safeSummary: studioAuthSafeSummary(request) };
  }
  const accountA = actor(auth.accountA, "accountA");
  const accountB = actor(auth.accountB, "accountB");
  if (accountA.principalId && accountB.principalId && accountA.principalId === accountB.principalId) {
    throw new Error("Account A and Account B must declare different principal IDs.");
  }
  return { authProfile: accountA, authProfileSet: { accountA, accountB }, safeSummary: studioAuthSafeSummary(request) };
}

export function studioAuthSafeSummary(request: DashboardScanCreateRequest): Record<string, unknown> {
  const auth = request.studio?.authentication;
  if (!auth || auth.mode === "public") return { mode: "public", redactionApplied: true };
  const summarize = (value: ScanStudioAuthActor) => value.source === "saved"
    ? { source: "saved", credentialProfileId: value.credentialProfileId }
    : { source: "ephemeral", safeAlias: value.profile.safeAlias ?? value.profile.label, identityVerification: value.profile.identityVerification.mode, headerNames: Object.keys(value.profile.headers), cookieNames: value.profile.cookies.map((cookie) => cookie.name), redactionApplied: true };
  return auth.mode === "primary"
    ? { mode: auth.mode, primary: summarize(auth.primary), redactionApplied: true }
    : { mode: auth.mode, accountA: summarize(auth.accountA), accountB: summarize(auth.accountB), redactionApplied: true };
}

function safeStudioSummary(request: DashboardScanCreateRequest): Record<string, unknown> {
  const studio = request.studio!;
  return {
    version: studio.version,
    scanName: studio.scanName,
    operatorNote: studio.operatorNote,
    authorization: studio.authorization,
    scope: studio.scope,
    authentication: studioAuthSafeSummary(request),
    evidenceLevel: studio.evidenceLevel,
    outputs: studio.outputs,
    workflowSummary: studio.workflowSummary,
    workflows: safeWorkflowConfigurationSummary(studio.workflows),
    retestContext: studio.retestContext
  };
}

function resolveStudioWorkflowPlans(
  request: DashboardScanCreateRequest,
  options: { target: string; scope: Awaited<ReturnType<typeof loadScope>>; authProfileSet?: AuthProfileSet }
): Pick<ScanPlannerInput, "objectPairTesting" | "fieldExposureTesting" | "authorizationMatrixTesting" | "equivalentRouteTesting" | "collectionAuthorizationTesting" | "bulkAuthorizationTesting" | "fileAuthorizationTesting"> {
  const plans: Pick<ScanPlannerInput, "objectPairTesting" | "fieldExposureTesting" | "authorizationMatrixTesting" | "equivalentRouteTesting" | "collectionAuthorizationTesting" | "bulkAuthorizationTesting" | "fileAuthorizationTesting"> = {};
  for (const workflow of request.studio?.workflows ?? []) {
    if (!workflow.enabled) continue;
    switch (workflow.workflowId) {
      case "object-pair": plans.objectPairTesting = planObjectPairTesting(workflow.config, options); break;
      case "field-exposure": plans.fieldExposureTesting = planFieldExposureTesting(workflow.config, options); break;
      case "authorization-matrix": plans.authorizationMatrixTesting = planAuthorizationMatrixTesting(workflow.config, options); break;
      case "equivalent-route": plans.equivalentRouteTesting = planEquivalentRouteTesting(workflow.config, options); break;
      case "collection-authorization": plans.collectionAuthorizationTesting = planCollectionAuthorizationTesting(workflow.config, options); break;
      case "bulk-authorization": plans.bulkAuthorizationTesting = planBulkAuthorizationTesting(workflow.config, options); break;
      case "file-authorization": plans.fileAuthorizationTesting = planFileAuthorizationTesting(workflow.config, options); break;
    }
  }
  return plans;
}

function safeWorkflowConfigurationSummary(workflows: NonNullable<DashboardScanCreateRequest["studio"]>["workflows"]): Array<Record<string, unknown>> {
  return workflows.map((workflow) => ({
    workflowId: workflow.workflowId,
    enabled: workflow.enabled,
    editorMode: workflow.editorMode,
    caseCount: workflowCaseCount(workflow.config),
    configurationHash: createHash("sha256").update(JSON.stringify(workflow.config)).digest("hex")
  }));
}

function workflowCaseCount(config: unknown): number {
  if (!config || typeof config !== "object") return 0;
  const value = config as Record<string, unknown>;
  if (Array.isArray(value.cases)) return value.cases.length;
  for (const key of ["matrices", "routeSets", "collections", "definitions"]) {
    const containers = value[key];
    if (Array.isArray(containers)) return containers.reduce((total, item) => total + (item && typeof item === "object" && Array.isArray((item as Record<string, unknown>).cases) ? ((item as Record<string, unknown>).cases as unknown[]).length : key === "routeSets" && item && typeof item === "object" && Array.isArray((item as Record<string, unknown>).routes) ? ((item as Record<string, unknown>).routes as unknown[]).length : 0), 0);
  }
  return 0;
}

function workflowPlanSummary(plan: { maxRequests: number; schemaVersion: number } | undefined): Record<string, unknown> | undefined {
  return plan ? { schemaVersion: plan.schemaVersion, maxRequests: plan.maxRequests, configured: true } : undefined;
}

function requiredScopeFile(request: DashboardScanCreateRequest): string {
  if (!request.scopeFile) throw new Error("Provide either an inline Scan Studio scope or a scope file.");
  return request.scopeFile;
}

function validatedStudioProfile(profile: AuthProfile): AuthProfile {
  validateStudioProfile(profile);
  return profile;
}

function validateStudioProfile(profile: AuthProfile): void {
  authHeadersForProfile(profile);
  if (Object.keys(profile.headers).length > 24 || profile.cookies.length > 24) throw new Error("AUTH_CONFIGURATION_INVALID: Authentication row count exceeds 24.");
  const bytes = Buffer.byteLength(JSON.stringify(profile), "utf8");
  if (bytes > 32 * 1024) throw new Error("AUTH_CONFIGURATION_INVALID: Authentication profile exceeds 32 KiB.");
}

function profileFromVault(vault: CredentialVault, id: string, request: DashboardScanCreateRequest, role: "single" | "accountA" | "accountB"): AuthProfile {
  const summary = vault.getSummary(id);
  if (!summary) throw new Error(`Credential profile for ${role} is unavailable.`);
  validateCredentialReference(summary, request, role);
  const secret = vault.decryptForUse(id);
  return authProfileFromSecret(summary, secret, role);
}

function validateCredentialReference(summary: CredentialProfileSummary, request: DashboardScanCreateRequest, role: string): void {
  if (!summary.enabled) throw new Error(`Credential profile for ${role} is disabled.`);
  if (summary.projectId && request.projectId && summary.projectId !== request.projectId) throw new Error(`Credential profile for ${role} is not assigned to this project.`);
  if (summary.targetId && request.targetId && summary.targetId !== request.targetId) throw new Error(`Credential profile for ${role} is not assigned to this target.`);
  if (summary.expiresAt && Date.parse(summary.expiresAt) <= Date.now()) throw new Error(`Credential profile for ${role} is expired.`);
}

function authProfileFromSecret(summary: CredentialProfileSummary, secret: CredentialProfileSecret, role: "single" | "accountA" | "accountB"): AuthProfile {
  const headers: Record<string, string> = { ...(secret.headers ?? {}) };
  if (secret.authorizationHeader) headers.Authorization = secret.authorizationHeader;
  if (secret.csrfToken) headers["X-CSRF-Token"] = secret.csrfToken;
  if (secret.tenantHeader) headers["X-Tenant-ID"] = secret.tenantHeader;
  if (secret.sessionHeader) headers["X-Session-ID"] = secret.sessionHeader;
  return {
    label: `${role}:${summary.safeAlias}`,
    safeAlias: summary.safeAlias,
    ...(typeof summary.safeIdentitySummary.principalId === "string" ? { principalId: summary.safeIdentitySummary.principalId } : {}),
    ...(typeof summary.safeIdentitySummary.tenantId === "string" ? { tenantId: summary.safeIdentitySummary.tenantId } : {}),
    ...(typeof summary.safeIdentitySummary.role === "string" ? { role: summary.safeIdentitySummary.role } : {}),
    ...(typeof summary.safeIdentitySummary.accountState === "string" ? { accountState: summary.safeIdentitySummary.accountState } : {}),
    headers,
    cookies: Object.entries(secret.cookies ?? {}).map(([name, value]) => ({ name, value })),
    identityVerification: secret.identityVerification
      ? {
          mode: "required",
          endpoint: secret.identityVerification.endpoint,
          method: "GET",
          principalIdField: secret.identityVerification.principalFieldPath ?? "id",
          ...(secret.identityVerification.tenantFieldPath ? { tenantIdField: secret.identityVerification.tenantFieldPath } : {}),
          ...(secret.identityVerification.roleFieldPath ? { roleField: secret.identityVerification.roleFieldPath } : {}),
          ...(secret.identityVerification.accountStateFieldPath ? { accountStateField: secret.identityVerification.accountStateFieldPath } : {}),
          expectedContentType: "application/json",
          successStatusCodes: [200],
          maxResponseBytes: 8192,
          anonymousMarkers: []
        }
      : { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] },
    notes: [`Loaded from encrypted dashboard credential profile ${summary.id}. Plaintext was not persisted.`]
  };
}

function safeCredentialReference(summary: CredentialProfileSummary | undefined, role: string): Record<string, unknown> {
  if (!summary) return safeCredentialReferenceForId("unknown", role);
  return {
    role,
    id: summary.id,
    safeAlias: summary.safeAlias,
    credentialTypeSummary: summary.credentialTypeSummary,
    enabled: summary.enabled,
    keyVersion: summary.keyVersion,
    safeIdentitySummary: summary.safeIdentitySummary
  };
}

function safeCredentialReferenceForId(id: string, role: string): Record<string, unknown> {
  return { role, id, redactionApplied: true };
}

function safePathLabel(path: string): string {
  return path.split(/[\\/]/).pop() ?? "file";
}
