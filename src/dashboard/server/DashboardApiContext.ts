import { type IncomingMessage,type ServerResponse } from "node:http";
import { ZodError } from "zod";
import { ControlPlaneInfrastructure } from "../../controlPlane/ControlPlaneInfrastructure.js";
import { WorkloadIdentityError } from "../../controlPlane/WorkloadIdentity.js";
import { AppError } from "../../core/errors/AppError.js";
import { LocalSessionManager,SessionError } from "../auth/LocalSession.js";
import type { DashboardPermission,DashboardPrincipal } from "../auth/Permissions.js";
import { PermissionError,ServerSessionManager } from "../auth/ServerSession.js";
import { savedConfigurationSchema } from "../contracts/DashboardSchemas.js";
import { CredentialVault } from "../credentials/CredentialVault.js";
import { ControlledMutationApprovalRepository } from "../db/ControlledMutationApprovalRepository.js";
import { DashboardDatabase,nowIso } from "../db/DashboardDatabase.js";
import { ArtifactRepository,AuditRepository,EventRepository,FindingRepository,ProjectRepository,SavedConfigurationRepository,ScanRepository,TargetRepository } from "../db/DashboardRepositories.js";
import { AdaptiveSecurityService } from "../execution/AdaptiveSecurityService.js";
import { ContinuousAssuranceService } from "../execution/ContinuousAssuranceService.js";
import { ControlledMutationRecoveryService } from "../execution/ControlledMutationRecoveryService.js";
import { EvidenceGovernanceService } from "../execution/EvidenceGovernanceService.js";
import { LiveAcceptanceService } from "../execution/LiveAcceptanceService.js";
import { ProviderAdapterService } from "../execution/ProviderAdapterService.js";
import { ScanExecutionService } from "../execution/ScanExecutionService.js";
import { WorkflowRecoveryService } from "../execution/WorkflowRecoveryService.js";
import { FindingCommandCenterService,FindingCommandError } from "../findings/FindingCommandCenterService.js";
import { HistoricalReportImporter } from "../import/HistoricalReportImporter.js";
import { BackupRestoreService } from "../operations/BackupRestoreService.js";
import { CloudSyncAuthError,CloudSyncService } from "../operations/CloudSyncService.js";
import { DistributedMutationCoordinatorError,DistributedMutationCoordinatorService } from "../operations/DistributedMutationCoordinatorService.js";
import { IntegrationExportService } from "../operations/IntegrationExportService.js";
import { NotificationService } from "../operations/NotificationService.js";
import { OrganizationPermissionError,OrganizationService } from "../operations/OrganizationService.js";
import type { RemoteWorkerOperations } from "../operations/RemoteWorkerOperations.js";
import { RemoteWorkerAuthError } from "../operations/RemoteWorkerService.js";
import { SsoService } from "../operations/SsoService.js";
import { ThirdPartyModuleService } from "../operations/ThirdPartyModuleService.js";
import { ProofPackService } from "../proofPacks/ProofPackService.js";
import { ComparisonService } from "../services/ComparisonService.js";
import { type DashboardPaths } from "../services/DashboardPaths.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import {
HttpError
} from "./DashboardHttpSupport.js";


export const maxJsonBodyBytes = 1024 * 1024;

export interface ApiContext {
  request: IncomingMessage;
  response: ServerResponse;
  url: URL;
  mode: "local" | "server";
  localSessions?: LocalSessionManager | undefined;
  serverSessions?: ServerSessionManager | undefined;
  principal?: DashboardPrincipal | undefined;
  scans: ScanRepository;
  projects: ProjectRepository;
  targets: TargetRepository;
  findings: FindingRepository;
  findingCommandCenter: FindingCommandCenterService;
  events: EventRepository;
  artifacts: ArtifactRepository;
  configurations: SavedConfigurationRepository;
  audit: AuditRepository;
  vault: CredentialVault;
  execution: ScanExecutionService;
  comparison: ComparisonService;
  proofPacks: ProofPackService;
  importer: HistoricalReportImporter;
  paths: DashboardPaths;
  database: DashboardDatabase;
  mutationApprovals: ControlledMutationApprovalRepository;
  mutationRecovery: ControlledMutationRecoveryService;
  workflowRecovery: WorkflowRecoveryService;
  liveAcceptance: LiveAcceptanceService;
  adaptiveSecurity: AdaptiveSecurityService;
  providerAdapters: ProviderAdapterService;
  continuousAssurance: ContinuousAssuranceService;
  evidenceGovernance: EvidenceGovernanceService;
  organizations: OrganizationService;
  notifications: NotificationService;
  remoteWorkers: RemoteWorkerOperations;
  infrastructure: ControlPlaneInfrastructure;
  cloudSync: CloudSyncService;
  backups: BackupRestoreService;
  integrationExports: IntegrationExportService;
  thirdPartyModules: ThirdPartyModuleService;
  sso: SsoService;
  mutationCoordinator?: DistributedMutationCoordinatorService | undefined;
}

export function requireRuntimeSession(context: ApiContext): DashboardPrincipal {
  if (context.mode === "local") {
    context.localSessions?.requireSession(context.request);
    return { mode: "local", userId: "local-operator", login: "local-operator", role: "OWNER", csrfToken: "local" };
  }
  if (!context.serverSessions) throw new SessionError("Server session manager unavailable.");
  return context.serverSessions.requireSession(context.request);
}

export function requireRuntimeMutation(context: ApiContext, csrfToken: string | undefined): DashboardPrincipal {
  if (context.mode === "local") {
    context.localSessions?.requireMutation(context.request, csrfToken);
    return { mode: "local", userId: "local-operator", login: "local-operator", role: "OWNER", csrfToken: "local" };
  }
  if (!context.serverSessions) throw new SessionError("Server session manager unavailable.");
  return context.serverSessions.requireMutation(context.request, csrfToken);
}

export function requirePermission(context: ApiContext, permission: DashboardPermission): void {
  if (!context.principal) throw new SessionError("Dashboard session required.");
  if (context.mode === "local") return;
  context.serverSessions?.requirePermission(context.principal, permission);
}

export function operationalOrganization(context: ApiContext): string {
  return context.url.searchParams.get("organizationId") ?? context.organizations.defaultOrganizationId();
}

export function resourceOrganization(context: ApiContext, permission: import("../operations/OrganizationService.js").OrganizationPermission = "org.read"): string {
  const header = context.request.headers["x-routecairn-organization-id"];
  const organizationId = (typeof header === "string" && header) || context.url.searchParams.get("organizationId") || context.organizations.defaultOrganizationId();
  requireOrg(context, organizationId, permission);
  return organizationId;
}

export function requireOrg(context: ApiContext, organizationId: string, permission: import("../operations/OrganizationService.js").OrganizationPermission): void {
  context.organizations.require(organizationId, context.principal!.userId, permission, context.mode === "local");
}

export function enforceTenantMutationBoundary(context: ApiContext): void {
  const match = /^\/api\/(?<kind>projects|targets|scans|findings|credential-profiles|configurations)\/(?<id>[0-9a-f-]{36})(?:\/|$)/i.exec(context.url.pathname);
  if (!match?.groups?.kind || !match.groups.id) return;
  const kind = ({ projects:"project", targets:"target", scans:"scan", findings:"finding", "credential-profiles":"credential", configurations:"configuration" } as const)[match.groups.kind.toLowerCase() as "projects"|"targets"|"scans"|"findings"|"credential-profiles"|"configurations"];
  requireSelectedResource(context,kind,match.groups.id,"resources.use");
}

export function requireSelectedResource(context:ApiContext,kind:"project"|"target"|"scan"|"finding"|"credential"|"configuration",id:string,permission:import("../operations/OrganizationService.js").OrganizationPermission):string{
  const selected=resourceOrganization(context,permission),actual=context.organizations.resourceOrganization(kind,id);
  if(!actual||actual!==selected)throw new HttpError(404,"Resource not found in the selected organization.");
  return selected;
}

export function requireSelectedResources(context:ApiContext,kind:"project"|"target"|"scan"|"finding"|"credential"|"configuration",ids:readonly string[],permission:import("../operations/OrganizationService.js").OrganizationPermission):void{for(const id of ids)requireSelectedResource(context,kind,id,permission);}

export function requireSelectedComparison(context:ApiContext,id:string):void{
  const organizationId=resourceOrganization(context);
  const row=context.database.db.prepare(`SELECT 1 FROM scan_comparisons c
    JOIN scans older ON older.id=c.older_scan_id
    JOIN scans newer ON newer.id=c.newer_scan_id
    WHERE c.id=? AND c.deleted_at IS NULL AND older.organization_id=? AND newer.organization_id=?`).get(id,organizationId,organizationId);
  if(!row)throw new HttpError(404,"Comparison not found in the selected organization.");
}

export async function assertProviderAdapterExecution(context: ApiContext, request: DashboardScanCreateRequest): Promise<void> {
  try { await context.providerAdapters.assertExecutionBinding(request); }
  catch (error) { throw new HttpError(409, error instanceof Error ? error.message : "PROVIDER_ADAPTER_EXECUTION_REJECTED"); }
}

export function requireCredentialUsePermission(context: ApiContext, request: { credentialProfileId?: string | undefined; credentialProfileAId?: string | undefined; credentialProfileBId?: string | undefined; studio?: { authentication: { mode: string; primary?: { source: string; credentialProfileId?: string }; accountA?: { source: string; credentialProfileId?: string }; accountB?: { source: string; credentialProfileId?: string } } } | undefined }): void {
  const studioUsesSaved = request.studio?.authentication.primary?.source === "saved" || request.studio?.authentication.accountA?.source === "saved" || request.studio?.authentication.accountB?.source === "saved";
  if (request.credentialProfileId || request.credentialProfileAId || request.credentialProfileBId || studioUsesSaved) {
    requirePermission(context, "credentials.use");
    const organizationId=resourceOrganization(context,"resources.use");
    const ids=[request.credentialProfileId,request.credentialProfileAId,request.credentialProfileBId,request.studio?.authentication.primary?.credentialProfileId,request.studio?.authentication.accountA?.credentialProfileId,request.studio?.authentication.accountB?.credentialProfileId].filter((id):id is string=>Boolean(id));
    for(const id of ids)if(!context.vault.getSummary(id,organizationId))throw new HttpError(404,"Credential profile not found in the selected organization.");
  }
}

export function validateScanReferences(context: ApiContext, request: { projectId?: string | undefined; targetId?: string | undefined; target: string }): void {
  const organizationId=resourceOrganization(context,"resources.use");
  if (request.projectId && !context.projects.get(request.projectId,true,organizationId)) throw new HttpError(404, "TARGET_NOT_FOUND: Project not found.");
  if (!request.targetId) return;
  const target = context.targets.get(request.targetId,true,organizationId);
  if (!target) throw new HttpError(404, "TARGET_NOT_FOUND: Target not found.");
  if (request.projectId && target.projectId !== request.projectId) throw new HttpError(400, "TARGET_INVALID: Target is not assigned to the selected project.");
  if (new URL(target.baseOrigin).origin !== new URL(request.target).origin) throw new HttpError(400, "TARGET_INVALID: Target URL does not match the selected target record.");
}

export function validateTargetDefaults(context: ApiContext, request: { projectId?: string | undefined; defaultConfigurationId?: string | undefined; defaultCredentialProfileId?: string | undefined }): void {
  const organizationId=resourceOrganization(context,"resources.use");
  if (request.projectId && !context.projects.get(request.projectId,true,organizationId)) throw new HttpError(404, "Project not found.");
  if (request.defaultConfigurationId && !context.configurations.get(request.defaultConfigurationId,false,organizationId)) throw new HttpError(400, "Default configuration is unavailable or archived.");
  if (request.defaultCredentialProfileId) {
    const credential = context.vault.getSummary(request.defaultCredentialProfileId,organizationId);
    if (!credential || !credential.enabled || ["EXPIRED", "INVALID", "IDENTITY_MISMATCH", "DISABLED"].includes(credential.health.classification)) throw new HttpError(400, "Default credential profile is unavailable or not scan-eligible.");
    if (credential.projectId && request.projectId && credential.projectId !== request.projectId) throw new HttpError(400, "Default credential profile is not assigned to the selected project.");
  }
}

export function identityResultCategories(result: Record<string, unknown>): Record<string, string> {
  const categories: Record<string, string> = {};
  for (const slot of ["primary", "accountA", "accountB"] as const) {
    const value = result[slot];
    if (typeof value === "object" && value !== null && "category" in value && typeof value.category === "string") categories[slot] = value.category;
  }
  return categories;
}

export async function serveEventStream(context: ApiContext, scanId: string): Promise<void> {
  const lastEventId = Number(context.request.headers["last-event-id"] ?? context.url.searchParams.get("after") ?? 0);
  context.response.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive"
  });
  let cursor = Number.isFinite(lastEventId) ? lastEventId : 0;
  let closed = false, paused=false;
  const sendEvents = () => {
    if (closed || paused) return;
    const events = context.events.list(scanId, cursor, 100);
    for (const event of events) {
      cursor = event.seq;
      if(!context.response.write(`id: ${event.seq}\nevent: ${event.eventType}\ndata: ${JSON.stringify(event)}\n\n`)){
        paused=true;context.response.once("drain",()=>{paused=false;sendEvents();});return;
      }
    }
    const scan = context.scans.get(scanId);
    if(events.length===100){setImmediate(sendEvents);return;}
    if (scan && ["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED", "IMPORTED"].includes(scan.status)) {
      close();
      context.response.end();
    }
  };
  const unsubscribe = context.infrastructure.subscribe("scan-events", (partitionKey) => {
    if(partitionKey===scanId)sendEvents();
  });
  const timer = setInterval(() => {
    sendEvents();
    if(!closed)context.response.write(": heartbeat\n\n");
  }, 15_000);
  timer.unref();
  function close(): void { if (closed) return; closed = true; clearInterval(timer); unsubscribe(); }
  context.request.on("close", close);
  sendEvents();
}

export function routeTemplate(pathname: string): string {
  return pathname.replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, ":id").replace(/\/[0-9]+(?=\/|$)/g, "/:number").slice(0, 200);
}

export function normalizeSavedConfiguration(parsed: ReturnType<typeof savedConfigurationSchema.parse>) {
  return {
    name: parsed.name,
    description: parsed.description,
    targetTemplate: parsed.targetTemplate,
    profile: parsed.profile,
    modules: parsed.modules,
    limits: parsed.limits,
    scopeSettings: parsed.scopeSettings,
    browserPolicySettings: parsed.browserPolicySettings,
    evidenceLevel: parsed.evidenceLevel,
    workflowRefs: parsed.workflowRefs,
    expectedVersion: parsed.expectedVersion,
    changeSummary: parsed.changeSummary
  };
}

export const mutableSettingDefaults = {
  defaultProfile: "quick",
  defaultEvidenceLevel: "normal",
  defaultRateLimitPerSecond: 4,
  defaultConcurrency: 3,
  retentionDays: 90,
  queueCapacity: 20,
  workerMemoryMb: 768,
  workerCpuTimeMs: 900_000,
  workerWallClockMs: 1_200_000,
  workerOutputQuotaMb: 512,
  workerTempQuotaMb: 256,
  workerHeartbeatTimeoutMs: 15_000,
  workerCleanupGraceMs: 135_000,
  workerForceKillGraceMs: 5_000,
  workerCrashLoopLimit: 3,
  workerCrashLoopWindowMs: 300_000
} as const;

export function mutableSettings(context: ApiContext): Record<string, { value: unknown; defaultValue: unknown; rowVersion: number; source: "database" | "default"; updatedAt?: string }> {
  const rows = context.database.db.prepare("SELECT key, value_json, row_version, updated_at FROM dashboard_settings").all() as Array<{ key: string; value_json: string; row_version: number; updated_at: string }>;
  const stored = new Map(rows.map((row) => [row.key, row]));
  return Object.fromEntries(Object.entries(mutableSettingDefaults).map(([key, defaultValue]) => {
    const row = stored.get(key);
    return [key, row ? { value: JSON.parse(row.value_json), defaultValue, rowVersion: row.row_version, source: "database", updatedAt: row.updated_at } : { value: defaultValue, defaultValue, rowVersion: 1, source: "default" }];
  }));
}

export function settingValue(context: ApiContext, key: keyof typeof mutableSettingDefaults, fallback: number): number {
  const setting = mutableSettings(context)[key];
  return typeof setting?.value === "number" ? setting.value : fallback;
}

export function environmentSettings(context: ApiContext): Record<string, unknown> {
  return {
    serverMode: { classification: "restart-required", source: "environment", configured: context.mode === "server" },
    publicOrigin: { classification: "restart-required", source: "environment", configured: Boolean(process.env.ROUTECAIRN_PUBLIC_ORIGIN) },
    trustProxy: { classification: "restart-required", source: "environment", configured: process.env.ROUTECAIRN_TRUST_PROXY === "true" },
    masterKey: { classification: "offline-sensitive", source: "environment", configured: context.vault.status().enabled },
    masterKeyVersion: { classification: "offline-sensitive", source: "environment", value: context.vault.status().keyVersion ?? "not configured" },
    distributedMutationCoordinator: { classification: "restart-required", source: "environment", configured: Boolean(context.mutationCoordinator) }
  };
}

export function updateSettings(context: ApiContext, values: Record<string, unknown>, expectedVersions: Record<string, number>, actor?: string): void {
  context.database.transaction(() => {
    for (const [key, value] of Object.entries(values)) {
      if (!(key in mutableSettingDefaults)) throw new Error(`Unknown mutable setting: ${key}`);
      const current = context.database.db.prepare("SELECT row_version FROM dashboard_settings WHERE key = ?").get(key) as { row_version: number } | undefined;
      const expected = expectedVersions[key];
      if (current && expected !== undefined && current.row_version !== expected) throw new Error(`SETTINGS_CONFLICT: ${key} changed concurrently.`);
      if (current) context.database.db.prepare("UPDATE dashboard_settings SET value_json = ?, row_version = row_version + 1, updated_by = ?, updated_at = ? WHERE key = ?").run(JSON.stringify(value), actor ?? null, nowIso(), key);
      else context.database.db.prepare("INSERT INTO dashboard_settings (key, value_json, row_version, updated_by, updated_at) VALUES (?, ?, 1, ?, ?)").run(key, JSON.stringify(value), actor ?? null, nowIso());
    }
  });
}

export function resetSettings(context: ApiContext, keys: string[]): void {
  if (keys.length === 0) context.database.db.prepare("DELETE FROM dashboard_settings").run();
  else context.database.transaction(() => { for (const key of keys) context.database.db.prepare("DELETE FROM dashboard_settings WHERE key = ?").run(key); });
}

export async function readJson(request: IncomingMessage, limit = maxJsonBodyBytes): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) throw new HttpError(413, "JSON body too large.");
    chunks.push(buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8") || "{}";
  return JSON.parse(raw);
}

export function sendJson(response: ServerResponse, statusCode: number, value: unknown): void {
  response.statusCode = statusCode;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(JSON.stringify(value));
}

export function redirect(response: ServerResponse, location: string): void {
  response.statusCode = 302;
  response.setHeader("location", location);
  response.setHeader("cache-control", "no-store");
  response.end();
}

export function sendError(response: ServerResponse, error: unknown): void {
  const message = error instanceof Error ? error.message : "Dashboard request failed.";
  const conflictCode = /^(PROJECT_CONFLICT|TARGET_CONFLICT|CONFIGURATION_CONFLICT|SETTINGS_CONFLICT|FINAL_OWNER_REQUIRED|CREDENTIAL_IN_USE|CREDENTIAL_DEPENDENCY_IMPACT_CHANGED|CREDENTIAL_CHANGED_AFTER_QUEUE|CREDENTIAL_READINESS_BLOCKED|CREDENTIAL_READINESS_BLOCKED_AT_EXECUTION|RECOVERY_ALREADY_RUNNING|RECOVERY_CHECKPOINT_CHANGED|RECOVERY_NOT_REQUIRED|RECOVERY_TARGET_MISMATCH|RECOVERY_SERVICE_STOPPING):?/.exec(message)?.[1];
  const statusCode = error instanceof DistributedMutationCoordinatorError ? error.statusCode : conflictCode ? 409 : error instanceof HttpError || error instanceof FindingCommandError ? error.statusCode : error instanceof PermissionError || error instanceof OrganizationPermissionError ? 403 : error instanceof SessionError || error instanceof RemoteWorkerAuthError || error instanceof WorkloadIdentityError || error instanceof CloudSyncAuthError ? 401 : error instanceof ZodError || error instanceof AppError ? 400 : 500;
  if (error instanceof DistributedMutationCoordinatorError) { sendJson(response, statusCode, { error: "Mutation coordination request rejected.", code: error.code }); return; }
  if (error instanceof ZodError) {
    const workflowError = error.issues.some((issue) => issue.path.map(String).includes("workflows"));
    sendJson(response, statusCode, { error: workflowError ? "Workflow validation failed." : "Request validation failed.", code: workflowError ? "WORKFLOW_CASE_INVALID" : "REQUEST_VALIDATION_FAILED", diagnostics: error.issues.map((issue) => ({ path: issue.path.map(String), message: issue.message })) });
    return;
  }
  if (error instanceof AppError) {
    sendJson(response, statusCode, { error: message, code: workflowErrorCategory(error.code), coreCode: error.code });
    return;
  }
  if (error instanceof FindingCommandError) {
    sendJson(response, statusCode, { error: message, code: error.code });
    return;
  }
  if (conflictCode) {
    sendJson(response, statusCode, { error: message.replace(`${conflictCode}:`, "").trim(), code: conflictCode });
    return;
  }
  sendJson(response, statusCode, { error: message });
}

export function workflowErrorCategory(code: string): string {
  if (/FIELD.*(?:PATH|SELECTOR)|OBJECT_FIELD/.test(code)) return "WORKFLOW_FIELD_PATH_INVALID";
  if (/AUTH_PAIR|AUTH_PROFILE|UNKNOWN_ACTOR|PRINCIPAL/.test(code)) return "WORKFLOW_ACTOR_MISSING";
  if (/IDENTIT/.test(code)) return "WORKFLOW_IDENTITY_REQUIRED";
  if (/METHOD|UNSAFE_ENDPOINT|POST_SAFETY|SAFETY/.test(code)) return "WORKFLOW_METHOD_UNSAFE";
  if (/PLACEHOLDER/.test(code)) return "WORKFLOW_PLACEHOLDER_INVALID";
  if (/DUPLICATE|IDENTICAL_OBJECT/.test(code)) return "WORKFLOW_DUPLICATE_OBJECT";
  if (/COMPLETENESS/.test(code)) return "WORKFLOW_COMPLETENESS_INVALID";
  if (/ORIGIN|SIGNED_URL/.test(code)) return "WORKFLOW_FILE_ORIGIN_INVALID";
  if (/(?:OBJECT_PAIR|FIELD_EXPOSURE|AUTHORIZATION_MATRIX|EQUIVALENT_ROUTE|COLLECTION_AUTHORIZATION|BULK_AUTHORIZATION|FILE_AUTHORIZATION)/.test(code)) return "WORKFLOW_CASE_INVALID";
  return code.startsWith("SCAN_PLAN") || code.includes("MODULE") ? "WORKFLOW_TYPE_INVALID" : code;
}
