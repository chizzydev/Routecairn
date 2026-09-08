import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID, createHash } from "node:crypto";
import { createReadStream, existsSync, realpathSync, statSync } from "node:fs";
import { mkdirSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { DashboardDatabase, nowIso } from "../db/DashboardDatabase.js";
import { ArtifactRepository, AuditRepository, EventRepository, FindingRepository, ProjectRepository, SavedConfigurationRepository, ScanRepository, TargetRepository } from "../db/DashboardRepositories.js";
import { ControlledMutationApprovalRepository } from "../db/ControlledMutationApprovalRepository.js";
import { LocalSessionManager, SessionError } from "../auth/LocalSession.js";
import { PermissionError, ServerSessionManager, type ServerRuntimeSecurity } from "../auth/ServerSession.js";
import type { DashboardPermission, DashboardPrincipal } from "../auth/Permissions.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { credentialDependencyAcknowledgementSchema, credentialHealthTestSchema, credentialMetadataSchema, credentialProfileSchema, credentialRenewalSchema, credentialReplacementSchema, dashboardScanCreateSchema, compareRequestSchema, dashboardSettingsUpdateSchema, importReportSchema, loginSchema, projectSchema, proofPackCreateSchema, savedConfigurationSchema, targetSchema, userCreateSchema, userUpdateSchema } from "../contracts/DashboardSchemas.js";
import { ScanExecutionService } from "../execution/ScanExecutionService.js";
import { ComparisonService } from "../services/ComparisonService.js";
import { HistoricalReportImporter } from "../import/HistoricalReportImporter.js";
import { ProofPackService } from "../proofPacks/ProofPackService.js";
import { AssistedReviewService } from "../reviews/AssistedReviewService.js";
import { isLoopbackHost, resolveDashboardPaths, type DashboardPaths } from "../services/DashboardPaths.js";
import { routeCairnCapabilityRegistry } from "../../core/planning/RouteCairnCapabilityRegistry.js";
import { CredentialVault, parseVaultKey } from "../credentials/CredentialVault.js";
import { RetestTemplateVault } from "../retests/RetestTemplateVault.js";
import { inspectImageDimensions } from "../security/ImageDimensions.js";
import { ZodError } from "zod";
import { AppError } from "../../core/errors/AppError.js";
import { FindingCommandCenterService, FindingCommandError, type FindingQuery } from "../findings/FindingCommandCenterService.js";
import {
  findingBulkReviewSchema,
  findingBulkRemediationSchema,
  findingBulkNoteSchema,
  findingNoteSchema,
  findingRemediationSchema,
  findingRetestSchema,
  findingReviewSchema,
  findingSeveritySchema,
  findingVerifySchema,
  savedFindingViewDeleteSchema,
  savedFindingViewDefaultSchema,
  savedFindingViewSchema
} from "../contracts/FindingSchemas.js";
import type { ReviewStatus } from "../types/DashboardTypes.js";
import { capabilityParityManifest, validateCapabilityParityManifest } from "../admin/CapabilityParityManifest.js";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { controlledMutationApprovalSchema } from "../contracts/ControlledMutationSchemas.js";
import { controlledMutationRecoverySchema } from "../contracts/ControlledMutationRecoverySchemas.js";
import { ControlledMutationRecoveryService } from "../execution/ControlledMutationRecoveryService.js";
import { WorkflowRecoveryService, workflowRecoveryRequestSchema } from "../execution/WorkflowRecoveryService.js";
import { productionMutationApprovalSchema } from "../contracts/ProductionMutationApprovalSchemas.js";
import { productionMutationCaseSchema } from "../contracts/ProductionMutationCaseSchemas.js";
import { compileProductionMutationCase, productionMutationPlanIdentity } from "../execution/ProductionMutationCaseCompiler.js";
import { LiveAcceptanceService } from "../execution/LiveAcceptanceService.js";
import { liveAcceptanceExecuteSchema, liveAcceptancePlanInputSchema, liveAcceptanceReviewSchema } from "../contracts/LiveAcceptanceSchemas.js";
import { advancedEngineCatalog, advancedEngineValidationRequestSchema, loadAdvancedEngineCatalog, validateAdvancedEngineInput } from "../contracts/AdvancedEngineSchemas.js";
import { AdaptiveSecurityService } from "../execution/AdaptiveSecurityService.js";
import { adaptiveAnalyzeSchema, adaptiveBaselineSchema, adaptivePolicyInputSchema, adaptiveRecommendationDecisionSchema, adaptiveRecommendationLinkSchema } from "../contracts/AdaptiveSecuritySchemas.js";
import { providerAdapterInputSchema, providerAdapterReviewSchema, providerAdapterStateSchema } from "../contracts/ProviderAdapterSchemas.js";
import { ProviderAdapterService } from "../execution/ProviderAdapterService.js";
import { ContinuousAssuranceService } from "../execution/ContinuousAssuranceService.js";
import { EvidenceGovernanceService } from "../execution/EvidenceGovernanceService.js";
import { ScanComparisonService } from "../comparisons/ScanComparisonService.js";
import { continuousAssuranceNotificationAckSchema, continuousAssurancePolicyInputSchema, continuousAssuranceReviewSchema, continuousAssuranceRunSchema, continuousAssuranceStateSchema, continuousAssuranceTokenRotationSchema, deploymentTriggerSchema, evidenceGovernancePolicySchema, evidenceExportSchema, evidencePurgeSchema } from "../contracts/ContinuousAssuranceSchemas.js";

export interface DashboardServerOptions {
  host?: string;
  port?: number;
  dataDir?: string;
  uiDistDir?: string;
  mode?: "local" | "server";
  publicOrigin?: string;
  sessionSecret?: string;
  trustProxy?: boolean;
  masterKey?: string;
  masterKeyVersion?: string;
}

export interface DashboardServerHandle {
  url: string;
  bootstrapUrl?: string;
  close(): Promise<void>;
}

const maxJsonBodyBytes = 1024 * 1024;

export async function startDashboardServer(options: DashboardServerOptions = {}): Promise<DashboardServerHandle> {
  const host = options.host ?? "127.0.0.1";
  const mode = options.mode ?? (process.env.ROUTECAIRN_DASHBOARD_MODE === "server" ? "server" : "local");
  const serverSecurity = validateDashboardStartup({ ...options, host, mode });
  if (mode === "local" && !isLoopbackHost(host)) {
    throw new Error("RouteCairn Dashboard refuses non-loopback binding in local mode.");
  }
  const paths = resolveDashboardPaths(options.dataDir);
  mkdirSync(paths.reportsDir, { recursive: true });
  mkdirSync(paths.artifactsDir, { recursive: true });
  mkdirSync(paths.proofPacksDir, { recursive: true });
  mkdirSync(paths.mutationJournalDir, { recursive: true });
  mkdirSync(paths.workersDir, { recursive: true });
  const database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  database.recoverInterruptedScans();

  const localSessions = mode === "local" ? new LocalSessionManager() : undefined;
  const serverSessions = mode === "server" && serverSecurity ? new ServerSessionManager(database, serverSecurity) : undefined;
  if (serverSessions && !serverSessions.hasEnabledOwner()) {
    throw new Error("RouteCairn Dashboard server mode requires a first owner. Run routecairn dashboard user create-owner.");
  }
  const scans = new ScanRepository(database);
  const projects = new ProjectRepository(database);
  const targets = new TargetRepository(database);
  const findings = new FindingRepository(database);
  const events = new EventRepository(database);
  const artifacts = new ArtifactRepository(database);
  const configurations = new SavedConfigurationRepository(database);
  const audit = new AuditRepository(database);
  const vaultKey = parseVaultKey(options.masterKey ?? process.env.ROUTECAIRN_MASTER_KEY, options.masterKeyVersion ?? process.env.ROUTECAIRN_MASTER_KEY_VERSION ?? "1");
  const vault = new CredentialVault(database, vaultKey);
  const mutationApprovals = new ControlledMutationApprovalRepository(database);
  const mutationRecovery = new ControlledMutationRecoveryService(database, paths, targets, vault);
  const workflowRecovery = new WorkflowRecoveryService(database, paths, targets, vault);
  const retestTemplates = new RetestTemplateVault(database.db, vaultKey);
  const findingCommandCenter = new FindingCommandCenterService(database, retestTemplates);
  const execution = new ScanExecutionService(database, paths, vault, retestTemplates);
  const liveAcceptance = new LiveAcceptanceService(database, execution, vaultKey);
  const adaptiveSecurity = new AdaptiveSecurityService(database);
  const providerAdapters = new ProviderAdapterService(database, execution, vault, vaultKey);
  const comparison = new ComparisonService(database);
  const evidenceGovernance = new EvidenceGovernanceService(database, paths, vaultKey);
  const continuousAssurance = new ContinuousAssuranceService(database, paths, execution, providerAdapters, new ScanComparisonService(database), evidenceGovernance);
  const proofPacks = new ProofPackService(database, paths);
  const importer = new HistoricalReportImporter(database, paths);
  const uiDistDir = options.uiDistDir ?? resolve("apps", "dashboard-ui", "dist");

  const server = createServer(async (request, response) => {
    try {
      setSecurityHeaders(response);
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? `${host}:${options.port ?? 0}`}`);
      if (request.method === "POST" && url.pathname === "/api/session/bootstrap") {
        const body = await readJson(request);
        const token = typeof body === "object" && body !== null && "token" in body && typeof body.token === "string" ? body.token : undefined;
        if (!localSessions) throw new HttpError(404, "Local bootstrap is unavailable in server mode.");
        const session = localSessions.exchange(token, response);
        audit.append({ action: "LOGIN_SUCCESS", resourceType: "SESSION", summary: "Local bootstrap session established." });
        sendJson(response, 200, session);
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/auth/login") {
        if (!serverSessions) throw new HttpError(404, "Server login is unavailable in local mode.");
        const parsed = loginSchema.parse(await readJson(request));
        const session = await serverSessions.login({ ...parsed, request, response });
        audit.append({ actorLabel: session.user.id, action: "LOGIN_SUCCESS", resourceType: "SESSION", summary: "Server dashboard login succeeded." });
        sendJson(response, 200, session);
        return;
      }
      if (request.method === "POST" && url.pathname === "/api/continuous-assurance/deployments") {
        const parsed = deploymentTriggerSchema.parse(await readJson(request));
        const authorization = request.headers.authorization;
        const headerToken = request.headers["x-routecairn-trigger-token"];
        const token = typeof authorization === "string" && authorization.startsWith("Bearer ") ? authorization.slice(7) : typeof headerToken === "string" ? headerToken : "";
        if (token.length < 32) throw new HttpError(401, "Invalid continuous assurance trigger.");
        try { const result=await continuousAssurance.deployment(parsed.policyId, token, parsed.deploymentId, parsed.buildFingerprint); audit.append({action:"CONTINUOUS_ASSURANCE_DEPLOYMENT_ACCEPTED",resourceType:"CONTINUOUS_ASSURANCE_POLICY",resourceId:parsed.policyId,summary:"Authenticated deployment trigger accepted.",metadata:{deploymentId:parsed.deploymentId,buildFingerprint:parsed.buildFingerprint,idempotentReplay:result.idempotentReplay}}); sendJson(response, 202, result); }
        catch (error) { if (error instanceof Error && ["CONTINUOUS_ASSURANCE_TRIGGER_REJECTED","CONTINUOUS_ASSURANCE_POLICY_NOT_FOUND"].includes(error.message)) throw new HttpError(401, "Invalid continuous assurance trigger."); throw error; }
        return;
      }

      if (url.pathname.startsWith("/api/")) {
        await handleApi({
          request,
          response,
          url,
          localSessions,
          serverSessions,
          mode,
          scans,
          projects,
          targets,
          findings,
          findingCommandCenter,
          events,
          artifacts,
          configurations,
          audit,
          vault,
          execution,
          comparison,
          proofPacks,
          importer,
          paths
          ,database
          ,mutationApprovals
          ,mutationRecovery
          ,workflowRecovery
          ,liveAcceptance
          ,adaptiveSecurity
          ,providerAdapters
          ,continuousAssurance
          ,evidenceGovernance
        });
        return;
      }

      serveStatic(response, uiDistDir, url.pathname);
    } catch (error) {
      sendError(response, error);
    }
  });

  await new Promise<void>((resolveListen) => server.listen(options.port ?? 0, host, resolveListen));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Dashboard server did not return a TCP address.");
  const url = `http://${host}:${address.port}`;
  return {
    url,
    ...(localSessions ? { bootstrapUrl: localSessions.bootstrapUrl(url) } : {}),
    close: async () => {
      continuousAssurance.shutdown();
      await execution.shutdown();
      await workflowRecovery.shutdown();
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      database.close();
    }
  };
}

function validateDashboardStartup(options: Required<Pick<DashboardServerOptions, "host" | "mode">> & DashboardServerOptions): ServerRuntimeSecurity | undefined {
  if (options.mode === "server") {
    const publicOrigin = options.publicOrigin ?? process.env.ROUTECAIRN_PUBLIC_ORIGIN;
    const sessionSecret = options.sessionSecret ?? process.env.ROUTECAIRN_SESSION_SECRET;
    const trustProxy = options.trustProxy ?? process.env.ROUTECAIRN_TRUST_PROXY === "true";
    const developmentInsecureHttp = process.env.ROUTECAIRN_DASHBOARD_INSECURE_HTTP === "true";
    if (!publicOrigin) throw new Error("RouteCairn Dashboard server mode requires ROUTECAIRN_PUBLIC_ORIGIN.");
    let parsed: URL;
    try {
      parsed = new URL(publicOrigin);
    } catch {
      throw new Error("RouteCairn Dashboard server mode public origin is malformed.");
    }
    if (parsed.protocol !== "https:" && !(developmentInsecureHttp && isLoopbackHost(parsed.hostname))) throw new Error("RouteCairn Dashboard server mode requires an HTTPS public origin.");
    if (!sessionSecret || sessionSecret.length < 32) throw new Error("RouteCairn Dashboard server mode requires a strong ROUTECAIRN_SESSION_SECRET.");
    if (!trustProxy && !isLoopbackHost(options.host)) throw new Error("RouteCairn Dashboard server mode requires trusted reverse-proxy configuration before external binding.");
    return { publicOrigin: parsed.origin, sessionSecret, trustProxy, developmentInsecureHttp };
  }
  return undefined;
}

interface ApiContext {
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
}

async function handleApi(context: ApiContext): Promise<void> {
  const { request } = context;
  if (request.method === "POST" && context.url.pathname === "/api/auth/csrf") {
    const csrfToken = context.mode === "local"
      ? context.localSessions?.refreshCsrf(request)
      : context.serverSessions?.refreshCsrf(request);
    if (!csrfToken) throw new SessionError("Dashboard session required.");
    sendJson(context.response, 200, { csrfToken });
    return;
  }
  if (request.method === "GET") {
    const principal = requireRuntimeSession(context);
    await handleApiGet({ ...context, principal });
    return;
  }

  const csrf = request.headers["x-csrf-token"];
  const principal = requireRuntimeMutation(context, typeof csrf === "string" ? csrf : undefined);
  await handleApiMutation({ ...context, principal });
}

function requireRuntimeSession(context: ApiContext): DashboardPrincipal {
  if (context.mode === "local") {
    context.localSessions?.requireSession(context.request);
    return { mode: "local", userId: "local-operator", login: "local-operator", role: "OWNER", csrfToken: "local" };
  }
  if (!context.serverSessions) throw new SessionError("Server session manager unavailable.");
  return context.serverSessions.requireSession(context.request);
}

function requireRuntimeMutation(context: ApiContext, csrfToken: string | undefined): DashboardPrincipal {
  if (context.mode === "local") {
    context.localSessions?.requireMutation(context.request, csrfToken);
    return { mode: "local", userId: "local-operator", login: "local-operator", role: "OWNER", csrfToken: "local" };
  }
  if (!context.serverSessions) throw new SessionError("Server session manager unavailable.");
  return context.serverSessions.requireMutation(context.request, csrfToken);
}

function requirePermission(context: ApiContext, permission: DashboardPermission): void {
  if (!context.principal) throw new SessionError("Dashboard session required.");
  if (context.mode === "local") return;
  context.serverSessions?.requirePermission(context.principal, permission);
}

async function handleApiGet(context: ApiContext): Promise<void> {
  const { response, url, scans, projects, targets, findingCommandCenter, comparison, events, artifacts, paths } = context;
  const assistedReview = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/assisted-review$/.exec(url.pathname);
  if (assistedReview?.groups?.id) {
    requirePermission(context, "findings.read");
    try { sendJson(response, 200, new AssistedReviewService(context.database, paths).get(assistedReview.groups.id)); }
    catch (error) { if (error instanceof Error && error.message === "ASSISTED_REVIEW_NOT_FOUND") sendJson(response, 404, { error: "No assisted review exists for this scan." }); else throw error; }
    return;
  }
  if (url.pathname === "/api/session") {
    sendJson(response, 200, { ok: true, principal: context.principal });
    return;
  }
  if (url.pathname === "/api/auth/session") {
    sendJson(response, 200, { ok: true, principal: context.principal });
    return;
  }
  if (url.pathname === "/api/users") {
    requirePermission(context, "users.manage");
    sendJson(response, 200, { mode: context.mode, users: context.serverSessions?.listUsers() ?? [] });
    return;
  }
  if (url.pathname === "/api/overview") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, scans.overview());
    return;
  }
  if (url.pathname === "/api/capabilities") {
    const registry = routeCairnCapabilityRegistry();
    sendJson(response, 200, {
      ...registry,
      modules: Object.values(registry.modules),
      advancedEngineDashboard: [
        ...advancedEngineCatalog.map(({ templateFile: _templateFile, ...engine }) => ({ ...engine, dashboardOperation: "GUIDED_BUILDER" as const })),
        { id: "live-target-acceptance", displayName: "Live Target Acceptance", description: "Encrypted, reviewed multi-lane staging and production acceptance orchestration.", dashboardOperation: "MANAGED_WORKSPACE" as const, safety: "Mutation and recovery evidence must originate from separately approved controlled-mutation scans." },
        { id: "fixture-provider-adapters", displayName: "Fixture & Provider Adapters", description: "Encrypted reusable provider fixtures and exact advanced-engine contracts.", dashboardOperation: "MANAGED_WORKSPACE" as const, safety: "Every reviewed adapter is target-, credential-version-, configuration-, budget-, and cleanup-bound; real payments remain forbidden." }
        ,{ id: "continuous-assurance", displayName: "Continuous Assurance & Evidence Governance", description: "Reviewed scheduled and deployment-triggered reassessment with exact remediation gates and encrypted retention controls.", dashboardOperation: "MANAGED_WORKSPACE" as const, safety: "Automation cannot add mutation authority; expired authorization, changed adapters, credentials, target scope, unresolved cleanup, or incomparable cases block a passing gate." }
      ]
    });
    return;
  }
  if (url.pathname === "/api/advanced-engines/catalog") {
    requirePermission(context, "scans.create");
    const target = url.searchParams.get("target") ?? undefined;
    if (target) {
      let parsed: URL;
      try { parsed = new URL(target); }
      catch { throw new HttpError(400, "Invalid advanced-engine template target."); }
      if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) throw new HttpError(400, "Invalid advanced-engine template target.");
    }
    sendJson(response, 200, { engines: await loadAdvancedEngineCatalog(target) });
    return;
  }
  if (url.pathname === "/api/live-acceptance/plans") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { available: context.liveAcceptance.available(), plans: context.liveAcceptance.listPlans() });
    return;
  }
  if (url.pathname === "/api/live-acceptance/runs") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { runs: context.liveAcceptance.listRuns() });
    return;
  }
  if (url.pathname === "/api/provider-adapters") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { available: context.providerAdapters.available(), adapters: context.providerAdapters.list(url.searchParams.get("targetId") ?? undefined) });
    return;
  }
  if (url.pathname === "/api/continuous-assurance") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { policies: context.continuousAssurance.list(), notifications: context.continuousAssurance.notifications() });
    return;
  }
  const baselineCases = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/workflow-cases$/.exec(url.pathname);
  if (baselineCases?.groups?.id) {
    requirePermission(context, "scans.read");
    const cases=context.database.db.prepare("SELECT workflow_id workflowId,safe_case_alias safeCaseAlias,safe_case_fingerprint caseFingerprint,execution_state executionState,request_transmitted requestTransmitted,matched_expectation matchedExpectation,evidence_strength evidenceStrength FROM scan_workflow_case_executions WHERE scan_id=? ORDER BY workflow_id,safe_case_alias LIMIT 500").all(baselineCases.groups.id) as Array<Record<string,unknown>&{requestTransmitted:number;matchedExpectation:number|null}>;
    sendJson(response,200,{cases:cases.map(item=>({...item,requestTransmitted:Boolean(item.requestTransmitted),matchedExpectation:item.matchedExpectation===null?null:Boolean(item.matchedExpectation)}))});return;
  }
  const continuousPolicy = /^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (continuousPolicy?.groups?.id) {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { policy: context.continuousAssurance.get(continuousPolicy.groups.id) });
    return;
  }
  if (url.pathname === "/api/evidence-governance") {
    requirePermission(context, "artifacts.download");
    sendJson(response, 200, { available: context.evidenceGovernance.available(), policy: context.evidenceGovernance.policy(), exports: context.evidenceGovernance.listExports(), purgePreview: context.evidenceGovernance.purgePreview() });
    return;
  }
  const evidenceDownload = /^\/api\/evidence-governance\/exports\/(?<id>[0-9a-f-]+)\/download$/.exec(url.pathname);
  if (evidenceDownload?.groups?.id) {
    requirePermission(context, "artifacts.download");
    const item = context.evidenceGovernance.downloadableExport(evidenceDownload.groups.id);
    response.statusCode = 200;
    response.setHeader("Content-Type", item.contentType);
    response.setHeader("Content-Disposition", `attachment; filename="${item.name}"`);
    response.setHeader("Cache-Control", "no-store");
    createReadStream(item.path).pipe(response);
    return;
  }
  const providerAdapter = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (providerAdapter?.groups?.id) {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { adapter: context.providerAdapters.get(providerAdapter.groups.id) });
    return;
  }
  const adaptiveTarget = /^\/api\/adaptive-security\/targets\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (adaptiveTarget?.groups?.id) {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { adaptiveSecurity: context.adaptiveSecurity.state(adaptiveTarget.groups.id) });
    return;
  }
  const liveAcceptancePlan = /^\/api\/live-acceptance\/plans\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (liveAcceptancePlan?.groups?.id) {
    requirePermission(context, "scans.create");
    sendJson(response, 200, { plan: context.liveAcceptance.getPlan(liveAcceptancePlan.groups.id) });
    return;
  }
  const liveAcceptanceRun = /^\/api\/live-acceptance\/runs\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (liveAcceptanceRun?.groups?.id) {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { run: context.liveAcceptance.getRun(liveAcceptanceRun.groups.id) });
    return;
  }
  if (url.pathname === "/api/admin/capability-parity") {
    requirePermission(context, "settings.manage");
    sendJson(response, 200, { entries: capabilityParityManifest, valid: validateCapabilityParityManifest().length === 0 });
    return;
  }
  const recoveryStatus = /^\/api\/controlled-mutations\/recovery\/(?<jobId>[0-9a-f-]+)$/.exec(url.pathname);
  if (recoveryStatus?.groups?.jobId) {
    requirePermission(context, "controlledMutation.recover");
    const approval = context.mutationApprovals.getByRecoveryJob(recoveryStatus.groups.jobId);
    if (!approval) throw new HttpError(404, "Controlled mutation recovery job not found.");
    sendJson(response, 200, { recoveryJob: approval });
    return;
  }
  const approvalDetail = /^\/api\/controlled-mutations\/approvals\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (approvalDetail?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const approval = context.mutationApprovals.get(approvalDetail.groups.id);
    if (!approval) throw new HttpError(404, "Controlled mutation approval not found.");
    sendJson(response, 200, { approval });
    return;
  }
  if (url.pathname === "/api/offensive/status") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, await readMutationCleanupStatus(paths.mutationJournalDir, paths.mutationJournalRegistryPath));
    return;
  }
  if (url.pathname === "/api/workflow-mutations/status") {
    requirePermission(context, "controlledMutation.recover");
    sendJson(response, 200, await context.workflowRecovery.inventory());
    return;
  }
  if (url.pathname === "/api/vault/status") {
    requirePermission(context, "credentials.readSummary");
    sendJson(response, 200, context.vault.status());
    return;
  }
  if (url.pathname === "/api/credential-profiles") {
    requirePermission(context, "credentials.readSummary");
    sendJson(response, 200, { profiles: context.vault.list() });
    return;
  }
  const credentialDetail = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (credentialDetail?.groups?.id) {
    requirePermission(context, "credentials.readSummary");
    const profile = context.vault.getSummary(credentialDetail.groups.id);
    if (!profile) throw new HttpError(404, "Credential profile not found.");
    sendJson(response, 200, { profile, dependencies: context.vault.dependencies(credentialDetail.groups.id), healthTimeline: context.vault.healthTimeline(credentialDetail.groups.id) });
    return;
  }
  if (url.pathname === "/api/projects") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { projects: projects.list(stringParam(url, "q"), booleanParam(url, "includeArchived") === true) });
    return;
  }
  const project = /^\/api\/projects\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (project?.groups?.id) {
    const item = projects.get(project.groups.id, booleanParam(url, "includeArchived") === true);
    if (!item) throw new HttpError(404, "Project not found.");
    sendJson(response, 200, { project: item, targets: targets.list({ projectId: project.groups.id }), scans: scans.list(25, { projectId: project.groups.id }), comparisons: comparison.list({ projectId: project.groups.id, limit: 20 }), findingIntelligence: findingCommandCenter.intelligence({ projectId: project.groups.id }) });
    return;
  }
  if (url.pathname === "/api/targets") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { targets: targets.list({ projectId: stringParam(url, "projectId"), search: stringParam(url, "q"), includeArchived: booleanParam(url, "includeArchived") === true }) });
    return;
  }
  const target = /^\/api\/targets\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (target?.groups?.id) {
    const item = targets.get(target.groups.id, booleanParam(url, "includeArchived") === true);
    if (!item) throw new HttpError(404, "Target not found.");
    sendJson(response, 200, { target: item, comparisons: comparison.list({ targetId: target.groups.id, limit: 20 }), findingIntelligence: findingCommandCenter.intelligence({ targetId: target.groups.id }) });
    return;
  }
  if (url.pathname === "/api/audit-events") {
    requirePermission(context, "audit.read");
    sendJson(response, 200, { events: context.audit.list({ search: stringParam(url, "q"), action: stringParam(url, "action"), resourceType: stringParam(url, "resourceType"), limit: numberParam(url, "limit", 100) }) });
    return;
  }
  if (url.pathname === "/api/scans") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, {
      scans: scans.list(numberParam(url, "limit", 50), {
        search: stringParam(url, "q"),
        status: scanStatusParam(url),
        profile: stringParam(url, "profile"),
        target: stringParam(url, "target"),
        sort: scanSortParam(url),
        offset: numberParam(url, "offset", 0)
      })
    });
    return;
  }
  if (url.pathname === "/api/comparisons/candidates") {
    requirePermission(context, "comparisons.read");
    sendJson(response, 200, { scans: comparison.candidates(stringParam(url, "targetId")) });
    return;
  }
  if (url.pathname === "/api/comparisons") {
    requirePermission(context, "comparisons.read");
    const targetId = stringParam(url, "targetId"), projectId = stringParam(url, "projectId");
    sendJson(response, 200, { comparisons: comparison.list({ ...(targetId ? { targetId } : {}), ...(projectId ? { projectId } : {}), limit: numberParam(url, "limit", 50) }) });
    return;
  }
  const comparisonDetail = /^\/api\/comparisons\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (comparisonDetail?.groups?.id) {
    requirePermission(context, "comparisons.read");
    const classification = enumParam(url, "classification", ["NEW", "PERSISTING", "CHANGED", "RESOLVED", "NOT_RETESTED", "INCOMPARABLE"] as const);
    const severity = enumParam(url, "severity", ["Critical", "High", "Medium", "Low", "Info"] as const);
    const sort = enumParam(url, "sort", ["classification", "severity", "module", "coverage", "title", "created"] as const);
    const direction = enumParam(url, "direction", ["asc", "desc"] as const);
    const regression = booleanParam(url, "regression");
    sendJson(response, 200, comparison.get(comparisonDetail.groups.id, { page: numberParam(url, "page", 1), pageSize: numberParam(url, "pageSize", 25), ...(classification ? { classification } : {}), ...(regression === undefined ? {} : { regression }), ...(severity ? { severity } : {}), ...(stringParam(url, "module") ? { module: stringParam(url, "module")! } : {}), ...(stringParam(url, "coverage") ? { coverage: stringParam(url, "coverage")! } : {}), ...(sort ? { sort } : {}), ...(direction ? { direction } : {}) }));
    return;
  }
  const comparisonExport = /^\/api\/comparisons\/(?<id>[0-9a-f-]+)\/export\/(?<format>json|markdown)$/.exec(url.pathname);
  if (comparisonExport?.groups?.id && comparisonExport.groups.format) {
    requirePermission(context, "comparisons.export");
    const format = comparisonExport.groups.format as "json" | "markdown";
    response.statusCode = 200;
    response.setHeader("content-type", format === "json" ? "application/json; charset=utf-8" : "text/markdown; charset=utf-8");
    response.setHeader("content-disposition", `attachment; filename=routecairn-comparison-${comparisonExport.groups.id}.${format === "json" ? "json" : "md"}`);
    response.end(comparison.export(comparisonExport.groups.id, format));
    return;
  }
  if (url.pathname === "/api/findings") {
    requirePermission(context, "findings.read");
    sendJson(response, 200, findingCommandCenter.list(findingQuery(url)));
    return;
  }
  if (url.pathname === "/api/findings/queue") {
    requirePermission(context, "findings.read");
    sendJson(response, 200, findingCommandCenter.queue(stringParam(url, "mode") ?? "UNREVIEWED", findingQuery(url)));
    return;
  }
  if (url.pathname === "/api/finding-views") {
    requirePermission(context, "findings.read");
    sendJson(response, 200, { views: findingCommandCenter.savedViews(context.principal!) });
    return;
  }
  if (url.pathname === "/api/finding-assignees") {
    requirePermission(context, "findings.read");
    const users = context.serverSessions?.listUsers().filter((user) => user.enabled && (user.role === "OWNER" || user.role === "ANALYST")) ?? [];
    sendJson(response, 200, { users: users.map((user) => ({ id: user.id, login: user.login, role: user.role })) });
    return;
  }
  if (url.pathname === "/api/proof-packs") {
    requirePermission(context, "proofPacks.read");
    sendJson(response, 200, { proofPacks: context.proofPacks.list() });
    return;
  }
  if (url.pathname === "/api/settings") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, {
      mode: context.mode,
      localOnly: context.mode === "local",
      serverModeAvailable: true,
      serverModeStatus: context.mode === "server" ? "enabled" : "available-with-explicit-server-configuration",
      persistence: "sqlite",
      queue: { activeScans: 1, maxQueuedScans: settingValue(context, "queueCapacity", 20), workerIsolation: "child-process" },
      liveUpdates: "sse",
      websocketUpdates: false,
      credentialVault: context.vault.status(),
      mutable: mutableSettings(context),
      environment: environmentSettings(context),
      restartRequired: ["serverMode", "publicOrigin", "trustProxy", "masterKeyVersion"]
    });
    return;
  }
  if (url.pathname === "/api/workers/diagnostics") {
    requirePermission(context, "workers.read");
    sendJson(response, 200, context.execution.workerDiagnostics());
    return;
  }
  if (url.pathname === "/api/configurations") {
    requirePermission(context, "scans.create");
    sendJson(response, 200, { configurations: context.configurations.list(stringParam(url, "q"), booleanParam(url, "includeArchived") === true) });
    return;
  }
  const configuration = /^\/api\/configurations\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (configuration?.groups?.id) {
    requirePermission(context, "scans.create");
    const item = context.configurations.get(configuration.groups.id, booleanParam(url, "includeArchived") === true);
    if (!item) throw new HttpError(404, "Configuration not found.");
    sendJson(response, 200, { configuration: item, history: context.configurations.history(configuration.groups.id) });
    return;
  }
  const configurationDiff = /^\/api\/configurations\/(?<id>[0-9a-f-]+)\/diff$/.exec(url.pathname);
  if (configurationDiff?.groups?.id) {
    requirePermission(context, "scans.create");
    sendJson(response, 200, context.configurations.diff(configurationDiff.groups.id, numberParam(url, "older", 1), numberParam(url, "newer", 1)));
    return;
  }
  const stream = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/stream$/.exec(url.pathname);
  if (stream?.groups?.id) {
    requirePermission(context, "scans.read");
    await serveEventStream(context, stream.groups.id);
    return;
  }
  const scanEvents = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/events$/.exec(url.pathname);
  if (scanEvents?.groups?.id) {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { events: events.list(scanEvents.groups.id, numberParam(url, "after", 0), numberParam(url, "limit", 200)) });
    return;
  }
  const scan = /^\/api\/scans\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (scan?.groups?.id) {
    requirePermission(context, "scans.read");
    const item = scans.get(scan.groups.id);
    if (!item) throw new HttpError(404, "Scan not found.");
    sendJson(response, 200, { scan: item });
    return;
  }
  const scanDetail = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/detail$/.exec(url.pathname);
  if (scanDetail?.groups?.id) {
    requirePermission(context, "scans.read");
    const item = scans.detail(scanDetail.groups.id);
    if (!item) throw new HttpError(404, "Scan not found.");
    sendJson(response, 200, item);
    return;
  }
  const findingDetail = /^\/api\/findings\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (findingDetail?.groups?.id) {
    requirePermission(context, "findings.read");
    sendJson(response, 200, findingCommandCenter.detail(findingDetail.groups.id));
    return;
  }
  const retestCandidates = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/retest-candidates$/.exec(url.pathname);
  if (retestCandidates?.groups?.id) {
    requirePermission(context, "findings.read");
    sendJson(response, 200, { scans: findingCommandCenter.retestCandidates(retestCandidates.groups.id) });
    return;
  }
  const retestDraft = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/retest-draft$/.exec(url.pathname);
  if (retestDraft?.groups?.id) {
    requirePermission(context, "findings.linkRetest");
    sendJson(response, 200, findingCommandCenter.retestDraft(retestDraft.groups.id));
    return;
  }
  const artifact = /^\/api\/artifacts\/(?<id>[0-9a-f-]+)\/download$/.exec(url.pathname);
  if (artifact?.groups?.id) {
    requirePermission(context, "artifacts.download");
    const item = artifacts.get(artifact.groups.id);
    if (!item) throw new HttpError(404, "Artifact not found.");
    serveArtifact(response, item, [paths.reportsDir, paths.proofPacksDir, paths.artifactsDir]);
    return;
  }
  const artifactPreview = /^\/api\/artifacts\/(?<id>[0-9a-f-]+)\/preview$/.exec(url.pathname);
  if (artifactPreview?.groups?.id) {
    requirePermission(context, "artifacts.download");
    const item = artifacts.get(artifactPreview.groups.id);
    if (!item) throw new HttpError(404, "Artifact not found.");
    serveImagePreview(response, item, [paths.reportsDir, paths.proofPacksDir, paths.artifactsDir]);
    return;
  }
  throw new HttpError(404, "API route not found.");
}

async function handleApiMutation(context: ApiContext): Promise<void> {
  const { request, response, url, execution, findingCommandCenter, comparison, proofPacks, importer, configurations, projects, targets, audit, mutationApprovals, mutationRecovery } = context;
  if (request.method === "POST" && url.pathname === "/api/provider-adapters/preview") {
    requirePermission(context, "scans.create");
    const parsed = providerAdapterInputSchema.parse(await readJson(request));
    const preview = await context.providerAdapters.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_PREVIEWED", resourceType: "TARGET", resourceId: parsed.targetId, summary: "Reusable fixture/provider adapter previewed without executing requests.", metadata: { engineId: parsed.engineId, provider: parsed.provider, adapterDigest: preview.adapterDigest, blockerCount: preview.blockers.length } });
    sendJson(response, 200, { preview });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/provider-adapters") {
    requirePermission(context, "controlledMutation.approve");
    const parsed = providerAdapterInputSchema.parse(await readJson(request));
    const adapter = await context.providerAdapters.create(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_CREATED", resourceType: "PROVIDER_ADAPTER", resourceId: String(adapter.id), summary: "Encrypted reusable fixture/provider adapter draft created.", metadata: { targetId: parsed.targetId, engineId: parsed.engineId, provider: parsed.provider } });
    sendJson(response, 201, { adapter });
    return;
  }
  const providerAdapterUpdate = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && providerAdapterUpdate?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = providerAdapterInputSchema.parse(await readJson(request));
    const adapter = await context.providerAdapters.update(providerAdapterUpdate.groups.id, parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_VERSION_CREATED", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterUpdate.groups.id, summary: "A new immutable provider-adapter draft version was created; the reviewed version remains unchanged until review.", metadata: { engineId: parsed.engineId, provider: parsed.provider } });
    sendJson(response, 200, { adapter });
    return;
  }
  const providerAdapterReview = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)\/review$/.exec(url.pathname);
  if (request.method === "POST" && providerAdapterReview?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = providerAdapterReviewSchema.parse(await readJson(request));
    const adapter = await context.providerAdapters.review(providerAdapterReview.groups.id, parsed.versionId, parsed.adapterDigest, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_REVIEWED", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterReview.groups.id, summary: "Exact encrypted provider-adapter version reviewed and activated.", metadata: { versionId: parsed.versionId, adapterDigest: parsed.adapterDigest } });
    sendJson(response, 200, { adapter });
    return;
  }
  const providerAdapterState = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)\/state$/.exec(url.pathname);
  if (request.method === "POST" && providerAdapterState?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = providerAdapterStateSchema.parse(await readJson(request));
    const adapter = context.providerAdapters.setEnabled(providerAdapterState.groups.id, parsed.enabled, parsed.impactDigest);
    audit.append({ actorLabel: context.principal?.userId, action: parsed.enabled ? "PROVIDER_ADAPTER_ENABLED" : "PROVIDER_ADAPTER_DISABLED", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterState.groups.id, summary: `Provider adapter ${parsed.enabled ? "enabled" : "disabled"} after dependency-impact verification.`, metadata: { impactDigest: parsed.impactDigest } });
    sendJson(response, 200, { adapter });
    return;
  }
  const providerAdapterMaterialize = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)\/materialize$/.exec(url.pathname);
  if (request.method === "POST" && providerAdapterMaterialize?.groups?.id) {
    requirePermission(context, "scans.create");
    const materialized = context.providerAdapters.materialize(providerAdapterMaterialize.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_MATERIALIZED", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterMaterialize.groups.id, summary: "Reviewed adapter materialized into a dashboard Scan Studio draft; execution remains separately previewed and authorized." });
    sendJson(response, 200, { materialized });
    return;
  }
  const providerAdapterRecommendation = /^\/api\/provider-adapters\/(?<id>[0-9a-f-]+)\/recommendation$/.exec(url.pathname);
  if (request.method === "POST" && providerAdapterRecommendation?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const body = await readJson(request) as { recommendationId?: unknown };
    if (typeof body.recommendationId !== "string") throw new HttpError(400, "recommendationId is required.");
    context.providerAdapters.bindRecommendation(providerAdapterRecommendation.groups.id, body.recommendationId, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "PROVIDER_ADAPTER_RECOMMENDATION_BOUND", resourceType: "PROVIDER_ADAPTER", resourceId: providerAdapterRecommendation.groups.id, summary: "Reviewed adapter bound to an exact approved adaptive recommendation.", metadata: { recommendationId: body.recommendationId } });
    sendJson(response, 200, { adapter: context.providerAdapters.get(providerAdapterRecommendation.groups.id) });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/continuous-assurance/preview") {
    requirePermission(context, "scans.create");
    const parsed = continuousAssurancePolicyInputSchema.parse(await readJson(request));
    const preview = await context.continuousAssurance.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CONTINUOUS_ASSURANCE_PREVIEWED", resourceType: "TARGET", resourceId: parsed.targetId, summary: "Continuous assurance policy previewed without execution.", metadata: { policyDigest: preview.policyDigest, blockers: preview.blockers.length, adapters: preview.adapterBindings.length } });
    sendJson(response, 200, { preview }); return;
  }
  if (request.method === "POST" && url.pathname === "/api/continuous-assurance/policies") {
    requirePermission(context, "controlledMutation.approve");
    const parsed = continuousAssurancePolicyInputSchema.parse(await readJson(request));
    const result = await context.continuousAssurance.create(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "CONTINUOUS_ASSURANCE_POLICY_CREATED", resourceType: "CONTINUOUS_ASSURANCE_POLICY", resourceId: String((result.policy as {id?:unknown}).id), summary: "Continuous assurance draft created; deployment token issued once.", metadata: { targetId: parsed.targetId } });
    sendJson(response, 201, result); return;
  }
  const assurancePolicyUpdate = /^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && assurancePolicyUpdate?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = continuousAssurancePolicyInputSchema.parse(await readJson(request));
    const policy = await context.continuousAssurance.update(assurancePolicyUpdate.groups.id, parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "CONTINUOUS_ASSURANCE_POLICY_UPDATED", resourceType: "CONTINUOUS_ASSURANCE_POLICY", resourceId: assurancePolicyUpdate.groups.id, summary: "Policy updated as a new immutable draft; execution paused pending review." });
    sendJson(response, 200, { policy }); return;
  }
  const assuranceReview = /^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)\/review$/.exec(url.pathname);
  if (request.method === "POST" && assuranceReview?.groups?.id) {
    requirePermission(context, "controlledMutation.approve"); const parsed=continuousAssuranceReviewSchema.parse(await readJson(request));
    const policy=await context.continuousAssurance.review(assuranceReview.groups.id,parsed.versionId,parsed.policyDigest,context.principal?.userId??"local-operator");
    audit.append({actorLabel:context.principal?.userId,action:"CONTINUOUS_ASSURANCE_POLICY_REVIEWED",resourceType:"CONTINUOUS_ASSURANCE_POLICY",resourceId:assuranceReview.groups.id,summary:"Exact policy, target revision, adapters, actors, budgets, authorization, baselines, and gates reviewed and activated.",metadata:{versionId:parsed.versionId,policyDigest:parsed.policyDigest}}); sendJson(response,200,{policy});return;
  }
  const assuranceState=/^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)\/state$/.exec(url.pathname);
  if(request.method==="POST"&&assuranceState?.groups?.id){requirePermission(context,"controlledMutation.approve");const parsed=continuousAssuranceStateSchema.parse(await readJson(request));const policy=context.continuousAssurance.setEnabled(assuranceState.groups.id,parsed.enabled,parsed.impactDigest);audit.append({actorLabel:context.principal?.userId,action:parsed.enabled?"CONTINUOUS_ASSURANCE_ENABLED":"CONTINUOUS_ASSURANCE_DISABLED",resourceType:"CONTINUOUS_ASSURANCE_POLICY",resourceId:assuranceState.groups.id,summary:`Continuous assurance ${parsed.enabled?"enabled":"disabled"} after dependency-impact verification.`});sendJson(response,200,{policy});return;}
  const assuranceRun=/^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)\/run$/.exec(url.pathname);
  if(request.method==="POST"&&assuranceRun?.groups?.id){requirePermission(context,"controlledMutation.approve");continuousAssuranceRunSchema.parse(await readJson(request));const run=await context.continuousAssurance.runNow(assuranceRun.groups.id,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"CONTINUOUS_ASSURANCE_RUN_STARTED",resourceType:"CONTINUOUS_ASSURANCE_RUN",resourceId:String(run.id),summary:"Reviewed continuous assurance run queued."});sendJson(response,202,{run});return;}
  const assuranceToken=/^\/api\/continuous-assurance\/policies\/(?<id>[0-9a-f-]+)\/rotate-token$/.exec(url.pathname);
  if(request.method==="POST"&&assuranceToken?.groups?.id){requirePermission(context,"settings.manage");continuousAssuranceTokenRotationSchema.parse(await readJson(request));const result=context.continuousAssurance.rotateTriggerToken(assuranceToken.groups.id,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"CONTINUOUS_ASSURANCE_TOKEN_ROTATED",resourceType:"CONTINUOUS_ASSURANCE_POLICY",resourceId:assuranceToken.groups.id,summary:"Deployment trigger token rotated; prior token invalidated."});sendJson(response,200,result);return;}
  const assuranceAck=/^\/api\/continuous-assurance\/notifications\/(?<id>[0-9a-f-]+)\/acknowledge$/.exec(url.pathname);
  if(request.method==="POST"&&assuranceAck?.groups?.id){requirePermission(context,"controlledMutation.approve");continuousAssuranceNotificationAckSchema.parse(await readJson(request));context.continuousAssurance.acknowledge(assuranceAck.groups.id,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"CONTINUOUS_ASSURANCE_NOTIFICATION_ACKNOWLEDGED",resourceType:"CONTINUOUS_ASSURANCE_NOTIFICATION",resourceId:assuranceAck.groups.id,summary:"Continuous assurance operator notification acknowledged."});sendJson(response,200,{ok:true});return;}
  if(request.method==="PUT"&&url.pathname==="/api/evidence-governance/policy"){requirePermission(context,"settings.manage");const parsed=evidenceGovernancePolicySchema.parse(await readJson(request));const policy=context.evidenceGovernance.updatePolicy(parsed,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"EVIDENCE_GOVERNANCE_POLICY_UPDATED",resourceType:"EVIDENCE_GOVERNANCE_POLICY",summary:"Retention policy updated; failed, cleanup, and unreviewed evidence remain protected."});sendJson(response,200,{policy});return;}
  if(request.method==="POST"&&url.pathname==="/api/evidence-governance/exports"){requirePermission(context,"proofPacks.create");const parsed=evidenceExportSchema.parse(await readJson(request));const exported=context.evidenceGovernance.createExport(parsed.scanIds,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"EVIDENCE_EXPORT_CREATED",resourceType:"EVIDENCE_EXPORT",resourceId:String(exported.id),summary:"Encrypted, integrity-signed evidence export created.",metadata:{scanCount:parsed.scanIds.length}});sendJson(response,201,{export:exported});return;}
  const evidenceVerify=/^\/api\/evidence-governance\/exports\/(?<id>[0-9a-f-]+)\/verify$/.exec(url.pathname);
  if(request.method==="POST"&&evidenceVerify?.groups?.id){requirePermission(context,"artifacts.download");const value=context.evidenceGovernance.verifyExport(evidenceVerify.groups.id);audit.append({actorLabel:context.principal?.userId,action:"EVIDENCE_EXPORT_VERIFIED",resourceType:"EVIDENCE_EXPORT",resourceId:evidenceVerify.groups.id,summary:"Evidence export authenticity, installation binding, decryption, manifest, and embedded artifact digests verified."});sendJson(response,200,{export:value});return;}
  if(request.method==="POST"&&url.pathname==="/api/evidence-governance/purge-preview"){requirePermission(context,"settings.manage");sendJson(response,200,context.evidenceGovernance.purgePreview());return;}
  if(request.method==="POST"&&url.pathname==="/api/evidence-governance/purge"){requirePermission(context,"settings.manage");const parsed=evidencePurgeSchema.parse(await readJson(request));const result=context.evidenceGovernance.purge(parsed.previewDigest,context.principal?.userId??"local-operator");audit.append({actorLabel:context.principal?.userId,action:"EVIDENCE_RETENTION_PURGE_EXECUTED",resourceType:"EVIDENCE_GOVERNANCE_POLICY",summary:`Purged ${result.purgedCount} eligible artifact(s); ${result.failedCount} failed.`,metadata:result});sendJson(response,200,result);return;}
  if (request.method === "POST" && url.pathname === "/api/adaptive-security/analyze") {
    requirePermission(context, "scans.create");
    const parsed = adaptiveAnalyzeSchema.parse(await readJson(request));
    const snapshot = await context.adaptiveSecurity.analyze(parsed.targetId, parsed.scanId);
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_SECURITY_MODEL_ANALYZED", resourceType: "SCAN", resourceId: parsed.scanId, summary: "Completed scan evidence analyzed into an adaptive security model.", metadata: { targetId: parsed.targetId, snapshotId: snapshot.id, modelDigest: snapshot.modelDigest } });
    sendJson(response, 201, { snapshot });
    return;
  }
  if (request.method === "PUT" && url.pathname === "/api/adaptive-security/policy") {
    requirePermission(context, "settings.manage");
    const parsed = adaptivePolicyInputSchema.parse(await readJson(request));
    const adaptiveSecurity = context.adaptiveSecurity.setPolicy(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_SECURITY_POLICY_UPDATED", resourceType: "TARGET", resourceId: parsed.targetId, summary: "Adaptive coverage and drift policy updated.", metadata: { requiredLanes: parsed.requiredLanes, requireEvidenceForNotApplicable: parsed.requireEvidenceForNotApplicable, detectRemovedSurfaces: parsed.detectRemovedSurfaces } });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  const adaptiveBaseline = /^\/api\/adaptive-security\/snapshots\/(?<id>[0-9a-f-]+)\/accept$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveBaseline?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = adaptiveBaselineSchema.parse(await readJson(request));
    const adaptiveSecurity = context.adaptiveSecurity.acceptBaseline(adaptiveBaseline.groups.id, parsed.modelDigest, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_SECURITY_BASELINE_ACCEPTED", resourceType: "ADAPTIVE_SECURITY_SNAPSHOT", resourceId: adaptiveBaseline.groups.id, summary: "Exact observed target security model accepted as the expected baseline.", metadata: { modelDigest: parsed.modelDigest } });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  const adaptiveRecommendation = /^\/api\/adaptive-security\/recommendations\/(?<id>[0-9a-f-]+)\/decision$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveRecommendation?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = adaptiveRecommendationDecisionSchema.parse(await readJson(request));
    const adaptiveSecurity = context.adaptiveSecurity.decideRecommendation(adaptiveRecommendation.groups.id, parsed.decision, parsed.rationale, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: `ADAPTIVE_RECOMMENDATION_${parsed.decision}`, resourceType: "ADAPTIVE_SECURITY_RECOMMENDATION", resourceId: adaptiveRecommendation.groups.id, summary: `Adaptive test recommendation ${parsed.decision.toLowerCase()}; no execution was implied.`, metadata: { rationale: parsed.rationale } });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  const adaptiveLink = /^\/api\/adaptive-security\/recommendations\/(?<id>[0-9a-f-]+)\/link$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveLink?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = adaptiveRecommendationLinkSchema.parse(await readJson(request));
    const adaptiveSecurity = context.adaptiveSecurity.linkRecommendation(adaptiveLink.groups.id, parsed.scanId, parsed.caseFingerprint, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_RECOMMENDATION_EXECUTION_LINKED", resourceType: "ADAPTIVE_SECURITY_RECOMMENDATION", resourceId: adaptiveLink.groups.id, summary: "An explicitly approved recommendation was linked to an exact same-target workflow case for verification.", metadata: { scanId: parsed.scanId, caseFingerprint: parsed.caseFingerprint } });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  const adaptiveRefresh = /^\/api\/adaptive-security\/recommendations\/(?<id>[0-9a-f-]+)\/refresh$/.exec(url.pathname);
  if (request.method === "POST" && adaptiveRefresh?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const adaptiveSecurity = context.adaptiveSecurity.refreshRecommendation(adaptiveRefresh.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "ADAPTIVE_RECOMMENDATION_VERIFICATION_REFRESHED", resourceType: "ADAPTIVE_SECURITY_RECOMMENDATION", resourceId: adaptiveRefresh.groups.id, summary: "Linked recommendation verification refreshed from durable scan evidence." });
    sendJson(response, 200, { adaptiveSecurity });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/live-acceptance/preview") {
    requirePermission(context, "scans.create");
    const parsed = liveAcceptancePlanInputSchema.parse(await readJson(request));
    const preview = await context.liveAcceptance.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_PLAN_PREVIEWED", resourceType: "TARGET", resourceId: parsed.targetId, summary: `Live acceptance plan previewed with ${parsed.lanes.length} lane(s).`, metadata: { planDigest: preview.planDigest, laneCount: parsed.lanes.length, blockerCount: preview.blockers.length } });
    sendJson(response, 200, { preview });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/live-acceptance/plans") {
    requirePermission(context, "scans.create");
    const parsed = liveAcceptancePlanInputSchema.parse(await readJson(request));
    const result = await context.liveAcceptance.create(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_PLAN_CREATED", resourceType: "LIVE_ACCEPTANCE_PLAN", resourceId: String(result.plan.id), summary: `Encrypted live acceptance plan created with ${parsed.lanes.length} lane(s).`, metadata: { targetId: parsed.targetId, planDigest: result.preview.planDigest } });
    sendJson(response, 201, result);
    return;
  }
  const liveAcceptancePlanUpdate = /^\/api\/live-acceptance\/plans\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && liveAcceptancePlanUpdate?.groups?.id) {
    requirePermission(context, "scans.create");
    const body = await readJson(request) as { input?: unknown; expectedVersion?: unknown };
    if (!Number.isInteger(body.expectedVersion)) throw new HttpError(400, "Live acceptance update requires expectedVersion.");
    const result = await context.liveAcceptance.update(liveAcceptancePlanUpdate.groups.id, body.input, Number(body.expectedVersion));
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_PLAN_UPDATED", resourceType: "LIVE_ACCEPTANCE_PLAN", resourceId: liveAcceptancePlanUpdate.groups.id, summary: "Live acceptance plan updated; prior review was invalidated.", metadata: { planDigest: result.preview.planDigest } });
    sendJson(response, 200, result);
    return;
  }
  const liveAcceptanceReview = /^\/api\/live-acceptance\/plans\/(?<id>[0-9a-f-]+)\/review$/.exec(url.pathname);
  if (request.method === "POST" && liveAcceptanceReview?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = liveAcceptanceReviewSchema.parse(await readJson(request));
    const plan = await context.liveAcceptance.review(liveAcceptanceReview.groups.id, parsed.planDigest, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_PLAN_REVIEWED", resourceType: "LIVE_ACCEPTANCE_PLAN", resourceId: liveAcceptanceReview.groups.id, summary: "Exact live acceptance plan reviewed and bound.", metadata: { planDigest: parsed.planDigest } });
    sendJson(response, 200, { plan });
    return;
  }
  const liveAcceptanceExecute = /^\/api\/live-acceptance\/plans\/(?<id>[0-9a-f-]+)\/execute$/.exec(url.pathname);
  if (request.method === "POST" && liveAcceptanceExecute?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = liveAcceptanceExecuteSchema.parse(await readJson(request));
    const run = await context.liveAcceptance.execute(liveAcceptanceExecute.groups.id, parsed.planDigest, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_RUN_STARTED", resourceType: "LIVE_ACCEPTANCE_RUN", resourceId: String(run.id), summary: "Reviewed live acceptance run started.", metadata: { planId: liveAcceptanceExecute.groups.id, planDigest: parsed.planDigest } });
    sendJson(response, 202, { run });
    return;
  }
  const liveAcceptanceCancel = /^\/api\/live-acceptance\/runs\/(?<id>[0-9a-f-]+)\/cancel$/.exec(url.pathname);
  if (request.method === "POST" && liveAcceptanceCancel?.groups?.id) {
    requirePermission(context, "scans.cancel");
    const run = context.liveAcceptance.cancelRun(liveAcceptanceCancel.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "LIVE_ACCEPTANCE_RUN_CANCELLED", resourceType: "LIVE_ACCEPTANCE_RUN", resourceId: liveAcceptanceCancel.groups.id, summary: "Live acceptance run cancellation requested." });
    sendJson(response, 202, { run });
    return;
  }
  const assistedPublication = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/assisted-review\/publish$/.exec(url.pathname);
  if (request.method === "POST" && assistedPublication?.groups?.id) {
    requirePermission(context, "proofPacks.create");
    try {
      const published = new AssistedReviewService(context.database, context.paths).publish(assistedPublication.groups.id, context.principal!.userId);
      audit.append({ actorLabel: context.principal!.userId, action: "ASSISTED_REVIEW_PUBLISHED", resourceType: "SCAN", resourceId: assistedPublication.groups.id, summary: "Published human-reviewed customer report.", metadata: published });
      sendJson(response, 201, published);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("ASSISTED_REVIEW_NOT_READY:")) sendJson(response, 409, { error: error.message });
      else if (error instanceof Error && error.message === "ASSISTED_REVIEW_NOT_FOUND") sendJson(response, 404, { error: "No assisted review exists for this scan." });
      else throw error;
    }
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/production-mutations/preview") {
    requirePermission(context, "controlledMutation.approve");
    const parsed = productionMutationCaseSchema.parse(await readJson(request));
    const target = targets.get(parsed.targetId);
    if (!target) throw new HttpError(404, "Production target not found.");
    const compiled = compileProductionMutationCase(parsed, target, nowIso(), context.principal?.userId ?? "local-operator");
    const planIdentity = productionMutationPlanIdentity(parsed, target);
    sendJson(response, 200, { preview: compiled.preview, planIdentity });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/production-mutations/approvals") {
    requirePermission(context, "controlledMutation.approve");
    const parsed = productionMutationApprovalSchema.parse(await readJson(request));
    const target = targets.get(parsed.case.targetId);
    if (!target) throw new HttpError(404, "Production target not found.");
    const compiled = compileProductionMutationCase(parsed.case, target, nowIso(), context.principal?.userId ?? "local-operator");
    const planIdentity = productionMutationPlanIdentity(parsed.case, target);
    const targetIdentityFingerprint = createHash("sha256").update(`${target.id}:${target.rowVersion}:${target.baseOrigin}`).digest("hex");
    const scopeDigest = createHash("sha256").update(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort())).digest("hex");
    const id = mutationApprovals.create({ caseId: parsed.case.caseId, targetId: parsed.case.targetId, targetOrigin: target.baseOrigin, targetIdentityFingerprint, scopeDigest, planIdentity, authorizationSummary: parsed.authorizationDeclaration, expiresAt: parsed.case.authorizationExpiresAt });
    audit.append({ actorLabel: context.principal?.userId, action: "PRODUCTION_MUTATION_APPROVAL_CREATED", resourceType: "MUTATION_APPROVAL", resourceId: id, summary: "Production controlled-mutation approval created from an explicit case.", metadata: { caseId: parsed.case.caseId, targetId: parsed.case.targetId, planIdentity } });
    sendJson(response, 201, { approval: mutationApprovals.get(id), preview: compiled.preview });
    return;
  }
  const productionExecute = /^\/api\/production-mutations\/approvals\/(?<id>[0-9a-f-]+)\/execute$/.exec(url.pathname);
  if (request.method === "POST" && productionExecute?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const parsed = productionMutationCaseSchema.parse(await readJson(request));
    const approval = mutationApprovals.get(productionExecute.groups.id);
    const target = targets.get(parsed.targetId);
    if (!approval || approval.status !== "APPROVED" || !target) throw new HttpError(409, "PRODUCTION_MUTATION_APPROVAL_REQUIRED");
    const compiled = compileProductionMutationCase(parsed, target, nowIso(), context.principal?.userId ?? "local-operator");
    const planIdentity = productionMutationPlanIdentity(parsed, target);
    if (approval.caseId !== parsed.caseId || approval.targetId !== parsed.targetId || approval.planIdentity !== planIdentity) throw new HttpError(409, "PRODUCTION_MUTATION_PLAN_MISMATCH");
    const requestForWorker: DashboardScanCreateRequest = { target: target.baseOrigin, targetId: target.id, profile: "authenticated", credentialProfileId: parsed.actorCredentialProfileId, authorizationDeclaration: "Approved production controlled-mutation case.", studio: { version: 1, scanName: `Production mutation ${parsed.caseId}`, authorization: { category: "OWNED", confirmed: true }, scope: scopeSchema.parse(target.approvedScope), authentication: { mode: "primary", primary: { source: "saved", credentialProfileId: parsed.actorCredentialProfileId } }, outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: [] }, includeModules: ["privilege-mutation-testing"] };
    const contract = { ...compiled.contract, approvalBinding: { planIdentity: approval.planIdentity, targetIdentityFingerprint: approval.targetIdentityFingerprint, scopeDigest: approval.scopeDigest } };
    const scanId = await execution.enqueue(requestForWorker, [contract], approval.id);
    audit.append({ actorLabel: context.principal?.userId, action: "PRODUCTION_MUTATION_EXECUTION_QUEUED", resourceType: "SCAN", resourceId: scanId, summary: "Approved production controlled-mutation case queued through the isolated worker.", metadata: { caseId: parsed.caseId, targetId: parsed.targetId, approvalId: productionExecute.groups.id } });
    sendJson(response, 202, { scanId, approvalId: productionExecute.groups.id, status: "QUEUED", preview: compiled.preview });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/controlled-mutations/approvals") {
    // Legacy controlled-contract approvals remain distinct from workflow cleanup authorization.
    requirePermission(context, "controlledMutation.approve");
    const parsed = controlledMutationApprovalSchema.parse(await readJson(request));
    const target = targets.get(parsed.targetId);
    if (!target || target.baseOrigin !== new URL(parsed.targetOrigin).origin) throw new HttpError(400, "Mutation approval target does not match the registered target origin.");
    const targetIdentityFingerprint = createHash("sha256").update(`${target.id}:${target.rowVersion}:${target.baseOrigin}`).digest("hex");
    const scopeDigest = createHash("sha256").update(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort())).digest("hex");
    const id = mutationApprovals.create({ ...parsed, authorizationSummary: parsed.authorizationDeclaration, targetIdentityFingerprint, scopeDigest });
    audit.append({ actorLabel: context.principal?.userId, action: "CONTROLLED_MUTATION_PREVIEWED", resourceType: "MUTATION_APPROVAL", resourceId: id, summary: "Controlled mutation approval preview persisted.", metadata: { caseId: parsed.caseId, targetId: parsed.targetId, planIdentity: parsed.planIdentity } });
    sendJson(response, 201, { approval: mutationApprovals.get(id) });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/workflow-mutations/recovery") {
    requirePermission(context, "controlledMutation.recover");
    const parsed = workflowRecoveryRequestSchema.parse(await readJson(request));
    const jobId = await context.workflowRecovery.enqueue(parsed, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "WORKFLOW_CLEANUP_AUTHORIZED", resourceType: "RECOVERY_JOB", resourceId: jobId, summary: "Operator authorized stored cleanup and verification only.", metadata: { caseId: parsed.caseId, checkpointDigest: parsed.checkpointDigest } });
    sendJson(response, 202, { jobId });
    return;
  }
  const approval = /^\/api\/controlled-mutations\/approvals\/(?<id>[0-9a-f-]+)\/approve$/.exec(url.pathname);
  if (request.method === "POST" && approval?.groups?.id) {
    requirePermission(context, "controlledMutation.approve");
    const approved = mutationApprovals.approve(approval.groups.id, context.principal?.userId ?? "local-operator");
    audit.append({ actorLabel: context.principal?.userId, action: "CONTROLLED_MUTATION_APPROVED", resourceType: "MUTATION_APPROVAL", resourceId: approval.groups.id, summary: "Controlled mutation case approved for exact execution.", metadata: { caseId: approved.caseId, targetId: approved.targetId, planIdentity: approved.planIdentity } });
    sendJson(response, 200, { approval: approved });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/controlled-mutations/recover") {
    requirePermission(context, "controlledMutation.recover");
    const parsed = controlledMutationRecoverySchema.parse(await readJson(request));
    const target = targets.get(parsed.targetId);
    if (!target) throw new HttpError(404, "Controlled mutation recovery target not found.");
    if (!parsed.credentialProfileId) throw new HttpError(400, "Controlled mutation recovery requires a fresh credential profile.");
    const jobId = randomUUID();
    void mutationRecovery.queueRecovery({ recoveryJobId: jobId, approvalId: parsed.approvalId, bundlePath: parsed.bundlePath, caseId: parsed.caseId, targetId: parsed.targetId, credentialProfileId: parsed.credentialProfileId, workerRequest: { target: target.baseOrigin, targetId: target.id, profile: "authenticated", authorizationDeclaration: "Approved controlled-mutation recovery operation.", includeModules: ["privilege-mutation-testing"], studio: { version: 1, scanName: `Recovery ${parsed.caseId}`, authorization: { category: "OWNED", confirmed: true }, scope: scopeSchema.parse(target.approvedScope), authentication: { mode: "primary", primary: { source: "saved", credentialProfileId: parsed.credentialProfileId } }, outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: [] } } }).then((result) => audit.append({ actorLabel: context.principal?.userId, action: "CONTROLLED_MUTATION_RECOVERY_COMPLETED", resourceType: "MUTATION_APPROVAL", resourceId: parsed.approvalId, summary: `Controlled mutation recovery completed with ${result.cleanupOutcome}.`, metadata: { caseId: parsed.caseId, targetId: parsed.targetId, cleanupOutcome: result.cleanupOutcome } })).catch((error: unknown) => audit.append({ actorLabel: context.principal?.userId, action: "CONTROLLED_MUTATION_RECOVERY_FAILED", resourceType: "MUTATION_APPROVAL", resourceId: parsed.approvalId, summary: "Controlled mutation recovery failed; operator action remains required.", metadata: { caseId: parsed.caseId, targetId: parsed.targetId, error: error instanceof Error ? error.message.slice(0, 200) : "unknown" } }));
    sendJson(response, 202, { recoveryJobId: jobId, status: "QUEUED" });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/session/logout") {
    if (context.mode === "local") context.localSessions?.destroy(response);
    else context.serverSessions?.logout(request, response);
    audit.append({ action: "LOGOUT", resourceType: "SESSION", summary: "Local session ended." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/auth/logout") {
    context.serverSessions?.logout(request, response);
    audit.append({ actorLabel: context.principal?.userId, action: "LOGOUT", resourceType: "SESSION", summary: "Server session logged out." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/auth/revoke-all") {
    requirePermission(context, "scans.read");
    if (context.principal?.mode === "server") context.serverSessions?.revokeUserSessions(context.principal.userId);
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/credential-profiles") {
    requirePermission(context, "credentials.create");
    const parsed = credentialProfileSchema.parse(await readJson(request));
    const profileId = context.vault.create({ ...parsed, createdByUserId: context.principal?.userId });
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_CREATED", resourceType: "CREDENTIAL_PROFILE", resourceId: profileId, summary: `Credential profile created: ${parsed.safeAlias}.` });
    sendJson(response, 201, { profileId });
    return;
  }
  const credential = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && credential?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialProfileSchema.parse(await readJson(request));
    context.vault.update(credential.groups.id, parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_UPDATED", resourceType: "CREDENTIAL_PROFILE", resourceId: credential.groups.id, summary: `Credential profile updated: ${parsed.safeAlias}.` });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialMetadata = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/metadata$/.exec(url.pathname);
  if (request.method === "PATCH" && credentialMetadata?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialMetadataSchema.parse(await readJson(request));
    context.vault.updateMetadata(credentialMetadata.groups.id, parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_METADATA_UPDATED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialMetadata.groups.id, summary: `Credential metadata updated: ${parsed.safeAlias}.` });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialSecret = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/replace-secret$/.exec(url.pathname);
  if (request.method === "POST" && credentialSecret?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialReplacementSchema.parse(await readJson(request));
    context.vault.assertImpactDigest(credentialSecret.groups.id, parsed.impactDigest);
    context.vault.replaceSecret(credentialSecret.groups.id, parsed.secret);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_SECRET_REPLACED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialSecret.groups.id, summary: "Credential secret material replaced after dependency-impact review; no secret value was retained in audit output.", metadata: { dependencyImpactDigest: parsed.impactDigest } });
    sendJson(response, 200, { ok: true, profile: context.vault.getSummary(credentialSecret.groups.id) });
    return;
  }
  const credentialRenew = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/renew$/.exec(url.pathname);
  if (request.method === "POST" && credentialRenew?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialRenewalSchema.parse(await readJson(request));
    const profile = context.vault.renew(credentialRenew.groups.id, parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_RENEWED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialRenew.groups.id, summary: "Credential renewed after dependency-impact review; a fresh health test is required.", metadata: { dependencyImpactDigest: parsed.impactDigest, expiresAt: parsed.expiresAt, secretVersion: profile.secretVersion } });
    sendJson(response, 200, { ok: true, profile });
    return;
  }
  const credentialEnable = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/enable$/.exec(url.pathname);
  if (request.method === "POST" && credentialEnable?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialDependencyAcknowledgementSchema.parse(await readJson(request));
    context.vault.setEnabled(credentialEnable.groups.id, true, parsed.impactDigest);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_ENABLED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialEnable.groups.id, summary: "Credential profile enabled after dependency-impact review; a fresh health test is required.", metadata: { dependencyImpactDigest: parsed.impactDigest } });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialDisable = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/disable$/.exec(url.pathname);
  if (request.method === "POST" && credentialDisable?.groups?.id) {
    requirePermission(context, "credentials.update");
    const parsed = credentialDependencyAcknowledgementSchema.parse(await readJson(request));
    context.vault.setEnabled(credentialDisable.groups.id, false, parsed.impactDigest);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_DISABLED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialDisable.groups.id, summary: "Credential profile disabled after dependency-impact review.", metadata: { dependencyImpactDigest: parsed.impactDigest } });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialDelete = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/delete$/.exec(url.pathname);
  if (request.method === "POST" && credentialDelete?.groups?.id) {
    requirePermission(context, "credentials.delete");
    context.vault.delete(credentialDelete.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_DELETED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialDelete.groups.id, summary: "Credential profile deleted." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialTest = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/test$/.exec(url.pathname);
  if (request.method === "POST" && credentialTest?.groups?.id) {
    requirePermission(context, "credentials.test");
    const parsed = credentialHealthTestSchema.parse(await readJson(request));
    const result = await context.execution.testCredentialProfile(credentialTest.groups.id, parsed.targetId);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_TEST_EXECUTED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialTest.groups.id, summary: "Bounded credential identity and structure validation completed; no secret value was retained.", metadata: { classification: (result.health as { classification?: unknown } | undefined)?.classification, targetId: parsed.targetId } });
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/users") {
    requirePermission(context, "users.manage");
    const parsed = userCreateSchema.parse(await readJson(request));
    const userId = await context.serverSessions!.createUser({ ...parsed, createdByUserId: context.principal?.userId });
    audit.append({ actorLabel: context.principal?.userId, action: "USER_CREATED", resourceType: "USER", resourceId: userId, summary: `User created with role ${parsed.role}.` });
    sendJson(response, 201, { userId });
    return;
  }
  const userUpdate = /^\/api\/users\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && userUpdate?.groups?.id) {
    requirePermission(context, "users.manage");
    const parsed = userUpdateSchema.parse(await readJson(request));
    if (parsed.role) {
      context.serverSessions!.setRole(userUpdate.groups.id, parsed.role);
      audit.append({ actorLabel: context.principal?.userId, action: "ROLE_CHANGED", resourceType: "USER", resourceId: userUpdate.groups.id, summary: `User role changed to ${parsed.role}.` });
    }
    if (typeof parsed.enabled === "boolean") {
      context.serverSessions!.setEnabled(userUpdate.groups.id, parsed.enabled);
      audit.append({ actorLabel: context.principal?.userId, action: parsed.enabled ? "USER_ENABLED" : "USER_DISABLED", resourceType: "USER", resourceId: userUpdate.groups.id, summary: parsed.enabled ? "User enabled." : "User disabled." });
    }
    if (parsed.password) {
      await context.serverSessions!.resetPassword(userUpdate.groups.id, parsed.password);
      audit.append({ actorLabel: context.principal?.userId, action: "PASSWORD_RESET", resourceType: "USER", resourceId: userUpdate.groups.id, summary: "User password reset and sessions revoked." });
    }
    sendJson(response, 200, { ok: true });
    return;
  }
  const userRevoke = /^\/api\/users\/(?<id>[0-9a-f-]+)\/revoke-sessions$/.exec(url.pathname);
  if (request.method === "POST" && userRevoke?.groups?.id) {
    requirePermission(context, "users.manage");
    context.serverSessions!.revokeUserSessions(userRevoke.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "SESSIONS_REVOKED", resourceType: "USER", resourceId: userRevoke.groups.id, summary: "All active sessions revoked." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/scans/plan-preview") {
    requirePermission(context, "scans.create");
    const parsed = dashboardScanCreateSchema.parse(await readJson(request));
    validateScanReferences(context, parsed);
    requireCredentialUsePermission(context, parsed);
    await assertProviderAdapterExecution(context, parsed);
    const preview = await execution.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "SCAN_STUDIO_PLAN_PREVIEW", resourceType: "TARGET", resourceId: parsed.targetId, summary: `Plan preview resolved for ${new URL(parsed.target).origin}.`, metadata: { projectId: parsed.projectId, profile: parsed.profile, moduleCount: preview.modules.length, studioVersion: parsed.studio?.version } });
    sendJson(response, 200, preview);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/advanced-engines/validate") {
    requirePermission(context, "scans.create");
    const parsed = advancedEngineValidationRequestSchema.parse(await readJson(request));
    const result = validateAdvancedEngineInput(parsed.engineId, parsed.value);
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/scans/identity-test") {
    requirePermission(context, "scans.create");
    const parsed = dashboardScanCreateSchema.parse(await readJson(request));
    validateScanReferences(context, parsed);
    requireCredentialUsePermission(context, parsed);
    const result = await execution.testIdentity(parsed);
    audit.append({
      actorLabel: context.principal?.userId,
      action: "SCAN_STUDIO_IDENTITY_TEST",
      resourceType: "TARGET",
      resourceId: parsed.targetId,
      summary: `Identity test completed for ${new URL(parsed.target).origin}.`,
      metadata: { projectId: parsed.projectId, profile: parsed.profile, authMode: parsed.studio?.authentication.mode ?? "legacy", categories: identityResultCategories(result) }
    });
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/scans") {
    requirePermission(context, "scans.create");
    const parsed = dashboardScanCreateSchema.parse(await readJson(request));
    validateScanReferences(context, parsed);
    requireCredentialUsePermission(context, parsed);
    if (parsed.studio?.retestContext) findingCommandCenter.validateRetestContext(parsed.studio.retestContext);
    await assertProviderAdapterExecution(context, parsed);
    const scanId = await execution.enqueue(parsed);
    if (parsed.providerAdapterBinding) context.providerAdapters.bindScan(scanId, parsed.providerAdapterBinding);
    if (parsed.studio?.retestContext) {
      findingCommandCenter.recordRetestLaunch({ context: parsed.studio.retestContext, newScanId: scanId, principal: context.principal! });
    }
    audit.append({
      action: "SCAN_CREATED",
      resourceType: "SCAN",
      resourceId: scanId,
      summary: `Queued ${parsed.profile} scan for ${new URL(parsed.target).origin}.`,
      metadata: { projectId: parsed.projectId, targetId: parsed.targetId, hasAuthorizationDeclaration: Boolean(parsed.authorizationDeclaration), retestFindingId: parsed.studio?.retestContext?.findingId }
    });
    sendJson(response, 202, { scanId });
    return;
  }
  const cancel = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/cancel$/.exec(url.pathname);
  if (request.method === "POST" && cancel?.groups?.id) {
    requirePermission(context, "scans.cancel");
    execution.cancel(cancel.groups.id);
    audit.append({ action: "SCAN_CANCELLED", resourceType: "SCAN", resourceId: cancel.groups.id, summary: "Scan cancellation requested." });
    sendJson(response, 202, { ok: true });
    return;
  }
  const rerun = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/rerun$/.exec(url.pathname);
  if (request.method === "POST" && rerun?.groups?.id) {
    requirePermission(context, "scans.create");
    const scanId = await execution.rerun(rerun.groups.id);
    audit.append({ action: "SCAN_RERUN", resourceType: "SCAN", resourceId: scanId, summary: `Created rerun from ${rerun.groups.id}.`, metadata: { sourceScanId: rerun.groups.id } });
    sendJson(response, 202, { scanId });
    return;
  }
  const archive = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/archive$/.exec(url.pathname);
  if (request.method === "POST" && archive?.groups?.id) {
    requirePermission(context, "scans.cancel");
    context.scans.markArchived(archive.groups.id);
    audit.append({ action: "SCAN_ARCHIVED", resourceType: "SCAN", resourceId: archive.groups.id, summary: "Scan archived." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const deleteScan = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/delete$/.exec(url.pathname);
  if (request.method === "POST" && deleteScan?.groups?.id) {
    requirePermission(context, "scans.cancel");
    context.scans.markDeleted(deleteScan.groups.id);
    audit.append({ action: "SCAN_DELETED", resourceType: "SCAN", resourceId: deleteScan.groups.id, summary: "Scan metadata marked deleted." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const review = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/review$/.exec(url.pathname);
  if (request.method === "PATCH" && review?.groups?.id) {
    requirePermission(context, "findings.review");
    const parsed = findingReviewSchema.parse(await readJson(request));
    if (parsed.newStatus === "DUPLICATE") requirePermission(context, "findings.markDuplicate");
    const finding = findingCommandCenter.review({ findingId: review.groups.id, ...parsed,
      principal: context.principal!, correlationId: correlationId(request) });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.takeover ? "FINDING_REVIEW_TAKEN_OVER" : reviewAuditAction(parsed.newStatus), resourceType: "FINDING", resourceId: review.groups.id, summary: parsed.takeover ? "Finding review ownership taken over cooperatively." : `Finding review changed to ${parsed.newStatus}.`, metadata: { newStatus: parsed.newStatus, takeover: parsed.takeover, hasReason: Boolean(parsed.reason), hasNote: Boolean(parsed.note), correlationId: correlationId(request) } });
    sendJson(response, 200, { finding });
    return;
  }
  const remediation = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/remediation$/.exec(url.pathname);
  if (request.method === "PATCH" && remediation?.groups?.id) {
    requirePermission(context, "findings.remediate");
    const parsed = findingRemediationSchema.parse(await readJson(request));
    if (parsed.assigneeUserId !== undefined) requirePermission(context, "findings.assign");
    const finding = findingCommandCenter.remediation({ findingId: remediation.groups.id, ...parsed,
      principal: context.principal!, correlationId: correlationId(request) });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.assigneeUserId !== undefined ? "FINDING_REMEDIATION_ASSIGNED" : "FINDING_REMEDIATION_CHANGED", resourceType: "FINDING", resourceId: remediation.groups.id, summary: `Finding remediation changed to ${parsed.newState}.`, metadata: { newState: parsed.newState, hasNote: Boolean(parsed.note), hasTargetDate: Boolean(parsed.targetFixDate) } });
    sendJson(response, 200, { finding });
    return;
  }
  const note = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/notes$/.exec(url.pathname);
  if (request.method === "POST" && note?.groups?.id) {
    requirePermission(context, "notes.create");
    const parsed = findingNoteSchema.parse(await readJson(request));
    const noteId = findingCommandCenter.addNote({ findingId: note.groups.id, text: parsed.text, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDING_NOTE_ADDED", resourceType: "FINDING", resourceId: note.groups.id, summary: "Safe analyst note added." });
    sendJson(response, 201, { noteId });
    return;
  }
  const retest = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/retest$/.exec(url.pathname);
  if (request.method === "POST" && retest?.groups?.id) {
    requirePermission(context, "findings.linkRetest");
    const parsed = findingRetestSchema.parse(await readJson(request));
    const result = findingCommandCenter.linkRetest({ findingId: retest.groups.id, ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDING_RETEST_LINKED", resourceType: "FINDING", resourceId: retest.groups.id, summary: `Retest linked with state ${result.state}.`, metadata: { scanId: parsed.scanId, compatible: result.compatible, reasonCount: result.reasons.length } });
    sendJson(response, 200, result);
    return;
  }
  const verify = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/verify-fixed$/.exec(url.pathname);
  if (request.method === "POST" && verify?.groups?.id) {
    requirePermission(context, "findings.remediate");
    const parsed = findingVerifySchema.parse(await readJson(request));
    if (parsed.ownerOverride) requirePermission(context, "findings.ownerOverride");
    const finding = findingCommandCenter.verifyFixed({ findingId: verify.groups.id, ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.ownerOverride ? "FINDING_OWNER_VERIFICATION_OVERRIDE" : "FINDING_FIXED_VERIFIED", resourceType: "FINDING", resourceId: verify.groups.id, summary: parsed.ownerOverride ? "Owner override verified finding remediation." : "Compatible retest verified finding remediation.", metadata: { ownerOverride: parsed.ownerOverride } });
    sendJson(response, 200, { finding });
    return;
  }
  const severityOverride = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/severity$/.exec(url.pathname);
  if (request.method === "PATCH" && severityOverride?.groups?.id) {
    requirePermission(context, "findings.overrideSeverity");
    const parsed = findingSeveritySchema.parse(await readJson(request));
    const finding = findingCommandCenter.overrideSeverity({ findingId: severityOverride.groups.id, ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDING_SEVERITY_OVERRIDDEN", resourceType: "FINDING", resourceId: severityOverride.groups.id, summary: `Effective finding severity changed to ${parsed.severity}.`, metadata: { severity: parsed.severity } });
    sendJson(response, 200, { finding });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/findings/bulk-review") {
    requirePermission(context, "findings.bulkReview");
    const parsed = findingBulkReviewSchema.parse(await readJson(request));
    const result = findingCommandCenter.bulkReview({ ...parsed, principal: context.principal!, correlationId: correlationId(request) });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDINGS_BULK_REVIEWED", resourceType: "FINDING_BATCH", summary: `Bulk review applied to ${result.succeeded.length} finding(s); ${result.failed.length} failed.`, metadata: { requested: parsed.findingIds.length, succeeded: result.succeeded.length, failed: result.failed.length, newStatus: parsed.newStatus } });
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/findings/bulk-remediation") {
    requirePermission(context, "findings.remediate");
    const parsed = findingBulkRemediationSchema.parse(await readJson(request));
    if (parsed.assigneeUserId !== undefined) requirePermission(context, "findings.assign");
    const result = findingCommandCenter.bulkRemediation({ ...parsed, principal: context.principal!, correlationId: correlationId(request) });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDINGS_BULK_REMEDIATED", resourceType: "FINDING_BATCH", summary: `Bulk remediation updated ${result.succeeded.length} finding(s); ${result.failed.length} failed.`, metadata: { requested: parsed.findingIds.length, succeeded: result.succeeded.length, failed: result.failed.length, newState: parsed.newState } });
    sendJson(response, 200, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/findings/bulk-note") {
    requirePermission(context, "notes.create");
    const parsed = findingBulkNoteSchema.parse(await readJson(request));
    const result = findingCommandCenter.bulkNote({ ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: "FINDINGS_BULK_NOTE_ADDED", resourceType: "FINDING_BATCH", summary: `Bulk note added to ${result.succeeded.length} finding(s); ${result.failed.length} failed.`, metadata: { requested: parsed.findingIds.length, succeeded: result.succeeded.length, failed: result.failed.length } });
    sendJson(response, 200, result);
    return;
  }
  if ((request.method === "POST" || request.method === "PATCH") && url.pathname === "/api/finding-views") {
    requirePermission(context, "savedViews.manage");
    const parsed = savedFindingViewSchema.parse(await readJson(request));
    const viewId = findingCommandCenter.saveView({ ...parsed, principal: context.principal! });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.shared ? "FINDING_VIEW_SHARED" : "FINDING_VIEW_SAVED", resourceType: "SAVED_FINDING_VIEW", resourceId: viewId, summary: `Finding view saved: ${parsed.name}.`, metadata: { shared: parsed.shared, isDefault: parsed.isDefault } });
    sendJson(response, parsed.id ? 200 : 201, { viewId });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/finding-views/delete") {
    requirePermission(context, "savedViews.manage");
    const parsed = savedFindingViewDeleteSchema.parse(await readJson(request));
    findingCommandCenter.deleteView(parsed.id, context.principal!);
    audit.append({ actorLabel: context.principal?.userId, action: "FINDING_VIEW_DELETED", resourceType: "SAVED_FINDING_VIEW", resourceId: parsed.id, summary: "Saved finding view deleted." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/finding-views/default") {
    requirePermission(context, "savedViews.manage");
    const parsed = savedFindingViewDefaultSchema.parse(await readJson(request));
    findingCommandCenter.setDefaultView(parsed.id, context.principal!);
    audit.append({ actorLabel: context.principal?.userId, action: parsed.id ? "FINDING_VIEW_DEFAULT_SET" : "FINDING_VIEW_DEFAULT_CLEARED", resourceType: "SAVED_FINDING_VIEW", resourceId: parsed.id ?? undefined, summary: parsed.id ? "Personal default finding view set." : "Personal default finding view cleared." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/compare") {
    requirePermission(context, "comparisons.create");
    const parsed = compareRequestSchema.parse(await readJson(request));
    if (parsed.recompute) requirePermission(context, "comparisons.recompute");
    const result = comparison.compare(parsed.oldScanId, parsed.newScanId, { ...(context.principal?.userId ? { createdByUserId: context.principal.userId } : {}), ...(parsed.recompute === undefined ? {} : { recompute: parsed.recompute }) });
    audit.append({ actorLabel: context.principal?.userId, action: parsed.recompute ? "COMPARISON_RECOMPUTED" : "COMPARISON_CREATED", resourceType: "SCAN_COMPARISON", resourceId: result.comparisonId, summary: parsed.recompute ? "Scan comparison recomputed with a traceable engine version." : "Scan comparison created.", metadata: { oldScanId: parsed.oldScanId, newScanId: parsed.newScanId, engineVersion: result.engineVersion } });
    sendJson(response, parsed.recompute ? 200 : 201, comparison.get(result.comparisonId, { page: 1, pageSize: 25 }));
    return;
  }
  const comparisonDelete = /^\/api\/comparisons\/(?<id>[0-9a-f-]+)\/delete$/.exec(url.pathname);
  if (request.method === "POST" && comparisonDelete?.groups?.id) {
    requirePermission(context, "comparisons.delete");
    comparison.delete(comparisonDelete.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "COMPARISON_DELETED", resourceType: "SCAN_COMPARISON", resourceId: comparisonDelete.groups.id, summary: "Scan comparison soft-deleted." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/proof-packs") {
    requirePermission(context, "proofPacks.create");
    const parsed = proofPackCreateSchema.parse(await readJson(request));
    const proofPackId = proofPacks.generate(parsed.title, parsed.description, parsed.findingIds);
    audit.append({ action: "PROOF_PACK_GENERATED", resourceType: "PROOF_PACK", resourceId: proofPackId, summary: `Generated proof pack with ${parsed.findingIds.length} finding(s).` });
    sendJson(response, 201, { proofPackId });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/import/report") {
    requirePermission(context, "imports.create");
    const parsed = importReportSchema.parse(await readJson(request));
    const result = importer.importReport(parsed.reportPath);
    audit.append({ action: "HISTORICAL_REPORT_IMPORTED", resourceType: "SCAN", resourceId: result.scanId, summary: "Imported historical report from approved report root.", metadata: { warningCount: result.warnings.length } });
    sendJson(response, 201, result);
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/projects") {
    requirePermission(context, "projects.manage");
    const parsed = projectSchema.parse(await readJson(request));
    const projectId = projects.create(parsed);
    audit.append({ action: "PROJECT_CREATED", resourceType: "PROJECT", resourceId: projectId, summary: `Project created: ${parsed.name}.` });
    sendJson(response, 201, { projectId });
    return;
  }
  const projectUpdate = /^\/api\/projects\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && projectUpdate?.groups?.id) {
    requirePermission(context, "projects.manage");
    const parsed = projectSchema.parse(await readJson(request));
    projects.update(projectUpdate.groups.id, parsed);
    audit.append({ action: "PROJECT_UPDATED", resourceType: "PROJECT", resourceId: projectUpdate.groups.id, summary: `Project updated: ${parsed.name}.` });
    sendJson(response, 200, { ok: true });
    return;
  }
  const projectArchive = /^\/api\/projects\/(?<id>[0-9a-f-]+)\/archive$/.exec(url.pathname);
  if (request.method === "POST" && projectArchive?.groups?.id) {
    requirePermission(context, "projects.manage");
    projects.archive(projectArchive.groups.id);
    audit.append({ action: "PROJECT_ARCHIVED", resourceType: "PROJECT", resourceId: projectArchive.groups.id, summary: "Project archived." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const projectRestore = /^\/api\/projects\/(?<id>[0-9a-f-]+)\/restore$/.exec(url.pathname);
  if (request.method === "POST" && projectRestore?.groups?.id) {
    requirePermission(context, "projects.manage");
    projects.restore(projectRestore.groups.id);
    audit.append({ action: "PROJECT_RESTORED", resourceType: "PROJECT", resourceId: projectRestore.groups.id, summary: "Project restored." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/targets") {
    requirePermission(context, "targets.manage");
    const parsed = targetSchema.parse(await readJson(request));
    validateTargetDefaults(context, parsed);
    const targetId = targets.create(parsed);
    audit.append({ action: "TARGET_CREATED", resourceType: "TARGET", resourceId: targetId, summary: `Target created: ${parsed.displayName}.`, metadata: { projectId: parsed.projectId, authorizationType: parsed.authorizationType } });
    sendJson(response, 201, { targetId });
    return;
  }
  const targetUpdate = /^\/api\/targets\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && targetUpdate?.groups?.id) {
    requirePermission(context, "targets.manage");
    const parsed = targetSchema.parse(await readJson(request));
    validateTargetDefaults(context, parsed);
    targets.update(targetUpdate.groups.id, parsed);
    audit.append({ action: "TARGET_UPDATED", resourceType: "TARGET", resourceId: targetUpdate.groups.id, summary: `Target updated: ${parsed.displayName}.`, metadata: { projectId: parsed.projectId, authorizationType: parsed.authorizationType } });
    sendJson(response, 200, { ok: true });
    return;
  }
  const targetArchive = /^\/api\/targets\/(?<id>[0-9a-f-]+)\/archive$/.exec(url.pathname);
  if (request.method === "POST" && targetArchive?.groups?.id) {
    requirePermission(context, "targets.manage");
    targets.archive(targetArchive.groups.id);
    audit.append({ action: "TARGET_ARCHIVED", resourceType: "TARGET", resourceId: targetArchive.groups.id, summary: "Target archived." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const targetRestore = /^\/api\/targets\/(?<id>[0-9a-f-]+)\/restore$/.exec(url.pathname);
  if (request.method === "POST" && targetRestore?.groups?.id) {
    requirePermission(context, "targets.manage");
    targets.restore(targetRestore.groups.id);
    audit.append({ action: "TARGET_RESTORED", resourceType: "TARGET", resourceId: targetRestore.groups.id, summary: "Target restored." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/configurations") {
    requirePermission(context, "configurations.manage");
    const parsed = savedConfigurationSchema.parse(await readJson(request));
    const configurationId = configurations.create(normalizeSavedConfiguration(parsed));
    audit.append({ action: "CONFIGURATION_CHANGED", resourceType: "SAVED_CONFIGURATION", resourceId: configurationId, summary: `Configuration created: ${parsed.name}.` });
    sendJson(response, 201, { configurationId });
    return;
  }
  const configUpdate = /^\/api\/configurations\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (request.method === "PATCH" && configUpdate?.groups?.id) {
    requirePermission(context, "configurations.manage");
    const parsed = savedConfigurationSchema.parse(await readJson(request));
    configurations.update(configUpdate.groups.id, normalizeSavedConfiguration(parsed));
    audit.append({ action: "CONFIGURATION_CHANGED", resourceType: "SAVED_CONFIGURATION", resourceId: configUpdate.groups.id, summary: `Configuration updated: ${parsed.name}.` });
    sendJson(response, 200, { ok: true });
    return;
  }
  const configArchive = /^\/api\/configurations\/(?<id>[0-9a-f-]+)\/archive$/.exec(url.pathname);
  if (request.method === "POST" && configArchive?.groups?.id) {
    requirePermission(context, "configurations.manage");
    configurations.archive(configArchive.groups.id);
    audit.append({ action: "CONFIGURATION_ARCHIVED", resourceType: "SAVED_CONFIGURATION", resourceId: configArchive.groups.id, summary: "Configuration archived." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const configRestore = /^\/api\/configurations\/(?<id>[0-9a-f-]+)\/restore$/.exec(url.pathname);
  if (request.method === "POST" && configRestore?.groups?.id) {
    requirePermission(context, "configurations.manage");
    configurations.restore(configRestore.groups.id);
    audit.append({ action: "CONFIGURATION_RESTORED", resourceType: "SAVED_CONFIGURATION", resourceId: configRestore.groups.id, summary: "Configuration restored." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const configClone = /^\/api\/configurations\/(?<id>[0-9a-f-]+)\/clone$/.exec(url.pathname);
  if (request.method === "POST" && configClone?.groups?.id) {
    requirePermission(context, "configurations.manage");
    const body = await readJson(request) as { name?: unknown };
    const name = typeof body.name === "string" && body.name.trim() ? body.name.trim().slice(0, 160) : "Configuration copy";
    const configurationId = configurations.clone(configClone.groups.id, name);
    audit.append({ action: "CONFIGURATION_CLONED", resourceType: "SAVED_CONFIGURATION", resourceId: configurationId, summary: `Configuration cloned: ${name}.`, metadata: { sourceId: configClone.groups.id } });
    sendJson(response, 201, { configurationId });
    return;
  }
  if (request.method === "PATCH" && url.pathname === "/api/settings") {
    requirePermission(context, "settings.manage");
    const parsed = dashboardSettingsUpdateSchema.parse(await readJson(request));
    updateSettings(context, parsed.values, parsed.expectedVersions, context.principal?.userId);
    audit.append({ actorLabel: context.principal?.userId, action: "SETTINGS_CHANGED", resourceType: "DASHBOARD_SETTINGS", summary: `Updated ${Object.keys(parsed.values).length} dashboard setting(s).`, metadata: { keys: Object.keys(parsed.values) } });
    sendJson(response, 200, { mutable: mutableSettings(context) });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/settings/reset") {
    requirePermission(context, "settings.manage");
    const body = await readJson(request) as { keys?: unknown };
    const keys = Array.isArray(body.keys) ? body.keys.filter((key): key is string => typeof key === "string") : [];
    resetSettings(context, keys);
    audit.append({ actorLabel: context.principal?.userId, action: "SETTINGS_RESET", resourceType: "DASHBOARD_SETTINGS", summary: `Reset ${keys.length || "all"} mutable setting(s).`, metadata: { keys } });
    sendJson(response, 200, { mutable: mutableSettings(context) });
    return;
  }
  const workerRestart = /^\/api\/workers\/(?<id>[0-9a-f-]+)\/restart$/.exec(url.pathname);
  if (request.method === "POST" && workerRestart?.groups?.id) {
    requirePermission(context, "workers.manage");
    context.execution.restartWorker(workerRestart.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_RESTART_REQUESTED", resourceType: "WORKER", resourceId: workerRestart.groups.id, summary: "Operator requested graceful restart of a job-scoped worker." });
    sendJson(response, 202, { ok: true });
    return;
  }
  const workerQuarantine = /^\/api\/workers\/(?<id>[0-9a-f-]+)\/quarantine$/.exec(url.pathname);
  if (request.method === "POST" && workerQuarantine?.groups?.id) {
    requirePermission(context, "workers.manage");
    const body = await readJson(request) as { reason?: unknown };
    const reason = typeof body.reason === "string" && body.reason.trim().length >= 8 ? body.reason.trim().slice(0, 500) : "Manual operator quarantine";
    context.execution.quarantineWorker(workerQuarantine.groups.id, reason);
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_QUARANTINED", resourceType: "WORKER", resourceId: workerQuarantine.groups.id, summary: "Operator quarantined a worker.", metadata: { reason } });
    sendJson(response, 202, { ok: true });
    return;
  }
  const workerRelease = /^\/api\/workers\/(?<id>[0-9a-f-]+)\/release$/.exec(url.pathname);
  if (request.method === "POST" && workerRelease?.groups?.id) {
    requirePermission(context, "workers.manage");
    context.execution.releaseWorker(workerRelease.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_QUARANTINE_RELEASED", resourceType: "WORKER", resourceId: workerRelease.groups.id, summary: "Operator released an individual worker quarantine record." });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/workers/fleet/quarantine") {
    requirePermission(context, "workers.manage");
    const body = await readJson(request) as { reason?: unknown };
    const reason = typeof body.reason === "string" && body.reason.trim().length >= 8 ? body.reason.trim().slice(0, 500) : "Manual operator quarantine";
    context.execution.quarantineWorkerFleet(reason);
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_FLEET_QUARANTINED", resourceType: "WORKER_FLEET", summary: "Operator blocked new worker dispatch.", metadata: { reason } });
    sendJson(response, 200, { ok: true });
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/workers/fleet/release") {
    requirePermission(context, "workers.manage");
    context.execution.releaseWorkerFleet();
    audit.append({ actorLabel: context.principal?.userId, action: "WORKER_FLEET_RELEASED", resourceType: "WORKER_FLEET", summary: "Operator released worker dispatch and reset crash-loop state." });
    sendJson(response, 200, { ok: true });
    return;
  }
  throw new HttpError(404, "API route not found.");
}

async function assertProviderAdapterExecution(context: ApiContext, request: DashboardScanCreateRequest): Promise<void> {
  try { await context.providerAdapters.assertExecutionBinding(request); }
  catch (error) { throw new HttpError(409, error instanceof Error ? error.message : "PROVIDER_ADAPTER_EXECUTION_REJECTED"); }
}

function requireCredentialUsePermission(context: ApiContext, request: { credentialProfileId?: string | undefined; credentialProfileAId?: string | undefined; credentialProfileBId?: string | undefined; studio?: { authentication: { mode: string; primary?: { source: string }; accountA?: { source: string }; accountB?: { source: string } } } | undefined }): void {
  const studioUsesSaved = request.studio?.authentication.primary?.source === "saved" || request.studio?.authentication.accountA?.source === "saved" || request.studio?.authentication.accountB?.source === "saved";
  if (request.credentialProfileId || request.credentialProfileAId || request.credentialProfileBId || studioUsesSaved) {
    requirePermission(context, "credentials.use");
  }
}

function validateScanReferences(context: ApiContext, request: { projectId?: string | undefined; targetId?: string | undefined; target: string }): void {
  if (request.projectId && !context.projects.get(request.projectId)) throw new HttpError(404, "TARGET_NOT_FOUND: Project not found.");
  if (!request.targetId) return;
  const target = context.targets.get(request.targetId);
  if (!target) throw new HttpError(404, "TARGET_NOT_FOUND: Target not found.");
  if (request.projectId && target.projectId !== request.projectId) throw new HttpError(400, "TARGET_INVALID: Target is not assigned to the selected project.");
  if (new URL(target.baseOrigin).origin !== new URL(request.target).origin) throw new HttpError(400, "TARGET_INVALID: Target URL does not match the selected target record.");
}

function validateTargetDefaults(context: ApiContext, request: { projectId?: string | undefined; defaultConfigurationId?: string | undefined; defaultCredentialProfileId?: string | undefined }): void {
  if (request.projectId && !context.projects.get(request.projectId)) throw new HttpError(404, "Project not found.");
  if (request.defaultConfigurationId && !context.configurations.get(request.defaultConfigurationId)) throw new HttpError(400, "Default configuration is unavailable or archived.");
  if (request.defaultCredentialProfileId) {
    const credential = context.vault.getSummary(request.defaultCredentialProfileId);
    if (!credential || !credential.enabled || ["EXPIRED", "INVALID", "IDENTITY_MISMATCH", "DISABLED"].includes(credential.health.classification)) throw new HttpError(400, "Default credential profile is unavailable or not scan-eligible.");
    if (credential.projectId && request.projectId && credential.projectId !== request.projectId) throw new HttpError(400, "Default credential profile is not assigned to the selected project.");
  }
}

function identityResultCategories(result: Record<string, unknown>): Record<string, string> {
  const categories: Record<string, string> = {};
  for (const slot of ["primary", "accountA", "accountB"] as const) {
    const value = result[slot];
    if (typeof value === "object" && value !== null && "category" in value && typeof value.category === "string") categories[slot] = value.category;
  }
  return categories;
}

async function serveEventStream(context: ApiContext, scanId: string): Promise<void> {
  const lastEventId = Number(context.request.headers["last-event-id"] ?? context.url.searchParams.get("after") ?? 0);
  context.response.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache, no-transform",
    connection: "keep-alive"
  });
  let cursor = Number.isFinite(lastEventId) ? lastEventId : 0;
  const sendEvents = () => {
    const events = context.events.list(scanId, cursor, 100);
    for (const event of events) {
      cursor = event.seq;
      context.response.write(`id: ${event.seq}\n`);
      context.response.write(`event: ${event.eventType}\n`);
      context.response.write(`data: ${JSON.stringify(event)}\n\n`);
    }
    const scan = context.scans.get(scanId);
    if (scan && ["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED", "IMPORTED"].includes(scan.status)) {
      clearInterval(timer);
      context.response.end();
    }
  };
  const timer = setInterval(() => {
    context.response.write(": heartbeat\n\n");
    sendEvents();
  }, 2000);
  context.request.on("close", () => clearInterval(timer));
  sendEvents();
}

function normalizeSavedConfiguration(parsed: ReturnType<typeof savedConfigurationSchema.parse>) {
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

const mutableSettingDefaults = {
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

function mutableSettings(context: ApiContext): Record<string, { value: unknown; defaultValue: unknown; rowVersion: number; source: "database" | "default"; updatedAt?: string }> {
  const rows = context.database.db.prepare("SELECT key, value_json, row_version, updated_at FROM dashboard_settings").all() as Array<{ key: string; value_json: string; row_version: number; updated_at: string }>;
  const stored = new Map(rows.map((row) => [row.key, row]));
  return Object.fromEntries(Object.entries(mutableSettingDefaults).map(([key, defaultValue]) => {
    const row = stored.get(key);
    return [key, row ? { value: JSON.parse(row.value_json), defaultValue, rowVersion: row.row_version, source: "database", updatedAt: row.updated_at } : { value: defaultValue, defaultValue, rowVersion: 1, source: "default" }];
  }));
}

function settingValue(context: ApiContext, key: keyof typeof mutableSettingDefaults, fallback: number): number {
  const setting = mutableSettings(context)[key];
  return typeof setting?.value === "number" ? setting.value : fallback;
}

function environmentSettings(context: ApiContext): Record<string, unknown> {
  return {
    serverMode: { classification: "restart-required", source: "environment", configured: context.mode === "server" },
    publicOrigin: { classification: "restart-required", source: "environment", configured: Boolean(process.env.ROUTECAIRN_PUBLIC_ORIGIN) },
    trustProxy: { classification: "restart-required", source: "environment", configured: process.env.ROUTECAIRN_TRUST_PROXY === "true" },
    masterKey: { classification: "offline-sensitive", source: "environment", configured: context.vault.status().enabled },
    masterKeyVersion: { classification: "offline-sensitive", source: "environment", value: context.vault.status().keyVersion ?? "not configured" }
  };
}

function updateSettings(context: ApiContext, values: Record<string, unknown>, expectedVersions: Record<string, number>, actor?: string): void {
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

function resetSettings(context: ApiContext, keys: string[]): void {
  if (keys.length === 0) context.database.db.prepare("DELETE FROM dashboard_settings").run();
  else context.database.transaction(() => { for (const key of keys) context.database.db.prepare("DELETE FROM dashboard_settings WHERE key = ?").run(key); });
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.length;
    if (size > maxJsonBodyBytes) throw new HttpError(413, "JSON body too large.");
    chunks.push(buffer);
  }
  const raw = Buffer.concat(chunks).toString("utf8") || "{}";
  return JSON.parse(raw);
}

function sendJson(response: ServerResponse, statusCode: number, value: unknown): void {
  response.statusCode = statusCode;
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.end(JSON.stringify(value));
}

function sendError(response: ServerResponse, error: unknown): void {
  const message = error instanceof Error ? error.message : "Dashboard request failed.";
  const conflictCode = /^(PROJECT_CONFLICT|TARGET_CONFLICT|CONFIGURATION_CONFLICT|SETTINGS_CONFLICT|FINAL_OWNER_REQUIRED|CREDENTIAL_IN_USE|CREDENTIAL_DEPENDENCY_IMPACT_CHANGED|CREDENTIAL_CHANGED_AFTER_QUEUE|CREDENTIAL_READINESS_BLOCKED|CREDENTIAL_READINESS_BLOCKED_AT_EXECUTION|RECOVERY_ALREADY_RUNNING|RECOVERY_CHECKPOINT_CHANGED|RECOVERY_NOT_REQUIRED|RECOVERY_TARGET_MISMATCH|RECOVERY_SERVICE_STOPPING):?/.exec(message)?.[1];
  const statusCode = conflictCode ? 409 : error instanceof HttpError || error instanceof FindingCommandError ? error.statusCode : error instanceof PermissionError ? 403 : error instanceof SessionError ? 401 : error instanceof ZodError || error instanceof AppError ? 400 : 500;
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

function workflowErrorCategory(code: string): string {
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

function serveStatic(response: ServerResponse, root: string, pathname: string): void {
  const candidate = pathname === "/" ? join(root, "index.html") : join(root, pathname);
  const filePath = existsSync(candidate) && statSync(candidate).isFile() ? candidate : join(root, "index.html");
  if (!existsSync(filePath)) {
    response.statusCode = 503;
    response.setHeader("content-type", "text/plain; charset=utf-8");
    response.end(`Dashboard UI is not built yet. Run npm run dashboard:build.\nExpected ${pathToFileURL(root).toString()}`);
    return;
  }
  response.setHeader("content-type", contentType(filePath));
  createReadStream(filePath).pipe(response);
}

function serveArtifact(response: ServerResponse, artifact: { path: string; contentType: string; name: string }, roots: readonly string[]): void {
  if (!existsSync(resolve(artifact.path))) throw new HttpError(404, "Artifact file missing.");
  const canonical = realpathSync(resolve(artifact.path));
  const allowed = roots.map((root) => realpathSync(resolve(root))).some((root) => canonical === root || canonical.startsWith(`${root}\\`) || canonical.startsWith(`${root}/`));
  if (!allowed) throw new HttpError(403, "Artifact path blocked.");
  if (!existsSync(canonical) || !statSync(canonical).isFile()) throw new HttpError(404, "Artifact file missing.");
  response.setHeader("content-type", artifact.contentType);
  response.setHeader("content-disposition", `attachment; filename="${artifact.name.replace(/"/g, "")}"`);
  response.setHeader("x-content-type-options", "nosniff");
  createReadStream(canonical).pipe(response);
}

function serveImagePreview(response: ServerResponse, artifact: { path: string; contentType: string; name: string }, roots: readonly string[]): void {
  if (!["image/png", "image/jpeg", "image/webp", "image/gif"].includes(artifact.contentType)) throw new HttpError(415, "Artifact is not a supported preview image.");
  if (!existsSync(resolve(artifact.path))) throw new HttpError(404, "Artifact file missing.");
  const canonical = realpathSync(resolve(artifact.path));
  const allowed = roots.map((root) => realpathSync(resolve(root))).some((root) => canonical === root || canonical.startsWith(`${root}\\`) || canonical.startsWith(`${root}/`));
  if (!allowed) throw new HttpError(403, "Artifact path blocked.");
  const stat = statSync(canonical);
  if (!stat.isFile()) throw new HttpError(404, "Artifact file missing.");
  if (stat.size > 10 * 1024 * 1024) throw new HttpError(413, "Screenshot preview exceeds the 10 MiB preview limit.");
  try {
    const dimensions = inspectImageDimensions(canonical, artifact.contentType);
    response.setHeader("x-routecairn-image-dimensions", `${dimensions.width}x${dimensions.height}`);
  } catch (error) {
    throw new HttpError(415, error instanceof Error ? error.message : "Image dimensions could not be validated.");
  }
  response.setHeader("content-type", artifact.contentType);
  response.setHeader("content-disposition", `inline; filename="${artifact.name.replace(/"/g, "")}"`);
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("content-security-policy", "default-src 'none'; img-src 'self'");
  response.setHeader("cache-control", "private, no-store");
  createReadStream(canonical).pipe(response);
}

function setSecurityHeaders(response: ServerResponse): void {
  response.setHeader("x-content-type-options", "nosniff");
  response.setHeader("referrer-policy", "no-referrer");
  response.setHeader("content-security-policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-src 'self'");
}

function contentType(path: string): string {
  switch (extname(path)) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".js":
      return "text/javascript; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".svg":
      return "image/svg+xml";
    default:
      return "application/octet-stream";
  }
}

function numberParam(url: URL, name: string, fallback: number): number {
  const value = Number(url.searchParams.get(name) ?? fallback);
  return Number.isFinite(value) ? value : fallback;
}

function stringParam(url: URL, name: string): string | undefined {
  const value = url.searchParams.get(name);
  return value && value.length <= 200 ? value : undefined;
}

function scanStatusParam(url: URL) {
  const value = url.searchParams.get("status");
  return value && ["QUEUED", "PLANNING", "RUNNING", "CANCEL_REQUESTED", "CANCELLED", "COMPLETED", "FAILED", "INTERRUPTED", "IMPORTED"].includes(value)
    ? (value as NonNullable<Parameters<ScanRepository["list"]>[1]>["status"])
    : undefined;
}

function scanSortParam(url: URL) {
  const value = url.searchParams.get("sort");
  return value && ["created_desc", "created_asc", "status", "target"].includes(value) ? (value as NonNullable<Parameters<ScanRepository["list"]>[1]>["sort"]) : undefined;
}

function findingQuery(url: URL): FindingQuery {
  return {
    scanId: stringParam(url, "scanId"),
    search: stringParam(url, "q"),
    projectId: stringParam(url, "projectId"),
    targetId: stringParam(url, "targetId"),
    module: stringParam(url, "module"),
    category: stringParam(url, "category"),
    severity: stringParam(url, "severity"),
    confidence: stringParam(url, "confidence"),
    reviewStatus: enumParam(url, "review", ["UNREVIEWED", "IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE", "RESOLVED", "REOPENED"] as const),
    remediationStatus: enumParam(url, "remediation", ["OPEN", "ASSIGNED", "FIX_IN_PROGRESS", "FIXED_PENDING_RETEST", "FIXED_VERIFIED", "WONT_FIX"] as const),
    assigneeUserId: stringParam(url, "assignee"),
    retestStatus: enumParam(url, "retest", ["NOT_RETESTED", "RETEST_SCHEDULED", "RETEST_RUNNING", "RETEST_PASSED", "RETEST_FAILED", "RETEST_INCONCLUSIVE"] as const),
    proofReadiness: enumParam(url, "proof", ["NOT_READY", "MISSING_REVIEW", "MISSING_EVIDENCE", "READY", "IN_PROOF_PACK"] as const),
    firstSeenFrom: stringParam(url, "firstSeenFrom"),
    firstSeenTo: stringParam(url, "firstSeenTo"),
    lastSeenFrom: stringParam(url, "lastSeenFrom"),
    lastSeenTo: stringParam(url, "lastSeenTo"),
    newOccurrence: booleanParam(url, "newOccurrence"),
    reopened: booleanParam(url, "reopened"),
    sourceKind: enumParam(url, "source", ["NATIVE", "IMPORTED"] as const),
    evidence: enumParam(url, "evidence", ["HAS_EVIDENCE", "MISSING_EVIDENCE"] as const),
    sort: enumParam(url, "sort", ["severity_desc", "confidence_desc", "first_seen_desc", "last_seen_desc", "occurrences_desc", "review", "remediation", "target", "project"] as const),
    page: numberParam(url, "page", 1),
    pageSize: numberParam(url, "pageSize", numberParam(url, "limit", 25))
  };
}

function enumParam<const T extends string>(url: URL, name: string, allowed: readonly T[]): T | undefined {
  const value = url.searchParams.get(name);
  if (!value) return undefined;
  if (!allowed.includes(value as T)) throw new FindingCommandError("FINDING_FILTER_INVALID", `Unsupported ${name} filter.`);
  return value as T;
}

function booleanParam(url: URL, name: string): boolean | undefined {
  const value = url.searchParams.get(name);
  if (value === null || value === "") return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new FindingCommandError("FINDING_FILTER_INVALID", `${name} must be true or false.`);
}

function correlationId(request: IncomingMessage): string {
  const value = request.headers["x-request-id"];
  return typeof value === "string" && /^[a-zA-Z0-9._-]{1,100}$/.test(value) ? value : randomUUID();
}

function reviewAuditAction(status: ReviewStatus): string {
  switch (status) {
    case "IN_REVIEW": return "FINDING_REVIEW_STARTED";
    case "CONFIRMED": return "FINDING_CONFIRMED";
    case "FALSE_POSITIVE": return "FINDING_FALSE_POSITIVE";
    case "ACCEPTED_RISK": return "FINDING_ACCEPTED_RISK";
    case "DUPLICATE": return "FINDING_DUPLICATE_MARKED";
    case "RESOLVED": return "FINDING_RESOLVED";
    case "REOPENED": return "FINDING_REOPENED";
    case "UNREVIEWED": return "FINDING_REVIEW_RESET";
  }
}

class HttpError extends Error {
  public constructor(public readonly statusCode: number, message: string) {
    super(message);
    this.name = "HttpError";
  }
}
