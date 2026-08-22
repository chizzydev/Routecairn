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
import { credentialMetadataSchema, credentialProfileSchema, credentialSecretSchema, dashboardScanCreateSchema, compareRequestSchema, dashboardSettingsUpdateSchema, importReportSchema, loginSchema, projectSchema, proofPackCreateSchema, savedConfigurationSchema, targetSchema, userCreateSchema, userUpdateSchema } from "../contracts/DashboardSchemas.js";
import { ScanExecutionService } from "../execution/ScanExecutionService.js";
import { ComparisonService } from "../services/ComparisonService.js";
import { HistoricalReportImporter } from "../import/HistoricalReportImporter.js";
import { ProofPackService } from "../proofPacks/ProofPackService.js";
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
  const retestTemplates = new RetestTemplateVault(database.db, vaultKey);
  const findingCommandCenter = new FindingCommandCenterService(database, retestTemplates);
  const execution = new ScanExecutionService(database, paths, vault, retestTemplates);
  const comparison = new ComparisonService(database);
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
      await execution.shutdown();
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
      modules: Object.values(registry.modules)
    });
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
    sendJson(response, 200, { profile, dependencies: context.vault.dependencies(credentialDetail.groups.id) });
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
  if (request.method === "POST" && url.pathname === "/api/controlled-mutations/approvals") {
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
    const parsed = credentialSecretSchema.parse(await readJson(request));
    context.vault.replaceSecret(credentialSecret.groups.id, parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_SECRET_REPLACED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialSecret.groups.id, summary: "Credential secret material replaced; no secret value was retained in audit output." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialEnable = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/enable$/.exec(url.pathname);
  if (request.method === "POST" && credentialEnable?.groups?.id) {
    requirePermission(context, "credentials.update");
    context.vault.setEnabled(credentialEnable.groups.id, true);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_ENABLED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialEnable.groups.id, summary: "Credential profile enabled." });
    sendJson(response, 200, { ok: true });
    return;
  }
  const credentialDisable = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)\/disable$/.exec(url.pathname);
  if (request.method === "POST" && credentialDisable?.groups?.id) {
    requirePermission(context, "credentials.update");
    context.vault.setEnabled(credentialDisable.groups.id, false);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_PROFILE_DISABLED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialDisable.groups.id, summary: "Credential profile disabled." });
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
    const secret = context.vault.decryptForUse(credentialTest.groups.id);
    audit.append({ actorLabel: context.principal?.userId, action: "CREDENTIAL_TEST_EXECUTED", resourceType: "CREDENTIAL_PROFILE", resourceId: credentialTest.groups.id, summary: "Credential profile decrypted for bounded local validation." });
    sendJson(response, 200, { ok: true, hasAuthorizationHeader: Boolean(secret.authorizationHeader), cookieCount: Object.keys(secret.cookies ?? {}).length, headerCount: Object.keys(secret.headers ?? {}).length, hasIdentityVerification: Boolean(secret.identityVerification) });
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
    const preview = await execution.preview(parsed);
    audit.append({ actorLabel: context.principal?.userId, action: "SCAN_STUDIO_PLAN_PREVIEW", resourceType: "TARGET", resourceId: parsed.targetId, summary: `Plan preview resolved for ${new URL(parsed.target).origin}.`, metadata: { projectId: parsed.projectId, profile: parsed.profile, moduleCount: preview.modules.length, studioVersion: parsed.studio?.version } });
    sendJson(response, 200, preview);
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
    const scanId = await execution.enqueue(parsed);
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
  throw new HttpError(404, "API route not found.");
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
    if (!credential || !credential.enabled) throw new HttpError(400, "Default credential profile is unavailable or disabled.");
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
  queueCapacity: 20
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
  const conflictCode = /^(PROJECT_CONFLICT|TARGET_CONFLICT|CONFIGURATION_CONFLICT|SETTINGS_CONFLICT|FINAL_OWNER_REQUIRED|CREDENTIAL_IN_USE):?/.exec(message)?.[1];
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
