import { readBoundedFileSync } from "../security/BoundedFile.js";
import { mkdirSync, realpathSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ControlPlaneInfrastructure } from "../../controlPlane/ControlPlaneInfrastructure.js";
import { acquireDashboardSingleton } from "../../controlPlane/DashboardSingleton.js";
import { decryptKmsConfigurationSecret } from "../../controlPlane/KeyManagement.js";
import { LocalSessionManager, SessionError } from "../auth/LocalSession.js";
import { ServerSessionManager, type ServerRuntimeSecurity } from "../auth/ServerSession.js";
import { ScanComparisonService } from "../comparisons/ScanComparisonService.js";
import { deploymentTriggerSchema } from "../contracts/ContinuousAssuranceSchemas.js";
import { loginSchema } from "../contracts/DashboardSchemas.js";
import { cloudSyncPushSchema, remoteHeartbeatSchema, remoteJobLeaseRenewSchema, remoteJobResultSchema, remoteWorkerEnrollSchema } from "../contracts/OperationalScaleSchemas.js";
import { CredentialVault, parseVaultKey } from "../credentials/CredentialVault.js";
import { ControlledMutationApprovalRepository } from "../db/ControlledMutationApprovalRepository.js";
import { DashboardDatabase } from "../db/DashboardDatabase.js";
import { ArtifactRepository, AuditRepository, EventRepository, FindingRepository, ProjectRepository, SavedConfigurationRepository, ScanRepository, TargetRepository } from "../db/DashboardRepositories.js";
import { AdaptiveSecurityService } from "../execution/AdaptiveSecurityService.js";
import { ContinuousAssuranceService } from "../execution/ContinuousAssuranceService.js";
import { ControlledMutationRecoveryService } from "../execution/ControlledMutationRecoveryService.js";
import { EvidenceGovernanceService } from "../execution/EvidenceGovernanceService.js";
import { LiveAcceptanceService } from "../execution/LiveAcceptanceService.js";
import { ProviderAdapterService } from "../execution/ProviderAdapterService.js";
import { ScanExecutionService } from "../execution/ScanExecutionService.js";
import { WorkflowRecoveryService } from "../execution/WorkflowRecoveryService.js";
import { FindingCommandCenterService } from "../findings/FindingCommandCenterService.js";
import { HistoricalReportImporter } from "../import/HistoricalReportImporter.js";
import { BackupRestoreService } from "../operations/BackupRestoreService.js";
import { CloudSyncService } from "../operations/CloudSyncService.js";
import { DistributedMutationCoordinatorService } from "../operations/DistributedMutationCoordinatorService.js";
import { IntegrationExportService } from "../operations/IntegrationExportService.js";
import { NotificationService } from "../operations/NotificationService.js";
import { OrganizationService } from "../operations/OrganizationService.js";
import { SsoService } from "../operations/SsoService.js";
import { ThirdPartyModuleService } from "../operations/ThirdPartyModuleService.js";
import { ProofPackService } from "../proofPacks/ProofPackService.js";
import { RetestTemplateVault } from "../retests/RetestTemplateVault.js";
import { ComparisonService } from "../services/ComparisonService.js";
import { isLoopbackHost, resolveDashboardPaths } from "../services/DashboardPaths.js";
import { readJson, redirect, requireRuntimeMutation, requireRuntimeSession, routeTemplate, sendError, sendJson, type ApiContext } from "./DashboardApiContext.js";
import { handleApiMutation } from "./DashboardApiMutation.js";
import { handleApiGet } from "./DashboardApiRead.js";
import { HttpError, serveStatic, setSecurityHeaders } from "./DashboardHttpSupport.js";

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
  mutationCoordinatorSecret?: string;
}

export interface DashboardServerHandle {
  url: string;
  bootstrapUrl?: string;
  close(): Promise<void>;
}

export function packagedDashboardUiDirectory(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "../../../apps/dashboard-ui/dist");
}

export async function startDashboardServer(options: DashboardServerOptions = {}): Promise<DashboardServerHandle> {
  const host = options.host ?? "127.0.0.1";
  const mode = options.mode ?? (process.env.ROUTECAIRN_DASHBOARD_MODE === "server" ? "server" : "local");
  const serverSecurity = validateDashboardStartup({ ...options, host, mode });
  if (mode === "local" && !isLoopbackHost(host)) {
    throw new Error("RouteCairn Dashboard refuses non-loopback binding in local mode.");
  }
  const paths = resolveDashboardPaths(options.dataDir);
  const vaultKey = parseVaultKey(await dashboardMasterKey(options), options.masterKeyVersion ?? process.env.ROUTECAIRN_MASTER_KEY_VERSION ?? "1");
  mkdirSync(paths.reportsDir, { recursive: true });
  mkdirSync(paths.artifactsDir, { recursive: true });
  mkdirSync(paths.proofPacksDir, { recursive: true });
  mkdirSync(paths.mutationJournalDir, { recursive: true });
  mkdirSync(paths.workersDir, { recursive: true });
  mkdirSync(paths.backupsDir, { recursive: true });
  mkdirSync(paths.integrationsDir, { recursive: true });
  mkdirSync(paths.thirdPartyModulesDir, { recursive: true });
  mkdirSync(paths.objectCacheDir, { recursive: true });
  const dashboardOwner=await acquireDashboardSingleton();
  let startupCleanup:(()=>Promise<void>)|undefined;
  try {
  BackupRestoreService.applyStagedRestore(paths, vaultKey);
  const database = new DashboardDatabase(paths.databasePath);
  database.migrate();
  database.recoverInterruptedScans();
  const infrastructure = await ControlPlaneInfrastructure.start(database, paths);
  startupCleanup=async()=>{await infrastructure.shutdown();database.close();};
  database.observeEvents((event) => { void infrastructure.publish("scan-events", event.scanId, { eventType: event.eventType, seq: event.seq, ...(event.moduleId ? { moduleId: event.moduleId } : {}), message: event.message, metadata: event.metadata, createdAt: event.createdAt }).catch(()=>infrastructure.telemetry.log("warn","Scan notification deferred; persisted events remain available.")); });
  database.observeArtifacts((artifact) => infrastructure.uploadEvidence(artifact));

  const localSessions = mode === "local" ? new LocalSessionManager() : undefined;
  const serverSessions = mode === "server" && serverSecurity ? new ServerSessionManager(database, serverSecurity) : undefined;
  if (serverSessions && !serverSessions.hasEnabledOwner()) {
    const bootstrapOwner = serverBootstrapOwner();
    if (bootstrapOwner) await serverSessions.createFirstOwner(bootstrapOwner.login, bootstrapOwner.password);
    else throw new Error("RouteCairn Dashboard server mode requires a first owner. Run routecairn dashboard user create-owner or configure the one-time bootstrap owner environment variables.");
  }
  const scans = new ScanRepository(database);
  const projects = new ProjectRepository(database);
  const targets = new TargetRepository(database);
  const findings = new FindingRepository(database);
  const events = new EventRepository(database);
  const artifacts = new ArtifactRepository(database);
  const configurations = new SavedConfigurationRepository(database);
  const audit = new AuditRepository(database);
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
  const continuousAssurance = new ContinuousAssuranceService(database, paths, execution, providerAdapters, new ScanComparisonService(database), evidenceGovernance, { startTimers: infrastructure.config.mode === "local" });
  const proofPacks = new ProofPackService(database, paths);
  const organizations = new OrganizationService(database);
  const notifications = new NotificationService(database); if(infrastructure.config.mode==="local")notifications.start();
  const remoteWorkers = infrastructure.remoteWorkers;
  const cloudSync = new CloudSyncService(database, vault); if(infrastructure.config.mode==="local")cloudSync.start();
  if(infrastructure.config.mode==="distributed"){
    infrastructure.registerScheduledTask("notifications",2_000,async()=>notifications.flush());
    infrastructure.registerScheduledTask("continuous-assurance",15_000,async()=>{await continuousAssurance.reconcileNow();await continuousAssurance.processDueNow();});
    infrastructure.registerScheduledTask("cloud-sync",Number(process.env.ROUTECAIRN_CLOUD_SYNC_INTERVAL_MS??30_000),async()=>{await cloudSync.synchronizeNow();});
  }
  const backups = new BackupRestoreService(database, paths, vaultKey);
  const integrationExports = new IntegrationExportService(database, paths);
  const thirdPartyModules = new ThirdPartyModuleService(database, paths);
  const sso = new SsoService(database);
  const mutationCoordinatorSecret = options.mutationCoordinatorSecret ?? environmentSecret("ROUTECAIRN_MUTATION_COORDINATOR_SECRET");
  const mutationCoordinator = mutationCoordinatorSecret ? new DistributedMutationCoordinatorService(database, mutationCoordinatorSecret) : undefined;
  const importer = new HistoricalReportImporter(database, paths);
  const uiDistDir = options.uiDistDir ?? packagedDashboardUiDirectory();

  const server = createServer(async (request, response) => {
    const requestSpan=infrastructure.telemetry.startSpan("http.request",{method:request.method??"UNKNOWN",route:routeTemplate((request.url??"/").split("?",1)[0]??"/")});
    response.once("finish",()=>{requestSpan.setAttribute("http.response.status_code",response.statusCode);if(response.statusCode>=500)requestSpan.setStatus({code:2});requestSpan.end();});
    try {
      setSecurityHeaders(response);
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? `${host}:${options.port ?? 0}`}`);
      response.once("finish", () => infrastructure.telemetry.countRequest(routeTemplate(url.pathname), response.statusCode));
      if (request.method === "GET" && url.pathname === "/healthz") {
        response.setHeader("cache-control", "no-store");
        sendJson(response, 200, { status: "ok" });
        return;
      }
      if (request.method === "GET" && url.pathname === "/readyz") {
        database.db.prepare("SELECT 1").get();
        const readiness = await infrastructure.ready();
        response.setHeader("cache-control", "no-store");
        sendJson(response, readiness.ready ? 200 : 503, readiness.mode === "distributed" ? { status: readiness.ready ? "ready" : "unavailable", infrastructure: readiness } : { status: readiness.ready ? "ready" : "unavailable" });
        return;
      }
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
      if (request.method === "GET" && url.pathname === "/api/auth/sso/providers") {
        sendJson(response, 200, { providers: sso.list() }); return;
      }
      const ssoStart = /^\/api\/auth\/sso\/(?<id>[0-9a-f-]+)\/start$/.exec(url.pathname);
      if (request.method === "GET" && ssoStart?.groups?.id) {
        if (!serverSessions || !serverSecurity) throw new HttpError(404, "SSO is unavailable in local mode.");
        const redirectUri = `${serverSecurity.publicOrigin}/api/auth/sso/${ssoStart.groups.id}/callback`;
        redirect(response, sso.start(ssoStart.groups.id, redirectUri)); return;
      }
      const ssoCallback = /^\/api\/auth\/sso\/(?<id>[0-9a-f-]+)\/callback$/.exec(url.pathname);
      if (request.method === "GET" && ssoCallback?.groups?.id) {
        if (!serverSessions || !serverSecurity) throw new HttpError(404, "SSO is unavailable in local mode.");
        const state = url.searchParams.get("state") ?? ""; const code = url.searchParams.get("code") ?? "";
        const userId = await sso.callback(ssoCallback.groups.id, state, code); const session = serverSessions.loginFederated(userId, request, response);
        audit.append({ actorLabel: session.user.id, action: "SSO_LOGIN_SUCCESS", resourceType: "SESSION", summary: "Federated dashboard login succeeded." });
        redirect(response, serverSecurity.publicOrigin); return;
      }
      if (request.method === "POST" && url.pathname === "/api/remote-agents/enroll") {
        const result=await remoteWorkers.enroll(remoteWorkerEnrollSchema.parse(await readJson(request)));cloudSync.record(await remoteWorkers.organizationForWorker(result.workerId),"remote-worker",result.workerId,"UPSERT",{status:"ONLINE",generation:result.generation});sendJson(response, 201, result); return;
      }
      if (request.method === "POST" && url.pathname.startsWith("/api/remote-agents/worker/")) {
        const body = await readJson(request); const worker = await remoteWorkers.authenticate(request.method, url.pathname, body, request.headers); await infrastructure.verifyWorkerIdentity(request, worker);
        if (url.pathname.endsWith("/heartbeat")) { await remoteWorkers.heartbeat(worker, remoteHeartbeatSchema.parse(body)); sendJson(response, 200, { ok: true }); return; }
        if (url.pathname.endsWith("/claim")) { sendJson(response, 200, await remoteWorkers.claim(worker, infrastructure.config.queue.claimWaitMs)); return; }
        const renew = /^\/api\/remote-agents\/worker\/jobs\/(?<id>[0-9a-f-]+)\/renew$/.exec(url.pathname);
        if (renew?.groups?.id) { const parsed=remoteJobLeaseRenewSchema.parse(body); sendJson(response,200,await remoteWorkers.renew(worker,renew.groups.id,parsed.leaseToken));return; }
        const complete = /^\/api\/remote-agents\/worker\/jobs\/(?<id>[0-9a-f-]+)\/complete$/.exec(url.pathname);
        if (complete?.groups?.id) { const parsed = remoteJobResultSchema.parse(body); await remoteWorkers.complete(worker, complete.groups.id, { leaseToken: parsed.leaseToken, status: parsed.status, ...(parsed.result ? { result: parsed.result } : {}), ...(parsed.error ? { error: parsed.error } : {}) }); cloudSync.record(worker.organization_id,"remote-job",complete.groups.id,"UPSERT",{status:parsed.status,workerId:worker.id});sendJson(response, 200, { ok: true }); return; }
        throw new HttpError(404, "Remote agent operation not found.");
      }
      if (request.method === "POST" && url.pathname === "/api/cloud-sync/receive") {
        const body = cloudSyncPushSchema.parse(await readJson(request, 16 * 1024 * 1024)); const peerName = String(request.headers["x-routecairn-sync-peer"] ?? ""); const signature = String(request.headers["x-routecairn-sync-signature"] ?? "");
        sendJson(response, 200, cloudSync.receiveFromPeer(peerName, body, signature)); return;
      }
      if (request.method === "POST" && url.pathname.startsWith("/api/mutation-coordination/")) {
        if (!mutationCoordinator) throw new HttpError(404, "Distributed mutation coordination is not configured.");
        const body = await readJson(request); mutationCoordinator.authenticate(request.method, url.pathname, body, request.headers);
        if (url.pathname.endsWith("/acquire")) { sendJson(response, 201, mutationCoordinator.acquire(body)); return; }
        if (url.pathname.endsWith("/renew")) { sendJson(response, 200, mutationCoordinator.renew(body)); return; }
        if (url.pathname.endsWith("/release")) { sendJson(response, 200, mutationCoordinator.release(body)); return; }
        throw new HttpError(404, "Mutation coordination operation not found.");
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
          ,organizations
          ,notifications
          ,remoteWorkers
          ,cloudSync
          ,backups
          ,integrationExports
          ,thirdPartyModules
          ,sso
          ,mutationCoordinator
          ,infrastructure
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
  let closed=false;
  const close=async()=>{
      if(closed)return;closed=true;
      continuousAssurance.shutdown();
      await cloudSync.shutdown();
      await notifications.shutdown();
      await execution.shutdown();
      await mutationRecovery.shutdown();
      await workflowRecovery.shutdown();
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      await infrastructure.shutdown();
      database.close();
      await dashboardOwner.release();
  };
  dashboardOwner.onLost(()=>{server.closeAllConnections();void close();});
  return {url,...(localSessions ? { bootstrapUrl: localSessions.bootstrapUrl(url) } : {}),close};
  } catch(error) {
    await startupCleanup?.();
    await dashboardOwner.release();
    throw error;
  };
}

export function validateDashboardStartup(options: Required<Pick<DashboardServerOptions, "host" | "mode">> & DashboardServerOptions): ServerRuntimeSecurity | undefined {
  if (options.mode === "server") {
    const publicOrigin = options.publicOrigin ?? process.env.ROUTECAIRN_PUBLIC_ORIGIN;
    const sessionSecret = options.sessionSecret ?? environmentSecret("ROUTECAIRN_SESSION_SECRET");
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

export function serverBootstrapOwner(): { login: string; password: string } | undefined {
  const login = process.env.ROUTECAIRN_BOOTSTRAP_OWNER_LOGIN?.trim();
  const hasPasswordSource = Boolean(process.env.ROUTECAIRN_BOOTSTRAP_OWNER_PASSWORD_FILE?.trim() || process.env.ROUTECAIRN_BOOTSTRAP_OWNER_PASSWORD);
  if (!login && !hasPasswordSource) return undefined;
  if (!login || !hasPasswordSource) {
    throw new Error("One-time owner bootstrap requires ROUTECAIRN_BOOTSTRAP_OWNER_LOGIN and exactly one password source.");
  }
  const password = environmentSecret("ROUTECAIRN_BOOTSTRAP_OWNER_PASSWORD", 16_384);
  if (!password) throw new Error("The owner bootstrap password source is empty.");
  return { login, password };
}

export async function dashboardMasterKey(options: DashboardServerOptions): Promise<string | undefined> {
  if (options.masterKey) return options.masterKey;
  const direct=environmentSecret("ROUTECAIRN_MASTER_KEY");const ciphertextFile=process.env.ROUTECAIRN_MASTER_KEY_KMS_CIPHERTEXT_FILE?.trim();const keyId=process.env.ROUTECAIRN_MASTER_KEY_KMS_KEY_ID?.trim();
  if (direct && (ciphertextFile || keyId)) throw new Error("Raw and KMS-backed dashboard master keys cannot both be configured.");
  if (!ciphertextFile && !keyId) return direct;if(!ciphertextFile||!keyId)throw new Error("KMS-backed dashboard master key requires both key ID and ciphertext file.");
  const canonical=realpathSync(ciphertextFile);const bytes=readBoundedFileSync(canonical,64*1024);if(bytes.length<32)throw new Error("KMS dashboard master-key ciphertext file is invalid.");
  const encoded=bytes.toString("utf8").trim();if(!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))throw new Error("KMS dashboard master-key ciphertext must be base64.");
  return decryptKmsConfigurationSecret({keyId,ciphertext:Buffer.from(encoded,"base64"),...(process.env.AWS_REGION?{region:process.env.AWS_REGION}:{}),...(process.env.ROUTECAIRN_KMS_ENDPOINT?{endpoint:process.env.ROUTECAIRN_KMS_ENDPOINT}:{}),context:{purpose:"routecairn-dashboard-master-key"}});
}

export function environmentSecret(name: string, maxBytes = 65_536): string | undefined {
  const inline = process.env[name];
  const file = process.env[`${name}_FILE`]?.trim();
  if (inline && file) throw new Error(`${name} and ${name}_FILE cannot both be configured.`);
  if (!file) return inline;
  const canonical = realpathSync(file);
  const value = readBoundedFileSync(canonical, maxBytes).toString("utf8").replace(/[\r\n]+$/, "");
  return value || undefined;
}

export async function handleApi(context: ApiContext): Promise<void> {
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
