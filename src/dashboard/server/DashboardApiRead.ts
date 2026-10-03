import { createReadStream,existsSync } from "node:fs";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";
import { routeCairnCapabilityRegistry } from "../../core/planning/RouteCairnCapabilityRegistry.js";
import { capabilityParityManifest,validateCapabilityParityManifest } from "../admin/CapabilityParityManifest.js";
import { advancedEngineCatalog,loadAdvancedEngineCatalog } from "../contracts/AdvancedEngineSchemas.js";
import { AssistedReviewService } from "../reviews/AssistedReviewService.js";
import { environmentSettings,mutableSettings,operationalOrganization,requireOrg,requirePermission,requireSelectedComparison,requireSelectedResource,resourceOrganization,sendJson,serveEventStream,settingValue,type ApiContext } from "./DashboardApiContext.js";
import {
HttpError,
booleanParam,
enumParam,
findingQuery,
numberParam,
scanSortParam,
scanStatusParam,
serveArtifact,
serveImagePreview,
stringParam
} from "./DashboardHttpSupport.js";

export async function handleApiGet(context: ApiContext): Promise<void> {
  const { response, url, scans, projects, targets, findingCommandCenter, comparison, events, artifacts, paths } = context;
  const assistedReview = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/assisted-review$/.exec(url.pathname);
  if (assistedReview?.groups?.id) {
    requirePermission(context, "findings.read");
    requireSelectedResource(context,"scan",assistedReview.groups.id,"org.read");
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
  if (url.pathname === "/api/operations/organizations") {
    requirePermission(context, "operations.read"); sendJson(response, 200, { organizations: context.organizations.list(context.principal!.userId, context.mode === "local") }); return;
  }
  const organizationDetail = /^\/api\/operations\/organizations\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (organizationDetail?.groups?.id) {
    requirePermission(context, "operations.read"); sendJson(response, 200, context.organizations.detail(organizationDetail.groups.id, context.principal!.userId, context.mode === "local")); return;
  }
  if (url.pathname === "/api/operations/notifications") {
    requirePermission(context, "operations.read"); const organizationId = operationalOrganization(context); requireOrg(context, organizationId, "org.read"); sendJson(response, 200, { channels: context.notifications.list(organizationId), deliveries: context.notifications.deliveries(organizationId) }); return;
  }
  if (url.pathname === "/api/operations/remote-workers") {
    requirePermission(context, "operations.read"); const organizationId = operationalOrganization(context); requireOrg(context, organizationId, "org.read"); sendJson(response, 200, await context.remoteWorkers.list(organizationId)); return;
  }
  if (url.pathname === "/api/operations/infrastructure") {
    requirePermission(context,"operations.read");sendJson(response,200,{infrastructure:await context.infrastructure.ready(),queue:{claimWaitMs:context.infrastructure.config.queue.claimWaitMs,leaseMs:context.infrastructure.config.queue.leaseMs},telemetry:{enabled:Boolean(context.infrastructure.config.telemetry.otlpEndpoint)},workloadIdentity:{required:context.infrastructure.config.workloadIdentity.required,issuerCount:context.infrastructure.config.workloadIdentity.trustedIssuers.length},evidence:{provider:context.infrastructure.objectStore.kind}});return;
  }
  if (url.pathname === "/api/operations/mutation-coordination") {
    requirePermission(context, "operations.read"); if (!context.mutationCoordinator) throw new HttpError(404, "Distributed mutation coordination is not configured.");
    const namespace = url.searchParams.get("namespace") ?? ""; sendJson(response, 200, context.mutationCoordinator.status(namespace)); return;
  }
  if (url.pathname === "/api/operations/cloud-sync") {
    requirePermission(context, "operations.read"); const organizationId = operationalOrganization(context); requireOrg(context, organizationId, "org.read"); sendJson(response, 200, { peers: context.cloudSync.list(organizationId), replicas: context.cloudSync.replicas(organizationId), pendingMemberships: context.cloudSync.pendingMemberships(organizationId) }); return;
  }
  if (url.pathname === "/api/operations/backups") {
    requirePermission(context, "operations.read"); sendJson(response, 200, { backups: context.backups.list(), restorePending: existsSync(context.paths.restoreMarkerPath) }); return;
  }
  if (url.pathname === "/api/operations/integrations") {
    requirePermission(context, "operations.read"); const organizationId = operationalOrganization(context); requireOrg(context, organizationId, "org.read"); sendJson(response, 200, { exports: context.integrationExports.list(organizationId) }); return;
  }
  if (url.pathname === "/api/operations/modules") {
    requirePermission(context, "operations.read"); const organizationId = operationalOrganization(context); requireOrg(context, organizationId, "org.read"); sendJson(response, 200, { modules: context.thirdPartyModules.list(organizationId) }); return;
  }
  if (url.pathname === "/api/operations/sso") {
    requirePermission(context, "operations.read"); const organizationId = operationalOrganization(context); requireOrg(context, organizationId, "org.read"); sendJson(response, 200, { providers: context.sso.list(organizationId) }); return;
  }
  if (url.pathname === "/api/users") {
    requirePermission(context, "users.manage");
    sendJson(response, 200, { mode: context.mode, users: context.serverSessions?.listUsers() ?? [] });
    return;
  }
  if (url.pathname === "/api/overview") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, scans.overview(resourceOrganization(context)));
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
    const targetId=url.searchParams.get("targetId");
    if(targetId)requireSelectedResource(context,"target",targetId,"org.read");
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
    requireSelectedResource(context,"scan",baselineCases.groups.id,"org.read");
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
    sendJson(response, 200, { profiles: context.vault.list(resourceOrganization(context)) });
    return;
  }
  const credentialDetail = /^\/api\/credential-profiles\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (credentialDetail?.groups?.id) {
    requirePermission(context, "credentials.readSummary");
    const organizationId = resourceOrganization(context);
    const profile = context.vault.getSummary(credentialDetail.groups.id, organizationId);
    if (!profile) throw new HttpError(404, "Credential profile not found.");
    sendJson(response, 200, { profile, dependencies: context.vault.dependencies(credentialDetail.groups.id), healthTimeline: context.vault.healthTimeline(credentialDetail.groups.id) });
    return;
  }
  if (url.pathname === "/api/projects") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { projects: projects.list(stringParam(url, "q"), booleanParam(url, "includeArchived") === true, resourceOrganization(context)) });
    return;
  }
  const project = /^\/api\/projects\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (project?.groups?.id) {
    const organizationId = resourceOrganization(context);
    const item = projects.get(project.groups.id, booleanParam(url, "includeArchived") === true, organizationId);
    if (!item) throw new HttpError(404, "Project not found.");
    sendJson(response, 200, { project: item, targets: targets.list({ organizationId, projectId: project.groups.id }), scans: scans.list(25, { organizationId, projectId: project.groups.id }), comparisons: comparison.list({ organizationId, projectId: project.groups.id, limit: 20 }), findingIntelligence: findingCommandCenter.intelligence({ projectId: project.groups.id }) });
    return;
  }
  if (url.pathname === "/api/targets") {
    requirePermission(context, "scans.read");
    sendJson(response, 200, { targets: targets.list({ organizationId: resourceOrganization(context), projectId: stringParam(url, "projectId"), search: stringParam(url, "q"), includeArchived: booleanParam(url, "includeArchived") === true }) });
    return;
  }
  const target = /^\/api\/targets\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (target?.groups?.id) {
    const organizationId = resourceOrganization(context);
    const item = targets.get(target.groups.id, booleanParam(url, "includeArchived") === true, organizationId);
    if (!item) throw new HttpError(404, "Target not found.");
    sendJson(response, 200, { target: item, comparisons: comparison.list({ organizationId, targetId: target.groups.id, limit: 20 }), findingIntelligence: findingCommandCenter.intelligence({ targetId: target.groups.id }) });
    return;
  }
  if (url.pathname === "/api/audit-events") {
    requirePermission(context, "audit.read");
    sendJson(response, 200, { events: context.audit.list({ search: stringParam(url, "q"), action: stringParam(url, "action"), resourceType: stringParam(url, "resourceType"), limit: numberParam(url, "limit", 100) }) });
    return;
  }
  if (url.pathname === "/api/scans") {
    requirePermission(context, "scans.read");
    const organizationId = resourceOrganization(context);
    sendJson(response, 200, {
      scans: scans.list(numberParam(url, "limit", 50), {
        organizationId,
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
    const organizationId=resourceOrganization(context),targetId=stringParam(url,"targetId");
    if(targetId)requireSelectedResource(context,"target",targetId,"org.read");
    sendJson(response, 200, { scans: comparison.candidates(targetId,organizationId) });
    return;
  }
  if (url.pathname === "/api/comparisons") {
    requirePermission(context, "comparisons.read");
    const targetId = stringParam(url, "targetId"), projectId = stringParam(url, "projectId");
    const organizationId=resourceOrganization(context);
    if(targetId)requireSelectedResource(context,"target",targetId,"org.read");
    if(projectId)requireSelectedResource(context,"project",projectId,"org.read");
    sendJson(response, 200, { comparisons: comparison.list({ organizationId, ...(targetId ? { targetId } : {}), ...(projectId ? { projectId } : {}), limit: numberParam(url, "limit", 50) }) });
    return;
  }
  const comparisonDetail = /^\/api\/comparisons\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (comparisonDetail?.groups?.id) {
    requirePermission(context, "comparisons.read");
    requireSelectedComparison(context,comparisonDetail.groups.id);
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
    requireSelectedComparison(context,comparisonExport.groups.id);
    const format = comparisonExport.groups.format as "json" | "markdown";
    response.statusCode = 200;
    response.setHeader("content-type", format === "json" ? "application/json; charset=utf-8" : "text/markdown; charset=utf-8");
    response.setHeader("content-disposition", `attachment; filename=routecairn-comparison-${comparisonExport.groups.id}.${format === "json" ? "json" : "md"}`);
    response.end(comparison.export(comparisonExport.groups.id, format));
    return;
  }
  if (url.pathname === "/api/findings") {
    requirePermission(context, "findings.read");
    sendJson(response, 200, findingCommandCenter.list({ ...findingQuery(url), organizationId: resourceOrganization(context) }));
    return;
  }
  if (url.pathname === "/api/findings/queue") {
    requirePermission(context, "findings.read");
    sendJson(response, 200, findingCommandCenter.queue(stringParam(url, "mode") ?? "UNREVIEWED", { ...findingQuery(url), organizationId: resourceOrganization(context) }));
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
    sendJson(response, 200, { proofPacks: context.proofPacks.list(resourceOrganization(context)) });
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
    sendJson(response, 200, { configurations: context.configurations.list(stringParam(url, "q"), booleanParam(url, "includeArchived") === true,resourceOrganization(context)) });
    return;
  }
  const configuration = /^\/api\/configurations\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (configuration?.groups?.id) {
    requirePermission(context, "scans.create");
    const organizationId=resourceOrganization(context);
    const item = context.configurations.get(configuration.groups.id, booleanParam(url, "includeArchived") === true,organizationId);
    if (!item) throw new HttpError(404, "Configuration not found.");
    sendJson(response, 200, { configuration: item, history: context.configurations.history(configuration.groups.id,organizationId) });
    return;
  }
  const configurationDiff = /^\/api\/configurations\/(?<id>[0-9a-f-]+)\/diff$/.exec(url.pathname);
  if (configurationDiff?.groups?.id) {
    requirePermission(context, "scans.create");
    sendJson(response, 200, context.configurations.diff(configurationDiff.groups.id, numberParam(url, "older", 1), numberParam(url, "newer", 1),resourceOrganization(context)));
    return;
  }
  const stream = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/stream$/.exec(url.pathname);
  if (stream?.groups?.id) {
    requirePermission(context, "scans.read");
    if (!scans.get(stream.groups.id, resourceOrganization(context))) throw new HttpError(404, "Scan not found.");
    await serveEventStream(context, stream.groups.id);
    return;
  }
  const scanEvents = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/events$/.exec(url.pathname);
  if (scanEvents?.groups?.id) {
    requirePermission(context, "scans.read");
    if (!scans.get(scanEvents.groups.id, resourceOrganization(context))) throw new HttpError(404, "Scan not found.");
    sendJson(response, 200, { events: events.list(scanEvents.groups.id, numberParam(url, "after", 0), numberParam(url, "limit", 200)) });
    return;
  }
  const scan = /^\/api\/scans\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (scan?.groups?.id) {
    requirePermission(context, "scans.read");
    const item = scans.get(scan.groups.id, resourceOrganization(context));
    if (!item) throw new HttpError(404, "Scan not found.");
    sendJson(response, 200, { scan: item });
    return;
  }
  const scanDetail = /^\/api\/scans\/(?<id>[0-9a-f-]+)\/detail$/.exec(url.pathname);
  if (scanDetail?.groups?.id) {
    requirePermission(context, "scans.read");
    const item = scans.detail(scanDetail.groups.id, resourceOrganization(context));
    if (!item) throw new HttpError(404, "Scan not found.");
    sendJson(response, 200, item);
    return;
  }
  const findingDetail = /^\/api\/findings\/(?<id>[0-9a-f-]+)$/.exec(url.pathname);
  if (findingDetail?.groups?.id) {
    requirePermission(context, "findings.read");
    sendJson(response, 200, findingCommandCenter.detail(findingDetail.groups.id, resourceOrganization(context)));
    return;
  }
  const retestCandidates = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/retest-candidates$/.exec(url.pathname);
  if (retestCandidates?.groups?.id) {
    requirePermission(context, "findings.read");
    requireSelectedResource(context,"finding",retestCandidates.groups.id,"org.read");
    sendJson(response, 200, { scans: findingCommandCenter.retestCandidates(retestCandidates.groups.id) });
    return;
  }
  const retestDraft = /^\/api\/findings\/(?<id>[0-9a-f-]+)\/retest-draft$/.exec(url.pathname);
  if (retestDraft?.groups?.id) {
    requirePermission(context, "findings.linkRetest");
    requireSelectedResource(context,"finding",retestDraft.groups.id,"org.read");
    sendJson(response, 200, findingCommandCenter.retestDraft(retestDraft.groups.id));
    return;
  }
  const artifact = /^\/api\/artifacts\/(?<id>[0-9a-f-]+)\/download$/.exec(url.pathname);
  if (artifact?.groups?.id) {
    requirePermission(context, "artifacts.download");
    const organizationId=resourceOrganization(context);const localItem = artifacts.get(artifact.groups.id,organizationId);const storedItem=localItem?undefined:await context.infrastructure.objectStore.lookup(artifact.groups.id,organizationId);const item=localItem??(storedItem?{id:storedItem.artifactId,organizationId:storedItem.organizationId,path:storedItem.path,contentType:storedItem.contentType,name:storedItem.name,size:storedItem.size,sha256:storedItem.sha256}:undefined);
    if (!item) throw new HttpError(404, "Artifact not found.");
    const path=context.infrastructure.objectStore.kind==="local"&&localItem?item.path:await context.infrastructure.objectStore.materialize({artifactId:item.id,organizationId:item.organizationId,path:item.path,sha256:item.sha256,size:item.size,contentType:item.contentType},paths.objectCacheDir);
    serveArtifact(response, { ...item, path }, [paths.reportsDir, paths.proofPacksDir, paths.artifactsDir, paths.integrationsDir, paths.objectCacheDir]);
    return;
  }
  const artifactPreview = /^\/api\/artifacts\/(?<id>[0-9a-f-]+)\/preview$/.exec(url.pathname);
  if (artifactPreview?.groups?.id) {
    requirePermission(context, "artifacts.download");
    const organizationId=resourceOrganization(context);const localItem=artifacts.get(artifactPreview.groups.id,organizationId);const storedItem=localItem?undefined:await context.infrastructure.objectStore.lookup(artifactPreview.groups.id,organizationId);const item=localItem??(storedItem?{id:storedItem.artifactId,organizationId:storedItem.organizationId,path:storedItem.path,contentType:storedItem.contentType,name:storedItem.name,size:storedItem.size,sha256:storedItem.sha256}:undefined);
    if (!item) throw new HttpError(404, "Artifact not found.");
    const path=context.infrastructure.objectStore.kind==="local"&&localItem?item.path:await context.infrastructure.objectStore.materialize({artifactId:item.id,organizationId:item.organizationId,path:item.path,sha256:item.sha256,size:item.size,contentType:item.contentType},paths.objectCacheDir);
    serveImagePreview(response, { ...item, path }, [paths.reportsDir, paths.proofPacksDir, paths.artifactsDir, paths.integrationsDir, paths.objectCacheDir]);
    return;
  }
  throw new HttpError(404, "API route not found.");
}
