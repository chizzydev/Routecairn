import { canonicalScanReportPaths, preservePartialScanReport } from "./PartialScanReport.js";
import { randomUUID, createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { ArtifactRepository, AuditRepository, EventRepository, ModuleExecutionRepository, PlanRepository, ScanRepository, TargetRepository } from "../db/DashboardRepositories.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { DashboardScanCreateRequest, PlanPreviewResponse } from "../types/DashboardTypes.js";
import type { ScanExecutionEvent, ScanEventSink } from "../../core/engine/ScanEvents.js";
import { loadReport } from "../../reports/ReportSummary.js";
import { entryFromReport, recordScan, scanIndexPath } from "../../storage/ScanIndex.js";
import { FindingNormalizer } from "../findings/FindingNormalizer.js";
import { ComparisonService } from "../services/ComparisonService.js";
import { FindingFingerprintService } from "../findings/FindingFingerprintService.js";
import { authProfileFromCredential, planSnapshot, reportDirectoryFor, resolveDashboardScanPlan, resolveCredentialAuthForDashboardScan, safeConfigurationSummary, safePlanIdentity, type DashboardResolvedAuth } from "./ScanExecutionShared.js";
import { assertExecutablePlanSourcesUnchanged, captureExecutablePlanSources, createExecutablePlanPayload, type BoundExecutablePlan } from "./ExecutablePlanSnapshot.js";
import { ExecutablePlanStore } from "./ExecutablePlanStore.js";
import { ScanWorkerManager, type WorkerRunResult } from "../worker/ScanWorkerManager.js";
import { redactDashboardValue } from "../security/Redaction.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { verifyScanIdentities } from "../../core/auth/IdentityVerification.js";
import { RetestTemplateVault } from "../retests/RetestTemplateVault.js";
import type { ControlledMutationContract } from "../../core/offensive/ControlledMutationTypes.js";
import { ControlledMutationApprovalRepository } from "../db/ControlledMutationApprovalRepository.js";
import { WorkerGovernanceError } from "../worker/WorkerGovernance.js";
import { assertCredentialBindingsCurrent, evaluateCredentialReadiness, type CredentialExecutionBinding, type CredentialReadinessResult } from "../credentials/CredentialReadiness.js";
import { assessCredentialIdentity } from "../credentials/CredentialHealth.js";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { defaultConfig } from "../../config/defaults.js";
import { ScanPlanner } from "../../core/planning/ScanPlanner.js";
import { createDefaultPluginRegistry } from "../../core/engine/ScanOrchestrator.js";
import { assertRegisteredTargetScope } from "./RegisteredTargetScope.js";
import { AdaptiveSecurityService } from "./AdaptiveSecurityService.js";
import { requestsForClass } from "../../modules/activeVulnerability/ActiveVulnerabilityPlanner.js";

const maxQueuedScans = 20;

interface QueueItem {
  scanId: string;
  request: DashboardScanCreateRequest;
  abortController: AbortController;
  executablePlanBinding: string;
  resolvedAuth: DashboardResolvedAuth;
  credentialBindings: CredentialExecutionBinding[];
  mutationContracts?: readonly ControlledMutationContract[];
}

export class ScanExecutionService {
  private readonly scans: ScanRepository;
  private readonly plans: PlanRepository;
  private readonly modules: ModuleExecutionRepository;
  private readonly events: EventRepository;
  private readonly artifacts: ArtifactRepository;
  private readonly audit: AuditRepository;
  private readonly normalizer: FindingNormalizer;
  private readonly workers: ScanWorkerManager;
  private readonly retestTemplates: RetestTemplateVault;
  private readonly executablePlans: ExecutablePlanStore;
  private readonly queue: QueueItem[] = [];
  private active: QueueItem | undefined;
  private activeCompletion: Promise<void> | undefined;
  private stopping = false;
  private reconciliation: Promise<void> | undefined;
  private readonly reconciliationTimer: ReturnType<typeof setInterval>;

  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly vault?: CredentialVault, retestTemplates?: RetestTemplateVault) {
    this.scans = new ScanRepository(database);
    this.plans = new PlanRepository(database);
    this.modules = new ModuleExecutionRepository(database);
    this.events = new EventRepository(database);
    this.artifacts = new ArtifactRepository(database);
    this.audit = new AuditRepository(database);
    this.normalizer = new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath));
    this.workers = new ScanWorkerManager(database, paths, vault);
    this.executablePlans = new ExecutablePlanStore(database, paths.executablePlanKeyPath);
    this.retestTemplates = retestTemplates ?? new RetestTemplateVault(database.db);
    void this.reconcileInterruptedReports();
    this.reconciliationTimer = setInterval(() => { if (!this.stopping && database.db.open) void this.reconcileInterruptedReports(); }, 30_000);
    this.reconciliationTimer.unref();
  }

  public async preview(request: DashboardScanCreateRequest): Promise<PlanPreviewResponse> {
    const credentialAuth = this.resolveCredentialAuth(request);
    const { plan, scope, config } = await resolveDashboardScanPlan(request, credentialAuth);
    this.assertTargetBinding(request, scope, plan.limits);
    const previewIdentity = safePlanIdentity(request, plan);
    const credentialReadiness = this.evaluateCredentialReadiness(request, plan.limits.maxScanDurationMs);
    return {
      previewIdentity,
      profile: plan.profile,
      modules: plan.modules.map((modulePlan) => ({ id: modulePlan.id, phase: modulePlan.phase, settings: modulePlan.settings as Record<string, unknown> })),
      limits: plan.limits as unknown as Record<string, unknown>,
      evidence: plan.evidence as unknown as Record<string, unknown>,
      transport: config.transport,
      skippedModules: plan.skippedModules.map((skipped) => ({ id: skipped.id, reason: skipped.reason })),
      controlledWorkflowRequests: ([
        ["object-pair", plan.objectPairTesting],
        ["field-exposure", plan.fieldExposureTesting],
        ["authorization-matrix", plan.authorizationMatrixTesting],
        ["equivalent-route", plan.equivalentRouteTesting],
        ["collection-authorization", plan.collectionAuthorizationTesting],
        ["bulk-authorization", plan.bulkAuthorizationTesting],
        ["file-authorization", plan.fileAuthorizationTesting],
        ["supabase-authorization", plan.supabaseAuthorization],
        ["authentication-lifecycle", plan.authenticationLifecycle],
        ["business-invariant", plan.businessInvariant],
        ["controlled-race", plan.controlledRace],
        ["api-graphql-authorization", plan.apiGraphql],
        ["protocol-security", plan.protocolSecurity],
        ["link-portal-export-security", plan.linkPortalSecurity],
        ["operational-endpoint-security", plan.operationalEndpointSecurity],
        ["billing-entitlement-security", plan.billingEntitlement],
        ["assisted-review", plan.assistedReview],
        ["pre-handover-assault", plan.preHandover],
        ["bug-bounty-authorization", plan.targetAuthorization],
        ["active-vulnerability-validation", plan.activeVulnerability]
      ] as const).flatMap(([workflowId, workflowPlan]) => workflowPlan ? [{ workflowId, exactRequests: exactWorkflowRequests(workflowId, workflowPlan) }] : []),
      planSnapshot: planSnapshot(plan, scope),
      credentialReadiness,
      warnings: [
        ...plan.skippedModules.map((skipped) => `${skipped.id}: ${skipped.reason}`),
        ...credentialReadiness.warnings.map((warning) => `${warning.code}: ${warning.message}`),
        ...credentialReadiness.blockers.map((blocker) => `${blocker.code}: ${blocker.message}`)
      ]
    };
  }

  public async testIdentity(request: DashboardScanCreateRequest): Promise<Record<string, unknown>> {
    const credentialAuth = this.resolveCredentialAuth(request);
    const resolved = await resolveDashboardScanPlan(request, credentialAuth);
    this.assertTargetBinding(request, resolved.scope, resolved.plan.limits);
    const boundedPlan = {
      ...resolved.plan,
      limits: {
        ...resolved.plan.limits,
        maxRequests: Math.min(resolved.plan.limits.maxRequests, 4),
        maxScanDurationMs: Math.min(resolved.plan.limits.maxScanDurationMs, 30_000),
        requestTimeoutMs: Math.min(resolved.plan.limits.requestTimeoutMs, 10_000),
        retry: { ...resolved.plan.limits.retry, maxAttempts: 1 }
      }
    };
    const context = new ScanContext({
      target: request.target,
      scope: resolved.scope,
      config: resolved.config,
      plan: boundedPlan,
      outputDir: this.paths.artifactsDir,
      ...(resolved.authProfile ? { authProfile: resolved.authProfile } : {}),
      ...(resolved.authProfileSet ? { authProfileSet: resolved.authProfileSet } : {})
    });
    const result = await verifyScanIdentities(context);
    if (!result) throw new Error("IDENTITY_CONFIGURATION_INVALID: No enabled identity verification configuration was supplied.");
    return redactDashboardValue({ ...result, requestAudit: context.state.getRequestAudit() }) as Record<string, unknown>;
  }

  public async testCredentialProfile(profileId: string, targetId?: string): Promise<Record<string, unknown>> {
    if (!this.vault) throw new Error("Credential vault is unavailable.");
    const profile = this.vault.getSummary(profileId);
    if (!profile) throw new Error("Credential profile not found.");
    const selectedTargetId = targetId ?? profile.targetId;
    if (!selectedTargetId) {
      this.vault.recordHealth(profileId, "UNVERIFIED", "DASHBOARD_TEST", "IDENTITY_TARGET_REQUIRED", "Select or bind an approved target before running an identity health check.");
      throw new Error("IDENTITY_TARGET_REQUIRED: Select or bind an approved target before testing this credential.");
    }
    if (profile.targetId && profile.targetId !== selectedTargetId) throw new Error("CREDENTIAL_TARGET_MISMATCH: Credential is bound to a different target.");
    const target = new TargetRepository(this.database).get(selectedTargetId);
    if (!target) throw new Error("TARGET_NOT_FOUND: Credential health-check target is unavailable or archived.");
    if (profile.projectId && target.projectId && profile.projectId !== target.projectId) throw new Error("CREDENTIAL_PROJECT_MISMATCH: Credential is bound to a different project.");
    const secret = this.vault.decryptForHealthCheck(profileId);
    if (!secret.identityVerification) {
      this.vault.recordHealth(profileId, "UNVERIFIED", "DASHBOARD_TEST", "IDENTITY_CONFIGURATION_REQUIRED", "Credential structure decrypted successfully, but no identity verification endpoint is configured.");
      return { ok: false, health: this.vault.getSummary(profileId)!.health, reason: "IDENTITY_CONFIGURATION_REQUIRED", structuralValidation: credentialStructureSummary(secret) };
    }
    const authProfile = authProfileFromCredential(profile, secret);
    const scope = scopeSchema.parse(target.approvedScope);
    const plan = new ScanPlanner(createDefaultPluginRegistry()).resolve({
      requestedProfile: "quick",
      scope,
      config: defaultConfig,
      authProfile,
      overrides: { maxRequests: 1, cleanupReservedRequests: 0, concurrency: 1, rateLimitPerSecond: 1 }
    });
    const context = new ScanContext({ target: target.baseOrigin, scope, config: defaultConfig, plan, outputDir: this.paths.artifactsDir, authProfile });
    const report = await verifyScanIdentities(context);
    if (!report) throw new Error("IDENTITY_CONFIGURATION_INVALID: Identity verification did not run.");
    const assessment = assessCredentialIdentity(profile, report);
    this.vault.recordHealth(profileId, assessment.classification, "DASHBOARD_IDENTITY_TEST", assessment.reasonCode, assessment.safeSummary, assessment.principalFingerprint);
    this.audit.append({ action: "CREDENTIAL_HEALTH_CHECKED", resourceType: "CREDENTIAL_PROFILE", resourceId: profileId, summary: assessment.safeSummary, metadata: { classification: assessment.classification, reasonCode: assessment.reasonCode, targetId: selectedTargetId, principalFingerprint: assessment.principalFingerprint } });
    return redactDashboardValue({ ok: assessment.classification === "HEALTHY" || assessment.classification === "NEAR_EXPIRY", health: this.vault.getSummary(profileId)!.health, identity: report.primary, structuralValidation: credentialStructureSummary(secret), requestAudit: context.state.getRequestAudit() }) as Record<string, unknown>;
  }

  public async enqueue(request: DashboardScanCreateRequest, mutationContracts?: readonly ControlledMutationContract[], approvalId?: string): Promise<string> {
    if (this.queue.length >= maxQueuedScans) {
      throw new Error(`Scan queue is full. Maximum queued scans: ${maxQueuedScans}.`);
    }
    const scanId = randomUUID();
    const sourceBindings = await captureExecutablePlanSources(request);
    const credentialAuth = this.resolveCredentialAuth(request);
    const resolved = await resolveDashboardScanPlan(request, credentialAuth, mutationContracts);
    this.assertTargetBinding(request, resolved.scope, resolved.plan.limits);
    await assertExecutablePlanSourcesUnchanged(sourceBindings);
    const { plan } = resolved;
    const credentialReadiness = this.evaluateCredentialReadiness(request, plan.limits.maxScanDurationMs);
    if (!credentialReadiness.ready) throw new Error(`CREDENTIAL_READINESS_BLOCKED: ${credentialReadiness.blockers.map((blocker) => blocker.message).join(" ")}`);
    if (request.studio?.previewIdentity && request.studio.previewIdentity !== safePlanIdentity({ ...request, studio: { ...request.studio, previewIdentity: undefined } }, plan)) {
      throw new Error("PREVIEW_STALE: Scan Studio configuration changed after plan preview.");
    }
    const targetOrigin = new URL(request.target).origin;
    const outputDirectory = reportDirectoryFor(this.paths.reportsDir, scanId);
    const resolvedAuth = this.executionAuth(resolved, credentialAuth, request);
    const executablePayload = createExecutablePlanPayload(request.target, resolved, resolvedAuth, sourceBindings);
    let executablePlan!: BoundExecutablePlan;
    this.database.transaction(() => {
      this.scans.create({
        id: scanId,
        source: "DASHBOARD",
        status: "QUEUED",
        targetOrigin,
        safeTargetLabel: targetOrigin,
        profile: request.profile,
        evidenceLevel: "pending",
        safeConfigurationSummary: safeConfigurationSummary(request),
        outputDirectory,
        projectId: request.projectId,
        targetId: request.targetId,
        authorizationDeclaration: request.authorizationDeclaration
      });
      executablePlan = this.executablePlans.save(scanId, targetOrigin, executablePayload);
      this.plans.create(scanId, planSnapshot(plan, resolved.scope));
      this.modules.createQueued(scanId, plan.modules.map((modulePlan) => ({ id: modulePlan.id, phase: modulePlan.phase })));
      this.scans.updatePlanSummary(scanId, plan.evidence.level, plan.modules.length);
      if (approvalId) new ControlledMutationApprovalRepository(this.database).beginExecution(approvalId, scanId);
      this.events.append(scanId, "PLAN_BOUND", "Reviewed executable plan encrypted and bound to the queued scan.", { binding: executablePlan.binding, schemaVersion: executablePayload.schemaVersion });
      this.events.append(scanId, "SCAN_QUEUED", "Scan queued.", { profile: request.profile, target: targetOrigin, executablePlanBinding: executablePlan.binding });
      if (credentialReadiness.profiles.length > 0) this.events.append(scanId, "CREDENTIAL_READINESS_VERIFIED", "Credential lifecycle readiness verified for the approved maximum scan duration.", { requiredValidThrough: credentialReadiness.requiredValidThrough, profiles: credentialReadiness.profiles, warnings: credentialReadiness.warnings });
      this.retestTemplates.save(scanId, request.studio?.workflows ?? []);
    });
    this.queue.push({ scanId, request, abortController: new AbortController(), executablePlanBinding: executablePlan.binding, resolvedAuth, credentialBindings: credentialReadiness.bindings, ...(mutationContracts?.length ? { mutationContracts } : {}) });
    void this.pump();
    return scanId;
  }

  private resolveCredentialAuth(request: DashboardScanCreateRequest) {
    if (!request.credentialProfileId && !request.credentialProfileAId && !request.credentialProfileBId && (!request.studio || request.studio.authentication.mode === "public")) return undefined;
    if (!this.vault) throw new Error("Credential vault is unavailable for this dashboard scan.");
    return resolveCredentialAuthForDashboardScan(this.vault, request);
  }

  private assertTargetBinding(request: DashboardScanCreateRequest, requestedScope: Parameters<typeof assertRegisteredTargetScope>[0], limits: Parameters<typeof assertRegisteredTargetScope>[2]): void {
    if (!request.targetId) return;
    const target = new TargetRepository(this.database).get(request.targetId);
    if (!target) throw new Error("TARGET_NOT_FOUND: The selected registered target is unavailable or archived.");
    if (new URL(target.baseOrigin).origin !== new URL(request.target).origin) throw new Error("TARGET_INVALID: The scan target origin does not match the selected registered target.");
    let approvedScope: ReturnType<typeof scopeSchema.parse>;
    try {
      approvedScope = scopeSchema.parse(target.approvedScope);
    } catch {
      throw new Error("REGISTERED_TARGET_SCOPE_INVALID: The selected target does not contain a complete approved scope.");
    }
    assertRegisteredTargetScope(requestedScope, approvedScope, limits);
  }

  private evaluateCredentialReadiness(request: DashboardScanCreateRequest, maximumExecutionMs: number): CredentialReadinessResult {
    const hasSavedCredentials = Boolean(request.credentialProfileId || request.credentialProfileAId || request.credentialProfileBId || (request.studio && request.studio.authentication.mode !== "public" && (
      (request.studio.authentication.mode === "primary" && request.studio.authentication.primary.source === "saved") ||
      (request.studio.authentication.mode === "account-pair" && (request.studio.authentication.accountA.source === "saved" || request.studio.authentication.accountB.source === "saved"))
    )));
    if (!hasSavedCredentials) {
      const now = new Date();
      return { ready: true, checkedAt: now.toISOString(), requiredValidThrough: new Date(now.getTime() + maximumExecutionMs).toISOString(), blockers: [], warnings: [], profiles: [], bindings: [] };
    }
    if (!this.vault) throw new Error("Credential vault is unavailable for this dashboard scan.");
    return evaluateCredentialReadiness(this.vault, request, maximumExecutionMs);
  }

  private executionAuth(resolved: Awaited<ReturnType<typeof resolveDashboardScanPlan>>, credentialAuth: DashboardResolvedAuth | undefined, request: DashboardScanCreateRequest): DashboardResolvedAuth {
    return {
      safeSummary: credentialAuth?.safeSummary ?? {
        source: request.authFile || request.authAFile ? "enqueue-resolved-auth-file" : "public",
        hasSingleProfile: Boolean(resolved.authProfile),
        hasAccountPair: Boolean(resolved.authProfileSet),
        redactionApplied: true
      },
      ...(resolved.authProfile ? { authProfile: resolved.authProfile } : {}),
      ...(resolved.authProfileSet ? { authProfileSet: resolved.authProfileSet } : {})
    };
  }

  public async rerun(scanId: string): Promise<string> {
    const row = this.database.db.prepare("SELECT safe_configuration_summary FROM scans WHERE id = ?").get(scanId) as { safe_configuration_summary: string } | undefined;
    if (!row) throw new Error("Scan not found.");
    const summary = JSON.parse(row.safe_configuration_summary) as Partial<DashboardScanCreateRequest> & { auth?: boolean; accountPair?: boolean };
    const authorizationSummary = JSON.parse(row.safe_configuration_summary) as Record<string, unknown>;
    if (authorizationSummary.targetMode || authorizationSummary.targetAuthorizationFileLabel || authorizationSummary.preHandover || authorizationSummary.preHandoverFileLabel) throw new Error("Rerun requires fresh explicit target authorization and workflow manifests.");
    if (summary.auth || summary.accountPair) {
      throw new Error("Rerun for authenticated scans requires supplying fresh ephemeral authentication material.");
    }
    if (!summary.target || (!summary.scopeFile && !summary.studio?.scope) || !summary.profile) {
      throw new Error("Scan does not contain enough non-secret configuration to rerun safely.");
    }
    return await this.enqueue({
      target: summary.target,
      ...(summary.scopeFile ? { scopeFile: summary.scopeFile } : {}),
      profile: summary.profile,
      ...(summary.projectId ? { projectId: summary.projectId } : {}),
      ...(summary.targetId ? { targetId: summary.targetId } : {}),
      ...(summary.authorizationDeclaration ? { authorizationDeclaration: summary.authorizationDeclaration } : {}),
      ...(summary.configFile ? { configFile: summary.configFile } : {}),
      ...(summary.rateLimitPerSecond ? { rateLimitPerSecond: summary.rateLimitPerSecond } : {}),
      ...(summary.concurrency ? { concurrency: summary.concurrency } : {}),
      ...(summary.studio ? { studio: summary.studio } : {})
    });
  }

  public cancel(scanId: string): void {
    const queuedIndex = this.queue.findIndex((item) => item.scanId === scanId);
    if (queuedIndex >= 0) {
      this.queue.splice(queuedIndex, 1);
      this.database.transaction(() => {
        this.scans.updateStatus(scanId, "CANCELLED", { cancelledAt: nowIso(), errorSummary: "Cancelled before execution started." });
        this.events.append(scanId, "CANCELLATION_REQUESTED", "Queued scan cancellation requested.", {});
        this.events.append(scanId, "SCAN_CANCELLED", "Queued scan cancelled.", {});
      });
      return;
    }

    if (this.active?.scanId === scanId) {
      this.database.transaction(() => {
        this.scans.updateStatus(scanId, "CANCEL_REQUESTED");
        this.events.append(scanId, "CANCELLATION_REQUESTED", "Running scan cancellation requested.", {});
      });
      this.active.abortController.abort();
      this.workers.cancel(scanId);
      return;
    }

    throw new Error("Scan is not queued or running.");
  }

  public workerDiagnostics() { return this.workers.diagnostics(); }
  public restartWorker(workerId: string): void { this.workers.restartWorker(workerId); }
  public quarantineWorker(workerId: string, reason: string): void { this.workers.quarantineWorker(workerId, reason); }
  public releaseWorker(workerId: string): void { this.workers.releaseWorker(workerId); }
  public quarantineWorkerFleet(reason: string): void { this.workers.quarantineFleet(reason); }
  public releaseWorkerFleet(): void { this.workers.releaseFleet(); }

  public async shutdown(): Promise<void> {
    this.stopping = true;
    clearInterval(this.reconciliationTimer);
    await this.reconciliation;
    if (this.active) {
      this.active.abortController.abort();
      this.workers.cancel(this.active.scanId);
    }
    for (const item of this.queue.splice(0)) {
      this.scans.updateStatus(item.scanId, "INTERRUPTED", { errorSummary: "Dashboard shutdown interrupted queued scan." });
      this.events.append(item.scanId, "SCAN_INTERRUPTED", "Dashboard shutdown interrupted queued scan.", {});
    }
    await this.workers.shutdown();
    await this.activeCompletion;
  }

  private async pump(): Promise<void> {
    if (this.active || this.stopping) return;
    const next = this.queue.shift();
    if (!next) return;
    this.active = next;
    this.activeCompletion = this.run(next);
    try {
      await this.activeCompletion;
    } finally {
      this.activeCompletion = undefined;
      this.active = undefined;
      if (!this.stopping) {
        void this.pump();
      }
    }
  }

  private async run(item: QueueItem): Promise<void> {
    try {
      this.scans.updateStatus(item.scanId, "PLANNING");
      this.events.append(item.scanId, "PLAN_STARTED", "Planning started.", {});
      const executablePlan = this.executablePlans.load(item.scanId, new URL(item.request.target).origin);
      if (executablePlan.binding !== item.executablePlanBinding) throw new Error("EXECUTABLE_PLAN_QUEUE_BINDING_MISMATCH");
      if (item.credentialBindings.length > 0) {
        if (!this.vault) throw new Error("CREDENTIAL_VAULT_UNAVAILABLE_AT_EXECUTION");
        assertCredentialBindingsCurrent(this.vault, item.credentialBindings);
        const readiness = evaluateCredentialReadiness(this.vault, item.request, executablePlan.payload.plan.limits.maxScanDurationMs);
        if (!readiness.ready) {
          this.events.append(item.scanId, "CREDENTIAL_READINESS_BLOCKED", "Credential lifecycle changed while queued; execution was refused.", { blockers: readiness.blockers, requiredValidThrough: readiness.requiredValidThrough });
          throw new Error(`CREDENTIAL_READINESS_BLOCKED_AT_EXECUTION: ${readiness.blockers.map((blocker) => blocker.message).join(" ")}`);
        }
      }
      this.scans.updateStatus(item.scanId, "RUNNING");
      const result = await this.workers.run(item.scanId, item.request, {
        onPlan: (message) => {
          this.database.transaction(() => {
            this.executablePlans.markWorkerVerified(item.scanId, message.executionPlanBinding);
            this.events.append(item.scanId, "PLAN_VERIFIED", "Worker verified and accepted the immutable executable plan.", { modules: message.modules.map((modulePlan) => modulePlan.id), workerId: message.workerId, executablePlanBinding: message.executionPlanBinding });
            this.events.append(item.scanId, "PLAN_COMPLETED", "Bound planning completed in isolated worker.", { modules: message.modules.map((modulePlan) => modulePlan.id), workerId: message.workerId, executablePlanBinding: message.executionPlanBinding });
          });
        },
        onEvent: (message) => {
          void this.eventSink(item.scanId).emit(message.event as ScanExecutionEvent);
        },
        onHeartbeat: (message) => {
          this.events.append(item.scanId, "WORKER_HEARTBEAT", "Worker heartbeat.", { workerId: message.workerId, timestamp: message.timestamp });
        }
      }, { executablePlan, resolvedAuth: item.resolvedAuth, ...(item.mutationContracts?.length ? { contracts: item.mutationContracts } : {}) });
      if (result.failureCategory) this.events.append(item.scanId, "WORKER_GOVERNANCE_FAILURE", result.error ?? "Worker governance stopped execution.", { workerId: result.workerId, failureCategory: result.failureCategory });
      await this.ingestResult(item.scanId, item.request.target, result, item.mutationContracts ?? []);
    } catch (error) {
      new ControlledMutationApprovalRepository(this.database).finishExecution(item.scanId, true);
      this.database.transaction(() => {
        this.scans.updateStatus(item.scanId, item.abortController.signal.aborted ? "CANCELLED" : "FAILED", {
          ...(item.abortController.signal.aborted ? { cancelledAt: nowIso() } : {}),
          errorSummary: safeErrorMessage(error)
        });
        this.events.append(item.scanId, item.abortController.signal.aborted ? "SCAN_CANCELLED" : "SCAN_FAILED", safeErrorMessage(error), {});
        if (error instanceof WorkerGovernanceError) this.events.append(item.scanId, "WORKER_GOVERNANCE_FAILURE", error.message, { failureCategory: error.category });
      });
    }
  }


  private async ingestResult(scanId: string, target: string, result: WorkerRunResult, contracts: readonly ControlledMutationContract[] = []): Promise<void> {
    const canonical = canonicalScanReportPaths(this.paths, scanId);
    if (result.status !== "COMPLETED") {
      const restored = await preservePartialScanReport(this.paths, scanId, target, result.status);
      if (!restored) {
        new ControlledMutationApprovalRepository(this.database).finishExecution(scanId, true);
        this.scans.updateStatus(scanId, result.status, { ...(result.status === "CANCELLED" ? { cancelledAt: nowIso() } : {}), errorSummary: result.error ?? "Execution ended before a report checkpoint was available." });
        this.events.append(scanId, result.status === "CANCELLED" ? "SCAN_CANCELLED" : result.status === "INTERRUPTED" ? "SCAN_INTERRUPTED" : "SCAN_FAILED", "Execution ended before any durable report was available. Consult recovery for outstanding cleanup.", {});
        this.database.db.prepare("UPDATE scans SET import_limitation_summary = COALESCE(import_limitation_summary, 'PARTIAL_REPORT_UNAVAILABLE') WHERE id = ?").run(scanId);
        return;
      }
      Object.assign(result, restored);
    }
    if (!result.reportPath || !result.markdownReportPath || !result.htmlReportPath) throw new Error("Worker completed without report paths.");
    if (resolve(result.reportPath) !== canonical.reportPath || resolve(result.markdownReportPath) !== canonical.markdownReportPath || resolve(result.htmlReportPath) !== canonical.htmlReportPath) throw new Error("Worker report path binding mismatch.");
      const report = await loadReport(result.reportPath);
      const expectedCases = contracts;
      const cleanupUnresolved = report.execution?.cleanup.state !== "CLEAR" || expectedCases.some((contract) => {
        const result = report.privilegeMutation?.observations.find((item) => item.caseId === contract.caseId)?.result;
        return !result || !["ROLLBACK_VERIFIED", "NOT_REQUIRED"].includes(result.cleanupOutcome);
      });
      new ControlledMutationApprovalRepository(this.database).finishExecution(scanId, cleanupUnresolved);
      const jsonArtifact = this.recordArtifact(scanId, result.reportPath, "JSON_REPORT", "application/json");
      const markdownArtifact = this.recordArtifact(scanId, result.markdownReportPath, "MARKDOWN_REPORT", "text/markdown; charset=utf-8");
      const htmlArtifact = this.recordArtifact(scanId, result.htmlReportPath, "HTML_REPORT", "text/html; charset=utf-8");
      if (report.assistedReview && !report.execution?.partial) {
        this.recordArtifact(scanId, join(dirname(result.reportPath), "assisted-review.evidence.json"), "ASSISTED_OPERATOR_EVIDENCE", "application/json");
        this.recordArtifact(scanId, join(dirname(result.reportPath), "assisted-review.customer.json"), "ASSISTED_COVERAGE_DRAFT", "application/json");
      }
      await recordScan(
        scanIndexPath(this.paths.reportsDir),
        entryFromReport(report, {
          outputDir: dirname(result.reportPath),
          reportPath: result.reportPath,
          markdownReportPath: result.markdownReportPath,
          htmlReportPath: result.htmlReportPath
        })
      );
      const findingCount = this.normalizer.normalizeReport(scanId, report);
      this.database.transaction(() => {
        this.scans.attachArtifacts(scanId, { json: jsonArtifact, markdown: markdownArtifact, html: htmlArtifact });
        this.scans.updateCounters(scanId);
        this.scans.updateStatus(scanId, result.status, { ...(result.status === "CANCELLED" ? { cancelledAt: nowIso() } : {}), ...(result.error ? { errorSummary: result.error } : {}) });
        this.events.append(scanId, result.status === "COMPLETED" ? "SCAN_COMPLETED" : result.status === "CANCELLED" ? "SCAN_CANCELLED" : result.status === "INTERRUPTED" ? "SCAN_INTERRUPTED" : "SCAN_FAILED", result.status === "COMPLETED" ? "Scan completed in isolated worker." : "Partial evidence ingested; incomplete coverage is not a security pass.", { findingCount, workerId: result.workerId, partial: result.status !== "COMPLETED", cleanupUnresolved });
        if (cleanupUnresolved) this.events.append(scanId, "MUTATION_CLEANUP_REQUIRED", "Cleanup remains unresolved or unknown. Use Offensive Safety recovery before further mutation.", { cleanup: report.execution?.cleanup });
      });
      if (result.status === "COMPLETED") {
        this.captureAdaptiveSecurityModel(scanId, report);
        this.createAutomaticComparison(scanId);
      }
  }

  private reconcileInterruptedReports(): Promise<void> {
    if (this.reconciliation) return this.reconciliation;
    this.reconciliation = (async () => {
      await this.workers.recoverExpiredLeases();
      if (!this.database.db.open) return;
      new ControlledMutationApprovalRepository(this.database).recoverInterruptedExecutions();
      const rows = this.database.db.prepare("SELECT id, target_origin AS target FROM scans WHERE status = 'INTERRUPTED' AND json_report_artifact_id IS NULL AND import_limitation_summary IS NULL AND deleted_at IS NULL").all() as Array<{ id: string; target: string }>;
      for (const row of rows) {
        try { await this.ingestResult(row.id, row.target, { workerId: "recovered", status: "INTERRUPTED", error: "Worker termination interrupted execution." }); }
        catch { this.audit.append({ action: "PARTIAL_REPORT_RECONCILIATION_FAILED", resourceType: "SCAN", resourceId: row.id, summary: "Interrupted scan report requires operator reconciliation; its durable checkpoint was retained." }); }
      }
    })().catch(() => {
      if (this.database.db.open) this.audit.append({ action: "PARTIAL_REPORT_RECONCILIATION_FAILED", resourceType: "SCAN", summary: "Interrupted scan evidence or cleanup requires reconciliation; durable checkpoints were retained." });
    }).finally(() => { this.reconciliation = undefined; });
    return this.reconciliation;
  }

  private createAutomaticComparison(scanId: string): void {
    const setting = this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key = 'comparisons.auto.enabled'").get() as { value: string } | undefined;
    if (setting?.value === "false") return;
    try {
      const scan = this.database.db.prepare("SELECT target_id, target_origin, created_at FROM scans WHERE id = ?").get(scanId) as { target_id: string | null; target_origin: string; created_at: string } | undefined;
      if (!scan) return;
      const previous = this.database.db.prepare(`SELECT id FROM scans WHERE id != ? AND deleted_at IS NULL AND status IN ('COMPLETED','IMPORTED') AND created_at < ? AND ((? IS NOT NULL AND target_id = ?) OR (? IS NULL AND target_id IS NULL AND target_origin = ?)) ORDER BY created_at DESC LIMIT 1`).get(scanId, scan.created_at, scan.target_id, scan.target_id, scan.target_id, scan.target_origin) as { id: string } | undefined;
      if (!previous) return;
      const existing = this.database.db.prepare("SELECT id FROM scan_comparisons WHERE older_scan_id = ? AND newer_scan_id = ? AND deleted_at IS NULL LIMIT 1").get(previous.id, scanId) as { id: string } | undefined;
      if (existing) return;
      const result = new ComparisonService(this.database).compare(previous.id, scanId);
      this.events.append(scanId, "OBSERVATION_RECORDED", "Automatic local scan comparison completed.", { comparisonId: result.comparisonId, olderScanId: previous.id, regressions: result.summary.regressions });
      this.audit.append({ action: "comparison.automatic_created", resourceType: "SCAN_COMPARISON", resourceId: result.comparisonId, summary: "Automatic comparison created after scan completion.", metadata: { comparisonId: result.comparisonId, olderScanId: previous.id, newerScanId: scanId, targetId: scan.target_id, timestamp: nowIso() } });
    } catch (error) {
      this.events.append(scanId, "OBSERVATION_RECORDED", "Automatic comparison could not be completed; scan completion was unaffected.", { category: error instanceof Error ? error.name : "COMPARISON_FAILED" });
    }
  }

  private captureAdaptiveSecurityModel(scanId: string, report: import("../../reports/ReportTypes.js").RouteCairnReport): void {
    try {
      const binding = this.database.db.prepare("SELECT target_id FROM scans WHERE id=?").get(scanId) as { target_id: string | null } | undefined;
      if (!binding?.target_id) return;
      const snapshot = new AdaptiveSecurityService(this.database).observeCompletedScan(scanId, report);
      this.events.append(scanId, "OBSERVATION_RECORDED", "Adaptive target security model captured from completed scan evidence.", { snapshotId: snapshot.id, modelDigest: snapshot.modelDigest });
      this.audit.append({ action: "ADAPTIVE_SECURITY_MODEL_CAPTURED", resourceType: "SCAN", resourceId: scanId, summary: "Completed scan evidence was converted into a safe target security model snapshot.", metadata: { snapshotId: snapshot.id, modelDigest: snapshot.modelDigest } });
    } catch (error) {
      this.events.append(scanId, "OBSERVATION_RECORDED", "Adaptive model capture was unavailable; scan completion was unaffected.", { category: safeErrorMessage(error) });
      this.audit.append({ action: "ADAPTIVE_SECURITY_MODEL_CAPTURE_FAILED", resourceType: "SCAN", resourceId: scanId, summary: "Adaptive model capture requires operator review; completed scan evidence remains available.", metadata: { category: safeErrorMessage(error) } });
    }
  }

  private eventSink(scanId: string): ScanEventSink {
    return {
      emit: (event: ScanExecutionEvent) => {
        const metadata = redactDashboardValue(event.metadata ?? {}) as Record<string, unknown>;
        this.database.transaction(() => {
          this.events.append(scanId, event.type, event.message, metadata, event.moduleId);
          if (event.type === "MODULE_STARTED" && event.moduleId) {
            this.modules.mark(scanId, event.moduleId, "RUNNING");
            if (this.active?.abortController.signal.aborted !== true) this.scans.updateStatus(scanId, "RUNNING", { currentModule: event.moduleId });
          }
          if (event.type === "MODULE_COMPLETED" && event.moduleId) {
            this.modules.mark(scanId, event.moduleId, "COMPLETED", undefined, typeof metadata.findings === "number" ? metadata.findings : undefined);
            this.scans.updateCounters(scanId);
          }
          if (event.type === "MODULE_FAILED" && event.moduleId) {
            this.modules.mark(scanId, event.moduleId, "FAILED", event.message);
            this.scans.updateCounters(scanId);
          }
          if (event.type === "MODULE_CANCELLED" && event.moduleId) {
            this.modules.mark(scanId, event.moduleId, "CANCELLED", event.message);
            this.scans.updateCounters(scanId);
          }
        });
      }
    };
  }

  private recordArtifact(scanId: string, path: string, type: string, contentType: string): string {
    const stat = statSync(path);
    const existing = this.database.db.prepare("SELECT id FROM artifacts WHERE scan_id = ? AND artifact_type = ? AND canonical_path = ? LIMIT 1").get(scanId, type, path) as { id: string } | undefined;
    if (existing) {
      this.database.db.prepare("UPDATE artifacts SET size = ?, scoped_or_full_safe_hash = ? WHERE id = ?").run(stat.size, fileHash(path), existing.id);
      return existing.id;
    }
    return this.artifacts.create({
      scanId,
      type,
      name: path.split(/[\\/]/).pop() ?? type,
      path,
      size: stat.size,
      contentType,
      hash: fileHash(path)
    });
  }
}

export function exactWorkflowRequests(workflowId: string, value: unknown): number {
  if (!value || typeof value !== "object") return 0;
  const plan = value as Record<string, unknown>;
  if (workflowId === "supabase-authorization") return array(plan.cases).reduce<number>((total, testCase) => total + 1 + (record(record(testCase).signedUrl).followOnce === true ? 1 : 0), 0);
  if (workflowId === "authentication-lifecycle") return plan.source === "BROWSER_LEARNED" ? numeric(plan.maxRequests, 0) : array(plan.cases).reduce<number>((total, testCase) => total + array(record(testCase).steps).length, 0);
  if (workflowId === "link-portal-export-security" || workflowId === "operational-endpoint-security") return array(plan.cases).reduce<number>((total, testCase) => total + array(record(testCase).steps).length, 0);
  if (workflowId === "business-invariant") return array(plan.cases).reduce<number>((total, testCase) => { const item = record(testCase); return total + array(item.preState).length + array(item.actions).reduce<number>((sum, action) => sum + numeric(record(record(action).execution).attempts, 1), 0) + array(item.postState).length + array(item.cleanup).length + array(item.cleanupVerification).length; }, 0);
  if (workflowId === "controlled-race") return array(plan.cases).reduce<number>((total, testCase) => { const item = record(testCase); return total + array(item.preState).length + array(item.groups).reduce<number>((sum, group) => sum + array(record(group).requests).length, 0) + array(item.postState).length + array(item.cleanup).length + array(item.cleanupVerification).length; }, 0);
  if (workflowId === "billing-entitlement-security") return array(plan.cases).reduce<number>((total, testCase) => total + array(record(testCase).steps).reduce<number>((sum, step) => sum + numeric(record(record(step).execution).attempts, 1), 0), 0);
  if (workflowId === "api-graphql-authorization") return array(plan.checks).reduce<number>((total, check) => { const item = record(check); if (item.kind === "METHOD_CONFUSION") return total + 1 + array(item.alternateMethods).length; if (item.kind === "GRAPHQL_ALIAS_LIMIT" || item.kind === "GRAPHQL_BATCH_LIMIT") return total + array(item.documents).length; if (item.kind === "VERSION_BOUNDARY") return total + 2; return total + 1; }, 0);
  if (workflowId === "active-vulnerability-validation") return array(plan.cases).reduce<number>((total, testCase) => total + requestsForClass(String(record(testCase).vulnerabilityClass ?? ""), Boolean(record(record(testCase).proof).callbackPollUrl)), 0) + numeric(record(plan.discovery).maxCandidates, 0) * 4;
  if (workflowId === "pre-handover-assault") return 3 + array(plan.objects).length;
  if (workflowId === "assisted-review" || workflowId === "bug-bounty-authorization") return 0;
  return numeric(plan.maxRequests, 0);
}

function array(value: unknown): unknown[] { return Array.isArray(value) ? value : []; }
function record(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
function numeric(value: unknown, fallback: number): number { return typeof value === "number" && Number.isFinite(value) ? value : fallback; }

function credentialStructureSummary(secret: import("../credentials/CredentialVault.js").CredentialProfileSecret): Record<string, unknown> {
  return {
    hasAuthorizationHeader: Boolean(secret.authorizationHeader),
    cookieCount: Object.keys(secret.cookies ?? {}).length,
    headerCount: Object.keys(secret.headers ?? {}).length,
    hasIdentityVerification: Boolean(secret.identityVerification),
    hasBrowserBootstrap: Boolean(secret.browserBootstrap),
    lifecycleSecretCount: Object.keys(secret.lifecycleSecrets ?? {}).length
  };
}

function safeErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown dashboard scan execution failure.";
}

function fileHash(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
