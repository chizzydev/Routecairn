import { randomUUID, createHash } from "node:crypto";
import { statSync } from "node:fs";
import { dirname } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { ArtifactRepository, AuditRepository, EventRepository, ModuleExecutionRepository, PlanRepository, ScanRepository } from "../db/DashboardRepositories.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { DashboardScanCreateRequest, PlanPreviewResponse } from "../types/DashboardTypes.js";
import type { ScanExecutionEvent, ScanEventSink } from "../../core/engine/ScanEvents.js";
import { loadReport } from "../../reports/ReportSummary.js";
import { entryFromReport, recordScan, scanIndexPath } from "../../storage/ScanIndex.js";
import { FindingNormalizer } from "../findings/FindingNormalizer.js";
import { ComparisonService } from "../services/ComparisonService.js";
import { FindingFingerprintService } from "../findings/FindingFingerprintService.js";
import { planSnapshot, reportDirectoryFor, resolveDashboardScanPlan, safeConfigurationSummary, safePlanIdentity } from "./ScanExecutionShared.js";
import { resolveCredentialAuthForDashboardScan } from "./ScanExecutionShared.js";
import { ScanWorkerManager } from "../worker/ScanWorkerManager.js";
import { redactDashboardValue } from "../security/Redaction.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { verifyScanIdentities } from "../../core/auth/IdentityVerification.js";
import { RetestTemplateVault } from "../retests/RetestTemplateVault.js";
import type { ControlledMutationContract } from "../../core/offensive/ControlledMutationTypes.js";

const maxQueuedScans = 20;

interface QueueItem {
  scanId: string;
  request: DashboardScanCreateRequest;
  abortController: AbortController;
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
  private readonly queue: QueueItem[] = [];
  private active: QueueItem | undefined;
  private activeCompletion: Promise<void> | undefined;
  private stopping = false;

  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly vault?: CredentialVault, retestTemplates?: RetestTemplateVault) {
    this.scans = new ScanRepository(database);
    this.plans = new PlanRepository(database);
    this.modules = new ModuleExecutionRepository(database);
    this.events = new EventRepository(database);
    this.artifacts = new ArtifactRepository(database);
    this.audit = new AuditRepository(database);
    this.normalizer = new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath));
    this.workers = new ScanWorkerManager(database, paths, vault);
    this.retestTemplates = retestTemplates ?? new RetestTemplateVault(database.db);
    this.workers.recoverExpiredLeases();
  }

  public async preview(request: DashboardScanCreateRequest): Promise<PlanPreviewResponse> {
    const credentialAuth = this.resolveCredentialAuth(request);
    const { plan, scope } = await resolveDashboardScanPlan(request, credentialAuth);
    const previewIdentity = safePlanIdentity(request, plan);
    return {
      previewIdentity,
      profile: plan.profile,
      modules: plan.modules.map((modulePlan) => ({ id: modulePlan.id, phase: modulePlan.phase, settings: modulePlan.settings as Record<string, unknown> })),
      limits: plan.limits as unknown as Record<string, unknown>,
      evidence: plan.evidence as unknown as Record<string, unknown>,
      skippedModules: plan.skippedModules.map((skipped) => ({ id: skipped.id, reason: skipped.reason })),
      controlledWorkflowRequests: ([
        ["object-pair", plan.objectPairTesting],
        ["field-exposure", plan.fieldExposureTesting],
        ["authorization-matrix", plan.authorizationMatrixTesting],
        ["equivalent-route", plan.equivalentRouteTesting],
        ["collection-authorization", plan.collectionAuthorizationTesting],
        ["bulk-authorization", plan.bulkAuthorizationTesting],
        ["file-authorization", plan.fileAuthorizationTesting]
      ] as const).flatMap(([workflowId, workflowPlan]) => workflowPlan && typeof workflowPlan.maxRequests === "number" ? [{ workflowId, exactRequests: workflowPlan.maxRequests }] : []),
      planSnapshot: planSnapshot(plan, scope),
      warnings: plan.skippedModules.map((skipped) => `${skipped.id}: ${skipped.reason}`)
    };
  }

  public async testIdentity(request: DashboardScanCreateRequest): Promise<Record<string, unknown>> {
    const credentialAuth = this.resolveCredentialAuth(request);
    const resolved = await resolveDashboardScanPlan(request, credentialAuth);
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

  public async enqueue(request: DashboardScanCreateRequest, mutationContracts?: readonly ControlledMutationContract[]): Promise<string> {
    if (this.queue.length >= maxQueuedScans) {
      throw new Error(`Scan queue is full. Maximum queued scans: ${maxQueuedScans}.`);
    }
    const scanId = randomUUID();
    const credentialAuth = this.resolveCredentialAuth(request);
    const { plan } = await resolveDashboardScanPlan(request, credentialAuth);
    if (request.studio?.previewIdentity && request.studio.previewIdentity !== safePlanIdentity({ ...request, studio: { ...request.studio, previewIdentity: undefined } }, plan)) {
      throw new Error("PREVIEW_STALE: Scan Studio configuration changed after plan preview.");
    }
    const targetOrigin = new URL(request.target).origin;
    const outputDirectory = reportDirectoryFor(this.paths.reportsDir, scanId);
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
      this.events.append(scanId, "SCAN_QUEUED", "Scan queued.", { profile: request.profile, target: targetOrigin });
      this.retestTemplates.save(scanId, request.studio?.workflows ?? []);
    });
    this.queue.push({ scanId, request, abortController: new AbortController(), ...(mutationContracts?.length ? { mutationContracts } : {}) });
    void this.pump();
    return scanId;
  }

  private resolveCredentialAuth(request: DashboardScanCreateRequest) {
    if (!request.credentialProfileId && !request.credentialProfileAId && !request.credentialProfileBId && (!request.studio || request.studio.authentication.mode === "public")) return undefined;
    if (!this.vault) throw new Error("Credential vault is unavailable for this dashboard scan.");
    return resolveCredentialAuthForDashboardScan(this.vault, request);
  }

  public async rerun(scanId: string): Promise<string> {
    const row = this.database.db.prepare("SELECT safe_configuration_summary FROM scans WHERE id = ?").get(scanId) as { safe_configuration_summary: string } | undefined;
    if (!row) throw new Error("Scan not found.");
    const summary = JSON.parse(row.safe_configuration_summary) as Partial<DashboardScanCreateRequest> & { auth?: boolean; accountPair?: boolean };
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

  public async shutdown(): Promise<void> {
    this.stopping = true;
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
      this.scans.updateStatus(item.scanId, "RUNNING");
      const result = await this.workers.run(item.scanId, item.request, {
        onPlan: (message) => {
          this.database.transaction(() => {
            this.plans.create(item.scanId, message.planSnapshot as Parameters<PlanRepository["create"]>[1]);
            this.modules.createQueued(item.scanId, message.modules);
            this.scans.updatePlanSummary(item.scanId, message.evidenceLevel, message.modules.length);
            this.events.append(item.scanId, "PLAN_COMPLETED", "Planning completed in isolated worker.", { modules: message.modules.map((modulePlan) => modulePlan.id), workerId: message.workerId });
          });
        },
        onEvent: (message) => {
          void this.eventSink(item.scanId).emit(message.event as ScanExecutionEvent);
        },
        onHeartbeat: (message) => {
          this.events.append(item.scanId, "WORKER_HEARTBEAT", "Worker heartbeat.", { workerId: message.workerId, timestamp: message.timestamp });
        }
      }, item.mutationContracts?.length ? { contracts: item.mutationContracts } : undefined);
      if (result.status === "FAILED" || result.status === "INTERRUPTED") throw new Error(result.error ?? "Worker scan failed.");
      if (result.status === "CANCELLED") {
        this.database.transaction(() => {
          this.scans.updateStatus(item.scanId, "CANCELLED", { cancelledAt: nowIso(), ...(result.error ? { errorSummary: result.error } : {}) });
          this.events.append(item.scanId, "SCAN_CANCELLED", "Scan cancelled by isolated worker.", { workerId: result.workerId });
        });
        return;
      }
      if (!result.reportPath || !result.markdownReportPath || !result.htmlReportPath) throw new Error("Worker completed without report paths.");
      const report = await loadReport(result.reportPath);
      const jsonArtifact = this.recordArtifact(item.scanId, result.reportPath, "JSON_REPORT", "application/json");
      const markdownArtifact = this.recordArtifact(item.scanId, result.markdownReportPath, "MARKDOWN_REPORT", "text/markdown; charset=utf-8");
      const htmlArtifact = this.recordArtifact(item.scanId, result.htmlReportPath, "HTML_REPORT", "text/html; charset=utf-8");
      await recordScan(
        scanIndexPath(this.paths.reportsDir),
        entryFromReport(report, {
          outputDir: dirname(result.reportPath),
          reportPath: result.reportPath,
          markdownReportPath: result.markdownReportPath,
          htmlReportPath: result.htmlReportPath
        })
      );
      const findingCount = this.normalizer.normalizeReport(item.scanId, report);
      this.database.transaction(() => {
        this.scans.attachArtifacts(item.scanId, { json: jsonArtifact, markdown: markdownArtifact, html: htmlArtifact });
        this.scans.updateCounters(item.scanId);
        this.scans.updateStatus(item.scanId, "COMPLETED");
        this.events.append(item.scanId, "SCAN_COMPLETED", "Scan completed in isolated worker.", { findingCount, workerId: result.workerId });
      });
      this.createAutomaticComparison(item.scanId);
    } catch (error) {
      this.database.transaction(() => {
        this.scans.updateStatus(item.scanId, item.abortController.signal.aborted ? "CANCELLED" : "FAILED", {
          ...(item.abortController.signal.aborted ? { cancelledAt: nowIso() } : {}),
          errorSummary: safeErrorMessage(error)
        });
        this.events.append(item.scanId, item.abortController.signal.aborted ? "SCAN_CANCELLED" : "SCAN_FAILED", safeErrorMessage(error), {});
      });
    }
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

  private eventSink(scanId: string): ScanEventSink {
    return {
      emit: (event: ScanExecutionEvent) => {
        const metadata = redactDashboardValue(event.metadata ?? {}) as Record<string, unknown>;
        this.database.transaction(() => {
          this.events.append(scanId, event.type, event.message, metadata, event.moduleId);
          if (event.type === "MODULE_STARTED" && event.moduleId) {
            this.modules.mark(scanId, event.moduleId, "RUNNING");
            this.scans.updateStatus(scanId, "RUNNING", { currentModule: event.moduleId });
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

function safeErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Unknown dashboard scan execution failure.";
}

function fileHash(path: string): string {
  return createHash("sha256").update(path).digest("hex");
}
