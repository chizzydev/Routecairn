import { readFile } from "node:fs/promises";
import { CleanupAttemptLedger, cleanupDigest } from "../recovery/CleanupAttemptLedger.js";
import { cleanupJournalBaseline, verifyCleanupRestoration } from "../recovery/CleanupAttemptProof.js";
import { cleanupCredentialDigest } from "../recovery/CleanupAttemptBindings.js";
import { MutationRecoveryVault } from "../../core/offensive/MutationRecoveryVault.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { ControlledMutationApprovalRepository } from "../db/ControlledMutationApprovalRepository.js";
import { resolve } from "node:path";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
import { resolveRecoveryBundlePath } from "../../core/offensive/MutationRecoveryPath.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import { ScanWorkerManager, type WorkerRecoveryResult } from "../worker/ScanWorkerManager.js";
import type { TargetRepository } from "../db/DashboardRepositories.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";

export class ControlledMutationRecoveryService {
  private readonly approvals: ControlledMutationApprovalRepository;
  private readonly workers: ScanWorkerManager;
  private readonly active = new Map<string, Promise<WorkerRecoveryResult>>();
  private stopping = false;
  private readonly starts = new Set<Promise<unknown>>();
  public constructor(
    private readonly database: DashboardDatabase,
    private readonly paths: DashboardPaths,
    private readonly targets: TargetRepository,
    private readonly vault?: import("../credentials/CredentialVault.js").CredentialVault
  ) {
    this.approvals = new ControlledMutationApprovalRepository(database);
    this.workers = new ScanWorkerManager(database, paths, vault);
  }

  public async startRecovery(input: {
    recoveryJobId: string;
    approvalId: string;
    bundlePath: string;
    caseId: string;
    targetId: string;
    credentialProfileId: string;
    workerRequest: DashboardScanCreateRequest;
    requestId?: string;
    requestedBy?: string;
    submissionDigest?: string;
  }) {
    if (this.stopping) throw Error("RECOVERY_SERVICE_STOPPING");
    const pending = this.prepareRecovery(structuredClone(input));
    this.starts.add(pending);
    try {
      return await pending;
    } finally {
      this.starts.delete(pending);
    }
  }
  private async prepareRecovery(input: {
    recoveryJobId: string;
    approvalId: string;
    bundlePath: string;
    caseId: string;
    targetId: string;
    credentialProfileId: string;
    workerRequest: DashboardScanCreateRequest;
    requestId?: string;
    requestedBy?: string;
    submissionDigest?: string;
  }) {
    if (this.stopping) throw Error("RECOVERY_SERVICE_STOPPING");
    const approval = this.approvals.get(input.approvalId);
    if (!approval || approval.caseId !== input.caseId || approval.targetId !== input.targetId)
      throw Error("RECOVERY_APPROVAL_MISMATCH");
    const target = this.targets.get(input.targetId);
    if (!target || target.baseOrigin !== approval.targetOrigin) throw Error("RECOVERY_TARGET_MISMATCH");
    const submissionDigest =
        input.submissionDigest ??
        cleanupDigest([input.approvalId, input.caseId, input.targetId, input.credentialProfileId]),
      prior = CleanupAttemptLedger.for(this.database).lookup(
        input.requestId,
        target.organizationId,
        input.requestedBy ?? "local-operator",
        submissionDigest
      );
    if (prior) return { attempt: prior, replayed: true, completion: this.active.get(prior.id) };
    const journalRoot = realpathSync(resolve(this.paths.mutationJournalDir)),
      canonicalBundle = resolveRecoveryBundlePath(journalRoot, input.bundlePath, input.caseId),
      bytes = await readFile(canonicalBundle),
      bundleDigest = createHash("sha256").update(bytes).digest("hex"),
      bundle = await new MutationRecoveryVault(journalRoot).open(canonicalBundle, input.caseId, bundleDigest);
    if (bundle.targetOrigin !== approval.targetOrigin) throw Error("RECOVERY_ORIGIN_MISMATCH");
    const fingerprint = createHash("sha256")
        .update(`${target.id}:${target.rowVersion}:${target.baseOrigin}`)
        .digest("hex"),
      scopeDigest = createHash("sha256")
        .update(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort()))
        .digest("hex");
    if (fingerprint !== approval.targetIdentityFingerprint || scopeDigest !== approval.scopeDigest)
      throw Error("RECOVERY_TARGET_CHANGED");
    const binding = bundle.approvalBinding;
    if (
      binding
        ? binding.targetIdentityFingerprint !== fingerprint ||
          binding.planIdentity !== approval.planIdentity ||
          binding.scopeDigest !== scopeDigest
        : bundle.targetIdentityFingerprint !== fingerprint || bundle.contractDigest !== approval.planIdentity
    )
      throw Error("RECOVERY_BINDING_MISMATCH");
    const ledger = CleanupAttemptLedger.for(this.database),
      baseline = await cleanupJournalBaseline(journalRoot),
      credentialDigest = cleanupCredentialDigest(this.vault, input.workerRequest, target.organizationId);
    const accepted = ledger.reserve(
      {
        jobId: input.recoveryJobId,
        organizationId: target.organizationId,
        targetId: target.id,
        caseId: input.caseId,
        kind: "CONTROLLED",
        authorityKey: "approval:" + approval.id,
        ...(input.requestId ? { requestId: input.requestId } : {}),
        requestedBy: input.requestedBy ?? "local-operator",
        binding: {
          submissionDigest,
          approvalId: approval.id,
          priorApproval: {
            expiresAt: approval.expiresAt,
            approvedBy: approval.approvedBy ?? null,
            approvedAt: approval.approvedAt ?? null,
            status: approval.status,
            recoveryJobId: approval.recoveryJobId ?? null,
            recoveryStartedAt: approval.recoveryStartedAt ?? null,
            recoveryCompletedAt: approval.recoveryCompletedAt ?? null,
            errorDigest: cleanupDigest(approval.recoveryErrorSummary ?? null)
          },
          origin: target.baseOrigin,
          targetFingerprint: fingerprint,
          scopeDigest,
          planIdentity: approval.planIdentity,
          bundleDigest,
          credentialDigest,
          ...baseline
        }
      },
      () => {
        if (this.stopping) throw Error("RECOVERY_SERVICE_STOPPING");
        const current = this.targets.get(target.id);
        if (!current || current.rowVersion !== target.rowVersion) throw Error("RECOVERY_TARGET_CHANGED");
        this.approvals.beginRecovery(approval.id, input.recoveryJobId);
      }
    );
    if (accepted.replayed) return { ...accepted, completion: this.active.get(accepted.attempt.id) };
    const completion = this.execute(accepted.attempt.id, input, canonicalBundle);
    this.active.set(accepted.attempt.id, completion);
    void completion.finally(() => this.active.delete(accepted.attempt.id)).catch(() => undefined);
    return { ...accepted, completion };
  }
  public async queueRecovery(
    input: Parameters<ControlledMutationRecoveryService["startRecovery"]>[0]
  ): Promise<WorkerRecoveryResult> {
    const accepted = await this.startRecovery(input);
    if (!accepted.completion) throw Error("RECOVERY_REQUEST_ALREADY_RECORDED");
    return accepted.completion;
  }
  private async execute(
    id: string,
    input: Parameters<ControlledMutationRecoveryService["startRecovery"]>[0],
    bundlePath: string
  ) {
    const ledger = CleanupAttemptLedger.for(this.database);
    try {
      const result = await this.workers.runRecovery(
        input.recoveryJobId,
        input.workerRequest,
        input.caseId,
        bundlePath,
        id
      );
      await this.workers.drainCompletedWorkers();
      const verified = await verifyCleanupRestoration(ledger, id, this.paths.mutationJournalDir, result);
      if (result.cleanupOutcome === "ROLLBACK_VERIFIED" && !verified)
        throw Error("RECOVERY_RESTORATION_PROOF_UNAVAILABLE");
      this.database.transaction(() => {
        ledger.append(id, verified ? "RESTORATION_VERIFIED" : "FAILED", {
          nativeCustodyDrained: true,
          independentJournalVerification: verified,
          ...(result.proof ? { proof: result.proof } : {})
        });
        this.approvals.updateStatus(
          input.approvalId,
          verified ? "COMPLETED" : "CLEANUP_FAILED",
          verified ? undefined : "CLEANUP_FAILED"
        );
      });
      return result;
    } catch (error) {
      try {
        await this.workers.drainCompletedWorkers();
      } catch {
        /* Uncertain native custody remains durable. */
      }
      ledger.interruptAndProject(id);
      throw Error(safeRecoveryErrorCode(error));
    }
  }

  public async shutdown(): Promise<void> {
    this.stopping = true;
    await Promise.allSettled(this.starts);
    await Promise.allSettled(this.active.values());
    await this.workers.shutdown();
  }
}

function safeRecoveryErrorCode(error: unknown): string {
  const value = error instanceof Error ? error.message : "RECOVERY_FAILED";
  return /^RECOVERY_[A-Z0-9_]+$/.test(value) ? value : "RECOVERY_FAILED";
}
