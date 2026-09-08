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
  public constructor(database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly targets: TargetRepository, vault?: import("../credentials/CredentialVault.js").CredentialVault) {
    this.approvals = new ControlledMutationApprovalRepository(database);
    this.workers = new ScanWorkerManager(database, paths, vault);
  }
  public async queueRecovery(input: { recoveryJobId: string; approvalId: string; bundlePath: string; caseId: string; targetId: string; credentialProfileId: string; workerRequest: DashboardScanCreateRequest }): Promise<WorkerRecoveryResult> {
    const approval = this.approvals.beginRecovery(input.approvalId, input.recoveryJobId);
    try {
      if (approval.caseId !== input.caseId || approval.targetId !== input.targetId) throw new Error("RECOVERY_APPROVAL_MISMATCH");
      const target = this.targets.get(input.targetId);
      if (!target || target.baseOrigin !== approval.targetOrigin) throw new Error("RECOVERY_TARGET_MISMATCH");
      const journalRoot = realpathSync(resolve(this.paths.mutationJournalDir));
      const canonicalBundle = resolveRecoveryBundlePath(journalRoot, input.bundlePath, input.caseId);
      const bundle = await new MutationRecoveryVault(journalRoot).open(canonicalBundle, input.caseId);
      if (bundle.targetOrigin !== approval.targetOrigin) throw new Error("RECOVERY_ORIGIN_MISMATCH");
      const targetFingerprint = createHash("sha256").update(`${target.id}:${target.rowVersion}:${target.baseOrigin}`).digest("hex");
      const scopeDigest = createHash("sha256").update(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort())).digest("hex");
      if (targetFingerprint !== approval.targetIdentityFingerprint || scopeDigest !== approval.scopeDigest) throw new Error("RECOVERY_TARGET_CHANGED");
      const binding = bundle.approvalBinding;
      if (binding ? binding.targetIdentityFingerprint !== approval.targetIdentityFingerprint || binding.planIdentity !== approval.planIdentity || binding.scopeDigest !== approval.scopeDigest : bundle.targetIdentityFingerprint !== approval.targetIdentityFingerprint || bundle.contractDigest !== approval.planIdentity) throw new Error("RECOVERY_BINDING_MISMATCH");
      const result = await this.workers.runRecovery(input.recoveryJobId, input.workerRequest, input.caseId, canonicalBundle);
      if (result.caseId !== input.caseId) throw new Error("RECOVERY_CASE_MISMATCH");
      const failure = result.cleanupOutcome === "ROLLBACK_VERIFIED" ? undefined : "CLEANUP_FAILED";
      this.approvals.updateStatus(input.approvalId, result.cleanupOutcome === "ROLLBACK_VERIFIED" ? "COMPLETED" : "CLEANUP_FAILED", failure);
      return result;
    } catch (error) {
      const code = safeRecoveryErrorCode(error);
      this.approvals.updateStatus(input.approvalId, "CLEANUP_FAILED", code);
      throw new Error(code);
    } finally {
      await this.workers.drainCompletedWorkers();
    }
  }
  public async shutdown(): Promise<void> { await this.workers.shutdown(); }
}

function safeRecoveryErrorCode(error: unknown): string {
  const value = error instanceof Error ? error.message : "RECOVERY_FAILED";
  return /^RECOVERY_[A-Z0-9_]+$/.test(value) ? value : "RECOVERY_FAILED";
}
