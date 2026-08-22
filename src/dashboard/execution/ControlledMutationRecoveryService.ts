import { MutationRecoveryVault } from "../../core/offensive/MutationRecoveryVault.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { ControlledMutationApprovalRepository } from "../db/ControlledMutationApprovalRepository.js";
import { isAbsolute, relative, resolve } from "node:path";
import { createHash } from "node:crypto";
import { realpathSync } from "node:fs";
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
    const approval = this.approvals.get(input.approvalId);
    if (!approval || approval.status !== "APPROVED" || approval.caseId !== input.caseId || approval.targetId !== input.targetId) throw new Error("RECOVERY_APPROVAL_MISMATCH: Recovery requires the exact approved case and target.");
    const target = this.targets.get(input.targetId);
    if (!target || target.baseOrigin !== approval.targetOrigin) throw new Error("RECOVERY_TARGET_MISMATCH: Registered target origin does not match the approval.");
    if (!isAbsolute(input.bundlePath) || input.bundlePath.includes("..") || input.bundlePath.includes("\\")) throw new Error("RECOVERY_PATH_INVALID: Bundle path must be absolute and cannot contain traversal.");
    const bundlePath = resolve(input.bundlePath);
    const journalRoot = resolve(this.paths.mutationJournalDir);
    const canonicalRoot = realpathSync(journalRoot);
    const canonicalBundle = realpathSync(bundlePath);
    const bundleRelative = relative(canonicalRoot, canonicalBundle);
    if (bundleRelative.startsWith("..") || bundleRelative.includes("..\\") || !canonicalBundle.endsWith(".recovery.enc")) throw new Error("RECOVERY_PATH_INVALID: Bundle must be an encrypted recovery file inside the registered mutation journal directory.");
    const bundle = await new MutationRecoveryVault(canonicalRoot).open(canonicalBundle, input.caseId);
    if (bundle.targetOrigin !== approval.targetOrigin) throw new Error("RECOVERY_ORIGIN_MISMATCH: Recovery bundle origin does not match the approval.");
    const currentTargetFingerprint = createHash("sha256").update(`${target.id}:${target.rowVersion}:${target.baseOrigin}`).digest("hex");
    const currentScopeDigest = createHash("sha256").update(JSON.stringify(target.approvedScope, Object.keys(target.approvedScope).sort())).digest("hex");
    if (currentTargetFingerprint !== approval.targetIdentityFingerprint || currentScopeDigest !== approval.scopeDigest) throw new Error("RECOVERY_TARGET_CHANGED: Registered target identity or approved scope changed after approval.");
    if (bundle.targetIdentityFingerprint !== approval.targetIdentityFingerprint || bundle.contractDigest !== approval.planIdentity) throw new Error("RECOVERY_BINDING_MISMATCH: Recovery bundle does not match the approved mutation identity.");
    this.approvals.beginRecovery(input.approvalId);
    try {
      const result = await this.workers.runRecovery(input.recoveryJobId, input.workerRequest, input.caseId, canonicalBundle);
      if (result.caseId !== input.caseId) throw new Error("RECOVERY_CASE_MISMATCH: Worker returned a different recovery case.");
      this.approvals.updateStatus(input.approvalId, result.cleanupOutcome === "ROLLBACK_VERIFIED" ? "COMPLETED" : "CLEANUP_FAILED");
      return result;
    } catch (error) {
      this.approvals.updateStatus(input.approvalId, "CLEANUP_FAILED");
      throw error;
    }
  }
}
