import { createHash, randomUUID } from "node:crypto";
import { join, resolve } from "node:path";
import { z } from "zod";
import { scopeSchema } from "../../config/ConfigSchema.js";
import { MutationRecoveryVault } from "../../core/offensive/MutationRecoveryVault.js";
import { MutationJournal } from "../../core/offensive/MutationJournal.js";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";
import { resolveRecoveryBundlePath } from "../../core/offensive/MutationRecoveryPath.js";
import type { WorkflowCheckpoint } from "../../core/offensive/WorkflowMutationCoordinator.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { TargetRepository } from "../db/DashboardRepositories.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import { ScanWorkerManager } from "../worker/ScanWorkerManager.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";

export const workflowRecoveryRequestSchema = z.object({
  caseId: z.string().regex(/^[A-Za-z0-9._-]{1,200}$/),
  checkpointDigest: z.string().regex(/^[a-f0-9]{64}$/), targetId: z.string().uuid(),
  credentialProfileId: z.string().uuid().optional(), credentialProfileAId: z.string().uuid().optional(), credentialProfileBId: z.string().uuid().optional(),
  confirmation: z.literal("I_AUTHORIZE_STORED_CLEANUP_ONLY")
}).strict().refine((value) => Boolean(value.credentialProfileAId) === Boolean(value.credentialProfileBId), "Recovery requires both A/B profiles.");

export class WorkflowRecoveryService {
  private readonly workers: ScanWorkerManager;
  private readonly active = new Set<Promise<void>>();
  private stopping = false;
  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly targets: TargetRepository, vault: CredentialVault) {
    this.workers = new ScanWorkerManager(database, paths, vault);
    database.db.prepare("UPDATE workflow_recovery_jobs SET status = 'INTERRUPTED', completed_at = ?, safe_summary = 'Dashboard restarted; cleanup remains unresolved. Reinspect before requesting recovery.' WHERE status = 'RUNNING'").run(new Date().toISOString());
  }

  public async inventory() {
    const status = await readMutationCleanupStatus(this.paths.mutationJournalDir, this.paths.mutationJournalRegistryPath);
    const cases = await Promise.all(status.cases.map(async (item) => {
      const centralJournalId = createHash("sha256").update(resolve(this.paths.mutationJournalDir)).digest("hex").slice(0, 16);
      if (item.journalId !== centralJournalId) return { ...item, recoveryKind: "REGISTERED_LEGACY" as const };
      try {
        const checkpoint = await this.open(item.caseId);
        if (checkpoint.kind !== "WORKFLOW_CLEANUP_V1") return { ...item, recoveryKind: "CONTROLLED_CONTRACT" as const };
        return { ...item, targetOrigin: checkpoint.targetOrigin, recoveryKind: "WORKFLOW" as const, workflow: checkpoint.workflow, sourceCaseId: checkpoint.sourceCaseId, checkpointDigest: checkpoint.digest, actorSlots: Object.keys(checkpoint.actorBindings), cleanupOnly: true };
      } catch { return { ...item, recoveryKind: "UNAVAILABLE" as const }; }
    }));
    return { ...status, cases, jobs: this.database.db.prepare("SELECT * FROM workflow_recovery_jobs ORDER BY created_at DESC LIMIT 100").all() };
  }

  public get(id: string) { return this.database.db.prepare("SELECT * FROM workflow_recovery_jobs WHERE id = ?").get(id); }

  public async enqueue(input: z.infer<typeof workflowRecoveryRequestSchema>, requestedBy: string): Promise<string> {
    if (this.stopping) throw new Error("RECOVERY_SERVICE_STOPPING");
    const request = workflowRecoveryRequestSchema.parse(input);
    const checkpoint = await this.open(request.caseId);
    if (checkpoint.kind !== "WORKFLOW_CLEANUP_V1" || checkpoint.digest !== request.checkpointDigest) throw new Error("RECOVERY_CHECKPOINT_CHANGED");
    const pending = await new MutationJournal(join(this.paths.mutationJournalDir, "mutation-journal.json")).unresolvedCaseIds();
    const status = await readMutationCleanupStatus(this.paths.mutationJournalDir, this.paths.mutationJournalRegistryPath);
    if (!pending.includes(request.caseId) && !status.cases.some((item) => item.caseId === request.caseId)) throw new Error("RECOVERY_NOT_REQUIRED");
    const target = this.targets.get(request.targetId);
    if (!target || target.baseOrigin !== checkpoint.targetOrigin) throw new Error("RECOVERY_TARGET_MISMATCH");
    // New target configuration cannot silently broaden or replace the scope sealed before mutation.
    const workerRequest: DashboardScanCreateRequest = { target: checkpoint.targetOrigin, targetId: target.id, profile: "authenticated", recoveryScope: scopeSchema.parse(target.approvedScope), ...(request.credentialProfileId ? { credentialProfileId: request.credentialProfileId } : {}), ...(request.credentialProfileAId ? { credentialProfileAId: request.credentialProfileAId, credentialProfileBId: request.credentialProfileBId! } : {}) };
    const id = randomUUID();
    workerRequest.workflowRecoveryDigest = checkpoint.digest;
    const bundlePath = resolveRecoveryBundlePath(this.paths.mutationJournalDir, join(this.paths.mutationJournalDir, `${request.caseId}.recovery.enc`), request.caseId);
    if (this.stopping) throw new Error("RECOVERY_SERVICE_STOPPING");
    if (this.database.db.prepare("SELECT 1 FROM workflow_recovery_jobs WHERE case_id = ? AND status = 'RUNNING'").get(request.caseId)) throw new Error("RECOVERY_ALREADY_RUNNING");
    this.database.db.prepare("INSERT INTO workflow_recovery_jobs(id,case_id,checkpoint_digest,target_id,status,requested_by,created_at,safe_summary) VALUES(?,?,?,?, 'RUNNING',?,?,?)").run(id, request.caseId, checkpoint.digest, target.id, requestedBy, new Date().toISOString(), "Explicit cleanup-only recovery requested; attack steps will not run.");
    const running = Promise.resolve().then(() => this.workers.runRecovery(id, workerRequest, request.caseId, bundlePath)).then((result) => {
      this.finish(id, result.cleanupOutcome, result.cleanupOutcome === "ROLLBACK_VERIFIED" ? "Restoration verified. No attack actions were replayed." : "Cleanup remains unresolved. Checkpoint retained.");
    }).catch(() => this.finish(id, "CLEANUP_FAILED", "Recovery could not verify restoration. Check credentials, policy and the retained cleanup obligation."));
    this.active.add(running);
    void running.finally(() => this.active.delete(running)).catch(() => undefined);
    return id;
  }

  public async shutdown(): Promise<void> {
    this.stopping = true;
    // Recovery workers already have a bounded timeout. Let cleanup finish before
    // closing the database rather than killing a restoration midway through.
    await Promise.allSettled(this.active);
    await this.workers.shutdown();
  }

  private finish(id: string, status: string, summary: string) { this.database.db.prepare("UPDATE workflow_recovery_jobs SET status = ?, completed_at = ?, safe_summary = ? WHERE id = ? AND status = 'RUNNING'").run(status, new Date().toISOString(), summary, id); }
  private async open(caseId: string): Promise<WorkflowCheckpoint> {
    const path = resolveRecoveryBundlePath(this.paths.mutationJournalDir, join(this.paths.mutationJournalDir, `${caseId}.recovery.enc`), caseId);
    return new MutationRecoveryVault(this.paths.mutationJournalDir).open<WorkflowCheckpoint>(path, caseId);
  }
}
