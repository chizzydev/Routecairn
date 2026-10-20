import { readFile } from "node:fs/promises";
import { CleanupAttemptLedger, cleanupDigest } from "../recovery/CleanupAttemptLedger.js";
import { cleanupJournalBaseline, verifyCleanupRestoration } from "../recovery/CleanupAttemptProof.js";
import { cleanupCredentialDigest } from "../recovery/CleanupAttemptBindings.js";
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

export const workflowRecoveryRequestSchema = z
  .object({
    requestId: z.string().uuid().optional(),
    caseId: z.string().regex(/^[A-Za-z0-9._-]{1,200}$/),
    checkpointDigest: z.string().regex(/^[a-f0-9]{64}$/),
    targetId: z.string().uuid(),
    credentialProfileId: z.string().uuid().optional(),
    credentialProfileAId: z.string().uuid().optional(),
    credentialProfileBId: z.string().uuid().optional(),
    confirmation: z.literal("I_AUTHORIZE_STORED_CLEANUP_ONLY")
  })
  .strict()
  .refine(
    (value) => Boolean(value.credentialProfileAId) === Boolean(value.credentialProfileBId),
    "Recovery requires both A/B profiles."
  );

export class WorkflowRecoveryService {
  private readonly workers: ScanWorkerManager;
  private readonly active = new Set<Promise<void>>();
  private stopping = false;
  private readonly starts = new Set<Promise<string>>();
  public constructor(
    private readonly database: DashboardDatabase,
    private readonly paths: DashboardPaths,
    private readonly targets: TargetRepository,
    private readonly vault: CredentialVault
  ) {
    this.workers = new ScanWorkerManager(database, paths, vault);
  }

  public async inventory() {
    const status = await readMutationCleanupStatus(
      this.paths.mutationJournalDir,
      this.paths.mutationJournalRegistryPath
    );
    const cases = await Promise.all(
      status.cases.map(async (item) => {
        const centralJournalId = createHash("sha256")
          .update(resolve(this.paths.mutationJournalDir))
          .digest("hex")
          .slice(0, 16);
        if (item.journalId !== centralJournalId) return { ...item, recoveryKind: "REGISTERED_LEGACY" as const };
        try {
          const checkpoint = await this.open(item.caseId);
          if (checkpoint.kind !== "WORKFLOW_CLEANUP_V1")
            return { ...item, recoveryKind: "CONTROLLED_CONTRACT" as const };
          return {
            ...item,
            targetOrigin: checkpoint.targetOrigin,
            recoveryKind: "WORKFLOW" as const,
            workflow: checkpoint.workflow,
            sourceCaseId: checkpoint.sourceCaseId,
            checkpointDigest: checkpoint.digest,
            actorSlots: Object.keys(checkpoint.actorBindings),
            cleanupOnly: true
          };
        } catch {
          return { ...item, recoveryKind: "UNAVAILABLE" as const };
        }
      })
    );
    return {
      ...status,
      cases,
      jobs: this.database.db.prepare("SELECT * FROM workflow_recovery_jobs ORDER BY created_at DESC LIMIT 100").all()
    };
  }

  public get(id: string) {
    return this.database.db.prepare("SELECT * FROM workflow_recovery_jobs WHERE id = ?").get(id);
  }

  public async enqueue(input: z.infer<typeof workflowRecoveryRequestSchema>, requestedBy: string): Promise<string> {
    if (this.stopping) throw Error("RECOVERY_SERVICE_STOPPING");
    const pending = this.enqueueBound(input, requestedBy);
    this.starts.add(pending);
    try {
      return await pending;
    } finally {
      this.starts.delete(pending);
    }
  }
  private async enqueueBound(
    input: z.infer<typeof workflowRecoveryRequestSchema>,
    requestedBy: string
  ): Promise<string> {
    if (this.stopping) throw new Error("RECOVERY_SERVICE_STOPPING");
    const request = workflowRecoveryRequestSchema.parse(input);
    const selected = this.targets.get(request.targetId);
    if (!selected) throw Error("RECOVERY_TARGET_MISMATCH");
    const { requestId: _requestId, ...submission } = request,
      submissionDigest = cleanupDigest(submission),
      ledger = CleanupAttemptLedger.for(this.database),
      prior = ledger.lookup(request.requestId, selected.organizationId, requestedBy, submissionDigest);
    if (prior) return prior.job_id;
    const checkpoint = await this.open(request.caseId);
    if (checkpoint.kind !== "WORKFLOW_CLEANUP_V1" || checkpoint.digest !== request.checkpointDigest)
      throw new Error("RECOVERY_CHECKPOINT_CHANGED");
    const pending = await new MutationJournal(
      join(this.paths.mutationJournalDir, "mutation-journal.json")
    ).unresolvedCaseIds();
    const status = await readMutationCleanupStatus(
      this.paths.mutationJournalDir,
      this.paths.mutationJournalRegistryPath
    );
    if (!pending.includes(request.caseId) && !status.cases.some((item) => item.caseId === request.caseId))
      throw new Error("RECOVERY_NOT_REQUIRED");
    const target = this.targets.get(request.targetId);
    if (!target || target.baseOrigin !== checkpoint.targetOrigin) throw new Error("RECOVERY_TARGET_MISMATCH");
    // New target configuration cannot silently broaden or replace the scope sealed before mutation.
    const workerRequest: DashboardScanCreateRequest = {
      target: checkpoint.targetOrigin,
      targetId: target.id,
      profile: "authenticated",
      recoveryScope: scopeSchema.parse(target.approvedScope),
      ...(request.credentialProfileId ? { credentialProfileId: request.credentialProfileId } : {}),
      ...(request.credentialProfileAId
        ? { credentialProfileAId: request.credentialProfileAId, credentialProfileBId: request.credentialProfileBId! }
        : {})
    };
    const id = randomUUID();
    workerRequest.workflowRecoveryDigest = checkpoint.digest;
    const bundlePath = resolveRecoveryBundlePath(
      this.paths.mutationJournalDir,
      join(this.paths.mutationJournalDir, `${request.caseId}.recovery.enc`),
      request.caseId
    );
    if (this.stopping) throw new Error("RECOVERY_SERVICE_STOPPING");
    if (
      this.database.db
        .prepare("SELECT 1 FROM workflow_recovery_jobs WHERE case_id = ? AND status = 'RUNNING'")
        .get(request.caseId)
    )
      throw new Error("RECOVERY_ALREADY_RUNNING");

    const baseline = await cleanupJournalBaseline(this.paths.mutationJournalDir),
      bundleDigest = createHash("sha256")
        .update(await readFile(bundlePath))
        .digest("hex"),
      targetFingerprint = cleanupDigest([target.id, target.rowVersion, target.baseOrigin, target.approvedScope]),
      credentialDigest = cleanupCredentialDigest(this.vault, workerRequest, target.organizationId);
    const accepted = ledger.reserve(
      {
        jobId: id,
        organizationId: target.organizationId,
        targetId: target.id,
        caseId: request.caseId,
        kind: "WORKFLOW",
        authorityKey: "workflow:" + request.checkpointDigest,
        ...(request.requestId ? { requestId: request.requestId } : {}),
        requestedBy,
        binding: {
          submissionDigest,
          targetFingerprint,
          checkpointDigest: checkpoint.digest,
          checkpointRevision: checkpoint.revision,
          bundleDigest,
          credentialDigest,
          ...baseline
        }
      },
      () => {
        if (this.stopping) throw Error("RECOVERY_SERVICE_STOPPING");
        const current = this.targets.get(target.id);
        if (
          !current ||
          cleanupDigest([current.id, current.rowVersion, current.baseOrigin, current.approvedScope]) !==
            targetFingerprint
        )
          throw Error("RECOVERY_TARGET_CHANGED");
        this.database.db
          .prepare(
            "INSERT INTO workflow_recovery_jobs(id,case_id,checkpoint_digest,target_id,status,requested_by,created_at,safe_summary) VALUES(?,?,?,?, 'RUNNING',?,?,?)"
          )
          .run(
            id,
            request.caseId,
            checkpoint.digest,
            target.id,
            requestedBy,
            new Date().toISOString(),
            "Explicit cleanup-only attempt authorized; no attack replay."
          );
      }
    );
    if (accepted.replayed) return accepted.attempt.job_id;
    const running = Promise.resolve()
      .then(() => this.workers.runRecovery(id, workerRequest, request.caseId, bundlePath, accepted.attempt.id))
      .then(async (result) => {
        await this.workers.drainCompletedWorkers();
        const verified = await verifyCleanupRestoration(
          ledger,
          accepted.attempt.id,
          this.paths.mutationJournalDir,
          result
        );
        if (result.cleanupOutcome === "ROLLBACK_VERIFIED" && !verified)
          throw Error("RECOVERY_RESTORATION_PROOF_UNAVAILABLE");
        this.database.transaction(() => {
          ledger.append(accepted.attempt.id, verified ? "RESTORATION_VERIFIED" : "FAILED", {
            nativeCustodyDrained: true,
            independentJournalVerification: verified,
            ...(result.proof ? { proof: result.proof } : {})
          });
          this.finish(
            id,
            verified ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED",
            verified
              ? "Restoration independently verified; immutable attempt evidence retained."
              : "Cleanup failed. Inspect retained attempt; its authorization cannot be reused."
          );
        });
      })
      .catch(async () => {
        try {
          await this.workers.drainCompletedWorkers();
        } catch {
          /* Preserve native UNKNOWN. */
        }
        ledger.interruptAndProject(accepted.attempt.id);
      });

    this.active.add(running);
    void running.finally(() => this.active.delete(running)).catch(() => undefined);
    return id;
  }

  public async shutdown(): Promise<void> {
    this.stopping = true;
    // Recovery workers already have a bounded timeout. Let cleanup finish before
    // closing the database rather than killing a restoration midway through.
    await Promise.allSettled(this.starts);
    await Promise.allSettled(this.active);
    await this.workers.shutdown();
  }

  private finish(id: string, status: string, summary: string) {
    this.database.db
      .prepare(
        "UPDATE workflow_recovery_jobs SET status = ?, completed_at = ?, safe_summary = ? WHERE id = ? AND status = 'RUNNING'"
      )
      .run(status, new Date().toISOString(), summary, id);
  }
  private async open(caseId: string): Promise<WorkflowCheckpoint> {
    const path = resolveRecoveryBundlePath(
      this.paths.mutationJournalDir,
      join(this.paths.mutationJournalDir, `${caseId}.recovery.enc`),
      caseId
    );
    return new MutationRecoveryVault(this.paths.mutationJournalDir).open<WorkflowCheckpoint>(path, caseId);
  }
}
