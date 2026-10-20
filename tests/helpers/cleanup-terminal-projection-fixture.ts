import { retainOwnedTestDirectory } from "./owned-test-directory.js";
import { randomUUID } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { recoveryCenterFixture } from "./recovery-center-fixture.js";
import { CleanupAttemptLedger, cleanupDigest } from "../../src/dashboard/recovery/CleanupAttemptLedger.js";
import { ControlledMutationApprovalRepository } from "../../src/dashboard/db/ControlledMutationApprovalRepository.js";
export function terminalProjectionFixture(kind: "CONTROLLED" | "WORKFLOW", armed = true) {
  const f = recoveryCenterFixture(),
    ledger = CleanupAttemptLedger.for(f.database),
    target = f.database.db
      .prepare("SELECT id,base_origin FROM targets WHERE organization_id=?")
      .get(f.scope.organizationId) as { id: string; base_origin: string },
    jobId = randomUUID(),
    caseId = "terminal-" + randomUUID(),
    digest = "a".repeat(64);
  let approvalId: string | undefined;
  if (kind === "CONTROLLED") {
    const approvals = new ControlledMutationApprovalRepository(f.database);
    approvalId = approvals.create({
      caseId,
      targetId: target.id,
      targetOrigin: target.base_origin,
      targetIdentityFingerprint: digest,
      scopeDigest: digest,
      planIdentity: digest,
      authorizationSummary: "Owned SQLite crash projection fixture; no target traffic",
      expiresAt: "2099-01-01T00:00:00.000Z"
    });
    approvals.approve(approvalId, "fixture-owner");
  }
  const admitted = ledger.reserve(
    {
      kind,
      jobId,
      caseId,
      targetId: target.id,
      organizationId: f.scope.organizationId,
      requestedBy: "fixture-owner",
      requestId: randomUUID(),
      authorityKey: kind === "CONTROLLED" ? "approval:" + approvalId : "workflow:" + digest,
      binding: {
        submissionDigest: cleanupDigest(jobId),
        ...(approvalId ? { approvalId } : { checkpointDigest: digest })
      }
    },
    () => {
      if (approvalId) new ControlledMutationApprovalRepository(f.database).beginRecovery(approvalId, jobId);
      else
        f.database.db
          .prepare(
            "INSERT INTO workflow_recovery_jobs(id,case_id,checkpoint_digest,target_id,status,requested_by,created_at,safe_summary) VALUES(?,?,?,?, 'RUNNING',?,?,?)"
          )
          .run(
            jobId,
            caseId,
            digest,
            target.id,
            "fixture-owner",
            new Date().toISOString(),
            "Owned disposable projection fixture"
          );
    }
  );
  if (armed) {
    ledger.append(admitted.attempt.id, "WORKER_PENDING", {});
    ledger.append(admitted.attempt.id, "WORKER_ACTIVATED", {});
    ledger.append(admitted.attempt.id, "DISPATCH_ARMED", {});
  }
  const status = () =>
    kind === "CONTROLLED"
      ? f.database.db
          .prepare(
            "SELECT status,recovery_error_summary,recovery_completed_at FROM controlled_mutation_approvals WHERE id=?"
          )
          .get(approvalId)
      : f.database.db
          .prepare("SELECT status,safe_summary,completed_at FROM workflow_recovery_jobs WHERE id=?")
          .get(jobId);
  const capture = (label: string) =>
    writeFileSync(
      join(f.root, label + ".json"),
      JSON.stringify(
        {
          kind,
          attempt: ledger.history(admitted.attempt.id),
          compatibility: status(),
          integrity: f.database.db.pragma("integrity_check"),
          foreignKeys: f.database.db.pragma("foreign_key_check"),
          provenance: "ACTUAL_OWNED_WINDOWS_SQLITE_NO_TARGET_TRAFFIC"
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  return {
    ...f,
    kind,
    jobId,
    caseId,
    approvalId,
    attemptId: admitted.attempt.id,
    ledger,
    status,
    capture,
    close() {
      if (f.database.db.open) f.close();
      else retainOwnedTestDirectory(f.root);
    }
  };
}
