import { ControlledMutationApprovalRepository } from "../../src/dashboard/db/ControlledMutationApprovalRepository.js";
import { RecoveryCenterService } from "../../src/dashboard/recovery/RecoveryCenterService.js";
import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { recoveryCenterFixture } from "../helpers/recovery-center-fixture.js";
import { CleanupAttemptLedger, cleanupDigest } from "../../src/dashboard/recovery/CleanupAttemptLedger.js";
function fixture() {
  const f = recoveryCenterFixture(),
    ledger = CleanupAttemptLedger.for(f.database),
    target = f.database.db.prepare("SELECT id FROM targets WHERE organization_id=?").get(f.scope.organizationId) as {
      id: string;
    },
    input = {
      jobId: randomUUID(),
      organizationId: f.scope.organizationId,
      targetId: target.id,
      caseId: "ledger-fixture",
      kind: "WORKFLOW" as const,
      authorityKey: "fixture:" + randomUUID(),
      requestId: randomUUID(),
      requestedBy: "fixture-owner",
      binding: { submissionDigest: cleanupDigest("fixture"), provenance: "STATE_MACHINE_FIXTURE_NO_WORKER_EXECUTION" }
    };
  return { ...f, ledger, input };
}
describe("append-only native SQLite cleanup state machine", () => {
  it("rolls back requested state and consumption together when authorization is refused", () => {
    const f = fixture();
    try {
      expect(() =>
        f.ledger.reserve(f.input, () => {
          throw Error("refused");
        })
      ).toThrow("refused");
      expect(f.database.db.prepare("SELECT COUNT(*) n FROM cleanup_attempts").get()).toEqual({ n: 0 });
    } finally {
      f.close();
    }
  });
  it("returns the recorded identity but rejects changed actor, submission and reused authority", () => {
    const f = fixture();
    try {
      const a = f.ledger.reserve(f.input, () => {}),
        b = f.ledger.reserve({ ...f.input, jobId: randomUUID() }, () => {
          throw Error("must not run");
        });
      expect(b.attempt.id).toBe(a.attempt.id);
      expect(b.replayed).toBe(true);
      expect(() => f.ledger.reserve({ ...f.input, requestedBy: "other" }, () => {})).toThrow("IDENTITY_CHANGED");
      expect(() => f.ledger.reserve({ ...f.input, binding: { submissionDigest: "changed" } }, () => {})).toThrow(
        "IDENTITY_CHANGED"
      );
      expect(() => f.ledger.reserve({ ...f.input, requestId: randomUUID() }, () => {})).toThrow(
        "AUTHORITY_ALREADY_CONSUMED"
      );
    } finally {
      f.close();
    }
  });
  it("rejects terminal outcomes out of order and SQL sequence gaps", () => {
    const f = fixture();
    try {
      const { id } = f.ledger.reserve(f.input, () => {}).attempt;
      expect(() => f.ledger.append(id, "RESTORATION_VERIFIED", {})).toThrow("TRANSITION");
      expect(() =>
        f.database.db
          .prepare("INSERT INTO cleanup_attempt_events VALUES(?,9,'UNKNOWN','{}',?,'bad','fixture')")
          .run(id, f.ledger.history(id).head)
      ).toThrow("SEQUENCE");
    } finally {
      f.close();
    }
  });
  it("reconciles committed authorization without a granted command as NOT_EXECUTED exactly once", () => {
    const f = fixture();
    try {
      const { id } = f.ledger.reserve(f.input, () => {}).attempt,
        second = new CleanupAttemptLedger(f.database);
      second.reconcileStartup();
      expect(second.history(id).phase).toBe("NOT_EXECUTED");
      const n = second.history(id).events.length;
      second.reconcileStartup();
      expect(second.history(id).events).toHaveLength(n);
      expect(() => second.append(id, "AUTHORIZED", {})).toThrow("TRANSITION");
    } finally {
      f.close();
    }
  });
  it("keeps an armed or result-received attempt UNKNOWN after restart", () => {
    for (const result of [false, true]) {
      const f = fixture();
      try {
        const { id } = f.ledger.reserve(f.input, () => {}).attempt;
        f.ledger.append(id, "WORKER_PENDING", {});
        f.ledger.append(id, "WORKER_ACTIVATED", {});
        f.ledger.append(id, "DISPATCH_ARMED", {});
        if (result) {
          f.ledger.gate(id, 1);
          f.ledger.append(id, "RESULT_RECEIVED", { cleanupOutcome: "ROLLBACK_VERIFIED" });
        }
        const second = new CleanupAttemptLedger(f.database);
        second.reconcileStartup();
        expect(second.history(id).phase).toBe("UNKNOWN");
        expect(second.unresolved()).toBe(true);
      } finally {
        f.close();
      }
    }
  });
  it("refuses replayed request ordinals and never reconciles a currently owned live attempt", () => {
    const f = fixture();
    try {
      const { id } = f.ledger.reserve(f.input, () => {}).attempt;
      f.ledger.append(id, "WORKER_PENDING", {});
      f.ledger.append(id, "WORKER_ACTIVATED", {});
      f.ledger.append(id, "DISPATCH_ARMED", {});
      f.ledger.gate(id, 1);
      expect(() => f.ledger.gate(id, 1)).toThrow("SEQUENCE");
      f.ledger.reconcileStartup();
      expect(f.ledger.history(id).phase).toBe("DISPATCH_ATTEMPTED");
    } finally {
      f.close();
    }
  });
  it("detects forged hash-chain rows and quarantines instead of inferring a clean outcome", () => {
    const f = fixture();
    try {
      const { id } = f.ledger.reserve(f.input, () => {}).attempt,
        h = f.ledger.history(id);
      f.database.db
        .prepare("INSERT INTO cleanup_attempt_events VALUES(?,3,'WORKER_PENDING','{}',?,'bad','fixture')")
        .run(id, h.head);
      expect(() => f.ledger.history(id)).toThrow("INTEGRITY");
      expect(f.ledger.unresolved()).toBe(true);
    } finally {
      f.close();
    }
  });
  it("requires FULL synchronous durability for recovery records", () => {
    const f = fixture();
    try {
      f.database.db.pragma("synchronous=NORMAL");
      expect(() => new CleanupAttemptLedger(f.database)).toThrow("DURABILITY");
    } finally {
      f.close();
    }
  });
  it("binds human review to the prefixed immutable attempt snapshot without clearing it", async () => {
    const f = fixture();
    try {
      const { id } = f.ledger.reserve(f.input, () => {}).attempt;
      f.ledger.append(id, "WORKER_PENDING", {});
      f.ledger.append(id, "WORKER_ACTIVATED", {});
      f.ledger.append(id, "DISPATCH_ARMED", {});
      f.ledger.append(id, "UNKNOWN", {});
      const service = new RecoveryCenterService(f.database, f.emptyWorkflow as never),
        issue = (await service.snapshot(f.scope, "QUARANTINED", { kind: "RECOVERY" })).issues.find(
          (i) => i.subjectId === "attempt:" + id
        )!;
      expect(issue).toBeTruthy();
      const result = await service.review(f.scope, {
        kind: issue.kind,
        subjectId: issue.subjectId,
        snapshotDigest: issue.snapshotDigest,
        decision: "ACKNOWLEDGED",
        reason: "EVIDENCE_INCOMPLETE",
        confirmation: "I_REVIEWED_EVIDENCE_WITHOUT_RESOLVING_UNCERTAINTY"
      });
      expect(result.uncertaintyResolved).toBe(false);
      expect(f.ledger.history(id).phase).toBe("UNKNOWN");
    } finally {
      f.close();
    }
  });

  it("reconciles an attempt and its compatibility approval atomically", () => {
    const f = fixture();
    try {
      const approvals = new ControlledMutationApprovalRepository(f.database),
        target = f.database.db.prepare("SELECT base_origin FROM targets WHERE id=?").get(f.input.targetId) as {
          base_origin: string;
        },
        approvalId = approvals.create({
          caseId: f.input.caseId,
          targetId: f.input.targetId,
          targetOrigin: target.base_origin,
          targetIdentityFingerprint: "a".repeat(64),
          scopeDigest: "b".repeat(64),
          planIdentity: "c".repeat(64),
          authorizationSummary: "Storage-boundary-only fixture",
          expiresAt: "2099-01-01T00:00:00.000Z"
        });
      approvals.approve(approvalId, "fixture");
      const { id } = f.ledger.reserve(
        { ...f.input, kind: "CONTROLLED", authorityKey: "approval:" + approvalId },
        () => {
          approvals.beginRecovery(approvalId, f.input.jobId);
        }
      ).attempt;
      f.ledger.append(id, "WORKER_PENDING", {});
      f.ledger.append(id, "WORKER_ACTIVATED", {});
      f.ledger.append(id, "DISPATCH_ARMED", {});
      f.database.db.exec(
        "CREATE TRIGGER fixture_reconcile_failure BEFORE UPDATE ON controlled_mutation_approvals BEGIN SELECT RAISE(ABORT,'FIXTURE_RECONCILE_UPDATE_FAILURE'); END"
      );
      const fresh = new CleanupAttemptLedger(f.database);
      expect(() => fresh.reconcileStartup()).toThrow("FIXTURE_RECONCILE_UPDATE_FAILURE");
      expect(fresh.history(id).phase).toBe("DISPATCH_ARMED");
      expect(approvals.get(approvalId)?.status).toBe("EXECUTING");
      expect(fresh.unresolved()).toBe(true);
      f.capture("ATOMIC_RECONCILIATION_FAULT");
    } finally {
      f.close();
    }
  });
});
