import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it, expect } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { CleanupAttemptLedger } from "../../src/dashboard/recovery/CleanupAttemptLedger.js";
import { terminalProjectionFixture } from "../helpers/cleanup-terminal-projection-fixture.js";
describe("terminal UNKNOWN compatibility restart projection", () => {
  it.each(["CONTROLLED", "WORKFLOW"] as const)(
    "repairs an already committed UNKNOWN without changing history: %s",
    (kind) => {
      const f = terminalProjectionFixture(kind);
      let reopened: DashboardDatabase | undefined;
      try {
        f.ledger.interrupt(f.attemptId);
        const before = f.ledger.history(f.attemptId);
        f.capture("BEFORE_RESTART_TERMINAL_UNKNOWN");
        f.database.close();
        reopened = new DashboardDatabase(f.database.databasePath);
        const fresh = new CleanupAttemptLedger(reopened);
        fresh.reconcileStartup();
        const row =
          kind === "CONTROLLED"
            ? reopened.db.prepare("SELECT status FROM controlled_mutation_approvals WHERE id=?").get(f.approvalId)
            : reopened.db.prepare("SELECT status FROM workflow_recovery_jobs WHERE id=?").get(f.jobId);
        const after = fresh.history(f.attemptId);
        writeFileSync(
          join(f.root, "AFTER_RESTART_TERMINAL_UNKNOWN.json"),
          JSON.stringify(
            {
              kind,
              history: after,
              compatibility: row,
              integrity: reopened.db.pragma("integrity_check"),
              foreignKeys: reopened.db.pragma("foreign_key_check")
            },
            null,
            2
          ),
          { flag: "wx" }
        );
        expect(after).toEqual(before);
        expect(fresh.unresolved()).toBe(true);
        expect(row).toEqual({ status: "CLEANUP_FAILED" });
        fresh.reconcileStartup();
        expect(fresh.history(f.attemptId)).toEqual(after);
      } finally {
        reopened?.close();
        f.close();
      }
    }
  );
  it.each(["CONTROLLED", "WORKFLOW"] as const)(
    "rolls back the new UNKNOWN and summary together on native SQLite failure: %s",
    (kind) => {
      const f = terminalProjectionFixture(kind);
      try {
        const table = kind === "CONTROLLED" ? "controlled_mutation_approvals" : "workflow_recovery_jobs",
          before = f.ledger.history(f.attemptId),
          status = f.status();
        f.database.db.exec(
          "CREATE TRIGGER fixture_projection_failure BEFORE UPDATE ON " +
            table +
            " BEGIN SELECT RAISE(ABORT,'FIXTURE_PROJECTION_FAILURE'); END"
        );
        expect(() => f.ledger.interruptAndProject(f.attemptId)).toThrow("FIXTURE_PROJECTION_FAILURE");
        expect(f.ledger.history(f.attemptId)).toEqual(before);
        expect(f.status()).toEqual(status);
        expect(f.ledger.unresolved()).toBe(true);
        f.capture("ATOMIC_PROJECTION_FAILURE");
        f.database.db.exec("DROP TRIGGER fixture_projection_failure");
        f.ledger.interruptAndProject(f.attemptId);
        expect(f.ledger.history(f.attemptId).phase).toBe("UNKNOWN");
        expect(f.status()).toMatchObject({ status: "CLEANUP_FAILED" });
        f.capture("ATOMIC_PROJECTION_RETRY");
      } finally {
        f.close();
      }
    }
  );
  it.each(["CONTROLLED", "WORKFLOW"] as const)(
    "retains terminal history on failed legacy projection, then safely reconciles once: %s",
    (kind) => {
      const f = terminalProjectionFixture(kind);
      try {
        f.ledger.interrupt(f.attemptId);
        const history = f.ledger.history(f.attemptId),
          prior = f.status(),
          fresh = new CleanupAttemptLedger(f.database),
          table = kind === "CONTROLLED" ? "controlled_mutation_approvals" : "workflow_recovery_jobs";
        f.database.db.exec(
          "CREATE TRIGGER fixture_projection_failure BEFORE UPDATE ON " +
            table +
            " BEGIN SELECT RAISE(ABORT,'FIXTURE_PROJECTION_FAILURE'); END"
        );
        expect(() => fresh.reconcileStartup()).toThrow("FIXTURE_PROJECTION_FAILURE");
        expect(fresh.history(f.attemptId)).toEqual(history);
        expect(f.status()).toEqual(prior);
        f.capture("LEGACY_PROJECTION_FAILURE");
        f.database.db.exec("DROP TRIGGER fixture_projection_failure");
        fresh.reconcileStartup();
        const projected = f.status();
        expect(projected).toMatchObject({ status: "CLEANUP_FAILED" });
        fresh.reconcileStartup();
        expect(f.status()).toEqual(projected);
        expect(fresh.history(f.attemptId)).toEqual(history);
      } finally {
        f.close();
      }
    }
  );
  it.each(["CONTROLLED", "WORKFLOW"] as const)("refuses to adopt a mismatched compatibility binding: %s", (kind) => {
    const f = terminalProjectionFixture(kind);
    try {
      f.ledger.interrupt(f.attemptId);
      const table = kind === "CONTROLLED" ? "controlled_mutation_approvals" : "workflow_recovery_jobs",
        key = kind === "CONTROLLED" ? "recovery_job_id" : "id";
      f.database.db
        .prepare("UPDATE " + table + " SET case_id='other-owned-fixture-case' WHERE " + key + "=?")
        .run(f.jobId);
      const history = f.ledger.history(f.attemptId),
        status = f.status(),
        fresh = new CleanupAttemptLedger(f.database);
      expect(() => fresh.reconcileStartup()).toThrow("COMPATIBILITY_BINDING_INVALID");
      expect(fresh.history(f.attemptId)).toEqual(history);
      expect(f.status()).toEqual(status);
      expect(fresh.unresolved()).toBe(true);
      f.capture("BINDING_REFUSAL");
    } finally {
      f.close();
    }
  });
  it.each(["CONTROLLED", "WORKFLOW"] as const)(
    "does not overwrite a non-active historical compatibility outcome: %s",
    (kind) => {
      const f = terminalProjectionFixture(kind);
      try {
        f.ledger.interrupt(f.attemptId);
        const table = kind === "CONTROLLED" ? "controlled_mutation_approvals" : "workflow_recovery_jobs",
          key = kind === "CONTROLLED" ? "recovery_job_id" : "id",
          status = kind === "CONTROLLED" ? "COMPLETED" : "ROLLBACK_VERIFIED";
        f.database.db.prepare("UPDATE " + table + " SET status=? WHERE " + key + "=?").run(status, f.jobId);
        const history = f.ledger.history(f.attemptId),
          prior = f.status(),
          fresh = new CleanupAttemptLedger(f.database);
        fresh.reconcileStartup();
        expect(f.status()).toEqual(prior);
        expect(fresh.history(f.attemptId)).toEqual(history);
        expect(fresh.unresolved()).toBe(true);
        f.capture("RESOLVED_SUMMARY_PRESERVED_WITH_UNKNOWN");
      } finally {
        f.close();
      }
    }
  );
  it.each(["CONTROLLED", "WORKFLOW"] as const)(
    "projects NOT_EXECUTED without asserting restoration or reusable authority: %s",
    (kind) => {
      const f = terminalProjectionFixture(kind, false);
      try {
        f.ledger.interruptAndProject(f.attemptId);
        const before = f.ledger.history(f.attemptId);
        expect(before.phase).toBe("NOT_EXECUTED");
        expect(f.status()).toMatchObject({ status: "CLEANUP_FAILED" });
        new CleanupAttemptLedger(f.database).reconcileStartup();
        expect(f.ledger.history(f.attemptId)).toEqual(before);
        f.capture("NOT_EXECUTED_NOT_RESTORATION");
      } finally {
        f.close();
      }
    }
  );
  it("keeps immutable UNKNOWN visible over a contradictory legacy verified label without leaking stored text", async () => {
    const f = terminalProjectionFixture("WORKFLOW");
    try {
      f.ledger.interrupt(f.attemptId);
      f.database.db
        .prepare(
          "UPDATE workflow_recovery_jobs SET status='ROLLBACK_VERIFIED',safe_summary='RAW_SUMMARY_SECRET' WHERE id=?"
        )
        .run(f.jobId);
      const before = f.ledger.history(f.attemptId),
        result = await f.service.workflowInventory(f.scope.organizationId);
      const job = result.jobs.find((j) => j.id === f.jobId)!;
      expect(job.safe_summary).toContain("UNKNOWN");
      expect(job.safe_summary).not.toContain("restoration verified");
      expect(JSON.stringify(result)).not.toContain("RAW_SUMMARY_SECRET");
      expect(f.ledger.history(f.attemptId)).toEqual(before);
      expect((await f.service.workflowInventory(f.other)).jobs).toEqual([]);
      f.capture("WORKFLOW_UNKNOWN_READER");
    } finally {
      f.close();
    }
  });
  it("withholds a verified reader claim when the immutable workflow binding does not match", async () => {
    const f = terminalProjectionFixture("WORKFLOW");
    try {
      f.ledger.interrupt(f.attemptId);
      f.database.db
        .prepare(
          "UPDATE workflow_recovery_jobs SET status='ROLLBACK_VERIFIED',case_id='mismatched-fixture-case' WHERE id=?"
        )
        .run(f.jobId);
      const result = await f.service.workflowInventory(f.scope.organizationId);
      expect(result.jobs.find((j) => j.id === f.jobId)!.safe_summary).toContain("UNKNOWN");
      f.capture("WORKFLOW_READER_BINDING_REFUSAL");
    } finally {
      f.close();
    }
  });
  it("reports no execution without claiming restoration or exposing stored summaries", async () => {
    const f = terminalProjectionFixture("WORKFLOW", false);
    try {
      f.ledger.interruptAndProject(f.attemptId);
      f.database.db
        .prepare("UPDATE workflow_recovery_jobs SET safe_summary='RAW_SUMMARY_SECRET' WHERE id=?")
        .run(f.jobId);
      const result = await f.service.workflowInventory(f.scope.organizationId);
      expect(result.jobs.find((j) => j.id === f.jobId)!.safe_summary).toContain("No recovery command");
      expect(JSON.stringify(result)).not.toContain("RAW_SUMMARY_SECRET");
      f.capture("WORKFLOW_READER_NOT_EXECUTED");
    } finally {
      f.close();
    }
  });
});
