import type { ChildProcess } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
import { describe, it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { CleanupAttemptLedger } from "../../src/dashboard/recovery/CleanupAttemptLedger.js";
import { cleanupAttemptFixture } from "../helpers/cleanup-attempt-fixture.js";
describe("native cleanup attempt correctness and uncertainty", () => {
  it("persists one immutable authorization and ordered request gates through independent restoration proof", async () => {
    const f = await cleanupAttemptFixture();
    try {
      const s = f.service(),
        [a, b] = await Promise.all([
          s.startRecovery(f.input),
          s.startRecovery({ ...f.input, recoveryJobId: randomUUID() })
        ]);
      expect(a.attempt.id).toBe(b.attempt.id);
      await a.completion;
      const h = CleanupAttemptLedger.for(f.database).history(a.attempt.id);
      expect(h.phase).toBe("RESTORATION_VERIFIED");
      expect(h.events.map((e) => e.kind)).toEqual([
        "REQUESTED",
        "AUTHORIZED",
        "WORKER_PENDING",
        "WORKER_ACTIVATED",
        "DISPATCH_ARMED",
        "DISPATCH_ATTEMPTED",
        "DISPATCH_ATTEMPTED",
        "DISPATCH_ATTEMPTED",
        "RESULT_RECEIVED",
        "RESTORATION_VERIFIED"
      ]);
      expect(f.requests).toEqual(["GET /identity", "POST /rollback", "GET /state"]);
      const again = await f.service().startRecovery({ ...f.input, recoveryJobId: randomUUID() });
      expect(again.replayed).toBe(true);
      expect(f.requests).toHaveLength(3);
      await expect(
        s.startRecovery({ ...f.input, requestId: randomUUID(), recoveryJobId: randomUUID() })
      ).rejects.toThrow("AUTHORITY_ALREADY_CONSUMED");
      expect(() => f.database.db.prepare("UPDATE cleanup_attempts SET requested_by='changed'").run()).toThrow(
        "IMMUTABLE"
      );
      expect(() => f.database.db.prepare("DELETE FROM cleanup_attempt_events").run()).toThrow("IMMUTABLE");
      f.capture("VERIFIED_AND_IDEMPOTENT");
    } finally {
      await f.close();
    }
  });
  it("refuses a request before network transmission when durable gate recording fails", async () => {
    const f = await cleanupAttemptFixture();
    try {
      f.database.db.exec(
        "CREATE TRIGGER fixture_gate_failure BEFORE INSERT ON cleanup_attempt_events WHEN NEW.kind='DISPATCH_ATTEMPTED' BEGIN SELECT RAISE(ABORT,'FIXTURE_GATE_WRITE_FAILURE'); END"
      );
      const a = await f.service().startRecovery(f.input);
      await expect(a.completion).rejects.toThrow();
      expect(f.requests).toEqual([]);
      expect(CleanupAttemptLedger.for(f.database).history(a.attempt.id).phase).toBe("UNKNOWN");
      expect(CleanupAttemptLedger.for(f.database).unresolved()).toBe(true);
      f.capture("FAILED_GATE_NO_TRANSMISSION");
    } finally {
      await f.close();
    }
  });
  it("proves no dispatch after native cancellation before activation", async () => {
    const f = await cleanupAttemptFixture();
    let release!: () => void;
    try {
      const s = f.service(),
        manager = (
          s as unknown as { workers: import("../../src/dashboard/worker/ScanWorkerManager.js").ScanWorkerManager }
        ).workers,
        bound = manager as unknown as { bindProcess: (...args: unknown[]) => Promise<void> },
        original = bound.bindProcess.bind(manager);
      let entered!: () => void;
      const ready = new Promise<void>((r) => (entered = r)),
        gate = new Promise<void>((r) => (release = r));
      bound.bindProcess = async (...args) => {
        await original(...args);
        entered();
        await gate;
      };
      const accepted = await s.startRecovery(f.input);
      await ready;
      const stopped = manager.shutdown();
      release();
      await expect(accepted.completion).rejects.toThrow();
      await stopped;
      expect(f.requests).toEqual([]);
      expect(CleanupAttemptLedger.for(f.database).history(accepted.attempt.id).phase).toBe("NOT_EXECUTED");
      f.capture("CANCELLED_BEFORE_ACTIVATION");
    } finally {
      release?.();
      await f.close();
    }
  });

  it("rejects a worker success whose original journal prefix was altered", async () => {
    const f = await cleanupAttemptFixture();
    try {
      const s = f.service(),
        manager = (s as unknown as { workers: ScanWorkerManager }).workers,
        original = manager.runRecovery.bind(manager);
      manager.runRecovery = async (...args) => {
        const result = await original(...args);
        await manager.drainCompletedWorkers();
        const path = join(f.paths.mutationJournalDir, "mutation-journal.json"),
          bytes = readFileSync(path);
        writeFileSync(join(f.root, "ORIGINAL_JOURNAL_BEFORE_FAULT.json"), bytes, { flag: "wx" });
        const entries = JSON.parse(bytes.toString());
        entries[0].note = "SYNTHETIC_PREFIX_MUTATION_FAULT";
        writeFileSync(path, JSON.stringify(entries));
        return result;
      };
      const a = await s.startRecovery(f.input);
      await expect(a.completion).rejects.toThrow("RESTORATION_PROOF");
      expect(CleanupAttemptLedger.for(f.database).history(a.attempt.id).phase).toBe("UNKNOWN");
      expect(manager.diagnostics().dispatchState).toBe("QUARANTINED");
      f.capture("ALTERED_PREFIX_REFUSED");
    } finally {
      await f.close();
    }
  });
  it("holds dispatch when both final outcome and uncertainty writes fail", async () => {
    const f = await cleanupAttemptFixture();
    try {
      f.database.db.exec(
        "CREATE TRIGGER fixture_final_write_failure BEFORE INSERT ON cleanup_attempt_events WHEN NEW.kind IN ('RESTORATION_VERIFIED','UNKNOWN') BEGIN SELECT RAISE(ABORT,'FIXTURE_FINAL_WRITE_FAILURE'); END"
      );
      const a = await f.service().startRecovery(f.input);
      await expect(a.completion).rejects.toThrow();
      const ledger = CleanupAttemptLedger.for(f.database);
      expect(ledger.history(a.attempt.id).phase).toBe("RESULT_RECEIVED");
      expect(ledger.unresolved()).toBe(true);
      const manager = new ScanWorkerManager(f.database, f.paths, f.vault);
      expect(manager.diagnostics().dispatchState).toBe("QUARANTINED");
      expect(() => manager.releaseFleet()).toThrow("CLEANUP_ATTEMPT_REVIEW_REQUIRED");
      await manager.shutdown();
      f.capture("FINAL_WRITE_FAILURE_HOLD");
    } finally {
      await f.close();
    }
  });
  it("waits for in-flight preflight on shutdown and never admits a late attempt", async () => {
    const f = await cleanupAttemptFixture();
    try {
      const s = f.service(),
        started = s.startRecovery(f.input),
        stopped = s.shutdown();
      await expect(started).rejects.toThrow("SERVICE_STOPPING");
      await stopped;
      expect(f.requests).toEqual([]);
      expect(f.database.db.prepare("SELECT COUNT(*) n FROM cleanup_attempts").get()).toEqual({ n: 0 });
      f.capture("SHUTDOWN_PREFLIGHT_REFUSAL");
    } finally {
      await f.close();
    }
  });
  it("rechecks the target revision after native activation and before granting dispatch", async () => {
    const f = await cleanupAttemptFixture();
    let release!: () => void;
    try {
      const s = f.service(),
        manager = (s as unknown as { workers: ScanWorkerManager }).workers,
        bound = manager as unknown as { bindProcess: (...args: unknown[]) => Promise<void> },
        original = bound.bindProcess.bind(manager);
      let entered!: () => void;
      const ready = new Promise<void>((r) => (entered = r)),
        gate = new Promise<void>((r) => (release = r));
      bound.bindProcess = async (...args) => {
        await original(...args);
        entered();
        await gate;
      };
      const accepted = await s.startRecovery(f.input);
      await ready;
      f.database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(f.input.targetId);
      release();
      await expect(accepted.completion).rejects.toThrow();
      expect(f.requests).toEqual([]);
      expect(CleanupAttemptLedger.for(f.database).history(accepted.attempt.id).phase).toBe("NOT_EXECUTED");
      f.capture("LATE_TARGET_REVISION_REFUSED");
    } finally {
      release?.();
      await f.close();
    }
  });
  it("retains UNKNOWN and refuses transmission after actual native custodian loss", async () => {
    const f = await cleanupAttemptFixture();
    try {
      const s = f.service(),
        manager = (s as unknown as { workers: ScanWorkerManager }).workers,
        ledger = CleanupAttemptLedger.for(f.database);
      ledger.gate = () => {
        const child = (manager as unknown as { recoveries: Map<string, { child: ChildProcess }> }).recoveries.get(
            f.input.recoveryJobId
          )!.child,
          helper = (
            manager as unknown as { custody: Map<ChildProcess, { job: { helper: ChildProcess } }> }
          ).custody.get(child)!.job.helper;
        helper.kill("SIGKILL");
        throw Error("FIXTURE_NATIVE_CUSTODIAN_LOST");
      };
      const a = await s.startRecovery(f.input);
      await expect(a.completion).rejects.toThrow();
      expect(f.requests).toEqual([]);
      expect(ledger.history(a.attempt.id).phase).toBe("UNKNOWN");
      expect(
        f.database.db.prepare("SELECT state FROM worker_resources WHERE job_id=?").get(f.input.recoveryJobId)
      ).toEqual({ state: "UNKNOWN_RETAINED" });
      expect(manager.diagnostics().dispatchState).toBe("QUARANTINED");
      expect(() => manager.releaseFleet()).toThrow();
      f.capture("RECOVERY_NATIVE_CUSTODIAN_LOSS");
    } finally {
      await f.close();
    }
  });
});
