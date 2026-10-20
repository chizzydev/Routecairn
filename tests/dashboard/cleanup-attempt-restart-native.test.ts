import { spawn, type ChildProcess } from "node:child_process";
import { join, resolve } from "node:path";
import { writeFileSync, existsSync } from "node:fs";
import { describe, it, expect } from "vitest";
import { cleanupAttemptFixture } from "../helpers/cleanup-attempt-fixture.js";
import { CleanupAttemptLedger } from "../../src/dashboard/recovery/CleanupAttemptLedger.js";
import { windowsProcessBirth } from "../../src/dashboard/worker/WindowsProcessIdentity.js";
import { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
describe.skipIf(process.platform !== "win32")("real controller crash and restart reconciliation", () => {
  it.each([
    "AUTHORIZED",
    "WORKER_ACTIVATED",
    "DISPATCH_ATTEMPTED",
    "AFTER_TARGET_MUTATION",
    "RESULT_RECEIVED",
    "COMMITTED"
  ])("retains the correct uncertainty after %s", async (phase) => {
    const f = await cleanupAttemptFixture({ holdRollbackResponse: phase === "AFTER_TARGET_MUTATION" });
    let child: ChildProcess | undefined;
    try {
      writeFileSync(join(f.root, "CONTROLLER_INPUT.json"), JSON.stringify(f.input), { flag: "wx" });
      writeFileSync(
        join(f.root, "CONTROLLER_ENVIRONMENT.json"),
        JSON.stringify({
          tsxCache: "DISABLED_AS_IN_ORIGINAL_WINDOWS_RUNNERS",
          temporaryDirectory: process.env.TEMP,
          deadlineMs: 15000,
          vitestDeadlineMs: 30000,
          noSourceChecksRemoved: true
        }),
        { flag: "wx" }
      );
      child = spawn(
        process.execPath,
        ["--import", "tsx", resolve("tests/helpers/cleanup-attempt-controller.ts"), f.root, phase],
        {
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
          env: {
            ...process.env,
            ROUTECAIRN_MUTATION_DIR: f.paths.mutationJournalDir,
            NODE_DISABLE_COMPILE_CACHE: "1",
            TSX_DISABLE_CACHE: "1"
          }
        }
      );
      let stdout = "",
        stderr = "";
      child.stdout!.on("data", (b) => {
        stdout += b;
        writeFileSync(join(f.root, "CONTROLLER_STDOUT.txt"), stdout);
      });
      child.stderr!.on("data", (b) => {
        stderr += b;
        writeFileSync(join(f.root, "CONTROLLER_STDERR.txt"), stderr);
      });
      const closed = new Promise<void>((r) => child!.once("close", () => r()));
      await expect.poll(() => existsSync(join(f.root, "CONTROLLER_READY.json")), { timeout: 10000 }).toBe(true);
      if (phase === "AFTER_TARGET_MUTATION") {
        await expect.poll(() => f.requests.includes("POST /rollback"), { timeout: 15000 }).toBe(true);
        f.capture("TARGET_MUTATED_RESPONSE_WITHHELD_BEFORE_CONTROLLER_CRASH");
      } else await expect.poll(() => existsSync(join(f.root, "CONTROLLER_PHASE.json")), { timeout: 15000 }).toBe(true);
      child.kill("SIGKILL");
      await closed;
      writeFileSync(
        join(f.root, "CONTROLLER_PROCESS_RECEIPT.json"),
        JSON.stringify({
          phase,
          exitCode: child.exitCode,
          signal: child.signalCode,
          stdout,
          stderr,
          liveChildHandleUsed: true
        }),
        { flag: "wx" }
      );
      const pid = f.database.db
        .prepare("SELECT process_identity_json FROM worker_resources WHERE job_id=?")
        .get(f.input.recoveryJobId) as { process_identity_json: string | null } | undefined;
      if (pid?.process_identity_json) {
        const identity = JSON.parse(pid.process_identity_json);
        await expect
          .poll(() => windowsProcessBirth(identity.pid, f.root), { timeout: 10000, interval: 500 })
          .toBeNull();
      }
      const ledger = CleanupAttemptLedger.for(f.database);
      ledger.reconcileStartup();
      const row = f.database.db.prepare("SELECT id FROM cleanup_attempts").get() as { id: string },
        history = ledger.history(row.id);
      expect(history.phase).toBe(
        phase === "COMMITTED" ? "RESTORATION_VERIFIED" : phase === "AUTHORIZED" ? "NOT_EXECUTED" : "UNKNOWN"
      );
      expect(f.requests).toEqual(
        phase === "COMMITTED" || phase === "RESULT_RECEIVED"
          ? ["GET /identity", "POST /rollback", "GET /state"]
          : phase === "AFTER_TARGET_MUTATION"
            ? ["GET /identity", "POST /rollback"]
            : []
      );
      if (phase === "AFTER_TARGET_MUTATION") {
        expect(history.events.some((e) => e.kind === "RESULT_RECEIVED")).toBe(false);
        await expect(f.service().startRecovery({ ...f.input, requestId: crypto.randomUUID() })).rejects.toThrow(
          "AUTHORITY_ALREADY_CONSUMED"
        );
        expect(f.requests).toEqual(["GET /identity", "POST /rollback"]);
      }
      const before = history.events.length;
      ledger.reconcileStartup();
      expect(ledger.history(row.id).events).toHaveLength(before);
      if (phase === "COMMITTED") {
        const resumed = await f.service().startRecovery(f.input);
        expect(resumed.replayed).toBe(true);
        expect(resumed.attempt.id).toBe(row.id);
        expect(f.requests).toHaveLength(3);
      } else if (phase !== "AUTHORIZED") {
        const manager = new ScanWorkerManager(f.database, f.paths, f.vault);
        expect(manager.diagnostics().dispatchState).toBe("QUARANTINED");
        expect(() => manager.releaseFleet()).toThrow();
        await manager.shutdown();
      }
      f.capture("RECONCILED_" + phase);
    } finally {
      if (child && child.exitCode === null && child.signalCode === null) {
        const closed = new Promise<void>((r) => child!.once("close", () => r()));
        child.kill("SIGKILL");
        await closed;
      }
      await f.close();
    }
  });
});
