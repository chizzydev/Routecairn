import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { afterEach, describe, it, expect } from "vitest";
import { cleanupAttemptFixture } from "../helpers/cleanup-attempt-fixture.js";
import { workflowRecoveryFixture, closeRecoveryFixtures } from "../helpers/workflow-recovery-fixture.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { CleanupAttemptLedger } from "../../src/dashboard/recovery/CleanupAttemptLedger.js";
import { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
afterEach(closeRecoveryFixtures);
describe.skipIf(process.platform !== "win32")("real service crash between UNKNOWN and compatibility projection", () => {
  it.each(["CONTROLLED", "WORKFLOW"] as const)("reconciles the native %s catch path without replay", async (family) => {
    const f = await cleanupAttemptFixture();
    let child: ChildProcess | undefined;
    try {
      let observedRequests = f.requests;
      let input: unknown = f.input;
      if (family === "WORKFLOW") {
        const saved = process.env.ROUTECAIRN_MUTATION_DIR;
        process.env.ROUTECAIRN_MUTATION_DIR = join(f.root, "wf");
        let w;
        try {
          w = await workflowRecoveryFixture("authenticationLifecycle", {
            authProfile: authProfileSchema.parse({
              principalId: "terminal-owner",
              headers: { authorization: "Bearer old" }
            }),
            requiredAuthorization: "Bearer fixture-fresh"
          });
        } finally {
          if (saved === undefined) delete process.env.ROUTECAIRN_MUTATION_DIR;
          else process.env.ROUTECAIRN_MUTATION_DIR = saved;
        }
        observedRequests = w.received;
        const targetId = f.targets.create({
            displayName: "Owned workflow crash fixture",
            baseOrigin: w.origin,
            tags: [],
            classification: "LOCAL",
            authorizationType: "OWNED",
            authorizationSummary: "Owned loopback cleanup only",
            approvedScope: w.scope,
            productionEnabled: false
          }),
          profileId = f.vault.create({
            name: "Fresh workflow",
            safeAlias: "terminal-owner",
            targetId,
            safeIdentitySummary: { principalId: "terminal-owner" },
            secret: { authorizationHeader: "Bearer fixture-fresh" }
          });
        input = {
          requestId: randomUUID(),
          caseId: w.checkpoint.caseId,
          checkpointDigest: w.checkpoint.digest,
          targetId,
          credentialProfileId: profileId,
          confirmation: "I_AUTHORIZE_STORED_CLEANUP_ONLY"
        };
      }
      writeFileSync(join(f.root, "TERMINAL_CONTROLLER_INPUT.json"), JSON.stringify(input), { flag: "wx" });
      child = spawn(
        process.execPath,
        ["--import", "tsx", resolve("tests/helpers/cleanup-terminal-crash-controller.ts"), f.root, family],
        {
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
          env: {
            ...process.env,
            ROUTECAIRN_MUTATION_DIR: family === "WORKFLOW" ? join(f.root, "wf") : f.paths.mutationJournalDir,
            TSX_DISABLE_CACHE: "1",
            NODE_DISABLE_COMPILE_CACHE: "1"
          }
        }
      );
      let stdout = "",
        stderr = "";
      child.stdout!.on("data", (b) => {
        stdout += b;
        writeFileSync(join(f.root, "TERMINAL_STDOUT.txt"), stdout);
      });
      child.stderr!.on("data", (b) => {
        stderr += b;
        writeFileSync(join(f.root, "TERMINAL_STDERR.txt"), stderr);
      });
      const closed = new Promise<void>((r) => child!.once("close", () => r()));
      await expect
        .poll(() => existsSync(join(f.root, "TERMINAL_CONTROLLER_READY.json")), { timeout: 10000 })
        .toBe(true);
      await expect
        .poll(() => existsSync(join(f.root, "TERMINAL_INTERRUPT_BOUNDARY.json")), { timeout: 15000 })
        .toBe(true);
      const recorded = JSON.parse(readFileSync(join(f.root, "TERMINAL_INTERRUPT_BOUNDARY.json"), "utf8")),
        id = recorded.history.attempt.id,
        ledger = CleanupAttemptLedger.for(f.database),
        before = ledger.history(id);
      writeFileSync(
        join(f.root, "PARENT_NATIVE_SQLITE_BEFORE_KILL.json"),
        JSON.stringify({ visibleHistory: before, controllerReported: recorded }, null, 2),
        { flag: "wx" }
      );
      child.kill("SIGKILL");
      await closed;
      ledger.reconcileStartup();
      const after = ledger.history(id),
        compatibility =
          family === "CONTROLLED"
            ? f.database.db
                .prepare("SELECT status FROM controlled_mutation_approvals WHERE recovery_job_id=?")
                .get(after.attempt.job_id)
            : f.database.db.prepare("SELECT status FROM workflow_recovery_jobs WHERE id=?").get(after.attempt.job_id);
      writeFileSync(
        join(f.root, "RESTART_COMPATIBILITY_RECEIPT.json"),
        JSON.stringify(
          {
            family,
            before,
            after,
            compatibility,
            child: { pid: child.pid, exitCode: child.exitCode, signal: child.signalCode },
            requests: observedRequests,
            integrity: f.database.db.pragma("integrity_check"),
            foreignKeys: f.database.db.pragma("foreign_key_check")
          },
          null,
          2
        ),
        { flag: "wx" }
      );
      expect(after.phase).toBe("UNKNOWN");
      expect(compatibility).toEqual({ status: "CLEANUP_FAILED" });
      if (before.phase === "UNKNOWN") expect(after).toEqual(before);
      expect(recorded.insideTransaction).toBe(true);
      expect(before.phase).toBe("DISPATCH_ARMED");
      expect(observedRequests).toEqual([]);
      const manager = new ScanWorkerManager(f.database, f.paths, f.vault);
      expect(manager.diagnostics().dispatchState).toBe("QUARANTINED");
      expect(() => manager.releaseFleet()).toThrow();
      await manager.shutdown();
      const head = ledger.history(id);
      ledger.reconcileStartup();
      expect(ledger.history(id)).toEqual(head);
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
