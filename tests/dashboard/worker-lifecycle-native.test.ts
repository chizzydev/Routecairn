import { existsSync, writeFileSync, readdirSync, readFileSync } from "node:fs";
import { fork, type ChildProcess } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { windowsProcessBirth } from "../../src/dashboard/worker/WindowsProcessIdentity.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { describe, it, expect } from "vitest";
import { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";
import { workerRestorationGraceMs } from "../../src/core/engine/CleanupExecution.js";
import { workerFixture } from "../helpers/worker-lifecycle-fixture.js";

describe.skipIf(process.platform !== "win32")("real native Windows scan-worker lifecycle", () => {
  it("quarantines an actual custodian-process failure and retains an UNKNOWN outcome", async () => {
    const f = await workerFixture(true); let injected = false;
    try {
      const id = await f.execution.enqueue(f.request); await f.seen(); const child = f.child(id)!;
      const custody = (f.workers as unknown as { custody: Map<ChildProcess, { job: { helper: ChildProcess } }> }).custody.get(child)!;
      custody.job.helper.kill("SIGKILL"); injected = true; f.release();
      await expect.poll(() => f.status(id), { timeout: 15000 }).toBe("FAILED");
      await expect(f.execution.shutdown()).rejects.toThrow("WORKER_RETENTION_UNKNOWN");
      expect(f.workers.diagnostics()).toMatchObject({ dispatchState: "QUARANTINED" });
      expect(() => f.workers.releaseFleet()).toThrow("WORKER_CUSTODY_REVIEW_REQUIRED");
      expect(f.database.db.prepare("SELECT state FROM worker_resources WHERE job_id = ?").get(id)).toEqual({ state: "UNKNOWN_RETAINED" });
      f.capture("EXPECTED_CUSTODY_LOSS");
    } finally { if (injected) await expect(f.close()).rejects.toThrow("WORKER_RETENTION_UNKNOWN"); else await f.close(); }
  });
  it("preserves shutdown evidence after disconnecting the actual worker IPC channel", async () => {
    const f = await workerFixture(true);
    try {
      const id = await f.execution.enqueue(f.request); await f.seen(); const child = f.child(id)!;
      child.disconnect(); f.release();
      await expect.poll(() => f.status(id), { timeout: 15000 }).toBe("INTERRUPTED"); f.capture("IPC_ROOT_TERMINAL"); await f.execution.shutdown();
      const row = f.database.db.prepare("SELECT resource_receipt_json FROM worker_resources WHERE job_id = ?").get(id) as { resource_receipt_json: string };
      const temp = join(JSON.parse(row.resource_receipt_json).root, "tmp"), lifecycle = readdirSync(temp).filter(n => /^lifecycle-[a-f0-9-]{36}\.json$/.test(n)).map(n => JSON.parse(readFileSync(join(temp, n), "utf8")));
      writeFileSync(join(f.resource.root, "IPC_LOSS_RECEIPT.json"), JSON.stringify({ id, lifecycle }, null, 2), { flag: "wx" });
      expect(lifecycle.map(r => (r.body ?? r).event)).toEqual(expect.arrayContaining(["SHUTDOWN_REQUESTED", "PROCESS_EXIT_READY", "PROCESS_EXIT"]));
    } finally { f.capture("IPC_BEFORE_TEARDOWN"); await f.close(); }
  });
  it("retains bound evidence without claiming cleanup after an actual controller hard crash", async () => {
    const f = await workerFixture(true);
    const parent = fork(fileURLToPath(new URL("../helpers/worker-parent-crash-fixture.ts", import.meta.url)), [], { execArgv: ["--import", "tsx"], env: { ...process.env, ROUTECAIRN_WORKER_LAB: process.env.ROUTECAIRN_WORKER_LAB ?? f.resource.root, ROUTECAIRN_PARENT_CRASH_TARGET: f.request.target }, stdio: ["ignore", "ignore", "ignore", "ipc"] });
    const closed = new Promise<void>(r => parent.once("close", () => r()));
    try {
      const ready = new Promise<{ root: string; scanId: string; identity: { pid: number; birth: string } }>((resolve, reject) => { parent.on("message", (raw: unknown) => { const value = raw as { type?: string; root: string; scanId: string; identity: { pid: number; birth: string } }; if (value.type === "OWNED_ROOT_READY") resolve(value); }); parent.once("error", reject); parent.once("exit", () => reject(Error("Controller exited before readiness"))); });
      const observations = f.resource.directory("observation");
      const binding = await ready; await f.seen();
      expect(await windowsProcessBirth(binding.identity.pid, observations)).toBe(binding.identity.birth);
      parent.kill("SIGKILL"); await closed; f.release();
      await expect.poll(() => windowsProcessBirth(binding.identity.pid, observations), { timeout: 15000, interval: 200 }).not.toBe(binding.identity.birth);
      const paths = resolveDashboardPaths(binding.root), db = new DashboardDatabase(paths.databasePath), recovery = new ScanWorkerManager(db, paths);
      try {
        // A real expired lease is not invented by changing the clock. Fresh
        // orphan leases remain unreleased until their original recovery window.
        expect(await recovery.recoverExpiredLeases()).toEqual([]);
        const receipt = { kind: "ACTUAL_CONTROLLER_SIGKILL_REAL_WORKER_IPC_LOSS", binding, workerExited: true, leases: db.db.prepare("SELECT * FROM scan_job_leases").all(), resources: db.db.prepare("SELECT * FROM worker_resources").all(), integrity: db.db.pragma("integrity_check"), reportRetained: existsSync(join(paths.reportsDir, binding.scanId, "report.json")), noReplay: f.requests() <= 4 };
        writeFileSync(join(f.resource.root, "PARENT_CRASH_RECEIPT.json"), JSON.stringify(receipt, null, 2), { flag: "wx" });
        const ledger = receipt.resources[0] as { resource_receipt_json: string };
        const temp = join(JSON.parse(ledger.resource_receipt_json).root, "tmp");
        const lifecycle = readdirSync(temp).filter(name => /^lifecycle-[a-f0-9-]{36}\.json$/.test(name)).map(name => JSON.parse(readFileSync(join(temp, name), "utf8")));
        expect(lifecycle.map(r => (r.body ?? r).event)).toEqual(expect.arrayContaining(["INITIALIZED", "EXECUTION_REQUESTED"]));
        expect(db.db.prepare("SELECT status FROM scans WHERE id = ?").get(binding.scanId)).toEqual({ status: "RUNNING" });
        expect(receipt.leases).toEqual(expect.arrayContaining([expect.objectContaining({ released_at: null })]));
        expect(receipt.noReplay).toBe(true);
      } finally { await recovery.shutdown(); db.close(); }
    } finally { if (parent.exitCode === null && parent.signalCode === null) parent.kill("SIGKILL"); await closed; await f.close(); }
  });
  it("cancels a forked worker before readiness without any target transmission", async () => {
    const f = await workerFixture();
    try {
      const id = await f.execution.enqueue(f.request);
      await expect.poll(() => Boolean(f.child(id)), { timeout: 5000 }).toBe(true);
      f.execution.cancel(id);
      await expect.poll(() => f.status(id), { timeout: 15000 }).toBe("CANCELLED"); await f.execution.shutdown();
      expect(f.requests()).toBe(0);
    } finally { await f.close(); }
  });
  it("binds the immutable plan, completes and drains the real worker and its kernel job", async () => {
    const f = await workerFixture();
    try {
      const id = await f.execution.enqueue(f.request);
      await expect.poll(() => f.status(id), { timeout: 20000 }).toBe("COMPLETED");
      await f.execution.shutdown();
      const row = f.database.db.prepare("SELECT state, evidence_json, resource_receipt_json FROM worker_resources WHERE job_id = ?").get(id) as { state: string; evidence_json: string; resource_receipt_json: string };
      expect(row.state).toBe("RETAINED"); expect(JSON.parse(row.evidence_json)).toMatchObject({ custody: { rootClosed: true, issues: [], job: { drained: true, completeDescendantContainment: true } } });
      expect(existsSync(JSON.parse(row.resource_receipt_json).root)).toBe(true);
      expect(f.database.db.prepare("SELECT COUNT(*) AS n FROM scan_job_leases WHERE released_at IS NULL").get()).toEqual({ n: 0 });
      const plan = f.database.db.prepare("SELECT plan_binding, worker_verified_binding FROM scan_executable_plans WHERE scan_id = ?").get(id) as { plan_binding: string; worker_verified_binding: string };
      expect(plan.worker_verified_binding).toBe(plan.plan_binding); expect(f.requests()).toBeGreaterThan(0); expect(f.requests()).toBeLessThanOrEqual(4);
    } finally { await f.close(); }
  });
  it("cooperatively cancels with original restoration grace and retains partial evidence", async () => {
    const f = await workerFixture(true);
    try {
      const id = await f.execution.enqueue(f.request); await f.seen(); f.execution.cancel(id); f.release();
      await expect.poll(() => f.status(id), { timeout: 15000 }).toBe("CANCELLED"); await f.execution.shutdown();
      expect(workerRestorationGraceMs).toBe(135000);
      expect(f.database.db.prepare("SELECT state FROM worker_resources WHERE job_id = ?").get(id)).toEqual({ state: "RETAINED" });
      expect(existsSync(join(f.paths.reportsDir, id, "report.json"))).toBe(true);
    } finally { await f.close(); }
  });
  it("shutdown waits for native process close and retains the cancelled job", async () => {
    const f = await workerFixture(true);
    try {
      const id = await f.execution.enqueue(f.request); await f.seen(); const child = f.child(id)!;
      const stopping = f.execution.shutdown(); f.release(); await stopping;
      expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
      expect(["CANCELLED", "INTERRUPTED"]).toContain(f.status(id));
      expect(f.database.db.prepare("SELECT state FROM worker_resources WHERE job_id = ?").get(id)).toEqual({ state: "RETAINED" });
    } finally { await f.close(); }
  });
  it("retains an abruptly crashed real worker and never replays its requests", async () => {
    const f = await workerFixture(true);
    try {
      const id = await f.execution.enqueue(f.request); await f.seen(); const child = f.child(id)!; child.kill("SIGKILL"); f.release();
      await expect.poll(() => f.status(id), { timeout: 15000 }).toBe("INTERRUPTED"); await f.execution.shutdown();
      const count = f.requests(); const restarted = new ScanWorkerManager(f.database, f.paths);
      expect(await restarted.recoverExpiredLeases()).toEqual([]); await restarted.shutdown(); expect(f.requests()).toBe(count);
      expect(f.database.db.prepare("SELECT state, failure_category FROM scan_workers WHERE id = (SELECT worker_id FROM worker_resources WHERE job_id = ?)").get(id)).toMatchObject({ state: "EXITED", failure_category: "PROCESS_CRASH" });
      expect(f.database.db.prepare("SELECT state FROM worker_resources WHERE job_id = ?").get(id)).toEqual({ state: "RETAINED" });
    } finally { await f.close(); }
  });
  it("rejects queued scope changes before any second-job transmission", async () => {
    const f = await workerFixture(true);
    try {
      const first = await f.execution.enqueue(f.request); await f.seen(); const second = await f.execution.enqueue(f.request);
      writeFileSync(f.scopeFile, JSON.stringify({ ...f.scope, program: "CHANGED_AFTER_REVIEW" })); f.release();
      await expect.poll(() => f.status(first), { timeout: 15000 }).toBe("COMPLETED");
      await expect.poll(() => f.status(second), { timeout: 15000 }).toBe("FAILED");
      expect(f.database.db.prepare("SELECT worker_verified_at FROM scan_executable_plans WHERE scan_id = ?").get(second)).toEqual({ worker_verified_at: null });
      expect(f.requests()).toBeLessThanOrEqual(4);
      expect(f.database.db.prepare("SELECT error_summary FROM scans WHERE id = ?").get(second)).toMatchObject({ error_summary: expect.stringContaining("EXECUTABLE_PLAN_SOURCE_CHANGED") });
    } finally { await f.close(); }
  });
  it("contains a post-fork database failure without leaking the owned process or transmitting", async () => {
    const f = await workerFixture();
    try {
      f.database.db.exec("CREATE TRIGGER fixture_worker_insert_failure BEFORE INSERT ON scan_workers BEGIN SELECT RAISE(ABORT, 'SYNTHETIC_BOOTSTRAP_FAILURE'); END;");
      const id = await f.execution.enqueue(f.request);
      await expect.poll(() => f.status(id), { timeout: 15000 }).toBe("FAILED"); await f.execution.shutdown();
      expect(f.requests()).toBe(0); expect(f.database.db.prepare("SELECT COUNT(*) AS n FROM scan_job_leases").get()).toEqual({ n: 0 });
      expect(f.database.db.prepare("SELECT state FROM worker_resources WHERE job_id = ?").get(id)).toEqual({ state: "RETAINED" });
    } finally { await f.close(); }
  });
});
