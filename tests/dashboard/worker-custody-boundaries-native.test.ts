import { spawn, fork, type ChildProcess } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import { describe, it, expect } from "vitest";
import { WorkerProcessCustody } from "../../src/dashboard/worker/WorkerProcessCustody.js";
import { windowsProcessBirth } from "../../src/dashboard/worker/WindowsProcessIdentity.js";
import { createWorkerBootstrap, confirmBootstrapIdentity } from "../../src/dashboard/worker/WorkerBootstrap.js";
import { OwnedTemporaryResource } from "../../src/core/storage/OwnedTemporaryResource.js";
import { workerFixture } from "../helpers/worker-lifecycle-fixture.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanWorkerManager } from "../../src/dashboard/worker/ScanWorkerManager.js";

function lab() { const p = process.env.ROUTECAIRN_WORKER_LAB; if (!p) throw Error("Owned lab required"); const dir = join(p, "boundaries-" + randomUUID()); mkdirSync(dir); return dir; }
function receipt(dir: string, name: string, value: unknown) { writeFileSync(join(dir, name + ".json"), JSON.stringify(value, null, 2), { flag: "wx" }); }

describe.skipIf(process.platform !== "win32")("native custody acknowledgement and registration boundaries", () => {
  it("returns from termination only after a native zero-membership acknowledgement", async () => {
    const dir = lab(), child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { windowsHide: true, stdio: "ignore" });
    const custody = new WorkerProcessCustody(child, dir);
    try {
      await custody.bind((await windowsProcessBirth(child.pid!, dir))!);
      await custody.terminate(); const observed = custody.receipt(); receipt(dir, "TERMINATE_RETURN", observed);
      expect(observed).toMatchObject({ job: { stopped: true, terminationAcknowledged: true, activeProcesses: 0 } });
    } finally { await custody.terminate(); await custody.drain(); receipt(dir, "FINAL", custody.receipt()); }
  });
  it("has no bootstrap-created process before registration and job attachment", async () => {
    const dir = lab(), resource = OwnedTemporaryResource.create(dir, { purpose: "registration-boundary" });
    const entry = join(dir, "runtime.mjs"), trace = join(dir, "PREATTACH_CHILDREN.jsonl"), hook = join(dir, "observe.mjs");
    writeFileSync(entry, "throw Error('RUNTIME_NOT_AUTHORIZED');\n", { flag: "wx" });
    writeFileSync(hook, `import cp from 'node:child_process';import {syncBuiltinESMExports} from 'node:module';import fs from 'node:fs';const original=cp.execFile;cp.execFile=function(...args){const c=original.apply(this,args);fs.appendFileSync(${JSON.stringify(trace)},JSON.stringify({pid:c.pid,root:process.pid,executable:args[0]})+'\\n');return c};syncBuiltinESMExports();`, { flag: "wx" });
    const workerId = randomUUID(), generation = randomUUID();
    const child = fork(createWorkerBootstrap(resource, entry), [], { execArgv: ["--import", pathToFileURL(hook).href], env: { ...process.env, ROUTECAIRN_WORKER_ID: workerId, ROUTECAIRN_WORKER_GENERATION: generation }, ...{ windowsHide: true }, stdio: ["ignore", "ignore", "ignore", "ipc"] });
    const exited = new Promise<void>(r => child.once("exit", () => r()));
    try {
      const ready = await new Promise<unknown>((r, reject) => { child.once("message", r); child.once("error", reject); child.once("exit", () => reject(Error("Bootstrap exited early"))); });
      const children = existsSync(trace) ? readFileSync(trace, "utf8") : ""; receipt(dir, "PRE_REGISTRATION", { ready, children });
      expect(children).toBe("");
    } finally { child.kill("SIGKILL"); await exited; resource.retain("POST_FORK_REGISTRATION_FAILURE_FIXTURE"); }
  });
  it("durably quarantines dispatch immediately on activated custodian loss before root exit", async () => {
    const f = await workerFixture(true); let injected = false;
    try {
      const id = await f.execution.enqueue(f.request); await f.seen(); const child = f.child(id)!;
      const custody = (f.workers as unknown as { custody: Map<ChildProcess, { job: { helper: ChildProcess } }> }).custody.get(child)!;
      custody.job.helper.kill("SIGKILL"); injected = true;
      await new Promise<void>(r => custody.job.helper.once("close", () => r()));
      f.capture("LIVE_ROOT_CUSTODY_LOSS");
      expect(f.workers.diagnostics()).toMatchObject({ dispatchState: "QUARANTINED" });
      expect(f.database.db.prepare("SELECT state FROM worker_resources WHERE job_id = ?").get(id)).toEqual({ state: "UNKNOWN_RETAINED" });
      const reopened = new DashboardDatabase(f.paths.databasePath), fresh = new ScanWorkerManager(reopened, f.paths);
      try {
        expect(fresh.diagnostics()).toMatchObject({ dispatchState: "QUARANTINED" });
        expect(() => fresh.releaseFleet()).toThrow("WORKER_CUSTODY_REVIEW_REQUIRED");
        expect(() => fresh.run(id, f.request, { onPlan() {}, onEvent() {}, onHeartbeat() {} }, {} as never)).toThrow("WORKER_CUSTODY_REVIEW_REQUIRED");
      } finally { await fresh.shutdown(); reopened.close(); }
    } finally { f.release(); if (injected) await expect(f.close()).rejects.toThrow("WORKER_RETENTION_UNKNOWN"); else await f.close(); }
  });
  it.each(["ACKNOWLEDGED", "CUSTODIAN_LOST"])("proves real child/grandchild custody after activation: %s", async outcome => {
    const dir = lab(), resource = OwnedTemporaryResource.create(dir, { purpose: "activated-descendant-custody-loss" });
    const stop = join(dir, "COOPERATIVE_FIXTURE_STOP"), runtime = join(dir, "runtime.mjs"), descendant = join(dir, "descendant.mjs");
    writeFileSync(descendant, `import {fork} from 'node:child_process';import {existsSync} from 'node:fs';
const stop=process.argv[2];if(process.argv[3]==='child'){const g=fork(import.meta.filename,[stop,'grandchild'],{execArgv:[],detached:true,windowsHide:true,stdio:['ignore','ignore','ignore','ipc']});g.on('message',m=>{if(process.connected)process.send({child:process.pid,grandchild:m.grandchild})})}else if(process.connected)process.send({grandchild:process.pid});
setInterval(()=>{if(existsSync(stop))process.exit(0)},25);`, { flag: "wx" });
    writeFileSync(runtime, `import {fork} from 'node:child_process';const c=fork(${JSON.stringify(descendant)},[${JSON.stringify(stop)},'child'],{execArgv:[],detached:true,windowsHide:true,stdio:['ignore','ignore','ignore','ipc']});c.on('message',m=>{if(process.connected)process.send({type:'FIXTURE_DESCENDANTS',...m})});setInterval(()=>{},1000);`, { flag: "wx" });
    const workerId = randomUUID(), generation = randomUUID(), child = fork(createWorkerBootstrap(resource, runtime), [], { execArgv: [], env: { ...process.env, ROUTECAIRN_WORKER_ID: workerId, ROUTECAIRN_WORKER_GENERATION: generation }, ...{ windowsHide: true }, stdio: ["ignore", "ignore", "ignore", "ipc"] });
    const custody = new WorkerProcessCustody(child, resource.directory("tmp"));
    let pids: { child: number; grandchild: number } | undefined;
    try {
      await new Promise<void>((r, reject) => { child.once("message", () => r()); child.once("error", reject); });
      const birth = await confirmBootstrapIdentity(child, workerId, generation, resource.directory("tmp")); await custody.bind(birth);
      const descendants = new Promise<{ child: number; grandchild: number }>(r => child.on("message", raw => { const m = raw as { type?: string; child: number; grandchild: number }; if (m.type === "FIXTURE_DESCENDANTS") r(m); }));
      child.send({ protocolVersion: 2, type: "ACTIVATE_RUNTIME", workerId, workerGeneration: generation }); pids = await descendants;
      const before = { child: await windowsProcessBirth(pids.child, dir), grandchild: await windowsProcessBirth(pids.grandchild, dir) }; expect(before.child).toBeTruthy(); expect(before.grandchild).toBeTruthy();
      const helper = (custody as unknown as { job: { helper: ChildProcess } }).job.helper;
      if (outcome === "CUSTODIAN_LOST") { const closed = new Promise<void>(r => helper.once("close", () => r())); helper.kill("SIGKILL"); await closed; }
      await custody.terminate(); await custody.drain();
      const after = { child: await windowsProcessBirth(pids.child, dir), grandchild: await windowsProcessBirth(pids.grandchild, dir) };
      receipt(dir, "ACTIVATED_DESCENDANTS_OUTCOME", { outcome, pids, before, after, custody: custody.receipt(), coverage: "NATIVE_BOOTSTRAP_AND_SYNTHETIC_RUNTIME_NO_TARGET_REQUESTS" });
      if (outcome === "CUSTODIAN_LOST") { expect(after).toEqual(before); expect(custody.receipt()).toMatchObject({ rootClosed: true, rootOnlyFallback: true, terminationOutcome: "UNKNOWN", job: { completeDescendantContainment: false, terminationAcknowledged: false } }); }
      else { expect(after).toEqual({ child: null, grandchild: null }); expect(custody.receipt()).toMatchObject({ rootClosed: true, rootOnlyFallback: false, terminationOutcome: "ACKNOWLEDGED_ZERO", job: { completeDescendantContainment: true, terminationAcknowledged: true, activeProcesses: 0 } }); }
    } finally {
      writeFileSync(stop, "OWNED_FIXTURE_COOPERATIVE_EXIT\n", { flag: "wx" });
      await custody.terminate(); await custody.drain();
      if (pids) { await expect.poll(() => windowsProcessBirth(pids!.child, dir), { timeout: 5000 }).toBeNull(); await expect.poll(() => windowsProcessBirth(pids!.grandchild, dir), { timeout: 5000 }).toBeNull(); }
      receipt(dir, "COOPERATIVE_DESCENDANT_EXIT", { pids, noPidSignals: true, custody: custody.receipt() }); resource.retain("EXPECTED_DESCENDANT_OUTCOME_FIXTURE");
    }
  });
  it("contains a delayed real registration failure before attachment without starting runtime", async () => {
    const f = await workerFixture();
    try {
      const manager = f.workers as unknown as { recordWorker: (...args: unknown[]) => void };
      manager.recordWorker = () => { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1500); throw Error("FIXTURE_DELAYED_REGISTRATION_FAILURE"); };
      const id = await f.execution.enqueue(f.request); await expect.poll(() => f.status(id), { timeout: 15000 }).toBe("FAILED");
      await f.execution.shutdown(); const evidence = f.capture("DELAYED_REGISTRATION_FAILURE");
      expect(f.requests()).toBe(0); expect(evidence.sqlite.leases).toEqual([]); expect(evidence.sqlite.resources).toEqual([expect.objectContaining({ state: "RETAINED", process_identity_json: null })]);
    } finally { await f.close(); }
  });

  it("awaits application bookkeeping even when native shutdown rejects UNKNOWN", async () => {
    const f = await workerFixture(true); let release!: () => void, reached!: () => void;
    const gate = new Promise<void>(r => { release = r; }), entered = new Promise<void>(r => { reached = r; });
    const execution = f.execution as unknown as { ingestResult: (...args: unknown[]) => Promise<void> };
    const original = execution.ingestResult.bind(f.execution); execution.ingestResult = async (...args) => { reached(); await gate; await original(...args); };
    let stopping: Promise<void> | undefined, injected = false, completed = false;
    try {
      const id = await f.execution.enqueue(f.request); await f.seen(); const root = f.child(id)!;
      const helper = (f.workers as unknown as { custody: Map<ChildProcess, { job: { helper: ChildProcess } }> }).custody.get(root)!.job.helper;
      const closed = new Promise<void>(r => helper.once("close", () => r())); helper.kill("SIGKILL"); injected = true; await closed; f.release(); await entered;
      stopping = f.execution.shutdown().then(() => { completed = true; }, () => { completed = true; });
      await expect(f.workers.shutdown()).rejects.toThrow("WORKER_RETENTION_UNKNOWN"); await new Promise<void>(r => setImmediate(r));
      f.capture("SHUTDOWN_BOOKKEEPING_PENDING"); expect(completed).toBe(false);
    } finally { release(); await stopping; if (injected) await expect(f.close()).rejects.toThrow("WORKER_RETENTION_UNKNOWN"); else await f.close(); }
  });

  it("refuses to acknowledge a deliberately withheld STOP and falls back only to its root handle", async () => {
    const dir = lab(), child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], { windowsHide: true, stdio: "ignore" });
    const custody = new WorkerProcessCustody(child, dir);
    try {
      await custody.bind((await windowsProcessBirth(child.pid!, dir))!);
      const helper = (custody as unknown as { job: { helper: ChildProcess } }).job.helper;
      const stream = helper.stdin! as unknown as { write: (chunk: unknown, ...args: unknown[]) => boolean }, original = stream.write.bind(stream);
      stream.write = (chunk, ...args) => { if (String(chunk).startsWith("STOP:")) { const callback = args.at(-1); if (typeof callback === "function") queueMicrotask(() => callback(null)); receipt(dir, "WITHHELD_STOP", { queuedOnly: true, nativeCommandDelivered: false }); return true; } return original(chunk, ...args); };
      await custody.terminate(); await custody.drain(); receipt(dir, "UNACKNOWLEDGED_STOP", custody.receipt());
      expect(custody.receipt()).toMatchObject({ rootClosed: true, rootOnlyFallback: true, terminationOutcome: "UNKNOWN", job: { terminationAcknowledged: false, failure: "WINDOWS_JOB_ACK_TIMEOUT", completeDescendantContainment: false } });
    } finally { await custody.terminate(); await custody.drain(); }
  });

  it.each(["STOPPING", "QUARANTINE"])("keeps custody fail-closed when %s SQLite bookkeeping fails", async fault => {
    const f = await workerFixture(true); let injected = false;
    try {
      const id = await f.execution.enqueue(f.request); await f.seen(); const child = f.child(id)!;
      if (fault === "STOPPING") f.database.db.exec("CREATE TRIGGER fixture_stopping_failure BEFORE UPDATE OF state ON scan_workers WHEN NEW.state = 'STOPPING' BEGIN SELECT RAISE(ABORT, 'FIXTURE_STOPPING_WRITE_FAILURE'); END;");
      else f.database.db.exec("CREATE TRIGGER fixture_quarantine_failure BEFORE UPDATE ON worker_governance_state WHEN NEW.dispatch_state = 'QUARANTINED' BEGIN SELECT RAISE(ABORT, 'FIXTURE_QUARANTINE_WRITE_FAILURE'); END;");
      const helper = (f.workers as unknown as { custody: Map<ChildProcess, { job: { helper: ChildProcess } }> }).custody.get(child)!.job.helper;
      const closed = new Promise<void>(r => helper.once("close", () => r())); helper.kill("SIGKILL"); injected = true; await closed;
      f.capture("BOOKKEEPING_FAILURE_LIVE_ROOT");
      if (fault === "STOPPING") {
        const active = (f.workers as unknown as { active: Map<string, { forceKillTimer?: { _idleTimeout: number } }> }).active.get(id)!;
        expect(active.forceKillTimer?._idleTimeout).toBe(135000);
      } else {
        const reopened = new DashboardDatabase(f.paths.databasePath), fresh = new ScanWorkerManager(reopened, f.paths);
        try { expect(() => fresh.run(id, f.request, { onPlan() {}, onEvent() {}, onHeartbeat() {} }, {} as never)).toThrow("WORKER_CUSTODY_REVIEW_REQUIRED"); expect(fresh.diagnostics()).toMatchObject({ dispatchState: "QUARANTINED" }); }
        finally { await fresh.shutdown(); reopened.close(); }
      }
    } finally { f.release(); if (injected) await expect(f.close()).rejects.toThrow("WORKER_RETENTION_UNKNOWN"); else await f.close(); }
  });

});
