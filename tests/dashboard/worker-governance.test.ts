import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { defaultWorkerGovernancePolicy, evaluateWorkerLimits, WorkerGovernanceRepository, type WorkerResourceSnapshot } from "../../src/dashboard/worker/WorkerGovernance.js";
import { descendantProcessIds, parsePosixProcessList, parseWindowsProcessCsv, workerProcessTreePlan } from "../../src/dashboard/worker/WorkerProcessTree.js";
import { dashboardSettingsUpdateSchema } from "../../src/dashboard/contracts/DashboardSchemas.js";

const directories: string[] = [];
afterEach(() => { for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true }); });

describe("worker resource governance", () => {
  it("validates dashboard-editable governance ceilings and preserves the cleanup minimum", () => {
    expect(dashboardSettingsUpdateSchema.parse({ values: { workerMemoryMb: 512, workerCpuTimeMs: 120000, workerWallClockMs: 180000, workerOutputQuotaMb: 128, workerTempQuotaMb: 64, workerHeartbeatTimeoutMs: 10000, workerCleanupGraceMs: 135000, workerForceKillGraceMs: 5000, workerCrashLoopLimit: 4, workerCrashLoopWindowMs: 300000 }, expectedVersions: {} }).values.workerMemoryMb).toBe(512);
    expect(() => dashboardSettingsUpdateSchema.parse({ values: { workerCleanupGraceMs: 120000 }, expectedVersions: {} })).toThrow();
  });
  it.each([
    ["memory", { rssBytes: defaultWorkerGovernancePolicy.memoryBytes + 1 }, "MEMORY_LIMIT"],
    ["cpu", { cpuUserMicros: defaultWorkerGovernancePolicy.cpuTimeMs * 1000 + 1 }, "CPU_LIMIT"],
    ["output", { outputBytes: defaultWorkerGovernancePolicy.outputBytes + 1 }, "OUTPUT_QUOTA"],
    ["temp", { tempBytes: defaultWorkerGovernancePolicy.tempBytes + 1 }, "TEMP_QUOTA"]
  ])("classifies the %s ceiling", (_label, changed, expected) => {
    expect(evaluateWorkerLimits(snapshot(changed), defaultWorkerGovernancePolicy, Date.now())).toMatchObject({ category: expected });
  });

  it("classifies a manager-owned wall-clock deadline", () => {
    expect(evaluateWorkerLimits(snapshot(), defaultWorkerGovernancePolicy, Date.now() - defaultWorkerGovernancePolicy.wallClockMs - 1)).toMatchObject({ category: "WALL_CLOCK_LIMIT" });
  });

  it("persists live diagnostics and quarantines dispatch after a bounded crash loop", () => {
    const database = createDatabase();
    try {
      const governance = new WorkerGovernanceRepository(database);
      const workerId = "00000000-0000-4000-8000-000000000001";
      database.db.prepare("INSERT INTO scans (id, source, status, target_origin, safe_target_label, profile, evidence_level, created_at, queued_at, safe_configuration_summary, output_directory) VALUES (?, 'DASHBOARD', 'RUNNING', 'https://example.test', 'example', 'quick', 'normal', ?, ?, '{}', ?)").run("00000000-0000-4000-8000-000000000002", new Date().toISOString(), new Date().toISOString(), resolve(tmpdir(), "report"));
      database.db.prepare("INSERT INTO scan_workers (id, process_id, state, started_at, last_heartbeat_at, current_job_id, version, governance_policy_json, cleanup_state, updated_at) VALUES (?, 4242, 'RUNNING', ?, ?, ?, '2', ?, 'UNKNOWN', ?)").run(workerId, new Date().toISOString(), new Date().toISOString(), "00000000-0000-4000-8000-000000000002", JSON.stringify(defaultWorkerGovernancePolicy), new Date().toISOString());
      governance.heartbeat(workerId, snapshot({ currentModule: "authentication-lifecycle", cleanupState: "RUNNING", rssBytes: 1234, outputBytes: 456 }), [4242, 4243]);
      expect(governance.fleet().workers[0]).toMatchObject({ currentModule: "authentication-lifecycle", cleanupState: "RUNNING", resources: { rssBytes: 1234, outputBytes: 456 }, processTreePids: [4242, 4243] });

      expect(governance.recordCrash()).toBe(false);
      expect(governance.recordCrash()).toBe(false);
      expect(governance.recordCrash()).toBe(true);
      expect(governance.fleet()).toMatchObject({ dispatchState: "QUARANTINED", crashCount: 3 });
      expect(() => governance.assertDispatchAllowed()).toThrow(/WORKER_FLEET_QUARANTINED/);
      governance.resetCrashLoop();
      expect(governance.fleet()).toMatchObject({ dispatchState: "NORMAL", crashCount: 0 });
    } finally { database.close(); }
  });
});

describe("cross-platform process-tree governance", () => {
  it("discovers nested children from Windows CSV and POSIX process listings", () => {
    expect(descendantProcessIds(parseWindowsProcessCsv('"10","1"\n"11","10"\n"12","11"\n"20","1"'), 10)).toEqual([11, 12]);
    expect(descendantProcessIds(parsePosixProcessList(" 10 1\n 11 10\n 12 11\n 20 1"), 10)).toEqual([11, 12]);
  });

  it.each(["linux", "darwin"] as const)("uses a detached process group on %s", (platform) => {
    expect(workerProcessTreePlan(4242, platform, true)).toMatchObject({ discovery: { file: "ps" }, termination: { kind: "process-group", pid: -4242, signal: "SIGKILL" } });
  });

  it("uses taskkill tree semantics on Windows", () => {
    expect(workerProcessTreePlan(4242, "win32", true)).toMatchObject({ discovery: { file: "powershell.exe" }, termination: { kind: "command", file: "taskkill.exe", args: ["/PID", "4242", "/T", "/F"] } });
  });
});

function snapshot(changed: Partial<WorkerResourceSnapshot> = {}): WorkerResourceSnapshot {
  return { sequence: 1, timestamp: new Date().toISOString(), rssBytes: 1, heapUsedBytes: 1, externalBytes: 0, cpuUserMicros: 1, cpuSystemMicros: 1, outputBytes: 0, tempBytes: 0, cleanupState: "CLEAR", ...changed };
}

function createDatabase(): DashboardDatabase {
  const directory = mkdtempSync(resolve(tmpdir(), "routecairn-worker-governance-")); directories.push(directory);
  const database = new DashboardDatabase(resolve(directory, "dashboard.sqlite")); database.migrate(); return database;
}
