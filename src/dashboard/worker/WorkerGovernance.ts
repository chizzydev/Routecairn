import { z } from "zod";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";

export const workerFailureCategorySchema = z.enum([
  "MEMORY_LIMIT",
  "CPU_LIMIT",
  "WALL_CLOCK_LIMIT",
  "OUTPUT_QUOTA",
  "TEMP_QUOTA",
  "HEARTBEAT_TIMEOUT",
  "PROCESS_CRASH",
  "IPC_FAILURE",
  "STARTUP_FAILURE",
  "PROTOCOL_FAILURE",
  "CLEANUP_TIMEOUT",
  "FORCED_TERMINATION",
  "CRASH_LOOP",
  "MANUAL_RESTART",
  "MANUAL_QUARANTINE"
]);

export type WorkerFailureCategory = z.infer<typeof workerFailureCategorySchema>;

export class WorkerGovernanceError extends Error {
  public constructor(public readonly category: WorkerFailureCategory, message: string) {
    super(message);
    this.name = "WorkerGovernanceError";
  }
}

export type WorkerCleanupState = "CLEAR" | "PENDING" | "RUNNING" | "REQUIRED" | "UNKNOWN";

export interface WorkerResourceSnapshot {
  sequence: number;
  timestamp: string;
  rssBytes: number;
  heapUsedBytes: number;
  externalBytes: number;
  cpuUserMicros: number;
  cpuSystemMicros: number;
  outputBytes: number;
  tempBytes: number;
  currentModule?: string;
  cleanupState: WorkerCleanupState;
}

export interface WorkerGovernancePolicy {
  memoryBytes: number;
  cpuTimeMs: number;
  wallClockMs: number;
  outputBytes: number;
  tempBytes: number;
  heartbeatTimeoutMs: number;
  cleanupGraceMs: number;
  forceKillGraceMs: number;
  crashLoopLimit: number;
  crashLoopWindowMs: number;
}

const workerGovernancePolicySchema = z.object({
  memoryBytes: z.number().int().min(128 * 1024 * 1024).max(4096 * 1024 * 1024),
  cpuTimeMs: z.number().int().min(10_000).max(7_200_000),
  wallClockMs: z.number().int().min(30_000).max(7_200_000),
  outputBytes: z.number().int().min(16 * 1024 * 1024).max(4096 * 1024 * 1024),
  tempBytes: z.number().int().min(16 * 1024 * 1024).max(4096 * 1024 * 1024),
  heartbeatTimeoutMs: z.number().int().min(5_000).max(120_000),
  cleanupGraceMs: z.number().int().min(135_000).max(600_000),
  forceKillGraceMs: z.number().int().min(1_000).max(60_000),
  crashLoopLimit: z.number().int().min(2).max(20),
  crashLoopWindowMs: z.number().int().min(30_000).max(3_600_000)
});

export const defaultWorkerGovernancePolicy: WorkerGovernancePolicy = Object.freeze({
  memoryBytes: 768 * 1024 * 1024,
  cpuTimeMs: 15 * 60_000,
  wallClockMs: 20 * 60_000,
  outputBytes: 512 * 1024 * 1024,
  tempBytes: 256 * 1024 * 1024,
  heartbeatTimeoutMs: 15_000,
  cleanupGraceMs: 135_000,
  forceKillGraceMs: 5_000,
  crashLoopLimit: 3,
  crashLoopWindowMs: 5 * 60_000
});

const numericSettings: Record<keyof WorkerGovernancePolicy, { key: string; scale?: number }> = {
  memoryBytes: { key: "workerMemoryMb", scale: 1024 * 1024 },
  cpuTimeMs: { key: "workerCpuTimeMs" },
  wallClockMs: { key: "workerWallClockMs" },
  outputBytes: { key: "workerOutputQuotaMb", scale: 1024 * 1024 },
  tempBytes: { key: "workerTempQuotaMb", scale: 1024 * 1024 },
  heartbeatTimeoutMs: { key: "workerHeartbeatTimeoutMs" },
  cleanupGraceMs: { key: "workerCleanupGraceMs" },
  forceKillGraceMs: { key: "workerForceKillGraceMs" },
  crashLoopLimit: { key: "workerCrashLoopLimit" },
  crashLoopWindowMs: { key: "workerCrashLoopWindowMs" }
};

export function loadWorkerGovernancePolicy(database: DashboardDatabase): WorkerGovernancePolicy {
  const rows = database.db.prepare("SELECT key, value_json FROM dashboard_settings WHERE key LIKE 'worker%'").all() as Array<{ key: string; value_json: string }>;
  const values = new Map(rows.map((row) => [row.key, JSON.parse(row.value_json) as unknown]));
  const candidate = Object.fromEntries(Object.entries(numericSettings).map(([field, setting]) => {
    const value = values.get(setting.key);
    const fallback = defaultWorkerGovernancePolicy[field as keyof WorkerGovernancePolicy];
    return [field, typeof value === "number" && Number.isFinite(value) ? Math.floor(value * (setting.scale ?? 1)) : fallback];
  }));
  const parsed = workerGovernancePolicySchema.safeParse(candidate);
  return parsed.success ? parsed.data : { ...defaultWorkerGovernancePolicy };
}

export function evaluateWorkerLimits(snapshot: WorkerResourceSnapshot, policy: WorkerGovernancePolicy, startedAtMs: number, nowMs = Date.now()): { category: WorkerFailureCategory; reason: string } | undefined {
  if (snapshot.rssBytes > policy.memoryBytes) return { category: "MEMORY_LIMIT", reason: `Worker RSS exceeded ${policy.memoryBytes} bytes.` };
  if ((snapshot.cpuUserMicros + snapshot.cpuSystemMicros) / 1000 > policy.cpuTimeMs) return { category: "CPU_LIMIT", reason: `Worker CPU time exceeded ${policy.cpuTimeMs} ms.` };
  if (nowMs - startedAtMs > policy.wallClockMs) return { category: "WALL_CLOCK_LIMIT", reason: `Worker wall-clock time exceeded ${policy.wallClockMs} ms.` };
  if (snapshot.outputBytes > policy.outputBytes) return { category: "OUTPUT_QUOTA", reason: `Worker output exceeded ${policy.outputBytes} bytes.` };
  if (snapshot.tempBytes > policy.tempBytes) return { category: "TEMP_QUOTA", reason: `Worker temporary storage exceeded ${policy.tempBytes} bytes.` };
  return undefined;
}

export interface WorkerDiagnostic {
  id: string;
  processId?: number;
  state: string;
  currentJobId?: string;
  startedAt: string;
  lastHeartbeatAt?: string;
  currentModule?: string;
  cleanupState: WorkerCleanupState;
  resources: { rssBytes: number; heapUsedBytes: number; cpuTimeMs: number; outputBytes: number; tempBytes: number };
  processTreePids: number[];
  failureCategory?: WorkerFailureCategory;
  terminationReason?: string;
  gracefulStopRequestedAt?: string;
  forcedTerminationAt?: string;
  quarantinedAt?: string;
  quarantineReason?: string;
  policy: WorkerGovernancePolicy;
}

export interface WorkerFleetDiagnostic {
  dispatchState: "NORMAL" | "QUARANTINED";
  quarantineReason?: string;
  crashCount: number;
  crashWindowStartedAt?: string;
  workers: WorkerDiagnostic[];
  policy: WorkerGovernancePolicy;
}

export class WorkerGovernanceRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public fleet(): WorkerFleetDiagnostic {
    const policy = loadWorkerGovernancePolicy(this.database);
    const fleet = this.database.db.prepare("SELECT * FROM worker_governance_state WHERE id = 'singleton'").get() as Record<string, unknown> | undefined;
    const rows = this.database.db.prepare("SELECT * FROM scan_workers ORDER BY started_at DESC LIMIT 100").all() as Array<Record<string, unknown>>;
    return {
      dispatchState: fleet?.dispatch_state === "QUARANTINED" ? "QUARANTINED" : "NORMAL",
      ...(typeof fleet?.quarantine_reason === "string" ? { quarantineReason: fleet.quarantine_reason } : {}),
      crashCount: Number(fleet?.crash_count ?? 0),
      ...(typeof fleet?.crash_window_started_at === "string" ? { crashWindowStartedAt: fleet.crash_window_started_at } : {}),
      workers: rows.map((row) => workerDiagnostic(row, policy)),
      policy
    };
  }

  public assertDispatchAllowed(): void {
    const row = this.database.db.prepare("SELECT dispatch_state, quarantine_reason FROM worker_governance_state WHERE id = 'singleton'").get() as { dispatch_state: string; quarantine_reason: string | null } | undefined;
    if (row?.dispatch_state === "QUARANTINED") throw new WorkerGovernanceError(row.quarantine_reason?.startsWith("Crash-loop") ? "CRASH_LOOP" : "MANUAL_QUARANTINE", `WORKER_FLEET_QUARANTINED: ${row.quarantine_reason ?? "Operator release is required."}`);
  }

  public heartbeat(workerId: string, snapshot: WorkerResourceSnapshot, processTreePids: readonly number[]): void {
    this.database.db.prepare(`UPDATE scan_workers SET last_heartbeat_at = ?, heartbeat_sequence = ?, memory_rss_bytes = ?, heap_used_bytes = ?, cpu_user_micros = ?, cpu_system_micros = ?, output_bytes = ?, temp_bytes = ?, current_module = ?, cleanup_state = ?, child_processes_json = ?, updated_at = ? WHERE id = ?`)
      .run(snapshot.timestamp, snapshot.sequence, snapshot.rssBytes, snapshot.heapUsedBytes, snapshot.cpuUserMicros, snapshot.cpuSystemMicros, snapshot.outputBytes, snapshot.tempBytes, snapshot.currentModule ?? null, snapshot.cleanupState, JSON.stringify(processTreePids), nowIso(), workerId);
  }

  public markStopping(workerId: string, category: WorkerFailureCategory, reason: string): void {
    this.database.db.prepare("UPDATE scan_workers SET state = 'STOPPING', failure_category = ?, termination_reason = ?, graceful_stop_requested_at = COALESCE(graceful_stop_requested_at, ?), updated_at = ? WHERE id = ?")
      .run(category, reason.slice(0, 800), nowIso(), nowIso(), workerId);
  }

  public markForced(workerId: string, reason: string): void {
    this.database.db.prepare("UPDATE scan_workers SET forced_termination_at = ?, termination_reason = COALESCE(termination_reason, ?), updated_at = ? WHERE id = ?")
      .run(nowIso(), reason.slice(0, 800), nowIso(), workerId);
  }

  public finish(workerId: string, input: { state: "STOPPED" | "EXITED"; category?: WorkerFailureCategory; reason?: string; exitCode?: number | null; exitSignal?: string | null }): void {
    this.database.db.prepare("UPDATE scan_workers SET state = ?, current_job_id = NULL, shutdown_at = COALESCE(shutdown_at, ?), failure_category = COALESCE(?, failure_category), termination_reason = COALESCE(?, termination_reason), exit_code = ?, exit_signal = ?, updated_at = ? WHERE id = ?")
      .run(input.state, nowIso(), input.category ?? null, input.reason?.slice(0, 800) ?? null, input.exitCode ?? null, input.exitSignal ?? null, nowIso(), workerId);
  }

  public quarantineWorker(workerId: string, reason: string): void {
    const result = this.database.db.prepare("UPDATE scan_workers SET quarantined_at = ?, quarantine_reason = ?, updated_at = ? WHERE id = ?").run(nowIso(), reason.slice(0, 500), nowIso(), workerId);
    if (result.changes === 0) throw new Error("Worker not found.");
  }

  public releaseWorker(workerId: string): void {
    const result = this.database.db.prepare("UPDATE scan_workers SET quarantined_at = NULL, quarantine_reason = NULL, updated_at = ? WHERE id = ?").run(nowIso(), workerId);
    if (result.changes === 0) throw new Error("Worker not found.");
  }

  public setFleetQuarantine(quarantined: boolean, reason?: string): void {
    this.database.db.prepare("UPDATE worker_governance_state SET dispatch_state = ?, quarantine_reason = ?, quarantined_at = ?, updated_at = ? WHERE id = 'singleton'")
      .run(quarantined ? "QUARANTINED" : "NORMAL", quarantined ? (reason ?? "Manual operator quarantine").slice(0, 500) : null, quarantined ? nowIso() : null, nowIso());
  }

  public recordCrash(): boolean {
    const policy = loadWorkerGovernancePolicy(this.database);
    const row = this.database.db.prepare("SELECT crash_count, crash_window_started_at, dispatch_state, quarantine_reason, quarantined_at FROM worker_governance_state WHERE id = 'singleton'").get() as { crash_count: number; crash_window_started_at: string | null; dispatch_state: string; quarantine_reason: string | null; quarantined_at: string | null };
    const now = Date.now();
    const inWindow = row.crash_window_started_at && now - Date.parse(row.crash_window_started_at) <= policy.crashLoopWindowMs;
    const count = inWindow ? row.crash_count + 1 : 1;
    const start = inWindow ? row.crash_window_started_at : new Date(now).toISOString();
    const tripped = count >= policy.crashLoopLimit;
    const alreadyQuarantined = row.dispatch_state === "QUARANTINED";
    this.database.db.prepare("UPDATE worker_governance_state SET crash_count = ?, crash_window_started_at = ?, dispatch_state = ?, quarantine_reason = ?, quarantined_at = ?, updated_at = ? WHERE id = 'singleton'")
      .run(count, start, tripped || alreadyQuarantined ? "QUARANTINED" : "NORMAL", tripped ? `Crash-loop protection stopped dispatch after ${count} unexpected worker failures.` : row.quarantine_reason, tripped ? nowIso() : row.quarantined_at, nowIso());
    return tripped;
  }

  public resetCrashLoop(): void {
    this.database.db.prepare("UPDATE worker_governance_state SET crash_count = 0, crash_window_started_at = NULL, dispatch_state = 'NORMAL', quarantine_reason = NULL, quarantined_at = NULL, updated_at = ? WHERE id = 'singleton'").run(nowIso());
  }
}

function workerDiagnostic(row: Record<string, unknown>, fallbackPolicy: WorkerGovernancePolicy): WorkerDiagnostic {
  const parsedPolicy = parseJsonObject(row.governance_policy_json);
  const policyResult = workerGovernancePolicySchema.safeParse(parsedPolicy);
  const policy = policyResult.success ? policyResult.data : fallbackPolicy;
  const category = typeof row.failure_category === "string" ? workerFailureCategorySchema.safeParse(row.failure_category) : undefined;
  return {
    id: String(row.id),
    ...(typeof row.process_id === "number" ? { processId: row.process_id } : {}),
    state: String(row.state),
    ...(typeof row.current_job_id === "string" ? { currentJobId: row.current_job_id } : {}),
    startedAt: String(row.started_at),
    ...(typeof row.last_heartbeat_at === "string" ? { lastHeartbeatAt: row.last_heartbeat_at } : {}),
    ...(typeof row.current_module === "string" ? { currentModule: row.current_module } : {}),
    cleanupState: (["CLEAR", "PENDING", "RUNNING", "REQUIRED", "UNKNOWN"].includes(String(row.cleanup_state)) ? String(row.cleanup_state) : "UNKNOWN") as WorkerCleanupState,
    resources: {
      rssBytes: Number(row.memory_rss_bytes ?? 0),
      heapUsedBytes: Number(row.heap_used_bytes ?? 0),
      cpuTimeMs: (Number(row.cpu_user_micros ?? 0) + Number(row.cpu_system_micros ?? 0)) / 1000,
      outputBytes: Number(row.output_bytes ?? 0),
      tempBytes: Number(row.temp_bytes ?? 0)
    },
    processTreePids: parseNumberArray(row.child_processes_json),
    ...(category?.success ? { failureCategory: category.data } : {}),
    ...(typeof row.termination_reason === "string" ? { terminationReason: row.termination_reason } : {}),
    ...(typeof row.graceful_stop_requested_at === "string" ? { gracefulStopRequestedAt: row.graceful_stop_requested_at } : {}),
    ...(typeof row.forced_termination_at === "string" ? { forcedTerminationAt: row.forced_termination_at } : {}),
    ...(typeof row.quarantined_at === "string" ? { quarantinedAt: row.quarantined_at } : {}),
    ...(typeof row.quarantine_reason === "string" ? { quarantineReason: row.quarantine_reason } : {}),
    policy
  };
}

function parseJsonObject(value: unknown): Record<string, unknown> {
  try { const parsed = JSON.parse(typeof value === "string" ? value : "{}"); return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}; }
  catch { return {}; }
}

function parseNumberArray(value: unknown): number[] {
  try { const parsed = JSON.parse(typeof value === "string" ? value : "[]"); return Array.isArray(parsed) ? parsed.filter((item): item is number => Number.isInteger(item) && item > 0) : []; }
  catch { return []; }
}
