import { fork, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { rm } from "node:fs/promises";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import { resolveCredentialAuthForDashboardScan, type DashboardResolvedAuth } from "../execution/ScanExecutionShared.js";
import { executableAuthenticationDigest, type BoundExecutablePlan } from "../execution/ExecutablePlanSnapshot.js";
import { parseWorkerMessage, workerProtocolVersion, type WorkerToApiMessage } from "./ScanWorkerProtocol.js";
import { controlledMutationContractSchema, type ControlledMutationContract } from "../../core/offensive/ControlledMutationTypes.js";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";
import { workerRestorationGraceMs } from "../../core/engine/CleanupExecution.js";
import { evaluateWorkerLimits, loadWorkerGovernancePolicy, WorkerGovernanceError, WorkerGovernanceRepository, type WorkerFailureCategory, type WorkerGovernancePolicy, type WorkerResourceSnapshot } from "./WorkerGovernance.js";
import { processTreeIds, terminateProcessTree } from "./WorkerProcessTree.js";

export interface WorkerRunHandlers {
  onPlan(message: Extract<WorkerToApiMessage, { type: "JOB_PLAN" }>): void;
  onEvent(message: Extract<WorkerToApiMessage, { type: "JOB_EVENT" }>): void;
  onHeartbeat(message: Extract<WorkerToApiMessage, { type: "JOB_HEARTBEAT" }>): void;
}

export interface WorkerRunResult {
  workerId: string;
  status: "COMPLETED" | "FAILED" | "CANCELLED" | "INTERRUPTED";
  reportPath?: string;
  markdownReportPath?: string;
  htmlReportPath?: string;
  error?: string;
  failureCategory?: WorkerFailureCategory;
}

export interface WorkerExecutionOptions {
  executablePlan: BoundExecutablePlan;
  resolvedAuth: DashboardResolvedAuth;
  contracts?: readonly ControlledMutationContract[];
}

export interface WorkerRecoveryResult { workerId: string; caseId: string; cleanupOutcome: "ROLLBACK_VERIFIED" | "CLEANUP_FAILED"; notes: string[]; }

const leaseTtlMs = 30_000;
const recoveryTimeoutMs = workerRestorationGraceMs;

interface ActiveWorker {
  child: ChildProcess;
  workerId: string;
  jobId: string;
  settled: Promise<void>;
  resolveSettled(): void;
  policy: WorkerGovernancePolicy;
  startedAtMs: number;
  lastHeartbeatMs: number;
  tempDir: string;
  processTreePids?: number[];
  monitorTimer?: ReturnType<typeof setInterval>;
  cancellationTimer?: ReturnType<typeof setTimeout>;
  forceKillTimer?: ReturnType<typeof setTimeout>;
  termination?: { category: WorkerFailureCategory; reason: string };
}

export class ScanWorkerManager {
  private readonly active = new Map<string, ActiveWorker>();
  private readonly governance: WorkerGovernanceRepository;

  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly vault?: CredentialVault) {
    this.governance = new WorkerGovernanceRepository(database);
  }

  public async recoverExpiredLeases(): Promise<string[]> {
    const expired = this.database.db.prepare("SELECT leases.job_id, leases.expires_at, workers.process_id FROM scan_job_leases leases LEFT JOIN scan_workers workers ON workers.id = leases.worker_id WHERE leases.released_at IS NULL AND leases.expires_at < ?").all(nowIso()) as Array<{ job_id: string; expires_at: string; process_id: number | null }>;
    const recovered: string[] = [];
    for (const row of expired) {
      // An orphaned worker uses its own restoration grace after IPC loss.
      // Do not ingest a moving checkpoint while that bounded cleanup is active.
      if (row.process_id && Date.now() < Date.parse(row.expires_at) + workerRestorationGraceMs && processAlive(row.process_id)) continue;
      const cleanupStatus = await readMutationCleanupStatus(this.paths.mutationJournalDir, this.paths.mutationJournalRegistryPath).catch(() => undefined);
      const cleanupRequired = !cleanupStatus || cleanupStatus.cleanupRequired > 0;
      this.database.transaction(() => {
        this.database.db.prepare("UPDATE scans SET status = 'INTERRUPTED', completed_at = ?, error_summary = ? WHERE id = ? AND status IN ('QUEUED','PLANNING','RUNNING','CANCEL_REQUESTED')").run(nowIso(), cleanupRequired ? "Worker lease expired while a controlled mutation cleanup obligation remains unresolved. Operator recovery is required before new mutations." : "Worker lease expired before the scan reached a terminal state.", row.job_id);
        this.database.db.prepare("INSERT INTO scan_events (id, seq, scan_id, event_type, safe_message, safe_metadata_json, created_at) SELECT ?, COALESCE(MAX(seq), 0) + 1, ?, ?, ?, ?, ? FROM scan_events WHERE scan_id = ?").run(randomUUID(), row.job_id, cleanupRequired ? "MUTATION_CLEANUP_REQUIRED" : "SCAN_INTERRUPTED", cleanupRequired ? "Worker lease expired; controlled mutation cleanup requires operator recovery." : "Worker lease expired before the scan reached a terminal state.", JSON.stringify({ cleanupRequired }), nowIso(), row.job_id);
        this.database.db.prepare("UPDATE scan_job_leases SET released_at = ?, release_category = 'EXPIRED' WHERE job_id = ? AND released_at IS NULL").run(nowIso(), row.job_id);
      });
      recovered.push(row.job_id);
    }
    return recovered;
  }

  public run(jobId: string, request: DashboardScanCreateRequest, handlers: WorkerRunHandlers, options: WorkerExecutionOptions): Promise<WorkerRunResult> {
    this.verifyExecutionAuthentication(request, options);
    this.governance.assertDispatchAllowed();
    const workerId = randomUUID();
    const workerGeneration = randomUUID();
    const workerSecret = randomBytes(32).toString("base64url");
    const policy = loadWorkerGovernancePolicy(this.database);
    const tempDir = resolve(this.paths.workersDir, workerId, "tmp");
    mkdirSync(tempDir, { recursive: true });
    let child: ChildProcess;
    try { child = fork(workerEntryPath(), [], {
      execArgv: [...(workerEntryPath().endsWith(".ts") ? ["--import", "tsx"] : []), `--max-old-space-size=${Math.max(64, Math.floor(policy.memoryBytes / 1024 / 1024 * 0.75))}`],
      env: { ...process.env, ROUTECAIRN_WORKER_ID: workerId, ROUTECAIRN_WORKER_GENERATION: workerGeneration, ROUTECAIRN_WORKER_SESSION_SECRET: workerSecret, TMP: tempDir, TEMP: tempDir, TMPDIR: tempDir },
      detached: process.platform !== "win32",
      stdio: ["ignore", "ignore", "ignore", "ipc"]
    }); } catch (error) { throw new WorkerGovernanceError("STARTUP_FAILURE", error instanceof Error ? `Worker startup failed: ${error.message}` : "Worker startup failed."); }
    let resolveSettled: () => void = () => {};
    const settled = new Promise<void>((resolvePromise) => {
      resolveSettled = resolvePromise;
    });
    const active: ActiveWorker = { child, workerId, jobId, settled, resolveSettled, policy, startedAtMs: Date.now(), lastHeartbeatMs: Date.now(), tempDir };
    this.scheduleTempCleanup(child, tempDir);
    this.active.set(jobId, active);
    this.recordWorker(workerId, child.pid ?? null, policy);
    this.acquireLease(jobId, workerId);
    active.monitorTimer = setInterval(() => this.enforceActive(active), 1_000);
    active.monitorTimer.unref();

    return new Promise<WorkerRunResult>((resolveRun) => {
      let settled = false;
      const settle = (result: WorkerRunResult) => {
        if (settled) return;
        settled = true;
        try {
          const current = this.active.get(jobId);
          clearTimeout(current?.cancellationTimer);
          clearTimeout(current?.forceKillTimer);
          clearInterval(current?.monitorTimer);
          const effective = current?.termination;
          if (effective && !result.failureCategory) result = { ...result, status: effective.category === "MANUAL_RESTART" || effective.category === "MANUAL_QUARANTINE" ? "INTERRUPTED" : "FAILED", failureCategory: effective.category, error: effective.reason };
          this.releaseLease(jobId, result.status);
          this.governance.finish(workerId, { state: result.status === "COMPLETED" ? "STOPPED" : "EXITED", ...(result.failureCategory ? { category: result.failureCategory } : {}), ...(result.error ? { reason: result.error } : {}) });
          this.active.delete(jobId);
          this.gracefulWorkerExit(child, workerId, policy);
          resolveRun(result);
        } finally {
          resolveSettled();
        }
      };

      child.on("message", (raw: unknown) => {
        if (settled) return;
        try {
          const message = parseWorkerMessage(raw);
          if (message.workerId !== workerId) throw new Error("Worker ID mismatch.");
          if ("jobId" in message && message.jobId && message.jobId !== jobId) throw new Error("Worker job binding mismatch.");
          switch (message.type) {
            case "WORKER_READY":
              child.send({ protocolVersion: workerProtocolVersion, type: "INITIALIZE_JOB", workerId, jobId, request: safeWorkerRequest(request), paths: { reportsDir: this.paths.reportsDir, artifactsDir: this.paths.artifactsDir, proofPacksDir: this.paths.proofPacksDir, fingerprintKeyPath: this.paths.fingerprintKeyPath, mutationJournalDir: this.paths.mutationJournalDir, tempDir } });
              break;
            case "JOB_ACCEPTED":
              this.database.db.prepare("UPDATE scan_workers SET state = 'RUNNING', current_job_id = ?, last_heartbeat_at = ? WHERE id = ?").run(jobId, nowIso(), workerId);
              child.send(secretEnvelopeMessage({ workerId, jobId, request, workerSecret, workerGeneration, attempt: 1, vault: this.vault, resolvedAuth: options.resolvedAuth }));
              child.send(executablePlanMessage({ workerId, jobId, workerSecret, workerGeneration, executablePlan: options.executablePlan }));
              if (options.contracts?.length) child.send(mutationContractMessage({ workerId, jobId, contracts: options.contracts, workerSecret }));
              child.send({ protocolVersion: workerProtocolVersion, type: "START_JOB", workerId, jobId });
              break;
            case "JOB_HEARTBEAT":
              active.lastHeartbeatMs = Date.now();
              this.renewLease(jobId, workerId);
              this.governance.heartbeat(workerId, heartbeatSnapshot(message), active.processTreePids ?? (child.pid ? [child.pid] : []));
              if (message.resource.sequence % 5 === 0) void processTreeIds(child.pid ?? 0).then((pids) => { active.processTreePids = pids; }).catch(() => { /* Diagnostics sampling must not affect worker execution. */ });
              this.enforceSnapshot(active, heartbeatSnapshot(message));
              handlers.onHeartbeat(message);
              break;
            case "JOB_PLAN":
              if (message.executionPlanBinding !== options.executablePlan.binding) throw new Error("Worker executable plan binding mismatch.");
              handlers.onPlan(message);
              break;
            case "JOB_EVENT":
              handlers.onEvent(message);
              break;
            case "JOB_COMPLETED":
              settle({ workerId, status: "COMPLETED", reportPath: message.reportPath, markdownReportPath: message.markdownReportPath, htmlReportPath: message.htmlReportPath });
              break;
            case "JOB_CANCELLED":
              settle({ workerId, status: "CANCELLED", error: message.summary, ...reportPaths(message) });
              break;
            case "JOB_FAILED":
              settle({ workerId, status: "FAILED", error: message.error, ...reportPaths(message) });
              break;
            case "WORKER_ERROR":
              settle({ workerId, status: "FAILED", error: message.error });
              break;
            case "WORKER_SHUTDOWN":
              settle({ workerId, status: "INTERRUPTED", error: "Worker shut down before terminal job result." });
              break;
          }
        } catch (error) {
          settle({ workerId, status: "INTERRUPTED", failureCategory: "PROTOCOL_FAILURE", error: error instanceof Error ? error.message : "Invalid worker protocol message." });
        }
      });

      child.on("exit", (code, signal) => {
        if (settled) return;
        const current = this.active.get(jobId);
        if (!current?.termination) this.governance.recordCrash();
        this.governance.finish(workerId, { state: "EXITED", ...(current?.termination ? { category: current.termination.category, reason: current.termination.reason } : { category: "PROCESS_CRASH", reason: `Worker exited before completion. code=${code ?? "none"} signal=${signal ?? "none"}` }), exitCode: code, exitSignal: signal });
        settle({ workerId, status: "INTERRUPTED", failureCategory: current?.termination?.category ?? "PROCESS_CRASH", error: current?.termination?.reason ?? `Worker exited before completion. code=${code ?? "none"} signal=${signal ?? "none"}` });
      });
      child.on("error", () => { if (settled) return; this.governance.recordCrash(); settle({ workerId, status: "INTERRUPTED", failureCategory: "IPC_FAILURE", error: "Worker process or IPC failed; recovery may be required." }); });
    });
  }

  public runRecovery(jobId: string, request: DashboardScanCreateRequest, caseId: string, bundlePath: string): Promise<WorkerRecoveryResult> {
    const workerId = randomUUID();
    const workerGeneration = randomUUID();
    const workerSecret = randomBytes(32).toString("base64url");
    const policy = loadWorkerGovernancePolicy(this.database);
    const recoveryStartedAt = Date.now();
    const tempDir = resolve(this.paths.workersDir, workerId, "tmp");
    mkdirSync(tempDir, { recursive: true });
    let child: ChildProcess;
    try { child = fork(workerEntryPath(), [], { execArgv: [...(workerEntryPath().endsWith(".ts") ? ["--import", "tsx"] : []), `--max-old-space-size=${Math.max(64, Math.floor(policy.memoryBytes / 1024 / 1024 * 0.75))}`], env: { ...process.env, ROUTECAIRN_WORKER_ID: workerId, ROUTECAIRN_WORKER_GENERATION: workerGeneration, ROUTECAIRN_WORKER_SESSION_SECRET: workerSecret, TMP: tempDir, TEMP: tempDir, TMPDIR: tempDir }, detached: process.platform !== "win32", stdio: ["ignore", "ignore", "ignore", "ipc"] }); }
    catch (error) { throw new WorkerGovernanceError("STARTUP_FAILURE", error instanceof Error ? `Recovery worker startup failed: ${error.message}` : "Recovery worker startup failed."); }
    this.scheduleTempCleanup(child, tempDir);
    this.recordWorker(workerId, child.pid ?? null, policy);
    this.acquireRecoveryLease(jobId, workerId);
    return new Promise<WorkerRecoveryResult>((resolveRecovery, rejectRecovery) => {
      let settled = false;
      let governanceTimer: ReturnType<typeof setTimeout> | undefined;
      const timeout = setTimeout(() => settle(undefined, new Error("Recovery worker exceeded the bounded cleanup timeout.")), recoveryTimeoutMs);
      timeout.unref();
      const settle = (result?: WorkerRecoveryResult, error?: Error) => { if (settled) return; settled = true; clearTimeout(timeout); clearTimeout(governanceTimer); this.releaseRecoveryLease(jobId, result?.cleanupOutcome ?? "FAILED"); this.governance.finish(workerId, { state: result?.cleanupOutcome === "ROLLBACK_VERIFIED" ? "STOPPED" : "EXITED", ...(error ? { category: error.message.includes("timeout") ? "CLEANUP_TIMEOUT" : "PROCESS_CRASH", reason: error.message } : {}) }); this.gracefulWorkerExit(child, workerId, policy); if (error) rejectRecovery(error); else resolveRecovery(result!); };
      child.on("message", (raw: unknown) => {
        if (settled) return;
        try {
          const message = parseWorkerMessage(raw);
          if (message.workerId !== workerId) throw new Error("Worker ID mismatch.");
          if (message.type === "WORKER_READY") { child.send({ protocolVersion: workerProtocolVersion, type: "INITIALIZE_JOB", workerId, jobId, request: safeWorkerRequest(request), paths: { reportsDir: this.paths.reportsDir, artifactsDir: this.paths.artifactsDir, proofPacksDir: this.paths.proofPacksDir, fingerprintKeyPath: this.paths.fingerprintKeyPath, mutationJournalDir: this.paths.mutationJournalDir, tempDir } }); return; }
          if (message.type === "JOB_ACCEPTED") { this.database.db.prepare("UPDATE scan_workers SET state = 'RUNNING', last_heartbeat_at = ?, updated_at = ? WHERE id = ?").run(nowIso(), nowIso(), workerId); child.send(secretEnvelopeMessage({ workerId, jobId, request, workerSecret, workerGeneration, attempt: 1, vault: this.vault })); child.send(recoveryMessage({ workerId, jobId, caseId, bundlePath, workerSecret })); return; }
          if (message.type === "JOB_HEARTBEAT") { this.renewRecoveryLease(jobId, workerId); this.governance.heartbeat(workerId, heartbeatSnapshot(message), child.pid ? [child.pid] : []); const violation = evaluateWorkerLimits(heartbeatSnapshot(message), policy, recoveryStartedAt); if (violation && !governanceTimer) { this.governance.markStopping(workerId, violation.category, violation.reason); if (child.connected) child.send({ protocolVersion: workerProtocolVersion, type: "CANCEL_JOB", workerId, jobId, reason: violation.reason }); governanceTimer = setTimeout(() => { if (child.pid && child.exitCode === null) { this.governance.markForced(workerId, `${violation.reason} Recovery cleanup grace expired.`); void terminateProcessTree(child.pid, true); } }, policy.cleanupGraceMs); governanceTimer.unref(); } return; }
          if (message.type === "JOB_MUTATION_RECOVERY") { if (message.jobId !== jobId || message.caseId !== caseId) throw new Error("Recovery result binding mismatch."); settle({ workerId, caseId: message.caseId, cleanupOutcome: message.cleanupOutcome, notes: message.notes }); return; }
          if (message.type === "WORKER_ERROR") { settle(undefined, new Error(message.error)); return; }
          if (message.type === "WORKER_SHUTDOWN") { settle(undefined, new Error("Recovery worker shut down before cleanup result.")); }
        } catch (error) { settle(undefined, error instanceof Error ? error : new Error("Invalid worker recovery message.")); }
      });
      child.on("exit", (code, signal) => settle(undefined, new Error(`Recovery worker exited before completion. code=${code ?? "none"} signal=${signal ?? "none"}`)));
    });
  }

  public cancel(jobId: string): void {
    const active = this.active.get(jobId);
    if (!active || active.cancellationTimer) return;
    if (active.child.connected) active.child.send({ protocolVersion: workerProtocolVersion, type: "CANCEL_JOB", workerId: active.workerId, jobId, reason: "Operator cancellation requested." }, () => {});
    active.cancellationTimer = setTimeout(() => {
      const current = this.active.get(jobId);
      if (current && !current.child.killed && current.child.pid) {
        this.governance.markForced(current.workerId, "Cancellation grace expired; process tree was forcibly terminated.");
        void terminateProcessTree(current.child.pid, true);
      }
    }, workerRestorationGraceMs);
    active.cancellationTimer.unref();
  }

  public async shutdown(): Promise<void> {
    const activeRuns = [...this.active.values()];
    for (const jobId of this.active.keys()) this.cancel(jobId);
    await Promise.all(activeRuns.map((active) => active.settled));
  }

  public diagnostics() { return this.governance.fleet(); }

  public restartWorker(workerId: string): void {
    const active = [...this.active.values()].find((entry) => entry.workerId === workerId);
    if (!active) throw new Error("Worker is not active; the next job already receives a fresh job-scoped worker.");
    this.requestTermination(active, "MANUAL_RESTART", "Operator requested a graceful worker restart. The job will be interrupted and partial evidence retained.");
  }

  public quarantineWorker(workerId: string, reason: string): void {
    this.governance.quarantineWorker(workerId, reason);
    const active = [...this.active.values()].find((entry) => entry.workerId === workerId);
    if (active) this.requestTermination(active, "MANUAL_QUARANTINE", `Worker quarantined by operator: ${reason}`);
  }

  public releaseWorker(workerId: string): void { this.governance.releaseWorker(workerId); }

  public quarantineFleet(reason: string): void { this.governance.setFleetQuarantine(true, reason); }
  public releaseFleet(): void { this.governance.resetCrashLoop(); }

  private verifyExecutionAuthentication(request: DashboardScanCreateRequest, options: WorkerExecutionOptions): void {
    if (executableAuthenticationDigest(options.resolvedAuth) !== options.executablePlan.payload.authenticationDigest) throw new Error("EXECUTABLE_PLAN_AUTH_BINDING_MISMATCH");
    const studioAuth = request.studio?.authentication;
    const studioSaved = studioAuth?.mode === "primary" ? studioAuth.primary.source === "saved" : studioAuth?.mode === "account-pair" ? studioAuth.accountA.source === "saved" || studioAuth.accountB.source === "saved" : false;
    const savedCredentialRequested = Boolean(request.credentialProfileId || request.credentialProfileAId || request.credentialProfileBId || studioSaved);
    if (!savedCredentialRequested) return;
    if (!this.vault) throw new Error("EXECUTABLE_PLAN_AUTH_SOURCE_UNAVAILABLE");
    const current = resolveCredentialAuthForDashboardScan(this.vault, request);
    if (executableAuthenticationDigest(current) !== options.executablePlan.payload.authenticationDigest) throw new Error("EXECUTABLE_PLAN_AUTH_SOURCE_CHANGED");
  }

  private recordWorker(workerId: string, pid: number | null, policy: WorkerGovernancePolicy): void {
    this.database.db
      .prepare("INSERT INTO scan_workers (id, process_id, state, started_at, last_heartbeat_at, version, governance_policy_json, cleanup_state, updated_at) VALUES (?, ?, 'STARTING', ?, ?, ?, ?, 'UNKNOWN', ?)")
      .run(workerId, pid, nowIso(), nowIso(), "2", JSON.stringify(policy), nowIso());
  }

  private enforceSnapshot(active: ActiveWorker, snapshot: WorkerResourceSnapshot): void {
    const violation = evaluateWorkerLimits(snapshot, active.policy, active.startedAtMs);
    if (violation) this.requestTermination(active, violation.category, violation.reason);
  }

  private enforceActive(active: ActiveWorker): void {
    if (active.termination) return;
    const now = Date.now();
    if (now - active.startedAtMs > active.policy.wallClockMs) this.requestTermination(active, "WALL_CLOCK_LIMIT", `Worker wall-clock time exceeded ${active.policy.wallClockMs} ms.`);
    else if (now - active.lastHeartbeatMs > active.policy.heartbeatTimeoutMs) this.requestTermination(active, "HEARTBEAT_TIMEOUT", `Worker heartbeat was stale for more than ${active.policy.heartbeatTimeoutMs} ms.`);
  }

  private requestTermination(active: ActiveWorker, category: WorkerFailureCategory, reason: string): void {
    if (active.termination) return;
    active.termination = { category, reason };
    this.governance.markStopping(active.workerId, category, reason);
    if (active.child.connected) active.child.send({ protocolVersion: workerProtocolVersion, type: "CANCEL_JOB", workerId: active.workerId, jobId: active.jobId, reason }, () => {});
    active.forceKillTimer = setTimeout(() => {
      if (!active.child.pid || active.child.killed) return;
      this.governance.markForced(active.workerId, `${reason} Graceful cleanup deadline expired.`);
      void terminateProcessTree(active.child.pid, true);
    }, active.policy.cleanupGraceMs);
    active.forceKillTimer.unref();
  }

  private gracefulWorkerExit(child: ChildProcess, workerId: string, policy: WorkerGovernancePolicy): void {
    if (child.connected) child.send({ protocolVersion: workerProtocolVersion, type: "SHUTDOWN", workerId }, () => {});
    const timer = setTimeout(() => {
      if (!child.pid || child.killed || child.exitCode !== null || child.signalCode !== null) return;
      if (this.database.db.open) this.governance.markForced(workerId, "Worker did not exit after terminal result; process tree was terminated.");
      void terminateProcessTree(child.pid, true);
    }, policy.forceKillGraceMs);
    timer.unref();
  }

  private scheduleTempCleanup(child: ChildProcess, tempDir: string): void {
    const workersRoot = resolve(this.paths.workersDir);
    const candidate = resolve(tempDir);
    const childPath = relative(workersRoot, candidate);
    if (!childPath || childPath.startsWith("..") || isAbsolute(childPath)) throw new Error("Refusing worker temp cleanup outside the worker root.");
    child.once("exit", () => { void rm(candidate, { recursive: true, force: true }).catch(() => { /* Quota data remains in durable diagnostics; stale temp cleanup can be retried operationally. */ }); });
  }

private acquireRecoveryLease(jobId: string, workerId: string): void { const now = Date.now(); this.database.db.prepare("INSERT INTO controlled_mutation_recovery_leases (job_id, worker_id, acquired_at, expires_at, last_renewed_at) VALUES (?, ?, ?, ?, ?)").run(jobId, workerId, new Date(now).toISOString(), new Date(now + leaseTtlMs).toISOString(), new Date(now).toISOString()); }
  private renewRecoveryLease(jobId: string, workerId: string): void { const now = Date.now(); this.database.db.prepare("UPDATE controlled_mutation_recovery_leases SET last_renewed_at = ?, expires_at = ? WHERE job_id = ? AND worker_id = ? AND released_at IS NULL").run(new Date(now).toISOString(), new Date(now + leaseTtlMs).toISOString(), jobId, workerId); }
  private releaseRecoveryLease(jobId: string, category: string): void { this.database.db.prepare("UPDATE controlled_mutation_recovery_leases SET released_at = COALESCE(released_at, ?), release_category = COALESCE(release_category, ?) WHERE job_id = ? AND released_at IS NULL").run(nowIso(), category, jobId); }

  private acquireLease(jobId: string, workerId: string): void {
    const now = Date.now();
    this.database.db
      .prepare("INSERT INTO scan_job_leases (job_id, worker_id, acquired_at, expires_at, last_renewed_at, attempt_number) VALUES (?, ?, ?, ?, ?, COALESCE((SELECT MAX(attempt_number) + 1 FROM scan_job_leases WHERE job_id = ?), 1))")
      .run(jobId, workerId, new Date(now).toISOString(), new Date(now + leaseTtlMs).toISOString(), new Date(now).toISOString(), jobId);
  }

  private renewLease(jobId: string, workerId: string): void {
    const now = Date.now();
    this.database.db.prepare("UPDATE scan_workers SET last_heartbeat_at = ? WHERE id = ?").run(new Date(now).toISOString(), workerId);
    this.database.db.prepare("UPDATE scan_job_leases SET last_renewed_at = ?, expires_at = ? WHERE job_id = ? AND worker_id = ? AND released_at IS NULL").run(new Date(now).toISOString(), new Date(now + leaseTtlMs).toISOString(), jobId, workerId);
  }

  private releaseLease(jobId: string, category: string): void {
    this.database.db.prepare("UPDATE scan_job_leases SET released_at = COALESCE(released_at, ?), release_category = COALESCE(release_category, ?) WHERE job_id = ? AND released_at IS NULL").run(nowIso(), category, jobId);
  }
}

function reportPaths(message: { reportPath?: string | undefined; markdownReportPath?: string | undefined; htmlReportPath?: string | undefined }): Pick<WorkerRunResult, "reportPath" | "markdownReportPath" | "htmlReportPath"> {
  return { ...(message.reportPath ? { reportPath: message.reportPath } : {}), ...(message.markdownReportPath ? { markdownReportPath: message.markdownReportPath } : {}), ...(message.htmlReportPath ? { htmlReportPath: message.htmlReportPath } : {}) };
}

function heartbeatSnapshot(message: Extract<WorkerToApiMessage, { type: "JOB_HEARTBEAT" }>): WorkerResourceSnapshot {
  return {
    sequence: message.resource.sequence,
    timestamp: message.timestamp,
    rssBytes: message.resource.rssBytes,
    heapUsedBytes: message.resource.heapUsedBytes,
    externalBytes: message.resource.externalBytes,
    cpuUserMicros: message.resource.cpuUserMicros,
    cpuSystemMicros: message.resource.cpuSystemMicros,
    outputBytes: message.resource.outputBytes,
    tempBytes: message.resource.tempBytes,
    ...(message.resource.currentModule ? { currentModule: message.resource.currentModule } : {}),
    cleanupState: message.resource.cleanupState
  };
}

function processAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return !(error && typeof error === "object" && "code" in error && error.code === "ESRCH"); }
}

export function workerEntryPath(): string {
  const managerPath = fileURLToPath(import.meta.url);
  const adjacent = resolve(dirname(managerPath), managerPath.endsWith(".ts") ? "ScanWorkerMain.ts" : "ScanWorkerMain.js");
  if (existsSync(adjacent)) return adjacent;
  throw new WorkerGovernanceError("STARTUP_FAILURE", "Worker entry module is unavailable beside the worker manager runtime.");
}

function secretEnvelopePayload(request: DashboardScanCreateRequest, vault: CredentialVault | undefined, resolvedAuth?: DashboardResolvedAuth): Record<string, unknown> {
  const summary: Record<string, unknown> = {
    hasSingleProfile: Boolean(request.authFile),
    hasAccountPair: Boolean(request.authAFile && request.authBFile),
    hasSavedCredentialProfile: Boolean(request.credentialProfileId),
    hasSavedCredentialPair: Boolean(request.credentialProfileAId && request.credentialProfileBId),
    hasStudioAuthentication: Boolean(request.studio && request.studio.authentication.mode !== "public")
  };
  if (resolvedAuth) return {
    ...summary,
    safeSummary: resolvedAuth.safeSummary,
    ...(resolvedAuth.authProfile ? { authProfile: resolvedAuth.authProfile } : {}),
    ...(resolvedAuth.authProfileSet ? { authProfileSet: resolvedAuth.authProfileSet } : {})
  };
  if (!request.credentialProfileId && !request.credentialProfileAId && !request.credentialProfileBId && (!request.studio || request.studio.authentication.mode === "public")) return summary;
  if (!vault && request.studio?.authentication.mode !== "primary" && request.studio?.authentication.mode !== "account-pair") throw new Error("Credential vault is unavailable for worker secret delivery.");
  if (!vault) throw new Error("Credential vault is unavailable for Scan Studio authentication.");
  const resolved = resolveCredentialAuthForDashboardScan(vault, request);
  return {
    ...summary,
    safeSummary: resolved.safeSummary,
    ...(resolved.authProfile ? { authProfile: resolved.authProfile } : {}),
    ...(resolved.authProfileSet ? { authProfileSet: resolved.authProfileSet } : {})
  };
}

export function safeWorkerRequest(request: DashboardScanCreateRequest): DashboardScanCreateRequest {
  return {
    target: request.target,
    profile: request.profile,
    ...(request.projectId ? { projectId: request.projectId } : {}),
    ...(request.targetId ? { targetId: request.targetId } : {}),
    ...(request.authorizationDeclaration ? { authorizationDeclaration: request.authorizationDeclaration } : {}),
    ...(request.recoveryScope ? { recoveryScope: request.recoveryScope } : {}),
    ...(request.workflowRecoveryDigest ? { workflowRecoveryDigest: request.workflowRecoveryDigest } : {}),
    ...(request.studio ? { studio: { ...request.studio, authentication: { mode: "public" } } } : {})
  };
}

function secretEnvelopeMessage(input: { workerId: string; jobId: string; request: DashboardScanCreateRequest; workerSecret: string; workerGeneration: string; attempt: number; vault?: CredentialVault | undefined; resolvedAuth?: DashboardResolvedAuth | undefined }) {
  const sequence = 1;
  const expiresAt = new Date(Date.now() + 30_000).toISOString();
  const nonce = randomBytes(18).toString("base64url");
  const envelope = secretEnvelopePayload(input.request, input.vault, input.resolvedAuth);
  const body = {
    protocolVersion: workerProtocolVersion,
    type: "PROVIDE_SECRET_ENVELOPE" as const,
    workerId: input.workerId,
    jobId: input.jobId,
    sequence,
    expiresAt,
    nonce,
    attempt: input.attempt,
    workerGeneration: input.workerGeneration,
    envelope
  };
  return { ...body, hmac: envelopeHmac(input.workerSecret, body) };
}

export function executablePlanMessage(input: { workerId: string; jobId: string; workerSecret: string; workerGeneration: string; executablePlan: BoundExecutablePlan }) {
  const body = {
    protocolVersion: workerProtocolVersion,
    type: "PROVIDE_EXECUTABLE_PLAN" as const,
    workerId: input.workerId,
    jobId: input.jobId,
    sequence: 2,
    expiresAt: new Date(Date.now() + 30_000).toISOString(),
    nonce: randomBytes(18).toString("base64url"),
    workerGeneration: input.workerGeneration,
    payload: input.executablePlan.payload as unknown as Record<string, unknown>,
    contentDigest: input.executablePlan.contentDigest,
    binding: input.executablePlan.binding
  };
  return { ...body, hmac: envelopeHmac(input.workerSecret, body) };
}

export function mutationContractMessage(input: { workerId: string; jobId: string; contracts: readonly ControlledMutationContract[]; workerSecret: string }) {
  // Sign the schema-normalized payload that the recipient verifies, including defaults and key order.
  const body = { protocolVersion: workerProtocolVersion, type: "PROVIDE_MUTATION_CONTRACTS" as const, workerId: input.workerId, jobId: input.jobId, sequence: 3, expiresAt: new Date(Date.now() + 30_000).toISOString(), nonce: randomBytes(18).toString("base64url"), contracts: input.contracts.map((contract) => controlledMutationContractSchema.parse(contract)) };
  return { ...body, hmac: envelopeHmac(input.workerSecret, body) };
}

function recoveryMessage(input: { workerId: string; jobId: string; caseId: string; bundlePath: string; workerSecret: string }) {
  const body = { protocolVersion: workerProtocolVersion, type: "RECOVER_MUTATION" as const, workerId: input.workerId, jobId: input.jobId, sequence: 2, expiresAt: new Date(Date.now() + 30_000).toISOString(), nonce: randomBytes(18).toString("base64url"), caseId: input.caseId, bundlePath: input.bundlePath };
  return { ...body, hmac: envelopeHmac(input.workerSecret, body) };
}

function envelopeHmac(secret: string, body: Record<string, unknown>): string {
  return createHmac("sha256", secret).update(JSON.stringify(body)).digest("hex");
}
