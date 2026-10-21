import { assertAuthorizationWorkbenchBinding } from "../execution/AuthorizationWorkbenchBinding.js";
import { TargetRepository } from "../db/DashboardRepositories.js";
import { cleanupDigest } from "../recovery/CleanupAttemptLedger.js";
import { cleanupCredentialDigest } from "../recovery/CleanupAttemptBindings.js";
import { CleanupAttemptLedger } from "../recovery/CleanupAttemptLedger.js";
import { cleanupMac, verifyCleanupMac } from "./CleanupAttemptProtocol.js";
import { fork, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { OwnedTemporaryResource } from "../../core/storage/OwnedTemporaryResource.js";
import { verifiedWorkerExit } from "./WorkerLifecycleEvidence.js";
import { createWorkerBootstrap, confirmBootstrapIdentity } from "./WorkerBootstrap.js";
import { WorkerProcessCustody } from "./WorkerProcessCustody.js";
import { recoverWorkerLeases } from "./WorkerLeaseRecovery.js";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import { resolveCredentialAuthForDashboardScan, type DashboardResolvedAuth } from "../execution/ScanExecutionShared.js";
import { executableAuthenticationDigest, type BoundExecutablePlan } from "../execution/ExecutablePlanSnapshot.js";
import { parseWorkerMessage, workerProtocolVersion, type WorkerToApiMessage } from "./ScanWorkerProtocol.js";
import {
  controlledMutationContractSchema,
  type ControlledMutationContract
} from "../../core/offensive/ControlledMutationTypes.js";
import { workerRestorationGraceMs } from "../../core/engine/CleanupExecution.js";
import {
  evaluateWorkerLimits,
  loadWorkerGovernancePolicy,
  WorkerGovernanceError,
  WorkerGovernanceRepository,
  type WorkerFailureCategory,
  type WorkerGovernancePolicy,
  type WorkerResourceSnapshot
} from "./WorkerGovernance.js";

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

export interface WorkerRecoveryResult {
  workerId: string;
  caseId: string;
  cleanupOutcome: "ROLLBACK_VERIFIED" | "CLEANUP_FAILED";
  notes: string[];
  proof?: { sequence: number; entryDigest: string };
}

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
  logicalDone?: boolean;
  cancelRequested?: boolean;
}

export class ScanWorkerManager {
  private readonly active = new Map<string, ActiveWorker>();
  private readonly pendingWorkerCleanup = new Set<Promise<void>>();
  private readonly governance: WorkerGovernanceRepository;
  private shuttingDown = false;
  private readonly resources = new Map<string, OwnedTemporaryResource>();
  private readonly custody = new Map<ChildProcess, WorkerProcessCustody>();
  private readonly recoveries = new Map<string, { child: ChildProcess; workerId: string; cancelRequested?: boolean }>();
  private readonly exitTimers = new Map<ChildProcess, ReturnType<typeof setTimeout>>();
  private readonly retentionFailures: string[] = [];

  public constructor(
    private readonly database: DashboardDatabase,
    private readonly paths: DashboardPaths,
    private readonly vault?: CredentialVault
  ) {
    this.governance = new WorkerGovernanceRepository(database);
  }

  public async recoverExpiredLeases(): Promise<string[]> {
    return recoverWorkerLeases(this.database, this.paths);
  }

  public run(
    jobId: string,
    request: DashboardScanCreateRequest,
    handlers: WorkerRunHandlers,
    options: WorkerExecutionOptions
  ): Promise<WorkerRunResult> {
    if (this.retentionFailures.length)
      throw new WorkerGovernanceError(
        "STARTUP_FAILURE",
        "Worker custody remains unresolved; operator review is required."
      );
    if (this.shuttingDown)
      throw new WorkerGovernanceError(
        "STARTUP_FAILURE",
        "Worker manager shutdown has started; new jobs are not accepted."
      );
    if (this.active.has(jobId) || this.recoveries.has(jobId)) throw Error("WORKER_JOB_ALREADY_OWNED");
    this.assertCustodyResolved();
    this.verifyExecutionAuthentication(request, options);
    this.governance.assertDispatchAllowed();
    const workerId = randomUUID();
    const workerGeneration = randomUUID();
    const workerSecret = randomBytes(32).toString("base64url");
    const policy = loadWorkerGovernancePolicy(this.database);
    const resource = this.createResource(workerId, jobId, workerGeneration);
    const tempDir = resource.directory("tmp");
    let child: ChildProcess;
    try {
      child = fork(createWorkerBootstrap(resource, workerEntryPath()), [], {
        execArgv: [`--max-old-space-size=${Math.max(64, Math.floor((policy.memoryBytes / 1024 / 1024) * 0.75))}`],
        env: {
          ...process.env,
          ROUTECAIRN_WORKER_ID: workerId,
          ROUTECAIRN_WORKER_GENERATION: workerGeneration,
          ROUTECAIRN_WORKER_SESSION_SECRET: workerSecret,
          TMP: tempDir,
          TEMP: tempDir,
          TMPDIR: tempDir
        },
        detached: process.platform !== "win32",
        stdio: ["ignore", "ignore", "ignore", "ipc"]
      });
    } catch (error) {
      this.retainResource(resource, "FORK_FAILED");
      throw new WorkerGovernanceError(
        "STARTUP_FAILURE",
        error instanceof Error ? `Worker startup failed: ${error.message}` : "Worker startup failed."
      );
    }
    let resolveSettled: () => void = () => {};
    const settled = new Promise<void>((resolvePromise) => {
      resolveSettled = resolvePromise;
    });
    const active: ActiveWorker = {
      child,
      workerId,
      jobId,
      settled,
      resolveSettled,
      policy,
      startedAtMs: Date.now(),
      lastHeartbeatMs: Date.now(),
      tempDir
    };
    this.registerOwnedChild(child, tempDir, resource, workerSecret);
    this.active.set(jobId, active);
    try {
      this.database.transaction(() => {
        this.recordWorker(workerId, child.pid ?? null, policy);
        this.acquireLease(jobId, workerId);
      });
    } catch (error) {
      this.active.delete(jobId);
      child.once("error", () => {});
      child.kill("SIGKILL");
      throw error;
    }
    active.monitorTimer = setInterval(() => this.enforceActive(active), 1_000);
    active.monitorTimer.unref();

    return new Promise<WorkerRunResult>((resolveRun) => {
      let settled = false;
      let phase: "BOOTING" | "BOOTSTRAPPED" | "INITIALIZING" | "RUNNING" = "BOOTING";
      const settle = (result: WorkerRunResult) => {
        if (settled) return;
        settled = true;
        active.logicalDone = true;
        try {
          const current = this.active.get(jobId);
          clearTimeout(current?.cancellationTimer);
          clearTimeout(current?.forceKillTimer);
          clearInterval(current?.monitorTimer);
          const effective = current?.termination;
          if (effective && !result.failureCategory)
            result = {
              ...result,
              status:
                effective.category === "MANUAL_RESTART" || effective.category === "MANUAL_QUARANTINE"
                  ? "INTERRUPTED"
                  : "FAILED",
              failureCategory: effective.category,
              error: effective.reason
            };
          this.releaseLease(jobId, workerId, result.status);
          this.governance.finish(workerId, {
            state: result.status === "COMPLETED" ? "STOPPED" : "EXITED",
            ...(result.failureCategory ? { category: result.failureCategory } : {}),
            ...(result.error ? { reason: result.error } : {})
          });
          // Logical completion does not release custody of a live process.
        } catch {
          this.retentionFailures.push(workerId + ":TERMINAL_BOOKKEEPING_FAILED");
          result = {
            workerId,
            status: "INTERRUPTED",
            failureCategory: "IPC_FAILURE",
            error: "Worker terminal bookkeeping failed; retained evidence requires operator review."
          };
        } finally {
          this.gracefulWorkerExit(
            child,
            workerId,
            policy,
            phase === "RUNNING" &&
              (result.failureCategory === "PROTOCOL_FAILURE" || result.failureCategory === "IPC_FAILURE")
              ? policy.cleanupGraceMs
              : 0
          );
          resolveRun(result);
          resolveSettled();
        }
      };

      let messageChain = Promise.resolve();
      child.on("message", (raw: unknown) => {
        messageChain = messageChain
          .then(async () => {
            if (settled) return;
            try {
              const message = parseWorkerMessage(raw);
              if (message.workerId !== workerId) throw new Error("Worker ID mismatch.");
              if ("jobId" in message && message.jobId && message.jobId !== jobId)
                throw new Error("Worker job binding mismatch.");
              if (
                ["JOB_PLAN", "JOB_EVENT", "JOB_COMPLETED", "JOB_CANCELLED", "JOB_FAILED"].includes(message.type) &&
                phase !== "RUNNING"
              )
                throw Error("WORKER_RESULT_BEFORE_EXECUTION");
              switch (message.type) {
                case "WORKER_BOOTSTRAP_READY":
                  if (phase !== "BOOTING") throw Error("WORKER_BOOTSTRAP_REPLAY");
                  await this.bindProcess(child, workerId, workerGeneration);
                  if (settled) return;
                  if (active.cancelRequested || active.termination) {
                    settle({ workerId, status: "CANCELLED", error: "Cancelled before runtime activation." });
                    return;
                  }
                  phase = "BOOTSTRAPPED";
                  child.send({
                    protocolVersion: workerProtocolVersion,
                    type: "ACTIVATE_RUNTIME",
                    workerId,
                    workerGeneration
                  });
                  break;
                case "WORKER_READY":
                  if (
                    phase !== "BOOTSTRAPPED" ||
                    (message.processBirth !== this.custody.get(child)?.identity()?.birth &&
                      process.platform === "win32")
                  )
                    throw Error("WORKER_INITIALIZATION_REPLAY");
                  if (settled) return;
                  if (active.cancelRequested || active.termination) {
                    settle({ workerId, status: "CANCELLED", error: "Cancelled before worker initialization." });
                    return;
                  }
                  phase = "INITIALIZING";
                  child.send({
                    protocolVersion: workerProtocolVersion,
                    type: "INITIALIZE_JOB",
                    workerId,
                    jobId,
                    request: safeWorkerRequest(request),
                    paths: {
                      reportsDir: this.paths.reportsDir,
                      artifactsDir: this.paths.artifactsDir,
                      proofPacksDir: this.paths.proofPacksDir,
                      fingerprintKeyPath: this.paths.fingerprintKeyPath,
                      mutationJournalDir: this.paths.mutationJournalDir,
                      tempDir,
                      resourceProof: resource.workerProof()
                    }
                  });
                  break;
                case "JOB_ACCEPTED":
                  if (phase !== "INITIALIZING") throw Error("WORKER_ACCEPTANCE_OUT_OF_ORDER");
                  phase = "RUNNING";
                  if (active.cancelRequested || active.termination) {
                    settle({ workerId, status: "CANCELLED", error: "Cancelled before worker execution." });
                    return;
                  }
                  this.database.db
                    .prepare(
                      "UPDATE scan_workers SET state = 'RUNNING', current_job_id = ?, last_heartbeat_at = ? WHERE id = ?"
                    )
                    .run(jobId, nowIso(), workerId);
                  assertAuthorizationWorkbenchBinding(this.database, request);
                  child.send(
                    secretEnvelopeMessage({
                      workerId,
                      jobId,
                      request,
                      workerSecret,
                      workerGeneration,
                      attempt: 1,
                      vault: this.vault,
                      resolvedAuth: options.resolvedAuth
                    })
                  );
                  child.send(
                    executablePlanMessage({
                      workerId,
                      jobId,
                      workerSecret,
                      workerGeneration,
                      executablePlan: options.executablePlan
                    })
                  );
                  if (options.contracts?.length)
                    child.send(
                      mutationContractMessage({ workerId, jobId, contracts: options.contracts, workerSecret })
                    );
                  child.send({ protocolVersion: workerProtocolVersion, type: "START_JOB", workerId, jobId });
                  break;
                case "JOB_HEARTBEAT":
                  active.lastHeartbeatMs = Date.now();
                  this.renewLease(jobId, workerId);
                  this.governance.heartbeat(
                    workerId,
                    heartbeatSnapshot(message),
                    active.processTreePids ?? (child.pid ? [child.pid] : [])
                  );
                  if (message.resource.sequence % 5 === 0) void this.custody.get(child)?.sample();
                  this.enforceSnapshot(active, heartbeatSnapshot(message));
                  handlers.onHeartbeat(message);
                  break;
                case "JOB_PLAN":
                  if (message.executionPlanBinding !== options.executablePlan.binding)
                    throw new Error("Worker executable plan binding mismatch.");
                  handlers.onPlan(message);
                  break;
                case "JOB_EVENT":
                  handlers.onEvent(message);
                  break;
                case "JOB_COMPLETED":
                  settle({
                    workerId,
                    status: "COMPLETED",
                    reportPath: message.reportPath,
                    markdownReportPath: message.markdownReportPath,
                    htmlReportPath: message.htmlReportPath
                  });
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
              settle({
                workerId,
                status: "INTERRUPTED",
                failureCategory: "PROTOCOL_FAILURE",
                error: error instanceof Error ? error.message : "Invalid worker protocol message."
              });
            }
          })
          .catch(() => {
            settle({
              workerId,
              status: "INTERRUPTED",
              failureCategory: "PROTOCOL_FAILURE",
              error: "Worker message processing failed."
            });
          });
      });

      child.on("exit", (code, signal) => {
        if (settled) return;
        const current = this.active.get(jobId);
        try {
          if (!current?.termination) this.governance.recordCrash();
        } catch {
          this.retentionFailures.push(workerId + ":CRASH_BOOKKEEPING_FAILED");
        }
        try {
          this.governance.finish(workerId, {
            state: "EXITED",
            ...(current?.termination
              ? { category: current.termination.category, reason: current.termination.reason }
              : {
                  category: "PROCESS_CRASH",
                  reason: `Worker exited before completion. code=${code ?? "none"} signal=${signal ?? "none"}`
                }),
            exitCode: code,
            exitSignal: signal
          });
        } catch {
          this.retentionFailures.push(workerId + ":EXIT_BOOKKEEPING_FAILED");
        }
        settle({
          workerId,
          status: "INTERRUPTED",
          failureCategory: current?.termination?.category ?? "PROCESS_CRASH",
          error:
            current?.termination?.reason ??
            `Worker exited before completion. code=${code ?? "none"} signal=${signal ?? "none"}`
        });
      });
      child.on("error", () => {
        if (settled) return;
        try {
          this.governance.recordCrash();
        } catch {
          this.retentionFailures.push(workerId + ":IPC_BOOKKEEPING_FAILED");
        }
        settle({
          workerId,
          status: "INTERRUPTED",
          failureCategory: "IPC_FAILURE",
          error: "Worker process or IPC failed; recovery may be required."
        });
      });
    });
  }

  public runRecovery(
    jobId: string,
    request: DashboardScanCreateRequest,
    caseId: string,
    bundlePath: string,
    attemptId: string
  ): Promise<WorkerRecoveryResult> {
    this.assertCustodyResolved();
    const ledger = CleanupAttemptLedger.for(this.database);
    ledger.owns(attemptId);
    const attempt = ledger.get(attemptId);
    if (
      !attempt ||
      attempt.job_id !== jobId ||
      attempt.case_id !== caseId ||
      ledger.history(attemptId).phase !== "AUTHORIZED"
    )
      throw Error("RECOVERY_ATTEMPT_BINDING_INVALID");
    if (this.shuttingDown)
      throw new WorkerGovernanceError(
        "STARTUP_FAILURE",
        "Worker manager shutdown has started; new recovery jobs are not accepted."
      );
    if (this.active.has(jobId) || this.recoveries.has(jobId)) throw Error("WORKER_JOB_ALREADY_OWNED");
    const workerId = randomUUID();
    const workerGeneration = randomUUID();
    const workerSecret = randomBytes(32).toString("base64url");
    const policy = loadWorkerGovernancePolicy(this.database);
    const recoveryStartedAt = Date.now();
    const resource = this.createResource(workerId, jobId, workerGeneration);
    const tempDir = resource.directory("tmp");
    try {
      ledger.append(attemptId, "WORKER_PENDING", { workerId, workerGeneration, resourceId: resource.id });
    } catch (error) {
      this.retainResource(resource, "ATTEMPT_LEDGER_FAILED_BEFORE_FORK");
      throw error;
    }
    let child: ChildProcess;
    try {
      child = fork(createWorkerBootstrap(resource, workerEntryPath()), [], {
        execArgv: [`--max-old-space-size=${Math.max(64, Math.floor((policy.memoryBytes / 1024 / 1024) * 0.75))}`],
        env: {
          ...process.env,
          ROUTECAIRN_WORKER_ID: workerId,
          ROUTECAIRN_WORKER_GENERATION: workerGeneration,
          ROUTECAIRN_WORKER_SESSION_SECRET: workerSecret,
          TMP: tempDir,
          TEMP: tempDir,
          TMPDIR: tempDir
        },
        detached: process.platform !== "win32",
        stdio: ["ignore", "ignore", "ignore", "ipc"]
      });
    } catch (error) {
      this.retainResource(resource, "FORK_FAILED");
      throw new WorkerGovernanceError(
        "STARTUP_FAILURE",
        error instanceof Error ? `Recovery worker startup failed: ${error.message}` : "Recovery worker startup failed."
      );
    }
    this.registerOwnedChild(child, tempDir, resource, workerSecret);
    this.recoveries.set(jobId, { child, workerId });
    try {
      this.database.transaction(() => {
        this.recordWorker(workerId, child.pid ?? null, policy);
        this.acquireRecoveryLease(jobId, workerId);
      });
    } catch (error) {
      this.recoveries.delete(jobId);
      child.once("error", () => {});
      child.kill("SIGKILL");
      throw error;
    }
    return new Promise<WorkerRecoveryResult>((resolveRecovery, rejectRecovery) => {
      let settled = false;
      let governanceTimer: ReturnType<typeof setTimeout> | undefined;
      const timeout = setTimeout(
        () => settle(undefined, new Error("Recovery worker exceeded the bounded cleanup timeout.")),
        recoveryTimeoutMs
      );
      timeout.unref();
      let phase: "BOOTING" | "BOOTSTRAPPED" | "INITIALIZING" | "RUNNING" = "BOOTING";
      const settle = (result?: WorkerRecoveryResult, error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        clearTimeout(governanceTimer);
        try {
          this.releaseRecoveryLease(jobId, workerId, result?.cleanupOutcome ?? "FAILED");
          this.governance.finish(workerId, {
            state: result?.cleanupOutcome === "ROLLBACK_VERIFIED" ? "STOPPED" : "EXITED",
            ...(error
              ? {
                  category: error.message.includes("timeout") ? "CLEANUP_TIMEOUT" : "PROCESS_CRASH",
                  reason: error.message
                }
              : {})
          });
        } catch {
          this.retentionFailures.push(workerId + ":RECOVERY_BOOKKEEPING_FAILED");
          error = new Error("Recovery bookkeeping failed; operator review is required.");
        } finally {
          this.gracefulWorkerExit(
            child,
            workerId,
            policy,
            error && phase === "RUNNING" ? Math.max(0, recoveryStartedAt + recoveryTimeoutMs - Date.now()) : 0
          );
          if (error) rejectRecovery(error);
          else resolveRecovery(result!);
        }
      };
      let messageChain = Promise.resolve();
      child.on("message", (raw: unknown) => {
        messageChain = messageChain
          .then(async () => {
            if (settled) return;
            try {
              const message = parseWorkerMessage(raw);
              if (message.workerId !== workerId) throw new Error("Worker ID mismatch.");
              if ("jobId" in message && message.jobId && message.jobId !== jobId)
                throw Error("Recovery job binding mismatch.");
              if (message.type === "WORKER_BOOTSTRAP_READY") {
                if (phase !== "BOOTING") throw Error("RECOVERY_BOOTSTRAP_REPLAY");
                await this.bindProcess(child, workerId, workerGeneration);
                if (settled) return;
                if (this.recoveries.get(jobId)?.cancelRequested) {
                  settle(undefined, new Error("Recovery cancelled before activation."));
                  return;
                }
                phase = "BOOTSTRAPPED";
                child.send({
                  protocolVersion: workerProtocolVersion,
                  type: "ACTIVATE_RUNTIME",
                  workerId,
                  workerGeneration
                });
                return;
              }
              if (message.type === "WORKER_READY") {
                if (
                  phase !== "BOOTSTRAPPED" ||
                  (process.platform === "win32" && message.processBirth !== this.custody.get(child)?.identity()?.birth)
                )
                  throw Error("RECOVERY_INITIALIZATION_REPLAY");
                if (settled) return;
                if (this.recoveries.get(jobId)?.cancelRequested) {
                  settle(undefined, new Error("Recovery cancelled before initialization."));
                  return;
                }
                ledger.append(attemptId, "WORKER_ACTIVATED", { workerId, workerGeneration, resourceId: resource.id });
                phase = "INITIALIZING";
                child.send({
                  protocolVersion: workerProtocolVersion,
                  type: "INITIALIZE_JOB",
                  workerId,
                  jobId,
                  request: safeWorkerRequest(request),
                  paths: {
                    reportsDir: this.paths.reportsDir,
                    artifactsDir: this.paths.artifactsDir,
                    proofPacksDir: this.paths.proofPacksDir,
                    fingerprintKeyPath: this.paths.fingerprintKeyPath,
                    mutationJournalDir: this.paths.mutationJournalDir,
                    tempDir,
                    resourceProof: resource.workerProof()
                  }
                });
                return;
              }
              if (message.type === "JOB_ACCEPTED") {
                if (phase !== "INITIALIZING") throw Error("RECOVERY_ACCEPTANCE_OUT_OF_ORDER");
                phase = "RUNNING";
                if (this.recoveries.get(jobId)?.cancelRequested) {
                  settle(undefined, new Error("Recovery cancelled before execution."));
                  return;
                }
                this.database.db
                  .prepare(
                    "UPDATE scan_workers SET state = 'RUNNING', last_heartbeat_at = ?, updated_at = ? WHERE id = ?"
                  )
                  .run(nowIso(), nowIso(), workerId);
                const envelope = this.database.transaction(() => {
                  const binding = JSON.parse(attempt.binding_json),
                    target = new TargetRepository(this.database).get(attempt.target_id);
                  if (
                    !target ||
                    target.organizationId !== attempt.organization_id ||
                    (attempt.kind === "WORKFLOW"
                      ? cleanupDigest([target.id, target.rowVersion, target.baseOrigin, target.approvedScope])
                      : createHash("sha256")
                          .update(`${target.id}:${target.rowVersion}:${target.baseOrigin}`)
                          .digest("hex")) !== binding.targetFingerprint
                  )
                    throw Error("RECOVERY_TARGET_CHANGED");
                  if (
                    cleanupCredentialDigest(this.vault, request, attempt.organization_id) !== binding.credentialDigest
                  )
                    throw Error("RECOVERY_CREDENTIAL_CHANGED");
                  return secretEnvelopeMessage({
                    workerId,
                    jobId,
                    request,
                    workerSecret,
                    workerGeneration,
                    attempt: 1,
                    vault: this.vault
                  });
                });
                ledger.append(attemptId, "DISPATCH_ARMED", { workerId, workerGeneration, resourceId: resource.id });
                child.send(envelope);
                child.send(
                  recoveryMessage({
                    workerId,
                    jobId,
                    caseId,
                    bundlePath,
                    workerSecret,
                    cleanupAttemptId: attemptId,
                    bundleDigest: JSON.parse(attempt.binding_json).bundleDigest
                  })
                );
                return;
              }
              if (message.type === "JOB_HEARTBEAT") {
                this.renewRecoveryLease(jobId, workerId);
                this.governance.heartbeat(workerId, heartbeatSnapshot(message), child.pid ? [child.pid] : []);
                const violation = evaluateWorkerLimits(heartbeatSnapshot(message), policy, recoveryStartedAt);
                if (violation && !governanceTimer) {
                  this.markStopping(workerId, violation.category, violation.reason);
                  if (child.connected)
                    child.send({
                      protocolVersion: workerProtocolVersion,
                      type: "CANCEL_JOB",
                      workerId,
                      jobId,
                      reason: violation.reason
                    });
                  governanceTimer = setTimeout(() => {
                    if (child.pid && child.exitCode === null) {
                      this.markForced(workerId, `${violation.reason} Recovery cleanup grace expired.`);
                      void this.terminateOwned(child);
                    }
                  }, policy.cleanupGraceMs);
                  governanceTimer.unref();
                }
                return;
              }
              if (message.type === "RECOVERY_REQUEST_GATE") {
                if (
                  phase !== "RUNNING" ||
                  message.attemptId !== attemptId ||
                  message.workerGeneration !== workerGeneration
                )
                  throw Error("RECOVERY_GATE_BINDING_INVALID");
                verifyCleanupMac(workerSecret, message);
                const capability = this.custody.get(child),
                  receipt = capability?.receipt();
                if (
                  !capability ||
                  !receipt ||
                  receipt.rootClosed ||
                  (receipt.issues as unknown[]).length ||
                  (process.platform === "win32" && !receipt.job) ||
                  (receipt.job as { failure?: unknown } | undefined)?.failure
                )
                  throw Error("RECOVERY_CUSTODY_UNKNOWN");
                resource.assertOwned();
                ledger.gate(attemptId, message.ordinal);
                const body = { ...message, type: "RECOVERY_REQUEST_ACK" as const };
                const { hmac: _old, ...unsigned } = body;
                child.send({ ...unsigned, hmac: cleanupMac(workerSecret, unsigned) });
                return;
              }
              if (message.type === "JOB_MUTATION_RECOVERY") {
                if (phase !== "RUNNING") throw Error("RECOVERY_RESULT_BEFORE_EXECUTION");
                if (message.jobId !== jobId || message.caseId !== caseId)
                  throw new Error("Recovery result binding mismatch.");
                if (message.attemptId !== attemptId || message.workerGeneration !== workerGeneration)
                  throw Error("RECOVERY_RESULT_ATTEMPT_MISMATCH");
                verifyCleanupMac(workerSecret, message);
                ledger.append(attemptId, "RESULT_RECEIVED", {
                  cleanupOutcome: message.cleanupOutcome,
                  ...(message.proof ? { proof: message.proof } : {})
                });
                settle({
                  workerId,
                  caseId: message.caseId,
                  cleanupOutcome: message.cleanupOutcome,
                  notes: message.notes,
                  ...(message.proof ? { proof: message.proof } : {})
                });
                return;
              }
              if (message.type === "WORKER_ERROR") {
                settle(undefined, new Error(message.error));
                return;
              }
              if (message.type === "WORKER_SHUTDOWN") {
                settle(undefined, new Error("Recovery worker shut down before cleanup result."));
              }
            } catch (error) {
              settle(undefined, error instanceof Error ? error : new Error("Invalid worker recovery message."));
            }
          })
          .catch(() => settle(undefined, new Error("Recovery message processing failed.")));
      });
      child.on("exit", (code, signal) =>
        settle(
          undefined,
          new Error(`Recovery worker exited before completion. code=${code ?? "none"} signal=${signal ?? "none"}`)
        )
      );
      child.on("error", () => settle(undefined, new Error("Recovery worker process or IPC failed.")));
    });
  }

  public cancel(jobId: string): void {
    const active = this.active.get(jobId);
    if (!active || active.cancellationTimer || active.logicalDone) return;
    active.cancelRequested = true;
    if (active.child.connected)
      active.child.send(
        {
          protocolVersion: workerProtocolVersion,
          type: "CANCEL_JOB",
          workerId: active.workerId,
          jobId,
          reason: "Operator cancellation requested."
        },
        () => {}
      );
    active.cancellationTimer = setTimeout(() => {
      const current = this.active.get(jobId);
      if (current && !current.child.killed && current.child.pid) {
        this.markForced(current.workerId, "Cancellation grace expired; process tree was forcibly terminated.");
        void this.terminateOwned(current.child);
      }
    }, workerRestorationGraceMs);
    active.cancellationTimer.unref();
  }

  public async shutdown(): Promise<void> {
    this.shuttingDown = true;
    const activeRuns = [...this.active.values()];
    for (const jobId of this.active.keys()) this.cancel(jobId);
    for (const [jobId, recovery] of this.recoveries) {
      recovery.cancelRequested = true;
      if (recovery.child.connected)
        recovery.child.send(
          {
            protocolVersion: workerProtocolVersion,
            type: "CANCEL_JOB",
            workerId: recovery.workerId,
            jobId,
            reason: "Worker manager shutdown."
          },
          () => {}
        );
    }
    await Promise.all(activeRuns.map((active) => active.settled));
    await this.drainCompletedWorkers();
  }

  public async drainCompletedWorkers(): Promise<void> {
    while (this.pendingWorkerCleanup.size > 0) await Promise.all([...this.pendingWorkerCleanup]);
    if (this.retentionFailures.length) throw Error("WORKER_RETENTION_UNKNOWN:" + this.retentionFailures.join(","));
  }

  public diagnostics() {
    const unresolved = this.hasUnresolvedCustody() || this.retentionFailures.length > 0;
    const cleanupAttemptQuarantine = CleanupAttemptLedger.for(this.database).unresolved();
    return {
      ...this.governance.fleet(),
      ...(cleanupAttemptQuarantine ? { dispatchState: "QUARANTINED" as const, cleanupAttemptQuarantine: true } : {}),
      ...(unresolved ? { dispatchState: "QUARANTINED" as const, custodyQuarantine: true } : {}),
      ownedResourceIds: [...this.resources.values()].map((resource) => resource.id),
      resources: this.database.db
        .prepare(
          "SELECT resource_id, worker_id, job_id, state, evidence_json, updated_at FROM worker_resources ORDER BY created_at DESC LIMIT 100"
        )
        .all(),
      retentionFailures: [...this.retentionFailures]
    };
  }

  public restartWorker(workerId: string): void {
    const active = [...this.active.values()].find((entry) => entry.workerId === workerId);
    if (!active) throw new Error("Worker is not active; the next job already receives a fresh job-scoped worker.");
    this.requestTermination(
      active,
      "MANUAL_RESTART",
      "Operator requested a graceful worker restart. The job will be interrupted and partial evidence retained."
    );
  }

  public quarantineWorker(workerId: string, reason: string): void {
    this.governance.quarantineWorker(workerId, reason);
    const active = [...this.active.values()].find((entry) => entry.workerId === workerId);
    if (active) this.requestTermination(active, "MANUAL_QUARANTINE", `Worker quarantined by operator: ${reason}`);
  }

  public releaseWorker(workerId: string): void {
    this.governance.releaseWorker(workerId);
  }

  public quarantineFleet(reason: string): void {
    this.governance.setFleetQuarantine(true, reason);
  }
  public releaseFleet(): void {
    this.assertCustodyResolved();
    if (this.retentionFailures.length)
      throw new WorkerGovernanceError(
        "STARTUP_FAILURE",
        "WORKER_CUSTODY_REVIEW_REQUIRED: review retained evidence and restart the supervisor before releasing dispatch."
      );
    this.governance.resetCrashLoop();
  }

  private verifyExecutionAuthentication(request: DashboardScanCreateRequest, options: WorkerExecutionOptions): void {
    if (executableAuthenticationDigest(options.resolvedAuth) !== options.executablePlan.payload.authenticationDigest)
      throw new Error("EXECUTABLE_PLAN_AUTH_BINDING_MISMATCH");
    const studioAuth = request.studio?.authentication;
    const studioSaved =
      studioAuth?.mode === "primary"
        ? studioAuth.primary.source === "saved"
        : studioAuth?.mode === "account-pair"
          ? studioAuth.accountA.source === "saved" || studioAuth.accountB.source === "saved"
          : false;
    const savedCredentialRequested = Boolean(
      request.credentialProfileId || request.credentialProfileAId || request.credentialProfileBId || studioSaved
    );
    if (!savedCredentialRequested) return;
    if (!this.vault) throw new Error("EXECUTABLE_PLAN_AUTH_SOURCE_UNAVAILABLE");
    const current = resolveCredentialAuthForDashboardScan(this.vault, request);
    if (executableAuthenticationDigest(current) !== options.executablePlan.payload.authenticationDigest)
      throw new Error("EXECUTABLE_PLAN_AUTH_SOURCE_CHANGED");
  }

  private recordWorker(workerId: string, pid: number | null, policy: WorkerGovernancePolicy): void {
    this.database.db
      .prepare(
        "INSERT INTO scan_workers (id, process_id, state, started_at, last_heartbeat_at, version, governance_policy_json, cleanup_state, updated_at) VALUES (?, ?, 'STARTING', ?, ?, ?, ?, 'UNKNOWN', ?)"
      )
      .run(workerId, pid, nowIso(), nowIso(), "2", JSON.stringify(policy), nowIso());
  }

  private enforceSnapshot(active: ActiveWorker, snapshot: WorkerResourceSnapshot): void {
    const violation = evaluateWorkerLimits(snapshot, active.policy, active.startedAtMs);
    if (violation) this.requestTermination(active, violation.category, violation.reason);
  }

  private enforceActive(active: ActiveWorker): void {
    if (active.termination) return;
    const now = Date.now();
    if (now - active.startedAtMs > active.policy.wallClockMs)
      this.requestTermination(
        active,
        "WALL_CLOCK_LIMIT",
        `Worker wall-clock time exceeded ${active.policy.wallClockMs} ms.`
      );
    else if (now - active.lastHeartbeatMs > active.policy.heartbeatTimeoutMs)
      this.requestTermination(
        active,
        "HEARTBEAT_TIMEOUT",
        `Worker heartbeat was stale for more than ${active.policy.heartbeatTimeoutMs} ms.`
      );
  }

  private markStopping(workerId: string, category: WorkerFailureCategory, reason: string): void {
    try {
      this.governance.markStopping(workerId, category, reason);
    } catch {
      this.retentionFailures.push(workerId + ":STOPPING_BOOKKEEPING_FAILED");
    }
  }

  private markForced(workerId: string, reason: string): void {
    try {
      this.governance.markForced(workerId, reason);
    } catch {
      this.retentionFailures.push(workerId + ":FORCED_BOOKKEEPING_FAILED");
    }
  }

  private requestTermination(active: ActiveWorker, category: WorkerFailureCategory, reason: string): void {
    if (active.termination) return;
    active.termination = { category, reason };
    this.markStopping(active.workerId, category, reason);
    if (active.child.connected)
      active.child.send(
        {
          protocolVersion: workerProtocolVersion,
          type: "CANCEL_JOB",
          workerId: active.workerId,
          jobId: active.jobId,
          reason
        },
        () => {}
      );
    active.forceKillTimer = setTimeout(() => {
      if (!active.child.pid || active.child.killed) return;
      this.markForced(active.workerId, `${reason} Graceful cleanup deadline expired.`);
      void this.terminateOwned(active.child);
    }, active.policy.cleanupGraceMs);
    active.forceKillTimer.unref();
  }

  private gracefulWorkerExit(
    child: ChildProcess,
    workerId: string,
    policy: WorkerGovernancePolicy,
    restorationRemainingMs = 0
  ): void {
    if (child.connected) child.send({ protocolVersion: workerProtocolVersion, type: "SHUTDOWN", workerId }, () => {});
    const timer = setTimeout(
      () => {
        if (!child.pid || child.killed || child.exitCode !== null || child.signalCode !== null) return;
        if (this.database.db.open)
          this.markForced(workerId, "Worker did not exit after terminal result; process tree was terminated.");
        void this.terminateOwned(child);
      },
      Math.max(policy.forceKillGraceMs, restorationRemainingMs)
    );
    timer.unref();
    this.exitTimers.set(child, timer);
    if (child.exitCode !== null || child.signalCode !== null) {
      clearTimeout(timer);
      this.exitTimers.delete(child);
    }
  }

  private createResource(workerId: string, jobId: string, generation: string): OwnedTemporaryResource {
    const installation = this.database.db
      .prepare("SELECT value FROM dashboard_meta WHERE key = 'installation_id'")
      .get() as { value: string };
    const resource = OwnedTemporaryResource.create(this.paths.workersDir, {
      installationId: installation.value,
      workerId,
      jobId,
      generation
    });
    try {
      resource.directory("tmp");
      this.database.db
        .prepare(
          "INSERT INTO worker_resources (resource_id, worker_id, job_id, generation, resource_receipt_json, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'CREATED', ?, ?)"
        )
        .run(resource.id, workerId, jobId, generation, JSON.stringify(resource.receipt()), nowIso(), nowIso());
      this.resources.set(resource.root, resource);
      return resource;
    } catch (error) {
      resource.retain("LEDGER_INSERT_FAILED");
      throw error;
    }
  }

  private recordCustodyLoss(resource: OwnedTemporaryResource, custody: WorkerProcessCustody): void {
    // Quarantine is synchronous with observed custody loss, before cooperative
    // cleanup or root exit. The ledger survives a supervisor restart.
    this.retentionFailures.push(resource.id + ":NATIVE_CUSTODY_LOST");
    try {
      this.database.transaction(() => {
        this.governance.setFleetQuarantine(
          true,
          "Native worker custody is UNKNOWN; retained evidence requires operator resolution."
        );
        this.database.db
          .prepare(
            "UPDATE worker_resources SET state = 'UNKNOWN_RETAINED', evidence_json = ?, updated_at = ? WHERE resource_id = ?"
          )
          .run(
            JSON.stringify({ phase: "CUSTODY_LOST_ROOT_MAY_BE_LIVE", custody: custody.receipt() }),
            nowIso(),
            resource.id
          );
      });
    } catch {
      this.retentionFailures.push(resource.id + ":QUARANTINE_PERSISTENCE_FAILED");
      try {
        this.database.db
          .prepare(
            "UPDATE worker_resources SET state = 'UNKNOWN_RETAINED', evidence_json = ?, updated_at = ? WHERE resource_id = ?"
          )
          .run(
            JSON.stringify({ phase: "CUSTODY_LOST_QUARANTINE_WRITE_FAILED", custody: custody.receipt() }),
            nowIso(),
            resource.id
          );
      } catch {
        this.retentionFailures.push(resource.id + ":UNKNOWN_LEDGER_WRITE_FAILED");
      }
    }
  }

  private hasUnresolvedCustody(): boolean {
    const rows = this.database.db
      .prepare(
        "SELECT resource_id, state FROM worker_resources WHERE state IN ('CREATED', 'RUNNING', 'DRAINING', 'UNKNOWN_RETAINED')"
      )
      .all() as { resource_id: string; state: string }[];
    const owned = new Set<string>([...this.resources.values()].map((resource) => resource.id));
    // Even if all writes fail, a restarted manager cannot adopt a nonterminal
    // historical resource as proof of resolved custody or dispatch authority.
    return rows.some((row) => row.state === "UNKNOWN_RETAINED" || !owned.has(row.resource_id));
  }

  private assertCustodyResolved(): void {
    if (CleanupAttemptLedger.for(this.database).unresolved())
      throw new WorkerGovernanceError(
        "STARTUP_FAILURE",
        "CLEANUP_ATTEMPT_REVIEW_REQUIRED: an outcome is UNKNOWN; dispatch and release remain blocked."
      );
    if (this.hasUnresolvedCustody() || this.retentionFailures.length)
      throw new WorkerGovernanceError(
        "STARTUP_FAILURE",
        "WORKER_CUSTODY_REVIEW_REQUIRED: native custody remains UNKNOWN; dispatch and release require operator resolution."
      );
  }

  private retainResource(resource: OwnedTemporaryResource, reason: string, custody?: WorkerProcessCustody): void {
    const receipt: Record<string, unknown> = {
      ...resource.retain(reason),
      ...(custody ? { custody: custody.receipt() } : {})
    };
    if (
      custody &&
      ((custody.receipt().issues as string[]).length ||
        (custody.receipt().job as Record<string, unknown> | undefined)?.failure)
    )
      receipt.state = "UNKNOWN_RETAINED";
    if (receipt.state === "UNKNOWN_RETAINED") this.retentionFailures.push(resource.id);
    if (this.database.db.open)
      this.database.db
        .prepare("UPDATE worker_resources SET state = ?, evidence_json = ?, updated_at = ? WHERE resource_id = ?")
        .run(receipt.state, JSON.stringify(receipt), nowIso(), resource.id);
    else this.retentionFailures.push(resource.id + ":DATABASE_CLOSED");
    if (receipt.state === "UNKNOWN_RETAINED" && this.database.db.open) {
      try {
        this.governance.setFleetQuarantine(
          true,
          "Worker resource custody is unresolved. Review retained evidence before releasing dispatch."
        );
      } catch {
        this.retentionFailures.push(resource.id + ":QUARANTINE_WRITE_FAILED");
      }
    }
  }

  private resourceForChild(workerId: string): OwnedTemporaryResource {
    const resource = [...this.resources.values()].find((value) => value.binding.workerId === workerId);
    if (!resource) throw Error("WORKER_RESOURCE_CAPABILITY_MISSING");
    return resource;
  }

  private async bindProcess(child: ChildProcess, workerId: string, generation: string): Promise<void> {
    const custody = this.custody.get(child);
    if (!custody) throw Error("WORKER_PROCESS_UNOWNED");
    const birth = await confirmBootstrapIdentity(
      child,
      workerId,
      generation,
      this.resourceForChild(workerId).directory("tmp")
    );
    await custody.bind(birth);
    this.database.db
      .prepare(
        "UPDATE worker_resources SET state = 'RUNNING', process_identity_json = ?, updated_at = ? WHERE worker_id = ?"
      )
      .run(JSON.stringify(custody.identity()), nowIso(), workerId);
  }

  private async terminateOwned(child: ChildProcess): Promise<void> {
    const custody = this.custody.get(child);
    if (!custody) {
      this.retentionFailures.push("PROCESS_CUSTODY_MISSING");
      return;
    }
    try {
      await custody.terminate();
    } catch {
      this.retentionFailures.push("PROCESS_TERMINATION_UNKNOWN");
    }
  }

  private registerOwnedChild(
    child: ChildProcess,
    tempDir: string,
    resource: OwnedTemporaryResource,
    secret: string
  ): void {
    try {
      this.scheduleTempCleanup(child, tempDir, secret);
    } catch (error) {
      child.once("error", () => {});
      const retention = new WorkerProcessCustody(child, tempDir).exited
        .then(() => this.retainResource(resource, "POST_FORK_REGISTRATION_FAILED"))
        .catch(() => {
          this.retentionFailures.push(resource.id);
        })
        .finally(() => {
          this.pendingWorkerCleanup.delete(retention);
          this.resources.delete(resource.root);
        });
      this.pendingWorkerCleanup.add(retention);
      child.kill("SIGKILL");
      throw error;
    }
  }

  private scheduleTempCleanup(child: ChildProcess, tempDir: string, secret?: string): void {
    const resource = this.resources.get(dirname(resolve(tempDir)));
    if (!resource || resource.directory("tmp") !== resolve(tempDir) || this.custody.has(child))
      throw Error("WORKER_TEMP_RESOURCE_UNOWNED");
    const custody = new WorkerProcessCustody(child, tempDir, () => {
      this.recordCustodyLoss(resource, custody);
      const active = this.active.get(resource.binding.jobId!);
      if (active && !active.logicalDone)
        this.requestTermination(
          active,
          "IPC_FAILURE",
          "Native worker custody was lost; cooperative cleanup requested."
        );
      const recovery = this.recoveries.get(resource.binding.jobId!);
      if (recovery?.child.connected)
        recovery.child.send(
          {
            protocolVersion: workerProtocolVersion,
            type: "CANCEL_JOB",
            workerId: recovery.workerId,
            jobId: resource.binding.jobId!,
            reason: "Native custody was lost."
          },
          () => {}
        );
    });
    this.custody.set(child, custody);
    const cleanup = custody.exited
      .then(async () => {
        clearTimeout(this.exitTimers.get(child));
        this.exitTimers.delete(child);
        const voluntaryExit = Boolean(secret && verifiedWorkerExit(resource, secret));
        try {
          this.database.db
            .prepare(
              "UPDATE worker_resources SET state = CASE WHEN state = 'UNKNOWN_RETAINED' THEN state ELSE 'DRAINING' END, evidence_json = ?, updated_at = ? WHERE resource_id = ?"
            )
            .run(
              JSON.stringify({ phase: "ROOT_CLOSED_DRAINING_JOB", voluntaryExit, custody: custody.receipt() }),
              nowIso(),
              resource.id
            );
        } catch {
          this.retentionFailures.push(resource.id + ":DRAINING_LEDGER_WRITE_FAILED");
        }
        await custody.drain(voluntaryExit);
        this.retainResource(resource, "PROCESS_CLOSED", custody);
      })
      .catch(() => {
        this.retentionFailures.push(resource.id + ":RETENTION_FAILED");
      })
      .finally(() => {
        const workerId = resource.binding.workerId,
          jobId = resource.binding.jobId!;
        const active = this.active.get(jobId);
        if (active && active.workerId === workerId) {
          clearInterval(active.monitorTimer);
          clearTimeout(active.cancellationTimer);
          clearTimeout(active.forceKillTimer);
          this.active.delete(jobId);
        }
        if (this.recoveries.get(jobId)?.workerId === workerId) this.recoveries.delete(jobId);
        this.custody.delete(child);
        this.resources.delete(resource.root);
        this.pendingWorkerCleanup.delete(cleanup);
      });
    this.pendingWorkerCleanup.add(cleanup);
  }

  private acquireRecoveryLease(jobId: string, workerId: string): void {
    const now = Date.now();
    this.database.db
      .prepare(
        "INSERT INTO controlled_mutation_recovery_leases (job_id, worker_id, acquired_at, expires_at, last_renewed_at) VALUES (?, ?, ?, ?, ?)"
      )
      .run(
        jobId,
        workerId,
        new Date(now).toISOString(),
        new Date(now + leaseTtlMs).toISOString(),
        new Date(now).toISOString()
      );
  }
  private renewRecoveryLease(jobId: string, workerId: string): void {
    const now = Date.now();
    this.database.db
      .prepare(
        "UPDATE controlled_mutation_recovery_leases SET last_renewed_at = ?, expires_at = ? WHERE job_id = ? AND worker_id = ? AND released_at IS NULL"
      )
      .run(new Date(now).toISOString(), new Date(now + leaseTtlMs).toISOString(), jobId, workerId);
  }
  private releaseRecoveryLease(jobId: string, workerId: string, category: string): void {
    this.database.db
      .prepare(
        "UPDATE controlled_mutation_recovery_leases SET released_at = COALESCE(released_at, ?), release_category = COALESCE(release_category, ?) WHERE job_id = ? AND worker_id = ? AND released_at IS NULL"
      )
      .run(nowIso(), category, jobId, workerId);
  }

  private acquireLease(jobId: string, workerId: string): void {
    const now = Date.now();
    this.database.db
      .prepare(
        "INSERT INTO scan_job_leases (job_id, worker_id, acquired_at, expires_at, last_renewed_at, attempt_number) VALUES (?, ?, ?, ?, ?, COALESCE((SELECT MAX(attempt_number) + 1 FROM scan_job_leases WHERE job_id = ?), 1))"
      )
      .run(
        jobId,
        workerId,
        new Date(now).toISOString(),
        new Date(now + leaseTtlMs).toISOString(),
        new Date(now).toISOString(),
        jobId
      );
  }

  private renewLease(jobId: string, workerId: string): void {
    const now = Date.now();
    this.database.db
      .prepare("UPDATE scan_workers SET last_heartbeat_at = ? WHERE id = ?")
      .run(new Date(now).toISOString(), workerId);
    this.database.db
      .prepare(
        "UPDATE scan_job_leases SET last_renewed_at = ?, expires_at = ? WHERE job_id = ? AND worker_id = ? AND released_at IS NULL"
      )
      .run(new Date(now).toISOString(), new Date(now + leaseTtlMs).toISOString(), jobId, workerId);
  }

  private releaseLease(jobId: string, workerId: string, category: string): void {
    this.database.db
      .prepare(
        "UPDATE scan_job_leases SET released_at = COALESCE(released_at, ?), release_category = COALESCE(release_category, ?) WHERE job_id = ? AND worker_id = ? AND released_at IS NULL"
      )
      .run(nowIso(), category, jobId, workerId);
  }
}

function reportPaths(message: {
  reportPath?: string | undefined;
  markdownReportPath?: string | undefined;
  htmlReportPath?: string | undefined;
}): Pick<WorkerRunResult, "reportPath" | "markdownReportPath" | "htmlReportPath"> {
  return {
    ...(message.reportPath ? { reportPath: message.reportPath } : {}),
    ...(message.markdownReportPath ? { markdownReportPath: message.markdownReportPath } : {}),
    ...(message.htmlReportPath ? { htmlReportPath: message.htmlReportPath } : {})
  };
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

export function workerEntryPath(): string {
  const managerPath = fileURLToPath(import.meta.url);
  const adjacent = resolve(
    dirname(managerPath),
    managerPath.endsWith(".ts") ? "ScanWorkerMain.ts" : "ScanWorkerMain.js"
  );
  if (existsSync(adjacent)) return adjacent;
  throw new WorkerGovernanceError(
    "STARTUP_FAILURE",
    "Worker entry module is unavailable beside the worker manager runtime."
  );
}

function secretEnvelopePayload(
  request: DashboardScanCreateRequest,
  vault: CredentialVault | undefined,
  resolvedAuth?: DashboardResolvedAuth
): Record<string, unknown> {
  const summary: Record<string, unknown> = {
    hasSingleProfile: Boolean(request.authFile),
    hasAccountPair: Boolean(request.authAFile && request.authBFile),
    hasSavedCredentialProfile: Boolean(request.credentialProfileId),
    hasSavedCredentialPair: Boolean(request.credentialProfileAId && request.credentialProfileBId),
    hasStudioAuthentication: Boolean(request.studio && request.studio.authentication.mode !== "public")
  };
  if (resolvedAuth)
    return {
      ...summary,
      safeSummary: resolvedAuth.safeSummary,
      ...(resolvedAuth.authProfile ? { authProfile: resolvedAuth.authProfile } : {}),
      ...(resolvedAuth.authProfileSet ? { authProfileSet: resolvedAuth.authProfileSet } : {}),
      ...(resolvedAuth.actorProfiles
        ? {
            actorProfiles: resolvedAuth.actorProfiles,
            ...(resolvedAuth.actorBindingKey ? { actorBindingKey: resolvedAuth.actorBindingKey } : {})
          }
        : {})
    };
  if (
    !request.credentialProfileId &&
    !request.credentialProfileAId &&
    !request.credentialProfileBId &&
    (!request.studio || request.studio.authentication.mode === "public")
  )
    return summary;
  if (
    !vault &&
    request.studio?.authentication.mode !== "primary" &&
    request.studio?.authentication.mode !== "account-pair"
  )
    throw new Error("Credential vault is unavailable for worker secret delivery.");
  if (!vault) throw new Error("Credential vault is unavailable for Scan Studio authentication.");
  const resolved = resolveCredentialAuthForDashboardScan(vault, request);
  return {
    ...summary,
    safeSummary: resolved.safeSummary,
    ...(resolved.authProfile ? { authProfile: resolved.authProfile } : {}),
    ...(resolved.authProfileSet ? { authProfileSet: resolved.authProfileSet } : {}),
    ...(resolved.actorProfiles
      ? {
          actorProfiles: resolved.actorProfiles,
          ...(resolved.actorBindingKey ? { actorBindingKey: resolved.actorBindingKey } : {})
        }
      : {})
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

function secretEnvelopeMessage(input: {
  workerId: string;
  jobId: string;
  request: DashboardScanCreateRequest;
  workerSecret: string;
  workerGeneration: string;
  attempt: number;
  vault?: CredentialVault | undefined;
  resolvedAuth?: DashboardResolvedAuth | undefined;
}) {
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

export function executablePlanMessage(input: {
  workerId: string;
  jobId: string;
  workerSecret: string;
  workerGeneration: string;
  executablePlan: BoundExecutablePlan;
}) {
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

export function mutationContractMessage(input: {
  workerId: string;
  jobId: string;
  contracts: readonly ControlledMutationContract[];
  workerSecret: string;
}) {
  // Sign the schema-normalized payload that the recipient verifies, including defaults and key order.
  const body = {
    protocolVersion: workerProtocolVersion,
    type: "PROVIDE_MUTATION_CONTRACTS" as const,
    workerId: input.workerId,
    jobId: input.jobId,
    sequence: 3,
    expiresAt: new Date(Date.now() + 30_000).toISOString(),
    nonce: randomBytes(18).toString("base64url"),
    contracts: input.contracts.map((contract) => controlledMutationContractSchema.parse(contract))
  };
  return { ...body, hmac: envelopeHmac(input.workerSecret, body) };
}

function recoveryMessage(input: {
  workerId: string;
  jobId: string;
  caseId: string;
  bundlePath: string;
  workerSecret: string;
  cleanupAttemptId: string;
  bundleDigest: string;
}) {
  const body = {
    protocolVersion: workerProtocolVersion,
    type: "RECOVER_MUTATION" as const,
    workerId: input.workerId,
    jobId: input.jobId,
    sequence: 2,
    expiresAt: new Date(Date.now() + 30_000).toISOString(),
    nonce: randomBytes(18).toString("base64url"),
    caseId: input.caseId,
    cleanupAttemptId: input.cleanupAttemptId,
    bundleDigest: input.bundleDigest,
    bundlePath: input.bundlePath
  };
  return { ...body, hmac: envelopeHmac(input.workerSecret, body) };
}

function envelopeHmac(secret: string, body: Record<string, unknown>): string {
  return createHmac("sha256", secret).update(JSON.stringify(body)).digest("hex");
}
