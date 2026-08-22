import { fork, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createHmac, randomBytes, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPaths } from "../services/DashboardPaths.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import { resolveCredentialAuthForDashboardScan } from "../execution/ScanExecutionShared.js";
import { parseWorkerMessage, workerProtocolVersion, type WorkerToApiMessage } from "./ScanWorkerProtocol.js";
import type { ControlledMutationContract } from "../../core/offensive/ControlledMutationTypes.js";
import { readMutationCleanupStatus } from "../../core/offensive/MutationCleanupStatus.js";

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
}

export interface WorkerMutationOptions { contracts: readonly ControlledMutationContract[] }

export interface WorkerRecoveryResult { workerId: string; caseId: string; cleanupOutcome: "ROLLBACK_VERIFIED" | "CLEANUP_FAILED"; notes: string[]; }

const leaseTtlMs = 30_000;
const recoveryTimeoutMs = 60_000;
const cancellationTimeoutMs = 5_000;

export class ScanWorkerManager {
  private readonly active = new Map<string, { child: ChildProcess; workerId: string; settled: Promise<void>; resolveSettled(): void }>();

  public constructor(private readonly database: DashboardDatabase, private readonly paths: DashboardPaths, private readonly vault?: CredentialVault) {}

  public async recoverExpiredLeases(): Promise<string[]> {
    const expired = this.database.db.prepare("SELECT job_id FROM scan_job_leases WHERE released_at IS NULL AND expires_at < ?").all(nowIso()) as Array<{ job_id: string }>;
    for (const row of expired) {
      const cleanupStatus = await readMutationCleanupStatus(this.paths.mutationJournalDir, this.paths.mutationJournalRegistryPath);
      const cleanupRequired = cleanupStatus.cleanupRequired > 0;
      this.database.transaction(() => {
        this.database.db.prepare("UPDATE scans SET status = 'INTERRUPTED', completed_at = ?, error_summary = ? WHERE id = ? AND status IN ('QUEUED','PLANNING','RUNNING','CANCEL_REQUESTED')").run(nowIso(), cleanupRequired ? "Worker lease expired while a controlled mutation cleanup obligation remains unresolved. Operator recovery is required before new mutations." : "Worker lease expired before the scan reached a terminal state.", row.job_id);
        this.database.db.prepare("INSERT INTO scan_events (id, seq, scan_id, event_type, safe_message, safe_metadata_json, created_at) SELECT ?, COALESCE(MAX(seq), 0) + 1, ?, ?, ?, ?, ? FROM scan_events WHERE scan_id = ?").run(randomUUID(), row.job_id, cleanupRequired ? "MUTATION_CLEANUP_REQUIRED" : "SCAN_INTERRUPTED", cleanupRequired ? "Worker lease expired; controlled mutation cleanup requires operator recovery." : "Worker lease expired before the scan reached a terminal state.", JSON.stringify({ cleanupRequired }), nowIso(), row.job_id);
        this.database.db.prepare("UPDATE scan_job_leases SET released_at = ?, release_category = 'EXPIRED' WHERE job_id = ? AND released_at IS NULL").run(nowIso(), row.job_id);
      });
    }
    return expired.map((row) => row.job_id);
  }

  public run(jobId: string, request: DashboardScanCreateRequest, handlers: WorkerRunHandlers, mutationOptions?: WorkerMutationOptions): Promise<WorkerRunResult> {
    const workerId = randomUUID();
    const workerGeneration = randomUUID();
    const workerSecret = randomBytes(32).toString("base64url");
    const child = fork(workerEntryPath(), [], {
      execArgv: workerEntryPath().endsWith(".ts") ? ["--import", "tsx"] : [],
      env: { ...process.env, ROUTECAIRN_WORKER_ID: workerId, ROUTECAIRN_WORKER_GENERATION: workerGeneration, ROUTECAIRN_WORKER_SESSION_SECRET: workerSecret },
      stdio: ["ignore", "ignore", "ignore", "ipc"]
    });
    let resolveSettled: () => void = () => {};
    const settled = new Promise<void>((resolvePromise) => {
      resolveSettled = resolvePromise;
    });
    this.active.set(jobId, { child, workerId, settled, resolveSettled });
    this.recordWorker(workerId, child.pid ?? null);
    this.acquireLease(jobId, workerId);

    return new Promise<WorkerRunResult>((resolveRun) => {
      let settled = false;
      const settle = (result: WorkerRunResult) => {
        if (settled) return;
        settled = true;
        try {
          this.releaseLease(jobId, result.status);
          this.database.db.prepare("UPDATE scan_workers SET state = ?, current_job_id = NULL, shutdown_at = COALESCE(shutdown_at, ?) WHERE id = ?").run(result.status === "COMPLETED" ? "STOPPED" : "EXITED", nowIso(), workerId);
          this.active.delete(jobId);
          if (!child.killed) child.kill();
          resolveRun(result);
        } finally {
          resolveSettled();
        }
      };

      child.on("message", (raw: unknown) => {
        try {
          const message = parseWorkerMessage(raw);
          if (message.workerId !== workerId) throw new Error("Worker ID mismatch.");
          switch (message.type) {
            case "WORKER_READY":
              child.send({ protocolVersion: workerProtocolVersion, type: "INITIALIZE_JOB", workerId, jobId, request: safeWorkerRequest(request), paths: { reportsDir: this.paths.reportsDir, artifactsDir: this.paths.artifactsDir, proofPacksDir: this.paths.proofPacksDir, fingerprintKeyPath: this.paths.fingerprintKeyPath, mutationJournalDir: this.paths.mutationJournalDir } });
              break;
            case "JOB_ACCEPTED":
              this.database.db.prepare("UPDATE scan_workers SET state = 'RUNNING', current_job_id = ?, last_heartbeat_at = ? WHERE id = ?").run(jobId, nowIso(), workerId);
              child.send(secretEnvelopeMessage({ workerId, jobId, request, workerSecret, workerGeneration, attempt: 1, vault: this.vault }));
              if (mutationOptions?.contracts.length) child.send(mutationContractMessage({ workerId, jobId, contracts: mutationOptions.contracts, workerSecret }));
              child.send({ protocolVersion: workerProtocolVersion, type: "START_JOB", workerId, jobId });
              break;
            case "JOB_HEARTBEAT":
              this.renewLease(jobId, workerId);
              handlers.onHeartbeat(message);
              break;
            case "JOB_PLAN":
              handlers.onPlan(message);
              break;
            case "JOB_EVENT":
              handlers.onEvent(message);
              break;
            case "JOB_COMPLETED":
              settle({ workerId, status: "COMPLETED", reportPath: message.reportPath, markdownReportPath: message.markdownReportPath, htmlReportPath: message.htmlReportPath });
              break;
            case "JOB_CANCELLED":
              settle({ workerId, status: "CANCELLED", error: message.summary });
              break;
            case "JOB_FAILED":
              settle({ workerId, status: "FAILED", error: message.error });
              break;
            case "WORKER_ERROR":
              settle({ workerId, status: "FAILED", error: message.error });
              break;
            case "WORKER_SHUTDOWN":
              settle({ workerId, status: "INTERRUPTED", error: "Worker shut down before terminal job result." });
              break;
          }
        } catch (error) {
          settle({ workerId, status: "INTERRUPTED", error: error instanceof Error ? error.message : "Invalid worker protocol message." });
        }
      });

      child.on("exit", (code, signal) => {
        settle({ workerId, status: "INTERRUPTED", error: `Worker exited before completion. code=${code ?? "none"} signal=${signal ?? "none"}` });
      });
    });
  }

  public runRecovery(jobId: string, request: DashboardScanCreateRequest, caseId: string, bundlePath: string): Promise<WorkerRecoveryResult> {
    const workerId = randomUUID();
    const workerGeneration = randomUUID();
    const workerSecret = randomBytes(32).toString("base64url");
    const child = fork(workerEntryPath(), [], { execArgv: workerEntryPath().endsWith(".ts") ? ["--import", "tsx"] : [], env: { ...process.env, ROUTECAIRN_WORKER_ID: workerId, ROUTECAIRN_WORKER_GENERATION: workerGeneration, ROUTECAIRN_WORKER_SESSION_SECRET: workerSecret }, stdio: ["ignore", "ignore", "ignore", "ipc"] });
    this.recordWorker(workerId, child.pid ?? null);
    this.acquireLease(jobId, workerId);
    return new Promise<WorkerRecoveryResult>((resolveRecovery, rejectRecovery) => {
      let settled = false;
      const timeout = setTimeout(() => settle(undefined, new Error("Recovery worker exceeded the bounded cleanup timeout.")), recoveryTimeoutMs);
      timeout.unref();
      const settle = (result?: WorkerRecoveryResult, error?: Error) => { if (settled) return; settled = true; clearTimeout(timeout); this.releaseLease(jobId, result?.cleanupOutcome ?? "FAILED"); this.database.db.prepare("UPDATE scan_workers SET state = ?, current_job_id = NULL, shutdown_at = ? WHERE id = ?").run(result?.cleanupOutcome === "ROLLBACK_VERIFIED" ? "STOPPED" : "EXITED", nowIso(), workerId); if (!child.killed) child.kill(); if (error) rejectRecovery(error); else resolveRecovery(result!); };
      child.on("message", (raw: unknown) => {
        try {
          const message = parseWorkerMessage(raw);
          if (message.workerId !== workerId) throw new Error("Worker ID mismatch.");
          if (message.type === "WORKER_READY") { child.send({ protocolVersion: workerProtocolVersion, type: "INITIALIZE_JOB", workerId, jobId, request: safeWorkerRequest(request), paths: { reportsDir: this.paths.reportsDir, artifactsDir: this.paths.artifactsDir, proofPacksDir: this.paths.proofPacksDir, fingerprintKeyPath: this.paths.fingerprintKeyPath, mutationJournalDir: this.paths.mutationJournalDir } }); return; }
          if (message.type === "JOB_ACCEPTED") { child.send(secretEnvelopeMessage({ workerId, jobId, request, workerSecret, workerGeneration, attempt: 1, vault: this.vault })); child.send(recoveryMessage({ workerId, jobId, caseId, bundlePath, workerSecret })); return; }
          if (message.type === "JOB_HEARTBEAT") { this.renewLease(jobId, workerId); return; }
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
    if (!active) return;
    active.child.send({ protocolVersion: workerProtocolVersion, type: "CANCEL_JOB", workerId: active.workerId, jobId });
    setTimeout(() => {
      const current = this.active.get(jobId);
      if (current && !current.child.killed) current.child.kill("SIGKILL");
    }, cancellationTimeoutMs).unref();
  }

  public async shutdown(): Promise<void> {
    const activeRuns = [...this.active.values()];
    for (const active of activeRuns) {
      active.child.send({ protocolVersion: workerProtocolVersion, type: "SHUTDOWN", workerId: active.workerId });
      active.child.kill();
    }
    await Promise.all(activeRuns.map((active) => active.settled));
  }

  private recordWorker(workerId: string, pid: number | null): void {
    this.database.db
      .prepare("INSERT INTO scan_workers (id, process_id, state, started_at, last_heartbeat_at, version) VALUES (?, ?, 'STARTING', ?, ?, ?)")
      .run(workerId, pid, nowIso(), nowIso(), "1");
  }

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

function workerEntryPath(): string {
  const built = resolve("dist", "dashboard", "worker", "ScanWorkerMain.js");
  if (existsSync(built)) return built;
  return resolve("src", "dashboard", "worker", "ScanWorkerMain.ts");
}

function secretEnvelopePayload(request: DashboardScanCreateRequest, vault: CredentialVault | undefined): Record<string, unknown> {
  const summary: Record<string, unknown> = {
    hasSingleProfile: Boolean(request.authFile),
    hasAccountPair: Boolean(request.authAFile && request.authBFile),
    hasSavedCredentialProfile: Boolean(request.credentialProfileId),
    hasSavedCredentialPair: Boolean(request.credentialProfileAId && request.credentialProfileBId),
    hasStudioAuthentication: Boolean(request.studio && request.studio.authentication.mode !== "public")
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
  if (!request.studio || request.studio.authentication.mode === "public") return request;
  return {
    ...request,
    studio: { ...request.studio, authentication: { mode: "public" } }
  };
}

function secretEnvelopeMessage(input: { workerId: string; jobId: string; request: DashboardScanCreateRequest; workerSecret: string; workerGeneration: string; attempt: number; vault?: CredentialVault | undefined }) {
  const sequence = 1;
  const expiresAt = new Date(Date.now() + 30_000).toISOString();
  const nonce = randomBytes(18).toString("base64url");
  const envelope = secretEnvelopePayload(input.request, input.vault);
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

function mutationContractMessage(input: { workerId: string; jobId: string; contracts: readonly ControlledMutationContract[]; workerSecret: string }) {
  const body = { protocolVersion: workerProtocolVersion, type: "PROVIDE_MUTATION_CONTRACTS" as const, workerId: input.workerId, jobId: input.jobId, sequence: 2, expiresAt: new Date(Date.now() + 30_000).toISOString(), nonce: randomBytes(18).toString("base64url"), contracts: [...input.contracts] };
  return { ...body, hmac: envelopeHmac(input.workerSecret, body) };
}

function recoveryMessage(input: { workerId: string; jobId: string; caseId: string; bundlePath: string; workerSecret: string }) {
  const body = { protocolVersion: workerProtocolVersion, type: "RECOVER_MUTATION" as const, workerId: input.workerId, jobId: input.jobId, sequence: 2, expiresAt: new Date(Date.now() + 30_000).toISOString(), nonce: randomBytes(18).toString("base64url"), caseId: input.caseId, bundlePath: input.bundlePath };
  return { ...body, hmac: envelopeHmac(input.workerSecret, body) };
}

function envelopeHmac(secret: string, body: Record<string, unknown>): string {
  return createHmac("sha256", secret).update(JSON.stringify(body)).digest("hex");
}
