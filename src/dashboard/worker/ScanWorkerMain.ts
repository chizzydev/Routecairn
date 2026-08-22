import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { createHmac, timingSafeEqual } from "node:crypto";
import { RouteCairnEngine } from "../../core/engine/RouteCairnEngine.js";
import type { ScanExecutionEvent, ScanEventSink } from "../../core/engine/ScanEvents.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { authProfileSchema, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { planSnapshot, resolveDashboardScanPlan } from "../execution/ScanExecutionShared.js";
import type { DashboardResolvedAuth } from "../execution/ScanExecutionShared.js";
import { parseApiMessage, workerProtocolVersion, type ApiToWorkerMessage, type WorkerToApiMessage } from "./ScanWorkerProtocol.js";

let workerId = process.env.ROUTECAIRN_WORKER_ID ?? "";
const workerGeneration = process.env.ROUTECAIRN_WORKER_GENERATION ?? "";
const workerSecret = process.env.ROUTECAIRN_WORKER_SESSION_SECRET ?? "";
let jobId = "";
let request: DashboardScanCreateRequest | undefined;
let paths: { reportsDir: string; artifactsDir: string; proofPacksDir: string; fingerprintKeyPath: string } | undefined;
let abortController: AbortController | undefined;
let acceptedEnvelope = false;
let acceptedEnvelopeAuth: DashboardResolvedAuth | undefined;
let acceptedMutationContracts: import("../../core/offensive/ControlledMutationTypes.js").ControlledMutationContract[] = [];
let lastSensitiveSequence = 0;

send({ protocolVersion: workerProtocolVersion, type: "WORKER_READY", workerId: requireWorkerId() });

const heartbeat = setInterval(() => {
  send({ protocolVersion: workerProtocolVersion, type: "JOB_HEARTBEAT", workerId: requireWorkerId(), ...(jobId ? { jobId } : {}), timestamp: new Date().toISOString() });
}, 1000);

process.on("message", (raw: unknown) => {
  void handleMessage(raw).catch((error: unknown) => {
    send({ protocolVersion: workerProtocolVersion, type: "WORKER_ERROR", workerId: requireWorkerId(), error: safeError(error) });
  });
});

process.on("disconnect", () => {
  clearInterval(heartbeat);
  abortController?.abort();
});

async function handleMessage(raw: unknown): Promise<void> {
  const message = parseApiMessage(raw);
  if (message.workerId !== requireWorkerId()) throw new Error("Worker ID mismatch.");
  switch (message.type) {
    case "INITIALIZE_JOB":
      initialize(message);
      break;
    case "PROVIDE_SECRET_ENVELOPE":
      if (message.jobId !== jobId) throw new Error("Secret envelope job mismatch.");
      validateSecretEnvelope(message);
      acceptedEnvelope = true;
      acceptedEnvelopeAuth = authFromEnvelope(message.envelope);
      break;
    case "PROVIDE_MUTATION_CONTRACTS":
      if (message.jobId !== jobId) throw new Error("Mutation contract job mismatch.");
      validateMutationContracts(message);
      acceptedMutationContracts = message.contracts;
      break;
    case "START_JOB":
      if (message.jobId !== jobId) throw new Error("Start job mismatch.");
      await startJob();
      break;
    case "CANCEL_JOB":
      if (message.jobId === jobId) abortController?.abort();
      break;
    case "SHUTDOWN":
      abortController?.abort();
      send({ protocolVersion: workerProtocolVersion, type: "WORKER_SHUTDOWN", workerId: requireWorkerId() });
      process.exit(0);
      break;
  }
}

function initialize(message: Extract<ApiToWorkerMessage, { type: "INITIALIZE_JOB" }>): void {
  jobId = message.jobId;
  request = message.request as unknown as DashboardScanCreateRequest;
  paths = message.paths;
  send({ protocolVersion: workerProtocolVersion, type: "JOB_ACCEPTED", workerId: requireWorkerId(), jobId });
}

async function startJob(): Promise<void> {
  if (!request || !paths) throw new Error("Worker job was not initialized.");
  if (!acceptedEnvelope) throw new Error("Worker refused to start without an authenticated job-bound secret envelope.");
  abortController = new AbortController();
  const outputDir = resolve(paths.reportsDir, jobId);
  mkdirSync(outputDir, { recursive: true });
  try {
    const resolved = await resolveDashboardScanPlan(request, acceptedEnvelopeAuth);
    send({
      protocolVersion: workerProtocolVersion,
      type: "JOB_PLAN",
      workerId: requireWorkerId(),
      jobId,
      planSnapshot: planSnapshot(resolved.plan, resolved.scope),
      modules: resolved.plan.modules.map((modulePlan) => ({ id: modulePlan.id, phase: modulePlan.phase })),
      evidenceLevel: resolved.plan.evidence.level
    });
    const sink: ScanEventSink = {
      emit: (event: ScanExecutionEvent) => {
        send({
          protocolVersion: workerProtocolVersion,
          type: "JOB_EVENT",
          workerId: requireWorkerId(),
          jobId,
          event: {
            type: event.type,
            message: event.message,
            ...(event.moduleId ? { moduleId: event.moduleId } : {}),
            metadata: event.metadata ?? {}
          }
        });
      }
    };
    const result = await new RouteCairnEngine().scan({
      target: request.target,
      scope: resolved.scope,
      config: resolved.config,
      plan: resolved.plan,
      outputDir,
      ...(resolved.authProfile ? { authProfile: resolved.authProfile } : {}),
      ...(resolved.authProfileSet ? { authProfileSet: resolved.authProfileSet } : {}),
      ...(acceptedMutationContracts.length > 0 ? { controlledMutationContracts: acceptedMutationContracts } : {}),
      eventSink: sink,
      abortSignal: abortController.signal
    });
    if (abortController.signal.aborted) {
      send({ protocolVersion: workerProtocolVersion, type: "JOB_CANCELLED", workerId: requireWorkerId(), jobId, summary: "Scan cancelled." });
      return;
    }
    send({
      protocolVersion: workerProtocolVersion,
      type: "JOB_COMPLETED",
      workerId: requireWorkerId(),
      jobId,
      reportPath: result.reportPath,
      markdownReportPath: result.markdownReportPath,
      htmlReportPath: result.htmlReportPath
    });
  } catch (error) {
    if (abortController.signal.aborted) {
      send({ protocolVersion: workerProtocolVersion, type: "JOB_CANCELLED", workerId: requireWorkerId(), jobId, summary: "Scan cancelled." });
      return;
    }
    send({ protocolVersion: workerProtocolVersion, type: "JOB_FAILED", workerId: requireWorkerId(), jobId, error: safeError(error) });
  }
}

function authFromEnvelope(envelope: Record<string, unknown>): DashboardResolvedAuth | undefined {
  const authProfile = envelope.authProfile ? authProfileSchema.parse(envelope.authProfile) : undefined;
  const authProfileSet = envelope.authProfileSet ? authProfileSetFromEnvelope(envelope.authProfileSet) : undefined;
  if (!authProfile && !authProfileSet) return { safeSummary: safeEnvelopeSummary(envelope) };
  return {
    ...(authProfile ? { authProfile } : {}),
    ...(authProfileSet ? { authProfileSet } : {}),
    safeSummary: safeEnvelopeSummary(envelope)
  };
}

function authProfileSetFromEnvelope(value: unknown): AuthProfileSet {
  const candidate = value as { accountA?: unknown; accountB?: unknown };
  return {
    accountA: authProfileSchema.parse(candidate.accountA) as AuthProfile,
    accountB: authProfileSchema.parse(candidate.accountB) as AuthProfile
  };
}

function safeEnvelopeSummary(envelope: Record<string, unknown>): Record<string, unknown> {
  return {
    hasSingleProfile: Boolean(envelope.hasSingleProfile),
    hasAccountPair: Boolean(envelope.hasAccountPair),
    hasSavedCredentialProfile: Boolean(envelope.hasSavedCredentialProfile),
    hasSavedCredentialPair: Boolean(envelope.hasSavedCredentialPair),
    hasStudioAuthentication: Boolean(envelope.hasStudioAuthentication),
    safeSummary: envelope.safeSummary
  };
}

function requireWorkerId(): string {
  if (!workerId) {
    workerId = process.env.ROUTECAIRN_WORKER_ID ?? "";
  }
  if (!workerId) throw new Error("Worker ID missing.");
  return workerId;
}

function validateSecretEnvelope(message: Extract<ApiToWorkerMessage, { type: "PROVIDE_SECRET_ENVELOPE" }>): void {
  if (!workerSecret || !workerGeneration) throw new Error("Worker IPC authentication was not initialized.");
  if (acceptedEnvelope) throw new Error("Duplicate secret envelope rejected.");
  if (abortController) throw new Error("Secret envelope received after scan start.");
  if (message.workerGeneration !== workerGeneration) throw new Error("Secret envelope generation mismatch.");
  if (Date.parse(message.expiresAt) < Date.now()) throw new Error("Expired secret envelope rejected.");
  if (message.sequence <= lastSensitiveSequence) throw new Error("Out-of-order secret envelope rejected.");
  const { hmac, ...body } = message;
  if (!constantEqual(hmac, createHmac("sha256", workerSecret).update(JSON.stringify(body)).digest("hex"))) throw new Error("Secret envelope authentication failed.");
  lastSensitiveSequence = message.sequence;
}

function validateMutationContracts(message: Extract<ApiToWorkerMessage, { type: "PROVIDE_MUTATION_CONTRACTS" }>): void {
  if (!workerSecret || !workerGeneration) throw new Error("Worker IPC authentication was not initialized.");
  if (abortController) throw new Error("Mutation contracts received after scan start.");
  if (message.sequence <= lastSensitiveSequence) throw new Error("Out-of-order mutation contract envelope rejected.");
  if (Date.parse(message.expiresAt) < Date.now()) throw new Error("Expired mutation contract envelope rejected.");
  const { hmac, ...body } = message;
  if (!constantEqual(hmac, createHmac("sha256", workerSecret).update(JSON.stringify(body)).digest("hex"))) throw new Error("Mutation contract envelope authentication failed.");
  lastSensitiveSequence = message.sequence;
}

function send(message: WorkerToApiMessage): void {
  process.send?.(message);
}

function safeError(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 800) : "Worker failure.";
}

function constantEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
