import { mkdirSync } from "node:fs";
import { workerRestorationGraceMs } from "../../core/engine/CleanupExecution.js";
import { resolve } from "node:path";
import { createHmac, timingSafeEqual } from "node:crypto";
import { ScanContext } from "../../core/engine/ScanContext.js";
import { resolveRecoveryBundlePath } from "../../core/offensive/MutationRecoveryPath.js";
import { ControlledMutationExecutor } from "../../core/offensive/ControlledMutationExecutor.js";
import { MutationRecoveryVault } from "../../core/offensive/MutationRecoveryVault.js";
import type { WorkflowCheckpoint } from "../../core/offensive/WorkflowMutationCoordinator.js";
import { recoverWorkflow } from "../../core/offensive/WorkflowRecoveryExecutor.js";
import { recoveryOnlyPlan } from "../../core/offensive/RecoveryRequestBudget.js";
import type { MutationTransport } from "../../core/offensive/ControlledMutationTypes.js";
import { RouteCairnEngine } from "../../core/engine/RouteCairnEngine.js";
import type { ScanExecutionEvent, ScanEventSink } from "../../core/engine/ScanEvents.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { authProfileSchema, authHeadersForProfile, type AuthProfile } from "../../core/auth/AuthProfile.js";
import type { AuthProfileSet } from "../../core/auth/AuthProfileSet.js";
import { planSnapshot, resolveDashboardScanPlan } from "../execution/ScanExecutionShared.js";
import type { DashboardResolvedAuth } from "../execution/ScanExecutionShared.js";
import { assertExecutablePlanSourcesUnchanged, executableAuthenticationDigest, executablePlanContentDigest, parseExecutablePlanPayload, type BoundExecutablePlan } from "../execution/ExecutablePlanSnapshot.js";
import { parseApiMessage, workerProtocolVersion, type ApiToWorkerMessage, type WorkerToApiMessage } from "./ScanWorkerProtocol.js";

let workerId = process.env.ROUTECAIRN_WORKER_ID ?? "";
const workerGeneration = process.env.ROUTECAIRN_WORKER_GENERATION ?? "";
const workerSecret = process.env.ROUTECAIRN_WORKER_SESSION_SECRET ?? "";
let jobId = "";
let request: DashboardScanCreateRequest | undefined;
let paths: { reportsDir: string; artifactsDir: string; proofPacksDir: string; fingerprintKeyPath: string; mutationJournalDir: string } | undefined;
const abortController = new AbortController();
let runningJob: Promise<void> | undefined;
let jobStarted = false;
let shutdownRequested = false;
let acceptedEnvelope = false;
let acceptedEnvelopeAuth: DashboardResolvedAuth | undefined;
let acceptedExecutablePlan: BoundExecutablePlan | undefined;
let acceptedMutationContracts: import("../../core/offensive/ControlledMutationTypes.js").ControlledMutationContract[] = [];
let lastSensitiveSequence = 0;
let messageChain = Promise.resolve();

send({ protocolVersion: workerProtocolVersion, type: "WORKER_READY", workerId: requireWorkerId() });

const heartbeat = setInterval(() => {
  send({ protocolVersion: workerProtocolVersion, type: "JOB_HEARTBEAT", workerId: requireWorkerId(), ...(jobId ? { jobId } : {}), timestamp: new Date().toISOString() });
}, 1000);

process.on("message", (raw: unknown) => {
  messageChain = messageChain.then(() => handleMessage(raw)).catch((error: unknown) => {
    send({ protocolVersion: workerProtocolVersion, type: "WORKER_ERROR", workerId: requireWorkerId(), error: safeError(error) });
  });
});

process.on("disconnect", () => {
  void shutdown();
});
process.on("SIGTERM", () => { void shutdown(); });
process.on("SIGINT", () => { void shutdown(); });

async function shutdown(): Promise<void> {
  if (shutdownRequested) return;
  shutdownRequested = true;
  clearInterval(heartbeat);
  abortController.abort();
  const deadline = setTimeout(() => process.exit(1), workerRestorationGraceMs);
  deadline.unref();
  try { await runningJob; }
  finally {
    clearTimeout(deadline);
    if (process.connected) {
      process.send?.({ protocolVersion: workerProtocolVersion, type: "WORKER_SHUTDOWN", workerId: requireWorkerId() }, () => process.exit(0));
    } else process.exit(0);
  }
}

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
    case "PROVIDE_EXECUTABLE_PLAN":
      if (message.jobId !== jobId) throw new Error("Executable plan job mismatch.");
      acceptedExecutablePlan = await validateExecutablePlan(message);
      break;
    case "START_JOB":
      if (message.jobId !== jobId) throw new Error("Start job mismatch.");
      if (jobStarted || shutdownRequested) throw new Error("Worker job already started or shutting down.");
      jobStarted = true;
      runningJob = startJob();
      break;
    case "RECOVER_MUTATION":
      if (message.jobId !== jobId) throw new Error("Recovery job mismatch.");
      validateRecoveryMessage(message);
      if (jobStarted || shutdownRequested) throw new Error("Worker job already started or shutting down.");
      jobStarted = true;
      runningJob = recoverMutation(message);
      await runningJob;
      break;
    case "CANCEL_JOB":
      if (message.jobId === jobId) abortController?.abort();
      break;
    case "SHUTDOWN":
      await shutdown();
      break;
  }
}

async function recoverMutation(message: Extract<ApiToWorkerMessage, { type: "RECOVER_MUTATION" }>): Promise<void> {
  if (!paths || !request || !acceptedEnvelope) throw new Error("Worker refused recovery without initialized paths and authenticated credentials.");
  const bundlePath = resolveRecoveryBundlePath(paths.mutationJournalDir, message.bundlePath, message.caseId);
  const vault = new MutationRecoveryVault(paths.mutationJournalDir);
  const candidate = await vault.open<WorkflowCheckpoint>(bundlePath, message.caseId);
  if (candidate.kind === "WORKFLOW_CLEANUP_V1") {
    if (!request.workflowRecoveryDigest || candidate.digest !== request.workflowRecoveryDigest) throw new Error("RECOVERY_CHECKPOINT_CHANGED");
    if (candidate.targetOrigin !== new URL(request.target).origin) throw new Error("RECOVERY_TARGET_MISMATCH");
    const result = await recoverWorkflow(candidate, { mutationJournalDir: paths.mutationJournalDir, ...(request.recoveryScope ? { recoveryScope: request.recoveryScope } : {}), ...(acceptedEnvelopeAuth?.authProfile ? { authProfile: acceptedEnvelopeAuth.authProfile } : {}), ...(acceptedEnvelopeAuth?.authProfileSet ? { authProfileSet: acceptedEnvelopeAuth.authProfileSet } : {}) });
    send({ protocolVersion: workerProtocolVersion, type: "JOB_MUTATION_RECOVERY", workerId: requireWorkerId(), jobId: message.jobId, ...result });
    return;
  }
  const bundle = await vault.open(bundlePath, message.caseId);
  // Recovery cannot discard the program policy that authorized the original mutation.
  const resolved = await resolveDashboardScanPlan({ ...request, includeModules: ["baseline"], ...(bundle.targetAuthorization ? { targetAuthorization: bundle.targetAuthorization } : {}) }, acceptedEnvelopeAuth);
  const recoveryRequestBudget = (bundle.actorIdentityVerification?.attempts ?? 0) + (bundle.targetIdentityVerification?.attempts ?? 0) + 1 + (bundle.rollbackVerification.attempts ?? 3);
  const recoveryPlan = recoveryOnlyPlan(resolved.plan, recoveryRequestBudget);
  const context = new ScanContext({ target: request.target, scope: resolved.scope, config: resolved.config, plan: recoveryPlan, outputDir: paths.mutationJournalDir, ...(resolved.authProfile ? { authProfile: resolved.authProfile } : {}), ...(resolved.authProfileSet ? { authProfileSet: resolved.authProfileSet } : {}) });
  const client = context.createWorkflowCleanupHttpClient(recoveryRequestBudget, 64 * 1024);
  const freshProfile = acceptedEnvelopeAuth?.authProfile;
  if (!freshProfile) throw new Error("Worker refused recovery without a fresh primary credential profile.");
  const freshHeaders = authHeadersForProfile(freshProfile);
  const transport: MutationTransport = { send: (request) => client.send({ ...request, skipCache: true, disableRetries: true, disableRedirects: true, headers: { ...Object.fromEntries(Object.entries(request.headers ?? {}).filter(([name]) => ["content-type", "accept"].includes(name.toLowerCase()))), ...freshHeaders } }) };
  const result = await new ControlledMutationExecutor(transport, { journalDirectory: paths.mutationJournalDir, cleanupSleep: (ms) => context.cleanupWait(client, ms) }).recover(bundlePath, message.caseId).finally(() => context.dispose());
  send({ protocolVersion: workerProtocolVersion, type: "JOB_MUTATION_RECOVERY", workerId: requireWorkerId(), jobId: message.jobId, caseId: message.caseId, cleanupOutcome: result.cleanupOutcome === "ROLLBACK_VERIFIED" ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED", notes: result.notes.slice(0, 20) });
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
  if (!acceptedExecutablePlan) throw new Error("Worker refused to start without a verified executable plan snapshot.");
  const outputDir = resolve(paths.reportsDir, jobId);
  mkdirSync(outputDir, { recursive: true });
  try {
    if (acceptedExecutablePlan.payload.target !== new URL(request.target).href) throw new Error("EXECUTABLE_PLAN_TARGET_BINDING_INVALID");
    const resolved = {
      plan: acceptedExecutablePlan.payload.plan,
      config: acceptedExecutablePlan.payload.config,
      scope: acceptedExecutablePlan.payload.scope,
      ...(acceptedEnvelopeAuth?.authProfile ? { authProfile: acceptedEnvelopeAuth.authProfile } : {}),
      ...(acceptedEnvelopeAuth?.authProfileSet ? { authProfileSet: acceptedEnvelopeAuth.authProfileSet } : {})
    };
    if (acceptedMutationContracts.length && resolved.authProfile) {
      const freshHeaders = authHeadersForProfile(resolved.authProfile);
      const withFreshHeaders = <T extends { headers?: Record<string, string> | undefined }>(value: T): T => ({ ...value, headers: Object.fromEntries([...Object.entries(value.headers ?? {}), ...Object.entries(freshHeaders)].map(([name, content]) => [name.toLowerCase(), content])) });
      acceptedMutationContracts = acceptedMutationContracts.map((contract) => ({ ...contract, ...(contract.identity ? { identity: { ...contract.identity, request: withFreshHeaders(contract.identity.request) } } : {}), attack: { ...contract.attack, request: withFreshHeaders(contract.attack.request) }, precondition: { ...contract.precondition, request: withFreshHeaders(contract.precondition.request) }, impact: { ...contract.impact, request: withFreshHeaders(contract.impact.request) }, ...(contract.protectedAction ? { protectedAction: { ...contract.protectedAction, request: withFreshHeaders(contract.protectedAction.request) } } : {}), rollback: { request: withFreshHeaders(contract.rollback.request), verification: { ...contract.rollback.verification, request: withFreshHeaders(contract.rollback.verification.request) } } }));
    }
    send({
      protocolVersion: workerProtocolVersion,
      type: "JOB_PLAN",
      workerId: requireWorkerId(),
      jobId,
      executionPlanBinding: acceptedExecutablePlan.binding,
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
      mutationJournalDir: paths.mutationJournalDir,
      ...(resolved.authProfile ? { authProfile: resolved.authProfile } : {}),
      ...(resolved.authProfileSet ? { authProfileSet: resolved.authProfileSet } : {}),
      ...(acceptedMutationContracts.length > 0 ? { controlledMutationContracts: acceptedMutationContracts } : {}),
      eventSink: sink,
      abortSignal: abortController.signal
    });
    if (result.status === "CANCELLED") {
      send({ protocolVersion: workerProtocolVersion, type: "JOB_CANCELLED", workerId: requireWorkerId(), jobId, summary: "Scan cancelled; partial evidence retained.", ...result });
      return;
    }
    if (result.status === "FAILED") {
      send({ protocolVersion: workerProtocolVersion, type: "JOB_FAILED", workerId: requireWorkerId(), jobId, error: "Execution failed; partial evidence retained.", ...result });
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
  if (jobStarted) throw new Error("Secret envelope received after scan start.");
  if (message.workerGeneration !== workerGeneration) throw new Error("Secret envelope generation mismatch.");
  if (Date.parse(message.expiresAt) < Date.now()) throw new Error("Expired secret envelope rejected.");
  if (message.sequence <= lastSensitiveSequence) throw new Error("Out-of-order secret envelope rejected.");
  const { hmac, ...body } = message;
  if (!constantEqual(hmac, createHmac("sha256", workerSecret).update(JSON.stringify(body)).digest("hex"))) throw new Error("Secret envelope authentication failed.");
  lastSensitiveSequence = message.sequence;
}

function validateMutationContracts(message: Extract<ApiToWorkerMessage, { type: "PROVIDE_MUTATION_CONTRACTS" }>): void {
  if (!workerSecret || !workerGeneration) throw new Error("Worker IPC authentication was not initialized.");
  if (jobStarted) throw new Error("Mutation contracts received after scan start.");
  if (message.sequence <= lastSensitiveSequence) throw new Error("Out-of-order mutation contract envelope rejected.");
  if (Date.parse(message.expiresAt) < Date.now()) throw new Error("Expired mutation contract envelope rejected.");
  const { hmac, ...body } = message;
  if (!constantEqual(hmac, createHmac("sha256", workerSecret).update(JSON.stringify(body)).digest("hex"))) throw new Error("Mutation contract envelope authentication failed.");
  lastSensitiveSequence = message.sequence;
}

async function validateExecutablePlan(message: Extract<ApiToWorkerMessage, { type: "PROVIDE_EXECUTABLE_PLAN" }>): Promise<BoundExecutablePlan> {
  if (!workerSecret || !workerGeneration) throw new Error("Worker IPC authentication was not initialized.");
  if (!acceptedEnvelope) throw new Error("Executable plan received before the authenticated credential envelope.");
  if (acceptedExecutablePlan) throw new Error("Duplicate executable plan rejected.");
  if (jobStarted) throw new Error("Executable plan received after scan start.");
  if (message.workerGeneration !== workerGeneration) throw new Error("Executable plan generation mismatch.");
  if (message.sequence <= lastSensitiveSequence) throw new Error("Out-of-order executable plan envelope rejected.");
  if (Date.parse(message.expiresAt) < Date.now()) throw new Error("Expired executable plan envelope rejected.");
  const { hmac, ...body } = message;
  if (!constantEqual(hmac, createHmac("sha256", workerSecret).update(JSON.stringify(body)).digest("hex"))) throw new Error("Executable plan envelope authentication failed.");
  const payload = parseExecutablePlanPayload(message.payload);
  if (!constantEqual(executablePlanContentDigest(payload), message.contentDigest)) throw new Error("EXECUTABLE_PLAN_SNAPSHOT_CHANGED");
  if (!constantEqual(payload.authenticationDigest, executableAuthenticationDigest(acceptedEnvelopeAuth))) throw new Error("EXECUTABLE_PLAN_AUTH_BINDING_MISMATCH");
  if (!request || payload.target !== new URL(request.target).href) throw new Error("EXECUTABLE_PLAN_TARGET_BINDING_INVALID");
  await assertExecutablePlanSourcesUnchanged(payload.sourceBindings);
  lastSensitiveSequence = message.sequence;
  return { payload, contentDigest: message.contentDigest, binding: message.binding };
}

function validateRecoveryMessage(message: Extract<ApiToWorkerMessage, { type: "RECOVER_MUTATION" }>): void {
  if (!workerSecret || !workerGeneration) throw new Error("Worker IPC authentication was not initialized.");
  if (jobStarted) throw new Error("Recovery received after scan start.");
  if (message.sequence <= lastSensitiveSequence) throw new Error("Out-of-order recovery envelope rejected.");
  if (Date.parse(message.expiresAt) < Date.now()) throw new Error("Expired recovery envelope rejected.");
  const { hmac, ...body } = message;
  if (!constantEqual(hmac, createHmac("sha256", workerSecret).update(JSON.stringify(body)).digest("hex"))) throw new Error("Recovery envelope authentication failed.");
  lastSensitiveSequence = message.sequence;
}

function send(message: WorkerToApiMessage): void {
  if (process.connected) process.send?.(message, () => { /* IPC loss must not interrupt restoration. */ });
}

function safeError(error: unknown): string {
  if (!(error instanceof Error)) return "Worker failure.";
  return error.message
    .replace(/(https?:\/\/[^\s?#]+)[?#][^\s]*/gi, "$1?<redacted>")
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 <redacted>")
    .replace(/\b(token|secret|password|api[-_]?key)\s*[=:]\s*[^\s,;]+/gi, "$1=<redacted>")
    .slice(0, 800);
}

function constantEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}
