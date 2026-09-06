import { z } from "zod";
import { controlledMutationContractSchema } from "../../core/offensive/ControlledMutationTypes.js";

export const workerProtocolVersion = 2;
export const maxWorkerMessageBytes = 4 * 1024 * 1024;

export const apiToWorkerMessageSchema = z.discriminatedUnion("type", [
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("INITIALIZE_JOB"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    request: z.record(z.unknown()),
    paths: z.object({
      reportsDir: z.string(),
      artifactsDir: z.string(),
      proofPacksDir: z.string(),
      fingerprintKeyPath: z.string(),
      mutationJournalDir: z.string(),
      tempDir: z.string()
    })
  }),
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("PROVIDE_SECRET_ENVELOPE"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    sequence: z.number().int().positive(),
    expiresAt: z.string(),
    nonce: z.string().min(16).max(120),
    attempt: z.number().int().positive(),
    workerGeneration: z.string().min(1).max(120),
    envelope: z.record(z.unknown()),
    hmac: z.string().regex(/^[a-f0-9]{64}$/)
  }),
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("PROVIDE_EXECUTABLE_PLAN"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    sequence: z.number().int().positive(),
    expiresAt: z.string().datetime(),
    nonce: z.string().min(16).max(120),
    workerGeneration: z.string().min(1).max(120),
    payload: z.record(z.unknown()),
    contentDigest: z.string().regex(/^[a-f0-9]{64}$/),
    binding: z.string().regex(/^[a-f0-9]{64}$/),
    hmac: z.string().regex(/^[a-f0-9]{64}$/)
  }),
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("PROVIDE_MUTATION_CONTRACTS"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    sequence: z.number().int().positive(),
    expiresAt: z.string().datetime(),
    nonce: z.string().min(16).max(120),
    contracts: z.array(controlledMutationContractSchema).min(1).max(10),
    hmac: z.string().regex(/^[a-f0-9]{64}$/)
  }),
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("RECOVER_MUTATION"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    sequence: z.number().int().positive(),
    expiresAt: z.string().datetime(),
    nonce: z.string().min(16).max(120),
    caseId: z.string().regex(/^[A-Za-z0-9._-]+$/).max(200),
    bundlePath: z.string().min(1).max(1000).regex(/\.recovery\.enc$/).refine((value) => !value.split(/[\\/]/).includes(".."), "Recovery bundle path traversal is not allowed"),
    hmac: z.string().regex(/^[a-f0-9]{64}$/)
  }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("START_JOB"), workerId: z.string().uuid(), jobId: z.string().uuid() }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("CANCEL_JOB"), workerId: z.string().uuid(), jobId: z.string().uuid(), reason: z.string().max(800).optional() }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("SHUTDOWN"), workerId: z.string().uuid() })
]);

export const workerToApiMessageSchema = z.discriminatedUnion("type", [
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("WORKER_READY"), workerId: z.string().uuid() }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("JOB_ACCEPTED"), workerId: z.string().uuid(), jobId: z.string().uuid() }),
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("JOB_HEARTBEAT"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid().optional(),
    timestamp: z.string().datetime(),
    resource: z.object({
      sequence: z.number().int().nonnegative(),
      rssBytes: z.number().int().nonnegative(),
      heapUsedBytes: z.number().int().nonnegative(),
      externalBytes: z.number().int().nonnegative(),
      cpuUserMicros: z.number().int().nonnegative(),
      cpuSystemMicros: z.number().int().nonnegative(),
      outputBytes: z.number().int().nonnegative(),
      tempBytes: z.number().int().nonnegative(),
      currentModule: z.string().max(160).optional(),
      cleanupState: z.enum(["CLEAR", "PENDING", "RUNNING", "REQUIRED", "UNKNOWN"])
    })
  }),
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("JOB_PLAN"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    executionPlanBinding: z.string().regex(/^[a-f0-9]{64}$/),
    planSnapshot: z.record(z.unknown()),
    modules: z.array(z.object({ id: z.string(), phase: z.string() })),
    evidenceLevel: z.string()
  }),
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("JOB_EVENT"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    event: z.object({
      type: z.string(),
      message: z.string(),
      moduleId: z.string().optional(),
      metadata: z.record(z.unknown()).optional()
    })
  }),
  z.object({
    protocolVersion: z.literal(workerProtocolVersion),
    type: z.literal("JOB_MUTATION_RECOVERY"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    caseId: z.string().regex(/^[A-Za-z0-9._-]+$/).max(200),
    cleanupOutcome: z.enum(["ROLLBACK_VERIFIED", "CLEANUP_FAILED"]),
    notes: z.array(z.string().max(800)).max(20)
  }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("JOB_COMPLETED"),
    workerId: z.string().uuid(),
    jobId: z.string().uuid(),
    reportPath: z.string(),
    markdownReportPath: z.string(),
    htmlReportPath: z.string()
  }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("JOB_CANCELLED"), workerId: z.string().uuid(), jobId: z.string().uuid(), summary: z.string(), reportPath: z.string().optional(), markdownReportPath: z.string().optional(), htmlReportPath: z.string().optional() }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("JOB_FAILED"), workerId: z.string().uuid(), jobId: z.string().uuid(), error: z.string(), reportPath: z.string().optional(), markdownReportPath: z.string().optional(), htmlReportPath: z.string().optional() }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("WORKER_ERROR"), workerId: z.string().uuid(), error: z.string() }),
  z.object({ protocolVersion: z.literal(workerProtocolVersion), type: z.literal("WORKER_SHUTDOWN"), workerId: z.string().uuid() })
]);

export type ApiToWorkerMessage = z.infer<typeof apiToWorkerMessageSchema>;
export type WorkerToApiMessage = z.infer<typeof workerToApiMessageSchema>;

export function parseApiMessage(value: unknown): ApiToWorkerMessage {
  assertMessageSize(value);
  return apiToWorkerMessageSchema.parse(value);
}

export function parseWorkerMessage(value: unknown): WorkerToApiMessage {
  assertMessageSize(value);
  return workerToApiMessageSchema.parse(value);
}

function assertMessageSize(value: unknown): void {
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > maxWorkerMessageBytes) {
    throw new Error("Worker IPC message exceeded size limit.");
  }
}
