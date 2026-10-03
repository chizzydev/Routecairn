import type { IncomingHttpHeaders } from "node:http";
import type { WorkerRow } from "./RemoteWorkerService.js";
import type { WorkerIdentityBinding } from "../contracts/OperationalScaleSchemas.js";

export type MaybePromise<T> = T | Promise<T>;
export interface RemoteWorkerOperations {
  createEnrollment(input: { organizationId: string; nameHint?: string; expiresInMinutes: number;workloadIdentity?:WorkerIdentityBinding }, actor: string): MaybePromise<{ enrollmentId: string; token: string; expiresAt: string }>;
  enroll(input: { token: string; name: string; publicKeyPem: string; capabilities: string[]; labels: Record<string, string> }): MaybePromise<{ workerId: string; generation: number; signatureProtocol: string }>;
  authenticate(method: string, path: string, body: unknown, headers: IncomingHttpHeaders): MaybePromise<WorkerRow>;
  heartbeat(worker: WorkerRow, input: { status: "ONLINE" | "DRAINING"; resources: unknown }): MaybePromise<void>;
  enqueue(input: { organizationId: string; kind: string; payload: Record<string, unknown>; requiredCapabilities: string[]; priority: number; maxAttempts: number; networkZone?: string }, actor: string): MaybePromise<string>;
  claim(worker: WorkerRow, waitMs?: number): MaybePromise<unknown>;
  complete(worker: WorkerRow, jobId: string, input: { leaseToken: string; status: "COMPLETED" | "FAILED"; result?: Record<string, unknown>; error?: string }): MaybePromise<void>;
  renew(worker: WorkerRow, jobId: string, leaseToken: string): MaybePromise<{ leaseExpiresAt: string }>;
  list(organizationId: string): MaybePromise<{ workers: unknown[]; jobs: unknown[] }>;
  setStatus(workerId: string, status: "DRAINING" | "QUARANTINED" | "REVOKED" | "ONLINE"): MaybePromise<void>;
  organizationForWorker(workerId: string): MaybePromise<string>;
}
