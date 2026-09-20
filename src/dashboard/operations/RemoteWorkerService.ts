import { createHash, createPublicKey, randomBytes, randomUUID, verify, type KeyObject } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";

export class RemoteWorkerService {
  public constructor(private readonly database: DashboardDatabase) {}

  public createEnrollment(input: { organizationId: string; nameHint?: string; expiresInMinutes: number }, actor: string): { enrollmentId: string; token: string; expiresAt: string } {
    const id = randomUUID(); const token = randomBytes(32).toString("base64url"); const expiresAt = new Date(Date.now() + input.expiresInMinutes * 60_000).toISOString();
    this.database.db.prepare("INSERT INTO remote_worker_enrollments (id,organization_id,token_hash,name_hint,expires_at,created_by,created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(id, input.organizationId, digest(token), input.nameHint ?? null, expiresAt, actor, nowIso());
    return { enrollmentId: id, token, expiresAt };
  }

  public enroll(input: { token: string; name: string; publicKeyPem: string; capabilities: string[]; labels: Record<string, string> }): { workerId: string; generation: number; signatureProtocol: string } {
    const publicKey = validateEd25519(input.publicKeyPem); const normalizedPublicKey = publicKey.export({ format: "pem", type: "spki" }).toString();
    const row = this.database.db.prepare("SELECT * FROM remote_worker_enrollments WHERE token_hash=?").get(digest(input.token)) as EnrollmentRow | undefined;
    if (!row || row.consumed_at || Date.parse(row.expires_at) <= Date.now()) throw new RemoteWorkerAuthError("REMOTE_ENROLLMENT_REJECTED");
    const id = randomUUID(); const now = nowIso(); const fingerprint = createHash("sha256").update(publicKey.export({ format: "der", type: "spki" })).digest("hex");
    this.database.transaction(() => {
      const consumed = this.database.db.prepare("UPDATE remote_worker_enrollments SET consumed_at=? WHERE id=? AND consumed_at IS NULL AND expires_at>?").run(now, row.id, now);
      if (consumed.changes !== 1) throw new RemoteWorkerAuthError("REMOTE_ENROLLMENT_REJECTED");
      this.database.db.prepare(`INSERT INTO remote_workers (id,organization_id,name,public_key_pem,public_key_fingerprint,capabilities_json,labels_json,status,generation,last_seen_at,created_at,updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'ONLINE', 1, ?, ?, ?)`).run(id, row.organization_id, input.name, normalizedPublicKey, fingerprint, JSON.stringify([...new Set(input.capabilities)].sort()), JSON.stringify(input.labels), now, now, now);
    });
    return { workerId: id, generation: 1, signatureProtocol: "routecairn-agent-ed25519-v1" };
  }

  public authenticate(method: string, path: string, body: unknown, headers: IncomingHttpHeaders): WorkerRow {
    const workerId = header(headers, "x-routecairn-worker-id"); const timestamp = header(headers, "x-routecairn-timestamp"); const nonce = header(headers, "x-routecairn-nonce"); const signature = header(headers, "x-routecairn-signature");
    if (!workerId || !timestamp || !nonce || !signature || nonce.length < 16 || nonce.length > 200) throw new RemoteWorkerAuthError("REMOTE_WORKER_SIGNATURE_REQUIRED");
    const time = Date.parse(timestamp); if (!Number.isFinite(time) || Math.abs(Date.now() - time) > 5 * 60_000) throw new RemoteWorkerAuthError("REMOTE_WORKER_TIMESTAMP_REJECTED");
    const worker = this.database.db.prepare("SELECT * FROM remote_workers WHERE id=?").get(workerId) as WorkerRow | undefined;
    if (!worker || ["QUARANTINED", "REVOKED"].includes(worker.status)) throw new RemoteWorkerAuthError("REMOTE_WORKER_REJECTED");
    const bodyHash = createHash("sha256").update(canonical(body)).digest("hex");
    const signed = Buffer.from(["routecairn-agent-ed25519-v1", method.toUpperCase(), path, timestamp, nonce, bodyHash].join("\n"));
    let valid = false; try { valid = verify(null, signed, createPublicKey(worker.public_key_pem), Buffer.from(signature, "base64url")); } catch { valid = false; }
    if (!valid) throw new RemoteWorkerAuthError("REMOTE_WORKER_SIGNATURE_REJECTED");
    this.database.db.prepare("DELETE FROM remote_worker_nonces WHERE expires_at<=?").run(nowIso());
    try { this.database.db.prepare("INSERT INTO remote_worker_nonces (worker_id,nonce,expires_at) VALUES (?, ?, ?)").run(workerId, nonce, new Date(Date.now() + 10 * 60_000).toISOString()); }
    catch { throw new RemoteWorkerAuthError("REMOTE_WORKER_REPLAY_REJECTED"); }
    return worker;
  }

  public heartbeat(worker: WorkerRow, input: { status: "ONLINE" | "DRAINING"; resources: unknown }): void {
    this.database.db.prepare("UPDATE remote_workers SET status=?,resources_json=?,last_seen_at=?,updated_at=? WHERE id=?").run(input.status, canonical(input.resources), nowIso(), nowIso(), worker.id);
  }

  public enqueue(input: { organizationId: string; kind: string; payload: Record<string, unknown>; requiredCapabilities: string[]; priority: number; maxAttempts: number }, actor: string): string {
    ensureSafeObject(input.payload); const id = randomUUID();
    this.database.db.prepare(`INSERT INTO remote_jobs (id,organization_id,kind,safe_payload_json,required_capabilities_json,status,priority,max_attempts,created_by,created_at)
      VALUES (?, ?, ?, ?, ?, 'QUEUED', ?, ?, ?, ?)`).run(id, input.organizationId, input.kind, canonical(input.payload), JSON.stringify([...new Set(input.requiredCapabilities)].sort()), input.priority, input.maxAttempts, actor, nowIso());
    return id;
  }

  public claim(worker: WorkerRow): unknown {
    this.requeueExpired();
    if (worker.status !== "ONLINE") return { job: null };
    const capabilities = new Set(JSON.parse(worker.capabilities_json) as string[]);
    const candidates = this.database.db.prepare("SELECT * FROM remote_jobs WHERE organization_id=? AND status='QUEUED' AND attempt_count<max_attempts ORDER BY priority DESC,created_at LIMIT 100").all(worker.organization_id) as JobRow[];
    const job = candidates.find((candidate) => (JSON.parse(candidate.required_capabilities_json) as string[]).every((capability) => capabilities.has(capability)));
    if (!job) return { job: null };
    const leaseToken = randomBytes(32).toString("base64url"); const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const changed = this.database.db.prepare("UPDATE remote_jobs SET status='LEASED',assigned_worker_id=?,lease_token_hash=?,lease_expires_at=?,attempt_count=attempt_count+1,started_at=COALESCE(started_at,?) WHERE id=? AND status='QUEUED'").run(worker.id, digest(leaseToken), expiresAt, nowIso(), job.id);
    if (changed.changes !== 1) return { job: null };
    return { job: { id: job.id, kind: job.kind, payload: JSON.parse(job.safe_payload_json), leaseToken, leaseExpiresAt: expiresAt } };
  }

  public complete(worker: WorkerRow, jobId: string, input: { leaseToken: string; status: "COMPLETED" | "FAILED"; result?: Record<string, unknown>; error?: string }): void {
    if (input.result) ensureSafeObject(input.result);
    const job = this.database.db.prepare("SELECT * FROM remote_jobs WHERE id=?").get(jobId) as JobRow | undefined;
    if (!job || !["LEASED","RUNNING"].includes(job.status) || job.assigned_worker_id !== worker.id || job.lease_token_hash !== digest(input.leaseToken) || !job.lease_expires_at || Date.parse(job.lease_expires_at) <= Date.now()) throw new RemoteWorkerAuthError("REMOTE_JOB_LEASE_REJECTED");
    this.database.db.prepare("UPDATE remote_jobs SET status=?,safe_result_json=?,safe_error=?,completed_at=?,lease_token_hash=NULL,lease_expires_at=NULL WHERE id=?").run(input.status, input.result ? canonical(input.result) : null, input.error ? safeRemoteError(input.error) : null, nowIso(), jobId);
  }

  public renew(worker: WorkerRow, jobId: string, leaseToken: string): { leaseExpiresAt: string } {
    const expiresAt=new Date(Date.now()+60_000).toISOString();
    const result=this.database.db.prepare("UPDATE remote_jobs SET status='RUNNING',lease_expires_at=? WHERE id=? AND assigned_worker_id=? AND lease_token_hash=? AND status IN ('LEASED','RUNNING') AND lease_expires_at>?").run(expiresAt,jobId,worker.id,digest(leaseToken),nowIso());
    if(result.changes!==1)throw new RemoteWorkerAuthError("REMOTE_JOB_LEASE_REJECTED");
    return {leaseExpiresAt:expiresAt};
  }

  public list(organizationId: string): { workers: unknown[]; jobs: unknown[] } {
    const workers = (this.database.db.prepare("SELECT * FROM remote_workers WHERE organization_id=? ORDER BY created_at DESC").all(organizationId) as WorkerRow[]).map((row) => ({ id: row.id, name: row.name, fingerprint: row.public_key_fingerprint, capabilities: JSON.parse(row.capabilities_json), labels: JSON.parse(row.labels_json), resources: row.resources_json ? JSON.parse(row.resources_json) : null, status: effectiveStatus(row), generation: row.generation, lastSeenAt: row.last_seen_at, createdAt: row.created_at }));
    const jobs = this.database.db.prepare("SELECT id,kind,status,priority,assigned_worker_id AS assignedWorkerId,attempt_count AS attemptCount,max_attempts AS maxAttempts,safe_error AS safeError,created_at AS createdAt,started_at AS startedAt,completed_at AS completedAt FROM remote_jobs WHERE organization_id=? ORDER BY created_at DESC LIMIT 200").all(organizationId);
    return { workers, jobs };
  }

  public setStatus(workerId: string, status: "DRAINING" | "QUARANTINED" | "REVOKED" | "ONLINE"): void { const result=this.database.db.prepare("UPDATE remote_workers SET status=?,generation=generation+1,updated_at=? WHERE id=?").run(status, nowIso(), workerId);if(result.changes!==1)throw new Error("REMOTE_WORKER_NOT_FOUND"); }
  public organizationForWorker(workerId: string): string { const row=this.database.db.prepare("SELECT organization_id FROM remote_workers WHERE id=?").get(workerId) as {organization_id:string}|undefined;if(!row)throw new Error("REMOTE_WORKER_NOT_FOUND");return row.organization_id; }
  private requeueExpired(): void { this.database.db.prepare(`UPDATE remote_jobs SET status=CASE WHEN attempt_count>=max_attempts THEN 'FAILED' ELSE 'QUEUED' END,assigned_worker_id=NULL,lease_token_hash=NULL,lease_expires_at=NULL,safe_error=CASE WHEN attempt_count>=max_attempts THEN 'Lease expired after maximum attempts.' ELSE safe_error END WHERE status IN ('LEASED','RUNNING') AND lease_expires_at<=?`).run(nowIso()); }
}

export class RemoteWorkerAuthError extends Error { public constructor(message: string) { super(message); this.name = "RemoteWorkerAuthError"; } }
function header(headers: IncomingHttpHeaders, name: string): string | undefined { const value = headers[name]; return Array.isArray(value) ? value[0] : value; }
function digest(value: string): string { return createHash("sha256").update("routecairn-remote-v1\0").update(value).digest("hex"); }
function canonical(value: unknown): string { return JSON.stringify(sort(value)); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sort(item)])); return value; }
function validateEd25519(pem: string): KeyObject { let key: KeyObject; try { key = createPublicKey(pem); } catch { throw new RemoteWorkerAuthError("REMOTE_WORKER_KEY_REJECTED"); } if (key.asymmetricKeyType !== "ed25519") throw new RemoteWorkerAuthError("REMOTE_WORKER_KEY_TYPE_REJECTED"); return key; }
function ensureSafeObject(value: Record<string, unknown>): void { const raw = canonical(value); if (Buffer.byteLength(raw) > 256 * 1024) throw new Error("REMOTE_JOB_PAYLOAD_TOO_LARGE"); const inspect=(item:unknown,depth:number):void=>{if(depth>12)throw new Error("REMOTE_JOB_PAYLOAD_TOO_DEEP");if(Array.isArray(item)){for(const child of item)inspect(child,depth+1);return;}if(item&&typeof item==="object")for(const [key,child] of Object.entries(item as Record<string,unknown>)){if(/(password|passwd|secret|token|cookie|authorization|private[_-]?key|api[_-]?key|credential|session|jwt|signature|signed)/i.test(key))throw new Error("REMOTE_JOB_SECRET_FIELD_REJECTED");inspect(child,depth+1);}};inspect(value,0); }
function effectiveStatus(row: WorkerRow): string { return row.status === "ONLINE" && (!row.last_seen_at || Date.parse(row.last_seen_at) < Date.now() - 90_000) ? "OFFLINE" : row.status; }
function safeRemoteError(value: string): string { return value.replace(/https?:\/\/[^\s]+/gi, "<endpoint>").replace(/\b(password|secret|token|cookie|authorization|private[_-]?key)\s*[:=]\s*[^\s,;]+/gi, "$1=<redacted>").replace(/[\r\n]+/g, " ").slice(0, 1000); }
interface EnrollmentRow { id: string; organization_id: string; expires_at: string; consumed_at: string | null }
export interface WorkerRow { id: string; organization_id: string; name: string; public_key_pem: string; public_key_fingerprint: string; capabilities_json: string; labels_json: string; resources_json: string | null; status: string; generation: number; last_seen_at: string | null; created_at: string }
interface JobRow { id: string; kind: string; status: string; safe_payload_json: string; required_capabilities_json: string; assigned_worker_id: string | null; lease_token_hash: string | null; lease_expires_at: string | null }
