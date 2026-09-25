import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";

const protocol = "routecairn-mutation-coordinator-v1";
const leaseDurationMs = 120_000;
const namespacePattern = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,199}$/;
const casePattern = /^[A-Za-z0-9._-]{1,200}$/;

export class DistributedMutationCoordinatorService {
  public constructor(private readonly database: DashboardDatabase, private readonly secret: string) {
    if (Buffer.byteLength(secret) < 32) throw new Error("RouteCairn mutation coordination requires a secret of at least 32 bytes.");
  }

  public authenticate(method: string, path: string, body: unknown, headers: IncomingHttpHeaders): void {
    const clientId = header(headers, "x-routecairn-coordinator-client"); const timestamp = header(headers, "x-routecairn-timestamp"); const nonce = header(headers, "x-routecairn-nonce"); const signature = header(headers, "x-routecairn-signature");
    if (!clientId || !namespacePattern.test(clientId) || !timestamp || !nonce || nonce.length < 24 || nonce.length > 200 || !signature) throw authError("MUTATION_COORDINATOR_SIGNATURE_REQUIRED");
    const time = Date.parse(timestamp); if (!Number.isFinite(time) || Math.abs(Date.now() - time) > 5 * 60_000) throw authError("MUTATION_COORDINATOR_TIMESTAMP_REJECTED");
    const bodyHash = createHash("sha256").update(canonical(body)).digest("hex");
    const expected = createHmac("sha256", this.secret).update([protocol, method.toUpperCase(), path, timestamp, nonce, bodyHash].join("\n")).digest();
    let supplied: Buffer; try { supplied = Buffer.from(signature, "base64url"); } catch { throw authError("MUTATION_COORDINATOR_SIGNATURE_REJECTED"); }
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw authError("MUTATION_COORDINATOR_SIGNATURE_REJECTED");
    this.database.db.prepare("DELETE FROM distributed_mutation_nonces WHERE expires_at<=?").run(nowIso());
    try { this.database.db.prepare("INSERT INTO distributed_mutation_nonces(client_id,nonce,expires_at) VALUES (?, ?, ?)").run(clientId, nonce, new Date(Date.now() + 10 * 60_000).toISOString()); }
    catch { throw authError("MUTATION_COORDINATOR_REPLAY_REJECTED"); }
  }

  public acquire(input: unknown): { leaseId: string; leaseToken: string; expiresAt: string; caseId: string; recovery: boolean } {
    const value = acquireInput(input); const now = nowIso(); const expiresAt = new Date(Date.now() + leaseDurationMs).toISOString(); const id = randomUUID(); const token = randomBytes(32).toString("base64url");
    return this.database.transaction(() => {
      const active = this.database.db.prepare("SELECT expires_at FROM distributed_mutation_leases WHERE namespace=? AND status='ACTIVE'").get(value.namespace) as { expires_at: string } | undefined;
      if (active) throw conflict(Date.parse(active.expires_at) <= Date.now() ? "MUTATION_LOCK_STALE_OPERATOR_ACTION_REQUIRED" : "MUTATION_LOCK_HELD");
      const obligations = this.database.db.prepare("SELECT case_id FROM distributed_mutation_obligations WHERE namespace=? ORDER BY first_seen_at").all(value.namespace) as Array<{ case_id: string }>;
      if (obligations.length && !(value.recovery && obligations.every((entry) => entry.case_id === value.caseId))) throw conflict("UNRESOLVED_PRIOR_CLEANUP");
      this.database.db.prepare("INSERT INTO distributed_mutation_leases(id,namespace,case_id,holder_id,lease_token_hash,recovery,status,acquired_at,heartbeat_at,expires_at) VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)").run(id, value.namespace, value.caseId, value.holderId, tokenHash(token), value.recovery ? 1 : 0, now, now, expiresAt);
      return { leaseId: id, leaseToken: token, expiresAt, caseId: value.caseId, recovery: value.recovery };
    });
  }

  public renew(input: unknown): { expiresAt: string } {
    const value = leaseInput(input); const expiresAt = new Date(Date.now() + leaseDurationMs).toISOString();
    const changed = this.database.db.prepare("UPDATE distributed_mutation_leases SET heartbeat_at=?,expires_at=? WHERE id=? AND namespace=? AND holder_id=? AND lease_token_hash=? AND status='ACTIVE'").run(nowIso(), expiresAt, value.leaseId, value.namespace, value.holderId, tokenHash(value.leaseToken));
    if (changed.changes !== 1) throw conflict("MUTATION_COORDINATOR_LEASE_REJECTED");
    return { expiresAt };
  }

  public release(input: unknown): { released: true; cleanupState: string } {
    const value = releaseInput(input); const now = nowIso();
    return this.database.transaction(() => {
      const lease = this.database.db.prepare("SELECT case_id FROM distributed_mutation_leases WHERE id=? AND namespace=? AND holder_id=? AND lease_token_hash=? AND status='ACTIVE'").get(value.leaseId, value.namespace, value.holderId, tokenHash(value.leaseToken)) as { case_id: string } | undefined;
      if (!lease) throw conflict("MUTATION_COORDINATOR_LEASE_REJECTED");
      if (value.cleanup.state === "CLEAN") this.database.db.prepare("DELETE FROM distributed_mutation_obligations WHERE namespace=? AND case_id=?").run(value.namespace, lease.case_id);
      else if (value.cleanup.state === "UNKNOWN") upsertObligation(this.database, value.namespace, lease.case_id, "UNKNOWN", value.cleanup.stage ?? "MUTATION_STATE_UNCERTAIN", now);
      else {
        const obligations = value.cleanup.obligations.length ? value.cleanup.obligations : [{ caseId: lease.case_id, stage: value.cleanup.stage ?? "MUTATION_STATE_UNCERTAIN" }];
        if (!obligations.some((entry) => entry.caseId === lease.case_id)) this.database.db.prepare("DELETE FROM distributed_mutation_obligations WHERE namespace=? AND case_id=?").run(value.namespace, lease.case_id);
        for (const obligation of obligations) upsertObligation(this.database, value.namespace, obligation.caseId, "UNRESOLVED", obligation.stage, now);
      }
      this.database.db.prepare("UPDATE distributed_mutation_leases SET status='RELEASED',lease_token_hash=NULL,released_at=?,heartbeat_at=? WHERE id=?").run(now, now, value.leaseId);
      return { released: true as const, cleanupState: value.cleanup.state };
    });
  }

  public status(namespace: string): { namespace: string; activeLease: Record<string, unknown> | null; obligations: Array<Record<string, unknown>> } {
    ensureNamespace(namespace);
    const lease = this.database.db.prepare("SELECT id,case_id,recovery,acquired_at,heartbeat_at,expires_at FROM distributed_mutation_leases WHERE namespace=? AND status='ACTIVE'").get(namespace) as LeaseStatusRow | undefined;
    const obligations = this.database.db.prepare("SELECT case_id,state,stage,first_seen_at,updated_at FROM distributed_mutation_obligations WHERE namespace=? ORDER BY first_seen_at").all(namespace) as ObligationRow[];
    return { namespace, activeLease: lease ? { leaseId: lease.id, caseId: lease.case_id, recovery: Boolean(lease.recovery), acquiredAt: lease.acquired_at, heartbeatAt: lease.heartbeat_at, expiresAt: lease.expires_at, stale: Date.parse(lease.expires_at) <= Date.now() } : null, obligations: obligations.map((entry) => ({ caseId: entry.case_id, state: entry.state, ...(entry.stage ? { stage: entry.stage } : {}), firstSeenAt: entry.first_seen_at, updatedAt: entry.updated_at })) };
  }

  public orphan(input: unknown): { orphaned: true; caseId: string } {
    const value = operatorInput(input, "MARK_STALE_LEASE_STATE_UNCERTAIN"); const now = nowIso();
    return this.database.transaction(() => {
      const lease = this.database.db.prepare("SELECT id,case_id,expires_at FROM distributed_mutation_leases WHERE namespace=? AND status='ACTIVE'").get(value.namespace) as { id: string; case_id: string; expires_at: string } | undefined;
      if (!lease) throw conflict("MUTATION_COORDINATOR_ACTIVE_LEASE_NOT_FOUND");
      if (Date.parse(lease.expires_at) > Date.now()) throw conflict("MUTATION_COORDINATOR_LEASE_NOT_STALE");
      this.database.db.prepare("UPDATE distributed_mutation_leases SET status='ORPHANED',lease_token_hash=NULL,released_at=? WHERE id=?").run(now, lease.id);
      this.database.db.prepare(`INSERT INTO distributed_mutation_obligations(namespace,case_id,state,stage,first_seen_at,updated_at) VALUES (?, ?, 'LEASE_ORPHANED', 'MUTATION_STATE_UNCERTAIN', ?, ?)
        ON CONFLICT(namespace,case_id) DO UPDATE SET state='LEASE_ORPHANED',stage='MUTATION_STATE_UNCERTAIN',updated_at=excluded.updated_at`).run(value.namespace, lease.case_id, now, now);
      return { orphaned: true as const, caseId: lease.case_id };
    });
  }

  public resolve(input: unknown): { resolved: true; caseId: string } {
    const value = resolveInput(input);
    return this.database.transaction(() => {
      const active = this.database.db.prepare("SELECT 1 FROM distributed_mutation_leases WHERE namespace=? AND status='ACTIVE'").get(value.namespace);
      if (active) throw conflict("MUTATION_LOCK_HELD");
      const deleted = this.database.db.prepare("DELETE FROM distributed_mutation_obligations WHERE namespace=? AND case_id=?").run(value.namespace, value.caseId);
      if (deleted.changes !== 1) throw conflict("MUTATION_COORDINATOR_OBLIGATION_NOT_FOUND");
      return { resolved: true as const, caseId: value.caseId };
    });
  }
}

export class DistributedMutationCoordinatorError extends Error { public constructor(public readonly code: string, public readonly statusCode: number) { super(code); this.name = "DistributedMutationCoordinatorError"; } }
function authError(code: string): DistributedMutationCoordinatorError { return new DistributedMutationCoordinatorError(code, 401); }
function conflict(code: string): DistributedMutationCoordinatorError { return new DistributedMutationCoordinatorError(code, 409); }
function invalid(code: string): DistributedMutationCoordinatorError { return new DistributedMutationCoordinatorError(code, 400); }
function header(headers: IncomingHttpHeaders, name: string): string | undefined { const value = headers[name]; return Array.isArray(value) ? value[0] : value; }
function tokenHash(value: string): string { return createHash("sha256").update(`${protocol}\0`).update(value).digest("hex"); }
function canonical(value: unknown): string { return JSON.stringify(sort(value)); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) => [key, sort(item)])); return value; }
function record(input: unknown): Record<string, unknown> { if (!input || typeof input !== "object" || Array.isArray(input)) throw invalid("MUTATION_COORDINATOR_REQUEST_INVALID"); return input as Record<string, unknown>; }
function text(value: unknown, pattern: RegExp, code: string): string { if (typeof value !== "string" || !pattern.test(value)) throw invalid(code); return value; }
function ensureNamespace(value: string): string { return text(value, namespacePattern, "MUTATION_COORDINATOR_NAMESPACE_INVALID"); }
function acquireInput(input: unknown): { namespace: string; caseId: string; holderId: string; recovery: boolean } { const value=record(input); if(typeof value.recovery!=="boolean")throw invalid("MUTATION_COORDINATOR_REQUEST_INVALID"); return { namespace:ensureNamespace(String(value.namespace??"")),caseId:text(value.caseId,casePattern,"MUTATION_COORDINATOR_CASE_INVALID"),holderId:text(value.holderId,namespacePattern,"MUTATION_COORDINATOR_HOLDER_INVALID"),recovery:value.recovery }; }
function leaseInput(input: unknown): { namespace: string; leaseId: string; leaseToken: string; holderId: string } { const value=record(input); return { namespace:ensureNamespace(String(value.namespace??"")),leaseId:text(value.leaseId,/^[0-9a-f-]{36}$/i,"MUTATION_COORDINATOR_LEASE_INVALID"),leaseToken:text(value.leaseToken,/^[A-Za-z0-9_-]{32,200}$/,"MUTATION_COORDINATOR_LEASE_INVALID"),holderId:text(value.holderId,namespacePattern,"MUTATION_COORDINATOR_HOLDER_INVALID") }; }
function releaseInput(input: unknown): ReturnType<typeof leaseInput> & { cleanup: { state: "CLEAN"|"UNRESOLVED"|"UNKNOWN"; stage?: string; obligations: Array<{caseId:string;stage:string}> } } { const value=record(input); const lease=leaseInput(value); const cleanup=record(value.cleanup); if(!["CLEAN","UNRESOLVED","UNKNOWN"].includes(String(cleanup.state)))throw invalid("MUTATION_COORDINATOR_CLEANUP_STATE_INVALID"); const stage=cleanup.stage===undefined?undefined:text(cleanup.stage,/^[A-Z][A-Z0-9_]{1,99}$/,"MUTATION_COORDINATOR_STAGE_INVALID"); if(cleanup.obligations!==undefined&&!Array.isArray(cleanup.obligations))throw invalid("MUTATION_COORDINATOR_OBLIGATIONS_INVALID"); const raw=cleanup.obligations as unknown[]|undefined;if((raw?.length??0)>1000)throw invalid("MUTATION_COORDINATOR_OBLIGATIONS_INVALID");const obligations=(raw??[]).map((item)=>{const entry=record(item);return{caseId:text(entry.caseId,casePattern,"MUTATION_COORDINATOR_CASE_INVALID"),stage:text(entry.stage,/^[A-Z][A-Z0-9_]{1,99}$/,"MUTATION_COORDINATOR_STAGE_INVALID")};});if(new Set(obligations.map((entry)=>entry.caseId)).size!==obligations.length)throw invalid("MUTATION_COORDINATOR_OBLIGATIONS_INVALID"); return { ...lease, cleanup:{ state:cleanup.state as "CLEAN"|"UNRESOLVED"|"UNKNOWN", ...(stage?{stage}:{}),obligations } }; }
function operatorInput(input: unknown, confirmation: string): { namespace: string } { const value=record(input); if(value.confirmation!==confirmation)throw invalid("MUTATION_COORDINATOR_CONFIRMATION_REQUIRED"); return {namespace:ensureNamespace(String(value.namespace??""))}; }
function resolveInput(input: unknown): { namespace: string; caseId: string } { const value=record(input); if(value.confirmation!=="I_VERIFIED_NO_MUTATION_WAS_TRANSMITTED_OR_TARGET_STATE_IS_RESTORED")throw invalid("MUTATION_COORDINATOR_CONFIRMATION_REQUIRED"); return {namespace:ensureNamespace(String(value.namespace??"")),caseId:text(value.caseId,casePattern,"MUTATION_COORDINATOR_CASE_INVALID")}; }
interface LeaseStatusRow { id:string;case_id:string;recovery:number;acquired_at:string;heartbeat_at:string;expires_at:string }
interface ObligationRow { case_id:string;state:string;stage:string|null;first_seen_at:string;updated_at:string }
function upsertObligation(database: DashboardDatabase, namespace: string, caseId: string, state: "UNRESOLVED"|"UNKNOWN", stage: string, now: string): void { database.db.prepare(`INSERT INTO distributed_mutation_obligations(namespace,case_id,state,stage,first_seen_at,updated_at) VALUES (?, ?, ?, ?, ?, ?)
  ON CONFLICT(namespace,case_id) DO UPDATE SET state=excluded.state,stage=excluded.stage,updated_at=excluded.updated_at`).run(namespace, caseId, state, stage, now, now); }
