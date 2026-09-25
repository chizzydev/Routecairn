import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { HttpClient } from "../../core/http/HttpClient.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import { OrganizationStateMergeService, type OrganizationStateSnapshot } from "./OrganizationStateMergeService.js";

export class CloudSyncService {
  private timer: ReturnType<typeof setInterval> | undefined;
  private running: Promise<CloudSyncCycleResult> | undefined;
  private readonly organizationRuns = new Map<string, Promise<CloudSyncCycleResult>>();
  private readonly stateMerge: OrganizationStateMergeService;
  public constructor(private readonly database: DashboardDatabase, vault?: CredentialVault) { this.stateMerge = new OrganizationStateMergeService(database, vault); }

  public start(intervalMs = syncInterval()): void {
    if (this.timer) return;
    void this.synchronizeNow().catch(() => undefined);
    this.timer = setInterval(() => { void this.synchronizeNow().catch(() => undefined); }, intervalMs); this.timer.unref();
  }

  public async shutdown(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.running?.catch(() => undefined);
    await Promise.all([...this.organizationRuns.values()].map((run) => run.catch(() => undefined)));
  }

  public synchronizeNow(): Promise<CloudSyncCycleResult> {
    if (this.running) return this.running;
    this.running = this.performCycle().finally(() => { this.running = undefined; });
    return this.running;
  }

  public synchronizeOrganization(organizationId: string): Promise<CloudSyncCycleResult> {
    const active = this.organizationRuns.get(organizationId);
    if (active) return active;
    const run = this.performOrganizationCycle(organizationId).finally(() => {
      if (this.organizationRuns.get(organizationId) === run) this.organizationRuns.delete(organizationId);
    });
    this.organizationRuns.set(organizationId, run);
    return run;
  }

  public createPeer(input: { organizationId: string; remoteOrganizationId?: string; name: string; endpoint: string; sharedSecretEnv: string; enabled: boolean; syncMode?: "FULL_STATE" | "SAFE_EVENTS" }, actor: string): string {
    const id = randomUUID(); const now = nowIso();
    this.database.db.prepare("INSERT INTO cloud_sync_peers (id,organization_id,remote_organization_id,name,endpoint,shared_secret_env,enabled,sync_mode,created_by,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(id, input.organizationId, input.remoteOrganizationId ?? null, input.name, input.endpoint, input.sharedSecretEnv, input.enabled ? 1 : 0, input.syncMode ?? "FULL_STATE", actor, now, now);
    return id;
  }

  public list(organizationId: string): unknown[] {
    const rows = this.database.db.prepare("SELECT id,organization_id,name,endpoint,remote_organization_id,shared_secret_env,enabled,sync_mode,last_state_digest,state_cursor,state_cursor_digest,outbound_cursor,inbound_cursor,last_attempt_at,last_success_at,safe_error,created_at,updated_at FROM cloud_sync_peers WHERE organization_id=? ORDER BY name").all(organizationId) as PeerRow[];
    return rows.map((row) => ({ id: row.id, name: row.name, endpoint: row.endpoint, remoteOrganizationId: row.remote_organization_id ?? row.organization_id, secretEnvironment: row.shared_secret_env, secretAvailable: Boolean(process.env[row.shared_secret_env]), enabled: row.enabled === 1, syncMode: row.sync_mode, stateSynchronized: Boolean(row.last_state_digest)&&!row.state_cursor,continuationPending:Boolean(row.state_cursor), outboundCursor: row.outbound_cursor, inboundCursor: row.inbound_cursor, lastAttemptAt: row.last_attempt_at, lastSuccessAt: row.last_success_at, safeError: row.safe_error, createdAt: row.created_at, updatedAt: row.updated_at }));
  }

  public replicas(organizationId: string): unknown[] { return this.database.db.prepare("SELECT origin_installation_id AS originInstallationId,entity_type AS entityType,entity_id AS entityId,operation,safe_payload_json AS safePayloadJson,payload_digest AS payloadDigest,event_id AS eventId,event_created_at AS eventCreatedAt,materialized_at AS materializedAt FROM cloud_sync_replicas WHERE organization_id=? ORDER BY materialized_at DESC LIMIT 2000").all(organizationId).map((row) => { const { safePayloadJson, ...metadata } = row as Record<string, unknown>; return { ...metadata, payload: JSON.parse(String(safePayloadJson)) }; }); }
  public pendingMemberships(organizationId:string):unknown[]{return this.stateMerge.pendingMemberships(organizationId);}
  public bindMembership(organizationId:string,originInstallationId:string,sourceUserId:string,localUserId:string):void{this.stateMerge.bindMembership(organizationId,originInstallationId,sourceUserId,localUserId);}

  public record(organizationId: string, entityType: string, entityId: string, operation: "UPSERT" | "DELETE", safePayload: Record<string, unknown>): string {
    ensureSafePayload(safePayload); const eventId = randomUUID(); const payload = canonical(safePayload); const installationId = this.meta("installation_id");
    const createdAt=nowIso(); const normalizedType=entityType.slice(0,100),normalizedId=entityId.slice(0,200),payloadDigest=hash(payload);
    this.database.db.prepare("INSERT INTO cloud_sync_events (organization_id,event_id,entity_type,entity_id,operation,safe_payload_json,payload_digest,origin_installation_id,created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(organizationId, eventId, normalizedType, normalizedId, operation, payload, payloadDigest, installationId, createdAt);
    this.materialize({ organizationId, eventId, entityType: normalizedType, entityId: normalizedId, operation, payload: safePayload, payloadDigest, originInstallationId: installationId, createdAt });
    return eventId;
  }

  public batch(peerId: string): { organizationId: string; cursor: number; events: unknown[]; state?: OrganizationStateSnapshot; signature: string } {
    const peer = this.peer(peerId); const secret = this.secret(peer);
    const rows = this.database.db.prepare("SELECT sequence,event_id,entity_type,entity_id,operation,safe_payload_json,payload_digest,origin_installation_id,created_at FROM cloud_sync_events WHERE organization_id=? AND sequence>? ORDER BY sequence LIMIT 10").all(peer.organization_id, peer.outbound_cursor) as EventRow[];
    const cursor = rows.at(-1)?.sequence ?? peer.outbound_cursor;
    const events = rows.map((row) => ({ eventId: row.event_id, entityType: row.entity_type, entityId: row.entity_id, operation: row.operation, payload: JSON.parse(row.safe_payload_json), payloadDigest: row.payload_digest, originInstallationId: row.origin_installation_id, createdAt: row.created_at }));
    const organizationId = peer.remote_organization_id ?? peer.organization_id;
    const snapshot = peer.sync_mode === "FULL_STATE" ? this.stateMerge.snapshot(peer.organization_id, secret, organizationId) : undefined;
    const effectiveCursor=snapshot&&peer.state_cursor_digest===snapshot.stateDigest?peer.state_cursor:null;
    const state = snapshot && snapshot.entities.length>0 && (peer.state_cursor||snapshot.stateDigest!==peer.last_state_digest) ? this.stateMerge.page(snapshot,effectiveCursor) : undefined;
    const unsigned = { organizationId, cursor, events, ...(state ? { state } : {}) };
    const body = canonical(unsigned);
    return { ...unsigned, signature: sign(body, secret) };
  }

  public receive(peerId: string, body: { organizationId: string; cursor: number; events: Array<{ eventId: string; entityType: string; entityId: string; operation: "UPSERT" | "DELETE"; payload: Record<string, unknown>; payloadDigest: string; originInstallationId: string; createdAt: string }>; state?: OrganizationStateSnapshot | undefined }, signature: string): { accepted: number; cursor: number; state?: { applied:number; ignored:number; conflicts:number } } {
    const peer = this.peer(peerId); if (peer.organization_id !== body.organizationId || body.cursor < peer.inbound_cursor) throw new CloudSyncAuthError("CLOUD_SYNC_AUTH_REJECTED");
    if (!constantEqual(sign(canonical(body), this.secret(peer)), signature)) throw new CloudSyncAuthError("CLOUD_SYNC_AUTH_REJECTED");
    let accepted = 0; let stateResult: {applied:number;ignored:number;conflicts:number}|undefined;
    this.database.transaction(() => {
      for (const event of body.events) {
        ensureSafePayload(event.payload); const payload = canonical(event.payload); if (hash(payload) !== event.payloadDigest) throw new Error("CLOUD_SYNC_DIGEST_REJECTED");
        const result = this.database.db.prepare("INSERT OR IGNORE INTO cloud_sync_events (organization_id,event_id,entity_type,entity_id,operation,safe_payload_json,payload_digest,origin_installation_id,created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(body.organizationId, event.eventId, event.entityType, event.entityId, event.operation, payload, event.payloadDigest, event.originInstallationId, event.createdAt);
        accepted += result.changes; if (result.changes === 1) this.materialize({ organizationId: body.organizationId, ...event, payload: event.payload });
      }
      this.database.db.prepare("UPDATE cloud_sync_peers SET inbound_cursor=MAX(inbound_cursor,?),updated_at=? WHERE id=?").run(body.cursor, nowIso(), peerId);
      if(body.state){if(peer.sync_mode!=="FULL_STATE")throw new CloudSyncAuthError("CLOUD_SYNC_STATE_NOT_ENABLED");stateResult=this.stateMerge.merge(body.organizationId,body.state,this.secret(peer));}
    });
    return { accepted, cursor: body.cursor, ...(stateResult ? { state: stateResult } : {}) };
  }

  public receiveFromPeer(peerName: string, body: Parameters<CloudSyncService["receive"]>[1], signature: string): { accepted: number; cursor: number } {
    const peer = this.database.db.prepare("SELECT * FROM cloud_sync_peers WHERE organization_id=? AND name=? AND enabled=1").get(body.organizationId, peerName) as PeerFull | undefined;
    if (!peer) throw new CloudSyncAuthError("CLOUD_SYNC_AUTH_REJECTED");
    return this.receive(peer.id, body, signature);
  }

  public async push(peerId: string): Promise<{ sent: number; cursor: number; hasMore:boolean }> {
    const peer = this.peer(peerId); const batch = this.batch(peerId); if (batch.events.length === 0 && !batch.state) return { sent: 0, cursor: batch.cursor,hasMore:false };
    const body = { organizationId: batch.organizationId, cursor: batch.cursor, events: batch.events, ...(batch.state ? { state: batch.state } : {}) }; let client: HttpClient | undefined;
    try {
      this.database.db.prepare("UPDATE cloud_sync_peers SET last_attempt_at=?,safe_error=NULL,updated_at=? WHERE id=?").run(nowIso(),nowIso(),peerId);
      client = new HttpClient({ userAgent: "RouteCairn-CloudSync/1", timeoutMs: 15_000, bodyPreviewBytes: 4096, maxResponseBytes: 8192, allowedPrivateOrigins: [new URL(peer.endpoint).origin] });
      const response = await client.send({ url: `${peer.endpoint.replace(/\/$/, "")}/api/cloud-sync/receive`, method: "POST", headers: { "content-type": "application/json", "x-routecairn-sync-peer": peer.name, "x-routecairn-sync-signature": sign(canonical(body), this.secret(peer)) }, body: canonical(body), disableRedirects: true, disableRetries: true });
      if (response.error || !response.statusCode || response.statusCode < 200 || response.statusCode >= 300) throw new Error(`CLOUD_SYNC_PUSH_FAILED:${response.statusCode ?? response.error?.code ?? "TRANSPORT"}`);
      let acknowledgement: { cursor?: unknown; state?: { conflicts?: unknown } };
      try { acknowledgement=JSON.parse(response.bodyPreview ?? "") as typeof acknowledgement; }
      catch { throw new Error("CLOUD_SYNC_ACKNOWLEDGEMENT_REJECTED"); }
      if (acknowledgement.cursor!==batch.cursor || (batch.state && (!acknowledgement.state || acknowledgement.state.conflicts!==0)))
        throw new Error("CLOUD_SYNC_STATE_CONFLICT_OR_ACKNOWLEDGEMENT_REJECTED");
      this.database.db.prepare("UPDATE cloud_sync_peers SET outbound_cursor=?,state_cursor=?,state_cursor_digest=?,last_state_digest=COALESCE(?,last_state_digest),last_success_at=?,safe_error=NULL,updated_at=? WHERE id=?").run(batch.cursor,batch.state?.nextCursor??null,batch.state?.nextCursor?(batch.state.fullStateDigest??batch.state.stateDigest):null,batch.state&&!batch.state.nextCursor?(batch.state.fullStateDigest??batch.state.stateDigest):null,nowIso(),nowIso(),peerId);
      const remaining=Boolean(this.database.db.prepare("SELECT 1 FROM cloud_sync_events WHERE organization_id=? AND sequence>? LIMIT 1").get(peer.organization_id,batch.cursor));
      return { sent: batch.events.length, cursor: batch.cursor,hasMore:Boolean(batch.state?.nextCursor)||remaining };
    } catch (error) {
      this.database.db.prepare("UPDATE cloud_sync_peers SET safe_error=?,updated_at=? WHERE id=?").run(safeError(error),nowIso(),peerId); throw error;
    } finally { await client?.close(); }
  }

  public reconcileLegacy(organizationId: string): number {
    const snapshots = legacySnapshots(this.database, organizationId);
    let recorded=0;
    this.database.transaction(() => {
      for (const snapshot of snapshots) {
        const payload=canonical(snapshot.payload),payloadDigest=hash(payload);
        const prior=this.database.db.prepare("SELECT payload_digest FROM cloud_sync_legacy_state WHERE organization_id=? AND entity_type=? AND entity_id=?").get(organizationId,snapshot.entityType,snapshot.entityId) as {payload_digest:string}|undefined;
        if (prior?.payload_digest===payloadDigest) continue;
        const eventId=this.record(organizationId,snapshot.entityType,snapshot.entityId,"UPSERT",snapshot.payload);
        this.database.db.prepare("INSERT INTO cloud_sync_legacy_state (organization_id,entity_type,entity_id,payload_digest,event_id,synchronized_at) VALUES (?,?,?,?,?,?) ON CONFLICT(organization_id,entity_type,entity_id) DO UPDATE SET payload_digest=excluded.payload_digest,event_id=excluded.event_id,synchronized_at=excluded.synchronized_at").run(organizationId,snapshot.entityType,snapshot.entityId,payloadDigest,eventId,nowIso()); recorded+=1;
      }
      const current=new Set(snapshots.map((item)=>`${item.entityType}\0${item.entityId}`));
      const prior=this.database.db.prepare("SELECT entity_type,entity_id FROM cloud_sync_legacy_state WHERE organization_id=?").all(organizationId) as Array<{entity_type:string;entity_id:string}>;
      for(const row of prior){if(current.has(`${row.entity_type}\0${row.entity_id}`))continue;this.record(organizationId,row.entity_type,row.entity_id,"DELETE",{});this.database.db.prepare("DELETE FROM cloud_sync_legacy_state WHERE organization_id=? AND entity_type=? AND entity_id=?").run(organizationId,row.entity_type,row.entity_id);recorded+=1;}
    });
    return recorded;
  }

  public organizationForPeer(peerId: string): string { return this.peer(peerId).organization_id; }
  private peer(id: string): PeerFull { const row = this.database.db.prepare("SELECT * FROM cloud_sync_peers WHERE id=? AND enabled=1").get(id) as PeerFull | undefined; if (!row) throw new Error("CLOUD_SYNC_PEER_NOT_FOUND"); return row; }
  private secret(peer: PeerFull): string { const value = process.env[peer.shared_secret_env]; if (!value || value.length < 32) throw new Error("CLOUD_SYNC_SECRET_UNAVAILABLE"); return value; }
  private meta(key: string): string { const row = this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key=?").get(key) as { value: string } | undefined; if (!row) throw new Error(`DASHBOARD_META_MISSING:${key}`); return row.value; }
  private materialize(event:{organizationId:string;eventId:string;entityType:string;entityId:string;operation:"UPSERT"|"DELETE";payload:Record<string,unknown>;payloadDigest:string;originInstallationId:string;createdAt:string}):void{this.database.db.prepare(`INSERT INTO cloud_sync_replicas (organization_id,origin_installation_id,entity_type,entity_id,operation,safe_payload_json,payload_digest,event_id,event_created_at,materialized_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,origin_installation_id,entity_type,entity_id) DO UPDATE SET operation=excluded.operation,safe_payload_json=excluded.safe_payload_json,payload_digest=excluded.payload_digest,event_id=excluded.event_id,event_created_at=excluded.event_created_at,materialized_at=excluded.materialized_at WHERE excluded.event_created_at>=cloud_sync_replicas.event_created_at`).run(event.organizationId,event.originInstallationId,event.entityType,event.entityId,event.operation,canonical(event.payload),event.payloadDigest,event.eventId,event.createdAt,nowIso());}
  private async performCycle():Promise<CloudSyncCycleResult>{let snapshotEvents=0,pushedEvents=0;const failures:string[]=[];const organizations=this.database.db.prepare("SELECT id FROM organizations WHERE status='ACTIVE'").all() as Array<{id:string}>;for(const organization of organizations){const result=await this.synchronizeOrganization(organization.id);snapshotEvents+=result.snapshotEvents;pushedEvents+=result.pushedEvents;failures.push(...result.failures);}return{snapshotEvents,pushedEvents,failures};}
  private async performOrganizationCycle(organizationId: string): Promise<CloudSyncCycleResult> {
    const snapshotEvents = this.reconcileLegacy(organizationId);
    let pushedEvents = 0;
    const failures: string[] = [];
    const peers = this.database.db.prepare("SELECT id FROM cloud_sync_peers WHERE organization_id=? AND enabled=1 ORDER BY id").all(organizationId) as Array<{ id: string }>;
    for (const peer of peers) {
      try { let more=false,pages=0;do{const result=await this.push(peer.id);pushedEvents+=result.sent;more=result.hasMore;pages+=1;}while(more&&pages<32);if(more)failures.push("CLOUD_SYNC_CONTINUATION_PENDING"); }
      catch (error) { failures.push(safeError(error)); }
    }
    return { snapshotEvents, pushedEvents, failures };
  }
}

export class CloudSyncAuthError extends Error { public constructor(message: string) { super(message); this.name="CloudSyncAuthError"; } }

function canonical(value: unknown): string { return JSON.stringify(sort(value)); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sort(item)])); return value; }
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function sign(value: string, secret: string): string { return createHmac("sha256", secret).update("routecairn-sync-v1\0").update(value).digest("hex"); }
function constantEqual(left: string, right: string): boolean { const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }
export interface CloudSyncCycleResult { snapshotEvents:number; pushedEvents:number; failures:string[] }
interface PeerRow { id: string; organization_id: string; remote_organization_id: string | null; name: string; endpoint: string; shared_secret_env: string; enabled: number; sync_mode:"FULL_STATE"|"SAFE_EVENTS";last_state_digest:string|null;state_cursor:string|null;state_cursor_digest:string|null;outbound_cursor: number; inbound_cursor: number; last_attempt_at:string|null;last_success_at:string|null;safe_error:string|null;created_at: string; updated_at: string }
interface PeerFull extends PeerRow { organization_id: string }
interface EventRow { sequence: number; event_id: string; entity_type: string; entity_id: string; operation: string; safe_payload_json: string; payload_digest: string; origin_installation_id: string; created_at: string }
function ensureSafePayload(value: Record<string, unknown>): void { const serialized=canonical(value);if(Buffer.byteLength(serialized)>256*1024)throw new Error("CLOUD_SYNC_PAYLOAD_TOO_LARGE");const visit=(item:unknown,depth:number):void=>{if(depth>12)throw new Error("CLOUD_SYNC_PAYLOAD_TOO_DEEP");if(Array.isArray(item)){item.forEach((child)=>visit(child,depth+1));return;}if(item&&typeof item==="object")for(const [key,child] of Object.entries(item as Record<string,unknown>)){if(/(?:password|passwd|secret|token|cookie|authorization|private[_-]?key|api[_-]?key|credential|session|jwt|signature|signed)/i.test(key))throw new Error("CLOUD_SYNC_SECRET_FIELD_REJECTED");visit(child,depth+1);}};visit(value,0); }
function syncInterval():number{const value=Number(process.env.ROUTECAIRN_CLOUD_SYNC_INTERVAL_MS);return Number.isFinite(value)?Math.max(5_000,Math.min(3_600_000,value)):30_000;}
function safeError(error:unknown):string{return(error instanceof Error?error.message:"CLOUD_SYNC_FAILED").replace(/https?:\/\/[^\s]+/gi,"<endpoint>").replace(/[\r\n]+/g," ").slice(0,500);}
function legacySnapshots(database:DashboardDatabase,organizationId:string):Array<{entityType:string;entityId:string;payload:Record<string,unknown>}>{const snapshots:Array<{entityType:string;entityId:string;payload:Record<string,unknown>}>=[];const add=(entityType:string,rows:Array<Record<string,unknown>>)=>{for(const row of rows){const entityId=String(row.id);delete row.id;snapshots.push({entityType,entityId,payload:row});}};add("legacy.project",database.db.prepare("SELECT id,name AS displayName,row_version AS rowVersion,updated_at AS updatedAt,archived_at AS archivedAt FROM projects WHERE organization_id=?").all(organizationId) as Array<Record<string,unknown>>);add("legacy.target",database.db.prepare("SELECT id,project_id AS projectId,display_name AS displayName,base_origin AS baseOrigin,classification,authorization_type AS authorityClass,row_version AS rowVersion,updated_at AS updatedAt,archived_at AS archivedAt FROM targets WHERE organization_id=?").all(organizationId) as Array<Record<string,unknown>>);add("legacy.scan",database.db.prepare("SELECT id,project_id AS projectId,target_id AS targetId,status,safe_target_label AS safeTargetLabel,profile,evidence_level AS evidenceLevel,created_at AS createdAt,completed_at AS completedAt,finding_count AS findingCount,observation_count AS observationCount FROM scans WHERE organization_id=? AND deleted_at IS NULL").all(organizationId) as Array<Record<string,unknown>>);add("legacy.finding",database.db.prepare("SELECT id,project_id AS projectId,target_id AS targetId,module,finding_category AS category,canonical_title AS title,current_scanner_severity AS severity,current_scanner_confidence AS confidence,human_review_status AS reviewStatus,remediation_state_v2 AS remediationState,first_seen_at AS firstSeenAt,last_seen_at AS lastSeenAt,occurrence_count AS occurrenceCount,row_version AS rowVersion FROM findings WHERE organization_id=? AND archived_at IS NULL").all(organizationId) as Array<Record<string,unknown>>);return snapshots;}
