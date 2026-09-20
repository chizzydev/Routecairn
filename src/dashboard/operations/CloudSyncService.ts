import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { HttpClient } from "../../core/http/HttpClient.js";

export class CloudSyncService {
  public constructor(private readonly database: DashboardDatabase) {}

  public createPeer(input: { organizationId: string; name: string; endpoint: string; sharedSecretEnv: string; enabled: boolean }, actor: string): string {
    const id = randomUUID(); const now = nowIso();
    this.database.db.prepare("INSERT INTO cloud_sync_peers (id,organization_id,name,endpoint,shared_secret_env,enabled,created_by,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(id, input.organizationId, input.name, input.endpoint, input.sharedSecretEnv, input.enabled ? 1 : 0, actor, now, now);
    return id;
  }

  public list(organizationId: string): unknown[] {
    const rows = this.database.db.prepare("SELECT id,name,endpoint,shared_secret_env,enabled,outbound_cursor,inbound_cursor,created_at,updated_at FROM cloud_sync_peers WHERE organization_id=? ORDER BY name").all(organizationId) as PeerRow[];
    return rows.map((row) => ({ id: row.id, name: row.name, endpoint: row.endpoint, secretEnvironment: row.shared_secret_env, secretAvailable: Boolean(process.env[row.shared_secret_env]), enabled: row.enabled === 1, outboundCursor: row.outbound_cursor, inboundCursor: row.inbound_cursor, createdAt: row.created_at, updatedAt: row.updated_at }));
  }

  public record(organizationId: string, entityType: string, entityId: string, operation: "UPSERT" | "DELETE", safePayload: Record<string, unknown>): string {
    ensureSafePayload(safePayload); const eventId = randomUUID(); const payload = canonical(safePayload); const installationId = this.meta("installation_id");
    this.database.db.prepare("INSERT INTO cloud_sync_events (organization_id,event_id,entity_type,entity_id,operation,safe_payload_json,payload_digest,origin_installation_id,created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(organizationId, eventId, entityType.slice(0, 100), entityId.slice(0, 200), operation, payload, hash(payload), installationId, nowIso());
    return eventId;
  }

  public batch(peerId: string): { cursor: number; events: unknown[]; signature: string } {
    const peer = this.peer(peerId); const secret = this.secret(peer);
    const rows = this.database.db.prepare("SELECT sequence,event_id,entity_type,entity_id,operation,safe_payload_json,payload_digest,origin_installation_id,created_at FROM cloud_sync_events WHERE organization_id=? AND sequence>? ORDER BY sequence LIMIT 500").all(peer.organization_id, peer.outbound_cursor) as EventRow[];
    const cursor = rows.at(-1)?.sequence ?? peer.outbound_cursor;
    const events = rows.map((row) => ({ eventId: row.event_id, entityType: row.entity_type, entityId: row.entity_id, operation: row.operation, payload: JSON.parse(row.safe_payload_json), payloadDigest: row.payload_digest, originInstallationId: row.origin_installation_id, createdAt: row.created_at }));
    const body = canonical({ organizationId: peer.organization_id, cursor, events });
    return { cursor, events, signature: sign(body, secret) };
  }

  public receive(peerId: string, body: { organizationId: string; cursor: number; events: Array<{ eventId: string; entityType: string; entityId: string; operation: "UPSERT" | "DELETE"; payload: Record<string, unknown>; payloadDigest: string; originInstallationId: string; createdAt: string }> }, signature: string): { accepted: number; cursor: number } {
    const peer = this.peer(peerId); if (peer.organization_id !== body.organizationId) throw new CloudSyncAuthError("CLOUD_SYNC_AUTH_REJECTED");
    if (!constantEqual(sign(canonical(body), this.secret(peer)), signature)) throw new CloudSyncAuthError("CLOUD_SYNC_AUTH_REJECTED");
    let accepted = 0;
    this.database.transaction(() => {
      for (const event of body.events) {
        ensureSafePayload(event.payload); const payload = canonical(event.payload); if (hash(payload) !== event.payloadDigest) throw new Error("CLOUD_SYNC_DIGEST_REJECTED");
        const result = this.database.db.prepare("INSERT OR IGNORE INTO cloud_sync_events (organization_id,event_id,entity_type,entity_id,operation,safe_payload_json,payload_digest,origin_installation_id,created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(body.organizationId, event.eventId, event.entityType, event.entityId, event.operation, payload, event.payloadDigest, event.originInstallationId, event.createdAt);
        accepted += result.changes;
      }
      this.database.db.prepare("UPDATE cloud_sync_peers SET inbound_cursor=MAX(inbound_cursor,?),updated_at=? WHERE id=?").run(body.cursor, nowIso(), peerId);
    });
    return { accepted, cursor: body.cursor };
  }

  public receiveFromPeer(peerName: string, body: Parameters<CloudSyncService["receive"]>[1], signature: string): { accepted: number; cursor: number } {
    const peer = this.database.db.prepare("SELECT * FROM cloud_sync_peers WHERE organization_id=? AND name=? AND enabled=1").get(body.organizationId, peerName) as PeerFull | undefined;
    if (!peer) throw new CloudSyncAuthError("CLOUD_SYNC_AUTH_REJECTED");
    return this.receive(peer.id, body, signature);
  }

  public async push(peerId: string): Promise<{ sent: number; cursor: number }> {
    const peer = this.peer(peerId); const batch = this.batch(peerId); if (batch.events.length === 0) return { sent: 0, cursor: batch.cursor };
    const body = { organizationId: peer.organization_id, cursor: batch.cursor, events: batch.events }; let client: HttpClient | undefined;
    try {
      client = new HttpClient({ userAgent: "RouteCairn-CloudSync/1", timeoutMs: 15_000, bodyPreviewBytes: 4096, maxResponseBytes: 8192 });
      const response = await client.send({ url: `${peer.endpoint.replace(/\/$/, "")}/api/cloud-sync/receive`, method: "POST", headers: { "content-type": "application/json", "x-routecairn-sync-peer": peer.name, "x-routecairn-sync-signature": sign(canonical(body), this.secret(peer)) }, body: canonical(body), disableRedirects: true, disableRetries: true });
      if (response.error || !response.statusCode || response.statusCode < 200 || response.statusCode >= 300) throw new Error(`CLOUD_SYNC_PUSH_FAILED:${response.statusCode ?? response.error?.code ?? "TRANSPORT"}`);
      this.database.db.prepare("UPDATE cloud_sync_peers SET outbound_cursor=?,updated_at=? WHERE id=?").run(batch.cursor, nowIso(), peerId);
      return { sent: batch.events.length, cursor: batch.cursor };
    } finally { await client?.close(); }
  }

  public organizationForPeer(peerId: string): string { return this.peer(peerId).organization_id; }
  private peer(id: string): PeerFull { const row = this.database.db.prepare("SELECT * FROM cloud_sync_peers WHERE id=? AND enabled=1").get(id) as PeerFull | undefined; if (!row) throw new Error("CLOUD_SYNC_PEER_NOT_FOUND"); return row; }
  private secret(peer: PeerFull): string { const value = process.env[peer.shared_secret_env]; if (!value || value.length < 32) throw new Error("CLOUD_SYNC_SECRET_UNAVAILABLE"); return value; }
  private meta(key: string): string { const row = this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key=?").get(key) as { value: string } | undefined; if (!row) throw new Error(`DASHBOARD_META_MISSING:${key}`); return row.value; }
}

export class CloudSyncAuthError extends Error { public constructor(message: string) { super(message); this.name="CloudSyncAuthError"; } }

function canonical(value: unknown): string { return JSON.stringify(sort(value)); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sort(item)])); return value; }
function hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function sign(value: string, secret: string): string { return createHmac("sha256", secret).update("routecairn-sync-v1\0").update(value).digest("hex"); }
function constantEqual(left: string, right: string): boolean { const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }
interface PeerRow { id: string; name: string; endpoint: string; shared_secret_env: string; enabled: number; outbound_cursor: number; inbound_cursor: number; created_at: string; updated_at: string }
interface PeerFull extends PeerRow { organization_id: string }
interface EventRow { sequence: number; event_id: string; entity_type: string; entity_id: string; operation: string; safe_payload_json: string; payload_digest: string; origin_installation_id: string; created_at: string }
function ensureSafePayload(value: Record<string, unknown>): void { const serialized=canonical(value);if(Buffer.byteLength(serialized)>256*1024)throw new Error("CLOUD_SYNC_PAYLOAD_TOO_LARGE");const visit=(item:unknown,depth:number):void=>{if(depth>12)throw new Error("CLOUD_SYNC_PAYLOAD_TOO_DEEP");if(Array.isArray(item)){item.forEach((child)=>visit(child,depth+1));return;}if(item&&typeof item==="object")for(const [key,child] of Object.entries(item as Record<string,unknown>)){if(/(?:password|passwd|secret|token|cookie|authorization|private[_-]?key|api[_-]?key|credential|session|jwt|signature|signed)/i.test(key))throw new Error("CLOUD_SYNC_SECRET_FIELD_REJECTED");visit(child,depth+1);}};visit(value,0); }
