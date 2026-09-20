import { createHmac, randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { nowIso } from "../db/DashboardDatabase.js";
import { HttpClient } from "../../core/http/HttpClient.js";
import type { z } from "zod";
import type { notificationChannelSchema, notificationEnqueueSchema } from "../contracts/OperationalScaleSchemas.js";
import { redactDashboardValue } from "../security/Redaction.js";

type ChannelInput = z.infer<typeof notificationChannelSchema>;
type EnqueueInput = z.infer<typeof notificationEnqueueSchema>;

export class NotificationService {
  private timer: ReturnType<typeof setInterval> | undefined;
  private activeFlush: Promise<void> | undefined;
  public constructor(private readonly database: DashboardDatabase) {}

  public start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.flush(), 2000); this.timer.unref();
    void this.flush();
  }

  public async shutdown(): Promise<void> { if (this.timer) clearInterval(this.timer); this.timer = undefined; await this.activeFlush; }

  public create(input: ChannelInput, actor: string): string {
    const id = randomUUID(); const now = nowIso();
    this.database.db.prepare(`INSERT INTO notification_channels (id,organization_id,name,kind,endpoint,secret_env,configuration_json,enabled,created_by,created_at,updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, input.organizationId, input.name, input.kind, input.endpoint ?? null, input.secretEnv ?? null, JSON.stringify(input.configuration), input.enabled ? 1 : 0, actor, now, now);
    return id;
  }

  public list(organizationId: string): unknown[] {
    const rows = this.database.db.prepare("SELECT id,name,kind,endpoint,secret_env,configuration_json,enabled,created_at,updated_at FROM notification_channels WHERE organization_id=? ORDER BY name").all(organizationId) as ChannelRow[];
    return rows.map((row) => ({ id: row.id, name: row.name, kind: row.kind, endpointConfigured: Boolean(row.endpoint), secretEnvironment: row.secret_env, secretAvailable: Boolean(row.secret_env && process.env[row.secret_env]), configuration: JSON.parse(row.configuration_json), enabled: row.enabled === 1, createdAt: row.created_at, updatedAt: row.updated_at }));
  }

  public enqueue(input: EnqueueInput): string[] {
    if (JSON.stringify(redactDashboardValue(input.payload)) !== JSON.stringify(input.payload)) throw new Error("NOTIFICATION_SECRET_MATERIAL_REJECTED");
    const now = nowIso(); const ids: string[] = [];
    this.database.transaction(() => {
      for (const channelId of input.channelIds) {
        const channel = this.database.db.prepare("SELECT id FROM notification_channels WHERE id=? AND enabled=1").get(channelId);
        if (!channel) throw new Error("NOTIFICATION_CHANNEL_NOT_FOUND_OR_DISABLED");
        const id = randomUUID();
        this.database.db.prepare(`INSERT OR IGNORE INTO notification_deliveries (id,channel_id,event_type,resource_type,resource_id,safe_payload_json,idempotency_key,status,next_attempt_at,created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)`).run(id, channelId, input.eventType, input.resourceType, input.resourceId ?? null, JSON.stringify(input.payload), input.idempotencyKey, now, now);
        const delivery = this.database.db.prepare("SELECT id FROM notification_deliveries WHERE channel_id=? AND idempotency_key=?").get(channelId, input.idempotencyKey) as { id: string };
        ids.push(delivery.id);
      }
    });
    void this.flush(); return ids;
  }

  public organizationForChannels(channelIds: readonly string[]): string {
    const rows = this.database.db.prepare(`SELECT DISTINCT organization_id FROM notification_channels WHERE id IN (${channelIds.map(() => "?").join(",")})`).all(...channelIds) as Array<{ organization_id: string }>;
    if (rows.length !== 1) throw new Error("NOTIFICATION_CHANNEL_ORGANIZATION_MISMATCH");
    return rows[0]!.organization_id;
  }

  public deliveries(organizationId: string): unknown[] {
    return this.database.db.prepare(`SELECT d.id,c.name AS channelName,c.kind,d.event_type AS eventType,d.resource_type AS resourceType,d.status,d.attempt_count AS attemptCount,d.next_attempt_at AS nextAttemptAt,d.delivered_at AS deliveredAt,d.response_status AS responseStatus,d.safe_error AS safeError,d.created_at AS createdAt
      FROM notification_deliveries d JOIN notification_channels c ON c.id=d.channel_id WHERE c.organization_id=? ORDER BY d.created_at DESC LIMIT 200`).all(organizationId);
  }

  public async flush(): Promise<void> {
    if (this.activeFlush) return this.activeFlush;
    const work = Promise.resolve().then(async () => {
      this.database.db.prepare("UPDATE notification_deliveries SET status='RETRY',next_attempt_at=?,safe_error=COALESCE(safe_error,'Interrupted delivery recovered.') WHERE status='DELIVERING' AND last_attempt_at<?").run(nowIso(), new Date(Date.now() - 10 * 60_000).toISOString());
      this.bridgeContinuousAssurance();
      const due = this.database.db.prepare(`SELECT d.*,c.kind,c.endpoint,c.secret_env,c.configuration_json FROM notification_deliveries d JOIN notification_channels c ON c.id=d.channel_id
        WHERE c.enabled=1 AND d.status IN ('PENDING','RETRY') AND d.next_attempt_at<=? ORDER BY d.created_at LIMIT 20`).all(nowIso()) as DeliveryRow[];
      for (const row of due) await this.deliver(row);
    });
    this.activeFlush = work;
    try { await work; } finally { if (this.activeFlush === work) this.activeFlush = undefined; }
  }

  private bridgeContinuousAssurance(): void {
    const organization=this.database.db.prepare("SELECT value FROM dashboard_meta WHERE key='default_organization_id'").get() as {value:string}|undefined;if(!organization)return;
    const rows=this.database.db.prepare(`SELECT n.id,n.run_id,n.category,n.severity,n.safe_summary,c.id AS channel_id,c.configuration_json FROM continuous_assurance_notifications n CROSS JOIN notification_channels c
      WHERE c.organization_id=? AND c.enabled=1 AND NOT EXISTS (SELECT 1 FROM notification_deliveries d WHERE d.channel_id=c.id AND d.idempotency_key='continuous-assurance:'||n.id)
      ORDER BY n.created_at LIMIT 200`).all(organization.value) as Array<{id:string;run_id:string;category:string;severity:string;safe_summary:string;channel_id:string;configuration_json:string}>;
    for(const row of rows){const configuration=JSON.parse(row.configuration_json) as {minimumSeverity?:"INFO"|"WARNING"|"CRITICAL"};const severity=row.severity==="CRITICAL"?"CRITICAL":"WARNING";if(severityRank(severity)<severityRank(configuration.minimumSeverity??"WARNING"))continue;this.enqueue({channelIds:[row.channel_id],eventType:`CONTINUOUS_ASSURANCE_${row.category}`.replace(/[^A-Z0-9_]/g,"_"),resourceType:"CONTINUOUS_ASSURANCE_RUN",resourceId:row.run_id,idempotencyKey:`continuous-assurance:${row.id}`,payload:{title:`Continuous assurance: ${row.category.replaceAll("_"," ")}`,summary:row.safe_summary,severity}});}
  }

  private async deliver(row: DeliveryRow): Promise<void> {
    const claimed = this.database.db.prepare("UPDATE notification_deliveries SET status='DELIVERING',attempt_count=attempt_count+1,last_attempt_at=? WHERE id=? AND status IN ('PENDING','RETRY')").run(nowIso(), row.id);
    if (claimed.changes !== 1) return;
    const payload = JSON.parse(row.safe_payload_json) as EnqueueInput["payload"];
    let client: HttpClient | undefined;
    try {
      const target = deliveryTarget(row);
      const body = JSON.stringify(deliveryBody(row.kind, payload, JSON.parse(row.configuration_json) as Record<string, unknown>));
      const secret = row.secret_env ? process.env[row.secret_env] : undefined;
      if (row.secret_env && !secret) throw new Error("CHANNEL_SECRET_ENV_UNAVAILABLE");
      const headers: Record<string, string> = { "content-type": "application/json", "idempotency-key": row.idempotency_key };
      if (row.kind === "WEBHOOK" && secret) headers["x-routecairn-signature"] = `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;
      if (["GITHUB", "JIRA", "EMAIL"].includes(row.kind) && secret) headers.authorization = `Bearer ${secret}`;
      client = new HttpClient({ userAgent: "RouteCairn-Notifications/1", timeoutMs: 10_000, bodyPreviewBytes: 2048, maxResponseBytes: 8192, transport: { maxOrigins: 8, maxConnectionsPerOrigin: 2, dnsCacheTtlMs: 0 } });
      const response = await client.send({ url: target, method: "POST", headers, body, disableRedirects: true, disableRetries: true });
      if (response.error || !response.statusCode || response.statusCode < 200 || response.statusCode >= 300) throw new DeliveryFailure(response.statusCode, response.error?.code ?? `HTTP_${response.statusCode ?? 0}`);
      this.database.db.prepare("UPDATE notification_deliveries SET status='DELIVERED',delivered_at=?,response_status=?,safe_error=NULL WHERE id=?").run(nowIso(), response.statusCode, row.id);
    } catch (error) {
      const current = this.database.db.prepare("SELECT attempt_count FROM notification_deliveries WHERE id=?").get(row.id) as { attempt_count: number };
      const final = current.attempt_count >= 6; const delay = Math.min(3600_000, 1000 * (2 ** current.attempt_count));
      this.database.db.prepare("UPDATE notification_deliveries SET status=?,next_attempt_at=?,response_status=?,safe_error=? WHERE id=?").run(final ? "FAILED" : "RETRY", new Date(Date.now() + delay).toISOString(), error instanceof DeliveryFailure ? error.status : null, safeDeliveryError(error), row.id);
    } finally { await client?.close(); }
  }
}

class DeliveryFailure extends Error { public constructor(public readonly status: number | undefined, code: string) { super(code); } }
function deliveryTarget(row: DeliveryRow): string {
  if (row.kind === "SLACK") { const value = row.secret_env ? process.env[row.secret_env] : undefined; if (!value?.startsWith("https://")) throw new Error("SLACK_WEBHOOK_ENV_INVALID"); return value; }
  if (!row.endpoint) throw new Error("NOTIFICATION_ENDPOINT_MISSING"); return row.endpoint;
}
function deliveryBody(kind: string, payload: EnqueueInput["payload"], configuration: Record<string, unknown>): unknown {
  if (kind === "SLACK") return { text: `${payload.severity}: ${payload.title}\n${payload.summary}${payload.url ? `\n${payload.url}` : ""}` };
  if (kind === "EMAIL") return { from: configuration.sender, to: configuration.recipients, subject: `[${payload.severity}] ${payload.title}`, text: `${payload.summary}${payload.url ? `\n\n${payload.url}` : ""}` };
  if (kind === "GITHUB") return { title: payload.title, body: `${payload.summary}${payload.url ? `\n\n${payload.url}` : ""}`, labels: configuration.labels ?? [] };
  if (kind === "JIRA") return { fields: { project: { key: configuration.projectKey }, summary: payload.title, description: payload.summary, issuetype: { name: "Bug" }, labels: configuration.labels ?? [] } };
  return payload;
}
function safeDeliveryError(error: unknown): string { const code = error instanceof Error ? error.message : "DELIVERY_FAILED"; return code.replace(/https?:\/\/[^\s]+/gi, "<endpoint>").slice(0, 500); }

interface ChannelRow { id: string; name: string; kind: string; endpoint: string | null; secret_env: string | null; configuration_json: string; enabled: number; created_at: string; updated_at: string }
interface DeliveryRow { id: string; idempotency_key: string; kind: string; endpoint: string | null; secret_env: string | null; configuration_json: string; safe_payload_json: string }
function severityRank(value:"INFO"|"WARNING"|"CRITICAL"):number{return value==="CRITICAL"?3:value==="WARNING"?2:1;}
