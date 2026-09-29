import pg from "pg";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import type { ControlPlaneConfig } from "./ControlPlaneConfig.js";
import type { ControlPlaneTelemetry } from "./Telemetry.js";

const { Pool, Client } = pg;

export const controlPlaneSchemaVersion = 1;

const migration = `
CREATE SCHEMA IF NOT EXISTS routecairn_control;
CREATE TABLE IF NOT EXISTS routecairn_control.schema_migrations (
  version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS routecairn_control.worker_enrollments (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, token_hash text NOT NULL UNIQUE,
  name_hint text, expires_at timestamptz NOT NULL, consumed_at timestamptz,
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS routecairn_control.workers (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, name text NOT NULL,
  public_key_pem text NOT NULL, public_key_fingerprint text NOT NULL UNIQUE,
  capabilities text[] NOT NULL, labels jsonb NOT NULL DEFAULT '{}'::jsonb,
  network_zone text NOT NULL DEFAULT 'default', resources jsonb,
  status text NOT NULL CHECK (status IN ('ONLINE','DRAINING','QUARANTINED','REVOKED')),
  generation integer NOT NULL DEFAULT 1, workload_identity text,
  last_seen_at timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS control_workers_org_status ON routecairn_control.workers(organization_id,status);
CREATE TABLE IF NOT EXISTS routecairn_control.worker_nonces (
  worker_id uuid NOT NULL REFERENCES routecairn_control.workers(id) ON DELETE CASCADE,
  nonce_hash text NOT NULL, expires_at timestamptz NOT NULL, PRIMARY KEY(worker_id,nonce_hash)
);
CREATE TABLE IF NOT EXISTS routecairn_control.jobs (
  id uuid PRIMARY KEY, organization_id uuid NOT NULL, kind text NOT NULL,
  safe_payload jsonb NOT NULL, required_capabilities text[] NOT NULL,
  network_zone text, status text NOT NULL CHECK (status IN ('QUEUED','LEASED','RUNNING','COMPLETED','FAILED')),
  priority integer NOT NULL, max_attempts integer NOT NULL, attempt_count integer NOT NULL DEFAULT 0,
  assigned_worker_id uuid REFERENCES routecairn_control.workers(id), lease_token_hash text, lease_expires_at timestamptz,
  safe_result jsonb, safe_error text, created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), started_at timestamptz, completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS control_jobs_claim ON routecairn_control.jobs(organization_id,status,priority DESC,created_at) WHERE status='QUEUED';
CREATE INDEX IF NOT EXISTS control_jobs_lease ON routecairn_control.jobs(lease_expires_at) WHERE status IN ('LEASED','RUNNING');
CREATE TABLE IF NOT EXISTS routecairn_control.object_records (
  object_key text PRIMARY KEY, organization_id uuid NOT NULL, artifact_id uuid NOT NULL UNIQUE,
  sha256 text NOT NULL, size bigint NOT NULL, content_type text NOT NULL, state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), stored_at timestamptz
);
CREATE TABLE IF NOT EXISTS routecairn_control.scheduler_runs (
  scheduler_key text PRIMARY KEY, instance_id text NOT NULL, fencing_token bigint NOT NULL,
  acquired_at timestamptz NOT NULL, renewed_at timestamptz NOT NULL, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS routecairn_control.outbox (
  id bigserial PRIMARY KEY, topic text NOT NULL, partition_key text NOT NULL, payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), published_at timestamptz
);
CREATE INDEX IF NOT EXISTS control_outbox_unpublished ON routecairn_control.outbox(id) WHERE published_at IS NULL;
`;

export class PostgresControlPlane {
  public readonly pool: pg.Pool;
  private listener?: pg.Client;
  private readonly events = new EventEmitter();
  private stopped = false;
  public constructor(private readonly config: NonNullable<ControlPlaneConfig["postgres"]>, private readonly telemetry: ControlPlaneTelemetry) {
    this.pool = new Pool({
      connectionString: config.url, max: config.maxConnections, statement_timeout: config.statementTimeoutMs,
      application_name: "routecairn-control-plane",
      ...(config.ssl ? { ssl: config.ssl } : {})
    });
    this.pool.on("error", (error) => this.telemetry.log("error", "PostgreSQL idle client failed.", { code: safePgCode(error) }));
  }
  public async start(): Promise<void> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1)", [advisoryKey("routecairn-schema")]);
      await client.query(migration);
      await client.query("INSERT INTO routecairn_control.schema_migrations(version) VALUES($1) ON CONFLICT(version) DO NOTHING", [controlPlaneSchemaVersion]);
      await client.query("COMMIT");
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
    await this.startListener();
  }
  public async ready(): Promise<boolean> {
    try { const result = await this.pool.query("SELECT version FROM routecairn_control.schema_migrations WHERE version=$1", [controlPlaneSchemaVersion]); return result.rowCount === 1; }
    catch { return false; }
  }
  public async maintenance():Promise<void>{await this.pool.query("DELETE FROM routecairn_control.worker_nonces WHERE expires_at<=clock_timestamp()");await this.pool.query("DELETE FROM routecairn_control.outbox WHERE published_at<clock_timestamp()-interval '7 days'");}
  public async publish(topic: string, partitionKey: string, payload: Record<string, unknown>): Promise<void> {
    const safeTopic = validateTopic(topic); const body = JSON.stringify({ topic: safeTopic, partitionKey: partitionKey.slice(0, 200), payload });
    if (Buffer.byteLength(body) > 7_500) throw new Error("CONTROL_PLANE_EVENT_TOO_LARGE");
    const client=await this.pool.connect();
    try{await client.query("BEGIN");const inserted=await client.query<{id:string}>("INSERT INTO routecairn_control.outbox(topic,partition_key,payload) VALUES($1,$2,$3::jsonb) RETURNING id",[safeTopic,partitionKey,JSON.stringify(payload)]);await client.query("SELECT pg_notify('routecairn_events',$1)",[body]);await client.query("UPDATE routecairn_control.outbox SET published_at=clock_timestamp() WHERE id=$1",[inserted.rows[0]!.id]);await client.query("COMMIT");}
    catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
  }
  public subscribe(topic: string, listener: (partitionKey: string, payload: Record<string, unknown>) => void): () => void {
    const event = `event:${validateTopic(topic)}`;
    const wrapped = (partitionKey: string, payload: Record<string, unknown>) => listener(partitionKey, payload);
    this.events.on(event, wrapped);
    return () => this.events.off(event, wrapped);
  }
  public async shutdown(): Promise<void> {
    this.stopped = true;
    if (this.listener) { await this.listener.query("UNLISTEN routecairn_events").catch(() => undefined); await this.listener.end().catch(() => undefined); }
    await this.pool.end();
  }
  private async startListener(): Promise<void> {
    const listener = new Client({ connectionString: this.config.url, application_name: "routecairn-events", ...(this.config.ssl ? { ssl: this.config.ssl } : {}) });
    await listener.connect(); await listener.query("LISTEN routecairn_events"); this.listener = listener;
    listener.on("notification", (notification) => {
      try {
        const parsed = JSON.parse(notification.payload ?? "") as { topic: string; partitionKey: string; payload: Record<string, unknown> };
        this.events.emit(`event:${validateTopic(parsed.topic)}`, parsed.partitionKey, parsed.payload);
      } catch { this.telemetry.log("warn", "Rejected malformed PostgreSQL event notification."); }
    });
    listener.on("error", (error) => {
      this.telemetry.log("error", "PostgreSQL event listener disconnected.", { code: safePgCode(error) });
      if (!this.stopped) setTimeout(() => void this.reconnectListener(), 1_000).unref();
    });
  }
  private async reconnectListener(): Promise<void> {
    if (this.stopped) return;
    try { await this.listener?.end().catch(() => undefined); await this.startListener(); }
    catch { if (!this.stopped) setTimeout(() => void this.reconnectListener(), 5_000).unref(); }
  }
}

export class PostgresLeaderElection {
  private held = false;
  private timer?: NodeJS.Timeout;
  private fencingToken = 0;
  private ticking=false;
  public constructor(private readonly database: PostgresControlPlane, private readonly instanceId: string, private readonly leaseMs: number) {}
  public async start(schedulerKey: string, onLeadership: (fencingToken: number) => Promise<void>): Promise<void> {
    const tick = async () => {
      if(this.ticking)return;this.ticking=true;
      try{
      const result = await this.database.pool.query<{ fencing_token: string }>(`INSERT INTO routecairn_control.scheduler_runs(scheduler_key,instance_id,fencing_token,acquired_at,renewed_at,expires_at)
        VALUES($1,$2,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+($3::text||' milliseconds')::interval)
        ON CONFLICT(scheduler_key) DO UPDATE SET instance_id=EXCLUDED.instance_id,
          fencing_token=CASE WHEN routecairn_control.scheduler_runs.instance_id=EXCLUDED.instance_id THEN routecairn_control.scheduler_runs.fencing_token ELSE routecairn_control.scheduler_runs.fencing_token+1 END,
          acquired_at=CASE WHEN routecairn_control.scheduler_runs.instance_id=EXCLUDED.instance_id THEN routecairn_control.scheduler_runs.acquired_at ELSE clock_timestamp() END,
          renewed_at=clock_timestamp(),expires_at=EXCLUDED.expires_at
        WHERE routecairn_control.scheduler_runs.expires_at<clock_timestamp() OR routecairn_control.scheduler_runs.instance_id=EXCLUDED.instance_id
        RETURNING fencing_token`, [schedulerKey, this.instanceId, this.leaseMs]);
      this.held = result.rowCount === 1;
      if (this.held) { this.fencingToken = Number(result.rows[0]!.fencing_token); void onLeadership(this.fencingToken).catch(()=>undefined); }
      }finally{this.ticking=false;}
    };
    await tick(); this.timer = setInterval(() => void tick().catch(() => { this.held = false; }), Math.max(1_000, Math.floor(this.leaseMs / 3))); this.timer.unref();
  }
  public isLeader(): boolean { return this.held; }
  public token(): number { if (!this.held) throw new Error("SCHEDULER_NOT_LEADER"); return this.fencingToken; }
  public async shutdown(): Promise<void> { if (this.timer) clearInterval(this.timer); this.held = false; }
}

function advisoryKey(value: string): number { return createHash("sha256").update(value).digest().readInt32BE(0); }
function validateTopic(value: string): string { if (!/^[a-z][a-z0-9._-]{0,63}$/.test(value)) throw new Error("CONTROL_PLANE_EVENT_TOPIC_INVALID"); return value; }
function safePgCode(error: Error): string { return "code" in error && typeof error.code === "string" ? error.code : "POSTGRES_ERROR"; }
