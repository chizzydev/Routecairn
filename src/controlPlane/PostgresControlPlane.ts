import pg from "pg";
import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import type { ControlPlaneConfig } from "./ControlPlaneConfig.js";
import type { ControlPlaneTelemetry } from "./Telemetry.js";

const { Pool, Client } = pg;

export const controlPlaneSchemaVersion = 2;

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
ALTER TABLE routecairn_control.worker_enrollments ADD COLUMN IF NOT EXISTS workload_identity text;
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
ALTER TABLE routecairn_control.jobs ADD COLUMN IF NOT EXISTS worker_generation integer;
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
  private cursor = "0";
  private draining = false;
  private retry: NodeJS.Timeout|undefined;
  private poll?: NodeJS.Timeout;
  private reconnecting = false;
  private listenerConnected = false;
  public constructor(private readonly config: NonNullable<ControlPlaneConfig["postgres"]>, private readonly telemetry: ControlPlaneTelemetry) {
    this.pool = new Pool({
      connectionString: config.url, max: config.maxConnections, statement_timeout: config.statementTimeoutMs,
      application_name: "routecairn-control-plane", connectionTimeoutMillis: 5_000,
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
    // Capture the subscription starting point before LISTEN; polling closes its startup race.
    const latest = await this.pool.query<{id:string}>("SELECT COALESCE(MAX(id),0)::text AS id FROM routecairn_control.outbox");
    this.cursor = latest.rows[0]!.id;
    await this.startListener();
    this.poll = setInterval(() => void this.drainEvents().catch(() => undefined), 1_000);
    this.poll.unref();
  }
  public async ready(): Promise<boolean> {
    try { const result = await this.pool.query("SELECT version FROM routecairn_control.schema_migrations WHERE version=$1", [controlPlaneSchemaVersion]); return result.rowCount === 1; }
    catch { return false; }
  }
  public async maintenance():Promise<void>{await this.pool.query("DELETE FROM routecairn_control.worker_nonces WHERE expires_at<=clock_timestamp()");await this.pool.query("DELETE FROM routecairn_control.outbox WHERE published_at<clock_timestamp()-interval '7 days'");}
  public async publish(topic: string, partitionKey: string, payload: Record<string, unknown>): Promise<void> {
    const client=await this.pool.connect();
    try{await client.query("BEGIN");await this.publishInTransaction(client,topic,partitionKey,payload);await client.query("COMMIT");}
    catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
  }
  public async publishInTransaction(client: pg.PoolClient, topic: string, partitionKey: string, payload: Record<string, unknown>): Promise<void> {
    const safeTopic = validateTopic(topic);
    if (partitionKey.length > 200 || Buffer.byteLength(JSON.stringify(payload)) > 7_000) throw new Error("CONTROL_PLANE_EVENT_TOO_LARGE");
    // Serialize event commits, so sequence cursors cannot skip a later-committing lower ID.
    // Call last in a transaction, after business row locks have been acquired.
    await client.query("SELECT pg_advisory_xact_lock($1)", [advisoryKey("routecairn-outbox-order")]);
    const result = await client.query<{id:string}>("INSERT INTO routecairn_control.outbox(topic,partition_key,payload,published_at) VALUES($1,$2,$3::jsonb,clock_timestamp()) RETURNING id", [safeTopic,partitionKey,JSON.stringify(payload)]);
    await client.query("SELECT pg_notify('routecairn_events',$1)", [result.rows[0]!.id]);
  }
  public async transaction<T>(work: (client: pg.PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try { await client.query("BEGIN"); const result = await work(client); await client.query("COMMIT"); return result; }
    catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  }
  public async fencedTransaction<T>(schedulerKey: string, instanceId: string, fence: number, work: (client: pg.PoolClient) => Promise<T>): Promise<T> {
    return this.transaction(async (client) => {
      const lease = await client.query("SELECT 1 FROM routecairn_control.scheduler_runs WHERE scheduler_key=$1 AND instance_id=$2 AND fencing_token=$3 AND expires_at>clock_timestamp() FOR UPDATE", [schedulerKey,instanceId,fence]);
      if (lease.rowCount !== 1) throw new Error("SCHEDULER_FENCE_REJECTED");
      return work(client);
    });
  }
  public subscribe(topic: string, listener: (partitionKey: string, payload: Record<string, unknown>) => void): () => void {
    const event = `event:${validateTopic(topic)}`;
    const wrapped = (partitionKey: string, payload: Record<string, unknown>) => listener(partitionKey, payload);
    this.events.on(event, wrapped);
    return () => this.events.off(event, wrapped);
  }
  public async shutdown(): Promise<void> {
    this.stopped = true;
    if (this.retry) clearTimeout(this.retry);
    if (this.poll) clearInterval(this.poll);
    if (this.listener) { await this.listener.query("UNLISTEN routecairn_events").catch(() => undefined); await this.listener.end().catch(() => undefined); }
    await this.pool.end();
  }
  private async startListener(): Promise<void> {
    const listener = new Client({ connectionString: this.config.url, application_name: "routecairn-events", connectionTimeoutMillis:5_000, ...(this.config.ssl ? { ssl: this.config.ssl } : {}) });
    listener.on("error", (error) => { this.telemetry.log("warn", "PostgreSQL event listener disconnected.", {code:safePgCode(error)}); this.scheduleReconnect(); });
    listener.on("end", () => { this.listenerConnected=false; this.scheduleReconnect(); });
    listener.on("notification", () => void this.drainEvents().catch(() => undefined));
    await listener.connect(); await listener.query("LISTEN routecairn_events"); this.listener = listener; this.listenerConnected=true;
    await this.drainEvents();
  }
  private async drainEvents(): Promise<void> {
    if (this.stopped || this.draining) return;
    this.draining = true;
    try {
      // Bounded pages; the next timer resumes any remaining backlog.
      const result = await this.pool.query<{id:string;topic:string;partition_key:string;payload:Record<string,unknown>}>("SELECT id::text,topic,partition_key,payload FROM routecairn_control.outbox WHERE id>$1::bigint ORDER BY id LIMIT 512", [this.cursor]);
      for (const row of result.rows) {
        this.cursor = row.id;
        for (const listener of this.events.listeners(`event:${validateTopic(row.topic)}`)) {
          try { listener(row.partition_key,row.payload); } catch { this.telemetry.log("warn","Control plane event consumer failed."); }
        }
      }
    } finally { this.draining = false; }
  }
  private scheduleReconnect(): void {
    if (this.stopped || this.retry || this.reconnecting) return;
    this.retry = setTimeout(() => { this.retry = undefined; void this.reconnectListener(); },1_000);
    this.retry.unref();
  }
  private async reconnectListener(): Promise<void> {
    if (this.stopped || this.reconnecting) return;
    this.reconnecting = true;
    this.listenerConnected=false;
    try { await this.listener?.end().catch(() => undefined); await this.startListener(); }
    catch { /* durable polling remains active */ }
    finally { this.reconnecting = false; if (!this.listenerConnected) this.scheduleReconnect(); }
  }
}

export class PostgresLeaderElection {
  private held = false;
  private timer?: NodeJS.Timeout;
  private fencingToken = 0;
  private ticking=false;
  private deadline=0;
  private schedulerKey?:string;
  private callback:Promise<void>|undefined;
  private stopped=false;
  public constructor(private readonly database: PostgresControlPlane, private readonly instanceId: string, private readonly leaseMs: number) {}
  public async start(schedulerKey: string, onLeadership: (fencingToken: number) => Promise<void>): Promise<void> {
    if (this.schedulerKey) throw new Error("SCHEDULER_ALREADY_STARTED");
    this.schedulerKey=schedulerKey;
    const tick = async () => {
      if(this.ticking||this.stopped)return;this.ticking=true;
      const started=performance.now();
      try{
      const result = await this.database.pool.query<{ fencing_token: string }>(`INSERT INTO routecairn_control.scheduler_runs(scheduler_key,instance_id,fencing_token,acquired_at,renewed_at,expires_at)
        VALUES($1,$2,1,clock_timestamp(),clock_timestamp(),clock_timestamp()+($3::text||' milliseconds')::interval)
        ON CONFLICT(scheduler_key) DO UPDATE SET instance_id=EXCLUDED.instance_id,
          fencing_token=CASE WHEN routecairn_control.scheduler_runs.instance_id=EXCLUDED.instance_id AND routecairn_control.scheduler_runs.expires_at>clock_timestamp() THEN routecairn_control.scheduler_runs.fencing_token ELSE routecairn_control.scheduler_runs.fencing_token+1 END,
          acquired_at=CASE WHEN routecairn_control.scheduler_runs.instance_id=EXCLUDED.instance_id THEN routecairn_control.scheduler_runs.acquired_at ELSE clock_timestamp() END,
          renewed_at=clock_timestamp(),expires_at=EXCLUDED.expires_at
        WHERE routecairn_control.scheduler_runs.expires_at<clock_timestamp() OR routecairn_control.scheduler_runs.instance_id=EXCLUDED.instance_id
        RETURNING fencing_token`, [schedulerKey, this.instanceId, this.leaseMs]);
      this.held = result.rowCount === 1;
      if (this.held) {
        this.deadline=started+this.leaseMs;
        this.fencingToken = Number(result.rows[0]!.fencing_token);
        if (!Number.isSafeInteger(this.fencingToken)) throw new Error("SCHEDULER_FENCE_INVALID");
        if (!this.callback && this.isLeader()) this.callback=onLeadership(this.fencingToken).catch(()=>undefined).finally(()=>{this.callback=undefined;});
      }
      }finally{this.ticking=false;}
    };
    await tick(); this.timer = setInterval(() => void tick().catch(() => { this.held = false; }), Math.max(1_000, Math.floor(this.leaseMs / 3))); this.timer.unref();
  }
  public isLeader(): boolean { return !this.stopped && this.held && performance.now()<this.deadline; }
  public token(): number { if (!this.isLeader()) throw new Error("SCHEDULER_NOT_LEADER"); return this.fencingToken; }
  public async shutdown(): Promise<void> {
    this.stopped=true;if (this.timer) clearInterval(this.timer);this.held=false;
    await this.callback;
    if(this.schedulerKey)await this.database.pool.query("UPDATE routecairn_control.scheduler_runs SET expires_at=clock_timestamp() WHERE scheduler_key=$1 AND instance_id=$2 AND fencing_token=$3",[this.schedulerKey,this.instanceId,this.fencingToken]);
  }
}

function advisoryKey(value: string): number { return createHash("sha256").update(value).digest().readInt32BE(0); }
function validateTopic(value: string): string { if (!/^[a-z][a-z0-9._-]{0,63}$/.test(value)) throw new Error("CONTROL_PLANE_EVENT_TOPIC_INVALID"); return value; }
function safePgCode(error: Error): string { return "code" in error && typeof error.code === "string" ? error.code : "POSTGRES_ERROR"; }
