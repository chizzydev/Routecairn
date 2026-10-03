import { createHash, createPublicKey, randomBytes, randomUUID, verify, type KeyObject } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";
import type { PoolClient } from "pg";
import type { WorkerIdentityBinding } from "../dashboard/contracts/OperationalScaleSchemas.js";
import type { RemoteWorkerOperations } from "../dashboard/operations/RemoteWorkerOperations.js";
import { RemoteWorkerAuthError, type WorkerRow } from "../dashboard/operations/RemoteWorkerService.js";
import type { PostgresControlPlane } from "./PostgresControlPlane.js";
import type { ControlPlaneTelemetry } from "./Telemetry.js";
import { remoteEnrollmentSchema, remoteWorkerEnrollSchema, remoteHeartbeatSchema, remoteJobSchema, remoteJobResultSchema } from "../dashboard/contracts/OperationalScaleSchemas.js";

interface PgWorker { id: string; organization_id: string; name: string; public_key_pem: string; public_key_fingerprint: string; capabilities: string[]; labels: Record<string,string>; resources: unknown; status: string; generation: number; last_seen_at: Date | null; created_at: Date;workload_identity:string|null }
interface PgJob { id: string; kind: string; safe_payload: Record<string,unknown>; lease_token_hash?: string; }

export class PostgresRemoteWorkerService implements RemoteWorkerOperations {
  public constructor(private readonly control: PostgresControlPlane, private readonly telemetry: ControlPlaneTelemetry, private readonly leaseMs: number, private readonly defaultWaitMs: number) {}
  public async createEnrollment(input: { organizationId: string; nameHint?: string; expiresInMinutes: number;workloadIdentity?:WorkerIdentityBinding }, actor: string): Promise<{ enrollmentId: string; token: string; expiresAt: string }> {
    remoteEnrollmentSchema.parse(input);
    const id = randomUUID(); const token = randomBytes(32).toString("base64url"); const expiresAt = new Date(Date.now() + input.expiresInMinutes * 60_000).toISOString();
    await this.control.pool.query("INSERT INTO routecairn_control.worker_enrollments(id,organization_id,token_hash,name_hint,expires_at,created_by,workload_identity) VALUES($1,$2,$3,$4,$5,$6,$7)", [id,input.organizationId,digest(token),input.nameHint??null,expiresAt,actor,input.workloadIdentity?JSON.stringify(input.workloadIdentity):null]);
    return { enrollmentId:id,token,expiresAt };
  }
  public async enroll(input: { token: string; name: string; publicKeyPem: string; capabilities: string[]; labels: Record<string,string> }): Promise<{ workerId: string; generation: number; signatureProtocol: string }> {
    input=remoteWorkerEnrollSchema.parse(input);
    const key=validateEd25519(input.publicKeyPem); const pem=key.export({format:"pem",type:"spki"}).toString(); const fingerprint=createHash("sha256").update(key.export({format:"der",type:"spki"})).digest("hex");
    const id=randomUUID(); const client=await this.control.pool.connect();
    try {
      await client.query("BEGIN");
      const enrollment=await client.query<{id:string;organization_id:string;workload_identity:string|null}>("UPDATE routecairn_control.worker_enrollments SET consumed_at=clock_timestamp() WHERE token_hash=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING id,organization_id,workload_identity",[digest(input.token)]);
      if(enrollment.rowCount!==1)throw new RemoteWorkerAuthError("REMOTE_ENROLLMENT_REJECTED");
      const networkZone=normalizeZone(input.labels.networkZone);const labels={...input.labels,networkZone};
      await client.query(`INSERT INTO routecairn_control.workers(id,organization_id,name,public_key_pem,public_key_fingerprint,capabilities,labels,network_zone,status,last_seen_at,workload_identity)
        VALUES($1,$2,$3,$4,$5,$6,$7::jsonb,$8,'ONLINE',clock_timestamp(),$9)`,[id,enrollment.rows[0]!.organization_id,input.name,pem,fingerprint,[...new Set(input.capabilities)].sort(),JSON.stringify(labels),networkZone,enrollment.rows[0]!.workload_identity]);
      await this.control.publishInTransaction(client,"workers",enrollment.rows[0]!.organization_id,{type:"enrolled",workerId:id});
      await client.query("COMMIT");
    } catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
    return {workerId:id,generation:1,signatureProtocol:"routecairn-agent-ed25519-v1"};
  }
  public async authenticate(method:string,path:string,body:unknown,headers:IncomingHttpHeaders):Promise<WorkerRow>{
    const workerId=header(headers,"x-routecairn-worker-id"),timestamp=header(headers,"x-routecairn-timestamp"),nonce=header(headers,"x-routecairn-nonce"),signature=header(headers,"x-routecairn-signature");
    if(!workerId||!timestamp||!nonce||!signature||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(workerId)||signature.length>128||nonce.length<16||nonce.length>200)throw new RemoteWorkerAuthError("REMOTE_WORKER_SIGNATURE_REQUIRED");
    const time=Date.parse(timestamp);if(!Number.isFinite(time)||Math.abs(Date.now()-time)>300_000)throw new RemoteWorkerAuthError("REMOTE_WORKER_TIMESTAMP_REJECTED");
    const result=await this.control.pool.query<PgWorker>("SELECT * FROM routecairn_control.workers WHERE id=$1",[workerId]);const worker=result.rows[0];
    if(!worker||["QUARANTINED","REVOKED"].includes(worker.status))throw new RemoteWorkerAuthError("REMOTE_WORKER_REJECTED");
    const bodyHash=createHash("sha256").update(canonical(body)).digest("hex");const signed=Buffer.from(["routecairn-agent-ed25519-v1",method.toUpperCase(),path,timestamp,nonce,bodyHash].join("\n"));
    let valid=false;try{valid=verify(null,signed,createPublicKey(worker.public_key_pem),Buffer.from(signature,"base64url"));}catch{valid=false;}if(!valid)throw new RemoteWorkerAuthError("REMOTE_WORKER_SIGNATURE_REJECTED");
    try{await this.control.pool.query("INSERT INTO routecairn_control.worker_nonces(worker_id,nonce_hash,expires_at) VALUES($1,$2,clock_timestamp()+interval '10 minutes')",[workerId,digest(nonce)]);}catch(error){if(pgConstraint(error))throw new RemoteWorkerAuthError("REMOTE_WORKER_REPLAY_REJECTED");throw error;}
    return fromPgWorker(worker);
  }
  public async heartbeat(worker:WorkerRow,input:{status:"ONLINE"|"DRAINING";resources:unknown}):Promise<void>{
    input=remoteHeartbeatSchema.parse(input);
    const result=await this.control.pool.query("UPDATE routecairn_control.workers SET status=CASE WHEN status='DRAINING' THEN status ELSE $1 END,resources=$2::jsonb,last_seen_at=clock_timestamp(),updated_at=clock_timestamp() WHERE id=$3 AND generation=$4 AND status IN ('ONLINE','DRAINING')",[input.status,canonical(input.resources),worker.id,worker.generation]);
    if(result.rowCount!==1)throw new RemoteWorkerAuthError("REMOTE_WORKER_REJECTED");
  }
  public async enqueue(input:{organizationId:string;kind:string;payload:Record<string,unknown>;requiredCapabilities:string[];priority:number;maxAttempts:number;networkZone?:string},actor:string):Promise<string>{
    remoteJobSchema.parse(input);ensureSafeObject(input.payload);const id=randomUUID(),caps=[...new Set([input.kind.toLowerCase(),...input.requiredCapabilities])].sort();
    await this.control.transaction(async(client)=>{await client.query(`INSERT INTO routecairn_control.jobs(id,organization_id,kind,safe_payload,required_capabilities,network_zone,status,priority,max_attempts,created_by)
      VALUES($1,$2,$3,$4::jsonb,$5,$6,'QUEUED',$7,$8,$9)`,[id,input.organizationId,input.kind,canonical(input.payload),caps,input.networkZone?normalizeZone(input.networkZone):null,input.priority,input.maxAttempts,actor]);
      await this.control.publishInTransaction(client,"jobs",input.organizationId,{type:"queued",jobId:id});});
    this.telemetry.countJob(input.kind,"queued");return id;
  }
  public async claim(worker:WorkerRow,waitMs=this.defaultWaitMs):Promise<unknown>{
    const deadline=performance.now()+Math.min(30_000,Math.max(0,waitMs));
    do { const result=await this.claimNow(worker);if((result as {job:unknown}).job||performance.now()>=deadline)return result;
      // Durable fallback closes missed-notification races and discovers expired leases.
      await waitForEvent(this.control,"jobs",worker.organization_id,Math.min(1_000,Math.max(1,deadline-performance.now())));
    } while(performance.now()<deadline);
    return this.claimNow(worker);
  }
  private async claimNow(worker:WorkerRow):Promise<unknown>{
    if(worker.status!=="ONLINE")return{job:null};const client=await this.control.pool.connect();
    try{await client.query("BEGIN");
      const current=await client.query("SELECT 1 FROM routecairn_control.workers WHERE id=$1 AND generation=$2 AND status='ONLINE' AND last_seen_at>clock_timestamp()-interval '90 seconds' FOR UPDATE",[worker.id,worker.generation]);
      if(current.rowCount!==1){await client.query("COMMIT");return{job:null};}
      await client.query(`WITH expired AS (SELECT id FROM routecairn_control.jobs WHERE organization_id=$1 AND status IN ('LEASED','RUNNING') AND lease_expires_at<=clock_timestamp() ORDER BY lease_expires_at LIMIT 100 FOR UPDATE SKIP LOCKED)
      UPDATE routecairn_control.jobs SET status=CASE WHEN attempt_count>=max_attempts THEN 'FAILED' ELSE 'QUEUED' END,assigned_worker_id=NULL,lease_token_hash=NULL,lease_expires_at=NULL,worker_generation=NULL,
      completed_at=CASE WHEN attempt_count>=max_attempts THEN clock_timestamp() ELSE NULL END,
      safe_error=CASE WHEN attempt_count>=max_attempts THEN 'Lease expired after maximum attempts.' ELSE safe_error END WHERE id IN (SELECT id FROM expired)`,[worker.organization_id]);
      const claimed=await client.query<PgJob>(`SELECT j.id,j.kind,j.safe_payload FROM routecairn_control.jobs j JOIN routecairn_control.workers w ON w.id=$1
        WHERE j.organization_id=w.organization_id AND j.status='QUEUED' AND j.attempt_count<j.max_attempts
        AND j.required_capabilities<@w.capabilities AND (j.network_zone IS NULL OR j.network_zone=w.network_zone)
        ORDER BY j.priority DESC,j.created_at LIMIT 1 FOR UPDATE OF j SKIP LOCKED`,[worker.id]);
      const job=claimed.rows[0];if(!job){await client.query("COMMIT");return{job:null};}
      const token=randomBytes(32).toString("base64url");
      const leased=await client.query<{lease_expires_at:Date}>("UPDATE routecairn_control.jobs SET status='LEASED',assigned_worker_id=$1,lease_token_hash=$2,lease_expires_at=clock_timestamp()+($3::text||' milliseconds')::interval,attempt_count=attempt_count+1,worker_generation=$5,started_at=COALESCE(started_at,clock_timestamp()) WHERE id=$4 RETURNING lease_expires_at",[worker.id,digest(token),this.leaseMs,job.id,worker.generation]);await client.query("COMMIT");const expiresAt=leased.rows[0]!.lease_expires_at.toISOString();
      this.telemetry.countJob(job.kind,"leased");return{job:{id:job.id,kind:job.kind,payload:job.safe_payload,leaseToken:token,leaseExpiresAt:expiresAt}};
    }catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
  }
  public async complete(worker:WorkerRow,jobId:string,input:{leaseToken:string;status:"COMPLETED"|"FAILED";result?:Record<string,unknown>;error?:string}):Promise<void>{
    remoteJobResultSchema.parse(input);if(input.result)ensureSafeObject(input.result);
    await this.control.transaction(async(client)=>{
      await lockActiveWorker(client,worker);
      const result=await client.query(`UPDATE routecairn_control.jobs SET status=$1,safe_result=$2::jsonb,safe_error=$3,completed_at=clock_timestamp(),lease_token_hash=NULL,lease_expires_at=NULL
      WHERE id=$4 AND assigned_worker_id=$5 AND lease_token_hash=$6 AND worker_generation=$7 AND status IN ('LEASED','RUNNING') AND lease_expires_at>clock_timestamp() RETURNING kind`,[input.status,input.result?canonical(input.result):null,input.error?safeError(input.error):null,jobId,worker.id,digest(input.leaseToken),worker.generation]);
      if(result.rowCount!==1)throw new RemoteWorkerAuthError("REMOTE_JOB_LEASE_REJECTED");
      await this.control.publishInTransaction(client,"jobs",worker.organization_id,{type:"completed",jobId,status:input.status});
    });this.telemetry.countJob("job",input.status.toLowerCase());
  }
  public async renew(worker:WorkerRow,jobId:string,leaseToken:string):Promise<{leaseExpiresAt:string}>{return this.control.transaction(async(client)=>{await lockActiveWorker(client,worker);const result=await client.query<{lease_expires_at:Date}>("UPDATE routecairn_control.jobs SET status='RUNNING',lease_expires_at=clock_timestamp()+($1::text||' milliseconds')::interval WHERE id=$2 AND assigned_worker_id=$3 AND lease_token_hash=$4 AND worker_generation=$5 AND status IN ('LEASED','RUNNING') AND lease_expires_at>clock_timestamp() RETURNING lease_expires_at",[this.leaseMs,jobId,worker.id,digest(leaseToken),worker.generation]);if(result.rowCount!==1)throw new RemoteWorkerAuthError("REMOTE_JOB_LEASE_REJECTED");return{leaseExpiresAt:result.rows[0]!.lease_expires_at.toISOString()};});}
  public async list(organizationId:string):Promise<{workers:unknown[];jobs:unknown[]}>{const [workers,jobs]=await Promise.all([this.control.pool.query<PgWorker>("SELECT * FROM routecairn_control.workers WHERE organization_id=$1 ORDER BY created_at DESC",[organizationId]),this.control.pool.query("SELECT id,kind,status,priority,network_zone AS \"networkZone\",assigned_worker_id AS \"assignedWorkerId\",attempt_count AS \"attemptCount\",max_attempts AS \"maxAttempts\",safe_result AS result,safe_error AS \"safeError\",created_at AS \"createdAt\",started_at AS \"startedAt\",completed_at AS \"completedAt\" FROM routecairn_control.jobs WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 200",[organizationId])]);return{workers:workers.rows.map(workerSummary),jobs:jobs.rows};}
  public async setStatus(workerId:string,status:"DRAINING"|"QUARANTINED"|"REVOKED"|"ONLINE"):Promise<void>{const result=await this.control.pool.query("UPDATE routecairn_control.workers SET status=$1,generation=generation+CASE WHEN $1='DRAINING' THEN 0 ELSE 1 END,updated_at=clock_timestamp() WHERE id=$2",[status,workerId]);if(result.rowCount!==1)throw new Error("REMOTE_WORKER_NOT_FOUND");}
  public async organizationForWorker(workerId:string):Promise<string>{const result=await this.control.pool.query<{organization_id:string}>("SELECT organization_id FROM routecairn_control.workers WHERE id=$1",[workerId]);if(!result.rows[0])throw new Error("REMOTE_WORKER_NOT_FOUND");return result.rows[0].organization_id;}
}

function fromPgWorker(row:PgWorker):WorkerRow{return{id:row.id,organization_id:row.organization_id,name:row.name,public_key_pem:row.public_key_pem,public_key_fingerprint:row.public_key_fingerprint,capabilities_json:JSON.stringify(row.capabilities),labels_json:JSON.stringify(row.labels),resources_json:row.resources?JSON.stringify(row.resources):null,status:row.status,generation:row.generation,last_seen_at:row.last_seen_at?.toISOString()??null,created_at:row.created_at.toISOString(),workload_identity:row.workload_identity};}
function workerSummary(row:PgWorker):unknown{return{id:row.id,name:row.name,fingerprint:row.public_key_fingerprint,capabilities:row.capabilities,labels:row.labels,resources:row.resources,status:row.status==="ONLINE"&&(!row.last_seen_at||row.last_seen_at.getTime()<Date.now()-90_000)?"OFFLINE":row.status,generation:row.generation,lastSeenAt:row.last_seen_at?.toISOString()??null,createdAt:row.created_at.toISOString()};}
function waitForEvent(control:PostgresControlPlane,topic:string,partitionKey:string,waitMs:number):Promise<void>{return new Promise((resolve)=>{let done=false;const finish=()=>{if(done)return;done=true;clearTimeout(timer);unsubscribe();resolve();};const unsubscribe=control.subscribe(topic,(partition)=>{if(partition===partitionKey)finish();});const timer=setTimeout(finish,waitMs);timer.unref();});}
async function lockActiveWorker(client:PoolClient,worker:WorkerRow):Promise<void>{const result=await client.query("SELECT 1 FROM routecairn_control.workers WHERE id=$1 AND generation=$2 AND status IN ('ONLINE','DRAINING') FOR UPDATE",[worker.id,worker.generation]);if(result.rowCount!==1)throw new RemoteWorkerAuthError("REMOTE_WORKER_REJECTED");}
function header(headers:IncomingHttpHeaders,name:string):string|undefined{const value=headers[name];return Array.isArray(value)?undefined:value;}
function digest(value:string):string{return createHash("sha256").update("routecairn-remote-v1\0").update(value).digest("hex");}
function canonical(value:unknown):string{return JSON.stringify(sort(value));}function sort(value:unknown):unknown{if(Array.isArray(value))return value.map(sort);if(value&&typeof value==="object")return Object.fromEntries(Object.entries(value as Record<string,unknown>).sort(([a],[b])=>a.localeCompare(b)).map(([key,item])=>[key,sort(item)]));return value;}
function validateEd25519(pem:string):KeyObject{let key:KeyObject;try{key=createPublicKey(pem);}catch{throw new RemoteWorkerAuthError("REMOTE_WORKER_KEY_REJECTED");}if(key.asymmetricKeyType!=="ed25519")throw new RemoteWorkerAuthError("REMOTE_WORKER_KEY_TYPE_REJECTED");return key;}
function normalizeZone(value:string|undefined):string{const zone=(value??"default").toLowerCase();if(!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(zone))throw new Error("REMOTE_WORKER_NETWORK_ZONE_INVALID");return zone;}
function ensureSafeObject(value:Record<string,unknown>):void{const raw=canonical(value);if(Buffer.byteLength(raw)>256*1024)throw new Error("REMOTE_JOB_PAYLOAD_TOO_LARGE");const inspect=(item:unknown,depth:number):void=>{if(depth>12)throw new Error("REMOTE_JOB_PAYLOAD_TOO_DEEP");if(Array.isArray(item)){for(const child of item)inspect(child,depth+1);return;}if(item&&typeof item==="object")for(const [key,child]of Object.entries(item as Record<string,unknown>)){if(/(password|passwd|secret|token|cookie|authorization|private[_-]?key|api[_-]?key|credential|session|jwt|signature|signed)/i.test(key)&&!/(?:path|ref|env)$/i.test(key))throw new Error("REMOTE_JOB_SECRET_FIELD_REJECTED");inspect(child,depth+1);}};inspect(value,0);}
function safeError(value:string):string{return value.replace(/https?:\/\/[^\s]+/gi,"<endpoint>").replace(/\b(password|secret|token|cookie|authorization|private[_-]?key)\s*[:=]\s*[^\s,;]+/gi,"$1=<redacted>").replace(/[\r\n]+/g," ").slice(0,1000);}
function pgConstraint(error:unknown):boolean{return typeof error==="object"&&error!==null&&"code"in error&&String((error as{code:unknown}).code)==="23505";}
