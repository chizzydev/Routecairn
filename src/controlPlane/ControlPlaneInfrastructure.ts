import { EventEmitter } from "node:events";
import { mkdir } from "node:fs/promises";
import type { IncomingMessage } from "node:http";
import type { DashboardPaths } from "../dashboard/services/DashboardPaths.js";
import type { RemoteWorkerOperations } from "../dashboard/operations/RemoteWorkerOperations.js";
import { RemoteWorkerService, type WorkerRow } from "../dashboard/operations/RemoteWorkerService.js";
import type { DashboardDatabase } from "../dashboard/db/DashboardDatabase.js";
import { controlPlaneConfigFromEnv, type ControlPlaneConfig } from "./ControlPlaneConfig.js";
import { ControlPlaneTelemetry } from "./Telemetry.js";
import { PostgresControlPlane, PostgresLeaderElection } from "./PostgresControlPlane.js";
import { PostgresRemoteWorkerService } from "./PostgresRemoteWorkerService.js";
import { createEvidenceObjectStore, type EvidenceObject, type EvidenceObjectStore } from "./ObjectStorage.js";
import { WorkloadIdentityVerifier } from "./WorkloadIdentity.js";

type EventListener = (partitionKey: string, payload: Record<string, unknown>) => void;

export class ControlPlaneInfrastructure {
  public readonly config: ControlPlaneConfig;
  public readonly telemetry: ControlPlaneTelemetry;
  public readonly remoteWorkers: RemoteWorkerOperations;
  public readonly objectStore: EvidenceObjectStore;
  public readonly workloadIdentity: WorkloadIdentityVerifier;
  private readonly localEvents = new EventEmitter();
  private readonly postgres: PostgresControlPlane | undefined;
  private readonly leader: PostgresLeaderElection | undefined;
  private pendingUploads = new Set<Promise<unknown>>();
  private readonly scheduledTasks=new Map<string,{intervalMs:number;lastRun:number;task:(fencingToken:number)=>Promise<void>}>();
  private schedulerRunning=false;
  private closing=false;
  private constructor(config: ControlPlaneConfig, telemetry: ControlPlaneTelemetry, remoteWorkers: RemoteWorkerOperations, objectStore: EvidenceObjectStore, workloadIdentity: WorkloadIdentityVerifier, postgres?: PostgresControlPlane, leader?: PostgresLeaderElection) {
    this.config=config;this.telemetry=telemetry;this.remoteWorkers=remoteWorkers;this.objectStore=objectStore;this.workloadIdentity=workloadIdentity;this.postgres=postgres;this.leader=leader;
  }
  public static async start(database: DashboardDatabase, paths: DashboardPaths, environment: NodeJS.ProcessEnv = process.env): Promise<ControlPlaneInfrastructure> {
    const config=controlPlaneConfigFromEnv(environment);const telemetry=new ControlPlaneTelemetry(config.telemetry);await telemetry.start();
    let postgres:PostgresControlPlane|undefined,leader:PostgresLeaderElection|undefined;let remoteWorkers:RemoteWorkerOperations;
    if(config.mode==="distributed"){
      postgres=new PostgresControlPlane(config.postgres!,telemetry);await postgres.start();
      remoteWorkers=new PostgresRemoteWorkerService(postgres,telemetry,config.queue.leaseMs,config.queue.claimWaitMs);
      leader=new PostgresLeaderElection(postgres,config.instanceId,config.leader.leaseMs);
    }else remoteWorkers=new RemoteWorkerService(database);
    const objectStore=createEvidenceObjectStore(config,postgres);await mkdir(paths.objectCacheDir,{recursive:true});
    const infrastructure=new ControlPlaneInfrastructure(config,telemetry,remoteWorkers,objectStore,new WorkloadIdentityVerifier(config.workloadIdentity),postgres,leader);
    if(postgres)infrastructure.registerScheduledTask("control-plane-maintenance",60*60_000,async()=>postgres!.maintenance());
    if(leader)await leader.start("control-plane-scheduler",async(fencingToken)=>{await infrastructure.runScheduledTasks(fencingToken);await postgres!.publish("scheduler","global",{type:"tick",fencingToken,instanceId:config.instanceId});});
    telemetry.log(config.mode==="distributed"?"info":"debug","Control plane infrastructure started.",{mode:config.mode,objectStorage:objectStore.kind,instanceId:config.instanceId});return infrastructure;
  }
  public async verifyWorkerIdentity(request:IncomingMessage,worker:WorkerRow):Promise<void>{const identity=await this.workloadIdentity.verify(request,worker);this.telemetry.log("debug","Worker identity accepted.",{workerId:worker.id,identityKind:identity.kind});}
  public async publish(topic:string,partitionKey:string,payload:Record<string,unknown>):Promise<void>{
    if(this.postgres)await this.postgres.publish(topic,partitionKey,payload);else queueMicrotask(()=>this.localEvents.emit(topic,partitionKey,payload));
  }
  public subscribe(topic:string,listener:EventListener):()=>void{
    if(this.postgres)return this.postgres.subscribe(topic,listener);this.localEvents.on(topic,listener);return()=>this.localEvents.off(topic,listener);
  }
  public uploadEvidence(item:EvidenceObject,attempt=0):void{
    if(this.objectStore.kind==="local")return;
    const task=this.objectStore.put(item).then(()=>this.publish("evidence",item.organizationId,{type:"stored",artifactId:item.artifactId,sha256:item.sha256})).catch((error)=>{this.telemetry.log("error","Evidence object upload failed.",{artifactId:item.artifactId,attempt:attempt+1,code:error instanceof Error?error.message:"UPLOAD_FAILED"});if(!this.closing&&attempt<2)setTimeout(()=>this.uploadEvidence(item,attempt+1),Math.min(30_000,1_000*2**attempt)).unref();}).finally(()=>this.pendingUploads.delete(task));
    this.pendingUploads.add(task);
  }
  public registerScheduledTask(name:string,intervalMs:number,task:(fencingToken:number)=>Promise<void>):void{if(!/^[a-z][a-z0-9._-]{0,63}$/.test(name)||intervalMs<1_000)throw new Error("SCHEDULED_TASK_INVALID");this.scheduledTasks.set(name,{intervalMs,lastRun:0,task});}
  public async ready():Promise<{ready:boolean;mode:string;postgres:boolean;objectStorage:boolean;leader:boolean}>{
    const [postgresReady,objectReady]=await Promise.all([this.postgres?this.postgres.ready():Promise.resolve(true),this.objectStore.ready()]);
    return{ready:postgresReady&&objectReady,mode:this.config.mode,postgres:postgresReady,objectStorage:objectReady,leader:this.leader?.isLeader()??true};
  }
  public async shutdown():Promise<void>{
    this.closing=true;await Promise.allSettled([...this.pendingUploads]);await this.leader?.shutdown();await this.objectStore.shutdown();await this.postgres?.shutdown();await this.telemetry.shutdown();
  }
  private async runScheduledTasks(fencingToken:number):Promise<void>{if(this.schedulerRunning)return;this.schedulerRunning=true;try{const now=Date.now();for(const [name,item]of this.scheduledTasks){if(now-item.lastRun<item.intervalMs)continue;item.lastRun=now;try{await item.task(fencingToken);}catch(error){this.telemetry.log("error","Leader scheduled task failed.",{task:name,fencingToken,code:error instanceof Error?error.message:"TASK_FAILED"});}}}finally{this.schedulerRunning=false;}}
}
