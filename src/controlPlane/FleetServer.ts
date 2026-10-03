import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createTlsServer } from "node:https";
import { readFile } from "node:fs/promises";
import { z } from "zod";
import { controlPlaneConfigFromEnv } from "./ControlPlaneConfig.js";
import { PostgresControlPlane, PostgresLeaderElection } from "./PostgresControlPlane.js";
import { PostgresRemoteWorkerService } from "./PostgresRemoteWorkerService.js";
import { ControlPlaneTelemetry } from "./Telemetry.js";
import { createEvidenceObjectStore } from "./ObjectStorage.js";
import { WorkloadIdentityVerifier, WorkloadIdentityError } from "./WorkloadIdentity.js";
import { RemoteWorkerAuthError } from "../dashboard/operations/RemoteWorkerService.js";
import { remoteWorkerEnrollSchema, remoteHeartbeatSchema, remoteJobResultSchema, remoteJobLeaseRenewSchema } from "../dashboard/contracts/OperationalScaleSchemas.js";

export interface FleetServerOptions { host?:string;port?:number;trustProxy?:boolean;tls?:{certFile:string;keyFile:string;caFile?:string};environment?:NodeJS.ProcessEnv }

/** Stateless worker ingress. Dashboard sessions, approvals and scan administration stay in the persistent dashboard. */
export async function startFleetServer(options:FleetServerOptions={}):Promise<{url:string;close():Promise<void>}> {
  const host=options.host??"127.0.0.1",config=controlPlaneConfigFromEnv(options.environment??process.env);
  if(config.mode!=="distributed"||!config.postgres)throw new Error("FLEET_REQUIRES_POSTGRES");
  if(!options.tls&&!options.trustProxy&&!['127.0.0.1','::1','localhost'].includes(host))throw new Error("FLEET_REQUIRES_TLS_OR_TRUSTED_INGRESS");
  if(config.workloadIdentity.directMtls&&!options.tls?.caFile)throw new Error("FLEET_MTLS_REQUIRES_CLIENT_CA");
  const tls=options.tls?{cert:await readFile(options.tls.certFile),key:await readFile(options.tls.keyFile),...(options.tls.caFile?{ca:await readFile(options.tls.caFile),requestCert:true,rejectUnauthorized:true}:{})}:undefined;
  const telemetry=new ControlPlaneTelemetry(config.telemetry);
  await telemetry.start();
  const control=new PostgresControlPlane(config.postgres,telemetry);
  const leader=new PostgresLeaderElection(control,config.instanceId,config.leader.leaseMs);
  const objects=createEvidenceObjectStore(config,control);
  try { await control.start();await leader.start("fleet-maintenance",async(fence)=>{
    await control.fencedTransaction("fleet-maintenance",config.instanceId,fence,async(client)=>{
      await client.query("DELETE FROM routecairn_control.worker_nonces WHERE expires_at<=clock_timestamp()");
    });
  }); } catch(error) { await Promise.allSettled([objects.shutdown(),control.shutdown(),telemetry.shutdown()]);throw error; }
  const workers=new PostgresRemoteWorkerService(control,telemetry,config.queue.leaseMs,config.queue.claimWaitMs);
  const identity=new WorkloadIdentityVerifier(config.workloadIdentity);
  let closing=false,active=0;
  const handler=async(request:IncomingMessage,response:ServerResponse)=>{
    response.setHeader("cache-control","no-store");response.setHeader("x-content-type-options","nosniff");
    if(closing||active>=128){response.setHeader("connection","close");send(response,503,{error:"FLEET_UNAVAILABLE"});return;}
    active++;
    let route="unknown";
    try {
      const path=request.url??"";
      if(request.method==="GET"&&path==="/healthz"){route="health";send(response,200,{status:"ok"});return;}
      if(request.method==="GET"&&path==="/readyz"){route="ready";const [database,storage]=await Promise.all([control.ready(),objects.ready()]);send(response,database&&storage?200:503,{ready:database&&storage,role:"fleet",leader:leader.isLeader()});return;}
      if(request.method!=="POST"){send(response,404,{error:"FLEET_ROUTE_NOT_FOUND"});return;}
      const allowed=/^\/api\/remote-agents\/(?:enroll|worker\/(?:heartbeat|claim|jobs\/[0-9a-f-]{36}\/(?:renew|complete)))$/i;
      if(!allowed.test(path)){send(response,404,{error:"FLEET_ROUTE_NOT_FOUND"});return;}
      const body=await readBody(request);
      if(path==="/api/remote-agents/enroll"){route="enroll";send(response,201,await workers.enroll(remoteWorkerEnrollSchema.parse(body)));return;}
      route=path.endsWith("/claim")?"claim":path.endsWith("/heartbeat")?"heartbeat":path.endsWith("/renew")?"renew":"complete";
      await telemetry.span(`fleet.${route}`,{instanceId:config.instanceId},async()=>{
        const worker=await workers.authenticate("POST",path,body,request.headers);await identity.verify(request,worker);
        response.setHeader("x-routecairn-instance-id",config.instanceId);
        if(route==="heartbeat"){await workers.heartbeat(worker,remoteHeartbeatSchema.parse(body));send(response,200,{ok:true});return;}
        if(route==="claim"){z.object({}).strict().parse(body);send(response,200,await workers.claim(worker));return;}
        const jobId=z.string().uuid().parse(path.split("/")[5]);
        if(route==="renew"){const input=remoteJobLeaseRenewSchema.parse(body);send(response,200,await workers.renew(worker,jobId,input.leaseToken));return;}
        const input=remoteJobResultSchema.parse(body);
        await workers.complete(worker,jobId,{leaseToken:input.leaseToken,status:input.status,...(input.result?{result:input.result}:{}),...(input.error?{error:input.error}:{})});send(response,200,{ok:true});
      });
    } catch(error) {
      const status=error instanceof RemoteWorkerAuthError||error instanceof WorkloadIdentityError?401:error instanceof z.ZodError?400: error instanceof FleetInputError?error.status:500;
      send(response,status,{error:status===500?"FLEET_REQUEST_FAILED":status===401?"FLEET_IDENTITY_REJECTED":"FLEET_INPUT_REJECTED"});
      if(status===500)telemetry.log("error","Fleet request failed.",{route});
    } finally {active--;telemetry.countRequest(route,response.statusCode);}
  };
  const server=tls?createTlsServer(tls,(req,res)=>void handler(req,res)):createServer((req,res)=>void handler(req,res));
  server.requestTimeout=45_000;server.headersTimeout=10_000;server.keepAliveTimeout=5_000;server.maxHeadersCount=64;
  try {await new Promise<void>((resolve,reject)=>{server.once("error",reject);server.listen(options.port??4712,host,()=>{server.off("error",reject);resolve();});});}
  catch(error){await leader.shutdown();await objects.shutdown();await control.shutdown();await telemetry.shutdown();throw error;}
  const address=server.address();if(!address||typeof address==="string")throw new Error("FLEET_LISTEN_FAILED");
  return {url:`${options.tls?"https":"http"}://${host.includes(":")?`[${host}]`:host}:${address.port}`,close:async()=>{
    if(closing)return;closing=true;const timer=setTimeout(()=>server.closeAllConnections(),35_000);timer.unref();
    await new Promise<void>((resolve)=>server.close(()=>resolve()));clearTimeout(timer);
    await leader.shutdown();await objects.shutdown();await control.shutdown();await telemetry.shutdown();
  }};
}
class FleetInputError extends Error { public constructor(public readonly status:number){super("FLEET_INPUT_REJECTED");} }
function send(response:ServerResponse,status:number,body:unknown):void {if(response.destroyed||response.writableEnded)return;response.writeHead(status,{"content-type":"application/json"});response.end(JSON.stringify(body));}
async function readBody(request:IncomingMessage):Promise<unknown>{
  if(request.headers["content-type"]?.split(";")[0]!=="application/json"||request.headers["content-encoding"])throw new FleetInputError(415);
  const critical=new Set(["x-routecairn-worker-id","x-routecairn-timestamp","x-routecairn-nonce","x-routecairn-signature","authorization","content-type"]),seen=new Set<string>();
  for(let i=0;i<request.rawHeaders.length;i+=2){const key=request.rawHeaders[i]!.toLowerCase();if(critical.has(key)&&seen.has(key))throw new FleetInputError(400);seen.add(key);}
  const chunks:Buffer[]=[];let size=0;for await(const chunk of request){size+=(chunk as Buffer).length;if(size>1024*1024)throw new FleetInputError(413);chunks.push(Buffer.from(chunk));}
  try{return JSON.parse(Buffer.concat(chunks).toString("utf8"));}catch{throw new FleetInputError(400);}
}
