import type { Command } from "commander";
import { startFleetServer } from "../../controlPlane/FleetServer.js";
import { initializeEvidenceStorage } from "../../controlPlane/InitializeEvidenceStorage.js";
export function registerFleetCommand(program:Command):void {
  program.command("initialize-evidence-storage").description("Explicitly create and version the configured evidence bucket.").action(async()=>{await initializeEvidenceStorage();process.stdout.write("Evidence storage initialized.\n");});
  program.command("fleet").description("Start stateless PostgreSQL-backed worker ingress.").option("--host <host>","Bind address","127.0.0.1").option("--port <port>","Listen port","4712").option("--trust-proxy","Use an isolated TLS-terminating ingress").option("--tls-cert <path>").option("--tls-key <path>").option("--tls-ca <path>").action(async(options:{host:string;port:string;trustProxy?:boolean;tlsCert?:string;tlsKey?:string;tlsCa?:string})=>{
    const port=Number(options.port);if(!Number.isInteger(port)||port<1||port>65535)throw new Error("FLEET_PORT_INVALID");
    if(Boolean(options.tlsCert)!==Boolean(options.tlsKey))throw new Error("FLEET_TLS_KEYPAIR_REQUIRED");
    const service=await startFleetServer({host:options.host,port,...(options.trustProxy?{trustProxy:true}:{}),...(options.tlsCert&&options.tlsKey?{tls:{certFile:options.tlsCert,keyFile:options.tlsKey,...(options.tlsCa?{caFile:options.tlsCa}:{})}}:{})});
    process.stdout.write(`${JSON.stringify({event:"fleet-ready",url:service.url})}\n`);
    let closing=false;const close=()=>{if(closing)return;closing=true;void service.close().then(()=>{process.exitCode=0;}).catch(()=>{process.exitCode=1;});};process.once("SIGINT",close);process.once("SIGTERM",close);
  });
}
