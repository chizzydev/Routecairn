import type { Command } from "commander";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

interface EnrollOptions { server: string; token: string; name: string; state: string; capability: string[] }
interface RunOptions { state: string; handler?: string; once?: boolean; interval?: string }
interface AgentState { server: string; workerId: string; privateKeyPem: string; publicKeyPem: string; capabilities: string[] }

export function registerAgentCommand(program: Command): void {
  const agent = program.command("agent").description("Enroll and run a signed RouteCairn remote worker agent.");
  agent.command("enroll").requiredOption("--server <url>").requiredOption("--token <token>").requiredOption("--name <name>").requiredOption("--state <file>").option("--capability <value...>", "Worker capabilities", ["ping"]).action((options: EnrollOptions) => enroll(options));
  agent.command("run").requiredOption("--state <file>").option("--handler <module>", "Local ESM job handler exporting handle(job)").option("--once").option("--interval <ms>", "Polling interval", "3000").action((options: RunOptions) => run(options));
}

async function enroll(options: EnrollOptions): Promise<void> {
  const pair = generateKeyPairSync("ed25519"); const publicKeyPem = pair.publicKey.export({ format: "pem", type: "spki" }).toString(); const privateKeyPem = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const response = await fetch(`${origin(options.server)}/api/remote-agents/enroll`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token: options.token, name: options.name, publicKeyPem, capabilities: options.capability, labels: { runtime: `node-${process.version}`, platform: process.platform, architecture: process.arch } }) });
  if (!response.ok) throw new Error(`Remote enrollment failed (${response.status}).`); const body = await response.json() as { workerId: string };
  const state: AgentState = { server: origin(options.server), workerId: body.workerId, privateKeyPem, publicKeyPem, capabilities: options.capability }; const statePath = resolve(options.state); await mkdir(dirname(statePath), { recursive: true }); await writeFile(statePath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 }); await chmod(statePath, 0o600);
  process.stdout.write(`${body.workerId}\n`);
}

async function run(options: RunOptions): Promise<void> {
  const state = JSON.parse(await readFile(resolve(options.state), "utf8")) as AgentState; const interval = Math.max(250, Math.min(60_000, Number(options.interval) || 3000));
  const external = options.handler ? await import(pathToFileURL(resolve(options.handler)).href) as { handle?: (job: { id: string; kind: string; payload: Record<string, unknown> }, context: { signal: AbortSignal }) => Promise<Record<string, unknown>> } : undefined;
  do {
    await signedRequest(state, "/api/remote-agents/worker/heartbeat", { status: "ONLINE", resources: { cpuPercent: 0, memoryBytes: process.memoryUsage().rss, activeJobs: 0 } });
    const claimed = await signedRequest(state, "/api/remote-agents/worker/claim", {}) as { job: { id: string; kind: string; payload: Record<string, unknown>; leaseToken: string } | null };
    if (claimed.job) {
      await executeJob(state, claimed.job, external);
    }
    if (!options.once) await new Promise((resolveWait) => setTimeout(resolveWait, interval));
  } while (!options.once);
}

async function executeJob(state:AgentState,job:{id:string;kind:string;payload:Record<string,unknown>;leaseToken:string},external:{handle?:(job:{id:string;kind:string;payload:Record<string,unknown>},context:{signal:AbortSignal})=>Promise<Record<string,unknown>>}|undefined):Promise<void>{const controller=new AbortController();let renewing=false;let renewalError:unknown;const timer=setInterval(()=>{if(renewing||renewalError)return;renewing=true;void signedRequest(state,`/api/remote-agents/worker/jobs/${job.id}/renew`,{leaseToken:job.leaseToken}).catch((error)=>{renewalError=error;controller.abort(error);}).finally(()=>{renewing=false;});},20_000);timer.unref();try{const result=job.kind==="PING"?{pong:true,at:new Date().toISOString()}:external?.handle?await external.handle(job,{signal:controller.signal}):(()=>{throw new Error(`No handler installed for ${job.kind}.`);})();if(renewalError)throw renewalError;await signedRequest(state,`/api/remote-agents/worker/jobs/${job.id}/complete`,{leaseToken:job.leaseToken,status:"COMPLETED",result});}catch(error){controller.abort(error);await signedRequest(state,`/api/remote-agents/worker/jobs/${job.id}/complete`,{leaseToken:job.leaseToken,status:"FAILED",error:(error instanceof Error?error.message:"Agent handler failed").slice(0,1000)});}finally{clearInterval(timer);}}

async function signedRequest(state: AgentState, path: string, body: Record<string, unknown>): Promise<unknown> { const timestamp=new Date().toISOString(),nonce=randomBytes(24).toString("base64url"),serialized=canonical(body),bodyHash=createHash("sha256").update(serialized).digest("hex"),message=["routecairn-agent-ed25519-v1","POST",path,timestamp,nonce,bodyHash].join("\n"),signature=sign(null,Buffer.from(message),state.privateKeyPem).toString("base64url"); const response=await fetch(`${state.server}${path}`,{method:"POST",headers:{"content-type":"application/json","x-routecairn-worker-id":state.workerId,"x-routecairn-timestamp":timestamp,"x-routecairn-nonce":nonce,"x-routecairn-signature":signature},body:serialized}); if(!response.ok)throw new Error(`Remote worker request failed (${response.status}).`);return response.json(); }
function origin(value:string):string{const parsed=new URL(value);if(parsed.protocol!=="https:"&&!(["127.0.0.1","localhost","::1"].includes(parsed.hostname)&&parsed.protocol==="http:"))throw new Error("Remote agents require HTTPS except on loopback.");return parsed.origin;}
function canonical(value:unknown):string{return JSON.stringify(sort(value));}function sort(value:unknown):unknown{if(Array.isArray(value))return value.map(sort);if(value&&typeof value==="object")return Object.fromEntries(Object.entries(value as Record<string,unknown>).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,sort(v)]));return value;}
