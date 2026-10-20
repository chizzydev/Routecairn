import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { randomUUID } from "node:crypto";
import type { ChildProcess } from "node:child_process";
import type { OwnedTemporaryResource } from "../../core/storage/OwnedTemporaryResource.js";
import { windowsProcessBirth } from "./WindowsProcessIdentity.js";

/** No descendants, application imports or loaders exist before attachment.
 * Native observation runs under controller custody after durable registration. */
export function createWorkerBootstrap(resource: OwnedTemporaryResource, entry: string): string {
  const temp = resource.directory("tmp"), path = join(temp, "bootstrap.mjs");
  const tsx = entry.endsWith(".ts") ? pathToFileURL(createRequire(import.meta.url).resolve("tsx/esm/api")).href : null;
  const source = `const workerId=process.env.ROUTECAIRN_WORKER_ID, generation=process.env.ROUTECAIRN_WORKER_GENERATION;
let activated=false, disconnected=false, identified=process.platform!=='win32';
const lost=()=>{disconnected=true;if(!activated)process.exit(0)};
process.on('disconnect',lost);
process.on('message',async raw=>{
 if(!raw || raw.workerId!==workerId || raw.protocolVersion!==2)return;
 if(raw.type==='SHUTDOWN' && !activated){process.exit(0);return}
 if(raw.type==='IDENTIFY_PROCESS' && !identified && !activated && raw.workerGeneration===generation && typeof raw.challenge==='string' && /^[a-f0-9-]{36}$/.test(raw.challenge) && typeof raw.processBirth==='string' && /^\\d{16,20}$/.test(raw.processBirth)){
  identified=true;process.env.ROUTECAIRN_WINDOWS_PROCESS_BIRTH=raw.processBirth;
  if(process.connected)process.send({protocolVersion:2,type:'WORKER_IDENTITY_CONFIRMED',workerId,processBirth:raw.processBirth,challenge:raw.challenge},()=>{});return;
 }
 if(raw.type!=='ACTIVATE_RUNTIME' || raw.workerGeneration!==generation || activated || !identified)return;
 activated=true;
 try {
  ${tsx ? `const {register}=await import(${JSON.stringify(tsx)});register();` : ""}
  await import(${JSON.stringify(pathToFileURL(entry).href)});
  process.removeListener('disconnect',lost);
  if(disconnected || !process.connected)process.emit('disconnect');
 }catch{process.exit(1)}
});
if(process.connected)process.send({protocolVersion:2,type:'WORKER_BOOTSTRAP_READY',workerId},()=>{});
`;
  resource.assertOwned(); writeFileSync(path, source, { flag: "wx", mode: 0o600 }); resource.assertOwned(); return path;
}

/** A private IPC challenge proves the originally forked process is still alive
 * after observation. PID reuse cannot authenticate a replacement process. */
export async function confirmBootstrapIdentity(child: ChildProcess, workerId: string, generation: string, temp: string): Promise<string | undefined> {
  if (process.platform !== "win32") return undefined;
  if (!child.pid || !child.connected || child.exitCode !== null || child.signalCode !== null) throw Error("WORKER_IDENTITY_UNAVAILABLE");
  const birth = await windowsProcessBirth(child.pid, temp);
  if (!birth || !child.connected || child.exitCode !== null || child.signalCode !== null) throw Error("WORKER_IDENTITY_UNAVAILABLE");
  const challenge = randomUUID();
  await new Promise<void>((resolve, reject) => {
    const finish = (error?: Error) => { clearTimeout(timer); child.removeListener("message", message); child.removeListener("exit", exited); child.removeListener("error", failed); if (error) reject(error); else resolve(); };
    const message = (raw: unknown) => { const value = raw as { type?: string; protocolVersion?: number; workerId?: string; processBirth?: string; challenge?: string } | null; if (value?.type === "WORKER_IDENTITY_CONFIRMED" && value.protocolVersion === 2 && value.workerId === workerId && value.challenge === challenge && value.processBirth === birth) finish(); };
    const exited = () => finish(Error("WORKER_IDENTITY_EXITED")), failed = () => finish(Error("WORKER_IDENTITY_IPC_FAILED"));
    const timer = setTimeout(() => finish(Error("WORKER_IDENTITY_TIMEOUT")), 5000);
    child.on("message", message); child.once("exit", exited); child.once("error", failed);
    child.send({ protocolVersion: 2, type: "IDENTIFY_PROCESS", workerId, workerGeneration: generation, processBirth: birth, challenge }, error => { if (error) failed(); });
  });
  return birth;
}
