import type { Command } from "commander";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { handleNativeAgentJob, nativeAgentCapabilities } from "../agent/NativeAgentJobHandler.js";

export interface EnrollOptions { server: string; token: string; name: string; state: string; capability: string[] }
export interface RunOptions { state: string; handler?: string; once?: boolean; interval?: string; workspace?: string; maxJobMs?: string; requestTimeoutMs?: string }
export interface AgentState { server: string; workerId: string; privateKeyPem: string; publicKeyPem: string; capabilities: string[] }
interface AgentJob { id: string; kind: string; payload: Record<string, unknown>; leaseToken: string }
interface AgentHandler { handle?: (job: AgentJob, context: { signal: AbortSignal; workspace: string }) => Promise<Record<string, unknown>> }

export function registerAgentCommand(program: Command): void {
  const agent = program.command("agent").description("Enroll and run a signed RouteCairn remote worker agent.");
  agent.command("enroll")
    .requiredOption("--server <url>")
    .requiredOption("--token <token>")
    .requiredOption("--name <name>")
    .requiredOption("--state <file>")
    .option("--capability <value...>", "Worker capabilities", [...nativeAgentCapabilities])
    .action((options: EnrollOptions) => enrollAgent(options));
  agent.command("run")
    .requiredOption("--state <file>")
    .option("--workspace <directory>", "Root containing worker-local scope, configuration, fixture and output files. Defaults beside the state file.")
    .option("--handler <module>", "Optional local ESM override exporting handle(job, context).")
    .option("--once")
    .option("--interval <ms>", "Polling interval", "3000")
    .option("--max-job-ms <ms>", "Maximum wall time for one native job.", "21600000")
    .option("--request-timeout-ms <ms>", "Control-plane request timeout.", "30000")
    .action((options: RunOptions) => runAgent(options));
}

export async function enrollAgent(options: EnrollOptions): Promise<void> {
  const pair = generateKeyPairSync("ed25519");
  const publicKeyPem = pair.publicKey.export({ format: "pem", type: "spki" }).toString();
  const privateKeyPem = pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const server = origin(options.server);
  const response = await fetch(`${server}/api/remote-agents/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: options.token, name: options.name, publicKeyPem, capabilities: options.capability, labels: { runtime: `node-${process.version}`, platform: process.platform, architecture: process.arch } }),
    signal: AbortSignal.timeout(30_000)
  });
  if (!response.ok) throw new Error(`Remote enrollment failed (${response.status}).`);
  const body = await response.json() as { workerId: string };
  const state: AgentState = { server, workerId: body.workerId, privateKeyPem, publicKeyPem, capabilities: options.capability };
  const statePath = resolve(options.state);
  await mkdir(dirname(statePath), { recursive: true });
  const temporaryStatePath = `${statePath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
  try {
    await writeFile(temporaryStatePath, `${JSON.stringify(state, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    await chmod(temporaryStatePath, 0o600);
    await rename(temporaryStatePath, statePath);
  } finally {
    await rm(temporaryStatePath, { force: true });
  }
  process.stdout.write(`${body.workerId}\n`);
}

export async function runAgent(options: RunOptions): Promise<void> {
  const statePath = resolve(options.state);
  const state = JSON.parse(await readFile(statePath, "utf8")) as AgentState;
  validateState(state);
  const interval = Math.max(250, Math.min(60_000, Number(options.interval) || 3000));
  const maxJobMs = Math.max(1_000, Math.min(24 * 60 * 60_000, Number(options.maxJobMs) || 6 * 60 * 60_000));
  const requestTimeoutMs = Math.max(1_000, Math.min(120_000, Number(options.requestTimeoutMs) || 30_000));
  const workspace = resolve(options.workspace ?? dirname(statePath));
  const external = options.handler ? await import(pathToFileURL(resolve(options.handler)).href) as AgentHandler : undefined;
  if (external && typeof external.handle !== "function") throw new Error("Agent handler module must export handle(job, context).");
  let retryDelay = interval;
  do {
    try {
      await signedRequest(state, "/api/remote-agents/worker/heartbeat", { status: "ONLINE", resources: { cpuPercent: 0, memoryBytes: process.memoryUsage().rss, activeJobs: 0 } }, requestTimeoutMs);
      const claimed = await signedRequest(state, "/api/remote-agents/worker/claim", {}, requestTimeoutMs) as { job: AgentJob | null };
      if (claimed.job) await executeJob(state, claimed.job, external, workspace, maxJobMs, requestTimeoutMs);
      retryDelay = interval;
      if (!options.once) await delay(interval);
    } catch (error) {
      if (options.once) throw error;
      process.stderr.write(`Remote worker cycle failed: ${safeError(error)}\n`);
      await delay(retryDelay);
      retryDelay = Math.min(60_000, Math.max(interval, retryDelay * 2));
    }
  } while (!options.once);
}

async function executeJob(state: AgentState, job: AgentJob, external: AgentHandler | undefined, workspace: string, maxJobMs: number, requestTimeoutMs: number): Promise<void> {
  const controller = new AbortController();
  let renewing = false;
  let renewalError: unknown;
  const deadline = setTimeout(() => controller.abort(new Error("AGENT_JOB_DEADLINE_EXCEEDED")), maxJobMs);
  deadline.unref();
  const timer = setInterval(() => {
    if (renewing || renewalError) return;
    renewing = true;
    void signedRequest(state, `/api/remote-agents/worker/jobs/${job.id}/renew`, { leaseToken: job.leaseToken }, requestTimeoutMs)
      .catch((error) => { renewalError = error; controller.abort(error); })
      .finally(() => { renewing = false; });
  }, 20_000);
  timer.unref();
  try {
    await signedRequest(state, "/api/remote-agents/worker/heartbeat", { status: "ONLINE", resources: { cpuPercent: 0, memoryBytes: process.memoryUsage().rss, activeJobs: 1 } }, requestTimeoutMs);
    const context = { signal: controller.signal, workspace };
    const result = external?.handle ? await external.handle(job, context) : await handleNativeAgentJob(job, context);
    if (controller.signal.aborted) throw controller.signal.reason instanceof Error ? controller.signal.reason : new Error("AGENT_JOB_ABORTED");
    if (renewalError) throw renewalError;
    await signedRequest(state, `/api/remote-agents/worker/jobs/${job.id}/complete`, { leaseToken: job.leaseToken, status: "COMPLETED", result }, requestTimeoutMs);
  } catch (error) {
    controller.abort(error);
    await signedRequest(state, `/api/remote-agents/worker/jobs/${job.id}/complete`, { leaseToken: job.leaseToken, status: "FAILED", error: safeError(error) }, requestTimeoutMs);
  } finally {
    clearInterval(timer);
    clearTimeout(deadline);
  }
}

async function signedRequest(state: AgentState, path: string, body: Record<string, unknown>, timeoutMs = 30_000): Promise<unknown> {
  const timestamp = new Date().toISOString();
  const nonce = randomBytes(24).toString("base64url");
  const serialized = canonical(body);
  const bodyHash = createHash("sha256").update(serialized).digest("hex");
  const message = ["routecairn-agent-ed25519-v1", "POST", path, timestamp, nonce, bodyHash].join("\n");
  const signature = sign(null, Buffer.from(message), state.privateKeyPem).toString("base64url");
  const response = await fetch(`${state.server}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-routecairn-worker-id": state.workerId,
      "x-routecairn-timestamp": timestamp,
      "x-routecairn-nonce": nonce,
      "x-routecairn-signature": signature
    },
    body: serialized,
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!response.ok) throw new Error(`Remote worker request failed (${response.status}).`);
  return response.json();
}

function origin(value: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== "https:" && !(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname) && parsed.protocol === "http:")) throw new Error("Remote agents require HTTPS except on loopback.");
  return parsed.origin;
}
function canonical(value: unknown): string { return JSON.stringify(sort(value)); }
function sort(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sort);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sort(item)]));
  return value;
}
function validateState(state: AgentState): void {
  if (!state || typeof state.server !== "string" || typeof state.workerId !== "string" || typeof state.privateKeyPem !== "string" || !Array.isArray(state.capabilities)) throw new Error("AGENT_STATE_INVALID");
  origin(state.server);
}
function safeError(error: unknown): string { return (error instanceof Error ? error.message : "Agent job failed").replace(/https?:\/\/[^\s]+/gi, "<endpoint>").replace(/\b(password|secret|token|cookie|authorization|private[_-]?key)\s*[:=]\s*[^\s,;]+/gi, "$1=<redacted>").replace(/[\r\n]+/g, " ").slice(0, 1000); }
function delay(milliseconds: number): Promise<void> { return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds)); }
