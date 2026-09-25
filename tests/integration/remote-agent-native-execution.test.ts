import { afterEach, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { enrollAgent, runAgent } from "../../src/cli/commands/agent.js";
import { exampleScope } from "../../src/config/defaults.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("turnkey signed remote agent", () => {
  it("executes native scan, module, and export jobs without an installed handler", async () => {
    const directory = await mkdtemp(join(tmpdir(), "routecairn-native-agent-")); directories.push(directory);
    const workspace = join(directory, "workspace"); const statePath = join(workspace, "agent-state.json");
    await mkdir(join(workspace, "inputs"), { recursive: true });
    const target = createServer((_request, response) => response.writeHead(200, { "content-type": "text/html" }).end("<!doctype html><title>native agent fixture</title>"));
    await new Promise<void>((resolve) => target.listen(0, "127.0.0.1", resolve));
    const origin = `http://127.0.0.1:${(target.address() as AddressInfo).port}`;
    await writeFile(join(workspace, "inputs", "scope.json"), `${JSON.stringify({ ...exampleScope, program: "Native agent fixture", allowedDomains: ["127.0.0.1"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 20, concurrency: 2, respectRobotsTxt: false }, null, 2)}\n`, "utf8");
    const dashboard = await startDashboardServer({ dataDir: join(directory, "dashboard"), uiDistDir: join(directory, "ui") });
    try {
      const auth = await bootstrap(dashboard.url, dashboard.bootstrapUrl!);
      const organizations = await apiGet<{ organizations: Array<{ id: string }> }>(dashboard.url, "/api/operations/organizations", auth.cookie); const organizationId = organizations.organizations[0]!.id;
      const enrollment = await apiPost<{ token: string }>(dashboard.url, "/api/operations/remote-workers/enrollments", auth, { organizationId, expiresInMinutes: 60 });
      await enrollAgent({ server: dashboard.url, token: enrollment.token, name: "native-worker", state: statePath, capability: ["ping", "scan", "module", "export"] });

      const basePayload = { schemaVersion: 1, target: origin, scopePath: "inputs/scope.json", profile: "quick", maxRequests: 12, modules: ["baseline"] };
      await queue(dashboard.url, auth, organizationId, "SCAN", { ...basePayload, outputPath: "outputs/scan" });
      await runAgent({ state: statePath, workspace, once: true, interval: "250", maxJobMs: "60000" });
      const report = JSON.parse(await readFile(join(workspace, "outputs", "scan", "report.json"), "utf8")) as { routeCairnVersion: string };
      expect(report.routeCairnVersion).toBe("0.1.0");
      await expect(readFile(join(workspace, ".routecairn", "scan-index.json"), "utf8")).resolves.toContain("outputs");

      await queue(dashboard.url, auth, organizationId, "MODULE", { ...basePayload, outputPath: "outputs/module", modules: ["baseline"] });
      await runAgent({ state: statePath, workspace, once: true, interval: "250", maxJobMs: "60000" });
      expect(JSON.parse(await readFile(join(workspace, "outputs", "module", "report.json"), "utf8"))).toEqual(expect.objectContaining({ routeCairnVersion: "0.1.0" }));

      await queue(dashboard.url, auth, organizationId, "EXPORT", { schemaVersion: 1, reportPath: "outputs/scan/report.json", outputPath: "outputs/export", format: "SARIF" });
      await runAgent({ state: statePath, workspace, once: true, interval: "250", maxJobMs: "60000" });
      expect(JSON.parse(await readFile(join(workspace, "outputs", "export", "routecairn.sarif.json"), "utf8"))).toEqual(expect.objectContaining({ version: "2.1.0" }));

      const operations = await apiGet<{ workers: Array<{ capabilities: string[] }>; jobs: Array<{ kind: string; status: string; result: Record<string, unknown> | null }> }>(dashboard.url, `/api/operations/remote-workers?organizationId=${organizationId}`, auth.cookie);
      expect(operations.workers[0]?.capabilities).toEqual(expect.arrayContaining(["scan", "module", "export"]));
      expect(operations.jobs.filter((job) => ["SCAN", "MODULE", "EXPORT"].includes(job.kind))).toHaveLength(3);
      expect(operations.jobs.every((job) => job.status === "COMPLETED")).toBe(true);
      expect(operations.jobs.every((job) => job.result !== null)).toBe(true);

      await queue(dashboard.url, auth, organizationId, "EXPORT", { schemaVersion: 1, reportPath: "outputs/scan/report.json", outputPath: "../escape", format: "JSON" });
      await runAgent({ state: statePath, workspace, once: true, interval: "250", maxJobMs: "60000" });
      const rejected = await apiGet<{ jobs: Array<{ status: string; safeError?: string }> }>(dashboard.url, `/api/operations/remote-workers?organizationId=${organizationId}`, auth.cookie);
      expect(rejected.jobs[0]).toEqual(expect.objectContaining({ status: "FAILED", safeError: "AGENT_WORKSPACE_PATH_REJECTED" }));

      const outside = join(directory, "outside"); await mkdir(outside); await symlink(outside, join(workspace, "linked-output"), process.platform === "win32" ? "junction" : "dir");
      await queue(dashboard.url, auth, organizationId, "EXPORT", { schemaVersion: 1, reportPath: "outputs/scan/report.json", outputPath: "linked-output/escape", format: "JSON" });
      await runAgent({ state: statePath, workspace, once: true, interval: "250", maxJobMs: "60000" });
      const linkedRejected = await apiGet<{ jobs: Array<{ status: string; safeError?: string }> }>(dashboard.url, `/api/operations/remote-workers?organizationId=${organizationId}`, auth.cookie);
      expect(linkedRejected.jobs[0]).toEqual(expect.objectContaining({ status: "FAILED", safeError: "AGENT_WORKSPACE_PATH_REJECTED" }));
      await expect(access(join(outside, "escape"))).rejects.toBeTruthy();
    } finally {
      await dashboard.close(); target.closeAllConnections(); await new Promise<void>((resolve) => target.close(() => resolve()));
    }
  }, 90_000);
});

async function queue(baseUrl:string,auth:{cookie:string;csrf:string},organizationId:string,kind:"SCAN"|"MODULE"|"EXPORT",payload:Record<string,unknown>):Promise<void>{await apiPost(baseUrl,"/api/operations/remote-jobs",auth,{organizationId,kind,payload,requiredCapabilities:[],priority:0,maxAttempts:2});}
async function bootstrap(baseUrl:string,bootstrapUrl:string):Promise<{cookie:string;csrf:string}>{const token=new URL(bootstrapUrl).hash.replace("#bootstrap=","");const response=await fetch(`${baseUrl}/api/session/bootstrap`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({token})});const body=await response.json() as {csrfToken:string};return{cookie:response.headers.get("set-cookie")?.split(";")[0]??"",csrf:body.csrfToken};}
async function apiGet<T>(baseUrl:string,path:string,cookie:string):Promise<T>{const response=await fetch(`${baseUrl}${path}`,{headers:{cookie}});if(!response.ok)throw new Error(`${path}:${response.status}:${await response.text()}`);return response.json() as Promise<T>;}
async function apiPost<T=unknown>(baseUrl:string,path:string,auth:{cookie:string;csrf:string},body:unknown):Promise<T>{const response=await fetch(`${baseUrl}${path}`,{method:"POST",headers:{cookie:auth.cookie,"x-csrf-token":auth.csrf,"content-type":"application/json",origin:baseUrl},body:JSON.stringify(body)});if(!response.ok)throw new Error(`${path}:${response.status}:${await response.text()}`);return response.json() as Promise<T>;}
