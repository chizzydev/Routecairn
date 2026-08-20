import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { dashboardScanCreateSchema } from "../../src/dashboard/contracts/DashboardSchemas.js";
import { resolveDashboardScanPlan, safeConfigurationSummary } from "../../src/dashboard/execution/ScanExecutionShared.js";
import { safeWorkerRequest } from "../../src/dashboard/worker/ScanWorkerManager.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

const tempDirs: string[] = [];
afterEach(() => { for (const dir of tempDirs.splice(0)) { try { rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 25 }); } catch { /* Windows handle cleanup is best effort. */ } } });

describe("Scan Studio core", () => {
  it("validates inline scope without requiring a server filesystem path", async () => {
    const request = dashboardScanCreateSchema.parse(publicStudioRequest("https://app.example.test"));
    const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.scope.allowedDomains).toEqual(["app.example.test"]);
    expect(resolved.plan.profile).toBe("quick");
  });

  it.each([
    ["Host", "secret", "forbidden"],
    ["X-Test", "line\r\nbreak", "newline"]
  ])("rejects unsafe ephemeral header %s during planning", async (name, value) => {
    const request = dashboardScanCreateSchema.parse(authenticatedStudioRequest("https://app.example.test", actor("A", "principal-a", name, value), actor("B", "principal-b")));
    await expect(resolveDashboardScanPlan(request)).rejects.toThrow(new RegExp(forbiddenPattern(name), "i"));
  });

  it("maps ephemeral account A/B auth into the real planner and keeps secrets out of safe metadata", async () => {
    const request = dashboardScanCreateSchema.parse(authenticatedStudioRequest("https://app.example.test", actor("A", "principal-a", "Authorization", "Bearer studio-secret-a"), actor("B", "principal-b", "Authorization", "Bearer studio-secret-b")));
    const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.authentication.hasSingleProfile).toBe(true);
    expect(resolved.plan.authentication.hasAccountPair).toBe(true);
    expect(resolved.plan.modules.some((module) => module.id === "role-comparison")).toBe(true);
    const safe = JSON.stringify(safeConfigurationSummary(request));
    expect(safe).not.toContain("studio-secret-a");
    expect(safe).not.toContain("studio-secret-b");
    expect(safe).toContain("Authorization");
  });

  it("removes ephemeral authentication from ordinary worker initialization data", () => {
    const request = dashboardScanCreateSchema.parse(authenticatedStudioRequest("https://app.example.test", actor("A", "principal-a", "Authorization", "Bearer worker-secret-a"), actor("B", "principal-b", "Authorization", "Bearer worker-secret-b")));
    const safe = JSON.stringify(safeWorkerRequest(request));
    expect(safe).not.toContain("worker-secret-a");
    expect(safe).not.toContain("worker-secret-b");
    expect(safe).toContain('"mode":"public"');
  });

  it("runs identity test, planner preview, and an authenticated A/B worker scan without persisting secrets", async () => {
    const fixture = await identityFixture();
    const dir = temporary("routecairn-authscan-");
    const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
    try {
      const auth = await authenticate(handle.url, handle.bootstrapUrl!);
      const request = authenticatedStudioRequest(fixture.url, identityActor("A", "principal-a", "Bearer studio-e2e-a", `${fixture.url}/identity`), identityActor("B", "principal-b", "Bearer studio-e2e-b", `${fixture.url}/identity`));
      const identity = await mutation<Record<string, any>>(handle.url, "/api/scans/identity-test", auth, request);
      expect(identity.accountA.category).toBe("VERIFIED");
      expect(identity.accountB.category).toBe("VERIFIED");
      const preview = await mutation<any>(handle.url, "/api/scans/plan-preview", auth, request);
      expect(preview.previewIdentity).toMatch(/^[a-f0-9]{64}$/);
      expect(JSON.stringify(preview)).not.toContain("studio-e2e-a");
      const launchRequest = structuredClone(request) as any;
      launchRequest.studio.previewIdentity = preview.previewIdentity;
      const queued = await mutation<{ scanId: string }>(handle.url, "/api/scans", auth, launchRequest);
      const scan = await waitForScan(handle.url, auth.cookie, queued.scanId);
      expect(scan.status).toBe("COMPLETED");

      const database = new DashboardDatabase(resolveDashboardPaths(dir).databasePath);
      const persisted = JSON.stringify({ scans: database.db.prepare("SELECT safe_configuration_summary FROM scans").all(), plans: database.db.prepare("SELECT redacted_plan_json FROM scan_plan_snapshots").all(), events: database.db.prepare("SELECT safe_message, safe_metadata_json FROM scan_events").all(), audits: database.db.prepare("SELECT safe_summary, safe_metadata_json FROM audit_events").all(), leases: database.db.prepare("SELECT * FROM scan_job_leases").all() });
      const artifacts = database.db.prepare("SELECT canonical_path FROM artifacts").all() as Array<{ canonical_path: string }>;
      database.close();
      const reports = artifacts.map((item) => readFileSync(item.canonical_path, "utf8")).join("\n");
      for (const secret of ["studio-e2e-a", "studio-e2e-b"]) { expect(persisted).not.toContain(secret); expect(reports).not.toContain(secret); }
    } finally { await handle.close(); await fixture.close(); }
  }, 45_000);
});

function publicStudioRequest(target: string) { const url = new URL(target); return { target, profile: "quick", studio: { version: 1, scanName: "Studio fixture", authorization: { category: "CONTROLLED_LAB", confirmed: true }, scope: scope(url.hostname), authentication: { mode: "public" }, evidenceLevel: "minimal", outputs: { json: true, markdown: true, html: true }, workflowSummary: [] } }; }
function authenticatedStudioRequest(target: string, accountA: any, accountB: any) { const url = new URL(target); return { target, profile: "authenticated", includeModules: ["baseline", "api-mapper", "auth-surface", "authenticated-testing", "role-comparison"], studio: { version: 1, scanName: "Authenticated Studio fixture", authorization: { category: "CONTROLLED_LAB", confirmed: true }, scope: scope(url.hostname), authentication: { mode: "account-pair", accountA: { source: "ephemeral", profile: accountA }, accountB: { source: "ephemeral", profile: accountB } }, evidenceLevel: "strong", outputs: { json: true, markdown: true, html: true }, workflowSummary: [] } }; }
function scope(hostname: string) { return { program: "controlled dashboard fixture", allowedDomains: [hostname], disallowedPaths: ["/logout", "/delete"], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 20, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Studio-Test/1.0" }; }
function actor(alias: string, principalId: string, headerName = "X-Actor", headerValue = alias) { return { label: alias, safeAlias: alias, principalId, headers: { [headerName]: headerValue }, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, notes: [] }; }
function identityActor(alias: string, principalId: string, authorization: string, endpoint: string) { return { ...actor(alias, principalId, "Authorization", authorization), identityVerification: { mode: "required", endpoint, method: "GET", principalIdField: "user.id", roleField: "user.role", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, role: alias === "A" ? "analyst" : "viewer" }; }
function forbiddenPattern(name: string) { return name === "Host" ? "not allowed" : "newline"; }
function temporary(prefix: string) { const dir = mkdtempSync(resolve(tmpdir(), prefix)); tempDirs.push(dir); return dir; }
async function identityFixture() { const server = createServer((request, response) => { if (request.url === "/identity") { const authorization = request.headers.authorization; const principal = authorization === "Bearer studio-e2e-a" ? { id: "principal-a", role: "analyst" } : authorization === "Bearer studio-e2e-b" ? { id: "principal-b", role: "viewer" } : undefined; response.statusCode = principal ? 200 : 401; response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ user: principal ?? null })); return; } response.setHeader("content-type", "text/html"); response.end("<html><head><title>Studio fixture</title></head><body>safe fixture</body></html>"); }); await new Promise<void>((done) => server.listen(0, "127.0.0.1", done)); const address = server.address(); if (!address || typeof address === "string") throw new Error("Fixture failed."); return { url: `http://127.0.0.1:${address.port}`, close: async () => new Promise<void>((done) => server.close(() => done())) }; }
async function authenticate(baseUrl: string, bootstrapUrl: string) { const token = new URL(bootstrapUrl).hash.replace("#bootstrap=", ""); const response = await fetch(`${baseUrl}/api/session/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) }); return { cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "", csrf: ((await response.json()) as { csrfToken: string }).csrfToken }; }
async function mutation<T>(baseUrl: string, path: string, auth: { cookie: string; csrf: string }, body: unknown): Promise<T> { const response = await fetch(`${baseUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": auth.csrf, cookie: auth.cookie, origin: baseUrl }, body: JSON.stringify(body) }); if (!response.ok) throw new Error(await response.text()); return await response.json() as T; }
async function get<T>(baseUrl: string, path: string, cookie: string): Promise<T> { const response = await fetch(`${baseUrl}${path}`, { headers: { cookie } }); if (!response.ok) throw new Error(await response.text()); return await response.json() as T; }
async function waitForScan(baseUrl: string, cookie: string, scanId: string): Promise<any> { for (let attempt = 0; attempt < 120; attempt += 1) { const body = await get<{ scan: any }>(baseUrl, `/api/scans/${scanId}`, cookie); if (["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"].includes(body.scan.status)) return body.scan; await new Promise((done) => setTimeout(done, 200)); } throw new Error("Timed out waiting for Studio scan."); }
