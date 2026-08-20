import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";

describe("continuous findings lifecycle", () => {
  it("runs scan, triage, retest, verified resolution, recurrence, concurrency, and viewer RBAC as one scenario", async () => {
    const fixture = await controlledFixture();
    const dir = mkdtempSync(resolve(tmpdir(), "routecairn-findings-e2e-"));
    const publicOrigin = "https://findings-e2e.routecairn.test";
    const sessionSecret = "continuous-findings-e2e-session-secret";
    const paths = resolveDashboardPaths(dir);
    const seed = new DashboardDatabase(paths.databasePath); seed.migrate();
    const sessions = new ServerSessionManager(seed, { publicOrigin, sessionSecret, trustProxy: true, developmentInsecureHttp: false });
    await sessions.createFirstOwner("owner@routecairn.test", "Owner continuous fixture password!");
    const analystId = await sessions.createUser({ login: "analyst@routecairn.test", password: "Analyst continuous fixture password!", role: "ANALYST" });
    await sessions.createUser({ login: "viewer@routecairn.test", password: "Viewer continuous fixture password!", role: "VIEWER" });
    seed.close();
    const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir: dir, publicOrigin, sessionSecret, trustProxy: true, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
    try {
      const analyst = await login(handle.url, publicOrigin, "analyst@routecairn.test", "Analyst continuous fixture password!");
      const project = await mutation<any>(handle.url, publicOrigin, "/api/projects", "POST", analyst, { name: "Continuous Fixture", tags: [], defaultProfile: "full", defaultScope: {} });
      const target = await mutation<any>(handle.url, publicOrigin, "/api/targets", "POST", analyst, { projectId: project.projectId, displayName: "Controlled headers fixture", baseOrigin: fixture.url, authorizationType: "CONTROLLED_LAB", authorizationSummary: "Local fixture owned by the test operator.", classification: "LOCAL", defaultProfile: "full", tags: [], approvedScope: { origins: [fixture.url] } });
      const request = studioRequest(fixture.url, project.projectId, target.targetId);
      const initialScanId = await launch(handle.url, publicOrigin, analyst, request);
      expect((await waitForScan(handle.url, publicOrigin, analyst.cookie, initialScanId)).status).toBe("COMPLETED");
      const page = await get<any>(handle.url, publicOrigin, "/api/findings?module=header-review&pageSize=100", analyst.cookie);
      expect(page.total).toBeGreaterThan(0);
      let finding = page.findings[0];
      const durableFindingId = finding.id;
      expect(finding.occurrenceCount).toBe(1);

      finding = (await mutation<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/review`, "PATCH", analyst, { newStatus: "IN_REVIEW", expectedVersion: finding.rowVersion })).finding;
      finding = (await mutation<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/review`, "PATCH", analyst, { newStatus: "CONFIRMED", expectedVersion: finding.rowVersion })).finding;
      finding = (await mutation<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/remediation`, "PATCH", analyst, { newState: "ASSIGNED", assigneeUserId: analystId, expectedVersion: finding.rowVersion })).finding;
      finding = (await mutation<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/remediation`, "PATCH", analyst, { newState: "FIX_IN_PROGRESS", expectedVersion: finding.rowVersion })).finding;
      expect((await mutation<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/notes`, "POST", analyst, { text: "Corrected response headers are ready for controlled retest." })).noteId).toBeTruthy();
      finding = (await mutation<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/remediation`, "PATCH", analyst, { newState: "FIXED_PENDING_RETEST", expectedVersion: finding.rowVersion })).finding;
      const staleVersion = finding.rowVersion;

      const draft = await get<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/retest-draft`, analyst.cookie);
      expect(draft).toMatchObject({ projectId: project.projectId, targetId: target.targetId, target: fixture.url });
      expect(draft.selectedModules).toContain("header-review");
      expect(JSON.stringify(draft)).not.toMatch(/Bearer |session=|historical-secret/i);
      fixture.setFixed(true);
      const retestRequest = studioRequest(fixture.url, project.projectId, target.targetId, draft.context);
      const retestScanId = await launch(handle.url, publicOrigin, analyst, retestRequest);
      expect((await waitForScan(handle.url, publicOrigin, analyst.cookie, retestScanId)).status).toBe("COMPLETED");
      const linked = await mutation<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/retest`, "POST", analyst, { scanId: retestScanId, expectedVersion: finding.rowVersion });
      expect(linked).toMatchObject({ compatible: true, state: "RETEST_PASSED" });
      finding = (await mutation<any>(handle.url, publicOrigin, `/api/findings/${finding.id}/verify-fixed`, "POST", analyst, { reason: "Compatible controlled header retest passed.", ownerOverride: false, expectedVersion: linked.finding.rowVersion })).finding;
      expect(finding).toMatchObject({ reviewStatus: "RESOLVED", remediationStatus: "FIXED_VERIFIED" });

      fixture.setFixed(false);
      const recurrenceScanId = await launch(handle.url, publicOrigin, analyst, studioRequest(fixture.url, project.projectId, target.targetId));
      expect((await waitForScan(handle.url, publicOrigin, analyst.cookie, recurrenceScanId)).status).toBe("COMPLETED");
      const recurrencePage = await get<any>(handle.url, publicOrigin, `/api/findings?q=${durableFindingId}&pageSize=10`, analyst.cookie);
      const recurrence = recurrencePage.findings[0];
      expect(recurrence).toMatchObject({ id: durableFindingId, reviewStatus: "REOPENED", remediationStatus: "OPEN", occurrenceCount: 2 });
      const conflict = await rawMutation(handle.url, publicOrigin, `/api/findings/${durableFindingId}/review`, "PATCH", analyst, { newStatus: "IN_REVIEW", expectedVersion: staleVersion });
      expect(conflict.status).toBe(409); expect(await conflict.json()).toMatchObject({ code: "FINDING_VERSION_CONFLICT" });

      const viewer = await login(handle.url, publicOrigin, "viewer@routecairn.test", "Viewer continuous fixture password!");
      const detail = await get<any>(handle.url, publicOrigin, `/api/findings/${durableFindingId}`, viewer.cookie);
      expect(detail.reviews.map((event: any) => event.new_review_status)).toEqual(expect.arrayContaining(["IN_REVIEW", "CONFIRMED", "RESOLVED", "REOPENED"]));
      expect(detail.remediationHistory.length).toBeGreaterThanOrEqual(4);
      expect((await rawMutation(handle.url, publicOrigin, `/api/findings/${durableFindingId}/review`, "PATCH", viewer, { newStatus: "IN_REVIEW", expectedVersion: recurrence.rowVersion })).status).toBe(403);
      const owner = await login(handle.url, publicOrigin, "owner@routecairn.test", "Owner continuous fixture password!");
      const persisted = JSON.stringify({ detail, audits: await get<any>(handle.url, publicOrigin, "/api/audit-events", owner.cookie) });
      expect(persisted).not.toMatch(/Bearer |session=|signed-secret|raw-token/i);
    } finally {
      await handle.close(); await fixture.close(); rmSync(dir, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 });
    }
  }, 120_000);
});

function studioRequest(target: string, projectId: string, targetId: string, retestContext?: Record<string, unknown>) {
  const host = new URL(target).hostname;
  return { target, projectId, targetId, profile: "full", includeModules: ["baseline", "header-review"], authorizationDeclaration: "CONTROLLED_LAB: Local fixture owned by the test operator.", studio: { version: 1, scanName: retestContext ? "Controlled remediation retest" : "Controlled initial scan", authorization: { category: "CONTROLLED_LAB", confirmed: true }, scope: { program: "Continuous findings fixture", allowedDomains: [host], disallowedPaths: ["/delete"], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 20, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Findings-E2E/1.0" }, authentication: { mode: "public" }, evidenceLevel: "normal", outputs: { json: true, markdown: true, html: true }, workflows: [], workflowSummary: [], ...(retestContext ? { retestContext } : {}) } };
}

async function launch(baseUrl: string, origin: string, auth: Auth, request: any): Promise<string> {
  const preview = await mutation<any>(baseUrl, origin, "/api/scans/plan-preview", "POST", auth, request);
  const launchRequest = structuredClone(request); launchRequest.studio.previewIdentity = preview.previewIdentity;
  return (await mutation<any>(baseUrl, origin, "/api/scans", "POST", auth, launchRequest)).scanId;
}

interface Auth { cookie: string; csrf: string; }
async function login(baseUrl: string, origin: string, loginValue: string, password: string): Promise<Auth> {
  const response = await fetch(`${baseUrl}/api/auth/login`, { method: "POST", headers: headers(origin, { "content-type": "application/json" }), body: JSON.stringify({ login: loginValue, password }) });
  if (!response.ok) throw new Error(await response.text()); const body = await response.json() as { csrfToken: string }; return { cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "", csrf: body.csrfToken };
}
async function mutation<T>(baseUrl: string, origin: string, path: string, method: "POST" | "PATCH", auth: Auth, body: unknown): Promise<T> { const response = await rawMutation(baseUrl, origin, path, method, auth, body); if (!response.ok) throw new Error(await response.text()); return await response.json() as T; }
async function rawMutation(baseUrl: string, origin: string, path: string, method: "POST" | "PATCH", auth: Auth, body: unknown): Promise<Response> { return fetch(`${baseUrl}${path}`, { method, headers: headers(origin, { "content-type": "application/json", "x-csrf-token": auth.csrf, cookie: auth.cookie }), body: JSON.stringify(body) }); }
async function get<T>(baseUrl: string, origin: string, path: string, cookie: string): Promise<T> { const response = await fetch(`${baseUrl}${path}`, { headers: headers(origin, { cookie }) }); if (!response.ok) throw new Error(await response.text()); return await response.json() as T; }
function headers(origin: string, values: Record<string, string>): Record<string, string> { return { ...values, origin, host: new URL(origin).host, "x-forwarded-host": new URL(origin).host, "x-forwarded-proto": "https" }; }
async function waitForScan(baseUrl: string, origin: string, cookie: string, scanId: string): Promise<any> { for (let attempt = 0; attempt < 180; attempt += 1) { const body = await get<any>(baseUrl, origin, `/api/scans/${scanId}`, cookie); if (["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"].includes(body.scan.status)) return body.scan; await new Promise((done) => setTimeout(done, 200)); } throw new Error("Timed out waiting for findings E2E scan."); }
async function controlledFixture() { let fixed = false; const server = createServer((_request, response) => { response.setHeader("content-type", "text/html; charset=utf-8"); if (fixed) { response.setHeader("content-security-policy", "default-src 'self'"); response.setHeader("strict-transport-security", "max-age=31536000"); response.setHeader("x-content-type-options", "nosniff"); response.setHeader("x-frame-options", "DENY"); response.setHeader("referrer-policy", "no-referrer"); response.setHeader("permissions-policy", "geolocation=()"); } response.end("<html><head><title>Controlled fixture</title></head><body>fixture</body></html>"); }); await new Promise<void>((done) => server.listen(0, "127.0.0.1", done)); const address = server.address(); if (!address || typeof address === "string") throw new Error("Fixture failed."); return { url: `http://127.0.0.1:${address.port}`, setFixed(value: boolean) { fixed = value; }, close: async () => new Promise<void>((done) => server.close(() => done())) }; }
