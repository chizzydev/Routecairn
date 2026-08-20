import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { authorizationWorkflowConfigurationSchema, scanStudioSchema, type AuthorizationWorkflowConfiguration, type ScanStudioData } from "../../src/dashboard/contracts/ScanStudioSchemas.js";
import { resolveDashboardScanPlan, safeConfigurationSummary } from "../../src/dashboard/execution/ScanExecutionShared.js";
import { routeCairnCapabilityRegistry } from "../../src/core/planning/RouteCairnCapabilityRegistry.js";
import type { AuthProfile } from "../../src/core/auth/AuthProfile.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { ServerSessionManager } from "../../src/dashboard/auth/ServerSession.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";

const workflowIds = ["object-pair", "field-exposure", "authorization-matrix", "equivalent-route", "collection-authorization", "bulk-authorization", "file-authorization"] as const;
const moduleIds = workflowIds.map((id) => id === "object-pair" ? "object-pair-testing" : id === "field-exposure" ? "field-exposure-testing" : id === "authorization-matrix" ? "authorization-matrix-testing" : id === "equivalent-route" ? "equivalent-route-testing" : `${id}-testing`);

describe("Authorization Workflow Studio contracts", () => {
  it("publishes complete safe metadata for all seven real workflow modules", () => {
    const workflows = routeCairnCapabilityRegistry().controlledWorkflows;
    expect(workflows.map((workflow) => workflow.id)).toEqual(workflowIds);
    expect(workflows.map((workflow) => workflow.moduleId)).toEqual(moduleIds);
    for (const workflow of workflows) {
      expect(workflow.dashboardSupport).toBe("FULL_DASHBOARD_PARITY");
      expect(workflow.guidedEditorSupport).toBe(true);
      expect(workflow.advancedJsonSupport).toBe(true);
      expect(workflow.schemaVersion).toBe(1);
      expect(workflow.expectationTypes.length).toBeGreaterThan(0);
      expect(workflow.guidedFieldCoverage.length).toBeGreaterThan(10);
      expect(workflow.advancedOnlyFields).toEqual([]);
      expect(workflow.safetyNotes.join(" ")).toMatch(/exact operator-supplied/i);
    }
  });

  it("round-trips every authoritative workflow schema without semantic change", () => {
    for (const envelope of allWorkflowEnvelopes()) {
      const first = authorizationWorkflowConfigurationSchema.parse(envelope);
      const second = authorizationWorkflowConfigurationSchema.parse(JSON.parse(JSON.stringify(first)));
      expect(second).toEqual(first);
    }
  });

  it("rejects unknown workflows, unsupported fields, and prototype-related input", () => {
    expect(() => authorizationWorkflowConfigurationSchema.parse({ workflowId: "unknown", enabled: true, editorMode: "guided", config: {} })).toThrow();
    const envelope = structuredClone(allWorkflowEnvelopes()[0]);
    Object.assign(envelope.config, { unsupportedDashboardField: true });
    expect(() => authorizationWorkflowConfigurationSchema.parse(envelope)).toThrow();
    expect(() => JSON.parse('{"__proto__":{"polluted":true}}', (key, value) => {
      if (["__proto__", "prototype", "constructor"].includes(key)) throw new Error("prototype key");
      return value;
    })).toThrow(/prototype key/);
  });

  it("resolves all seven dashboard configs through their real planners and ScanPlanner", async () => {
    const target = "https://app.example.com";
    const request = {
      target,
      profile: "authenticated" as const,
      includeModules: moduleIds,
      studio: scanStudio(target, allWorkflowEnvelopes(), authProfile("A", "fictional-principal-a", undefined, "session-a"), authProfile("B", "fictional-principal-b", undefined, "session-b"))
    };
    const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.filter((module) => moduleIds.includes(module.id)).map((module) => module.id).sort()).toEqual([...moduleIds].sort());
    expect(resolved.plan.objectPairTesting?.requestMatrix).toHaveLength(4);
    expect(resolved.plan.fieldExposureTesting?.requestMatrix.length).toBeGreaterThan(0);
    expect(resolved.plan.authorizationMatrixTesting?.requestMatrix.length).toBeGreaterThan(0);
    expect(resolved.plan.equivalentRouteTesting?.requestMatrix.length).toBeGreaterThan(0);
    expect(resolved.plan.collectionAuthorizationTesting?.requestMatrix.length).toBeGreaterThan(0);
    expect(resolved.plan.bulkAuthorizationTesting?.requestMatrix.length).toBeGreaterThan(0);
    expect(resolved.plan.fileAuthorizationTesting?.requestMatrix.length).toBeGreaterThan(0);
  });

  it("rejects missing account-pair auth and module/config mismatches before execution", async () => {
    const target = "https://app.example.com";
    const workflow = allWorkflowEnvelopes()[0];
    await expect(resolveDashboardScanPlan({ target, profile: "authenticated", includeModules: ["object-pair-testing"], studio: scanStudio(target, [workflow], undefined, undefined) })).rejects.toThrow(/authentication|auth-a|auth-b/i);
    await expect(resolveDashboardScanPlan({ target, profile: "authenticated", includeModules: ["baseline"], studio: scanStudio(target, [workflow], authProfile("A", "fictional-principal-a", undefined, "session-a"), authProfile("B", "fictional-principal-b", undefined, "session-b")) })).rejects.toThrow(/module was not selected/i);
  });

  it("persists only hashed workflow summaries, never raw references or auth material", () => {
    const target = "https://app.example.com";
    const studio = scanStudio(target, allWorkflowEnvelopes(), authProfile("A", "fictional-principal-a", undefined, "workflow-secret-a"), authProfile("B", "fictional-principal-b", undefined, "workflow-secret-b"));
    const safe = JSON.stringify(safeConfigurationSummary({ target, profile: "authenticated", studio }));
    for (const forbidden of ["workflow-secret-a", "workflow-secret-b", "object-a-001", "private-file-a"]) expect(safe).not.toContain(forbidden);
    expect(safe).toContain("configurationHash");
    expect(safe).toContain("object-pair");
  });

  it("runs all seven workflows through server mode, the real worker, and redacted persistence", async () => {
    const fixture = await startCompositeFixture();
    const dataDir = mkdtempSync(resolve(tmpdir(), "routecairn-workflow-studio-e2e-"));
    const paths = resolveDashboardPaths(dataDir);
    const sessionSecret = "workflow-studio-server-session-secret-value";
    const publicOrigin = "https://routecairn-workflow.test";
    const seed = new DashboardDatabase(paths.databasePath);
    seed.migrate();
    const sessions = new ServerSessionManager(seed, { publicOrigin, sessionSecret, trustProxy: true, developmentInsecureHttp: false });
    const ownerId = await sessions.createFirstOwner("owner@example.test", "correct horse battery staple");
    seed.close();
    const handle = await startDashboardServer({ mode: "server", host: "127.0.0.1", dataDir, publicOrigin, sessionSecret, trustProxy: true, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
    try {
      const auth = await login(handle.url, publicOrigin);
      const workflows = replaceWorkflowOrigin(allWorkflowEnvelopes(), fixture.url);
      const accountA = verifiedAuthProfile("A", "fictional-principal-a", "workflow-e2e-a", `${fixture.url}/identity`);
      const accountB = verifiedAuthProfile("B", "fictional-principal-b", "workflow-e2e-b", `${fixture.url}/identity`);
      const request = { target: fixture.url, profile: "authenticated" as const, includeModules: moduleIds, studio: scanStudio(fixture.url, workflows, accountA, accountB) };
      const preview = await mutation<{ previewIdentity: string; planSnapshot: Record<string, unknown>; controlledWorkflowRequests: Array<{ workflowId: string; exactRequests: number }> }>(handle.url, "/api/scans/plan-preview", publicOrigin, auth, request);
      expect(JSON.stringify(preview.planSnapshot)).not.toContain("object-a-001");
      expect(preview.controlledWorkflowRequests.map((item) => item.workflowId).sort()).toEqual([...workflowIds].sort());
      expect(preview.controlledWorkflowRequests.find((item) => item.workflowId === "object-pair")?.exactRequests).toBe(4);
      request.studio.previewIdentity = preview.previewIdentity;
      const queued = await mutation<{ scanId: string }>(handle.url, "/api/scans", publicOrigin, auth, request);
      const scan = await waitForScan(handle.url, auth.cookie, queued.scanId);
      expect(scan.status).toBe("COMPLETED");
      const detail = await apiGet<{ events: Array<{ eventType: string; moduleId?: string }>; artifacts: unknown[] }>(handle.url, `/api/scans/${queued.scanId}/detail`, auth.cookie);
      const startedModules = new Set(detail.events.filter((event) => event.eventType === "MODULE_STARTED").map((event) => event.moduleId));
      for (const moduleId of moduleIds) expect(startedModules.has(moduleId), `${moduleId}; observed=${JSON.stringify([...startedModules])}`).toBe(true);
      expect(detail.artifacts.length).toBeGreaterThanOrEqual(3);

      const changedWorkflows = structuredClone(workflows);
      const changedObjectPair = changedWorkflows.find((item) => item.workflowId === "object-pair")!;
      (changedObjectPair.config as ReturnType<typeof objectPairConfig>).cases[0]!.template.url = `${fixture.url}/api/records-v2/{{OBJECT_ID}}`;
      const changedCaseRequest = { ...request, studio: scanStudio(fixture.url, changedWorkflows, accountA, accountB) };
      const changedCasePreview = await mutation<{ previewIdentity: string }>(handle.url, "/api/scans/plan-preview", publicOrigin, auth, changedCaseRequest);
      changedCaseRequest.studio.previewIdentity = changedCasePreview.previewIdentity;
      const changedCase = await mutation<{ scanId: string }>(handle.url, "/api/scans", publicOrigin, auth, changedCaseRequest);
      expect((await waitForScan(handle.url, auth.cookie, changedCase.scanId)).status).toBe("COMPLETED");
      const missingCaseComparison = await comparisonBetween(handle.url, auth.cookie, queued.scanId, changedCase.scanId);
      const changedObjectPairResult = missingCaseComparison.items.find((item: any) => item.finding.module === "object-pair-testing" && item.classification === "INCOMPARABLE");
      expect(changedObjectPairResult, JSON.stringify(missingCaseComparison.items.filter((item: any) => item.finding.module === "object-pair-testing"))).toMatchObject({ classification: "INCOMPARABLE", reasonCode: "CASE_CHANGED" });

      const omittedRequest = { target: fixture.url, profile: "quick" as const, includeModules: ["baseline"], studio: scanStudio(fixture.url, []) };
      const omittedPreview = await mutation<{ previewIdentity: string }>(handle.url, "/api/scans/plan-preview", publicOrigin, auth, omittedRequest);
      omittedRequest.studio.previewIdentity = omittedPreview.previewIdentity;
      const omitted = await mutation<{ scanId: string }>(handle.url, "/api/scans", publicOrigin, auth, omittedRequest);
      expect((await waitForScan(handle.url, auth.cookie, omitted.scanId)).status).toBe("COMPLETED");
      const omissionComparison = await mutation<any>(handle.url, "/api/compare", publicOrigin, auth, { oldScanId: queued.scanId, newScanId: omitted.scanId });
      const omittedObjectPair = omissionComparison.items.find((item: any) => item.finding.module === "object-pair-testing");
      expect(omittedObjectPair).toMatchObject({ classification: "NOT_RETESTED", reasonCode: "MODULE_NOT_PLANNED" });
      expect(omissionComparison.findings.resolved).not.toEqual(expect.arrayContaining([expect.objectContaining({ finding: { module: "object-pair-testing" } })]));

      const secondRequest = structuredClone(request);
      const secondPreview = await mutation<{ previewIdentity: string }>(handle.url, "/api/scans/plan-preview", publicOrigin, auth, secondRequest);
      secondRequest.studio.previewIdentity = secondPreview.previewIdentity;
      const second = await mutation<{ scanId: string }>(handle.url, "/api/scans", publicOrigin, auth, secondRequest);
      expect((await waitForScan(handle.url, auth.cookie, second.scanId)).status).toBe("COMPLETED");
      const recurrenceComparison = await comparisonBetween(handle.url, auth.cookie, omitted.scanId, second.scanId);
      const recurrentObjectPair = recurrenceComparison.items.find((item: any) => item.finding.module === "object-pair-testing");
      expect(recurrentObjectPair?.regressionFlags).toContain("RECURRENCE");
      expect(recurrentObjectPair?.regressionFlags).not.toContain("REGRESSION");
      const comparison = await mutation<any>(handle.url, "/api/compare", publicOrigin, auth, { oldScanId: queued.scanId, newScanId: second.scanId });
      const findingPage = await apiGet<any>(handle.url, `/api/comparisons/${comparison.comparisonId}?page=1&pageSize=1&sort=severity&direction=desc`, auth.cookie);
      expect(findingPage.findingPage).toMatchObject({ page: 1, pageSize: 1 });
      expect(findingPage.findingPage.total).toBeGreaterThan(1);
      expect(findingPage.items).toHaveLength(1);
      expect((await fetch(`${handle.url}/api/comparisons/${comparison.comparisonId}?sort=created_at%3BDELETE`, { headers: { cookie: auth.cookie } })).status).toBe(400);
      for (const workflowId of workflowIds) {
        const workflowCoverage = comparison.coverage.workflows.find((item: any) => item.workflowId === workflowId);
        expect(workflowCoverage, `${workflowId}: ${JSON.stringify(workflowCoverage)}; cases=${JSON.stringify(comparison.coverage.cases.filter((item: any) => item.workflowId === workflowId))}`).toMatchObject({ missingCases: 0, changedCases: 0 });
        expect(workflowCoverage.executedMatchedCases, workflowId).toBeGreaterThan(0);
        const cases = comparison.coverage.cases.filter((item: any) => item.workflowId === workflowId);
        expect(cases.length, workflowId).toBeGreaterThan(0);
        expect(cases.every((item: any) => ["CASE_MATCHED_EXECUTED", "CASE_BLOCKED"].includes(item.state) && Boolean(item.reasonCode) && Boolean(item.reason)), workflowId).toBe(true);
      }

      fixture.setFixed(true);
      const fixedRequest = structuredClone(request);
      const fixedPreview = await mutation<{ previewIdentity: string }>(handle.url, "/api/scans/plan-preview", publicOrigin, auth, fixedRequest);
      fixedRequest.studio.previewIdentity = fixedPreview.previewIdentity;
      const fixed = await mutation<{ scanId: string }>(handle.url, "/api/scans", publicOrigin, auth, fixedRequest);
      expect((await waitForScan(handle.url, auth.cookie, fixed.scanId)).status).toBe("COMPLETED");
      const resolution = await comparisonBetween(handle.url, auth.cookie, second.scanId, fixed.scanId);
      const resolvedObjectPair = resolution.items.find((item: any) => item.finding.module === "object-pair-testing" && item.classification === "RESOLVED");
      expect(resolvedObjectPair).toMatchObject({ classification: "RESOLVED", coverageState: "ADEQUATE" });

      let finding = resolvedObjectPair.finding;
      finding = (await mutate<any>(handle.url, `/api/findings/${finding.id}/review`, "PATCH", publicOrigin, auth, { newStatus: "IN_REVIEW", expectedVersion: finding.rowVersion })).finding;
      finding = (await mutate<any>(handle.url, `/api/findings/${finding.id}/review`, "PATCH", publicOrigin, auth, { newStatus: "CONFIRMED", expectedVersion: finding.rowVersion })).finding;
      finding = (await mutate<any>(handle.url, `/api/findings/${finding.id}/remediation`, "PATCH", publicOrigin, auth, { newState: "ASSIGNED", assigneeUserId: ownerId, expectedVersion: finding.rowVersion })).finding;
      finding = (await mutate<any>(handle.url, `/api/findings/${finding.id}/remediation`, "PATCH", publicOrigin, auth, { newState: "FIX_IN_PROGRESS", expectedVersion: finding.rowVersion })).finding;
      finding = (await mutate<any>(handle.url, `/api/findings/${finding.id}/remediation`, "PATCH", publicOrigin, auth, { newState: "FIXED_PENDING_RETEST", expectedVersion: finding.rowVersion })).finding;
      const linked = await mutation<any>(handle.url, `/api/findings/${finding.id}/retest`, publicOrigin, auth, { scanId: fixed.scanId, expectedVersion: finding.rowVersion });
      finding = (await mutation<any>(handle.url, `/api/findings/${finding.id}/verify-fixed`, publicOrigin, auth, { reason: "Live object-pair cross-owner denial verified.", ownerOverride: false, expectedVersion: linked.finding.rowVersion })).finding;
      expect(finding).toMatchObject({ reviewStatus: "RESOLVED", remediationStatus: "FIXED_VERIFIED" });

      fixture.setFixed(false);
      const regressedRequest = structuredClone(request);
      const regressedPreview = await mutation<{ previewIdentity: string }>(handle.url, "/api/scans/plan-preview", publicOrigin, auth, regressedRequest);
      regressedRequest.studio.previewIdentity = regressedPreview.previewIdentity;
      const regressed = await mutation<{ scanId: string }>(handle.url, "/api/scans", publicOrigin, auth, regressedRequest);
      expect((await waitForScan(handle.url, auth.cookie, regressed.scanId)).status).toBe("COMPLETED");
      const regression = await comparisonBetween(handle.url, auth.cookie, fixed.scanId, regressed.scanId);
      const regressedObjectPair = regression.items.find((item: any) => item.finding.id === finding.id);
      expect(regressedObjectPair).toMatchObject({ classification: "NEW", reasonCode: "VERIFIED_REGRESSION" });
      expect(regressedObjectPair.regressionFlags).toContain("REGRESSION");
      expect(regressedObjectPair.explanation).toMatch(/verified-resolved|verified remediation/i);
      const reopened = await apiGet<any>(handle.url, `/api/findings/${finding.id}`, auth.cookie);
      expect(reopened.finding).toMatchObject({ id: finding.id, reviewStatus: "REOPENED", remediationStatus: "OPEN" });

      const audits = await apiGet<{ events: Array<{ action: string; resource_id: string }> }>(handle.url, "/api/audit-events?action=comparison.automatic_created", auth.cookie);
      expect(audits.events.length).toBeGreaterThanOrEqual(4);
    } finally {
      await handle.close();
      await fixture.close();
    }
    const persisted = readFileSync(paths.databasePath);
    for (const forbidden of ["workflow-e2e-a", "workflow-e2e-b", "object-a-001", "private-file-a"]) expect(persisted.includes(Buffer.from(forbidden))).toBe(false);
    rmSync(dataDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  }, 90_000);
});

function allWorkflowEnvelopes(): AuthorizationWorkflowConfiguration[] {
  return [
    workflowEnvelope("object-pair", objectPairConfig()),
    workflowEnvelope("field-exposure", fieldExposureConfig()),
    workflowEnvelope("authorization-matrix", example("authorization-matrix.example.json")),
    workflowEnvelope("equivalent-route", example("equivalent-routes.example.json")),
    workflowEnvelope("collection-authorization", example("collection-authorization.example.json")),
    workflowEnvelope("bulk-authorization", example("bulk-authorization.example.json")),
    workflowEnvelope("file-authorization", example("file-authorization.example.json"))
  ];
}

function workflowEnvelope(workflowId: typeof workflowIds[number], config: unknown): AuthorizationWorkflowConfiguration { return authorizationWorkflowConfigurationSchema.parse({ workflowId, enabled: true, editorMode: "guided", config }); }
function example(name: string): unknown { return JSON.parse(readFileSync(resolve("examples", name), "utf8")) as unknown; }
function objectPairConfig() { const assertion = (id: string, source: string) => ({ id, source, confirmedSafeToTest: true, readOnly: true, tenantId: id.endsWith("a-001") ? "tenant-a" : "tenant-b", expectedObjectIdField: "id", expectedOwnerField: "owner", expectedTenantField: "tenant", expectedPrivateHeaders: [], expectedSafeMarkers: [], expectedPrivateFields: ["privateNote"] }); return { schemaVersion: 1, maxPairs: 5, principals: { accountA: { expectedAccountId: "fictional-principal-a", tenantId: "tenant-a", role: "member" }, accountB: { expectedAccountId: "fictional-principal-b", tenantId: "tenant-b", role: "viewer" } }, cases: [{ id: "pair-1", objectType: "record", expectedVisibility: "PRIVATE_TO_OWNER", template: { id: "read", method: "GET", url: "https://app.example.com/api/records/{{OBJECT_ID}}", headers: {} }, accountAObject: assertion("object-a-001", "operator A"), accountBObject: assertion("object-b-001", "operator B") }] }; }
function fieldExposureConfig() { return { schemaVersion: 1, maxCases: 5, maxResponseBytes: 65536, maxPreviewLength: 120, cases: [{ id: "fields-1", objectType: "record", objectId: "object-a-001", declaredOwnerActor: "owner", expectedVisibility: "OWNER_ONLY", requireVerifiedIdentity: true, template: { id: "read", method: "GET", url: "https://app.example.com/api/records/{{OBJECT_ID}}", headers: {} }, objectConfirmation: { expectedObjectIdField: "id", expectedOwnerField: "owner", expectedTenantField: "tenant" }, actors: [{ id: "owner", type: "OWNER", authProfile: "account_a", safeAlias: "Account A", principalId: "fictional-principal-a", tenantId: "tenant-a" }, { id: "non-owner", type: "NON_OWNER", authProfile: "account_b", safeAlias: "Account B", principalId: "fictional-principal-b", tenantId: "tenant-b" }], fieldExpectations: [{ id: "private", path: "privateNote", label: "Private note", sensitivity: "PRIVATE", expectation: "MUST_BE_ABSENT", allowedActors: ["owner"], prohibitedActors: ["non-owner"], allowPreview: false }] }] }; }
function authProfile(label: string, principalId: string, tenantId: string | undefined, secret: string): AuthProfile { return { label, safeAlias: label, principalId, ...(tenantId ? { tenantId } : {}), headers: { Authorization: `Bearer ${secret}` }, cookies: [], identityVerification: { mode: "disabled", method: "GET", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] }, notes: [] }; }
function scanStudio(target: string, workflows: AuthorizationWorkflowConfiguration[], accountA?: AuthProfile, accountB?: AuthProfile): ScanStudioData { return scanStudioSchema.parse({ version: 1, scanName: "Workflow Studio test", authorization: { category: "CONTROLLED_LAB", confirmed: true }, scope: { program: "Workflow fixture", allowedDomains: [new URL(target).hostname], disallowedPaths: ["/delete"], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"], rateLimitPerSecond: 10, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn-Workflow-Test/1.0" }, authentication: accountA && accountB ? { mode: "account-pair", accountA: { source: "ephemeral", profile: accountA }, accountB: { source: "ephemeral", profile: accountB } } : { mode: "public" }, evidenceLevel: "strong", outputs: { json: true, markdown: true, html: true }, workflows, workflowSummary: [] }); }
function verifiedAuthProfile(label: string, principalId: string, secret: string, endpoint: string): AuthProfile { return { ...authProfile(label, principalId, undefined, secret), identityVerification: { mode: "required", endpoint, method: "GET", principalIdField: "user.id", expectedContentType: "application/json", successStatusCodes: [200], maxResponseBytes: 8192, anonymousMarkers: [] } }; }
function replaceWorkflowOrigin<T>(value: T, target: string): T { return JSON.parse(JSON.stringify(value).replaceAll("https://app.example.com", target)) as T; }
async function startCompositeFixture() { let fixed = false; const server = createServer((request, response) => { const authorization = request.headers.authorization; if (request.url === "/identity") { const id = authorization === "Bearer workflow-e2e-a" ? "fictional-principal-a" : authorization === "Bearer workflow-e2e-b" ? "fictional-principal-b" : undefined; response.statusCode = id ? 200 : 401; response.setHeader("content-type", "application/json"); response.end(JSON.stringify({ user: { id } })); return; } const requested = decodeURIComponent((request.url ?? "").split("?")[0]!.split("/").pop() ?? "object-a-001"); const owner = /(?:object-b|tenant-b)/.test(requested) ? "fictional-principal-b" : "fictional-principal-a"; const requester = authorization === "Bearer workflow-e2e-a" ? "fictional-principal-a" : authorization === "Bearer workflow-e2e-b" ? "fictional-principal-b" : undefined; response.setHeader("content-type", "application/json"); if (fixed && requester && requester !== owner) { response.statusCode = 403; response.end(JSON.stringify({ error: "cross-owner access denied" })); return; } response.end(JSON.stringify({ id: requested, owner, tenant: owner.endsWith("b") ? "tenant-b" : "tenant-a", state: "active", privateNote: "fixture-private-value", preview: true, items: [{ id: "fictional-private-project-a", tenant: "tenant-a", owner: "fictional-principal-a", state: "active", type: "project" }], rejected: [], file: { id: requested, state: "active" } })); }); await new Promise<void>((done) => server.listen(0, "127.0.0.1", done)); const address = server.address(); if (!address || typeof address === "string") throw new Error("Fixture did not start."); return { url: `http://127.0.0.1:${address.port}`, setFixed(value: boolean) { fixed = value; }, close: async () => new Promise<void>((done) => server.close(() => done())) }; }
async function login(baseUrl: string, origin: string) { const response = await fetch(`${baseUrl}/api/auth/login`, { method: "POST", headers: { "content-type": "application/json", origin, "x-forwarded-proto": "https" }, body: JSON.stringify({ login: "owner@example.test", password: "correct horse battery staple" }) }); if (!response.ok) throw new Error(await response.text()); const body = await response.json() as { csrfToken: string }; return { cookie: response.headers.get("set-cookie")?.split(";")[0] ?? "", csrf: body.csrfToken }; }
async function mutation<T>(baseUrl: string, path: string, origin: string, auth: { cookie: string; csrf: string }, body: unknown): Promise<T> { const response = await fetch(`${baseUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", origin, "x-forwarded-proto": "https", "x-csrf-token": auth.csrf, cookie: auth.cookie }, body: JSON.stringify(body) }); if (!response.ok) throw new Error(await response.text()); return await response.json() as T; }
async function mutate<T>(baseUrl: string, path: string, method: "POST" | "PATCH", origin: string, auth: { cookie: string; csrf: string }, body: unknown): Promise<T> { const response = await fetch(`${baseUrl}${path}`, { method, headers: { "content-type": "application/json", origin, "x-forwarded-proto": "https", "x-csrf-token": auth.csrf, cookie: auth.cookie }, body: JSON.stringify(body) }); if (!response.ok) throw new Error(await response.text()); return await response.json() as T; }
async function apiGet<T>(baseUrl: string, path: string, cookie: string): Promise<T> { const response = await fetch(`${baseUrl}${path}`, { headers: { cookie } }); if (!response.ok) throw new Error(await response.text()); return await response.json() as T; }
async function comparisonBetween(baseUrl: string, cookie: string, olderScanId: string, newerScanId: string): Promise<any> { const page = await apiGet<{ comparisons: Array<{ id: string; olderScanId: string; newerScanId: string }> }>(baseUrl, "/api/comparisons", cookie); const match = page.comparisons.find((item) => item.olderScanId === olderScanId && item.newerScanId === newerScanId); expect(match, `${olderScanId} -> ${newerScanId}`).toBeTruthy(); return apiGet<any>(baseUrl, `/api/comparisons/${match!.id}?pageSize=100`, cookie); }
async function waitForScan(baseUrl: string, cookie: string, scanId: string): Promise<{ status: string }> { for (let attempt = 0; attempt < 180; attempt += 1) { const body = await apiGet<{ scan: { status: string } }>(baseUrl, `/api/scans/${scanId}`, cookie); if (["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"].includes(body.scan.status)) return body.scan; await new Promise((done) => setTimeout(done, 250)); } throw new Error("Timed out waiting for workflow scan."); }
