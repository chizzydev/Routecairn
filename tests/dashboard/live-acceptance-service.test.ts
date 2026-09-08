import { randomBytes, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { LiveAcceptanceService, rotateLiveAcceptancePlanKey } from "../../src/dashboard/execution/LiveAcceptanceService.js";
import type { DashboardScanCreateRequest } from "../../src/dashboard/types/DashboardTypes.js";

describe("live acceptance orchestration", () => {
  it("encrypts, reviews, binds, executes, and derives lane coverage from child scans", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = new TargetRepository(database).create({ displayName: "Owned production", baseOrigin: "https://app.example.test", tags: [], classification: "PRODUCTION", authorizationType: "OWNED", authorizationSummary: "Owned disposable production acceptance target", productionEnabled: true, approvedScope: scope() });
    const requests: DashboardScanCreateRequest[] = [];
    const execution = {
      preview: async (request: DashboardScanCreateRequest) => { requests.push(request); return preview(); },
      enqueue: async (request: DashboardScanCreateRequest) => { requests.push(request); const id = randomUUID(); new ScanRepository(database).create({ id, source: "DASHBOARD", status: "COMPLETED", targetOrigin: request.target, safeTargetLabel: request.target, profile: request.profile, evidenceLevel: "strong", safeConfigurationSummary: {}, targetId }); return id; },
      cancel: () => undefined
    } as any;
    const key = { bytes: randomBytes(32), version: "one" };
    const service = new LiveAcceptanceService(database, execution, key);
    const input = plan(targetId);
    const previewed = await service.preview(input);
    expect(previewed).toMatchObject({ totalRequestBudget: 40, cleanupReservedRequests: 4, blockers: [] });
    expect((requests[0]?.studio?.scope.disallowedPaths ?? [])).toContain("/danger");
    const created = await service.create(input, "owner");
    expect(created.plan.status).toBe("DRAFT");
    const stored = database.db.prepare("SELECT ciphertext FROM live_acceptance_plans").get() as { ciphertext: string };
    expect(Buffer.from(stored.ciphertext, "base64url").toString("utf8")).not.toContain("Acceptance fixture");
    const reviewed = await service.review(String(created.plan.id), previewed.planDigest, "owner");
    expect(reviewed.status).toBe("REVIEWED");
    const run = await service.execute(String(created.plan.id), previewed.planDigest, "owner") as any;
    expect(run).toMatchObject({ status: "COMPLETED", coverage: { assessed: 1, notApplicable: 1, requiredGaps: 0 } });
    expect(run.lanes[0]).toMatchObject({ outcome: "ASSESSED", cleanupUnresolved: false });
    database.close();
  });

  it("invalidates review when semantics or target binding changes and rotates encrypted plans", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = new TargetRepository(database).create({ displayName: "Owned production", baseOrigin: "https://app.example.test", tags: [], classification: "PRODUCTION", authorizationType: "OWNED", authorizationSummary: "Owned disposable production acceptance target", productionEnabled: true, approvedScope: scope() });
    const execution = { preview: async () => preview(), enqueue: async () => randomUUID(), cancel: () => undefined } as any;
    const current = { bytes: randomBytes(32), version: "one" }; const next = { bytes: randomBytes(32), version: "two" };
    const service = new LiveAcceptanceService(database, execution, current);
    const created = await service.create(plan(targetId), "owner");
    await expect(service.review(String(created.plan.id), "0".repeat(64), "owner")).rejects.toThrow("CHANGED_AFTER_PREVIEW");
    database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(targetId);
    await expect(service.review(String(created.plan.id), String(created.plan.planDigest), "owner")).rejects.toThrow("CHANGED_AFTER_PREVIEW");
    expect(rotateLiveAcceptancePlanKey(database, current, next)).toBe(1);
    expect(new LiveAcceptanceService(database, execution, next).getPlan(String(created.plan.id))).toMatchObject({ name: "Acceptance fixture" });
    database.close();
  });

  it("blocks short authorization windows and ordinary scans masquerading as mutation evidence", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = new TargetRepository(database).create({ displayName: "Owned production", baseOrigin: "https://app.example.test", tags: [], classification: "PRODUCTION", authorizationType: "OWNED", authorizationSummary: "Owned disposable production acceptance target", productionEnabled: true, approvedScope: scope() });
    const ordinaryScan = randomUUID(); new ScanRepository(database).create({ id: ordinaryScan, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.example.test", safeTargetLabel: "fixture", profile: "quick", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
    const execution = { preview: async () => ({ ...preview(), limits: { maxRequests: 40, cleanupReservedRequests: 4, maxScanDurationMs: 120_000 } }), enqueue: async () => randomUUID(), cancel: () => undefined } as any;
    const service = new LiveAcceptanceService(database, execution, { bytes: randomBytes(32), version: "one" });
    const value = plan(targetId); value.authorization.mutationPermitted = true;
    value.lanes.push({ id: "mutation", label: "Mutation evidence", kind: "MUTATION_ACCEPTANCE", required: true, execution: { disposition: "LINK_SCAN", scanId: ordinaryScan } } as any);
    const result = await service.preview(value);
    expect(result.blockers).toEqual(expect.arrayContaining([expect.stringContaining("may expire"), expect.stringContaining("controlled-mutation approval")]));
    database.close();
  });

  it("binds NOT_APPLICABLE to completed exact-target evidence when supplied", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = new TargetRepository(database).create({ displayName: "Owned production", baseOrigin: "https://app.example.test", tags: [], classification: "PRODUCTION", authorizationType: "OWNED", authorizationSummary: "Owned disposable production acceptance target", productionEnabled: true, approvedScope: scope() });
    const evidenceScanId = randomUUID(); new ScanRepository(database).create({ id: evidenceScanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.example.test", safeTargetLabel: "fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
    const execution = { preview: async () => preview(), enqueue: async (request: DashboardScanCreateRequest) => { const id = randomUUID(); new ScanRepository(database).create({ id, source: "DASHBOARD", status: "COMPLETED", targetOrigin: request.target, safeTargetLabel: request.target, profile: request.profile, evidenceLevel: "strong", safeConfigurationSummary: {}, targetId }); return id; }, cancel: () => undefined } as any;
    const service = new LiveAcceptanceService(database, execution, { bytes: randomBytes(32), version: "one" });
    const value = plan(targetId); (value.lanes[1]!.execution as any).evidenceScanId = evidenceScanId;
    const previewed = await service.preview(value);
    expect(previewed.lanes[1]).toMatchObject({ disposition: "NOT_APPLICABLE", evidenceScanId, warnings: [] });
    const created = await service.create(value, "owner"); await service.review(String(created.plan.id), created.preview.planDigest, "owner");
    const run = await service.execute(String(created.plan.id), created.preview.planDigest, "owner") as any;
    expect(run.lanes[1]).toMatchObject({ outcome: "NOT_APPLICABLE", evidenceScanId, evidenceScanStatus: "COMPLETED" });
    database.close();
  });
});

function plan(targetId: string) {
  const now = Date.now();
  return { schemaVersion: 1, name: "Acceptance fixture", targetId, environment: "PRODUCTION", authorization: { mode: "OWNED_PRODUCTION", proofReference: "OWNER-APPROVAL-1", proofSha256: "a".repeat(64), authorizedBy: "owner", startsAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), neverTestPaths: ["/danger"], authenticationPermitted: false, mutationPermitted: false, disposableAccountsOnly: true, realPaymentsAllowed: false, destructiveAdministrationAllowed: false }, lanes: [
    { id: "public", label: "Public baseline", kind: "PUBLIC_BASELINE", required: true, execution: { disposition: "EXECUTE_SCAN", profile: "quick", authentication: { mode: "public" }, includeModules: [], workflows: [], advancedEngines: [], maxRequests: 40, cleanupReservedRequests: 4, rateLimitPerSecond: 2, concurrency: 2, evidenceLevel: "strong" } },
    { id: "tenant", label: "Tenant isolation", kind: "DATA_AUTHORIZATION", required: true, execution: { disposition: "NOT_APPLICABLE", reason: "This product has no tenant or organization data model." } }
  ] };
}
function scope() { return { program: "Owned acceptance", allowedDomains: ["app.example.test"], disallowedPaths: ["/delete"], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 3, concurrency: 3, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" }; }
function preview() { return { previewIdentity: "b".repeat(64), profile: "quick", modules: [{ id: "baseline", phase: "discovery", settings: {} }], limits: { maxRequests: 40, cleanupReservedRequests: 4 }, evidence: {}, skippedModules: [], controlledWorkflowRequests: [], planSnapshot: {}, credentialReadiness: { ready: true, checkedAt: new Date().toISOString(), requiredValidThrough: new Date().toISOString(), blockers: [], warnings: [], profiles: [] }, warnings: [] }; }
