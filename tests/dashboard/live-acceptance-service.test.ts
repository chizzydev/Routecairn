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

  it("verifies the complete broader real-target grid from semantic evidence and an exact remediation rerun", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = new TargetRepository(database).create({ displayName: "Disposable SaaS", baseOrigin: "https://saas.routecairn.app", tags: [], classification: "PRODUCTION", authorizationType: "OWNED", authorizationSummary: "Owned disposable acceptance tenant", productionEnabled: true, approvedScope: scope("saas.routecairn.app") });
    const scans = new ScanRepository(database); const baselineScanId = randomUUID(); const rerunScanId = randomUUID();
    for (const id of [baselineScanId, rerunScanId]) scans.create({ id, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://saas.routecairn.app", safeTargetLabel: "fixture", profile: "authenticated", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
    const modules = ["supabase-authorization", "authentication-lifecycle", "api-graphql-authorization", "link-portal-export-security", "billing-entitlement-security", "operational-endpoint-security"];
    const insertModule = database.db.prepare("INSERT INTO scan_module_executions (id,scan_id,module_id,module_label,planned_order,status,executed_request_count) VALUES (?,?,?,?,?,'COMPLETED',1)");
    for (const scanId of [baselineScanId, rerunScanId]) modules.forEach((moduleId, index) => insertModule.run(randomUUID(), scanId, moduleId, moduleId, index + 1));
    const insertCase = database.db.prepare("INSERT INTO scan_workflow_case_executions (id,scan_id,workflow_id,module_id,safe_case_alias,safe_case_fingerprint,execution_state,request_transmitted,matched_expectation,evidence_strength,safe_semantics_json,safe_result_json,created_at) VALUES (?,?,?,?,?,?,'COMPLETED',1,1,'STRONG',?,'{}',?)");
    const evidence: Array<[string, string, Record<string, unknown>]> = [
      ["supabase-authorization", "table", { surface: "TABLE", boundary: "CROSS_TENANT" }], ["supabase-authorization", "storage", { surface: "STORAGE" }], ["supabase-authorization", "rpc", { surface: "RPC" }],
      ["authentication-lifecycle", "oauth", { category: "OAUTH_OIDC_STATE_REDIRECT_VALIDATION" }], ["authentication-lifecycle", "mfa", { category: "MFA_ENROLLMENT_REMOVAL" }], ["authentication-lifecycle", "passkey", { category: "PASSKEY_ENROLLMENT_REMOVAL" }],
      ["api-graphql-authorization", "graphql", { kind: "OBJECT_AUTHORIZATION", protocols: ["GRAPHQL"] }],
      ["link-portal-export-security", "signed", { category: "SIGNED_LINK_EXPIRY" }], ["link-portal-export-security", "portal", { category: "PORTAL_TENANT_BINDING" }], ["link-portal-export-security", "export", { category: "EXPORT_AUTHORIZATION" }],
      ["billing-entitlement-security", "billing", { category: "UNVERIFIED_PAYMENT_ENTITLEMENT" }],
      ["operational-endpoint-security", "webhook", { category: "WEBHOOK_SIGNATURE_REJECTION" }], ["operational-endpoint-security", "cron", { category: "CRON_AUTHENTICATION" }]
    ];
    for (const scanId of [baselineScanId, rerunScanId]) evidence.forEach(([workflow, alias, semantics], index) => insertCase.run(randomUUID(), scanId, workflow, workflow, alias, index.toString(16).padStart(64, "0"), JSON.stringify(semantics), new Date().toISOString()));
    const adapterId = randomUUID(), versionId = randomUUID(), now = new Date().toISOString();
    database.db.prepare("INSERT INTO provider_adapters (id,name,target_id,provider,engine_id,enabled,created_by,created_at,updated_at) VALUES (?,?,?,?,?,1,'owner',?,?)").run(adapterId, "Synthetic Stripe", targetId, "STRIPE", "billing-entitlement-security", now, now);
    database.db.prepare("INSERT INTO provider_adapter_versions (id,profile_id,revision,status,adapter_digest,target_row_version,credential_binding_json,algorithm,key_version,nonce,ciphertext,auth_tag,created_by,created_at,reviewed_by,reviewed_at) VALUES (?,?,1,'REVIEWED',?,1,'[]','aes-256-gcm','one','n','c','t','owner',?,'owner',?)").run(versionId, adapterId, "b".repeat(64), now, now);
    database.db.prepare("UPDATE provider_adapters SET active_version_id=? WHERE id=?").run(versionId, adapterId);
    database.db.prepare("INSERT INTO scan_provider_adapter_bindings (scan_id,profile_id,version_id,adapter_digest,created_at) VALUES (?,?,?,?,?)").run(rerunScanId, adapterId, versionId, "b".repeat(64), now);
    const comparisonId = randomUUID();
    database.db.prepare("INSERT INTO scan_comparisons (id,target_id,older_scan_id,newer_scan_id,state,compatibility_state,source_quality_older,source_quality_newer,created_at,completed_at,engine_version,coverage_algorithm_version,summary_json,coverage_summary_json,warning_json) VALUES (?,?,?,?,'COMPLETED','COMPATIBLE','NATIVE','NATIVE',?,?,'test','test','{}','{}','[]')").run(comparisonId, targetId, baselineScanId, rerunScanId, now, now);
    const execution = { preview: async () => preview(), enqueue: async () => randomUUID(), cancel: () => undefined } as any;
    const service = new LiveAcceptanceService(database, execution, { bytes: randomBytes(32), version: "one" });
    const value = broaderPlan(targetId, rerunScanId, baselineScanId, comparisonId);
    await expect(service.preview({ ...value, environment: "STAGING" })).rejects.toThrow("Broader real-target acceptance requires a production-classified target");
    database.db.prepare("UPDATE scans SET source='REPORT_IMPORTED',status='IMPORTED' WHERE id=?").run(rerunScanId);
    expect((await service.preview(value)).blockers).toEqual(expect.arrayContaining([expect.stringContaining("native completed scan")]));
    database.db.prepare("UPDATE scans SET source='DASHBOARD',status='COMPLETED' WHERE id=?").run(rerunScanId);
    database.db.prepare("UPDATE scan_workflow_case_executions SET safe_case_fingerprint='not-durable' WHERE scan_id=? AND safe_case_alias='table'").run(rerunScanId);
    expect((await service.preview(value)).blockers).toEqual(expect.arrayContaining([expect.stringContaining("durable case fingerprint")]));
    database.db.prepare("UPDATE scan_workflow_case_executions SET safe_case_fingerprint=? WHERE scan_id=? AND safe_case_alias='table'").run("0".repeat(64), rerunScanId);
    const previewed = await service.preview(value);
    expect(previewed).toMatchObject({ standard: "BROADER_REAL_TARGET_V1", blockers: [] });
    expect(previewed.lanes.every((lane) => lane.proofResult?.verified)).toBe(true);
    const created = await service.create(value, "owner"); await service.review(String(created.plan.id), created.preview.planDigest, "owner");
    const run = await service.execute(String(created.plan.id), created.preview.planDigest, "owner") as any;
    expect(run).toMatchObject({ status: "COMPLETED", standard: "BROADER_REAL_TARGET_V1", coverage: { assessed: 8, requiredGaps: 0, complete: true } });
    expect(run.lanes.find((lane: any) => lane.kind === "REMEDIATION_RERUNS")).toMatchObject({ outcome: "ASSESSED", proof: { verified: true, comparison: { compatibility: "COMPATIBLE", matchedCases: evidence.length } } });
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
function scope(domain = "app.example.test") { return { program: "Owned acceptance", allowedDomains: [domain], disallowedPaths: ["/delete"], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 3, concurrency: 3, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" }; }
function preview() { return { previewIdentity: "b".repeat(64), profile: "quick", modules: [{ id: "baseline", phase: "discovery", settings: {} }], limits: { maxRequests: 40, cleanupReservedRequests: 4 }, evidence: {}, skippedModules: [], controlledWorkflowRequests: [], planSnapshot: {}, credentialReadiness: { ready: true, checkedAt: new Date().toISOString(), requiredValidThrough: new Date().toISOString(), blockers: [], warnings: [], profiles: [] }, warnings: [] }; }

function broaderPlan(targetId: string, scanId: string, baselineScanId: string, comparisonId: string) {
  const now = Date.now(); const definitions = [
    ["multi-tenant", "MULTI_TENANT_APPLICATION"], ["supabase", "SUPABASE_RLS_STORAGE_RPC"], ["auth", "OAUTH_MFA_PASSKEYS"], ["graphql", "GRAPHQL_AUTHORIZATION"], ["signed", "SIGNED_PORTALS_EXPORTS"], ["billing", "SYNTHETIC_PAYMENT_PROVIDER"], ["operations", "WEBHOOKS_CRON"]
  ];
  return { schemaVersion: 1, standard: "BROADER_REAL_TARGET_V1", name: "Broader external proof", targetId, environment: "PRODUCTION", authorization: { mode: "OWNED_PRODUCTION", proofReference: "OWNER-APPROVAL-GRID", proofSha256: "c".repeat(64), authorizedBy: "owner", startsAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), neverTestPaths: [], authenticationPermitted: true, mutationPermitted: true, disposableAccountsOnly: true, realPaymentsAllowed: false, destructiveAdministrationAllowed: false }, lanes: [
    ...definitions.map(([id, kind]) => ({ id, label: `${kind} evidence`, kind, required: true, execution: { disposition: "LINK_SCAN", scanId } })),
    { id: "remediation", label: "Remediation rerun evidence", kind: "REMEDIATION_RERUNS", required: true, execution: { disposition: "LINK_REMEDIATION", baselineScanId, rerunScanId: scanId, comparisonId } }
  ] };
}
