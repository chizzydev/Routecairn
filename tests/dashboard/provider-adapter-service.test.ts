import { randomBytes, randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { CredentialVault } from "../../src/dashboard/credentials/CredentialVault.js";
import { loadAdvancedEngineCatalog } from "../../src/dashboard/contracts/AdvancedEngineSchemas.js";
import { ProviderAdapterService, rotateProviderAdapterKey } from "../../src/dashboard/execution/ProviderAdapterService.js";
import type { DashboardScanCreateRequest, PlanPreviewResponse } from "../../src/dashboard/types/DashboardTypes.js";

describe("reusable fixture and provider adapters", () => {
  it("encrypts, reviews, materializes, and revalidates an exact reusable adapter", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = target(database);
    const key = { bytes: randomBytes(32), version: "one" };
    const execution = { preview: async () => scanPreview(), enqueue: async () => randomUUID() } as any;
    const service = new ProviderAdapterService(database, execution, new CredentialVault(database, key), key);
    const configuration = (await loadAdvancedEngineCatalog("https://app.example.test")).find((item) => item.id === "api-graphql-authorization")!.template;
    const input = adapterInput(targetId, configuration);
    const preview = await service.preview(input);
    expect(preview).toMatchObject({ blockers: [], engine: { id: "api-graphql-authorization", capability: "API_GRAPHQL_AUTHORIZATION" } });

    const created = await service.create(input, "owner") as any;
    const stored = database.db.prepare("SELECT ciphertext FROM provider_adapter_versions WHERE id=?").get(created.pendingVersionId) as { ciphertext: string };
    expect(Buffer.from(stored.ciphertext, "base64url").toString("utf8")).not.toContain("/api/graphql");
    const reviewed = await service.review(created.id, created.pendingVersionId, preview.adapterDigest, "owner") as any;
    expect(reviewed).toMatchObject({ activeVersionId: created.pendingVersionId, pendingVersionId: null, enabled: true });

    const materialized = service.materialize(created.id);
    expect(materialized).toMatchObject({ target: { id: targetId }, input: { engineId: "api-graphql-authorization" }, binding: { adapterDigest: preview.adapterDigest } });
    const request = requestFor(materialized.target.baseOrigin, targetId, configuration, materialized.binding);
    await expect(service.assertExecutionBinding(request)).resolves.toBeUndefined();
    await expect(service.assertExecutionBinding({ ...request, apiGraphql: { ...(configuration as any), maxCases: 1 } } as any)).rejects.toThrow("CONFIGURATION_MISMATCH");

    database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(targetId);
    await expect(service.assertExecutionBinding(request)).rejects.toThrow("EXECUTION_STALE");
    database.close();
  });

  it("binds approved adaptive recommendations and blocks disable while a bound scan is active", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate(); const targetId = target(database);
    const key = { bytes: randomBytes(32), version: "one" }; const service = new ProviderAdapterService(database, { preview: async () => scanPreview() } as any, new CredentialVault(database, key), key);
    const configuration = (await loadAdvancedEngineCatalog("https://app.example.test")).find((item) => item.id === "api-graphql-authorization")!.template;
    const preview = await service.preview(adapterInput(targetId, configuration)); const created = await service.create(adapterInput(targetId, configuration), "owner") as any; await service.review(created.id, created.pendingVersionId, preview.adapterDigest, "owner");

    const evidenceScan = randomUUID(); new ScanRepository(database).create({ id: evidenceScan, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.example.test", safeTargetLabel: "fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
    const snapshotId = randomUUID(); database.db.prepare("INSERT INTO adaptive_security_snapshots (id,target_id,source_scan_id,status,model_digest,target_row_version,inventory_json,build_fingerprint,created_at) VALUES (?,?,?,'CANDIDATE',?,1,'{}',?,?)").run(snapshotId,targetId,evidenceScan,"a".repeat(64),"b".repeat(64),new Date().toISOString());
    const recommendationId = randomUUID(); database.db.prepare(`INSERT INTO adaptive_security_recommendations (id,target_id,snapshot_id,category,engine_id,lane_kind,source_fingerprint,status,mutation_hypothesis,operator_approval_required,safe_draft_json,required_bindings_json,reviewed_at,created_at,updated_at) VALUES (?,?,?,'API_AUTHORIZATION_MATRIX','api-graphql-authorization','API_GRAPHQL_AUTHORIZATION',?,'APPROVED',0,1,'{}','[]',?,?,?)`).run(recommendationId,targetId,snapshotId,"c".repeat(64),new Date().toISOString(),new Date().toISOString(),new Date().toISOString());
    service.bindRecommendation(created.id,recommendationId,"owner");
    expect(service.impact(created.id)).toMatchObject({ recommendationBindings: 1 });

    const activeScan = randomUUID(); new ScanRepository(database).create({ id: activeScan, source: "DASHBOARD", status: "RUNNING", targetOrigin: "https://app.example.test", safeTargetLabel: "fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
    service.bindScan(activeScan, service.materialize(created.id).binding);
    const impact = service.impact(created.id) as any; expect(impact).toMatchObject({ activeScans: 1, canDisable: false });
    expect(() => service.setEnabled(created.id,false,impact.impactDigest)).toThrow("ACTIVE_SCAN_DEPENDENCY");
    database.close();
  });

  it("rejects provider and engine mismatches before persistence", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate(); const targetId = target(database); const key = { bytes: randomBytes(32), version: "one" };
    const service = new ProviderAdapterService(database, { preview: async () => scanPreview() } as any, new CredentialVault(database,key),key);
    const configuration = (await loadAdvancedEngineCatalog("https://app.example.test")).find((item) => item.id === "api-graphql-authorization")!.template;
    await expect(service.preview({ ...adapterInput(targetId,configuration), provider: "STRIPE_TEST" })).rejects.toThrow("Payment-provider adapters may only configure");
    await expect(service.create({ ...adapterInput(targetId,configuration), provider: "STRIPE_TEST" },"owner")).rejects.toThrow("Payment-provider adapters may only configure");
    await expect(service.preview({ ...adapterInput(targetId,configuration), fixture: { ...(adapterInput(targetId,configuration) as any).fixture, allowedPathPrefixes: ["/api/../admin"] } })).rejects.toThrow("canonical URL paths");
    const billing = (await loadAdvancedEngineCatalog("https://app.example.test")).find((item) => item.id === "billing-entitlement-security")!.template;
    const billingPreview = await service.preview({ ...adapterInput(targetId,billing), provider: "ADYEN_TEST", engineId: "billing-entitlement-security", capabilities: ["SYNTHETIC_BILLING"], fixture: { ...(adapterInput(targetId,billing) as any).fixture, allowedPathPrefixes: ["/fixtures/"], cleanupRequired: true, cleanupEvidenceRequired: true }, limits: { ...(adapterInput(targetId,billing) as any).limits, cleanupReservedRequests: 10 } });
    expect(billingPreview.blockers).toEqual(expect.arrayContaining([expect.stringContaining("does not match billing configuration provider")]));
    database.close();
  });

  it("rotates every encrypted immutable version with the dashboard master key", async () => {
    const database = new DashboardDatabase(":memory:"); database.migrate(); const targetId = target(database);
    const current = { bytes: randomBytes(32), version: "one" }; const next = { bytes: randomBytes(32), version: "two" };
    const execution = { preview: async () => scanPreview() } as any; const service = new ProviderAdapterService(database,execution,new CredentialVault(database,current),current);
    const configuration = (await loadAdvancedEngineCatalog("https://app.example.test")).find((item) => item.id === "api-graphql-authorization")!.template;
    await service.create(adapterInput(targetId,configuration),"owner");
    expect(rotateProviderAdapterKey(database,current,next)).toBe(1);
    expect((database.db.prepare("SELECT key_version FROM provider_adapter_versions").get() as { key_version: string }).key_version).toBe("two");
    expect((new ProviderAdapterService(database,execution,new CredentialVault(database,next),next).list()[0] as any).name).toBe("Reusable API fixture");
    database.close();
  });
});

function target(database: DashboardDatabase): string { return new TargetRepository(database).create({ displayName: "Owned production", baseOrigin: "https://app.example.test", tags: [], classification: "PRODUCTION", authorizationType: "OWNED", authorizationSummary: "Owned disposable production fixture", productionEnabled: true, approvedScope: { program: "Owned fixture", allowedDomains: ["app.example.test"], disallowedPaths: ["/delete"], allowedMethods: ["GET","HEAD","OPTIONS","POST"], rateLimitPerSecond: 3, concurrency: 3, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" } }); }
function adapterInput(targetId: string, configuration: unknown) { return { schemaVersion: 1, name: "Reusable API fixture", description: "Exact Account A/B API fixture", targetId, environment: "PRODUCTION", provider: "GENERIC_HTTP", engineId: "api-graphql-authorization", capabilities: ["API_GRAPHQL_AUTHORIZATION"], authentication: { mode: "public" }, engineConfiguration: configuration, fixture: { disposableOnly: true, realPaymentExecution: "FORBIDDEN", allowedPathPrefixes: ["/"], cleanupRequired: false, cleanupEvidenceRequired: false, operatorNotes: "Read-only fixture" }, limits: { maxRequests: 100, cleanupReservedRequests: 0, rateLimitPerSecond: 2, concurrency: 2, evidenceLevel: "strong" } }; }
function scanPreview(): PlanPreviewResponse { return { previewIdentity: "d".repeat(64), profile: "full", modules: [{ id: "api-graphql-authorization", phase: "controlled", settings: {} }], limits: { maxRequests: 100 }, evidence: {}, skippedModules: [], controlledWorkflowRequests: [{ workflowId: "api-graphql-authorization", exactRequests: 4 }], planSnapshot: {}, credentialReadiness: { ready: true, checkedAt: new Date().toISOString(), requiredValidThrough: new Date().toISOString(), blockers: [], warnings: [], profiles: [] }, warnings: [] }; }
function requestFor(origin: string, targetId: string, configuration: unknown, binding: { profileId: string; versionId: string; adapterDigest: string }): DashboardScanCreateRequest { return { target: origin, targetId, profile: "full", rateLimitPerSecond: 2, concurrency: 2, maxRequests: 100, cleanupReservedRequests: 0, includeModules: ["api-graphql-authorization"], apiGraphql: configuration as any, providerAdapterBinding: binding, studio: { version: 1, scanName: "adapter", authorization: { category: "OWNED", confirmed: true }, scope: { program: "Owned fixture", allowedDomains: ["app.example.test"], disallowedPaths: ["/delete"], allowedMethods: ["GET","HEAD","OPTIONS","POST"], rateLimitPerSecond: 3, concurrency: 3, maxDepth: 2, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" }, authentication: { mode: "public" }, evidenceLevel: "strong", outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: [] } }; }
