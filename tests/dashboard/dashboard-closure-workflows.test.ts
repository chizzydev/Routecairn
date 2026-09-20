import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ArtifactRepository, FindingRepository, ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { FindingFingerprintService } from "../../src/dashboard/findings/FindingFingerprintService.js";
import { FindingNormalizer } from "../../src/dashboard/findings/FindingNormalizer.js";
import { ProofPackService } from "../../src/dashboard/proofPacks/ProofPackService.js";
import { startDashboardServer } from "../../src/dashboard/server/DashboardServer.js";
import { resolveDashboardPaths } from "../../src/dashboard/services/DashboardPaths.js";
import { LocalSessionManager } from "../../src/dashboard/auth/LocalSession.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { advancedEngineIds } from "../../src/dashboard/contracts/AdvancedEngineSchemas.js";

describe("dashboard closure workflows", () => {
  it("serves overview, scan detail, finding detail, and proof-pack listing from real persisted data", async () => {
    const dir = tempDir("routecairn-dashboard-closure-api-");
    try {
      const paths = resolveDashboardPaths(dir);
      const database = new DashboardDatabase(paths.databasePath);
      database.migrate();
      mkdirSync(paths.reportsDir, { recursive: true });
      const scanId = "11111111-1111-4111-8111-111111111111";
      seedScan(database, scanId, "COMPLETED");
      new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath)).normalizeReport(scanId, fixtureReport("High", "Medium", "role:user"));
      const finding = database.db.prepare("SELECT id FROM findings").get() as { id: string };
      new FindingRepository(database).review({ findingId: finding.id, newStatus: "CONFIRMED" });
      const proofPackId = new ProofPackService(database, paths).generate("Closure <script>alert(1)</script>", undefined, [finding.id]);
      database.close();

      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const overview = await apiGet<any>(handle.url, "/api/overview", auth.cookie);
        expect(overview.scans.completed).toBe(1);
        expect(overview.findings.confirmed).toBe(1);
        const detail = await apiGet<any>(handle.url, `/api/scans/${scanId}/detail`, auth.cookie);
        expect(detail.modules).toHaveLength(1);
        expect(detail.findings).toHaveLength(1);
        const findingDetail = await apiGet<any>(handle.url, `/api/findings/${finding.id}`, auth.cookie);
        expect(findingDetail.occurrences).toHaveLength(1);
        expect(findingDetail.reviews).toHaveLength(1);
        const packs = await apiGet<any>(handle.url, "/api/proof-packs", auth.cookie);
        expect(packs.proofPacks[0].id).toBe(proofPackId);
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("exposes planner capabilities, saved configuration CRUD, and SSE event replay", async () => {
    const dir = tempDir("routecairn-dashboard-product-api-");
    try {
      const database = new DashboardDatabase(resolveDashboardPaths(dir).databasePath);
      database.migrate();
      const scanId = "22222222-2222-4222-8222-222222222222";
      seedScan(database, scanId, "COMPLETED");
      database.appendEvent(scanId, "SCAN_COMPLETED", "Completed safely.", {});
      database.close();
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const capabilities = await apiGet<any>(handle.url, "/api/capabilities", auth.cookie);
        expect(capabilities.modules.some((module: any) => module.id === "object-pair-testing")).toBe(true);
        expect(capabilities.advancedEngineDashboard).toHaveLength(advancedEngineIds.length + 3);
        expect(capabilities.advancedEngineDashboard.filter((engine: any) => !["live-target-acceptance", "fixture-provider-adapters", "continuous-assurance"].includes(engine.id)).every((engine: any) => engine.dashboardOperation === "GUIDED_BUILDER")).toBe(true);
        expect(capabilities.advancedEngineDashboard.find((engine: any) => engine.id === "live-target-acceptance")?.dashboardOperation).toBe("MANAGED_WORKSPACE");
        expect(capabilities.advancedEngineDashboard.find((engine: any) => engine.id === "fixture-provider-adapters")?.dashboardOperation).toBe("MANAGED_WORKSPACE");
        expect(capabilities.advancedEngineDashboard.find((engine: any) => engine.id === "continuous-assurance")?.dashboardOperation).toBe("MANAGED_WORKSPACE");
        const advanced = await apiGet<any>(handle.url, "/api/advanced-engines/catalog?target=https%3A%2F%2Fapp.example.test", auth.cookie);
        expect(advanced.engines).toHaveLength(advancedEngineIds.length);
        expect(advanced.engines.find((engine: any) => engine.id === "supabase-authorization")?.template.projectUrl).toBe("https://app.example.test");
        const invalidCatalogTarget = await fetch(`${handle.url}/api/advanced-engines/catalog?target=not-a-url`, { headers: { cookie: auth.cookie } });
        expect(invalidCatalogTarget.status).toBe(400);
        const invalidAdvanced = await apiMutation<any>(handle.url, "/api/advanced-engines/validate", auth, { engineId: "supabase-authorization", value: { schemaVersion: 1 } });
        expect(invalidAdvanced.valid).toBe(false);
        expect(invalidAdvanced.diagnostics.some((diagnostic: any) => diagnostic.path.join(".") === "projectUrl")).toBe(true);
        const created = await apiMutation<any>(handle.url, "/api/configurations", auth, {
          name: "Quick smoke",
          profile: "quick",
          modules: ["baseline"],
          limits: {},
          scopeSettings: {},
          browserPolicySettings: {},
          evidenceLevel: "minimal",
          workflowRefs: {}
        });
        expect(created.configurationId).toMatch(/[0-9a-f-]{36}/);
        const configs = await apiGet<any>(handle.url, "/api/configurations", auth.cookie);
        expect(configs.configurations.some((config: any) => config.name === "Quick smoke")).toBe(true);
        const stream = await fetch(`${handle.url}/api/scans/${scanId}/stream`, { headers: { cookie: auth.cookie } });
        expect(stream.status).toBe(200);
        const text = await stream.text();
        expect(text).toContain("event: SCAN_COMPLETED");
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("operates encrypted live acceptance preview, review, execution, and coverage through the dashboard API", async () => {
    const dir = tempDir("routecairn-live-acceptance-api-");
    try {
      const database = new DashboardDatabase(resolveDashboardPaths(dir).databasePath); database.migrate();
      const targetId = new TargetRepository(database).create({ displayName: "Acceptance API fixture", baseOrigin: "https://acceptance.example.test", tags: [], classification: "PRODUCTION", authorizationType: "OWNED", authorizationSummary: "Owned disposable external acceptance fixture", productionEnabled: true, approvedScope: { program: "Acceptance", allowedDomains: ["acceptance.example.test"], disallowedPaths: ["/delete"], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 2, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" } });
      database.close();
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist"), masterKey: "11".repeat(32), masterKeyVersion: "acceptance-test" });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl); const now = Date.now();
        const input = { schemaVersion: 1, name: "API live acceptance", targetId, environment: "PRODUCTION", authorization: { mode: "OWNED_PRODUCTION", proofReference: "OWNER-TEST-APPROVAL", proofSha256: "a".repeat(64), authorizedBy: "owner", startsAt: new Date(now - 60_000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(), neverTestPaths: ["/billing"], authenticationPermitted: false, mutationPermitted: false, disposableAccountsOnly: true, realPaymentsAllowed: false, destructiveAdministrationAllowed: false }, lanes: [{ id: "tenant", label: "Tenant isolation", kind: "DATA_AUTHORIZATION", required: true, execution: { disposition: "NOT_APPLICABLE", reason: "The fixture has no tenant or organization data model." } }, { id: "billing", label: "Synthetic billing", kind: "BILLING_ENTITLEMENTS", required: false, execution: { disposition: "NOT_ASSESSED", reason: "No synthetic payment provider is configured for this fixture." } }] };
        const preview = await apiMutation<any>(handle.url, "/api/live-acceptance/preview", auth, input);
        expect(preview.preview).toMatchObject({ blockers: [], totalRequestBudget: 0 });
        const created = await apiMutation<any>(handle.url, "/api/live-acceptance/plans", auth, input);
        const reviewed = await apiMutation<any>(handle.url, `/api/live-acceptance/plans/${created.plan.id}/review`, auth, { planDigest: created.preview.planDigest, confirmation: "I_CONFIRM_REVIEWED_LIVE_ACCEPTANCE_PLAN" });
        expect(reviewed.plan.status).toBe("REVIEWED");
        const executed = await apiMutation<any>(handle.url, `/api/live-acceptance/plans/${created.plan.id}/execute`, auth, { planDigest: created.preview.planDigest, confirmation: "I_CONFIRM_EXECUTE_REVIEWED_LIVE_ACCEPTANCE_PLAN" });
        expect(executed.run).toMatchObject({ status: "COMPLETED", coverage: { notApplicable: 1, notAssessed: 1, requiredGaps: 0 } });
        const listed = await apiGet<any>(handle.url, "/api/live-acceptance/plans", auth.cookie);
        expect(listed.plans[0]).toMatchObject({ id: created.plan.id, status: "REVIEWED" });
      } finally { await handle.close(); }
    } finally { cleanup(dir); }
  });

  it("operates encrypted versioned provider adapters through dashboard APIs", async () => {
    const dir = tempDir("routecairn-provider-adapter-api-");
    try {
      const database = new DashboardDatabase(resolveDashboardPaths(dir).databasePath); database.migrate();
      const targetId = new TargetRepository(database).create({ displayName: "Adapter API fixture", baseOrigin: "https://adapter.example.test", tags: [], classification: "PRODUCTION", authorizationType: "OWNED", authorizationSummary: "Owned disposable provider fixture", productionEnabled: true, approvedScope: { program: "Adapter", allowedDomains: ["adapter.example.test"], disallowedPaths: ["/delete"], allowedMethods: ["GET", "HEAD", "OPTIONS"], rateLimitPerSecond: 2, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" } });
      database.close();
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist"), masterKey: "22".repeat(32), masterKeyVersion: "adapter-test" });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const configuration = { schemaVersion: 1, maxRequests: 10, maxResponseBytes: 4096, maxJsonDepth: 8, maxGraphqlDocumentBytes: 4096, maxGraphqlAliases: 3, maxGraphqlBatchOperations: 2, actors: [{ id: "anonymous", safeAlias: "anonymous", authSlot: "anonymous", relationship: "PUBLIC" }], routes: [{ id: "health", safeAlias: "public-health", protocol: "REST", kind: "FUNCTION", url: "https://adapter.example.test/api/health", functionName: "health.read", documented: true, documentedMethods: ["GET"], documentedResponseFields: [] }], checks: [{ id: "health-read", matrixId: "health-access", label: "Public health behavior", kind: "FUNCTION_AUTHORIZATION", routeId: "health", actorId: "anonymous", requireVerifiedIdentity: false, request: { method: "GET", headers: {}, operatorConfirmedNonMutating: false }, response: { expectedDecision: "OBSERVE", allowedStatuses: [200], deniedStatuses: [401,403,404], fieldRules: [] } }] };
        const input = { schemaVersion: 1, name: "Reusable API review fixture", description: "Target-bound reusable public API inventory", targetId, environment: "PRODUCTION", provider: "GENERIC_HTTP", engineId: "api-graphql-authorization", capabilities: ["API_GRAPHQL_AUTHORIZATION"], authentication: { mode: "public" }, engineConfiguration: configuration, fixture: { disposableOnly: true, realPaymentExecution: "FORBIDDEN", allowedPathPrefixes: ["/api/"], cleanupRequired: false, cleanupEvidenceRequired: false, operatorNotes: "Read-only API fixture" }, limits: { maxRequests: 100, cleanupReservedRequests: 0, rateLimitPerSecond: 2, concurrency: 2, evidenceLevel: "strong" } };
        const previewed = await apiMutation<any>(handle.url,"/api/provider-adapters/preview",auth,input); expect(previewed.preview.blockers).toEqual([]);
        const created = await apiMutation<any>(handle.url,"/api/provider-adapters",auth,input); expect(created.adapter.pendingVersionId).toMatch(/[0-9a-f-]{36}/);
        const reviewed = await apiMutation<any>(handle.url,`/api/provider-adapters/${created.adapter.id}/review`,auth,{ versionId: created.adapter.pendingVersionId, adapterDigest: previewed.preview.adapterDigest, confirmation: "I_CONFIRM_REVIEWED_PROVIDER_ADAPTER" }); expect(reviewed.adapter.activeVersionId).toBe(created.adapter.pendingVersionId);
        const materialized = await apiMutation<any>(handle.url,`/api/provider-adapters/${created.adapter.id}/materialize`,auth,{}); expect(materialized.materialized).toMatchObject({ target: { id: targetId }, input: { engineId: "api-graphql-authorization" }, binding: { adapterDigest: previewed.preview.adapterDigest } });
        const scanRequest = { target: "https://adapter.example.test", targetId, profile: "full", authorizationDeclaration: "Reviewed reusable provider adapter", rateLimitPerSecond: 2, concurrency: 2, maxRequests: 100, cleanupReservedRequests: 0, includeModules: ["api-graphql-authorization"], providerAdapterBinding: materialized.materialized.binding, apiGraphql: configuration, studio: { version: 1, scanName: "Reusable API review fixture", authorization: { category: "OWNED", confirmed: true }, scope: { program: "Adapter", allowedDomains: ["adapter.example.test"], disallowedPaths: ["/delete"], allowedMethods: ["GET","HEAD","OPTIONS"], rateLimitPerSecond: 2, concurrency: 2, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" }, authentication: { mode: "public" }, evidenceLevel: "strong", outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: [] } };
        const exactPlan = await apiMutation<any>(handle.url,"/api/scans/plan-preview",auth,scanRequest); expect(exactPlan.previewIdentity).toMatch(/[a-f0-9]{64}/);
        const tampered = await rawMutation(handle.url,"/api/scans/plan-preview",auth,{ ...scanRequest, maxRequests: 101 }); expect(tampered.status).toBe(409); expect(await tampered.text()).toContain("PROVIDER_ADAPTER_EXECUTION_CONTRACT_MISMATCH");
        const listed = await apiGet<any>(handle.url,"/api/provider-adapters",auth.cookie); expect(listed.adapters[0]).toMatchObject({ id: created.adapter.id, enabled: true });
      } finally { await handle.close(); }
    } finally { cleanup(dir); }
  });

  it("operates adaptive model analysis, policy, and baseline binding through the dashboard API", async () => {
    const dir = tempDir("routecairn-adaptive-security-api-");
    try {
      const paths = resolveDashboardPaths(dir); mkdirSync(paths.reportsDir, { recursive: true });
      const database = new DashboardDatabase(paths.databasePath); database.migrate();
      const targetId = new TargetRepository(database).create({ displayName: "Adaptive API fixture", baseOrigin: "https://app.test", tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned disposable adaptive fixture", productionEnabled: false, approvedScope: { program: "Adaptive", allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" } });
      const scanId = "91919191-9191-4191-8191-919191919191";
      new ScanRepository(database).create({ id: scanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.test", safeTargetLabel: "adaptive", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
      const adaptiveReport = fixtureReport();
      adaptiveReport.scanPlan = {} as RouteCairnReport["scanPlan"];
      adaptiveReport.requestAudit = [{ requestedUrl: "https://app.test/api/catalog", finalUrl: "https://app.test/api/catalog", method: "GET", outcome: "sent", statusCode: 200, requestHeaders: {}, redirectChain: [], source: "http" }];
      adaptiveReport.responses = [{ requestedUrl: "https://app.test/api/catalog", finalUrl: "https://app.test/api/catalog", method: "GET", statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", bodyHash: "c".repeat(64), responseTimeMs: 4, redirectChain: [] }];
      adaptiveReport.apiMapper = { endpoints: [{ endpoint: "https://app.test/api/catalog", method: "GET", routeType: "api", riskTags: [], likelyManualTests: [], authRelevance: "low", hasObjectId: false, privilegeSensitivity: "low", dataExposureSensitivity: "low", rateLimitSensitivity: "low" }], graphQlEndpoints: [], notes: [] };
      const serializedAdaptiveReport = JSON.stringify(adaptiveReport);
      const reportPath = resolve(paths.reportsDir, "adaptive-report.json"); writeFileSync(reportPath, serializedAdaptiveReport, "utf8");
      const artifactId = new ArtifactRepository(database).create({ scanId, type: "JSON_REPORT", name: "adaptive-report.json", path: reportPath, size: Buffer.byteLength(serializedAdaptiveReport), contentType: "application/json", hash: "a".repeat(64) });
      new ScanRepository(database).attachArtifacts(scanId, { json: artifactId }); database.close();
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const analyzed = await apiMutation<any>(handle.url, "/api/adaptive-security/analyze", auth, { targetId, scanId });
        expect(analyzed.snapshot).toMatchObject({ sourceScanId: scanId, status: "CANDIDATE" });
        const policy = await apiMutation<any>(handle.url, "/api/adaptive-security/policy", auth, { targetId, requiredLanes: ["PUBLIC_BASELINE"], requireEvidenceForNotApplicable: true, detectRemovedSurfaces: true, confirmation: "I_CONFIRM_TARGET_SECURITY_MODEL_POLICY" }, "PUT");
        expect(policy.adaptiveSecurity.coverage).toMatchObject({ complete: false, gaps: 1 });
        const accepted = await apiMutation<any>(handle.url, `/api/adaptive-security/snapshots/${analyzed.snapshot.id}/accept`, auth, { modelDigest: analyzed.snapshot.modelDigest, confirmation: "I_CONFIRM_EXPECTED_SECURITY_MODEL_BASELINE" });
        expect(accepted.adaptiveSecurity.snapshots[0]).toMatchObject({ status: "BASELINE" });
        const state = await apiGet<any>(handle.url, `/api/adaptive-security/targets/${targetId}`, auth.cookie);
        expect(state.adaptiveSecurity.policy.requiredLanes).toEqual(["PUBLIC_BASELINE"]);
        const ready = state.adaptiveSecurity.recommendations.find((item: any) => item.category === "API_READ_ONLY_REGRESSION");
        expect(ready).toMatchObject({ operatorApprovalRequired: false, requiredBindings: [], draft: { executable: true, automation: { state: "READY_READ_ONLY" } } });
        const materialized = await apiMutation<any>(handle.url, `/api/adaptive-security/recommendations/${ready.id}/materialize`, auth, {});
        expect(materialized.materialized).toMatchObject({ targetId, engineId: "api-graphql-authorization", limits: { cleanupReservedRequests: 0, evidenceLevel: "strong" }, binding: { recommendationId: ready.id, sourceFingerprint: ready.sourceFingerprint, compilerVersion: 1 } });
      } finally { await handle.close(); }
    } finally { cleanup(dir); }
  });

  it("rejects expired bootstrap credentials, wrong origins, oversized bodies, and outside-root artifacts", async () => {
    const session = new LocalSessionManager(0);
    expect(() => session.exchange("bad", fakeResponse())).toThrow(/Invalid or expired/);

    const dir = tempDir("routecairn-dashboard-closure-security-");
    try {
      const paths = resolveDashboardPaths(dir);
      const database = new DashboardDatabase(paths.databasePath);
      database.migrate();
      const outside = resolve(dir, "outside.txt");
      writeFileSync(outside, "secret");
      const artifactId = new ArtifactRepository(database).create({ type: "TEXT", name: "outside.txt", path: outside, size: 6, contentType: "text/plain", hash: "hash" });
      database.close();
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const wrongOrigin = await fetch(`${handle.url}/api/scans`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-csrf-token": auth.csrf, cookie: auth.cookie, origin: "http://evil.test" },
          body: "{}"
        });
        expect(wrongOrigin.status).toBe(401);
        const huge = await fetch(`${handle.url}/api/scans`, {
          method: "POST",
          headers: { "content-type": "application/json", "x-csrf-token": auth.csrf, cookie: auth.cookie, origin: handle.url },
          body: JSON.stringify({ padding: "x".repeat(1024 * 1024 + 1) })
        });
        expect(huge.status).toBe(413);
        const artifact = await fetch(`${handle.url}/api/artifacts/${artifactId}/download`, { headers: { cookie: auth.cookie } });
        expect(artifact.status).toBe(403);
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("keeps stable findings across severity and confidence changes while separating boundaries and targets", () => {
    const dir = tempDir("routecairn-dashboard-closure-fingerprints-");
    try {
      const paths = resolveDashboardPaths(dir);
      const database = new DashboardDatabase(paths.databasePath);
      database.migrate();
      const normalizer = new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath));
      for (const scanId of ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"]) {
        seedScan(database, scanId, "COMPLETED");
      }
      normalizer.normalizeReport("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", fixtureReport("High", "Medium", "role:user"));
      normalizer.normalizeReport("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", fixtureReport("Critical", "High", "role:user"));
      normalizer.normalizeReport("cccccccc-cccc-4ccc-8ccc-cccccccccccc", fixtureReport("High", "Medium", "role:admin"));
      normalizer.normalizeReport("dddddddd-dddd-4ddd-8ddd-dddddddddddd", fixtureReport("High", "Medium", "role:user", "https://other.test"));
      expect(database.db.prepare("SELECT COUNT(*) AS count FROM findings").get()).toEqual({ count: 3 });
      const same = database.db.prepare("SELECT occurrence_count, current_scanner_severity, current_scanner_confidence FROM findings WHERE target_identity = 'https://app.test' AND safe_authorization_boundary_identity LIKE '%role:user%'").get();
      expect(same).toEqual({ occurrence_count: 2, current_scanner_severity: "Critical", current_scanner_confidence: "High" });
      database.close();
    } finally {
      cleanup(dir);
    }
  });

  it("blocks proof-pack generation for missing evidence and escapes target-controlled HTML when generated", () => {
    const dir = tempDir("routecairn-dashboard-closure-proof-");
    try {
      const paths = resolveDashboardPaths(dir);
      const database = new DashboardDatabase(paths.databasePath);
      database.migrate();
      seedScan(database, "11111111-1111-4111-8111-111111111111", "COMPLETED");
      const normalizer = new FindingNormalizer(database.db, new FindingFingerprintService(paths.fingerprintKeyPath));
      normalizer.normalizeReport("11111111-1111-4111-8111-111111111111", fixtureReport("High", "Medium", "role:user", "https://app.test", "<img src=x onerror=alert(1)>"));
      const finding = database.db.prepare("SELECT id FROM findings").get() as { id: string };
      const reviews = new FindingRepository(database);
      reviews.review({ findingId: finding.id, newStatus: "CONFIRMED" });
      database.db.prepare("DELETE FROM evidence_records").run();
      const service = new ProofPackService(database, paths);
      expect(() => service.generate("No evidence", undefined, [finding.id])).toThrow(/no retained eligible evidence/);
      expect(database.db.prepare("SELECT COUNT(*) AS count FROM proof_packs").get()).toEqual({ count: 0 });
      seedScan(database, "22222222-2222-4222-8222-222222222222", "COMPLETED");
      normalizer.normalizeReport("22222222-2222-4222-8222-222222222222", fixtureReport("High", "Medium", "role:user", "https://app.test", "<img src=x onerror=alert(1)>"));
      const fingerprint = `hmac-sha256:${"c".repeat(64)}`;
      const rawDecoy = "proof-pack-decoy-secret-must-not-persist";
      database.db.prepare("UPDATE evidence_records SET safe_structured_data_json = ?").run(JSON.stringify({
        valueAttestations: [{
          schemaVersion: 1,
          location: "query",
          name: "access_token",
          classification: "opaque-auth-value",
          valueLength: 24,
          fingerprintAlgorithm: "HMAC-SHA-256",
          fingerprintScope: "scan",
          correlationFingerprint: fingerprint,
          observedAt: "2026-08-19T08:00:00.000Z",
          requestId: "33333333-3333-4333-8333-333333333333",
          statusCode: 200,
          responseHash: "d".repeat(64),
          transportOutcome: "transmitted",
          reproductionSteps: ["Repeat the authorized request using fresh authentication material."],
          rawValue: rawDecoy
        }]
      }));
      const proofPackId = service.generate("Safe proof", undefined, [finding.id]);
      const artifactIds = JSON.parse((database.db.prepare("SELECT output_artifact_ids_json FROM proof_packs WHERE id = ?").get(proofPackId) as { output_artifact_ids_json: string }).output_artifact_ids_json) as string[];
      const htmlPath = (database.db.prepare("SELECT canonical_path FROM artifacts WHERE id = ?").get(artifactIds[1]) as { canonical_path: string }).canonical_path;
      const html = readFileSync(htmlPath, "utf8");
      expect(html).not.toContain("<script");
      expect(html).not.toContain("onerror=");
      expect(html).toContain("&lt;img");
      const artifacts = artifactIds.map((id) => database.db.prepare("SELECT canonical_path FROM artifacts WHERE id = ?").get(id) as { canonical_path: string });
      const serializedPack = artifacts.map((artifact) => readFileSync(artifact.canonical_path, "utf8")).join("\n");
      expect(serializedPack).toContain(fingerprint);
      expect(serializedPack).toContain("Sensitive value presence attestations");
      expect(serializedPack).not.toContain(rawDecoy);
      database.close();
    } finally {
      cleanup(dir);
    }
  });

  it("imports reports idempotently from approved roots and rejects traversal outside them", async () => {
    const dir = tempDir("routecairn-dashboard-closure-import-");
    try {
      const paths = resolveDashboardPaths(dir);
      mkdirSync(paths.reportsDir, { recursive: true });
      const reportPath = resolve(paths.reportsDir, "report.json");
      writeFileSync(reportPath, JSON.stringify(fixtureReport()), "utf8");
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const first = await apiMutation<any>(handle.url, "/api/import/report", auth, { reportPath });
        const second = await apiMutation<any>(handle.url, "/api/import/report", auth, { reportPath });
        expect(second.scanId).toBe(first.scanId);
        const outside = resolve(dir, "outside-report.json");
        writeFileSync(outside, JSON.stringify(fixtureReport()), "utf8");
        const rejected = await rawMutation(handle.url, "/api/import/report", auth, { reportPath: outside });
        expect(rejected.status).toBe(500);
      } finally {
        await handle.close();
      }
    } finally {
      cleanup(dir);
    }
  });

  it("runs one controlled dashboard scan end to end and preserves CLI-compatible report output", async () => {
    const dir = tempDir("routecairn-dashboard-closure-e2e-");
    const fixture = await startFixtureServer();
    try {
      const scopePath = resolve(dir, "scope.json");
      writeFileSync(scopePath, JSON.stringify({
        program: "dashboard fixture",
        allowedDomains: ["127.0.0.1"],
        disallowedPaths: ["/logout", "/delete"],
        allowedMethods: ["GET", "HEAD", "OPTIONS"],
        rateLimitPerSecond: 50,
        concurrency: 2,
        maxDepth: 1,
        sameOriginOnly: true,
        includeSubdomains: false,
        respectRobotsTxt: false,
        userAgent: "RouteCairn-Test/1.0"
      }), "utf8");
      const handle = await startDashboardServer({ dataDir: dir, uiDistDir: resolve("apps", "dashboard-ui", "dist") });
      try {
        const auth = await authenticate(handle.url, handle.bootstrapUrl);
        const preview = await apiMutation<any>(handle.url, "/api/scans/plan-preview", auth, { target: fixture.url, profile: "quick", scopeFile: scopePath });
        expect(preview.modules.length).toBeGreaterThan(0);
        const queued = await apiMutation<any>(handle.url, "/api/scans", auth, { target: fixture.url, profile: "quick", scopeFile: scopePath });
        const scan = await waitForScan(handle.url, auth.cookie, queued.scanId);
        expect(scan.status).toBe("COMPLETED");
        const detail = await apiGet<any>(handle.url, `/api/scans/${queued.scanId}/detail`, auth.cookie);
        expect(detail.artifacts.some((artifact: any) => artifact.artifact_type === "JSON_REPORT")).toBe(true);
      } finally {
        await handle.close();
      }
    } finally {
      await fixture.close();
      cleanup(dir);
    }
  }, 45000);
});

function tempDir(prefix: string): string {
  return mkdtempSync(resolve(tmpdir(), prefix));
}

function cleanup(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  } catch {
    // Windows can keep SQLite/WAL handles alive briefly after close; temp cleanup is best effort.
  }
}

function seedScan(database: DashboardDatabase, scanId: string, status: "COMPLETED" | "RUNNING" | "QUEUED"): void {
  const scans = new ScanRepository(database);
  scans.create({ id: scanId, source: "DASHBOARD", status, targetOrigin: "https://app.test", safeTargetLabel: "https://app.test", profile: "quick", evidenceLevel: "minimal", safeConfigurationSummary: { target: "https://app.test", scopeFile: "scope.json", profile: "quick" } });
  database.db.prepare("INSERT INTO scan_module_executions (id, scan_id, module_id, module_label, planned_order, status) VALUES (?, ?, 'baseline', 'baseline', 1, 'COMPLETED')").run(`${scanId}-module`, scanId);
}

function fixtureReport(severity = "High", confidence = "Medium", boundary = "role:user", target = "https://app.test", title = "Missing authorization check"): RouteCairnReport {
  return {
    routeCairnVersion: "0.1.0",
    target,
    mode: "quick",
    program: "fixture",
    scope: { allowedDomains: [new URL(target).hostname], disallowedPaths: [], allowedMethods: ["GET"], rateLimitPerSecond: 1, concurrency: 1, sameOriginOnly: true, includeSubdomains: false },
    metadata: { startedAt: new Date(0).toISOString(), completedAt: new Date(1).toISOString(), durationMs: 1, totalRequests: 1, failedRequests: 0 },
    scopeDecisions: [],
    requestAudit: [],
    responses: [],
    technologies: [],
    discoveredUrls: [],
    findings: [{
      id: "f1",
      title,
      type: "Authorization",
      severity,
      confidence,
      url: `${target}/api/orders/123?sig=secret`,
      method: "GET",
      evidence: { url: `${target}/api/orders/123?sig=<redacted>`, method: "GET", source: "fixture", title: "Observed", bodyHash: "abc", reproductionNotes: "Repeat the safe GET request." },
      sourceModule: "authorization-matrix-testing",
      tags: ["authorization", boundary]
    }]
  };
}

async function authenticate(baseUrl: string, bootstrapUrl: string): Promise<{ cookie: string; csrf: string }> {
  const token = new URL(bootstrapUrl).hash.replace("#bootstrap=", "");
  const response = await fetch(`${baseUrl}/api/session/bootstrap`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ token }) });
  const cookie = response.headers.get("set-cookie")?.split(";")[0] ?? "";
  const body = await response.json() as { csrfToken: string };
  return { cookie, csrf: body.csrfToken };
}

async function apiGet<T>(baseUrl: string, path: string, cookie: string): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`, { headers: { cookie } });
  if (!response.ok) throw new Error(await response.text());
  return await response.json() as T;
}

async function apiMutation<T>(baseUrl: string, path: string, auth: { cookie: string; csrf: string }, body: unknown, method = "POST"): Promise<T> {
  const response = await rawMutation(baseUrl, path, auth, body, method);
  if (!response.ok) throw new Error(await response.text());
  return await response.json() as T;
}

async function rawMutation(baseUrl: string, path: string, auth: { cookie: string; csrf: string }, body: unknown, method = "POST"): Promise<Response> {
  return await fetch(`${baseUrl}${path}`, { method, headers: { "content-type": "application/json", "x-csrf-token": auth.csrf, cookie: auth.cookie, origin: baseUrl }, body: JSON.stringify(body) });
}

async function waitForScan(baseUrl: string, cookie: string, scanId: string): Promise<any> {
  for (let i = 0; i < 120; i += 1) {
    const body = await apiGet<{ scan: any }>(baseUrl, `/api/scans/${scanId}`, cookie);
    if (["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED"].includes(body.scan.status)) return body.scan;
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 250));
  }
  throw new Error("Timed out waiting for dashboard scan.");
}

async function startFixtureServer(): Promise<{ url: string; close(): Promise<void> }> {
  const server = createServer((request, response) => {
    response.setHeader("content-type", "text/html; charset=utf-8");
    response.end(`<html><head><title>Fixture</title></head><body><a href="/api/orders/123">order</a><script src="/app.js"></script></body></html>`);
  });
  await new Promise<void>((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture server did not start.");
  return { url: `http://127.0.0.1:${address.port}`, close: async () => new Promise((resolveClose) => server.close(() => resolveClose())) };
}

function fakeResponse(): any {
  return { setHeader: () => undefined };
}
