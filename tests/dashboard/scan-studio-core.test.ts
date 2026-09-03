import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

  it("validates and resolves ordinary Next.js Deep Review settings through Scan Studio", async () => {
    const input: any = publicStudioRequest("https://app.example.test");
    input.profile = "full";
    input.studio.moduleSettings = { nextJsReview: { inspectNextJsSourceMaps: true, inspectKnownNextJsDataSurfaces: true, nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW", maxNextJsManifestRequests: 5, maxNextJsDataSurfaceRequests: 9, maxNextJsSourceMapRequests: 3, maxNextJsCacheDifferentialRequests: 0, maxNextJsAssetsInspected: 40, maxNextJsRoutesProcessed: 250 } };
    const request = dashboardScanCreateSchema.parse(input);
    const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.find((module) => module.id === "nextjs-review")?.settings).toMatchObject({ maxNextJsManifestRequests: 5, maxNextJsDataSurfaceRequests: 9, maxNextJsSourceMapRequests: 3, nextJsCacheReviewMode: "PASSIVE_CACHE_REVIEW" });
  });

  it("plans the automated secret-boundary engine through Scan Studio", async () => {
    const input: any = publicStudioRequest("https://app.example.test");
    input.includeModules = ["baseline", "secret-boundary"];
    const request = dashboardScanCreateSchema.parse(input);
    const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["baseline", "secret-boundary"]);
    expect(resolved.plan.modules.find((module) => module.id === "secret-boundary")?.settings).toMatchObject({ maxSecretBoundaryAdditionalRequests: 12, maxSecretBoundarySourceMaps: 4, inspectSecretBoundarySourceMaps: true });
  });

  it("loads an explicit authentication lifecycle manifest through Scan Studio and adds the dedicated module", async () => {
    const dir = temporary("routecairn-studio-lifecycle-");
    const manifestPath = resolve(dir, "lifecycle.json");
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, cases: [{ id: "idle-observe", label: "Idle expiry observation", category: "IDLE_EXPIRATION", actors: [{ id: "public", safeAlias: "public-actor", authSlot: "anonymous", relationship: "PUBLIC", declaredState: "ANONYMOUS" }], authorization: { mode: "OBSERVE_ONLY", environment: "TEST" }, steps: [{ id: "verify", phase: "VERIFY", actorId: "public", request: { method: "GET", url: "https://app.example.test/session", stateChanging: false }, assertions: [{ kind: "STATUS_IN", values: [200, 401] }] }] }] }));
    const request = dashboardScanCreateSchema.parse({ ...publicStudioRequest("https://app.example.test"), authenticationLifecycleFile: manifestPath });
    const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["authentication-lifecycle"]);
    expect(resolved.plan.authenticationLifecycle?.cases[0]?.category).toBe("IDLE_EXPIRATION");
    expect(JSON.stringify(safeConfigurationSummary(request))).not.toContain(manifestPath);
  });

  it("loads an explicit business-invariant manifest through Scan Studio without exposing its path or authority", async () => {
    const dir = temporary("routecairn-studio-invariant-");
    const manifestPath = resolve(dir, "invariant.json");
    const auth = { mode: "CONTROLLED_INVARIANT", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING", authorizedBy: "operator-dashboard", changeTicket: "BIZ-DASH", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableEntities: true };
    const actor = [{ id: "public", safeAlias: "disposable-public", authSlot: "anonymous", relationship: "PUBLIC", declaredState: "TEST" }];
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, cases: [{ id: "once", label: "One effect", category: "ONE_TIME_ACTION", actors: actor, authorization: auth, preState: [{ id: "before", actorId: "public", request: { method: "GET", url: "https://app.example.test/state", stateChanging: false }, captures: [{ name: "before_count", source: "JSON", path: "count" }] }], actions: [{ id: "act", actorId: "public", request: { method: "POST", url: "https://app.example.test/action", stateChanging: true }, expectation: { authorization: "ALLOW", businessRule: "NOT_EVALUATED" } }], postState: [{ id: "after", actorId: "public", request: { method: "GET", url: "https://app.example.test/state", stateChanging: false }, captures: [{ name: "after_count", source: "JSON", path: "count" }] }], invariants: [{ id: "delta", kind: "NUMERIC_DELTA", before: "before_count", after: "after_count", operator: "LTE", expected: 1 }], cleanupRequired: true, cleanup: [{ id: "reset", actorId: "public", request: { method: "DELETE", url: "https://app.example.test/action", stateChanging: true }, successStatusCodes: [204] }], cleanupVerification: [{ id: "restored", actorId: "public", request: { method: "GET", url: "https://app.example.test/state", stateChanging: false }, captures: [{ name: "restored_count", source: "JSON", path: "count" }] }], cleanupInvariants: [{ id: "reset", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "restored_count" }, operator: "EQ", right: { source: "CAPTURE", ref: "before_count" } }] }] }));
    const raw: any = publicStudioRequest("https://app.example.test"); raw.studio.scope.allowedMethods = ["GET", "HEAD", "OPTIONS", "POST", "DELETE"]; raw.businessInvariantFile = manifestPath;
    const request = dashboardScanCreateSchema.parse(raw); const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["business-invariant"]);
    expect(resolved.plan.businessInvariant?.cases[0]?.category).toBe("ONE_TIME_ACTION");
    const safe = JSON.stringify(safeConfigurationSummary(request)); expect(safe).not.toContain(manifestPath); expect(safe).not.toContain("operator-dashboard"); expect(safe).not.toContain("BIZ-DASH");
  });

  it("loads a controlled-race manifest through Scan Studio and adds only the dedicated module", async () => {
    const dir = temporary("routecairn-studio-race-"); const manifestPath = resolve(dir, "race.json");
    const authorization = { mode: "CONTROLLED_RACE", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_RACE_TESTING", authorizedBy: "operator-race", changeTicket: "RACE-DASH", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableEntities: true };
    const actor = [{ id: "public", safeAlias: "disposable-public", authSlot: "anonymous", relationship: "PUBLIC", declaredState: "TEST" }]; const observe = (id: string, name: string) => ({ id, actorId: "public", request: { method: "GET", url: "https://app.example.test/state", stateChanging: false }, captures: [{ name, source: "JSON", path: "events" }] }); const member = (id: string) => ({ id, actorId: "public", request: { method: "POST", url: "https://app.example.test/action", stateChanging: true }, expectation: { authorization: "ALLOW", businessRule: "NOT_EVALUATED" } });
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, cases: [{ id: "race", label: "Race", category: "SAME_OBJECT", target: { type: "fixture", safeAlias: "fixture", identityFingerprint: "a".repeat(64), disposable: true }, actors: actor, authorization, preState: [observe("before", "events_before")], groups: [{ id: "barrier", label: "Barrier", requests: [member("a"), member("b")] }], postState: [observe("after", "events_after")], invariants: [{ id: "once", kind: "EVENT_COUNT_DELTA", before: "events_before", after: "events_after", operator: "LTE", expected: 1 }], cleanupRequired: true, cleanup: [{ id: "reset", actorId: "public", request: { method: "DELETE", url: "https://app.example.test/action", stateChanging: true }, successStatusCodes: [204] }], cleanupVerification: [observe("restored", "events_restored")], cleanupInvariants: [{ id: "restored", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "events_restored" }, operator: "EQ", right: { source: "CAPTURE", ref: "events_before" } }] }] }));
    const raw: any = publicStudioRequest("https://app.example.test"); raw.studio.scope.allowedMethods = ["GET", "HEAD", "OPTIONS", "POST", "DELETE"]; raw.controlledRaceFile = manifestPath;
    const request = dashboardScanCreateSchema.parse(raw); const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["controlled-race"]); expect(resolved.plan.controlledRace?.cases[0]?.groups[0]?.requests).toHaveLength(2); expect(JSON.stringify(safeConfigurationSummary(request))).not.toContain(manifestPath);
  });

  it("loads an API/GraphQL manifest through Scan Studio without exposing its path", async () => {
    const dir = temporary("routecairn-studio-api-graphql-"); const manifestPath = resolve(dir, "api-graphql.json");
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, actors: [{ id: "public", safeAlias: "public", authSlot: "anonymous", relationship: "PUBLIC" }], routes: [{ id: "graphql", safeAlias: "graphql", protocol: "GRAPHQL", kind: "FUNCTION", functionName: "graphql.query", url: "https://app.example.test/graphql", documentedMethods: ["POST"] }], checks: [{ id: "introspection", label: "Introspection policy", kind: "GRAPHQL_INTROSPECTION", routeId: "graphql", actorId: "public", requireVerifiedIdentity: false, expectedClassification: "RESTRICTED" }] }));
    const raw: any = publicStudioRequest("https://app.example.test"); raw.studio.scope.allowedMethods = ["GET", "HEAD", "OPTIONS", "POST"]; raw.apiGraphqlFile = manifestPath;
    const request = dashboardScanCreateSchema.parse(raw); const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["api-graphql-authorization"]); expect(resolved.plan.apiGraphql?.checks[0]?.kind).toBe("GRAPHQL_INTROSPECTION"); expect(JSON.stringify(safeConfigurationSummary(request))).not.toContain(manifestPath);
  });

  it("loads a signed-link security manifest through Scan Studio without exposing its path", async () => {
    const dir = temporary("routecairn-studio-link-portal-"); const manifestPath = resolve(dir, "link-portal.json");
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, actors: [{ id: "public", safeAlias: "public", authSlot: "anonymous", relationship: "PUBLIC" }], resources: [{ id: "expired", safeAlias: "expired-link", kind: "SIGNED_LINK", pathTemplate: "/signed/{object}", allowedOrigins: ["https://app.example.test"], declaredState: "EXPIRED" }], cases: [{ id: "expiry", label: "Expired link denied", category: "SIGNED_LINK_EXPIRY", authorization: { mode: "OBSERVE_ONLY", environment: "TEST" }, steps: [{ id: "verify", phase: "VERIFY", actorId: "public", resourceId: "expired", request: { method: "GET", urlTemplate: "https://app.example.test/signed/disposable-public-object", secretSource: "anonymous" }, assertions: [{ kind: "DECISION", expected: "DENY" }] }] }] }));
    const raw: any = publicStudioRequest("https://app.example.test"); raw.linkPortalSecurityFile = manifestPath;
    const request = dashboardScanCreateSchema.parse(raw); const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["link-portal-export-security"]); expect(resolved.plan.linkPortalSecurity?.cases[0]?.category).toBe("SIGNED_LINK_EXPIRY"); expect(JSON.stringify(safeConfigurationSummary(request))).not.toContain(manifestPath);
  });

  it("loads an operational endpoint manifest through Scan Studio without exposing its path", async () => {
    const dir = temporary("routecairn-studio-operational-"); const manifestPath = resolve(dir, "operational.json");
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, actors: [{ id: "public", safeAlias: "public", authSlot: "anonymous", relationship: "PUBLIC" }], endpoints: [{ id: "health", safeAlias: "health", kind: "HEALTH", pathTemplate: "/health", allowedOrigins: ["https://app.example.test"] }], cases: [{ id: "health", label: "minimal health response", category: "HEALTH_INFORMATION_EXPOSURE", authorization: { mode: "OBSERVE_ONLY", environment: "TEST" }, steps: [{ id: "verify", phase: "VERIFY", actorId: "public", endpointId: "health", request: { method: "GET", urlTemplate: "https://app.example.test/health", secretSource: "anonymous" }, assertions: [{ kind: "JSON_FIELD_ABSENT", path: "databaseUrl", classification: "SECRET" }] }] }] }));
    const raw: any = publicStudioRequest("https://app.example.test"); raw.operationalEndpointSecurityFile = manifestPath;
    const request = dashboardScanCreateSchema.parse(raw); const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["operational-endpoint-security"]); expect(resolved.plan.operationalEndpointSecurity?.cases[0]?.category).toBe("HEALTH_INFORMATION_EXPOSURE"); expect(JSON.stringify(safeConfigurationSummary(request))).not.toContain(manifestPath);
  });

  it("loads a synthetic billing manifest through Scan Studio without exposing its path", async () => {
    const dir = temporary("routecairn-studio-billing-"); const manifestPath = resolve(dir, "billing.json");
    writeFileSync(manifestPath, JSON.stringify({ schemaVersion: 1, provider: { kind: "CUSTOM_SYNTHETIC", mode: "TEST", fixturePathPrefix: "/__routecairn__/billing-fixtures", realPaymentExecution: "FORBIDDEN" }, actors: [{ id: "owner", safeAlias: "owner", authSlot: "account_a", relationship: "OWNER", principalId: "principal-a" }, { id: "foreign", safeAlias: "foreign", authSlot: "account_b", relationship: "CROSS_TENANT", principalId: "principal-b" }], endpoints: [{ id: "premium", safeAlias: "premium-access", kind: "PREMIUM_ACCESS", pathTemplate: "/premium", allowedOrigins: ["https://app.example.test"] }], cases: [{ id: "cross-account", label: "cross account premium", category: "CROSS_ACCOUNT_PREMIUM_ACCESS", authorization: { mode: "OBSERVE_ONLY", environment: "TEST" }, steps: [{ id: "owner", phase: "ACTION", actorId: "owner", endpointId: "premium", operation: "PREMIUM_ACCESS_PROBE", request: { method: "GET", urlTemplate: "https://app.example.test/premium", secretSource: "anonymous" }, expectation: { authorization: "ALLOW", businessRule: "NOT_EVALUATED" } }, { id: "foreign", phase: "ACTION", actorId: "foreign", endpointId: "premium", operation: "PREMIUM_ACCESS_PROBE", request: { method: "GET", urlTemplate: "https://app.example.test/premium", secretSource: "anonymous" }, expectation: { authorization: "DENY", businessRule: "NOT_EVALUATED" } }], assertions: [{ id: "foreign-denied", scope: "MAIN", kind: "ACTION_OUTCOME_COUNT", dimension: "ACCESS", stepId: "foreign", outcome: "DENIED", operator: "EQ", expected: 1 }] }] }));
    const raw: any = authenticatedStudioRequest("https://app.example.test", actor("A", "principal-a", "Authorization", "Bearer billing-a"), actor("B", "principal-b", "Authorization", "Bearer billing-b")); raw.billingEntitlementFile = manifestPath;
    const request = dashboardScanCreateSchema.parse(raw); const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toContain("billing-entitlement-security"); expect(resolved.plan.billingEntitlement?.provider.realPaymentExecution).toBe("FORBIDDEN"); expect(JSON.stringify(safeConfigurationSummary(request))).not.toContain(manifestPath);
  });

  it("plans browser-learned lifecycle automation through Scan Studio", async () => {
    const dir = temporary("routecairn-studio-lifecycle-auto-");
    const authPath = resolve(dir, "auth.json");
    const policyPath = resolve(dir, "automation.json");
    writeFileSync(authPath, JSON.stringify({ label: "member", headers: {}, browserBootstrap: { schemaVersion: 1, loginSecrets: { username: "member@example.test", password: "valid-password" }, login: { startUrl: "https://app.example.test/login", allowedWritePaths: ["/api/session"], successUrlPrefix: "https://app.example.test/app", steps: [{ action: "fill", selector: "#username", valueRef: "username" }, { action: "fill", selector: "#password", valueRef: "password" }, { action: "click", selector: "button[type=submit]" }, { action: "waitForUrl", urlPrefix: "https://app.example.test/app" }] } }, lifecycleSecrets: { unknown_username: "absent@example.test", invalid_password: "invalid-value", fixed_session: "fixed-value" } }));
    writeFileSync(policyPath, JSON.stringify({ authorization: { mode: "CONTROLLED_LIFECYCLE", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_AUTH_LIFECYCLE_TESTING", authorizedBy: "operator", changeTicket: "AUTH-AUTO", authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2099-01-01T00:00:00.000Z", disposableAccounts: true }, login: { unknownAccountSecretRef: "unknown_username", invalidPasswordSecretRef: "invalid_password", fixedSessionSecretRef: "fixed_session" }, cleanup: { method: "POST", url: "https://app.example.test/api/logout" } }));
    const request = dashboardScanCreateSchema.parse({ ...publicStudioRequest("https://app.example.test"), authFile: authPath, authenticationLifecycleAutoFile: policyPath });
    const resolved = await resolveDashboardScanPlan(request);
    expect(resolved.plan.modules.map((module) => module.id)).toEqual(["baseline", "browser-crawler", "authentication-lifecycle"]);
    expect(resolved.plan.authenticationLifecycle).toMatchObject({ source: "BROWSER_LEARNED", cases: [] });
    const safe = JSON.stringify(safeConfigurationSummary(request));
    expect(safe).not.toContain(policyPath);
    expect(safe).not.toContain(authPath);
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
