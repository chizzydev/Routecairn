import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { AdaptiveSecurityService } from "../../src/dashboard/execution/AdaptiveSecurityService.js";
import { compileBillingReadOnlyCase, compileBusinessInvariantReadOnlyCase, compileGraphqlIntrospectionCase, compileOperationalHealthCase, compileRouteReadOnlyCase, compileSupabaseReadOnlyCase } from "../../src/dashboard/execution/AdaptiveReadOnlyCompiler.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { reportFixture } from "../helpers/assisted-review.js";

describe("adaptive discovery-to-execution compiler", () => {
  it("compiles an exact anonymous GET into a complete schema-valid API case", () => {
    const report = publicReport("/api/public-profile", 200, "application/json");
    const compiled = compileRouteReadOnlyCase(report, { protocol: "REST", method: "GET", pathTemplate: "/api/public-profile", source: "api-mapper", stateChanging: false });
    expect(compiled).toMatchObject({ engineId: "api-graphql-authorization", requestCount: 1, evidenceStrength: "EXACT_ANONYMOUS_RESPONSE" });
    expect(compiled?.engineConfiguration).toMatchObject({ actors: [{ authSlot: "anonymous" }], checks: [{ requireVerifiedIdentity: false, response: { expectedDecision: "ALLOW" } }] });
    expect(JSON.stringify(compiled)).not.toMatch(/bearer\s|cookie=|secret-value|access[_-]?token/i);
  });

  it("refuses unstable identifiers, authenticated observations, and state-changing routes", () => {
    const unstable = publicReport("/api/users/12345", 200, "application/json");
    expect(compileRouteReadOnlyCase(unstable, { protocol: "REST", method: "GET", pathTemplate: "/api/users/12345", source: "api-mapper", stateChanging: false })).toBeUndefined();
    const authenticated = publicReport("/api/profile", 200, "application/json", { Authorization: "<redacted>" });
    expect(compileRouteReadOnlyCase(authenticated, { protocol: "REST", method: "GET", pathTemplate: "/api/profile", source: "api-mapper", stateChanging: false })).toBeUndefined();
    expect(compileRouteReadOnlyCase(publicReport("/api/profile", 200, "application/json"), { protocol: "REST", method: "POST", pathTemplate: "/api/profile", source: "browser-learning", stateChanging: true })).toBeUndefined();
  });

  it("compiles public JSON health checks with status and sensitive-field absence assertions", () => {
    const compiled = compileOperationalHealthCase(publicReport("/health", 200, "application/json"), { protocol: "REST", method: "GET", pathTemplate: "/health", source: "api-mapper", stateChanging: false });
    expect(compiled).toMatchObject({ engineId: "operational-endpoint-security", requestCount: 1 });
    expect(JSON.stringify(compiled?.engineConfiguration)).toContain("JSON_FIELD_ABSENT");
  });

  it("compiles generated GraphQL introspection without treating the transport POST as mutation authority", () => {
    const compiled = compileGraphqlIntrospectionCase(publicReport("/graphql", 200, "application/json"), "/graphql");
    expect(compiled).toMatchObject({ engineId: "api-graphql-authorization", requestCount: 1 });
    expect(compiled?.engineConfiguration).toMatchObject({ actors: [{ authSlot: "anonymous" }], checks: [{ kind: "GRAPHQL_INTROSPECTION", requireVerifiedIdentity: false }] });
  });

  it("compiles only exact anonymous Supabase SELECT evidence", () => {
    const report = reportFixture() as RouteCairnReport;
    report.scanPlan = {} as RouteCairnReport["scanPlan"];
    report.scanPlan.supabaseAuthorization = { anonKeyEnv: "SUPABASE_ANON_KEY" } as RouteCairnReport["scanPlan"]["supabaseAuthorization"];
    report.supabaseAuthorization = {
      projectOrigin: "https://project.supabase.co",
      observations: [{ caseId: "public-rows", comparisonFingerprint: "b".repeat(64), surface: "TABLE", resource: "public_articles", operation: "SELECT", actor: "ANONYMOUS", boundary: "PUBLIC", method: "GET", url: "/rest/v1/public_articles?select=id,title&limit=1", expectedDecision: "ALLOW", observedDecision: "ALLOW", statusCode: 200, evidenceIds: [], safeSummary: "Anonymous list read observed." }],
      resourceCoverage: []
    } as RouteCairnReport["supabaseAuthorization"];
    const compiled = compileSupabaseReadOnlyCase(report, { surface: "TABLE", resource: "public_articles", operations: ["SELECT"], actors: ["ANONYMOUS"] });
    expect(compiled).toMatchObject({ engineId: "supabase-authorization", requestCount: 1, evidenceStrength: "EXACT_ENGINE_OBSERVATION" });
    expect(compiled?.engineConfiguration).toMatchObject({ cases: [{ operation: "SELECT", actor: "ANONYMOUS", method: "GET", requireVerifiedIdentity: false }] });
  });

  it("compiles billing and invariant read observations without mutation authority", () => {
    const billing = compileBillingReadOnlyCase(publicReport("/billing/subscription", 200, "application/json"), { protocol: "REST", method: "GET", pathTemplate: "/billing/subscription", source: "api-mapper", stateChanging: false });
    expect(billing).toMatchObject({ engineId: "billing-entitlement-security", requestCount: 1, evidenceStrength: "EXACT_ANONYMOUS_RESPONSE" });
    expect(billing?.engineConfiguration).toMatchObject({ cases: [{ authorization: { mode: "OBSERVE_ONLY" }, cleanupRequired: false, steps: [{ operation: "OBSERVE", request: { stateChanging: false } }] }] });
    const invariant = compileBusinessInvariantReadOnlyCase(publicReport("/account/state", 200, "application/json"), { protocol: "REST", method: "GET", pathTemplate: "/account/state", source: "api-mapper", stateChanging: false });
    expect(invariant).toMatchObject({ engineId: "business-invariant", requestCount: 2, evidenceStrength: "EXACT_ANONYMOUS_RESPONSE" });
    expect(invariant?.engineConfiguration).toMatchObject({ cases: [{ authorization: { mode: "OBSERVE_ONLY" }, actions: [], cleanupRequired: false }] });
    expect(JSON.stringify({ billing, invariant })).not.toMatch(/bearer\s|cookie=|secret-value|access[_-]?token/i);
  });

  it("materializes an immutable read-only recommendation and rejects changed execution semantics", () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = new TargetRepository(database).create({ displayName: "Adaptive fixture", baseOrigin: "https://app.test", tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned adaptive read-only fixture", productionEnabled: false, approvedScope: scope() });
    const sourceScanId = randomUUID();
    new ScanRepository(database).create({ id: sourceScanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.test", safeTargetLabel: "fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
    const service = new AdaptiveSecurityService(database);
    const observed = service.observeCompletedScan(sourceScanId, publicReport("/api/public-profile", 200, "application/json"), targetId) as any;
    const recommendation = observed.state.recommendations.find((item: any) => item.category === "API_READ_ONLY_REGRESSION");
    expect(recommendation).toMatchObject({ operatorApprovalRequired: false, mutationHypothesis: false, requiredBindings: [], draft: { executable: true, automation: { state: "READY_READ_ONLY" } } });
    const materialized = service.materializeRecommendation(recommendation.id) as any;
    const request: any = { target: "https://app.test", targetId, profile: "full", maxRequests: materialized.limits.maxRequests, cleanupReservedRequests: 0, includeModules: ["api-graphql-authorization"], apiGraphql: materialized.engineConfiguration, adaptiveExecutionBinding: materialized.binding, studio: { version: 1, scanName: "Adaptive read-only", authorization: { category: "OWNED", confirmed: true }, scope: scope(), authentication: { mode: "public" }, evidenceLevel: "strong", outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: [], workflowSummary: [] } };
    expect(() => service.assertExecutionBinding(request)).not.toThrow();
    request.operationalEndpointSecurity = {};
    expect(() => service.assertExecutionBinding(request)).toThrow("ADDITIONAL_ENGINE_FORBIDDEN");
    delete request.operationalEndpointSecurity;
    request.apiGraphql.checks[0].response.expectedDecision = "DENY";
    expect(() => service.assertExecutionBinding(request)).toThrow("CONFIGURATION_CHANGED");
    database.close();
  });

  it("materializes billing and invariant observations through the same binding gate", () => {
    const database = new DashboardDatabase(":memory:"); database.migrate();
    const targetId = new TargetRepository(database).create({ displayName: "Adaptive billing fixture", baseOrigin: "https://app.test", tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned adaptive read-only fixture", productionEnabled: false, approvedScope: scope() });
    const sourceScanId = randomUUID();
    new ScanRepository(database).create({ id: sourceScanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: "https://app.test", safeTargetLabel: "fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId });
    const service = new AdaptiveSecurityService(database);
    const observed = service.observeCompletedScan(sourceScanId, publicReport("/billing/subscription", 200, "application/json"), targetId) as any;
    for (const category of ["SYNTHETIC_BILLING_READ_ONLY", "BUSINESS_INVARIANT_READ_ONLY"]) {
      const recommendation = observed.state.recommendations.find((item: any) => item.category === category);
      expect(recommendation).toMatchObject({ operatorApprovalRequired: false, mutationHypothesis: false, draft: { executable: true, automation: { state: "READY_READ_ONLY" } } });
      expect(() => service.materializeRecommendation(recommendation.id)).not.toThrow();
    }
    database.close();
  });
});

function publicReport(path: string, statusCode: number, contentType: string, requestHeaders: Record<string, string> = {}): RouteCairnReport {
  const url = `https://app.test${path}`;
  return { ...reportFixture(), scanPlan: {} as RouteCairnReport["scanPlan"], requestAudit: [{ requestedUrl: url, finalUrl: url, method: path === "/graphql" ? "POST" : "GET", outcome: "sent", statusCode, requestHeaders, redirectChain: [], source: "http" }], responses: [{ requestedUrl: url, finalUrl: url, method: path === "/graphql" ? "POST" : "GET", statusCode, headers: { "content-type": contentType }, contentType, bodyHash: "a".repeat(64), responseTimeMs: 5, redirectChain: [] }], apiMapper: { endpoints: [{ endpoint: url, method: path === "/graphql" ? "POST" : "GET", routeType: "api", riskTags: [], likelyManualTests: [], authRelevance: "low", hasObjectId: false, privilegeSensitivity: "low", dataExposureSensitivity: "low", rateLimitSensitivity: "low" }], graphQlEndpoints: path === "/graphql" ? [url] : [], notes: [] } } as RouteCairnReport;
}

function scope() { return { program: "fixture", allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const, rateLimitPerSecond: 1, concurrency: 1, maxDepth: 1, sameOriginOnly: true, includeSubdomains: false, respectRobotsTxt: false, userAgent: "RouteCairn/Test" }; }
