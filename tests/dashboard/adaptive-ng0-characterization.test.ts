import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ModuleExecutionRepository, ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { recordWorkflowCaseExecutions } from "../../src/dashboard/comparisons/WorkflowCaseExecutionRecorder.js";
import { dashboardScanCreateSchema } from "../../src/dashboard/contracts/DashboardSchemas.js";
import { AdaptiveSecurityService } from "../../src/dashboard/execution/AdaptiveSecurityService.js";
import type { AdaptiveAttackStateGraph } from "../../src/dashboard/execution/AdaptiveAttackStateGraph.js";
import type { DashboardScanCreateRequest } from "../../src/dashboard/types/DashboardTypes.js";
import { apiGraphqlInputSchema, planApiGraphqlReview } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";
import { businessInvariantInputSchema, planBusinessInvariant } from "../../src/modules/businessInvariant/BusinessInvariantPlanner.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { reportFixture } from "../helpers/assisted-review.js";

const origin = "https://app.test";
const scope = { ...exampleScope, allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const };
const databases: DashboardDatabase[] = [];
const privateQueryCanary = "rc-ng0-private-query-canary";

interface Recommendation {
  id: string;
  category: string;
  engineId: string;
  laneKind: string;
  sourceFingerprint: string;
  mutationHypothesis: boolean;
  operatorApprovalRequired: boolean;
  requiredBindings: string[];
  draft: { executable?: boolean; automation: Record<string, unknown>; attackGraphBinding?: unknown };
  createdAt: string;
}
interface Snapshot {
  id: string;
  modelDigest: string;
  inventory: { attackGraph: AdaptiveAttackStateGraph };
  state: { recommendations: Recommendation[] };
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close();
  vi.useRealTimers();
});

describe("RC-NG0 adaptive characterization", () => {
  it("A1 rejects baseline acceptance with a different model digest", () => {
    const { service, snapshot } = observed();
    const differentDigest = (snapshot.modelDigest[0] === "a" ? "b" : "a") + snapshot.modelDigest.slice(1);
    expect(() => service.acceptBaseline(snapshot.id, differentDigest, "fixture-owner"))
      .toThrowError(new Error("ADAPTIVE_BASELINE_BINDING_MISMATCH"));
    expect(service.snapshot(snapshot.id)).toMatchObject({ status: "CANDIDATE" });
    expect(() => service.acceptBaseline(snapshot.id, snapshot.modelDigest, "fixture-owner")).not.toThrow();
  });

  it("A2 rejects baseline acceptance after target row-version drift", () => {
    const { database, targetId, service, snapshot } = observed();
    database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(targetId);
    expect(() => service.acceptBaseline(snapshot.id, snapshot.modelDigest, "fixture-owner"))
      .toThrowError(new Error("ADAPTIVE_TARGET_CHANGED_AFTER_OBSERVATION"));
    expect(service.snapshot(snapshot.id)).toMatchObject({ status: "CANDIDATE" });
  });

  it("A3 rejects a foreign-origin report for a completed registered target scan", () => {
    const database = memoryDatabase();
    const targetId = createTarget(database);
    const scanId = createScan(database, targetId);
    const report = publicReport();
    report.target = "https://other.test";
    const service = new AdaptiveSecurityService(database);
    expect(() => service.observeCompletedScan(scanId, report, targetId))
      .toThrowError(new Error("ADAPTIVE_TARGET_BINDING_MISMATCH"));
    expect(database.db.prepare("SELECT COUNT(*) AS count FROM adaptive_security_snapshots").get()).toEqual({ count: 0 });
    expect(() => service.observeCompletedScan(scanId, publicReport(), targetId)).not.toThrow();
  });

  it.each([
    { name: "absent", template: {} },
    { name: "malformed saved ID", template: { primary: { source: "saved", credentialProfileId: "not-a-uuid" } } },
    { name: "unsaved actor", template: { primary: { source: "ephemeral", credentialProfileId: randomUUID() } } }
  ])("B1 requires a saved PRIMARY fixture when it is $name", ({ template }) => {
    const { service, snapshot } = observed(exactApiReport("primary"), template);
    const recommendation = findRecommendation(snapshot, "EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION");
    expect(recommendation).toMatchObject({ draft: { executable: true, automation: { compilerVersion: 2, authentication: "primary", evidenceStrength: "EXACT_EXECUTED_CONTRACT" } } });
    expect(() => service.materializeRecommendation(recommendation.id))
      .toThrowError(new Error("ADAPTIVE_PRIMARY_AUTHENTICATION_FIXTURE_REQUIRED"));
  });

  it.each([
    { name: "absent pair", template: {} },
    { name: "missing Account B", template: { accountA: { source: "saved", credentialProfileId: randomUUID() } } },
    { name: "malformed Account B", template: { accountAProfileId: randomUUID(), accountBProfileId: "not-a-uuid" } },
    ...(() => { const sameId = randomUUID(); return [{ name: "identical Account A/B IDs", template: { accountAProfileId: sameId, accountBProfileId: sameId } }]; })()
  ])("B2 rejects an incomplete or non-distinct saved pair: $name", ({ template }) => {
    const { service, snapshot } = observed(exactApiReport("account_a"), template);
    const recommendation = findRecommendation(snapshot, "EXACT_CONTRACT_REPLAY_API_GRAPHQL_AUTHORIZATION");
    expect(recommendation).toMatchObject({ draft: { executable: true, automation: { authentication: "account-pair", evidenceStrength: "EXACT_EXECUTED_CONTRACT" } } });
    expect(() => service.materializeRecommendation(recommendation.id))
      .toThrowError(new Error("ADAPTIVE_ACCOUNT_PAIR_AUTHENTICATION_FIXTURE_REQUIRED"));
  });

  it.each([
    { name: "C1 another registered target ID", error: "ADAPTIVE_EXECUTION_TARGET_MISMATCH", alter: (request: DashboardScanCreateRequest, otherTargetId: string) => { request.targetId = otherTargetId; } },
    { name: "C2 another request origin", error: "ADAPTIVE_EXECUTION_TARGET_MISMATCH", alter: (request: DashboardScanCreateRequest) => { request.target = "https://other.test"; } },
    { name: "C3 substituted authentication", error: "ADAPTIVE_EXECUTION_AUTHENTICATION_CHANGED", alter: (request: DashboardScanCreateRequest) => { request.studio!.authentication = { mode: "primary", primary: { source: "saved", credentialProfileId: randomUUID() } }; } },
    { name: "C4 an additional advanced engine", error: "ADAPTIVE_EXECUTION_ADDITIONAL_ENGINE_FORBIDDEN", alter: (request: DashboardScanCreateRequest) => { request.apiGraphql = apiGraphqlInputSchema.parse(publicApiInput()); } },
    { name: "C5 changed cleanup reserve", error: "ADAPTIVE_EXECUTION_CLEANUP_RESERVE_INVALID", alter: (request: DashboardScanCreateRequest) => { request.cleanupReservedRequests = request.cleanupReservedRequests! - 1; } }
  ])("rejects $name independently of the valid materialized request", ({ alter, error }) => {
    const { database, targetId, service, recommendation } = approvedMutation();
    const request = materializedRequest(service, recommendation.id, targetId);
    expect(request.cleanupReservedRequests).toBe(2);
    expect(() => service.assertExecutionBinding(request)).not.toThrow();
    const original = structuredClone(request);
    const altered = structuredClone(request);
    alter(altered, createTarget(database, "https://other.test"));
    expect(dashboardScanCreateSchema.safeParse(altered).success).toBe(true);
    expect(() => service.assertExecutionBinding(altered)).toThrowError(new Error(error));
    expect(request).toEqual(original);
    expect(() => service.assertExecutionBinding(request)).not.toThrow();
  });

  it("D1 rejects linking a recommendation to a scan of another registered target", () => {
    const { database, targetId, service, snapshot } = observed();
    const recommendation = findRecommendation(snapshot, "API_READ_ONLY_REGRESSION");
    const request = materializedRequest(service, recommendation.id, targetId);
    const foreignScan = createScan(database, createTarget(database, "https://other.test"), "https://other.test", request.adaptiveExecutionBinding);
    expect(() => service.linkRecommendation(recommendation.id, foreignScan, "a".repeat(64), "fixture-owner"))
      .toThrowError(new Error("ADAPTIVE_EXECUTION_TARGET_MISMATCH"));
  });

  it("D2 rejects a correctly bound completed execution created before review", () => {
    const { database, targetId, service, recommendation, report } = approvedMutation();
    const reviewedAt = new Date(Date.now() - 60_000).toISOString();
    database.db.prepare("UPDATE adaptive_security_recommendations SET reviewed_at=? WHERE id=?").run(reviewedAt, recommendation.id);
    const request = materializedRequest(service, recommendation.id, targetId);
    expect(() => service.assertExecutionBinding(request)).not.toThrow();
    const execution = (createdAt: string) => {
      const scanId = createScan(database, targetId, origin, request.adaptiveExecutionBinding);
      database.db.prepare("UPDATE scans SET created_at=? WHERE id=?").run(createdAt, scanId);
      const modules = new ModuleExecutionRepository(database);
      modules.createQueued(scanId, [{ id: "business-invariant", phase: "active" }]);
      modules.mark(scanId, "business-invariant", "COMPLETED");
      recordWorkflowCaseExecutions(database.db, scanId, report);
      return scanId;
    };
    const before = execution(new Date(Date.parse(reviewedAt) - 1000).toISOString());
    const after = execution(new Date(Date.parse(reviewedAt) + 1000).toISOString());
    const fingerprint = report.businessInvariant!.observations[0]!.comparisonFingerprint;
    expect(() => service.linkRecommendation(recommendation.id, before, fingerprint, "fixture-owner"))
      .toThrowError(new Error("ADAPTIVE_POST_APPROVAL_EXECUTION_REQUIRED"));
    const linked = service.linkRecommendation(recommendation.id, after, fingerprint, "fixture-owner") as Snapshot["state"];
    expect(linked.recommendations.find((item) => item.id === recommendation.id)).toMatchObject({ status: "VERIFIED", executionOutcome: "VERIFIED", linkedScanId: after });
  });

  it.each(["target row-version drift", "source scan becomes ineligible"])("E rejects source staleness from %s without a newer model", (condition) => {
    const { database, targetId, scanId, service, snapshot } = observed();
    const recommendation = findRecommendation(snapshot, "API_READ_ONLY_REGRESSION");
    expect(() => service.materializeRecommendation(recommendation.id)).not.toThrow();
    if (condition === "target row-version drift") database.db.prepare("UPDATE targets SET row_version=row_version+1 WHERE id=?").run(targetId);
    else database.db.prepare("UPDATE scans SET status='FAILED' WHERE id=?").run(scanId);
    expect(database.db.prepare("SELECT COUNT(*) AS count FROM adaptive_security_snapshots WHERE target_id=?").get(targetId)).toEqual({ count: 1 });
    expect(() => service.materializeRecommendation(recommendation.id))
      .toThrowError(new Error("ADAPTIVE_EXECUTION_SOURCE_STALE"));
  });

  it("F preserves recommendation semantics and graph fingerprints across independent databases", () => {
    const report = semanticReport();
    const original = structuredClone(report);
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-04T10:00:00.000Z"));
    const left = observed(structuredClone(report));
    vi.setSystemTime(new Date("2026-10-04T11:00:00.000Z"));
    const right = observed(structuredClone(report));
    expect(left.targetId).not.toBe(right.targetId);
    expect(left.scanId).not.toBe(right.scanId);
    expect(left.snapshot.id).not.toBe(right.snapshot.id);
    expect(left.snapshot.state.recommendations[0]!.createdAt).not.toBe(right.snapshot.state.recommendations[0]!.createdAt);
    const project = (snapshot: Snapshot) => snapshot.state.recommendations.map((item) => canonical({
      category: item.category, engineId: item.engineId, laneKind: item.laneKind,
      sourceFingerprint: item.sourceFingerprint, mutationHypothesis: item.mutationHypothesis,
      operatorApprovalRequired: item.operatorApprovalRequired, requiredBindings: item.requiredBindings,
      // Preserve the complete safe draft: graph bindings, engine semantics, compiler and evidence fingerprints.
      draft: item.draft
    })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    const leftSemantics = project(left.snapshot);
    expect(leftSemantics.length).toBeGreaterThanOrEqual(4);
    expect(leftSemantics).toEqual(project(right.snapshot));
    expect(left.snapshot.state.recommendations.map((item) => item.sourceFingerprint).sort())
      .toEqual(right.snapshot.state.recommendations.map((item) => item.sourceFingerprint).sort());
    expect(left.snapshot.inventory.attackGraph.graphFingerprint).toBe(right.snapshot.inventory.attackGraph.graphFingerprint);
    for (const snapshot of [left.snapshot, right.snapshot]) {
      expect(snapshot.state.recommendations.some((item) => item.draft.automation.state === "READY_READ_ONLY")).toBe(true);
      expect(snapshot.state.recommendations.some((item) => item.draft.automation.state === "READY_APPROVAL_GATED")).toBe(true);
      expect(snapshot.state.recommendations.some((item) => item.draft.automation.state === "REQUIRES_BINDINGS")).toBe(true);
      const serialized = JSON.stringify(snapshot);
      expect(serialized.includes(privateQueryCanary)).toBe(false);
      // Inventory cookie metadata is expected; credential values and secret-bearing payloads are not.
      expect(serialized.match(/Bearer\s|"password"\s*:|"lifecycleSecrets"\s*:|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/i)).toBeNull();
    }
    expect(report).toEqual(original);
  });
});

function memoryDatabase(): DashboardDatabase {
  const database = new DashboardDatabase(":memory:");
  databases.push(database);
  database.migrate();
  return database;
}

function createTarget(database: DashboardDatabase, baseOrigin = origin, defaultAuthTemplate: Record<string, unknown> = {}): string {
  return new TargetRepository(database).create({ displayName: "RC-NG0 disposable fixture", baseOrigin, tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned characterization fixture; no network execution", productionEnabled: false, approvedScope: { ...scope, allowedDomains: [new URL(baseOrigin).hostname] }, defaultAuthTemplate });
}

function createScan(database: DashboardDatabase, targetId: string, targetOrigin = origin, binding?: DashboardScanCreateRequest["adaptiveExecutionBinding"]): string {
  const id = randomUUID();
  new ScanRepository(database).create({ id, source: "DASHBOARD", status: "COMPLETED", targetOrigin, safeTargetLabel: "RC-NG0 fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: binding ? { adaptiveExecutionBinding: binding } : {}, targetId });
  return id;
}

function observed(report = publicReport(), template: Record<string, unknown> = {}) {
  const database = memoryDatabase();
  const targetId = createTarget(database, origin, template);
  const scanId = createScan(database, targetId);
  const service = new AdaptiveSecurityService(database);
  const snapshot = service.observeCompletedScan(scanId, report, targetId) as unknown as Snapshot;
  return { database, targetId, scanId, service, snapshot };
}

function findRecommendation(snapshot: Snapshot, category: string): Recommendation {
  const recommendation = snapshot.state.recommendations.find((item) => item.category === category);
  expect(recommendation, `Pipeline did not produce ${category}`).toBeDefined();
  return recommendation!;
}

function approvedMutation() {
  const report = mutationReport();
  const fixture = observed(report);
  const recommendation = findRecommendation(fixture.snapshot, "EXACT_CONTRACT_REPLAY_BUSINESS_INVARIANT");
  expect(recommendation).toMatchObject({ operatorApprovalRequired: true, draft: { executable: true, automation: { state: "READY_APPROVAL_GATED" } } });
  fixture.service.decideRecommendation(recommendation.id, "APPROVED", "Review disposable exact transition with verified restoration", "fixture-owner");
  return { ...fixture, recommendation, report };
}

function materializedRequest(service: AdaptiveSecurityService, id: string, targetId: string): DashboardScanCreateRequest {
  const materialized = service.materializeRecommendation(id) as {
    engineId: string; engineConfiguration: unknown; binding: DashboardScanCreateRequest["adaptiveExecutionBinding"];
    authentication: NonNullable<DashboardScanCreateRequest["studio"]>["authentication"];
    limits: { maxRequests: number; cleanupReservedRequests: number };
  };
  const field = materialized.engineId === "business-invariant" ? "businessInvariant" : "apiGraphql";
  return dashboardScanCreateSchema.parse({ target: origin, targetId, profile: "full", ...materialized.limits,
    includeModules: [materialized.engineId], [field]: materialized.engineConfiguration, adaptiveExecutionBinding: materialized.binding,
    studio: { version: 1, scanName: "RC-NG0 characterized replay", authorization: { category: "OWNED", confirmed: true }, scope, authentication: materialized.authentication }
  });
}

function publicReport(): RouteCairnReport {
  const url = `${origin}/api/public-profile`;
  return { ...reportFixture(), scanPlan: {},
    apiMapper: { endpoints: [{ endpoint: url, method: "GET", source: "html" }], graphQlEndpoints: [] },
    requestAudit: [{ requestedUrl: url, finalUrl: url, method: "GET", outcome: "sent", statusCode: 200, requestHeaders: {}, redirectChain: [], source: "http" }],
    responses: [{ requestedUrl: url, finalUrl: url, method: "GET", statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", bodyHash: "a".repeat(64), responseTimeMs: 1, redirectChain: [] }]
  } as unknown as RouteCairnReport;
}

function publicApiInput(authSlot: "anonymous" | "primary" | "account_a" = "anonymous") {
  return { schemaVersion: 1, maxRequests: 1,
    actors: [{ id: "owner", safeAlias: "Fixture owner", authSlot, relationship: authSlot === "anonymous" ? "PUBLIC" : "OWNER" }],
    routes: [{ id: "object", safeAlias: "Disposable object", protocol: "REST", kind: "OBJECT", objectType: "invoice", url: `${origin}/api/invoices/inv_fixture`, pathTemplate: "/api/invoices/:id", documentedMethods: ["GET"] }],
    checks: [{ id: "owner-read", matrixId: "invoice-owner", label: "Exact owner read", kind: "OBJECT_AUTHORIZATION", routeId: "object", actorId: "owner", requireVerifiedIdentity: false, request: { method: "GET" }, response: { expectedDecision: "ALLOW" } }]
  };
}

function exactApiReport(authSlot: "primary" | "account_a"): RouteCairnReport {
  // Planner-only actor profiles have no headers, cookies or secret values; reports retain slots only.
  const profile = authProfileSchema.parse({ label: "Fixture actor" });
  const plan = planApiGraphqlReview(apiGraphqlInputSchema.parse(publicApiInput(authSlot)), { target: origin, scope, authProfile: profile, authProfileSet: { accountA: profile, accountB: authProfileSchema.parse({ label: "Other fixture actor" }) } });
  return { ...reportFixture(), scanPlan: { apiGraphql: plan },
    apiGraphql: { inventory: [], authorizationMatrices: [], checks: [{ checkId: plan.checks[0]!.id, comparisonFingerprint: plan.checks[0]!.comparisonFingerprint, outcome: "PASS", kind: "OBJECT_AUTHORIZATION", protocols: ["REST"], routeAliases: ["Disposable object"], actorAlias: "Fixture owner", fields: [] }] }
  } as unknown as RouteCairnReport;
}

function mutationReport(): RouteCairnReport {
  const now = new Date();
  const read = (id: string, name: string) => ({ id, actorId: "fixture", request: { method: "GET", url: `${origin}/fixture/state`, stateChanging: false }, captures: [{ name, source: "JSON", path: "balance" }] });
  const plan = planBusinessInvariant(businessInvariantInputSchema.parse({ schemaVersion: 1, maxRequests: 5, maxConcurrency: 1, cases: [{
    id: "disposable-change", label: "Disposable state transition", category: "STATE_TRANSITION",
    actors: [{ id: "fixture", safeAlias: "Fixture actor", authSlot: "anonymous", requestAuthentication: "NONE", relationship: "SELF", declaredState: "FIXTURE" }],
    authorization: { mode: "CONTROLLED_INVARIANT", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING", authorizedBy: "fixture-owner", changeTicket: "RC-NG0 fixture evidence", authorizedAt: new Date(now.getTime() - 1000).toISOString(), expiresAt: new Date(now.getTime() + 3600_000).toISOString(), disposableEntities: true },
    preState: [read("before", "balance_before")],
    actions: [{ id: "change", actorId: "fixture", request: { method: "POST", url: `${origin}/fixture/change`, stateChanging: true, bodyFormat: "JSON", fields: { amount: 1 } }, execution: { mode: "ONCE", attempts: 1, maxConcurrency: 1 }, expectation: { authorization: "ALLOW", businessRule: "ACCEPT" } }],
    postState: [read("after", "balance_after")], invariants: [{ id: "delta", kind: "NUMERIC_DELTA", before: "balance_before", after: "balance_after", operator: "EQ", expected: -1 }],
    cleanupRequired: true, cleanup: [{ id: "restore", actorId: "fixture", request: { method: "POST", url: `${origin}/fixture/restore`, stateChanging: true, bodyFormat: "JSON", fields: { balance: "{{CAPTURE:balance_before}}" } }, successStatusCodes: [204] }],
    cleanupVerification: [read("restored", "balance_restored")], cleanupInvariants: [{ id: "restored-equality", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "balance_before" }, operator: "EQ", right: { source: "CAPTURE", ref: "balance_restored" } }]
  }] }), { target: origin, scope, now });
  return { ...reportFixture(), scanPlan: { businessInvariant: plan }, businessInvariant: { observations: [{ caseId: plan.cases[0]!.id, comparisonFingerprint: plan.cases[0]!.comparisonFingerprint, outcome: "PASS", cleanupOutcome: "ROLLBACK_VERIFIED", preStateVerified: true, postStateVerified: true, actorModel: [], actions: [], invariants: [] }] } } as unknown as RouteCairnReport;
}

function semanticReport(): RouteCairnReport {
  const publicEvidence = publicReport();
  const exact = exactApiReport("primary");
  const mutation = mutationReport();
  return { ...publicEvidence, scanPlan: { ...exact.scanPlan, ...mutation.scanPlan }, apiGraphql: exact.apiGraphql!, businessInvariant: mutation.businessInvariant!,
    apiMapper: { ...publicEvidence.apiMapper!, endpoints: [...publicEvidence.apiMapper!.endpoints, { method: "POST", endpoint: `${origin}/api/share?value=${privateQueryCanary}` }] }
  } as RouteCairnReport;
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, canonical(child)]));
}
