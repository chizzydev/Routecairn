import { createHash, randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { exampleScope } from "../../src/config/defaults.js";
import { authProfileSchema } from "../../src/core/auth/AuthProfile.js";
import { DashboardDatabase } from "../../src/dashboard/db/DashboardDatabase.js";
import { ScanRepository, TargetRepository } from "../../src/dashboard/db/DashboardRepositories.js";
import { recordWorkflowCaseExecutions } from "../../src/dashboard/comparisons/WorkflowCaseExecutionRecorder.js";
import { AdaptiveSecurityService } from "../../src/dashboard/execution/AdaptiveSecurityService.js";
import { adaptiveDigest, adaptiveExecutionFingerprint } from "../../src/dashboard/execution/AdaptiveCanonical.js";
import { buildAdaptiveInventory, compareAdaptiveInventories, synthesizeAdaptiveRecommendations, type AdaptiveInventory, type AdaptiveDrift, type AdaptiveRecommendation } from "../../src/dashboard/execution/AdaptiveSynthesisCore.js";
import { apiGraphqlInputSchema, planApiGraphqlReview } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";
import { businessInvariantInputSchema, planBusinessInvariant } from "../../src/modules/businessInvariant/BusinessInvariantPlanner.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { reportFixture } from "../helpers/assisted-review.js";

const origin = "https://app.test";
const scope = { ...exampleScope, allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const };
const privateQueryCanary = "rc-ng0-private-query-canary";
const initialDrift = { type: "INITIAL_MODEL", severity: "INFO", semanticKey: "model", summary: "Initial target security model captured; operator baseline acceptance is required." };
// Captured BEFORE production extraction at 70624ff0ac1552e5e7c526e9eb1a3287f3df9e7c.
const preExtractionGolden = "801fef56cf61089427df18971a453480c0e0120209e71b4960440bac6e6a0769";
const databases: DashboardDatabase[] = [];
afterEach(() => { for (const database of databases.splice(0)) database.close(); vi.useRealTimers(); });

describe("RC-NG1 synthesis semantic contract", () => {
  it("preserves the pre-extraction ordered service golden", () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-04T12:00:00.000Z"));
    const { baseline, changed } = evidence();
    const fixture = serviceFixture();
    const first = observe(fixture, baseline);
    const states = first.recommendations.map((item) => (item.draft.automation as Record<string, unknown>).state);
    for (const state of ["READY_READ_ONLY", "READY_APPROVAL_GATED", "REQUIRES_BINDINGS"]) expect(states).toContain(state);
    expect(new Set(first.recommendations.map((item) => item.category)).size).toBeGreaterThan(3);
    expect(first.drifts).toEqual([initialDrift]);
    fixture.service.acceptBaseline(first.id, first.modelDigest, "fixture-owner");
    const second = observe(fixture, changed);
    expect(second.drifts).toEqual(expect.arrayContaining([expect.objectContaining({ type: "FIELD_ACCESS_CHANGED", severity: "HIGH" }), expect.objectContaining({ type: "COOKIE_SECURITY_CHANGED", severity: "HIGH" })]));
    const value = goldenDigest([project(first), project(second)]);
    expect(value).toBe(preExtractionGolden);
  });

  it("builds the ordered golden directly without creating a database", () => {
    const { baseline, changed } = evidence();
    const first = synthesize(baseline);
    const second = synthesize(changed, first.inventory);
    expect(goldenDigest([project(first), project(second)])).toBe(preExtractionGolden);
    expect(databases).toHaveLength(0);
    expect(JSON.stringify([first, second])).not.toContain(privateQueryCanary);
  });

  it("preserves evidence, workflow rows and baseline inventory without mutating inputs", () => {
    const { baseline, changed } = evidence();
    const workflowCases = workflowEvidence(changed);
    const before = buildAdaptiveInventory(baseline, workflowEvidence(baseline));
    const original = structuredClone({ baseline, changed, workflowCases, before });
    const after = buildAdaptiveInventory(changed, workflowCases);
    const drifts = compareAdaptiveInventories(before, after, true);
    const driftsBefore = structuredClone(drifts);
    const inventoryBefore = structuredClone(after);
    synthesizeAdaptiveRecommendations(changed, after, drifts);
    expect({ baseline, changed, workflowCases, before }).toEqual(original);
    expect(after).toEqual(inventoryBefore);
    expect(drifts).toEqual(driftsBefore);
    expect(databases).toHaveLength(0);
  });

  it("returns equal inventories, ordered drifts and recommendations for equal cloned inputs", () => {
    const { baseline, changed } = evidence();
    const left = synthesize(baseline);
    const right = synthesize(structuredClone(baseline));
    expect(left).toEqual(right);
    const afterLeft = synthesize(changed, left.inventory);
    const afterRight = synthesize(structuredClone(changed), structuredClone(right.inventory));
    expect(afterLeft).toEqual(afterRight);
    expect(afterLeft.recommendations.map((item) => item.sourceFingerprint)).toEqual(afterRight.recommendations.map((item) => item.sourceFingerprint));
    expect(adaptiveDigest(afterLeft.inventory)).toBe(adaptiveDigest(afterRight.inventory));
  });

  it("matches persisted service insertion semantics and baseline drift for both removal policies", () => {
    vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-04T12:00:00.000Z"));
    const { baseline, changed } = evidence();
    for (const includeRemoved of [true, false]) {
      const fixture = serviceFixture();
      fixture.service.setPolicy({ targetId: fixture.targetId, requiredLanes: ["PUBLIC_BASELINE"], requireEvidenceForNotApplicable: true, detectRemovedSurfaces: includeRemoved, confirmation: "I_CONFIRM_TARGET_SECURITY_MODEL_POLICY" }, "fixture-owner");
      const before = observe(fixture, baseline);
      const directBefore = synthesize(baseline);
      expect(project(before)).toEqual(jsonValue(project(directBefore)));
      expect(before.drifts).toEqual([initialDrift]);
      fixture.service.acceptBaseline(before.id, before.modelDigest, "fixture-owner");
      const after = observe(fixture, changed);
      const directAfter = synthesize(changed, directBefore.inventory, includeRemoved);
      expect(project(after)).toEqual(jsonValue(project(directAfter)));
      expect(after.drifts.some((item) => item.severity === "HIGH")).toBe(true);
      if (includeRemoved) expect(goldenDigest([project(before), project(after)])).toBe(preExtractionGolden);
    }
  });

  it("keeps canonical JSON semantics, array order and both legacy fingerprint purposes", () => {
    const input = { z: undefined, a: [{ z: 2, a: undefined }, undefined, null, { b: false, a: 1 }] };
    expect(adaptiveDigest(input)).toBe(goldenDigest(input));
    expect(adaptiveDigest({ a: 1, b: 2 })).toBe(adaptiveDigest({ b: 2, a: 1 }));
    expect(adaptiveDigest([1, 2])).not.toBe(adaptiveDigest([2, 1]));
    // Preserve legacy root-undefined rejection; do not normalize it to null.
    expect(() => adaptiveDigest(undefined)).toThrow(TypeError);
    for (const compilerVersion of [1, 2] as const) {
      expect(adaptiveExecutionFingerprint("business-invariant", "a".repeat(64), "b".repeat(64), input, compilerVersion)).toBe(goldenDigest({ purpose: compilerVersion === 1 ? "adaptive-read-only-execution" : "adaptive-exact-contract-execution", engineId: "business-invariant", sourceFingerprint: "a".repeat(64), evidenceFingerprint: "b".repeat(64), engineConfiguration: input, compilerVersion }));
    }
  });
});

interface SemanticSnapshot { id: string; inventory: AdaptiveInventory; modelDigest: string; recommendations: AdaptiveRecommendation[]; drifts: AdaptiveDrift[] }
function serviceFixture() {
  const database = new DashboardDatabase(":memory:"); databases.push(database); database.migrate();
  const targetId = new TargetRepository(database).create({ displayName: "RC-NG1 semantic fixture", baseOrigin: origin, tags: [], classification: "PRIVATE", authorizationType: "OWNED", authorizationSummary: "Owned in-memory synthesis evidence; no transmission", productionEnabled: false, approvedScope: scope });
  return { database, targetId, service: new AdaptiveSecurityService(database) };
}
function observe(fixture: ReturnType<typeof serviceFixture>, report: RouteCairnReport): SemanticSnapshot {
  const scanId = randomUUID();
  new ScanRepository(fixture.database).create({ id: scanId, source: "DASHBOARD", status: "COMPLETED", targetOrigin: origin, safeTargetLabel: "NG1 fixture", profile: "full", evidenceLevel: "strong", safeConfigurationSummary: {}, targetId: fixture.targetId });
  recordWorkflowCaseExecutions(fixture.database.db, scanId, report);
  const snapshot = fixture.service.observeCompletedScan(scanId, report, fixture.targetId) as unknown as { id: string; modelDigest: string; inventory: AdaptiveInventory };
  // rowid preserves synthesis insertion order, avoiding UUIDs and timestamp tie sorting.
  const recommendations = (fixture.database.db.prepare("SELECT * FROM adaptive_security_recommendations WHERE snapshot_id=? ORDER BY rowid").all(snapshot.id) as Array<Record<string, unknown>>).map((row) => ({ category: String(row.category), engineId: String(row.engine_id), laneKind: String(row.lane_kind) as AdaptiveRecommendation["laneKind"], sourceFingerprint: String(row.source_fingerprint), mutationHypothesis: Boolean(row.mutation_hypothesis), operatorApprovalRequired: Boolean(row.operator_approval_required), requiredBindings: JSON.parse(String(row.required_bindings_json)) as string[], draft: JSON.parse(String(row.safe_draft_json)) as Record<string, unknown> }));
  const drifts = (fixture.database.db.prepare("SELECT * FROM adaptive_security_drifts WHERE snapshot_id=? ORDER BY rowid").all(snapshot.id) as Array<Record<string, unknown>>).map((row) => ({ type: String(row.drift_type), severity: String(row.severity) as AdaptiveDrift["severity"], semanticKey: String(row.semantic_key), summary: String(row.safe_summary) }));
  return { ...snapshot, recommendations, drifts };
}
function project(value: Omit<SemanticSnapshot, "id">) { return { inventory: value.inventory, modelDigest: value.modelDigest, attackGraphFingerprint: (value.inventory as { attackGraph: { graphFingerprint: string } }).attackGraph.graphFingerprint, recommendations: value.recommendations, drifts: value.drifts }; }
function goldenDigest(value: unknown): string { return createHash("sha256").update(JSON.stringify(canonical(value))).digest("hex"); }
function canonical(value: unknown): unknown { if (Array.isArray(value)) return value.map(canonical); if (!value || typeof value !== "object") return value; return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, canonical(child)])); }
function jsonValue<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T; }
function workflowEvidence(report: RouteCairnReport): AdaptiveInventory["workflowCases"] {
  // Safe recorder-shaped values; no repository or DB is needed for direct synthesis.
  return [
    ...(report.apiGraphql?.checks ?? []).map((item) => ({ workflowId: "api-graphql-authorization", fingerprint: item.comparisonFingerprint })),
    ...(report.businessInvariant?.observations ?? []).map((item) => ({ workflowId: "business-invariant", fingerprint: item.comparisonFingerprint }))
  ].map((item) => ({ ...item, key: `${item.workflowId}:${item.fingerprint}`, executionState: "COMPLETED" })).sort((a, b) => a.key.localeCompare(b.key));
}
function synthesize(report: RouteCairnReport, baseline?: AdaptiveInventory, includeRemoved = true): Omit<SemanticSnapshot, "id"> {
  const inventory = buildAdaptiveInventory(report, workflowEvidence(report));
  const drifts: AdaptiveDrift[] = baseline ? compareAdaptiveInventories(baseline, inventory, includeRemoved) : [{ ...initialDrift, severity: "INFO" }];
  return { inventory, modelDigest: adaptiveDigest(inventory), drifts, recommendations: synthesizeAdaptiveRecommendations(report, inventory, drifts) };
}
function evidence() {
  const baseline = semanticReport();
  baseline.browserCrawl = { startUrl: origin, renderedLinks: [], networkRequests: [], consoleErrors: [], formsDetected: 1, formsSubmitted: 0, notes: [], authentication: { fields: [{ pageUrl: origin + "/settings", name: "profile-name", controlType: "text", access: "read-only" }], storage: [{ origin, storage: "cookie", name: "session", classification: "authentication", valueLength: 64, valueDigest: "c".repeat(64), httpOnly: true, secure: true, sameSite: "Lax" }], adminRoutes: [], learnedTestCases: [] } } as unknown as RouteCairnReport["browserCrawl"];
  const changed = structuredClone(baseline);
  changed.browserCrawl!.authentication!.fields[0]!.access = "writable";
  changed.browserCrawl!.authentication!.storage[0]!.secure = false;
  changed.browserCrawl!.authentication!.adminRoutes.push(origin + "/admin");
  changed.apiMapper!.endpoints.push({ method: "POST", endpoint: origin + "/api/admin" } as NonNullable<RouteCairnReport["apiMapper"]>["endpoints"][number]);
  return { baseline, changed };
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
