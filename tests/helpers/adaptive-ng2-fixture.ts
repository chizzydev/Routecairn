import { exampleScope } from "../../src/config/defaults.js";
import { buildAdaptiveInventory, compareAdaptiveInventories, synthesizeAdaptiveRecommendations } from "../../src/dashboard/execution/AdaptiveSynthesisCore.js";
import { apiGraphqlInputSchema, planApiGraphqlReview } from "../../src/modules/apiGraphql/ApiGraphqlPlanner.js";
import { businessInvariantInputSchema, planBusinessInvariant } from "../../src/modules/businessInvariant/BusinessInvariantPlanner.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { reportFixture } from "./assisted-review.js";

export const ng2Origin = "https://app.test";
export const ng2Scope = { ...exampleScope, allowedDomains: ["app.test"], disallowedPaths: [], allowedMethods: ["GET", "HEAD", "OPTIONS", "POST"] as const };
export const ng2Canary = "ng2-private-query-canary";

/** Production planners and NG1 synthesis create drafts; this fixture never transmits. */
export function ng2Report(slot: "primary" | "account_a" = "primary"): RouteCairnReport {
  // Empty planner context provides slot availability, never credentials or a vault system.
  const profile = { label: "Fixture slot", headers: {}, cookies: [] } as NonNullable<Parameters<typeof planApiGraphqlReview>[1]["authProfile"]>;
  const apiPlan = planApiGraphqlReview(apiGraphqlInputSchema.parse({ schemaVersion: 1, maxRequests: 1,
    actors: [{ id: "owner", safeAlias: "Fixture owner", authSlot: slot, relationship: "OWNER" }],
    routes: [{ id: "object", safeAlias: "Disposable object", protocol: "REST", kind: "OBJECT", objectType: "invoice", url: `${ng2Origin}/api/invoices/inv_fixture`, pathTemplate: "/api/invoices/:id", documentedMethods: ["GET"] }],
    checks: [{ id: "owner-read", matrixId: "invoice-owner", label: "Exact owner read", kind: "OBJECT_AUTHORIZATION", routeId: "object", actorId: "owner", requireVerifiedIdentity: false, request: { method: "GET" }, response: { expectedDecision: "ALLOW" } }]
  }), { target: ng2Origin, scope: ng2Scope, authProfile: profile, authProfileSet: { accountA: profile, accountB: { ...profile, label: "Other slot" } } });
  const now = new Date("2026-10-13T08:00:00.000Z");
  const read = (id: string, name: string) => ({ id, actorId: "fixture", request: { method: "GET", url: `${ng2Origin}/fixture/state`, stateChanging: false }, captures: [{ name, source: "JSON", path: "balance" }] });
  const mutation = { id: "disposable-change", label: "Disposable state transition", category: "STATE_TRANSITION",
    actors: [{ id: "fixture", safeAlias: "Fixture actor", authSlot: "anonymous", requestAuthentication: "NONE", relationship: "SELF", declaredState: "FIXTURE" }],
    authorization: { mode: "CONTROLLED_INVARIANT", environment: "TEST", confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING", authorizedBy: "fixture-owner", changeTicket: "NG2 disposable fixture evidence", authorizedAt: new Date(now.getTime() - 1000).toISOString(), expiresAt: new Date(now.getTime() + 3600_000).toISOString(), disposableEntities: true },
    preState: [read("before", "balance_before")],
    actions: [{ id: "change", actorId: "fixture", request: { method: "POST", url: `${ng2Origin}/fixture/change`, stateChanging: true, bodyFormat: "JSON", fields: { amount: 1 } }, execution: { mode: "ONCE", attempts: 1, maxConcurrency: 1 }, expectation: { authorization: "ALLOW", businessRule: "ACCEPT" } }],
    postState: [read("after", "balance_after")], invariants: [{ id: "delta", kind: "NUMERIC_DELTA", before: "balance_before", after: "balance_after", operator: "EQ", expected: -1 }],
    cleanupRequired: true, cleanup: [{ id: "restore", actorId: "fixture", request: { method: "POST", url: `${ng2Origin}/fixture/restore`, stateChanging: true, bodyFormat: "JSON", fields: { balance: "{{CAPTURE:balance_before}}" } }, successStatusCodes: [204] }],
    cleanupVerification: [read("restored", "balance_restored")], cleanupInvariants: [{ id: "restored-equality", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "balance_before" }, operator: "EQ", right: { source: "CAPTURE", ref: "balance_restored" } }]
  };
  const incomplete = { ...mutation, id: "incomplete-transition", actions: mutation.actions.map((action) => ({ ...action, request: { ...action.request, fields: { amount: 2 } } })), invariants: mutation.invariants.map((item) => ({ ...item, expected: -2 })) };
  const businessPlan = planBusinessInvariant(businessInvariantInputSchema.parse({ schemaVersion: 1, maxRequests: 10, maxConcurrency: 1, cases: [mutation, incomplete] }), { target: ng2Origin, scope: ng2Scope, now });
  const publicPaths = ["/api/public-profile", "/health", "/billing/subscription", "/graphql"];
  const urlFor = (path: string) => `${ng2Origin}${path}`;
  return { ...reportFixture(), target: ng2Origin, scanPlan: { apiGraphql: apiPlan, businessInvariant: businessPlan },
    apiMapper: { endpoints: [...publicPaths.map((path) => ({ endpoint: urlFor(path), method: path === "/graphql" ? "POST" : "GET", source: "html" })), ...["/api/share", "/webhook", "/checkout", "/portal/export"].map((path) => ({ endpoint: `${urlFor(path)}?value=${ng2Canary}`, method: "POST", source: "html" }))], graphQlEndpoints: [urlFor("/graphql")] },
    requestAudit: publicPaths.map((path) => ({ requestedUrl: urlFor(path), finalUrl: urlFor(path), method: path === "/graphql" ? "POST" : "GET", outcome: "sent", statusCode: 200, requestHeaders: {}, redirectChain: [], source: "http" })),
    responses: publicPaths.map((path) => ({ requestedUrl: urlFor(path), finalUrl: urlFor(path), method: path === "/graphql" ? "POST" : "GET", statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", bodyHash: "a".repeat(64), responseTimeMs: 1, redirectChain: [] })),
    apiGraphql: { inventory: [], authorizationMatrices: [], checks: [{ checkId: apiPlan.checks[0]!.id, comparisonFingerprint: apiPlan.checks[0]!.comparisonFingerprint, outcome: "PASS", kind: "OBJECT_AUTHORIZATION", protocols: ["REST"], routeAliases: ["Disposable object"], actorAlias: "Fixture owner", fields: [] }] },
    businessInvariant: { observations: businessPlan.cases.map((item, index) => ({ caseId: item.id, comparisonFingerprint: item.comparisonFingerprint, outcome: "PASS", cleanupOutcome: index === 0 ? "ROLLBACK_VERIFIED" : "CLEANUP_FAILED", preStateVerified: true, postStateVerified: true, actorModel: [], actions: [], invariants: [] })) },
    browserCrawl: { startUrl: ng2Origin, renderedLinks: [], networkRequests: [], consoleErrors: [], formsDetected: 0, formsSubmitted: 0, notes: [], authentication: { fields: [], storage: [], adminRoutes: [], learnedTestCases: [{ id: "learned-logout", source: "browser-learned-traffic", method: "POST", endpoint: `${ng2Origin}/api/logout?token=${ng2Canary}`, observedFieldNames: [], requestSecretBindings: {}, observedStatusCodes: [], responseCookieNames: [], authorizationContext: "BLOCKED_MUTATION_HYPOTHESIS", transmitted: false, suggestedLifecycleCategories: ["LOGOUT_INVALIDATION"], classification: "MUTATION_HYPOTHESIS", state: "DRAFT_REQUIRES_OPERATOR_CASE", executable: false, operatorApprovalRequired: true }] } }
  } as unknown as RouteCairnReport;
}

export function ng2Corpus(slot: "primary" | "account_a" = "primary") {
  const report = ng2Report(slot);
  const inventory = buildAdaptiveInventory(report, []);
  const previous = buildAdaptiveInventory({ ...reportFixture(), target: ng2Origin, scanPlan: {} } as RouteCairnReport, []);
  const drifts = compareAdaptiveInventories(previous, inventory, true);
  return { report, inventory, drifts, recommendations: synthesizeAdaptiveRecommendations(report, inventory, drifts) };
}
