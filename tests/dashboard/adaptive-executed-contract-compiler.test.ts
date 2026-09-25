import { describe, expect, it } from "vitest";
import { compileExecutedContracts, authorizeConfiguration } from "../../src/dashboard/execution/AdaptiveContractCompiler.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

const fingerprint = "a".repeat(64);

describe("adaptive exact executed-contract compiler", () => {
  it("compiles an authenticated object-specific API case without operator case bindings", () => {
    const report = {
      scanPlan: {
        apiGraphql: {
          schemaVersion: 1, enabled: true, targetOrigin: "https://app.test", maxRequests: 10, maxResponseBytes: 65536, maxJsonDepth: 12, maxGraphqlDocumentBytes: 16384, maxGraphqlAliases: 5, maxGraphqlBatchOperations: 3,
          actors: [{ id: "owner", safeAlias: "Owner", authSlot: "primary", relationship: "OWNER", principalFingerprint: "b".repeat(64) }],
          routes: [{ id: "invoice", safeAlias: "Exact invoice", protocol: "REST", kind: "OBJECT", url: "https://app.test/api/invoices/inv_fixture_1", path: "/api/invoices/:id", objectType: "invoice", documented: true, documentedMethods: ["GET"], documentedResponseFields: ["id"], operatorConfirmedNonMutatingPost: false }],
          checks: [{ id: "owner-read", matrixId: "invoice-matrix", label: "Owner reads exact invoice", kind: "OBJECT_AUTHORIZATION", routeId: "invoice", actorId: "owner", requireVerifiedIdentity: false, request: { method: "GET", headers: {} }, response: { expectedDecision: "ALLOW", allowedStatuses: [200], deniedStatuses: [401, 403, 404], fieldRules: [{ path: "id", classification: "OBJECT_IDENTITY", expectation: "MUST_BE_PRESENT" }] }, comparisonFingerprint: fingerprint }], notes: []
        }
      },
      apiGraphql: { checks: [{ checkId: "owner-read", outcome: "PASS", comparisonFingerprint: fingerprint }] }
    } as unknown as RouteCairnReport;
    const [compiled] = compileExecutedContracts(report);
    expect(compiled).toMatchObject({ engineId: "api-graphql-authorization", authentication: "primary", mutationApprovalRequired: false, evidenceStrength: "EXACT_EXECUTED_CONTRACT" });
    expect(compiled?.engineConfiguration).toMatchObject({ actors: [{ authSlot: "primary" }], routes: [{ url: "https://app.test/api/invoices/inv_fixture_1", pathTemplate: "/api/invoices/:id" }], checks: [{ id: "owner-read" }] });
    expect(JSON.stringify(compiled)).not.toContain("principalFingerprint");
  });

  it("compiles a completed business mutation only with verified cleanup and rehydrates fresh approval", () => {
    const planCase = {
      id: "change-plan", label: "Change disposable plan", category: "STATE_TRANSITION",
      actors: [{ id: "owner", safeAlias: "Owner", authSlot: "primary", requestAuthentication: "PROFILE", relationship: "OWNER", declaredState: "ACTIVE" }],
      authorization: { mode: "CONTROLLED_INVARIANT", environment: "STAGING", authorizationIdentityConfirmed: true, changeTicketConfirmed: true, authorizedAt: "2026-01-01T00:00:00.000Z", expiresAt: "2026-01-01T01:00:00.000Z", disposableEntities: true, productionAcknowledged: false, confirmationAccepted: true },
      preState: [{ id: "before", actorId: "owner", request: { method: "GET", url: "https://app.test/fixtures/account", stateChanging: false, headers: {} }, captures: [{ name: "beforePlan", source: "JSON", path: "plan" }] }],
      actions: [{ id: "change", actorId: "owner", request: { method: "POST", url: "https://app.test/fixtures/account/plan", stateChanging: true, headers: {}, bodyFormat: "JSON", fields: { plan: "test_plus" } }, execution: { mode: "ONCE", attempts: 1, maxConcurrency: 1 }, expectation: { authorization: "ALLOW", businessRule: "ACCEPT", authorizationAllowedStatuses: [200, 204], authorizationDeniedStatuses: [401, 403], businessAcceptedStatuses: [200, 204], businessRejectedStatuses: [409, 422] }, captures: [], captureFromAttempt: "LAST" }],
      postState: [{ id: "after", actorId: "owner", request: { method: "GET", url: "https://app.test/fixtures/account", stateChanging: false, headers: {} }, captures: [{ name: "afterPlan", source: "JSON", path: "plan" }] }],
      invariants: [{ id: "changed", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "beforePlan" }, operator: "NEQ", right: { source: "CAPTURE", ref: "afterPlan" } }],
      cleanupRequired: true,
      cleanup: [{ id: "restore", actorId: "owner", request: { method: "POST", url: "https://app.test/fixtures/account/plan", stateChanging: true, headers: {}, bodyFormat: "JSON", fields: { plan: "{{CAPTURE:beforePlan}}" } }, successStatusCodes: [200, 204] }],
      cleanupVerification: [{ id: "restored", actorId: "owner", request: { method: "GET", url: "https://app.test/fixtures/account", stateChanging: false, headers: {} }, captures: [{ name: "restoredPlan", source: "JSON", path: "plan" }] }],
      cleanupInvariants: [{ id: "restored-check", kind: "VALUE_COMPARE", left: { source: "CAPTURE", ref: "beforePlan" }, operator: "EQ", right: { source: "CAPTURE", ref: "restoredPlan" } }],
      comparisonFingerprint: fingerprint
    };
    const report = { scanPlan: { businessInvariant: { schemaVersion: 1, enabled: true, targetOrigin: "https://app.test", maxCases: 1, maxRequests: 8, maxResponseBytes: 32768, maxConcurrency: 1, cases: [planCase], notes: [] } }, businessInvariant: { observations: [{ caseId: "change-plan", outcome: "PASS", cleanupOutcome: "ROLLBACK_VERIFIED", comparisonFingerprint: fingerprint }] } } as unknown as RouteCairnReport;
    const [compiled] = compileExecutedContracts(report);
    expect(compiled).toMatchObject({ engineId: "business-invariant", authentication: "primary", mutationApprovalRequired: true, cleanupRequestCount: 2 });
    const authorized = authorizeConfiguration(compiled!.engineConfiguration, { reviewedAt: "2026-09-20T10:00:00.000Z", reviewedBy: "owner-user", rationale: "CHG-42 approved disposable fixture replay", expiresAt: "2026-09-20T14:00:00.000Z" });
    expect((authorized.cases as any[])[0].authorization).toMatchObject({ confirmation: "I_AUTHORIZE_CONTROLLED_BUSINESS_INVARIANT_TESTING", authorizedBy: "owner-user", changeTicket: "CHG-42 approved disposable fixture replay" });
  });

  it("rejects mutation evidence when cleanup was not verified", () => {
    const unsafe = { scanPlan: { businessInvariant: { cases: [{ id: "x", cleanupRequired: true, comparisonFingerprint: fingerprint }] } }, businessInvariant: { observations: [{ caseId: "x", outcome: "PASS", cleanupOutcome: "CLEANUP_FAILED", comparisonFingerprint: fingerprint }] } } as unknown as RouteCairnReport;
    expect(compileExecutedContracts(unsafe)).toEqual([]);
  });
});
