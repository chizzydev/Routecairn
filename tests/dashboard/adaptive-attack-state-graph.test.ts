import { describe, expect, it } from "vitest";
import { buildAdaptiveAttackStateGraph } from "../../src/dashboard/execution/AdaptiveAttackStateGraph.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { reportFixture } from "../helpers/assisted-review.js";

describe("adaptive attack-state graph", () => {
  it("builds bounded evidence-backed actors, assets, transitions, and request dependencies", () => {
    const fingerprint = "a".repeat(64);
    const report = {
      ...reportFixture(),
      target: "https://app.test",
      apiMapper: { endpoints: [{ method: "GET", endpoint: "https://app.test/api/objects/:id?view=summary" }, { method: "POST", endpoint: "https://app.test/api/objects/:id/share" }], graphQlEndpoints: [], websocketEndpoints: [], rpcEndpoints: [], documentationUrls: [] },
      requestAudit: [{ requestedUrl: "https://app.test/api/objects/:id?view=summary", finalUrl: "https://app.test/api/objects/:id?view=summary", method: "GET", outcome: "sent", statusCode: 200, requestHeaders: {}, redirectChain: [], source: "http" }],
      responses: [{ requestedUrl: "https://app.test/api/objects/:id?view=summary", finalUrl: "https://app.test/api/objects/:id?view=summary", method: "GET", statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", bodyHash: "b".repeat(64), responseTimeMs: 3, redirectChain: [] }],
      objectPairTesting: { cases: [{ caseId: "object-ownership", objectType: "document", expectedVisibility: "owner-only", baselineA: { objectIdHash: "c".repeat(64) }, baselineB: { objectIdHash: "d".repeat(64) } }] },
      browserCrawl: {
        startUrl: "https://app.test/home",
        visitedPages: [{ url: "https://app.test/documents", depth: 1 }],
        renderedLinks: [], networkRequests: [], consoleErrors: [], formsDetected: 0, formsSubmitted: 0, notes: [],
        authentication: {
          learnedTestCases: [{ id: "share-document", source: "browser-learned-traffic", method: "POST", endpoint: "https://app.test/api/objects/:id/share", observedFieldNames: ["recipient"], requestSecretBindings: {}, observedStatusCodes: [], responseCookieNames: [], authorizationContext: "BLOCKED_MUTATION_HYPOTHESIS", transmitted: false, suggestedLifecycleCategories: ["INVITATION_ACCEPTANCE"], classification: "MUTATION_HYPOTHESIS", state: "DRAFT_REQUIRES_OPERATOR_CASE", executable: false, operatorApprovalRequired: true }],
          storage: [{ origin: "https://app.test", storage: "cookie", name: "session", valueLength: 64, valueDigest: "e".repeat(64), classification: "authentication", httpOnly: true, secure: true }],
          fields: [], adminRoutes: []
        }
      },
      scanPlan: {
        businessInvariant: {
          cases: [{
            id: "share-workflow", comparisonFingerprint: fingerprint,
            actors: [{ id: "owner", safeAlias: "Owner", authSlot: "primary", declaredState: "authenticated", relationship: "owner", tenantAlias: "Tenant A" }],
            preState: [{ id: "before", actorId: "owner", request: { method: "GET", urlTemplate: "/api/objects/:id", stateChanging: false, headers: { Authorization: "Bearer raw-secret-must-not-survive" } }, captures: [{ name: "document_token", source: "JSON", path: "$.token" }] }],
            actions: [{ id: "share", actorId: "owner", request: { method: "POST", urlTemplate: "/api/objects/:id/share", stateChanging: true, headers: { "X-Document": "{{CAPTURE:document_token}}" } }, captures: [{ name: "invitation", source: "HEADER", header: "Location" }] }],
            postState: [{ id: "after", actorId: "owner", request: { method: "GET", urlTemplate: "/api/objects/:id", stateChanging: false, headers: {} }, captures: [] }],
            cleanup: [{ id: "cleanup", actorId: "owner", request: { method: "DELETE", urlTemplate: "/api/objects/:id/share", stateChanging: true, headers: { "X-Invite": "{{CAPTURE:invitation}}" } }, captures: [] }],
            cleanupVerification: [{ id: "verify-cleanup", actorId: "owner", request: { method: "GET", urlTemplate: "/api/objects/:id", stateChanging: false, headers: {} }, captures: [] }]
          }]
        }
      },
      businessInvariant: { observations: [{ caseId: "share-workflow", comparisonFingerprint: fingerprint, outcome: "PASS", cleanupOutcome: "ROLLBACK_VERIFIED", actorModel: [{ safeAlias: "Owner", authSlot: "primary", declaredState: "authenticated", relationship: "owner", tenantAlias: "Tenant A" }], actions: [], invariants: [] }] }
    } as unknown as RouteCairnReport;

    const graph = buildAdaptiveAttackStateGraph(report);
    const kinds = new Set(graph.nodes.map((node) => node.kind));
    for (const kind of ["ACTOR", "ROLE", "TENANT", "OBJECT", "ROUTE", "PARAMETER", "OPERATION", "BROWSER_STATE", "CAPABILITY", "PRECONDITION", "EFFECT", "CLEANUP"]) expect(kinds).toContain(kind);
    for (const kind of ["OWNS", "PERFORMS", "PRODUCES", "CONSUMES", "REQUIRES", "EFFECTS", "CLEANED_BY", "TRANSITIONS_TO"]) expect(graph.edges.some((edge) => edge.kind === kind)).toBe(true);
    expect(graph.paths).toEqual(expect.arrayContaining([
      expect.objectContaining({ mutability: "READ_ONLY", automationState: "READ_ONLY_AUTO_COMPILE_CANDIDATE", contractReadiness: "COMPLETE" }),
      expect.objectContaining({ mutability: "STATE_CHANGING", automationState: "STATE_CHANGE_PROPOSED", contractReadiness: "COMPLETE", sourceCaseFingerprints: [fingerprint] })
    ]));
    expect(graph.bounds).toMatchObject({ maxNodes: 1200, maxEdges: 3000, maxPaths: 500, truncated: false });
    expect(graph.graphFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(buildAdaptiveAttackStateGraph(report).graphFingerprint).toBe(graph.graphFingerprint);
    expect(JSON.stringify(graph)).not.toMatch(/raw-secret-must-not-survive|Bearer /i);
  });

  it("caps graph growth and records truncation", () => {
    const graph = buildAdaptiveAttackStateGraph({
      ...reportFixture(), target: "https://app.test",
      apiMapper: { endpoints: Array.from({ length: 1_300 }, (_, index) => ({ method: "GET", endpoint: `https://app.test/api/generated/route-${index}` })), graphQlEndpoints: [], websocketEndpoints: [], rpcEndpoints: [], documentationUrls: [] }
    } as unknown as RouteCairnReport);
    expect(graph.bounds.truncated).toBe(true);
    expect(graph.nodes.length).toBeLessThanOrEqual(graph.bounds.maxNodes);
    expect(graph.edges.length).toBeLessThanOrEqual(graph.bounds.maxEdges);
    expect(graph.paths.length).toBeLessThanOrEqual(graph.bounds.maxPaths);
  });

  it("separates a proven generated GraphQL read from an otherwise unknown POST transition", () => {
    const url = "https://app.test/graphql";
    const graph = buildAdaptiveAttackStateGraph({
      ...reportFixture(), target: "https://app.test",
      apiMapper: { endpoints: [{ method: "POST", endpoint: url }], graphQlEndpoints: [url], websocketEndpoints: [], rpcEndpoints: [], documentationUrls: [] },
      requestAudit: [{ requestedUrl: url, finalUrl: url, method: "POST", outcome: "sent", statusCode: 200, requestHeaders: {}, redirectChain: [], source: "http" }],
      responses: [{ requestedUrl: url, finalUrl: url, method: "POST", statusCode: 200, headers: { "content-type": "application/json" }, contentType: "application/json", bodyHash: "f".repeat(64), responseTimeMs: 2, redirectChain: [] }]
    } as unknown as RouteCairnReport);
    expect(graph.paths).toEqual(expect.arrayContaining([
      expect.objectContaining({ label: "GraphQL introspection /graphql", mutability: "READ_ONLY", automationState: "READ_ONLY_AUTO_COMPILE_CANDIDATE" }),
      expect.objectContaining({ label: "POST /graphql", mutability: "STATE_CHANGING", automationState: "STATE_CHANGE_PROPOSED" })
    ]));
  });
});
