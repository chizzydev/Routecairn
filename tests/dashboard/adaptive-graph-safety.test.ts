import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { buildAdaptiveAttackStateGraph } from "../../src/dashboard/execution/AdaptiveAttackStateGraph.js";
import { exactAdaptiveResponse } from "../../src/dashboard/execution/AdaptiveEvidenceSafety.js";
import { compileRouteReadOnlyCase, compileSupabaseReadOnlyCase } from "../../src/dashboard/execution/AdaptiveReadOnlyCompiler.js";
import { reportFixture } from "../helpers/assisted-review.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

const fingerprint = "a".repeat(64);
function report(extra: unknown): RouteCairnReport { return { ...reportFixture(), target: "https://app.test", scanPlan: {}, ...extra as object } as RouteCairnReport; }
function exchange(url: string) {
  return { audit: { requestedUrl: url, finalUrl: url, method: "GET", outcome: "sent" as const, statusCode: 200, requestHeaders: {}, redirectChain: [] }, response: { requestedUrl: url, finalUrl: url, method: "GET" as const, statusCode: 200, headers: {}, responseTimeMs: 1, redirectChain: [] } };
}
function workflow(cleanupOutcome = "ROLLBACK_VERIFIED", field = "{{CAPTURE:before}}", outcome = "PASS"): RouteCairnReport {
  const step = (id: string, method: string, captures: unknown[] = [], fields = {}) => ({ id, actorId: "owner", request: { method, url: `/fixture/${id}`, stateChanging: method !== "GET", fields }, captures });
  return report({ scanPlan: { businessInvariant: { cases: [{ id: "workflow", comparisonFingerprint: fingerprint, actors: [{ id: "owner", authSlot: "primary" }], preState: [step("before", "GET", [{ name: "before", source: "JSON" }])], actions: [step("action", "POST", [{ name: "after", source: "JSON" }], { value: field })], postState: [step("verify", "GET")], cleanup: [step("cleanup", "DELETE")], cleanupVerification: [step("restored", "GET")], cleanupRequired: true }] } }, businessInvariant: { observations: [{ comparisonFingerprint: fingerprint, outcome, cleanupOutcome, actorModel: [] }] } });
}

describe("attack graph evidence and execution boundaries", () => {
  it.each(["https://app.test/objects/123?view=one", "https://app.test/objects/456?view=one", "https://app.test/objects/123?view=two"])("does not conflate exact request identity for %s", (responseUrl) => {
    const { audit } = exchange("https://app.test/objects/123?view=one");
    const { response } = exchange(responseUrl);
    const graph = buildAdaptiveAttackStateGraph(report({ requestAudit: [audit], responses: [response] }));
    expect(graph.paths[0]?.automationState).toBe(responseUrl === audit.requestedUrl ? "READ_ONLY_AUTO_COMPILE_CANDIDATE" : "EVIDENCE_ONLY");
  });

  it("requires request ID correlation when multiple actors request the same endpoint", () => {
    const { audit, response } = exchange("https://app.test/profile");
    const privateAudit = { ...audit, requestHeaders: { Authorization: "<redacted>" } };
    expect(exactAdaptiveResponse(audit, [audit, privateAudit], [response], "https://app.test")).toBeUndefined();
    const publicAudit = { ...audit, requestId: "public" };
    expect(exactAdaptiveResponse(publicAudit, [publicAudit, privateAudit], [{ ...response, requestId: "private" }], "https://app.test")).toBeUndefined();
    expect(exactAdaptiveResponse(publicAudit, [publicAudit, privateAudit], [{ ...response, requestId: "public" }], "https://app.test")).toBeDefined();
  });

  it("keeps authenticated and browser requests out of anonymous automation", () => {
    const { audit, response } = exchange("https://app.test/profile");
    for (const altered of [{ ...audit, requestHeaders: { "X-Auth-Token": "redacted" } }, { ...audit, source: "browser" as const }]) {
      const input = report({ requestAudit: [altered], responses: [response] });
      expect(buildAdaptiveAttackStateGraph(input).paths[0]?.automationState).toBe("EVIDENCE_ONLY");
      expect(compileRouteReadOnlyCase(input, { protocol: "REST", method: "GET", pathTemplate: "/profile", source: "api-mapper", stateChanging: false })).toBeUndefined();
    }
  });

  it("recognizes configured proprietary credential headers", () => {
    const { audit, response } = exchange("https://app.test/profile");
    const input = report({ authenticatedScan: { profile: { headerNames: ["X-Workspace-Credential"] } }, requestAudit: [{ ...audit, requestHeaders: { "X-Workspace-Credential": "private-fixture-value" } }], responses: [response] });
    expect(buildAdaptiveAttackStateGraph(input).paths[0]?.automationState).toBe("EVIDENCE_ONLY");
    expect(compileRouteReadOnlyCase(input, { protocol: "REST", method: "GET", pathTemplate: "/profile", source: "api-mapper", stateChanging: false })).toBeUndefined();
  });

  it("never promotes invalid methods, invalid URLs or GraphQL mutations to read-only automation", () => {
    const input = report({ apiMapper: { endpoints: [{ method: "", endpoint: "https://app.test/unknown" }, { method: "GET", endpoint: "http://[" }, { method: "GET", endpoint: "file:///private" }], graphQlEndpoints: [] }, scanPlan: { apiGraphql: { actors: [], routes: [{ id: "graphql", protocol: "GRAPHQL", url: "https://app.test/graphql", documentedMethods: ["POST"] }], checks: [{ comparisonFingerprint: fingerprint, routeId: "graphql", request: { method: "POST", graphql: { document: "mutation { deleteAccount }" } } }] } }, apiGraphql: { checks: [{ comparisonFingerprint: fingerprint, outcome: "PASS" }] } });
    const graph = buildAdaptiveAttackStateGraph(input);
    expect(graph.paths.find((path) => path.sourceCaseFingerprints.includes(fingerprint))).toMatchObject({ mutability: "STATE_CHANGING", automationState: "STATE_CHANGE_PROPOSED" });
    expect(graph.nodes.filter((node) => node.kind === "ROUTE")).toHaveLength(2);
    expect(graph.nodes.find((node) => node.label === "UNKNOWN /unknown")?.attributes.stateChanging).toBe(true);
  });

  it.each(["UNVERIFIED", "NOT_VERIFIED", "FAILED_VERIFIED", "NOT_REQUIRED", "CLEANUP_FAILED"])("requires real cleanup verification for %s", (outcome) => {
    const path = buildAdaptiveAttackStateGraph(workflow(outcome)).paths.find((item) => item.sourceCaseFingerprints.includes(fingerprint));
    expect(path).toMatchObject({ contractReadiness: "REQUIRES_BINDINGS", mutability: "STATE_CHANGING" });
    expect(path?.requiredBindings).toContain("verified cleanup evidence");
  });

  it.each(["missing", "after"])("requires an earlier producer for %s", (capture) => {
    const graph = buildAdaptiveAttackStateGraph(workflow("ROLLBACK_VERIFIED", `{{CAPTURE:${capture}}}`));
    const path = graph.paths.find((item) => item.sourceCaseFingerprints.includes(fingerprint));
    expect(path?.requiredBindings).toContain(`prior producer for capture ${capture}`);
    for (const edge of graph.edges.filter((item) => item.kind === "CONSUMES")) expect(graph.edges.some((item) => item.kind === "PRODUCES" && item.from === edge.from && item.to === edge.to)).toBe(false);
  });

  it.each(["", "NOT_OBSERVED", "UNKNOWN", "NOT_ASSESSED"])("does not treat %s as completed contract evidence", (outcome) => {
    expect(buildAdaptiveAttackStateGraph(workflow("ROLLBACK_VERIFIED", "{{CAPTURE:before}}", outcome)).paths.find((item) => item.sourceCaseFingerprints.includes(fingerprint))?.requiredBindings).toContain("conclusive executed contract");
  });

  it("keeps origin identities separate and rejects foreign-origin route compilation", () => {
    const { audit, response } = exchange("https://app.test/profile");
    const input = report({ requestAudit: [audit], responses: [response], apiMapper: { endpoints: [{ method: "GET", endpoint: "https://other.test/profile" }], graphQlEndpoints: [] } });
    expect(buildAdaptiveAttackStateGraph(input).nodes.filter((node) => node.kind === "OPERATION")).toHaveLength(2);
    expect(compileRouteReadOnlyCase(input, { origin: "https://other.test", protocol: "REST", method: "GET", pathTemplate: "/profile", source: "api-mapper", stateChanging: false })).toBeUndefined();
  });

  it("keeps truncated paths closed and requires completion before replay", () => {
    const input = workflow();
    const testCase = (input.scanPlan.businessInvariant!.cases[0] as any);
    testCase.preState.push(...Array.from({ length: 60 }, (_, index) => ({ id: `read-${index}`, actorId: "owner", request: { method: "GET", url: `/fixture/read-${index}`, stateChanging: false }, captures: [] })));
    const graph = buildAdaptiveAttackStateGraph(input);
    const path = graph.paths.find((item) => item.sourceCaseFingerprints.includes(fingerprint))!;
    expect(graph.bounds.truncated).toBe(true);
    expect(path.contractReadiness).toBe("REQUIRES_BINDINGS");
    expect(path.requiredBindings).toContain("complete bounded graph path");
    expect(path.nodeIds.length).toBeLessThanOrEqual(100);
    for (const edgeId of path.edgeIds) { const edge = graph.edges.find((item) => item.id === edgeId)!; expect(path.nodeIds).toContain(edge.from); expect(path.nodeIds).toContain(edge.to); }
  });

  it("preserves declared step order when validating producer dependencies", () => {
    const input = report({ scanPlan: { authenticationLifecycle: { cases: [{ id: "ordering", comparisonFingerprint: fingerprint, actors: [], steps: [{ id: "first", phase: "ACTION", request: { method: "POST", url: "/consume", fields: { token: "{{CAPTURE:later}}" } } }, { id: "second", phase: "SETUP", request: { method: "GET", url: "/produce" }, captures: [{ name: "later", source: "JSON" }] }] }] } } });
    const path = buildAdaptiveAttackStateGraph(input).paths.find((item) => item.sourceCaseFingerprints.includes(fingerprint));
    expect(path?.requiredBindings).toContain("prior producer for capture later");
  });

  it("rejects inconclusive Supabase observations", () => {
    const input = report({ supabaseAuthorization: { projectOrigin: "https://project.supabase.co", observations: [{ operation: "SELECT", actor: "ANONYMOUS", method: "GET", resource: "articles", url: "/rest/v1/articles", comparisonFingerprint: fingerprint, observedDecision: "EXECUTION_ERROR" }], resourceCoverage: [] } });
    expect(compileSupabaseReadOnlyCase(input, { surface: "TABLE", resource: "articles", operations: ["SELECT"], actors: ["ANONYMOUS"] })).toBeUndefined();
  });

  it("retains no supplied token values or malformed identity digests", () => {
    const input = workflow();
    (input as any).browserCrawl = { startUrl: "https://app.test/", authentication: { storage: [{ origin: "https://app.test", storage: "cookie", name: "session", classification: "authentication", valueDigest: "raw-private-digest" }] } };
    (input as any).apiMapper = { endpoints: [{ method: "GET", endpoint: "https://app.test/reset-password/private-canary" }], graphQlEndpoints: [] };
    const graph = buildAdaptiveAttackStateGraph(input);
    expect(JSON.stringify(graph)).not.toMatch(/raw-private-digest|private-canary/);
  });

  it("preserves graph closure and bounds over generated route inventories", () => {
    fc.assert(fc.property(fc.array(fc.record({ method: fc.constantFrom("GET", "POST", "DELETE", "invalid method"), origin: fc.constantFrom("https://app.test", "https://other.test"), name: fc.stringMatching(/^[a-z]{1,16}$/) }), { maxLength: 800 }), (routes) => {
      const graph = buildAdaptiveAttackStateGraph(report({ apiMapper: { endpoints: routes.map((route) => ({ method: route.method, endpoint: `${route.origin}/${route.name}` })), graphQlEndpoints: [] } }));
      const ids = new Set(graph.nodes.map((node) => node.id));
      expect(graph.nodes.length).toBeLessThanOrEqual(graph.bounds.maxNodes);
      for (const edge of graph.edges) { expect(ids.has(edge.from)).toBe(true); expect(ids.has(edge.to)).toBe(true); }
      for (const path of graph.paths) for (const edgeId of path.edgeIds) { const edge = graph.edges.find((item) => item.id === edgeId)!; expect(path.nodeIds).toContain(edge.from); expect(path.nodeIds).toContain(edge.to); }
    }), { seed: 20261002, numRuns: 50 });
    const graph = buildAdaptiveAttackStateGraph(workflow());
    for (const path of graph.paths) for (const edgeId of path.edgeIds) { const edge = graph.edges.find((item) => item.id === edgeId)!; expect(path.nodeIds).toContain(edge.from); expect(path.nodeIds).toContain(edge.to); }
  });
});
