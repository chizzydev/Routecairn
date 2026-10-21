import { it, expect } from "vitest";
import { prepareProductionWebCampaign } from "../../src/cli/commands/webAssessment.js";
import { projectProductionDiscovery } from "../../src/intelligence/inventory/ProductionApplicationDiscovery.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
it.each([0, 1])("does not label attempted browser navigation as rendered coverage (sent=%s)", (sent) => {
  const input = prepareProductionWebCampaign("https://owned.example.test/", "Owned coverage fixture");
  const report = {
    target: input.entryUrl,
    responses: [],
    requestAudit: [],
    findings: [],
    scanPlan: {},
    browserCrawl: {
      visitedPages: [{ url: input.entryUrl, depth: 0 }],
      formsDetected: 0,
      formsSubmitted: 0,
      networkRequests: sent
        ? [{ url: input.entryUrl, method: "GET", resourceType: "document", transmitted: true }]
        : [],
      policyEvents: sent ? [] : [{ reason: "REQUEST_DISPATCH_POLICY_DENIED", transmitted: false }],
      networkIsolation: { state: "HEALTHY", connectionsAllowed: sent }
    }
  } as unknown as RouteCairnReport;
  const out = projectProductionDiscovery(report, input.authorization, "a".repeat(64));
  expect(out.browser?.coverage).toBe(sent ? "PARTIAL_NATIVE_BROWSER_OBSERVATION" : "UNTESTED_NO_TRANSMISSION");
  expect(out.browser?.transmittedRequests).toBe(sent);
  expect(out.applicationSecureConclusion).toBe(false);
});

it("accepts an omitted optional policy-event collection without claiming browser coverage", () => {
  const input = prepareProductionWebCampaign("https://owned.example.test/", "Owned optional event fixture");
  const report = {
    target: input.entryUrl,
    responses: [],
    requestAudit: [],
    findings: [],
    scanPlan: {},
    browserCrawl: { visitedPages: [], formsDetected: 0, formsSubmitted: 0, networkRequests: [] }
  } as unknown as RouteCairnReport;
  const out = projectProductionDiscovery(report, input.authorization, "a".repeat(64));
  expect(out.browser?.policyReasons).toEqual([]);
  expect(out.browser?.coverage).toBe("UNTESTED_NO_TRANSMISSION");
});
