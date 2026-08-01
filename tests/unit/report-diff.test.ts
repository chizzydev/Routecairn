import { describe, expect, it } from "vitest";
import { ReportDiffer } from "../../src/modules/changeMonitor/ReportDiffer.js";
import type { Finding } from "../../src/core/findings/Finding.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { summarizeReport } from "../../src/reports/ReportSummary.js";

describe("ReportDiffer", () => {
  it("compares URLs, findings, technologies, endpoints, and auth surfaces", () => {
    const oldReport = report({
      urls: [
        ["https://example.com/old", 200],
        ["https://example.com/changed", 200]
      ],
      findings: [finding("Old finding", "https://example.com/old", "Low")],
      technologies: ["Next.js"],
      jsEndpoints: ["/api/old"],
      apiEndpoints: ["https://example.com/api/old"],
      authSurfaces: ["https://example.com/login"]
    });
    const newReport = report({
      urls: [
        ["https://example.com/new", 200],
        ["https://example.com/changed", 500]
      ],
      findings: [finding("New finding", "https://example.com/new", "High"), finding("Severity finding", "https://example.com/changed", "High")],
      technologies: ["Next.js", "Cloudflare"],
      jsEndpoints: ["/api/new"],
      apiEndpoints: ["https://example.com/api/new"],
      authSurfaces: ["https://example.com/reset-password"]
    });
    oldReport.findings.push(finding("Severity finding", "https://example.com/changed", "Low"));

    const diff = new ReportDiffer().diff(oldReport, newReport);

    expect(diff.urls.new).toEqual(["https://example.com/new"]);
    expect(diff.urls.removed).toEqual(["https://example.com/old"]);
    expect(diff.urls.changedStatuses).toEqual([{ url: "https://example.com/changed", oldStatus: 200, newStatus: 500 }]);
    expect(diff.findings.new.some((item) => item.title === "New finding")).toBe(true);
    expect(diff.findings.resolved.some((item) => item.title === "Old finding")).toBe(true);
    expect(diff.findings.severityChanges).toEqual([
      {
        id: expect.any(String),
        title: "Severity finding",
        url: "https://example.com/changed",
        oldSeverity: "Low",
        newSeverity: "High"
      }
    ]);
    expect(diff.technologies.new).toEqual(["Cloudflare"]);
    expect(diff.jsEndpoints.new).toEqual(["/api/new"]);
    expect(diff.apiEndpoints.new).toEqual(["https://example.com/api/new"]);
    expect(diff.authSurfaces.new).toEqual(["https://example.com/reset-password"]);
  });

  it("summarizes reports cleanly", () => {
    const summary = summarizeReport(
      report({
        urls: [["https://example.com/admin", 200]],
        findings: [finding("Admin", "https://example.com/admin", "Medium")],
        technologies: ["Next.js"],
        jsEndpoints: ["/api/admin"],
        apiEndpoints: ["https://example.com/api/admin"],
        authSurfaces: ["https://example.com/login"]
      })
    );

    expect(summary.findingsBySeverity.Medium).toBe(1);
    expect(summary.technologies).toEqual(["Next.js"]);
    expect(summary.apiEndpoints).toEqual(["https://example.com/api/admin"]);
  });
});

function report(input: {
  urls: Array<[string, number]>;
  findings: Finding[];
  technologies: string[];
  jsEndpoints: string[];
  apiEndpoints: string[];
  authSurfaces: string[];
}): RouteCairnReport {
  return {
    routeCairnVersion: "0.1.0",
    target: "https://example.com/",
    mode: "quick",
    program: "Test",
    scope: {
      allowedDomains: ["example.com"],
      disallowedPaths: [],
      allowedMethods: ["GET"],
      rateLimitPerSecond: 10,
      concurrency: 2,
      sameOriginOnly: true,
      includeSubdomains: true
    },
    metadata: {
      startedAt: "2026-01-01T00:00:00.000Z",
      completedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      totalRequests: input.urls.length,
      failedRequests: 0
    },
    scopeDecisions: [],
    responses: [],
    technologies: input.technologies.map((name) => ({ name, category: "framework", confidence: "High", signals: [] })),
    jsIntelligence: {
      scripts: [],
      queuedEndpoints: input.jsEndpoints.map((path) => ({ path, source: "js:endpoint" })),
      sourceMaps: [],
      notes: []
    },
    apiMapper: {
      endpoints: input.apiEndpoints.map((endpoint) => ({
        endpoint,
        method: "GET",
        routeType: "api",
        riskTags: ["api"],
        likelyManualTests: [],
        authRelevance: "medium",
        hasObjectId: false,
        privilegeSensitivity: "medium",
        dataExposureSensitivity: "medium",
        rateLimitSensitivity: "medium"
      })),
      graphQlEndpoints: [],
      notes: []
    },
    authSurface: {
      surfaces: input.authSurfaces.map((endpoint) => ({
        endpoint,
        purpose: "login",
        abuseCategories: [],
        rateLimitSensitivity: "high",
        accountEnumerationRelevance: "high",
        suggestedTests: []
      })),
      notes: []
    },
    discoveredUrls: input.urls.map(([url, statusCode]) => ({
      url,
      method: "GET",
      source: "test",
      statusCode,
      responseTimeMs: 1,
      falsePositiveStatus: "likely-valid",
      classificationReason: `status ${statusCode}`
    })),
    findings: input.findings
  };
}

function finding(title: string, url: string, severity: Finding["severity"]): Finding {
  return {
    id: `${title}-${url}`,
    title,
    type: "Interesting But Needs Manual Testing",
    severity,
    confidence: "High",
    url,
    method: "GET",
    statusCode: 200,
    evidence: {
      url,
      method: "GET",
      statusCode: 200
    },
    impact: "test",
    recommendation: "test",
    manualTestingSuggestions: [],
    tags: [],
    riskScore: severity === "High" ? 75 : severity === "Medium" ? 50 : 25,
    sourceModule: "test",
    falsePositiveStatus: "likely-valid",
    timestamp: "2026-01-01T00:00:00.000Z"
  };
}
