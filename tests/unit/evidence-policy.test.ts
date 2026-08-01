import { describe, expect, it } from "vitest";
import { ScanState } from "../../src/core/engine/ScanState.js";
import type { Finding } from "../../src/core/findings/Finding.js";
import type { HttpResponse } from "../../src/core/http/HttpTypes.js";
import { testPlan } from "../helpers/plan.js";

describe("evidence policy enforcement", () => {
  it("strips body previews from minimal evidence reports", () => {
    const state = stateWithEvidence();
    const report = state.toReport(testPlan("quick"));

    expect(report.responses[0]).not.toHaveProperty("bodyPreview");
    expect(report.discoveredUrls[0]).not.toHaveProperty("bodyPreview");
    expect(report.findings[0]?.evidence).not.toHaveProperty("bodyPreview");
    expect(report.requestAudit).toHaveLength(1);
    expect(JSON.stringify(report)).not.toContain("secret=value");
    expect(JSON.stringify(report)).not.toContain("session=server-secret");
  });

  it("retains redacted body previews for normal evidence reports", () => {
    const state = stateWithEvidence();
    const report = state.toReport(testPlan("full"));

    expect(report.responses[0]?.bodyPreview).toContain("secret=<redacted>");
    expect(report.discoveredUrls[0]?.bodyPreview).toContain("secret=<redacted>");
    expect(report.findings[0]?.evidence.bodyPreview).toContain("secret=<redacted>");
    expect(JSON.stringify(report)).not.toContain("secret=value");
    expect(JSON.stringify(report)).not.toContain("session=server-secret");
  });

  it("uses strong evidence policy for proof plans", () => {
    const plan = testPlan("proof");

    expect(plan.evidence.level).toBe("strong");
    expect(plan.evidence.requireReproducibleEvidence).toBe(true);
    expect(plan.evidence.retainProofBlocks).toBe(true);
    expect(plan.limits.bodyPreviewBytes).toBeGreaterThan(testPlan("full").limits.bodyPreviewBytes);
  });
});

function stateWithEvidence(): ScanState {
  const state = new ScanState();
  const response: HttpResponse = {
    requestedUrl: "https://example.test/.env",
    finalUrl: "https://example.test/.env",
    method: "GET",
    statusCode: 200,
    headers: { "set-cookie": "session=server-secret; HttpOnly" },
    bodyPreview: "secret=value",
    bodyHash: "hash",
    responseTimeMs: 12,
    redirectChain: [],
    contentLength: 12,
    contentType: "text/plain"
  };
  state.recordResponse(response);
  state.recordDiscoveredUrls([
    {
      url: response.finalUrl,
      method: response.method,
      source: "test",
      statusCode: 200,
      bodyPreview: "secret=value",
      responseTimeMs: 12,
      falsePositiveStatus: "likely-valid",
      classificationReason: "test"
    }
  ]);
  state.recordFindings([finding()]);
  state.recordRequestAudit({
    requestedUrl: response.requestedUrl,
    finalUrl: response.finalUrl,
    method: "GET",
    outcome: "sent",
    requestHeaders: {},
    redirectChain: []
  });
  return state;
}

function finding(): Finding {
  return {
    id: "finding-test",
    title: "Test",
    type: "Sensitive File Exposure",
    severity: "High",
    confidence: "High",
    url: "https://example.test/.env",
    method: "GET",
    statusCode: 200,
    evidence: {
      url: "https://example.test/.env",
      method: "GET",
      statusCode: 200,
      source: "test",
      bodyPreview: "secret=value"
    },
    impact: "test",
    recommendation: "test",
    manualTestingSuggestions: [],
    tags: ["test"],
    riskScore: 10,
    sourceModule: "test",
    falsePositiveStatus: "likely-valid",
    timestamp: "2026-01-01T00:00:00.000Z"
  };
}
