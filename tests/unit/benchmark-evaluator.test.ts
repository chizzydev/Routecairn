import { describe, expect, it } from "vitest";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";
import { evaluateBenchmark } from "../../src/benchmark/BenchmarkEvaluator.js";

describe("benchmark evaluator", () => {
  it("measures quality, coverage, efficiency, unexpected findings, and required-case gates", () => {
    const result = evaluateBenchmark(manifest(), [{ report: report(), telemetry: { runtimeMs: 100, peakRssBytes: 1_000, requestCount: 10, transmittedRequestCount: 8 } }]);
    expect(result.confusion).toMatchObject({ truePositive: 1, falseNegative: 1, falsePositive: 1, trueNegative: 1, inconclusive: 1, uncovered: 1, unexpectedFindings: 1 });
    expect(result.metrics).toMatchObject({ recall: 0.25, falsePositiveRate: 0.5, inconclusiveRate: 0.2, coverageCompleteness: 0.8, conclusiveCoverage: 0.6, stabilityRate: 1 });
    expect(result.efficiency.requestsPerAssessedCase.mean).toBeCloseTo(10 / 3);
    expect(result.gates.find((gate) => gate.id === "required-case/missed")?.passed).toBe(false);
    expect(result.status).toBe("FAILED");
  });

  it("detects case and performance regressions against a compatible baseline", () => {
    const baselineManifest = { ...manifest(), cases: manifest().cases.slice(0, 2), thresholds: { minRecall: 0, maxFalsePositiveRate: 1, maxInconclusiveRate: 1, minCoverageCompleteness: 0 } };
    const baseline = evaluateBenchmark(baselineManifest, [{ report: report(), telemetry: { runtimeMs: 100, peakRssBytes: 1000, requestCount: 10 } }]);
    const changed = report(); changed.apiGraphql!.checks = changed.apiGraphql!.checks.map((item) => item.checkId === "positive" ? { ...item, outcome: "PASS" } : item) as never; changed.findings = changed.findings.filter((item) => item.workflow?.caseId !== "positive");
    const current = evaluateBenchmark(baselineManifest, [{ report: changed, telemetry: { runtimeMs: 200, peakRssBytes: 2000, requestCount: 20 } }], { baseline });
    expect(current.regressions.find((gate) => gate.id === "case-regressions")?.passed).toBe(false);
    expect(current.regressions.find((gate) => gate.id === "runtime-increase")?.passed).toBe(false);
    expect(current.status).toBe("FAILED");
  });
});

function manifest() {
  const truth = (id: string, expected: "FINDING" | "NO_FINDING", required = false) => ({ id, label: id, expected, selectors: [{ workflowId: "api-graphql-authorization", caseId: id }], tags: [], required });
  return { schemaVersion: 1 as const, id: "evaluator-fixture", label: "Evaluator fixture", cases: [truth("positive", "FINDING", true), truth("negative", "NO_FINDING", true), truth("missed", "FINDING", true), truth("uncertain", "FINDING"), truth("absent", "FINDING")], thresholds: { minRecall: 1, maxFalsePositiveRate: 0, maxInconclusiveRate: 0, minCoverageCompleteness: 1 }, regression: { maxRecallDrop: 0, maxFalsePositiveRateIncrease: 0, maxInconclusiveRateIncrease: 0, maxCoverageDrop: 0, maxRuntimeIncreaseRatio: 0.25, maxMemoryIncreaseRatio: 0.25, maxRequestIncreaseRatio: 0.25, failOnCaseRegression: true }, metadata: {} };
}

function report(): RouteCairnReport {
  const check = (checkId: string, outcome: "PASS" | "FAIL" | "INCONCLUSIVE") => ({ checkId, label: checkId, outcome, comparisonFingerprint: checkId });
  return {
    routeCairnVersion: "0.1.0",
    findings: [finding("positive"), finding("unexpected")],
    apiGraphql: { checks: [check("positive", "FAIL"), check("negative", "PASS"), check("missed", "PASS"), check("uncertain", "INCONCLUSIVE")], schemaComparisons: [] },
    requestAudit: [], metadata: { startedAt: "2026-01-01T00:00:00Z", completedAt: "2026-01-01T00:00:00Z", durationMs: 0, totalRequests: 0, failedRequests: 0 }
  } as unknown as RouteCairnReport;
}
function finding(caseId: string) { return { id: `finding-${caseId}`, type: "API Authorization Issue", sourceModule: "api-graphql-authorization", workflow: { workflowId: "api-graphql-authorization", caseId }, workflowCase: { id: caseId } } as never; }
