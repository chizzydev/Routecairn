import { createHash } from "node:crypto";
import type { Finding } from "../core/findings/Finding.js";
import { collectReportAssistedCases } from "../modules/assistedReview/AssistedCaseCollector.js";
import type { RouteCairnReport } from "../reports/ReportTypes.js";
import { benchmarkManifestSchema, benchmarkTelemetrySchema, type BenchmarkClassification, type BenchmarkManifest, type BenchmarkSelector, type BenchmarkTelemetry } from "./BenchmarkSchemas.js";

export interface BenchmarkRunInput { report: RouteCairnReport; telemetry: BenchmarkTelemetry; reportDigest?: string }
export interface BenchmarkCaseRun { run: number; classification: BenchmarkClassification; observed: "FINDING" | "NO_FINDING" | "INCONCLUSIVE" | "UNCOVERED"; matchedFindingIds: string[] }
export interface BenchmarkCaseResult { id: string; label: string; expected: "FINDING" | "NO_FINDING"; category?: string; tags: string[]; required: boolean; runs: BenchmarkCaseRun[]; aggregate: BenchmarkClassification; stable: boolean }
export interface BenchmarkGate { id: string; passed: boolean; actual: number | boolean; expected: string }
export interface BenchmarkRegression { id: string; passed: boolean; actual: number | boolean; expected: string }
export interface BenchmarkCategoryResult { category: string; caseCount: number; positiveCases: number; negativeCases: number; confusion: { truePositive: number; falseNegative: number; falsePositive: number; trueNegative: number; inconclusive: number; uncovered: number }; metrics: { recall: number; falsePositiveRate: number; inconclusiveRate: number; coverageCompleteness: number; stabilityRate: number } }
export interface BenchmarkResult {
  schemaVersion: 1; kind: "ROUTECAIRN_BENCHMARK_RESULT"; benchmarkId: string; label: string; generatedAt: string; release: { label?: string; build?: string; routeCairnVersion: string };
  manifestDigest: string; reportDigests: string[]; repetitions: number;
  runTelemetry: BenchmarkTelemetry[];
  confusion: { truePositive: number; falseNegative: number; falsePositive: number; trueNegative: number; inconclusive: number; uncovered: number; unexpectedFindings: number };
  metrics: { recall: number; precision: number; falsePositiveRate: number; inconclusiveRate: number; coverageCompleteness: number; conclusiveCoverage: number; stabilityRate: number };
  cleanup: { observed: number; passed: number; failed: number; successRate: number };
  categories: BenchmarkCategoryResult[];
  efficiency: { runtimeMs: Distribution; peakRssBytes: Distribution; requestCount: Distribution; transmittedRequestCount: Distribution; requestsPerAssessedCase: Distribution; runtimePerRequestMs: Distribution };
  cases: BenchmarkCaseResult[]; unexpectedFindings: Array<{ run: number; findingId: string; sourceModule: string; findingType: string; workflowId?: string; caseId?: string }>;
  gates: BenchmarkGate[]; regressions: BenchmarkRegression[]; status: "PASSED" | "FAILED";
}
interface Distribution { min: number; median: number; p95: number; max: number; mean: number }

export function evaluateBenchmark(rawManifest: unknown, rawRuns: readonly BenchmarkRunInput[], options: { baseline?: BenchmarkResult; release?: string; build?: string; routeCairnVersion?: string } = {}): BenchmarkResult {
  const manifest = benchmarkManifestSchema.parse(rawManifest);
  if (rawRuns.length === 0) throw new Error("BENCHMARK_RUNS_REQUIRED");
  const runs = rawRuns.map((run) => ({ ...run, telemetry: benchmarkTelemetrySchema.parse(run.telemetry) }));
  if (runs.some((run) => typeof run.report.routeCairnVersion !== "string" || !Array.isArray(run.report.findings) || !Array.isArray(run.report.requestAudit))) throw new Error("BENCHMARK_REPORT_INVALID");
  if (new Set(runs.map((run) => run.report.routeCairnVersion)).size > 1) throw new Error("BENCHMARK_RUN_VERSION_MISMATCH");
  assertUnambiguousSelectors(manifest, runs.map((run) => run.report));
  const unexpectedFindings: BenchmarkResult["unexpectedFindings"] = [];
  const cases = manifest.cases.map((truth): BenchmarkCaseResult => {
    const caseRuns = runs.map((run, index): BenchmarkCaseRun => classifyRun(truth.expected, truth.selectors, run.report, index + 1));
    return { id: truth.id, label: truth.label, expected: truth.expected, ...(truth.category ? { category: truth.category } : {}), tags: truth.tags, required: truth.required, runs: caseRuns, aggregate: aggregateClass(caseRuns.map((item) => item.classification)), stable: new Set(caseRuns.map((item) => item.classification)).size === 1 };
  });
  runs.forEach((run, index) => {
    for (const finding of run.report.findings ?? []) if (manifest.cases.some((truth) => truth.selectors.some((selector) => findingInSelectorDomain(finding, selector))) && !manifest.cases.some((truth) => truth.selectors.some((selector) => findingMatches(finding, selector)))) unexpectedFindings.push({ run: index + 1, findingId: finding.id, sourceModule: finding.sourceModule, findingType: finding.type, ...(finding.workflow?.workflowId ? { workflowId: finding.workflow.workflowId } : {}), ...(finding.workflow?.caseId ? { caseId: finding.workflow.caseId } : {}) });
  });
  const all = cases.flatMap((item) => item.runs);
  const count = (classification: BenchmarkClassification) => all.filter((item) => item.classification === classification).length;
  const confusion = { truePositive: count("TRUE_POSITIVE"), falseNegative: count("FALSE_NEGATIVE"), falsePositive: count("FALSE_POSITIVE") + unexpectedFindings.length, trueNegative: count("TRUE_NEGATIVE"), inconclusive: count("INCONCLUSIVE"), uncovered: count("UNCOVERED"), unexpectedFindings: unexpectedFindings.length };
  const total = all.length;
  const assessed = total - confusion.inconclusive - confusion.uncovered;
  const metrics = {
    recall: ratio(confusion.truePositive, confusion.truePositive + confusion.falseNegative + positiveUnresolved(cases)),
    precision: ratio(confusion.truePositive, confusion.truePositive + confusion.falsePositive),
    falsePositiveRate: ratio(confusion.falsePositive, confusion.falsePositive + confusion.trueNegative),
    inconclusiveRate: ratio(confusion.inconclusive, total),
    coverageCompleteness: ratio(total - confusion.uncovered, total),
    conclusiveCoverage: ratio(assessed, total),
    stabilityRate: ratio(cases.filter((item) => item.stable).length, cases.length)
  };
  const categories = categoryResults(cases);
  const cleanupCases = runs.flatMap((run) => collectReportAssistedCases(run.report).filter((observed) => observed.cleanupOutcome !== undefined && observed.cleanupOutcome !== "NOT_REQUIRED" && manifest.cases.some((truth) => truth.selectors.some((selector) => caseMatches(observed.workflowId, observed.caseId, selector)))));
  const cleanup = { observed: cleanupCases.length, passed: cleanupCases.filter((item) => !item.cleanupFailed).length, failed: cleanupCases.filter((item) => item.cleanupFailed).length, successRate: ratio(cleanupCases.filter((item) => !item.cleanupFailed).length, cleanupCases.length) };
  const assessedByRun = runs.map((_, i) => cases.filter((item) => !["INCONCLUSIVE", "UNCOVERED"].includes(item.runs[i]!.classification)).length);
  const runtime = runs.map((run) => run.telemetry.runtimeMs);
  const requests = runs.map((run) => run.telemetry.requestCount);
  const transmitted = runs.map((run) => run.telemetry.transmittedRequestCount ?? run.telemetry.requestCount);
  const efficiency = { runtimeMs: distribution(runtime), peakRssBytes: distribution(runs.map((run) => run.telemetry.peakRssBytes)), requestCount: distribution(requests), transmittedRequestCount: distribution(transmitted), requestsPerAssessedCase: distribution(requests.map((value, i) => ratio(value, assessedByRun[i]!))), runtimePerRequestMs: distribution(runtime.map((value, i) => ratio(value, transmitted[i]!))) };
  const gates = thresholdGates(manifest, metrics, cleanup, efficiency, cases, categories, runs.length);
  const partial: Omit<BenchmarkResult, "regressions" | "status"> = { schemaVersion: 1, kind: "ROUTECAIRN_BENCHMARK_RESULT", benchmarkId: manifest.id, label: manifest.label, generatedAt: new Date().toISOString(), release: { ...(options.release ? { label: options.release } : {}), ...(options.build ? { build: options.build } : {}), routeCairnVersion: options.routeCairnVersion ?? runs[0]!.report.routeCairnVersion }, manifestDigest: digest(manifest), reportDigests: runs.map((run) => run.reportDigest ?? digest(run.report)), repetitions: runs.length, runTelemetry: runs.map((run) => run.telemetry), confusion, metrics, cleanup, categories, efficiency, cases, unexpectedFindings, gates };
  const regressions = options.baseline ? regressionGates(manifest, partial, options.baseline) : [];
  return { ...partial, regressions, status: [...gates, ...regressions].every((item) => item.passed) ? "PASSED" : "FAILED" };
}

function classifyRun(expected: "FINDING" | "NO_FINDING", selectors: readonly BenchmarkSelector[], report: RouteCairnReport, run: number): BenchmarkCaseRun {
  const findings = (report.findings ?? []).filter((finding) => selectors.some((selector) => findingMatches(finding, selector)));
  const cases = collectReportAssistedCases(report).filter((item) => selectors.some((selector) => caseMatches(item.workflowId, item.caseId, selector)));
  const findingIds = findings.map((finding) => finding.id).sort();
  let observed: BenchmarkCaseRun["observed"];
  if (findings.length > 0 || cases.some((item) => item.assessmentOutcome === "PROVEN" && item.conclusion === "FINDING")) observed = "FINDING";
  else if (cases.some((item) => item.assessmentOutcome === "PROVEN" && item.conclusion === "NO_FINDING")) observed = "NO_FINDING";
  else if (cases.length > 0) observed = "INCONCLUSIVE";
  else observed = "UNCOVERED";
  const classification: BenchmarkClassification = observed === "UNCOVERED" ? "UNCOVERED" : observed === "INCONCLUSIVE" ? "INCONCLUSIVE" : expected === "FINDING" ? (observed === "FINDING" ? "TRUE_POSITIVE" : "FALSE_NEGATIVE") : (observed === "FINDING" ? "FALSE_POSITIVE" : "TRUE_NEGATIVE");
  return { run, classification, observed, matchedFindingIds: findingIds };
}

function findingMatches(finding: Finding, selector: BenchmarkSelector): boolean {
  return (!selector.workflowId || finding.workflow?.workflowId === selector.workflowId) && (!selector.caseId || finding.workflow?.caseId === selector.caseId || finding.workflowCase?.id === selector.caseId) && (!selector.sourceModule || finding.sourceModule === selector.sourceModule) && (!selector.findingType || finding.type === selector.findingType);
}
function findingInSelectorDomain(finding: Finding, selector: BenchmarkSelector): boolean { return selector.workflowId ? finding.workflow?.workflowId === selector.workflowId : selector.sourceModule ? finding.sourceModule === selector.sourceModule : selector.findingType ? finding.type === selector.findingType : false; }
function caseMatches(workflowId: string, caseId: string, selector: BenchmarkSelector): boolean { return (!selector.workflowId || selector.workflowId === workflowId) && (!selector.caseId || selector.caseId === caseId) && (!selector.sourceModule || selector.sourceModule === workflowId) && !selector.findingType; }
function positiveUnresolved(cases: readonly BenchmarkCaseResult[]): number { return cases.filter((item) => item.expected === "FINDING").flatMap((item) => item.runs).filter((item) => item.classification === "INCONCLUSIVE" || item.classification === "UNCOVERED").length; }
function aggregateClass(values: readonly BenchmarkClassification[]): BenchmarkClassification { const order: BenchmarkClassification[] = ["FALSE_POSITIVE", "FALSE_NEGATIVE", "INCONCLUSIVE", "UNCOVERED", "TRUE_POSITIVE", "TRUE_NEGATIVE"]; return order.find((item) => values.includes(item))!; }
function ratio(numerator: number, denominator: number): number { return denominator === 0 ? 0 : numerator / denominator; }
function distribution(values: readonly number[]): Distribution { const sorted = [...values].sort((a, b) => a - b); return { min: sorted[0] ?? 0, median: percentile(sorted, 0.5), p95: percentile(sorted, 0.95), max: sorted.at(-1) ?? 0, mean: ratio(sorted.reduce((sum, value) => sum + value, 0), sorted.length) }; }
function percentile(sorted: readonly number[], quantile: number): number { if (!sorted.length) return 0; const index = (sorted.length - 1) * quantile; const low = Math.floor(index); const high = Math.ceil(index); return sorted[low]! + (sorted[high]! - sorted[low]!) * (index - low); }
function digest(value: unknown): string { return createHash("sha256").update(JSON.stringify(value)).digest("hex"); }
function categoryResults(cases: readonly BenchmarkCaseResult[]): BenchmarkCategoryResult[] {
  return [...new Set(cases.map((item) => item.category ?? "UNCATEGORIZED"))].sort().map((category) => {
    const selected = cases.filter((item) => (item.category ?? "UNCATEGORIZED") === category); const runs = selected.flatMap((item) => item.runs);
    const count = (classification: BenchmarkClassification) => runs.filter((item) => item.classification === classification).length;
    const confusion = { truePositive: count("TRUE_POSITIVE"), falseNegative: count("FALSE_NEGATIVE"), falsePositive: count("FALSE_POSITIVE"), trueNegative: count("TRUE_NEGATIVE"), inconclusive: count("INCONCLUSIVE"), uncovered: count("UNCOVERED") }; const total = runs.length;
    return { category, caseCount: selected.length, positiveCases: selected.filter((item) => item.expected === "FINDING").length, negativeCases: selected.filter((item) => item.expected === "NO_FINDING").length, confusion, metrics: { recall: ratio(confusion.truePositive, confusion.truePositive + confusion.falseNegative + selected.filter((item) => item.expected === "FINDING").flatMap((item) => item.runs).filter((item) => ["INCONCLUSIVE", "UNCOVERED"].includes(item.classification)).length), falsePositiveRate: ratio(confusion.falsePositive, confusion.falsePositive + confusion.trueNegative), inconclusiveRate: ratio(confusion.inconclusive, total), coverageCompleteness: ratio(total - confusion.uncovered, total), stabilityRate: ratio(selected.filter((item) => item.stable).length, selected.length) } };
  });
}

function assertUnambiguousSelectors(manifest: BenchmarkManifest, reports: readonly RouteCairnReport[]): void {
  for (const report of reports) {
    for (const finding of report.findings) {
      const matches = manifest.cases.filter((truth) => truth.selectors.some((selector) => findingMatches(finding, selector)));
      if (matches.length > 1) throw new Error(`BENCHMARK_SELECTOR_OVERLAP:${matches.map((item) => item.id).join(",")}`);
    }
    for (const observed of collectReportAssistedCases(report)) {
      const matches = manifest.cases.filter((truth) => truth.selectors.some((selector) => caseMatches(observed.workflowId, observed.caseId, selector)));
      if (matches.length > 1) throw new Error(`BENCHMARK_SELECTOR_OVERLAP:${matches.map((item) => item.id).join(",")}`);
    }
  }
}

function thresholdGates(manifest: BenchmarkManifest, metrics: BenchmarkResult["metrics"], cleanup: BenchmarkResult["cleanup"], efficiency: BenchmarkResult["efficiency"], cases: readonly BenchmarkCaseResult[], categories: readonly BenchmarkCategoryResult[], repetitions: number): BenchmarkGate[] {
  const t = manifest.thresholds; const gates: BenchmarkGate[] = [
    { id: "recall", passed: metrics.recall >= t.minRecall, actual: metrics.recall, expected: `>= ${t.minRecall}` },
    { id: "false-positive-rate", passed: metrics.falsePositiveRate <= t.maxFalsePositiveRate, actual: metrics.falsePositiveRate, expected: `<= ${t.maxFalsePositiveRate}` },
    { id: "inconclusive-rate", passed: metrics.inconclusiveRate <= t.maxInconclusiveRate, actual: metrics.inconclusiveRate, expected: `<= ${t.maxInconclusiveRate}` },
    { id: "coverage-completeness", passed: metrics.coverageCompleteness >= t.minCoverageCompleteness, actual: metrics.coverageCompleteness, expected: `>= ${t.minCoverageCompleteness}` },
    { id: "minimum-repetitions", passed: repetitions >= t.minRepetitions, actual: repetitions, expected: `>= ${t.minRepetitions}` },
    { id: "cleanup-observations", passed: cleanup.observed >= t.minCleanupObservationsPerRun * repetitions, actual: cleanup.observed, expected: `>= ${t.minCleanupObservationsPerRun * repetitions}` },
    { id: "cleanup-failures", passed: cleanup.failed <= t.maxCleanupFailures, actual: cleanup.failed, expected: `<= ${t.maxCleanupFailures}` }
  ];
  if (t.maxMedianRuntimeMs !== undefined) gates.push({ id: "median-runtime", passed: efficiency.runtimeMs.median <= t.maxMedianRuntimeMs, actual: efficiency.runtimeMs.median, expected: `<= ${t.maxMedianRuntimeMs} ms` });
  if (t.maxP95RuntimeMs !== undefined) gates.push({ id: "p95-runtime", passed: efficiency.runtimeMs.p95 <= t.maxP95RuntimeMs, actual: efficiency.runtimeMs.p95, expected: `<= ${t.maxP95RuntimeMs} ms` });
  if (t.maxPeakRssBytes !== undefined) gates.push({ id: "peak-rss", passed: efficiency.peakRssBytes.max <= t.maxPeakRssBytes, actual: efficiency.peakRssBytes.max, expected: `<= ${t.maxPeakRssBytes} bytes` });
  if (t.maxRequestsPerAssessedCase !== undefined) gates.push({ id: "request-efficiency", passed: efficiency.requestsPerAssessedCase.mean <= t.maxRequestsPerAssessedCase, actual: efficiency.requestsPerAssessedCase.mean, expected: `<= ${t.maxRequestsPerAssessedCase} requests/assessed case` });
  for (const category of categories) {
    gates.push({ id: `category-size/${category.category}`, passed: category.caseCount >= t.minCasesPerCategory, actual: category.caseCount, expected: `>= ${t.minCasesPerCategory}` });
    if (t.requireBalancedCategories) gates.push({ id: `category-balance/${category.category}`, passed: category.positiveCases > 0 && category.negativeCases > 0, actual: category.positiveCases > 0 && category.negativeCases > 0, expected: "at least one FINDING and one NO_FINDING case" });
  }
  for (const item of cases.filter((value) => value.required)) { const expected = item.expected === "FINDING" ? "TRUE_POSITIVE" : "TRUE_NEGATIVE"; gates.push({ id: `required-case/${item.id}`, passed: item.aggregate === expected, actual: item.aggregate === expected, expected }); }
  return gates;
}

function regressionGates(manifest: BenchmarkManifest, current: Omit<BenchmarkResult, "regressions" | "status">, baseline: BenchmarkResult): BenchmarkRegression[] {
  if (baseline.benchmarkId !== current.benchmarkId || baseline.manifestDigest !== current.manifestDigest) throw new Error("BENCHMARK_BASELINE_INCOMPATIBLE");
  const p = manifest.regression; const ratioIncrease = (now: number, before: number) => before === 0 ? (now === 0 ? 0 : Number.MAX_VALUE) : (now - before) / before;
  const regressedCases = current.cases.filter((item) => { const prior = baseline.cases.find((old) => old.id === item.id); return prior && ["TRUE_POSITIVE", "TRUE_NEGATIVE"].includes(prior.aggregate) && prior.aggregate !== item.aggregate; }).length;
  return [
    { id: "recall-drop", passed: baseline.metrics.recall - current.metrics.recall <= p.maxRecallDrop, actual: baseline.metrics.recall - current.metrics.recall, expected: `<= ${p.maxRecallDrop}` },
    { id: "false-positive-rate-increase", passed: current.metrics.falsePositiveRate - baseline.metrics.falsePositiveRate <= p.maxFalsePositiveRateIncrease, actual: current.metrics.falsePositiveRate - baseline.metrics.falsePositiveRate, expected: `<= ${p.maxFalsePositiveRateIncrease}` },
    { id: "inconclusive-rate-increase", passed: current.metrics.inconclusiveRate - baseline.metrics.inconclusiveRate <= p.maxInconclusiveRateIncrease, actual: current.metrics.inconclusiveRate - baseline.metrics.inconclusiveRate, expected: `<= ${p.maxInconclusiveRateIncrease}` },
    { id: "coverage-drop", passed: baseline.metrics.coverageCompleteness - current.metrics.coverageCompleteness <= p.maxCoverageDrop, actual: baseline.metrics.coverageCompleteness - current.metrics.coverageCompleteness, expected: `<= ${p.maxCoverageDrop}` },
    { id: "runtime-increase", passed: ratioIncrease(current.efficiency.runtimeMs.median, baseline.efficiency.runtimeMs.median) <= p.maxRuntimeIncreaseRatio, actual: ratioIncrease(current.efficiency.runtimeMs.median, baseline.efficiency.runtimeMs.median), expected: `<= ${p.maxRuntimeIncreaseRatio}` },
    { id: "memory-increase", passed: ratioIncrease(current.efficiency.peakRssBytes.max, baseline.efficiency.peakRssBytes.max) <= p.maxMemoryIncreaseRatio, actual: ratioIncrease(current.efficiency.peakRssBytes.max, baseline.efficiency.peakRssBytes.max), expected: `<= ${p.maxMemoryIncreaseRatio}` },
    { id: "request-increase", passed: ratioIncrease(current.efficiency.requestCount.mean, baseline.efficiency.requestCount.mean) <= p.maxRequestIncreaseRatio, actual: ratioIncrease(current.efficiency.requestCount.mean, baseline.efficiency.requestCount.mean), expected: `<= ${p.maxRequestIncreaseRatio}` },
    { id: "case-regressions", passed: !p.failOnCaseRegression || regressedCases === 0, actual: regressedCases, expected: p.failOnCaseRegression ? "0" : "not enforced" }
  ];
}
