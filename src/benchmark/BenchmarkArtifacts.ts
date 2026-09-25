import { mkdir, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import type { BenchmarkResult } from "./BenchmarkEvaluator.js";

export async function writeBenchmarkArtifacts(outputDirectory: string, result: BenchmarkResult): Promise<{ jsonPath: string; markdownPath: string; junitPath: string }> {
  const directory = resolve(outputDirectory); await mkdir(directory, { recursive: true });
  const jsonPath = join(directory, "benchmark-result.json"); const markdownPath = join(directory, "benchmark-report.md"); const junitPath = join(directory, "benchmark-junit.xml");
  await Promise.all([
    writeFile(jsonPath, `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 }),
    writeFile(markdownPath, markdown(result), { mode: 0o600 }),
    writeFile(junitPath, junit(result), { mode: 0o600 })
  ]);
  return { jsonPath, markdownPath, junitPath };
}

function markdown(result: BenchmarkResult): string {
  const pct = (value: number) => `${(value * 100).toFixed(2)}%`;
  const rows = result.cases.map((item) => `| ${escapeMd(item.id)} | ${item.expected} | ${item.aggregate} | ${item.stable ? "yes" : "no"} |`).join("\n");
  const categories = result.categories.map((item) => `| ${escapeMd(item.category)} | ${item.caseCount} | ${item.positiveCases} | ${item.negativeCases} | ${pct(item.metrics.recall)} | ${pct(item.metrics.falsePositiveRate)} | ${pct(item.metrics.coverageCompleteness)} |`).join("\n");
  const gates = [...result.gates, ...result.regressions].map((gate) => `| ${escapeMd(gate.id)} | ${gate.passed ? "PASS" : "FAIL"} | ${gate.actual} | ${escapeMd(gate.expected)} |`).join("\n");
  return `# ${result.label}\n\nStatus: **${result.status}**  \nRelease: ${escapeMd(result.release.label ?? result.release.routeCairnVersion)}  \nRepetitions: ${result.repetitions}\n\n## Detection quality\n\n| Metric | Value |\n|---|---:|\n| Recall | ${pct(result.metrics.recall)} |\n| Precision | ${pct(result.metrics.precision)} |\n| False-positive rate | ${pct(result.metrics.falsePositiveRate)} |\n| Inconclusive rate | ${pct(result.metrics.inconclusiveRate)} |\n| Coverage completeness | ${pct(result.metrics.coverageCompleteness)} |\n| Conclusive coverage | ${pct(result.metrics.conclusiveCoverage)} |\n| Stability | ${pct(result.metrics.stabilityRate)} |\n| Cleanup success | ${pct(result.cleanup.successRate)} (${result.cleanup.passed}/${result.cleanup.observed}) |\n| Cleanup failures | ${result.cleanup.failed} |\n\n## Category coverage\n\n| Category | Cases | Positive | Negative | Recall | False-positive rate | Coverage |\n|---|---:|---:|---:|---:|---:|---:|\n${categories}\n\n## Efficiency\n\n| Metric | Median | P95 | Max |\n|---|---:|---:|---:|\n| Runtime (ms) | ${result.efficiency.runtimeMs.median.toFixed(2)} | ${result.efficiency.runtimeMs.p95.toFixed(2)} | ${result.efficiency.runtimeMs.max.toFixed(2)} |\n| Peak RSS (bytes) | ${result.efficiency.peakRssBytes.median.toFixed(0)} | ${result.efficiency.peakRssBytes.p95.toFixed(0)} | ${result.efficiency.peakRssBytes.max.toFixed(0)} |\n| Requests | ${result.efficiency.requestCount.median.toFixed(2)} | ${result.efficiency.requestCount.p95.toFixed(2)} | ${result.efficiency.requestCount.max.toFixed(2)} |\n| Requests/assessed case | ${result.efficiency.requestsPerAssessedCase.median.toFixed(2)} | ${result.efficiency.requestsPerAssessedCase.p95.toFixed(2)} | ${result.efficiency.requestsPerAssessedCase.max.toFixed(2)} |\n\n## Cases\n\n| ID | Expected | Result | Stable |\n|---|---|---|---|\n${rows}\n\n## Gates\n\n| Gate | Status | Actual | Required |\n|---|---|---:|---|\n${gates || "| none | PASS | - | - |"}\n`;
}

function junit(result: BenchmarkResult): string {
  const failed = result.cases.filter((item) => item.required && !["TRUE_POSITIVE", "TRUE_NEGATIVE"].includes(item.aggregate));
  const tests = result.cases.map((item) => { const correct = ["TRUE_POSITIVE", "TRUE_NEGATIVE"].includes(item.aggregate); const detail = correct ? "" : item.required ? `<failure message="${xml(item.aggregate)}">Expected ${xml(item.expected)}, observed ${xml(item.aggregate)}</failure>` : `<system-out>Optional case: expected ${xml(item.expected)}, observed ${xml(item.aggregate)}</system-out>`; return `<testcase classname="routecairn.benchmark.${xml(result.benchmarkId)}" name="${xml(item.id)}">${detail}</testcase>`; }).join("");
  const allGates = [...result.gates, ...result.regressions];
  const gateTests = allGates.map((item) => `<testcase classname="routecairn.benchmark.gates" name="${xml(item.id)}">${item.passed ? "" : `<failure message="gate failed">Actual ${xml(String(item.actual))}; expected ${xml(item.expected)}</failure>`}</testcase>`).join("");
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="RouteCairn benchmark" tests="${result.cases.length + allGates.length}" failures="${failed.length + allGates.filter((item) => !item.passed).length}">${tests}${gateTests}</testsuite>\n`;
}
function escapeMd(value: string): string { return value.replaceAll("|", "\\|").replaceAll("\n", " "); }
function xml(value: string): string { return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;"); }
