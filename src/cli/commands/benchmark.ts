import type { Command } from "commander";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { benchmarkManifestSchema, benchmarkTelemetrySchema } from "../../benchmark/BenchmarkSchemas.js";
import { evaluateBenchmark, type BenchmarkResult, type BenchmarkRunInput } from "../../benchmark/BenchmarkEvaluator.js";
import { writeBenchmarkArtifacts } from "../../benchmark/BenchmarkArtifacts.js";
import { runLocalBenchmark } from "../../benchmark/LocalBenchmarkLab.js";

export function registerBenchmarkCommand(program: Command): void {
  const command = program.command("benchmark").description("Measure detection quality, coverage, efficiency, and release regressions.");
  command.command("evaluate")
    .requiredOption("--manifest <file>", "Ground-truth benchmark manifest.")
    .requiredOption("--reports <files...>", "One or more RouteCairn report JSON files.")
    .option("--telemetry <files...>", "Optional telemetry JSON files, one per report.")
    .option("--baseline <file>", "Prior benchmark-result.json for regression gating.")
    .option("--output <directory>", "Artifact directory.", "./routecairn-benchmark")
    .option("--release <label>", "Release label recorded in artifacts.")
    .option("--build <id>", "Build or commit identifier recorded in artifacts.")
    .action(async (options: { manifest: string; reports: string[]; telemetry?: string[]; baseline?: string; output: string; release?: string; build?: string }) => {
      const result = await evaluateFiles(options); const artifacts = await writeBenchmarkArtifacts(options.output, result);
      process.stdout.write(`${JSON.stringify({ status: result.status, metrics: result.metrics, artifacts }, null, 2)}\n`);
      if (result.status === "FAILED") process.exitCode = 2;
    });
  command.command("local")
    .description("Run the bundled mutation-free intentionally vulnerable loopback laboratory.")
    .option("--output <directory>", "Parent directory for a fresh benchmark run.")
    .option("--repetitions <number>", "Repetitions, from 1 to 20.", "3")
    .option("--baseline <file>", "Prior benchmark-result.json for regression gating.")
    .option("--release <label>", "Release label recorded in artifacts.")
    .option("--build <id>", "Build or commit identifier recorded in artifacts.")
    .action(async (options: { output?: string; repetitions: string; baseline?: string; release?: string; build?: string }) => {
      const baseline = options.baseline ? await loadJson<BenchmarkResult>(options.baseline) : undefined;
      const summary = await runLocalBenchmark({ ...(options.output ? { output: options.output } : {}), repetitions: Number(options.repetitions), ...(baseline ? { baseline } : {}), ...(options.release ? { release: options.release } : {}), ...(options.build ? { build: options.build } : {}) });
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`); if (summary.result.status === "FAILED") process.exitCode = 2;
    });
}

async function evaluateFiles(options: { manifest: string; reports: string[]; telemetry?: string[]; baseline?: string; release?: string; build?: string }): Promise<BenchmarkResult> {
  if (options.telemetry && options.telemetry.length !== options.reports.length) throw new Error("BENCHMARK_TELEMETRY_COUNT_MISMATCH");
  const manifest = benchmarkManifestSchema.parse(await loadJson(options.manifest));
  const runs: BenchmarkRunInput[] = [];
  for (let index = 0; index < options.reports.length; index += 1) {
    const report = await loadJson<RouteCairnReport>(options.reports[index]!);
    const telemetry = options.telemetry ? benchmarkTelemetrySchema.parse(await loadJson(options.telemetry[index]!)) : inferTelemetry(report);
    runs.push({ report, telemetry });
  }
  const baseline = options.baseline ? await loadJson<BenchmarkResult>(options.baseline) : undefined;
  return evaluateBenchmark(manifest, runs, { ...(baseline ? { baseline } : {}), ...(options.release ? { release: options.release } : {}), ...(options.build ? { build: options.build } : {}) });
}
function inferTelemetry(report: RouteCairnReport) { const transmitted = report.requestAudit.reduce((sum, entry) => sum + (entry.transmittedRequests ?? (entry.outcome === "sent" ? 1 : 0)), 0); return { runtimeMs: report.metadata.durationMs, peakRssBytes: 0, requestCount: report.metadata.totalRequests || transmitted, transmittedRequestCount: transmitted }; }
async function loadJson<T = unknown>(path: string): Promise<T> { return JSON.parse(await readFile(resolve(path), "utf8")) as T; }
