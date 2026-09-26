import type { Command } from "commander";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { benchmarkManifestSchema, benchmarkTelemetrySchema } from "../../benchmark/BenchmarkSchemas.js";
import { evaluateBenchmark, type BenchmarkResult, type BenchmarkRunInput } from "../../benchmark/BenchmarkEvaluator.js";
import { writeBenchmarkArtifacts } from "../../benchmark/BenchmarkArtifacts.js";
import { runLocalBenchmark } from "../../benchmark/LocalBenchmarkLab.js";
import { openBenchmarkPack, sealBenchmarkManifest, signBenchmarkManifest, verifyBenchmarkManifest } from "../../benchmark/BenchmarkCorpus.js";
import { credibilityTruthManifest, runCredibilityBenchmark } from "../../benchmark/CredibilityBenchmarkLab.js";

export function registerBenchmarkCommand(program: Command): void {
  const command = program.command("benchmark").description("Measure detection quality, coverage, efficiency, and release regressions.");
  command.command("evaluate")
    .option("--manifest <file>", "Ground-truth benchmark manifest.")
    .option("--blind-pack <file>", "Encrypted blinded ground-truth pack.")
    .option("--blind-key-env <name>", "Environment variable containing the blind-pack secret.")
    .option("--corpus-public-key <file>", "Verify an independently signed corpus before evaluation.")
    .option("--corpus-key-id <id>", "Required signing-key identity.")
    .requiredOption("--reports <files...>", "One or more RouteCairn report JSON files.")
    .option("--telemetry <files...>", "Optional telemetry JSON files, one per report.")
    .option("--baseline <file>", "Prior benchmark-result.json for regression gating.")
    .option("--output <directory>", "Artifact directory.", "./routecairn-benchmark")
    .option("--release <label>", "Release label recorded in artifacts.")
    .option("--build <id>", "Build or commit identifier recorded in artifacts.")
    .action(async (options: { manifest?: string; blindPack?: string; blindKeyEnv?: string; corpusPublicKey?: string; corpusKeyId?: string; reports: string[]; telemetry?: string[]; baseline?: string; output: string; release?: string; build?: string }) => {
      const result = await evaluateFiles(options); const artifacts = await writeBenchmarkArtifacts(options.output, result);
      process.stdout.write(`${JSON.stringify({ status: result.status, metrics: result.metrics, artifacts }, null, 2)}\n`);
      if (result.status === "FAILED") process.exitCode = 2;
    });
  const corpus = command.command("corpus").description("Sign, verify, and blind independently maintained benchmark corpora.");
  corpus.command("generate-public").requiredOption("--output <file>").action(async (options: { output: string }) => {
    const manifest = credibilityTruthManifest([{ id: "node-http", language: "TypeScript", framework: "node:http" }, { id: "python-http", language: "Python", framework: "http.server" }]); await writeJsonFile(options.output, manifest);
    process.stdout.write(`${JSON.stringify({ status: "GENERATED", output: resolve(options.output), corpusVersion: manifest.corpus?.version, caseCount: manifest.cases.length }, null, 2)}\n`);
  });
  corpus.command("seal").requiredOption("--manifest <file>").requiredOption("--key-env <name>").requiredOption("--output <file>").action(async (options: { manifest: string; keyEnv: string; output: string }) => {
    const secret = requiredEnvironment(options.keyEnv); const pack = sealBenchmarkManifest(await loadJson(options.manifest), secret); await writeJsonFile(options.output, pack);
    process.stdout.write(`${JSON.stringify({ status: "SEALED", output: resolve(options.output), caseCount: pack.public.caseCount, publicDigest: pack.sealedTruth.publicDigest }, null, 2)}\n`);
  });
  corpus.command("sign").requiredOption("--manifest <file>").requiredOption("--private-key <file>").requiredOption("--key-id <id>").requiredOption("--output <file>").action(async (options: { manifest: string; privateKey: string; keyId: string; output: string }) => {
    const signed = signBenchmarkManifest(await loadJson(options.manifest), await readFile(resolve(options.privateKey), "utf8"), options.keyId); await writeJsonFile(options.output, signed);
    process.stdout.write(`${JSON.stringify({ status: "SIGNED", output: resolve(options.output), keyId: options.keyId, caseCount: signed.cases.length }, null, 2)}\n`);
  });
  corpus.command("verify").requiredOption("--manifest <file>").requiredOption("--public-key <file>").option("--key-id <id>").action(async (options: { manifest: string; publicKey: string; keyId?: string }) => {
    const verified = verifyBenchmarkManifest(await loadJson(options.manifest), await readFile(resolve(options.publicKey), "utf8"), options.keyId);
    process.stdout.write(`${JSON.stringify({ status: "VERIFIED", benchmarkId: verified.id, corpusVersion: verified.corpus?.version, caseCount: verified.cases.length, keyId: verified.corpus?.signature?.keyId }, null, 2)}\n`);
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
  command.command("credibility")
    .description("Run the versioned 240-case multi-language public credibility corpus.")
    .option("--output <directory>", "Parent directory for a fresh benchmark run.")
    .option("--repetitions <number>", "Repetitions, from 1 to 10.", "1")
    .option("--baseline <file>", "Prior benchmark-result.json for regression gating.")
    .option("--release <label>", "Release label recorded in artifacts.")
    .option("--build <id>", "Build or commit identifier recorded in artifacts.")
    .option("--python <command>", "Python 3 executable.")
    .action(async (options: { output?: string; repetitions: string; baseline?: string; release?: string; build?: string; python?: string }) => {
      const baseline = options.baseline ? await loadJson<BenchmarkResult>(options.baseline) : undefined;
      const summary = await runCredibilityBenchmark({ ...(options.output ? { output: options.output } : {}), repetitions: Number(options.repetitions), ...(baseline ? { baseline } : {}), ...(options.release ? { release: options.release } : {}), ...(options.build ? { build: options.build } : {}), ...(options.python ? { pythonCommand: options.python } : {}) });
      process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`); if (summary.result.status === "FAILED") process.exitCode = 2;
    });
}

async function evaluateFiles(options: { manifest?: string; blindPack?: string; blindKeyEnv?: string; corpusPublicKey?: string; corpusKeyId?: string; reports: string[]; telemetry?: string[]; baseline?: string; release?: string; build?: string }): Promise<BenchmarkResult> {
  if (options.telemetry && options.telemetry.length !== options.reports.length) throw new Error("BENCHMARK_TELEMETRY_COUNT_MISMATCH");
  if (Boolean(options.manifest) === Boolean(options.blindPack)) throw new Error("BENCHMARK_TRUTH_SOURCE_REQUIRED");
  if (options.blindPack && !options.blindKeyEnv) throw new Error("BENCHMARK_BLIND_KEY_ENV_REQUIRED");
  const loadedManifest = options.manifest ? benchmarkManifestSchema.parse(await loadJson(options.manifest)) : openBenchmarkPack(await loadJson(options.blindPack!), requiredEnvironment(options.blindKeyEnv!));
  if (options.corpusKeyId && !options.corpusPublicKey) throw new Error("BENCHMARK_CORPUS_PUBLIC_KEY_REQUIRED");
  const manifest = options.corpusPublicKey ? verifyBenchmarkManifest(loadedManifest, await readFile(resolve(options.corpusPublicKey), "utf8"), options.corpusKeyId) : loadedManifest;
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
async function writeJsonFile(path: string, value: unknown): Promise<void> { await writeFile(resolve(path), `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 }); }
function requiredEnvironment(name: string): string { if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) throw new Error("BENCHMARK_ENV_NAME_INVALID"); const value = process.env[name]; if (!value) throw new Error(`BENCHMARK_ENV_REQUIRED:${name}`); return value; }
