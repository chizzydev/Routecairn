import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runLocalBenchmark } from "../../src/benchmark/LocalBenchmarkLab.js";

const directories: string[] = [];
afterEach(async () => { await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true }))); });

describe("local benchmark laboratory", () => {
  it("runs every balanced detector family and enforces repeated execution", async () => {
    const parent = await mkdtemp(join(tmpdir(), "routecairn-benchmark-test-")); directories.push(parent);
    const summary = await runLocalBenchmark({ output: parent, repetitions: 1, release: "test" });
    expect(summary).toMatchObject({ fixtureOnly: true, externalTargetsTested: false, targetKind: "INTENTIONALLY_VULNERABLE_LOOPBACK" });
    expect(summary.result).toMatchObject({ status: "FAILED", repetitions: 1, confusion: { truePositive: 15, falseNegative: 0, falsePositive: 0, trueNegative: 15, inconclusive: 0, uncovered: 0 }, metrics: { recall: 1, falsePositiveRate: 0, inconclusiveRate: 0, coverageCompleteness: 1 } });
    expect(summary.result.categories).toHaveLength(15);
    for (const category of summary.result.categories) expect(category).toMatchObject({ caseCount: 2, positiveCases: 1, negativeCases: 1, metrics: { recall: 1, falsePositiveRate: 0, inconclusiveRate: 0, coverageCompleteness: 1 } });
    expect(summary.result.cleanup).toEqual({ observed: 6, passed: 6, failed: 0, successRate: 1 });
    expect(summary.result.gates.filter((gate) => !gate.passed)).toEqual([expect.objectContaining({ id: "minimum-repetitions", actual: 1, expected: ">= 3" })]);
    expect(summary.result.efficiency.requestCount.mean).toBeGreaterThan(0);
    const scanReport = JSON.parse(await readFile(join(summary.directory, "scans", "run-1", "report.json"), "utf8")) as { transport: { poolingEnabled: boolean; requestsDispatched: number; dnsResolutions: number; activeOriginPools: number; peakOriginPools: number } };
    expect(scanReport.transport).toMatchObject({ poolingEnabled: true, activeOriginPools: 0, peakOriginPools: 1 });
    expect(scanReport.transport.requestsDispatched).toBeGreaterThan(0); expect(scanReport.transport.dnsResolutions).toBeGreaterThan(0);
    expect(await readFile(summary.artifacts.markdownPath, "utf8")).toContain("Category coverage");
    expect(await readFile(summary.artifacts.junitPath, "utf8")).toContain("testsuite");
  }, 120_000);
});
