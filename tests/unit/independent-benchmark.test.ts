import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { lookup } from "node:dns/promises";
import { runScanCommand } from "../../src/cli/commands/scan.js";
import { openBenchmarkPack, sealBenchmarkManifest, signBenchmarkManifest, verifyBenchmarkManifest } from "../../src/benchmark/BenchmarkCorpus.js";
import { credibilityTargetMatrix, credibilityTruthManifest } from "../../src/benchmark/CredibilityBenchmarkLab.js";
import { evaluateIndependentBenchmark, runIndependentBenchmark, independentTrustSchema, signIndependentSubmission, trustedBenchmarkKey, verifyIndependentSubmission, assertExternalOrigin } from "../../src/benchmark/IndependentBenchmark.js";
import { evaluateBenchmark, wilsonInterval } from "../../src/benchmark/BenchmarkEvaluator.js";
import type { RouteCairnReport } from "../../src/reports/ReportTypes.js";

const directories: string[] = [];
vi.mock("../../src/cli/commands/scan.js", () => ({ runScanCommand: vi.fn() }));
vi.mock("node:dns/promises", () => ({ lookup: vi.fn() }));
afterEach(async () => { vi.resetAllMocks(); await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true }))); });
const secret = "fixture-only evaluator secret of at least 32 bytes";
function keys() { const pair = generateKeyPairSync("ed25519"); return { publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(), privateKeyPem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString() }; }

describe("independent benchmark evidence boundary", () => {
  it("executes only digest-bound contracts without opening truth and rejects DNS loopback before scanning", async () => {
    const directory = await mkdtemp(join(tmpdir(), "independent-runner-test-")); directories.push(directory);
    const operator = keys(); const keyPath = join(directory, "operator.pem"); await writeFile(keyPath, operator.privateKeyPem);
    const trust = { schemaVersion: 1, keys: [{ id: "operator", organization: "Operator fixture lab", role: "OPERATOR", publicKeyPem: operator.publicKeyPem, validFrom: "2020-01-01T00:00:00.000Z", validUntil: "2099-01-01T00:00:00.000Z", revoked: false, independence: "INDEPENDENT_THIRD_PARTY" }] };
    const trustPath = join(directory, "trust.json"); await writeFile(trustPath, JSON.stringify(trust));
    const contractPath = join(directory, "contract.json"); const contract = Buffer.from("{}"); await writeFile(contractPath, contract);
    const binding = { path: contractPath, sha256: digest(contract) };
    const plan = { schemaVersion: 1, operatorKeyId: "operator", repetitions: 3, releaseVersion: "0.1.0", sourceCommit: "a".repeat(40), targets: [{ id: "authorized", url: "https://authorized.security-lab.org", scope: binding, targetAuthorization: binding, inputs: { activeVulnerability: binding }, maxRequests: 50, cleanupReservedRequests: 10 }] };
    const planPath = join(directory, "plan.json"); await writeFile(planPath, JSON.stringify(plan));
    const packPath = join(directory, "pack.json"); await writeFile(packPath, JSON.stringify(sealBenchmarkManifest(credibilityTruthManifest(credibilityTargetMatrix), secret)));
    const artifactPath = join(directory, "artifact.tgz"); await writeFile(artifactPath, "test artifact");
    const options = { plan: planPath, pack: packPath, trust: trustPath, releaseArtifact: artifactPath, signingKey: keyPath, output: join(directory, "output") };
    // The transport is mocked: this test never contacts an external host.
    vi.mocked(lookup).mockResolvedValue([{ address: "127.0.0.1", family: 4 }] as never);
    await expect(runIndependentBenchmark(options)).rejects.toThrow("EXTERNAL_TARGET_REQUIRED"); expect(runScanCommand).not.toHaveBeenCalled();
    vi.mocked(lookup).mockResolvedValue([{ address: "192.0.2.1", family: 4 }] as never);
    let iteration = 0;
    vi.mocked(runScanCommand).mockImplementation(async (target, scanOptions) => {
      expect(scanOptions.includeModules).toEqual(["active-vulnerability-validation"]); expect(scanOptions.replaceProfileModules).toBe(true);
      expect(scanOptions.maxRequests).toBe("50"); expect(scanOptions.cleanupReservedRequests).toBe("10");
      expect(scanOptions.activeVulnerability).not.toBe(contractPath);
      const reportPath = join(directory, `mock-scan-${iteration++}.json`);
      await writeFile(reportPath, JSON.stringify({ target, routeCairnVersion: "0.1.0", findings: [], requestAudit: [{ outcome: "sent", requestedUrl: target, transmittedRequests: 1 }], execution: { status: "COMPLETED", partial: false }, metadata: { run: iteration } }));
      return { reportPath } as Awaited<ReturnType<typeof runScanCommand>>;
    });
    const run = await runIndependentBenchmark(options); expect(run.status).toBe("AWAITING_INDEPENDENT_TRUTH");
    const submission = verifyIndependentSubmission(JSON.parse(await readFile(run.submissionPath, "utf8")), independentTrustSchema.parse(trust));
    expect(submission.runs).toHaveLength(3); expect(runScanCommand).toHaveBeenCalledTimes(3);
    vi.mocked(runScanCommand).mockClear(); await writeFile(contractPath, "changed");
    await expect(runIndependentBenchmark(options)).rejects.toThrow("INPUT_COMMITMENT_MISMATCH"); expect(runScanCommand).not.toHaveBeenCalled();
  });
  it("signs the prepared blinded manifest and authenticates the public envelope", () => {
    const pair = keys(); const manifest = credibilityTruthManifest(credibilityTargetMatrix);
    const pack = sealBenchmarkManifest(manifest, secret, { ...pair, keyId: "publisher" });
    expect(verifyBenchmarkManifest(openBenchmarkPack(pack, secret), pair.publicKeyPem, "publisher").corpus?.blinded).toBe(true);
    const publicValue = { ...pack.public, label: "changed" };
    const publicDigest = createHash("sha256").update(JSON.stringify(sort(publicValue))).digest("hex");
    expect(() => openBenchmarkPack({ ...pack, public: publicValue, sealedTruth: { ...pack.sealedTruth, publicDigest } }, secret)).toThrow("BENCHMARK_BLIND_DECRYPTION_FAILED");
    expect(() => sealBenchmarkManifest(signBenchmarkManifest(manifest, pair.privateKeyPem, "publisher"), secret)).toThrow("BENCHMARK_SIGNED_TRUTH_RESEAL_REQUIRES_SIGNER");
  });

  it("rejects untrusted, revoked, wrong-role and expired keys", () => {
    const key = { id: "operator", organization: "Fixture lab", role: "OPERATOR" as const, ...keys(), validFrom: "2026-01-01T00:00:00.000Z", validUntil: "2027-01-01T00:00:00.000Z", revoked: false, independence: "INDEPENDENT_THIRD_PARTY" as const };
    const { privateKeyPem: _private, ...publicKey } = key;
    const trust = { schemaVersion: 1 as const, keys: [publicKey] };
    expect(() => trustedBenchmarkKey(trust, "missing", "OPERATOR", "2026-09-29T00:00:00.000Z")).toThrow("UNTRUSTED");
    expect(() => trustedBenchmarkKey(trust, "operator", "PUBLISHER", "2026-09-29T00:00:00.000Z")).toThrow("UNTRUSTED");
    expect(() => trustedBenchmarkKey(trust, "operator", "OPERATOR", "2027-01-01T00:00:00.000Z")).toThrow("UNTRUSTED");
    expect(() => trustedBenchmarkKey({ ...trust, keys: [{ ...publicKey, revoked: true }] }, "operator", "OPERATOR", "2026-09-29T00:00:00.000Z")).toThrow("UNTRUSTED");
    expect(() => independentTrustSchema.parse({ ...trust, keys: [publicKey, publicKey] })).toThrow();
    expect(() => independentTrustSchema.parse({ ...trust, keys: [publicKey, { ...publicKey, id: "renamed-revoked-key", revoked: true }] })).toThrow();
  });

  it("verifies signed submissions, repeated executions, release commitments, and tamper rejection", async () => {
    // Synthetic reports exercise verifier behavior. They are never published as external scorecards.
    const directory = await mkdtemp(join(tmpdir(), "independent-benchmark-test-")); directories.push(directory);
    const operator = keys(); const publisher = keys();
    const now = new Date().toISOString(); const validFrom = "2020-01-01T00:00:00.000Z"; const validUntil = "2099-01-01T00:00:00.000Z";
    const trust = independentTrustSchema.parse({ schemaVersion: 1, keys: [
      { id: "operator", organization: "Operator fixture lab", role: "OPERATOR", publicKeyPem: operator.publicKeyPem, validFrom, validUntil, revoked: false, independence: "INDEPENDENT_THIRD_PARTY" },
      { id: "publisher", organization: "Publisher fixture lab", role: "PUBLISHER", publicKeyPem: publisher.publicKeyPem, validFrom, validUntil, revoked: false, independence: "INDEPENDENT_THIRD_PARTY" }
    ] });
    const raw = credibilityTruthManifest(credibilityTargetMatrix);
    const manifest = { ...raw, corpus: { ...raw.corpus!, publisher: "Publisher fixture lab", independence: "EXTERNAL" as const, source: "https://github.com/fixture-lab/corpus", commit: "b".repeat(40) }, thresholds: { ...raw.thresholds, minCleanupObservationsPerRun: 0 } };
    const pack = sealBenchmarkManifest(manifest, secret, { privateKeyPem: publisher.privateKeyPem, keyId: "publisher" });
    const packPath = join(directory, "pack.json"); const packBytes = Buffer.from(JSON.stringify(pack)); await writeFile(packPath, packBytes);
    const artifactPath = join(directory, "artifact.tgz"); const artifact = Buffer.from("fixture release bytes"); await writeFile(artifactPath, artifact);
    const runs = [];
    for (let i = 0; i < 3; i += 1) {
      const observations = manifest.cases.map((item) => ({ checkId: item.id, caseId: item.id, label: item.label, outcome: item.expected === "FINDING" ? "FAIL" : "PASS", vulnerabilityClass: "SQL_INJECTION", category: "LOGIN_ENUMERATION_RESISTANCE", comparisonFingerprint: "c".repeat(64) }));
      const report = { routeCairnVersion: "0.1.0", target: "https://target.security-lab.org", findings: manifest.cases.filter((item) => item.expected === "FINDING").map((item) => ({ id: `finding-${item.id}`, sourceModule: item.selectors[0]!.workflowId, workflow: { workflowId: item.selectors[0]!.workflowId, caseId: item.id } })), execution: { status: "COMPLETED", partial: false }, metadata: { durationMs: 10, startedAt: now, completedAt: now, run: i }, requestAudit: [{ requestedUrl: "https://target.security-lab.org/test", outcome: "sent", transmittedRequests: 1 }],
        apiGraphql: { checks: observations.filter((item) => item.caseId.includes("-obj-") || item.caseId.includes("-fn-")), schemaComparisons: [] },
        activeVulnerability: { cases: observations.filter((item) => !item.caseId.includes("-obj-") && !item.caseId.includes("-fn-") && !item.caseId.includes("-auth-") && !item.caseId.includes("-so-")).map((item) => ({ ...item, outcome: item.outcome === "FAIL" ? "PROVEN" : "SECURE_FOR_CASE" })) },
        authenticationLifecycle: { observations: observations.filter((item) => item.caseId.includes("-auth-") || item.caseId.includes("-so-")) }
      } as unknown as RouteCairnReport;
      const path = join(directory, `report-${i}.json`); const bytes = Buffer.from(JSON.stringify(report)); await writeFile(path, bytes);
      runs.push({ report: { path, sha256: digest(bytes) }, telemetry: { runtimeMs: 10, peakRssBytes: 100, requestCount: 1, transmittedRequestCount: 1 } });
    }
    const submission = signIndependentSubmission({ schemaVersion: 1, kind: "ROUTECAIRN_INDEPENDENT_BENCHMARK_SUBMISSION", createdAt: now, benchmarkId: manifest.id, packSha256: digest(packBytes), operatorOrganization: "Operator fixture lab", release: { version: "0.1.0", sourceCommit: "a".repeat(40), artifactSha256: digest(artifact) }, runs }, operator.privateKeyPem, "operator");
    expect(() => verifyIndependentSubmission({ ...submission, benchmarkId: "tampered" }, trust)).toThrow("SIGNATURE_INVALID");
    const replay = signIndependentSubmission({ ...submission, runs: [runs[0]!, runs[0]!, runs[0]!] }, operator.privateKeyPem, "operator");
    expect(() => verifyIndependentSubmission(replay, trust)).toThrow("REPETITION_REPLAY");
    const submissionPath = join(directory, "submission.json"); const trustPath = join(directory, "trust.json"); await writeFile(submissionPath, JSON.stringify(submission)); await writeFile(trustPath, JSON.stringify(trust));
    const options = { submission: submissionPath, pack: packPath, secret, trust: trustPath, releaseArtifact: artifactPath, output: join(directory, "evaluated") };
    const result = await evaluateIndependentBenchmark(options);
    expect(result.result.status, JSON.stringify(result.result.gates.filter((gate) => !gate.passed))).toBe("PASSED");
    expect(JSON.parse(await readFile(result.verificationPath, "utf8"))).toMatchObject({ publisherKeyId: "publisher", operatorKeyId: "operator", blinded: true, externalTargetsTested: true });
    await writeFile(runs[0]!.report.path, "{}"); await expect(evaluateIndependentBenchmark(options)).rejects.toThrow("INPUT_COMMITMENT_MISMATCH");
    await writeFile(artifactPath, "changed"); await expect(evaluateIndependentBenchmark(options)).rejects.toThrow("RELEASE_COMMITMENT_MISMATCH");
  });

  it("rejects loopback and reserved target names", () => {
    for (const url of ["http://127.0.0.1", "http://2130706433", "http://[::1]", "http://localhost", "http://LOCALHOST.", "http://demo.localhost", "http://demo.test.", "http://[::ffff:7f00:1]", "http://0.0.0.0"]) expect(() => assertExternalOrigin(url), url).toThrow();
    expect(() => assertExternalOrigin("https://authorized.security-lab.org")).not.toThrow();
  });

  it("reports uncertainty without treating repetitions as independent samples", () => {
    expect(wilsonInterval(0, 0)).toEqual({ lower: 0, upper: 1, sampleSize: 0 });
    expect(wilsonInterval(10, 10).lower).toBeCloseTo(0.7225, 3);
    expect(wilsonInterval(0, 10).upper).toBeCloseTo(0.2775, 3);
    expect(() => wilsonInterval(11, 10)).toThrow();
    const manifest = { id: "one", label: "one", cases: [{ id: "one", label: "one", expected: "NO_FINDING", selectors: [{ workflowId: "api-graphql-authorization", caseId: "one" }] }], thresholds: {}, regression: {}, metadata: {} };
    const report = { routeCairnVersion: "0.1.0", findings: [], requestAudit: [], apiGraphql: { checks: [{ checkId: "one", outcome: "PASS" }], schemaComparisons: [] } } as unknown as RouteCairnReport;
    const run = { report, telemetry: { runtimeMs: 1, peakRssBytes: 1, requestCount: 1 } };
    expect(evaluateBenchmark(manifest, [run, run, run]).statisticalEvidence.falsePositiveRate.sampleSize).toBe(1);
  });
});
function digest(bytes: Buffer) { return createHash("sha256").update(bytes).digest("hex"); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, sort(item)])); return value; }
