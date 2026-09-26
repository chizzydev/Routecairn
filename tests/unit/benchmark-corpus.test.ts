import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { openBenchmarkPack, sealBenchmarkManifest, signBenchmarkManifest, verifyBenchmarkManifest } from "../../src/benchmark/BenchmarkCorpus.js";
import { credibilityTruthManifest } from "../../src/benchmark/CredibilityBenchmarkLab.js";

describe("benchmark corpus integrity", () => {
  it("builds a policy-gated corpus with hundreds of balanced executable cases", () => {
    const manifest = credibilityTruthManifest([
      { id: "node-http", language: "TypeScript", framework: "node:http" },
      { id: "python-http", language: "Python", framework: "http.server" }
    ]);
    expect(manifest.cases).toHaveLength(240);
    expect(manifest.cases.filter((item) => item.expected === "FINDING")).toHaveLength(120);
    expect(manifest.cases.filter((item) => item.control === "NEAR_MISS")).toHaveLength(60);
    expect(manifest.cases.filter((item) => item.complexity === "MULTI_STEP")).toHaveLength(40);
    expect(manifest.cases.filter((item) => item.complexity === "SECOND_ORDER")).toHaveLength(40);
    expect(new Set(manifest.cases.map((item) => item.framework))).toEqual(new Set(["node:http", "http.server"]));
  });

  it("seals ground truth without exposing expectations and detects wrong keys or tampering", () => {
    const manifest = fixture(); const secret = "this-is-a-long-independent-evaluator-secret"; const pack = sealBenchmarkManifest(manifest, secret);
    expect(JSON.stringify(pack.public)).not.toContain("FINDING");
    expect(JSON.stringify(pack.public)).not.toContain("positive");
    expect(openBenchmarkPack(pack, secret).cases[0]).toMatchObject({ expected: "FINDING", blindId: expect.stringMatching(/^[a-f0-9]{64}$/) });
    expect(() => openBenchmarkPack(pack, "this-is-a-different-long-evaluator-secret")).toThrow("BENCHMARK_BLIND_DECRYPTION_FAILED");
    expect(() => openBenchmarkPack({ ...pack, public: { ...pack.public, label: "tampered" } }, secret)).toThrow("BENCHMARK_BLIND_PUBLIC_DIGEST_MISMATCH");
  });

  it("verifies detached corpus authorship with Ed25519", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519"); const signed = signBenchmarkManifest(fixture(), privateKey.export({ type: "pkcs8", format: "pem" }).toString(), "independent-lab-2026");
    expect(verifyBenchmarkManifest(signed, publicKey.export({ type: "spki", format: "pem" }).toString(), "independent-lab-2026").corpus?.signature?.keyId).toBe("independent-lab-2026");
    expect(() => verifyBenchmarkManifest({ ...signed, label: "tampered" }, publicKey.export({ type: "spki", format: "pem" }).toString())).toThrow("BENCHMARK_CORPUS_SIGNATURE_INVALID");
  });
});

function fixture() {
  return { schemaVersion: 1 as const, id: "signed-corpus", label: "Signed corpus", cases: [{ id: "case-1", label: "opaque case", expected: "FINDING" as const, selectors: [{ workflowId: "api-graphql-authorization", caseId: "case-1" }], category: "AUTHORIZATION", tags: ["blind"], language: "TypeScript", framework: "node:http", weaknessId: "CWE-639", control: "VULNERABLE" as const, complexity: "SINGLE_STEP" as const, required: true }], thresholds: {}, regression: {}, corpus: { version: "1.0.0", publisher: "Independent fixture maintainer", publishedAt: "2026-09-26T00:00:00.000Z", license: "MIT", independence: "EXTERNAL" as const, blinded: false }, metadata: {} };
}
