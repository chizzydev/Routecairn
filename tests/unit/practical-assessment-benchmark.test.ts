import { it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  importPracticalBenchmark,
  commitPracticalRun,
  scorePracticalRun,
  summarizePracticalRuns
} from "../../src/benchmark/PracticalAssessmentBenchmark.js";
const hash = (b: Buffer | string) => createHash("sha256").update(b).digest("hex"),
  h = "a".repeat(64);
const oracle = Buffer.from(
  JSON.stringify({
    version: 1,
    cases: [
      { id: "one-positive", truth: "VULNERABLE" },
      { id: "two-negative", truth: "SECURE" },
      { id: "two-unknown", truth: "UNCERTAIN" }
    ]
  })
);
const manifest = {
  version: 1,
  datasetId: "local",
  publisher: "Same-author controls",
  provenance: "SELF_MAINTAINED",
  repetitions: 2,
  contract: {
    version: 1,
    provenance: "SELF_MAINTAINED_HELD_OUT",
    oracleSha256: hash(oracle),
    productSources: [{ path: "src/example.ts", sha256: h }],
    applications: [
      {
        id: "one",
        implementationSha256: h,
        caseIds: ["one-positive"],
        sourceOpportunities: 4,
        routeOpportunities: 1,
        requestCeiling: 8
      },
      {
        id: "two",
        implementationSha256: h,
        caseIds: ["two-negative", "two-unknown"],
        sourceOpportunities: 4,
        routeOpportunities: 2,
        requestCeiling: 12
      }
    ]
  }
};
const measurements = [
  {
    applicationId: "one",
    predictions: [{ id: "one-positive", outcome: "NO_FINDING", sourceHash: h, reason: "counterexample" }],
    observedSources: 4,
    discoveredRoutes: 1,
    requests: 8,
    wallMs: 2,
    parentCpuMicros: { user: 0, system: 0 }
  },
  {
    applicationId: "two",
    predictions: [
      { id: "two-negative", outcome: "FINDING", sourceHash: h, reason: "counterexample" },
      { id: "two-unknown", outcome: "ABSTAIN", sourceHash: h, reason: "missing controls" }
    ],
    observedSources: 4,
    discoveredRoutes: 2,
    requests: 12,
    wallMs: 3,
    parentCpuMicros: { user: 0, system: 0 }
  }
];
it("imports a locked public manifest without opening the private answer key; signatures never establish independent authorship", () => {
  const b = Buffer.from(JSON.stringify(manifest)),
    keys = generateKeyPairSync("ed25519"),
    pem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  expect(
    importPracticalBenchmark(b, hash(b), {
      publicKeyPem: pem,
      expectedKeySha256: hash(pem),
      signature: sign(null, b, keys.privateKey)
    })
  ).toMatchObject({ publisherSignatureVerified: true, independentAcceptance: false });
  expect(() => importPracticalBenchmark(b, h)).toThrow("COMMITMENT");
  expect(() =>
    importPracticalBenchmark(b, hash(b), {
      publicKeyPem: pem,
      expectedKeySha256: h,
      signature: sign(null, b, keys.privateKey)
    })
  ).toThrow("SIGNATURE");
});
it("retains actual false-positive and false-negative counterexamples, abstentions and the full missing-run denominator", () => {
  const r = commitPracticalRun(manifest, "first", measurements),
    s = scorePracticalRun(manifest, r, oracle);
  expect(s.counts).toMatchObject({ falsePositives: 1, falseNegatives: 1, correctAbstentions: 1 });
  expect(s.falsePositiveReview).toHaveLength(1);
  const summary = summarizePracticalRuns(manifest, [r], oracle);
  expect(summary).toMatchObject({ caseOpportunities: 6, missingRuns: 1, allCasesRepeatable: false });
  expect(summary.cells.every((c) => c.outcomes[1] === "UNTESTED")).toBe(true);
});
it("detects unstable predictions across exact source-bound repetitions without hiding either result", () => {
  const a = commitPracticalRun(manifest, "a", measurements),
    b = commitPracticalRun(manifest, "b", []);
  expect(summarizePracticalRuns(manifest, [a, b], oracle).cells.some((c) => !c.repeatable)).toBe(true);
  expect(
    summarizePracticalRuns(manifest, [a, commitPracticalRun(manifest, "b", measurements)], oracle).allCasesRepeatable
  ).toBe(true);
  expect(() => summarizePracticalRuns(manifest, [a, a], oracle)).toThrow("REPETITIONS");
});
it("rejects changed labels, receipt tampering, over-budget and unregistered cases", () => {
  const r = commitPracticalRun(manifest, "a", measurements);
  expect(() => scorePracticalRun(manifest, r, Buffer.from("{}"))).toThrow("COMMITMENT");
  expect(() => scorePracticalRun(manifest, { ...r, manifestFingerprint: h }, oracle)).toThrow("BINDING");
  expect(() => commitPracticalRun(manifest, "b", [{ ...measurements[0], requests: 9 }])).toThrow("BUDGET");
  expect(() =>
    commitPracticalRun(manifest, "b", [
      { ...measurements[0], predictions: [{ id: "unregistered", outcome: "FINDING", sourceHash: h, reason: "x" }] }
    ])
  ).toThrow("BUDGET");
});
