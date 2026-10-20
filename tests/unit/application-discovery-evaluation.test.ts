import { it, expect } from "vitest";
import { evaluateApplicationDiscovery } from "../../src/benchmark/ApplicationDiscoveryEvaluation.js";
const hash = "a".repeat(64),
  truth = {
    schemaVersion: 1,
    commitment: hash,
    maintainer: "SELF_MAINTAINED",
    blinded: false,
    cases: [
      { id: "p", truth: "VULNERABLE" },
      { id: "n", truth: "SECURE" },
      { id: "u", truth: "UNCERTAIN" }
    ]
  };
it("counts false positives, missed positives and unsafe uncertainty rather than reporting synthetic perfect accuracy", () => {
  const result = evaluateApplicationDiscovery(truth, [
    { id: "p", outcome: "NO_FINDING", sourceHash: hash, reason: "missed" },
    { id: "n", outcome: "FINDING", sourceHash: hash, reason: "false claim" },
    { id: "u", outcome: "NO_FINDING", sourceHash: hash, reason: "incomplete" }
  ]);
  expect(result.counts).toMatchObject({ falsePositives: 1, falseNegatives: 1, unsafeUncertainConclusions: 1 });
  expect(result.metrics.precision).toBe(0);
  expect(result.independentAcceptance).toBe(false);
});
it("reports missing cases as untested and null zero-denominator metrics", () => {
  const r = evaluateApplicationDiscovery(truth, []);
  expect(r.counts.untested).toBe(3);
  expect(r.metrics.precision).toBe(null);
  expect(r.metrics.conservativeRecall).toBe(0);
});
it("rejects duplicate or extraneous predictions and does not count abstention as a negative", () => {
  const p = { id: "n", outcome: "ABSTAIN", sourceHash: hash, reason: "missing controls" };
  expect(evaluateApplicationDiscovery(truth, [p]).counts.trueNegatives).toBe(0);
  expect(() => evaluateApplicationDiscovery(truth, [p, p])).toThrow("EXACT_UNIQUE");
  expect(() => evaluateApplicationDiscovery(truth, [{ ...p, id: "outside" }])).toThrow("EXACT_UNIQUE");
});

it("distinguishes accounted abstention from conclusive proof coverage", () => {
  const r = evaluateApplicationDiscovery(truth, [
    { id: "p", outcome: "FINDING", sourceHash: hash, reason: "native proof" },
    { id: "n", outcome: "NO_FINDING", sourceHash: hash, reason: "native protected controls" },
    { id: "u", outcome: "ABSTAIN", sourceHash: hash, reason: "missing controls" }
  ]);
  expect(r.metrics.predictionCoverage).toBe(1);
  expect(r.metrics.conclusivePredictionFraction).toBe(2 / 3);
});
