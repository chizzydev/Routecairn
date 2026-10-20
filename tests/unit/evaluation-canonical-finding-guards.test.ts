import { it, expect } from "vitest";
import { createHash, sign } from "node:crypto";
import { witnessFixture } from "../helpers/evaluation-witness-fixture.js";
import {
  sealEvaluationEvidence,
  scoreEvaluationEvidence,
  evaluationWitnessMessage
} from "../../src/benchmark/IndependentEvaluationEvidence.js";
import { commitPracticalRun } from "../../src/benchmark/PracticalAssessmentBenchmark.js";
import { sealProspectivePredictions, oracleReleaseMessage } from "../../src/benchmark/ProspectiveAssessmentIntake.js";
import { heldOutHash } from "../../src/benchmark/HeldOutDiscoveryEvaluation.js";
it("requires canonical proven non-cleanup-failed case and fingerprint linkage, not intermediate module findings", () => {
  const f = witnessFixture(),
    first = f.catalog[0]!,
    original = JSON.parse(f.read(first.path).toString());
  for (const patch of [
    { workflow: { ...original.findings[0].workflow, assessmentOutcome: "INCONCLUSIVE" } },
    { workflow: { ...original.findings[0].workflow, cleanupFailed: true } },
    { workflow: { ...original.findings[0].workflow, comparisonFingerprint: "b".repeat(64) } },
    { sourceModule: "other-module" },
    { workflowCase: { id: first.caseId, comparisonFingerprint: "a".repeat(64) }, workflow: undefined }
  ]) {
    const report = { ...original, findings: [{ ...original.findings[0], ...patch }] },
      bytes = Buffer.from(JSON.stringify(report)),
      hash = createHash("sha256").update(bytes).digest("hex"),
      runs = f.seal.runs.map((r) =>
        commitPracticalRun(
          f.study.benchmark,
          r.runId,
          r.prediction.measurements.map((a) => ({
            ...a,
            predictions: a.predictions.map((p) => (p.id === first.caseId ? { ...p, sourceHash: hash } : p))
          }))
        )
      ),
      seal = sealProspectivePredictions(f.study, runs, f.bindings),
      catalog = f.catalog.map((c) => (c.caseId === first.caseId ? { ...c, sha256: hash } : c));
    expect(() =>
      sealEvaluationEvidence(f.study, f.enrollment, seal, catalog, (p) => (p === first.path ? bytes : f.read(p)))
    ).toThrow("FINDING_LINK");
  }
});
it("keeps abstained known vulnerabilities in missed totals and the fixed denominator", () => {
  const f = witnessFixture(),
    runs = f.seal.runs.map((r) =>
      commitPracticalRun(
        f.study.benchmark,
        r.runId,
        r.prediction.measurements.map((a) => ({
          ...a,
          predictions: a.predictions.map((p) => (p.id === "b-fn" ? { ...p, outcome: "ABSTAIN" } : p))
        }))
      )
    ),
    seal = sealProspectivePredictions(f.study, runs, f.bindings),
    w = sealEvaluationEvidence(f.study, f.enrollment, seal, f.catalog, f.read),
    message = oracleReleaseMessage(f.study as never, seal),
    release = {
      ...message,
      signatureBase64: sign(null, Buffer.from(heldOutHash(message), "ascii"), f.keys.privateKey).toString("base64")
    },
    signature = sign(
      null,
      Buffer.from(heldOutHash(evaluationWitnessMessage(f.study, w)), "ascii"),
      f.keys.privateKey
    ).toString("base64"),
    score = scoreEvaluationEvidence(f.study, seal, release, f.pem, w, signature, f.oracle);
  expect(score.knownVulnerabilities).toEqual({
    total: 6,
    detected: 2,
    falseNegatives: 0,
    abstained: 2,
    untested: 2,
    missed: 4
  });
  expect(score.caseOpportunities).toBe(14);
  expect(score.counts.abstainedKnownTruth).toBe(2);
});
