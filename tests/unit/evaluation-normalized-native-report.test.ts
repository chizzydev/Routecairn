import { it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { witnessFixture } from "../helpers/evaluation-witness-fixture.js";
import { sealEvaluationEvidence } from "../../src/benchmark/IndependentEvaluationEvidence.js";
import { commitPracticalRun } from "../../src/benchmark/PracticalAssessmentBenchmark.js";
import { sealProspectivePredictions } from "../../src/benchmark/ProspectiveAssessmentIntake.js";
it("accepts the exact final normalized finding contract from retained real Windows proof", () => {
  const bytes = readFileSync(new URL("../fixtures/evaluation-normalized-native-report.receipt", import.meta.url)),
    hash = createHash("sha256").update(bytes).digest("hex");
  expect(hash).toBe("07051cb9c4819e354a5f94f8c7c7f2dde33c7e04be35596c05b5ea14b84db9c5");
  const report = JSON.parse(bytes.toString()),
    f = witnessFixture(),
    first = f.catalog[0]!,
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
    catalog = f.catalog.map((c) => (c.caseId === first.caseId ? { ...c, path: "native.receipt", sha256: hash } : c)),
    enrollment = {
      ...f.enrollment,
      cases: f.enrollment.cases.map((c) =>
        c.caseId === first.caseId
          ? { ...c, checkIds: report.scanPlan.apiGraphql.checks.map((c: { id: string }) => c.id) }
          : c
      )
    };
  expect(report.findings[0].workflowCase).toBeUndefined();
  expect(report.findings[0].workflow.assessmentOutcome).toBe("PROVEN");
  const witness = sealEvaluationEvidence(f.study, enrollment, seal, catalog, (p) =>
    p === "native.receipt" ? bytes : f.read(p)
  );
  expect(witness.evidence.filter((e) => e.caseId === first.caseId)).toHaveLength(2);
  expect(witness.independentAcceptance).toBe(false);
});
