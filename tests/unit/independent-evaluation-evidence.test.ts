import { it, expect } from "vitest";
import { createHash } from "node:crypto";
import { commitPracticalRun } from "../../src/benchmark/PracticalAssessmentBenchmark.js";
import { sealProspectivePredictions } from "../../src/benchmark/ProspectiveAssessmentIntake.js";
import {
  sealEvaluationEvidence,
  verifyEvaluationWitness,
  scoreEvaluationEvidence
} from "../../src/benchmark/IndependentEvaluationEvidence.js";
const h = (v: Buffer) => createHash("sha256").update(v).digest("hex");
import { witnessFixture as fixture } from "../helpers/evaluation-witness-fixture.js";

it("binds case evidence and families before signed reveal and counts all missed vulnerabilities", () => {
  const f = fixture(),
    r = scoreEvaluationEvidence(f.study, f.seal, f.release, f.pem, f.witness, f.signature, f.oracle);
  expect(r).toMatchObject({
    caseOpportunities: 14,
    evidenceFiles: 12,
    independentAcceptance: false,
    blinded: false,
    knownVulnerabilities: { total: 6, detected: 2, falseNegatives: 2, abstained: 0, untested: 2, missed: 4 }
  });
  expect(r.families).toHaveLength(2);
  expect(r.decisionCoverage).toBe(10 / 14);
});
it("rejects changed bytes, missing/extra/duplicate evidence and changed case denominator", () => {
  const f = fixture();
  for (const c of [f.catalog.slice(1), [...f.catalog, f.catalog[0]!], [f.catalog[0]!, ...f.catalog.slice(0, -1)]])
    expect(() => sealEvaluationEvidence(f.study, f.enrollment, f.seal, c, f.read)).toThrow("DENOMINATOR");
  expect(() => sealEvaluationEvidence(f.study, f.enrollment, f.seal, f.catalog, () => Buffer.from("{}"))).toThrow(
    "BYTES"
  );
  expect(() =>
    sealEvaluationEvidence(f.study, { ...f.enrollment, cases: f.enrollment.cases.slice(1) }, f.seal, f.catalog, f.read)
  ).toThrow("CASE_BINDINGS");
});
it("refuses observation-only evidence as decisive proof and requires exact finding linkage", () => {
  const f = fixture(),
    path = f.catalog[0]!.path,
    b = JSON.parse(f.files.get(path)!.toString());
  b.scanPlan.apiGraphql.checks[0].response.expectedDecision = "OBSERVE";
  const bytes = Buffer.from(JSON.stringify(b));
  const runs = f.seal.runs.map((r) =>
      commitPracticalRun(
        f.study.benchmark,
        r.runId,
        r.prediction.measurements.map((a) => ({
          ...a,
          predictions: a.predictions.map((p) => (p.id === f.catalog[0]!.caseId ? { ...p, sourceHash: h(bytes) } : p))
        }))
      )
    ),
    s = sealProspectivePredictions(f.study, runs, f.bindings),
    cat = f.catalog.map((c) => (c.path === path ? { ...c, sha256: h(bytes) } : c));
  expect(() => sealEvaluationEvidence(f.study, f.enrollment, s, cat, (p) => (p === path ? bytes : f.read(p)))).toThrow(
    "DECISIVE"
  );
  b.scanPlan.apiGraphql.checks[0].response.expectedDecision = "DENY";
  b.findings = [];
  const b2 = Buffer.from(JSON.stringify(b)),
    r2 = runs.map((r) =>
      commitPracticalRun(
        f.study.benchmark,
        r.runId,
        r.prediction.measurements.map((a) => ({
          ...a,
          predictions: a.predictions.map((p) => (p.id === f.catalog[0]!.caseId ? { ...p, sourceHash: h(b2) } : p))
        }))
      )
    );
  expect(() =>
    sealEvaluationEvidence(
      f.study,
      f.enrollment,
      sealProspectivePredictions(f.study, r2, f.bindings),
      cat.map((c) => (c.path === path ? { ...c, sha256: h(b2) } : c)),
      (p) => (p === path ? b2 : f.read(p))
    )
  ).toThrow("FINDING_LINK");
});
it("requires pinned witness signature and original global release before accepting labels", () => {
  const f = fixture();
  expect(() => verifyEvaluationWitness(f.study, f.seal, f.release, f.pem, f.witness, "bad")).toThrow("SIGNATURE");
  const w = structuredClone(f.witness);
  w.enrollment.evaluatorId = "changed";
  expect(() => verifyEvaluationWitness(f.study, f.seal, f.release, f.pem, w, f.signature)).toThrow("CUSTODY");
  expect(() =>
    scoreEvaluationEvidence(f.study, f.seal, f.release, f.pem, f.witness, f.signature, Buffer.from("{}"))
  ).toThrow("COMMITMENT");
  expect(() => sealEvaluationEvidence(f.study, { ...f.enrollment, labels: [] }, f.seal, f.catalog, f.read)).toThrow();
});
