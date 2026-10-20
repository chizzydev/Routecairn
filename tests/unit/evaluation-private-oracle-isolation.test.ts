import { it, expect, vi } from "vitest";
import { createHash } from "node:crypto";
import { witnessFixture } from "../helpers/evaluation-witness-fixture.js";
import { sealEvaluationEvidence } from "../../src/benchmark/IndependentEvaluationEvidence.js";
import { commitPracticalRun } from "../../src/benchmark/PracticalAssessmentBenchmark.js";
import { sealProspectivePredictions } from "../../src/benchmark/ProspectiveAssessmentIntake.js";
import { heldOutHash } from "../../src/benchmark/HeldOutDiscoveryEvaluation.js";
it("refuses the designated private oracle disguised as native evidence before invoking any loader", () => {
  const f = witnessFixture(),
    first = f.catalog[0]!,
    dual = Buffer.from(
      JSON.stringify({ ...JSON.parse(f.read(first.path).toString()), ...JSON.parse(f.oracle.toString()) })
    ),
    hash = createHash("sha256").update(dual).digest("hex"),
    study = {
      ...f.study,
      benchmark: { ...f.study.benchmark, contract: { ...f.study.benchmark.contract, oracleSha256: hash } }
    },
    runs = f.seal.runs.map((r) =>
      commitPracticalRun(
        study.benchmark,
        r.runId,
        r.prediction.measurements.map((a) => ({
          ...a,
          predictions: a.predictions.map((p) => (p.id === first.caseId ? { ...p, sourceHash: hash } : p))
        }))
      )
    ),
    seal = sealProspectivePredictions(study, runs, f.bindings),
    enrollment = { ...f.enrollment, studyFingerprint: heldOutHash(study) },
    catalog = f.catalog.map((c) => (c.path === first.path ? { ...c, sha256: hash } : c)).reverse(),
    read = vi.fn((p: string) => (p === first.path ? dual : f.read(p)));
  expect(() => sealEvaluationEvidence(study, enrollment, seal, catalog, read)).toThrow(
    "EVALUATION_PRIVATE_ORACLE_EVIDENCE_REFUSED"
  );
  expect(read).not.toHaveBeenCalled();
});
it("states the narrower API and hash guarantees without claiming label secrecy", () => {
  const f = witnessFixture();
  expect(f.witness).toMatchObject({
    oracleArgumentAccepted: false,
    labelSecrecyEstablished: false,
    privateOracleHashExcludedFromDeclaredEvidence: true,
    independentAcceptance: false,
    blinded: false
  });
  expect(f.witness).not.toHaveProperty("oracleRead");
});
