import type { Finding } from "../../src/core/findings/Finding.js";
import { acceptAssistedWorkflowFindings } from "../../src/core/findings/AssistedWorkflowFindingAcceptance.js";
import { createHash, sign } from "node:crypto";
import { evaluationEvidenceFixture } from "./evaluation-evidence-fixture.js";
import { heldOutHash } from "../../src/benchmark/HeldOutDiscoveryEvaluation.js";
import { commitPracticalRun } from "../../src/benchmark/PracticalAssessmentBenchmark.js";
import { sealProspectivePredictions, oracleReleaseMessage } from "../../src/benchmark/ProspectiveAssessmentIntake.js";
import { sealEvaluationEvidence, evaluationWitnessMessage } from "../../src/benchmark/IndependentEvaluationEvidence.js";
function nativeFinding(caseId: string, comparisonFingerprint: string) {
  // A typed local fixture input; the real production acceptance boundary creates workflow provenance.
  // Avoid importing unrelated legacy report factories into the strict evaluator test type scope.
  const module = "api-graphql-authorization";
  const finding: Finding = {
    id: module + "-" + caseId,
    title: "Session remains valid",
    type: "Authentication Lifecycle Issue",
    severity: "High",
    confidence: "High",
    url: "https://app.test/session",
    method: "POST",
    sourceModule: module,
    evidence: {
      url: "https://app.test/session",
      method: "POST",
      statusCode: 200,
      bodyHash: "a".repeat(64),
      source: "fixture"
    },
    impact: "The old session retains access.",
    recommendation: "Invalidate old sessions on logout.",
    manualTestingSuggestions: [],
    tags: [],
    riskScore: 0,
    falsePositiveStatus: "likely-valid",
    timestamp: new Date(0).toISOString(),
    workflowCase: { id: caseId, comparisonFingerprint: "a".repeat(64), cleanupOutcome: "ROLLBACK_VERIFIED" }
  };
  finding.method = "GET";
  finding.evidence.method = "GET";
  finding.workflowCase!.comparisonFingerprint = comparisonFingerprint;
  return acceptAssistedWorkflowFindings({ pluginName: "api-graphql-authorization", findings: [finding] }).findings![0]!;
}
const h = (v: Buffer) => createHash("sha256").update(v).digest("hex");
export function witnessFixture() {
  const f = evaluationEvidenceFixture(),
    files = new Map<string, Buffer>(),
    enrollment = {
      version: 1,
      studyFingerprint: heldOutHash(f.study),
      evaluatorId: "same-author-development-only",
      provenance: "SELF_MAINTAINED",
      families: f.study.benchmark.contract.applications.map((a) => ({
        applicationId: a.id,
        familyId: "synthetic-" + a.id
      })),
      cases: f.study.benchmark.contract.applications.flatMap((a) =>
        a.caseIds.map((caseId) => ({ applicationId: a.id, caseId, checkIds: [caseId] }))
      )
    };
  const measurements = f.runs[0]!.prediction.measurements.map((a) => ({
    ...a,
    predictions: a.predictions.map((p) => {
      const fp = "a".repeat(64),
        outcome = p.outcome === "FINDING" ? "FAIL" : p.outcome === "ABSTAIN" ? "INCONCLUSIVE" : "PASS",
        report = {
          execution: { status: "COMPLETED", partial: false },
          scanPlan: {
            apiGraphql: { checks: [{ id: p.id, comparisonFingerprint: fp, response: { expectedDecision: "DENY" } }] }
          },
          apiGraphql: { checks: [{ checkId: p.id, outcome, comparisonFingerprint: fp }] },
          findings: outcome === "FAIL" ? [nativeFinding(p.id, fp)] : []
        },
        bytes = Buffer.from(JSON.stringify(report));
      files.set(p.id + ".json", bytes);
      return { ...p, sourceHash: h(bytes) };
    })
  }));
  const runs = f.study.runIds.map((id) => commitPracticalRun(f.study.benchmark, id, measurements)),
    seal = sealProspectivePredictions(f.study, runs, f.bindings),
    catalog = runs.flatMap((r) =>
      r.prediction.measurements.flatMap((a) =>
        a.predictions
          .filter((p) => p.outcome !== "UNTESTED")
          .map((p) => ({
            runId: r.runId,
            applicationId: a.applicationId,
            caseId: p.id,
            path: p.id + ".json",
            sha256: p.sourceHash
          }))
      )
    ),
    read = (p: string) => files.get(p)!;
  const witness = sealEvaluationEvidence(f.study, enrollment, seal, catalog, read),
    message = oracleReleaseMessage(f.study as never, seal),
    release = {
      ...message,
      signatureBase64: sign(null, Buffer.from(heldOutHash(message), "ascii"), f.keys.privateKey).toString("base64")
    },
    signature = sign(
      null,
      Buffer.from(heldOutHash(evaluationWitnessMessage(f.study, witness)), "ascii"),
      f.keys.privateKey
    ).toString("base64");
  return { ...f, files, enrollment, seal, catalog, read, witness, release, signature };
}
