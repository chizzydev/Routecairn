import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { commitPracticalRun } from "../../src/benchmark/PracticalAssessmentBenchmark.js";
import { heldOutHash } from "../../src/benchmark/HeldOutDiscoveryEvaluation.js";
import {
  sealProspectivePredictions,
  prospectiveSourceExpectations,
  oracleReleaseMessage
} from "../../src/benchmark/ProspectiveAssessmentIntake.js";
const h = (v: string | Buffer) => createHash("sha256").update(v).digest("hex");
export function evaluationEvidenceFixture() {
  const keys = generateKeyPairSync("ed25519"),
    pem = keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    oracle = Buffer.from(
      JSON.stringify({
        version: 1,
        cases: [
          { id: "a-tp", truth: "VULNERABLE" },
          { id: "a-fp", truth: "SECURE" },
          { id: "a-unknown", truth: "UNCERTAIN" },
          { id: "b-fn", truth: "VULNERABLE" },
          { id: "b-tn", truth: "SECURE" },
          { id: "b-missed", truth: "VULNERABLE" },
          { id: "b-unsafe", truth: "UNCERTAIN" }
        ]
      })
    );
  const applications = [
    {
      id: "a",
      implementationSha256: h("a"),
      caseIds: ["a-tp", "a-fp", "a-unknown"],
      sourceOpportunities: 4,
      routeOpportunities: 2,
      requestCeiling: 20
    },
    {
      id: "b",
      implementationSha256: h("b"),
      caseIds: ["b-fn", "b-tn", "b-missed", "b-unsafe"],
      sourceOpportunities: 4,
      routeOpportunities: 2,
      requestCeiling: 20
    }
  ];
  const benchmark = {
    version: 1,
    datasetId: "owned",
    publisher: "Same-author synthetic protocol tests",
    provenance: "SELF_MAINTAINED",
    repetitions: 2,
    contract: {
      version: 1,
      provenance: "SELF_MAINTAINED_HELD_OUT",
      oracleSha256: h(oracle),
      productSources: [{ path: "src/core.ts", sha256: h("product") }],
      applications
    }
  };
  const study = {
    version: 1,
    studyId: "protocol-control",
    sourceVersionId: "frozen-1",
    runIds: ["r1", "r2"],
    publisherKeySha256: h(pem),
    implementationSources: applications.map((a) => ({
      applicationId: a.id,
      path: "fixtures/" + a.id + ".ts",
      sha256: a.implementationSha256
    })),
    benchmark
  };
  const measurements = applications.map((a) => ({
    applicationId: a.id,
    predictions: a.caseIds.map((id) => ({
      id,
      outcome: id.endsWith("unknown")
        ? "ABSTAIN"
        : id.endsWith("missed")
          ? "UNTESTED"
          : id.endsWith("fn") || id.endsWith("tn")
            ? "NO_FINDING"
            : "FINDING",
      sourceHash: h("native-" + a.id),
      reason: "Synthetic counterexample, not native accuracy evidence"
    })),
    observedSources: 4,
    discoveredRoutes: 2,
    requests: 12,
    wallMs: 1,
    parentCpuMicros: { user: 0, system: 0 }
  }));
  const runs = study.runIds.map((id) => commitPracticalRun(benchmark, id, measurements)),
    bindings = prospectiveSourceExpectations(study),
    sealed = sealProspectivePredictions(study, runs, bindings),
    message = oracleReleaseMessage(study as never, sealed),
    release = {
      ...message,
      signatureBase64: sign(null, Buffer.from(heldOutHash(message), "ascii"), keys.privateKey).toString("base64")
    };
  return { study, runs, bindings, sealed, release, oracle, pem, keys };
}
