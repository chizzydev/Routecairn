import { it, expect } from "vitest";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { commitPracticalRun } from "../../src/benchmark/PracticalAssessmentBenchmark.js";
import { heldOutHash } from "../../src/benchmark/HeldOutDiscoveryEvaluation.js";
import {
  sealProspectivePredictions,
  prospectiveSourceExpectations,
  oracleReleaseMessage,
  verifyProspectiveRelease,
  revealProspectiveStudy
} from "../../src/benchmark/ProspectiveAssessmentIntake.js";
const h = (v: string | Buffer) => createHash("sha256").update(v).digest("hex");
function fixture() {
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
  return { study, runs, bindings, sealed, release, oracle, pem };
}
it("requires all applications, cases and repetitions globally before any signed label release", () => {
  const f = fixture();
  expect(f.sealed.oracleReadBySeal).toBe(false);
  expect(() => sealProspectivePredictions(f.study, f.runs.slice(0, 1), f.bindings)).toThrow("ALL_RUNS");
  const missing = commitPracticalRun(f.study.benchmark, "r1", []);
  expect(() => sealProspectivePredictions(f.study, [missing, f.runs[1]!], f.bindings)).toThrow("ALL_CASES");
});
it("requires exact source versions and implementation commitments, without inferring independent authorship", () => {
  const f = fixture();
  expect(() => sealProspectivePredictions(f.study, f.runs, f.bindings.slice(1))).toThrow("SOURCE");
  const r = revealProspectiveStudy(f.study, f.sealed, f.release, f.pem, f.oracle);
  expect(r).toMatchObject({
    releaseSignatureVerified: true,
    independentAcceptance: false,
    blinded: false,
    secrecyOrTrustedWallClockProven: false
  });
  expect(r.caseOpportunities).toBe(14);
});
it("reports TP, FP, TN, FN, correct abstentions, unsafe uncertain conclusions and explicit missed cases", () => {
  const f = fixture(),
    r = revealProspectiveStudy(f.study, f.sealed, f.release, f.pem, f.oracle);
  expect(r.counts).toMatchObject({
    truePositives: 2,
    falsePositives: 2,
    trueNegatives: 2,
    falseNegatives: 2,
    correctAbstentions: 2,
    unsafeUncertainConclusions: 2,
    untested: 2
  });
  expect(r.runs[0]!.applications.every((a) => !!a.neutralAlwaysAbstain)).toBe(true);
});
it("refuses late prediction edits, changed public denominator and replayed release under another source version", () => {
  const f = fixture(),
    bad = structuredClone(f.sealed);
  bad.runs[0]!.prediction.measurements[0]!.predictions[0]!.outcome = "NO_FINDING";
  expect(() => verifyProspectiveRelease(f.study, bad, f.release, f.pem)).toThrow();
  expect(() =>
    verifyProspectiveRelease({ ...f.study, sourceVersionId: "changed" }, f.sealed, f.release, f.pem)
  ).toThrow();
  expect(() =>
    verifyProspectiveRelease(
      { ...f.study, benchmark: { ...f.study.benchmark, repetitions: 3 } },
      f.sealed,
      f.release,
      f.pem
    )
  ).toThrow();
});
it("refuses an unsigned, unpinned or altered oracle release before accepting any labels", () => {
  const f = fixture();
  expect(() => verifyProspectiveRelease(f.study, f.sealed, { ...f.release, signatureBase64: "" }, f.pem)).toThrow(
    "RELEASE_BINDING"
  );
  expect(() =>
    verifyProspectiveRelease(
      f.study,
      f.sealed,
      { ...f.release, signatureBase64: Buffer.alloc(64).toString("base64") },
      f.pem
    )
  ).toThrow("SIGNATURE");
  expect(() => revealProspectiveStudy(f.study, f.sealed, f.release, f.pem, Buffer.from("{}"))).toThrow("COMMITMENT");
});
it("rejects duplicate implementations and unsafe source paths rather than adopting arbitrary filesystem inputs", () => {
  const f = fixture();
  expect(() =>
    prospectiveSourceExpectations({
      ...f.study,
      implementationSources: f.study.implementationSources.map((a) => ({ ...a, path: "same.ts" }))
    })
  ).toThrow("IMPLEMENTATION");
  expect(() =>
    prospectiveSourceExpectations({
      ...f.study,
      benchmark: {
        ...f.study.benchmark,
        contract: { ...f.study.benchmark.contract, productSources: [{ path: "../private", sha256: h("x") }] }
      }
    })
  ).toThrow("SAFE");
});

it("refuses private signing material even if an operator mistakenly pins its digest as a publisher key", () => {
  const f = fixture(),
    keys = generateKeyPairSync("ed25519"),
    privatePem = keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    study = { ...f.study, publisherKeySha256: h(privatePem) },
    sealed = sealProspectivePredictions(study, f.runs, f.bindings),
    message = oracleReleaseMessage(study as never, sealed),
    release = {
      ...message,
      signatureBase64: sign(null, Buffer.from(heldOutHash(message), "ascii"), keys.privateKey).toString("base64")
    };
  expect(() => verifyProspectiveRelease(study, sealed, release, privatePem)).toThrow("SIGNATURE");
});

it("refuses to read the designated private oracle disguised as a public source commitment", () => {
  const f = fixture(),
    study = {
      ...f.study,
      benchmark: {
        ...f.study.benchmark,
        contract: {
          ...f.study.benchmark.contract,
          productSources: [{ path: "disguised.ts", sha256: f.study.benchmark.contract.oracleSha256 }]
        }
      }
    };
  expect(() => prospectiveSourceExpectations(study)).toThrow("SOURCE_CANNOT_BE_ORACLE");
});
