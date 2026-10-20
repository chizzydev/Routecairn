import { z } from "zod";
import { createHash, createPublicKey, verify } from "node:crypto";
import { heldOutHash } from "./HeldOutDiscoveryEvaluation.js";
import {
  prospectiveStudySchema,
  sealProspectivePredictions,
  verifyProspectiveRelease,
  revealProspectiveStudy,
  type ProspectiveSeal,
  type OracleRelease
} from "./ProspectiveAssessmentIntake.js";
const id = z.string().regex(/^[A-Za-z0-9_:.-]{1,160}$/),
  sha = z.string().regex(/^[a-f0-9]{64}$/);
export const evaluationEnrollmentSchema = z
  .object({
    version: z.literal(1),
    studyFingerprint: sha,
    evaluatorId: id,
    provenance: z.enum(["SELF_MAINTAINED", "EXTERNAL_EVALUATOR_CLAIM"]),
    families: z
      .array(z.object({ applicationId: id, familyId: id }).strict())
      .min(2)
      .max(32),
    cases: z
      .array(z.object({ applicationId: id, caseId: id, checkIds: z.array(id).min(1).max(64) }).strict())
      .min(1)
      .max(8192)
  })
  .strict();
export const evaluationCatalogSchema = z
  .array(
    z
      .object({
        runId: id,
        applicationId: id,
        caseId: id,
        path: z.string().regex(/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/),
        sha256: sha
      })
      .strict()
  )
  .max(81920);
const canonicalApiFinding = z
  .object({
    sourceModule: z.literal("api-graphql-authorization"),
    workflow: z
      .object({
        workflowId: z.literal("api-graphql-authorization"),
        caseId: id,
        comparisonFingerprint: sha,
        assessmentOutcome: z.literal("PROVEN"),
        humanReviewState: z.literal("REQUIRED"),
        cleanupFailed: z.literal(false)
      })
      .passthrough()
  })
  .passthrough();
const reportSchema = z
  .object({
    execution: z.object({ status: z.string(), partial: z.boolean() }).passthrough(),
    scanPlan: z
      .object({
        apiGraphql: z
          .object({
            checks: z
              .array(
                z
                  .object({
                    id,
                    comparisonFingerprint: sha,
                    response: z.object({ expectedDecision: z.enum(["ALLOW", "DENY", "OBSERVE"]) }).passthrough()
                  })
                  .passthrough()
              )
              .max(8192)
          })
          .passthrough()
      })
      .passthrough(),
    apiGraphql: z
      .object({
        checks: z
          .array(
            z
              .object({
                checkId: id,
                comparisonFingerprint: sha,
                outcome: z.enum(["PASS", "FAIL", "INCONCLUSIVE", "BLOCKED"])
              })
              .passthrough()
          )
          .max(8192)
      })
      .passthrough(),
    findings: z.array(z.unknown()).max(8192)
  })
  .passthrough();
const pair = (a: string, b: string) => a + "/" + b;
function enrollment(study: unknown, value: unknown) {
  const m = prospectiveStudySchema.parse(study),
    e = evaluationEnrollmentSchema.parse(value),
    apps = m.benchmark.contract.applications;
  if (
    e.studyFingerprint !== heldOutHash(m) ||
    new Set(e.families.map((f) => f.applicationId)).size !== apps.length ||
    e.families.length !== apps.length ||
    e.families.some((f) => !apps.some((a) => a.id === f.applicationId))
  )
    throw Error("EVALUATION_EXACT_FAMILY_ENROLLMENT");
  const expected = apps.flatMap((a) => a.caseIds.map((c) => pair(a.id, c))).sort(),
    actual = e.cases.map((c) => pair(c.applicationId, c.caseId)).sort();
  if (
    heldOutHash(expected) !== heldOutHash(actual) ||
    e.cases.some((c) => new Set(c.checkIds).size !== c.checkIds.length)
  )
    throw Error("EVALUATION_EXACT_PUBLIC_CASE_BINDINGS");
  return { m, e };
}
/** Reports remain private inputs. Export only hashes and exact check receipts. This authenticates bytes, not their author or ground truth. */
export function sealEvaluationEvidence(
  study: unknown,
  value: unknown,
  seal: ProspectiveSeal,
  catalogValue: unknown,
  read: (path: string) => Buffer
) {
  const { m, e } = enrollment(study, value),
    catalog = evaluationCatalogSchema.parse(catalogValue),
    bound = sealProspectivePredictions(m, seal.runs, seal.sourceBindings);
  if (heldOutHash(bound) !== heldOutHash(seal)) throw Error("EVALUATION_SEAL_CUSTODY");
  if (catalog.some((c) => c.path.split("/").some((p) => p === "." || p === "..")))
    throw Error("EVALUATION_SAFE_EVIDENCE_PATH");
  const predictions = seal.runs.flatMap((r) =>
      r.prediction.measurements.flatMap((a) =>
        a.predictions.map((p) => ({ runId: r.runId, applicationId: a.applicationId, ...p }))
      )
    ),
    required = predictions.filter((p) => p.outcome !== "UNTESTED"),
    key = (p: { runId: string; applicationId: string; caseId: string }) =>
      p.runId + "/" + pair(p.applicationId, p.caseId);
  if (
    catalog.length !== required.length ||
    new Set(catalog.map(key)).size !== catalog.length ||
    catalog.some((c) => !required.some((p) => key(c) === key({ ...p, caseId: p.id })))
  )
    throw Error("EVALUATION_EXACT_EVIDENCE_DENOMINATOR");
  // Reject the designated private oracle anywhere in the catalog before invoking any loader.
  // Hash exclusion cannot prove that other public files contain no answer leakage.
  if (catalog.some((c) => c.sha256 === m.benchmark.contract.oracleSha256))
    throw Error("EVALUATION_PRIVATE_ORACLE_EVIDENCE_REFUSED");
  const receipts = catalog.map((c) => {
    const p = required.find((p) => key(c) === key({ ...p, caseId: p.id }))!,
      bytes = read(c.path);
    if (
      bytes.length > 8388608 ||
      createHash("sha256").update(bytes).digest("hex") !== c.sha256 ||
      p.sourceHash !== c.sha256
    )
      throw Error("EVALUATION_EVIDENCE_BYTES_CHANGED");
    const report = reportSchema.parse(JSON.parse(bytes.toString("utf8"))),
      binding = e.cases.find((b) => b.applicationId === c.applicationId && b.caseId === c.caseId)!;
    const checks = binding.checkIds.map((id) => {
      const plans = report.scanPlan.apiGraphql.checks.filter((x) => x.id === id),
        observed = report.apiGraphql.checks.filter((x) => x.checkId === id);
      if (
        plans.length !== 1 ||
        observed.length !== 1 ||
        plans[0]!.comparisonFingerprint !== observed[0]!.comparisonFingerprint
      )
        throw Error("EVALUATION_EXACT_NATIVE_CHECK_REQUIRED");
      return {
        id,
        outcome: observed[0]!.outcome,
        expectedDecision: plans[0]!.response.expectedDecision,
        comparisonFingerprint: observed[0]!.comparisonFingerprint
      };
    });
    if (
      p.outcome !== "ABSTAIN" &&
      (report.execution.status !== "COMPLETED" ||
        report.execution.partial ||
        checks.some((c) => c.expectedDecision === "OBSERVE" || ["INCONCLUSIVE", "BLOCKED"].includes(c.outcome)))
    )
      throw Error("EVALUATION_DECISIVE_PROOF_COVERAGE_REQUIRED");
    if (p.outcome === "NO_FINDING" && checks.some((c) => c.outcome !== "PASS"))
      throw Error("EVALUATION_NO_FINDING_REQUIRES_ALL_PASS");
    if (
      p.outcome === "FINDING" &&
      !checks.some(
        (c) =>
          c.outcome === "FAIL" &&
          report.findings.some((f) => {
            const accepted = canonicalApiFinding.safeParse(f);
            return (
              accepted.success &&
              accepted.data.workflow.caseId === c.id &&
              accepted.data.workflow.comparisonFingerprint === c.comparisonFingerprint
            );
          })
      )
    )
      throw Error("EVALUATION_FINDING_LINK_REQUIRED");
    return { ...c, checks, prediction: p.outcome };
  });
  const body = {
    version: 1 as const,
    enrollment: e,
    predictionBundleSha256: seal.predictionBundleSha256,
    evidence: receipts,
    oracleArgumentAccepted: false as const,
    labelSecrecyEstablished: false as const,
    privateOracleHashExcludedFromDeclaredEvidence: true as const
  };
  return {
    ...body,
    witnessSha256: heldOutHash(body),
    independentAcceptance: false as const,
    blinded: false as const,
    executionAuthority: "NONE" as const
  };
}
export type EvaluationWitness = ReturnType<typeof sealEvaluationEvidence>;
export function evaluationWitnessMessage(study: unknown, w: EvaluationWitness) {
  const m = prospectiveStudySchema.parse(study);
  return {
    version: 1,
    studyFingerprint: heldOutHash(m),
    predictionBundleSha256: w.predictionBundleSha256,
    witnessSha256: w.witnessSha256,
    oracleSha256: m.benchmark.contract.oracleSha256
  };
}
export function verifyEvaluationWitness(
  study: unknown,
  seal: ProspectiveSeal,
  release: OracleRelease,
  pem: string,
  w: EvaluationWitness,
  signature: string
) {
  verifyProspectiveRelease(study, seal, release, pem);
  enrollment(study, w.enrollment);
  const { witnessSha256, independentAcceptance, blinded, executionAuthority, ...body } = w;
  if (
    witnessSha256 !== heldOutHash(body) ||
    independentAcceptance !== false ||
    blinded !== false ||
    executionAuthority !== "NONE" ||
    w.oracleArgumentAccepted !== false ||
    w.labelSecrecyEstablished !== false ||
    w.privateOracleHashExcludedFromDeclaredEvidence !== true ||
    w.predictionBundleSha256 !== seal.predictionBundleSha256
  )
    throw Error("EVALUATION_WITNESS_CUSTODY");
  if (
    createPublicKey(pem).asymmetricKeyType !== "ed25519" ||
    !/^[A-Za-z0-9+/]{86}==$/.test(signature) ||
    !verify(
      null,
      Buffer.from(heldOutHash(evaluationWitnessMessage(study, w)), "ascii"),
      pem,
      Buffer.from(signature, "base64")
    )
  )
    throw Error("EVALUATION_WITNESS_RELEASE_SIGNATURE");
}
export function scoreEvaluationEvidence(
  study: unknown,
  seal: ProspectiveSeal,
  release: OracleRelease,
  pem: string,
  w: EvaluationWitness,
  signature: string,
  oracle: Buffer
) {
  verifyEvaluationWitness(study, seal, release, pem, w, signature);
  const result = revealProspectiveStudy(study, seal, release, pem, oracle),
    cells = result.runs.flatMap((r) =>
      r.applications.flatMap((a) => a.score.cells.map((c) => ({ ...c, applicationId: a.id, runId: r.runId })))
    ),
    positive = cells.filter((c) => c.truth === "VULNERABLE"),
    decisive = cells.filter((c) => c.outcome === "FINDING" || c.outcome === "NO_FINDING");
  const families = [...new Set(w.enrollment.families.map((f) => f.familyId))].map((familyId) => {
    const apps = w.enrollment.families.filter((f) => f.familyId === familyId).map((f) => f.applicationId),
      cases = cells.filter((c) => apps.includes(c.applicationId)),
      repeated = result.cells.filter((c) => apps.includes(c.applicationId));
    return {
      familyId,
      applications: apps,
      caseOpportunities: cases.length,
      counts: Object.fromEntries(
        [...new Set(cases.map((c) => c.classification))].map((k) => [
          k,
          cases.filter((c) => c.classification === k).length
        ])
      ),
      repeatableCases: repeated.filter((c) => c.repeatable).length,
      totalCases: repeated.length,
      independentFamilyDiversityEstablished: false
    };
  });
  return {
    ...result,
    evidenceWitnessSha256: w.witnessSha256,
    evidenceFiles: w.evidence.length,
    families,
    knownVulnerabilities: {
      total: positive.length,
      detected: positive.filter((c) => c.classification === "TRUE_POSITIVE").length,
      falseNegatives: positive.filter((c) => c.classification === "FALSE_NEGATIVE").length,
      abstained: positive.filter((c) => c.outcome === "ABSTAIN").length,
      untested: positive.filter((c) => c.outcome === "UNTESTED").length,
      missed: positive.filter((c) => c.classification !== "TRUE_POSITIVE").length
    },
    decisionCoverage: cells.length ? decisive.length / cells.length : null,
    evaluatorProvenance: w.enrollment.provenance,
    independentAcceptance: false,
    blinded: false,
    limitation: "BYTE_AND_SIGNATURE_BINDING_DOES_NOT_PROVE_SEPARATE_OWNER_CUSTODY_TRUSTED_TIME_OR_TRUTH_CORRECTNESS"
  };
}
