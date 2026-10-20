import { z } from "zod";
import { createHash } from "node:crypto";
import { canonicalJson } from "./BenchmarkCorpus.js";
import { evaluateApplicationDiscovery } from "./ApplicationDiscoveryEvaluation.js";
const hash = z.string().regex(/^[a-f0-9]{64}$/),
  id = z.string().min(1).max(160),
  natural = z.number().int().min(0).max(1000000);
export const heldOutContractSchema = z
  .object({
    version: z.literal(1),
    provenance: z.literal("SELF_MAINTAINED_HELD_OUT"),
    oracleSha256: hash,
    productSources: z
      .array(z.object({ path: id, sha256: hash }).strict())
      .min(1)
      .max(2000),
    applications: z
      .array(
        z
          .object({
            id,
            implementationSha256: hash,
            caseIds: z.array(id).min(1).max(256),
            sourceOpportunities: natural,
            routeOpportunities: natural,
            requestCeiling: natural
          })
          .strict()
      )
      .min(2)
      .max(32)
  })
  .strict();
export const heldOutHash = (v: unknown) => createHash("sha256").update(canonicalJson(v)).digest("hex");
const prediction = z
  .object({
    id,
    outcome: z.enum(["FINDING", "NO_FINDING", "ABSTAIN", "UNTESTED"]),
    sourceHash: hash,
    reason: z.string().min(1).max(200)
  })
  .strict();
const measurement = z
  .object({
    applicationId: id,
    predictions: z.array(prediction).max(256),
    observedSources: natural,
    discoveredRoutes: natural,
    requests: natural,
    wallMs: z.number().finite().nonnegative(),
    parentCpuMicros: z
      .object({ user: z.number().int().nonnegative().max(1e12), system: z.number().int().nonnegative().max(1e12) })
      .strict()
  })
  .strict();
export function commitHeldOutPredictions(contractValue: unknown, measurementsValue: unknown) {
  const contract = heldOutContractSchema.parse(contractValue),
    measurements = z.array(measurement).max(32).parse(measurementsValue);
  const appIds = contract.applications.map((a) => a.id),
    allIds = contract.applications.flatMap((a) => a.caseIds);
  if (
    new Set(appIds).size !== appIds.length ||
    new Set(allIds).size !== allIds.length ||
    new Set(measurements.map((a) => a.applicationId)).size !== measurements.length ||
    measurements.some((m) => !appIds.includes(m.applicationId))
  )
    throw Error("HELDOUT_EXACT_UNIQUE_APPLICATIONS_AND_CASES_REQUIRED");
  for (const m of measurements) {
    const a = contract.applications.find((a) => a.id === m.applicationId)!;
    if (
      m.observedSources > a.sourceOpportunities ||
      m.discoveredRoutes > a.routeOpportunities ||
      m.requests > a.requestCeiling ||
      new Set(m.predictions.map((p) => p.id)).size !== m.predictions.length ||
      m.predictions.some((p) => !a.caseIds.includes(p.id))
    )
      throw Error("HELDOUT_FIXED_DENOMINATOR_OR_BUDGET_VIOLATION");
  }
  return {
    contractFingerprint: heldOutHash(contract),
    measurements,
    predictionFingerprint: heldOutHash(measurements),
    oracleNotYetRevealed: true as const
  };
}
/** Pure offline scoring. Commitments prove byte binding, never independent authorship or honest wall-clock ordering. */
export function revealHeldOutDiscovery(
  contractValue: unknown,
  receipt: ReturnType<typeof commitHeldOutPredictions>,
  oracleBytes: Buffer
) {
  const contract = heldOutContractSchema.parse(contractValue),
    bound = commitHeldOutPredictions(contract, receipt.measurements);
  if (
    receipt.contractFingerprint !== bound.contractFingerprint ||
    receipt.predictionFingerprint !== bound.predictionFingerprint ||
    receipt.oracleNotYetRevealed !== true ||
    createHash("sha256").update(oracleBytes).digest("hex") !== contract.oracleSha256
  )
    throw Error("HELDOUT_COMMITMENT_MISMATCH");
  const oracle = z
      .object({
        version: z.literal(1),
        cases: z
          .array(z.object({ id, truth: z.enum(["VULNERABLE", "SECURE", "UNCERTAIN"]) }).strict())
          .min(1)
          .max(8192)
      })
      .strict()
      .parse(JSON.parse(oracleBytes.toString("utf8"))),
    ids = contract.applications.flatMap((a) => a.caseIds);
  if (
    oracle.cases.length !== ids.length ||
    new Set(oracle.cases.map((c) => c.id)).size !== ids.length ||
    oracle.cases.some((c) => !ids.includes(c.id))
  )
    throw Error("HELDOUT_ORACLE_EXACT_MEMBERSHIP_REQUIRED");
  const divide = (n: number, d: number) => (d ? n / d : null);
  const applications = contract.applications.map((a) => {
    const m = bound.measurements.find((m) => m.applicationId === a.id),
      score = evaluateApplicationDiscovery(
        {
          schemaVersion: 1,
          commitment: contract.oracleSha256,
          maintainer: "SELF_MAINTAINED",
          blinded: false,
          cases: oracle.cases.filter((c) => a.caseIds.includes(c.id))
        },
        m?.predictions ?? []
      );
    return {
      ...a,
      score,
      cost: m
        ? {
            requests: m.requests,
            wallMs: m.wallMs,
            parentCpuMicros: m.parentCpuMicros,
            cpuScope: "PARENT_ONLY_EXCLUDES_WORKER"
          }
        : null,
      coverage: {
        source: divide(m?.observedSources ?? 0, a.sourceOpportunities),
        route: divide(m?.discoveredRoutes ?? 0, a.routeOpportunities)
      },
      neutralAlwaysAbstain: evaluateApplicationDiscovery(
        {
          schemaVersion: 1,
          commitment: contract.oracleSha256,
          maintainer: "SELF_MAINTAINED",
          blinded: false,
          cases: oracle.cases.filter((c) => a.caseIds.includes(c.id))
        },
        a.caseIds.map((id) => ({
          id,
          outcome: "ABSTAIN",
          sourceHash: contract.oracleSha256,
          reason: "NEUTRAL_BASELINE_NO_DETECTOR"
        }))
      )
    };
  });
  return {
    version: 1,
    provenance: contract.provenance,
    independentAcceptance: false,
    blinded: false,
    claims: "SOURCE_BOUND_SELF_MAINTAINED_HELD_OUT_ONLY",
    contractFingerprint: bound.contractFingerprint,
    predictionFingerprint: bound.predictionFingerprint,
    applications,
    counts: applications.reduce(
      (sum, a) => {
        for (const [k, v] of Object.entries(a.score.counts)) sum[k] = (sum[k] ?? 0) + v;
        return sum;
      },
      {} as Record<string, number>
    )
  };
}
