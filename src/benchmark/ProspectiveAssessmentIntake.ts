import { createHash, createPublicKey, verify } from "node:crypto";
import { z } from "zod";
import {
  practicalBenchmarkSchema,
  commitPracticalRun,
  summarizePracticalRuns
} from "./PracticalAssessmentBenchmark.js";
import { heldOutHash } from "./HeldOutDiscoveryEvaluation.js";
const hash = z.string().regex(/^[a-f0-9]{64}$/),
  id = z.string().regex(/^[A-Za-z0-9_-]{1,80}$/);
export const prospectiveStudySchema = z
  .object({
    version: z.literal(1),
    studyId: id,
    sourceVersionId: id,
    implementationSources: z
      .array(z.object({ applicationId: id, path: z.string().min(1).max(160), sha256: hash }).strict())
      .min(2)
      .max(32),
    runIds: z.array(id).min(2).max(10),
    publisherKeySha256: hash,
    benchmark: practicalBenchmarkSchema
  })
  .strict();
type Study = z.infer<typeof prospectiveStudySchema>;
export type PracticalRun = ReturnType<typeof commitPracticalRun>;
function study(value: unknown) {
  const m = prospectiveStudySchema.parse(value);
  if (m.runIds.length !== m.benchmark.repetitions || new Set(m.runIds).size !== m.runIds.length)
    throw Error("PROSPECTIVE_EXACT_RUN_IDS");
  const apps = m.benchmark.contract.applications;
  if (
    m.implementationSources.length !== apps.length ||
    new Set(m.implementationSources.map((a) => a.applicationId)).size !== apps.length ||
    new Set(m.implementationSources.map((a) => a.path)).size !== apps.length ||
    m.implementationSources.some(
      (a) => !apps.some((b) => b.id === a.applicationId && b.implementationSha256 === a.sha256)
    )
  )
    throw Error("PROSPECTIVE_EXACT_IMPLEMENTATION_SOURCES");
  const sources = m.benchmark.contract.productSources;
  if (new Set(sources.map((s) => s.path)).size !== sources.length) throw Error("PROSPECTIVE_UNIQUE_SOURCES");
  return m;
}
export function prospectiveSourceExpectations(value: unknown) {
  const m = study(value),
    rows = [
      ...m.benchmark.contract.productSources,
      ...m.implementationSources.map(({ path, sha256 }) => ({ path, sha256 }))
    ],
    seen = new Map<string, string>();
  for (const r of rows) {
    if (r.sha256 === m.benchmark.contract.oracleSha256) throw Error("PROSPECTIVE_SOURCE_CANNOT_BE_ORACLE");
    if (
      !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(r.path) ||
      r.path.split("/").some((p) => p === "." || p === "..") ||
      (seen.has(r.path) && seen.get(r.path) !== r.sha256)
    )
      throw Error("PROSPECTIVE_SAFE_UNIQUE_SOURCE_PATHS");
    seen.set(r.path, r.sha256);
  }
  return [...seen].map(([path, sha256]) => ({ path, sha256 })).sort((a, b) => a.path.localeCompare(b.path));
}
export function sealProspectivePredictions(
  value: unknown,
  receipts: PracticalRun[],
  sourceBindings: { path: string; sha256: string }[]
) {
  const m = study(value),
    expected = prospectiveSourceExpectations(m);
  if (
    heldOutHash([...sourceBindings].sort((a, b) => a.path.localeCompare(b.path))) !==
    heldOutHash([...expected].sort((a, b) => a.path.localeCompare(b.path)))
  )
    throw Error("PROSPECTIVE_EXACT_SOURCE_BINDING");
  if (
    receipts.length !== m.runIds.length ||
    new Set(receipts.map((r) => r.runId)).size !== m.runIds.length ||
    receipts.some((r) => !m.runIds.includes(r.runId))
  )
    throw Error("PROSPECTIVE_ALL_RUNS_BEFORE_ANY_REVEAL");
  const runs = m.runIds.map((runId) => {
    const r = receipts.find((r) => r.runId === runId)!;
    const bound = commitPracticalRun(m.benchmark, runId, r.prediction.measurements);
    if (heldOutHash(bound) !== heldOutHash(r)) throw Error("PROSPECTIVE_PREDICTION_CUSTODY");
    for (const app of m.benchmark.contract.applications) {
      const a = bound.prediction.measurements.find((v) => v.applicationId === app.id);
      if (
        !a ||
        a.predictions.length !== app.caseIds.length ||
        app.caseIds.some((id) => !a.predictions.some((p) => p.id === id))
      )
        throw Error("PROSPECTIVE_ALL_CASES_OR_EXPLICIT_UNTESTED");
    }
    return bound;
  });
  const body = {
    version: 1 as const,
    studyFingerprint: heldOutHash(m),
    sourceVersionId: m.sourceVersionId,
    sourceBindings: expected,
    runs,
    allApplicationsAndCasesSealed: true as const
  };
  return {
    ...body,
    predictionBundleSha256: heldOutHash(body),
    oracleReadBySeal: false as const,
    executionAuthority: "NONE" as const
  };
}
export type ProspectiveSeal = ReturnType<typeof sealProspectivePredictions>;
export type OracleRelease = {
  version: 1;
  studyFingerprint: string;
  predictionBundleSha256: string;
  oracleSha256: string;
  sourceVersionId: string;
  signatureBase64: string;
};
export function oracleReleaseMessage(m: Study, s: ProspectiveSeal) {
  return {
    version: 1 as const,
    studyFingerprint: heldOutHash(m),
    predictionBundleSha256: s.predictionBundleSha256,
    oracleSha256: m.benchmark.contract.oracleSha256,
    sourceVersionId: m.sourceVersionId
  };
}
export function verifyProspectiveRelease(
  value: unknown,
  seal: ProspectiveSeal,
  release: OracleRelease,
  keyPem: string
) {
  const m = study(value),
    bound = sealProspectivePredictions(m, seal.runs, seal.sourceBindings);
  if (heldOutHash(bound) !== heldOutHash(seal)) throw Error("PROSPECTIVE_SEAL_CHANGED");
  const message = oracleReleaseMessage(m, bound),
    { signatureBase64, ...actual } = release;
  if (
    heldOutHash(actual) !== heldOutHash(message) ||
    typeof signatureBase64 !== "string" ||
    !/^[A-Za-z0-9+/]{86}==$/.test(signatureBase64)
  )
    throw Error("PROSPECTIVE_RELEASE_BINDING");
  if (
    !keyPem.startsWith("-----BEGIN PUBLIC KEY-----") ||
    keyPem.length > 16384 ||
    createHash("sha256").update(keyPem).digest("hex") !== m.publisherKeySha256 ||
    createPublicKey(keyPem).asymmetricKeyType !== "ed25519" ||
    !verify(null, Buffer.from(heldOutHash(message), "ascii"), keyPem, Buffer.from(signatureBase64, "base64"))
  )
    throw Error("PROSPECTIVE_PINNED_ORACLE_SIGNATURE");
  return { study: m, seal: bound };
}
export function revealProspectiveStudy(
  value: unknown,
  seal: ProspectiveSeal,
  release: OracleRelease,
  keyPem: string,
  oracle: Buffer
) {
  const { study: m } = verifyProspectiveRelease(value, seal, release, keyPem);
  return {
    ...summarizePracticalRuns(m.benchmark, seal.runs, oracle),
    protocol: "ALL_APPLICATIONS_ALL_CASES_ALL_RUNS_COMMITTED_BEFORE_SIGNED_ORACLE_RELEASE",
    predictionBundleSha256: seal.predictionBundleSha256,
    sourceVersionId: m.sourceVersionId,
    releaseSignatureVerified: true,
    independentAcceptance: false,
    blinded: false,
    independence: "HOLD_SEPARATE_ORACLE_OWNERSHIP_AND_PROSPECTIVE_CUSTODY_REVIEW_REQUIRED",
    secrecyOrTrustedWallClockProven: false,
    executionAuthority: "NONE"
  };
}
