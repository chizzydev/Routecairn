import { createHash, createPublicKey, verify } from "node:crypto";
import { z } from "zod";
import {
  heldOutContractSchema,
  commitHeldOutPredictions,
  revealHeldOutDiscovery,
  heldOutHash
} from "./HeldOutDiscoveryEvaluation.js";
const sha = z.string().regex(/^[a-f0-9]{64}$/),
  id = z.string().regex(/^[A-Za-z0-9_-]{1,80}$/);
export const practicalBenchmarkSchema = z
  .object({
    version: z.literal(1),
    datasetId: id,
    publisher: z.string().min(1).max(160),
    provenance: z.enum(["SELF_MAINTAINED", "EXTERNAL_PUBLISHER_CLAIM"]),
    repetitions: z.number().int().min(2).max(10),
    contract: heldOutContractSchema
  })
  .strict();
export function importPracticalBenchmark(
  bytes: Buffer,
  expectedSha256: string,
  publisher?: { publicKeyPem: string; expectedKeySha256: string; signature: Buffer }
) {
  if (bytes.length > 1048576 || createHash("sha256").update(bytes).digest("hex") !== sha.parse(expectedSha256))
    throw Error("BENCHMARK_SOURCE_COMMITMENT");
  const manifest = practicalBenchmarkSchema.parse(JSON.parse(bytes.toString("utf8")));
  // Reuse the existing exact denominator/budget validator, with no measurements and no answer-key access.
  commitHeldOutPredictions(manifest.contract, []);
  if (publisher) {
    if (createPublicKey(publisher.publicKeyPem).asymmetricKeyType !== "ed25519")
      throw Error("BENCHMARK_ED25519_PUBLISHER_REQUIRED");
    if (
      createHash("sha256").update(publisher.publicKeyPem).digest("hex") !== sha.parse(publisher.expectedKeySha256) ||
      !verify(null, bytes, publisher.publicKeyPem, publisher.signature)
    )
      throw Error("BENCHMARK_PUBLISHER_SIGNATURE");
  }
  return {
    manifest,
    manifestSha256: expectedSha256,
    publisherSignatureVerified: !!publisher,
    independentAcceptance: false as const,
    independence: "HOLD_REQUIRES_SEPARATE_ORACLE_OWNERSHIP_REVIEW" as const
  };
}
export function commitPracticalRun(manifestValue: unknown, runId: string, measurements: unknown) {
  const manifest = practicalBenchmarkSchema.parse(manifestValue);
  return {
    version: 1 as const,
    runId: id.parse(runId),
    manifestFingerprint: heldOutHash(manifest),
    prediction: commitHeldOutPredictions(manifest.contract, measurements)
  };
}
export function scorePracticalRun(
  manifestValue: unknown,
  receipt: ReturnType<typeof commitPracticalRun>,
  oracle: Buffer
) {
  const manifest = practicalBenchmarkSchema.parse(manifestValue);
  if (
    !receipt ||
    receipt.version !== 1 ||
    !id.safeParse(receipt.runId).success ||
    receipt.manifestFingerprint !== heldOutHash(manifest)
  )
    throw Error("BENCHMARK_RUN_BINDING");
  const evaluation = revealHeldOutDiscovery(manifest.contract, receipt.prediction, oracle);
  return {
    ...evaluation,
    runId: receipt.runId,
    manifestFingerprint: receipt.manifestFingerprint,
    falsePositiveReview: evaluation.applications.flatMap((a) =>
      a.score.cells
        .filter((c) => c.classification === "FALSE_POSITIVE")
        .map((c) => ({ applicationId: a.id, caseId: c.id, sourceHash: c.sourceHash, review: "REQUIRES_HUMAN_REVIEW" }))
    ),
    executionAuthority: "NONE",
    independence: "HOLD_REQUIRES_SEPARATE_ORACLE_OWNERSHIP_REVIEW"
  };
}
export function summarizePracticalRuns(
  manifestValue: unknown,
  receipts: ReturnType<typeof commitPracticalRun>[],
  oracle: Buffer
) {
  const manifest = practicalBenchmarkSchema.parse(manifestValue);
  if (receipts.length > manifest.repetitions || new Set(receipts.map((r) => r.runId)).size !== receipts.length)
    throw Error("BENCHMARK_EXACT_REPETITIONS");
  const runs = receipts.map((r) => scorePracticalRun(manifest, r, oracle));
  const cells = manifest.contract.applications.flatMap((a) =>
    a.caseIds.map((caseId) => {
      const outcomes = runs.map(
        (r) => r.applications.find((x) => x.id === a.id)!.score.cells.find((c) => c.id === caseId)!.outcome
      );
      while (outcomes.length < manifest.repetitions) outcomes.push("UNTESTED");
      return {
        applicationId: a.id,
        caseId,
        outcomes,
        repeatable:
          receipts.length === manifest.repetitions && !outcomes.includes("UNTESTED") && new Set(outcomes).size === 1
      };
    })
  );
  return {
    version: 1,
    manifestFingerprint: heldOutHash(manifest),
    expectedRuns: manifest.repetitions,
    executedRuns: runs.length,
    missingRuns: manifest.repetitions - runs.length,
    counts: runs.reduce(
      (sum, run) => {
        for (const [k, v] of Object.entries(run.counts)) sum[k] = (sum[k] ?? 0) + v;
        return sum;
      },
      { untested: (manifest.repetitions - runs.length) * cells.length } as Record<string, number>
    ),
    caseOpportunities: cells.length * manifest.repetitions,
    cells,
    runs,
    allCasesRepeatable: cells.every((c) => c.repeatable),
    independentAcceptance: false,
    executionAuthority: "NONE",
    claims: "FIXED_DENOMINATORS_MISSING_RUNS_ARE_UNTESTED_NO_GENERALIZATION_OR_TRUSTED_TIME_CLAIM"
  };
}
