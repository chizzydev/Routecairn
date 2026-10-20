import { z } from "zod";
import { createHash } from "node:crypto";
const sha = z.string().regex(/^[a-f0-9]{64}$/),
  id = z.string().min(1).max(160);
export const applicationGroundTruthSchema = z
  .object({
    schemaVersion: z.literal(1),
    commitment: sha,
    maintainer: z.enum(["SELF_MAINTAINED", "INDEPENDENT_OWNER"]),
    blinded: z.boolean(),
    cases: z
      .array(z.object({ id, truth: z.enum(["VULNERABLE", "SECURE", "UNCERTAIN"]) }).strict())
      .min(1)
      .max(256)
  })
  .strict();
const predictionSchema = z
  .array(
    z
      .object({
        id,
        outcome: z.enum(["FINDING", "NO_FINDING", "ABSTAIN", "UNTESTED"]),
        sourceHash: sha,
        reason: z.string().min(1).max(200)
      })
      .strict()
  )
  .max(256);
/** Scores frozen labels only after native predictions have been retained. No target I/O or finding creation. */
export function evaluateApplicationDiscovery(truthValue: unknown, predictionValue: unknown) {
  const truth = applicationGroundTruthSchema.parse(truthValue),
    predictions = predictionSchema.parse(predictionValue),
    ids = truth.cases.map((c) => c.id);
  if (
    new Set(ids).size !== ids.length ||
    new Set(predictions.map((c) => c.id)).size !== predictions.length ||
    predictions.some((p) => !ids.includes(p.id))
  )
    throw Error("EVALUATION_EXACT_UNIQUE_CASES_REQUIRED");
  const cells = truth.cases.map((c) => {
    const p = predictions.find((p) => p.id === c.id),
      outcome = p?.outcome ?? "UNTESTED";
    return {
      ...c,
      ...p,
      outcome,
      classification:
        outcome === "UNTESTED"
          ? "UNTESTED"
          : c.truth === "UNCERTAIN"
            ? outcome === "ABSTAIN"
              ? "CORRECT_ABSTENTION"
              : "UNCERTAIN_NOT_SAFELY_ABSTAINED"
            : outcome === "ABSTAIN"
              ? "ABSTAINED_KNOWN_TRUTH"
              : c.truth === "VULNERABLE"
                ? outcome === "FINDING"
                  ? "TRUE_POSITIVE"
                  : "FALSE_NEGATIVE"
                : outcome === "FINDING"
                  ? "FALSE_POSITIVE"
                  : "TRUE_NEGATIVE"
    };
  });
  const count = (name: string) => cells.filter((c) => c.classification === name).length,
    tp = count("TRUE_POSITIVE"),
    fp = count("FALSE_POSITIVE"),
    tn = count("TRUE_NEGATIVE"),
    fn = count("FALSE_NEGATIVE"),
    positive = truth.cases.filter((c) => c.truth === "VULNERABLE").length,
    negative = truth.cases.filter((c) => c.truth === "SECURE").length,
    div = (a: number, b: number) => (b ? a / b : null);
  return {
    schemaVersion: 1,
    commitment: truth.commitment,
    maintainer: truth.maintainer,
    blinded: truth.blinded,
    labelsAuthenticatedByScorer: false,
    independentAcceptance: false,
    cells,
    counts: {
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
      correctAbstentions: count("CORRECT_ABSTENTION"),
      unsafeUncertainConclusions: count("UNCERTAIN_NOT_SAFELY_ABSTAINED"),
      abstainedKnownTruth: count("ABSTAINED_KNOWN_TRUTH"),
      untested: count("UNTESTED")
    },
    metrics: {
      precision: div(tp, tp + fp),
      measuredNegativeFalsePositiveRate: div(fp, fp + tn),
      negativeDenominatorCoverage: div(fp + tn, negative),
      conservativeRecall: div(tp, positive),
      predictionCoverage: div(cells.filter((c) => c.outcome !== "UNTESTED").length, cells.length),
      conclusivePredictionFraction: div(
        cells.filter((c) => c.outcome === "FINDING" || c.outcome === "NO_FINDING").length,
        cells.length
      )
    },
    predictionFingerprint: createHash("sha256").update(JSON.stringify(predictions)).digest("hex"),
    scope: "FROZEN_OWNED_CORPUS_ONLY_NO_GENERALIZATION_CLAIM"
  };
}
