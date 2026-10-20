import { it, expect } from "vitest";
import { createHash } from "node:crypto";
import { commitHeldOutPredictions, revealHeldOutDiscovery } from "../../src/benchmark/HeldOutDiscoveryEvaluation.js";
const oracle = Buffer.from(
    JSON.stringify({
      version: 1,
      cases: [
        { id: "a:1", truth: "VULNERABLE" },
        { id: "a:2", truth: "SECURE" },
        { id: "b:1", truth: "UNCERTAIN" }
      ]
    })
  ),
  h = "a".repeat(64),
  contract = {
    version: 1,
    provenance: "SELF_MAINTAINED_HELD_OUT",
    oracleSha256: createHash("sha256").update(oracle).digest("hex"),
    productSources: [{ path: "product.ts", sha256: h }],
    applications: [
      {
        id: "a",
        implementationSha256: h,
        caseIds: ["a:1", "a:2"],
        sourceOpportunities: 2,
        routeOpportunities: 3,
        requestCeiling: 20
      },
      {
        id: "b",
        implementationSha256: h,
        caseIds: ["b:1"],
        sourceOpportunities: 1,
        routeOpportunities: 2,
        requestCeiling: 20
      }
    ]
  },
  row = (id: string, outcome: string) => ({ id, outcome, sourceHash: h, reason: "native" }),
  measure = (predictions: unknown[]) => [
    {
      applicationId: "a",
      predictions,
      observedSources: 1,
      discoveredRoutes: 2,
      requests: 12,
      wallMs: 200,
      parentCpuMicros: { user: 1, system: 1 }
    }
  ];
it("keeps false positives, false negatives, untested applications and fixed denominators visible", () => {
  const r = revealHeldOutDiscovery(
    contract,
    commitHeldOutPredictions(contract, measure([row("a:1", "NO_FINDING"), row("a:2", "FINDING")])),
    oracle
  );
  expect(r.counts).toMatchObject({ falseNegatives: 1, falsePositives: 1, untested: 1 });
  expect(r.applications[0]!.coverage).toEqual({ source: 0.5, route: 2 / 3 });
  expect(r.independentAcceptance).toBe(false);
});
it("refuses changed predictions and changed oracle after commitment", () => {
  const r = commitHeldOutPredictions(contract, measure([row("a:1", "ABSTAIN")]));
  expect(() => revealHeldOutDiscovery(contract, { ...r, predictionFingerprint: "b".repeat(64) }, oracle)).toThrow(
    "COMMITMENT"
  );
  expect(() => revealHeldOutDiscovery(contract, r, Buffer.from("{}"))).toThrow("COMMITMENT");
});
it("refuses duplicate opportunities, extraneous cases and budget or coverage inflation", () => {
  for (const v of [
    measure([row("unknown", "FINDING")]),
    measure([row("a:1", "FINDING"), row("a:1", "FINDING")]),
    [{ ...measure([])[0], requests: 21 }],
    [{ ...measure([])[0], observedSources: 3 }]
  ])
    expect(() => commitHeldOutPredictions(contract, v)).toThrow();
});
it("scores abstention on known truth separately from correct uncertain abstention", () => {
  const ms = [
    ...measure([row("a:1", "ABSTAIN"), row("a:2", "ABSTAIN")]),
    {
      applicationId: "b",
      predictions: [row("b:1", "ABSTAIN")],
      observedSources: 0,
      discoveredRoutes: 0,
      requests: 0,
      wallMs: 0,
      parentCpuMicros: { user: 0, system: 0 }
    }
  ];
  const r = revealHeldOutDiscovery(contract, commitHeldOutPredictions(contract, ms), oracle);
  expect(r.counts).toMatchObject({ abstainedKnownTruth: 2, correctAbstentions: 1, untested: 0 });
  expect(r.applications[0]!.score.metrics.measuredNegativeFalsePositiveRate).toBeNull();
});
