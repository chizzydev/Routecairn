import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { discoveryApplicationFixture } from "../helpers/discovery-application-fixture.js";
import { evaluateApplicationDiscovery } from "../../src/benchmark/ApplicationDiscoveryEvaluation.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
it("discovers, reasons, reviews, proves and measures frozen ArchiveHub quartz truth without false policy inference", async () => {
  const start = Date.now(),
    cpu = process.cpuUsage(),
    f = await discoveryApplicationFixture("quartz");
  try {
    const seed = await f.acquire(f.seedInput),
      p = f.propose(seed.revision.revisionId),
      observed = await f.acquire(f.select(p)),
      before = f.wire.length,
      proposal = f.hypotheses.generate(f.org, { mapRevisionId: observed.revision.revisionId }, "operator");
    expect(f.wire).toHaveLength(before);
    expect(proposal.findingsInferred).toBe(false);
    expect(proposal.executionAuthority).toBe("NONE");
    for (const id of ["restricted", "privileged", "shared"])
      expect(proposal.candidates.find((c) => c.routeId === id)?.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
    for (const id of ["personal", "missing", "untyped", "sealed"])
      expect(proposal.candidates.find((c) => c.routeId === id)?.eligibility).toBe("ABSTAIN");
    const shared = proposal.candidates.find((c) => c.routeId === "shared")!,
      decision = await f.hypotheses.decide(
        f.org,
        proposal.proposalId,
        {
          action: "REJECT",
          digest: proposal.digest,
          candidateId: shared.candidateId,
          reason: "EXPECTED_SHARED_ACCESS"
        },
        "operator"
      );
    expect(decision.status).toBe("REJECTED");
    expect(f.wire).toHaveLength(before);
    const restricted = proposal.candidates.find((c) => c.routeId === "restricted")!,
      resource = f.cases.find((c) => c.id === "restricted")!,
      review = await f.hypotheses.decide(
        f.org,
        proposal.proposalId,
        {
          action: "REVIEW",
          digest: proposal.digest,
          candidateId: restricted.candidateId,
          policyConfirmed: true,
          ownershipConfirmed: true,
          identity: resource.ref,
          tenant: "north",
          explanation: "Independent fixture owner declares exact private object and tenant ownership.",
          decisions: { primary: "ALLOW", "account-a": "DENY", "account-b": "DENY", anonymous: "DENY" }
        },
        "operator"
      );
    expect(review.matrix).not.toBeNull();
    expect(f.wire).toHaveLength(before);
    // One separately reviewed matrix measures all evaluable routes; uncertain routes remain abstentions with named controls.
    const matrix = await f.mapping.createMatrix(
        f.org,
        observed.revision.revisionId,
        f.policy(observed.revision.input),
        "operator"
      ),
      run = await f.workbench.execute(f.org, matrix.revisionId, matrix.digest, "operator");
    await f.wait(run.scanId!);
    const result = f.workbench.result(f.org, matrix.revisionId);
    expect(result.status).toBe("FINDINGS");
    const predictions = f.cases.map((c) => {
      const checks = result.checks?.filter((k) => k.routeIds?.includes(c.id)) ?? [];
      return {
        id: c.id,
        outcome: checks.some((k) => k.outcome === "FAIL")
          ? "FINDING"
          : checks.length && checks.every((k) => k.outcome === "PASS")
            ? "NO_FINDING"
            : "ABSTAIN",
        sourceHash: result.sourceHash!,
        reason: checks.length
          ? checks
              .map((k) => k.reasonCode)
              .join(",")
              .slice(0, 200)
          : proposal.candidates.find((k) => k.routeId === c.id)?.missingControls.join(",") || "NO_COMPLETE_NATIVE_PROOF"
      };
    });
    writeFileSync(join(f.root, "PREDICTIONS_BEFORE_ORACLE_SCORING.json"), JSON.stringify(predictions, null, 2), {
      flag: "wx"
    });
    const truthBytes = readFileSync(join(f.root, "FROZEN_ORACLE.json")),
      commitment = createHash("sha256").update(truthBytes).digest("hex"),
      labels = {
        schemaVersion: 1,
        commitment,
        maintainer: "SELF_MAINTAINED",
        blinded: false,
        cases: f.cases.map((c) => ({
          id: c.id,
          truth: c.expected === "POSITIVE" ? "VULNERABLE" : c.expected === "NEGATIVE" ? "SECURE" : "UNCERTAIN"
        }))
      },
      score = evaluateApplicationDiscovery(labels, predictions);
    expect(score.counts).toEqual({
      truePositives: 2,
      falsePositives: 0,
      trueNegatives: 2,
      falseNegatives: 0,
      correctAbstentions: 3,
      unsafeUncertainConclusions: 0,
      abstainedKnownTruth: 0,
      untested: 0
    });
    expect(result.findings).toHaveLength(3);
    f.setFixed();
    const fixed = await f.workbench.create(f.org, matrix.input, "operator"),
      fixedRun = await f.workbench.execute(f.org, fixed.revisionId, fixed.digest, "operator");
    await f.wait(fixedRun.scanId!);
    const after = f.workbench.result(f.org, fixed.revisionId);
    expect(after.findings).toHaveLength(0);
    const comparison = new ScanComparisonService(f.database).compare(run.scanId!, fixedRun.scanId!, {
      createdByUserId: "operator"
    });
    expect(comparison.summary.resolved).toBe(3);
    expect(f.wire.every((w) => w.method === "GET")).toBe(true);
    expect(f.wire.every((w) => w.path === "/" || w.path === "/identity" || w.path.startsWith(f.prefix))).toBe(true);
    f.capture("FROZEN_EVALUATION_RESULT", {
      seed: "quartz",
      score,
      predictions,
      proposal,
      decision,
      reviewDecision: review.decisionId,
      nativeScan: run.scanId,
      remediationScan: fixedRun.scanId,
      comparison,
      wireRequests: f.wire.length,
      routeCoverage: {
        advertised: 8,
        discovered: p.candidates.length,
        nativeObserved: observed.result.observations.length,
        oracleResources: 7,
        actors: 4,
        scoredNativeRouteControls: 4,
        abstained: 3
      },
      cpuMicros: process.cpuUsage(cpu),
      elapsedMs: Date.now() - start,
      independentMaintainer: false,
      blinded: false,
      ownerAcceptance: false
    });
  } finally {
    await f.close();
  }
});
