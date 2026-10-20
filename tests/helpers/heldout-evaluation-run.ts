import { expect } from "vitest";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { heldOutApplicationFixture } from "./heldout-application-fixture.js";
import type { ApplicationFamily } from "./heldout-applications.js";
import { commitHeldOutPredictions, revealHeldOutDiscovery } from "../../src/benchmark/HeldOutDiscoveryEvaluation.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
export async function evaluateHeldOutFamily(family: ApplicationFamily) {
  const start = Date.now(),
    cpu = process.cpuUsage(),
    contractPath = process.env.ROUTECAIRN_HELDOUT_CONTRACT;
  if (!contractPath) throw Error("PREDECLARED_CONTRACT_REQUIRED");
  const contract = JSON.parse(readFileSync(contractPath, "utf8")),
    f = await heldOutApplicationFixture(family);
  try {
    writeFileSync(join(f.root, "EVALUATION_CONTRACT.json"), JSON.stringify(contract, null, 2), { flag: "wx" });
    const seed = await f.acquire(f.seedInput),
      p = f.propose(seed.revision.revisionId),
      map = await f.acquire(f.select(p, (c) => f.cases.some((r) => r.path === c))),
      before = f.wire.length,
      proposal = f.hypotheses.generate(f.org, { mapRevisionId: map.revision.revisionId }, "operator");
    expect(f.wire.length).toBe(before);
    expect(p.candidates.length).toBe(7);
    expect(proposal.findingsInferred).toBe(false);
    const matrix = await f.mapping.createMatrix(
        f.org,
        map.revision.revisionId,
        f.policy(map.revision.input),
        "operator"
      ),
      run = await f.workbench.execute(f.org, matrix.revisionId, matrix.digest, "operator");
    await f.wait(run.scanId!);
    const result = f.workbench.result(f.org, matrix.revisionId),
      predictions = f.cases.map((c) => {
        const checks = result.checks?.filter((k) => k.routeIds?.includes(c.id)) ?? [];
        return {
          id: family + ":" + c.id,
          outcome: checks.some((k) => k.outcome === "FAIL")
            ? ("FINDING" as const)
            : checks.length && checks.every((k) => k.outcome === "PASS")
              ? ("NO_FINDING" as const)
              : ("ABSTAIN" as const),
          sourceHash: result.sourceHash!,
          reason:
            checks
              .map((k) => k.reasonCode)
              .join(",")
              .slice(0, 200) ||
            proposal.candidates.find((k) => k.routeId === c.id)?.missingControls.join(",") ||
            "INCOMPLETE_NATIVE_CONTROL"
        };
      });
    const measurements = [
        {
          applicationId: family,
          predictions,
          observedSources: new Set(p.candidates.flatMap((c) => c.provenance.map((w) => w.actorId))).size,
          discoveredRoutes: p.candidates.length,
          requests: f.wire.length,
          wallMs: Date.now() - start,
          parentCpuMicros: process.cpuUsage(cpu)
        }
      ],
      commit = commitHeldOutPredictions(contract, measurements);
    writeFileSync(join(f.root, "01_PREDICTIONS_COMMITTED.json"), JSON.stringify(commit, null, 2), { flag: "wx" });
    // Labels are opened only after the immutable prediction file exists; policies are separately owner-declared input.
    const oracle = readFileSync(new URL("../fixtures/heldout-discovery-oracle-v1.json", import.meta.url)),
      score = revealHeldOutDiscovery(contract, commit, oracle);
    writeFileSync(join(f.root, "02_ORACLE_REVEALED.json"), oracle, { flag: "wx" });
    writeFileSync(join(f.root, "03_SCORE.json"), JSON.stringify(score, null, 2), { flag: "wx" });
    const thisApp = score.applications.find((a) => a.id === family)!;
    expect(thisApp.score.counts).toEqual({
      truePositives: 1,
      falsePositives: 0,
      trueNegatives: family === "helpdesk" ? 1 : 2,
      falseNegatives: 0,
      correctAbstentions: 3,
      unsafeUncertainConclusions: 0,
      abstainedKnownTruth: family === "helpdesk" ? 1 : 0,
      untested: 0
    });
    f.setFixed();
    const fix = await f.workbench.create(f.org, matrix.input, "operator"),
      fixedRun = await f.workbench.execute(f.org, fix.revisionId, fix.digest, "operator");
    await f.wait(fixedRun.scanId!);
    const comparison = new ScanComparisonService(f.database).compare(run.scanId!, fixedRun.scanId!, {
      createdByUserId: "operator"
    });
    expect(comparison.summary.resolved).toBe(result.findings!.length);
    expect(f.workbench.result(f.org, fix.revisionId).findings!.length).toBe(0);
    expect(
      f.wire.every(
        (w) => w.method === "GET" && (w.path === "/" || w.path === "/identity" || w.path.startsWith(f.prefix))
      )
    ).toBe(true);
    f.capture("HELDOUT_NATIVE_RESULT", {
      family,
      proposal,
      score,
      comparison,
      predictionFileSha256: createHash("sha256")
        .update(readFileSync(join(f.root, "01_PREDICTIONS_COMMITTED.json")))
        .digest("hex"),
      allJourneyRequests: f.wire.length,
      allJourneyWallMs: Date.now() - start,
      parentCpuMicros: process.cpuUsage(cpu),
      independentMaintainer: false,
      blinded: false
    });
  } finally {
    await f.close();
  }
}
