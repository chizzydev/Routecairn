import { it, expect } from "vitest";
import { retainDeepFlowPrediction } from "../helpers/deep-flow-prediction.js";
import { deepBusinessFixture } from "../helpers/deep-businessflow-fixture.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ApplicationAnalystHandoff } from "../../src/dashboard/execution/ApplicationAnalystHandoff.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
for (const steps of [3, 4] as const)
  it(
    "observes and separately proves " + steps + " linked native GET steps, retains findings, and compares remediation",
    async () => {
      const started = Date.now(),
        cpu = process.cpuUsage(),
        f = await deepBusinessFixture(steps);
      try {
        const a = await f.acquire(f.input),
          p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
          wire = f.wire.length;
        expect(p.relationships!.relationships).toHaveLength(steps - 1);
        expect(p.relationships!.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
        expect(p.relationships!.causalProof).toBe(false);
        const d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
        expect(f.wire.length).toBe(wire);
        if (!d.matrix) throw Error("MATRIX_REQUIRED");
        const run = await f.workbench.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
        await f.wait(run.scanId!);
        const native = f.workbench.result(f.org, d.matrix.revisionId);
        retainDeepFlowPrediction(
          f.root,
          "procurement" + steps,
          "vulnerable",
          f.wire.length,
          Date.now() - started,
          process.cpuUsage(cpu),
          p.source.sourceHash!,
          native
        );
        expect(native.findings).toHaveLength(2);
        f.setFixed();
        const fixed = await f.workbench.create(f.org, d.matrix.input, "operator"),
          after = await f.workbench.execute(f.org, fixed.revisionId, fixed.digest, "operator");
        await f.wait(after.scanId!);
        expect(f.workbench.result(f.org, fixed.revisionId).verifiedPass).toBe(true);
        const comparison = new ScanComparisonService(f.database).compare(run.scanId!, after.scanId!, {
          createdByUserId: "operator"
        });
        expect(comparison.summary.resolved).toBe(2);
        const triage = new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
          packet = new ApplicationAnalystHandoff(f.database, triage, f.workbench).export(f.org, p.proposalId);
        expect(packet.nativeProofs.some((p) => p.findings.length === 2)).toBe(true);
        expect(packet.comparisons).toHaveLength(1);
        expect(packet.causalProof).toBe(false);
        expect(JSON.stringify(packet)).not.toContain("Bearer");
        f.capture("DEEP_NATIVE_" + steps + "_STEP_REMEDIATION", { proposal: p, packet, comparison });
      } finally {
        await f.close();
      }
    }
  );
