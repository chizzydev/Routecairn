import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { roleflowApplicationFixture } from "../helpers/roleflow-application-fixture.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
for (const application of ["procurement", "membership"] as const)
  it("reviews role and state differentials then proves and pins remediation on " + application, async () => {
    const f = await roleflowApplicationFixture(application);
    try {
      expect(f.wire).toHaveLength(0);
      const revision = await f.mapping.create(
          f.org,
          { ...f.mappingInput, routes: f.mappingInput.routes.slice(0, f.workflow.routeIds.length) },
          "operator"
        ),
        acquisition = await f.mapping.execute(f.org, revision.revisionId, revision.digest, "operator");
      await f.wait(acquisition.scanId!);
      const a = { revision, run: acquisition },
        p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator");
      expect(f.wire).toHaveLength(4 + 4 * f.workflow.routeIds.length);
      expect(p.flow!.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
      expect(p.flow!.steps[1]!.dependsOn).toEqual(["source"]);
      expect(p.flow!.steps.every((s) => s.irCaseIds.length > 0)).toBe(true);
      const q = f.hypotheses.generate(
        f.org,
        { mapRevisionId: a.revision.revisionId, workflow: f.workflow },
        "operator"
      );
      expect(q.digest).toBe(p.digest);
      const decision = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
      if (!decision.matrix) throw Error("Expected reviewed matrix");
      expect(f.wire).toHaveLength(4 + 4 * f.workflow.routeIds.length);
      expect(decision.matrix.matrix).toHaveLength(4 * f.workflow.routeIds.length);
      expect(decision.matrix.request.apiGraphql!.checks.filter((c) => "prerequisiteCheckIds" in c).length).toBe(
        4 * (f.workflow.routeIds.length - 1)
      );
      const before = await f.service.execute(f.org, decision.matrix.revisionId, decision.matrix.digest, "operator");
      await f.wait(before.scanId!);
      const vulnerable = f.service.result(f.org, decision.matrix.revisionId);
      expect(vulnerable.findings).toHaveLength(2);
      expect(vulnerable.checks!.filter((c) => c.checkId.startsWith("source-")).every((c) => c.outcome === "PASS")).toBe(
        true
      );
      f.setFixed();
      const matrix = await f.service.create(f.org, decision.matrix.input, "operator"),
        run = await f.service.execute(f.org, matrix.revisionId, matrix.digest, "operator");
      await f.wait(run.scanId!);
      const fixed = f.service.result(f.org, matrix.revisionId);
      expect(fixed.findings).toHaveLength(0);
      expect(fixed.verifiedPass).toBe(true);
      const comparison = new ScanComparisonService(f.database).compare(before.scanId!, run.scanId!, {
        createdByUserId: "operator"
      });
      expect(comparison.summary.resolved).toBe(2);
      expect(f.wire).toHaveLength(3 * (4 + 4 * f.workflow.routeIds.length));
      expect(f.wire.every((r) => r.method === "GET")).toBe(true);
      writeFileSync(
        join(f.root, "ROLEFLOW_METRICS.json"),
        JSON.stringify(
          {
            application,
            flow: p.flow,
            reviewedMatrices: 2,
            nativeProofs: 2,
            findingsBefore: 2,
            findingsAfter: 0,
            resolved: 2,
            requests: f.wire.length,
            stateMutationRequests: 0,
            legitimateCrossTenantSourceAllowed: true,
            typedStates: true,
            comparison,
            actualFullApplicationAcceptance: false
          },
          null,
          2
        ),
        { flag: "wx" }
      );
    } finally {
      await f.close();
    }
  });
