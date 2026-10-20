import { it, expect } from "vitest";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
it("keeps real failed, partial and malformed comparison evidence visible instead of quietly resolving triage", async () => {
  const f = await businessFlowFixture("orders");
  try {
    const a = await f.acquire(f.input),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
    if (!d.matrix) throw Error("MATRIX");
    const first = await f.workbench.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
    await f.wait(first.scanId!);
    await f.fix();
    const second = await f.workbench.create(f.org, d.matrix.input, "operator"),
      after = await f.workbench.execute(f.org, second.revisionId, second.digest, "operator");
    await f.wait(after.scanId!);
    const c = new ScanComparisonService(f.database).compare(first.scanId!, after.scanId!, {
        createdByUserId: "operator"
      }),
      triage = new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench);
    expect(triage.get(f.org, p.proposalId).nextAction).toBe("REVIEW_RECORDED_REMEDIATION_DELTA");
    f.capture("COMPARISON_BEFORE_OWNED_FAULTS", { comparison: c, triage: triage.get(f.org, p.proposalId) });
    const original = (
      f.database.db.prepare("SELECT summary_json FROM scan_comparisons WHERE id=?").get(c.comparisonId) as {
        summary_json: string;
      }
    ).summary_json;
    for (const fault of ["FAILED", "PARTIAL", "MALFORMED"] as const) {
      f.database.db
        .prepare("UPDATE scan_comparisons SET state=?,summary_json=? WHERE id=?")
        .run(fault === "MALFORMED" ? "COMPLETED" : fault, fault === "MALFORMED" ? "{}" : original, c.comparisonId);
      const t = triage.get(f.org, p.proposalId);
      f.capture("COMPARISON_OWNED_FAULT_" + fault, {
        triage: t,
        exclusivelyOwnedSyntheticFault: true,
        operationalResetAuthorized: false
      });
      expect(t.comparisons[0]!.coverageComplete).toBe(false);
      expect(t.nextAction).toBe("REVIEW_INCOMPLETE_OR_FAILED_COMPARISON");
      expect(t.proofs.some((p) => p.findings.length > 0)).toBe(true);
    }
    expect(f.wire.length).toBe(36);
  } finally {
    await f.close();
  }
});
