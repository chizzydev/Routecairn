import { it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ApplicationAnalystHandoff } from "../../src/dashboard/execution/ApplicationAnalystHandoff.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
it("finds a real cached FAILED comparison beyond the one-hundred-proof detail cutoff with read-only continuation", async () => {
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
    const comparison = new ScanComparisonService(f.database).compare(first.scanId!, after.scanId!, {
      createdByUserId: "operator"
    });
    f.capture("OLD_COMPARISON_BEFORE_OWNED_CACHED_FAILURE", { comparison });
    f.database.db.prepare("UPDATE scan_comparisons SET state='FAILED' WHERE id=?").run(comparison.comparisonId);
    const clone = f.database.db.prepare(
      "INSERT INTO authorization_workbench_revisions SELECT ?,organization_id,target_id,?,source_scan_id,input_json,request_json,context_digest,digest,preview_identity,created_by,?,expires_at,review_json FROM authorization_workbench_revisions WHERE id=?"
    );
    f.database.db
      .transaction(() => {
        for (let i = 0; i < 105; i++)
          clone.run(randomUUID(), i + 3, new Date(Date.now() + i + 1).toISOString(), d.matrix!.revisionId);
      })
      .immediate();
    const triage = new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
      service = new ApplicationAnalystHandoff(f.database, triage, f.workbench),
      view = triage.get(f.org, p.proposalId);
    expect(view.historyIncomplete).toBe(true);
    expect(view.comparisons).toHaveLength(0);
    expect(view.nextAction).toBe("REVIEW_INCOMPLETE_HISTORY");
    f.capture("OLD_FAILED_NATIVE_DB_BEFORE_PAGING", {
      view,
      rows: f.database.db.prepare("SELECT id,state,older_scan_id,newer_scan_id FROM scan_comparisons").all(),
      wire: f.wire.length
    });
    const history = service.page(f.org, p.proposalId, { kind: "comparisons", query: "FAILED" });
    f.capture("OLD_FAILED_COMPARISON_PAGE_RED_GREEN", { history, view, wire: f.wire.length });
    expect(history.total).toBe(1);
    expect(history.entries[0]!.id).toBe(comparison.comparisonId);
    expect(history.entries[0]!.state).toBe("FAILED");
    expect(history.entries[0]!.detail).toMatchObject({ coverageComplete: false });
    const packet = service.export(f.org, p.proposalId) as unknown as {
      comparisonIndex: { id: string; state: string }[];
    };
    expect(packet.comparisonIndex).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: comparison.comparisonId, state: "FAILED" })])
    );
    expect(f.wire).toHaveLength(36);
  } finally {
    await f.close();
  }
});
