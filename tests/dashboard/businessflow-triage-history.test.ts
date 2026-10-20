import { it, expect } from "vitest";
import { randomUUID } from "node:crypto";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
it("never hides the latest durable UNKNOWN behind a bounded older proof-history page", async () => {
  const f = await businessFlowFixture("orders");
  try {
    const a = await f.acquire(f.input),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
    if (!d.matrix) throw Error("MATRIX");
    const clone = f.database.db.prepare(
      "INSERT INTO authorization_workbench_revisions SELECT ?,organization_id,target_id,?,source_scan_id,input_json,request_json,context_digest,digest,preview_identity,created_by,?,expires_at,review_json FROM authorization_workbench_revisions WHERE id=?"
    );
    let last = "";
    f.database.db
      .transaction(() => {
        for (let i = 0; i < 101; i++) {
          last = randomUUID();
          clone.run(last, i + 2, new Date(Date.now() + i + 1).toISOString(), d.matrix!.revisionId);
        }
        f.database.db
          .prepare("INSERT INTO authorization_workbench_dispatches VALUES(?,?,?)")
          .run(last, "operator", new Date().toISOString());
      })
      .immediate();
    const t = new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench).get(f.org, p.proposalId);
    f.capture("TRIAGE_HISTORY_UNKNOWN_RECEIPT", {
      triage: t,
      insertedFreshFixtureRows: 101,
      last,
      actualDispatches: f.database.db.prepare("SELECT * FROM authorization_workbench_dispatches").all(),
      noDispatchEnqueueWasInvoked: true
    });
    expect(t.proofs.some((p) => p.status === "UNKNOWN" && p.revisionId === last)).toBe(true);
    expect(t.nextAction).toBe("REVIEW_INCOMPLETE_HISTORY");
    expect(t.proofs.length).toBeLessThanOrEqual(100);
    expect((t as unknown as { historyIncomplete: boolean }).historyIncomplete).toBe(true);
    expect(f.wire).toHaveLength(12);
  } finally {
    await f.close();
  }
});
