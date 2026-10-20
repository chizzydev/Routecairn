import { it, expect } from "vitest";
import { roleflowApplicationFixture } from "../helpers/roleflow-application-fixture.js";
it("binds exact order, typed state, policy, source custody, supersession and missing matrix ACK without replay", async () => {
  const f = await roleflowApplicationFixture();
  try {
    const a = await f.acquire(),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      review = f.reviewFor(p);
    const reversed = { ...review, expectations: [...review.expectations].reverse() };
    await expect(f.hypotheses.decide(f.org, p.proposalId, reversed, "operator")).rejects.toThrow("EXACT_ORDER");
    const typed = structuredClone(review);
    typed.expectations[0]!.states[0]!.expectedValue = "1";
    await expect(f.hypotheses.decide(f.org, p.proposalId, typed, "operator")).rejects.toThrow("TYPED_STATE");
    const d = await f.hypotheses.decide(f.org, p.proposalId, review, "operator");
    if (!d.matrix) throw Error("matrix");
    const edit = structuredClone(d.matrix.input);
    edit.expectations[1]!.dependsOn = [];
    await expect(f.service.preview(f.org, edit)).rejects.toThrow("POLICY_OR_SOURCE_CHANGED");
    const next = f.hypotheses.generate(
      f.org,
      { mapRevisionId: a.revision.revisionId, workflow: f.workflow, supersedes: p.proposalId },
      "operator"
    );
    await expect(f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator")).rejects.toThrow(
      "SUPERSEDED"
    );
    f.database.db.exec(
      "CREATE TRIGGER owned_flow_matrix_failure BEFORE INSERT ON authorization_workbench_revisions BEGIN SELECT RAISE(ABORT,'OWNED_FLOW_ACK_FAILURE');END;"
    );
    await expect(f.hypotheses.decide(f.org, next.proposalId, f.reviewFor(next), "operator")).rejects.toThrow(
      "OWNED_FLOW_ACK_FAILURE"
    );
    expect(f.hypotheses.get(f.org, next.proposalId).decisions).toHaveLength(1);
    expect(f.hypotheses.get(f.org, next.proposalId).matrices).toHaveLength(0);
    await expect(f.hypotheses.decide(f.org, next.proposalId, f.reviewFor(next), "operator")).rejects.toThrow();
    expect(f.wire).toHaveLength(16);
  } finally {
    await f.close();
  }
});
