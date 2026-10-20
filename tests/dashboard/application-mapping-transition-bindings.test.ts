import { it, expect } from "vitest";
import { transitionApplicationFixture } from "../helpers/transition-application-fixture.js";
it("requires exact transition trust, policy and purpose then refuses missing-ack replay", async () => {
  const f = await transitionApplicationFixture("membership");
  try {
    const before = await f.acquire(),
      event = await f.apply("account-b"),
      after = await f.acquire(),
      proposal = f.hypotheses.generate(
        f.org,
        {
          mapRevisionId: after.revision.revisionId,
          workflow: f.workflow,
          transition: f.declaration(before.revision.revisionId, event)
        },
        "operator"
      ),
      review = f.transitionReviewFor(proposal),
      requests = f.wire.length;
    const authority = structuredClone(review);
    authority.transitionReview.authorityKeySha256 = "0".repeat(64);
    await expect(f.hypotheses.decide(f.org, proposal.proposalId, authority, "operator")).rejects.toThrow("AUTHORITY");
    const incomplete = structuredClone(review);
    incomplete.transitionReview.checks.pop();
    await expect(f.hypotheses.decide(f.org, proposal.proposalId, incomplete, "operator")).rejects.toThrow(
      "PURPOSE_CONSENT"
    );
    const changed = structuredClone(review);
    changed.expectations[0]!.states[0]!.expectedValue = 999;
    await expect(f.hypotheses.decide(f.org, proposal.proposalId, changed, "operator")).rejects.toThrow("TYPED_STATE");
    f.database.db.exec(
      "CREATE TRIGGER owned_transition_matrix_failure BEFORE INSERT ON authorization_workbench_revisions BEGIN SELECT RAISE(ABORT,'OWNED_TRANSITION_ACK_FAILURE');END;"
    );
    await expect(f.hypotheses.decide(f.org, proposal.proposalId, review, "operator")).rejects.toThrow(
      "OWNED_TRANSITION_ACK_FAILURE"
    );
    const h = f.hypotheses.get(f.org, proposal.proposalId);
    expect(h.decisions).toHaveLength(1);
    expect(h.matrices).toHaveLength(0);
    await expect(f.hypotheses.decide(f.org, proposal.proposalId, review, "operator")).rejects.toThrow(
      "ALREADY_RECORDED"
    );
    expect(f.wire.length).toBe(requests);
    f.capture("TRANSITION_MISSING_ACK_RETAINED");
  } finally {
    await f.close();
  }
});
