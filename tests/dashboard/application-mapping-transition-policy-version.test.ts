import { it, expect } from "vitest";
import { transitionApplicationFixture } from "../helpers/transition-application-fixture.js";
it("requires a new explicit review for changed transition policy and refuses old-matrix admission", async () => {
  const f = await transitionApplicationFixture("membership");
  try {
    const before = await f.acquire(),
      event = await f.apply("account-b"),
      after = await f.acquire(),
      input = {
        mapRevisionId: after.revision.revisionId,
        workflow: f.workflow,
        transition: f.declaration(before.revision.revisionId, event, "LEGITIMATE")
      },
      p = f.hypotheses.generate(f.org, input, "operator"),
      review = f.transitionReviewFor(p),
      d = await f.hypotheses.decide(f.org, p.proposalId, review, "operator");
    if (!d.matrix) throw Error("reviewed matrix required");
    const requests = f.wire.length,
      changed = structuredClone(d.matrix.input);
    changed.expectations[0]!.decisions["account-a"] = "DENY";
    await expect(f.service.preview(f.org, changed)).rejects.toThrow("POLICY_OR_SOURCE_CHANGED");
    const next = f.hypotheses.generate(
      f.org,
      { ...input, supersedes: p.proposalId, transition: { ...input.transition, policy: "FORBIDDEN" } },
      "operator"
    );
    expect(next.digest).not.toBe(p.digest);
    expect(next.transition!.findingsInferred).toBe(false);
    expect(next.transition!.executionAuthority).toBe("NONE");
    await expect(f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator")).rejects.toThrow(
      "SUPERSEDED"
    );
    await expect(f.hypotheses.decide(f.org, next.proposalId, review, "operator")).rejects.toThrow("STALE_REVIEW");
    expect(f.hypotheses.get(f.org, p.proposalId).decisions).toHaveLength(1);
    expect(f.hypotheses.get(f.org, next.proposalId).decisions).toHaveLength(0);
    expect(f.wire.length).toBe(requests);
    f.capture("TRANSITION_POLICY_VERSION_AND_SUPERSESSION");
  } finally {
    await f.close();
  }
});
