import { it, expect } from "vitest";
import { transitionApplicationFixture } from "../helpers/transition-application-fixture.js";
for (const scenario of ["wrong-tenant", "concurrent-state", "role-reassignment"] as const)
  it("retains native abstention for " + scenario, async () => {
    const f = await transitionApplicationFixture("procurement");
    try {
      const before = await f.acquire(),
        event = await f.apply("account-a");
      if (scenario === "wrong-tenant") f.control.resourceTenant = "workspace-blue";
      if (scenario === "concurrent-state") {
        f.control.revision++;
        f.control.values["business.phase"] = "CONCURRENT";
      }
      if (scenario === "role-reassignment") f.control.actorRoles = { account_a: "other-role" };
      const after = await f.acquire(),
        proposal = f.hypotheses.generate(
          f.org,
          {
            mapRevisionId: after.revision.revisionId,
            workflow: f.workflow,
            transition: f.declaration(before.revision.revisionId, event)
          },
          "operator"
        );
      expect(proposal.transition!.eligibility).toBe("ABSTAIN");
      expect(proposal.transition!.policyOutcome).toBe("INCONCLUSIVE");
      const requests = f.wire.length;
      await expect(
        f.hypotheses.decide(f.org, proposal.proposalId, f.transitionReviewFor(proposal), "operator")
      ).rejects.toThrow();
      expect(f.wire.length).toBe(requests);
      expect(f.hypotheses.get(f.org, proposal.proposalId).matrices).toHaveLength(0);
      f.capture("TRANSITION_COUNTEREXAMPLE_" + scenario);
    } finally {
      await f.close();
    }
  });
