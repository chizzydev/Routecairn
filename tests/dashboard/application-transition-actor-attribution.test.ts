import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { transitionApplicationFixture } from "../helpers/transition-application-fixture.js";
for (const app of ["procurement", "membership"] as const)
  it("refuses primary marker substitution for an independently verified account-a on " + app, async () => {
    const f = await transitionApplicationFixture(app);
    try {
      const before = await f.acquire(),
        event = await f.apply("account-a");
      if (app === "procurement") f.setActorStateDrift();
      const after = await f.acquire(),
        requests = f.wire.length;
      const proposal = f.hypotheses.generate(
        f.org,
        {
          mapRevisionId: after.revision.revisionId,
          workflow: f.workflow,
          transition: f.declaration(before.revision.revisionId, event)
        },
        "operator"
      );
      const route = event.signed.event.routeId;
      const selected = after.result.observations
        .find((o) => o.routeId === route)!
        .cells.find((c) => c.actorId === "account-a")!;
      const primary = after.result.observations
        .find((o) => o.routeId === route)!
        .cells.find((c) => c.actorId === "primary")!;
      writeFileSync(
        join(f.root, "ACTOR_ATTRIBUTION_ACTUAL_NATIVE.json"),
        JSON.stringify(
          {
            app,
            proposal,
            primary,
            selected,
            requests,
            integrity: f.database.db.pragma("integrity_check"),
            foreignKeys: f.database.db.pragma("foreign_key_check")
          },
          null,
          2
        ),
        { flag: "wx" }
      );
      expect(primary.nativeDecision).toBe("ALLOWED");
      expect(selected.identityVerified).toBe(true);
      if (app === "membership") expect(selected.nativeDecision).toBe("DENIED");
      expect(proposal.transition!.eligibility).toBe("ABSTAIN");
      expect(proposal.transition!.findingsInferred).toBe(false);
      await expect(
        f.hypotheses.decide(f.org, proposal.proposalId, f.transitionReviewFor(proposal), "operator")
      ).rejects.toThrow();
      expect(f.wire.length).toBe(requests);
      expect(f.hypotheses.get(f.org, proposal.proposalId).matrices).toHaveLength(0);
    } finally {
      await f.close();
    }
  });
