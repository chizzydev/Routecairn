import { it, expect } from "vitest";
import { ApplicationAnalystHandoff } from "../../src/dashboard/execution/ApplicationAnalystHandoff.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ownedResourceFixture } from "../helpers/owned-resource-fixture.js";
it("never promotes a different actor-visible owner to the primary owned-resource relationship", async () => {
  const f = await ownedResourceFixture(4, "owner-drift");
  try {
    const a = await f.acquire(f.input),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      edge = p.relationships!.relationships[0]!,
      cell = edge.cells.find((c) => c.actorId === "account-b")!,
      q = p.relationships!.questions.find(
        (q) => q.relationshipId === edge.relationshipId && q.actorId === "account-b"
      )!,
      wire = f.wire.length;
    f.capture("OWNER_DRIFT_BEFORE_ASSERTION", { proposal: p, wire });
    expect(cell.relationshipObserved).toBe(false);
    expect(cell.reasons).toContain("ACTOR_RESOURCE_OWNER_CONFLICT_OR_MISSING");
    expect(q).toMatchObject({ eligibility: "ABSTAIN_OR_COUNTEREVIDENCE", priority: 0, findingInferred: false });
    await expect(f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator")).rejects.toThrow(
      "CONTROLS_INCOMPLETE"
    );
    const handoff = new ApplicationAnalystHandoff(
      f.database,
      new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
      f.workbench
    ).export(f.org, p.proposalId);
    expect(
      handoff.analystBrief.uncertain.relationshipCounterevidence.some(
        (c) => c.actorId === "account-b" && c.reasons.includes("ACTOR_RESOURCE_OWNER_CONFLICT_OR_MISSING")
      )
    ).toBe(true);
    expect(JSON.stringify(handoff)).not.toContain("different-owner");
    expect(f.wire.length).toBe(wire);
    f.capture("OWNER_DRIFT_REVIEW_BLOCKED_WITHOUT_PROOF", { proposal: p, wire });
  } finally {
    await f.close();
  }
});
