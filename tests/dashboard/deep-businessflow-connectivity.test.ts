import { it, expect } from "vitest";
import { deepBusinessFixture } from "../helpers/deep-businessflow-fixture.js";
it("abstains when a four-step declared workflow leaves observed steps without a producer relationship", async () => {
  const f = await deepBusinessFixture();
  try {
    const a = await f.acquire(f.input),
      p = f.hypotheses.generate(
        f.org,
        {
          mapRevisionId: a.revision.revisionId,
          workflow: { ...f.workflow, relationships: f.workflow.relationships.slice(0, 1) }
        },
        "operator"
      );
    f.capture("DISCONNECTED_FOUR_STEP_NATIVE_RED_GREEN", { proposal: p, wire: f.wire.length });
    expect(p.relationships!.eligibility).toBe("ABSTAIN");
    await expect(f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator")).rejects.toThrow(
      "RELATIONSHIP_ABSTAIN"
    );
    expect(f.wire.every((r) => r.method === "GET")).toBe(true);
  } finally {
    await f.close();
  }
});
