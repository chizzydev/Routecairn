import { it, expect } from "vitest";
import { businessFlowFixture } from "../helpers/businessflow-fixture.js";
it("never mistakes equal tenant labels for a producer entity identifier and consumer foreign reference", async () => {
  const f = await businessFlowFixture("orders");
  try {
    const a = await f.acquire(f.input),
      workflow = {
        ...f.workflow,
        relationships: f.workflow.relationships.map((e) => ({
          ...e,
          identifier: "record.tenant",
          reference: "record.tenant"
        }))
      },
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow }, "operator");
    f.capture("TENANT_LABEL_NOT_ENTITY_RELATIONSHIP", { proposal: p, applicationRequests: f.wire.length });
    expect(p.relationships!.eligibility).toBe("ABSTAIN");
    await expect(f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator")).rejects.toThrow(
      "RELATIONSHIP_ABSTAIN"
    );
    expect(f.wire).toHaveLength(12);
  } finally {
    await f.close();
  }
});
