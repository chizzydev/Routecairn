import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { roleflowApplicationFixture } from "../helpers/roleflow-application-fixture.js";
it("abstains from a predeclared incomplete state workflow without wire from proposals", async () => {
  const f = await roleflowApplicationFixture("membership", "missing-state");
  try {
    const a = await f.acquire(),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator");
    expect(p.flow!.eligibility).toBe("ABSTAIN");
    await expect(f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator")).rejects.toThrow("ABSTAIN");
    expect(f.wire).toHaveLength(16);
  } finally {
    await f.close();
  }
});
it("verifies declared shared function access and legitimate cross-tenant collaboration without a finding", async () => {
  const f = await roleflowApplicationFixture("membership", "shared");
  try {
    const a = await f.acquire(),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
    if (!d.matrix) throw Error("matrix");
    const run = await f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
    await f.wait(run.scanId!);
    expect(f.service.result(f.org, d.matrix.revisionId).findings).toHaveLength(0);
    expect(f.wire).toHaveLength(8 + 4 * (f.mappingInput.routes.length + f.workflow.routeIds.length));
  } finally {
    await f.close();
  }
});
for (const fault of ["state", "reassignment", "revocation", "wrong-object"] as const)
  it("retains honest native uncertainty for " + fault, async () => {
    const f = await roleflowApplicationFixture("procurement", fault === "wrong-object" ? "wrong-object" : "vulnerable");
    try {
      const a = await f.acquire(),
        p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator");
      if (fault === "wrong-object") {
        await expect(f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator")).rejects.toThrow(
          "CONTROLS_INCOMPLETE"
        );
        expect(f.wire).toHaveLength(16);
        return;
      }
      const d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
      if (!d.matrix) throw Error("matrix");
      if (fault === "state") f.setStateDrift();
      if (fault === "reassignment") f.setReassigned();
      if (fault === "revocation") f.setRevoked();
      const r = await f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
      await f.wait(r.scanId!);
      const result = f.service.result(f.org, d.matrix.revisionId);
      expect(result.findings).toHaveLength(0);
      expect(result.verifiedPass).toBe(false);
      expect(result.status).toBe("INCONCLUSIVE");
      if (fault === "state")
        expect(
          result
            .checks!.filter((c) => c.checkId.startsWith("operation-"))
            .every((c) => c.reasonCode === "PREREQUISITE_STATE_NOT_CONFIRMED")
        ).toBe(true);
      writeFileSync(
        join(f.root, "COUNTEREXAMPLE_" + fault + ".json"),
        JSON.stringify(
          { fault, result, wire: f.wire, stateChangingRequests: f.wire.filter((r) => r.method !== "GET").length },
          null,
          2
        ),
        { flag: "wx" }
      );
    } finally {
      await f.close();
    }
  });

it("keeps prerequisite state custody separated per actor", async () => {
  const f = await roleflowApplicationFixture();
  try {
    const a = await f.acquire(),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
    if (!d.matrix) throw Error("matrix");
    f.setActorStateDrift();
    const run = await f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
    await f.wait(run.scanId!);
    const result = f.service.result(f.org, d.matrix.revisionId);
    expect(result.checks!.find((c) => c.checkId === "operation-account-a")!.reasonCode).toBe(
      "PREREQUISITE_STATE_NOT_CONFIRMED"
    );
    expect(result.checks!.find((c) => c.checkId === "operation-account-b")!.outcome).toBe("FAIL");
    expect(result.findings).toHaveLength(1);
    expect(result.verifiedPass).toBe(false);
  } finally {
    await f.close();
  }
});
