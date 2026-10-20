import { it, expect } from "vitest";
import { roleflowApplicationFixture } from "../helpers/roleflow-application-fixture.js";
import { writeFileSync } from "node:fs";
import { join } from "node:path";
it("refuses a role finding when same-scalar response belongs to a different tenant", async () => {
  const f = await roleflowApplicationFixture();
  try {
    const a = await f.acquire(),
      p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId, workflow: f.workflow }, "operator"),
      d = await f.hypotheses.decide(f.org, p.proposalId, f.reviewFor(p), "operator");
    if (!d.matrix) throw Error("matrix");
    f.setTenantReassigned();
    const run = await f.service.execute(f.org, d.matrix.revisionId, d.matrix.digest, "operator");
    await f.wait(run.scanId!);
    const result = f.service.result(f.org, d.matrix.revisionId);
    writeFileSync(
      join(f.root, "TENANT_PROOF_RESULT.json"),
      JSON.stringify(
        {
          result,
          wire: f.wire,
          expected:
            "No protected-tenant object exposure proven; wrong-tenant same-scalar responses must be INCONCLUSIVE"
        },
        null,
        2
      ),
      { flag: "wx" }
    );
    expect(result.findings).toHaveLength(0);
    expect(result.status).toBe("INCONCLUSIVE");
    expect(
      result
        .checks!.filter((c) => ["operation-account-a", "operation-account-b"].includes(c.checkId))
        .every((c) => c.reasonCode === "EXPECTED_FLOW_RESOURCE_NOT_PROVEN")
    ).toBe(true);
    expect(f.wire).toHaveLength(28);
  } finally {
    await f.close();
  }
});
