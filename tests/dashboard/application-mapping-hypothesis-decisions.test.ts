import { it, expect } from "vitest";
import { applicationMappingFixture } from "../helpers/application-mapping-fixture.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
it("records concurrent policy once and never adopts a decision after a missing matrix acknowledgement", async () => {
  const f = await applicationMappingFixture();
  try {
    const a = await f.acquire(),
      s = new ApplicationHypothesisService(f.database, f.vault, f.execution),
      p = s.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
      c = p.candidates.find((c) => c.priority > 0)!;
    const value = {
      action: "REVIEW",
      digest: p.digest,
      candidateId: c.candidateId,
      policyConfirmed: true,
      ownershipConfirmed: true,
      identity: "doc-a",
      tenant: "tenant-a",
      explanation: "Owner declares this object private to its primary actor.",
      decisions: { primary: "ALLOW", "account-a": "DENY", "account-b": "DENY", anonymous: "DENY" }
    };
    const runs = await Promise.allSettled([
      s.decide(f.org, p.proposalId, value, "operator"),
      s.decide(f.org, p.proposalId, value, "operator")
    ]);
    expect(runs.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(s.get(f.org, p.proposalId).decisions).toHaveLength(1);
    const q = s.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator");
    f.database.db.exec(
      "CREATE TRIGGER fixture_hypothesis_matrix_failure BEFORE INSERT ON authorization_workbench_revisions BEGIN SELECT RAISE(ABORT,'FIXTURE_MATRIX_ACK_UNAVAILABLE'); END"
    );
    await expect(s.decide(f.org, q.proposalId, { ...value, digest: q.digest }, "operator")).rejects.toThrow(
      "FIXTURE_MATRIX_ACK_UNAVAILABLE"
    );
    const history = s.get(f.org, q.proposalId);
    expect(history.decisions).toHaveLength(1);
    expect(history.matrices).toHaveLength(0);
    await expect(s.decide(f.org, q.proposalId, { ...value, digest: q.digest }, "operator")).rejects.toThrow(
      "ALREADY_RECORDED"
    );
    expect(f.wire).toHaveLength(20);
  } finally {
    await f.close();
  }
});
