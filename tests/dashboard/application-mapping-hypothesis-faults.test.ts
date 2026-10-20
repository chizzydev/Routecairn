import { it, expect } from "vitest";
import { schemaApplicationFixture } from "../helpers/schema-application-fixture.js";
import { ApplicationHypothesisService } from "../../src/dashboard/execution/ApplicationHypothesisService.js";
for (const fault of ["missing-control", "wrong-object", "identity-spoof"])
  it("abstains from native " + fault + " without proof authority", async () => {
    const f = await schemaApplicationFixture();
    try {
      const { mappingInput } = f.makeInput();
      if (fault === "missing-control") f.setMissingControl();
      if (fault === "wrong-object") f.setWrongPrimary();
      if (fault === "identity-spoof") f.setIdentitySpoof();
      const a = await f.mapping.create(f.org, mappingInput, "operator"),
        run = await f.mapping.execute(f.org, a.revisionId, a.digest, "operator");
      await f.wait(run.scanId!);
      const service = new ApplicationHypothesisService(f.database, f.vault, f.execution),
        p = service.generate(f.org, { mapRevisionId: a.revisionId }, "operator"),
        c = p.candidates.find((c) => c.routeId === "schema-route-1")!;
      expect(c.eligibility).toBe(fault === "wrong-object" ? "EVIDENCE_READY_FOR_POLICY_REVIEW" : "ABSTAIN");
      await expect(
        service.decide(
          f.org,
          p.proposalId,
          {
            action: "REVIEW",
            digest: p.digest,
            candidateId: c.candidateId,
            policyConfirmed: true,
            ownershipConfirmed: true,
            identity: 42,
            tenant: "workspace-red",
            explanation: "Owner declares the exact fixture boundary.",
            decisions: { primary: "ALLOW", "account-a": "DENY", "account-b": "DENY", anonymous: "DENY" }
          },
          "operator"
        )
      ).rejects.toThrow(fault === "wrong-object" ? "TYPED_PRIMARY_MARKER" : "ABSTAIN");
      expect(f.wire).toHaveLength(fault === "identity-spoof" ? 8 : 20);
      expect(f.database.db.prepare("SELECT COUNT(*) n FROM application_hypothesis_decisions").get()).toEqual({ n: 0 });
    } finally {
      await f.close();
    }
  });
