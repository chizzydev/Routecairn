import { it, expect } from "vitest";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { transitionApplicationFixture } from "../helpers/transition-application-fixture.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
for (const app of ["procurement", "membership"] as const)
  it("reviews recorded before/after transitions and pins read-only proof/remediation on " + app, async () => {
    const f = await transitionApplicationFixture(app);
    try {
      const before = await f.acquire(),
        signed = await f.apply(app === "procurement" ? "account-a" : "account-b"),
        after = await f.acquire();
      const proposal = f.hypotheses.generate(
        f.org,
        {
          mapRevisionId: after.revision.revisionId,
          workflow: f.workflow,
          transition: f.declaration(
            before.revision.revisionId,
            signed,
            app === "procurement" ? "FORBIDDEN" : "LEGITIMATE"
          )
        },
        "operator"
      );
      expect(proposal.transition!.signatureVerified).toBe(true);
      expect(proposal.transition!.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
      expect(proposal.transition!.findingsInferred).toBe(false);
      const requests = f.wire.length,
        decision = await f.hypotheses.decide(f.org, proposal.proposalId, f.transitionReviewFor(proposal), "operator");
      expect(f.wire.length).toBe(requests);
      if (!decision.matrix) throw Error("reviewed transition matrix missing");
      const old = await f.service.execute(f.org, decision.matrix.revisionId, decision.matrix.digest, "operator");
      await f.wait(old.scanId!);
      const vulnerable = f.service.result(f.org, decision.matrix.revisionId);
      expect(vulnerable.findings).toHaveLength(2);
      f.setFixed();
      const fixedMatrix = await f.service.create(f.org, decision.matrix.input, "operator"),
        run = await f.service.execute(f.org, fixedMatrix.revisionId, fixedMatrix.digest, "operator");
      await f.wait(run.scanId!);
      const fixed = f.service.result(f.org, fixedMatrix.revisionId);
      writeFileSync(join(f.root, "TRANSITION_ASSESSMENT_SCOPE_RECEIPT.json"), JSON.stringify(fixed, null, 2), {
        flag: "wx"
      });
      expect(fixed.findings).toHaveLength(0);
      expect(fixed.verifiedPass).toBe(false);
      expect(fixed.verifiedReadOnlyChecksPass).toBe(true);
      expect(fixed.status).toBe("INCONCLUSIVE");
      const comparison = new ScanComparisonService(f.database).compare(old.scanId!, run.scanId!, {
        createdByUserId: "operator"
      });
      expect(comparison.summary.resolved).toBe(2);
      expect(f.wire.every((r) => r.method === "GET")).toBe(true);
      writeFileSync(
        join(f.root, "REVIEWED_TRANSITION_NATIVE_RESULT.json"),
        JSON.stringify(
          {
            app,
            proposal,
            decision,
            comparison,
            requests: f.wire.length,
            targetJournalReadRequests: 1,
            productStateChangingRequests: 0,
            findingsAreRoleReadBoundaryProofNotCausalTransitionProof: true,
            integrity: f.database.db.pragma("integrity_check"),
            foreignKeys: f.database.db.pragma("foreign_key_check"),
            fullAcceptance: false
          },
          null,
          2
        ),
        { flag: "wx" }
      );
    } finally {
      await f.close();
    }
  });
