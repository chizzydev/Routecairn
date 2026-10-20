import { it, expect, vi } from "vitest";
import { tenantlessApplicationFixture } from "../helpers/tenantless-application-fixture.js";
import { ApplicationAssessmentReadiness } from "../../src/dashboard/execution/ApplicationAssessmentReadiness.js";
import { ApplicationEvidenceTriage } from "../../src/dashboard/execution/ApplicationEvidenceTriage.js";
import { ApplicationAnalystHandoff } from "../../src/dashboard/execution/ApplicationAnalystHandoff.js";
it.each(["PRINCIPAL_ROLE", "TENANT_AWARE"] as const)(
  "verifies %s through real native mapping, reviewed hypothesis, proof and handoff",
  async (model) => {
    const f = await tenantlessApplicationFixture(model);
    try {
      const decrypt = vi.spyOn(f.vault, "decryptForHealthCheck"),
        before = f.wire.length,
        ready = new ApplicationAssessmentReadiness(f.database).get(f.org, {
          targetId: f.onboard.targetId,
          ...f.onboard.credentials
        });
      expect(ready.actorsReady).toBe(true);
      expect(ready.executionAuthority).toBe("NONE");
      expect(decrypt).not.toHaveBeenCalled();
      expect(f.wire.length).toBe(before);
      decrypt.mockRestore();
      const a = await f.acquire();
      expect(a.report.identityVerification?.primary).toMatchObject({
        verified: true,
        principalMatched: true,
        roleMatched: true,
        identityModel: model
      });
      if (model === "PRINCIPAL_ROLE") {
        expect(a.report.identityVerification?.primary?.tenantMatched).toBeUndefined();
        expect(a.report.identityVerification?.primary?.tenantHash).toBeUndefined();
        expect(a.report.identityVerification?.primary?.tenantVerification).toBe("NOT_APPLICABLE");
      } else expect(a.report.identityVerification?.primary?.tenantMatched).toBe(true);
      const p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator"),
        c = p.candidates[0]!;
      expect(c.eligibility).toBe("EVIDENCE_READY_FOR_POLICY_REVIEW");
      expect(c.identityModel).toBe(model);
      const review = await f.hypotheses.decide(
        f.org,
        p.proposalId,
        {
          action: "REVIEW",
          digest: p.digest,
          candidateId: c.candidateId,
          policyConfirmed: true,
          ownershipConfirmed: true,
          explanation: "Synthetic owner declares generated shared object restricted to primary",
          decisions: { primary: "ALLOW", "account-a": "DENY", "account-b": "DENY", anonymous: "DENY" },
          identity: "generated-shared-object",
          ...(model === "TENANT_AWARE" ? { tenant: "tenant-0" } : {})
        },
        "operator"
      );
      expect(review.matrix).toBeTruthy();
      const matrix = review.matrix!;
      const run = await f.workbench.execute(f.org, matrix.revisionId, matrix.digest, "operator");
      await f.wait(run.scanId!);
      const result = f.workbench.result(f.org, matrix.revisionId);
      expect(result.status).toBe("FINDINGS");
      expect(result.verifiedPass).toBe(false);
      const handoff = new ApplicationAnalystHandoff(
        f.database,
        new ApplicationEvidenceTriage(f.database, f.hypotheses, f.workbench),
        f.workbench
      ).export(f.org, p.proposalId);
      expect(handoff.identityModel).toBe(model);
      expect(handoff.fullApplicationAcceptance).toBe(false);
      f.capture("IDENTITY_NATIVE_PROOF_HANDOFF", { ready, report: a.report, proposal: p, proof: result, handoff });
    } finally {
      await f.close();
    }
  }
);
it.each(["missing-principal", "missing-role", "conflicting-principal", "conflicting-role", "revoked"])(
  "keeps %s identity evidence out of hypotheses and native proof",
  async (behavior) => {
    const f = await tenantlessApplicationFixture();
    try {
      f.setBehavior(behavior);
      const a = await f.acquire();
      expect(a.report.identityVerification?.primary?.verified).toBe(false);
      const p = f.hypotheses.generate(f.org, { mapRevisionId: a.revision.revisionId }, "operator");
      expect(p.candidates.every((c) => c.eligibility === "ABSTAIN")).toBe(true);
      expect(
        a.report.apiGraphql?.checks.filter((c) => c.actorId === "primary").every((c) => c.outcome === "BLOCKED")
      ).toBe(true);
      f.capture("IDENTITY_NATIVE_REFUSAL", { behavior, report: a.report, proposal: p });
    } finally {
      await f.close();
    }
  }
);
