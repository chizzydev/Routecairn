import { it, expect } from "vitest";
import { readFileSync, appendFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
import { observedStateRegressionFixture } from "../helpers/observed-state-regression-fixture.js";
for (const fault of [
  "missing-later",
  "revision-changed",
  "contradictory-type",
  "wrong-object",
  "wrong-tenant",
  "role-changed",
  "missing-identity",
  "cached-failed-comparison",
  "revoked-policy",
  "tampered-before-witness"
] as const) {
  it("never quiets observed-state uncertainty: " + fault, async () => {
    const f = await observedStateRegressionFixture("procurement");
    try {
      const p = await f.prepare();
      if (fault === "revision-changed") f.control.revision++;
      if (fault === "contradictory-type") f.control.actorValues = { account_a: { "business.phase": "2" } };
      if (fault === "wrong-object") f.setReassigned();
      if (fault === "wrong-tenant") f.control.resourceTenant = "workspace-blue";
      if (fault === "role-changed") f.control.actorRoles = { account_a: "wrong-role" };
      if (fault === "missing-identity") f.setRevoked();
      const later = fault === "missing-later" ? undefined : await f.acquire();
      if (fault === "cached-failed-comparison") {
        const c = new ScanComparisonService(f.database).compare(p.after.run.scanId!, later!.run.scanId!);
        f.database.db.prepare("UPDATE scan_comparisons SET state='FAILED' WHERE id=?").run(c.comparisonId);
      }
      if (fault === "revoked-policy")
        f.states.decide(
          f.org,
          p.policy.id,
          { action: "REVOKE", digest: p.policy.digest, reason: "Explicit owner policy authority withdrawal" },
          "operator"
        );
      if (fault === "tampered-before-witness") {
        const artifact = f.database.db
          .prepare(
            "SELECT canonical_path FROM artifacts WHERE id=(SELECT json_report_artifact_id FROM scans WHERE id=?)"
          )
          .get(p.before.run.scanId) as { canonical_path: string };
        writeFileSync(join(f.root, "AUTHENTIC_BEFORE_WITNESS.json"), readFileSync(artifact.canonical_path), {
          flag: "wx"
        });
        appendFileSync(artifact.canonical_path, " ");
      }
      const count = f.wire.length,
        run = await f.ca.runNow(p.assurancePolicyId, "operator", later?.revision.revisionId),
        result = f.states.assessment(
          f.org,
          (run.safeSummary as { observationAssessmentId: string }).observationAssessmentId
        );
      f.receipt("OBSERVED_STATE_UNCERTAINTY_" + fault, { fault, p, later, run, result });
      expect(run.gateStatus).toBe("INCONCLUSIVE");
      expect(result.outcome).toBe("INCONCLUSIVE");
      expect(result.quiet).toBe(false);
      expect(result.requiresHumanReview).toBe(true);
      expect(result.confirmedVulnerability).toBe(false);
      expect(f.ca.notifications()).toHaveLength(1);
      expect(f.wire.length).toBe(count);
      if (fault === "cached-failed-comparison") expect(result.reasons).toContain("NATIVE_COMPARISON_UNUSABLE");
      if (fault === "revoked-policy") expect(result.reasons).toContain("POLICY_REVOKED");
      if (fault === "tampered-before-witness") {
        expect(result.reasons).toContain("NATIVE_SOURCE_OR_AUTHORITY_UNAVAILABLE");
        expect(result.sourceErrorCode).toContain("SOURCE_CHANGED");
      }
    } finally {
      await f.close();
    }
  });
}
it("versions reviewed policy and refuses old authority without rewriting assessments", async () => {
  const f = await observedStateRegressionFixture("membership");
  try {
    const p = await f.prepare(),
      draft = f.states.create(
        f.org,
        { ...p.policy.snapshot.input, name: "Reviewed successor observed-state policy", supersedes: p.policy.id },
        "operator"
      );
    expect(f.states.get(f.org, p.policy.id).status).toBe("APPROVED");
    const approved = f.states.decide(
      f.org,
      draft.id,
      {
        action: "APPROVE",
        digest: draft.digest,
        authorityConfirmed: true,
        expectationsConfirmed: true,
        scopeConfirmation: "OBSERVATIONS_ONLY_TRANSITION_AUTHORIZATION_NOT_TESTED"
      },
      "operator"
    );
    expect(approved.revision).toBe(2);
    expect(f.states.get(f.org, p.policy.id).status).toBe("SUPERSEDED");
    const wire = f.wire.length,
      run = await f.ca.runNow(p.assurancePolicyId, "operator");
    expect(run.gateStatus).toBe("INCONCLUSIVE");
    expect(f.wire.length).toBe(wire);
    f.receipt("OBSERVED_STATE_SUCCESSOR_AUTHORITY", { p, draft, approved, run });
  } finally {
    await f.close();
  }
});
