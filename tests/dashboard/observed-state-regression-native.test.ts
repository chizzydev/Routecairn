import { it, expect } from "vitest";
import { observedStateRegressionFixture } from "../helpers/observed-state-regression-fixture.js";
for (const app of ["procurement", "membership"] as const) {
  it("matches reviewed actor-specific later native observations with zero analysis traffic on " + app, async () => {
    const f = await observedStateRegressionFixture(app);
    try {
      const p = await f.prepare(),
        later = await f.acquire(),
        wire = f.wire.length,
        scanCount = (f.database.db.prepare("SELECT COUNT(*) n FROM scans").get() as { n: number }).n;
      const run = await f.ca.runNow(p.assurancePolicyId, "operator", later.revision.revisionId),
        summary = run.safeSummary as {
          observationAssessmentId: string;
          quiet: boolean;
          verifiedApplicationPass: boolean;
          stateChangeAuthorizationAssessment: string;
        };
      const result = f.states.assessment(f.org, summary.observationAssessmentId);
      f.receipt("OBSERVED_STATE_HEALTHY_NATIVE", { app, p, run, result });
      expect(run.gateStatus).toBe("PASSED");
      expect(summary.quiet).toBe(true);
      expect(summary.verifiedApplicationPass).toBe(false);
      expect(summary.stateChangeAuthorizationAssessment).toBe("NOT_TESTED");
      expect(result.outcome).toBe("MATCHED");
      expect(result.confirmedVulnerability).toBe(false);
      expect(result.cells.every((c) => c.outcome === "MATCHED")).toBe(true);
      expect(result.cells.some((c) => c.stateAssessment === "NOT_OBSERVED_DUE_TO_DENIAL")).toBe(true);
      expect(f.wire.length).toBe(wire);
      expect((f.database.db.prepare("SELECT COUNT(*) n FROM scans").get() as { n: number }).n).toBe(scanCount);
      expect(f.wire.every((r) => r.method === "GET")).toBe(true);
      expect(() =>
        f.database.db
          .prepare("UPDATE application_observation_policy_versions SET digest=? WHERE id=?")
          .run("0".repeat(64), p.policy.id)
      ).toThrow("IMMUTABLE_OBSERVATION_POLICY");
      expect(() =>
        f.database.db
          .prepare("UPDATE application_observation_assessments SET snapshot_json='{}' WHERE id=?")
          .run(result.id)
      ).toThrow("IMMUTABLE_OBSERVATION_ASSESSMENT");
      await f.ca.reconcileNow();
      expect(
        (f.database.db.prepare("SELECT COUNT(*) n FROM application_observation_assessments").get() as { n: number }).n
      ).toBe(1);
    } finally {
      await f.close();
    }
  });
  it("alerts selective typed state drift and retains history after healthy retest on " + app, async () => {
    const f = await observedStateRegressionFixture(app);
    try {
      const p = await f.prepare(),
        actor = app === "procurement" ? "account_a" : "account_b",
        path = app === "procurement" ? "business.phase" : "consent.state";
      f.control.actorValues = { [actor]: { [path]: app === "procurement" ? 3 : "REACTIVATED" } };
      const later = await f.acquire(),
        wire = f.wire.length,
        run = await f.ca.runNow(p.assurancePolicyId, "operator", later.revision.revisionId),
        result = f.states.assessment(
          f.org,
          (run.safeSummary as { observationAssessmentId: string }).observationAssessmentId
        );
      f.receipt("OBSERVED_STATE_SELECTIVE_NATIVE_RED_POLICY", { app, p, run, result });
      expect(run.gateStatus).toBe("REGRESSION");
      expect(result.outcome).toBe("DRIFT");
      expect(
        result.cells.filter((c) => c.outcome === "DRIFT").every((c) => c.actorId === actor.replaceAll("_", "-"))
      ).toBe(true);
      expect(
        result.cells.filter((c) => c.actorId !== actor.replaceAll("_", "-")).every((c) => c.outcome === "MATCHED")
      ).toBe(true);
      expect(result.confirmedVulnerability).toBe(false);
      expect((f.database.db.prepare("SELECT COUNT(*) n FROM findings").get() as { n: number }).n).toBe(0);
      expect(f.wire.length).toBe(wire);
      const notices = f.ca.notifications();
      expect(notices).toHaveLength(1);
      expect(notices[0]!.category).toBe("REGRESSION");
      expect(notices[0]!.severity).toBe("WARNING");
      f.control.actorValues = {};
      const repaired = await f.acquire(),
        healthy = await f.ca.runNow(p.assurancePolicyId, "operator", repaired.revision.revisionId);
      expect(healthy.gateStatus).toBe("PASSED");
      expect(f.ca.notifications()[0]!.acknowledgedAt).toBeNull();
      f.ca.acknowledge(String(notices[0]!.id), "operator");
      expect(f.states.assessment(f.org, result.id).outcome).toBe("DRIFT");
      const stale = await f.ca.runNow(p.assurancePolicyId, "operator", later.revision.revisionId);
      expect(stale.gateStatus).toBe("INCONCLUSIVE");
      expect((stale.safeSummary as { quiet: boolean }).quiet).toBe(false);
      f.receipt("OBSERVED_STATE_PINNED_RETEST_AND_STALE_SELECTION", { app, p, run, result, healthy, stale });
    } finally {
      await f.close();
    }
  });
}

for (const app of ["procurement", "membership"] as const)
  it("alerts real role-access regression without manufacturing a finding on " + app, async () => {
    const f = await observedStateRegressionFixture(app);
    try {
      const p = await f.prepare();
      f.setAccessRegression();
      const later = await f.acquire(),
        wire = f.wire.length,
        run = await f.ca.runNow(p.assurancePolicyId, "operator", later.revision.revisionId),
        result = f.states.assessment(
          f.org,
          (run.safeSummary as { observationAssessmentId: string }).observationAssessmentId
        );
      f.receipt("OBSERVED_STATE_REAL_ROLE_ACCESS_DRIFT", { app, p, run, result });
      expect(run.gateStatus).toBe("REGRESSION");
      expect(
        result.cells.some(
          (c) => c.expectedDecision === "DENY" && c.observedDecision === "ALLOWED" && c.outcome === "DRIFT"
        )
      ).toBe(true);
      expect(result.confirmedVulnerability).toBe(false);
      expect((f.database.db.prepare("SELECT COUNT(*) n FROM findings").get() as { n: number }).n).toBe(0);
      expect(f.wire.length).toBe(wire);
    } finally {
      await f.close();
    }
  });
