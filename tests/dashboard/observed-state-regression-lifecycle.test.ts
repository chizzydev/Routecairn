import { it, expect } from "vitest";
import { observedStateRegressionFixture } from "../helpers/observed-state-regression-fixture.js";
it("retains actual cancelled native observation as nonquiet and never falls back to healthy history", async () => {
  const f = await observedStateRegressionFixture("procurement");
  try {
    const p = await f.prepare();
    f.control.delayBusinessResponseMs = 500;
    const revision = await f.mapping.create(f.org, f.mappingInput, "operator"),
      run = await f.mapping.execute(f.org, revision.revisionId, revision.digest, "operator");
    const until = Date.now() + 20000;
    let verified = false;
    while (Date.now() < until) {
      const row = f.database.db
        .prepare("SELECT worker_verified_at FROM scan_executable_plans WHERE scan_id=?")
        .get(run.scanId) as { worker_verified_at: string | null } | undefined;
      if (row?.worker_verified_at && f.wire.length > 2 * (4 + 4 * f.workflow.routeIds.length) + 1) {
        verified = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(verified).toBe(true);
    f.execution.cancel(run.scanId!);
    await expect(f.wait(run.scanId!)).rejects.toThrow(/NATIVE_(CANCELLED|INTERRUPTED)/);
    const wire = f.wire.length,
      result = await f.ca.runNow(p.assurancePolicyId, "operator"),
      a = f.states.assessment(
        f.org,
        (result.safeSummary as { observationAssessmentId: string }).observationAssessmentId
      );
    expect(result.gateStatus).toBe("INCONCLUSIVE");
    expect(a.quiet).toBe(false);
    expect(a.requestedMapRevisionId).toBe(revision.revisionId);
    expect(a.reasons.some((r) => /CANCELLED|INTERRUPTED|UNAVAILABLE/.test(r))).toBe(true);
    expect(f.wire.length).toBe(wire);
    f.receipt("OBSERVED_STATE_NATIVE_CANCELLED_NO_REPLAY", { p, run, result, a });
  } finally {
    await f.close();
  }
});
it("uses existing deployment replay protection and scheduling without observation dispatch", async () => {
  const f = await observedStateRegressionFixture("procurement");
  try {
    const p = await f.prepare(),
      later = await f.acquire(),
      wire = f.wire.length,
      token = f.ca.rotateTriggerToken(p.assurancePolicyId, "operator") as { deploymentTriggerToken: string },
      deployment = await f.ca.deployment(
        p.assurancePolicyId,
        token.deploymentTriggerToken,
        "owned-build-1",
        "a".repeat(64)
      ),
      replay = await f.ca.deployment(
        p.assurancePolicyId,
        token.deploymentTriggerToken,
        "owned-build-1",
        "a".repeat(64)
      );
    expect(replay.runId).toBe(deployment.runId);
    expect(replay.idempotentReplay).toBe(true);
    await expect(
      f.ca.deployment(p.assurancePolicyId, token.deploymentTriggerToken, "owned-build-1", "b".repeat(64))
    ).rejects.toThrow("REPLAY_MISMATCH");
    expect(f.wire.length).toBe(wire);
    expect(
      (f.database.db.prepare("SELECT COUNT(*) n FROM application_observation_assessments").get() as { n: number }).n
    ).toBe(1);
    f.receipt("OBSERVED_STATE_DEPLOYMENT_REPLAY", { p, later, deployment, replay });
    const scheduledInput = { ...p.input, triggers: { ...p.input.triggers, scheduleEnabled: true } },
      updated = await f.ca.update(p.assurancePolicyId, scheduledInput, "operator"),
      scheduledPreview = await f.ca.preview(scheduledInput);
    await f.ca.review(p.assurancePolicyId, String(updated.pendingVersionId), scheduledPreview.policyDigest, "operator");
    f.database.db
      .prepare("UPDATE continuous_assurance_policies SET next_due_at=? WHERE id=?")
      .run(new Date(Date.now() - 1000).toISOString(), p.assurancePolicyId);
    await f.ca.processDueNow();
    expect(
      (
        f.database.db
          .prepare(
            "SELECT COUNT(*) n FROM continuous_assurance_runs WHERE trigger_type='SCHEDULE' AND gate_status='PASSED'"
          )
          .get() as { n: number }
      ).n
    ).toBe(1);
    expect(f.wire.length).toBe(wire);
    f.receipt("OBSERVED_STATE_SCHEDULE_NO_DISPATCH", { scheduledPreview });
    // Retention preview only: never execute purge against evidence, even in fixtures.
    f.database.db
      .prepare("UPDATE artifacts SET created_at='2020-01-01T00:00:00.000Z' WHERE scan_id IN (?,?,?)")
      .run(p.before.run.scanId, p.after.run.scanId, later.run.scanId);
    const preview = f.evidence.purgePreview();
    expect((preview.protectedCounts as { observedState: number }).observedState).toBeGreaterThan(0);
    const scans = new Set([p.before.run.scanId, p.after.run.scanId, later.run.scanId]);
    for (const c of preview.candidates as Array<{ id: string }>) {
      const row = f.database.db.prepare("SELECT scan_id FROM artifacts WHERE id=?").get(c.id) as
        { scan_id: string } | undefined;
      expect(row ? scans.has(row.scan_id) : false).toBe(false);
    }
    f.receipt("OBSERVED_STATE_RETENTION_PREVIEW_ONLY", { preview });
  } finally {
    await f.close();
  }
});
