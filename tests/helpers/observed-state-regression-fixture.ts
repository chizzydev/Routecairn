import { createHash } from "node:crypto";
import { join } from "node:path";
import { writeFileSync } from "node:fs";
import { transitionApplicationFixture } from "./transition-application-fixture.js";
import { ContinuousAssuranceService } from "../../src/dashboard/execution/ContinuousAssuranceService.js";
import { EvidenceGovernanceService } from "../../src/dashboard/execution/EvidenceGovernanceService.js";
import { ScanComparisonService } from "../../src/dashboard/comparisons/ScanComparisonService.js";
import { ObservedStateRegressionService } from "../../src/dashboard/execution/ObservedStateRegressionService.js";
export async function observedStateRegressionFixture(app: "procurement" | "membership") {
  const f = await transitionApplicationFixture(app);
  f.setFixed();
  writeFileSync(
    join(f.root, "OBSERVED_STATE_SCENARIO_TRUTH.json"),
    JSON.stringify({
      app,
      policy: "Declared exact typed actor/role/tenant/object/state/revision expectations; no causal claim",
      baselineAccess: "fixed",
      purpose:
        "Owned fixture transitions performed outside product dispatch; regression analysis itself sends zero target requests",
      expectedStateChangeAuthorization: "NOT_TESTED",
      expectationsNotBlinded: true
    }),
    { flag: "wx" }
  );
  const evidence = new EvidenceGovernanceService(f.database, f.paths, { bytes: f.key, version: "owned-fixture-v1" }),
    states = new ObservedStateRegressionService(f.database);
  const adapters = {
    materialize() {
      throw Error("OBSERVED_STATE_MUST_NOT_MATERIALIZE_ADAPTER");
    },
    materializeScanRequest() {
      throw Error("OBSERVED_STATE_MUST_NOT_MATERIALIZE_REQUEST");
    },
    async assertExecutionBinding() {
      throw Error("OBSERVED_STATE_MUST_NOT_ASSERT_ADAPTER");
    },
    bindScan() {
      throw Error("OBSERVED_STATE_MUST_NOT_BIND_SCAN");
    }
  };
  const ca = new ContinuousAssuranceService(
    f.database,
    f.paths,
    f.execution,
    adapters,
    new ScanComparisonService(f.database),
    evidence,
    { startTimers: false }
  );
  const prepare = async () => {
    const before = await f.acquire(),
      event = await f.apply(app === "procurement" ? "account-a" : "account-b"),
      after = await f.acquire();
    const proposal = f.hypotheses.generate(
      f.org,
      {
        mapRevisionId: after.revision.revisionId,
        workflow: f.workflow,
        transition: f.declaration(before.revision.revisionId, event)
      },
      "operator"
    );
    const decision = await f.hypotheses.decide(f.org, proposal.proposalId, f.transitionReviewFor(proposal), "operator");
    if (!decision.matrix) throw Error("Owned reviewed matrix required");
    const draft = states.create(
      f.org,
      {
        name: app + " reviewed observed-state policy",
        purpose: "Track exactly reviewed role and business-state expectations without transition execution",
        matrixRevisionId: decision.matrix.revisionId,
        maximumObservationAgeMinutes: 60,
        revisionPaths: f.workflow.routeIds.map((routeId) => ({ routeId, path: "record.revision" }))
      },
      "operator"
    );
    const policy = states.decide(
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
    const input = {
      schemaVersion: 1 as const,
      name: app + " observed-state assurance",
      targetId: f.targetId,
      authorization: {
        proofReference: "fixture://owned-observation-only/" + app,
        proofDigest: createHash("sha256")
          .update("owned-" + app)
          .digest("hex"),
        validFrom: new Date(Date.now() - 60000).toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString()
      },
      triggers: { scheduleEnabled: false, intervalMinutes: 15, deploymentEnabled: true, quietWhenHealthy: true },
      observedStatePolicyVersionId: policy.id,
      adapterProfileIds: [],
      baselines: [],
      requiredCases: [],
      gates: {
        failOnRegression: true,
        failOnNewFinding: true,
        failOnOpenDrift: true,
        requireExactCases: true,
        requireCleanupResolved: true
      },
      evidence: { retentionDays: 90, autoExportOn: [], preserveFailures: true, preserveCleanupEvidence: true }
    };
    const created = await ca.create(input, "operator"),
      createdPolicy = created.policy as { id: string; pendingVersionId: string };
    const preview = await ca.preview(input);
    await ca.review(createdPolicy.id, createdPolicy.pendingVersionId, preview.policyDigest, "operator");
    return { before, event, after, proposal, decision, policy, assurancePolicyId: createdPolicy.id, input };
  };
  const receipt = (label: string, data: unknown) =>
    writeFileSync(
      join(f.root, label + ".json"),
      JSON.stringify(
        {
          data,
          policies: f.database.db.prepare("SELECT * FROM application_observation_policy_versions").all(),
          decisions: f.database.db.prepare("SELECT * FROM application_observation_policy_decisions").all(),
          assessments: f.database.db.prepare("SELECT * FROM application_observation_assessments").all(),
          runs: f.database.db.prepare("SELECT * FROM continuous_assurance_runs").all(),
          notifications: f.database.db.prepare("SELECT * FROM continuous_assurance_notifications").all(),
          comparisons: f.database.db
            .prepare("SELECT id,state,compatibility_state,summary_json FROM scan_comparisons")
            .all(),
          wire: f.wire,
          integrity: f.database.db.pragma("integrity_check"),
          foreignKeys: f.database.db.pragma("foreign_key_check")
        },
        null,
        2
      ),
      { flag: "wx" }
    );
  return {
    ...f,
    ca,
    states,
    evidence,
    prepare,
    receipt,
    async close() {
      ca.shutdown();
      await f.close();
    }
  };
}
