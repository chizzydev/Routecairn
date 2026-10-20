import { randomUUID, createHash } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { ContinuousAssurancePolicyInput } from "../contracts/ContinuousAssuranceSchemas.js";
import { ObservedStateRegressionService } from "./ObservedStateRegressionService.js";
/** Same durable CA runs/notifications, with a deliberately non-transmitting lane.
 * Assessment and terminal gate commit together; no worker dispatch or replay. */
export function recordObservedStateAssurance(
  db: DashboardDatabase,
  policy: { id: string; target_id: string; active_version_id: string | null },
  input: ContinuousAssurancePolicyInput,
  installationId: string,
  trigger: "MANUAL" | "SCHEDULE" | "DEPLOYMENT",
  actor: string,
  cleanupRequired: number,
  requestedMapId?: string,
  reference?: string,
  buildFingerprint?: string
) {
  return db.transaction(() => {
    const live = db.db
      .prepare("SELECT status,active_version_id FROM continuous_assurance_policies WHERE id=? AND deleted_at IS NULL")
      .get(policy.id) as { status: string; active_version_id: string | null };
    if (!live || live.status !== "ACTIVE" || live.active_version_id !== policy.active_version_id)
      throw Error("CONTINUOUS_ASSURANCE_POLICY_DRIFT");
    if (
      db.db
        .prepare(
          "SELECT 1 FROM continuous_assurance_runs WHERE policy_id=? AND (status IN ('LAUNCHING','RUNNING') OR json_extract(safe_summary_json,'$.launchOutcome')='UNKNOWN')"
        )
        .get(policy.id)
    )
      throw Error("CONTINUOUS_ASSURANCE_RUN_ALREADY_ACTIVE");
    if (
      db.db
        .prepare(
          "SELECT 1 FROM continuous_assurance_deployments WHERE policy_id=? AND run_id IS NULL AND deployment_id<>?"
        )
        .get(policy.id, trigger === "DEPLOYMENT" ? (reference ?? "") : "")
    )
      throw Error("CONTINUOUS_ASSURANCE_DEPLOYMENT_OUTCOME_UNKNOWN");
    const target = db.db
      .prepare("SELECT organization_id,row_version FROM targets WHERE id=? AND archived_at IS NULL")
      .get(policy.target_id) as { organization_id: string; row_version: number } | undefined;
    if (!target) throw Error("CONTINUOUS_ASSURANCE_TARGET_NOT_FOUND");
    const observations = new ObservedStateRegressionService(db),
      baseline = observations.row(target.organization_id, input.observedStatePolicyVersionId!);
    if (baseline.target_id !== policy.target_id) throw Error("OBSERVED_STATE_TARGET_MISMATCH");
    const now = new Date().toISOString(),
      id = randomUUID();
    const version = db.db
      .prepare(
        "SELECT policy_digest,policy_json,status,target_row_version FROM continuous_assurance_policy_versions WHERE id=? AND policy_id=?"
      )
      .get(live.active_version_id, policy.id) as {
      policy_digest: string;
      policy_json: string;
      status: string;
      target_row_version: number;
    };
    if (version.status !== "REVIEWED") throw Error("CONTINUOUS_ASSURANCE_REVIEWED_VERSION_REQUIRED");
    const reviewed = observations.get(target.organization_id, baseline.id);
    const binding = {
      input,
      target: {
        id: policy.target_id,
        origin: new URL(reviewed.snapshot.expectations.expectations[0]!.url!).origin,
        rowVersion: version.target_row_version
      },
      adapterBindings: [],
      observedStateBinding: { versionId: reviewed.id, digest: reviewed.digest, algorithm: reviewed.snapshot.algorithm }
    };
    const sort = (v: unknown): unknown =>
      Array.isArray(v)
        ? v.map(sort)
        : v && typeof v === "object"
          ? Object.fromEntries(
              Object.entries(v)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([k, n]) => [k, sort(n)])
            )
          : v;
    if (
      createHash("sha256")
        .update(JSON.stringify(sort(binding)))
        .digest("hex") !== version.policy_digest
    )
      throw Error("CONTINUOUS_ASSURANCE_REVIEW_CUSTODY_INVALID");
    db.db
      .prepare(
        "INSERT INTO continuous_assurance_runs(id,policy_id,version_id,policy_digest,trigger_type,trigger_reference,build_fingerprint,status,gate_status,requested_by,installation_id,created_at,started_at) VALUES(?,?,?,?,?,?,?,'RUNNING','PENDING',?,?,?,?)"
      )
      .run(
        id,
        policy.id,
        live.active_version_id,
        version.policy_digest,
        trigger,
        reference ?? null,
        buildFingerprint ?? null,
        actor,
        installationId,
        now,
        now
      );
    if (trigger === "DEPLOYMENT") {
      const r = db.db
        .prepare(
          "UPDATE continuous_assurance_deployments SET run_id=? WHERE policy_id=? AND deployment_id=? AND build_fingerprint=? AND run_id IS NULL"
        )
        .run(id, policy.id, reference, buildFingerprint);
      if (r.changes !== 1) throw Error("CONTINUOUS_ASSURANCE_DEPLOYMENT_OUTCOME_UNKNOWN");
    }
    const latest = db.db
      .prepare(
        "SELECT id FROM application_mapping_revisions WHERE organization_id=? AND target_id=? AND version>(SELECT version FROM application_mapping_revisions WHERE id=?) ORDER BY version DESC LIMIT 1"
      )
      .get(target.organization_id, policy.target_id, baseline.baseline_map_revision_id) as { id: string } | undefined;
    const valid =
      Date.parse(input.authorization.validFrom) <= Date.now() && Date.parse(input.authorization.expiresAt) > Date.now();
    const assessment = observations.assess(
      target.organization_id,
      baseline.id,
      requestedMapId ?? latest?.id,
      id,
      valid,
      target.row_version !== version.target_row_version
        ? "CA_TARGET_BINDING_CHANGED"
        : requestedMapId && requestedMapId !== latest?.id
          ? "NEWEST_NATIVE_OBSERVATION_REQUIRED"
          : undefined
    );
    const gate = cleanupRequired
      ? "BLOCKED"
      : assessment.outcome === "DRIFT"
        ? "REGRESSION"
        : assessment.outcome === "MATCHED"
          ? "PASSED"
          : "INCONCLUSIVE";
    const summary = {
      scope: "OBSERVED_STATE_POLICY_ONLY",
      observationAssessmentId: assessment.id,
      observationOutcome: assessment.outcome,
      policyVersionId: baseline.id,
      counts: assessment.summary,
      quiet: gate === "PASSED",
      requiresHumanReview: gate !== "PASSED",
      stateChangeAuthorizationAssessment: "NOT_TESTED",
      verifiedApplicationPass: false,
      confirmedVulnerability: false,
      targetRequests: 0,
      dispatchNotAttempted: true,
      automaticReplay: false,
      quarantineUnchanged: true,
      unresolvedCleanup: cleanupRequired
    };
    const category = cleanupRequired
      ? "CLEANUP_REQUIRED"
      : assessment.outcome === "DRIFT"
        ? "REGRESSION"
        : assessment.outcome === "INCONCLUSIVE"
          ? "APPROVAL_REQUIRED"
          : undefined;
    db.db
      .prepare(
        "UPDATE continuous_assurance_runs SET status='COMPLETED',gate_status=?,safe_summary_json=?,comparison_ids_json=?,notification_required=?,completed_at=? WHERE id=?"
      )
      .run(
        gate,
        JSON.stringify(summary),
        JSON.stringify(assessment.comparisonId ? [assessment.comparisonId] : []),
        category ? 1 : 0,
        new Date().toISOString(),
        id
      );
    if (category)
      db.db
        .prepare(
          "INSERT INTO continuous_assurance_notifications(id,run_id,category,severity,safe_summary,created_at) VALUES(?,?,?,?,?,?)"
        )
        .run(
          randomUUID(),
          id,
          category,
          cleanupRequired ? "CRITICAL" : "WARNING",
          cleanupRequired
            ? "Observed-state analysis cannot clear unresolved cleanup. Explicit recovery review remains required."
            : assessment.outcome === "DRIFT"
              ? "Reviewed observed-state policy drift. Inspect actor-specific retained evidence; this is not a confirmed vulnerability or transition authorization test."
              : "Observed-state comparison INCONCLUSIVE. Missing, stale, incompatible or untrusted evidence requires review; no healthy outcome or replay is inferred.",
          now
        );
    db.db
      .prepare("UPDATE continuous_assurance_policies SET last_run_at=?,next_due_at=?,updated_at=? WHERE id=?")
      .run(
        now,
        input.triggers.scheduleEnabled
          ? new Date(Date.now() + input.triggers.intervalMinutes * 60_000).toISOString()
          : null,
        now,
        policy.id
      );
    return id;
  });
}
