import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import {
  observedStateDraftSchema,
  observedStateDecisionSchema,
  type ObservedStateDraft,
  type ObservedStateOutcome
} from "../contracts/ObservedStateContracts.js";
import {
  authorizationWorkbenchInputSchema,
  type AuthorizationWorkbenchInput
} from "../contracts/AuthorizationWorkbenchContracts.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import {
  assertHypothesisReviewBinding,
  freshHypothesisProposal,
  hypothesisSource
} from "./ApplicationHypothesisBinding.js";
import { observedMarkerFingerprint } from "../../modules/apiGraphql/ObservedMarker.js";
import { OBSERVATION_ALGORITHM, readActorObservation } from "./ObservedActorEvidence.js";
import { ScanComparisonService } from "../comparisons/ScanComparisonService.js";
import { assertAssuranceComparison, ComparisonIntegrityError } from "../comparisons/ComparisonIntegrity.js";
type Source = ReturnType<typeof hypothesisSource>;
type PolicyRow = {
  id: string;
  organization_id: string;
  target_id: string;
  lineage_id: string;
  revision: number;
  matrix_revision_id: string;
  baseline_map_revision_id: string;
  baseline_scan_id: string;
  supersedes: string | null;
  digest: string;
  snapshot_json: string;
  created_by: string;
  created_at: string;
};
type Cell = {
  routeId: string;
  actorId: string;
  expectedDecision: string;
  observedDecision: string;
  outcome: ObservedStateOutcome;
  reasons: string[];
  expectedMarkers: Array<{ path: string; scalarType: string; fingerprint: string }>;
  observedMarkers: Array<{ path: string; scalarType: string; valueFingerprint: string }>;
  stateAssessment: string;
  checkId: string;
  actorBindingFingerprint: string;
};
const actors = ["primary", "account-a", "account-b", "anonymous"] as const;
export const OBSERVED_STATE_POLICY_ALGORITHM = "reviewed-observed-state-regression-v1/" + OBSERVATION_ALGORITHM;
const scope = {
  proofScope: "OBSERVED_STATE_AND_ACCESS_POLICY_ONLY",
  stateChangeAuthorizationAssessment: "NOT_TESTED",
  causalProof: false,
  confirmedVulnerability: false,
  verifiedApplicationPass: false,
  executionAuthority: "NONE",
  stateChangingExecution: "HOLD",
  automaticReplay: false
} as const;
type PolicySnapshot = {
  algorithm: string;
  input: ObservedStateDraft;
  matrixDigest: string;
  expectations: AuthorizationWorkbenchInput;
  source: Source["sourceBinding"];
  sourceCompletedAt: string;
  actorBindings: Record<string, string>;
  authority: {
    reviewDecisionId: string;
    proposalId: string;
    transitionDigest: string;
    authorityKeySha256: string;
    eventId: string;
    confirmedBy: string;
    confirmedAt: string;
  };
} & typeof scope;
/** A policy on retained native observations. Never queues scans or transmissions. */
export class ObservedStateRegressionService {
  constructor(private readonly db: DashboardDatabase) {}
  private build(
    org: string,
    value: unknown,
    freshBaseline = true
  ): { snapshot: PolicySnapshot; digest: string; cells: Cell[] } {
    const input = observedStateDraftSchema.parse(value);
    const matrix = this.db.db
      .prepare("SELECT * FROM authorization_workbench_revisions WHERE id=? AND organization_id=?")
      .get(input.matrixRevisionId, org) as Record<string, string> | undefined;
    if (!matrix) throw Error("OBSERVED_STATE_MATRIX_NOT_FOUND");
    const expectations = authorizationWorkbenchInputSchema.parse(JSON.parse(matrix.input_json!));
    if (!expectations.mappingAcquisitionId || !expectations.hypothesisReviewId)
      throw Error("OBSERVED_STATE_REVIEWED_MAPPING_REQUIRED");
    assertHypothesisReviewBinding(this.db, org, expectations);
    const decision = this.db.db
      .prepare("SELECT * FROM application_hypothesis_decisions WHERE id=?")
      .get(expectations.hypothesisReviewId) as Record<string, string>;
    const proposal = freshHypothesisProposal(this.db, org, decision.proposal_id!);
    if (!proposal.snapshot.transition) throw Error("OBSERVED_STATE_REVIEWED_AUTHORITY_REQUIRED");
    const receipt = JSON.parse(decision.receipt_json!);
    if (
      !receipt.transitionReview?.authorityConfirmed ||
      receipt.transitionReview.authorityKeySha256 !== proposal.snapshot.transition.declaration.authorityKeySha256
    )
      throw Error("OBSERVED_STATE_AUTHORITY_CUSTODY_INVALID");
    const source = hypothesisSource(this.db, org, expectations.mappingAcquisitionId);
    if (!source.report || source.status !== "COMPLETED" || !source.sourceHash)
      throw Error("OBSERVED_STATE_COMPLETE_BASELINE_REQUIRED");
    if (
      freshBaseline &&
      Date.now() - Date.parse(source.report.metadata.completedAt) > input.maximumObservationAgeMinutes * 60_000
    )
      throw Error("OBSERVED_STATE_STALE_BASELINE");
    if (
      input.revisionPaths.length !== expectations.expectations.length ||
      new Set(input.revisionPaths.map((r) => r.routeId)).size !== input.revisionPaths.length
    )
      throw Error("OBSERVED_STATE_EXACT_REVISION_PATHS_REQUIRED");
    for (const e of expectations.expectations) {
      const revision = input.revisionPaths.find((r) => r.routeId === e.routeId),
        marker = e.states?.find((m) => m.path === revision?.path);
      if (
        !e.identity ||
        !e.tenant ||
        !e.states?.length ||
        e.decisions.primary !== "ALLOW" ||
        actors.some((a) => !["ALLOW", "DENY"].includes(e.decisions[a] ?? "")) ||
        !marker ||
        typeof marker.expectedValue !== "number" ||
        !Number.isSafeInteger(marker.expectedValue) ||
        marker.expectedValue < 0
      )
        throw Error("OBSERVED_STATE_EXACT_OBJECT_TENANT_STATE_REVISION_REQUIRED");
    }
    const bindings = Object.fromEntries(
      actors.map((a) => [a, readActorObservation(source, expectations.expectations[0]!.routeId, a).bindingFingerprint])
    );
    const snapshot = {
      algorithm: OBSERVED_STATE_POLICY_ALGORITHM,
      input,
      matrixDigest: matrix.digest!,
      expectations,
      source: source.sourceBinding,
      sourceCompletedAt: source.report.metadata.completedAt,
      actorBindings: bindings,
      authority: {
        reviewDecisionId: decision.id!,
        proposalId: proposal.row.id!,
        transitionDigest: adaptiveDigest(proposal.snapshot.transition),
        authorityKeySha256: receipt.transitionReview.authorityKeySha256,
        eventId: proposal.snapshot.transition.declaration.event.eventId,
        confirmedBy: decision.created_by!,
        confirmedAt: decision.created_at!
      },
      ...scope
    };
    const cells = this.cells(source, snapshot);
    if (cells.some((c) => c.outcome !== "MATCHED")) throw Error("OBSERVED_STATE_HEALTHY_NATIVE_BASELINE_REQUIRED");
    return { snapshot, digest: adaptiveDigest(snapshot), cells };
  }
  public preview(org: string, value: unknown) {
    return this.build(org, value);
  }
  public assertApproved(org: string, id: string) {
    const p = this.get(org, id);
    if (p.status !== "APPROVED") throw Error("OBSERVED_STATE_APPROVED_POLICY_REQUIRED");
    if (this.build(org, p.snapshot.input, false).digest !== p.digest)
      throw Error("OBSERVED_STATE_POLICY_SEMANTICS_CHANGED");
    return p;
  }
  public create(org: string, value: unknown, actor: string) {
    return this.db.transaction(() => {
      const p = this.build(org, value),
        id = randomUUID(),
        now = new Date().toISOString();
      let lineage: string = id,
        revision = 1;
      if (p.snapshot.input.supersedes) {
        const old = this.row(org, p.snapshot.input.supersedes);
        if (old.target_id !== p.snapshot.expectations.targetId) throw Error("OBSERVED_STATE_TARGET_IMMUTABLE");
        lineage = old.lineage_id;
        revision = old.revision + 1;
      }
      this.db.db
        .prepare("INSERT INTO application_observation_policy_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .run(
          id,
          org,
          p.snapshot.expectations.targetId,
          lineage,
          revision,
          p.snapshot.input.matrixRevisionId,
          p.snapshot.source.mapRevisionId,
          p.snapshot.source.sourceScanId,
          p.snapshot.input.supersedes ?? null,
          p.digest,
          JSON.stringify(p.snapshot),
          actor,
          now
        );
      return this.get(org, id);
    });
  }
  public row(org: string, id: string) {
    const r = this.db.db
      .prepare("SELECT * FROM application_observation_policy_versions WHERE id=? AND organization_id=?")
      .get(id, org) as PolicyRow | undefined;
    if (!r) throw Error("OBSERVED_STATE_POLICY_NOT_FOUND");
    return r;
  }
  public get(org: string, id: string) {
    const row = this.row(org, id),
      snapshot = JSON.parse(row.snapshot_json) as ReturnType<ObservedStateRegressionService["build"]>["snapshot"];
    if (adaptiveDigest(snapshot) !== row.digest) throw Error("OBSERVED_STATE_POLICY_CUSTODY_INVALID");
    const decisions = this.db.db
      .prepare(
        "SELECT id,action,receipt_json,created_by,created_at FROM application_observation_policy_decisions WHERE version_id=? ORDER BY created_at,id"
      )
      .all(id) as Array<{ id: string; action: string; receipt_json: string; created_by: string; created_at: string }>;
    const approved = decisions.find((d) => d.action === "APPROVE"),
      revoked = decisions.some((d) => d.action === "REVOKE"),
      superseded = !!this.db.db
        .prepare(
          "SELECT 1 FROM application_observation_policy_versions v JOIN application_observation_policy_decisions d ON d.version_id=v.id AND d.action='APPROVE' WHERE v.organization_id=? AND v.target_id=? AND v.lineage_id=? AND v.revision>?"
        )
        .get(org, row.target_id, row.lineage_id, row.revision);
    if (approved) {
      const receipt = JSON.parse(approved.receipt_json);
      if (receipt.digest !== row.digest || receipt.algorithm !== snapshot.algorithm)
        throw Error("OBSERVED_STATE_REVIEW_CUSTODY_INVALID");
    }
    const status = revoked
      ? "REVOKED"
      : superseded
        ? "SUPERSEDED"
        : snapshot.algorithm !== OBSERVED_STATE_POLICY_ALGORITHM
          ? "ALGORITHM_REVIEW_REQUIRED"
          : approved
            ? "APPROVED"
            : "REVIEW_REQUIRED";
    return {
      id: row.id,
      lineageId: row.lineage_id,
      revision: row.revision,
      targetId: row.target_id,
      digest: row.digest,
      status,
      createdBy: row.created_by,
      createdAt: row.created_at,
      snapshot,
      decisions: decisions.map((d) => ({ ...d, receipt: JSON.parse(d.receipt_json), receipt_json: undefined })),
      ...scope
    };
  }
  public list(org: string) {
    return (
      this.db.db
        .prepare(
          "SELECT id FROM application_observation_policy_versions WHERE organization_id=? ORDER BY created_at DESC,id LIMIT 100"
        )
        .all(org) as { id: string }[]
    ).map((r) => this.get(org, r.id));
  }
  public decide(org: string, id: string, value: unknown, actor: string) {
    return this.db.transaction(() => {
      const input = observedStateDecisionSchema.parse(value),
        p = this.get(org, id);
      if (input.digest !== p.digest) throw Error("OBSERVED_STATE_STALE_REVIEW");
      if (input.action === "APPROVE") {
        if (p.status !== "REVIEW_REQUIRED") throw Error("OBSERVED_STATE_DRAFT_REQUIRED");
        const fresh = this.build(org, p.snapshot.input);
        if (fresh.digest !== p.digest) throw Error("OBSERVED_STATE_REVIEW_SOURCE_CHANGED");
      } else if (p.status === "REVOKED") throw Error("OBSERVED_STATE_ALREADY_REVOKED");
      this.db.db
        .prepare("INSERT INTO application_observation_policy_decisions VALUES(?,?,?,?,?,?)")
        .run(
          randomUUID(),
          id,
          input.action,
          JSON.stringify({ ...input, algorithm: p.snapshot.algorithm, ...scope }),
          actor,
          new Date().toISOString()
        );
      return this.get(org, id);
    });
  }
  public cells(source: Source, policy: ReturnType<ObservedStateRegressionService["build"]>["snapshot"]): Cell[] {
    const rows: Cell[] = [];
    for (const e of policy.expectations.expectations) {
      const primary = readActorObservation(source, e.routeId, "primary");
      const matching = (
        ob: ReturnType<typeof readActorObservation>,
        m: { path: string; expectedValue: string | number }
      ) =>
        ob.markers.filter(
          (v) =>
            v.path === m.path &&
            v.scalarType === typeof m.expectedValue &&
            v.valueFingerprint === observedMarkerFingerprint(m.expectedValue)
        ).length === 1;
      const positive =
        primary.bindingValid &&
        primary.request?.decision === "ALLOWED" &&
        !!e.identity &&
        !!e.tenant &&
        matching(primary, e.identity) &&
        matching(primary, e.tenant);
      const revision = policy.input.revisionPaths.find((r) => r.routeId === e.routeId)!;
      for (const actorId of actors) {
        const o = readActorObservation(source, e.routeId, actorId),
          reasons = [...o.missingControls];
        let outcome: ObservedStateOutcome = "MATCHED";
        if (!positive) reasons.push("MISSING_POSITIVE_OBJECT_TENANT_CONTROL");
        if (o.bindingFingerprint !== policy.actorBindings[actorId])
          reasons.push("ACTOR_ROLE_TENANT_CREDENTIAL_CHANGED");
        if (o.request?.decision === "ALLOWED") {
          if (!e.identity || !matching(o, e.identity) || !e.tenant || !matching(o, e.tenant))
            reasons.push("OBJECT_OR_TENANT_NOT_PROVEN");
          for (const m of e.states ?? []) {
            const markers = o.markers.filter((v) => v.path === m.path);
            if (markers.length !== 1 || markers[0]!.scalarType !== typeof m.expectedValue)
              reasons.push("MISSING_OR_CONTRADICTORY_TYPED_STATE:" + m.path);
            else if (!matching(o, m)) {
              if (m.path === revision.path) reasons.push("REVISION_CHANGED_REVIEW_REQUIRED");
              else outcome = "DRIFT";
            }
          }
        }
        if (reasons.length) outcome = "INCONCLUSIVE";
        else if ((e.decisions[actorId] === "ALLOW") !== (o.request?.decision === "ALLOWED")) outcome = "DRIFT";
        const expectedMarkers = [e.identity!, e.tenant!, ...(e.states ?? [])].map((m) => ({
          path: m.path,
          scalarType: typeof m.expectedValue,
          fingerprint: observedMarkerFingerprint(m.expectedValue)
        }));
        rows.push({
          routeId: e.routeId,
          actorId,
          expectedDecision: e.decisions[actorId]!,
          observedDecision: o.request?.decision ?? "UNCLASSIFIED",
          outcome,
          reasons: reasons.length ? reasons : outcome === "DRIFT" ? ["REVIEWED_OBSERVATION_POLICY_DIFFERS"] : [],
          expectedMarkers,
          observedMarkers: [...o.markers],
          stateAssessment:
            o.request?.decision === "DENIED"
              ? "NOT_OBSERVED_DUE_TO_DENIAL"
              : outcome === "MATCHED"
                ? "EXACT_TYPED_STATE_MATCH"
                : outcome,
          checkId: e.routeId + "-observe-" + actorId,
          actorBindingFingerprint: o.bindingFingerprint
        });
      }
    }
    return rows;
  }
  /** Called under the existing CA terminal transaction; no target requests. */
  public assess(
    org: string,
    policyId: string,
    mapId: string | undefined,
    runId: string,
    authorizationValid = true,
    sourceSelectionIssue?: string
  ) {
    const p = this.get(org, policyId),
      reasons: string[] = [];
    let cells: Cell[] = [],
      current: Source | undefined,
      comparisonId: string | undefined;
    let sourceErrorCode: string | null = null;
    if (p.status !== "APPROVED") reasons.push("POLICY_" + p.status);
    if (sourceSelectionIssue) reasons.push(sourceSelectionIssue);
    if (!authorizationValid) reasons.push("AUTHORIZATION_NOT_CURRENT");
    if (!mapId) reasons.push("NO_LATER_NATIVE_OBSERVATION");
    if (mapId) {
      const r = this.db.db
        .prepare("SELECT target_id FROM application_mapping_revisions WHERE id=? AND organization_id=?")
        .get(mapId, org) as { target_id: string } | undefined;
      if (!r || r.target_id !== p.targetId) throw Error("OBSERVED_STATE_SOURCE_NOT_FOUND");
    }
    try {
      if (this.build(org, p.snapshot.input, false).digest !== p.digest)
        reasons.push("REVIEWED_BASELINE_SEMANTICS_CHANGED");
      const base = hypothesisSource(this.db, org, p.snapshot.source.mapRevisionId);
      if (adaptiveDigest(base.sourceBinding) !== adaptiveDigest(p.snapshot.source))
        reasons.push("BASELINE_SOURCE_CHANGED");
      if (mapId) current = hypothesisSource(this.db, org, mapId);
      if (current) {
        if (!current.report || current.status !== "COMPLETED") reasons.push("OBSERVATION_" + current.status);
        else {
          const end = Date.parse(current.report.metadata.completedAt),
            start = Date.parse(current.report.metadata.startedAt);
          if (
            current.row.id === base.row.id ||
            current.scanId === base.scanId ||
            !Number.isFinite(end) ||
            !Number.isFinite(start) ||
            start <= Date.parse(p.snapshot.sourceCompletedAt)
          )
            reasons.push("LATER_INDEPENDENT_OBSERVATION_REQUIRED");
          if (Date.now() - end > p.snapshot.input.maximumObservationAgeMinutes * 60_000 || end > Date.now() + 30_000)
            reasons.push("OBSERVATION_FRESHNESS_UNPROVEN");
          if (
            current.contextDigest !== p.snapshot.source.contextDigest ||
            adaptiveDigest(current.input) !== adaptiveDigest(base.input)
          )
            reasons.push("SOURCE_CONTEXT_NOT_COMPARABLE");
          cells = this.cells(current, p.snapshot);
          if (!reasons.length && base.scanId && current.scanId) {
            try {
              const comparison = new ScanComparisonService(this.db).compare(base.scanId, current.scanId);
              comparisonId = comparison.comparisonId;
              assertAssuranceComparison(comparison, base.scanId, current.scanId, []);
            } catch (error) {
              if (error instanceof ComparisonIntegrityError) comparisonId = error.comparisonId;
              reasons.push("NATIVE_COMPARISON_UNUSABLE");
            }
          }
        }
      }
    } catch (error) {
      sourceErrorCode =
        error instanceof Error && /^(WORKBENCH|OBSERVED_STATE)_[A-Z_]{1,160}$/.test(error.message)
          ? error.message
          : "UNCLASSIFIED_SOURCE_UNAVAILABLE";
      reasons.push("NATIVE_SOURCE_OR_AUTHORITY_UNAVAILABLE");
    }
    const inconclusive = cells.filter((c) => c.outcome === "INCONCLUSIVE").length,
      drift = cells.filter((c) => c.outcome === "DRIFT").length;
    const outcome: ObservedStateOutcome =
      reasons.length || inconclusive || !cells.length ? "INCONCLUSIVE" : drift ? "DRIFT" : "MATCHED";
    const id = randomUUID(),
      now = new Date().toISOString(),
      snapshot = {
        id,
        algorithm: OBSERVED_STATE_POLICY_ALGORITHM,
        policyId: p.id,
        policyDigest: p.digest,
        policyStatus: p.status,
        baselineSource: p.snapshot.source,
        currentSource: current?.sourceBinding ?? null,
        requestedMapRevisionId: mapId ?? null,
        comparisonId: comparisonId ?? null,
        sourceErrorCode,
        outcome,
        reasons: [...new Set(reasons)],
        cells,
        summary: {
          matched: cells.filter((c) => c.outcome === "MATCHED").length,
          drift,
          inconclusive,
          policyChecks: cells.length
        },
        quiet: outcome === "MATCHED",
        requiresHumanReview: outcome !== "MATCHED",
        createdAt: now,
        ...scope
      };
    this.db.db
      .prepare("INSERT INTO application_observation_assessments VALUES(?,?,?,?,?,?,?,?)")
      .run(
        id,
        policyId,
        mapId ?? null,
        current?.scanId ?? null,
        runId,
        adaptiveDigest(snapshot),
        JSON.stringify(snapshot),
        now
      );
    return snapshot;
  }
  public assessment(org: string, id: string) {
    const row = this.db.db
      .prepare(
        "SELECT a.* FROM application_observation_assessments a JOIN application_observation_policy_versions p ON p.id=a.policy_version_id WHERE a.id=? AND p.organization_id=?"
      )
      .get(id, org) as { digest: string; snapshot_json: string } | undefined;
    if (!row) throw Error("OBSERVED_STATE_ASSESSMENT_NOT_FOUND");
    const snapshot = JSON.parse(row.snapshot_json) as ReturnType<ObservedStateRegressionService["assess"]>;
    if (adaptiveDigest(snapshot) !== row.digest) throw Error("OBSERVED_STATE_ASSESSMENT_CUSTODY_INVALID");
    return snapshot;
  }
}
