import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { AuthorizationWorkbenchInput } from "../contracts/AuthorizationWorkbenchContracts.js";
import { hypothesisProposal } from "./ApplicationHypothesisBinding.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
/** Historical evidence context, not fresh dispatch authority. Immutable decision
 * and proposal custody are checked without rewriting prior outcomes on later drift. */
export function transitionAssessmentContext(db: DashboardDatabase, org: string, input: AuthorizationWorkbenchInput) {
  if (!input.hypothesisReviewId) return null;
  const d = db.db
    .prepare(
      "SELECT d.* FROM application_hypothesis_decisions d JOIN application_hypothesis_proposals p ON p.id=d.proposal_id WHERE d.id=? AND p.organization_id=?"
    )
    .get(input.hypothesisReviewId, org) as Record<string, string> | undefined;
  if (!d || d.action !== "REVIEW") throw Error("WORKBENCH_HYPOTHESIS_REVIEW_NOT_FOUND");
  const p = hypothesisProposal(db, org, d.proposal_id!),
    t = p.snapshot.transition;
  if (!t) return null;
  const receipt = JSON.parse(d.receipt_json!);
  if (
    receipt.transitionDigest !== adaptiveDigest(t) ||
    !receipt.transitionReview?.authorityConfirmed ||
    receipt.transitionReview.authorityKeySha256 !== t.declaration.authorityKeySha256 ||
    d.policy_digest !== adaptiveDigest(input.expectations)
  )
    throw Error("WORKBENCH_RESULT_TRANSITION_CUSTODY_INVALID");
  return {
    version: t.version as string,
    eventId: t.declaration.event.eventId as string,
    beforeMapRevisionId: t.beforeSource.mapRevisionId as string,
    beforeScanId: t.beforeSource.sourceScanId as string,
    afterScanId: t.afterSource.sourceScanId as string,
    proposalId: p.row.id!,
    purpose: t.declaration.purpose as string,
    statePath: t.declaration.event.statePath as string,
    beforeState: t.declaration.event.beforeState as string | number,
    afterState: t.declaration.event.afterState as string | number,
    fromRevision: t.declaration.event.fromRevision as number,
    toRevision: t.declaration.event.toRevision as number,
    afterMapRevisionId: t.afterSource.mapRevisionId as string,
    beforeSourceHash: t.beforeSource.sourceHash as string,
    afterSourceHash: t.afterSource.sourceHash as string,
    authorityKeySha256: t.declaration.authorityKeySha256 as string,
    declaredPolicy: t.declaration.policy as string,
    reviewDecisionId: d.id!,
    nativeProofScope: "POSTCONDITION_ROLE_ACCESS_ONLY" as const,
    stateChangeAuthorizationAssessment: "NOT_TESTED" as const,
    requiresHumanReview: true as const,
    causalProof: false as const,
    stateChangingExecution: "HOLD" as const
  };
}
