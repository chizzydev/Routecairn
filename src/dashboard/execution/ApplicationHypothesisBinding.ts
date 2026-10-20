import { BUSINESS_RELATIONSHIP_VERSION, buildBusinessRelationships } from "./BusinessRelationshipEvidence.js";
import { TRANSITION_VERSION, buildTransitionEvidence } from "./ApplicationTransitionEvidence.js";
import { DIFFERENTIAL_VERSION } from "./ApplicationDifferentialEvidence.js";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { AuthorizationWorkbenchInput } from "../contracts/AuthorizationWorkbenchContracts.js";
import { mappingObservation } from "./ApplicationMappingEvidence.js";
import { mappingContext } from "./ApplicationMappingBinding.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { HYPOTHESIS_ALGORITHM } from "./ApplicationSecurityHypotheses.js";
export function hypothesisSource(db: DashboardDatabase, org: string, id: string) {
  const o = mappingObservation(db, org, id),
    current = mappingContext(db, org, o.input.targetId, Object.values(o.input.credentials));
  if (current.digest !== o.row.context_digest) throw Error("WORKBENCH_HYPOTHESIS_AUTHORITY_CHANGED");
  const request = JSON.parse(o.row.request_json!);
  if (
    adaptiveDigest({
      input: o.input,
      contextDigest: o.row.context_digest,
      request,
      previewIdentity: o.row.preview_identity
    }) !== o.row.digest
  )
    throw Error("WORKBENCH_HYPOTHESIS_MAP_CUSTODY_INVALID");
  return {
    ...o,
    contextDigest: current.digest,
    sourceBinding: {
      organizationId: org,
      targetId: o.input.targetId,
      mapRevisionId: id,
      mapDigest: o.row.digest!,
      sourceScanId: o.scanId ?? null,
      sourceHash: o.sourceHash ?? null,
      status: o.status,
      contextDigest: current.digest
    }
  };
}
export function hypothesisProposal(db: DashboardDatabase, org: string, id: string) {
  const row = db.db
    .prepare("SELECT * FROM application_hypothesis_proposals WHERE id=? AND organization_id=?")
    .get(id, org) as Record<string, string> | undefined;
  if (!row) throw Error("WORKBENCH_HYPOTHESIS_NOT_FOUND");
  const snapshot = JSON.parse(row.snapshot_json!);
  if (adaptiveDigest(snapshot) !== row.digest) throw Error("WORKBENCH_HYPOTHESIS_CUSTODY_INVALID");
  return { row, snapshot };
}
export function freshHypothesisProposal(db: DashboardDatabase, org: string, id: string) {
  const p = hypothesisProposal(db, org, id);
  if (p.snapshot.algorithm !== HYPOTHESIS_ALGORITHM) throw Error("WORKBENCH_HYPOTHESIS_ALGORITHM_CHANGED");
  if (db.db.prepare("SELECT 1 FROM application_hypothesis_proposals WHERE supersedes=?").get(id))
    throw Error("WORKBENCH_HYPOTHESIS_SUPERSEDED");
  if (p.snapshot.flow && p.snapshot.flow.version !== DIFFERENTIAL_VERSION)
    throw Error("WORKBENCH_FLOW_ALGORITHM_CHANGED");
  const source = hypothesisSource(db, org, p.row.map_revision_id!);
  if (adaptiveDigest(source.sourceBinding) !== adaptiveDigest(p.snapshot.source))
    throw Error("WORKBENCH_HYPOTHESIS_SOURCE_CHANGED");
  if (
    p.snapshot.relationships &&
    (p.snapshot.relationships.version !== BUSINESS_RELATIONSHIP_VERSION ||
      !p.snapshot.relationshipWorkflow ||
      adaptiveDigest(buildBusinessRelationships(source, p.snapshot.relationshipWorkflow)) !==
        adaptiveDigest(p.snapshot.relationships))
  )
    throw Error("WORKBENCH_RELATIONSHIP_SOURCE_CHANGED");
  if (p.snapshot.transition) {
    const saved = p.snapshot.transition;
    if (saved.version !== TRANSITION_VERSION) throw Error("WORKBENCH_TRANSITION_ALGORITHM_CHANGED");
    const before = hypothesisSource(db, org, saved.declaration.beforeMapRevisionId);
    if (adaptiveDigest(buildTransitionEvidence(before, source, saved.declaration)) !== adaptiveDigest(saved))
      throw Error("WORKBENCH_TRANSITION_SOURCE_CHANGED");
  }
  return { ...p, source };
}
export function assertHypothesisReviewBinding(
  db: DashboardDatabase,
  org: string,
  input: AuthorizationWorkbenchInput,
  operator?: string
) {
  if (!input.hypothesisReviewId) return;
  const decision = db.db
    .prepare(
      "SELECT d.*,p.organization_id FROM application_hypothesis_decisions d JOIN application_hypothesis_proposals p ON p.id=d.proposal_id WHERE d.id=? AND p.organization_id=?"
    )
    .get(input.hypothesisReviewId, org) as Record<string, string> | undefined;
  if (!decision || decision.action !== "REVIEW" || (operator && decision.created_by !== operator))
    throw Error("WORKBENCH_HYPOTHESIS_REVIEW_NOT_FOUND");
  const p = freshHypothesisProposal(db, org, decision.proposal_id!);
  if (p.snapshot.relationships) {
    const receipt = JSON.parse(decision.receipt_json!);
    if (
      receipt.relationshipDigest !== adaptiveDigest(p.snapshot.relationships) ||
      p.snapshot.relationships.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW"
    )
      throw Error("WORKBENCH_RELATIONSHIP_REVIEW_CUSTODY_INVALID");
  }
  if (p.snapshot.transition) {
    const receipt = JSON.parse(decision.receipt_json!);
    if (
      receipt.transitionDigest !== adaptiveDigest(p.snapshot.transition) ||
      !receipt.transitionReview?.authorityConfirmed
    )
      throw Error("WORKBENCH_TRANSITION_REVIEW_CUSTODY_INVALID");
  }
  if (p.snapshot.flow && p.snapshot.flow.version !== DIFFERENTIAL_VERSION)
    throw Error("WORKBENCH_FLOW_ALGORITHM_CHANGED");
  if (
    input.mappingAcquisitionId !== p.source.row.id ||
    input.targetId !== p.source.input.targetId ||
    input.sourceScanId !== p.source.scanId ||
    adaptiveDigest(input.credentials) !== adaptiveDigest(p.source.input.credentials) ||
    adaptiveDigest(input.expectations) !== decision.policy_digest
  )
    throw Error("WORKBENCH_HYPOTHESIS_POLICY_OR_SOURCE_CHANGED");
}
