import { nativeApplicationActorMatches } from "./ApplicationIdentity.js";
import { buildBusinessRelationships } from "./BusinessRelationshipEvidence.js";
import { buildTransitionEvidence } from "./ApplicationTransitionEvidence.js";
import { buildDifferentialEvidence, reviewedDifferentialExpectations } from "./ApplicationDifferentialEvidence.js";
import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { CredentialVault } from "../credentials/CredentialVault.js";
import type { ScanExecutionService } from "./ScanExecutionService.js";
import { hypothesisGenerateSchema, hypothesisDecisionSchema } from "../contracts/ApplicationHypothesisContracts.js";
import { hypothesisSource, hypothesisProposal, freshHypothesisProposal } from "./ApplicationHypothesisBinding.js";
import { ApplicationMappingService } from "./ApplicationMappingService.js";
import { AuthorizationWorkbenchService } from "./AuthorizationWorkbenchService.js";
import { buildApplicationHypotheses, HYPOTHESIS_ALGORITHM } from "./ApplicationSecurityHypotheses.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { observedMarkerFingerprint } from "../../modules/apiGraphql/ObservedMarker.js";
export class ApplicationHypothesisService {
  constructor(
    private readonly db: DashboardDatabase,
    private readonly vault: CredentialVault,
    private readonly execution: ScanExecutionService
  ) {}
  public generate(org: string, value: unknown, actor: string) {
    const input = hypothesisGenerateSchema.parse(value);
    return this.db.db
      .transaction(() => {
        const o = hypothesisSource(this.db, org, input.mapRevisionId),
          map = new ApplicationMappingService(this.db, this.vault, this.execution).result(org, input.mapRevisionId);
        if (input.supersedes) {
          const prior = hypothesisProposal(this.db, org, input.supersedes);
          if (prior.row.target_id !== o.input.targetId)
            throw Error("WORKBENCH_HYPOTHESIS_SUPERSESSION_CONTEXT_REQUIRED");
        }
        // Native role/tenant matches are required, not merely a successful identity HTTP request.
        for (const r of map.observations)
          for (const c of r.cells)
            if (c.actorId !== "anonymous") {
              const v =
                c.actorId === "primary"
                  ? o.report?.identityVerification?.primary
                  : c.actorId === "account-a"
                    ? o.report?.identityVerification?.accountA
                    : o.report?.identityVerification?.accountB;
              const slot = c.actorId.replaceAll("-", "_") as keyof typeof o.input.credentials,
                summary = this.vault.getSummary(o.input.credentials[slot], org)?.safeIdentitySummary,
                planActor = o.report?.scanPlan?.apiGraphql?.actors.find((a) => a.id === c.actorId);
              c.identityVerified =
                c.identityVerified === true &&
                !!summary &&
                nativeApplicationActorMatches(summary, planActor, v) &&
                planActor?.authSlot === slot;
            }
        const candidates = buildApplicationHypotheses(map, org, (id) => {
          const route = o.input.routes.find((r) => r.id === id)!,
            fingerprints =
              o.report?.scanPlan?.apiGraphql?.checks
                .filter((c) => "routeId" in c && c.routeId === id)
                .map((c) => c.comparisonFingerprint) ?? [];
          return (map.provenance?.securityCases.cases ?? [])
            .filter(
              (c) =>
                c.source.engineId === "api-graphql-authorization" &&
                (c.subject.kind === "ROUTE"
                  ? c.subject.pathTemplate === route.pathTemplate
                  : c.provenance.sourceCaseFingerprints?.some((f) => fingerprints.includes(f)) ||
                    c.provenance.graph?.pathIds.some((id) =>
                      map.provenance?.attackGraph?.paths
                        .find((p) => p.id === id)
                        ?.sourceCaseFingerprints.some((f) => fingerprints.includes(f))
                    ))
            )
            .map((c) => c.caseId);
        });
        if (input.transition && (!input.workflow || !input.workflow.routeIds.includes(input.transition.event.routeId)))
          throw Error("WORKBENCH_TRANSITION_ORDERED_FLOW_REQUIRED");
        const transition = input.transition
          ? buildTransitionEvidence(
              hypothesisSource(this.db, org, input.transition.beforeMapRevisionId),
              o,
              input.transition
            )
          : undefined;
        const snapshot = {
            algorithm: HYPOTHESIS_ALGORITHM,
            source: o.sourceBinding,
            candidates,
            supersedes: input.supersedes ?? null,
            ...(input.workflow ? { flow: buildDifferentialEvidence(o.input, candidates, input.workflow) } : {}),
            ...(transition ? { transition } : {}),
            ...(input.workflow?.relationships
              ? { relationships: buildBusinessRelationships(o, input.workflow), relationshipWorkflow: input.workflow }
              : {}),
            findingsInferred: false,
            executionAuthority: "NONE",
            policyAuthority: "HUMAN_DECLARATION_REQUIRED"
          },
          id = randomUUID(),
          digest = adaptiveDigest(snapshot),
          createdAt = new Date().toISOString();
        this.db.db
          .prepare("INSERT INTO application_hypothesis_proposals VALUES(?,?,?,?,?,?,?,?,?,?)")
          .run(
            id,
            org,
            o.input.targetId,
            input.mapRevisionId,
            o.contextDigest,
            digest,
            JSON.stringify(snapshot),
            input.supersedes ?? null,
            actor,
            createdAt
          );
        return { proposalId: id, digest, createdAt, ...snapshot };
      })
      .immediate();
  }
  private async reviewFlow(
    org: string,
    id: string,
    p: ReturnType<typeof freshHypothesisProposal>,
    input: Extract<ReturnType<typeof hypothesisDecisionSchema.parse>, { action: "REVIEW_FLOW" }>,
    actor: string
  ) {
    if (input.candidateId !== p.snapshot.flow?.flowId) throw Error("WORKBENCH_FLOW_REVIEW_ID_REQUIRED");
    if (
      this.db.db
        .prepare("SELECT 1 FROM application_hypothesis_decisions WHERE proposal_id=? AND candidate_id=?")
        .get(id, input.candidateId)
    )
      throw Error("WORKBENCH_HYPOTHESIS_DECISION_ALREADY_RECORDED");
    if (p.snapshot.transition) {
      const t = p.snapshot.transition,
        r = input.transitionReview;
      if (
        t.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW" ||
        !r?.authorityConfirmed ||
        r.authorityKeySha256 !== t.declaration.authorityKeySha256
      )
        throw Error("WORKBENCH_TRANSITION_TRUSTED_AUTHORITY_REVIEW_REQUIRED");
      const expected = p.snapshot.flow.steps
        .flatMap((s: { routeId: string }) =>
          ["primary", "account-a", "account-b", "anonymous"].map((a) => s.routeId + ":" + a)
        )
        .sort();
      const actual = r.checks.map((c) => c.routeId + ":" + c.actorId).sort();
      if (JSON.stringify(actual) !== JSON.stringify(expected))
        throw Error("WORKBENCH_TRANSITION_EXACT_CHECK_PURPOSE_CONSENT_REQUIRED");
    } else if (input.transitionReview) throw Error("WORKBENCH_TRANSITION_UNEXPECTED_REVIEW");
    if (p.snapshot.relationships?.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW" && p.snapshot.relationships)
      throw Error("WORKBENCH_RELATIONSHIP_ABSTAIN");
    const expectations = reviewedDifferentialExpectations(p.snapshot, input.expectations),
      base = {
        targetId: p.source.input.targetId,
        sourceScanId: p.source.scanId,
        mappingAcquisitionId: p.source.row.id,
        credentials: p.source.input.credentials,
        expectations
      };
    const wb = new AuthorizationWorkbenchService(this.db, this.vault, this.execution),
      preview = await wb.preview(org, base);
    if (preview.blockers.length) throw Error("WORKBENCH_FLOW_CONTROLS_INCOMPLETE");
    const fresh = freshHypothesisProposal(this.db, org, id);
    if (fresh.row.digest !== p.row.digest) throw Error("WORKBENCH_HYPOTHESIS_STALE_REVIEW");
    const decisionId = randomUUID(),
      policyDigest = adaptiveDigest(preview.input.expectations),
      receipt = {
        proposalDigest: p.row.digest,
        policyDigest,
        flowId: input.candidateId,
        dependencyMeaning: p.snapshot.flow.dependencyMeaning,
        ...(p.snapshot.relationships
          ? {
              relationshipDigest: adaptiveDigest(p.snapshot.relationships),
              relationshipAuthority: "EXPLICIT_OWNER_POLICY_NOT_INFERRED"
            }
          : {}),
        humanOwnershipConfirmed: true,
        humanPolicyConfirmed: true,
        relationshipExplanation: input.relationshipExplanation,
        ...(p.snapshot.transition
          ? {
              transitionDigest: adaptiveDigest(p.snapshot.transition),
              transitionReview: input.transitionReview,
              transitionConclusion: {
                eventId: p.snapshot.transition.declaration.event.eventId,
                keyAuthority: "HUMAN_CONFIRMED_FOR_THIS_EXACT_REVIEW",
                policyOutcome:
                  p.snapshot.transition.declaration.policy === "FORBIDDEN"
                    ? "RECORDED_DEVIATION_REQUIRES_HUMAN_REVIEW"
                    : "REVIEWED_LEGITIMATE_EVENT_CORRELATION",
                causalProof: false,
                findingsInferred: false,
                stateChangingExecution: "HOLD"
              }
            }
          : {}),
        executionAuthority: "NONE"
      };
    this.db.db
      .prepare("INSERT INTO application_hypothesis_decisions VALUES(?,?,?,?,?,?,?,?)")
      .run(
        decisionId,
        id,
        input.candidateId,
        "REVIEW",
        policyDigest,
        JSON.stringify(receipt),
        actor,
        new Date().toISOString()
      );
    const matrix = await wb.create(org, { ...preview.input, hypothesisReviewId: decisionId }, actor);
    return { decisionId, status: "MATRIX_REVIEW_REQUIRED", matrix };
  }
  public inspect(org: string, id: string) {
    const p = hypothesisProposal(this.db, org, id);
    let freshness = "CURRENT";
    try {
      freshHypothesisProposal(this.db, org, id);
    } catch (e) {
      freshness = e instanceof Error && e.message.startsWith("WORKBENCH_") ? e.message : "UNKNOWN_EVIDENCE_UNAVAILABLE";
    }
    return { ...p, freshness };
  }
  public get(org: string, id: string) {
    const p = this.inspect(org, id),
      freshness = p.freshness;
    const decisions = this.db.db
      .prepare(
        "SELECT id,candidate_id,action,receipt_json,created_at FROM application_hypothesis_decisions WHERE proposal_id=? ORDER BY created_at,id"
      )
      .all(id) as { id: string; candidate_id: string; action: string; receipt_json: string; created_at: string }[];
    const matrices = this.db.db
      .prepare(
        "SELECT id,created_at FROM authorization_workbench_revisions WHERE organization_id=? AND json_extract(input_json,'$.hypothesisReviewId') IN (SELECT id FROM application_hypothesis_decisions WHERE proposal_id=?) ORDER BY created_at,id"
      )
      .all(org, id);
    return {
      ...p.snapshot,
      proposalId: id,
      digest: p.row.digest!,
      createdAt: p.row.created_at!,
      freshness,
      decisions: decisions.map((d) => ({
        id: d.id,
        candidateId: d.candidate_id,
        action: d.action,
        receipt: JSON.parse(d.receipt_json),
        createdAt: d.created_at
      })),
      matrices,
      readOnlyHistory: true
    };
  }
  public async decide(org: string, id: string, value: unknown, actor: string) {
    const input = hypothesisDecisionSchema.parse(value),
      p = freshHypothesisProposal(this.db, org, id);
    if (p.row.digest !== input.digest) throw Error("WORKBENCH_HYPOTHESIS_STALE_REVIEW");
    if (input.action === "REVIEW_FLOW") return this.reviewFlow(org, id, p, input, actor);
    if ((p.snapshot.transition || p.snapshot.relationships) && input.action === "REVIEW")
      throw Error("WORKBENCH_TRANSITION_FULL_FLOW_REVIEW_REQUIRED");
    const candidates = p.snapshot.candidates as ReturnType<typeof buildApplicationHypotheses>,
      c =
        candidates.find((c) => c.candidateId === input.candidateId) ??
        (input.action === "REJECT" && p.snapshot.flow?.flowId === input.candidateId
          ? { ...candidates[0]!, candidateId: input.candidateId }
          : undefined);
    if (!c) throw Error("WORKBENCH_HYPOTHESIS_CANDIDATE_NOT_FOUND");
    if (
      this.db.db
        .prepare("SELECT 1 FROM application_hypothesis_decisions WHERE proposal_id=? AND candidate_id=?")
        .get(id, c.candidateId)
    )
      throw Error("WORKBENCH_HYPOTHESIS_DECISION_ALREADY_RECORDED");
    const decisionId = randomUUID(),
      now = new Date().toISOString();
    if (input.action === "REJECT") {
      this.db.db
        .prepare("INSERT INTO application_hypothesis_decisions VALUES(?,?,?,?,?,?,?,?)")
        .run(
          decisionId,
          id,
          c.candidateId,
          "REJECT",
          null,
          JSON.stringify({ reason: input.reason, proposalDigest: p.row.digest, executionAuthority: "NONE" }),
          actor,
          now
        );
      return { decisionId, status: "REJECTED", matrix: null };
    }
    if (c.eligibility !== "EVIDENCE_READY_FOR_POLICY_REVIEW" || !p.source.scanId)
      throw Error("WORKBENCH_HYPOTHESIS_ABSTAIN_REQUIRES_NEW_EVIDENCE");
    if (
      c.collection &&
      (input.identity !== undefined ||
        input.tenant !== undefined ||
        input.decisions.anonymous !== "DENY" ||
        input.decisions["account-a"] !== "ALLOW" ||
        input.decisions["account-b"] !== "ALLOW")
    )
      throw Error("WORKBENCH_COLLECTION_SELF_POLICY_ONLY");
    const primary = c.evidence[0]!,
      matches = (path: string, value: string | number) =>
        primary.markers.some(
          (m) => m.path === path && m.fingerprint === observedMarkerFingerprint(value) && m.scalarType === typeof value
        );
    if (
      !c.collection &&
      (input.identity === undefined ||
        !matches(c.identityPath, input.identity) ||
        (c.tenantPath && (input.tenant === undefined || !matches(c.tenantPath, input.tenant))))
    )
      throw Error("WORKBENCH_HYPOTHESIS_TYPED_PRIMARY_MARKER_REQUIRED");
    const expectations = [
      {
        routeId: c.routeId,
        url: c.url,
        kind: c.kind === "FUNCTION" ? "FUNCTION_AUTHORIZATION" : "TENANT_ISOLATION",
        explanation: input.explanation,
        decisions: input.decisions,
        ...(c.collection
          ? { collection: c.collection }
          : { identity: { path: c.identityPath, expectedValue: input.identity! } }),
        ...(c.tenantPath ? { tenant: { path: c.tenantPath, expectedValue: input.tenant! } } : {})
      }
    ];
    if (!c.tenantPath && c.kind !== "FUNCTION") expectations[0]!.kind = "OBJECT_AUTHORIZATION";
    const base = {
      targetId: p.source.input.targetId,
      sourceScanId: p.source.scanId,
      mappingAcquisitionId: p.source.row.id,
      credentials: p.source.input.credentials,
      expectations
    };
    const workbench = new AuthorizationWorkbenchService(this.db, this.vault, this.execution),
      preview = await workbench.preview(org, base);
    if (preview.blockers.length) throw Error("WORKBENCH_HYPOTHESIS_POLICY_CONTROLS_INCOMPLETE");
    // Recheck after the asynchronous ordinary preview, before recording a one-time decision.
    const fresh = freshHypothesisProposal(this.db, org, id);
    if (fresh.row.digest !== p.row.digest) throw Error("WORKBENCH_HYPOTHESIS_STALE_REVIEW");
    const receipt = {
      proposalDigest: p.row.digest,
      policyDigest: adaptiveDigest(preview.input.expectations),
      expectedMarkers: primary.markers,
      ...(c.collection
        ? { collectionContract: c.collection, ownershipRuleConfirmed: true, coverage: c.collection.coverage }
        : {}),
      humanOwnershipConfirmed: true,
      humanPolicyConfirmed: true,
      executionAuthority: "NONE"
    };
    this.db.db
      .prepare("INSERT INTO application_hypothesis_decisions VALUES(?,?,?,?,?,?,?,?)")
      .run(decisionId, id, c.candidateId, "REVIEW", receipt.policyDigest, JSON.stringify(receipt), actor, now);
    // No transmission occurs here. A missing matrix acknowledgement stays a visible retained review; never dispatch/replay.
    const matrix = await workbench.create(org, { ...preview.input, hypothesisReviewId: decisionId }, actor);
    return { decisionId, status: "MATRIX_REVIEW_REQUIRED", matrix };
  }
}
