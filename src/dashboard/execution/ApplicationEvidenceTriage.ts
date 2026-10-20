import { ObservedStateRegressionService } from "./ObservedStateRegressionService.js";
import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { hypothesisProposal } from "./ApplicationHypothesisBinding.js";
import type { ApplicationHypothesisService } from "./ApplicationHypothesisService.js";
import type { AuthorizationWorkbenchService } from "./AuthorizationWorkbenchService.js";
import { ScanComparisonService } from "../comparisons/ScanComparisonService.js";
import { assertAssuranceComparison, assertComparisonSummary } from "../comparisons/ComparisonIntegrity.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { triageNoteSchema } from "../contracts/BusinessRelationshipContracts.js";
import { redactString } from "../security/Redaction.js";
/** Read-only projection of existing evidence, never a second findings or execution engine. */
export class ApplicationEvidenceTriage {
  constructor(
    private db: DashboardDatabase,
    private hypotheses: ApplicationHypothesisService,
    private workbench: AuthorizationWorkbenchService
  ) {}
  public get(org: string, id: string) {
    return this.db.db.transaction(() => this.project(org, id)).deferred();
  }
  private project(org: string, id: string) {
    const inspected = this.hypotheses.inspect(org, id),
      p = {
        ...inspected.snapshot,
        digest: inspected.row.digest!,
        freshness: inspected.freshness,
        decisions: this.db.db
          .prepare(
            "SELECT id,candidate_id,action,receipt_json,created_at FROM application_hypothesis_decisions WHERE proposal_id=? ORDER BY created_at,id LIMIT 16"
          )
          .all(id)
      },
      linked = this.db.db
        .prepare(
          "SELECT id FROM authorization_workbench_revisions WHERE organization_id=? AND json_extract(input_json,'$.hypothesisReviewId') IN (SELECT id FROM application_hypothesis_decisions WHERE proposal_id=?) ORDER BY created_at DESC,id DESC LIMIT 100"
        )
        .all(org, id) as { id: string }[];
    const proofCount = (
      this.db.db
        .prepare(
          "SELECT count(*) n FROM authorization_workbench_revisions WHERE organization_id=? AND json_extract(input_json,'$.hypothesisReviewId') IN (SELECT id FROM application_hypothesis_decisions WHERE proposal_id=?)"
        )
        .get(org, id) as { n: number }
    ).n;
    let historyIncomplete = proofCount > linked.length;
    const proofs = linked.map((m) => {
      try {
        const r = this.workbench.result(org, m.id);
        return {
          revisionId: m.id,
          scanId: r.scanId ?? null,
          status: r.status,
          sourceHash: r.sourceHash ?? null,
          verifiedReadOnlyChecksPass: r.verifiedReadOnlyChecksPass,
          checks:
            r.checks?.map((c) => ({
              checkId: c.checkId,
              actorId: c.actorId,
              outcome: c.outcome,
              reason: c.reasonCode,
              comparisonFingerprint: c.comparisonFingerprint,
              ...(c.collection ? { collection: c.collection } : {})
            })) ?? [],
          findings: r.findings ?? [],
          missing:
            r.status === "INCONCLUSIVE" ||
            r.checks?.some((c) => c.outcome === "INCONCLUSIVE" || c.outcome === "BLOCKED")
              ? ["INCOMPLETE_NATIVE_CONTROLS"]
              : []
        };
      } catch {
        return {
          revisionId: m.id,
          scanId: null,
          status: "UNKNOWN",
          sourceHash: null,
          verifiedReadOnlyChecksPass: false,
          checks: [],
          findings: [],
          missing: ["NATIVE_PROOF_UNAVAILABLE_OR_CHANGED"]
        };
      }
    });
    const scanIds = proofs.flatMap((r) => (r.scanId ? [r.scanId] : [])),
      comparisons: Record<string, unknown>[] = [];
    if (scanIds.length) {
      const marks = scanIds.map(() => "?").join(",");
      const rows = this.db.db
        .prepare(
          "SELECT c.id,c.state,c.summary_json,c.older_scan_id,c.newer_scan_id FROM scan_comparisons c JOIN scans a ON a.id=c.older_scan_id JOIN scans b ON b.id=c.newer_scan_id WHERE c.deleted_at IS NULL AND a.organization_id=? AND b.organization_id=? AND c.older_scan_id IN (" +
            marks +
            ") AND c.newer_scan_id IN (" +
            marks +
            ") ORDER BY c.created_at DESC,c.id DESC LIMIT 101"
        )
        .all(org, org, ...scanIds, ...scanIds) as {
        id: string;
        state: string;
        summary_json: string;
        older_scan_id: string;
        newer_scan_id: string;
      }[];
      historyIncomplete ||= rows.length > 100;
      for (const row of rows.slice(0, 100)) {
        try {
          const r = new ScanComparisonService(this.db).get(row.id);
          assertComparisonSummary(JSON.parse(row.summary_json), row.id);
          let complete = false;
          try {
            assertAssuranceComparison(r, row.older_scan_id, row.newer_scan_id, []);
            complete = true;
          } catch {
            /* Partial or failed coverage cannot quietly resolve the assessment. */
          }
          comparisons.push({
            comparisonId: row.id,
            state: r.state,
            compatible: r.compatible,
            summary: r.summary,
            coverageComplete: complete,
            disposition: complete ? "COMPARABLE_RECORDED_RESULT" : "HUMAN_REVIEW_INCOMPLETE_OR_FAILED",
            oldScanId: r.oldScanId,
            newScanId: r.newScanId
          });
        } catch {
          comparisons.push({
            comparisonId: row.id,
            state: ["FAILED", "ANALYZING", "PARTIAL", "COMPLETED"].includes(row.state) ? row.state : "UNKNOWN",
            coverageComplete: false,
            disposition: "HUMAN_REVIEW_INVALID_COMPARISON"
          });
        }
      }
    }
    const notes = this.db.db
        .prepare(
          "SELECT id,evidence_digest,disposition,rationale,created_at FROM application_triage_notes WHERE proposal_id=? ORDER BY created_at DESC,id DESC LIMIT 100"
        )
        .all(id),
      noteCount = (
        this.db.db.prepare("SELECT count(*) n FROM application_triage_notes WHERE proposal_id=?").get(id) as {
          n: number;
        }
      ).n;
    historyIncomplete ||= noteCount > notes.length;
    const observationPolicies: Record<string, unknown>[] = [];
    if (linked.length) {
      const ids = linked.map((m) => m.id),
        rows = this.db.db
          .prepare(
            "SELECT id FROM application_observation_policy_versions WHERE organization_id=? AND matrix_revision_id IN (" +
              ids.map(() => "?").join(",") +
              ") ORDER BY created_at DESC,id DESC LIMIT 21"
          )
          .all(org, ...ids) as { id: string }[];
      historyIncomplete ||= rows.length > 20;
      const service = new ObservedStateRegressionService(this.db);
      for (const row of rows.slice(0, 20)) {
        try {
          const policy = service.get(org, row.id),
            assessments = this.db.db
              .prepare(
                "SELECT id FROM application_observation_assessments WHERE policy_version_id=? ORDER BY created_at DESC,id DESC LIMIT 21"
              )
              .all(row.id) as { id: string }[];
          historyIncomplete ||= assessments.length > 20;
          observationPolicies.push({
            id: policy.id,
            status: policy.status,
            baselineScanId: policy.snapshot.source.sourceScanId,
            assessments: assessments.slice(0, 20).map((a) => {
              try {
                const r = service.assessment(org, a.id);
                return {
                  id: a.id,
                  outcome: r.outcome,
                  reasons: r.reasons,
                  comparisonId: r.comparisonId,
                  requiresHumanReview: r.requiresHumanReview
                };
              } catch {
                return {
                  id: a.id,
                  outcome: "INCONCLUSIVE",
                  requiresHumanReview: true,
                  reasons: ["OBSERVED_STATE_CUSTODY_UNAVAILABLE"]
                };
              }
            })
          });
        } catch {
          observationPolicies.push({ id: row.id, status: "UNKNOWN", requiresHumanReview: true });
        }
      }
    }
    const evidence = {
      version: "application-evidence-triage-v1",
      proposalId: id,
      proposalDigest: p.digest,
      freshness: p.freshness,
      source: p.source,
      relationships: p.relationships ?? null,
      questions: (p.candidates as ReturnType<ApplicationHypothesisService["generate"]>["candidates"]).map((c) => ({
        candidateId: c.candidateId,
        routeId: c.routeId,
        priority: c.priority,
        eligibility: c.eligibility,
        missingControls: c.missingControls,
        irCaseIds: c.irCaseIds
      })),
      relationshipQuestions: p.relationships?.questions ?? [],
      decisions: p.decisions,
      proofs,
      comparisons,
      observationPolicies,
      proofCount,
      noteCount,
      historyIncomplete
    };
    return {
      ...evidence,
      digest: adaptiveDigest(evidence),
      notes,
      observationIsFinding: false,
      policyAuthority: "OWNER_DECLARATION",
      executionAuthority: "NONE",
      stateChangingExecution: "HOLD",
      automaticReplay: false,
      nextAction: historyIncomplete
        ? "REVIEW_INCOMPLETE_HISTORY"
        : p.freshness !== "CURRENT"
          ? "REVIEW_STALE_SOURCE_OR_AUTHORITY"
          : proofs.some((r) => r.status === "UNKNOWN" || r.status === "INCONCLUSIVE" || r.missing.length > 0)
            ? "REVIEW_UNCERTAIN_EVIDENCE"
            : comparisons.some((c) => c.coverageComplete !== true)
              ? "REVIEW_INCOMPLETE_OR_FAILED_COMPARISON"
              : observationPolicies.some((p) => p.status === "UNKNOWN")
                ? "REVIEW_OBSERVED_STATE_UNCERTAINTY"
                : proofs[0]?.findings.length
                  ? "TRIAGE_VERIFIED_NATIVE_DEVIATIONS"
                  : comparisons.some((c) => c.coverageComplete === true && c.newScanId === proofs[0]?.scanId)
                    ? "REVIEW_RECORDED_REMEDIATION_DELTA"
                    : proofs.some((r) => r.findings.length)
                      ? "TRIAGE_HISTORICAL_DEVIATIONS_WITHOUT_COMPLETE_RETEST"
                      : proofs.length
                        ? "REVIEW_EXACT_PROOF_AND_COMPARISON_COVERAGE"
                        : "REVIEW_POLICY_THEN_SEPARATELY_AUTHORIZE_PROOF"
    };
  }
  public note(org: string, id: string, value: unknown, actor: string) {
    const input = triageNoteSchema.parse(value);
    hypothesisProposal(this.db, org, id);
    return this.db.db
      .transaction(() => {
        const current = this.get(org, id);
        if (current.digest !== input.digest) throw Error("WORKBENCH_TRIAGE_STALE_EVIDENCE");
        const noteId = randomUUID();
        this.db.db
          .prepare("INSERT INTO application_triage_notes VALUES(?,?,?,?,?,?,?)")
          .run(
            noteId,
            id,
            current.digest,
            input.disposition,
            redactString(input.rationale),
            actor,
            new Date().toISOString()
          );
        return {
          noteId,
          disposition: input.disposition,
          scannerOutcomeChanged: false,
          executionAuthority: "NONE",
          reviewRequired: true
        };
      })
      .immediate();
  }
}
