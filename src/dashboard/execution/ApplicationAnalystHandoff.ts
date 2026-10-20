import { z } from "zod";
import { ScanComparisonService } from "../comparisons/ScanComparisonService.js";
import { assertAssuranceComparison } from "../comparisons/ComparisonIntegrity.js";
import { OwnedApplicationIntakeService } from "./OwnedApplicationIntake.js";
import type { buildBusinessRelationships } from "./BusinessRelationshipEvidence.js";
import { createHash } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import type { ApplicationEvidenceTriage } from "./ApplicationEvidenceTriage.js";
import type { AuthorizationWorkbenchService } from "./AuthorizationWorkbenchService.js";
import { hypothesisProposal } from "./ApplicationHypothesisBinding.js";
import { adaptiveDigest } from "./AdaptiveCanonical.js";
import { observedMarkerFingerprint } from "../../modules/apiGraphql/ObservedMarker.js";
import { identityFingerprint } from "./ObservedActorEvidence.js";
import type { AuthorizationWorkbenchInput } from "../contracts/AuthorizationWorkbenchContracts.js";
export const analystHistoryQuerySchema = z
  .object({
    kind: z.enum(["proofs", "notes", "comparisons"]).default("proofs"),
    query: z
      .string()
      .regex(/^[A-Za-z0-9 _:.-]{0,80}$/)
      .default(""),
    cursor: z.string().max(2048).optional()
  })
  .strict();
type IndexRow = { id: string; at: string; state: string; scanId: string | null; oldScanId?: string; binding: string };
/** Read-only, membership-bound continuation. No raw request, credential, body or free-text note is exported. */
export class ApplicationAnalystHandoff {
  constructor(
    private db: DashboardDatabase,
    private triage: ApplicationEvidenceTriage,
    private workbench: AuthorizationWorkbenchService
  ) {}
  private index(org: string, id: string, kind: "proofs" | "notes" | "comparisons") {
    hypothesisProposal(this.db, org, id);
    if (kind === "comparisons") {
      const rows = this.db.db
        .prepare(
          "SELECT c.id,c.created_at at,c.state,c.newer_scan_id scanId,c.older_scan_id oldScanId,c.summary_json binding FROM scan_comparisons c JOIN scans a ON a.id=c.older_scan_id JOIN scans b ON b.id=c.newer_scan_id WHERE c.deleted_at IS NULL AND a.organization_id=? AND b.organization_id=? AND EXISTS(SELECT 1 FROM authorization_workbench_revisions r JOIN authorization_workbench_acknowledgements k ON k.revision_id=r.id WHERE r.organization_id=? AND k.scan_id=c.older_scan_id AND json_extract(r.input_json,'$.hypothesisReviewId') IN(SELECT id FROM application_hypothesis_decisions WHERE proposal_id=?)) AND EXISTS(SELECT 1 FROM authorization_workbench_revisions r JOIN authorization_workbench_acknowledgements k ON k.revision_id=r.id WHERE r.organization_id=? AND k.scan_id=c.newer_scan_id AND json_extract(r.input_json,'$.hypothesisReviewId') IN(SELECT id FROM application_hypothesis_decisions WHERE proposal_id=?)) ORDER BY c.created_at DESC,c.id DESC LIMIT 10001"
        )
        .all(org, org, org, id, org, id) as IndexRow[];
      if (rows.length > 10000) throw Error("WORKBENCH_HANDOFF_HISTORY_BOUND_REQUIRES_REVIEW");
      return rows.map((r) => ({
        ...r,
        binding: adaptiveDigest({ state: r.state, summary: r.binding, oldScanId: r.oldScanId, newScanId: r.scanId })
      }));
    }
    const rows = (
      kind === "proofs"
        ? this.db.db
            .prepare(
              "SELECT r.id,r.created_at at,CASE WHEN d.revision_id IS NULL THEN 'UNTESTED' WHEN a.scan_id IS NULL THEN 'UNKNOWN' ELSE coalesce(s.status,'UNKNOWN') END state,a.scan_id scanId,r.digest binding FROM authorization_workbench_revisions r LEFT JOIN authorization_workbench_dispatches d ON d.revision_id=r.id LEFT JOIN authorization_workbench_acknowledgements a ON a.revision_id=r.id LEFT JOIN scans s ON s.id=a.scan_id AND s.organization_id=r.organization_id WHERE r.organization_id=? AND json_extract(r.input_json,'$.hypothesisReviewId') IN (SELECT id FROM application_hypothesis_decisions WHERE proposal_id=?) ORDER BY r.created_at DESC,r.id DESC LIMIT 10001"
            )
            .all(org, id)
        : this.db.db
            .prepare(
              "SELECT id,created_at at,disposition state,NULL scanId,evidence_digest binding FROM application_triage_notes WHERE proposal_id=? ORDER BY created_at DESC,id DESC LIMIT 10001"
            )
            .all(id)
    ) as IndexRow[];
    if (rows.length > 10000) throw Error("WORKBENCH_HANDOFF_HISTORY_BOUND_REQUIRES_REVIEW");
    return rows;
  }
  page(org: string, id: string, value: unknown) {
    const input = analystHistoryQuerySchema.parse(value);
    return this.db.db
      .transaction(() => {
        const index = this.index(org, id, input.kind),
          snapshot = adaptiveDigest({ proposalId: id, kind: input.kind, index }),
          q = input.query.toLowerCase();
        const rows = index.filter((r) => (r.id + " " + r.state + " " + (r.scanId ?? "")).toLowerCase().includes(q));
        let offset = 0;
        if (input.cursor) {
          let cursor;
          try {
            cursor = z
              .object({ snapshot: z.string(), kind: z.string(), query: z.string(), after: z.string() })
              .strict()
              .parse(JSON.parse(Buffer.from(input.cursor, "base64url").toString("utf8")));
          } catch {
            throw Error("WORKBENCH_HANDOFF_CURSOR_INVALID");
          }
          if (cursor.snapshot !== snapshot || cursor.kind !== input.kind || cursor.query !== input.query)
            throw Error("WORKBENCH_HANDOFF_HISTORY_CHANGED_RESTART_REQUIRED");
          offset = rows.findIndex((r) => r.id === cursor.after) + 1;
          if (offset === 0) throw Error("WORKBENCH_HANDOFF_CURSOR_UNAVAILABLE");
        }
        const selected = rows.slice(offset, offset + 20),
          next =
            offset + selected.length < rows.length
              ? Buffer.from(
                  JSON.stringify({ snapshot, kind: input.kind, query: input.query, after: selected.at(-1)!.id })
                ).toString("base64url")
              : null;
        const entries = selected.map((r) => {
          if (input.kind === "comparisons") {
            try {
              const c = new ScanComparisonService(this.db).get(r.id);
              let coverageComplete = false;
              try {
                assertAssuranceComparison(c, r.oldScanId!, r.scanId!, []);
                coverageComplete = true;
              } catch {
                /* Incomplete or failed comparison never closes the case. */
              }
              return {
                ...r,
                detail: {
                  status: c.state,
                  oldScanId: c.oldScanId,
                  newScanId: c.newScanId,
                  summary: c.summary,
                  coverageComplete,
                  requiresHumanReview: !coverageComplete
                }
              };
            } catch {
              return {
                ...r,
                detail: {
                  status: r.state === "FAILED" ? "FAILED" : "UNKNOWN",
                  coverageComplete: false,
                  requiresHumanReview: true
                }
              };
            }
          }
          if (input.kind === "notes") return { ...r, detail: { disposition: r.state, freeTextOmitted: true } };
          try {
            const p = this.workbench.result(org, r.id);
            return {
              ...r,
              detail: {
                status: p.status,
                checks:
                  p.checks?.map((c) => ({
                    id: c.checkId,
                    actor: c.actorId,
                    outcome: c.outcome,
                    reason: c.reasonCode,
                    fingerprint: c.comparisonFingerprint
                  })) ?? [],
                findings: p.findings?.map((f) => ({ id: f.id, severity: f.severity, confidence: f.confidence })) ?? [],
                sourceHash: p.sourceHash ?? null
              }
            };
          } catch {
            return { ...r, detail: { status: "UNKNOWN", requiresHumanReview: true } };
          }
        });
        return {
          version: 1,
          proposalId: id,
          kind: input.kind,
          query: input.query,
          snapshot,
          total: index.length,
          matching: rows.length,
          offset,
          entries,
          nextCursor: next,
          pageSha256: adaptiveDigest({ snapshot, offset, entries, next }),
          completeHistoryOnThisPage: offset === 0 && !next && input.query === "",
          executionAuthority: "NONE",
          unknownIsSuccess: false
        };
      })
      .deferred();
  }
  export(org: string, id: string) {
    return this.db.db
      .transaction(() => {
        const t = this.triage.get(org, id),
          index = this.index(org, id, "proofs"),
          notes = this.index(org, id, "notes"),
          comparisonIndex = this.index(org, id, "comparisons");
        const relationships = t.relationships as ReturnType<typeof buildBusinessRelationships> | undefined;
        const context =
          relationships?.relationships.map((r) => ({
            id: r.relationshipId,
            producer: r.declaration.producer,
            consumer: r.declaration.consumer,
            identifierField: r.declaration.identifier,
            referenceField: r.declaration.reference,
            eligibility: r.eligibility,
            ownerContext: r.ownerContext,
            missing: r.missingControls,
            cells: r.cells.map((c) => ({
              actorId: c.actorId,
              ownerRelationship: c.ownerRelationship,
              observedOwner: c.observedOwner,
              actorBindingFingerprint: c.actorBindingFingerprint,
              principalFingerprint: c.actorBinding.principalFingerprint,
              actorTenantFingerprint: c.actorBinding.tenantFingerprint,
              roleFingerprint: c.actorBinding.role ? identityFingerprint(c.actorBinding.role) : null,
              producerCheckId: c.producerCheckId,
              consumerCheckId: c.consumerCheckId,
              producerDecision: c.producerDecision,
              consumerDecision: c.consumerDecision,
              identifier: c.identifier,
              reference: c.reference,
              producerTenant: c.producerTenant,
              consumerTenant: c.consumerTenant,
              producerVersion: c.producerVersion,
              consumerVersion: c.consumerVersion,
              relationshipObserved: c.relationshipObserved,
              reasons: c.reasons
            }))
          })) ?? [];
        const reviewedPolicies = t.proofs.map((p) => {
          try {
            const row = this.db.db
              .prepare("SELECT input_json FROM authorization_workbench_revisions WHERE id=? AND organization_id=?")
              .get(p.revisionId, org) as { input_json: string };
            const input = JSON.parse(row.input_json) as AuthorizationWorkbenchInput,
              marker = (m: { path: string; expectedValue: string | number } | undefined) =>
                m
                  ? {
                      path: m.path,
                      scalarType: typeof m.expectedValue,
                      valueFingerprint: observedMarkerFingerprint(m.expectedValue)
                    }
                  : null;
            return {
              revisionId: p.revisionId,
              expectations: input.expectations.map((e) => ({
                routeId: e.routeId,
                kind: e.kind,
                decisions: e.decisions,
                identity: marker(e.identity),
                tenant: marker(e.tenant),
                states: e.states?.map(marker) ?? [],
                dependsOn: e.dependsOn ?? []
              }))
            };
          } catch {
            return { revisionId: p.revisionId, status: "UNKNOWN_POLICY_CUSTODY" };
          }
        });
        const reviewBindings = (
          this.db.db
            .prepare(
              "SELECT id,candidate_id,action,receipt_json,created_at FROM application_hypothesis_decisions WHERE proposal_id=? ORDER BY created_at,id LIMIT 17"
            )
            .all(id) as { id: string; candidate_id: string; action: string; receipt_json: string; created_at: string }[]
        ).map((d) => ({
          id: d.id,
          candidateId: d.candidate_id,
          action: d.action,
          at: d.created_at,
          receiptSha256: createHash("sha256").update(d.receipt_json).digest("hex")
        }));
        const proposal = hypothesisProposal(this.db, org, id),
          map = this.db.db
            .prepare("SELECT input_json FROM application_mapping_revisions WHERE id=? AND organization_id=?")
            .get(proposal.row.map_revision_id, org) as { input_json: string };
        const intakeBinding = JSON.parse(map.input_json).intakeBinding as
          { revisionId: string; digest: string } | undefined;
        let intakeProvenance: Record<string, unknown> | null = null;
        if (intakeBinding) {
          try {
            const i = new OwnedApplicationIntakeService(this.db).get(org, intakeBinding.revisionId);
            if (i.digest !== intakeBinding.digest) throw Error("INTAKE_DIGEST");
            intakeProvenance = {
              revisionId: i.revisionId,
              digest: i.digest,
              artifactSha256: i.artifactSha256,
              exportSha256: i.exportSha256,
              declaredProvenance: i.provenance,
              provenanceAuthority: i.provenanceAuthority,
              capturedAt: i.capturedAt,
              freshness: i.freshness,
              identityStatus: i.identityStatus,
              sessionStatus: i.sessionStatus
            };
          } catch {
            intakeProvenance = { status: "UNKNOWN_REQUIRES_REVIEW" };
          }
        }
        const packet = {
          comparisonIndex,
          analystBrief: {
            observed: {
              mapRevisionId: t.source.mapRevisionId,
              scanId: t.source.sourceScanId ?? null,
              sourceHash: t.source.sourceHash ?? null,
              relationshipCount: context.length
            },
            verified: {
              meaning: "NATIVE_CHECKS_AGAINST_EXPLICIT_REVIEWED_POLICY_ONLY",
              proofCount: index.length,
              latestStatus: t.proofs[0]?.status ?? "UNTESTED",
              latestFindingCount: t.proofs[0]?.findings.length ?? 0
            },
            uncertain: {
              freshness: t.freshness,
              incompleteHistory: t.historyIncomplete || comparisonIndex.length !== t.comparisons.length,
              missing: t.proofs.flatMap((p) => p.missing),
              relationshipCounterevidence: context.flatMap((r) =>
                r.cells.flatMap((c) => {
                  const reasons = c.reasons.filter((reason) => reason !== "NATIVE_DENIAL_COUNTEREVIDENCE");
                  return reasons.length ? [{ relationshipId: r.id, actorId: c.actorId, reasons }] : [];
                })
              ),
              relationshipControls: context.flatMap((c) => c.missing)
            },
            remediation: {
              comparisonCount: comparisonIndex.length,
              completeComparisons: t.comparisons.filter((c) => c.coverageComplete === true).length,
              meaning: "COMPARISON_DELTA_FOR_EXACT_TESTED_CHECKS_NOT_FULL_APPLICATION_ACCEPTANCE"
            },
            nextAction: t.nextAction,
            policySource: "EXPLICIT_OWNER_DECLARATION",
            nativeCompletionIsSecurityPass: false,
            stateMutationProved: false
          },
          intakeProvenance,
          version: 1,
          reviewedPolicies,
          reviewBindings,
          format: "ROUTECAIRN_REDACTED_ANALYST_CASE",
          proposalId: id,
          proposalDigest: t.proposalDigest,
          evidenceDigest: t.digest,
          sourceScanId: t.source.sourceScanId ?? null,
          sourceHash: t.source.sourceHash ?? null,
          freshness: t.freshness,
          question: "DO_THE_REVIEWED_ACTORS_HAVE_THE_DECLARED_ACCESS_TO_THE_EXACT_LINKED_ENTITY_VERSIONS",
          relationships: context,
          questions: t.questions.map((q) => ({
            id: q.candidateId,
            routeId: q.routeId,
            eligibility: q.eligibility,
            missing: q.missingControls,
            caseIds: q.irCaseIds
          })),
          nativeProofs: t.proofs.map((p) => ({
            revisionId: p.revisionId,
            scanId: p.scanId,
            status: p.status,
            sourceHash: p.sourceHash,
            missing: p.missing,
            checks: p.checks,
            findings: p.findings.map((f) => ({ id: f.id, severity: f.severity, confidence: f.confidence }))
          })),
          comparisons: t.comparisons,
          observedState: t.observationPolicies,
          proofIndex: index,
          noteIndex: notes,
          historyIncomplete: t.historyIncomplete || comparisonIndex.length !== t.comparisons.length,
          requiresHumanReview: true,
          nextAction: t.nextAction,
          redaction: "NO_RAW_HEADERS_BODIES_SESSIONS_SECRETS_OR_FREE_TEXT_NOTES",
          notesNeverSuppressFindings: true,
          stateChangingExecution: "HOLD",
          executionAuthority: "NONE",
          causalProof: false,
          ownershipInferred: false,
          fullApplicationAcceptance: false
        };
        const bytes = JSON.stringify(packet);
        if (Buffer.byteLength(bytes) > 4 * 1024 * 1024) throw Error("WORKBENCH_HANDOFF_OUTPUT_BOUND");
        return {
          ...packet,
          packetSha256: createHash("sha256").update(bytes).digest("hex"),
          integrityMeaning: "SHA256_OF_JSON_BODY_EXCLUDING_PACKET_SHA256_NOT_A_PUBLISHER_SIGNATURE"
        };
      })
      .deferred();
  }
}
