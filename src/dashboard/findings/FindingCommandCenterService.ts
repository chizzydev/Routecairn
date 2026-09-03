import { randomUUID } from "node:crypto";
import type { DashboardDatabase, SqlValue } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import type { DashboardPrincipal } from "../auth/Permissions.js";
import type { RetestTemplateVault } from "../retests/RetestTemplateVault.js";
import { ScanComparisonCoverageService } from "../comparisons/ScanComparisonCoverageService.js";
import { hasOccurrenceReview } from "../reviews/AssistedOccurrenceReview.js";
import type {
  DashboardFindingSummary,
  FindingRetestContext,
  ProofReadinessStatus,
  RemediationStatus,
  RetestStatus,
  ReviewStatus
} from "../types/DashboardTypes.js";

export const findingPageSizeMaximum = 100;
export const findingBulkMaximum = 100;
export const findingNoteMaximum = 4_000;

export type FindingSort =
  | "severity_desc"
  | "confidence_desc"
  | "first_seen_desc"
  | "last_seen_desc"
  | "occurrences_desc"
  | "review"
  | "remediation"
  | "target"
  | "project";

export interface FindingQuery {
  scanId?: string | undefined;
  search?: string | undefined;
  projectId?: string | undefined;
  targetId?: string | undefined;
  module?: string | undefined;
  category?: string | undefined;
  severity?: string | undefined;
  confidence?: string | undefined;
  reviewStatus?: ReviewStatus | undefined;
  remediationStatus?: RemediationStatus | undefined;
  assigneeUserId?: string | undefined;
  retestStatus?: RetestStatus | undefined;
  proofReadiness?: ProofReadinessStatus | undefined;
  firstSeenFrom?: string | undefined;
  firstSeenTo?: string | undefined;
  lastSeenFrom?: string | undefined;
  lastSeenTo?: string | undefined;
  newOccurrence?: boolean | undefined;
  reopened?: boolean | undefined;
  sourceKind?: "NATIVE" | "IMPORTED" | undefined;
  evidence?: "HAS_EVIDENCE" | "MISSING_EVIDENCE" | undefined;
  sort?: FindingSort | undefined;
  page?: number | undefined;
  pageSize?: number | undefined;
}

export interface FindingPage {
  findings: DashboardFindingSummary[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export class FindingCommandError extends Error {
  public constructor(
    public readonly code: string,
    message: string,
    public readonly statusCode = 400
  ) {
    super(message);
    this.name = "FindingCommandError";
  }
}

interface FindingRow {
  id: string;
  canonical_title: string;
  module: string;
  finding_category: string;
  safe_endpoint_identity: string;
  http_method: string;
  current_scanner_severity: string;
  current_scanner_confidence: string;
  effective_severity: string | null;
  human_review_status: ReviewStatus;
  remediation_state_v2: RemediationStatus;
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
  project_id: string | null;
  project_name: string | null;
  target_id: string | null;
  target_name: string | null;
  assignee_user_id: string | null;
  assignee_label: string | null;
  reviewer_user_id: string | null;
  reviewer_label: string | null;
  review_started_at: string | null;
  retest_state: RetestStatus;
  proof_readiness: ProofReadinessStatus;
  new_occurrence_kind: string | null;
  row_version: number;
}

interface MutableFindingRow {
  id: string;
  target_identity: string;
  module: string;
  human_review_status: ReviewStatus;
  remediation_state_v2: RemediationStatus;
  duplicate_of_finding_id: string | null;
  row_version: number;
  latest_occurrence_id: string | null;
  proof_readiness: ProofReadinessStatus;
  reviewer_user_id: string | null;
  review_started_at: string | null;
}

export class FindingCommandCenterService {
  private readonly comparisonCoverage: ScanComparisonCoverageService;
  public constructor(private readonly database: DashboardDatabase, private readonly retestTemplates?: RetestTemplateVault) { this.comparisonCoverage = new ScanComparisonCoverageService(database); }

  public list(query: FindingQuery = {}): FindingPage {
    const pageSize = Math.min(Math.max(query.pageSize ?? 25, 1), findingPageSizeMaximum);
    const page = Math.max(query.page ?? 1, 1);
    const { where, values } = findingWhere(query);
    const total = (this.database.db.prepare(`SELECT COUNT(*) AS count FROM findings f ${where}`).get(...values) as { count: number }).count;
    const rows = this.database.db
      .prepare(
        `SELECT f.*, p.name AS project_name, t.display_name AS target_name, u.login AS assignee_label,
                reviewer.login AS reviewer_label
         FROM findings f
         LEFT JOIN projects p ON p.id = f.project_id
         LEFT JOIN targets t ON t.id = f.target_id
         LEFT JOIN dashboard_users u ON u.id = f.assignee_user_id
         LEFT JOIN dashboard_users reviewer ON reviewer.id = f.reviewer_user_id
         ${where}
         ORDER BY ${findingSortSql(query.sort)}
         LIMIT ? OFFSET ?`
      )
      .all(...values, pageSize, (page - 1) * pageSize) as FindingRow[];
    return {
      findings: rows.map(findingSummary),
      page,
      pageSize,
      total,
      totalPages: Math.max(1, Math.ceil(total / pageSize))
    };
  }

  public queue(mode: string, query: FindingQuery = {}): FindingPage {
    const queueQuery: FindingQuery = { ...query };
    switch (mode) {
      case "UNREVIEWED": queueQuery.reviewStatus = "UNREVIEWED"; break;
      case "IN_REVIEW": queueQuery.reviewStatus = "IN_REVIEW"; break;
      case "REOPENED": queueQuery.reviewStatus = "REOPENED"; break;
      case "HIGH_SEVERITY": queueQuery.severity = "High"; break;
      case "HIGH_CONFIDENCE": queueQuery.confidence = "High"; break;
      case "NEW_OCCURRENCE": queueQuery.newOccurrence = true; break;
      case "AFTER_FALSE_POSITIVE": queueQuery.newOccurrence = true; queueQuery.reviewStatus = "FALSE_POSITIVE"; break;
      case "MISSING_EVIDENCE": queueQuery.evidence = "MISSING_EVIDENCE"; break;
      case "PROOF_READY": queueQuery.proofReadiness = "READY"; break;
      default: throw new FindingCommandError("FINDING_QUEUE_INVALID", "Unknown review queue mode.");
    }
    return this.list(queueQuery);
  }

  public detail(findingId: string): unknown {
    this.refreshProofReadiness(findingId);
    const row = this.database.db
      .prepare(
        `SELECT f.*, p.name AS project_name, t.display_name AS target_name, u.login AS assignee_label,
                reviewer.login AS reviewer_label
         FROM findings f
         LEFT JOIN projects p ON p.id = f.project_id
         LEFT JOIN targets t ON t.id = f.target_id
         LEFT JOIN dashboard_users u ON u.id = f.assignee_user_id
         LEFT JOIN dashboard_users reviewer ON reviewer.id = f.reviewer_user_id
         WHERE f.id = ? AND f.archived_at IS NULL`
      )
      .get(findingId) as FindingRow | undefined;
    if (!row) throw new FindingCommandError("FINDING_NOT_FOUND", "Finding not found.", 404);
    const occurrences = this.database.db
      .prepare(
        `SELECT id, finding_id, scan_id, module, finding_category, severity, confidence, title,
                safe_endpoint, safe_actor_relationship, safe_tenant_or_role_boundary,
                safe_state_boundary, description, impact, reproduction_steps, remediation,
                limitations, evidence_summary, source_kind, workflow_case_alias,
                coverage_reference_json, safe_reproduction_json, created_at
         FROM finding_occurrences WHERE finding_id = ? ORDER BY created_at DESC`
      )
      .all(findingId);
    const evidence = this.database.db
      .prepare(
        `SELECT e.id, e.finding_occurrence_id, e.evidence_type, e.evidence_level, e.safe_summary,
                e.safe_structured_data_json, e.scoped_fingerprint, e.artifact_id, e.byte_count,
                e.retention_classification, e.created_at, a.missing_file_flag
         FROM evidence_records e
         JOIN finding_occurrences o ON o.id = e.finding_occurrence_id
         LEFT JOIN artifacts a ON a.id = e.artifact_id
         WHERE o.finding_id = ? ORDER BY e.created_at DESC`
      )
      .all(findingId);
    const reviews = this.database.db
      .prepare(
        `SELECT r.id, r.previous_review_status, r.new_review_status, r.reason, r.review_note,
                r.duplicate_target_finding_id, r.created_at, r.local_reviewer_label,
                r.source, r.correlation_id, r.safe_metadata_json, u.login AS actor_label
         FROM finding_reviews r LEFT JOIN dashboard_users u ON u.id = r.user_id
         WHERE r.finding_id = ? ORDER BY r.created_at ASC`
      )
      .all(findingId);
    const remediationHistory = this.database.db
      .prepare(
        `SELECT h.*, u.login AS actor_label, a.login AS assignee_label
         FROM finding_remediation_history h
         LEFT JOIN dashboard_users u ON u.id = h.user_id
         LEFT JOIN dashboard_users a ON a.id = h.assignee_user_id
         WHERE h.finding_id = ? ORDER BY h.created_at ASC`
      )
      .all(findingId);
    const notes = this.database.db
      .prepare(
        `SELECT n.id, n.safe_text, n.created_at, n.updated_at, u.login AS author_label
         FROM finding_notes n LEFT JOIN dashboard_users u ON u.id = n.user_id
         WHERE n.finding_id = ? ORDER BY n.created_at ASC`
      )
      .all(findingId);
    const retests = this.database.db
      .prepare("SELECT * FROM finding_retests WHERE finding_id = ? ORDER BY created_at DESC")
      .all(findingId);
    const duplicates = this.database.db
      .prepare("SELECT id, canonical_title, human_review_status, occurrence_count FROM findings WHERE duplicate_of_finding_id = ? ORDER BY last_seen_at DESC")
      .all(findingId);
    const related = this.database.db
      .prepare(
        `SELECT id, canonical_title, module, finding_category, safe_endpoint_identity,
                human_review_status, current_scanner_severity
         FROM findings
         WHERE id != ? AND archived_at IS NULL AND
               (target_identity = (SELECT target_identity FROM findings WHERE id = ?) OR
                module = (SELECT module FROM findings WHERE id = ?) OR
                finding_category = (SELECT finding_category FROM findings WHERE id = ?) OR
                safe_endpoint_identity = (SELECT safe_endpoint_identity FROM findings WHERE id = ?))
         ORDER BY last_seen_at DESC LIMIT 20`
      )
      .all(findingId, findingId, findingId, findingId, findingId);
    return {
      finding: findingSummary(row),
      description: safeNullableText((row as unknown as Record<string, unknown>).canonical_description),
      occurrences,
      occurrenceDifferences: occurrenceDifferences(occurrences as OccurrenceRow[]),
      evidence,
      reviews,
      remediationHistory,
      notes,
      retests,
      duplicates,
      related
    };
  }

  public retestDraft(findingId: string): Record<string, unknown> {
    const finding = this.requiredSummary(findingId);
    const occurrence = this.database.db.prepare(
      `SELECT id, scan_id, workflow_case_alias, coverage_reference_json
       FROM finding_occurrences WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1`
    ).get(findingId) as { id: string; scan_id: string; workflow_case_alias: string | null; coverage_reference_json: string } | undefined;
    if (!occurrence) throw new FindingCommandError("RETEST_SOURCE_MISSING", "Finding has no source occurrence to retest.", 409);
    const scan = this.database.db.prepare(
      `SELECT project_id, target_id, target_origin, profile, safe_configuration_summary
       FROM scans WHERE id = ?`
    ).get(occurrence.scan_id) as { project_id: string | null; target_id: string | null; target_origin: string; profile: string; safe_configuration_summary: string } | undefined;
    if (!scan) throw new FindingCommandError("RETEST_SOURCE_SCAN_MISSING", "The source scan is unavailable.", 409);
    const snapshot = this.database.db.prepare(
      "SELECT modules_json, limits_json, evidence_policy_json, browser_policy_summary_json, scope_summary_json, controlled_workflow_summary_json FROM scan_plan_snapshots WHERE scan_id = ?"
    ).get(occurrence.scan_id) as Record<string, string> | undefined;
    const summary = safeObject(scan.safe_configuration_summary);
    const studio = isObject(summary.studio) ? summary.studio : {};
    const authentication = isObject(studio.authentication) ? studio.authentication : { mode: "public" };
    const authMode = typeof authentication.mode === "string" ? authentication.mode : "public";
    const safeTargetId = matchingSavedTargetId(this.database, scan.target_id, scan.project_id, scan.target_origin);
    const targetReferenceWarning = scan.target_id && !safeTargetId
      ? "The historical saved-target reference no longer matches the scan origin and was not restored."
      : undefined;
    const relevantWorkflow = workflowForModule(finding.module);
    let reusableWorkflows: unknown[] = [];
    let workflowTemplateStatus: "RESTORED" | "NOT_CONFIGURED" | "VAULT_UNAVAILABLE" | "UNAVAILABLE" = "NOT_CONFIGURED";
    if (relevantWorkflow) {
      if (!this.retestTemplates?.available()) workflowTemplateStatus = "VAULT_UNAVAILABLE";
      else {
        const restored = this.retestTemplates.load(occurrence.scan_id);
        if (restored) {
          reusableWorkflows = restored.filter((workflow) => workflow.workflowId === relevantWorkflow);
          workflowTemplateStatus = reusableWorkflows.length > 0 ? "RESTORED" : "UNAVAILABLE";
        } else workflowTemplateStatus = "UNAVAILABLE";
      }
    }
    const context: FindingRetestContext = {
      findingId,
      sourceOccurrenceId: occurrence.id,
      sourceScanId: occurrence.scan_id,
      relevantModule: finding.module,
      ...(relevantWorkflow ? { relevantWorkflow } : {}),
      ...(occurrence.workflow_case_alias ? { relevantCase: occurrence.workflow_case_alias } : {}),
      purpose: `Retest of RC-FIND-${findingId.slice(0, 8)}`
    };
    return {
      context,
      projectId: scan.project_id,
      ...(safeTargetId ? { targetId: safeTargetId } : {}),
      target: scan.target_origin,
      profile: scan.profile,
      scope: isObject(studio.scope) ? studio.scope : snapshot ? safeObject(snapshot.scope_summary_json) : undefined,
      selectedModules: snapshot ? safeArray(safeJsonValue(snapshot.modules_json ?? "[]")).flatMap((item) => isObject(item) && typeof item.id === "string" ? [item.id] : []) : [finding.module],
      limits: snapshot ? safeObject(snapshot.limits_json) : {},
      browserPolicy: snapshot ? safeObject(snapshot.browser_policy_summary_json) : {},
      evidenceLevel: typeof studio.evidenceLevel === "string" ? studio.evidenceLevel : "normal",
      outputs: isObject(studio.outputs) ? studio.outputs : { json: true, markdown: true, html: true },
      historicalAuthenticationMode: authMode,
      freshCredentialsRequired: authMode !== "public" && !hasUsableSavedCredentialReference(authentication, this.database),
      savedCredentialReferences: usableSavedCredentialReferences(authentication, this.database),
      relevantWorkflowSummary: snapshot ? safeObject(snapshot.controlled_workflow_summary_json) : {},
      reusableWorkflows,
      historicalWorkflowConfigurationRetained: workflowTemplateStatus === "RESTORED",
      workflowTemplateStatus,
      warning: [workflowTemplateStatus === "RESTORED"
        ? "An encrypted, schema-validated workflow template was restored. Authentication secrets were not restored; review identifiers, scope, credentials, workflow, and case before previewing the current plan."
        : "No encrypted workflow template is available. Authentication secrets are never restored; review scope, credentials, workflow, and case before previewing the current plan.", targetReferenceWarning].filter(Boolean).join(" ")
    };
  }

  public recordRetestLaunch(input: { context: FindingRetestContext; newScanId: string; principal: DashboardPrincipal }): void {
    this.validateRetestContext(input.context);
    const now = nowIso();
    this.database.db.prepare(
      `INSERT INTO finding_retest_launches
       (id, finding_id, source_occurrence_id, source_scan_id, new_scan_id, retest_intent, created_by_user_id, created_at, launched_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(randomUUID(), input.context.findingId, input.context.sourceOccurrenceId, input.context.sourceScanId,
      input.newScanId, safeRequired(input.context.purpose, "Retest purpose is required.", 240),
      this.persistedUserId(input.principal.userId), now, now);
  }

  public validateRetestContext(context: FindingRetestContext): void {
    const finding = this.mutable(context.findingId);
    if (finding.latest_occurrence_id !== context.sourceOccurrenceId) {
      throw new FindingCommandError("RETEST_SOURCE_STALE", "The selected retest source is no longer the latest occurrence.", 409);
    }
    const occurrence = this.database.db.prepare("SELECT scan_id FROM finding_occurrences WHERE id = ? AND finding_id = ?")
      .get(context.sourceOccurrenceId, context.findingId) as { scan_id: string } | undefined;
    if (!occurrence || occurrence.scan_id !== context.sourceScanId || finding.module !== context.relevantModule) {
      throw new FindingCommandError("RETEST_CONTEXT_INVALID", "Retest context does not match the source finding.", 409);
    }
  }

  public review(input: {
    findingId: string;
    newStatus: ReviewStatus;
    reason?: string | undefined;
    note?: string | undefined;
    duplicateTargetFindingId?: string | undefined;
    expectedVersion: number;
    takeover?: boolean | undefined;
    principal: DashboardPrincipal;
    correlationId?: string | undefined;
    source?: "HUMAN" | "SYSTEM_REOPEN" | "IMPORT" | undefined;
  }): DashboardFindingSummary {
    const current = this.mutable(input.findingId);
    assertVersion(current, input.expectedVersion);
    const userId = this.persistedUserId(input.principal.userId);
    const ownedByAnother = current.human_review_status === "IN_REVIEW" && current.reviewer_user_id !== null && current.reviewer_user_id !== userId;
    if (ownedByAnother && !input.takeover) {
      throw new FindingCommandError("REVIEW_TAKEOVER_REQUIRED", "Another analyst is reviewing this finding. Confirm takeover before changing review state.", 409);
    }
    if (input.takeover && !ownedByAnother) {
      throw new FindingCommandError("REVIEW_TAKEOVER_INVALID", "Review takeover is only valid when another analyst owns the active review.", 409);
    }
    validateReviewTransition(current.human_review_status, input.newStatus, input);
    let canonicalId: string | null = null;
    if (input.newStatus === "DUPLICATE") {
      if (!input.duplicateTargetFindingId) throw new FindingCommandError("DUPLICATE_TARGET_REQUIRED", "Duplicate review requires a canonical finding.");
      canonicalId = this.canonicalDuplicateRoot(input.findingId, input.duplicateTargetFindingId);
    }
    const now = nowIso();
    this.database.transaction(() => {
      this.database.db.prepare(
        `INSERT INTO finding_reviews
         (id, finding_id, previous_review_status, new_review_status, reason, review_note,
          duplicate_target_finding_id, created_at, local_reviewer_label, source, user_id,
          correlation_id, safe_metadata_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(randomUUID(), input.findingId, current.human_review_status, input.newStatus,
        input.reason ? safeText(input.reason, 1_000) : null,
        input.note ? safeText(input.note, 4_000) : null,
        canonicalId, now, input.principal.login, input.source ?? "HUMAN", userId,
        input.correlationId ?? null, JSON.stringify({ occurrenceId: current.latest_occurrence_id, actorRole: input.principal.role, takeover: Boolean(input.takeover), previousReviewerUserId: input.takeover ? current.reviewer_user_id : undefined }));
      const result = this.database.db.prepare(
        `UPDATE findings SET human_review_status = ?, duplicate_of_finding_id = ?,
          reviewer_user_id = CASE WHEN ? = 'IN_REVIEW' OR ? THEN ? ELSE reviewer_user_id END,
          review_started_at = CASE WHEN ? = 'IN_REVIEW' OR ? THEN ? ELSE review_started_at END,
          new_occurrence_kind = CASE WHEN ? IN ('IN_REVIEW','CONFIRMED','REOPENED') THEN NULL ELSE new_occurrence_kind END,
          updated_at = ?, row_version = row_version + 1
         WHERE id = ? AND row_version = ?`
      ).run(input.newStatus, canonicalId, input.newStatus, input.takeover ? 1 : 0, userId, input.newStatus, input.takeover ? 1 : 0, now,
        input.newStatus, now, input.findingId, input.expectedVersion);
      if (result.changes !== 1) throw staleConflict();
    });
    this.refreshProofReadiness(input.findingId);
    return this.requiredSummary(input.findingId);
  }

  public remediation(input: {
    findingId: string;
    newState: RemediationStatus;
    assigneeUserId?: string | null | undefined;
    targetFixDate?: string | null | undefined;
    note?: string | undefined;
    expectedVersion: number;
    principal: DashboardPrincipal;
    correlationId?: string | undefined;
  }): DashboardFindingSummary {
    const current = this.mutable(input.findingId);
    assertVersion(current, input.expectedVersion);
    validateRemediationTransition(current.remediation_state_v2, input.newState, input);
    if (input.newState === "FIXED_VERIFIED") {
      throw new FindingCommandError("RETEST_VERIFICATION_REQUIRED", "Use retest verification or an owner override to mark a finding fixed verified.");
    }
    const assignee = input.assigneeUserId === undefined ? undefined : this.validAssignee(input.assigneeUserId);
    const now = nowIso();
    const userId = this.persistedUserId(input.principal.userId);
    this.database.transaction(() => {
      this.database.db.prepare(
        `INSERT INTO finding_remediation_history
         (id, finding_id, user_id, previous_state, new_state, assignee_user_id,
          target_fix_date, safe_note, owner_override, source, correlation_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 'HUMAN', ?, ?)`
      ).run(randomUUID(), input.findingId, userId, current.remediation_state_v2, input.newState,
        assignee === undefined ? null : assignee, input.targetFixDate ?? null,
        input.note ? safeText(input.note, 4_000) : null, input.correlationId ?? null, now);
      const result = this.database.db.prepare(
        `UPDATE findings SET remediation_state_v2 = ?, remediation_status = ?,
          assignee_user_id = CASE WHEN ? THEN ? ELSE assignee_user_id END,
          assigned_by_user_id = CASE WHEN ? THEN ? ELSE assigned_by_user_id END,
          assigned_at = CASE WHEN ? THEN ? ELSE assigned_at END,
          target_fix_date = CASE WHEN ? THEN ? ELSE target_fix_date END,
          updated_at = ?, row_version = row_version + 1
         WHERE id = ? AND row_version = ?`
      ).run(input.newState, legacyRemediation(input.newState), assignee !== undefined ? 1 : 0,
        assignee ?? null, assignee !== undefined ? 1 : 0, userId,
        assignee !== undefined ? 1 : 0, now, input.targetFixDate !== undefined ? 1 : 0,
        input.targetFixDate ?? null, now, input.findingId, input.expectedVersion);
      if (result.changes !== 1) throw staleConflict();
    });
    this.refreshProofReadiness(input.findingId);
    return this.requiredSummary(input.findingId);
  }

  public overrideSeverity(input: {
    findingId: string;
    severity: string;
    reason: string;
    expectedVersion: number;
    principal: DashboardPrincipal;
  }): DashboardFindingSummary {
    const current = this.mutable(input.findingId);
    assertVersion(current, input.expectedVersion);
    const severity = assertSeverity(input.severity);
    const reason = safeRequired(input.reason, "Severity override requires a reason.", 1_000);
    const now = nowIso();
    const result = this.database.db.prepare(
      `UPDATE findings SET effective_severity = ?, severity_override_reason = ?,
       severity_override_user_id = ?, severity_override_at = ?, updated_at = ?,
       row_version = row_version + 1 WHERE id = ? AND row_version = ?`
    ).run(severity, reason, this.persistedUserId(input.principal.userId), now, now,
      input.findingId, input.expectedVersion);
    if (result.changes !== 1) throw staleConflict();
    return this.requiredSummary(input.findingId);
  }

  public addNote(input: { findingId: string; text: string; principal: DashboardPrincipal }): string {
    this.mutable(input.findingId);
    const id = randomUUID();
    const now = nowIso();
    this.database.db.prepare(
      "INSERT INTO finding_notes (id, finding_id, user_id, safe_text, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(id, input.findingId, this.persistedUserId(input.principal.userId),
      safeRequired(input.text, "Note text is required.", findingNoteMaximum), now, now);
    return id;
  }

  public linkRetest(input: {
    findingId: string;
    scanId: string;
    expectedVersion: number;
    principal: DashboardPrincipal;
  }): { finding: DashboardFindingSummary; compatible: boolean; state: RetestStatus; reasons: string[] } {
    const finding = this.mutable(input.findingId);
    assertVersion(finding, input.expectedVersion);
    const compatibility = this.retestCompatibility(finding, input.scanId);
    const recurrence = this.database.db.prepare(
      "SELECT id FROM finding_occurrences WHERE finding_id = ? AND scan_id = ? LIMIT 1"
    ).get(input.findingId, input.scanId) as { id: string } | undefined;
    const state: RetestStatus = !compatibility.compatible
      ? "RETEST_INCONCLUSIVE"
      : recurrence ? "RETEST_FAILED" : "RETEST_PASSED";
    const id = randomUUID();
    const now = nowIso();
    const userId = this.persistedUserId(input.principal.userId);
    this.database.transaction(() => {
      this.database.db.prepare(
        `INSERT INTO finding_retests
         (id, finding_id, scan_id, occurrence_id, state, compatible,
          compatibility_reasons_json, linked_by_user_id, owner_override, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`
      ).run(id, input.findingId, input.scanId, recurrence?.id ?? null, state,
        compatibility.compatible ? 1 : 0, JSON.stringify(compatibility.reasons), userId, now, now);
      const result = this.database.db.prepare(
        `UPDATE findings SET retest_state = ?, retest_scan_id = ?, retest_occurrence_id = ?,
          retest_at = ?, updated_at = ?, row_version = row_version + 1
         WHERE id = ? AND row_version = ?`
      ).run(state, input.scanId, recurrence?.id ?? null, now, now,
        input.findingId, input.expectedVersion);
      if (result.changes !== 1) throw staleConflict();
    });
    return { finding: this.requiredSummary(input.findingId), compatible: compatibility.compatible, state, reasons: compatibility.reasons };
  }

  public verifyFixed(input: {
    findingId: string;
    reason: string;
    ownerOverride: boolean;
    expectedVersion: number;
    principal: DashboardPrincipal;
  }): DashboardFindingSummary {
    const finding = this.mutable(input.findingId);
    assertVersion(finding, input.expectedVersion);
    const reason = safeRequired(input.reason, "Verification requires a reason.", 1_000);
    const retest = this.database.db.prepare(
      "SELECT id, state, compatible FROM finding_retests WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1"
    ).get(input.findingId) as { id: string; state: RetestStatus; compatible: number } | undefined;
    if (input.ownerOverride && input.principal.role !== "OWNER") {
      throw new FindingCommandError("OWNER_OVERRIDE_FORBIDDEN", "Only an owner may override retest verification policy.", 403);
    }
    if (!input.ownerOverride && (!retest || retest.state !== "RETEST_PASSED" || retest.compatible !== 1)) {
      throw new FindingCommandError("COMPATIBLE_RETEST_REQUIRED", "Fixed verification requires a compatible passing retest.");
    }
    const now = nowIso();
    const userId = this.persistedUserId(input.principal.userId);
    this.database.transaction(() => {
      this.database.db.prepare(
        `INSERT INTO finding_remediation_history
         (id, finding_id, user_id, previous_state, new_state, safe_note,
          related_scan_id, owner_override, source, created_at)
         VALUES (?, ?, ?, ?, 'FIXED_VERIFIED', ?, ?, ?, 'HUMAN', ?)`
      ).run(randomUUID(), input.findingId, userId, finding.remediation_state_v2,
        reason, this.scanIdForRetest(retest?.id), input.ownerOverride ? 1 : 0, now);
      this.database.db.prepare(
        `INSERT INTO finding_reviews
         (id, finding_id, previous_review_status, new_review_status, reason,
          review_note, created_at, local_reviewer_label, source, user_id, safe_metadata_json)
         VALUES (?, ?, ?, 'RESOLVED', ?, ?, ?, ?, 'HUMAN', ?, ?)`
      ).run(randomUUID(), input.findingId, finding.human_review_status, reason,
        "Resolution verified through the remediation workflow.", now, input.principal.login,
        userId, JSON.stringify({ ownerOverride: input.ownerOverride }));
      const result = this.database.db.prepare(
        `UPDATE findings SET remediation_state_v2 = 'FIXED_VERIFIED',
          remediation_status = 'FIXED_VERIFIED', human_review_status = 'RESOLVED',
          verified_by_user_id = ?, verification_reason = ?, verification_owner_override = ?,
          updated_at = ?, row_version = row_version + 1
         WHERE id = ? AND row_version = ?`
      ).run(userId, reason, input.ownerOverride ? 1 : 0, now,
        input.findingId, input.expectedVersion);
      if (result.changes !== 1) throw staleConflict();
    });
    this.refreshProofReadiness(input.findingId);
    return this.requiredSummary(input.findingId);
  }

  public retestCandidates(findingId: string): unknown[] {
    const finding = this.mutable(findingId);
    return this.database.db.prepare(
      `SELECT s.id, s.completed_at, s.target_origin, s.profile, s.status,
              EXISTS(SELECT 1 FROM scan_module_executions m WHERE m.scan_id = s.id AND m.module_id = ? AND m.status = 'COMPLETED') AS relevant_module_completed
       FROM scans s WHERE s.deleted_at IS NULL AND s.status IN ('COMPLETED','IMPORTED')
       ORDER BY s.completed_at DESC LIMIT 100`
    ).all(finding.module);
  }

  public saveView(input: {
    id?: string | undefined;
    name: string;
    query: FindingQuery;
    columns: string[];
    isDefault: boolean;
    shared: boolean;
    expectedVersion?: number | undefined;
    principal: DashboardPrincipal;
  }): string {
    if (input.shared && input.principal.role !== "OWNER") {
      throw new FindingCommandError("SAVED_VIEW_SHARE_FORBIDDEN", "Only an owner may share a finding view installation-wide.", 403);
    }
    validateFindingQuery(input.query);
    const columns = safeColumns(input.columns);
    const id = input.id ?? randomUUID();
    const now = nowIso();
    const ownerId = this.persistedUserId(input.principal.userId);
    this.database.transaction(() => {
      if (input.isDefault) {
        if (ownerId) this.database.db.prepare("UPDATE saved_finding_views SET is_default = 0 WHERE owner_user_id = ?").run(ownerId);
        else this.database.db.prepare("UPDATE saved_finding_views SET is_default = 0 WHERE owner_user_id IS NULL").run();
      }
      if (input.id) {
        const existing = this.database.db.prepare("SELECT owner_user_id, shared_installation_wide, row_version FROM saved_finding_views WHERE id = ?")
          .get(id) as { owner_user_id: string | null; shared_installation_wide: number; row_version: number } | undefined;
        if (!existing) throw new FindingCommandError("SAVED_VIEW_NOT_FOUND", "Saved finding view not found.", 404);
        const owns = existing.owner_user_id === ownerId || (existing.owner_user_id === null && ownerId === null);
        if (!owns && input.principal.role !== "OWNER") throw new FindingCommandError("SAVED_VIEW_UPDATE_FORBIDDEN", "You do not own this finding view.", 403);
        if ((existing.shared_installation_wide || input.shared) && input.principal.role !== "OWNER") throw new FindingCommandError("SAVED_VIEW_SHARE_FORBIDDEN", "Only an owner may modify a shared finding view.", 403);
        if (input.expectedVersion === undefined || input.expectedVersion !== existing.row_version) throw new FindingCommandError("SAVED_VIEW_VERSION_CONFLICT", "This saved view changed after it was loaded.", 409);
        const result = this.database.db.prepare(
          `UPDATE saved_finding_views SET safe_name = ?, query_json = ?, columns_json = ?,
            is_default = ?, shared_installation_wide = ?, updated_at = ?, row_version = row_version + 1
           WHERE id = ? AND row_version = ?`
        ).run(safeRequired(input.name, "View name is required.", 120), JSON.stringify(input.query),
          JSON.stringify(columns), input.isDefault ? 1 : 0,
          input.shared ? 1 : 0, now, id, input.expectedVersion);
        if (result.changes !== 1) throw new FindingCommandError("SAVED_VIEW_VERSION_CONFLICT", "This saved view changed after it was loaded.", 409);
      } else {
        const duplicate = this.database.db.prepare("SELECT 1 FROM saved_finding_views WHERE owner_user_id IS ? AND lower(safe_name) = lower(?)")
          .get(ownerId, input.name.trim());
        if (duplicate) throw new FindingCommandError("SAVED_VIEW_NAME_DUPLICATE", "A saved view with this name already exists.", 409);
        this.database.db.prepare(
          `INSERT INTO saved_finding_views
           (id, owner_user_id, safe_name, query_json, columns_json, is_default,
            shared_installation_wide, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).run(id, ownerId, safeRequired(input.name, "View name is required.", 120),
          JSON.stringify(input.query), JSON.stringify(columns),
          input.isDefault ? 1 : 0, input.shared ? 1 : 0, now, now);
      }
    });
    return id;
  }

  public savedViews(principal: DashboardPrincipal): unknown[] {
    const userId = this.persistedUserId(principal.userId);
    return this.database.db.prepare(
      `SELECT id, owner_user_id, safe_name, query_json, columns_json, is_default,
              shared_installation_wide, row_version, created_at, updated_at
       FROM saved_finding_views
       WHERE shared_installation_wide = 1 OR owner_user_id = ? OR (owner_user_id IS NULL AND ? IS NULL)
       ORDER BY is_default DESC, updated_at DESC LIMIT 100`
    ).all(userId, userId);
  }

  public setDefaultView(id: string | null, principal: DashboardPrincipal): void {
    const userId = this.persistedUserId(principal.userId);
    this.database.transaction(() => {
      this.database.db.prepare("UPDATE saved_finding_views SET is_default = 0 WHERE owner_user_id IS ?").run(userId);
      if (!id) return;
      const result = this.database.db.prepare("UPDATE saved_finding_views SET is_default = 1, row_version = row_version + 1, updated_at = ? WHERE id = ? AND owner_user_id IS ?")
        .run(nowIso(), id, userId);
      if (result.changes !== 1) throw new FindingCommandError("SAVED_VIEW_DEFAULT_FORBIDDEN", "Only a personal view can be your default.", 403);
    });
  }

  public deleteView(id: string, principal: DashboardPrincipal): void {
    const userId = this.persistedUserId(principal.userId);
    const row = this.database.db.prepare(
      "SELECT owner_user_id, shared_installation_wide FROM saved_finding_views WHERE id = ?"
    ).get(id) as { owner_user_id: string | null; shared_installation_wide: number } | undefined;
    if (!row) throw new FindingCommandError("SAVED_VIEW_NOT_FOUND", "Saved finding view not found.", 404);
    if (row.shared_installation_wide && principal.role !== "OWNER") {
      throw new FindingCommandError("SAVED_VIEW_DELETE_FORBIDDEN", "Only an owner may delete a shared finding view.", 403);
    }
    if (row.owner_user_id !== userId && !(row.owner_user_id === null && userId === null) && principal.role !== "OWNER") {
      throw new FindingCommandError("SAVED_VIEW_DELETE_FORBIDDEN", "You do not own this finding view.", 403);
    }
    this.database.db.prepare("DELETE FROM saved_finding_views WHERE id = ?").run(id);
  }

  public bulkReview(input: {
    findingIds: string[];
    newStatus: Exclude<ReviewStatus, "DUPLICATE" | "RESOLVED" | "REOPENED">;
    reason?: string | undefined;
    note?: string | undefined;
    versions: Record<string, number>;
    principal: DashboardPrincipal;
    correlationId?: string | undefined;
  }): { succeeded: string[]; failed: Array<{ findingId: string; reason: string }> } {
    const ids = uniqueBoundedIds(input.findingIds);
    const succeeded: string[] = [];
    const failed: Array<{ findingId: string; reason: string }> = [];
    for (const findingId of ids) {
      try {
        this.review({ findingId, newStatus: input.newStatus,
          ...(input.reason ? { reason: input.reason } : {}),
          ...(input.note ? { note: input.note } : {}),
          expectedVersion: requiredVersion(input.versions, findingId),
          principal: input.principal,
          ...(input.correlationId ? { correlationId: input.correlationId } : {}) });
        succeeded.push(findingId);
      } catch (error) {
        failed.push({ findingId, reason: error instanceof Error ? error.message : "Bulk review failed." });
      }
    }
    return { succeeded, failed };
  }

  public bulkRemediation(input: {
    findingIds: string[];
    newState: Exclude<RemediationStatus, "FIXED_VERIFIED">;
    assigneeUserId?: string | null | undefined;
    targetFixDate?: string | null | undefined;
    note?: string | undefined;
    versions: Record<string, number>;
    principal: DashboardPrincipal;
    correlationId?: string | undefined;
  }): { succeeded: string[]; failed: Array<{ findingId: string; reason: string }> } {
    const ids = uniqueBoundedIds(input.findingIds);
    const succeeded: string[] = [];
    const failed: Array<{ findingId: string; reason: string }> = [];
    for (const findingId of ids) {
      try {
        this.remediation({ findingId, newState: input.newState,
          ...(input.assigneeUserId !== undefined ? { assigneeUserId: input.assigneeUserId } : {}),
          ...(input.targetFixDate !== undefined ? { targetFixDate: input.targetFixDate } : {}),
          ...(input.note ? { note: input.note } : {}),
          expectedVersion: requiredVersion(input.versions, findingId), principal: input.principal,
          ...(input.correlationId ? { correlationId: input.correlationId } : {}) });
        succeeded.push(findingId);
      } catch (error) {
        failed.push({ findingId, reason: error instanceof Error ? error.message : "Bulk remediation failed." });
      }
    }
    return { succeeded, failed };
  }

  public bulkNote(input: {
    findingIds: string[];
    text: string;
    principal: DashboardPrincipal;
  }): { succeeded: string[]; failed: Array<{ findingId: string; reason: string }> } {
    const ids = uniqueBoundedIds(input.findingIds);
    const succeeded: string[] = [];
    const failed: Array<{ findingId: string; reason: string }> = [];
    for (const findingId of ids) {
      try {
        this.addNote({ findingId, text: input.text, principal: input.principal });
        succeeded.push(findingId);
      } catch (error) {
        failed.push({ findingId, reason: error instanceof Error ? error.message : "Bulk note failed." });
      }
    }
    return { succeeded, failed };
  }

  public intelligence(filter: { projectId?: string; targetId?: string }): unknown {
    const clauses = ["f.archived_at IS NULL"];
    const values: SqlValue[] = [];
    if (filter.projectId) { clauses.push("f.project_id = ?"); values.push(filter.projectId); }
    if (filter.targetId) { clauses.push("f.target_id = ?"); values.push(filter.targetId); }
    const where = clauses.join(" AND ");
    const rows = this.database.db.prepare(
      `SELECT human_review_status AS review, remediation_state_v2 AS remediation,
              COALESCE(effective_severity, current_scanner_severity) AS severity,
              COUNT(*) AS count
       FROM findings f WHERE ${where}
       GROUP BY human_review_status, remediation_state_v2, COALESCE(effective_severity, current_scanner_severity)`
    ).all(...values) as Array<{ review: string; remediation: string; severity: string; count: number }>;
    const falsePositive = sumRows(rows, (row) => row.review === "FALSE_POSITIVE");
    const byModule = this.database.db.prepare(`SELECT f.module AS label, COUNT(*) AS count FROM findings f WHERE ${where} GROUP BY f.module ORDER BY count DESC, label ASC LIMIT 30`).all(...values);
    const byTarget = this.database.db.prepare(`SELECT COALESCE(t.display_name, f.target_identity) AS label, f.target_id AS id, COUNT(*) AS count FROM findings f LEFT JOIN targets t ON t.id = f.target_id WHERE ${where} GROUP BY f.target_id, label ORDER BY count DESC, label ASC LIMIT 30`).all(...values);
    const recentOccurrences = this.database.db.prepare(`SELECT o.id, o.finding_id, o.scan_id, o.title, o.severity, o.safe_endpoint, o.created_at FROM finding_occurrences o JOIN findings f ON f.id = o.finding_id WHERE ${where} ORDER BY o.created_at DESC LIMIT 12`).all(...values);
    const recentReviews = this.database.db.prepare(`SELECT r.id, r.finding_id, r.new_review_status, r.created_at, u.login AS actor_label FROM finding_reviews r JOIN findings f ON f.id = r.finding_id LEFT JOIN dashboard_users u ON u.id = r.user_id WHERE ${where} ORDER BY r.created_at DESC LIMIT 12`).all(...values);
    const firstLast = this.database.db.prepare(`SELECT MIN(f.first_seen_at) AS first_seen_at, MAX(f.last_seen_at) AS last_seen_at FROM findings f WHERE ${where}`).get(...values);
    return {
      totalOpen: rows.filter((row) => row.remediation !== "FIXED_VERIFIED").reduce((sum, row) => sum + row.count, 0),
      unreviewed: sumRows(rows, (row) => row.review === "UNREVIEWED"),
      confirmed: sumRows(rows, (row) => row.review === "CONFIRMED"),
      reopened: sumRows(rows, (row) => row.review === "REOPENED"),
      acceptedRisk: sumRows(rows, (row) => row.review === "ACCEPTED_RISK"),
      falsePositive,
      resolved: sumRows(rows, (row) => row.review === "RESOLVED"),
      fixedPendingRetest: sumRows(rows, (row) => row.remediation === "FIXED_PENDING_RETEST"),
      fixedVerified: sumRows(rows, (row) => row.remediation === "FIXED_VERIFIED"),
      severity: Object.fromEntries(["Critical", "High", "Medium", "Low", "Info"].map((severity) => [severity, sumRows(rows, (row) => row.severity === severity)])),
      remediation: Object.fromEntries(["OPEN", "ASSIGNED", "FIX_IN_PROGRESS", "FIXED_PENDING_RETEST", "FIXED_VERIFIED", "WONT_FIX"].map((state) => [state, sumRows(rows, (row) => row.remediation === state)])),
      byModule,
      byTarget,
      recentOccurrences,
      recentReviews,
      retestNeeded: this.list({ ...filter, remediationStatus: "FIXED_PENDING_RETEST", pageSize: 12 }).findings,
      proofReady: this.list({ ...filter, proofReadiness: "READY", pageSize: 12 }).findings,
      firstLast
    };
  }

  public refreshProofReadiness(findingId: string): ProofReadinessStatus {
    const row = this.database.db.prepare(
      `SELECT human_review_status,
              EXISTS(SELECT 1 FROM evidence_records e JOIN finding_occurrences o ON o.id = e.finding_occurrence_id WHERE o.finding_id = findings.id) AS has_evidence,
              EXISTS(SELECT 1 FROM proof_pack_findings p WHERE p.finding_id = findings.id) AS in_pack
       FROM findings WHERE id = ?`
    ).get(findingId) as { human_review_status: ReviewStatus; has_evidence: number; in_pack: number } | undefined;
    if (!row) throw new FindingCommandError("FINDING_NOT_FOUND", "Finding not found.", 404);
    const latest = this.database.db.prepare("SELECT id, finding_source_json FROM finding_occurrences WHERE finding_id = ? ORDER BY (id = (SELECT latest_occurrence_id FROM findings WHERE findings.id = finding_occurrences.finding_id)) DESC, created_at DESC, id DESC LIMIT 1").get(findingId) as { id: string; finding_source_json: string } | undefined;
    const assistedNeedsReview = latest && (JSON.parse(latest.finding_source_json) as { workflow?: unknown }).workflow && !hasOccurrenceReview(this.database, findingId, latest.id, "CONFIRMED");
    const readiness: ProofReadinessStatus = assistedNeedsReview ? "MISSING_REVIEW" : row.in_pack
      ? "IN_PROOF_PACK"
      : row.human_review_status !== "CONFIRMED"
        ? "MISSING_REVIEW"
        : row.has_evidence ? "READY" : "MISSING_EVIDENCE";
    this.database.db.prepare("UPDATE findings SET proof_readiness = ? WHERE id = ?").run(readiness, findingId);
    return readiness;
  }

  private mutable(id: string): MutableFindingRow {
    const row = this.database.db.prepare(
      `SELECT id, target_identity, module, human_review_status, remediation_state_v2,
              duplicate_of_finding_id, row_version, latest_occurrence_id, proof_readiness,
              reviewer_user_id, review_started_at
       FROM findings WHERE id = ? AND archived_at IS NULL`
    ).get(id) as MutableFindingRow | undefined;
    if (!row) throw new FindingCommandError("FINDING_NOT_FOUND", "Finding not found.", 404);
    return row;
  }

  private requiredSummary(id: string): DashboardFindingSummary {
    const row = this.database.db.prepare(
      `SELECT f.*, p.name AS project_name, t.display_name AS target_name, u.login AS assignee_label,
              reviewer.login AS reviewer_label
       FROM findings f
       LEFT JOIN projects p ON p.id = f.project_id
       LEFT JOIN targets t ON t.id = f.target_id
       LEFT JOIN dashboard_users u ON u.id = f.assignee_user_id
       LEFT JOIN dashboard_users reviewer ON reviewer.id = f.reviewer_user_id
       WHERE f.id = ?`
    ).get(id) as FindingRow | undefined;
    if (!row) throw new FindingCommandError("FINDING_NOT_FOUND", "Finding not found.", 404);
    return findingSummary(row);
  }

  private canonicalDuplicateRoot(findingId: string, requestedId: string): string {
    if (findingId === requestedId) throw new FindingCommandError("DUPLICATE_SELF", "A finding cannot duplicate itself.");
    let cursor = requestedId;
    const seen = new Set([findingId]);
    for (let depth = 0; depth < 100; depth += 1) {
      if (seen.has(cursor)) throw new FindingCommandError("DUPLICATE_CYCLE", "Duplicate relationship would create a cycle.");
      seen.add(cursor);
      const row = this.database.db.prepare(
        "SELECT duplicate_of_finding_id FROM findings WHERE id = ? AND archived_at IS NULL"
      ).get(cursor) as { duplicate_of_finding_id: string | null } | undefined;
      if (!row) throw new FindingCommandError("DUPLICATE_TARGET_NOT_FOUND", "Canonical finding not found.");
      if (!row.duplicate_of_finding_id) return cursor;
      cursor = row.duplicate_of_finding_id;
    }
    throw new FindingCommandError("DUPLICATE_CYCLE", "Duplicate relationship is too deep or cyclic.");
  }

  private validAssignee(userId: string | null): string | null {
    if (userId === null) return null;
    const row = this.database.db.prepare(
      "SELECT id FROM dashboard_users WHERE id = ? AND enabled = 1 AND role IN ('OWNER','ANALYST')"
    ).get(userId) as { id: string } | undefined;
    if (!row) throw new FindingCommandError("ASSIGNEE_INVALID", "Assignee must be an enabled owner or analyst.");
    return row.id;
  }

  private retestCompatibility(finding: MutableFindingRow, scanId: string): { compatible: boolean; reasons: string[] } {
    if (!finding.latest_occurrence_id) return { compatible: false, reasons: ["The finding has no source occurrence for coverage analysis."] };
    const occurrence = this.database.db.prepare(`SELECT id, finding_id, scan_id, module, safe_endpoint,
      safe_actor_relationship, safe_tenant_or_role_boundary, safe_state_boundary, workflow_case_alias,
      coverage_reference_json, source_kind FROM finding_occurrences WHERE id = ?`).get(finding.latest_occurrence_id) as any;
    if (!occurrence) return { compatible: false, reasons: ["The finding source occurrence is unavailable."] };
    try {
      const coverage = this.comparisonCoverage.evaluateFinding(occurrence.scan_id, scanId, occurrence);
      return { compatible: coverage.disposition === "ADEQUATE", reasons: coverage.disposition === "ADEQUATE" ? [] : [`${coverage.reasonCode}: ${coverage.explanation}`] };
    } catch (error) {
      if (error instanceof Error && /was not found/.test(error.message)) throw new FindingCommandError("RETEST_SCAN_NOT_FOUND", "Retest scan not found.", 404);
      throw error;
    }
  }

  private persistedUserId(userId: string): string | null {
    const row = this.database.db.prepare("SELECT id FROM dashboard_users WHERE id = ?").get(userId) as { id: string } | undefined;
    return row?.id ?? null;
  }

  private scanIdForRetest(retestId: string | undefined): string | null {
    if (!retestId) return null;
    const row = this.database.db.prepare("SELECT scan_id FROM finding_retests WHERE id = ?").get(retestId) as { scan_id: string } | undefined;
    return row?.scan_id ?? null;
  }
}

function findingWhere(query: FindingQuery): { where: string; values: SqlValue[] } {
  validateFindingQuery(query);
  const clauses = ["f.archived_at IS NULL"];
  const values: SqlValue[] = [];
  if (query.search) {
    clauses.push("(f.id LIKE ? OR f.canonical_title LIKE ? OR f.safe_endpoint_identity LIKE ? OR f.finding_category LIKE ? OR f.module LIKE ? OR EXISTS(SELECT 1 FROM projects sp WHERE sp.id = f.project_id AND sp.name LIKE ?) OR EXISTS(SELECT 1 FROM targets st WHERE st.id = f.target_id AND st.display_name LIKE ?))");
    const search = `%${clamp(query.search, 160)}%`;
    values.push(search, search, search, search, search, search, search);
  }
  addEquality(clauses, values, "f.project_id", query.projectId);
  addEquality(clauses, values, "f.target_id", query.targetId);
  addEquality(clauses, values, "f.module", query.module);
  if (query.scanId) { clauses.push("EXISTS(SELECT 1 FROM finding_occurrences scan_occurrence WHERE scan_occurrence.finding_id = f.id AND scan_occurrence.scan_id = ?)"); values.push(query.scanId); }
  addEquality(clauses, values, "f.finding_category", query.category);
  if (query.severity === "High") clauses.push("COALESCE(f.effective_severity, f.current_scanner_severity) IN ('Critical','High')");
  else addEquality(clauses, values, "COALESCE(f.effective_severity, f.current_scanner_severity)", query.severity);
  addEquality(clauses, values, "f.current_scanner_confidence", query.confidence);
  addEquality(clauses, values, "f.human_review_status", query.reviewStatus);
  addEquality(clauses, values, "f.remediation_state_v2", query.remediationStatus);
  addEquality(clauses, values, "f.assignee_user_id", query.assigneeUserId);
  addEquality(clauses, values, "f.retest_state", query.retestStatus);
  addEquality(clauses, values, "f.proof_readiness", query.proofReadiness);
  addRange(clauses, values, "f.first_seen_at", query.firstSeenFrom, query.firstSeenTo);
  addRange(clauses, values, "f.last_seen_at", query.lastSeenFrom, query.lastSeenTo);
  if (query.newOccurrence) clauses.push("f.new_occurrence_kind IS NOT NULL");
  if (query.reopened) clauses.push("f.human_review_status = 'REOPENED'");
  if (query.sourceKind) clauses.push("EXISTS(SELECT 1 FROM finding_occurrences so WHERE so.finding_id = f.id AND so.source_kind = ?)");
  if (query.sourceKind) values.push(query.sourceKind);
  if (query.evidence === "HAS_EVIDENCE") clauses.push("EXISTS(SELECT 1 FROM evidence_records e JOIN finding_occurrences eo ON eo.id = e.finding_occurrence_id WHERE eo.finding_id = f.id)");
  if (query.evidence === "MISSING_EVIDENCE") clauses.push("NOT EXISTS(SELECT 1 FROM evidence_records e JOIN finding_occurrences eo ON eo.id = e.finding_occurrence_id WHERE eo.finding_id = f.id)");
  return { where: `WHERE ${clauses.join(" AND ")}`, values };
}

function validateFindingQuery(query: FindingQuery): void {
  if (query.page !== undefined && (!Number.isInteger(query.page) || query.page < 1)) throw new FindingCommandError("FINDING_PAGE_INVALID", "Page must be a positive integer.");
  if (query.pageSize !== undefined && (!Number.isInteger(query.pageSize) || query.pageSize < 1)) throw new FindingCommandError("FINDING_PAGE_SIZE_INVALID", "Page size must be a positive integer.");
  if (query.sort && !findingSorts.includes(query.sort)) throw new FindingCommandError("FINDING_SORT_INVALID", "Unsupported finding sort.");
}

const findingSorts: readonly FindingSort[] = ["severity_desc", "confidence_desc", "first_seen_desc", "last_seen_desc", "occurrences_desc", "review", "remediation", "target", "project"];

function findingSortSql(sort: FindingSort | undefined): string {
  switch (sort) {
    case "severity_desc": return "CASE COALESCE(f.effective_severity, f.current_scanner_severity) WHEN 'Critical' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 2 ELSE 1 END DESC, f.last_seen_at DESC, f.id ASC";
    case "confidence_desc": return "CASE f.current_scanner_confidence WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, f.last_seen_at DESC, f.id ASC";
    case "first_seen_desc": return "f.first_seen_at DESC, f.id ASC";
    case "occurrences_desc": return "f.occurrence_count DESC, f.last_seen_at DESC, f.id ASC";
    case "review": return "f.human_review_status ASC, f.last_seen_at DESC, f.id ASC";
    case "remediation": return "f.remediation_state_v2 ASC, f.last_seen_at DESC, f.id ASC";
    case "target": return "COALESCE(t.display_name, f.target_identity) ASC, f.id ASC";
    case "project": return "COALESCE(p.name, '') ASC, f.last_seen_at DESC, f.id ASC";
    case "last_seen_desc":
    case undefined: return "f.last_seen_at DESC, f.id ASC";
  }
}

function findingSummary(row: FindingRow): DashboardFindingSummary {
  return {
    id: row.id,
    title: row.canonical_title,
    module: row.module,
    category: row.finding_category,
    endpoint: row.safe_endpoint_identity,
    method: row.http_method,
    severity: row.current_scanner_severity,
    effectiveSeverity: row.effective_severity ?? row.current_scanner_severity,
    confidence: row.current_scanner_confidence,
    reviewStatus: row.human_review_status,
    remediationStatus: row.remediation_state_v2,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    occurrenceCount: row.occurrence_count,
    ...(row.project_id ? { projectId: row.project_id } : {}),
    ...(row.project_name ? { projectName: row.project_name } : {}),
    ...(row.target_id ? { targetId: row.target_id } : {}),
    ...(row.target_name ? { targetName: row.target_name } : {}),
    ...(row.assignee_user_id ? { assigneeUserId: row.assignee_user_id } : {}),
    ...(row.assignee_label ? { assigneeLabel: row.assignee_label } : {}),
    ...(row.reviewer_user_id ? { reviewerUserId: row.reviewer_user_id } : {}),
    ...(row.reviewer_label ? { reviewerLabel: row.reviewer_label } : {}),
    ...(row.review_started_at ? { reviewStartedAt: row.review_started_at } : {}),
    retestStatus: row.retest_state,
    proofReadiness: row.proof_readiness,
    ...(row.new_occurrence_kind ? { newOccurrenceKind: row.new_occurrence_kind } : {}),
    rowVersion: row.row_version
  };
}

function validateReviewTransition(previous: ReviewStatus, next: ReviewStatus, input: { reason?: string | undefined; note?: string | undefined }): void {
  if (previous === "IN_REVIEW" && next === "IN_REVIEW") return;
  const allowed: Record<ReviewStatus, readonly ReviewStatus[]> = {
    UNREVIEWED: ["IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE"],
    IN_REVIEW: ["UNREVIEWED", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE"],
    CONFIRMED: ["IN_REVIEW", "ACCEPTED_RISK", "DUPLICATE"],
    FALSE_POSITIVE: ["IN_REVIEW", "CONFIRMED", "DUPLICATE"],
    ACCEPTED_RISK: ["IN_REVIEW", "CONFIRMED"],
    DUPLICATE: ["IN_REVIEW", "CONFIRMED"],
    RESOLVED: ["REOPENED", "IN_REVIEW"],
    REOPENED: ["IN_REVIEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DUPLICATE"]
  };
  if (!allowed[previous].includes(next)) throw new FindingCommandError("REVIEW_TRANSITION_INVALID", `Invalid review transition from ${previous} to ${next}.`);
  if (["FALSE_POSITIVE", "ACCEPTED_RISK", "REOPENED"].includes(next) && !input.reason?.trim()) {
    throw new FindingCommandError("REVIEW_REASON_REQUIRED", `${reviewLabel(next)} requires a reason.`);
  }
}

function validateRemediationTransition(previous: RemediationStatus, next: RemediationStatus, input: { note?: string | undefined; assigneeUserId?: string | null | undefined }): void {
  const allowed: Record<RemediationStatus, readonly RemediationStatus[]> = {
    OPEN: ["ASSIGNED", "FIX_IN_PROGRESS", "WONT_FIX"],
    ASSIGNED: ["OPEN", "FIX_IN_PROGRESS", "WONT_FIX"],
    FIX_IN_PROGRESS: ["OPEN", "ASSIGNED", "FIXED_PENDING_RETEST", "WONT_FIX"],
    FIXED_PENDING_RETEST: ["FIX_IN_PROGRESS", "OPEN"],
    FIXED_VERIFIED: ["OPEN"],
    WONT_FIX: ["OPEN", "ASSIGNED"]
  };
  if (!allowed[previous].includes(next)) throw new FindingCommandError("REMEDIATION_TRANSITION_INVALID", `Invalid remediation transition from ${previous} to ${next}.`);
  if (next === "ASSIGNED" && !input.assigneeUserId) throw new FindingCommandError("ASSIGNEE_REQUIRED", "Assigned remediation requires an owner or analyst.");
  if (next === "WONT_FIX" && !input.note?.trim()) throw new FindingCommandError("REMEDIATION_REASON_REQUIRED", "Won't fix requires a reason.");
}

function assertVersion(row: { row_version: number }, expected: number): void {
  if (row.row_version !== expected) throw staleConflict();
}

function staleConflict(): FindingCommandError {
  return new FindingCommandError("FINDING_VERSION_CONFLICT", "This finding changed after it was loaded. Refresh and reapply the action.", 409);
}

function safeText(value: string, maximum: number): string {
  const trimmed = value.trim();
  if (/\b(?:bearer|basic)\s+[a-z0-9._~+\/-]{8,}|(?:authorization|cookie|token|password|secret)\s*[:=]\s*\S+/i.test(trimmed)) {
    throw new FindingCommandError("SENSITIVE_TEXT_REJECTED", "Text appears to contain authentication or secret material. Remove it before saving.");
  }
  return clamp(trimmed, maximum);
}

function safeRequired(value: string, message: string, maximum: number): string {
  if (!value.trim()) throw new FindingCommandError("SAFE_TEXT_REQUIRED", message);
  if (value.length > maximum) throw new FindingCommandError("SAFE_TEXT_TOO_LARGE", `Text must not exceed ${maximum} characters.`);
  return safeText(value, maximum);
}

function safeNullableText(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function safeColumns(columns: string[]): string[] {
  const allowed = new Set(["severity", "confidence", "review", "remediation", "title", "project", "target", "module", "category", "endpoint", "firstSeen", "lastSeen", "occurrences", "assignee", "retest", "proof", "newOccurrence"]);
  const invalid = columns.find((column) => !allowed.has(column));
  if (invalid) throw new FindingCommandError("SAVED_VIEW_COLUMN_INVALID", `Unsupported finding column: ${invalid}.`);
  const result = [...new Set(columns)].slice(0, allowed.size);
  if (!result.includes("title")) throw new FindingCommandError("SAVED_VIEW_TITLE_REQUIRED", "The title column must remain visible.");
  return result;
}

function uniqueBoundedIds(ids: string[]): string[] {
  const unique = [...new Set(ids)];
  if (unique.length === 0) throw new FindingCommandError("BULK_FINDINGS_REQUIRED", "Select at least one finding.");
  if (unique.length > findingBulkMaximum) throw new FindingCommandError("BULK_LIMIT_EXCEEDED", `Bulk actions are limited to ${findingBulkMaximum} findings.`);
  return unique;
}

function requiredVersion(versions: Record<string, number>, findingId: string): number {
  const version = versions[findingId];
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) throw new FindingCommandError("FINDING_VERSION_REQUIRED", `A row version is required for finding ${findingId.slice(0, 8)}.`);
  return version;
}

function addEquality(clauses: string[], values: SqlValue[], column: string, value: string | undefined): void {
  if (value) { clauses.push(`${column} = ?`); values.push(value); }
}

function addRange(clauses: string[], values: SqlValue[], column: string, from: string | undefined, to: string | undefined): void {
  if (from) { clauses.push(`${column} >= ?`); values.push(from); }
  if (to) { clauses.push(`${column} <= ?`); values.push(to); }
}

function legacyRemediation(state: RemediationStatus): Exclude<RemediationStatus, "ASSIGNED"> {
  return state === "ASSIGNED" ? "OPEN" : state;
}

function assertSeverity(value: string): string {
  if (!["Critical", "High", "Medium", "Low", "Info"].includes(value)) throw new FindingCommandError("SEVERITY_INVALID", "Unsupported severity.");
  return value;
}

function reviewLabel(value: ReviewStatus): string {
  return value.toLowerCase().replaceAll("_", " ");
}

interface OccurrenceRow {
  id: string;
  severity: string;
  confidence: string;
  safe_endpoint: string;
  evidence_summary: string;
  safe_actor_relationship: string | null;
  created_at: string;
}

function occurrenceDifferences(rows: OccurrenceRow[]): unknown[] {
  const differences: unknown[] = [];
  for (let index = 0; index < rows.length - 1; index += 1) {
    const current = rows[index]!;
    const previous = rows[index + 1]!;
    const changed: string[] = [];
    if (current.severity !== previous.severity) changed.push(`Severity ${previous.severity} -> ${current.severity}`);
    if (current.confidence !== previous.confidence) changed.push(`Confidence ${previous.confidence} -> ${current.confidence}`);
    if (current.safe_endpoint !== previous.safe_endpoint) changed.push("Endpoint representation changed");
    if (current.evidence_summary !== previous.evidence_summary) changed.push("Evidence summary changed");
    if (current.safe_actor_relationship !== previous.safe_actor_relationship) changed.push("Actor result changed");
    differences.push({ currentOccurrenceId: current.id, previousOccurrenceId: previous.id, changed });
  }
  return differences;
}

function sumRows<T extends { count: number }>(rows: T[], predicate: (row: T) => boolean): number {
  return rows.filter(predicate).reduce((sum, row) => sum + row.count, 0);
}

function safeJsonValue(value: string): unknown {
  try { return JSON.parse(value) as unknown; } catch { return undefined; }
}

function safeObject(value: string | unknown): Record<string, unknown> {
  const parsed = typeof value === "string" ? safeJsonValue(value) : value;
  return isObject(parsed) ? parsed : {};
}

function safeArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function matchingSavedTargetId(database: DashboardDatabase, targetId: string | null, projectId: string | null, targetOrigin: string): string | undefined {
  if (!targetId) return undefined;
  const target = database.db.prepare("SELECT project_id, base_origin FROM targets WHERE id = ? AND archived_at IS NULL").get(targetId) as { project_id: string | null; base_origin: string } | undefined;
  if (!target || (projectId && target.project_id !== projectId)) return undefined;
  try {
    return new URL(target.base_origin).origin === new URL(targetOrigin).origin ? targetId : undefined;
  } catch {
    return undefined;
  }
}

function workflowForModule(moduleId: string): string | undefined {
  const workflows: Record<string, string> = {
    "object-pair-testing": "object-pair",
    "field-exposure-testing": "field-exposure",
    "authorization-matrix-testing": "authorization-matrix",
    "equivalent-route-testing": "equivalent-route",
    "collection-authorization-testing": "collection-authorization",
    "bulk-authorization-testing": "bulk-authorization",
    "file-authorization-testing": "file-authorization"
  };
  return workflows[moduleId];
}

function usableSavedCredentialReferences(authentication: Record<string, unknown>, database: DashboardDatabase): string[] {
  const references = [authentication.primary, authentication.accountA, authentication.accountB]
    .flatMap((value) => isObject(value) && value.source === "saved" && typeof value.credentialProfileId === "string" ? [value.credentialProfileId] : []);
  return references.filter((id) => Boolean(database.db.prepare("SELECT 1 FROM credential_profiles WHERE id = ? AND enabled = 1 AND deleted_at IS NULL").get(id)));
}

function hasUsableSavedCredentialReference(authentication: Record<string, unknown>, database: DashboardDatabase): boolean {
  const mode = authentication.mode;
  const count = usableSavedCredentialReferences(authentication, database).length;
  return mode === "primary" ? count === 1 : mode === "account-pair" ? count === 2 : mode === "public";
}
