import { randomUUID } from "node:crypto";
import type { DashboardDatabase } from "./DashboardDatabase.js";
import { clamp, nowIso } from "./DashboardDatabase.js";
import type { DashboardFindingSummary, DashboardScanSource, DashboardScanStatus, DashboardScanSummary, ModuleExecutionStatus, ReviewStatus } from "../types/DashboardTypes.js";
import { FindingCommandCenterService } from "../findings/FindingCommandCenterService.js";

export interface ScanListFilters {
  search?: string | undefined;
  status?: DashboardScanStatus | undefined;
  profile?: string | undefined;
  target?: string | undefined;
  projectId?: string | undefined;
  targetId?: string | undefined;
  sort?: "created_desc" | "created_asc" | "status" | "target" | undefined;
  offset?: number | undefined;
}

export interface FindingListFilters {
  search?: string | undefined;
  reviewStatus?: ReviewStatus | undefined;
  severity?: string | undefined;
  confidence?: string | undefined;
  module?: string | undefined;
  category?: string | undefined;
  sort?: "last_seen_desc" | "first_seen_desc" | "severity" | "title" | undefined;
  offset?: number | undefined;
}

export interface ProjectSummary {
  id: string;
  name: string;
  description?: string;
  tags: string[];
  defaultProfile?: string;
  defaultScope: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
  openFindingCount: number;
  targetCount: number;
  scanCount: number;
  archived: boolean;
  rowVersion: number;
}

export interface TargetSummary {
  id: string;
  projectId?: string;
  displayName: string;
  baseOrigin: string;
  description?: string;
  tags: string[];
  classification: string;
  authorizationType: string;
  authorizationSummary: string;
  approvedScope: Record<string, unknown>;
  productionEnabled: boolean;
  defaultProfile?: string;
  createdAt: string;
  updatedAt: string;
  openFindingCount: number;
  scanCount: number;
  defaultConfigurationId?: string;
  defaultCredentialProfileId?: string;
  defaultEvidenceLevel?: string;
  defaultAuthTemplate: Record<string, unknown>;
  archived: boolean;
  rowVersion: number;
}

export class ProjectRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public list(search?: string, includeArchived = false): ProjectSummary[] {
    const archived = includeArchived ? "1 = 1" : "archived_at IS NULL";
    const rows = search
      ? this.database.db.prepare(`SELECT * FROM projects WHERE ${archived} AND (name LIKE ? OR description LIKE ?) ORDER BY updated_at DESC LIMIT 100`).all(`%${search}%`, `%${search}%`)
      : this.database.db.prepare(`SELECT * FROM projects WHERE ${archived} ORDER BY updated_at DESC LIMIT 100`).all();
    return (rows as DbProjectRow[]).map((row) => projectFromRow(this.database, row));
  }

  public get(id: string, includeArchived = false): ProjectSummary | undefined {
    const row = this.database.db.prepare(`SELECT * FROM projects WHERE id = ? ${includeArchived ? "" : "AND archived_at IS NULL"}`).get(id) as DbProjectRow | undefined;
    return row ? projectFromRow(this.database, row) : undefined;
  }

  public create(input: { name: string; description?: string | undefined; tags: string[]; defaultProfile?: string | undefined; defaultScope: Record<string, unknown>; createdBy?: string | undefined }): string {
    const id = randomUUID();
    const now = nowIso();
    this.database.db
      .prepare(
        "INSERT INTO projects (id, name, description, tags_json, default_profile, default_scope_json, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .run(id, clamp(input.name, 160), input.description ? clamp(input.description, 2000) : null, JSON.stringify(input.tags), input.defaultProfile ?? null, JSON.stringify(input.defaultScope), input.createdBy ?? null, now, now);
    return id;
  }

  public update(id: string, input: { name: string; description?: string | undefined; tags: string[]; defaultProfile?: string | undefined; defaultScope: Record<string, unknown>; expectedVersion?: number | undefined }): void {
    const result = this.database.db
      .prepare(`UPDATE projects SET name = ?, description = ?, tags_json = ?, default_profile = ?, default_scope_json = ?, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND archived_at IS NULL ${input.expectedVersion === undefined ? "" : "AND row_version = ?"}`)
      .run(clamp(input.name, 160), input.description ? clamp(input.description, 2000) : null, JSON.stringify(input.tags), input.defaultProfile ?? null, JSON.stringify(input.defaultScope), nowIso(), id, ...(input.expectedVersion === undefined ? [] : [input.expectedVersion]));
    if (result.changes !== 1) throw new Error("PROJECT_CONFLICT: Project changed or is unavailable.");
  }

  public archive(id: string): void {
    this.database.db.prepare("UPDATE projects SET archived_at = ?, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND archived_at IS NULL").run(nowIso(), nowIso(), id);
  }

  public restore(id: string): void {
    this.database.db.prepare("UPDATE projects SET archived_at = NULL, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND archived_at IS NOT NULL").run(nowIso(), id);
  }
}

export class TargetRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public list(filters: { projectId?: string | undefined; search?: string | undefined; includeArchived?: boolean | undefined } = {}): TargetSummary[] {
    const clauses = [filters.includeArchived ? "1 = 1" : "archived_at IS NULL"];
    const values: string[] = [];
    if (filters.projectId) {
      clauses.push("project_id = ?");
      values.push(filters.projectId);
    }
    if (filters.search) {
      clauses.push("(display_name LIKE ? OR base_origin LIKE ? OR authorization_summary LIKE ?)");
      values.push(`%${filters.search}%`, `%${filters.search}%`, `%${filters.search}%`);
    }
    const rows = this.database.db.prepare(`SELECT * FROM targets WHERE ${clauses.join(" AND ")} ORDER BY updated_at DESC LIMIT 100`).all(...values) as DbTargetRow[];
    return rows.map((row) => targetFromRow(this.database, row));
  }

  public get(id: string, includeArchived = false): TargetSummary | undefined {
    const row = this.database.db.prepare(`SELECT * FROM targets WHERE id = ? ${includeArchived ? "" : "AND archived_at IS NULL"}`).get(id) as DbTargetRow | undefined;
    return row ? targetFromRow(this.database, row) : undefined;
  }

  public create(input: {
    projectId?: string | undefined;
    displayName: string;
    baseOrigin: string;
    description?: string | undefined;
    tags: string[];
    classification: string;
    authorizationType: string;
    authorizationSummary: string;
    approvedScope: Record<string, unknown>;
    productionEnabled?: boolean;
    defaultProfile?: string | undefined;
    defaultConfigurationId?: string | undefined;
    defaultCredentialProfileId?: string | undefined;
    defaultEvidenceLevel?: string | undefined;
    defaultAuthTemplate?: Record<string, unknown> | undefined;
    createdBy?: string | undefined;
  }): string {
    const id = randomUUID();
    const now = nowIso();
    this.database.db
      .prepare(
        `INSERT INTO targets (id, project_id, display_name, base_origin, description, tags_json, classification, authorization_type, authorization_summary, approved_scope_json, default_profile, default_configuration_id, default_credential_profile_id, default_evidence_level, default_auth_template_json, created_by, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        input.projectId ?? null,
        clamp(input.displayName, 160),
        originOnly(input.baseOrigin),
        input.description ? clamp(input.description, 2000) : null,
        JSON.stringify(input.tags),
        input.classification,
        input.authorizationType,
        clamp(input.authorizationSummary, 1000),
        JSON.stringify(input.approvedScope),
        input.defaultProfile ?? null,
        input.defaultConfigurationId ?? null,
        input.defaultCredentialProfileId ?? null,
        input.defaultEvidenceLevel ?? null,
        JSON.stringify(input.defaultAuthTemplate ?? {}),
        input.createdBy ?? null,
        now,
        now
      );
    this.database.db.prepare("UPDATE targets SET production_mutation_enabled = ? WHERE id = ?").run(input.productionEnabled ? 1 : 0, id);
    return id;
  }

  public update(id: string, input: Omit<Parameters<TargetRepository["create"]>[0], "createdBy" | "baseOrigin"> & { expectedVersion?: number | undefined }): void {
    const result = this.database.db
      .prepare(
        `UPDATE targets
         SET project_id = ?, display_name = ?, description = ?, tags_json = ?, classification = ?, authorization_type = ?, authorization_summary = ?, approved_scope_json = ?, default_profile = ?, default_configuration_id = ?, default_credential_profile_id = ?, default_evidence_level = ?, default_auth_template_json = ?, updated_at = ?, row_version = row_version + 1
         WHERE id = ? AND archived_at IS NULL ${input.expectedVersion === undefined ? "" : "AND row_version = ?"}`
      )
      .run(
        input.projectId ?? null,
        clamp(input.displayName, 160),
        input.description ? clamp(input.description, 2000) : null,
        JSON.stringify(input.tags),
        input.classification,
        input.authorizationType,
        clamp(input.authorizationSummary, 1000),
        JSON.stringify(input.approvedScope),
        input.defaultProfile ?? null,
        input.defaultConfigurationId ?? null,
        input.defaultCredentialProfileId ?? null,
        input.defaultEvidenceLevel ?? null,
        JSON.stringify(input.defaultAuthTemplate ?? {}),
        nowIso(),
        id,
        ...(input.expectedVersion === undefined ? [] : [input.expectedVersion])
      );
    if (result.changes !== 1) throw new Error("TARGET_CONFLICT: Target changed or is unavailable.");
    if (input.productionEnabled !== undefined) this.database.db.prepare("UPDATE targets SET production_mutation_enabled = ? WHERE id = ?").run(input.productionEnabled ? 1 : 0, id);
  }

  public archive(id: string): void {
    this.database.db.prepare("UPDATE targets SET archived_at = ?, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND archived_at IS NULL").run(nowIso(), nowIso(), id);
  }

  public restore(id: string): void {
    this.database.db.prepare("UPDATE targets SET archived_at = NULL, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND archived_at IS NOT NULL").run(nowIso(), id);
  }
}

export class AuditRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public append(input: { actorLabel?: string | undefined; action: string; resourceType: string; resourceId?: string | undefined; summary: string; metadata?: Record<string, unknown> | undefined; requestCorrelationId?: string | undefined }): void {
    this.database.db
      .prepare(
        "INSERT INTO audit_events (id, actor_label, action, resource_type, resource_id, safe_summary, safe_metadata_json, request_correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .run(randomUUID(), clamp(input.actorLabel ?? "local-operator", 120), clamp(input.action, 120), clamp(input.resourceType, 120), input.resourceId ?? null, clamp(input.summary, 800), clamp(JSON.stringify(input.metadata ?? {}), 4000), input.requestCorrelationId ?? null, nowIso());
  }

  public list(filters: { search?: string | undefined; action?: string | undefined; resourceType?: string | undefined; limit?: number | undefined } = {}): unknown[] {
    const clauses = ["1 = 1"];
    const values: Array<string | number> = [];
    if (filters.search) {
      clauses.push("(action LIKE ? OR resource_type LIKE ? OR safe_summary LIKE ?)");
      values.push(`%${filters.search}%`, `%${filters.search}%`, `%${filters.search}%`);
    }
    if (filters.action) {
      clauses.push("action = ?");
      values.push(filters.action);
    }
    if (filters.resourceType) {
      clauses.push("resource_type = ?");
      values.push(filters.resourceType);
    }
    values.push(Math.min(Math.max(filters.limit ?? 100, 1), 500));
    return this.database.db
      .prepare(`SELECT id, actor_label, action, resource_type, resource_id, safe_summary, safe_metadata_json, created_at FROM audit_events WHERE ${clauses.join(" AND ")} ORDER BY created_at DESC LIMIT ?`)
      .all(...values);
  }
}

export class ScanRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public create(input: {
    id: string;
    source: DashboardScanSource;
    status: DashboardScanStatus;
    targetOrigin: string;
    safeTargetLabel: string;
    profile: string;
    evidenceLevel: string;
    safeConfigurationSummary: Record<string, unknown>;
    outputDirectory?: string;
    projectId?: string | undefined;
    targetId?: string | undefined;
    authorizationDeclaration?: string | undefined;
  }): void {
    this.database.db
      .prepare(
        `INSERT INTO scans (id, display_sequence, source, status, target_origin, safe_target_label, profile, evidence_level, created_at, queued_at, safe_configuration_summary, output_directory, project_id, target_id, authorization_declaration)
         VALUES (?, (SELECT COALESCE(MAX(display_sequence), 0) + 1 FROM scans), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        input.id,
        input.source,
        input.status,
        input.targetOrigin,
        input.safeTargetLabel,
        input.profile,
        input.evidenceLevel,
        nowIso(),
        input.status === "QUEUED" ? nowIso() : null,
        JSON.stringify(input.safeConfigurationSummary),
        input.outputDirectory ?? null,
        input.projectId ?? null,
        input.targetId ?? null,
        input.authorizationDeclaration ? clamp(input.authorizationDeclaration, 1000) : null
      );
  }

  public updateStatus(id: string, status: DashboardScanStatus, extra: Partial<{ errorSummary: string; currentModule: string; completedAt: string; cancelledAt: string }> = {}): void {
    const completedAt = status === "COMPLETED" || status === "FAILED" || status === "CANCELLED" || status === "INTERRUPTED" || status === "IMPORTED" ? extra.completedAt ?? nowIso() : undefined;
    this.database.db
      .prepare(
        `UPDATE scans
         SET status = ?,
             started_at = CASE WHEN ? = 'RUNNING' AND started_at IS NULL THEN ? ELSE started_at END,
             completed_at = COALESCE(?, completed_at),
             cancelled_at = COALESCE(?, cancelled_at),
             current_module = COALESCE(?, current_module),
             error_summary = COALESCE(?, error_summary)
         WHERE id = ?`
      )
      .run(status, status, nowIso(), completedAt ?? null, extra.cancelledAt ?? null, extra.currentModule ?? null, extra.errorSummary ? clamp(extra.errorSummary, 800) : null, id);
  }

  public attachArtifacts(scanId: string, artifacts: { json?: string; markdown?: string; html?: string }): void {
    this.database.db
      .prepare("UPDATE scans SET json_report_artifact_id = ?, markdown_report_artifact_id = ?, html_report_artifact_id = ? WHERE id = ?")
      .run(artifacts.json ?? null, artifacts.markdown ?? null, artifacts.html ?? null, scanId);
  }

  public markArchived(scanId: string): void {
    this.database.db.prepare("UPDATE scans SET archived_at = ? WHERE id = ? AND status NOT IN ('RUNNING','PLANNING','CANCEL_REQUESTED')").run(nowIso(), scanId);
  }

  public markDeleted(scanId: string): void {
    this.database.db.prepare("UPDATE scans SET deleted_at = ? WHERE id = ? AND status NOT IN ('RUNNING','PLANNING','CANCEL_REQUESTED')").run(nowIso(), scanId);
  }

  public updatePlanSummary(scanId: string, evidenceLevel: string, plannedModuleCount: number): void {
    this.database.db.prepare("UPDATE scans SET evidence_level = ?, planned_module_count = ? WHERE id = ?").run(evidenceLevel, plannedModuleCount, scanId);
  }

  public updateCounters(scanId: string): void {
    this.database.db
      .prepare(
        `UPDATE scans
         SET planned_module_count = (SELECT COUNT(*) FROM scan_module_executions WHERE scan_id = scans.id),
             completed_module_count = (SELECT COUNT(*) FROM scan_module_executions WHERE scan_id = scans.id AND status = 'COMPLETED'),
             failed_module_count = (SELECT COUNT(*) FROM scan_module_executions WHERE scan_id = scans.id AND status = 'FAILED'),
             blocked_module_count = (SELECT COUNT(*) FROM scan_module_executions WHERE scan_id = scans.id AND status IN ('BLOCKED','SKIPPED','CANCELLED')),
             finding_count = (SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = scans.id)
         WHERE id = ?`
      )
      .run(scanId);
  }

  public list(limit: number, filters: ScanListFilters = {}): DashboardScanSummary[] {
    const boundedLimit = Math.min(Math.max(limit, 1), 100);
    const clauses = ["deleted_at IS NULL"];
    const values: Array<string | number> = [];
    if (filters.search) {
      clauses.push("(safe_target_label LIKE ? OR profile LIKE ? OR status LIKE ?)");
      values.push(`%${filters.search}%`, `%${filters.search}%`, `%${filters.search}%`);
    }
    if (filters.status) {
      clauses.push("status = ?");
      values.push(filters.status);
    }
    if (filters.profile) {
      clauses.push("profile = ?");
      values.push(filters.profile);
    }
    if (filters.target) {
      clauses.push("safe_target_label LIKE ?");
      values.push(`%${filters.target}%`);
    }
    if (filters.projectId) {
      clauses.push("project_id = ?");
      values.push(filters.projectId);
    }
    if (filters.targetId) {
      clauses.push("target_id = ?");
      values.push(filters.targetId);
    }
    values.push(boundedLimit, Math.max(filters.offset ?? 0, 0));
    const rows = this.database.db.prepare(`SELECT * FROM scans WHERE ${clauses.join(" AND ")} ORDER BY ${scanSort(filters.sort)} LIMIT ? OFFSET ?`).all(...values);
    return (rows as DbScanRow[]).map(scanSummaryFromRow);
  }

  public get(id: string): DashboardScanSummary | undefined {
    const row = this.database.db.prepare("SELECT * FROM scans WHERE id = ? AND deleted_at IS NULL").get(id) as DbScanRow | undefined;
    return row ? scanSummaryFromRow(row) : undefined;
  }

  public getReportPath(id: string): string | undefined {
    const row = this.database.db
      .prepare(
        "SELECT artifacts.canonical_path AS path FROM scans JOIN artifacts ON scans.json_report_artifact_id = artifacts.id WHERE scans.id = ?"
      )
      .get(id) as { path: string } | undefined;
    return row?.path;
  }

  public detail(id: string): unknown {
    const scan = this.database.db.prepare("SELECT * FROM scans WHERE id = ? AND deleted_at IS NULL").get(id);
    if (!scan) return undefined;
    return {
      scan: scanSummaryFromRow(scan as DbScanRow),
      raw: scan,
      modules: this.database.db.prepare("SELECT * FROM scan_module_executions WHERE scan_id = ? ORDER BY planned_order ASC").all(id),
      events: new EventRepository(this.database).list(id, 0, 200),
      planSnapshot: this.database.db.prepare("SELECT * FROM scan_plan_snapshots WHERE scan_id = ?").get(id),
      artifacts: this.database.db.prepare("SELECT id, artifact_type, safe_display_name, size, content_type, retention_state, missing_file_flag FROM artifacts WHERE scan_id = ?").all(id),
      findings: this.database.db
        .prepare(
          `SELECT findings.* FROM findings
           JOIN finding_occurrences ON finding_occurrences.finding_id = findings.id
           WHERE finding_occurrences.scan_id = ?
           GROUP BY findings.id
           ORDER BY findings.current_scanner_severity DESC, findings.last_seen_at DESC`
        )
        .all(id)
        .map((row) => findingSummaryFromRow(row as DbFindingRow))
    };
  }

  public overview(): unknown {
    const scanCounts = this.database.db.prepare("SELECT status, COUNT(*) AS count FROM scans WHERE deleted_at IS NULL GROUP BY status").all() as Array<{ status: string; count: number }>;
    const findingCounts = this.database.db.prepare("SELECT human_review_status AS status, COUNT(*) AS count FROM findings WHERE archived_at IS NULL GROUP BY human_review_status").all() as Array<{ status: string; count: number }>;
    return {
      scans: {
        total: scalarCount(this.database, "SELECT COUNT(*) AS count FROM scans WHERE deleted_at IS NULL"),
        queued: countBy(scanCounts, "QUEUED"),
        running: countBy(scanCounts, "RUNNING") + countBy(scanCounts, "PLANNING") + countBy(scanCounts, "CANCEL_REQUESTED"),
        completed: countBy(scanCounts, "COMPLETED"),
        failed: countBy(scanCounts, "FAILED"),
        interrupted: countBy(scanCounts, "INTERRUPTED")
      },
      findings: {
        open: scalarCount(this.database, "SELECT COUNT(*) AS count FROM findings WHERE archived_at IS NULL AND remediation_status != 'FIXED_VERIFIED'"),
        unreviewed: countBy(findingCounts, "UNREVIEWED"),
        confirmed: countBy(findingCounts, "CONFIRMED"),
        falsePositive: countBy(findingCounts, "FALSE_POSITIVE"),
        acceptedRisk: countBy(findingCounts, "ACCEPTED_RISK"),
        resolved: countBy(findingCounts, "RESOLVED"),
        reopened: countBy(findingCounts, "REOPENED")
      },
      recentScans: this.list(5),
      recentReviews: this.database.db
        .prepare("SELECT finding_reviews.*, findings.canonical_title FROM finding_reviews JOIN findings ON findings.id = finding_reviews.finding_id ORDER BY finding_reviews.created_at DESC LIMIT 10")
        .all()
    };
  }
}

export class PlanRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public create(scanId: string, snapshot: {
    plannerVersion: string;
    profile: string;
    modules: unknown;
    limits: unknown;
    evidencePolicy: unknown;
    browserPolicySummary: unknown;
    scopeSummary: unknown;
    authenticationSummary: unknown;
    controlledWorkflowSummary: unknown;
    redactedPlan: unknown;
  }): void {
    this.database.db
      .prepare(
        `INSERT INTO scan_plan_snapshots (id, scan_id, planner_version, profile, modules_json, limits_json, evidence_policy_json, browser_policy_summary_json, scope_summary_json, authentication_summary_json, controlled_workflow_summary_json, redacted_plan_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        randomUUID(),
        scanId,
        snapshot.plannerVersion,
        snapshot.profile,
        JSON.stringify(snapshot.modules),
        JSON.stringify(snapshot.limits),
        JSON.stringify(snapshot.evidencePolicy),
        JSON.stringify(snapshot.browserPolicySummary),
        JSON.stringify(snapshot.scopeSummary),
        JSON.stringify(snapshot.authenticationSummary),
        JSON.stringify(snapshot.controlledWorkflowSummary),
        JSON.stringify(snapshot.redactedPlan),
        nowIso()
      );
  }
}

export class ModuleExecutionRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public createQueued(scanId: string, modules: readonly { id: string; phase: string }[]): void {
    const statement = this.database.db.prepare(
      "INSERT INTO scan_module_executions (id, scan_id, module_id, module_label, planned_order, status) VALUES (?, ?, ?, ?, ?, 'QUEUED')"
    );
    for (const [index, modulePlan] of modules.entries()) {
      statement.run(randomUUID(), scanId, modulePlan.id, modulePlan.id, index + 1);
    }
  }

  public mark(scanId: string, moduleId: string, status: ModuleExecutionStatus, summary?: string, findings?: number): void {
    this.database.db
      .prepare(
        `UPDATE scan_module_executions
         SET status = ?,
             started_at = CASE WHEN ? = 'RUNNING' AND started_at IS NULL THEN ? ELSE started_at END,
             completed_at = CASE WHEN ? IN ('COMPLETED','FAILED','BLOCKED','SKIPPED','CANCELLED') THEN ? ELSE completed_at END,
             finding_count = COALESCE(?, finding_count),
             safe_failure_summary = COALESCE(?, safe_failure_summary)
         WHERE scan_id = ? AND module_id = ?`
      )
      .run(status, status, nowIso(), status, nowIso(), findings ?? null, summary ? clamp(summary, 800) : null, scanId, moduleId);
  }
}

export class EventRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public append(scanId: string, eventType: string, message: string, metadata: Record<string, unknown>, moduleId?: string): void {
    this.database.appendEvent(scanId, eventType, message, metadata, moduleId);
  }

  public list(scanId: string, afterSeq = 0, limit = 200): Array<{ seq: number; eventType: string; moduleId?: string; message: string; metadata: unknown; createdAt: string }> {
    const rows = this.database.db
      .prepare("SELECT seq, event_type, module_id, safe_message, safe_metadata_json, created_at FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?")
      .all(scanId, afterSeq, Math.min(Math.max(limit, 1), 500)) as Array<{
      seq: number;
      event_type: string;
      module_id: string | null;
      safe_message: string;
      safe_metadata_json: string;
      created_at: string;
    }>;
    return rows.map((row) => ({
      seq: row.seq,
      eventType: row.event_type,
      ...(row.module_id ? { moduleId: row.module_id } : {}),
      message: row.safe_message,
      metadata: JSON.parse(row.safe_metadata_json),
      createdAt: row.created_at
    }));
  }
}

export class ArtifactRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public create(input: { scanId?: string; proofPackId?: string; type: string; name: string; path: string; size: number; contentType: string; hash: string; retentionState?: string }): string {
    const id = randomUUID();
    this.database.db
      .prepare(
        "INSERT INTO artifacts (id, scan_id, proof_pack_id, artifact_type, safe_display_name, canonical_path, size, content_type, scoped_or_full_safe_hash, created_at, retention_state) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .run(id, input.scanId ?? null, input.proofPackId ?? null, input.type, clamp(input.name, 200), input.path, input.size, input.contentType, input.hash, nowIso(), input.retentionState ?? "RETAIN");
    return id;
  }

  public get(id: string): { id: string; path: string; contentType: string; name: string } | undefined {
    const row = this.database.db.prepare("SELECT id, canonical_path, content_type, safe_display_name FROM artifacts WHERE id = ?").get(id) as
      | { id: string; canonical_path: string; content_type: string; safe_display_name: string }
      | undefined;
    return row ? { id: row.id, path: row.canonical_path, contentType: row.content_type, name: row.safe_display_name } : undefined;
  }
}

export class FindingRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public list(limit: number, filters: FindingListFilters = {}): DashboardFindingSummary[] {
    const boundedLimit = Math.min(Math.max(limit, 1), 100);
    const clauses = ["archived_at IS NULL"];
    const values: Array<string | number> = [];
    if (filters.search) {
      clauses.push("(canonical_title LIKE ? OR safe_endpoint_identity LIKE ? OR module LIKE ?)");
      values.push(`%${filters.search}%`, `%${filters.search}%`, `%${filters.search}%`);
    }
    if (filters.reviewStatus) {
      clauses.push("human_review_status = ?");
      values.push(filters.reviewStatus);
    }
    if (filters.severity) {
      clauses.push("current_scanner_severity = ?");
      values.push(filters.severity);
    }
    if (filters.confidence) {
      clauses.push("current_scanner_confidence = ?");
      values.push(filters.confidence);
    }
    if (filters.module) {
      clauses.push("module = ?");
      values.push(filters.module);
    }
    if (filters.category) {
      clauses.push("finding_category = ?");
      values.push(filters.category);
    }
    values.push(boundedLimit, Math.max(filters.offset ?? 0, 0));
    const rows = this.database.db.prepare(`SELECT * FROM findings WHERE ${clauses.join(" AND ")} ORDER BY ${findingSort(filters.sort)} LIMIT ? OFFSET ?`).all(...values) as DbFindingRow[];
    return rows.map(findingSummaryFromRow);
  }

  public get(id: string): DashboardFindingSummary | undefined {
    const row = this.database.db.prepare("SELECT * FROM findings WHERE id = ?").get(id) as DbFindingRow | undefined;
    return row ? findingSummaryFromRow(row) : undefined;
  }

  public detail(id: string): unknown {
    const row = this.database.db.prepare("SELECT * FROM findings WHERE id = ?").get(id) as DbFindingRow | undefined;
    if (!row) return undefined;
    return {
      finding: findingSummaryFromRow(row),
      raw: this.database.db.prepare("SELECT * FROM findings WHERE id = ?").get(id),
      occurrences: this.database.db.prepare("SELECT * FROM finding_occurrences WHERE finding_id = ? ORDER BY created_at DESC").all(id),
      evidence: this.database.db
        .prepare(
          "SELECT evidence_records.* FROM evidence_records JOIN finding_occurrences ON finding_occurrences.id = evidence_records.finding_occurrence_id WHERE finding_occurrences.finding_id = ? ORDER BY evidence_records.created_at DESC"
        )
        .all(id),
      reviews: this.database.db.prepare("SELECT * FROM finding_reviews WHERE finding_id = ? ORDER BY created_at DESC").all(id),
      proofPacks: this.database.db.prepare("SELECT proof_pack_id, selected_occurrence_id, sort_order, created_at FROM proof_pack_findings WHERE finding_id = ? ORDER BY created_at DESC").all(id)
    };
  }

  public review(input: {
    findingId: string;
    newStatus: ReviewStatus;
    reason?: string | undefined;
    note?: string | undefined;
    duplicateTargetFindingId?: string | undefined;
    reviewerLabel?: string | undefined;
    source?: "HUMAN" | "SYSTEM_REOPEN" | "IMPORT" | undefined;
  }): void {
    const current = this.database.db.prepare("SELECT row_version FROM findings WHERE id = ?").get(input.findingId) as { row_version: number } | undefined;
    if (!current) throw new Error("Finding not found.");
    new FindingCommandCenterService(this.database).review({
      findingId: input.findingId,
      newStatus: input.newStatus,
      ...(input.reason ? { reason: input.reason } : {}),
      ...(input.note ? { note: input.note } : {}),
      ...(input.duplicateTargetFindingId ? { duplicateTargetFindingId: input.duplicateTargetFindingId } : {}),
      expectedVersion: current.row_version,
      principal: {
        mode: "local",
        userId: "local-operator",
        login: input.reviewerLabel ?? "local-operator",
        role: "OWNER",
        csrfToken: "compatibility-adapter"
      },
      ...(input.source ? { source: input.source } : {})
    });
  }
}

export class SavedConfigurationRepository {
  public constructor(private readonly database: DashboardDatabase) {}

  public list(search?: string, includeArchived = false): unknown[] {
    const archived = includeArchived ? "1 = 1" : "archived_at IS NULL";
    const rows = search
      ? this.database.db
          .prepare(`SELECT * FROM saved_scan_configurations WHERE ${archived} AND (name LIKE ? OR description LIKE ?) ORDER BY updated_at DESC LIMIT 100`)
          .all(`%${search}%`, `%${search}%`)
      : this.database.db.prepare(`SELECT * FROM saved_scan_configurations WHERE ${archived} ORDER BY updated_at DESC LIMIT 100`).all();
    return (rows as SavedConfigurationRow[]).map(configurationFromRow);
  }

  public get(id: string, includeArchived = false): Record<string, unknown> | undefined {
    const row = this.database.db.prepare(`SELECT * FROM saved_scan_configurations WHERE id = ? ${includeArchived ? "" : "AND archived_at IS NULL"}`).get(id) as SavedConfigurationRow | undefined;
    return row ? configurationFromRow(row) : undefined;
  }

  public create(input: {
    name: string;
    description?: string | undefined;
    targetTemplate?: string | undefined;
    profile: string;
    modules: unknown;
    limits: unknown;
    scopeSettings: unknown;
    browserPolicySettings: unknown;
    evidenceLevel: string;
    workflowRefs: unknown;
  }): string {
    const id = randomUUID();
    const now = nowIso();
    this.database.db
      .prepare(
        `INSERT INTO saved_scan_configurations (id, name, description, target_template, profile, modules_json, limits_json, scope_settings_json, browser_policy_settings_json, evidence_level, non_secret_controlled_workflow_refs_json, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        id,
        input.name,
        input.description ?? null,
        input.targetTemplate ?? null,
        input.profile,
        JSON.stringify(input.modules),
        JSON.stringify(input.limits),
        JSON.stringify(input.scopeSettings),
        JSON.stringify(input.browserPolicySettings),
        input.evidenceLevel,
        JSON.stringify(input.workflowRefs),
        now,
        now
      );
    this.addVersion(id, 1, input, "Initial saved configuration");
    return id;
  }

  public update(id: string, input: Parameters<SavedConfigurationRepository["create"]>[0] & { expectedVersion?: number | undefined; changeSummary?: string | undefined }): number {
    const current = this.database.db.prepare("SELECT current_version, row_version FROM saved_scan_configurations WHERE id = ? AND archived_at IS NULL").get(id) as { current_version: number; row_version: number } | undefined;
    if (!current || (input.expectedVersion !== undefined && input.expectedVersion !== current.row_version)) throw new Error("CONFIGURATION_CONFLICT: Configuration changed or is unavailable.");
    const nextVersion = current.current_version + 1;
    const result = this.database.db
      .prepare(
        `UPDATE saved_scan_configurations
         SET name = ?, description = ?, target_template = ?, profile = ?, modules_json = ?, limits_json = ?, scope_settings_json = ?, browser_policy_settings_json = ?, evidence_level = ?, non_secret_controlled_workflow_refs_json = ?, updated_at = ?, current_version = ?, row_version = row_version + 1
         WHERE id = ? AND row_version = ?`
      )
      .run(
        input.name,
        input.description ?? null,
        input.targetTemplate ?? null,
        input.profile,
        JSON.stringify(input.modules),
        JSON.stringify(input.limits),
        JSON.stringify(input.scopeSettings),
        JSON.stringify(input.browserPolicySettings),
        input.evidenceLevel,
        JSON.stringify(input.workflowRefs),
        nowIso(),
        nextVersion,
        id,
        current.row_version
      );
    if (result.changes !== 1) throw new Error("CONFIGURATION_CONFLICT: Configuration changed concurrently.");
    this.addVersion(id, nextVersion, input, input.changeSummary ?? "Saved as a new immutable version");
    return nextVersion;
  }

  public archive(id: string): void {
    this.database.db.prepare("UPDATE saved_scan_configurations SET archived_at = ?, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND archived_at IS NULL").run(nowIso(), nowIso(), id);
  }

  public restore(id: string): void {
    this.database.db.prepare("UPDATE saved_scan_configurations SET archived_at = NULL, updated_at = ?, row_version = row_version + 1 WHERE id = ? AND archived_at IS NOT NULL").run(nowIso(), id);
  }

  public clone(id: string, name: string): string {
    const item = this.get(id, true);
    if (!item) throw new Error("Configuration not found.");
    return this.create({
      name, description: typeof item.description === "string" ? item.description : undefined,
      targetTemplate: typeof item.targetTemplate === "string" ? item.targetTemplate : undefined,
      profile: String(item.profile), modules: item.modules, limits: item.limits, scopeSettings: item.scopeSettings,
      browserPolicySettings: item.browserPolicySettings, evidenceLevel: String(item.evidenceLevel), workflowRefs: item.workflowRefs
    });
  }

  public history(id: string): unknown[] {
    return this.database.db.prepare("SELECT id, configuration_id AS configurationId, version, snapshot_json AS snapshotJson, change_summary AS changeSummary, created_by AS createdBy, created_at AS createdAt FROM saved_scan_configuration_versions WHERE configuration_id = ? ORDER BY version DESC").all(id);
  }

  public diff(id: string, olderVersion: number, newerVersion: number): Record<string, unknown> {
    const rows = this.database.db.prepare("SELECT version, snapshot_json FROM saved_scan_configuration_versions WHERE configuration_id = ? AND version IN (?, ?)").all(id, olderVersion, newerVersion) as Array<{ version: number; snapshot_json: string }>;
    if (rows.length !== 2) throw new Error("Both configuration versions are required for diff.");
    const older = JSON.parse(rows.find((row) => row.version === olderVersion)!.snapshot_json) as Record<string, unknown>;
    const newer = JSON.parse(rows.find((row) => row.version === newerVersion)!.snapshot_json) as Record<string, unknown>;
    const changes = [...new Set([...Object.keys(older), ...Object.keys(newer)])].filter((key) => JSON.stringify(older[key]) !== JSON.stringify(newer[key])).map((key) => ({ field: key, older: older[key], newer: newer[key] }));
    return { olderVersion, newerVersion, changes };
  }

  private addVersion(id: string, version: number, input: Parameters<SavedConfigurationRepository["create"]>[0], summary: string): void {
    const snapshot = { name: input.name, ...(input.description ? { description: input.description } : {}), ...(input.targetTemplate ? { targetTemplate: input.targetTemplate } : {}), profile: input.profile,
      modules: input.modules, limits: input.limits, scopeSettings: input.scopeSettings, browserPolicySettings: input.browserPolicySettings, evidenceLevel: input.evidenceLevel, workflowRefs: input.workflowRefs };
    this.database.db.prepare("INSERT INTO saved_scan_configuration_versions (id, configuration_id, version, snapshot_json, change_summary, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(randomUUID(), id, version, JSON.stringify(snapshot), clamp(summary, 500), nowIso());
  }
}

interface SavedConfigurationRow {
  id: string; name: string; description: string | null; target_template: string | null; profile: string;
  modules_json: string; limits_json: string; scope_settings_json: string; browser_policy_settings_json: string;
  evidence_level: string; non_secret_controlled_workflow_refs_json: string; created_at: string; updated_at: string;
  archived_at: string | null; row_version: number; current_version: number;
}

function configurationFromRow(row: SavedConfigurationRow): Record<string, unknown> {
  return { id: row.id, name: row.name, ...(row.description ? { description: row.description } : {}), ...(row.target_template ? { targetTemplate: row.target_template } : {}), profile: row.profile,
    modules: JSON.parse(row.modules_json), limits: JSON.parse(row.limits_json), scopeSettings: JSON.parse(row.scope_settings_json), browserPolicySettings: JSON.parse(row.browser_policy_settings_json),
    evidenceLevel: row.evidence_level, workflowRefs: JSON.parse(row.non_secret_controlled_workflow_refs_json), createdAt: row.created_at, updatedAt: row.updated_at,
    archived: Boolean(row.archived_at), rowVersion: row.row_version, currentVersion: row.current_version };
}

function scanSort(sort: ScanListFilters["sort"]): string {
  switch (sort) {
    case "created_asc":
      return "created_at ASC";
    case "status":
      return "status ASC, created_at DESC";
    case "target":
      return "safe_target_label ASC, created_at DESC";
    case "created_desc":
    case undefined:
      return "created_at DESC";
  }
}

function findingSort(sort: FindingListFilters["sort"]): string {
  switch (sort) {
    case "first_seen_desc":
      return "first_seen_at DESC";
    case "severity":
      return "current_scanner_severity DESC, last_seen_at DESC";
    case "title":
      return "canonical_title ASC";
    case "last_seen_desc":
    case undefined:
      return "last_seen_at DESC";
  }
}

function scalarCount(database: DashboardDatabase, sql: string): number {
  return (database.db.prepare(sql).get() as { count: number }).count;
}

function scalarCountPrepared(database: DashboardDatabase, sql: string, value: string): number {
  return (database.db.prepare(sql).get(value) as { count: number }).count;
}

function countBy(rows: readonly { status: string; count: number }[], status: string): number {
  return rows.find((row) => row.status === status)?.count ?? 0;
}

interface DbScanRow {
  id: string;
  source: DashboardScanSource;
  status: DashboardScanStatus;
  safe_target_label: string;
  profile: string;
  evidence_level: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  current_module: string | null;
  planned_module_count: number;
  completed_module_count: number;
  failed_module_count: number;
  finding_count: number;
  error_summary: string | null;
}

interface DbProjectRow {
  id: string;
  name: string;
  description: string | null;
  tags_json: string;
  default_profile: string | null;
  default_scope_json: string;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  row_version: number;
}

interface DbTargetRow {
  id: string;
  project_id: string | null;
  display_name: string;
  base_origin: string;
  description: string | null;
  tags_json: string;
  classification: string;
  authorization_type: string;
  authorization_summary: string;
  approved_scope_json: string;
  default_profile: string | null;
  default_configuration_id: string | null;
  default_credential_profile_id: string | null;
  default_evidence_level: string | null;
  default_auth_template_json: string;
  production_mutation_enabled: number;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  row_version: number;
}

interface DbFindingRow {
  id: string;
  module: string;
  finding_category: string;
  safe_endpoint_identity: string;
  canonical_title: string;
  current_scanner_severity: string;
  current_scanner_confidence: string;
  human_review_status: ReviewStatus;
  remediation_status: string;
  first_seen_at: string;
  last_seen_at: string;
  occurrence_count: number;
  http_method: string;
  effective_severity: string | null;
  retest_state: DashboardFindingSummary["retestStatus"];
  proof_readiness: DashboardFindingSummary["proofReadiness"];
  new_occurrence_kind: string | null;
  row_version: number;
}

function projectFromRow(database: DashboardDatabase, row: DbProjectRow): ProjectSummary {
  return {
    id: row.id,
    name: row.name,
    ...(row.description ? { description: row.description } : {}),
    tags: safeJsonArray(row.tags_json),
    ...(row.default_profile ? { defaultProfile: row.default_profile } : {}),
    defaultScope: safeJsonObject(row.default_scope_json),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    openFindingCount: scalarCountPrepared(database, "SELECT COUNT(*) AS count FROM findings WHERE project_id = ? AND archived_at IS NULL AND remediation_state_v2 != 'FIXED_VERIFIED'", row.id),
    targetCount: scalarCountPrepared(database, "SELECT COUNT(*) AS count FROM targets WHERE project_id = ? AND archived_at IS NULL", row.id),
    scanCount: scalarCountPrepared(database, "SELECT COUNT(*) AS count FROM scans WHERE project_id = ? AND deleted_at IS NULL", row.id)
    ,archived: Boolean(row.archived_at),
    rowVersion: row.row_version
  };
}

function targetFromRow(database: DashboardDatabase, row: DbTargetRow): TargetSummary {
  return {
    id: row.id,
    ...(row.project_id ? { projectId: row.project_id } : {}),
    displayName: row.display_name,
    baseOrigin: row.base_origin,
    ...(row.description ? { description: row.description } : {}),
    tags: safeJsonArray(row.tags_json),
    classification: row.classification,
    authorizationType: row.authorization_type,
    authorizationSummary: row.authorization_summary,
    approvedScope: safeJsonObject(row.approved_scope_json),
    productionEnabled: Boolean(row.production_mutation_enabled),
    ...(row.default_profile ? { defaultProfile: row.default_profile } : {}),
    ...(row.default_configuration_id ? { defaultConfigurationId: row.default_configuration_id } : {}),
    ...(row.default_credential_profile_id ? { defaultCredentialProfileId: row.default_credential_profile_id } : {}),
    ...(row.default_evidence_level ? { defaultEvidenceLevel: row.default_evidence_level } : {}),
    defaultAuthTemplate: safeJsonObject(row.default_auth_template_json),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    openFindingCount: scalarCountPrepared(database, "SELECT COUNT(*) AS count FROM findings WHERE target_id = ? AND archived_at IS NULL AND remediation_state_v2 != 'FIXED_VERIFIED'", row.id),
    scanCount: scalarCountPrepared(database, "SELECT COUNT(*) AS count FROM scans WHERE target_id = ? AND deleted_at IS NULL", row.id),
    archived: Boolean(row.archived_at),
    rowVersion: row.row_version
  };
}

function scanSummaryFromRow(row: DbScanRow): DashboardScanSummary {
  const terminal = row.status === "COMPLETED" || row.status === "FAILED" || row.status === "CANCELLED" || row.status === "INTERRUPTED" || row.status === "IMPORTED";
  const moduleProgress = row.planned_module_count > 0 ? Math.round((row.completed_module_count / row.planned_module_count) * 95) : 0;
  return {
    id: row.id,
    shortId: row.id.slice(0, 8),
    source: row.source,
    status: row.status,
    target: row.safe_target_label,
    profile: row.profile,
    evidenceLevel: row.evidence_level,
    createdAt: row.created_at,
    ...(row.started_at ? { startedAt: row.started_at } : {}),
    ...(row.completed_at ? { completedAt: row.completed_at } : {}),
    ...(row.current_module ? { currentModule: row.current_module } : {}),
    progressPercent: terminal ? 100 : moduleProgress,
    plannedModuleCount: row.planned_module_count,
    completedModuleCount: row.completed_module_count,
    failedModuleCount: row.failed_module_count,
    findingCount: row.finding_count,
    ...(row.error_summary ? { errorSummary: row.error_summary } : {})
  };
}

function findingSummaryFromRow(row: DbFindingRow): DashboardFindingSummary {
  return {
    id: row.id,
    title: row.canonical_title,
    module: row.module,
    category: row.finding_category,
    endpoint: row.safe_endpoint_identity,
    severity: row.current_scanner_severity,
    confidence: row.current_scanner_confidence,
    reviewStatus: row.human_review_status,
    remediationStatus: row.remediation_status as DashboardFindingSummary["remediationStatus"],
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    occurrenceCount: row.occurrence_count,
    method: row.http_method,
    effectiveSeverity: row.effective_severity ?? row.current_scanner_severity,
    retestStatus: row.retest_state,
    proofReadiness: row.proof_readiness,
    ...(row.new_occurrence_kind ? { newOccurrenceKind: row.new_occurrence_kind } : {}),
    rowVersion: row.row_version
  };
}

function originOnly(value: string): string {
  return new URL(value).origin;
}

function safeJsonArray(value: string): string[] {
  const parsed = JSON.parse(value) as unknown;
  return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
}

function safeJsonObject(value: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
}
