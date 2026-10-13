import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import type { RouteCairnReport } from "../../reports/ReportTypes.js";
import { adaptivePolicyInputSchema } from "../contracts/AdaptiveSecuritySchemas.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { validateAdvancedEngineInput, advancedEngineCatalog, type AdvancedEngineId } from "../contracts/AdvancedEngineSchemas.js";
import { adaptiveExecutionBindingSchema, type AdaptiveExecutionBinding } from "../contracts/AdaptiveSecuritySchemas.js";
import { authorizeConfiguration, type AdaptiveAuthenticationRequirement } from "./AdaptiveContractCompiler.js";

import { adaptiveDigest, adaptiveExecutionFingerprint } from "./AdaptiveCanonical.js";
import { buildAdaptiveInventory, compareAdaptiveInventories, synthesizeAdaptiveRecommendations, type AdaptiveInventory, type AdaptiveDrift, type AdaptiveRecommendation } from "./AdaptiveSynthesisCore.js";
export type { AdaptiveInventory } from "./AdaptiveSynthesisCore.js";

const defaultRequiredLanes = ["PUBLIC_BASELINE", "AUTHENTICATED_IDENTITY", "ACCOUNT_PAIR_AUTHORIZATION", "BROWSER_LEARNING", "AUTHENTICATION_LIFECYCLE", "API_GRAPHQL_AUTHORIZATION", "DATA_AUTHORIZATION", "BUSINESS_LOGIC", "OPERATIONAL_ENDPOINTS", "BILLING_ENTITLEMENTS", "MUTATION_ACCEPTANCE", "RECOVERY_ACCEPTANCE"] as const;
const terminalScans = new Set(["COMPLETED", "IMPORTED", "FAILED", "CANCELLED", "INTERRUPTED"]);

export class AdaptiveSecurityService {
  public constructor(private readonly database: DashboardDatabase) {}

  public async analyze(targetId: string, scanId: string): Promise<Record<string, unknown>> {
    const artifact = this.database.db.prepare(`SELECT a.canonical_path AS path FROM scans s JOIN artifacts a ON a.id=s.json_report_artifact_id WHERE s.id=? AND s.target_id=? AND s.deleted_at IS NULL AND s.status IN ('COMPLETED','IMPORTED')`).get(scanId, targetId) as { path: string } | undefined;
    if (!artifact) throw new Error("ADAPTIVE_COMPLETED_TARGET_SCAN_REQUIRED");
    const report = JSON.parse(await readFile(artifact.path, "utf8")) as RouteCairnReport;
    return this.observeCompletedScan(scanId, report, targetId);
  }

  public observeCompletedScan(scanId: string, report: RouteCairnReport, expectedTargetId?: string): Record<string, unknown> {
    const scan = this.database.db.prepare("SELECT target_id,target_origin,status FROM scans WHERE id=? AND deleted_at IS NULL").get(scanId) as { target_id: string | null; target_origin: string; status: string } | undefined;
    if (!scan?.target_id || !["COMPLETED", "IMPORTED"].includes(scan.status) || (expectedTargetId && scan.target_id !== expectedTargetId)) throw new Error("ADAPTIVE_COMPLETED_REGISTERED_TARGET_SCAN_REQUIRED");
    const target = this.database.db.prepare("SELECT id,row_version,base_origin FROM targets WHERE id=?").get(scan.target_id) as { id: string; row_version: number; base_origin: string } | undefined;
    if (!target || scan.target_origin !== target.base_origin || new URL(report.target).origin !== target.base_origin) throw new Error("ADAPTIVE_TARGET_BINDING_MISMATCH");
    const existing = this.database.db.prepare("SELECT id FROM adaptive_security_snapshots WHERE source_scan_id=?").get(scanId) as { id: string } | undefined;
    if (existing) return this.snapshot(existing.id);
    const inventory = buildAdaptiveInventory(report, this.workflowCases(scanId));
    const modelDigest = adaptiveDigest(inventory);
    const baseline = this.database.db.prepare("SELECT id,inventory_json FROM adaptive_security_snapshots WHERE target_id=? AND status='BASELINE' ORDER BY accepted_at DESC LIMIT 1").get(target.id) as { id: string; inventory_json: string } | undefined;
    const snapshotId = randomUUID();
    const createdAt = nowIso();
    this.database.transaction(() => {
      this.database.db.prepare("INSERT INTO adaptive_security_snapshots (id,target_id,source_scan_id,status,model_digest,target_row_version,build_fingerprint,inventory_json,created_at) VALUES (?,?,?,'CANDIDATE',?,?,?,?,?)")
        .run(snapshotId, target.id, scanId, modelDigest, target.row_version, inventory.buildFingerprint, JSON.stringify(inventory), createdAt);
      const drifts: AdaptiveDrift[] = baseline ? compareAdaptiveInventories(JSON.parse(baseline.inventory_json) as AdaptiveInventory, inventory, this.policy(target.id).detectRemovedSurfaces) : [{ type: "INITIAL_MODEL", severity: "INFO", semanticKey: "model", summary: "Initial target security model captured; operator baseline acceptance is required." }];
      for (const drift of drifts) this.database.db.prepare("INSERT INTO adaptive_security_drifts (id,target_id,snapshot_id,baseline_snapshot_id,drift_type,severity,semantic_key,semantic_fingerprint,safe_summary,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,'OPEN',?)")
        .run(randomUUID(), target.id, snapshotId, baseline?.id ?? null, drift.type, drift.severity, drift.semanticKey, adaptiveDigest(drift), clamp(drift.summary, 500), createdAt);
      for (const recommendation of synthesizeAdaptiveRecommendations(report, inventory, drifts)) this.insertRecommendation(target.id, snapshotId, recommendation, createdAt);
    });
    return this.snapshot(snapshotId);
  }

  public setPolicy(input: unknown, actor: string): Record<string, unknown> {
    const policy = adaptivePolicyInputSchema.parse(input);
    this.requireTarget(policy.targetId);
    const now = nowIso();
    this.database.db.prepare(`INSERT INTO adaptive_target_policies (target_id,required_lanes_json,require_na_evidence,detect_removed_surfaces,updated_by,updated_at,row_version) VALUES (?,?,?,?,?,?,1)
      ON CONFLICT(target_id) DO UPDATE SET required_lanes_json=excluded.required_lanes_json,require_na_evidence=excluded.require_na_evidence,detect_removed_surfaces=excluded.detect_removed_surfaces,updated_by=excluded.updated_by,updated_at=excluded.updated_at,row_version=adaptive_target_policies.row_version+1`)
      .run(policy.targetId, JSON.stringify(policy.requiredLanes), policy.requireEvidenceForNotApplicable ? 1 : 0, policy.detectRemovedSurfaces ? 1 : 0, actor, now);
    return this.state(policy.targetId);
  }

  public acceptBaseline(snapshotId: string, modelDigest: string, actor: string): Record<string, unknown> {
    const row = this.database.db.prepare("SELECT id,target_id,status,model_digest,target_row_version FROM adaptive_security_snapshots WHERE id=?").get(snapshotId) as { id: string; target_id: string; status: string; model_digest: string; target_row_version: number } | undefined;
    if (!row || row.status !== "CANDIDATE" || row.model_digest !== modelDigest) throw new Error("ADAPTIVE_BASELINE_BINDING_MISMATCH");
    const target = this.database.db.prepare("SELECT row_version FROM targets WHERE id=?").get(row.target_id) as { row_version: number } | undefined;
    if (!target || target.row_version !== row.target_row_version) throw new Error("ADAPTIVE_TARGET_CHANGED_AFTER_OBSERVATION");
    this.database.transaction(() => {
      this.database.db.prepare("UPDATE adaptive_security_snapshots SET status='SUPERSEDED' WHERE target_id=? AND status='BASELINE'").run(row.target_id);
      this.database.db.prepare("UPDATE adaptive_security_snapshots SET status='BASELINE',accepted_by=?,accepted_at=? WHERE id=? AND status='CANDIDATE'").run(actor, nowIso(), snapshotId);
      this.database.db.prepare("UPDATE adaptive_security_drifts SET status='ACKNOWLEDGED' WHERE snapshot_id=? AND status='OPEN'").run(snapshotId);
    });
    return this.state(row.target_id);
  }

  public decideRecommendation(id: string, decision: "APPROVED" | "DISMISSED", rationale: string, actor: string): Record<string, unknown> {
    const row = this.recommendationRow(id);
    if (decision === "APPROVED" && (rationale.trim().length < 12 || !actor.trim())) throw new Error("ADAPTIVE_EXPLICIT_REVIEW_REQUIRED");
    if (!['PROPOSED','APPROVED'].includes(row.status)) throw new Error("ADAPTIVE_RECOMMENDATION_STATE_CONFLICT");
    this.database.db.prepare("UPDATE adaptive_security_recommendations SET status=?,operator_rationale=?,reviewed_by=?,reviewed_at=?,updated_at=? WHERE id=?")
      .run(decision, clamp(rationale, 1000), actor, nowIso(), nowIso(), id);
    return this.state(row.target_id);
  }

  public linkRecommendation(id: string, scanId: string, caseFingerprint: string, actor: string): Record<string, unknown> {
    const row = this.recommendationRow(id);
    if (row.status !== "APPROVED" && !(row.status === "PROPOSED" && row.operator_approval_required === 0)) throw new Error("ADAPTIVE_RECOMMENDATION_APPROVAL_REQUIRED");
    const scan = this.database.db.prepare("SELECT target_id,status,created_at FROM scans WHERE id=? AND deleted_at IS NULL").get(scanId) as { target_id: string | null; status: string; created_at: string } | undefined;
    if (!scan || scan.target_id !== row.target_id) throw new Error("ADAPTIVE_EXECUTION_TARGET_MISMATCH");
    const eligibleAfter = row.reviewed_at ?? (row.operator_approval_required === 0 ? row.created_at : undefined);
    if (!eligibleAfter || Date.parse(scan.created_at) < Date.parse(eligibleAfter)) throw new Error("ADAPTIVE_POST_APPROVAL_EXECUTION_REQUIRED");
    this.assertLinkedExecution(row, scanId);
    const status = verifyRecommendation(this.database, row.engine_id, scanId, scan.status, caseFingerprint);
    this.database.db.prepare("UPDATE adaptive_security_recommendations SET status=?,linked_scan_id=?,linked_case_fingerprint=?,execution_outcome=?,reviewed_by=COALESCE(reviewed_by,?),updated_at=? WHERE id=?")
      .run(status === "VERIFIED" ? "VERIFIED" : status === "INCONCLUSIVE" ? "INCONCLUSIVE" : "EXECUTION_LINKED", scanId, caseFingerprint, status, actor, nowIso(), id);
    return this.state(row.target_id);
  }

  public refreshRecommendation(id: string): Record<string, unknown> {
    const row = this.recommendationRow(id);
    if (!row.linked_scan_id) throw new Error("ADAPTIVE_EXECUTION_LINK_REQUIRED");
    const scan = this.database.db.prepare("SELECT status FROM scans WHERE id=?").get(row.linked_scan_id) as { status: string } | undefined;
    if (!scan) throw new Error("ADAPTIVE_LINKED_SCAN_UNAVAILABLE");
    if (!row.linked_case_fingerprint) throw new Error("ADAPTIVE_EXACT_CASE_BINDING_REQUIRED");
    this.assertLinkedExecution(row, row.linked_scan_id);
    const outcome = verifyRecommendation(this.database, row.engine_id, row.linked_scan_id, scan.status, row.linked_case_fingerprint);
    this.database.db.prepare("UPDATE adaptive_security_recommendations SET status=?,execution_outcome=?,updated_at=? WHERE id=?")
      .run(outcome === "VERIFIED" ? "VERIFIED" : outcome === "INCONCLUSIVE" ? "INCONCLUSIVE" : "EXECUTION_LINKED", outcome, nowIso(), id);
    return this.state(row.target_id);
  }

  public materializeRecommendation(id: string): Record<string, unknown> {
    const row = this.recommendationRow(id);
    const materialized = this.materialization(row);
    return {
      targetId: row.target_id,
      engineId: row.engine_id,
      engineConfiguration: materialized.engineConfiguration,
      binding: materialized.binding,
      authentication: materialized.authentication,
      limits: { maxRequests: Math.max(10, materialized.requestCount + materialized.cleanupRequestCount + 4), cleanupReservedRequests: materialized.cleanupRequestCount, evidenceLevel: "strong" },
      automation: materialized.automation
    };
  }

  public recommendationRequiresApproval(id: string): boolean {
    return Boolean(this.recommendationRow(id).operator_approval_required);
  }

  public assertExecutionBinding(request: DashboardScanCreateRequest): void {
    if (!request.adaptiveExecutionBinding) return;
    const binding = adaptiveExecutionBindingSchema.parse(request.adaptiveExecutionBinding);
    const row = this.recommendationRow(binding.recommendationId);
    const materialized = this.materialization(row);
    if (adaptiveDigest(binding) !== adaptiveDigest(materialized.binding) || binding.sourceFingerprint !== row.source_fingerprint) throw new Error("ADAPTIVE_EXECUTION_BINDING_MISMATCH");
    if (request.targetId !== row.target_id) throw new Error("ADAPTIVE_EXECUTION_TARGET_MISMATCH");
    const target = this.database.db.prepare("SELECT base_origin FROM targets WHERE id=?").get(row.target_id) as { base_origin: string } | undefined;
    if (!target || new URL(request.target).origin !== target.base_origin) throw new Error("ADAPTIVE_EXECUTION_TARGET_MISMATCH");
    const requestField = advancedEngineCatalog.find((entry) => entry.id === row.engine_id)?.requestField;
    if (!requestField) throw new Error("ADAPTIVE_EXECUTION_ENGINE_UNAVAILABLE");
    const configured = (request as unknown as Record<string, unknown>)[requestField];
    if (adaptiveDigest(configured) !== adaptiveDigest(materialized.engineConfiguration)) throw new Error("ADAPTIVE_EXECUTION_CONFIGURATION_CHANGED");
    const configuredAdvancedEngines = advancedEngineCatalog.filter((entry) => (request as unknown as Record<string, unknown>)[entry.requestField] !== undefined);
    if (configuredAdvancedEngines.length !== 1 || configuredAdvancedEngines[0]?.id !== row.engine_id) throw new Error("ADAPTIVE_EXECUTION_ADDITIONAL_ENGINE_FORBIDDEN");
    if (adaptiveDigest(request.studio?.authentication) !== adaptiveDigest(materialized.authentication)) throw new Error("ADAPTIVE_EXECUTION_AUTHENTICATION_CHANGED");
    if ((request.cleanupReservedRequests ?? 0) !== materialized.cleanupRequestCount) throw new Error("ADAPTIVE_EXECUTION_CLEANUP_RESERVE_INVALID");
  }

  public state(targetId: string): Record<string, unknown> {
    this.requireTarget(targetId);
    const policy = this.policy(targetId);
    const snapshots = (this.database.db.prepare("SELECT id,source_scan_id,status,model_digest,target_row_version,build_fingerprint,created_at,accepted_at FROM adaptive_security_snapshots WHERE target_id=? ORDER BY created_at DESC LIMIT 30").all(targetId) as SnapshotListRow[]).map(snapshotSummary);
    const drifts = this.database.db.prepare("SELECT id,snapshot_id,baseline_snapshot_id,drift_type,severity,semantic_key,semantic_fingerprint,safe_summary,status,created_at FROM adaptive_security_drifts WHERE target_id=? ORDER BY created_at DESC LIMIT 200").all(targetId);
    const recommendations = (this.database.db.prepare("SELECT r.id,r.target_id,r.snapshot_id,r.category,r.engine_id,r.lane_kind,r.source_fingerprint,r.status,r.mutation_hypothesis,r.operator_approval_required,r.safe_draft_json,r.required_bindings_json,r.operator_rationale,r.reviewed_by,r.reviewed_at,r.linked_scan_id,r.linked_case_fingerprint,r.execution_outcome,r.created_at,r.updated_at,b.profile_id AS adapter_profile_id,b.version_id AS adapter_version_id FROM adaptive_security_recommendations r LEFT JOIN provider_adapter_recommendation_bindings b ON b.recommendation_id=r.id WHERE r.target_id=? ORDER BY r.created_at DESC LIMIT 200").all(targetId) as RecommendationListRow[]).map((row) => ({ ...recommendationSummary(row), executionCandidates: this.executionCandidates(row) }));
    const latest = this.database.db.prepare("SELECT inventory_json FROM adaptive_security_snapshots WHERE target_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1").get(targetId) as { inventory_json: string } | undefined;
    const attackGraph = latest ? (JSON.parse(latest.inventory_json) as AdaptiveInventory).attackGraph : undefined;
    return { targetId, policy, coverage: this.coverage(targetId, policy), snapshots, drifts, recommendations, ...(attackGraph ? { attackGraph } : {}) };
  }

  public snapshot(id: string): Record<string, unknown> {
    const row = this.database.db.prepare("SELECT * FROM adaptive_security_snapshots WHERE id=?").get(id) as SnapshotRow | undefined;
    if (!row) throw new Error("ADAPTIVE_SNAPSHOT_NOT_FOUND");
    return { ...snapshotSummary(row), inventory: JSON.parse(row.inventory_json), state: this.state(row.target_id) };
  }

  private policy(targetId: string): { targetId: string; requiredLanes: string[]; requireEvidenceForNotApplicable: boolean; detectRemovedSurfaces: boolean; rowVersion: number } {
    const row = this.database.db.prepare("SELECT * FROM adaptive_target_policies WHERE target_id=?").get(targetId) as PolicyRow | undefined;
    return row ? { targetId, requiredLanes: JSON.parse(row.required_lanes_json), requireEvidenceForNotApplicable: Boolean(row.require_na_evidence), detectRemovedSurfaces: Boolean(row.detect_removed_surfaces), rowVersion: row.row_version } : { targetId, requiredLanes: [...defaultRequiredLanes], requireEvidenceForNotApplicable: true, detectRemovedSurfaces: true, rowVersion: 0 };
  }

  private coverage(targetId: string, policy: ReturnType<AdaptiveSecurityService["policy"]>): Record<string, unknown> {
    const run = this.database.db.prepare("SELECT r.id,r.created_at FROM live_acceptance_runs r JOIN live_acceptance_plans p ON p.id=r.plan_id WHERE p.target_id=? ORDER BY r.created_at DESC LIMIT 1").get(targetId) as { id: string; created_at: string } | undefined;
    const rows = run ? this.database.db.prepare(`SELECT l.kind,l.disposition,l.configured_outcome,l.safe_reason,l.scan_id,l.evidence_scan_id,s.status AS scan_status,es.status AS evidence_scan_status FROM live_acceptance_run_lanes l LEFT JOIN scans s ON s.id=l.scan_id LEFT JOIN scans es ON es.id=l.evidence_scan_id WHERE l.run_id=?`).all(run.id) as CoverageLaneRow[] : [];
    const lanes = policy.requiredLanes.map((kind) => {
      const matches = rows.filter((row) => row.kind === kind);
      if (!matches.length) return { kind, state: "MISSING", reason: "Required lane is absent from the latest acceptance run." };
      const assessed = matches.find((row) => row.scan_status === "COMPLETED" || row.scan_status === "IMPORTED");
      if (assessed && assessed.configured_outcome !== "NOT_APPLICABLE") return { kind, state: "ASSESSED", scanId: assessed.scan_id };
      const na = matches.find((row) => row.configured_outcome === "NOT_APPLICABLE");
      if (na) {
        const evidenceReady = Boolean(na.evidence_scan_id && (na.evidence_scan_status === "COMPLETED" || na.evidence_scan_status === "IMPORTED"));
        return evidenceReady || !policy.requireEvidenceForNotApplicable ? { kind, state: "NOT_APPLICABLE", reason: na.safe_reason, evidenceScanId: na.evidence_scan_id } : { kind, state: "EVIDENCE_REQUIRED", reason: "NOT_APPLICABLE requires a completed same-target evidence scan." };
      }
      return { kind, state: "NOT_ASSESSED", reason: matches[0]?.safe_reason ?? "The latest acceptance run did not assess this lane." };
    });
    const latestSnapshot = this.database.db.prepare("SELECT id,created_at FROM adaptive_security_snapshots WHERE target_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1").get(targetId) as { id: string; created_at: string } | undefined;
    const openDrift = run && latestSnapshot && Date.parse(latestSnapshot.created_at) >= Date.parse(run.created_at) ? this.database.db.prepare("SELECT COUNT(*) AS count FROM adaptive_security_drifts WHERE snapshot_id=? AND status='OPEN'").get(latestSnapshot.id) as { count: number } : undefined;
    const staleByDrift = Boolean(openDrift?.count);
    const laneGaps = lanes.filter((lane) => !["ASSESSED", "NOT_APPLICABLE"].includes(lane.state)).length;
    return { runId: run?.id, complete: laneGaps === 0 && !staleByDrift, required: lanes.length, gaps: laneGaps + (staleByDrift ? 1 : 0), modelGate: staleByDrift ? { state: "STALE", snapshotId: latestSnapshot?.id, openDriftCount: openDrift?.count, reason: "The deployed target model changed after the latest acceptance run began; acknowledge a new exact baseline or re-run after remediation." } : { state: "CURRENT" }, lanes };
  }

  private workflowCases(scanId: string): AdaptiveInventory["workflowCases"] {
    return (this.database.db.prepare("SELECT workflow_id,safe_case_fingerprint,execution_state FROM scan_workflow_case_executions WHERE scan_id=? ORDER BY workflow_id,safe_case_fingerprint").all(scanId) as Array<{ workflow_id: string; safe_case_fingerprint: string; execution_state: string }>).map((row) => ({ key: `${row.workflow_id}:${row.safe_case_fingerprint}`, workflowId: row.workflow_id, fingerprint: row.safe_case_fingerprint, executionState: row.execution_state }));
  }

  private insertRecommendation(targetId: string, snapshotId: string, item: AdaptiveRecommendation, createdAt: string): void {
    this.database.db.prepare(`INSERT OR IGNORE INTO adaptive_security_recommendations (id,target_id,snapshot_id,category,engine_id,lane_kind,source_fingerprint,status,mutation_hypothesis,operator_approval_required,safe_draft_json,required_bindings_json,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,'PROPOSED',?,?,?, ?,?,?)`).run(randomUUID(), targetId, snapshotId, item.category, item.engineId, item.laneKind, item.sourceFingerprint, item.mutationHypothesis ? 1 : 0, item.operatorApprovalRequired ? 1 : 0, JSON.stringify(item.draft), JSON.stringify(item.requiredBindings), createdAt, createdAt);
  }

  private executionCandidates(row: RecommendationListRow): Record<string, unknown>[] {
    if (row.status === "DISMISSED" || (row.operator_approval_required === 1 && (row.status === "PROPOSED" || !row.reviewed_at))) return [];
    const workflowId = engineWorkflow(row.engine_id);
    if (!workflowId) return [];
    const eligibleAfter = row.reviewed_at ?? row.created_at;
    return (this.database.db.prepare(`SELECT w.scan_id,w.safe_case_alias,w.safe_case_fingerprint,w.execution_state,w.matched_expectation,w.evidence_strength,s.status AS scan_status,s.created_at,s.safe_configuration_summary
      FROM scan_workflow_case_executions w JOIN scans s ON s.id=w.scan_id
      WHERE s.target_id=? AND s.deleted_at IS NULL AND s.status IN ('COMPLETED','IMPORTED') AND s.created_at>=? AND w.workflow_id=? AND w.execution_state='COMPLETED' AND w.request_transmitted=1 AND w.evidence_strength!=''
      ORDER BY s.created_at DESC LIMIT 30`).all(row.target_id, eligibleAfter, workflowId) as ExecutionCandidateRow[]).filter((item) => {
      try { this.assertLinkedExecution(row, item.scan_id); return true; } catch { return false; }
    }).map((item) => ({ scanId: item.scan_id, caseAlias: item.safe_case_alias, caseFingerprint: item.safe_case_fingerprint, executionState: item.execution_state, matchedExpectation: item.matched_expectation === null ? undefined : Boolean(item.matched_expectation), evidenceStrength: item.evidence_strength, scanStatus: item.scan_status, createdAt: item.created_at }));
  }

  private materialization(row: RecommendationRow): { engineConfiguration: Record<string, unknown>; requestCount: number; cleanupRequestCount: number; authentication: NonNullable<DashboardScanCreateRequest["studio"]>["authentication"]; binding: AdaptiveExecutionBinding; automation: Record<string, unknown> } {
    if (row.status === "DISMISSED") throw new Error("ADAPTIVE_AUTOMATION_UNAVAILABLE");
    const snapshot = this.database.db.prepare("SELECT target_row_version,source_scan_id,model_digest,inventory_json FROM adaptive_security_snapshots WHERE id=? AND target_id=?").get(row.snapshot_id, row.target_id) as { target_row_version: number; source_scan_id: string; model_digest: string; inventory_json: string } | undefined;
    const target = this.database.db.prepare("SELECT row_version,classification,production_mutation_enabled,default_credential_profile_id,default_auth_template_json FROM targets WHERE id=?").get(row.target_id) as { row_version: number; classification: string; production_mutation_enabled: number; default_credential_profile_id: string | null; default_auth_template_json: string } | undefined;
    const scan = snapshot ? this.database.db.prepare("SELECT status FROM scans WHERE id=? AND target_id=? AND deleted_at IS NULL").get(snapshot.source_scan_id, row.target_id) as { status: string } | undefined : undefined;
    if (!snapshot || !target || snapshot.target_row_version !== target.row_version || !scan || !["COMPLETED", "IMPORTED"].includes(scan.status)) throw new Error("ADAPTIVE_EXECUTION_SOURCE_STALE");
    const latest = this.database.db.prepare("SELECT model_digest FROM adaptive_security_snapshots WHERE target_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1").get(row.target_id) as { model_digest: string } | undefined;
    if (latest && latest.model_digest !== snapshot.model_digest) throw new Error("ADAPTIVE_EXECUTION_MODEL_STALE");
    const draft = JSON.parse(row.safe_draft_json) as Record<string, unknown>;
    const automation = draft.automation;
    const configuration = draft.engineConfiguration;
    if (!automation || typeof automation !== "object" || !configuration || typeof configuration !== "object" || Array.isArray(configuration) || draft.executable !== true) throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_INVALID");
    const state = automation as Record<string, unknown>;
    if (!["READY_READ_ONLY", "READY_APPROVAL_GATED"].includes(String(state.state)) || ![1, 2].includes(Number(state.compilerVersion)) || typeof state.requestCount !== "number" || typeof state.evidenceFingerprint !== "string") throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_INVALID");
    const compilerVersion = state.compilerVersion as 1 | 2;
    const templateExpected = adaptiveExecutionFingerprint(row.engine_id, row.source_fingerprint, String(state.evidenceFingerprint), configuration, compilerVersion);
    if (draft.executionFingerprint !== templateExpected) throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_FINGERPRINT_MISMATCH");
    const approvalRequired = state.mutationApprovalRequired === true;
    if (approvalRequired && (row.status !== "APPROVED" || !row.reviewed_at || !row.reviewed_by || !row.operator_rationale)) throw new Error("ADAPTIVE_MUTATION_APPROVAL_REQUIRED");
    if (approvalRequired && target.classification === "PRODUCTION" && target.production_mutation_enabled !== 1) throw new Error("ADAPTIVE_PRODUCTION_MUTATION_DISABLED");
    const expiresAt = row.reviewed_at ? new Date(Date.parse(row.reviewed_at) + 4 * 60 * 60 * 1000).toISOString() : "";
    if (approvalRequired && (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(row.reviewed_at!) > Date.now() || Date.parse(expiresAt) <= Date.now())) throw new Error("ADAPTIVE_MUTATION_APPROVAL_EXPIRED");
    const authorized = approvalRequired ? authorizeConfiguration(configuration as Record<string, unknown>, { reviewedAt: row.reviewed_at!, reviewedBy: row.reviewed_by!, rationale: row.operator_rationale!, expiresAt }) : configuration as Record<string, unknown>;
    const validated = validateAdvancedEngineInput(row.engine_id as AdvancedEngineId, authorized);
    if (!validated.valid || !validated.value || typeof validated.value !== "object" || Array.isArray(validated.value)) throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_INVALID");
    if (compilerVersion === 1 && !isReadOnlyConfiguration(row.engine_id, validated.value as Record<string, unknown>)) throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_NOT_READ_ONLY");
    const authentication = resolveAuthentication(String(state.authentication ?? "public") as AdaptiveAuthenticationRequirement, target);
    const expected = adaptiveDigest({ templateExpected, authorizedConfiguration: validated.value, authentication });
    const cleanupRequestCount = Number(state.cleanupRequestCount ?? 0);
    const graphBinding = attackGraphBinding(draft);
    const graph = (JSON.parse(snapshot.inventory_json) as AdaptiveInventory).attackGraph;
    if (graphBinding.graphFingerprint && (!graph || graphBinding.graphFingerprint !== graph.graphFingerprint || graphBinding.graphPathIds?.some((id) => !graph.paths.some((path) => path.id === id)))) throw new Error("ADAPTIVE_ATTACK_GRAPH_BINDING_INVALID");
    return { engineConfiguration: validated.value as Record<string, unknown>, requestCount: state.requestCount, cleanupRequestCount, authentication, binding: { recommendationId: row.id, sourceFingerprint: row.source_fingerprint, executionFingerprint: expected, compilerVersion, ...graphBinding }, automation: { ...state, approvalExpiresAt: approvalRequired ? expiresAt : undefined } };
  }

  private assertLinkedExecution(row: RecommendationRow, scanId: string): void {
    const draft = JSON.parse(row.safe_draft_json) as Record<string, unknown>;
    if (draft.executable !== true) return;
    const scan = this.database.db.prepare("SELECT safe_configuration_summary FROM scans WHERE id=?").get(scanId) as { safe_configuration_summary: string } | undefined;
    const binding = adaptiveExecutionBindingSchema.safeParse(JSON.parse(scan?.safe_configuration_summary ?? "{}").adaptiveExecutionBinding);
    const graph = attackGraphBinding(draft);
    if (!binding.success || binding.data.recommendationId !== row.id || binding.data.sourceFingerprint !== row.source_fingerprint || adaptiveDigest({ graphFingerprint: binding.data.graphFingerprint, graphPathIds: binding.data.graphPathIds }) !== adaptiveDigest(graph)) throw new Error("ADAPTIVE_LINKED_EXECUTION_BINDING_MISMATCH");
  }

  private recommendationRow(id: string): RecommendationRow { const row = this.database.db.prepare("SELECT * FROM adaptive_security_recommendations WHERE id=?").get(id) as RecommendationRow | undefined; if (!row) throw new Error("ADAPTIVE_RECOMMENDATION_NOT_FOUND"); return row; }
  private requireTarget(id: string): void { if (!this.database.db.prepare("SELECT 1 FROM targets WHERE id=?").get(id)) throw new Error("ADAPTIVE_TARGET_NOT_FOUND"); }
}
function attackGraphBinding(draft: Record<string, unknown>): Pick<AdaptiveExecutionBinding, "graphFingerprint" | "graphPathIds"> {
  if (draft.attackGraphBinding === undefined) return {};
  const binding = draft.attackGraphBinding;
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) throw new Error("ADAPTIVE_ATTACK_GRAPH_BINDING_INVALID");
  const value = binding as Record<string, unknown>;
  if (typeof value.graphFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(value.graphFingerprint) || !Array.isArray(value.graphPathIds) || value.graphPathIds.length < 1 || value.graphPathIds.length > 32 || value.graphPathIds.some((id) => typeof id !== "string" || !/^[a-f0-9]{64}$/.test(id))) throw new Error("ADAPTIVE_ATTACK_GRAPH_BINDING_INVALID");
  return { graphFingerprint: value.graphFingerprint, graphPathIds: [...new Set(value.graphPathIds as string[])].sort() };
}
function isReadOnlyConfiguration(engineId: string, value: Record<string, unknown>): boolean {
  if (engineId === "api-graphql-authorization") { const routes = Array.isArray(value.routes) ? value.routes as Array<Record<string, unknown>> : []; const checks = Array.isArray(value.checks) ? value.checks as Array<Record<string, unknown>> : []; return routes.length > 0 && checks.length > 0 && routes.every((route) => route.protocol === "GRAPHQL" || (Array.isArray(route.documentedMethods) && (route.documentedMethods as unknown[]).every((method) => ["GET", "HEAD", "OPTIONS"].includes(String(method))))) && checks.every((check) => check.kind === "GRAPHQL_INTROSPECTION" || !containsUnsafeMethod(check)); }
  if (engineId === "operational-endpoint-security") return !containsUnsafeMethod(value) && !containsTrueStateChanging(value);
  if (engineId === "billing-entitlement-security") { const cases = Array.isArray(value.cases) ? value.cases as Array<Record<string, unknown>> : []; return cases.length > 0 && cases.every((item) => item.authorization && (item.authorization as Record<string, unknown>).mode === "OBSERVE_ONLY" && item.cleanupRequired !== true && Array.isArray(item.steps) && (item.steps as Array<Record<string, unknown>>).length > 0 && (item.steps as Array<Record<string, unknown>>).every((step) => step.operation === "OBSERVE" && !containsUnsafeMethod(step) && step.request && (step.request as Record<string, unknown>).stateChanging !== true)); }
  if (engineId === "business-invariant") { const cases = Array.isArray(value.cases) ? value.cases as Array<Record<string, unknown>> : []; return cases.length > 0 && cases.every((item) => item.authorization && (item.authorization as Record<string, unknown>).mode === "OBSERVE_ONLY" && item.cleanupRequired !== true && Array.isArray(item.actions) && (item.actions as unknown[]).length === 0 && Array.isArray(item.cleanup) && (item.cleanup as unknown[]).length === 0 && Array.isArray(item.cleanupVerification) && (item.cleanupVerification as unknown[]).length === 0 && !containsTrueStateChanging(item) && Array.isArray(item.preState) && Array.isArray(item.postState) && [...(item.preState as Array<Record<string, unknown>>), ...(item.postState as Array<Record<string, unknown>>)].every((state) => ["GET", "HEAD"].includes(String((state.request as Record<string, unknown>)?.method)))); }
  if (engineId === "supabase-authorization") { const cases = Array.isArray(value.cases) ? value.cases as Array<Record<string, unknown>> : []; return cases.length > 0 && cases.every((item) => item.operation === "SELECT" && ["GET", "HEAD"].includes(String(item.method)) && item.actor === "ANONYMOUS"); }
  return false;
}
function containsUnsafeMethod(value: unknown): boolean { if (Array.isArray(value)) return value.some(containsUnsafeMethod); if (!value || typeof value !== "object") return false; const item = value as Record<string, unknown>; if (typeof item.method === "string" && !["GET", "HEAD", "OPTIONS"].includes(item.method)) return true; return Object.values(item).some(containsUnsafeMethod); }
function containsTrueStateChanging(value: unknown): boolean { if (Array.isArray(value)) return value.some(containsTrueStateChanging); if (!value || typeof value !== "object") return false; const item = value as Record<string, unknown>; if (item.stateChanging === true || item.cleanupRequired === true) return true; return Object.values(item).some(containsTrueStateChanging); }
function resolveAuthentication(requirement: AdaptiveAuthenticationRequirement, target: { default_credential_profile_id: string | null; default_auth_template_json: string }): NonNullable<DashboardScanCreateRequest["studio"]>["authentication"] {
  if (requirement === "public") return { mode: "public" };
  let template: Record<string, unknown> = {};
  try { const parsed = JSON.parse(target.default_auth_template_json) as unknown; if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) template = parsed as Record<string, unknown>; } catch { /* target templates are validated elsewhere; fail closed below */ }
  const savedId = (value: unknown): string | undefined => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value) ? value : undefined;
  const actorId = (value: unknown): string | undefined => value && typeof value === "object" && !Array.isArray(value) && (value as Record<string, unknown>).source === "saved" ? savedId((value as Record<string, unknown>).credentialProfileId) : undefined;
  if (requirement === "primary") {
    const id = target.default_credential_profile_id ?? savedId(template.credentialProfileId) ?? actorId(template.primary);
    if (!id) throw new Error("ADAPTIVE_PRIMARY_AUTHENTICATION_FIXTURE_REQUIRED");
    return { mode: "primary", primary: { source: "saved", credentialProfileId: id } };
  }
  const left = savedId(template.accountAProfileId) ?? savedId(template.accountACredentialProfileId) ?? actorId(template.accountA);
  const right = savedId(template.accountBProfileId) ?? savedId(template.accountBCredentialProfileId) ?? actorId(template.accountB);
  if (!left || !right || left === right) throw new Error("ADAPTIVE_ACCOUNT_PAIR_AUTHENTICATION_FIXTURE_REQUIRED");
  return { mode: "account-pair", accountA: { source: "saved", credentialProfileId: left }, accountB: { source: "saved", credentialProfileId: right } };
}
function verifyRecommendation(database: DashboardDatabase, engineId: string, scanId: string, scanStatus: string, caseFingerprint: string): "RUNNING" | "VERIFIED" | "INCONCLUSIVE" { if (!terminalScans.has(scanStatus)) return "RUNNING"; if (!["COMPLETED","IMPORTED"].includes(scanStatus)) return "INCONCLUSIVE"; const module = engineModule(engineId); const workflow = engineWorkflow(engineId); if (!module || !workflow) return "INCONCLUSIVE"; const moduleRow = database.db.prepare("SELECT status FROM scan_module_executions WHERE scan_id=? AND module_id=?").get(scanId, module) as { status: string } | undefined; const caseRow = database.db.prepare("SELECT execution_state,request_transmitted,evidence_strength FROM scan_workflow_case_executions WHERE scan_id=? AND workflow_id=? AND safe_case_fingerprint=?").get(scanId, workflow, caseFingerprint) as { execution_state: string; request_transmitted: number; evidence_strength: string } | undefined; return moduleRow?.status === "COMPLETED" && caseRow?.execution_state === "COMPLETED" && caseRow.request_transmitted === 1 && Boolean(caseRow.evidence_strength) ? "VERIFIED" : "INCONCLUSIVE"; }
function engineModule(id: string): string | undefined { return ({ "authentication-lifecycle": "authentication-lifecycle", "api-graphql-authorization": "api-graphql-authorization", "link-portal-export-security": "link-portal-export-security", "operational-endpoint-security": "operational-endpoint-security", "billing-entitlement-security": "billing-entitlement-security", "business-invariant": "business-invariant", "supabase-authorization": "supabase-authorization", "active-vulnerability-validation": "active-vulnerability-validation" } as Record<string,string>)[id]; }
function engineWorkflow(id: string): string | undefined { return engineModule(id); }
function snapshotSummary(row: SnapshotListRow | SnapshotRow): Record<string, unknown> { return { id: row.id, sourceScanId: row.source_scan_id, status: row.status, modelDigest: row.model_digest, targetRowVersion: row.target_row_version, buildFingerprint: row.build_fingerprint, createdAt: row.created_at, ...(row.accepted_at ? { acceptedAt: row.accepted_at } : {}) }; }
function recommendationSummary(row: RecommendationListRow): Record<string, unknown> { return { id: row.id, snapshotId: row.snapshot_id, category: row.category, engineId: row.engine_id, laneKind: row.lane_kind, sourceFingerprint: row.source_fingerprint, status: row.status, mutationHypothesis: Boolean(row.mutation_hypothesis), operatorApprovalRequired: Boolean(row.operator_approval_required), draft: JSON.parse(row.safe_draft_json), requiredBindings: JSON.parse(row.required_bindings_json), ...(row.operator_rationale ? { rationale: row.operator_rationale } : {}), ...(row.linked_scan_id ? { linkedScanId: row.linked_scan_id } : {}), ...(row.linked_case_fingerprint ? { linkedCaseFingerprint: row.linked_case_fingerprint } : {}), ...(row.execution_outcome ? { executionOutcome: row.execution_outcome } : {}), ...(row.adapter_profile_id ? { adapterProfileId: row.adapter_profile_id, adapterVersionId: row.adapter_version_id } : {}), createdAt: row.created_at, updatedAt: row.updated_at }; }
interface PolicyRow { required_lanes_json: string; require_na_evidence: number; detect_removed_surfaces: number; row_version: number }
interface SnapshotListRow { id: string; source_scan_id: string; status: string; model_digest: string; target_row_version: number; build_fingerprint: string; created_at: string; accepted_at: string | null }
interface SnapshotRow extends SnapshotListRow { target_id: string; inventory_json: string }
interface RecommendationListRow { id: string; target_id: string; snapshot_id: string; category: string; engine_id: string; lane_kind: string; source_fingerprint: string; status: string; mutation_hypothesis: number; operator_approval_required: number; safe_draft_json: string; required_bindings_json: string; operator_rationale: string | null; reviewed_by: string | null; reviewed_at: string | null; linked_scan_id: string | null; linked_case_fingerprint: string | null; execution_outcome: string | null; adapter_profile_id?: string | null; adapter_version_id?: string | null; created_at: string; updated_at: string }
interface RecommendationRow extends RecommendationListRow { target_id: string }
interface CoverageLaneRow { kind: string; disposition: string; configured_outcome: string | null; safe_reason: string | null; scan_id: string | null; evidence_scan_id: string | null; scan_status: string | null; evidence_scan_status: string | null }
interface ExecutionCandidateRow { scan_id: string; safe_case_alias: string; safe_case_fingerprint: string; execution_state: string; matched_expectation: number | null; evidence_strength: string; scan_status: string; created_at: string }
