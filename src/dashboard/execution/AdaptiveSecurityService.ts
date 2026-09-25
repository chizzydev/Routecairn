import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import type { RouteCairnReport, BrowserLearnedTestCase } from "../../reports/ReportTypes.js";
import { adaptivePolicyInputSchema } from "../contracts/AdaptiveSecuritySchemas.js";
import type { LiveAcceptanceLane } from "../contracts/LiveAcceptanceSchemas.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { validateAdvancedEngineInput, advancedEngineCatalog, type AdvancedEngineId } from "../contracts/AdvancedEngineSchemas.js";
import { adaptiveExecutionBindingSchema, type AdaptiveExecutionBinding } from "../contracts/AdaptiveSecuritySchemas.js";
import { compileBillingReadOnlyCase, compileBusinessInvariantReadOnlyCase, compileGraphqlIntrospectionCase, compileOperationalHealthCase, compileRouteReadOnlyCase, compileSupabaseReadOnlyCase, type AdaptiveCompiledReadOnlyCase } from "./AdaptiveReadOnlyCompiler.js";
import { authorizeConfiguration, compileExecutedContracts, type AdaptiveCompiledContract, type AdaptiveAuthenticationRequirement } from "./AdaptiveContractCompiler.js";

const defaultRequiredLanes = ["PUBLIC_BASELINE", "AUTHENTICATED_IDENTITY", "ACCOUNT_PAIR_AUTHORIZATION", "BROWSER_LEARNING", "AUTHENTICATION_LIFECYCLE", "API_GRAPHQL_AUTHORIZATION", "DATA_AUTHORIZATION", "BUSINESS_LOGIC", "OPERATIONAL_ENDPOINTS", "BILLING_ENTITLEMENTS", "MUTATION_ACCEPTANCE", "RECOVERY_ACCEPTANCE"] as const;
const terminalScans = new Set(["COMPLETED", "IMPORTED", "FAILED", "CANCELLED", "INTERRUPTED"]);

export interface AdaptiveInventory {
  schemaVersion: 1;
  buildFingerprint: string;
  buildEvidence: boolean;
  producers: string[];
  origins: string[];
  routes: Array<{ key: string; protocol: "REST" | "GRAPHQL"; method: string; pathTemplate: string; source: string; stateChanging: boolean }>;
  fields: Array<{ key: string; pagePath: string; name: string; controlType: string; access: string }>;
  apiFields: Array<{ key: string; path: string; classification: string; expectation: string }>;
  cookies: Array<{ key: string; origin: string; name: string; classification: string; httpOnly?: boolean; secure?: boolean; sameSite?: string }>;
  graphql: string[];
  graphqlOperations: Array<{ key: string; kind: string; routeAliases: string[]; fingerprint: string }>;
  adminRoutes: string[];
  roles: string[];
  versions: string[];
  supabaseResources: Array<{ key: string; surface: string; resource: string; operations: string[]; actors: string[] }>;
  lifecycleCategories: string[];
  workflowCases: Array<{ key: string; workflowId: string; fingerprint: string; executionState: string }>;
}

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
    if (!target || new URL(report.target).origin !== target.base_origin) throw new Error("ADAPTIVE_TARGET_BINDING_MISMATCH");
    const existing = this.database.db.prepare("SELECT id FROM adaptive_security_snapshots WHERE source_scan_id=?").get(scanId) as { id: string } | undefined;
    if (existing) return this.snapshot(existing.id);
    const inventory = inventoryFrom(report, this.workflowCases(scanId));
    const modelDigest = digest(inventory);
    const baseline = this.database.db.prepare("SELECT id,inventory_json FROM adaptive_security_snapshots WHERE target_id=? AND status='BASELINE' ORDER BY accepted_at DESC LIMIT 1").get(target.id) as { id: string; inventory_json: string } | undefined;
    const snapshotId = randomUUID();
    const createdAt = nowIso();
    this.database.transaction(() => {
      this.database.db.prepare("INSERT INTO adaptive_security_snapshots (id,target_id,source_scan_id,status,model_digest,target_row_version,build_fingerprint,inventory_json,created_at) VALUES (?,?,?,'CANDIDATE',?,?,?,?,?)")
        .run(snapshotId, target.id, scanId, modelDigest, target.row_version, inventory.buildFingerprint, JSON.stringify(inventory), createdAt);
      const drifts: Drift[] = baseline ? compareInventory(JSON.parse(baseline.inventory_json) as AdaptiveInventory, inventory, this.policy(target.id).detectRemovedSurfaces) : [{ type: "INITIAL_MODEL", severity: "INFO", semanticKey: "model", summary: "Initial target security model captured; operator baseline acceptance is required." }];
      for (const drift of drifts) this.database.db.prepare("INSERT INTO adaptive_security_drifts (id,target_id,snapshot_id,baseline_snapshot_id,drift_type,severity,semantic_key,semantic_fingerprint,safe_summary,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,'OPEN',?)")
        .run(randomUUID(), target.id, snapshotId, baseline?.id ?? null, drift.type, drift.severity, drift.semanticKey, digest(drift), clamp(drift.summary, 500), createdAt);
      for (const recommendation of recommendations(report, inventory, drifts)) this.insertRecommendation(target.id, snapshotId, recommendation, createdAt);
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
    if (binding.sourceFingerprint !== row.source_fingerprint || binding.executionFingerprint !== materialized.binding.executionFingerprint || binding.compilerVersion !== materialized.binding.compilerVersion) throw new Error("ADAPTIVE_EXECUTION_BINDING_MISMATCH");
    if (request.targetId !== row.target_id) throw new Error("ADAPTIVE_EXECUTION_TARGET_MISMATCH");
    const target = this.database.db.prepare("SELECT base_origin FROM targets WHERE id=?").get(row.target_id) as { base_origin: string } | undefined;
    if (!target || new URL(request.target).origin !== target.base_origin) throw new Error("ADAPTIVE_EXECUTION_TARGET_MISMATCH");
    const requestField = advancedEngineCatalog.find((entry) => entry.id === row.engine_id)?.requestField;
    if (!requestField) throw new Error("ADAPTIVE_EXECUTION_ENGINE_UNAVAILABLE");
    const configured = (request as unknown as Record<string, unknown>)[requestField];
    if (digest(configured) !== digest(materialized.engineConfiguration)) throw new Error("ADAPTIVE_EXECUTION_CONFIGURATION_CHANGED");
    const configuredAdvancedEngines = advancedEngineCatalog.filter((entry) => (request as unknown as Record<string, unknown>)[entry.requestField] !== undefined);
    if (configuredAdvancedEngines.length !== 1 || configuredAdvancedEngines[0]?.id !== row.engine_id) throw new Error("ADAPTIVE_EXECUTION_ADDITIONAL_ENGINE_FORBIDDEN");
    if (digest(request.studio?.authentication) !== digest(materialized.authentication)) throw new Error("ADAPTIVE_EXECUTION_AUTHENTICATION_CHANGED");
    if ((request.cleanupReservedRequests ?? 0) !== materialized.cleanupRequestCount) throw new Error("ADAPTIVE_EXECUTION_CLEANUP_RESERVE_INVALID");
  }

  public state(targetId: string): Record<string, unknown> {
    this.requireTarget(targetId);
    const policy = this.policy(targetId);
    const snapshots = (this.database.db.prepare("SELECT id,source_scan_id,status,model_digest,target_row_version,build_fingerprint,created_at,accepted_at FROM adaptive_security_snapshots WHERE target_id=? ORDER BY created_at DESC LIMIT 30").all(targetId) as SnapshotListRow[]).map(snapshotSummary);
    const drifts = this.database.db.prepare("SELECT id,snapshot_id,baseline_snapshot_id,drift_type,severity,semantic_key,semantic_fingerprint,safe_summary,status,created_at FROM adaptive_security_drifts WHERE target_id=? ORDER BY created_at DESC LIMIT 200").all(targetId);
    const recommendations = (this.database.db.prepare("SELECT r.id,r.target_id,r.snapshot_id,r.category,r.engine_id,r.lane_kind,r.source_fingerprint,r.status,r.mutation_hypothesis,r.operator_approval_required,r.safe_draft_json,r.required_bindings_json,r.operator_rationale,r.reviewed_by,r.reviewed_at,r.linked_scan_id,r.linked_case_fingerprint,r.execution_outcome,r.created_at,r.updated_at,b.profile_id AS adapter_profile_id,b.version_id AS adapter_version_id FROM adaptive_security_recommendations r LEFT JOIN provider_adapter_recommendation_bindings b ON b.recommendation_id=r.id WHERE r.target_id=? ORDER BY r.created_at DESC LIMIT 200").all(targetId) as RecommendationListRow[]).map((row) => ({ ...recommendationSummary(row), executionCandidates: this.executionCandidates(row) }));
    return { targetId, policy, coverage: this.coverage(targetId, policy), snapshots, drifts, recommendations };
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

  private insertRecommendation(targetId: string, snapshotId: string, item: Recommendation, createdAt: string): void {
    this.database.db.prepare(`INSERT OR IGNORE INTO adaptive_security_recommendations (id,target_id,snapshot_id,category,engine_id,lane_kind,source_fingerprint,status,mutation_hypothesis,operator_approval_required,safe_draft_json,required_bindings_json,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,'PROPOSED',?,?,?, ?,?,?)`).run(randomUUID(), targetId, snapshotId, item.category, item.engineId, item.laneKind, item.sourceFingerprint, item.mutationHypothesis ? 1 : 0, item.operatorApprovalRequired ? 1 : 0, JSON.stringify(item.draft), JSON.stringify(item.requiredBindings), createdAt, createdAt);
  }

  private executionCandidates(row: RecommendationListRow): Record<string, unknown>[] {
    if (row.status === "DISMISSED" || (row.operator_approval_required === 1 && (row.status === "PROPOSED" || !row.reviewed_at))) return [];
    const workflowId = engineWorkflow(row.engine_id);
    if (!workflowId) return [];
    const eligibleAfter = row.reviewed_at ?? row.created_at;
    return (this.database.db.prepare(`SELECT w.scan_id,w.safe_case_alias,w.safe_case_fingerprint,w.execution_state,w.matched_expectation,w.evidence_strength,s.status AS scan_status,s.created_at
      FROM scan_workflow_case_executions w JOIN scans s ON s.id=w.scan_id
      WHERE s.target_id=? AND s.deleted_at IS NULL AND s.status IN ('COMPLETED','IMPORTED') AND s.created_at>=? AND w.workflow_id=? AND w.execution_state='COMPLETED'
      ORDER BY s.created_at DESC LIMIT 30`).all(row.target_id, eligibleAfter, workflowId) as ExecutionCandidateRow[]).map((item) => ({ scanId: item.scan_id, caseAlias: item.safe_case_alias, caseFingerprint: item.safe_case_fingerprint, executionState: item.execution_state, matchedExpectation: item.matched_expectation === null ? undefined : Boolean(item.matched_expectation), evidenceStrength: item.evidence_strength, scanStatus: item.scan_status, createdAt: item.created_at }));
  }

  private materialization(row: RecommendationRow): { engineConfiguration: Record<string, unknown>; requestCount: number; cleanupRequestCount: number; authentication: NonNullable<DashboardScanCreateRequest["studio"]>["authentication"]; binding: AdaptiveExecutionBinding; automation: Record<string, unknown> } {
    if (row.status === "DISMISSED") throw new Error("ADAPTIVE_AUTOMATION_UNAVAILABLE");
    const snapshot = this.database.db.prepare("SELECT target_row_version,source_scan_id FROM adaptive_security_snapshots WHERE id=? AND target_id=?").get(row.snapshot_id, row.target_id) as { target_row_version: number; source_scan_id: string } | undefined;
    const target = this.database.db.prepare("SELECT row_version,classification,production_mutation_enabled,default_credential_profile_id,default_auth_template_json FROM targets WHERE id=?").get(row.target_id) as { row_version: number; classification: string; production_mutation_enabled: number; default_credential_profile_id: string | null; default_auth_template_json: string } | undefined;
    const scan = snapshot ? this.database.db.prepare("SELECT status FROM scans WHERE id=? AND target_id=? AND deleted_at IS NULL").get(snapshot.source_scan_id, row.target_id) as { status: string } | undefined : undefined;
    if (!snapshot || !target || snapshot.target_row_version !== target.row_version || !scan || !["COMPLETED", "IMPORTED"].includes(scan.status)) throw new Error("ADAPTIVE_EXECUTION_SOURCE_STALE");
    const draft = JSON.parse(row.safe_draft_json) as Record<string, unknown>;
    const automation = draft.automation;
    const configuration = draft.engineConfiguration;
    if (!automation || typeof automation !== "object" || !configuration || typeof configuration !== "object" || Array.isArray(configuration) || draft.executable !== true) throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_INVALID");
    const state = automation as Record<string, unknown>;
    if (!["READY_READ_ONLY", "READY_APPROVAL_GATED"].includes(String(state.state)) || ![1, 2].includes(Number(state.compilerVersion)) || typeof state.requestCount !== "number" || typeof state.evidenceFingerprint !== "string") throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_INVALID");
    const compilerVersion = state.compilerVersion as 1 | 2;
    const templateExpected = executionFingerprint(row.engine_id, row.source_fingerprint, String(state.evidenceFingerprint), configuration, compilerVersion);
    if (draft.executionFingerprint !== templateExpected) throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_FINGERPRINT_MISMATCH");
    const approvalRequired = state.mutationApprovalRequired === true;
    if (approvalRequired && (row.status !== "APPROVED" || !row.reviewed_at || !row.reviewed_by || !row.operator_rationale)) throw new Error("ADAPTIVE_MUTATION_APPROVAL_REQUIRED");
    if (approvalRequired && target.classification === "PRODUCTION" && target.production_mutation_enabled !== 1) throw new Error("ADAPTIVE_PRODUCTION_MUTATION_DISABLED");
    const expiresAt = row.reviewed_at ? new Date(Date.parse(row.reviewed_at) + 4 * 60 * 60 * 1000).toISOString() : "";
    if (approvalRequired && Date.parse(expiresAt) <= Date.now()) throw new Error("ADAPTIVE_MUTATION_APPROVAL_EXPIRED");
    const authorized = approvalRequired ? authorizeConfiguration(configuration as Record<string, unknown>, { reviewedAt: row.reviewed_at!, reviewedBy: row.reviewed_by!, rationale: row.operator_rationale!, expiresAt }) : configuration as Record<string, unknown>;
    const validated = validateAdvancedEngineInput(row.engine_id as AdvancedEngineId, authorized);
    if (!validated.valid || !validated.value || typeof validated.value !== "object" || Array.isArray(validated.value)) throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_INVALID");
    if (compilerVersion === 1 && !isReadOnlyConfiguration(row.engine_id, validated.value as Record<string, unknown>)) throw new Error("ADAPTIVE_EXECUTABLE_DRAFT_NOT_READ_ONLY");
    const authentication = resolveAuthentication(String(state.authentication ?? "public") as AdaptiveAuthenticationRequirement, target);
    const expected = digest({ templateExpected, authorizedConfiguration: validated.value, authentication });
    const cleanupRequestCount = Number(state.cleanupRequestCount ?? 0);
    return { engineConfiguration: validated.value as Record<string, unknown>, requestCount: state.requestCount, cleanupRequestCount, authentication, binding: { recommendationId: row.id, sourceFingerprint: row.source_fingerprint, executionFingerprint: expected, compilerVersion }, automation: { ...state, approvalExpiresAt: approvalRequired ? expiresAt : undefined } };
  }

  private recommendationRow(id: string): RecommendationRow { const row = this.database.db.prepare("SELECT * FROM adaptive_security_recommendations WHERE id=?").get(id) as RecommendationRow | undefined; if (!row) throw new Error("ADAPTIVE_RECOMMENDATION_NOT_FOUND"); return row; }
  private requireTarget(id: string): void { if (!this.database.db.prepare("SELECT 1 FROM targets WHERE id=?").get(id)) throw new Error("ADAPTIVE_TARGET_NOT_FOUND"); }
}

function inventoryFrom(report: RouteCairnReport, workflowCases: AdaptiveInventory["workflowCases"]): AdaptiveInventory {
  const routes = new Map<string, AdaptiveInventory["routes"][number]>();
  const origins = new Set<string>([new URL(report.target).origin]);
  const addRoute = (raw: string, method: string, protocol: "REST" | "GRAPHQL", source: string) => { try { const url = new URL(raw, report.target); origins.add(url.origin); const pathTemplate = safePath(url.pathname); const normalizedMethod = method.toUpperCase().slice(0, 12); const key = `${protocol}:${normalizedMethod}:${pathTemplate}`; routes.set(key, { key, protocol, method: normalizedMethod, pathTemplate, source, stateChanging: ["POST","PUT","PATCH","DELETE"].includes(normalizedMethod) }); } catch { /* invalid learned URL omitted */ } };
  for (const item of report.apiMapper?.endpoints ?? []) addRoute(item.endpoint, item.method, item.endpoint.toLowerCase().includes("graphql") ? "GRAPHQL" : "REST", "api-mapper");
  for (const item of report.browserCrawl?.authentication?.learnedTestCases ?? []) addRoute(item.endpoint, item.method, item.endpoint.toLowerCase().includes("graphql") ? "GRAPHQL" : "REST", "browser-learning");
  for (const item of report.apiGraphql?.inventory ?? []) addRoute(new URL(item.path, report.target).toString(), item.documentedMethods[0] ?? "POST", item.protocol, "api-graphql-inventory");
  const fields = (report.browserCrawl?.authentication?.fields ?? []).map((item) => { const pagePath = safePath(new URL(item.pageUrl, report.target).pathname); const name = safeName(item.name); return { key: `${pagePath}:${name}:${safeName(item.controlType)}`, pagePath, name, controlType: safeName(item.controlType), access: item.access }; }).sort(byKey);
  const cookies = (report.browserCrawl?.authentication?.storage ?? []).filter((item) => item.storage === "cookie").map((item) => ({ key: `${safeName(item.origin)}:${safeName(item.name)}`, origin: safeName(item.origin), name: safeName(item.name), classification: item.classification, ...(item.httpOnly !== undefined ? { httpOnly: item.httpOnly } : {}), ...(item.secure !== undefined ? { secure: item.secure } : {}), ...(item.sameSite ? { sameSite: safeName(item.sameSite) } : {}) })).sort(byKey);
  const graphql = [...new Set([...(report.apiMapper?.graphQlEndpoints ?? []), ...(report.apiProbe?.graphQlEndpoints ?? []), ...(report.apiGraphql?.inventory.filter((item) => item.protocol === "GRAPHQL").map((item) => item.path) ?? [])].map((item) => safePath(new URL(item, report.target).pathname)))].sort();
  const graphqlOperations = (report.apiGraphql?.checks ?? []).filter((item) => item.protocols.includes("GRAPHQL")).map((item) => ({ key: `${safeName(item.kind)}:${item.routeAliases.map(safeName).sort().join(",")}:${item.comparisonFingerprint}`, kind: safeName(item.kind), routeAliases: item.routeAliases.map(safeName).sort(), fingerprint: item.comparisonFingerprint })).sort(byKey);
  const apiFields = (report.apiGraphql?.checks ?? []).flatMap((check) => check.fields.map((item) => ({ key: `${safeName(check.checkId)}:${safeName(item.path)}`, path: safeName(item.path), classification: safeName(item.classification), expectation: safeName(item.expectation) }))).sort(byKey);
  const supabaseResources = (report.supabaseAuthorization?.resourceCoverage ?? []).map((item) => ({ key: `${item.surface}:${safeName(item.resource)}`, surface: item.surface, resource: safeName(item.resource), operations: [...item.operations].sort(), actors: [...item.actors].sort() })).sort(byKey);
  const lifecycleCategories = Object.entries(report.authenticationLifecycle?.coverage ?? {}).filter(([, value]) => value.planned > 0).map(([key]) => key).sort();
  const roles = [...new Set([
    ...(report.authenticationLifecycle?.observations ?? []).flatMap((item) => item.actorModel.flatMap((actor) => [actor.safeAlias, actor.relationship, actor.tenantAlias ?? ""])),
    ...(report.businessInvariant?.observations ?? []).flatMap((item) => item.actorModel.flatMap((actor) => [actor.safeAlias, actor.relationship, actor.tenantAlias ?? ""])),
    ...(report.apiGraphql?.authorizationMatrices ?? []).flatMap((item) => item.cells.flatMap((cell) => [cell.actorAlias, cell.relationship])),
    ...(report.supabaseAuthorization?.observations ?? []).flatMap((item) => [item.actor, item.boundary])
  ].filter(Boolean).map(safeName))].sort();
  const versions = [...new Set((report.apiGraphql?.inventory ?? []).flatMap((item) => item.version ? [safeName(item.version)] : []))].sort();
  const reportCases = observedWorkflowCases(report);
  const mergedCases = new Map([...workflowCases, ...reportCases].map((item) => [item.key, item]));
  const producers = [report.apiMapper && "api-mapper", report.apiProbe && "api-probe", report.apiGraphql && "api-graphql", report.browserCrawl?.authentication && "browser-learning", report.supabaseAuthorization && "supabase-authorization", report.authenticationLifecycle && "authentication-lifecycle", report.businessInvariant && "business-invariant", report.controlledRace && "controlled-race", report.linkPortalSecurity && "link-portal-export-security", report.operationalEndpointSecurity && "operational-endpoint-security", report.billingEntitlement && "billing-entitlement-security", report.activeVulnerability && "active-vulnerability-validation", report.protocolSecurity && "protocol-security"].filter((item): item is string => Boolean(item)).sort();
  const buildSignals = { technologies: report.technologies.map((item) => item.name).sort(), nextBuild: report.nextJsReview?.buildIds ?? [] };
  return { schemaVersion: 1, buildFingerprint: digest(buildSignals), buildEvidence: buildSignals.technologies.length > 0 || buildSignals.nextBuild.length > 0, producers, origins: [...origins].sort(), routes: [...routes.values()].sort(byKey), fields, apiFields, cookies, graphql, graphqlOperations, adminRoutes: [...new Set((report.browserCrawl?.authentication?.adminRoutes ?? []).map((item) => safePath(new URL(item, report.target).pathname)))].sort(), roles, versions, supabaseResources, lifecycleCategories, workflowCases: [...mergedCases.values()].sort(byKey) };
}

function observedWorkflowCases(report: RouteCairnReport): AdaptiveInventory["workflowCases"] {
  const output: AdaptiveInventory["workflowCases"] = [];
  const add = (workflowId: string, values: readonly unknown[], idFields: readonly string[] = ["caseId", "checkId", "id"]): void => {
    for (const value of values) {
      if (!value || typeof value !== "object") continue;
      const item = value as Record<string, unknown>;
      const alias = idFields.map((field) => item[field]).find((candidate) => typeof candidate === "string") as string | undefined;
      const fingerprint = typeof item.comparisonFingerprint === "string" && /^[a-f0-9]{64}$/i.test(item.comparisonFingerprint) ? item.comparisonFingerprint.toLowerCase() : undefined;
      if (!alias || !fingerprint) continue;
      const outcome = String(item.outcome ?? item.observedDecision ?? "OBSERVED");
      output.push({ key: `${workflowId}:${safeName(alias)}:${fingerprint}`, workflowId, fingerprint, executionState: /BLOCKED/.test(outcome) ? "BLOCKED" : /INCONCLUSIVE|ERROR|FAILED/.test(outcome) ? "FAILED" : "COMPLETED" });
    }
  };
  add("supabase-authorization", report.supabaseAuthorization?.observations ?? []);
  add("supabase-static-risk", report.supabaseAuthorization?.staticRisks ?? []);
  add("authentication-lifecycle", report.authenticationLifecycle?.observations ?? []);
  add("business-invariant", report.businessInvariant?.observations ?? []);
  add("controlled-race", report.controlledRace?.observations ?? []);
  add("api-graphql-authorization", report.apiGraphql?.checks ?? []);
  add("api-schema-comparison", report.apiGraphql?.schemaComparisons ?? [], ["routeId"]);
  add("link-portal-export-security", report.linkPortalSecurity?.observations ?? []);
  add("operational-endpoint-security", report.operationalEndpointSecurity?.observations ?? []);
  add("billing-entitlement-security", report.billingEntitlement?.observations ?? []);
  add("active-vulnerability-validation", report.activeVulnerability?.cases ?? []);
  add("protocol-security", report.protocolSecurity?.observations ?? []);
  return output;
}

function compareInventory(before: AdaptiveInventory, after: AdaptiveInventory, includeRemoved: boolean): Drift[] {
  const output: Drift[] = [];
  const covered = (producer: string): boolean => (before.producers ?? []).includes(producer) && (after.producers ?? []).includes(producer);
  const routeRemovalCovered = [...new Set(before.routes.map((item) => item.source))].every((source) => (after.producers ?? []).includes(source === "api-graphql-inventory" ? "api-graphql" : source));
  compareSet(before.routes, after.routes, "key", "NEW_ROUTE", "REMOVED_ROUTE", output, includeRemoved && routeRemovalCovered, (item) => item.stateChanging ? "HIGH" : "MEDIUM");
  compareSet(before.graphql.map((key) => ({ key })), after.graphql.map((key) => ({ key })), "key", "NEW_GRAPHQL_OPERATION", "REMOVED_GRAPHQL_OPERATION", output, includeRemoved && covered("api-graphql"), () => "HIGH");
  compareSet(before.graphqlOperations ?? [], after.graphqlOperations ?? [], "key", "NEW_GRAPHQL_TEST_CONTRACT", "REMOVED_GRAPHQL_TEST_CONTRACT", output, includeRemoved && covered("api-graphql"), () => "HIGH");
  compareSet(before.origins.map((key) => ({ key })), after.origins.map((key) => ({ key })), "key", "NEW_ORIGIN", "REMOVED_ORIGIN", output, includeRemoved && routeRemovalCovered, () => "HIGH");
  compareSet(before.adminRoutes.map((key) => ({ key })), after.adminRoutes.map((key) => ({ key })), "key", "NEW_ADMIN_ROUTE", "REMOVED_ADMIN_ROUTE", output, includeRemoved && covered("browser-learning"), () => "HIGH");
  const allBeforeProducersCovered = (before.producers ?? []).every((producer) => (after.producers ?? []).includes(producer));
  compareSet((before.roles ?? []).map((key) => ({ key })), (after.roles ?? []).map((key) => ({ key })), "key", "NEW_ACTOR_ROLE", "REMOVED_ACTOR_ROLE", output, includeRemoved && allBeforeProducersCovered, () => "MEDIUM");
  compareSet((before.versions ?? []).map((key) => ({ key })), (after.versions ?? []).map((key) => ({ key })), "key", "NEW_API_VERSION", "REMOVED_API_VERSION", output, includeRemoved && covered("api-graphql"), () => "HIGH");
  compareSet(before.lifecycleCategories.map((key) => ({ key })), after.lifecycleCategories.map((key) => ({ key })), "key", "NEW_LIFECYCLE_CATEGORY", "REMOVED_LIFECYCLE_CATEGORY", output, includeRemoved && covered("authentication-lifecycle"), () => "MEDIUM");
  compareSet(before.supabaseResources, after.supabaseResources, "key", "NEW_DATA_RESOURCE", "REMOVED_DATA_RESOURCE", output, includeRemoved && covered("supabase-authorization"), () => "HIGH");
  const workflowRemovalCovered = [...new Set(before.workflowCases.map((item) => item.workflowId))].every((workflow) => (after.producers ?? []).includes(workflow) || after.workflowCases.some((item) => item.workflowId === workflow));
  compareSet(before.workflowCases, after.workflowCases, "key", "NEW_TEST_CONTRACT", "REMOVED_TEST_CONTRACT", output, includeRemoved && workflowRemovalCovered, () => "HIGH");
  const previousFields = new Map(before.fields.map((item) => [item.key, item]));
  for (const item of after.fields) { const old = previousFields.get(item.key); if (!old && item.access === "writable") output.push(drift("NEW_WRITABLE_FIELD", "HIGH", item.key, `New writable browser field observed at ${item.pagePath}.`)); else if (old && old.access !== item.access) output.push(drift("FIELD_ACCESS_CHANGED", item.access === "writable" ? "HIGH" : "MEDIUM", item.key, `Browser field access changed from ${old.access} to ${item.access}.`)); }
  const previousCookies = new Map(before.cookies.map((item) => [item.key, item]));
  for (const item of after.cookies) { const old = previousCookies.get(item.key); if (!old && item.classification === "authentication") output.push(drift("NEW_AUTH_COOKIE", "HIGH", item.key, "A new authentication cookie was observed.")); else if (old && digest(old) !== digest(item)) output.push(drift("COOKIE_SECURITY_CHANGED", "HIGH", item.key, "Authentication or cookie security attributes changed.")); }
  const previousApiFields = new Map((before.apiFields ?? []).map((item) => [item.key, item]));
  for (const item of after.apiFields ?? []) { const old = previousApiFields.get(item.key); if (!old) output.push(drift("NEW_API_RESPONSE_FIELD", /secret|token|credential|payment|identity|private|sensitive/i.test(item.classification) ? "HIGH" : "MEDIUM", item.key, `A new API response field classification was observed at ${item.path}.`)); else if (digest(old) !== digest(item)) output.push(drift("API_FIELD_EXPECTATION_CHANGED", "HIGH", item.key, "An API response field classification or expected exposure changed.")); }
  const previousResources = new Map(before.supabaseResources.map((item) => [item.key, item]));
  for (const item of after.supabaseResources) { const old = previousResources.get(item.key); if (old && digest(old) !== digest(item)) output.push(drift("DATA_RESOURCE_POLICY_CHANGED", "HIGH", item.key, "A Supabase/PostgREST resource actor or operation boundary changed.")); }
  if (before.buildEvidence && after.buildEvidence && before.buildFingerprint !== after.buildFingerprint) output.push(drift("BUILD_CHANGED", "INFO", "build", "The observed product/build fingerprint changed; required acceptance coverage must be re-evaluated."));
  return output;
}

function recommendations(report: RouteCairnReport, inventory: AdaptiveInventory, drifts: Drift[]): Recommendation[] {
  const result = new Map<string, Recommendation>();
  type Compiled = AdaptiveCompiledReadOnlyCase | AdaptiveCompiledContract;
  const add = (item: Omit<Recommendation, "sourceFingerprint" | "operatorApprovalRequired"> & { source: unknown; compiled?: Compiled | undefined }) => {
    const sourceFingerprint = digest(item.source);
    const key = `${item.category}:${sourceFingerprint}`;
    const draft = item.compiled ? executableDraft(item.draft, item.compiled, sourceFingerprint) : { ...item.draft, automation: { state: "REQUIRES_BINDINGS", compilerVersion: 1, mutationApprovalRequired: item.mutationHypothesis, unresolvedBindings: item.requiredBindings } };
    const approvalRequired = item.compiled ? "mutationApprovalRequired" in item.compiled && item.compiled.mutationApprovalRequired : true;
    result.set(key, { category: item.category, engineId: item.engineId, laneKind: item.laneKind, mutationHypothesis: item.mutationHypothesis, sourceFingerprint, operatorApprovalRequired: approvalRequired, draft, requiredBindings: item.compiled ? [] : item.requiredBindings });
  };
  for (const compiled of compileExecutedContracts(report)) {
    add({
      category: `EXACT_CONTRACT_REPLAY_${compiled.engineId.toUpperCase().replaceAll("-", "_")}`,
      engineId: compiled.engineId,
      laneKind: engineLane(compiled.engineId),
      mutationHypothesis: compiled.mutationApprovalRequired,
      source: { engineId: compiled.engineId, evidenceFingerprint: compiled.evidenceFingerprint, sourceCaseFingerprints: compiled.sourceCaseFingerprints },
      draft: { exactExecutedContract: true, sourceCaseFingerprints: compiled.sourceCaseFingerprints },
      requiredBindings: [],
      compiled
    });
  }
  for (const candidate of report.browserCrawl?.authentication?.learnedTestCases ?? []) {
    for (const category of candidate.suggestedLifecycleCategories) add({ category: `LIFECYCLE_${category}`, engineId: "authentication-lifecycle", laneKind: "AUTHENTICATION_LIFECYCLE", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { category, method: candidate.method, endpoint: safePath(new URL(candidate.endpoint).pathname), fields: candidate.observedFieldNames.map(safeName).sort(), bodyFormat: candidate.requestBodyFormat ?? "NONE", authorizationContext: candidate.authorizationContext, classification: candidate.classification }, draft: learnedDraft(candidate, category), requiredBindings: lifecycleBindings(category) });
    const path = safePath(new URL(candidate.endpoint).pathname);
    if (/graphql/i.test(path)) { const compiled = candidate.classification === "READ_ONLY_OBSERVATION" ? compileGraphqlIntrospectionCase(report, path) : undefined; add({ category: compiled ? "GRAPHQL_INTROSPECTION_READ_ONLY" : "GRAPHQL_OPERATION_REVIEW", engineId: "api-graphql-authorization", laneKind: "API_GRAPHQL_AUTHORIZATION", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { method: candidate.method, path, fields: candidate.observedFieldNames.map(safeName).sort() }, draft: { sourceCandidateId: candidate.id, protocol: "GRAPHQL", pathTemplate: path, method: candidate.method, executable: Boolean(compiled) }, requiredBindings: ["named operation", "actor matrix", "field expectations", "tenant expectation"], compiled }); }
    if (/signed|invite|portal|export|download/i.test(path)) add({ category: "CAPABILITY_LINK_REVIEW", engineId: "link-portal-export-security", laneKind: "DATA_AUTHORIZATION", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { method: candidate.method, path, fields: candidate.observedFieldNames.map(safeName).sort() }, draft: { sourceCandidateId: candidate.id, pathTemplate: path, method: candidate.method, executable: false }, requiredBindings: ["resource owner", "tenant", "expiry", "tamper/replay assertions", "cleanup"] });
    if (/webhook|cron|job|health|admin|worker/i.test(path)) {
      const operational = candidate.classification === "READ_ONLY_OBSERVATION" ? compileOperationalHealthCase(report, { protocol: "REST", method: candidate.method, pathTemplate: path, source: "browser-learning", stateChanging: false }) : undefined;
      add({ category: operational ? "OPERATIONAL_HEALTH_READ_ONLY" : "OPERATIONAL_ENDPOINT_REVIEW", engineId: "operational-endpoint-security", laneKind: "OPERATIONAL_ENDPOINTS", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { method: candidate.method, path, fields: candidate.observedFieldNames.map(safeName).sort() }, draft: { sourceCandidateId: candidate.id, pathTemplate: path, method: candidate.method, executable: Boolean(operational) }, requiredBindings: operational ? [] : ["endpoint kind", "authorized actor", "signature/auth expectation", "replay/workload bounds", "cleanup"], compiled: operational });
    }
    if (/checkout|billing|payment|subscription|plan|entitlement|premium|refund|invoice/i.test(path)) {
      const billing = candidate.classification === "READ_ONLY_OBSERVATION" ? compileBillingReadOnlyCase(report, { protocol: "REST", method: candidate.method, pathTemplate: path, source: "browser-learning", stateChanging: false }) : undefined;
      add({ category: billing ? "SYNTHETIC_BILLING_READ_ONLY" : "SYNTHETIC_BILLING_REVIEW", engineId: "billing-entitlement-security", laneKind: "BILLING_ENTITLEMENTS", mutationHypothesis: candidate.classification === "MUTATION_HYPOTHESIS", source: { method: candidate.method, path, fields: candidate.observedFieldNames.map(safeName).sort() }, draft: { sourceCandidateId: candidate.id, pathTemplate: path, method: candidate.method, providerMode: "SYNTHETIC_ONLY", realPaymentExecution: "FORBIDDEN", executable: Boolean(billing) }, requiredBindings: billing ? [] : ["test-provider fixture", "synthetic event", "account ownership", "authoritative entitlement verification", "cleanup"], compiled: billing });
    }
    if (!/graphql|signed|invite|portal|export|download|webhook|cron|job|health|admin|worker|checkout|billing|payment|subscription|plan|entitlement|premium|refund|invoice/i.test(path) && candidate.classification === "READ_ONLY_OBSERVATION") {
      const invariant = compileBusinessInvariantReadOnlyCase(report, { protocol: "REST", method: candidate.method, pathTemplate: path, source: "browser-learning", stateChanging: false });
      if (invariant) add({ category: "BUSINESS_INVARIANT_READ_ONLY", engineId: "business-invariant", laneKind: "BUSINESS_LOGIC", mutationHypothesis: false, source: { method: candidate.method, path, kind: "stable-observation" }, draft: { sourceCandidateId: candidate.id, pathTemplate: path, method: candidate.method, executable: true }, requiredBindings: [], compiled: invariant });
    }
  }
  for (const item of inventory.routes.filter((route) => route.source === "api-mapper" || route.source === "api-graphql-inventory" || (route.source === "browser-learning" && !route.stateChanging))) {
    const compiled = item.protocol === "REST" ? compileRouteReadOnlyCase(report, item) : !item.stateChanging ? compileGraphqlIntrospectionCase(report, item.pathTemplate) : undefined;
    add({ category: compiled ? (item.protocol === "REST" ? "API_READ_ONLY_REGRESSION" : "GRAPHQL_INTROSPECTION_READ_ONLY") : "API_AUTHORIZATION_MATRIX", engineId: "api-graphql-authorization", laneKind: "API_GRAPHQL_AUTHORIZATION", mutationHypothesis: item.stateChanging && !compiled, source: item, draft: { protocol: item.protocol, pathTemplate: item.pathTemplate, documentedMethods: [item.method], executable: Boolean(compiled) }, requiredBindings: ["Account A/B object identities", "expected decisions", "response field rules"], compiled });
    if (item.stateChanging) {
      add({ category: "BUSINESS_INVARIANT_CANDIDATE", engineId: "business-invariant", laneKind: "BUSINESS_LOGIC", mutationHypothesis: true, source: { method: item.method, pathTemplate: item.pathTemplate }, draft: { pathTemplate: item.pathTemplate, method: item.method, executable: false }, requiredBindings: ["pre-state", "bounded action sequence", "expected invariant", "authoritative post-state", "verified cleanup"] });
    } else {
      const invariant = item.protocol === "REST" ? compileBusinessInvariantReadOnlyCase(report, item) : undefined;
      if (invariant) add({ category: "BUSINESS_INVARIANT_READ_ONLY", engineId: "business-invariant", laneKind: "BUSINESS_LOGIC", mutationHypothesis: false, source: { method: item.method, pathTemplate: item.pathTemplate, kind: "stable-observation" }, draft: { pathTemplate: item.pathTemplate, method: item.method, executable: true }, requiredBindings: [], compiled: invariant });
    }
    if (/signed|invite|portal|export|download|report|evidence/i.test(item.pathTemplate)) add({ category: "CAPABILITY_LINK_REVIEW", engineId: "link-portal-export-security", laneKind: "DATA_AUTHORIZATION", mutationHypothesis: item.stateChanging, source: { method: item.method, pathTemplate: item.pathTemplate }, draft: { pathTemplate: item.pathTemplate, method: item.method, executable: false }, requiredBindings: ["resource owner", "tenant", "expiry", "tamper/replay assertions", "cleanup"] });
    if (/webhook|cron|job|health|incident|admin|worker|status|readiness|liveness/i.test(item.pathTemplate)) { const operational = compileOperationalHealthCase(report, item); add({ category: operational ? "OPERATIONAL_HEALTH_READ_ONLY" : "OPERATIONAL_ENDPOINT_REVIEW", engineId: "operational-endpoint-security", laneKind: "OPERATIONAL_ENDPOINTS", mutationHypothesis: item.stateChanging, source: { method: item.method, pathTemplate: item.pathTemplate }, draft: { pathTemplate: item.pathTemplate, method: item.method, executable: Boolean(operational) }, requiredBindings: ["endpoint kind", "authorized actor", "signature/auth expectation", "replay/workload bounds", "cleanup"], compiled: operational }); }
    if (/checkout|billing|payment|subscription|plan|entitlement|premium|refund|invoice/i.test(item.pathTemplate)) {
      const billing = item.protocol === "REST" ? compileBillingReadOnlyCase(report, item) : undefined;
      add({ category: billing ? "SYNTHETIC_BILLING_READ_ONLY" : "SYNTHETIC_BILLING_REVIEW", engineId: "billing-entitlement-security", laneKind: "BILLING_ENTITLEMENTS", mutationHypothesis: item.stateChanging, source: { method: item.method, pathTemplate: item.pathTemplate }, draft: { pathTemplate: item.pathTemplate, method: item.method, providerMode: "SYNTHETIC_ONLY", realPaymentExecution: "FORBIDDEN", executable: Boolean(billing) }, requiredBindings: billing ? [] : ["test-provider fixture", "synthetic event", "account ownership", "authoritative entitlement verification", "cleanup"], compiled: billing });
    }
  }
  for (const path of inventory.graphql) {
    const compiled = compileGraphqlIntrospectionCase(report, path);
    if (!compiled) continue;
    add({ category: "GRAPHQL_INTROSPECTION_READ_ONLY", engineId: "api-graphql-authorization", laneKind: "API_GRAPHQL_AUTHORIZATION", mutationHypothesis: false, source: { protocol: "GRAPHQL", path, kind: "generated-introspection" }, draft: { protocol: "GRAPHQL", pathTemplate: path, operation: "GENERATED_INTROSPECTION", executable: true }, requiredBindings: [], compiled });
  }
  for (const item of inventory.supabaseResources) { const compiled = item.operations.every((operation) => operation === "SELECT") ? compileSupabaseReadOnlyCase(report, item) : undefined; add({ category: compiled ? "SUPABASE_ANONYMOUS_READ_REGRESSION" : "SUPABASE_AUTHORIZATION_MATRIX", engineId: "supabase-authorization", laneKind: "DATA_AUTHORIZATION", mutationHypothesis: item.operations.some((operation) => operation !== "SELECT"), source: item, draft: { surface: item.surface, resource: item.resource, operations: item.operations, actors: item.actors, executable: Boolean(compiled) }, requiredBindings: ["Account A/B and tenant identities", "exact object bindings", "expected decisions", "sensitive columns", "cleanup for writes"], compiled }); }
  for (const item of drifts.filter((entry) => entry.severity === "HIGH")) add({ category: `DRIFT_${item.type}`, engineId: driftEngine(item.type), laneKind: driftLane(item.type), mutationHypothesis: false, source: item, draft: { semanticKey: item.semanticKey, safeSummary: item.summary }, requiredBindings: ["operator review", "exact regression case", "authoritative expected outcome"] });
  return [...result.values()];
}

function learnedDraft(candidate: BrowserLearnedTestCase, category: string): Record<string, unknown> { return { sourceCandidateId: candidate.id, category, method: candidate.method, pathTemplate: safePath(new URL(candidate.endpoint).pathname), requestBodyFormat: candidate.requestBodyFormat ?? "UNKNOWN", observedFieldNames: candidate.observedFieldNames.map(safeName).sort(), observedStatusCodes: [...candidate.observedStatusCodes].sort(), state: "DRAFT_REQUIRES_OPERATOR_CASE", executable: false }; }
function executableDraft(summary: Record<string, unknown>, compiled: AdaptiveCompiledReadOnlyCase | AdaptiveCompiledContract, sourceFingerprint: string): Record<string, unknown> { const exactContract = "mutationApprovalRequired" in compiled; const compilerVersion = exactContract ? 2 : 1; const mutationApprovalRequired = exactContract && compiled.mutationApprovalRequired; const automation = { state: mutationApprovalRequired ? "READY_APPROVAL_GATED" : "READY_READ_ONLY", compilerVersion, evidenceStrength: compiled.evidenceStrength, evidenceFingerprint: compiled.evidenceFingerprint, requestCount: compiled.requestCount, cleanupRequestCount: exactContract ? compiled.cleanupRequestCount : 0, authentication: exactContract ? compiled.authentication : "public", mutationApprovalRequired, summary: compiled.summary }; const executionFingerprintValue = executionFingerprint(compiled.engineId, sourceFingerprint, compiled.evidenceFingerprint, compiled.engineConfiguration, compilerVersion); return { ...summary, executable: true, automation, engineConfiguration: compiled.engineConfiguration, executionFingerprint: executionFingerprintValue }; }
function executionFingerprint(engineId: string, sourceFingerprint: string, evidenceFingerprint: string, engineConfiguration: unknown, compilerVersion: number): string { return digest({ purpose: compilerVersion === 1 ? "adaptive-read-only-execution" : "adaptive-exact-contract-execution", engineId, sourceFingerprint, evidenceFingerprint, engineConfiguration, compilerVersion }); }
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
function lifecycleBindings(category: string): string[] { const common = ["disposable actor", "exact assertions", "expiring authorization", "verified cleanup"]; if (/RESET|INVITATION|MFA|PASSKEY|RECOVERY|LINKING|VERIFICATION/.test(category)) common.push("single-use token/fixture binding"); if (/EXPIRATION/.test(category)) common.push("bounded wait contract"); return common; }
function driftEngine(type: string): string { return type.includes("COOKIE") || type.includes("AUTH") ? "authentication-lifecycle" : type.includes("DATA") ? "supabase-authorization" : type.includes("WRITABLE") ? "business-invariant" : "api-graphql-authorization"; }
function driftLane(type: string): LiveAcceptanceLane["kind"] { return type.includes("COOKIE") || type.includes("AUTH") ? "AUTHENTICATION_LIFECYCLE" : type.includes("DATA") ? "DATA_AUTHORIZATION" : type.includes("WRITABLE") ? "BUSINESS_LOGIC" : "API_GRAPHQL_AUTHORIZATION"; }
function engineLane(engineId: string): LiveAcceptanceLane["kind"] { return engineId === "api-graphql-authorization" ? "API_GRAPHQL_AUTHORIZATION" : engineId === "supabase-authorization" || engineId === "link-portal-export-security" ? "DATA_AUTHORIZATION" : engineId === "billing-entitlement-security" ? "BILLING_ENTITLEMENTS" : "BUSINESS_LOGIC"; }
function compareSet<T extends Record<string, unknown>>(before: T[], after: T[], key: keyof T, added: string, removed: string, output: Drift[], includeRemoved: boolean, severity: (item: T) => Drift["severity"]): void { const old = new Map(before.map((item) => [String(item[key]), item])); const next = new Map(after.map((item) => [String(item[key]), item])); for (const [id, item] of next) if (!old.has(id)) output.push(drift(added, severity(item), id, `${added.replaceAll("_", " ").toLowerCase()} observed: ${id}.`)); if (includeRemoved) for (const id of old.keys()) if (!next.has(id)) output.push(drift(removed, "MEDIUM", id, `${removed.replaceAll("_", " ").toLowerCase()} observed: ${id}.`)); }
function drift(type: string, severity: Drift["severity"], semanticKey: string, summary: string): Drift { return { type, severity, semanticKey, summary }; }
function verifyRecommendation(database: DashboardDatabase, engineId: string, scanId: string, scanStatus: string, caseFingerprint: string): "RUNNING" | "VERIFIED" | "INCONCLUSIVE" { if (!terminalScans.has(scanStatus)) return "RUNNING"; if (!["COMPLETED","IMPORTED"].includes(scanStatus)) return "INCONCLUSIVE"; const module = engineModule(engineId); const workflow = engineWorkflow(engineId); if (!module || !workflow) return "INCONCLUSIVE"; const moduleRow = database.db.prepare("SELECT status FROM scan_module_executions WHERE scan_id=? AND module_id=?").get(scanId, module) as { status: string } | undefined; const caseRow = database.db.prepare("SELECT execution_state FROM scan_workflow_case_executions WHERE scan_id=? AND workflow_id=? AND safe_case_fingerprint=?").get(scanId, workflow, caseFingerprint) as { execution_state: string } | undefined; return moduleRow?.status === "COMPLETED" && caseRow?.execution_state === "COMPLETED" ? "VERIFIED" : "INCONCLUSIVE"; }
function engineModule(id: string): string | undefined { return ({ "authentication-lifecycle": "authentication-lifecycle", "api-graphql-authorization": "api-graphql-authorization", "link-portal-export-security": "link-portal-export-security", "operational-endpoint-security": "operational-endpoint-security", "billing-entitlement-security": "billing-entitlement-security", "business-invariant": "business-invariant", "supabase-authorization": "supabase-authorization", "active-vulnerability-validation": "active-vulnerability-validation" } as Record<string,string>)[id]; }
function engineWorkflow(id: string): string | undefined { return engineModule(id); }
function safePath(value: string): string { const path = value.split("?")[0]!.replace(/\/[0-9]{2,}(?=\/|$)/g, "/:id").replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, "/:id").replace(/\/[A-Za-z0-9_-]{32,}(?=\/|$)/g, "/:token"); return (path.startsWith("/") ? path : `/${path}`).slice(0, 500); }
function safeName(value: string): string { return value.replace(/[\r\n\0|]/g, "_").slice(0, 160); }
function digest(value: unknown): string { return createHash("sha256").update(JSON.stringify(sort(value))).digest("hex"); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (!value || typeof value !== "object") return value; return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a],[b]) => a.localeCompare(b)).map(([key, child]) => [key, sort(child)])); }
function byKey<T extends { key: string }>(a: T, b: T): number { return a.key.localeCompare(b.key); }
function snapshotSummary(row: SnapshotListRow | SnapshotRow): Record<string, unknown> { return { id: row.id, sourceScanId: row.source_scan_id, status: row.status, modelDigest: row.model_digest, targetRowVersion: row.target_row_version, buildFingerprint: row.build_fingerprint, createdAt: row.created_at, ...(row.accepted_at ? { acceptedAt: row.accepted_at } : {}) }; }
function recommendationSummary(row: RecommendationListRow): Record<string, unknown> { return { id: row.id, snapshotId: row.snapshot_id, category: row.category, engineId: row.engine_id, laneKind: row.lane_kind, sourceFingerprint: row.source_fingerprint, status: row.status, mutationHypothesis: Boolean(row.mutation_hypothesis), operatorApprovalRequired: Boolean(row.operator_approval_required), draft: JSON.parse(row.safe_draft_json), requiredBindings: JSON.parse(row.required_bindings_json), ...(row.operator_rationale ? { rationale: row.operator_rationale } : {}), ...(row.linked_scan_id ? { linkedScanId: row.linked_scan_id } : {}), ...(row.linked_case_fingerprint ? { linkedCaseFingerprint: row.linked_case_fingerprint } : {}), ...(row.execution_outcome ? { executionOutcome: row.execution_outcome } : {}), ...(row.adapter_profile_id ? { adapterProfileId: row.adapter_profile_id, adapterVersionId: row.adapter_version_id } : {}), createdAt: row.created_at, updatedAt: row.updated_at }; }

interface Drift { type: string; severity: "INFO" | "LOW" | "MEDIUM" | "HIGH"; semanticKey: string; summary: string }
interface Recommendation { category: string; engineId: string; laneKind: LiveAcceptanceLane["kind"]; sourceFingerprint: string; mutationHypothesis: boolean; operatorApprovalRequired: boolean; draft: Record<string, unknown>; requiredBindings: string[] }
interface PolicyRow { required_lanes_json: string; require_na_evidence: number; detect_removed_surfaces: number; row_version: number }
interface SnapshotListRow { id: string; source_scan_id: string; status: string; model_digest: string; target_row_version: number; build_fingerprint: string; created_at: string; accepted_at: string | null }
interface SnapshotRow extends SnapshotListRow { target_id: string; inventory_json: string }
interface RecommendationListRow { id: string; target_id: string; snapshot_id: string; category: string; engine_id: string; lane_kind: string; source_fingerprint: string; status: string; mutation_hypothesis: number; operator_approval_required: number; safe_draft_json: string; required_bindings_json: string; operator_rationale: string | null; reviewed_by: string | null; reviewed_at: string | null; linked_scan_id: string | null; linked_case_fingerprint: string | null; execution_outcome: string | null; adapter_profile_id?: string | null; adapter_version_id?: string | null; created_at: string; updated_at: string }
interface RecommendationRow extends RecommendationListRow { target_id: string }
interface CoverageLaneRow { kind: string; disposition: string; configured_outcome: string | null; safe_reason: string | null; scan_id: string | null; evidence_scan_id: string | null; scan_status: string | null; evidence_scan_status: string | null }
interface ExecutionCandidateRow { scan_id: string; safe_case_alias: string; safe_case_fingerprint: string; execution_state: string; matched_expectation: number | null; evidence_strength: string; scan_status: string; created_at: string }
