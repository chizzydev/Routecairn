import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import type { DashboardDatabase } from "../db/DashboardDatabase.js";
import { clamp, nowIso } from "../db/DashboardDatabase.js";
import { TargetRepository, type TargetSummary } from "../db/DashboardRepositories.js";
import type { CredentialVaultKey } from "../credentials/CredentialVault.js";
import { credentialVaultAlgorithm } from "../credentials/CredentialVault.js";
import type { ScanExecutionService } from "./ScanExecutionService.js";
import { scopeSchema, type RouteCairnScope } from "../../config/ConfigSchema.js";
import { liveAcceptancePlanInputSchema, type LiveAcceptanceLane, type LiveAcceptancePlanInput } from "../contracts/LiveAcceptanceSchemas.js";
import { advancedEngineCatalog, validateAdvancedEngineInput, type AdvancedEngineId } from "../contracts/AdvancedEngineSchemas.js";
import { dashboardScanCreateSchema } from "../contracts/DashboardSchemas.js";
import type { DashboardScanCreateRequest } from "../types/DashboardTypes.js";
import { effectiveLiveAcceptanceProof, evaluateLiveAcceptanceProof, type LiveAcceptanceProofContract, type LiveAcceptanceProofResult } from "./LiveAcceptanceProof.js";

const maximumPlanBytes = 1024 * 1024;
const terminalScanStatuses = new Set(["COMPLETED", "FAILED", "CANCELLED", "INTERRUPTED", "IMPORTED"]);

export interface LiveAcceptancePlanPreview {
  planDigest: string;
  target: { id: string; origin: string; rowVersion: number; scopeDigest: string };
  authorization: { active: boolean; startsAt: string; expiresAt: string; mode: string };
  requiredValidThrough: string;
  totalRequestBudget: number;
  cleanupReservedRequests: number;
  standard: string;
  lanes: Array<{ id: string; label: string; kind: string; required: boolean; disposition: string; previewIdentity?: string; moduleCount?: number; requestBudget?: number; warnings: string[]; linkedScanId?: string; baselineScanId?: string; comparisonId?: string; evidenceScanId?: string; configuredOutcome?: string; proof: LiveAcceptanceProofContract; proofResult?: LiveAcceptanceProofResult }>;
  blockers: string[];
}

export class LiveAcceptanceService {
  private readonly targets: TargetRepository;
  public constructor(private readonly database: DashboardDatabase, private readonly execution: ScanExecutionService, private readonly key?: CredentialVaultKey) {
    this.targets = new TargetRepository(database);
  }

  public available(): boolean { return Boolean(this.key); }

  public async preview(input: unknown): Promise<LiveAcceptancePlanPreview> {
    const plan = liveAcceptancePlanInputSchema.parse(input);
    const target = this.targetFor(plan);
    const scope = acceptanceScope(target, plan.authorization.neverTestPaths);
    const binding = planBinding(plan, target, scope);
    const lanes: LiveAcceptancePlanPreview["lanes"] = [];
    const blockers: string[] = [];
    let totalRequestBudget = 0;
    let cleanupReservedRequests = 0;
    let maximumExecutionMs = 0;
    for (const lane of plan.lanes) {
      const proof = effectiveLiveAcceptanceProof(lane, plan.standard === "BROADER_REAL_TARGET_V1");
      if (lane.execution.disposition === "EXECUTE_SCAN") {
        try {
          const request = this.requestFor(plan, target, scope, lane, binding.planDigest);
          const preview = await this.execution.preview(request);
          const requestBudget = numeric(preview.limits.maxRequests);
          const cleanupBudget = numeric(preview.limits.cleanupReservedRequests);
          totalRequestBudget += requestBudget;
          cleanupReservedRequests += cleanupBudget;
          maximumExecutionMs += numeric(preview.limits.maxScanDurationMs);
          const plannedModules = preview.modules.map((module) => module.id);
          const proofWarnings = proof.requiredModules.filter((moduleId) => !plannedModules.includes(moduleId)).map((moduleId) => `Required proof module ${moduleId} is not present in the resolved scan plan.`);
          if (proofWarnings.length) blockers.push(`${lane.id}: ${proofWarnings[0]}`);
          lanes.push({ id: lane.id, label: lane.label, kind: lane.kind, required: lane.required, disposition: lane.execution.disposition, previewIdentity: preview.previewIdentity, moduleCount: preview.modules.length, requestBudget, warnings: [...preview.warnings, ...proofWarnings], proof });
          if (!preview.credentialReadiness.ready) blockers.push(`${lane.id}: credential readiness failed.`);
        } catch (error) {
          const message = safeError(error);
          blockers.push(`${lane.id}: ${message}`);
          lanes.push({ id: lane.id, label: lane.label, kind: lane.kind, required: lane.required, disposition: lane.execution.disposition, warnings: [message], proof });
        }
      } else if (lane.execution.disposition === "LINK_SCAN") {
        const linkedError = this.linkedScanError(lane.execution.scanId, target, lane.kind, plan.standard === "BROADER_REAL_TARGET_V1");
        const proofResult = linkedError ? undefined : evaluateLiveAcceptanceProof(this.database, lane.execution.scanId, proof);
        const warnings = linkedError ? [linkedError] : proofResult && !proofResult.verified ? proofResult.missing : [];
        if (warnings.length) blockers.push(`${lane.id}: ${warnings[0]}`);
        lanes.push({ id: lane.id, label: lane.label, kind: lane.kind, required: lane.required, disposition: lane.execution.disposition, linkedScanId: lane.execution.scanId, warnings, proof, ...(proofResult ? { proofResult } : {}) });
      } else if (lane.execution.disposition === "LINK_REMEDIATION") {
        const linkedError = this.remediationError(lane.execution, target, plan.standard === "BROADER_REAL_TARGET_V1");
        const proofResult = linkedError ? undefined : evaluateLiveAcceptanceProof(this.database, lane.execution.rerunScanId, proof, lane.execution);
        const warnings = linkedError ? [linkedError] : proofResult && !proofResult.verified ? proofResult.missing : [];
        if (warnings.length) blockers.push(`${lane.id}: ${warnings[0]}`);
        lanes.push({ id: lane.id, label: lane.label, kind: lane.kind, required: lane.required, disposition: lane.execution.disposition, linkedScanId: lane.execution.rerunScanId, baselineScanId: lane.execution.baselineScanId, comparisonId: lane.execution.comparisonId, warnings, proof, ...(proofResult ? { proofResult } : {}) });
      } else {
        const evidenceScanId = lane.execution.disposition === "NOT_APPLICABLE" ? lane.execution.evidenceScanId : undefined;
        const evidenceError = evidenceScanId ? this.evidenceScanError(evidenceScanId, target) : undefined;
        const warnings = evidenceError ? [evidenceError] : lane.execution.disposition === "NOT_APPLICABLE" && !evidenceScanId ? ["No completed same-target evidence scan is attached; adaptive completeness will treat this lane as an evidence gap."] : [];
        if (evidenceError) blockers.push(`${lane.id}: ${evidenceError}`);
        lanes.push({ id: lane.id, label: lane.label, kind: lane.kind, required: lane.required, disposition: lane.execution.disposition, configuredOutcome: lane.execution.disposition, ...(evidenceScanId ? { evidenceScanId } : {}), warnings, proof });
      }
    }
    const now = Date.now();
    const active = now >= Date.parse(plan.authorization.startsAt) && now < Date.parse(plan.authorization.expiresAt);
    if (!active) blockers.push("Authorization window is not currently active.");
    const requiredValidThrough = new Date(now + maximumExecutionMs).toISOString();
    if (maximumExecutionMs > 0 && Date.parse(plan.authorization.expiresAt) < Date.parse(requiredValidThrough)) blockers.push("Authorization may expire before all sequential acceptance lanes reach their maximum execution duration.");
    return { planDigest: binding.planDigest, standard: plan.standard, target: { id: target.id, origin: target.baseOrigin, rowVersion: target.rowVersion, scopeDigest: binding.scopeDigest }, authorization: { active, startsAt: plan.authorization.startsAt, expiresAt: plan.authorization.expiresAt, mode: plan.authorization.mode }, requiredValidThrough, totalRequestBudget, cleanupReservedRequests, lanes, blockers };
  }

  public async create(input: unknown, actor: string): Promise<{ plan: Record<string, unknown>; preview: LiveAcceptancePlanPreview }> {
    this.requireKey();
    const parsed = liveAcceptancePlanInputSchema.parse(input);
    const preview = await this.preview(parsed);
    const id = randomUUID();
    const encrypted = this.encrypt(id, parsed);
    const now = nowIso();
    this.database.db.prepare(`INSERT INTO live_acceptance_plans
      (id,name,target_id,environment,status,plan_digest,target_row_version,scope_digest,authorization_mode,authorization_expires_at,lane_count,algorithm,key_version,nonce,ciphertext,auth_tag,created_by,created_at,updated_at,standard)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .run(id, parsed.name, parsed.targetId, parsed.environment, "DRAFT", preview.planDigest, preview.target.rowVersion, preview.target.scopeDigest, parsed.authorization.mode, parsed.authorization.expiresAt, parsed.lanes.length, credentialVaultAlgorithm, this.key!.version, encrypted.nonce, encrypted.ciphertext, encrypted.authTag, actor, now, now, parsed.standard);
    return { plan: this.getPlan(id), preview };
  }

  public async update(id: string, input: unknown, expectedVersion: number): Promise<{ plan: Record<string, unknown>; preview: LiveAcceptancePlanPreview }> {
    this.requireKey();
    const parsed = liveAcceptancePlanInputSchema.parse(input);
    const preview = await this.preview(parsed);
    const encrypted = this.encrypt(id, parsed);
    const result = this.database.db.prepare(`UPDATE live_acceptance_plans SET name=?, target_id=?, environment=?, status='DRAFT', plan_digest=?, target_row_version=?, scope_digest=?, authorization_mode=?, authorization_expires_at=?, lane_count=?, algorithm=?, key_version=?, nonce=?, ciphertext=?, auth_tag=?, standard=?, reviewed_by=NULL, reviewed_at=NULL, updated_at=?, row_version=row_version+1 WHERE id=? AND row_version=? AND status!='ARCHIVED'`)
      .run(parsed.name, parsed.targetId, parsed.environment, preview.planDigest, preview.target.rowVersion, preview.target.scopeDigest, parsed.authorization.mode, parsed.authorization.expiresAt, parsed.lanes.length, credentialVaultAlgorithm, this.key!.version, encrypted.nonce, encrypted.ciphertext, encrypted.authTag, parsed.standard, nowIso(), id, expectedVersion);
    if (result.changes !== 1) throw new Error("LIVE_ACCEPTANCE_PLAN_VERSION_CONFLICT");
    return { plan: this.getPlan(id), preview };
  }

  public async review(id: string, digest: string, actor: string): Promise<Record<string, unknown>> {
    const row = this.planRow(id);
    const plan = this.decrypt(row);
    const preview = await this.preview(plan);
    if (preview.blockers.length) throw new Error(`LIVE_ACCEPTANCE_REVIEW_BLOCKED: ${preview.blockers.join(" ")}`);
    if (digest !== row.plan_digest || digest !== preview.planDigest) throw new Error("LIVE_ACCEPTANCE_PLAN_CHANGED_AFTER_PREVIEW");
    const result = this.database.db.prepare("UPDATE live_acceptance_plans SET status='REVIEWED', reviewed_by=?, reviewed_at=?, updated_at=?, row_version=row_version+1 WHERE id=? AND plan_digest=? AND status='DRAFT'").run(actor, nowIso(), nowIso(), id, digest);
    if (result.changes !== 1) throw new Error("LIVE_ACCEPTANCE_REVIEW_STATE_CONFLICT");
    return this.getPlan(id);
  }

  public async execute(id: string, digest: string, actor: string): Promise<Record<string, unknown>> {
    const row = this.planRow(id);
    if (row.status !== "REVIEWED") throw new Error("LIVE_ACCEPTANCE_REVIEW_REQUIRED");
    const plan = this.decrypt(row);
    const preview = await this.preview(plan);
    if (digest !== row.plan_digest || digest !== preview.planDigest) throw new Error("LIVE_ACCEPTANCE_PLAN_BINDING_MISMATCH");
    if (preview.blockers.length) throw new Error(`LIVE_ACCEPTANCE_EXECUTION_BLOCKED: ${preview.blockers.join(" ")}`);
    const target = this.targetFor(plan);
    const scope = acceptanceScope(target, plan.authorization.neverTestPaths);
    const runId = randomUUID();
    this.database.db.prepare("INSERT INTO live_acceptance_runs (id,plan_id,plan_digest,status,requested_by,created_at,standard) VALUES (?,?,?,'RUNNING',?,?,?)").run(runId, id, digest, actor, nowIso(), plan.standard);
    for (const [ordinal, lane] of plan.lanes.entries()) {
      const scanId = lane.execution.disposition === "LINK_SCAN" ? lane.execution.scanId : lane.execution.disposition === "LINK_REMEDIATION" ? lane.execution.rerunScanId : undefined;
      const baselineScanId = lane.execution.disposition === "LINK_REMEDIATION" ? lane.execution.baselineScanId : undefined;
      const comparisonId = lane.execution.disposition === "LINK_REMEDIATION" ? lane.execution.comparisonId : undefined;
      const evidenceScanId = lane.execution.disposition === "NOT_APPLICABLE" ? lane.execution.evidenceScanId : undefined;
      const configuredOutcome = lane.execution.disposition === "NOT_APPLICABLE" || lane.execution.disposition === "NOT_ASSESSED" ? lane.execution.disposition : undefined;
      const reason = lane.execution.disposition === "NOT_APPLICABLE" || lane.execution.disposition === "NOT_ASSESSED" ? lane.execution.reason : undefined;
      this.insertLane(runId, lane, ordinal, effectiveLiveAcceptanceProof(lane, plan.standard === "BROADER_REAL_TARGET_V1"), scanId, baselineScanId, comparisonId, evidenceScanId, configuredOutcome, reason);
    }
    try {
      for (const lane of plan.lanes) if (lane.execution.disposition === "EXECUTE_SCAN") {
        const scanId = await this.execution.enqueue(this.requestFor(plan, target, scope, lane, digest));
        this.database.db.prepare("UPDATE live_acceptance_run_lanes SET scan_id=? WHERE run_id=? AND lane_id=? AND scan_id IS NULL").run(scanId, runId, lane.id);
      }
    } catch (error) {
      this.database.db.prepare("UPDATE live_acceptance_runs SET status='FAILED',completed_at=?,safe_error_summary=? WHERE id=?").run(nowIso(), clamp(safeError(error), 800), runId);
      throw error;
    }
    return this.getRun(runId);
  }

  public listPlans(): Record<string, unknown>[] {
    return (this.database.db.prepare(`SELECT p.id,p.name,p.target_id,p.environment,p.standard,p.status,p.plan_digest,p.authorization_mode,p.authorization_expires_at,p.lane_count,p.reviewed_at,p.created_at,p.updated_at,p.row_version,t.display_name AS target_name,t.base_origin,
      (SELECT id FROM live_acceptance_runs r WHERE r.plan_id=p.id ORDER BY r.created_at DESC LIMIT 1) AS latest_run_id
      FROM live_acceptance_plans p JOIN targets t ON t.id=p.target_id WHERE p.status!='ARCHIVED' ORDER BY p.updated_at DESC`).all() as PlanListRow[]).map(planSummary);
  }

  public getPlan(id: string): Record<string, unknown> {
    const row = this.planRow(id);
    return { ...planSummary(row), input: this.decrypt(row), runs: this.listRuns(id) };
  }

  public listRuns(planId?: string): Record<string, unknown>[] {
    const rows = (planId ? this.database.db.prepare("SELECT * FROM live_acceptance_runs WHERE plan_id=? ORDER BY created_at DESC").all(planId) : this.database.db.prepare("SELECT * FROM live_acceptance_runs ORDER BY created_at DESC LIMIT 100").all()) as RunRow[];
    return rows.map((row) => this.getRun(row.id));
  }

  public getRun(id: string): Record<string, unknown> {
    const run = this.database.db.prepare("SELECT * FROM live_acceptance_runs WHERE id=?").get(id) as RunRow | undefined;
    if (!run) throw new Error("LIVE_ACCEPTANCE_RUN_NOT_FOUND");
    const laneRows = this.database.db.prepare(`SELECT l.*,s.status AS scan_status,s.finding_count,s.error_summary,es.status AS evidence_scan_status,
      CASE WHEN EXISTS (SELECT 1 FROM controlled_mutation_approvals a WHERE a.execution_scan_id=s.id AND a.status IN ('CLEANUP_REQUIRED','CLEANUP_FAILED'))
        OR EXISTS (SELECT 1 FROM assisted_case_results c WHERE c.scan_id=s.id AND c.cleanup_unresolved=1) THEN 1 ELSE 0 END AS cleanup_unresolved
      ,(SELECT COUNT(*) FROM scan_workflow_case_executions w WHERE w.scan_id=s.id AND w.execution_state!='COMPLETED') AS case_gap_count
      ,(SELECT COUNT(*) FROM assisted_case_results c WHERE c.scan_id=s.id AND c.assessment_outcome IN ('INCONCLUSIVE','NOT_ASSESSED','BLOCKED')) AS assisted_gap_count
      FROM live_acceptance_run_lanes l
      LEFT JOIN scans s ON s.id=l.scan_id
      LEFT JOIN scans es ON es.id=l.evidence_scan_id
      WHERE l.run_id=? ORDER BY l.ordinal`).all(id) as LaneRow[];
    const lanes = laneRows.map((row) => deriveLane(this.database, row));
    if (run.status === "RUNNING" && lanes.length > 0 && lanes.every((lane) => lane.terminal)) {
      const gaps = coverage(lanes, run.standard).requiredGaps > 0;
      const status = gaps ? "COMPLETED_WITH_GAPS" : "COMPLETED";
      this.database.db.prepare("UPDATE live_acceptance_runs SET status=?,completed_at=? WHERE id=? AND status='RUNNING'").run(status, nowIso(), id);
      run.status = status;
      run.completed_at = nowIso();
    }
    return { id: run.id, planId: run.plan_id, planDigest: run.plan_digest, standard: run.standard, status: run.status, requestedBy: run.requested_by, createdAt: run.created_at, ...(run.completed_at ? { completedAt: run.completed_at } : {}), ...(run.safe_error_summary ? { errorSummary: run.safe_error_summary } : {}), lanes, coverage: coverage(lanes, run.standard) };
  }

  public cancelRun(id: string): Record<string, unknown> {
    const run = this.database.db.prepare("SELECT status FROM live_acceptance_runs WHERE id=?").get(id) as { status: string } | undefined;
    if (!run) throw new Error("LIVE_ACCEPTANCE_RUN_NOT_FOUND");
    if (run.status !== "RUNNING") throw new Error("LIVE_ACCEPTANCE_RUN_NOT_RUNNING");
    const scans = this.database.db.prepare("SELECT s.id,s.status FROM live_acceptance_run_lanes l JOIN scans s ON s.id=l.scan_id WHERE l.run_id=?").all(id) as Array<{ id: string; status: string }>;
    for (const scan of scans) if (!terminalScanStatuses.has(scan.status)) { try { this.execution.cancel(scan.id); } catch { /* another terminal transition won the race */ } }
    this.database.db.prepare("UPDATE live_acceptance_runs SET status='CANCELLED',completed_at=? WHERE id=? AND status='RUNNING'").run(nowIso(), id);
    return this.getRun(id);
  }

  public rotateKey(nextKey: CredentialVaultKey): number {
    this.requireKey();
    return rotateLiveAcceptancePlanKey(this.database, this.key!, nextKey);
  }

  private requestFor(plan: LiveAcceptancePlanInput, target: TargetSummary, scope: RouteCairnScope, lane: LiveAcceptanceLane, planDigest: string): DashboardScanCreateRequest {
    if (lane.execution.disposition !== "EXECUTE_SCAN") throw new Error("LIVE_ACCEPTANCE_LANE_NOT_EXECUTABLE");
    const auth = lane.execution.authentication;
    const authentication = auth.mode === "public" ? { mode: "public" as const } : auth.mode === "primary" ? { mode: "primary" as const, primary: { source: "saved" as const, credentialProfileId: auth.credentialProfileId } } : { mode: "account-pair" as const, accountA: { source: "saved" as const, credentialProfileId: auth.accountAProfileId }, accountB: { source: "saved" as const, credentialProfileId: auth.accountBProfileId } };
    const advanced: Record<string, unknown> = {};
    const modules = new Set(lane.execution.includeModules);
    for (const configured of lane.execution.advancedEngines) {
      const validated = validateAdvancedEngineInput(configured.engineId, configured.value);
      if (!validated.valid) throw new Error(`${configured.engineId}: ${validated.diagnostics.map((item) => `${item.path.join(".")}: ${item.message}`).join("; ")}`);
      const catalog = advancedEngineCatalog.find((item) => item.id === configured.engineId)!;
      if (catalog.moduleId) modules.add(catalog.moduleId);
      assignAdvanced(advanced, configured.engineId, validated.value);
    }
    const category = target.authorizationType === "BUG_BOUNTY" ? "BUG_BOUNTY" : target.authorizationType === "CLIENT_AUTHORIZED" ? "CLIENT_AUTHORIZED" : target.authorizationType === "CONTROLLED_LAB" ? "CONTROLLED_LAB" : target.authorizationType === "OTHER_AUTHORIZED" ? "OTHER_AUTHORIZED" : "OWNED";
    return dashboardScanCreateSchema.parse({ target: target.baseOrigin, targetId: target.id, ...(target.projectId ? { projectId: target.projectId } : {}), profile: lane.execution.profile, authorizationDeclaration: `Live acceptance ${planDigest.slice(0, 12)} / ${lane.id}`, rateLimitPerSecond: lane.execution.rateLimitPerSecond, concurrency: lane.execution.concurrency, maxRequests: lane.execution.maxRequests, cleanupReservedRequests: lane.execution.cleanupReservedRequests, ...(modules.size ? { includeModules: [...modules] } : {}), ...advanced, studio: { version: 1, scanName: `${plan.name} · ${lane.label}`, authorization: { category, confirmed: true, note: `Immutable live acceptance plan ${planDigest}.` }, scope, authentication, evidenceLevel: lane.execution.evidenceLevel, outputs: { json: true, markdown: true, html: true }, moduleSettings: {}, workflows: lane.execution.workflows, workflowSummary: lane.execution.workflows.map((item) => ({ type: item.workflowId, caseCount: workflowCaseCount(item.config), valid: item.enabled })) } });
  }

  private targetFor(plan: LiveAcceptancePlanInput): TargetSummary {
    const target = this.targets.get(plan.targetId);
    if (!target) throw new Error("LIVE_ACCEPTANCE_TARGET_NOT_FOUND");
    if (plan.environment === "PRODUCTION" && target.classification !== "PRODUCTION") throw new Error("LIVE_ACCEPTANCE_PRODUCTION_TARGET_REQUIRED");
    if (plan.standard === "BROADER_REAL_TARGET_V1") {
      if (target.authorizationType === "CONTROLLED_LAB") throw new Error("BROADER_REAL_TARGET_CONTROLLED_LAB_FORBIDDEN");
      if (!isPublicHttpsOrigin(target.baseOrigin)) throw new Error("BROADER_REAL_TARGET_PUBLIC_HTTPS_REQUIRED");
    }
    return target;
  }

  private linkedScanError(scanId: string, target: TargetSummary, kind: LiveAcceptanceLane["kind"], strictNative = false): string | undefined {
    const row = this.database.db.prepare("SELECT target_id,target_origin,status,source FROM scans WHERE id=? AND deleted_at IS NULL").get(scanId) as { target_id: string | null; target_origin: string; status: string; source: string } | undefined;
    if (!row || row.target_origin !== target.baseOrigin || (row.target_id !== null && row.target_id !== target.id)) return "Linked scan is unavailable or belongs to another target.";
    if (!terminalScanStatuses.has(row.status)) return "Linked scan has not reached a terminal state.";
    if (strictNative && (row.target_id !== target.id || row.status !== "COMPLETED" || row.source !== "DASHBOARD")) return "Broader real-target proof requires a native completed scan with the exact registered-target binding.";
    if (["MUTATION_ACCEPTANCE", "RECOVERY_ACCEPTANCE"].includes(kind)) {
      const approval = this.database.db.prepare("SELECT status FROM controlled_mutation_approvals WHERE execution_scan_id=?").get(scanId) as { status: string } | undefined;
      if (!approval) return "Mutation and recovery lanes require a scan bound to a controlled-mutation approval.";
      if (kind === "RECOVERY_ACCEPTANCE" && approval.status !== "COMPLETED") return "Recovery acceptance requires a controlled-mutation approval whose restoration completed.";
    }
  }

  private remediationError(execution: Extract<LiveAcceptanceLane["execution"], { disposition: "LINK_REMEDIATION" }>, target: TargetSummary, strictNative = false): string | undefined {
    const baselineError = this.linkedScanError(execution.baselineScanId, target, "CUSTOM", strictNative);
    if (baselineError) return `Baseline: ${baselineError}`;
    const rerunError = this.linkedScanError(execution.rerunScanId, target, "CUSTOM", strictNative);
    if (rerunError) return `Rerun: ${rerunError}`;
    const comparison = this.database.db.prepare("SELECT older_scan_id,newer_scan_id,state FROM scan_comparisons WHERE id=? AND deleted_at IS NULL").get(execution.comparisonId) as { older_scan_id: string; newer_scan_id: string; state: string } | undefined;
    if (!comparison || comparison.older_scan_id !== execution.baselineScanId || comparison.newer_scan_id !== execution.rerunScanId) return "The comparison is unavailable or does not bind the exact baseline and rerun scans.";
    if (!['COMPLETED', 'PARTIAL'].includes(comparison.state)) return "The remediation comparison has not completed.";
  }

  private evidenceScanError(scanId: string, target: TargetSummary): string | undefined {
    const row = this.database.db.prepare("SELECT target_id,target_origin,status FROM scans WHERE id=? AND deleted_at IS NULL").get(scanId) as { target_id: string | null; target_origin: string; status: string } | undefined;
    if (!row || row.target_id !== target.id || row.target_origin !== target.baseOrigin) return "NOT_APPLICABLE evidence scan is unavailable or lacks the exact registered-target binding.";
    if (!["COMPLETED", "IMPORTED"].includes(row.status)) return "NOT_APPLICABLE evidence must be a completed or imported same-target scan.";
  }

  private insertLane(runId: string, lane: LiveAcceptanceLane, ordinal: number, proof: LiveAcceptanceProofContract, scanId?: string, baselineScanId?: string, comparisonId?: string, evidenceScanId?: string, configuredOutcome?: string, reason?: string): void {
    this.database.db.prepare("INSERT INTO live_acceptance_run_lanes (id,run_id,lane_id,label,kind,required,disposition,scan_id,baseline_scan_id,comparison_id,evidence_scan_id,configured_outcome,safe_reason,ordinal,proof_contract_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").run(randomUUID(), runId, lane.id, lane.label, lane.kind, lane.required ? 1 : 0, lane.execution.disposition, scanId ?? null, baselineScanId ?? null, comparisonId ?? null, evidenceScanId ?? null, configuredOutcome ?? null, reason ? clamp(reason, 1000) : null, ordinal, JSON.stringify(proof));
  }

  private planRow(id: string): PlanRow {
    const row = this.database.db.prepare(`SELECT p.*,t.display_name AS target_name,t.base_origin FROM live_acceptance_plans p JOIN targets t ON t.id=p.target_id WHERE p.id=?`).get(id) as PlanRow | undefined;
    if (!row) throw new Error("LIVE_ACCEPTANCE_PLAN_NOT_FOUND");
    return row;
  }

  private encrypt(id: string, plan: LiveAcceptancePlanInput): { nonce: string; ciphertext: string; authTag: string } {
    this.requireKey();
    const plaintext = Buffer.from(JSON.stringify(plan), "utf8");
    if (plaintext.length > maximumPlanBytes) throw new Error("LIVE_ACCEPTANCE_PLAN_TOO_LARGE");
    const nonce = randomBytes(12); const cipher = createCipheriv(credentialVaultAlgorithm, this.key!.bytes, nonce); cipher.setAAD(this.aad(id, this.key!.version));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { nonce: nonce.toString("base64url"), ciphertext: ciphertext.toString("base64url"), authTag: cipher.getAuthTag().toString("base64url") };
  }

  private decrypt(row: PlanRow): LiveAcceptancePlanInput {
    this.requireKey();
    if (row.algorithm !== credentialVaultAlgorithm || row.key_version !== this.key!.version) throw new Error("LIVE_ACCEPTANCE_PLAN_KEY_UNAVAILABLE");
    const decipher = createDecipheriv(credentialVaultAlgorithm, this.key!.bytes, Buffer.from(row.nonce, "base64url")); decipher.setAAD(this.aad(row.id, row.key_version)); decipher.setAuthTag(Buffer.from(row.auth_tag, "base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(row.ciphertext, "base64url")), decipher.final()]);
    if (plaintext.length > maximumPlanBytes) throw new Error("LIVE_ACCEPTANCE_PLAN_TOO_LARGE");
    return liveAcceptancePlanInputSchema.parse(JSON.parse(plaintext.toString("utf8")));
  }

  private aad(id: string, keyVersion: string): Buffer { return aadFor(this.database, id, keyVersion); }
  private requireKey(): void { if (!this.key) throw new Error("LIVE_ACCEPTANCE_VAULT_REQUIRED"); }
}

export function rotateLiveAcceptancePlanKey(database: DashboardDatabase, currentKey: CredentialVaultKey, nextKey: CredentialVaultKey): number {
  const rows = database.db.prepare("SELECT id,algorithm,key_version,nonce,ciphertext,auth_tag FROM live_acceptance_plans ORDER BY id").all() as Array<Pick<PlanRow, "id" | "algorithm" | "key_version" | "nonce" | "ciphertext" | "auth_tag">>;
  for (const row of rows) {
    if (row.algorithm !== credentialVaultAlgorithm || row.key_version !== currentKey.version) throw new Error(`Live acceptance plan ${row.id} is not encrypted with the current key version.`);
    const decipher = createDecipheriv(credentialVaultAlgorithm, currentKey.bytes, Buffer.from(row.nonce, "base64url")); decipher.setAAD(aadFor(database, row.id, currentKey.version)); decipher.setAuthTag(Buffer.from(row.auth_tag, "base64url"));
    const plaintext = Buffer.concat([decipher.update(Buffer.from(row.ciphertext, "base64url")), decipher.final()]);
    if (plaintext.length > maximumPlanBytes) throw new Error("LIVE_ACCEPTANCE_PLAN_TOO_LARGE");
    liveAcceptancePlanInputSchema.parse(JSON.parse(plaintext.toString("utf8")));
    const nonce = randomBytes(12); const cipher = createCipheriv(credentialVaultAlgorithm, nextKey.bytes, nonce); cipher.setAAD(aadFor(database, row.id, nextKey.version)); const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    database.db.prepare("UPDATE live_acceptance_plans SET algorithm=?,key_version=?,nonce=?,ciphertext=?,auth_tag=?,updated_at=? WHERE id=?").run(credentialVaultAlgorithm, nextKey.version, nonce.toString("base64url"), ciphertext.toString("base64url"), cipher.getAuthTag().toString("base64url"), nowIso(), row.id);
  }
  return rows.length;
}

function acceptanceScope(target: TargetSummary, neverTestPaths: readonly string[]): RouteCairnScope {
  const scope = scopeSchema.parse(target.approvedScope);
  return scopeSchema.parse({ ...scope, disallowedPaths: [...new Set([...(scope.disallowedPaths ?? []), ...neverTestPaths])] });
}
function aadFor(database: DashboardDatabase, id: string, keyVersion: string): Buffer { const installation = database.db.prepare("SELECT value FROM dashboard_meta WHERE key='installation_id'").get() as { value: string } | undefined; return Buffer.from(JSON.stringify({ purpose: "routecairn-live-acceptance-plan", id, installationId: installation?.value ?? "unknown", keyVersion }), "utf8"); }
function planBinding(plan: LiveAcceptancePlanInput, target: TargetSummary, scope: RouteCairnScope) { const scopeDigest = digest(scope); return { scopeDigest, planDigest: digest({ plan, target: { id: target.id, origin: target.baseOrigin, rowVersion: target.rowVersion, scopeDigest } }) }; }
function digest(value: unknown): string { return createHash("sha256").update(JSON.stringify(sort(value))).digest("hex"); }
function sort(value: unknown): unknown { if (Array.isArray(value)) return value.map(sort); if (!value || typeof value !== "object") return value; return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([key, child]) => [key, sort(child)])); }
function numeric(value: unknown): number { return typeof value === "number" && Number.isFinite(value) ? value : 0; }
function safeError(error: unknown): string { return error instanceof Error ? error.message.slice(0, 800) : "Live acceptance operation failed."; }
function isPublicHttpsOrigin(value: string): boolean {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) return false;
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal") || hostname.endsWith(".test") || hostname.endsWith(".invalid") || hostname.endsWith(".example")) return false;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
      const octets = hostname.split(".").map(Number);
      if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
      const [a, b] = octets as [number, number, number, number];
      if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return false;
    }
    if (hostname.includes(":")) {
      const compact = hostname.replace(/:/g, "");
      if (hostname === "::" || hostname === "::1" || /^f[cd]/.test(compact) || /^fe[89ab]/.test(compact)) return false;
    }
    return hostname.includes(".");
  } catch { return false; }
}
function workflowCaseCount(value: unknown): number { if (!value || typeof value !== "object") return 0; const record = value as Record<string, unknown>; if (Array.isArray(record.cases)) return record.cases.length; if (Array.isArray(record.definitions)) return record.definitions.reduce((sum, item) => sum + workflowCaseCount(item), 0); return 0; }
function assignAdvanced(target: Record<string, unknown>, id: AdvancedEngineId, value: unknown): void {
  const field = advancedEngineCatalog.find((item) => item.id === id)!.requestField;
  if (id === "pre-handover-assault") { const record = value as { orchestration: unknown; authorization: unknown }; target.preHandover = record.orchestration; target.targetAuthorization = record.authorization; }
  else target[field] = value;
}
function planSummary(row: PlanListRow | PlanRow): Record<string, unknown> { return { id: row.id, name: row.name, targetId: row.target_id, targetName: row.target_name, targetOrigin: row.base_origin, environment: row.environment, standard: row.standard, status: row.status, planDigest: row.plan_digest, authorizationMode: row.authorization_mode, authorizationExpiresAt: row.authorization_expires_at, laneCount: row.lane_count, ...(row.reviewed_at ? { reviewedAt: row.reviewed_at } : {}), createdAt: row.created_at, updatedAt: row.updated_at, rowVersion: row.row_version, ...("latest_run_id" in row && row.latest_run_id ? { latestRunId: row.latest_run_id } : {}) }; }
function deriveLane(database: DashboardDatabase, row: LaneRow): { id: string; label: string; kind: string; required: boolean; disposition: string; scanId?: string; scanStatus?: string; baselineScanId?: string; comparisonId?: string; evidenceScanId?: string; evidenceScanStatus?: string; findingCount: number; outcome: string; reason?: string; terminal: boolean; cleanupUnresolved: boolean; proof?: LiveAcceptanceProofResult } {
  if (row.configured_outcome) return { id: row.lane_id, label: row.label, kind: row.kind, required: Boolean(row.required), disposition: row.disposition, ...(row.scan_id ? { scanId: row.scan_id } : {}), ...(row.scan_status ? { scanStatus: row.scan_status } : {}), ...(row.evidence_scan_id ? { evidenceScanId: row.evidence_scan_id } : {}), ...(row.evidence_scan_status ? { evidenceScanStatus: row.evidence_scan_status } : {}), findingCount: 0, outcome: row.configured_outcome, ...(row.safe_reason ? { reason: row.safe_reason } : {}), terminal: true, cleanupUnresolved: false };
  const status = row.scan_status ?? "MISSING"; const cleanupUnresolved = Boolean(row.cleanup_unresolved); const semanticGaps = (row.case_gap_count ?? 0) + (row.assisted_gap_count ?? 0);
  const proofContract = parseProof(row.proof_contract_json);
  const remediation = row.baseline_scan_id && row.comparison_id && row.scan_id ? { baselineScanId: row.baseline_scan_id, rerunScanId: row.scan_id, comparisonId: row.comparison_id } : undefined;
  const proof = evaluateLiveAcceptanceProof(database, row.scan_id ?? undefined, proofContract, remediation);
  if (cleanupUnresolved && proofContract.requireResolvedCleanup) proof.missing.push("Cleanup or restoration remains unresolved.");
  proof.verified = proof.missing.length === 0;
  const outcome = status === "COMPLETED" || status === "IMPORTED" ? (cleanupUnresolved && proofContract.requireResolvedCleanup || semanticGaps > 0 || !proof.verified ? "INCONCLUSIVE" : "ASSESSED") : terminalScanStatuses.has(status) ? "INCONCLUSIVE" : "RUNNING";
  const reason = row.error_summary ? clamp(row.error_summary, 500) : proof.missing.length ? clamp(proof.missing.join(" "), 500) : undefined;
  return { id: row.lane_id, label: row.label, kind: row.kind, required: Boolean(row.required), disposition: row.disposition, ...(row.scan_id ? { scanId: row.scan_id } : {}), ...(row.baseline_scan_id ? { baselineScanId: row.baseline_scan_id } : {}), ...(row.comparison_id ? { comparisonId: row.comparison_id } : {}), scanStatus: status, findingCount: row.finding_count ?? 0, outcome, ...(reason ? { reason } : {}), terminal: outcome !== "RUNNING", cleanupUnresolved, proof };
}
function coverage(lanes: ReturnType<typeof deriveLane>[], standard: string) { const counts = { assessed: 0, notAssessed: 0, inconclusive: 0, notApplicable: 0, running: 0 }; for (const lane of lanes) { if (lane.outcome === "ASSESSED") counts.assessed++; else if (lane.outcome === "NOT_ASSESSED") counts.notAssessed++; else if (lane.outcome === "NOT_APPLICABLE") counts.notApplicable++; else if (lane.outcome === "INCONCLUSIVE") counts.inconclusive++; else counts.running++; } const accepted = standard === "BROADER_REAL_TARGET_V1" ? ["ASSESSED"] : ["ASSESSED", "NOT_APPLICABLE"]; const requiredGaps = lanes.filter((lane) => lane.required && !accepted.includes(lane.outcome)).length; return { ...counts, total: lanes.length, requiredGaps, complete: requiredGaps === 0 && lanes.length > 0, standard, findingCount: lanes.reduce((sum, lane) => sum + lane.findingCount, 0), cleanupUnresolved: lanes.filter((lane) => lane.cleanupUnresolved).length }; }

function parseProof(value: string): LiveAcceptanceProofContract {
  const parsed = JSON.parse(value) as Partial<LiveAcceptanceProofContract>;
  return { requiredModules: parsed.requiredModules ?? [], requiredWorkflows: parsed.requiredWorkflows ?? [], requiredFeatures: parsed.requiredFeatures ?? [], minimumCompletedCases: parsed.minimumCompletedCases ?? 0, minimumTransmittedCases: parsed.minimumTransmittedCases ?? 0, requireStrongEvidence: parsed.requireStrongEvidence ?? false, requireProviderAdapter: parsed.requireProviderAdapter ?? false, requireResolvedCleanup: parsed.requireResolvedCleanup ?? true, requireComparableRemediation: parsed.requireComparableRemediation ?? false, requireNoUnretestedCases: parsed.requireNoUnretestedCases ?? false };
}

interface PlanListRow { id: string; name: string; target_id: string; target_name: string; base_origin: string; environment: string; standard: string; status: string; plan_digest: string; authorization_mode: string; authorization_expires_at: string; lane_count: number; reviewed_at: string | null; created_at: string; updated_at: string; row_version: number; latest_run_id: string | null; }
interface PlanRow extends PlanListRow { target_row_version: number; scope_digest: string; algorithm: string; key_version: string; nonce: string; ciphertext: string; auth_tag: string; }
interface RunRow { id: string; plan_id: string; plan_digest: string; standard: string; status: string; requested_by: string; created_at: string; completed_at: string | null; safe_error_summary: string | null; }
interface LaneRow { lane_id: string; label: string; kind: string; required: number; disposition: string; scan_id: string | null; baseline_scan_id: string | null; comparison_id: string | null; proof_contract_json: string; evidence_scan_id: string | null; configured_outcome: string | null; safe_reason: string | null; scan_status: string | null; evidence_scan_status: string | null; finding_count: number | null; cleanup_unresolved: number | null; case_gap_count: number | null; assisted_gap_count: number | null; error_summary: string | null; }
